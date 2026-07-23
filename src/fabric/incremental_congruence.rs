#![forbid(unsafe_code)]

//! Rollback incremental congruence closure backed by signature buckets.
//!
//! [`RollbackCongruence`](super::congruence::RollbackCongruence) remains the
//! deterministic full-scan oracle. This engine has the same decision, result,
//! conflict, proof-cause, explanation, and semantic-cap vocabulary, but obtains
//! congruence candidates from [`RollbackSignatureIndex`] and its reverse uses.

use super::congruence::{
    Abstention, ApplyOutcome, ApplyStats, CONGRUENCE_PARTITION_REASON, CappedResource,
    ConflictOrigin, CongruenceConflict, CongruenceError, CongruenceLimits, Decision, EqualityCause,
    EqualityMerge, ExplanationOutcome, RollbackStats,
};
use super::partition::{
    Conflict as PartitionConflict, MAX_TERMS, MergeOutcome, Partition, PartitionError, ReasonId,
    Relation, SeparationOutcome, SeparationRecord, Snapshot as PartitionSnapshot, SnapshotError,
    TermId,
};
use super::semantic::SemanticTerm;
use super::signature::{
    CollisionPair, RollbackSignatureIndex, SignatureError, SignatureLimits, SignatureResource,
    SignatureSnapshot, SignatureTelemetry,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static NEXT_INCREMENTAL_ENGINE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct StateShape {
    partition_depth: usize,
    signature_depth: usize,
    proof_depth: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LineageEntry {
    state_id: u64,
    shape: StateShape,
}

/// Opaque rollback point spanning partition, signatures, proof history, and
/// the public-decision lineage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct IncrementalCongruenceSnapshot {
    engine_id: u64,
    transaction_depth: usize,
    state_id: u64,
    partition: PartitionSnapshot,
    signatures: SignatureSnapshot,
    proof_depth: usize,
}

impl IncrementalCongruenceSnapshot {
    /// Active partition-update depth, matching [`RollbackCongruence`]'s
    /// snapshot depth convention.
    pub(crate) const fn depth(self) -> usize {
        self.partition.depth()
    }

    pub(crate) const fn transaction_depth(self) -> usize {
        self.transaction_depth
    }

    pub(crate) const fn signature_depth(self) -> usize {
        self.signatures.depth()
    }

    pub(crate) const fn proof_depth(self) -> usize {
        self.proof_depth
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SaturationStats {
    merges: usize,
    passes: usize,
    pair_checks: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct IncrementalConstructionTimings {
    pub(crate) universe_validation_ns: u128,
    pub(crate) partition_construction_ns: u128,
    pub(crate) signature_index_construction_ns: u128,
    pub(crate) initial_saturation_ns: u128,
    pub(crate) post_construction_validation_ns: u128,
}

#[derive(Clone, Copy, Debug, Default)]
struct ExplanationBudget {
    edge_visits: usize,
}

enum WorkFailure {
    Abstained(Abstention),
    Error(CongruenceError),
}

enum SaturationFailure {
    Conflict(CongruenceConflict),
    Abstained(Abstention),
    Error(CongruenceError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FunctionShape {
    first_term: TermId,
    result_sort: u32,
    argument_sorts: Vec<u32>,
}

/// Incremental rollback congruence closure over one fixed semantic universe.
#[derive(Debug)]
pub(crate) struct RollbackIncrementalCongruence<'terms> {
    terms: &'terms [SemanticTerm],
    limits: CongruenceLimits,
    signature_limits: SignatureLimits,
    partition: Partition,
    signatures: RollbackSignatureIndex<'terms>,
    merges: Vec<EqualityMerge>,
    merge_adjacency: Vec<Vec<usize>>,
    engine_id: u64,
    lineage: Vec<LineageEntry>,
    next_state_id: u64,
    baseline: StateShape,
    construction_timings: IncrementalConstructionTimings,
}

pub(crate) type IncrementalCongruence<'terms> = RollbackIncrementalCongruence<'terms>;
pub(crate) type IncrementalCongruenceEngine<'terms> = RollbackIncrementalCongruence<'terms>;

impl<'terms> RollbackIncrementalCongruence<'terms> {
    pub(crate) fn new(terms: &'terms [SemanticTerm]) -> Result<Self, CongruenceError> {
        Self::with_limits(terms, CongruenceLimits::default())
    }

    /// Builds an incremental engine with signature caps derived from the
    /// corresponding full-scan semantic caps.
    pub(crate) fn with_limits(
        terms: &'terms [SemanticTerm],
        limits: CongruenceLimits,
    ) -> Result<Self, CongruenceError> {
        Self::with_limits_and_signature_limits_and_validation(
            terms,
            limits,
            derived_signature_limits(limits),
            true,
        )
    }

    pub(crate) fn with_limits_and_post_validation(
        terms: &'terms [SemanticTerm],
        limits: CongruenceLimits,
        post_construction_validation: bool,
    ) -> Result<Self, CongruenceError> {
        Self::with_limits_and_signature_limits_and_validation(
            terms,
            limits,
            derived_signature_limits(limits),
            post_construction_validation,
        )
    }

    /// Builds an engine with independently configurable signature-index caps.
    pub(crate) fn with_signature_limits(
        terms: &'terms [SemanticTerm],
        limits: CongruenceLimits,
        signature_limits: SignatureLimits,
    ) -> Result<Self, CongruenceError> {
        Self::with_limits_and_signature_limits(terms, limits, signature_limits)
    }

    pub(crate) fn with_limits_and_signature_limits(
        terms: &'terms [SemanticTerm],
        limits: CongruenceLimits,
        signature_limits: SignatureLimits,
    ) -> Result<Self, CongruenceError> {
        Self::with_limits_and_signature_limits_and_validation(terms, limits, signature_limits, true)
    }

    fn with_limits_and_signature_limits_and_validation(
        terms: &'terms [SemanticTerm],
        limits: CongruenceLimits,
        signature_limits: SignatureLimits,
        post_construction_validation: bool,
    ) -> Result<Self, CongruenceError> {
        let mut construction_timings = IncrementalConstructionTimings::default();
        let phase_start = Instant::now();
        validate_universe(terms, limits)?;
        construction_timings.universe_validation_ns = phase_start.elapsed().as_nanos();
        let phase_start = Instant::now();
        let partition = Partition::new(terms.len())?;
        construction_timings.partition_construction_ns = phase_start.elapsed().as_nanos();
        let phase_start = Instant::now();
        let signatures =
            match RollbackSignatureIndex::with_limits(terms, &partition, signature_limits) {
                Ok(index) => index,
                Err(error) => return Err(construction_signature_error(error)),
            };
        construction_timings.signature_index_construction_ns = phase_start.elapsed().as_nanos();
        let engine_id = NEXT_INCREMENTAL_ENGINE_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| {
                CongruenceError::InvariantViolation("incremental congruence engine ID exhausted")
            })?;
        let mut merge_adjacency = Vec::new();
        merge_adjacency
            .try_reserve_exact(terms.len())
            .map_err(|_| CongruenceError::AllocationFailed)?;
        merge_adjacency.resize_with(terms.len(), Vec::new);

        let mut engine = Self {
            terms,
            limits,
            signature_limits,
            partition,
            signatures,
            merges: Vec::new(),
            merge_adjacency,
            engine_id,
            lineage: Vec::new(),
            next_state_id: 1,
            baseline: StateShape::default(),
            construction_timings,
        };
        let pending = engine.signatures.collisions().collect::<BTreeSet<_>>();
        let phase_start = Instant::now();
        match engine.saturate(pending) {
            Ok(_) => {
                engine.construction_timings.initial_saturation_ns =
                    phase_start.elapsed().as_nanos();
                engine.baseline = engine.current_shape();
                if post_construction_validation {
                    let phase_start = Instant::now();
                    engine.validate()?;
                    engine.construction_timings.post_construction_validation_ns =
                        phase_start.elapsed().as_nanos();
                }
                Ok(engine)
            }
            Err(SaturationFailure::Abstained(reason)) => {
                Err(CongruenceError::ConstructionAbstained(reason))
            }
            Err(SaturationFailure::Conflict(_)) => Err(CongruenceError::InvariantViolation(
                "identity partition produced an incremental congruence conflict",
            )),
            Err(SaturationFailure::Error(error)) => Err(error),
        }
    }

    pub(crate) fn term_count(&self) -> usize {
        self.terms.len()
    }

    pub(crate) fn limits(&self) -> CongruenceLimits {
        self.limits
    }

    pub(crate) fn signature_limits(&self) -> SignatureLimits {
        self.signature_limits
    }

    pub(crate) fn partition(&self) -> &Partition {
        &self.partition
    }

    pub(crate) fn signature_index(&self) -> &RollbackSignatureIndex<'terms> {
        &self.signatures
    }

    pub(crate) fn signature_telemetry(&self) -> SignatureTelemetry {
        self.signatures.telemetry()
    }

    pub(crate) fn construction_timings(&self) -> IncrementalConstructionTimings {
        self.construction_timings
    }

    pub(crate) fn equality_merges(&self) -> &[EqualityMerge] {
        &self.merges
    }

    pub(crate) fn congruence_merges(&self) -> impl Iterator<Item = &EqualityMerge> {
        self.merges
            .iter()
            .filter(|merge| matches!(merge.cause, EqualityCause::Congruence { .. }))
    }

    pub(crate) fn snapshot(&self) -> IncrementalCongruenceSnapshot {
        IncrementalCongruenceSnapshot {
            engine_id: self.engine_id,
            transaction_depth: self.lineage.len(),
            state_id: self.lineage.last().map_or(0, |entry| entry.state_id),
            partition: self.partition.snapshot(),
            signatures: self.signatures.snapshot(),
            proof_depth: self.merges.len(),
        }
    }

    pub(crate) fn checkpoint(&self) -> IncrementalCongruenceSnapshot {
        self.snapshot()
    }

    pub(crate) fn rollback(
        &mut self,
        snapshot: IncrementalCongruenceSnapshot,
    ) -> Result<RollbackStats, CongruenceError> {
        self.validate_composite_snapshot(snapshot)?;
        let before_merges = self.merges.len();

        self.signatures.rollback(snapshot.signatures).map_err(|_| {
            CongruenceError::InvariantViolation(
                "validated composite snapshot failed signature rollback",
            )
        })?;
        let partition_updates = self.partition.rollback(snapshot.partition)?;
        self.truncate_merge_records(snapshot.proof_depth)?;
        self.lineage.truncate(snapshot.transaction_depth);

        if self.current_shape() != snapshot_shape(snapshot)
            || self.partition.merge_count() != self.merges.len()
        {
            return Err(CongruenceError::InvariantViolation(
                "composite rollback did not restore aligned state",
            ));
        }
        Ok(RollbackStats {
            partition_updates,
            equality_merges: before_merges - snapshot.proof_depth,
        })
    }

    pub(crate) fn rollback_to(
        &mut self,
        snapshot: IncrementalCongruenceSnapshot,
    ) -> Result<RollbackStats, CongruenceError> {
        self.rollback(snapshot)
    }

    pub(crate) fn relation(
        &self,
        left: TermId,
        right: TermId,
    ) -> Result<Relation, CongruenceError> {
        self.validate_pair(left, right)?;
        self.partition.relation(left, right).map_err(Into::into)
    }

    pub(crate) fn are_equal(&self, left: TermId, right: TermId) -> Result<bool, CongruenceError> {
        Ok(matches!(self.relation(left, right)?, Relation::Equal))
    }

    pub(crate) fn apply(&mut self, decision: Decision) -> Result<ApplyOutcome, CongruenceError> {
        match decision {
            Decision::Equality {
                left,
                right,
                reason,
            } => self.assert_equality(left, right, reason),
            Decision::Disequality {
                left,
                right,
                reason,
            } => self.assert_disequality(left, right, reason),
        }
    }

    pub(crate) fn assert_equality(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
    ) -> Result<ApplyOutcome, CongruenceError> {
        self.validate_pair(left, right)?;
        self.validate_reason(reason)?;
        let checkpoint = self.snapshot();
        let prior_relation = self.partition.relation(left, right)?;
        if matches!(prior_relation, Relation::Equal) {
            return Ok(ApplyOutcome::Applied(ApplyStats::default()));
        }

        if matches!(prior_relation, Relation::Disequal) {
            return match self.partition.merge(left, right, reason) {
                Err(PartitionError::Conflict(conflict)) => {
                    match self.explicit_equality_conflict(left, right, reason, conflict) {
                        Ok(conflict) => Ok(ApplyOutcome::Conflict(conflict)),
                        Err(WorkFailure::Abstained(abstention)) => {
                            Ok(ApplyOutcome::Abstained(abstention))
                        }
                        Err(WorkFailure::Error(error)) => Err(error),
                    }
                }
                Ok(_) => Err(CongruenceError::InvariantViolation(
                    "known disequality accepted an equality merge",
                )),
                Err(error) => Err(CongruenceError::Partition(error)),
            };
        }

        if let Err(abstention) = self.check_partition_update_capacity() {
            return Ok(ApplyOutcome::Abstained(abstention));
        }
        self.reserve_merge_record(left, right)?;
        let lineage_state = self.prepare_lineage_update()?;
        let changed_terms = changed_representatives_for_merge(&self.partition, left, right)?;

        match self.partition.merge(left, right, reason) {
            Ok(MergeOutcome::Merged { .. }) => {
                self.push_merge_record(EqualityMerge {
                    left,
                    right,
                    cause: EqualityCause::Explicit { reason },
                });
            }
            Ok(MergeOutcome::AlreadyEqual { .. }) => {
                return Err(CongruenceError::InvariantViolation(
                    "unknown relation became equal without an incremental merge",
                ));
            }
            Err(PartitionError::Conflict(conflict)) => {
                return match self.explicit_equality_conflict(left, right, reason, conflict) {
                    Ok(conflict) => Ok(ApplyOutcome::Conflict(conflict)),
                    Err(WorkFailure::Abstained(abstention)) => {
                        Ok(ApplyOutcome::Abstained(abstention))
                    }
                    Err(WorkFailure::Error(error)) => Err(error),
                };
            }
            Err(error) => return Err(CongruenceError::Partition(error)),
        }

        let update = match self
            .signatures
            .update_after_partition_change(&self.partition, &changed_terms)
        {
            Ok(update) => update,
            Err(error) => {
                let failure = signature_work_failure(error);
                self.restore_transaction(checkpoint)?;
                return match failure {
                    WorkFailure::Abstained(reason) => Ok(ApplyOutcome::Abstained(reason)),
                    WorkFailure::Error(error) => Err(error),
                };
            }
        };
        let pending = update.newly_colliding.into_iter().collect();

        match self.saturate(pending) {
            Ok(saturation) => {
                if let Err(error) = self.commit_lineage_update(lineage_state) {
                    self.restore_transaction(checkpoint)?;
                    return Err(error);
                }
                Ok(ApplyOutcome::Applied(ApplyStats {
                    explicit_update: true,
                    congruence_merges: saturation.merges,
                    saturation_passes: saturation.passes,
                    application_pair_checks: saturation.pair_checks,
                }))
            }
            Err(SaturationFailure::Conflict(conflict)) => {
                self.restore_transaction(checkpoint)?;
                Ok(ApplyOutcome::Conflict(conflict))
            }
            Err(SaturationFailure::Abstained(reason)) => {
                self.restore_transaction(checkpoint)?;
                Ok(ApplyOutcome::Abstained(reason))
            }
            Err(SaturationFailure::Error(error)) => {
                self.restore_transaction(checkpoint)?;
                Err(error)
            }
        }
    }

    pub(crate) fn assert_equal(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
    ) -> Result<ApplyOutcome, CongruenceError> {
        self.assert_equality(left, right, reason)
    }

    pub(crate) fn assert_disequality(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
    ) -> Result<ApplyOutcome, CongruenceError> {
        self.validate_pair(left, right)?;
        self.validate_reason(reason)?;
        let checkpoint = self.snapshot();
        let prior_relation = self.partition.relation(left, right)?;
        let duplicate = if matches!(prior_relation, Relation::Disequal) {
            self.is_duplicate_separation(left, right, reason)?
        } else {
            false
        };
        let will_update = !matches!(prior_relation, Relation::Equal) && !duplicate;
        let lineage_state = if will_update {
            if let Err(abstention) = self.check_partition_update_capacity() {
                return Ok(ApplyOutcome::Abstained(abstention));
            }
            Some(self.prepare_lineage_update()?)
        } else {
            None
        };

        match self.partition.separate(left, right, reason) {
            Ok(outcome) => {
                let changed = matches!(outcome, SeparationOutcome::Added { .. });
                if changed {
                    let Some(state_id) = lineage_state else {
                        self.restore_transaction(checkpoint)?;
                        return Err(CongruenceError::InvariantViolation(
                            "disequality update had no prepared lineage state",
                        ));
                    };
                    if let Err(error) = self.commit_lineage_update(state_id) {
                        self.restore_transaction(checkpoint)?;
                        return Err(error);
                    }
                } else if lineage_state.is_some() {
                    return Err(CongruenceError::InvariantViolation(
                        "prepared disequality update did not change partition state",
                    ));
                }
                Ok(ApplyOutcome::Applied(ApplyStats {
                    explicit_update: changed,
                    ..ApplyStats::default()
                }))
            }
            Err(PartitionError::Conflict(PartitionConflict::DisequalityAgainstEquality {
                ..
            })) => {
                let mut budget = ExplanationBudget::default();
                let outcome = match self.explain_equal_internal(left, right, &mut budget) {
                    Ok(Some(equality_reasons)) => match self.checked_single_reason(reason) {
                        Ok(disequality_reasons) => Ok(ApplyOutcome::Conflict(CongruenceConflict {
                            origin: ConflictOrigin::ExplicitDisequality {
                                left,
                                right,
                                reason,
                            },
                            equality_reasons,
                            disequality_reasons,
                        })),
                        Err(WorkFailure::Abstained(abstention)) => {
                            Ok(ApplyOutcome::Abstained(abstention))
                        }
                        Err(WorkFailure::Error(error)) => Err(error),
                    },
                    Ok(None) => Err(CongruenceError::InvariantViolation(
                        "partition disequality conflict has no equality proof",
                    )),
                    Err(WorkFailure::Abstained(abstention)) => {
                        Ok(ApplyOutcome::Abstained(abstention))
                    }
                    Err(WorkFailure::Error(error)) => Err(error),
                };
                self.restore_transaction(checkpoint)?;
                outcome
            }
            Err(PartitionError::Conflict(_)) => {
                self.restore_transaction(checkpoint)?;
                Err(CongruenceError::InvariantViolation(
                    "disequality assertion produced an equality conflict variant",
                ))
            }
            Err(error) => {
                self.restore_transaction(checkpoint)?;
                Err(CongruenceError::Partition(error))
            }
        }
    }

    pub(crate) fn assert_disequal(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
    ) -> Result<ApplyOutcome, CongruenceError> {
        self.assert_disequality(left, right, reason)
    }

    pub(crate) fn explain_equal(
        &self,
        left: TermId,
        right: TermId,
    ) -> Result<ExplanationOutcome, CongruenceError> {
        self.validate_pair(left, right)?;
        let mut budget = ExplanationBudget::default();
        match self.explain_equal_internal(left, right, &mut budget) {
            Ok(Some(reasons)) => Ok(ExplanationOutcome::Explained(reasons)),
            Ok(None) => Ok(ExplanationOutcome::NotEqual),
            Err(WorkFailure::Abstained(reason)) => Ok(ExplanationOutcome::Abstained(reason)),
            Err(WorkFailure::Error(error)) => Err(error),
        }
    }

    /// Explains equality using only proof edges that existed at `snapshot`.
    ///
    /// This is used by lazy external-propagation reasons: the solver may ask
    /// for a reason after extending the trail, but the returned explanation
    /// must not depend on assignments made after the propagation itself.
    pub(crate) fn explain_equal_at(
        &self,
        left: TermId,
        right: TermId,
        snapshot: IncrementalCongruenceSnapshot,
    ) -> Result<ExplanationOutcome, CongruenceError> {
        self.validate_pair(left, right)?;
        self.validate_composite_snapshot(snapshot)?;
        let mut budget = ExplanationBudget::default();
        match self.explain_equal_bounded(left, right, snapshot.proof_depth, &mut budget) {
            Ok(Some(reasons)) => Ok(ExplanationOutcome::Explained(reasons)),
            Ok(None) => Ok(ExplanationOutcome::NotEqual),
            Err(WorkFailure::Abstained(reason)) => Ok(ExplanationOutcome::Abstained(reason)),
            Err(WorkFailure::Error(error)) => Err(error),
        }
    }

    /// Expensive structural validation, including a full signature-to-partition
    /// oracle check and closure of every active collision.
    pub(crate) fn validate(&self) -> Result<(), CongruenceError> {
        self.partition.validate()?;
        self.signatures
            .validate_against_partition(&self.partition)
            .map_err(signature_internal_error)?;
        if self.partition.merge_count() != self.merges.len()
            || self.partition.merge_records().len() != self.merges.len()
        {
            return Err(CongruenceError::InvariantViolation(
                "partition merge count differs from incremental proof history",
            ));
        }
        if self.merge_adjacency.len() != self.terms.len() {
            return Err(CongruenceError::InvariantViolation(
                "merge adjacency has the wrong term cardinality",
            ));
        }
        let mut incidence_counts = Vec::new();
        incidence_counts
            .try_reserve_exact(self.merges.len())
            .map_err(|_| CongruenceError::AllocationFailed)?;
        incidence_counts.resize(self.merges.len(), 0u8);
        for (term_index, adjacency) in self.merge_adjacency.iter().enumerate() {
            if adjacency.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(CongruenceError::InvariantViolation(
                    "merge adjacency is not strictly ordered",
                ));
            }
            for &edge_index in adjacency {
                let edge =
                    self.merges
                        .get(edge_index)
                        .ok_or(CongruenceError::InvariantViolation(
                            "merge adjacency references a missing proof edge",
                        ))?;
                if edge.left.index() != term_index && edge.right.index() != term_index {
                    return Err(CongruenceError::InvariantViolation(
                        "merge adjacency edge is not incident to its term",
                    ));
                }
                incidence_counts[edge_index] = incidence_counts[edge_index].checked_add(1).ok_or(
                    CongruenceError::InvariantViolation(
                        "merge adjacency incidence count overflowed",
                    ),
                )?;
            }
        }
        for (edge, count) in self.merges.iter().zip(incidence_counts) {
            let expected = if edge.left == edge.right { 1 } else { 2 };
            if count != expected {
                return Err(CongruenceError::InvariantViolation(
                    "merge adjacency does not contain both proof endpoints",
                ));
            }
        }
        if self.current_shape() != self.expected_current_shape() {
            return Err(CongruenceError::InvariantViolation(
                "incremental lineage shape differs from mutable state",
            ));
        }

        let explicit_reasons = self
            .merges
            .iter()
            .filter_map(|merge| match merge.cause {
                EqualityCause::Explicit { reason } => Some(reason),
                EqualityCause::Congruence { .. } => None,
            })
            .collect::<BTreeSet<_>>();
        for (partition_record, proof) in self.partition.merge_records().iter().zip(&self.merges) {
            if partition_record.left != proof.left || partition_record.right != proof.right {
                return Err(CongruenceError::InvariantViolation(
                    "partition merge endpoints differ from incremental proof endpoints",
                ));
            }
            self.validate_pair(proof.left, proof.right)?;
            match &proof.cause {
                EqualityCause::Explicit { reason } => {
                    if *reason == CONGRUENCE_PARTITION_REASON || partition_record.reason != *reason
                    {
                        return Err(CongruenceError::InvariantViolation(
                            "explicit incremental proof reason differs from partition reason",
                        ));
                    }
                }
                EqualityCause::Congruence {
                    argument_pairs,
                    antecedent_reasons,
                } => {
                    if partition_record.reason != CONGRUENCE_PARTITION_REASON {
                        return Err(CongruenceError::InvariantViolation(
                            "derived incremental merge lacks its partition marker",
                        ));
                    }
                    let left_term = &self.terms[proof.left.index()];
                    let right_term = &self.terms[proof.right.index()];
                    if !same_application_head(left_term, right_term)
                        || argument_pairs.len() != left_term.arguments.len()
                        || argument_pairs.iter().copied().ne(left_term
                            .arguments
                            .iter()
                            .copied()
                            .zip(right_term.arguments.iter().copied()))
                    {
                        return Err(CongruenceError::InvariantViolation(
                            "derived incremental proof records wrong argument pairs",
                        ));
                    }
                    if antecedent_reasons.windows(2).any(|pair| pair[0] >= pair[1])
                        || antecedent_reasons.contains(&CONGRUENCE_PARTITION_REASON)
                        || antecedent_reasons
                            .iter()
                            .any(|reason| !explicit_reasons.contains(reason))
                    {
                        return Err(CongruenceError::InvariantViolation(
                            "derived incremental antecedents are not active explicit reasons",
                        ));
                    }
                    for &(left, right) in argument_pairs {
                        if !self.partition.are_equal(left, right)? {
                            return Err(CongruenceError::InvariantViolation(
                                "derived incremental proof has unequal arguments",
                            ));
                        }
                    }
                }
            }
        }

        for collision in self.signatures.collisions() {
            if !self.partition.are_equal(collision.left, collision.right)? {
                return Err(CongruenceError::InvariantViolation(
                    "active signature collision is not congruence-closed",
                ));
            }
        }
        Ok(())
    }

    fn saturate(
        &mut self,
        mut pending: BTreeSet<CollisionPair>,
    ) -> Result<SaturationStats, SaturationFailure> {
        if self.terms.len() < 2 {
            if pending.is_empty() {
                return Ok(SaturationStats::default());
            }
            return Err(SaturationFailure::Error(
                CongruenceError::InvariantViolation(
                    "a singleton universe has an application collision",
                ),
            ));
        }

        let mut stats = SaturationStats::default();
        let mut explanation_budget = ExplanationBudget::default();
        spend(
            &mut stats.passes,
            CappedResource::SaturationPasses,
            self.limits.max_saturation_passes,
        )
        .map_err(SaturationFailure::Abstained)?;

        while let Some(collision) = pending.pop_first() {
            spend(
                &mut stats.pair_checks,
                CappedResource::ApplicationPairChecks,
                self.limits.max_application_pair_checks,
            )
            .map_err(SaturationFailure::Abstained)?;

            let left = collision.left;
            let right = collision.right;
            let keys_match = {
                let left_key = self
                    .signatures
                    .application_signature(left)
                    .map_err(signature_internal_error)
                    .map_err(SaturationFailure::Error)?;
                let right_key = self
                    .signatures
                    .application_signature(right)
                    .map_err(signature_internal_error)
                    .map_err(SaturationFailure::Error)?;
                left_key == right_key
            };
            if !keys_match {
                return Err(SaturationFailure::Error(
                    CongruenceError::InvariantViolation(
                        "queued collision no longer has equal signatures",
                    ),
                ));
            }
            if self
                .partition
                .are_equal(left, right)
                .map_err(CongruenceError::Partition)
                .map_err(SaturationFailure::Error)?
            {
                continue;
            }

            let left_term = &self.terms[left.index()];
            let right_term = &self.terms[right.index()];
            if !same_application_head(left_term, right_term) {
                return Err(SaturationFailure::Error(
                    CongruenceError::InvariantViolation(
                        "equal signature keys have different application heads",
                    ),
                ));
            }
            let mut argument_pairs = Vec::new();
            argument_pairs
                .try_reserve_exact(left_term.arguments.len())
                .map_err(|_| SaturationFailure::Error(CongruenceError::AllocationFailed))?;
            for (&left_argument, &right_argument) in
                left_term.arguments.iter().zip(right_term.arguments.iter())
            {
                if !self
                    .partition
                    .are_equal(left_argument, right_argument)
                    .map_err(CongruenceError::Partition)
                    .map_err(SaturationFailure::Error)?
                {
                    return Err(SaturationFailure::Error(
                        CongruenceError::InvariantViolation(
                            "signature collision has unequal corresponding arguments",
                        ),
                    ));
                }
                argument_pairs.push((left_argument, right_argument));
            }
            let antecedent_reasons = self
                .congruence_antecedents(&argument_pairs, &mut explanation_budget)
                .map_err(|failure| match failure {
                    WorkFailure::Abstained(reason) => SaturationFailure::Abstained(reason),
                    WorkFailure::Error(error) => SaturationFailure::Error(error),
                })?;

            match self
                .partition
                .relation(left, right)
                .map_err(CongruenceError::Partition)
                .map_err(SaturationFailure::Error)?
            {
                Relation::Equal => {
                    return Err(SaturationFailure::Error(
                        CongruenceError::InvariantViolation(
                            "non-equal collision became equal without a merge",
                        ),
                    ));
                }
                Relation::Disequal => {
                    let separations = self
                        .partition
                        .separation_witnesses(left, right)
                        .map_err(CongruenceError::Partition)
                        .map_err(SaturationFailure::Error)?
                        .ok_or_else(|| {
                            SaturationFailure::Error(CongruenceError::InvariantViolation(
                                "disequal collision has no separation witnesses",
                            ))
                        })?;
                    let (equality_reasons, disequality_reasons) = self
                        .aligned_conflict_reasons(
                            left,
                            right,
                            &antecedent_reasons,
                            &separations,
                            &mut explanation_budget,
                        )
                        .map_err(|failure| match failure {
                            WorkFailure::Abstained(reason) => SaturationFailure::Abstained(reason),
                            WorkFailure::Error(error) => SaturationFailure::Error(error),
                        })?;
                    return Err(SaturationFailure::Conflict(CongruenceConflict {
                        origin: ConflictOrigin::Congruence {
                            left_application: left,
                            right_application: right,
                            argument_pairs,
                        },
                        equality_reasons,
                        disequality_reasons,
                    }));
                }
                Relation::Unknown => {}
            }

            let attempted_merges = stats.merges.checked_add(1).ok_or_else(|| {
                SaturationFailure::Abstained(Abstention::ArithmeticOverflow {
                    resource: CappedResource::CongruenceMerges,
                })
            })?;
            if attempted_merges > self.limits.max_congruence_merges {
                return Err(SaturationFailure::Abstained(Abstention::CapExceeded {
                    resource: CappedResource::CongruenceMerges,
                    attempted: attempted_merges,
                    limit: self.limits.max_congruence_merges,
                }));
            }
            self.check_partition_update_capacity()
                .map_err(SaturationFailure::Abstained)?;
            self.reserve_merge_record(left, right)
                .map_err(SaturationFailure::Error)?;
            let changed_terms = changed_representatives_for_merge(&self.partition, left, right)
                .map_err(CongruenceError::Partition)
                .map_err(SaturationFailure::Error)?;

            match self
                .partition
                .merge(left, right, CONGRUENCE_PARTITION_REASON)
            {
                Ok(MergeOutcome::Merged { .. }) => {}
                Ok(MergeOutcome::AlreadyEqual { .. }) => {
                    return Err(SaturationFailure::Error(
                        CongruenceError::InvariantViolation(
                            "unknown collision was already equal during merge",
                        ),
                    ));
                }
                Err(PartitionError::Conflict(PartitionConflict::EqualityAgainstDisequality {
                    separations,
                    ..
                })) => {
                    let (equality_reasons, disequality_reasons) = self
                        .aligned_conflict_reasons(
                            left,
                            right,
                            &antecedent_reasons,
                            &separations,
                            &mut explanation_budget,
                        )
                        .map_err(|failure| match failure {
                            WorkFailure::Abstained(reason) => SaturationFailure::Abstained(reason),
                            WorkFailure::Error(error) => SaturationFailure::Error(error),
                        })?;
                    return Err(SaturationFailure::Conflict(CongruenceConflict {
                        origin: ConflictOrigin::Congruence {
                            left_application: left,
                            right_application: right,
                            argument_pairs,
                        },
                        equality_reasons,
                        disequality_reasons,
                    }));
                }
                Err(PartitionError::Conflict(_)) => {
                    return Err(SaturationFailure::Error(
                        CongruenceError::InvariantViolation(
                            "congruence merge produced a disequality conflict variant",
                        ),
                    ));
                }
                Err(error) => {
                    return Err(SaturationFailure::Error(CongruenceError::Partition(error)));
                }
            }
            self.push_merge_record(EqualityMerge {
                left,
                right,
                cause: EqualityCause::Congruence {
                    argument_pairs,
                    antecedent_reasons,
                },
            });
            stats.merges = attempted_merges;

            let update = self
                .signatures
                .update_after_partition_change(&self.partition, &changed_terms)
                .map_err(signature_work_failure)
                .map_err(|failure| match failure {
                    WorkFailure::Abstained(reason) => SaturationFailure::Abstained(reason),
                    WorkFailure::Error(error) => SaturationFailure::Error(error),
                })?;
            pending.extend(update.newly_colliding);
        }
        Ok(stats)
    }

    fn congruence_antecedents(
        &self,
        argument_pairs: &[(TermId, TermId)],
        budget: &mut ExplanationBudget,
    ) -> Result<Vec<ReasonId>, WorkFailure> {
        let mut antecedents = Vec::new();
        for &(left, right) in argument_pairs {
            let Some(reasons) = self.explain_equal_internal(left, right, budget)? else {
                return Err(WorkFailure::Error(CongruenceError::InvariantViolation(
                    "signature collision has no argument equality explanation",
                )));
            };
            antecedents
                .try_reserve(reasons.len())
                .map_err(|_| WorkFailure::Error(CongruenceError::AllocationFailed))?;
            antecedents.extend(reasons);
            canonicalize_reasons(&mut antecedents);
            check_reason_cap(antecedents.len(), self.limits.max_antecedent_reasons)
                .map_err(WorkFailure::Abstained)?;
        }
        Ok(antecedents)
    }

    fn explain_equal_internal(
        &self,
        left: TermId,
        right: TermId,
        budget: &mut ExplanationBudget,
    ) -> Result<Option<Vec<ReasonId>>, WorkFailure> {
        let equal = self
            .partition
            .are_equal(left, right)
            .map_err(CongruenceError::Partition)
            .map_err(WorkFailure::Error)?;
        if !equal {
            return Ok(None);
        }
        let explanation = self.explain_equal_bounded(left, right, self.merges.len(), budget)?;
        if explanation.is_none() {
            return Err(WorkFailure::Error(CongruenceError::InvariantViolation(
                "equal terms have no incremental causal merge path",
            )));
        }
        Ok(explanation)
    }

    fn explain_equal_bounded(
        &self,
        left: TermId,
        right: TermId,
        proof_depth: usize,
        budget: &mut ExplanationBudget,
    ) -> Result<Option<Vec<ReasonId>>, WorkFailure> {
        if proof_depth > self.merges.len() {
            return Err(WorkFailure::Error(CongruenceError::InvariantViolation(
                "historical explanation depth exceeds active proof history",
            )));
        }
        if left == right {
            return Ok(Some(Vec::new()));
        }

        let term_count = self.terms.len();
        let mut seen = Vec::new();
        seen.try_reserve_exact(term_count)
            .map_err(|_| WorkFailure::Error(CongruenceError::AllocationFailed))?;
        seen.resize(term_count, false);
        let mut predecessor = Vec::new();
        predecessor
            .try_reserve_exact(term_count)
            .map_err(|_| WorkFailure::Error(CongruenceError::AllocationFailed))?;
        predecessor.resize(term_count, None::<(usize, usize)>);
        let mut queue = VecDeque::new();
        queue
            .try_reserve(term_count)
            .map_err(|_| WorkFailure::Error(CongruenceError::AllocationFailed))?;

        seen[left.index()] = true;
        queue.push_back(left.index());
        while let Some(current) = queue.pop_front() {
            if current == right.index() {
                break;
            }
            for &edge_index in &self.merge_adjacency[current] {
                if edge_index >= proof_depth {
                    break;
                }
                spend(
                    &mut budget.edge_visits,
                    CappedResource::ExplanationEdgeVisits,
                    self.limits.max_explanation_edge_visits,
                )
                .map_err(WorkFailure::Abstained)?;
                let edge = self.merges.get(edge_index).ok_or_else(|| {
                    WorkFailure::Error(CongruenceError::InvariantViolation(
                        "merge adjacency references a missing proof edge",
                    ))
                })?;
                let next = if edge.left.index() == current {
                    edge.right.index()
                } else if edge.right.index() == current {
                    edge.left.index()
                } else {
                    return Err(WorkFailure::Error(CongruenceError::InvariantViolation(
                        "merge adjacency edge is not incident to its term",
                    )));
                };
                if !seen[next] {
                    seen[next] = true;
                    predecessor[next] = Some((current, edge_index));
                    queue.push_back(next);
                }
            }
        }
        if !seen[right.index()] {
            return Ok(None);
        }

        let mut reasons = Vec::new();
        let mut current = right.index();
        while current != left.index() {
            let Some((previous, edge_index)) = predecessor[current] else {
                return Err(WorkFailure::Error(CongruenceError::InvariantViolation(
                    "incremental causal predecessor chain is incomplete",
                )));
            };
            let edge = self.merges.get(edge_index).ok_or_else(|| {
                WorkFailure::Error(CongruenceError::InvariantViolation(
                    "incremental causal predecessor references no proof edge",
                ))
            })?;
            match &edge.cause {
                EqualityCause::Explicit { reason } => {
                    reasons
                        .try_reserve(1)
                        .map_err(|_| WorkFailure::Error(CongruenceError::AllocationFailed))?;
                    reasons.push(*reason);
                }
                EqualityCause::Congruence {
                    antecedent_reasons, ..
                } => {
                    reasons
                        .try_reserve(antecedent_reasons.len())
                        .map_err(|_| WorkFailure::Error(CongruenceError::AllocationFailed))?;
                    reasons.extend_from_slice(antecedent_reasons);
                }
            }
            current = previous;
        }
        canonicalize_reasons(&mut reasons);
        check_reason_cap(reasons.len(), self.limits.max_antecedent_reasons)
            .map_err(WorkFailure::Abstained)?;
        Ok(Some(reasons))
    }

    fn validate_pair(&self, left: TermId, right: TermId) -> Result<(), CongruenceError> {
        let left_term = self
            .terms
            .get(left.index())
            .ok_or(CongruenceError::InvalidTerm {
                term: left,
                term_count: self.terms.len(),
            })?;
        let right_term = self
            .terms
            .get(right.index())
            .ok_or(CongruenceError::InvalidTerm {
                term: right,
                term_count: self.terms.len(),
            })?;
        if left_term.sort != right_term.sort {
            return Err(CongruenceError::SortMismatch {
                left,
                left_sort: left_term.sort,
                right,
                right_sort: right_term.sort,
            });
        }
        Ok(())
    }

    fn validate_reason(&self, reason: ReasonId) -> Result<(), CongruenceError> {
        if reason == CONGRUENCE_PARTITION_REASON {
            Err(CongruenceError::ReservedReason(reason))
        } else {
            Ok(())
        }
    }

    fn reserve_merge_record(&mut self, left: TermId, right: TermId) -> Result<(), CongruenceError> {
        self.merges
            .try_reserve(1)
            .map_err(|_| CongruenceError::AllocationFailed)?;
        self.merge_adjacency[left.index()]
            .try_reserve(1)
            .map_err(|_| CongruenceError::AllocationFailed)?;
        if right != left {
            self.merge_adjacency[right.index()]
                .try_reserve(1)
                .map_err(|_| CongruenceError::AllocationFailed)?;
        }
        Ok(())
    }

    fn push_merge_record(&mut self, merge: EqualityMerge) {
        let edge_index = self.merges.len();
        let left = merge.left;
        let right = merge.right;
        self.merges.push(merge);
        self.merge_adjacency[left.index()].push(edge_index);
        if right != left {
            self.merge_adjacency[right.index()].push(edge_index);
        }
    }

    fn truncate_merge_records(&mut self, proof_depth: usize) -> Result<(), CongruenceError> {
        for edge_index in (proof_depth..self.merges.len()).rev() {
            let merge = &self.merges[edge_index];
            if self.merge_adjacency[merge.left.index()].pop() != Some(edge_index) {
                return Err(CongruenceError::InvariantViolation(
                    "left merge adjacency rollback is not stack-aligned",
                ));
            }
            if merge.right != merge.left
                && self.merge_adjacency[merge.right.index()].pop() != Some(edge_index)
            {
                return Err(CongruenceError::InvariantViolation(
                    "right merge adjacency rollback is not stack-aligned",
                ));
            }
        }
        self.merges.truncate(proof_depth);
        Ok(())
    }

    fn check_partition_update_capacity(&self) -> Result<(), Abstention> {
        let attempted = self.partition.snapshot().depth().checked_add(1).ok_or(
            Abstention::ArithmeticOverflow {
                resource: CappedResource::PartitionUpdates,
            },
        )?;
        if attempted > self.limits.max_partition_updates {
            Err(Abstention::CapExceeded {
                resource: CappedResource::PartitionUpdates,
                attempted,
                limit: self.limits.max_partition_updates,
            })
        } else {
            Ok(())
        }
    }

    fn prepare_lineage_update(&mut self) -> Result<u64, CongruenceError> {
        let state_id = self.next_state_id;
        state_id
            .checked_add(1)
            .ok_or(CongruenceError::InvariantViolation(
                "incremental congruence state ID exhausted",
            ))?;
        self.lineage
            .try_reserve(1)
            .map_err(|_| CongruenceError::AllocationFailed)?;
        Ok(state_id)
    }

    fn commit_lineage_update(&mut self, state_id: u64) -> Result<(), CongruenceError> {
        if state_id != self.next_state_id {
            return Err(CongruenceError::InvariantViolation(
                "prepared incremental lineage state is stale",
            ));
        }
        let next_state_id = state_id
            .checked_add(1)
            .ok_or(CongruenceError::InvariantViolation(
                "incremental congruence state ID exhausted",
            ))?;
        self.lineage.push(LineageEntry {
            state_id,
            shape: self.current_shape(),
        });
        self.next_state_id = next_state_id;
        Ok(())
    }

    fn validate_composite_snapshot(
        &self,
        snapshot: IncrementalCongruenceSnapshot,
    ) -> Result<(), CongruenceError> {
        if snapshot.engine_id != self.engine_id {
            return Err(invalid_snapshot(SnapshotError::ForeignPartition));
        }
        if snapshot.transaction_depth > self.lineage.len() {
            return Err(invalid_snapshot(SnapshotError::FutureState));
        }
        let expected_state_id = if snapshot.transaction_depth == 0 {
            0
        } else {
            self.lineage[snapshot.transaction_depth - 1].state_id
        };
        if snapshot.state_id != expected_state_id {
            return Err(invalid_snapshot(SnapshotError::DiscardedBranch));
        }
        let expected_shape = if snapshot.transaction_depth == 0 {
            self.baseline
        } else {
            self.lineage[snapshot.transaction_depth - 1].shape
        };
        if snapshot_shape(snapshot) != expected_shape {
            return Err(invalid_snapshot(SnapshotError::DiscardedBranch));
        }
        Ok(())
    }

    fn current_shape(&self) -> StateShape {
        StateShape {
            partition_depth: self.partition.snapshot().depth(),
            signature_depth: self.signatures.snapshot().depth(),
            proof_depth: self.merges.len(),
        }
    }

    fn expected_current_shape(&self) -> StateShape {
        self.lineage
            .last()
            .map_or(self.baseline, |entry| entry.shape)
    }

    fn restore_transaction(
        &mut self,
        checkpoint: IncrementalCongruenceSnapshot,
    ) -> Result<(), CongruenceError> {
        if checkpoint.engine_id != self.engine_id
            || checkpoint.transaction_depth != self.lineage.len()
            || checkpoint.state_id != self.lineage.last().map_or(0, |entry| entry.state_id)
        {
            return Err(CongruenceError::InvariantViolation(
                "transaction checkpoint is outside the active incremental lineage",
            ));
        }
        self.signatures
            .rollback(checkpoint.signatures)
            .map_err(|_| {
                CongruenceError::InvariantViolation(
                    "signature rollback failed while restoring incremental transaction",
                )
            })?;
        self.partition
            .rollback(checkpoint.partition)
            .map_err(CongruenceError::TransactionRollbackFailed)?;
        if checkpoint.proof_depth > self.merges.len() {
            return Err(CongruenceError::InvariantViolation(
                "transaction checkpoint exceeds incremental proof history",
            ));
        }
        self.truncate_merge_records(checkpoint.proof_depth)?;
        if self.current_shape() != snapshot_shape(checkpoint)
            || self.current_shape() != self.expected_current_shape()
        {
            return Err(CongruenceError::InvariantViolation(
                "transaction rollback did not restore all incremental layers",
            ));
        }
        Ok(())
    }

    fn is_duplicate_separation(
        &self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
    ) -> Result<bool, CongruenceError> {
        let requested = normalized_pair(left, right);
        Ok(self
            .partition
            .separation_witnesses(left, right)?
            .is_some_and(|records| {
                records.into_iter().any(|record| {
                    normalized_pair(record.left, record.right) == requested
                        && record.reason == reason
                })
            }))
    }

    fn explicit_equality_conflict(
        &self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
        conflict: PartitionConflict,
    ) -> Result<CongruenceConflict, WorkFailure> {
        let PartitionConflict::EqualityAgainstDisequality { separations, .. } = conflict else {
            return Err(WorkFailure::Error(CongruenceError::InvariantViolation(
                "equality assertion produced a disequality conflict variant",
            )));
        };
        let mut budget = ExplanationBudget::default();
        let base = self.checked_single_reason(reason)?;
        let (equality_reasons, disequality_reasons) =
            self.aligned_conflict_reasons(left, right, &base, &separations, &mut budget)?;
        Ok(CongruenceConflict {
            origin: ConflictOrigin::ExplicitEquality {
                left,
                right,
                reason,
            },
            equality_reasons,
            disequality_reasons,
        })
    }

    fn aligned_conflict_reasons(
        &self,
        left: TermId,
        right: TermId,
        base_equality_reasons: &[ReasonId],
        separations: &[SeparationRecord],
        budget: &mut ExplanationBudget,
    ) -> Result<(Vec<ReasonId>, Vec<ReasonId>), WorkFailure> {
        let mut ordered = Vec::new();
        ordered
            .try_reserve_exact(separations.len())
            .map_err(|_| WorkFailure::Error(CongruenceError::AllocationFailed))?;
        ordered.extend_from_slice(separations);
        ordered.sort_by_key(|record| (record.reason, record.left, record.right));

        let mut best: Option<(Vec<ReasonId>, Vec<ReasonId>)> = None;
        for separation in ordered {
            let direct = self
                .partition
                .are_equal(left, separation.left)
                .map_err(CongruenceError::Partition)
                .map_err(WorkFailure::Error)?
                && self
                    .partition
                    .are_equal(right, separation.right)
                    .map_err(CongruenceError::Partition)
                    .map_err(WorkFailure::Error)?;
            let swapped = self
                .partition
                .are_equal(left, separation.right)
                .map_err(CongruenceError::Partition)
                .map_err(WorkFailure::Error)?
                && self
                    .partition
                    .are_equal(right, separation.left)
                    .map_err(CongruenceError::Partition)
                    .map_err(WorkFailure::Error)?;
            let (left_witness, right_witness) = if direct {
                (separation.left, separation.right)
            } else if swapped {
                (separation.right, separation.left)
            } else {
                continue;
            };

            let mut equality_reasons = Vec::new();
            equality_reasons
                .try_reserve(base_equality_reasons.len())
                .map_err(|_| WorkFailure::Error(CongruenceError::AllocationFailed))?;
            equality_reasons.extend_from_slice(base_equality_reasons);
            for (endpoint, witness) in [(left, left_witness), (right, right_witness)] {
                let Some(reasons) = self.explain_equal_internal(endpoint, witness, budget)? else {
                    return Err(WorkFailure::Error(CongruenceError::InvariantViolation(
                        "disequality witness endpoint lacks its class-alignment proof",
                    )));
                };
                equality_reasons
                    .try_reserve(reasons.len())
                    .map_err(|_| WorkFailure::Error(CongruenceError::AllocationFailed))?;
                equality_reasons.extend(reasons);
            }
            canonicalize_reasons(&mut equality_reasons);
            check_reason_cap(equality_reasons.len(), self.limits.max_antecedent_reasons)
                .map_err(WorkFailure::Abstained)?;
            let disequality_reasons = self.checked_single_reason(separation.reason)?;
            let replace = best.as_ref().is_none_or(|current| {
                let candidate_len = equality_reasons.len() + disequality_reasons.len();
                let current_len = current.0.len() + current.1.len();
                candidate_len < current_len
                    || (candidate_len == current_len
                        && (&equality_reasons, &disequality_reasons) < (&current.0, &current.1))
            });
            if replace {
                best = Some((equality_reasons, disequality_reasons));
            }
        }
        best.ok_or_else(|| {
            WorkFailure::Error(CongruenceError::InvariantViolation(
                "no disequality witness aligns with the conflicting classes",
            ))
        })
    }

    fn checked_single_reason(&self, reason: ReasonId) -> Result<Vec<ReasonId>, WorkFailure> {
        if self.limits.max_antecedent_reasons < 1 {
            return Err(WorkFailure::Abstained(Abstention::CapExceeded {
                resource: CappedResource::AntecedentReasons,
                attempted: 1,
                limit: self.limits.max_antecedent_reasons,
            }));
        }
        let mut reasons = Vec::new();
        reasons
            .try_reserve_exact(1)
            .map_err(|_| WorkFailure::Error(CongruenceError::AllocationFailed))?;
        reasons.push(reason);
        Ok(reasons)
    }
}

fn snapshot_shape(snapshot: IncrementalCongruenceSnapshot) -> StateShape {
    StateShape {
        partition_depth: snapshot.partition.depth(),
        signature_depth: snapshot.signatures.depth(),
        proof_depth: snapshot.proof_depth,
    }
}

fn invalid_snapshot(reason: SnapshotError) -> CongruenceError {
    CongruenceError::Partition(PartitionError::InvalidSnapshot(reason))
}

fn derived_signature_limits(limits: CongruenceLimits) -> SignatureLimits {
    SignatureLimits {
        max_terms: limits.max_terms,
        max_argument_cells: limits.max_total_arguments,
        max_updates: limits.max_application_pair_checks,
        max_bucket_work: limits.max_application_pair_checks,
    }
}

fn changed_representatives_for_merge(
    partition: &Partition,
    left: TermId,
    right: TermId,
) -> Result<BTreeSet<TermId>, PartitionError> {
    let left_representative = partition.canonical_representative(left)?;
    let right_representative = partition.canonical_representative(right)?;
    if left_representative == right_representative {
        return Ok(BTreeSet::new());
    }
    let changed_class = if left_representative > right_representative {
        left
    } else {
        right
    };
    partition
        .class_members(changed_class)
        .map(|members| members.into_iter().collect())
}

fn construction_signature_error(error: SignatureError) -> CongruenceError {
    match signature_work_failure(error) {
        WorkFailure::Abstained(reason) => CongruenceError::ConstructionAbstained(reason),
        WorkFailure::Error(error) => error,
    }
}

fn signature_work_failure(error: SignatureError) -> WorkFailure {
    match error {
        SignatureError::CapExceeded {
            resource,
            attempted,
            limit,
        } => WorkFailure::Abstained(Abstention::CapExceeded {
            resource: congruence_resource(resource),
            attempted,
            limit,
        }),
        SignatureError::ArithmeticOverflow { resource } => {
            WorkFailure::Abstained(Abstention::ArithmeticOverflow {
                resource: congruence_resource(resource),
            })
        }
        error => WorkFailure::Error(signature_internal_error(error)),
    }
}

fn congruence_resource(resource: SignatureResource) -> CappedResource {
    match resource {
        SignatureResource::Terms => CappedResource::Terms,
        SignatureResource::ArgumentCells => CappedResource::TotalArguments,
        SignatureResource::Updates | SignatureResource::BucketWork => {
            CappedResource::ApplicationPairChecks
        }
    }
}

fn signature_internal_error(error: SignatureError) -> CongruenceError {
    match error {
        SignatureError::TooManyTerms { requested, .. } => CongruenceError::TermIdSpaceExceeded {
            term_count: requested,
        },
        SignatureError::InvalidArgument {
            application,
            argument,
            term_count,
        } => CongruenceError::InvalidArgument {
            term: application,
            argument,
            term_count,
        },
        SignatureError::AllocationFailed { .. } => CongruenceError::AllocationFailed,
        SignatureError::Partition(error) => CongruenceError::Partition(error),
        SignatureError::CapExceeded { .. } | SignatureError::ArithmeticOverflow { .. } => {
            CongruenceError::InvariantViolation(
                "signature cap escaped incremental semantic-work handling",
            )
        }
        SignatureError::InvalidChangedTerm { .. } => CongruenceError::InvariantViolation(
            "incremental engine produced an invalid changed representative",
        ),
        SignatureError::InvalidApplication { .. } => CongruenceError::InvariantViolation(
            "incremental collision referenced an invalid application",
        ),
        SignatureError::PartitionTermCountMismatch { .. } => CongruenceError::InvariantViolation(
            "incremental partition and signature term counts diverged",
        ),
        SignatureError::InvalidSnapshot(_) => CongruenceError::InvariantViolation(
            "incremental composite snapshot failed signature lineage validation",
        ),
        SignatureError::IndexIdExhausted => {
            CongruenceError::InvariantViolation("signature index ID space exhausted")
        }
        SignatureError::StateIdExhausted => {
            CongruenceError::InvariantViolation("signature state ID space exhausted")
        }
        SignatureError::InvariantViolation(_) => {
            CongruenceError::InvariantViolation("signature index invariant violation")
        }
    }
}

fn validate_universe(
    terms: &[SemanticTerm],
    limits: CongruenceLimits,
) -> Result<(), CongruenceError> {
    if terms.len() > limits.max_terms {
        return Err(CongruenceError::ConstructionAbstained(
            Abstention::CapExceeded {
                resource: CappedResource::Terms,
                attempted: terms.len(),
                limit: limits.max_terms,
            },
        ));
    }
    if u64::try_from(terms.len()).map_or(true, |count| count > MAX_TERMS) {
        return Err(CongruenceError::TermIdSpaceExceeded {
            term_count: terms.len(),
        });
    }

    let mut total_arguments = 0usize;
    for (index, term) in terms.iter().enumerate() {
        total_arguments = total_arguments.checked_add(term.arguments.len()).ok_or(
            CongruenceError::ConstructionAbstained(Abstention::ArithmeticOverflow {
                resource: CappedResource::TotalArguments,
            }),
        )?;
        if total_arguments > limits.max_total_arguments {
            return Err(CongruenceError::ConstructionAbstained(
                Abstention::CapExceeded {
                    resource: CappedResource::TotalArguments,
                    attempted: total_arguments,
                    limit: limits.max_total_arguments,
                },
            ));
        }
        let id = term_id(index)?;
        for &argument in term.arguments.iter() {
            if argument.index() >= terms.len() {
                return Err(CongruenceError::InvalidArgument {
                    term: id,
                    argument,
                    term_count: terms.len(),
                });
            }
        }
    }

    let mut shapes = BTreeMap::<u32, FunctionShape>::new();
    for (index, term) in terms.iter().enumerate() {
        let id = term_id(index)?;
        let mut argument_sorts = Vec::new();
        argument_sorts
            .try_reserve_exact(term.arguments.len())
            .map_err(|_| CongruenceError::AllocationFailed)?;
        argument_sorts.extend(
            term.arguments
                .iter()
                .map(|argument| terms[argument.index()].sort),
        );
        if let Some(first) = shapes.get(&term.function) {
            if first.result_sort != term.sort || first.argument_sorts != argument_sorts {
                return Err(CongruenceError::InconsistentFunctionSignature {
                    function: term.function,
                    first_term: first.first_term,
                    conflicting_term: id,
                });
            }
        } else {
            shapes.insert(
                term.function,
                FunctionShape {
                    first_term: id,
                    result_sort: term.sort,
                    argument_sorts,
                },
            );
        }
    }
    Ok(())
}

fn same_application_head(left: &SemanticTerm, right: &SemanticTerm) -> bool {
    left.function == right.function
        && left.sort == right.sort
        && left.arguments.len() == right.arguments.len()
}

fn term_id(index: usize) -> Result<TermId, CongruenceError> {
    TermId::try_from(index).map_err(|_| CongruenceError::TermIdSpaceExceeded {
        term_count: index.saturating_add(1),
    })
}

fn spend(used: &mut usize, resource: CappedResource, limit: usize) -> Result<(), Abstention> {
    let attempted = used
        .checked_add(1)
        .ok_or(Abstention::ArithmeticOverflow { resource })?;
    if attempted > limit {
        return Err(Abstention::CapExceeded {
            resource,
            attempted,
            limit,
        });
    }
    *used = attempted;
    Ok(())
}

fn check_reason_cap(attempted: usize, limit: usize) -> Result<(), Abstention> {
    if attempted > limit {
        Err(Abstention::CapExceeded {
            resource: CappedResource::AntecedentReasons,
            attempted,
            limit,
        })
    } else {
        Ok(())
    }
}

fn canonicalize_reasons(reasons: &mut Vec<ReasonId>) {
    reasons.sort_unstable();
    reasons.dedup();
}

fn normalized_pair(left: TermId, right: TermId) -> (TermId, TermId) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

#[cfg(test)]
mod tests {
    use super::super::congruence::RollbackCongruence;
    use super::*;

    fn id(raw: usize) -> TermId {
        TermId::new(raw as u32)
    }

    fn reason(raw: u64) -> ReasonId {
        ReasonId::new(raw)
    }

    fn semantic(function: u32, sort: u32, arguments: &[usize]) -> SemanticTerm {
        SemanticTerm {
            function,
            sort,
            arguments: arguments
                .iter()
                .copied()
                .map(id)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    fn nested_terms() -> Vec<SemanticTerm> {
        vec![
            semantic(1, 1, &[]),
            semantic(2, 1, &[]),
            semantic(3, 1, &[]),
            semantic(10, 1, &[0]),
            semantic(10, 1, &[1]),
            semantic(10, 1, &[2]),
            semantic(11, 1, &[3]),
            semantic(11, 1, &[4]),
        ]
    }

    fn assert_outcomes_match(incremental: &ApplyOutcome, oracle: &ApplyOutcome, context: &str) {
        match (incremental, oracle) {
            (ApplyOutcome::Applied(left), ApplyOutcome::Applied(right)) => {
                assert_eq!(left.explicit_update, right.explicit_update, "{context}");
                assert_eq!(left.congruence_merges, right.congruence_merges, "{context}");
            }
            (ApplyOutcome::Conflict(left), ApplyOutcome::Conflict(right)) => {
                assert_eq!(
                    std::mem::discriminant(&left.origin),
                    std::mem::discriminant(&right.origin),
                    "{context}"
                );
                assert_eq!(left.equality_reasons, right.equality_reasons, "{context}");
                assert_eq!(
                    left.disequality_reasons, right.disequality_reasons,
                    "{context}"
                );
                assert_eq!(
                    left.explicit_antecedents(),
                    right.explicit_antecedents(),
                    "{context}"
                );
            }
            (ApplyOutcome::Abstained(left), ApplyOutcome::Abstained(right)) => {
                assert_eq!(left, right, "{context}");
            }
            _ => panic!(
                "outcome mismatch at {context}: incremental={incremental:?}, oracle={oracle:?}"
            ),
        }
    }

    fn assert_relations_match(
        incremental: &RollbackIncrementalCongruence<'_>,
        oracle: &RollbackCongruence<'_>,
        context: &str,
    ) {
        assert_eq!(incremental.term_count(), oracle.term_count());
        for left in 0..incremental.term_count() {
            for right in 0..incremental.term_count() {
                assert_eq!(
                    incremental.relation(id(left), id(right)).unwrap(),
                    oracle.relation(id(left), id(right)).unwrap(),
                    "relation mismatch at {context} for {left},{right}"
                );
            }
        }
    }

    #[test]
    fn construction_saturates_nullary_and_nested_application_collisions() {
        let terms = vec![
            semantic(1, 1, &[]),
            semantic(1, 1, &[]),
            semantic(10, 1, &[0]),
            semantic(10, 1, &[1]),
            semantic(11, 1, &[2]),
            semantic(11, 1, &[3]),
        ];
        let incremental = RollbackIncrementalCongruence::new(&terms).unwrap();
        let oracle = RollbackCongruence::new(&terms).unwrap();

        assert_relations_match(&incremental, &oracle, "construction");
        assert!(incremental.are_equal(id(0), id(1)).unwrap());
        assert!(incremental.are_equal(id(2), id(3)).unwrap());
        assert!(incremental.are_equal(id(4), id(5)).unwrap());
        assert_eq!(incremental.equality_merges(), oracle.equality_merges());
        assert!(incremental.congruence_merges().all(|merge| matches!(
            &merge.cause,
            EqualityCause::Congruence {
                antecedent_reasons,
                ..
            } if antecedent_reasons.is_empty()
        )));
        incremental.validate().unwrap();
    }

    #[test]
    fn deferred_post_construction_validation_preserves_checked_construction() {
        let terms = nested_terms();
        let audited = RollbackIncrementalCongruence::with_limits_and_post_validation(
            &terms,
            CongruenceLimits::default(),
            true,
        )
        .unwrap();
        let deferred = RollbackIncrementalCongruence::with_limits_and_post_validation(
            &terms,
            CongruenceLimits::default(),
            false,
        )
        .unwrap();
        deferred.validate().unwrap();
        assert_eq!(deferred.equality_merges(), audited.equality_merges());
        assert_eq!(
            deferred.signature_telemetry(),
            audited.signature_telemetry()
        );
        assert_eq!(
            deferred
                .construction_timings()
                .post_construction_validation_ns,
            0
        );

        let malformed = vec![semantic(1, 1, &[1])];
        for validate in [false, true] {
            assert!(matches!(
                RollbackIncrementalCongruence::with_limits_and_post_validation(
                    &malformed,
                    CongruenceLimits::default(),
                    validate,
                ),
                Err(CongruenceError::InvalidArgument { .. })
            ));
        }
    }

    #[test]
    fn historical_explanations_exclude_future_merge_edges() {
        let terms = vec![
            semantic(1, 1, &[]),
            semantic(2, 1, &[]),
            semantic(3, 1, &[]),
        ];
        let mut engine = RollbackIncrementalCongruence::new(&terms).unwrap();
        engine.assert_equality(id(0), id(1), reason(11)).unwrap();
        let after_first = engine.snapshot();
        engine.assert_equality(id(1), id(2), reason(12)).unwrap();

        assert_eq!(
            engine.explain_equal(id(0), id(2)).unwrap(),
            ExplanationOutcome::Explained(vec![reason(11), reason(12)])
        );
        assert_eq!(
            engine.explain_equal_at(id(0), id(1), after_first).unwrap(),
            ExplanationOutcome::Explained(vec![reason(11)])
        );
        assert_eq!(
            engine.explain_equal_at(id(0), id(2), after_first).unwrap(),
            ExplanationOutcome::NotEqual
        );
    }

    #[test]
    fn historical_explanations_reject_discarded_branches() {
        let terms = vec![
            semantic(1, 1, &[]),
            semantic(2, 1, &[]),
            semantic(3, 1, &[]),
        ];
        let mut engine = RollbackIncrementalCongruence::new(&terms).unwrap();
        engine.assert_equality(id(0), id(1), reason(21)).unwrap();
        let ancestor = engine.snapshot();
        engine.assert_equality(id(1), id(2), reason(22)).unwrap();
        let discarded = engine.snapshot();
        engine.rollback(ancestor).unwrap();
        engine.assert_equality(id(0), id(2), reason(23)).unwrap();

        assert!(matches!(
            engine.explain_equal_at(id(0), id(2), discarded),
            Err(CongruenceError::Partition(PartitionError::InvalidSnapshot(
                SnapshotError::DiscardedBranch
            )))
        ));
    }

    #[test]
    fn explicit_conflict_includes_disequality_endpoint_alignment() {
        let terms = vec![
            semantic(1, 1, &[]),
            semantic(2, 1, &[]),
            semantic(3, 1, &[]),
        ];
        let mut engine = RollbackIncrementalCongruence::new(&terms).unwrap();
        engine.assert_disequality(id(0), id(1), reason(31)).unwrap();
        engine.assert_equality(id(1), id(2), reason(32)).unwrap();

        let conflict = engine.assert_equality(id(0), id(2), reason(33)).unwrap();
        let ApplyOutcome::Conflict(conflict) = conflict else {
            panic!("expected aligned equality conflict, got {conflict:?}");
        };
        assert_eq!(conflict.equality_reasons, vec![reason(32), reason(33)]);
        assert_eq!(conflict.disequality_reasons, vec![reason(31)]);
    }

    #[test]
    fn nested_conflict_has_stable_explicit_antecedents_and_is_transactional() {
        let terms = nested_terms();
        let mut incremental = RollbackIncrementalCongruence::new(&terms).unwrap();
        let mut oracle = RollbackCongruence::new(&terms).unwrap();

        let incremental_disequality = incremental
            .assert_disequality(id(6), id(7), reason(20))
            .unwrap();
        let oracle_disequality = oracle.assert_disequality(id(6), id(7), reason(20)).unwrap();
        assert_outcomes_match(
            &incremental_disequality,
            &oracle_disequality,
            "nested disequality",
        );
        let before = incremental.snapshot();
        let before_telemetry = incremental.signature_telemetry();

        let incremental_outcome = incremental
            .assert_equality(id(0), id(1), reason(10))
            .unwrap();
        let oracle_outcome = oracle.assert_equality(id(0), id(1), reason(10)).unwrap();
        assert_outcomes_match(&incremental_outcome, &oracle_outcome, "nested conflict");
        let ApplyOutcome::Conflict(conflict) = incremental_outcome else {
            panic!("expected a nested congruence conflict");
        };
        assert_eq!(
            conflict.origin,
            ConflictOrigin::Congruence {
                left_application: id(6),
                right_application: id(7),
                argument_pairs: vec![(id(3), id(4))],
            }
        );
        assert_eq!(conflict.equality_reasons, vec![reason(10)]);
        assert_eq!(conflict.disequality_reasons, vec![reason(20)]);
        assert_eq!(
            conflict.explicit_antecedents(),
            vec![reason(10), reason(20)]
        );
        assert_eq!(incremental.snapshot(), before);
        assert_eq!(incremental.signature_telemetry(), before_telemetry);
        assert_relations_match(&incremental, &oracle, "after nested conflict");
        incremental.validate().unwrap();
    }

    #[test]
    fn changed_representative_frontier_is_exact_for_whole_classes() {
        let mut partition = Partition::new(6).unwrap();
        partition.merge(id(0), id(3), reason(1)).unwrap();
        partition.merge(id(3), id(4), reason(2)).unwrap();
        partition.merge(id(1), id(2), reason(3)).unwrap();
        let before = (0..6)
            .map(|term| partition.canonical_representative(id(term)).unwrap())
            .collect::<Vec<_>>();

        let predicted = changed_representatives_for_merge(&partition, id(4), id(2)).unwrap();
        assert_eq!(predicted, BTreeSet::from([id(1), id(2)]));
        partition.merge(id(4), id(2), reason(4)).unwrap();
        let actual = (0..6)
            .filter(|&term| partition.canonical_representative(id(term)).unwrap() != before[term])
            .map(id)
            .collect::<BTreeSet<_>>();
        assert_eq!(predicted, actual);
    }

    #[test]
    fn exhaustive_four_term_decisions_match_full_scan_oracle() {
        let terms = vec![
            semantic(1, 1, &[]),
            semantic(2, 1, &[]),
            semantic(10, 1, &[0]),
            semantic(10, 1, &[1]),
        ];
        let pairs = [(0usize, 1usize), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];
        let state_count = 3usize.pow(pairs.len() as u32);
        assert_eq!(state_count, 729);

        for encoded in 0..state_count {
            let mut choices = encoded;
            let mut incremental = RollbackIncrementalCongruence::new(&terms).unwrap();
            let mut oracle = RollbackCongruence::new(&terms).unwrap();
            for (pair_index, &(left, right)) in pairs.iter().enumerate() {
                let choice = choices % 3;
                choices /= 3;
                if choice != 0 {
                    let why = reason((encoded * pairs.len() + pair_index + 1) as u64);
                    let (incremental_outcome, oracle_outcome) = if choice == 1 {
                        (
                            incremental
                                .assert_equality(id(left), id(right), why)
                                .unwrap(),
                            oracle.assert_equality(id(left), id(right), why).unwrap(),
                        )
                    } else {
                        (
                            incremental
                                .assert_disequality(id(left), id(right), why)
                                .unwrap(),
                            oracle.assert_disequality(id(left), id(right), why).unwrap(),
                        )
                    };
                    assert_outcomes_match(
                        &incremental_outcome,
                        &oracle_outcome,
                        &format!("encoded={encoded} pair={pair_index}"),
                    );
                }
                assert_relations_match(
                    &incremental,
                    &oracle,
                    &format!("encoded={encoded} after={pair_index}"),
                );
                incremental.validate().unwrap();
            }
        }
    }

    #[derive(Clone, Copy)]
    struct PairedSnapshot {
        incremental: IncrementalCongruenceSnapshot,
        oracle: super::super::congruence::CongruenceSnapshot,
    }

    fn next_random(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state
    }

    #[test]
    fn randomized_nested_decisions_and_rollbacks_match_full_scan_oracle() {
        let mut terms = (0..5)
            .map(|function| semantic(function, 1, &[]))
            .collect::<Vec<_>>();
        for argument in 0..5 {
            terms.push(semantic(20, 1, &[argument]));
        }
        for argument in 5..10 {
            terms.push(semantic(21, 1, &[argument]));
        }
        terms.extend([
            semantic(30, 1, &[0, 1]),
            semantic(30, 1, &[2, 3]),
            semantic(30, 1, &[1, 4]),
        ]);

        for seed in 0..6u64 {
            let mut incremental = RollbackIncrementalCongruence::new(&terms).unwrap();
            let mut oracle = RollbackCongruence::new(&terms).unwrap();
            let mut checkpoints = vec![PairedSnapshot {
                incremental: incremental.snapshot(),
                oracle: oracle.snapshot(),
            }];
            let mut random = 0xa076_1d64_78bd_642fu64 ^ seed.wrapping_mul(0x9e37_79b9);

            for step in 0..240usize {
                if checkpoints.len() > 1 && next_random(&mut random) % 6 == 0 {
                    let selected = (next_random(&mut random) as usize) % checkpoints.len();
                    let checkpoint = checkpoints[selected];
                    incremental.rollback(checkpoint.incremental).unwrap();
                    oracle.rollback(checkpoint.oracle).unwrap();
                    checkpoints.truncate(selected + 1);
                } else {
                    let left = (next_random(&mut random) as usize) % terms.len();
                    let right = (next_random(&mut random) as usize) % terms.len();
                    let equality = next_random(&mut random) & 1 == 0;
                    let why = reason(1 + seed * 1_000 + step as u64);
                    let (incremental_outcome, oracle_outcome) = if equality {
                        (
                            incremental.assert_equal(id(left), id(right), why).unwrap(),
                            oracle.assert_equal(id(left), id(right), why).unwrap(),
                        )
                    } else {
                        (
                            incremental
                                .assert_disequal(id(left), id(right), why)
                                .unwrap(),
                            oracle.assert_disequal(id(left), id(right), why).unwrap(),
                        )
                    };
                    assert_outcomes_match(
                        &incremental_outcome,
                        &oracle_outcome,
                        &format!("seed={seed} step={step}"),
                    );
                    if step % 11 == 0 {
                        checkpoints.push(PairedSnapshot {
                            incremental: incremental.snapshot(),
                            oracle: oracle.snapshot(),
                        });
                    }
                }
                assert_relations_match(&incremental, &oracle, &format!("seed={seed} step={step}"));
                if step % 17 == 0 {
                    incremental.validate().unwrap();
                    oracle.validate().unwrap();
                }
            }
        }
    }

    #[test]
    fn shared_semantic_caps_match_oracle_and_restore_every_layer() {
        let terms = vec![
            semantic(1, 1, &[]),
            semantic(2, 1, &[]),
            semantic(10, 1, &[0]),
            semantic(10, 1, &[1]),
        ];

        for limits in [
            CongruenceLimits {
                max_partition_updates: 1,
                ..CongruenceLimits::default()
            },
            CongruenceLimits {
                max_congruence_merges: 0,
                ..CongruenceLimits::default()
            },
            CongruenceLimits {
                max_antecedent_reasons: 0,
                ..CongruenceLimits::default()
            },
        ] {
            let mut incremental =
                RollbackIncrementalCongruence::with_limits(&terms, limits).unwrap();
            let mut oracle = RollbackCongruence::with_limits(&terms, limits).unwrap();
            let root = incremental.snapshot();
            let telemetry = incremental.signature_telemetry();
            let incremental_outcome = incremental.assert_equal(id(0), id(1), reason(1)).unwrap();
            let oracle_outcome = oracle.assert_equal(id(0), id(1), reason(1)).unwrap();
            assert_outcomes_match(&incremental_outcome, &oracle_outcome, "shared cap");
            assert!(matches!(incremental_outcome, ApplyOutcome::Abstained(_)));
            assert_eq!(incremental.snapshot(), root);
            assert_eq!(incremental.signature_telemetry(), telemetry);
            assert_relations_match(&incremental, &oracle, "shared cap rollback");
            incremental.validate().unwrap();
        }
    }

    #[test]
    fn collision_and_signature_caps_abstain_with_exact_rollback() {
        let terms = vec![
            semantic(1, 1, &[]),
            semantic(2, 1, &[]),
            semantic(10, 1, &[0]),
            semantic(10, 1, &[1]),
        ];

        let collision_limits = CongruenceLimits {
            max_application_pair_checks: 0,
            ..CongruenceLimits::default()
        };
        let mut collision_engine = RollbackIncrementalCongruence::with_signature_limits(
            &terms,
            collision_limits,
            SignatureLimits::default(),
        )
        .unwrap();
        let root = collision_engine.snapshot();
        let telemetry = collision_engine.signature_telemetry();
        assert_eq!(
            collision_engine
                .assert_equal(id(0), id(1), reason(1))
                .unwrap(),
            ApplyOutcome::Abstained(Abstention::CapExceeded {
                resource: CappedResource::ApplicationPairChecks,
                attempted: 1,
                limit: 0,
            })
        );
        assert_eq!(collision_engine.snapshot(), root);
        assert_eq!(collision_engine.signature_telemetry(), telemetry);
        collision_engine.validate().unwrap();

        let signature_limits = SignatureLimits {
            max_updates: 0,
            ..SignatureLimits::default()
        };
        let mut signature_engine = RollbackIncrementalCongruence::with_signature_limits(
            &terms,
            CongruenceLimits::default(),
            signature_limits,
        )
        .unwrap();
        let root = signature_engine.snapshot();
        let telemetry = signature_engine.signature_telemetry();
        assert_eq!(
            signature_engine
                .assert_equal(id(0), id(1), reason(2))
                .unwrap(),
            ApplyOutcome::Abstained(Abstention::CapExceeded {
                resource: CappedResource::ApplicationPairChecks,
                attempted: 1,
                limit: 0,
            })
        );
        assert_eq!(signature_engine.snapshot(), root);
        assert_eq!(signature_engine.signature_telemetry(), telemetry);
        signature_engine.validate().unwrap();
    }

    #[test]
    fn composite_rollback_restores_closure_and_rejects_bad_lineages() {
        let terms = nested_terms();
        let mut engine = RollbackIncrementalCongruence::new(&terms).unwrap();
        let root = engine.checkpoint();
        let root_telemetry = engine.signature_telemetry();
        let outcome = engine.assert_equal(id(0), id(1), reason(1)).unwrap();
        assert!(matches!(outcome, ApplyOutcome::Applied(_)));
        assert!(engine.are_equal(id(6), id(7)).unwrap());
        let rollback = engine.rollback_to(root).unwrap();
        assert_eq!(rollback.partition_updates, 3);
        assert_eq!(rollback.equality_merges, 3);
        assert_eq!(engine.signature_telemetry(), root_telemetry);
        assert!(!engine.are_equal(id(0), id(1)).unwrap());
        assert!(!engine.are_equal(id(6), id(7)).unwrap());

        let second = RollbackIncrementalCongruence::new(&terms).unwrap();
        assert_eq!(
            engine.rollback(second.snapshot()),
            Err(CongruenceError::Partition(PartitionError::InvalidSnapshot(
                SnapshotError::ForeignPartition
            )))
        );

        let root = engine.snapshot();
        engine.assert_equal(id(0), id(1), reason(10)).unwrap();
        let discarded = engine.snapshot();
        engine.rollback(root).unwrap();
        engine.assert_equal(id(0), id(2), reason(11)).unwrap();
        let replacement = engine.snapshot();
        assert_eq!(
            discarded.transaction_depth(),
            replacement.transaction_depth()
        );
        assert_eq!(
            engine.rollback(discarded),
            Err(CongruenceError::Partition(PartitionError::InvalidSnapshot(
                SnapshotError::DiscardedBranch
            )))
        );
        assert_eq!(engine.snapshot(), replacement);
        assert!(engine.are_equal(id(0), id(2)).unwrap());
        engine.validate().unwrap();
    }
}
