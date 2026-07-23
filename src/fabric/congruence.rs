#![forbid(unsafe_code)]

//! Correctness-first rollback congruence closure for Fabric E1.
//!
//! The reference implementation deliberately performs deterministic full
//! scans.  Every public decision is transactional: explicit and derived
//! partition updates are rolled back together when closure finds a conflict,
//! reaches a resource cap, or encounters an error.  Successful equality
//! merges have a parallel proof record whose cause is either one explicit
//! [`ReasonId`] or a congruence step with all of its explicit antecedents.

use super::partition::{
    Conflict as PartitionConflict, MAX_TERMS, MergeOutcome, Partition, PartitionError, ReasonId,
    Relation, SeparationOutcome, SeparationRecord, Snapshot as PartitionSnapshot, TermId,
};
use super::semantic::SemanticTerm;
use std::collections::{BTreeMap, VecDeque};
use std::error::Error;
use std::fmt;

/// Marker stored in [`Partition`] for a merge justified by congruence.
///
/// The real causal reasons are retained in [`EqualityCause::Congruence`].
/// Explicit decisions using this value are rejected so raw partition records
/// cannot confuse a derived marker with an explicit antecedent.
pub(crate) const CONGRUENCE_PARTITION_REASON: ReasonId = ReasonId::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CongruenceLimits {
    pub(crate) max_terms: usize,
    pub(crate) max_total_arguments: usize,
    pub(crate) max_partition_updates: usize,
    pub(crate) max_saturation_passes: usize,
    pub(crate) max_application_pair_checks: usize,
    pub(crate) max_congruence_merges: usize,
    pub(crate) max_explanation_edge_visits: usize,
    pub(crate) max_antecedent_reasons: usize,
}

impl Default for CongruenceLimits {
    fn default() -> Self {
        Self {
            max_terms: 1_000_000,
            max_total_arguments: 4_000_000,
            max_partition_updates: 1_000_000,
            max_saturation_passes: 1_000_001,
            max_application_pair_checks: 100_000_000,
            max_congruence_merges: 1_000_000,
            max_explanation_edge_visits: 1_000_000,
            max_antecedent_reasons: 4_096,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CappedResource {
    Terms,
    TotalArguments,
    PartitionUpdates,
    SaturationPasses,
    ApplicationPairChecks,
    CongruenceMerges,
    ExplanationEdgeVisits,
    AntecedentReasons,
}

impl fmt::Display for CappedResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Terms => "terms",
            Self::TotalArguments => "total arguments",
            Self::PartitionUpdates => "partition updates",
            Self::SaturationPasses => "saturation passes",
            Self::ApplicationPairChecks => "application pair checks",
            Self::CongruenceMerges => "congruence merges",
            Self::ExplanationEdgeVisits => "explanation edge visits",
            Self::AntecedentReasons => "antecedent reasons",
        };
        output.write_str(name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Abstention {
    CapExceeded {
        resource: CappedResource,
        attempted: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        resource: CappedResource,
    },
}

impl fmt::Display for Abstention {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapExceeded {
                resource,
                attempted,
                limit,
            } => write!(
                output,
                "congruence {resource} cap exceeded: attempted {attempted}, limit {limit}"
            ),
            Self::ArithmeticOverflow { resource } => {
                write!(output, "congruence {resource} accounting overflowed")
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CongruenceError {
    ConstructionAbstained(Abstention),
    TermIdSpaceExceeded {
        term_count: usize,
    },
    InvalidArgument {
        term: TermId,
        argument: TermId,
        term_count: usize,
    },
    InconsistentFunctionSignature {
        function: u32,
        first_term: TermId,
        conflicting_term: TermId,
    },
    InvalidTerm {
        term: TermId,
        term_count: usize,
    },
    SortMismatch {
        left: TermId,
        left_sort: u32,
        right: TermId,
        right_sort: u32,
    },
    ReservedReason(ReasonId),
    AllocationFailed,
    Partition(PartitionError),
    TransactionRollbackFailed(PartitionError),
    InvariantViolation(&'static str),
}

impl fmt::Display for CongruenceError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConstructionAbstained(reason) => {
                write!(output, "congruence construction abstained: {reason}")
            }
            Self::TermIdSpaceExceeded { term_count } => {
                write!(output, "{term_count} semantic terms do not fit in TermId")
            }
            Self::InvalidArgument {
                term,
                argument,
                term_count,
            } => write!(
                output,
                "semantic term {term} references argument {argument} outside 0..{term_count}"
            ),
            Self::InconsistentFunctionSignature {
                function,
                first_term,
                conflicting_term,
            } => write!(
                output,
                "function {function} has inconsistent signatures at terms {first_term} and {conflicting_term}"
            ),
            Self::InvalidTerm { term, term_count } => {
                write!(output, "term {term} is outside 0..{term_count}")
            }
            Self::SortMismatch {
                left,
                left_sort,
                right,
                right_sort,
            } => write!(
                output,
                "cannot compare term {left} of sort {left_sort} with term {right} of sort {right_sort}"
            ),
            Self::ReservedReason(reason) => write!(
                output,
                "explicit reason {reason} is reserved for derived congruence merges"
            ),
            Self::AllocationFailed => output.write_str("congruence allocation failed"),
            Self::Partition(error) => error.fmt(output),
            Self::TransactionRollbackFailed(error) => {
                write!(output, "congruence transaction rollback failed: {error}")
            }
            Self::InvariantViolation(message) => {
                write!(output, "congruence invariant violation: {message}")
            }
        }
    }
}

impl Error for CongruenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Partition(error) | Self::TransactionRollbackFailed(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PartitionError> for CongruenceError {
    fn from(error: PartitionError) -> Self {
        Self::Partition(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    Equality {
        left: TermId,
        right: TermId,
        reason: ReasonId,
    },
    Disequality {
        left: TermId,
        right: TermId,
        reason: ReasonId,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ApplyStats {
    pub(crate) explicit_update: bool,
    pub(crate) congruence_merges: usize,
    pub(crate) saturation_passes: usize,
    pub(crate) application_pair_checks: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ConflictOrigin {
    ExplicitEquality {
        left: TermId,
        right: TermId,
        reason: ReasonId,
    },
    ExplicitDisequality {
        left: TermId,
        right: TermId,
        reason: ReasonId,
    },
    Congruence {
        left_application: TermId,
        right_application: TermId,
        argument_pairs: Vec<(TermId, TermId)>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CongruenceConflict {
    pub(crate) origin: ConflictOrigin,
    /// Explicit equality decisions sufficient for the equality side.
    pub(crate) equality_reasons: Vec<ReasonId>,
    /// Explicit disequality decisions witnessing the disequality side.
    pub(crate) disequality_reasons: Vec<ReasonId>,
}

impl CongruenceConflict {
    pub(crate) fn explicit_antecedents(&self) -> Vec<ReasonId> {
        let mut reasons = Vec::with_capacity(
            self.equality_reasons
                .len()
                .saturating_add(self.disequality_reasons.len()),
        );
        reasons.extend_from_slice(&self.equality_reasons);
        reasons.extend_from_slice(&self.disequality_reasons);
        canonicalize_reasons(&mut reasons);
        reasons
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ApplyOutcome {
    Applied(ApplyStats),
    Conflict(CongruenceConflict),
    Abstained(Abstention),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EqualityCause {
    Explicit {
        reason: ReasonId,
    },
    Congruence {
        argument_pairs: Vec<(TermId, TermId)>,
        antecedent_reasons: Vec<ReasonId>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EqualityMerge {
    pub(crate) left: TermId,
    pub(crate) right: TermId,
    pub(crate) cause: EqualityCause,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CongruenceSnapshot {
    partition: PartitionSnapshot,
    merge_len: usize,
}

impl CongruenceSnapshot {
    pub(crate) const fn depth(self) -> usize {
        self.partition.depth()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RollbackStats {
    pub(crate) partition_updates: usize,
    pub(crate) equality_merges: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ExplanationOutcome {
    NotEqual,
    Explained(Vec<ReasonId>),
    Abstained(Abstention),
}

#[derive(Debug)]
pub(crate) struct RollbackCongruence<'terms> {
    terms: &'terms [SemanticTerm],
    limits: CongruenceLimits,
    partition: Partition,
    merges: Vec<EqualityMerge>,
}

pub(crate) type CongruenceEngine<'terms> = RollbackCongruence<'terms>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct FunctionShape {
    first_term: TermId,
    result_sort: u32,
    argument_sorts: Vec<u32>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SaturationStats {
    merges: usize,
    passes: usize,
    pair_checks: usize,
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

impl<'terms> RollbackCongruence<'terms> {
    pub(crate) fn new(terms: &'terms [SemanticTerm]) -> Result<Self, CongruenceError> {
        Self::with_limits(terms, CongruenceLimits::default())
    }

    pub(crate) fn with_limits(
        terms: &'terms [SemanticTerm],
        limits: CongruenceLimits,
    ) -> Result<Self, CongruenceError> {
        validate_universe(terms, limits)?;
        let partition = Partition::new(terms.len())?;
        let mut engine = Self {
            terms,
            limits,
            partition,
            merges: Vec::new(),
        };
        match engine.saturate() {
            Ok(_) => {
                engine.validate()?;
                Ok(engine)
            }
            Err(SaturationFailure::Abstained(reason)) => {
                Err(CongruenceError::ConstructionAbstained(reason))
            }
            Err(SaturationFailure::Conflict(_)) => Err(CongruenceError::InvariantViolation(
                "identity partition produced a congruence conflict",
            )),
            Err(SaturationFailure::Error(error)) => Err(error),
        }
    }

    pub(crate) fn term_count(&self) -> usize {
        self.terms.len()
    }

    pub(crate) fn partition(&self) -> &Partition {
        &self.partition
    }

    pub(crate) fn equality_merges(&self) -> &[EqualityMerge] {
        &self.merges
    }

    pub(crate) fn congruence_merges(&self) -> impl Iterator<Item = &EqualityMerge> {
        self.merges
            .iter()
            .filter(|merge| matches!(merge.cause, EqualityCause::Congruence { .. }))
    }

    pub(crate) fn snapshot(&self) -> CongruenceSnapshot {
        CongruenceSnapshot {
            partition: self.partition.snapshot(),
            merge_len: self.merges.len(),
        }
    }

    pub(crate) fn checkpoint(&self) -> CongruenceSnapshot {
        self.snapshot()
    }

    pub(crate) fn rollback(
        &mut self,
        snapshot: CongruenceSnapshot,
    ) -> Result<RollbackStats, CongruenceError> {
        let before_merges = self.merges.len();
        let partition_updates = self.partition.rollback(snapshot.partition)?;
        if snapshot.merge_len > before_merges {
            return Err(CongruenceError::InvariantViolation(
                "snapshot proof depth exceeds current proof history",
            ));
        }
        self.merges.truncate(snapshot.merge_len);
        if self.partition.merge_count() != self.merges.len() {
            return Err(CongruenceError::InvariantViolation(
                "partition and congruence proof histories diverged after rollback",
            ));
        }
        Ok(RollbackStats {
            partition_updates,
            equality_merges: before_merges - snapshot.merge_len,
        })
    }

    pub(crate) fn rollback_to(
        &mut self,
        snapshot: CongruenceSnapshot,
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
        if matches!(self.partition.relation(left, right)?, Relation::Unknown) {
            if let Err(abstention) = self.check_partition_update_capacity() {
                return Ok(ApplyOutcome::Abstained(abstention));
            }
            self.reserve_merge_record()?;
        }

        match self.partition.merge(left, right, reason) {
            Ok(MergeOutcome::AlreadyEqual { .. }) => {
                return Ok(ApplyOutcome::Applied(ApplyStats::default()));
            }
            Ok(MergeOutcome::Merged { .. }) => {
                self.merges.push(EqualityMerge {
                    left,
                    right,
                    cause: EqualityCause::Explicit { reason },
                });
            }
            Err(PartitionError::Conflict(conflict)) => {
                return match self.explicit_equality_conflict(left, right, reason, conflict) {
                    Ok(converted) => {
                        self.restore_transaction(checkpoint)?;
                        Ok(ApplyOutcome::Conflict(converted))
                    }
                    Err(WorkFailure::Abstained(abstention)) => {
                        self.restore_transaction(checkpoint)?;
                        Ok(ApplyOutcome::Abstained(abstention))
                    }
                    Err(WorkFailure::Error(error)) => {
                        self.restore_transaction(checkpoint)?;
                        Err(error)
                    }
                };
            }
            Err(error) => {
                self.restore_transaction(checkpoint)?;
                return Err(CongruenceError::Partition(error));
            }
        }

        match self.saturate() {
            Ok(saturation) => Ok(ApplyOutcome::Applied(ApplyStats {
                explicit_update: true,
                congruence_merges: saturation.merges,
                saturation_passes: saturation.passes,
                application_pair_checks: saturation.pair_checks,
            })),
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
        if !matches!(prior_relation, Relation::Equal) && !duplicate {
            if let Err(abstention) = self.check_partition_update_capacity() {
                return Ok(ApplyOutcome::Abstained(abstention));
            }
        }

        match self.partition.separate(left, right, reason) {
            Ok(outcome) => Ok(ApplyOutcome::Applied(ApplyStats {
                explicit_update: matches!(outcome, SeparationOutcome::Added { .. }),
                ..ApplyStats::default()
            })),
            Err(PartitionError::Conflict(PartitionConflict::DisequalityAgainstEquality {
                ..
            })) => {
                let mut budget = ExplanationBudget::default();
                match self.explain_equal_internal(left, right, &mut budget) {
                    Ok(Some(equality_reasons)) => match self.checked_single_reason(reason) {
                        Ok(disequality_reasons) => {
                            let conflict = CongruenceConflict {
                                origin: ConflictOrigin::ExplicitDisequality {
                                    left,
                                    right,
                                    reason,
                                },
                                equality_reasons,
                                disequality_reasons,
                            };
                            self.restore_transaction(checkpoint)?;
                            Ok(ApplyOutcome::Conflict(conflict))
                        }
                        Err(WorkFailure::Abstained(abstention)) => {
                            self.restore_transaction(checkpoint)?;
                            Ok(ApplyOutcome::Abstained(abstention))
                        }
                        Err(WorkFailure::Error(error)) => {
                            self.restore_transaction(checkpoint)?;
                            Err(error)
                        }
                    },
                    Ok(None) => {
                        self.restore_transaction(checkpoint)?;
                        Err(CongruenceError::InvariantViolation(
                            "partition conflict has no equality proof",
                        ))
                    }
                    Err(WorkFailure::Abstained(abstention)) => {
                        self.restore_transaction(checkpoint)?;
                        Ok(ApplyOutcome::Abstained(abstention))
                    }
                    Err(WorkFailure::Error(error)) => {
                        self.restore_transaction(checkpoint)?;
                        Err(error)
                    }
                }
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

    pub(crate) fn validate(&self) -> Result<(), CongruenceError> {
        self.partition.validate()?;
        if self.partition.merge_count() != self.merges.len()
            || self.partition.merge_records().len() != self.merges.len()
        {
            return Err(CongruenceError::InvariantViolation(
                "partition merge count differs from congruence proof history",
            ));
        }

        for (partition_record, proof) in self.partition.merge_records().iter().zip(&self.merges) {
            if partition_record.left != proof.left || partition_record.right != proof.right {
                return Err(CongruenceError::InvariantViolation(
                    "partition merge endpoints differ from proof endpoints",
                ));
            }
            self.validate_pair(proof.left, proof.right)?;
            match &proof.cause {
                EqualityCause::Explicit { reason } => {
                    if *reason == CONGRUENCE_PARTITION_REASON || partition_record.reason != *reason
                    {
                        return Err(CongruenceError::InvariantViolation(
                            "explicit merge reason differs from partition reason",
                        ));
                    }
                }
                EqualityCause::Congruence {
                    argument_pairs,
                    antecedent_reasons,
                } => {
                    if partition_record.reason != CONGRUENCE_PARTITION_REASON {
                        return Err(CongruenceError::InvariantViolation(
                            "derived merge lacks the congruence partition marker",
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
                            "derived merge does not record corresponding arguments",
                        ));
                    }
                    if antecedent_reasons.windows(2).any(|pair| pair[0] >= pair[1])
                        || antecedent_reasons.contains(&CONGRUENCE_PARTITION_REASON)
                    {
                        return Err(CongruenceError::InvariantViolation(
                            "derived antecedent reasons are not canonical explicit reasons",
                        ));
                    }
                }
            }
        }
        Ok(())
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

    fn reserve_merge_record(&mut self) -> Result<(), CongruenceError> {
        self.merges
            .try_reserve(1)
            .map_err(|_| CongruenceError::AllocationFailed)
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

    fn restore_transaction(
        &mut self,
        checkpoint: CongruenceSnapshot,
    ) -> Result<(), CongruenceError> {
        self.partition
            .rollback(checkpoint.partition)
            .map_err(CongruenceError::TransactionRollbackFailed)?;
        if checkpoint.merge_len > self.merges.len() {
            return Err(CongruenceError::InvariantViolation(
                "transaction checkpoint exceeds proof history",
            ));
        }
        self.merges.truncate(checkpoint.merge_len);
        if self.partition.merge_count() != self.merges.len() {
            return Err(CongruenceError::InvariantViolation(
                "transaction rollback did not restore proof alignment",
            ));
        }
        Ok(())
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

    fn saturate(&mut self) -> Result<SaturationStats, SaturationFailure> {
        let term_count = self.terms.len();
        if term_count < 2 {
            return Ok(SaturationStats::default());
        }

        let mut stats = SaturationStats::default();
        let mut explanation_budget = ExplanationBudget::default();
        loop {
            spend(
                &mut stats.passes,
                CappedResource::SaturationPasses,
                self.limits.max_saturation_passes,
            )
            .map_err(SaturationFailure::Abstained)?;
            let mut changed = false;

            for left_index in 0..term_count {
                for right_index in left_index + 1..term_count {
                    spend(
                        &mut stats.pair_checks,
                        CappedResource::ApplicationPairChecks,
                        self.limits.max_application_pair_checks,
                    )
                    .map_err(SaturationFailure::Abstained)?;

                    let left = term_id(left_index).map_err(SaturationFailure::Error)?;
                    let right = term_id(right_index).map_err(SaturationFailure::Error)?;
                    if self
                        .partition
                        .are_equal(left, right)
                        .map_err(CongruenceError::Partition)
                        .map_err(SaturationFailure::Error)?
                    {
                        continue;
                    }

                    let argument_pairs = {
                        let left_term = &self.terms[left_index];
                        let right_term = &self.terms[right_index];
                        if !same_application_head(left_term, right_term) {
                            continue;
                        }
                        let mut pairs = Vec::new();
                        pairs
                            .try_reserve_exact(left_term.arguments.len())
                            .map_err(|_| {
                                SaturationFailure::Error(CongruenceError::AllocationFailed)
                            })?;
                        let mut congruent = true;
                        for (&left_argument, &right_argument) in
                            left_term.arguments.iter().zip(right_term.arguments.iter())
                        {
                            if !self
                                .partition
                                .are_equal(left_argument, right_argument)
                                .map_err(CongruenceError::Partition)
                                .map_err(SaturationFailure::Error)?
                            {
                                congruent = false;
                                break;
                            }
                            pairs.push((left_argument, right_argument));
                        }
                        if !congruent {
                            continue;
                        }
                        pairs
                    };

                    let antecedent_reasons = self
                        .congruence_antecedents(&argument_pairs, &mut explanation_budget)
                        .map_err(|failure| match failure {
                            WorkFailure::Abstained(reason) => SaturationFailure::Abstained(reason),
                            WorkFailure::Error(error) => SaturationFailure::Error(error),
                        })?;

                    let output_relation = self
                        .partition
                        .relation(left, right)
                        .map_err(CongruenceError::Partition)
                        .map_err(SaturationFailure::Error)?;
                    let attempted_merges = if matches!(output_relation, Relation::Unknown) {
                        let attempted = stats.merges.checked_add(1).ok_or_else(|| {
                            SaturationFailure::Abstained(Abstention::ArithmeticOverflow {
                                resource: CappedResource::CongruenceMerges,
                            })
                        })?;
                        if attempted > self.limits.max_congruence_merges {
                            return Err(SaturationFailure::Abstained(Abstention::CapExceeded {
                                resource: CappedResource::CongruenceMerges,
                                attempted,
                                limit: self.limits.max_congruence_merges,
                            }));
                        }
                        self.check_partition_update_capacity()
                            .map_err(SaturationFailure::Abstained)?;
                        self.reserve_merge_record()
                            .map_err(SaturationFailure::Error)?;
                        Some(attempted)
                    } else {
                        None
                    };

                    match self
                        .partition
                        .merge(left, right, CONGRUENCE_PARTITION_REASON)
                    {
                        Ok(MergeOutcome::Merged { .. }) => {
                            let Some(attempted_merges) = attempted_merges else {
                                return Err(SaturationFailure::Error(
                                    CongruenceError::InvariantViolation(
                                        "known application relation changed during merge",
                                    ),
                                ));
                            };
                            self.merges.push(EqualityMerge {
                                left,
                                right,
                                cause: EqualityCause::Congruence {
                                    argument_pairs,
                                    antecedent_reasons,
                                },
                            });
                            stats.merges = attempted_merges;
                            changed = true;
                        }
                        Ok(MergeOutcome::AlreadyEqual { .. }) => {
                            return Err(SaturationFailure::Error(
                                CongruenceError::InvariantViolation(
                                    "non-equal applications became equal without a merge",
                                ),
                            ));
                        }
                        Err(PartitionError::Conflict(
                            PartitionConflict::EqualityAgainstDisequality { separations, .. },
                        )) => {
                            let (equality_reasons, disequality_reasons) = self
                                .aligned_conflict_reasons(
                                    left,
                                    right,
                                    &antecedent_reasons,
                                    &separations,
                                    &mut explanation_budget,
                                )
                                .map_err(|failure| match failure {
                                    WorkFailure::Abstained(reason) => {
                                        SaturationFailure::Abstained(reason)
                                    }
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
                            return Err(SaturationFailure::Error(CongruenceError::Partition(
                                error,
                            )));
                        }
                    }
                }
            }

            if !changed {
                return Ok(stats);
            }
        }
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
                    "congruent applications have unequal corresponding arguments",
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
            for (edge_index, edge) in self.merges.iter().enumerate() {
                spend(
                    &mut budget.edge_visits,
                    CappedResource::ExplanationEdgeVisits,
                    self.limits.max_explanation_edge_visits,
                )
                .map_err(WorkFailure::Abstained)?;
                let next = if edge.left.index() == current {
                    edge.right.index()
                } else if edge.right.index() == current {
                    edge.left.index()
                } else {
                    continue;
                };
                if !seen[next] {
                    seen[next] = true;
                    predecessor[next] = Some((current, edge_index));
                    queue.push_back(next);
                }
            }
        }

        if !seen[right.index()] {
            return Err(WorkFailure::Error(CongruenceError::InvariantViolation(
                "equal terms have no causal merge path",
            )));
        }

        let mut reasons = Vec::new();
        let mut current = right.index();
        while current != left.index() {
            let Some((previous, edge_index)) = predecessor[current] else {
                return Err(WorkFailure::Error(CongruenceError::InvariantViolation(
                    "causal merge predecessor chain is incomplete",
                )));
            };
            let edge = self.merges.get(edge_index).ok_or_else(|| {
                WorkFailure::Error(CongruenceError::InvariantViolation(
                    "causal merge predecessor references no edge",
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
    use super::super::partition::{SnapshotError, TruthValue};
    use super::*;

    fn id(raw: u32) -> TermId {
        TermId::new(raw)
    }

    fn reason(raw: u64) -> ReasonId {
        ReasonId::new(raw)
    }

    fn semantic(function: u32, sort: u32, arguments: &[u32]) -> SemanticTerm {
        SemanticTerm {
            function,
            sort,
            arguments: arguments
                .iter()
                .copied()
                .map(TermId::new)
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

    fn applied(outcome: ApplyOutcome) -> ApplyStats {
        let ApplyOutcome::Applied(stats) = outcome else {
            panic!("expected applied outcome, got {outcome:?}");
        };
        stats
    }

    #[test]
    fn initial_and_nested_congruence_are_canonical_and_causal() {
        let duplicate_constants = vec![semantic(7, 1, &[]), semantic(7, 1, &[])];
        let duplicate_engine = RollbackCongruence::new(&duplicate_constants).unwrap();
        assert!(duplicate_engine.are_equal(id(0), id(1)).unwrap());
        assert_eq!(duplicate_engine.equality_merges().len(), 1);
        assert_eq!(
            duplicate_engine.equality_merges()[0],
            EqualityMerge {
                left: id(0),
                right: id(1),
                cause: EqualityCause::Congruence {
                    argument_pairs: Vec::new(),
                    antecedent_reasons: Vec::new(),
                },
            }
        );

        let terms = nested_terms();
        let mut engine = RollbackCongruence::new(&terms).unwrap();
        let stats = applied(engine.assert_equality(id(0), id(1), reason(10)).unwrap());
        assert!(stats.explicit_update);
        assert_eq!(stats.congruence_merges, 2);
        assert!(engine.are_equal(id(3), id(4)).unwrap());
        assert!(engine.are_equal(id(6), id(7)).unwrap());
        assert_eq!(
            engine.explain_equal(id(6), id(7)).unwrap(),
            ExplanationOutcome::Explained(vec![reason(10)])
        );
        assert_eq!(engine.partition().representative(id(7)).unwrap(), id(6));
        engine.validate().unwrap();
    }

    #[test]
    fn multi_argument_merge_retains_all_sorted_explicit_antecedents() {
        let terms = vec![
            semantic(1, 1, &[]),
            semantic(2, 1, &[]),
            semantic(3, 1, &[]),
            semantic(4, 1, &[]),
            semantic(20, 1, &[0, 2]),
            semantic(20, 1, &[1, 3]),
        ];
        let mut engine = RollbackCongruence::new(&terms).unwrap();
        applied(engine.assert_equal(id(0), id(1), reason(20)).unwrap());
        applied(engine.assert_equal(id(2), id(3), reason(10)).unwrap());

        let congruence = engine.congruence_merges().last().unwrap();
        assert_eq!(congruence.left, id(4));
        assert_eq!(congruence.right, id(5));
        assert_eq!(
            congruence.cause,
            EqualityCause::Congruence {
                argument_pairs: vec![(id(0), id(1)), (id(2), id(3))],
                antecedent_reasons: vec![reason(10), reason(20)],
            }
        );
        assert_eq!(
            engine.explain_equal(id(4), id(5)).unwrap(),
            ExplanationOutcome::Explained(vec![reason(10), reason(20)])
        );
    }

    #[test]
    fn congruence_conflict_rolls_back_the_entire_equality_decision() {
        let terms = nested_terms();
        let mut engine = RollbackCongruence::new(&terms).unwrap();
        applied(engine.assert_disequality(id(6), id(7), reason(20)).unwrap());
        let before = engine.snapshot();

        let outcome = engine.assert_equality(id(0), id(1), reason(10)).unwrap();
        let ApplyOutcome::Conflict(conflict) = outcome else {
            panic!("expected congruence conflict, got {outcome:?}");
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
        assert_eq!(engine.snapshot(), before);
        assert!(!engine.are_equal(id(0), id(1)).unwrap());
        assert!(!engine.are_equal(id(3), id(4)).unwrap());
        assert_eq!(engine.relation(id(6), id(7)).unwrap(), Relation::Disequal);
        engine.validate().unwrap();
    }

    #[test]
    fn explicit_disequality_conflict_uses_congruence_antecedents_transactionally() {
        let terms = nested_terms();
        let mut engine = RollbackCongruence::new(&terms).unwrap();
        applied(engine.assert_equality(id(0), id(1), reason(8)).unwrap());
        let before = engine.snapshot();

        let outcome = engine.assert_disequality(id(6), id(7), reason(9)).unwrap();
        let ApplyOutcome::Conflict(conflict) = outcome else {
            panic!("expected explicit disequality conflict, got {outcome:?}");
        };
        assert_eq!(
            conflict.origin,
            ConflictOrigin::ExplicitDisequality {
                left: id(6),
                right: id(7),
                reason: reason(9),
            }
        );
        assert_eq!(conflict.equality_reasons, vec![reason(8)]);
        assert_eq!(conflict.disequality_reasons, vec![reason(9)]);
        assert_eq!(engine.snapshot(), before);
        assert_eq!(engine.partition().separation_count(), 0);
        engine.validate().unwrap();
    }

    #[test]
    fn caps_abstain_and_restore_all_partial_congruence_updates() {
        let terms = vec![
            semantic(1, 1, &[]),
            semantic(2, 1, &[]),
            semantic(10, 1, &[0]),
            semantic(10, 1, &[1]),
        ];
        let limits = CongruenceLimits {
            max_application_pair_checks: 6,
            ..CongruenceLimits::default()
        };
        let mut engine = RollbackCongruence::with_limits(&terms, limits).unwrap();
        let before = engine.snapshot();
        assert_eq!(
            engine.assert_equal(id(0), id(1), reason(1)).unwrap(),
            ApplyOutcome::Abstained(Abstention::CapExceeded {
                resource: CappedResource::ApplicationPairChecks,
                attempted: 7,
                limit: 6,
            })
        );
        assert_eq!(engine.snapshot(), before);
        assert!(!engine.are_equal(id(0), id(1)).unwrap());
        assert!(!engine.are_equal(id(2), id(3)).unwrap());
        assert!(engine.equality_merges().is_empty());
        engine.validate().unwrap();
    }

    #[test]
    fn active_update_cap_covers_explicit_and_derived_partition_state() {
        let application_terms = vec![
            semantic(1, 1, &[]),
            semantic(2, 1, &[]),
            semantic(10, 1, &[0]),
            semantic(10, 1, &[1]),
        ];
        let limits = CongruenceLimits {
            max_partition_updates: 1,
            ..CongruenceLimits::default()
        };
        let mut engine = RollbackCongruence::with_limits(&application_terms, limits).unwrap();
        let root = engine.snapshot();
        assert_eq!(
            engine.assert_equal(id(0), id(1), reason(1)).unwrap(),
            ApplyOutcome::Abstained(Abstention::CapExceeded {
                resource: CappedResource::PartitionUpdates,
                attempted: 2,
                limit: 1,
            })
        );
        assert_eq!(engine.snapshot(), root);

        let constants = vec![
            semantic(1, 1, &[]),
            semantic(2, 1, &[]),
            semantic(3, 1, &[]),
        ];
        let mut engine = RollbackCongruence::with_limits(&constants, limits).unwrap();
        applied(engine.assert_disequal(id(0), id(1), reason(2)).unwrap());
        let full = engine.snapshot();
        let duplicate = applied(engine.assert_disequal(id(1), id(0), reason(2)).unwrap());
        assert!(!duplicate.explicit_update);
        assert_eq!(engine.snapshot(), full);
        assert_eq!(
            engine.assert_disequal(id(1), id(2), reason(3)).unwrap(),
            ApplyOutcome::Abstained(Abstention::CapExceeded {
                resource: CappedResource::PartitionUpdates,
                attempted: 2,
                limit: 1,
            })
        );
        assert_eq!(engine.snapshot(), full);
        engine.validate().unwrap();
    }

    #[test]
    fn rollback_restores_closure_and_checks_foreign_and_discarded_lineages() {
        let terms = nested_terms();
        let mut engine = RollbackCongruence::new(&terms).unwrap();
        let root = engine.checkpoint();
        applied(engine.assert_equality(id(0), id(1), reason(1)).unwrap());
        assert_eq!(engine.equality_merges().len(), 3);
        let stats = engine.rollback_to(root).unwrap();
        assert_eq!(stats.partition_updates, 3);
        assert_eq!(stats.equality_merges, 3);
        assert!(!engine.are_equal(id(0), id(1)).unwrap());
        assert!(!engine.are_equal(id(6), id(7)).unwrap());

        let simple = vec![
            semantic(1, 1, &[]),
            semantic(2, 1, &[]),
            semantic(3, 1, &[]),
        ];
        let mut first = RollbackCongruence::new(&simple).unwrap();
        let second = RollbackCongruence::new(&simple).unwrap();
        assert_eq!(
            first.rollback(second.snapshot()),
            Err(CongruenceError::Partition(PartitionError::InvalidSnapshot(
                SnapshotError::ForeignPartition
            )))
        );

        let root = first.snapshot();
        applied(first.assert_equal(id(0), id(1), reason(10)).unwrap());
        let discarded = first.snapshot();
        first.rollback(root).unwrap();
        applied(first.assert_equal(id(0), id(2), reason(11)).unwrap());
        let replacement = first.snapshot();
        assert_eq!(discarded.depth(), replacement.depth());
        assert_eq!(
            first.rollback(discarded),
            Err(CongruenceError::Partition(PartitionError::InvalidSnapshot(
                SnapshotError::DiscardedBranch
            )))
        );
        assert_eq!(first.snapshot(), replacement);
        assert!(first.are_equal(id(0), id(2)).unwrap());
        first.validate().unwrap();
    }

    #[test]
    fn malformed_semantics_and_reserved_reasons_fail_without_mutation() {
        let invalid_argument = vec![semantic(1, 1, &[1])];
        assert!(matches!(
            RollbackCongruence::new(&invalid_argument),
            Err(CongruenceError::InvalidArgument { .. })
        ));

        let inconsistent = vec![semantic(7, 1, &[]), semantic(7, 2, &[])];
        assert!(matches!(
            RollbackCongruence::new(&inconsistent),
            Err(CongruenceError::InconsistentFunctionSignature { .. })
        ));

        let terms = vec![semantic(1, 1, &[]), semantic(2, 2, &[])];
        let mut engine = RollbackCongruence::new(&terms).unwrap();
        let before = engine.snapshot();
        assert!(matches!(
            engine.assert_equal(id(0), id(1), reason(1)),
            Err(CongruenceError::SortMismatch { .. })
        ));
        assert_eq!(
            engine.assert_equal(id(0), id(0), CONGRUENCE_PARTITION_REASON),
            Err(CongruenceError::ReservedReason(CONGRUENCE_PARTITION_REASON))
        );
        assert_eq!(engine.snapshot(), before);
    }

    #[derive(Clone, Debug, Default)]
    struct SlowState {
        equalities: Vec<(usize, usize)>,
        disequalities: Vec<(usize, usize)>,
    }

    impl SlowState {
        fn try_apply(&mut self, terms: &[SemanticTerm], pair: (usize, usize), equal: bool) -> bool {
            let mut candidate = self.clone();
            if equal {
                candidate.equalities.push(pair);
            } else {
                candidate.disequalities.push(pair);
            }
            let roots = candidate.closure(terms);
            if candidate
                .disequalities
                .iter()
                .any(|&(left, right)| slow_root(&roots, left) == slow_root(&roots, right))
            {
                false
            } else {
                *self = candidate;
                true
            }
        }

        fn closure(&self, terms: &[SemanticTerm]) -> Vec<usize> {
            let mut parent = (0..terms.len()).collect::<Vec<_>>();
            for &(left, right) in &self.equalities {
                slow_union(&mut parent, left, right);
            }
            loop {
                let mut changed = false;
                for left in 0..terms.len() {
                    for right in left + 1..terms.len() {
                        if same_application_head(&terms[left], &terms[right])
                            && terms[left]
                                .arguments
                                .iter()
                                .zip(terms[right].arguments.iter())
                                .all(|(&left_argument, &right_argument)| {
                                    slow_root(&parent, left_argument.index())
                                        == slow_root(&parent, right_argument.index())
                                })
                        {
                            changed |= slow_union(&mut parent, left, right);
                        }
                    }
                }
                if !changed {
                    return parent;
                }
            }
        }

        fn relation(&self, terms: &[SemanticTerm], left: usize, right: usize) -> Relation {
            let roots = self.closure(terms);
            let left_root = slow_root(&roots, left);
            let right_root = slow_root(&roots, right);
            if left_root == right_root {
                return Relation::Equal;
            }
            if self.disequalities.iter().any(|&(first, second)| {
                let first_root = slow_root(&roots, first);
                let second_root = slow_root(&roots, second);
                (first_root == left_root && second_root == right_root)
                    || (first_root == right_root && second_root == left_root)
            }) {
                Relation::Disequal
            } else {
                Relation::Unknown
            }
        }
    }

    fn slow_root(parent: &[usize], mut term: usize) -> usize {
        while parent[term] != term {
            term = parent[term];
        }
        term
    }

    fn slow_union(parent: &mut [usize], left: usize, right: usize) -> bool {
        let left_root = slow_root(parent, left);
        let right_root = slow_root(parent, right);
        if left_root == right_root {
            return false;
        }
        let (kept, removed) = if left_root < right_root {
            (left_root, right_root)
        } else {
            (right_root, left_root)
        };
        parent[removed] = kept;
        true
    }

    #[test]
    fn exhaustive_four_term_decisions_match_fresh_semantic_closure() {
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
            let mut engine = RollbackCongruence::new(&terms).unwrap();
            let mut slow = SlowState::default();
            for (pair_index, &(left, right)) in pairs.iter().enumerate() {
                let choice = choices % 3;
                choices /= 3;
                if choice != 0 {
                    let equality = choice == 1;
                    let expected_applied = slow.try_apply(&terms, (left, right), equality);
                    let decision_reason = reason((encoded * pairs.len() + pair_index + 1) as u64);
                    let outcome = if equality {
                        engine.assert_equal(id(left as u32), id(right as u32), decision_reason)
                    } else {
                        engine.assert_disequal(id(left as u32), id(right as u32), decision_reason)
                    }
                    .unwrap();
                    assert_eq!(
                        matches!(outcome, ApplyOutcome::Applied(_)),
                        expected_applied,
                        "encoded={encoded} pair={left},{right} equality={equality} outcome={outcome:?}"
                    );
                }

                for first in 0..terms.len() {
                    for second in 0..terms.len() {
                        assert_eq!(
                            engine
                                .relation(id(first as u32), id(second as u32))
                                .unwrap(),
                            slow.relation(&terms, first, second),
                            "encoded={encoded} after_pair={pair_index} terms={first},{second}"
                        );
                    }
                }
                engine.validate().unwrap();
            }
        }
    }

    #[test]
    fn partition_truth_remains_three_valued_under_engine_updates() {
        let terms = vec![
            semantic(1, 1, &[]),
            semantic(2, 1, &[]),
            semantic(3, 1, &[]),
        ];
        let mut engine = RollbackCongruence::new(&terms).unwrap();
        applied(
            engine
                .apply(Decision::Equality {
                    left: id(0),
                    right: id(1),
                    reason: reason(1),
                })
                .unwrap(),
        );
        applied(
            engine
                .apply(Decision::Disequality {
                    left: id(1),
                    right: id(2),
                    reason: reason(2),
                })
                .unwrap(),
        );
        assert_eq!(
            engine.partition().equality_truth(id(0), id(1)).unwrap(),
            TruthValue::True
        );
        assert_eq!(
            engine.partition().equality_truth(id(0), id(2)).unwrap(),
            TruthValue::False
        );
    }
}
