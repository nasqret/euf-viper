#![forbid(unsafe_code)]

//! Rollback domains over canonical quotient-class actions.
//!
//! This module is the state substrate for Fabric E2. It deliberately does not
//! implement clause watches: it owns only one pivot's allowed/pruned action
//! domain, pruning provenance, deterministic reconciliation after partition
//! updates, and rollback. Existing-class actions are always named by stable
//! [`TermId`] values. Union-find roots and dense class numbers never escape the
//! partition.
//!
//! A pruning states the logical prohibition `pivot = target`. If two target
//! classes later merge, either target's pruning therefore prunes the collapsed
//! action. The earliest active pruning is retained as a sufficient stable
//! reason. Callers must snapshot and roll back this domain together with its
//! partition; reconciliation cannot split a class after an uncoordinated
//! partition rollback.

use super::partition::{Partition, PartitionError, Relation, TermId};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DOMAIN_ID: AtomicU64 = AtomicU64::new(1);

/// A stable action in one pivot's quotient domain.
///
/// Derived ordering puts existing targets in increasing [`TermId`] order and
/// the unique fresh action last.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum DomainAction {
    Existing(TermId),
    Fresh,
}

/// A caller-owned, stable identifier for a replayable pruning reason.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ReasonToken(u64);

impl ReasonToken {
    pub(crate) const MIN: Self = Self(0);
    pub(crate) const MAX: Self = Self(u64::MAX);

    pub(crate) const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub(crate) const fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ReasonToken {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(output)
    }
}

/// A never-reused time assigned to a committed pruning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PruneTime(u64);

impl PruneTime {
    pub(crate) const fn raw(self) -> u64 {
        self.0
    }
}

/// Replay metadata for one active pruning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Pruning {
    pub(crate) time: PruneTime,
    pub(crate) level: u32,
    pub(crate) reason: ReasonToken,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DomainState {
    Allowed,
    Pruned(Pruning),
}

impl DomainState {
    pub(crate) const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }

    pub(crate) const fn pruning(self) -> Option<Pruning> {
        match self {
            Self::Allowed => None,
            Self::Pruned(pruning) => Some(pruning),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DomainEntry {
    pub(crate) action: DomainAction,
    pub(crate) state: DomainState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DomainStatus {
    Empty,
    Unit(DomainAction),
    Open { remaining: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DomainCaps {
    /// Maximum input and live canonical existing-target count.
    pub(crate) max_targets: usize,
    /// Maximum charged canonicalization/relation operations per reconcile.
    pub(crate) max_reconcile_work: usize,
    /// Maximum new logical prunings committed by one operation.
    pub(crate) max_prunings_per_transaction: usize,
    /// Maximum active rollback transactions on one branch.
    pub(crate) max_transactions: usize,
}

impl Default for DomainCaps {
    fn default() -> Self {
        Self {
            max_targets: 1_000_000,
            max_reconcile_work: 8_000_000,
            max_prunings_per_transaction: 1_000_000,
            max_transactions: 8_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DomainResource {
    Targets,
    ReconcileWork,
    Prunings,
    Transactions,
    PruneTime,
}

impl fmt::Display for DomainResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Targets => "quotient-domain targets",
            Self::ReconcileWork => "quotient-domain reconcile work",
            Self::Prunings => "quotient-domain prunings",
            Self::Transactions => "active quotient-domain transactions",
            Self::PruneTime => "quotient-domain prune time",
        };
        output.write_str(name)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DomainAbstention {
    pub(crate) resource: DomainResource,
    pub(crate) attempted: usize,
    pub(crate) limit: usize,
}

impl fmt::Display for DomainAbstention {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "{} cap exceeded: attempted {}, limit {}",
            self.resource, self.attempted, self.limit
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DomainSnapshotError {
    ForeignDomain,
    FutureState,
    DiscardedBranch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DomainError {
    PartitionTermCountMismatch {
        domain_terms: usize,
        partition_terms: usize,
    },
    UnknownTarget {
        target: TermId,
    },
    InvalidSnapshot(DomainSnapshotError),
    AllocationFailed,
    DomainIdExhausted,
    StateIdExhausted,
    Partition(PartitionError),
    InvariantViolation(&'static str),
}

impl fmt::Display for DomainError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PartitionTermCountMismatch {
                domain_terms,
                partition_terms,
            } => write!(
                output,
                "quotient domain has {domain_terms} terms but partition has {partition_terms}"
            ),
            Self::UnknownTarget { target } => {
                write!(output, "term {target} is not a live quotient-domain target")
            }
            Self::InvalidSnapshot(DomainSnapshotError::ForeignDomain) => {
                output.write_str("snapshot belongs to a different quotient domain")
            }
            Self::InvalidSnapshot(DomainSnapshotError::FutureState) => {
                output.write_str("quotient-domain snapshot is newer than the current state")
            }
            Self::InvalidSnapshot(DomainSnapshotError::DiscardedBranch) => {
                output.write_str("quotient-domain snapshot belongs to a discarded history branch")
            }
            Self::AllocationFailed => {
                output.write_str("allocation failed while updating quotient domain")
            }
            Self::DomainIdExhausted => output.write_str("quotient-domain ID space exhausted"),
            Self::StateIdExhausted => output.write_str("quotient-domain state ID space exhausted"),
            Self::Partition(error) => error.fmt(output),
            Self::InvariantViolation(message) => {
                write!(output, "quotient-domain invariant violation: {message}")
            }
        }
    }
}

impl Error for DomainError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Partition(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PartitionError> for DomainError {
    fn from(error: PartitionError) -> Self {
        Self::Partition(error)
    }
}

#[derive(Debug)]
pub(crate) enum DomainBuildOutcome {
    Built(RollbackQuotientDomain),
    Abstained(DomainAbstention),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DomainDelta {
    pub(crate) collapsed_targets: usize,
    pub(crate) newly_pruned: usize,
    pub(crate) status: DomainStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DomainMutation {
    Changed(DomainDelta),
    Unchanged { status: DomainStatus },
    Abstained(DomainAbstention),
}

impl DomainMutation {
    pub(crate) const fn status(self) -> Option<DomainStatus> {
        match self {
            Self::Changed(delta) => Some(delta.status),
            Self::Unchanged { status } => Some(status),
            Self::Abstained(_) => None,
        }
    }
}

/// Opaque rollback point tied to one domain and one history lineage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct DomainSnapshot {
    domain_id: u64,
    trail_len: usize,
    state_id: u64,
}

impl DomainSnapshot {
    pub(crate) const fn depth(self) -> usize {
        self.trail_len
    }
}

#[derive(Debug)]
struct TrailEntry {
    state_id: u64,
    undo: Undo,
}

#[derive(Debug)]
enum Undo {
    PruneExisting {
        target: TermId,
    },
    PruneFresh,
    Reconcile {
        targets: BTreeMap<TermId, DomainState>,
        fresh: DomainState,
    },
}

/// Rollback allowed/pruned actions for one stable pivot term.
///
/// The type is intentionally not `Clone`: snapshots belong to the unique
/// history that created them.
#[derive(Debug)]
pub(crate) struct RollbackQuotientDomain {
    domain_id: u64,
    term_count: usize,
    pivot: TermId,
    targets: BTreeMap<TermId, DomainState>,
    fresh: DomainState,
    caps: DomainCaps,
    trail: Vec<TrailEntry>,
    next_state_id: u64,
    next_prune_time: u64,
}

pub(crate) type QuotientDomain = RollbackQuotientDomain;

impl RollbackQuotientDomain {
    pub(crate) fn new(
        pivot: TermId,
        targets: &[TermId],
        partition: &Partition,
    ) -> Result<DomainBuildOutcome, DomainError> {
        Self::with_caps(pivot, targets, partition, DomainCaps::default())
    }

    pub(crate) fn with_caps(
        pivot: TermId,
        targets: &[TermId],
        partition: &Partition,
        caps: DomainCaps,
    ) -> Result<DomainBuildOutcome, DomainError> {
        if targets.len() > caps.max_targets {
            return Ok(DomainBuildOutcome::Abstained(DomainAbstention {
                resource: DomainResource::Targets,
                attempted: targets.len(),
                limit: caps.max_targets,
            }));
        }

        partition.canonical_representative(pivot)?;
        let mut canonical_targets = BTreeMap::new();
        for &target in targets {
            let representative = partition.canonical_representative(target)?;
            canonical_targets
                .entry(representative)
                .or_insert(DomainState::Allowed);
        }
        if canonical_targets.len() > caps.max_targets {
            return Ok(DomainBuildOutcome::Abstained(DomainAbstention {
                resource: DomainResource::Targets,
                attempted: canonical_targets.len(),
                limit: caps.max_targets,
            }));
        }

        let domain_id = NEXT_DOMAIN_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| DomainError::DomainIdExhausted)?;
        let domain = Self {
            domain_id,
            term_count: partition.term_count(),
            pivot,
            targets: canonical_targets,
            fresh: DomainState::Allowed,
            caps,
            trail: Vec::new(),
            next_state_id: 1,
            next_prune_time: 1,
        };
        debug_assert!(domain.validate().is_ok());
        Ok(DomainBuildOutcome::Built(domain))
    }

    pub(crate) const fn pivot(&self) -> TermId {
        self.pivot
    }

    pub(crate) const fn term_count(&self) -> usize {
        self.term_count
    }

    pub(crate) fn target_count(&self) -> usize {
        self.targets.len()
    }

    pub(crate) const fn caps(&self) -> DomainCaps {
        self.caps
    }

    /// The next never-reused time. Rollback removes records but never rewinds
    /// this clock, so a replacement branch cannot alias a discarded event.
    pub(crate) const fn next_prune_time(&self) -> u64 {
        self.next_prune_time
    }

    pub(crate) fn snapshot(&self) -> DomainSnapshot {
        DomainSnapshot {
            domain_id: self.domain_id,
            trail_len: self.trail.len(),
            state_id: self.trail.last().map_or(0, |entry| entry.state_id),
        }
    }

    pub(crate) fn checkpoint(&self) -> DomainSnapshot {
        self.snapshot()
    }

    pub(crate) fn rollback(&mut self, snapshot: DomainSnapshot) -> Result<usize, DomainError> {
        self.validate_snapshot(snapshot)?;
        let undone = self.trail.len() - snapshot.trail_len;
        while self.trail.len() > snapshot.trail_len {
            let entry = self.trail.pop().ok_or(DomainError::InvariantViolation(
                "rollback trail unexpectedly empty",
            ))?;
            match entry.undo {
                Undo::PruneExisting { target } => {
                    let state =
                        self.targets
                            .get_mut(&target)
                            .ok_or(DomainError::InvariantViolation(
                                "pruned target disappeared before rollback",
                            ))?;
                    if !matches!(state, DomainState::Pruned(_)) {
                        return Err(DomainError::InvariantViolation(
                            "target prune rollback found an allowed target",
                        ));
                    }
                    *state = DomainState::Allowed;
                }
                Undo::PruneFresh => {
                    if !matches!(self.fresh, DomainState::Pruned(_)) {
                        return Err(DomainError::InvariantViolation(
                            "fresh prune rollback found an allowed action",
                        ));
                    }
                    self.fresh = DomainState::Allowed;
                }
                Undo::Reconcile { targets, fresh } => {
                    self.targets = targets;
                    self.fresh = fresh;
                }
            }
        }
        debug_assert!(self.validate().is_ok());
        Ok(undone)
    }

    pub(crate) fn rollback_to(&mut self, snapshot: DomainSnapshot) -> Result<usize, DomainError> {
        self.rollback(snapshot)
    }

    pub(crate) fn entries(&self) -> impl Iterator<Item = DomainEntry> + '_ {
        self.targets
            .iter()
            .map(|(&target, &state)| DomainEntry {
                action: DomainAction::Existing(target),
                state,
            })
            .chain(std::iter::once(DomainEntry {
                action: DomainAction::Fresh,
                state: self.fresh,
            }))
    }

    pub(crate) fn allowed_actions(&self) -> impl Iterator<Item = DomainAction> + '_ {
        self.entries()
            .filter(|entry| entry.state.is_allowed())
            .map(|entry| entry.action)
    }

    pub(crate) fn pruned_entries(&self) -> impl Iterator<Item = DomainEntry> + '_ {
        self.entries().filter(|entry| !entry.state.is_allowed())
    }

    pub(crate) fn state(&self, action: DomainAction) -> Result<DomainState, DomainError> {
        match action {
            DomainAction::Existing(target) => self
                .targets
                .get(&target)
                .copied()
                .ok_or(DomainError::UnknownTarget { target }),
            DomainAction::Fresh => Ok(self.fresh),
        }
    }

    pub(crate) fn status(&self) -> DomainStatus {
        let mut allowed = self.allowed_actions();
        match (allowed.next(), allowed.next()) {
            (None, _) => DomainStatus::Empty,
            (Some(action), None) => DomainStatus::Unit(action),
            (Some(_), Some(_)) => DomainStatus::Open {
                remaining: 2 + allowed.count(),
            },
        }
    }

    /// Prunes one current action. Existing targets are first canonicalized by
    /// the supplied partition, so a stable pre-merge member remains usable
    /// after the caller has reconciled this domain.
    pub(crate) fn prune(
        &mut self,
        action: DomainAction,
        partition: &Partition,
        level: u32,
        reason: ReasonToken,
    ) -> Result<DomainMutation, DomainError> {
        self.validate_partition(partition)?;
        let action = match action {
            DomainAction::Existing(target) => {
                DomainAction::Existing(partition.canonical_representative(target)?)
            }
            DomainAction::Fresh => DomainAction::Fresh,
        };
        let current = self.state(action)?;
        if !current.is_allowed() {
            return Ok(DomainMutation::Unchanged {
                status: self.status(),
            });
        }
        if let Some(abstention) = self.pruning_cap(1) {
            return Ok(DomainMutation::Abstained(abstention));
        }
        if let Some(abstention) = self.transaction_cap() {
            return Ok(DomainMutation::Abstained(abstention));
        }
        let Some(next_prune_time) = self.next_prune_time.checked_add(1) else {
            return Ok(DomainMutation::Abstained(DomainAbstention {
                resource: DomainResource::PruneTime,
                attempted: usize::MAX,
                limit: usize::MAX,
            }));
        };
        let (state_id, next_state_id) = self.prepare_state_id()?;
        self.trail
            .try_reserve(1)
            .map_err(|_| DomainError::AllocationFailed)?;

        let pruning = Pruning {
            time: PruneTime(self.next_prune_time),
            level,
            reason,
        };
        let undo = match action {
            DomainAction::Existing(target) => {
                let state =
                    self.targets
                        .get_mut(&target)
                        .ok_or(DomainError::InvariantViolation(
                            "validated target disappeared before prune",
                        ))?;
                *state = DomainState::Pruned(pruning);
                Undo::PruneExisting { target }
            }
            DomainAction::Fresh => {
                self.fresh = DomainState::Pruned(pruning);
                Undo::PruneFresh
            }
        };
        self.trail.push(TrailEntry { state_id, undo });
        self.next_state_id = next_state_id;
        self.next_prune_time = next_prune_time;
        let status = self.status();
        debug_assert!(self.validate().is_ok());
        Ok(DomainMutation::Changed(DomainDelta {
            collapsed_targets: 0,
            newly_pruned: 1,
            status,
        }))
    }

    /// Canonicalizes target identities after partition merges. If the pivot is
    /// equal to one target, that existing action is fixed and every competing
    /// action is pruned. Otherwise, every target known disequal from the pivot
    /// is pruned while the fresh action remains available.
    ///
    /// The operation is all-or-nothing. It builds and checks the complete next
    /// state, including all cap and clock checks, before changing this domain.
    pub(crate) fn reconcile(
        &mut self,
        partition: &Partition,
        level: u32,
    ) -> Result<DomainMutation, DomainError> {
        self.validate_partition(partition)?;
        let work = match self.targets.len().checked_mul(3) {
            Some(work) => work,
            None => {
                return Ok(DomainMutation::Abstained(DomainAbstention {
                    resource: DomainResource::ReconcileWork,
                    attempted: usize::MAX,
                    limit: self.caps.max_reconcile_work,
                }));
            }
        };
        if work > self.caps.max_reconcile_work {
            return Ok(DomainMutation::Abstained(DomainAbstention {
                resource: DomainResource::ReconcileWork,
                attempted: work,
                limit: self.caps.max_reconcile_work,
            }));
        }

        let canonical_pivot = partition.canonical_representative(self.pivot)?;
        let mut next_targets = BTreeMap::new();
        for (&target, &state) in &self.targets {
            let representative = partition.canonical_representative(target)?;
            next_targets
                .entry(representative)
                .and_modify(|current| *current = combine_states(*current, state))
                .or_insert(state);
        }
        if next_targets.len() > self.caps.max_targets {
            return Ok(DomainMutation::Abstained(DomainAbstention {
                resource: DomainResource::Targets,
                attempted: next_targets.len(),
                limit: self.caps.max_targets,
            }));
        }

        let mut equal_target = None;
        let mut disequal = Vec::new();
        disequal
            .try_reserve(next_targets.len())
            .map_err(|_| DomainError::AllocationFailed)?;
        for (&target, &state) in &next_targets {
            match partition.relation(canonical_pivot, target)? {
                Relation::Equal => {
                    if equal_target.is_some() {
                        return Err(DomainError::InvariantViolation(
                            "pivot is equal to multiple canonical targets",
                        ));
                    }
                    let reasons = partition.equality_reasons(self.pivot, target)?.ok_or(
                        DomainError::InvariantViolation("known equality has no stable reason path"),
                    )?;
                    let reason = reasons
                        .into_iter()
                        .map(|reason| ReasonToken::new(reason.raw()))
                        .min()
                        .unwrap_or(ReasonToken::MIN);
                    equal_target = Some((target, reason));
                }
                Relation::Unknown => {}
                Relation::Disequal => {
                    if !state.is_allowed() {
                        continue;
                    }
                    let reasons = partition
                        .disequality_reasons(canonical_pivot, target)?
                        .ok_or(DomainError::InvariantViolation(
                            "known disequality has no stable reason",
                        ))?;
                    let reason = reasons
                        .into_iter()
                        .map(|reason| ReasonToken::new(reason.raw()))
                        .min()
                        .ok_or(DomainError::InvariantViolation(
                            "known disequality has an empty reason set",
                        ))?;
                    disequal.push((target, reason));
                }
            }
        }

        let mut prunings = Vec::new();
        prunings
            .try_reserve(next_targets.len().saturating_add(1))
            .map_err(|_| DomainError::AllocationFailed)?;
        if let Some((fixed_target, reason)) = equal_target {
            for (&target, &state) in &next_targets {
                if target != fixed_target && state.is_allowed() {
                    prunings.push((DomainAction::Existing(target), reason));
                }
            }
            if self.fresh.is_allowed() {
                prunings.push((DomainAction::Fresh, reason));
            }
        } else {
            prunings.extend(
                disequal
                    .iter()
                    .map(|&(target, reason)| (DomainAction::Existing(target), reason)),
            );
        }

        if let Some(abstention) = self.pruning_cap(prunings.len()) {
            return Ok(DomainMutation::Abstained(abstention));
        }
        let next_prune_time = match u64::try_from(prunings.len())
            .ok()
            .and_then(|count| self.next_prune_time.checked_add(count))
        {
            Some(time) => time,
            None => {
                return Ok(DomainMutation::Abstained(DomainAbstention {
                    resource: DomainResource::PruneTime,
                    attempted: usize::MAX,
                    limit: usize::MAX,
                }));
            }
        };
        let mut next_fresh = self.fresh;
        for (offset, (action, reason)) in prunings.iter().copied().enumerate() {
            let offset = u64::try_from(offset)
                .map_err(|_| DomainError::InvariantViolation("pruning offset does not fit u64"))?;
            let time =
                self.next_prune_time
                    .checked_add(offset)
                    .ok_or(DomainError::InvariantViolation(
                        "prechecked pruning time overflowed",
                    ))?;
            let pruning = DomainState::Pruned(Pruning {
                time: PruneTime(time),
                level,
                reason,
            });
            match action {
                DomainAction::Existing(target) => {
                    let state =
                        next_targets
                            .get_mut(&target)
                            .ok_or(DomainError::InvariantViolation(
                                "target disappeared while applying reconcile pruning",
                            ))?;
                    *state = pruning;
                }
                DomainAction::Fresh => next_fresh = pruning,
            }
        }

        if next_targets == self.targets && next_fresh == self.fresh {
            return Ok(DomainMutation::Unchanged {
                status: self.status(),
            });
        }
        if let Some(abstention) = self.transaction_cap() {
            return Ok(DomainMutation::Abstained(abstention));
        }
        let (state_id, next_state_id) = self.prepare_state_id()?;
        self.trail
            .try_reserve(1)
            .map_err(|_| DomainError::AllocationFailed)?;
        let old_count = self.targets.len();
        let old_targets = std::mem::replace(&mut self.targets, next_targets);
        let old_fresh = std::mem::replace(&mut self.fresh, next_fresh);
        self.trail.push(TrailEntry {
            state_id,
            undo: Undo::Reconcile {
                targets: old_targets,
                fresh: old_fresh,
            },
        });
        self.next_state_id = next_state_id;
        self.next_prune_time = next_prune_time;
        let status = self.status();
        debug_assert!(self.validate().is_ok());
        Ok(DomainMutation::Changed(DomainDelta {
            collapsed_targets: old_count - self.targets.len(),
            newly_pruned: prunings.len(),
            status,
        }))
    }

    pub(crate) fn validate(&self) -> Result<(), DomainError> {
        if self.pivot.index() >= self.term_count {
            return Err(DomainError::InvariantViolation(
                "pivot is outside term universe",
            ));
        }
        if self.targets.len() > self.caps.max_targets {
            return Err(DomainError::InvariantViolation("target cap is violated"));
        }
        let mut active_times = BTreeMap::new();
        for (&target, &state) in &self.targets {
            if target.index() >= self.term_count {
                return Err(DomainError::InvariantViolation(
                    "target is outside term universe",
                ));
            }
            if let Some(pruning) = state.pruning() {
                validate_pruning(pruning, self.next_prune_time, &mut active_times)?;
            }
        }
        if let Some(pruning) = self.fresh.pruning() {
            validate_pruning(pruning, self.next_prune_time, &mut active_times)?;
        }
        if self.trail.len() > self.caps.max_transactions {
            return Err(DomainError::InvariantViolation(
                "transaction cap is violated",
            ));
        }
        let mut previous_state_id = 0;
        for entry in &self.trail {
            if entry.state_id <= previous_state_id || entry.state_id >= self.next_state_id {
                return Err(DomainError::InvariantViolation(
                    "trail state IDs are not strictly increasing",
                ));
            }
            previous_state_id = entry.state_id;
        }
        Ok(())
    }

    fn validate_partition(&self, partition: &Partition) -> Result<(), DomainError> {
        if partition.term_count() != self.term_count {
            return Err(DomainError::PartitionTermCountMismatch {
                domain_terms: self.term_count,
                partition_terms: partition.term_count(),
            });
        }
        Ok(())
    }

    fn validate_snapshot(&self, snapshot: DomainSnapshot) -> Result<(), DomainError> {
        if snapshot.domain_id != self.domain_id {
            return Err(DomainError::InvalidSnapshot(
                DomainSnapshotError::ForeignDomain,
            ));
        }
        if snapshot.trail_len > self.trail.len() {
            return Err(DomainError::InvalidSnapshot(
                DomainSnapshotError::FutureState,
            ));
        }
        let expected_state_id = if snapshot.trail_len == 0 {
            0
        } else {
            self.trail[snapshot.trail_len - 1].state_id
        };
        if snapshot.state_id != expected_state_id {
            return Err(DomainError::InvalidSnapshot(
                DomainSnapshotError::DiscardedBranch,
            ));
        }
        Ok(())
    }

    fn pruning_cap(&self, attempted: usize) -> Option<DomainAbstention> {
        (attempted > self.caps.max_prunings_per_transaction).then_some(DomainAbstention {
            resource: DomainResource::Prunings,
            attempted,
            limit: self.caps.max_prunings_per_transaction,
        })
    }

    fn transaction_cap(&self) -> Option<DomainAbstention> {
        let attempted = self.trail.len().checked_add(1).unwrap_or(usize::MAX);
        (attempted > self.caps.max_transactions).then_some(DomainAbstention {
            resource: DomainResource::Transactions,
            attempted,
            limit: self.caps.max_transactions,
        })
    }

    fn prepare_state_id(&self) -> Result<(u64, u64), DomainError> {
        let state_id = self.next_state_id;
        let next_state_id = state_id
            .checked_add(1)
            .ok_or(DomainError::StateIdExhausted)?;
        Ok((state_id, next_state_id))
    }
}

fn combine_states(left: DomainState, right: DomainState) -> DomainState {
    match (left, right) {
        (DomainState::Allowed, DomainState::Allowed) => DomainState::Allowed,
        (DomainState::Pruned(pruning), DomainState::Allowed)
        | (DomainState::Allowed, DomainState::Pruned(pruning)) => DomainState::Pruned(pruning),
        (DomainState::Pruned(left), DomainState::Pruned(right)) => {
            DomainState::Pruned(left.min(right))
        }
    }
}

fn validate_pruning(
    pruning: Pruning,
    next_prune_time: u64,
    active_times: &mut BTreeMap<PruneTime, ()>,
) -> Result<(), DomainError> {
    if pruning.time.raw() == 0 || pruning.time.raw() >= next_prune_time {
        return Err(DomainError::InvariantViolation(
            "active pruning time is outside the committed clock",
        ));
    }
    if active_times.insert(pruning.time, ()).is_some() {
        return Err(DomainError::InvariantViolation(
            "active pruning times are not unique",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::partition::{ReasonId, Snapshot as PartitionSnapshot};
    use super::*;
    use std::collections::BTreeSet;

    fn term(raw: u32) -> TermId {
        TermId::new(raw)
    }

    fn reason(raw: u64) -> ReasonToken {
        ReasonToken::new(raw)
    }

    fn partition_reason(raw: u64) -> ReasonId {
        ReasonId::new(raw)
    }

    fn built(outcome: DomainBuildOutcome) -> RollbackQuotientDomain {
        match outcome {
            DomainBuildOutcome::Built(domain) => domain,
            DomainBuildOutcome::Abstained(limit) => panic!("unexpected abstention: {limit}"),
        }
    }

    fn domain(partition: &Partition) -> RollbackQuotientDomain {
        built(
            RollbackQuotientDomain::new(term(3), &[term(0), term(1), term(2)], partition).unwrap(),
        )
    }

    fn entries(domain: &RollbackQuotientDomain) -> Vec<DomainEntry> {
        domain.entries().collect()
    }

    fn allowed(domain: &RollbackQuotientDomain) -> BTreeSet<DomainAction> {
        domain.allowed_actions().collect()
    }

    #[test]
    fn deterministic_iteration_status_and_monotone_pruning_metadata() {
        let partition = Partition::new(4).unwrap();
        let mut domain = built(
            RollbackQuotientDomain::new(term(3), &[term(2), term(0), term(1), term(1)], &partition)
                .unwrap(),
        );
        assert_eq!(domain.pivot(), term(3));
        assert_eq!(domain.term_count(), 4);
        assert_eq!(domain.target_count(), 3);
        assert_eq!(
            domain
                .entries()
                .map(|entry| entry.action)
                .collect::<Vec<_>>(),
            vec![
                DomainAction::Existing(term(0)),
                DomainAction::Existing(term(1)),
                DomainAction::Existing(term(2)),
                DomainAction::Fresh,
            ]
        );
        assert_eq!(domain.status(), DomainStatus::Open { remaining: 4 });

        assert!(matches!(
            domain
                .prune(DomainAction::Existing(term(1)), &partition, 2, reason(11))
                .unwrap(),
            DomainMutation::Changed(DomainDelta {
                newly_pruned: 1,
                ..
            })
        ));
        let first = domain
            .state(DomainAction::Existing(term(1)))
            .unwrap()
            .pruning()
            .unwrap();
        assert_eq!(first.time.raw(), 1);
        assert_eq!(first.level, 2);
        assert_eq!(first.reason, reason(11));
        assert_eq!(domain.next_prune_time(), 2);
        let after_first = domain.snapshot();

        domain
            .prune(DomainAction::Fresh, &partition, 3, reason(12))
            .unwrap();
        assert_eq!(domain.fresh.pruning().unwrap().time.raw(), 2);
        assert!(matches!(
            domain
                .prune(DomainAction::Fresh, &partition, 9, reason(99))
                .unwrap(),
            DomainMutation::Unchanged { .. }
        ));
        assert_eq!(domain.next_prune_time(), 3);
        domain.rollback(after_first).unwrap();
        assert_eq!(
            domain.state(DomainAction::Fresh).unwrap(),
            DomainState::Allowed
        );
        domain
            .prune(DomainAction::Fresh, &partition, 4, reason(13))
            .unwrap();
        assert_eq!(domain.fresh.pruning().unwrap().time.raw(), 3);

        domain
            .prune(DomainAction::Existing(term(0)), &partition, 4, reason(14))
            .unwrap();
        assert_eq!(
            domain.status(),
            DomainStatus::Unit(DomainAction::Existing(term(2)))
        );
        domain
            .prune(DomainAction::Existing(term(2)), &partition, 4, reason(15))
            .unwrap();
        assert_eq!(domain.status(), DomainStatus::Empty);
        domain.validate().unwrap();
    }

    #[test]
    fn target_collapse_preserves_logical_pruning_and_rolls_back_exactly() {
        let mut partition = Partition::new(4).unwrap();
        let mut domain = domain(&partition);
        domain
            .prune(DomainAction::Existing(term(1)), &partition, 1, reason(21))
            .unwrap();
        let before_partition = partition.snapshot();
        let before_domain = domain.snapshot();
        let before_entries = entries(&domain);

        partition
            .merge(term(1), term(0), partition_reason(1))
            .unwrap();
        assert!(matches!(
            domain.reconcile(&partition, 2).unwrap(),
            DomainMutation::Changed(DomainDelta {
                collapsed_targets: 1,
                newly_pruned: 0,
                ..
            })
        ));
        assert_eq!(domain.target_count(), 2);
        let collapsed = domain
            .state(DomainAction::Existing(term(0)))
            .unwrap()
            .pruning()
            .unwrap();
        assert_eq!(collapsed.reason, reason(21));
        assert_eq!(collapsed.time.raw(), 1);
        assert_eq!(
            allowed(&domain),
            BTreeSet::from([DomainAction::Existing(term(2)), DomainAction::Fresh])
        );
        assert!(matches!(
            domain
                .prune(DomainAction::Existing(term(1)), &partition, 3, reason(22))
                .unwrap(),
            DomainMutation::Unchanged { .. }
        ));

        domain.rollback(before_domain).unwrap();
        partition.rollback(before_partition).unwrap();
        assert_eq!(entries(&domain), before_entries);
        domain.validate().unwrap();
    }

    #[test]
    fn disequality_pruning_uses_stable_partition_reason_and_keeps_fresh() {
        let mut partition = Partition::new(4).unwrap();
        let mut domain = domain(&partition);
        partition
            .separate(term(3), term(1), partition_reason(77))
            .unwrap();
        let mutation = domain.reconcile(&partition, 4).unwrap();
        assert_eq!(
            mutation,
            DomainMutation::Changed(DomainDelta {
                collapsed_targets: 0,
                newly_pruned: 1,
                status: DomainStatus::Open { remaining: 3 },
            })
        );
        let pruning = domain
            .state(DomainAction::Existing(term(1)))
            .unwrap()
            .pruning()
            .unwrap();
        assert_eq!(pruning.level, 4);
        assert_eq!(pruning.reason, reason(77));
        assert!(domain.state(DomainAction::Fresh).unwrap().is_allowed());

        partition
            .separate(term(3), term(0), partition_reason(76))
            .unwrap();
        partition
            .separate(term(3), term(2), partition_reason(78))
            .unwrap();
        domain.reconcile(&partition, 5).unwrap();
        assert_eq!(domain.status(), DomainStatus::Unit(DomainAction::Fresh));
        assert_eq!(
            domain
                .state(DomainAction::Existing(term(0)))
                .unwrap()
                .pruning()
                .unwrap()
                .reason,
            reason(76)
        );
        assert_eq!(
            domain
                .state(DomainAction::Existing(term(2)))
                .unwrap()
                .pruning()
                .unwrap()
                .reason,
            reason(78)
        );
    }

    #[test]
    fn pivot_equality_fixes_existing_action_prunes_fresh_and_rolls_back_exactly() {
        let mut partition = Partition::new(4).unwrap();
        let mut domain = domain(&partition);
        let partition_root = partition.snapshot();
        let domain_root = domain.snapshot();
        let root_entries = entries(&domain);

        partition
            .merge(term(3), term(1), partition_reason(55))
            .unwrap();
        assert_eq!(
            domain.reconcile(&partition, 4).unwrap(),
            DomainMutation::Changed(DomainDelta {
                collapsed_targets: 0,
                newly_pruned: 3,
                status: DomainStatus::Unit(DomainAction::Existing(term(1))),
            })
        );
        assert_eq!(
            allowed(&domain),
            BTreeSet::from([DomainAction::Existing(term(1))])
        );
        for action in [
            DomainAction::Existing(term(0)),
            DomainAction::Existing(term(2)),
            DomainAction::Fresh,
        ] {
            let pruning = domain.state(action).unwrap().pruning().unwrap();
            assert_eq!(pruning.level, 4);
            assert_eq!(pruning.reason, reason(55));
        }

        domain.rollback(domain_root).unwrap();
        partition.rollback(partition_root).unwrap();
        assert_eq!(entries(&domain), root_entries);
        assert_eq!(domain.next_prune_time(), 4);
        domain.validate().unwrap();
    }

    #[test]
    fn pruned_equal_action_makes_domain_empty_and_cap_abstains_atomically() {
        let mut partition = Partition::new(4).unwrap();
        let mut domain = domain(&partition);
        domain
            .prune(DomainAction::Existing(term(1)), &partition, 1, reason(21))
            .unwrap();
        partition
            .merge(term(3), term(1), partition_reason(56))
            .unwrap();
        assert_eq!(
            domain.reconcile(&partition, 2).unwrap().status(),
            Some(DomainStatus::Empty)
        );

        let base_partition = Partition::new(4).unwrap();
        let caps = DomainCaps {
            max_prunings_per_transaction: 2,
            ..DomainCaps::default()
        };
        let mut capped = built(
            RollbackQuotientDomain::with_caps(
                term(3),
                &[term(0), term(1), term(2)],
                &base_partition,
                caps,
            )
            .unwrap(),
        );
        let before = entries(&capped);
        let before_snapshot = capped.snapshot();
        let before_time = capped.next_prune_time();
        let mut fixed_partition = Partition::new(4).unwrap();
        fixed_partition
            .merge(term(3), term(1), partition_reason(57))
            .unwrap();
        assert!(matches!(
            capped.reconcile(&fixed_partition, 3).unwrap(),
            DomainMutation::Abstained(DomainAbstention {
                resource: DomainResource::Prunings,
                attempted: 3,
                limit: 2,
            })
        ));
        assert_eq!(entries(&capped), before);
        assert_eq!(capped.snapshot(), before_snapshot);
        assert_eq!(capped.next_prune_time(), before_time);
    }

    #[test]
    fn canonical_targets_ignore_union_root_and_merge_order() {
        let mut first_partition = Partition::new(4).unwrap();
        let mut second_partition = Partition::new(4).unwrap();
        let mut first_domain = domain(&first_partition);
        let mut second_domain = domain(&second_partition);
        first_domain
            .prune(
                DomainAction::Existing(term(2)),
                &first_partition,
                1,
                reason(31),
            )
            .unwrap();
        second_domain
            .prune(
                DomainAction::Existing(term(2)),
                &second_partition,
                1,
                reason(31),
            )
            .unwrap();

        first_partition
            .merge(term(2), term(1), partition_reason(1))
            .unwrap();
        first_partition
            .merge(term(1), term(0), partition_reason(2))
            .unwrap();
        second_partition
            .merge(term(0), term(1), partition_reason(2))
            .unwrap();
        second_partition
            .merge(term(0), term(2), partition_reason(1))
            .unwrap();
        first_domain.reconcile(&first_partition, 2).unwrap();
        second_domain.reconcile(&second_partition, 2).unwrap();

        assert_eq!(entries(&first_domain), entries(&second_domain));
        assert_eq!(
            first_domain
                .entries()
                .map(|entry| entry.action)
                .collect::<Vec<_>>(),
            vec![DomainAction::Existing(term(0)), DomainAction::Fresh]
        );
        assert_eq!(
            first_domain
                .state(DomainAction::Existing(term(0)))
                .unwrap()
                .pruning()
                .unwrap()
                .reason,
            reason(31)
        );
    }

    #[test]
    fn invalid_terms_partitions_and_snapshot_lineages_are_rejected() {
        let partition = Partition::new(4).unwrap();
        assert!(matches!(
            RollbackQuotientDomain::new(term(4), &[term(0)], &partition),
            Err(DomainError::Partition(PartitionError::InvalidTerm { .. }))
        ));
        assert!(matches!(
            RollbackQuotientDomain::new(term(3), &[term(4)], &partition),
            Err(DomainError::Partition(PartitionError::InvalidTerm { .. }))
        ));

        let mut first = domain(&partition);
        let second = domain(&partition);
        let root = first.snapshot();
        assert_eq!(
            first.rollback(second.snapshot()),
            Err(DomainError::InvalidSnapshot(
                DomainSnapshotError::ForeignDomain
            ))
        );
        assert!(matches!(
            first.prune(DomainAction::Existing(term(4)), &partition, 1, reason(1)),
            Err(DomainError::Partition(PartitionError::InvalidTerm { .. }))
        ));
        let narrow = built(RollbackQuotientDomain::new(term(3), &[term(0)], &partition).unwrap());
        assert_eq!(
            narrow.state(DomainAction::Existing(term(1))),
            Err(DomainError::UnknownTarget { target: term(1) })
        );
        assert!(matches!(
            first.reconcile(&Partition::new(5).unwrap(), 0),
            Err(DomainError::PartitionTermCountMismatch {
                domain_terms: 4,
                partition_terms: 5
            })
        ));

        first
            .prune(DomainAction::Existing(term(0)), &partition, 1, reason(1))
            .unwrap();
        let discarded = first.snapshot();
        first
            .prune(DomainAction::Existing(term(1)), &partition, 1, reason(2))
            .unwrap();
        let future = first.snapshot();
        first.rollback(root).unwrap();
        assert_eq!(
            first.rollback(future),
            Err(DomainError::InvalidSnapshot(
                DomainSnapshotError::FutureState
            ))
        );
        first
            .prune(DomainAction::Existing(term(2)), &partition, 1, reason(3))
            .unwrap();
        assert_eq!(first.snapshot().depth(), discarded.depth());
        assert_eq!(
            first.rollback(discarded),
            Err(DomainError::InvalidSnapshot(
                DomainSnapshotError::DiscardedBranch
            ))
        );
        first.validate().unwrap();
    }

    #[test]
    fn every_cap_abstains_without_mutating_domain_state() {
        let partition = Partition::new(4).unwrap();
        let construction_caps = DomainCaps {
            max_targets: 2,
            ..DomainCaps::default()
        };
        assert!(matches!(
            RollbackQuotientDomain::with_caps(
                term(3),
                &[term(0), term(1), term(2)],
                &partition,
                construction_caps
            )
            .unwrap(),
            DomainBuildOutcome::Abstained(DomainAbstention {
                resource: DomainResource::Targets,
                attempted: 3,
                limit: 2
            })
        ));

        let caps = DomainCaps {
            max_targets: 3,
            max_reconcile_work: 2,
            max_prunings_per_transaction: 0,
            max_transactions: 0,
        };
        let mut domain = built(
            RollbackQuotientDomain::with_caps(
                term(3),
                &[term(0), term(1), term(2)],
                &partition,
                caps,
            )
            .unwrap(),
        );
        let initial_entries = entries(&domain);
        let initial_snapshot = domain.snapshot();
        let initial_time = domain.next_prune_time();
        assert!(matches!(
            domain
                .prune(DomainAction::Existing(term(0)), &partition, 1, reason(1))
                .unwrap(),
            DomainMutation::Abstained(DomainAbstention {
                resource: DomainResource::Prunings,
                ..
            })
        ));

        let mut changed_partition = Partition::new(4).unwrap();
        changed_partition
            .merge(term(0), term(1), partition_reason(1))
            .unwrap();
        assert!(matches!(
            domain.reconcile(&changed_partition, 1).unwrap(),
            DomainMutation::Abstained(DomainAbstention {
                resource: DomainResource::ReconcileWork,
                ..
            })
        ));
        assert_eq!(entries(&domain), initial_entries);
        assert_eq!(domain.snapshot(), initial_snapshot);
        assert_eq!(domain.next_prune_time(), initial_time);

        let transaction_caps = DomainCaps {
            max_targets: 3,
            max_reconcile_work: 9,
            max_prunings_per_transaction: 3,
            max_transactions: 0,
        };
        let mut transaction_domain = built(
            RollbackQuotientDomain::with_caps(
                term(3),
                &[term(0), term(1), term(2)],
                &partition,
                transaction_caps,
            )
            .unwrap(),
        );
        let before = entries(&transaction_domain);
        assert!(matches!(
            transaction_domain
                .prune(DomainAction::Existing(term(0)), &partition, 1, reason(1))
                .unwrap(),
            DomainMutation::Abstained(DomainAbstention {
                resource: DomainResource::Transactions,
                ..
            })
        ));
        assert_eq!(entries(&transaction_domain), before);
        assert_eq!(transaction_domain.next_prune_time(), 1);
    }

    fn restricted_growth_partitions(size: usize) -> Vec<Vec<usize>> {
        fn extend(prefix: &mut Vec<usize>, size: usize, maximum: usize, out: &mut Vec<Vec<usize>>) {
            if prefix.len() == size {
                out.push(prefix.clone());
                return;
            }
            for label in 0..=maximum + 1 {
                prefix.push(label);
                extend(prefix, size, maximum.max(label), out);
                prefix.pop();
            }
        }

        if size == 0 {
            return vec![Vec::new()];
        }
        let mut out = Vec::new();
        let mut prefix = vec![0];
        extend(&mut prefix, size, 0, &mut out);
        out
    }

    fn apply_target_partition(partition: &mut Partition, labels: &[usize], reverse: bool) {
        let maximum = labels.iter().copied().max().unwrap_or(0);
        for label in 0..=maximum {
            let mut block = labels
                .iter()
                .enumerate()
                .filter_map(|(index, &candidate)| {
                    (candidate == label).then_some(term(index as u32))
                })
                .collect::<Vec<_>>();
            if reverse {
                block.reverse();
            }
            if let Some((&anchor, rest)) = block.split_first() {
                for &member in rest {
                    partition
                        .merge(anchor, member, partition_reason(1_000 + label as u64))
                        .unwrap();
                }
            }
        }
    }

    fn canonical_targets(labels: &[usize]) -> Vec<TermId> {
        let mut representatives = BTreeMap::<usize, TermId>::new();
        for (index, &label) in labels.iter().enumerate() {
            representatives.entry(label).or_insert(term(index as u32));
        }
        representatives.into_values().collect()
    }

    fn oracle_allowed(
        labels: &[usize],
        prune_mask: usize,
        separated: &BTreeSet<TermId>,
    ) -> BTreeSet<DomainAction> {
        let mut group_allowed = BTreeMap::<usize, bool>::new();
        let mut group_representative = BTreeMap::<usize, TermId>::new();
        for (index, &label) in labels.iter().enumerate() {
            group_representative
                .entry(label)
                .or_insert(term(index as u32));
            let member_allowed = prune_mask & (1 << index) == 0;
            group_allowed
                .entry(label)
                .and_modify(|allowed| *allowed &= member_allowed)
                .or_insert(member_allowed);
        }
        let mut result = BTreeSet::new();
        for (label, is_allowed) in group_allowed {
            let representative = group_representative[&label];
            if is_allowed && !separated.contains(&representative) {
                result.insert(DomainAction::Existing(representative));
            }
        }
        if prune_mask & (1 << labels.len()) == 0 {
            result.insert(DomainAction::Fresh);
        }
        result
    }

    fn expected_status(actions: &BTreeSet<DomainAction>) -> DomainStatus {
        match actions.len() {
            0 => DomainStatus::Empty,
            1 => DomainStatus::Unit(*actions.first().unwrap()),
            remaining => DomainStatus::Open { remaining },
        }
    }

    fn apply_separations(
        partition: &mut Partition,
        representatives: &[TermId],
        mask: usize,
    ) -> BTreeSet<TermId> {
        let mut separated = BTreeSet::new();
        for (index, &target) in representatives.iter().enumerate() {
            if mask & (1 << index) != 0 {
                partition
                    .separate(
                        term(3),
                        target,
                        partition_reason(2_000 + target.raw() as u64),
                    )
                    .unwrap();
                separated.insert(target);
            }
        }
        separated
    }

    #[test]
    fn exhaustive_four_term_domains_match_btree_oracle_across_rollback_branches() {
        let partitions = restricted_growth_partitions(3);
        assert_eq!(partitions.len(), 5);
        for labels in partitions {
            let representatives = canonical_targets(&labels);
            for prune_mask in 0..(1 << 4) {
                for separation_mask in 0..(1 << representatives.len()) {
                    let mut partition = Partition::new(4).unwrap();
                    let mut domain = domain(&partition);
                    let partition_root: PartitionSnapshot = partition.snapshot();
                    let domain_root = domain.snapshot();

                    for index in 0..3 {
                        if prune_mask & (1 << index) != 0 {
                            domain
                                .prune(
                                    DomainAction::Existing(term(index as u32)),
                                    &partition,
                                    1,
                                    reason(10 + index as u64),
                                )
                                .unwrap();
                        }
                    }
                    if prune_mask & (1 << 3) != 0 {
                        domain
                            .prune(DomainAction::Fresh, &partition, 1, reason(13))
                            .unwrap();
                    }
                    let before_merge_partition = partition.snapshot();
                    let before_merge_domain = domain.snapshot();

                    apply_target_partition(&mut partition, &labels, false);
                    let separated =
                        apply_separations(&mut partition, &representatives, separation_mask);
                    let first_mutation = domain.reconcile(&partition, 2).unwrap();
                    let expected = oracle_allowed(&labels, prune_mask, &separated);
                    assert_eq!(allowed(&domain), expected);
                    assert_eq!(domain.status(), expected_status(&expected));
                    domain.validate().unwrap();
                    let first_branch = domain.snapshot();

                    domain.rollback(before_merge_domain).unwrap();
                    partition.rollback(before_merge_partition).unwrap();
                    apply_target_partition(&mut partition, &labels, true);
                    let separated =
                        apply_separations(&mut partition, &representatives, separation_mask);
                    domain.reconcile(&partition, 2).unwrap();
                    let expected = oracle_allowed(&labels, prune_mask, &separated);
                    assert_eq!(allowed(&domain), expected);
                    assert_eq!(domain.status(), expected_status(&expected));
                    domain.validate().unwrap();

                    if matches!(first_mutation, DomainMutation::Changed(_)) {
                        assert_eq!(
                            domain.rollback(first_branch),
                            Err(DomainError::InvalidSnapshot(
                                DomainSnapshotError::DiscardedBranch
                            ))
                        );
                    }
                    domain.rollback(domain_root).unwrap();
                    partition.rollback(partition_root).unwrap();
                    assert_eq!(
                        allowed(&domain),
                        BTreeSet::from([
                            DomainAction::Existing(term(0)),
                            DomainAction::Existing(term(1)),
                            DomainAction::Existing(term(2)),
                            DomainAction::Fresh,
                        ])
                    );
                    assert_eq!(domain.status(), DomainStatus::Open { remaining: 4 });
                    domain.validate().unwrap();
                }
            }
        }
    }
}
