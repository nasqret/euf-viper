#![forbid(unsafe_code)]

//! Rollback equality partitions with explicit disequality constraints.
//!
//! The implementation deliberately does not use path compression: every
//! parent change is therefore local to a successful merge and can be undone
//! exactly. Roots are selected by class size, while the public canonical
//! representative of a class is always its minimum [`TermId`]. Disequality
//! edges are stored symmetrically between current roots and are rewired when
//! roots merge.
//!
//! All APIs which accept a term or snapshot are checked. A rejected merge,
//! separation, or rollback leaves the partition unchanged.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use rustc_hash::FxHashMap;
#[path="group_rows.rs"] mod group_rows;
pub(crate) use group_rows::GroupRowsStats;
#[path="virtual_adjacency.rs"] mod virtual_adjacency;
#[path="single_audit.rs"] mod single_audit;
pub(crate) use virtual_adjacency::VirtualAdjacencyStats;
#[cfg(test)]
#[path="virtual_adjacency_tests.rs"] mod virtual_adjacency_tests;

pub const MAX_TERMS: u64 = u32::MAX as u64 + 1;
static NEXT_PARTITION_ID: AtomicU64 = AtomicU64::new(1);

/// A stable identifier in a partition's fixed term universe.
///
/// `TermId` is intentionally independent of the crate's parser or term arena.
/// A partition checks every ID against its own term count before indexing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TermId(u32);

impl TermId {
    pub const MIN: Self = Self(0);
    pub const MAX: Self = Self(u32::MAX);

    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

impl From<u32> for TermId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<TermId> for u32 {
    fn from(value: TermId) -> Self {
        value.0
    }
}

impl TryFrom<usize> for TermId {
    type Error = TermIdOverflow;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        u32::try_from(value)
            .map(Self)
            .map_err(|_| TermIdOverflow { value })
    }
}

impl fmt::Display for TermId {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(output)
    }
}

/// Failure to represent a host-sized index as a stable [`TermId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TermIdOverflow {
    pub value: usize,
}

impl fmt::Display for TermIdOverflow {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "term index {} exceeds u32::MAX", self.value)
    }
}

impl Error for TermIdOverflow {}

/// An opaque caller-supplied reason for a merge or separation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReasonId(u64);

impl ReasonId {
    pub const MIN: Self = Self(0);
    pub const MAX: Self = Self(u64::MAX);

    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl From<u64> for ReasonId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<ReasonId> for u64 {
    fn from(value: ReasonId) -> Self {
        value.0
    }
}

impl fmt::Display for ReasonId {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(output)
    }
}

/// Three-valued truth of an equality or disequality literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TruthValue {
    True,
    False,
    Unknown,
}

pub type QueryTruth = TruthValue;
pub type Truth = TruthValue;

impl TruthValue {
    pub const fn negate(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }

    pub const fn is_decided(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// The known relation between two terms in a partial partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Relation {
    Equal,
    Disequal,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProspectiveMergeIncidenceResource {
    NeighborClasses,
    Terms,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProspectiveMergeIncidenceOutcome {
    Complete {
        kept: TermId,
        terms: Vec<TermId>,
    },
    LimitExceeded {
        resource: ProspectiveMergeIncidenceResource,
        attempted: usize,
        limit: usize,
    },
}

/// The original endpoints and reason of a structural equality merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MergeRecord {
    pub left: TermId,
    pub right: TermId,
    pub reason: ReasonId,
}

/// The original endpoints and reason of an explicit disequality assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeparationRecord {
    pub left: TermId,
    pub right: TermId,
    pub reason: ReasonId,
}

/// A quotient class in canonical minimum-term order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalClass {
    pub representative: TermId,
    pub members: Vec<TermId>,
}

impl CanonicalClass {
    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

/// A canonical pair of classes with all active explicit witnesses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisequalityEdge {
    pub left: TermId,
    pub right: TermId,
    pub witnesses: Vec<SeparationRecord>,
}

impl DisequalityEdge {
    pub fn reasons(&self) -> impl ExactSizeIterator<Item = ReasonId> + '_ {
        self.witnesses.iter().map(|record| record.reason)
    }
}

/// An opaque rollback point tied to one partition and one history lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Snapshot {
    partition_id: u64,
    trail_len: usize,
    state_id: u64,
}

impl Snapshot {
    pub const fn depth(self) -> usize {
        self.trail_len
    }
}

/// Result of requesting an equality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeOutcome {
    Merged { representative: TermId, size: usize },
    AlreadyEqual { representative: TermId, size: usize },
}

impl MergeOutcome {
    pub const fn changed(self) -> bool {
        matches!(self, Self::Merged { .. })
    }

    pub const fn representative(self) -> TermId {
        match self {
            Self::Merged { representative, .. } | Self::AlreadyEqual { representative, .. } => {
                representative
            }
        }
    }

    pub const fn size(self) -> usize {
        match self {
            Self::Merged { size, .. } | Self::AlreadyEqual { size, .. } => size,
        }
    }
}

/// Result of requesting an explicit disequality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeparationOutcome {
    Added { relation_was_known: bool },
    AlreadyPresent,
}

impl SeparationOutcome {
    pub const fn changed(self) -> bool {
        matches!(self, Self::Added { .. })
    }

    pub const fn relation_was_known(self) -> bool {
        match self {
            Self::Added { relation_was_known } => relation_was_known,
            Self::AlreadyPresent => true,
        }
    }
}

/// A rejected assertion together with the reasons already in the state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conflict {
    EqualityAgainstDisequality {
        equality: MergeRecord,
        separations: Vec<SeparationRecord>,
    },
    DisequalityAgainstEquality {
        separation: SeparationRecord,
        equality_reasons: Vec<ReasonId>,
    },
}

impl fmt::Display for Conflict {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EqualityAgainstDisequality {
                equality,
                separations,
            } => write!(
                output,
                "equality {} = {} (reason {}) contradicts {} explicit separation(s)",
                equality.left,
                equality.right,
                equality.reason,
                separations.len()
            ),
            Self::DisequalityAgainstEquality {
                separation,
                equality_reasons,
            } => write!(
                output,
                "disequality {} != {} (reason {}) contradicts equality supported by {} reason(s)",
                separation.left,
                separation.right,
                separation.reason,
                equality_reasons.len()
            ),
        }
    }
}

/// Why a snapshot cannot be used with the current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotError {
    ForeignPartition,
    FutureState,
    DiscardedBranch,
}

/// Checked partition operation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionError {
    InvalidTerm { term: TermId, term_count: usize },
    TooManyTerms { requested: usize, maximum: u64 },
    AllocationFailed,
    PartitionIdExhausted,
    StateIdExhausted,
    InvalidSnapshot(SnapshotError),
    Conflict(Conflict),
    InvariantViolation(&'static str),
}

impl fmt::Display for PartitionError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTerm { term, term_count } => {
                write!(output, "term {term} is outside 0..{term_count}")
            }
            Self::TooManyTerms { requested, maximum } => write!(
                output,
                "partition requested {requested} terms, maximum is {maximum}"
            ),
            Self::AllocationFailed => write!(output, "partition allocation failed"),
            Self::PartitionIdExhausted => write!(output, "partition ID space exhausted"),
            Self::StateIdExhausted => write!(output, "partition state ID space exhausted"),
            Self::InvalidSnapshot(SnapshotError::ForeignPartition) => {
                write!(output, "snapshot belongs to a different partition")
            }
            Self::InvalidSnapshot(SnapshotError::FutureState) => {
                write!(output, "snapshot is newer than the current state")
            }
            Self::InvalidSnapshot(SnapshotError::DiscardedBranch) => {
                write!(output, "snapshot belongs to a discarded history branch")
            }
            Self::Conflict(conflict) => conflict.fmt(output),
            Self::InvariantViolation(message) => {
                write!(output, "partition invariant violation: {message}")
            }
        }
    }
}

impl Error for PartitionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

pub type PartitionResult<T> = Result<T, PartitionError>;

type EdgeId = u64;
type Adjacency = BTreeMap<usize, BTreeSet<EdgeId>>;

#[derive(Debug, Clone)]
struct TrailEntry {
    state_id: u64,
    undo: Undo,
}

#[derive(Debug, Clone)]
enum Undo {
    Merge {
        kept: usize,
        removed: usize,
        kept_size: usize,
        kept_minimum: TermId,
        kept_adjacency: Adjacency,
        removed_adjacency: Adjacency,
        record: MergeRecord,
    },
    Separation {
        left_root: usize,
        right_root: usize,
        edge_id: EdgeId,
        record: SeparationRecord,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HistoricalUnionLabel {
    merge_index: usize,
    trail_index: usize,
}

/// A checked rollback equality partition over a fixed set of terms.
///
/// The type is not `Clone`: snapshots are meaningful only for the unique
/// history that created them.
#[derive(Debug)]
pub struct Partition {
    partition_id: u64,
    parent: Vec<usize>,
    historical_union_labels: Option<Vec<Option<HistoricalUnionLabel>>>,
    size: Vec<usize>,
    minimum: Vec<TermId>,
    next_member: Vec<usize>,
    disequalities: Vec<Adjacency>,
    classes: usize,
    merge_records: Vec<MergeRecord>,
    separation_records: FxHashMap<EdgeId, SeparationRecord>,
    group_rows: group_rows::Slot,
    virtual_rows: virtual_adjacency::Slot,
    single_audit: std::sync::OnceLock<Box<single_audit::Observer>>,
    trail: Vec<TrailEntry>,
    next_state_id: u64,
}

pub type RollbackPartition = Partition;
pub type EqualityPartition = Partition;

/// Reuses adjacency checks only across this token's checked insertions.
/// Any other partition mutation starts a new validation epoch.
#[derive(Debug)]
pub(crate) struct CheckedSeparationBatch {
    snapshot: Snapshot,
    next_state_id: u64,
    representation_stamp: u8,
    epoch: u64,
    checked_roots: Vec<u64>,
}

impl CheckedSeparationBatch {
    fn synchronize(&mut self, partition: &Partition) -> PartitionResult<()> {
        if self.snapshot.partition_id != partition.partition_id
            || self.checked_roots.len() != partition.term_count()
        {
            return Err(PartitionError::InvariantViolation(
                "checked separation batch belongs to another partition",
            ));
        }
        if self.snapshot != partition.snapshot() || self.next_state_id != partition.next_state_id
            || self.representation_stamp != partition.virtual_rows.stamp() {
            if let Some(epoch) = self.epoch.checked_add(1) {
                self.epoch = epoch;
            } else {
                self.checked_roots.fill(0);
                self.epoch = 1;
            }
            self.bind(partition);
        }
        Ok(())
    }

    fn check_root(&mut self, partition: &Partition, root: usize) -> PartitionResult<()> {
        let checked =
            self.checked_roots
                .get_mut(root)
                .ok_or(PartitionError::InvariantViolation(
                    "checked separation root is out of range",
                ))?;
        if let Some(o)=partition.single_audit.get(){o.batch(*checked==self.epoch,partition.has_virtual_adjacency())}
        if *checked != self.epoch {
            partition.check_root_adjacency(root)?;
            *checked = self.epoch;
        }
        Ok(())
    }

    fn bind(&mut self, partition: &Partition) {
        self.snapshot = partition.snapshot();
        self.next_state_id = partition.next_state_id;
        self.representation_stamp = partition.virtual_rows.stamp();
    }
}

impl Partition {
    /// Constructs an identity partition containing `term_count` stable terms.
    pub fn new(term_count: usize) -> PartitionResult<Self> {
        Self::try_new(term_count)
    }

    /// Fallible constructor; equivalent to [`Partition::new`].
    pub fn try_new(term_count: usize) -> PartitionResult<Self> {
        Self::with_historical_union_index(term_count, false)
    }

    pub(crate) fn with_historical_union_index(
        term_count: usize,
        enabled: bool,
    ) -> PartitionResult<Self> {
        let requested = u64::try_from(term_count).map_err(|_| PartitionError::TooManyTerms {
            requested: term_count,
            maximum: MAX_TERMS,
        })?;
        if requested > MAX_TERMS {
            return Err(PartitionError::TooManyTerms {
                requested: term_count,
                maximum: MAX_TERMS,
            });
        }

        let mut parent = Vec::new();
        let mut size = Vec::new();
        let mut minimum = Vec::new();
        let mut next_member = Vec::new();
        let mut disequalities = Vec::new();
        parent
            .try_reserve_exact(term_count)
            .map_err(|_| PartitionError::AllocationFailed)?;
        size.try_reserve_exact(term_count)
            .map_err(|_| PartitionError::AllocationFailed)?;
        minimum
            .try_reserve_exact(term_count)
            .map_err(|_| PartitionError::AllocationFailed)?;
        next_member
            .try_reserve_exact(term_count)
            .map_err(|_| PartitionError::AllocationFailed)?;
        disequalities
            .try_reserve_exact(term_count)
            .map_err(|_| PartitionError::AllocationFailed)?;
        let historical_union_labels = if enabled {
            let mut labels = Vec::new();
            labels
                .try_reserve_exact(term_count)
                .map_err(|_| PartitionError::AllocationFailed)?;
            labels.resize(term_count, None);
            Some(labels)
        } else {
            None
        };

        for index in 0..term_count {
            let term = TermId::try_from(index).map_err(|_| PartitionError::TooManyTerms {
                requested: term_count,
                maximum: MAX_TERMS,
            })?;
            parent.push(index);
            size.push(1);
            minimum.push(term);
            next_member.push(index);
            disequalities.push(BTreeMap::new());
        }

        let partition_id = NEXT_PARTITION_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| PartitionError::PartitionIdExhausted)?;

        Ok(Self {
            partition_id,
            parent,
            historical_union_labels,
            size,
            minimum,
            next_member,
            disequalities,
            classes: term_count,
            merge_records: Vec::new(),
            separation_records: FxHashMap::default(),
            group_rows: group_rows::Slot::default(),
            virtual_rows: virtual_adjacency::Slot::default(),
            single_audit: std::sync::OnceLock::new(),
            trail: Vec::new(),
            next_state_id: 1,
        })
    }

    pub fn term_count(&self) -> usize {
        self.parent.len()
    }

    pub(crate) fn checked_separation_batch(&self) -> PartitionResult<CheckedSeparationBatch> {
        let mut checked_roots = Vec::new();
        checked_roots
            .try_reserve_exact(self.term_count())
            .map_err(|_| PartitionError::AllocationFailed)?;
        checked_roots.resize(self.term_count(), 0);
        Ok(CheckedSeparationBatch {
            snapshot: self.snapshot(),
            next_state_id: self.next_state_id,
            representation_stamp: self.virtual_rows.stamp(),
            epoch: 1,
            checked_roots,
        })
    }

    pub(crate) fn has_historical_union_index(&self) -> bool {
        self.historical_union_labels.is_some()
    }

    /// Returns a parent link in an active merge prefix, not a snapshot token.
    /// Callers must validate snapshot lineage before choosing the cutoff.
    pub(crate) fn historical_union_link(
        &self,
        term: TermId,
        merge_cutoff: usize,
    ) -> PartitionResult<Option<(TermId, usize)>> {
        let index = self.term_index(term)?;
        if merge_cutoff > self.merge_records.len() {
            return Err(PartitionError::InvariantViolation(
                "historical union cutoff exceeds active merges",
            ));
        }
        let labels =
            self.historical_union_labels
                .as_ref()
                .ok_or(PartitionError::InvariantViolation(
                    "historical union index is unavailable",
                ))?;
        if labels.len() != self.term_count() {
            return Err(PartitionError::InvariantViolation(
                "historical union index has the wrong term count",
            ));
        }
        let parent = self.parent[index];
        if parent >= self.term_count() {
            return Err(PartitionError::InvariantViolation(
                "historical union parent is out of range",
            ));
        }
        if parent == index {
            if labels[index].is_some() {
                return Err(PartitionError::InvariantViolation(
                    "historical union root has a label",
                ));
            }
            return Ok(None);
        }
        let label = labels[index].ok_or(PartitionError::InvariantViolation(
            "historical union parent is missing its label",
        ))?;
        let record =
            self.merge_records
                .get(label.merge_index)
                .ok_or(PartitionError::InvariantViolation(
                    "historical union label references no merge",
                ))?;
        let entry = self
            .trail
            .get(label.trail_index)
            .ok_or(PartitionError::InvariantViolation(
                "historical union label references no undo entry",
            ))?;
        if !matches!(
            &entry.undo,
            Undo::Merge { kept, removed, record: recorded, .. }
                if *kept == parent && *removed == index && recorded == record
        ) {
            return Err(PartitionError::InvariantViolation(
                "historical union label differs from its undo entry",
            ));
        }
        if self.parent[parent] == parent {
            if labels[parent].is_some() {
                return Err(PartitionError::InvariantViolation(
                    "historical union root has a label",
                ));
            }
        } else if !labels[parent].is_some_and(|next| {
            next.merge_index > label.merge_index && next.trail_index > label.trail_index
        }) {
            return Err(PartitionError::InvariantViolation(
                "historical union labels do not strictly increase toward the root",
            ));
        }
        if label.merge_index >= merge_cutoff {
            return Ok(None);
        }
        Ok(Some((self.term_from_index(parent)?, label.merge_index)))
    }

    pub fn len(&self) -> usize {
        self.term_count()
    }

    pub fn is_empty(&self) -> bool {
        self.parent.is_empty()
    }

    pub fn class_count(&self) -> usize {
        self.classes
    }

    pub fn merge_count(&self) -> usize {
        self.merge_records.len()
    }

    /// Number of active explicit separation assertions, including distinct
    /// reasons which currently induce the same class edge.
    pub fn separation_count(&self) -> usize {
        self.separation_records.len()+self.group_rows.storage().map_or(0,|c|c.live())
    }

    /// Number of active merge and separation updates in rollback order.
    pub fn update_count(&self) -> usize {
        self.trail.len()
    }

    /// Stable endpoints of every active update after `depth`, in trail order.
    /// This is a read-only invalidation aid; it exposes neither union roots nor
    /// mutable rollback internals.
    pub fn update_endpoints_since(&self, depth: usize) -> PartitionResult<Vec<(TermId, TermId)>> {
        let Some(suffix) = self.trail.get(depth..) else {
            return Err(PartitionError::InvalidSnapshot(SnapshotError::FutureState));
        };
        let mut endpoints = Vec::new();
        endpoints
            .try_reserve_exact(suffix.len())
            .map_err(|_| PartitionError::AllocationFailed)?;
        for entry in suffix {
            let pair = match &entry.undo {
                Undo::Merge { record, .. } => (record.left, record.right),
                Undo::Separation { record, .. } => (record.left, record.right),
            };
            endpoints.push(pair);
        }
        Ok(endpoints)
    }

    /// Number of distinct current class-to-class disequality edges.
    pub fn disequality_edge_count(&self) -> PartitionResult<usize> {
        if self.disequalities.len() != self.term_count() {
            return Err(PartitionError::InvariantViolation("wrong adjacency universe"));
        }
        let mut directed = 0usize;
        for (root, adjacency) in self.disequalities.iter().enumerate() {
            if self.parent.get(root).copied() != Some(root) {
                if !adjacency.is_empty() || self.virtual_member(root) {
                    return Err(PartitionError::InvariantViolation("non-root has disequality adjacency"));
                }
                continue;
            }
            directed =
                directed
                    .checked_add(self.checked_root_degree(root)?)
                    .ok_or(PartitionError::InvariantViolation(
                        "disequality edge count overflow",
                    ))?;
        }
        if directed % 2 != 0 {
            return Err(PartitionError::InvariantViolation(
                "disequality adjacency is not symmetric",
            ));
        }
        Ok(directed / 2)
    }

    /// Returns the canonical representatives of every class currently known
    /// disequal to `term`'s class. The result is independent of union roots and
    /// sorted by stable minimum-term representative.
    pub fn disequal_class_representatives(&self, term: TermId) -> PartitionResult<Vec<TermId>> {
        self.single_representatives(term,None)
    }

    pub(crate) fn single_representatives(&self,term:TermId,mut impact:Option<&mut single_audit::Impact<'_>>)
        ->PartitionResult<Vec<TermId>> {
        let root = self.root_of_term(term)?;
        let degree = self.checked_root_degree(root)?;
        if let Some(i)=impact.as_deref_mut(){i.success(root,false)}
        let mut representatives = Vec::new();
        representatives
            .try_reserve_exact(degree)
            .map_err(|_| PartitionError::AllocationFailed)?;
        for neighbor_root in self.logical_neighbors(root)? {
            if self.parent.get(neighbor_root).copied() != Some(neighbor_root) {
                return Err(PartitionError::InvariantViolation(
                    "disequality adjacency names a non-root class",
                ));
            }
            self.check_root_adjacency(neighbor_root)?;
            if let Some(i)=impact.as_deref_mut(){i.success(neighbor_root,true)}
            representatives.push(*self.minimum.get(neighbor_root).ok_or(
                PartitionError::InvariantViolation(
                    "disequality neighbor has no canonical representative",
                ),
            )?);
        }
        representatives.sort_unstable();
        representatives.dedup();
        if representatives.len() != degree {
            return Err(PartitionError::InvariantViolation(
                "distinct disequality neighbors share a representative",
            ));
        }
        Ok(representatives)
    }

    pub fn contains_term(&self, term: TermId) -> bool {
        usize::try_from(term.raw())
            .ok()
            .is_some_and(|index| index < self.term_count())
    }

    /// Captures the current rollback point in O(1).
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            partition_id: self.partition_id,
            trail_len: self.trail.len(),
            state_id: self.trail.last().map_or(0, |entry| entry.state_id),
        }
    }

    pub fn checkpoint(&self) -> Snapshot {
        self.snapshot()
    }

    /// Restores an ancestor snapshot and returns the number of undone updates.
    pub fn rollback(&mut self, snapshot: Snapshot) -> PartitionResult<usize> {
        self.validate_snapshot(snapshot)?;
        debug_assert!(self.validate().is_ok());

        let undone = self.trail.len() - snapshot.trail_len;
        if undone != 0 && self.virtual_rows.active() {
            self.materialize_virtual(virtual_adjacency::Trigger::Rollback)?;
        }
        while self.trail.len() > snapshot.trail_len {
            self.undo_last()?;
        }
        debug_assert!(self.validate().is_ok());
        Ok(undone)
    }

    pub fn rollback_to(&mut self, snapshot: Snapshot) -> PartitionResult<usize> {
        self.rollback(snapshot)
    }

    /// Returns the canonical minimum-term representative.
    pub fn representative(&self, term: TermId) -> PartitionResult<TermId> {
        let root = self.root_of_term(term)?;
        self.minimum
            .get(root)
            .copied()
            .ok_or(PartitionError::InvariantViolation(
                "root has no canonical minimum",
            ))
    }

    pub fn canonical_representative(&self, term: TermId) -> PartitionResult<TermId> {
        self.representative(term)
    }

    pub fn class_size(&self, term: TermId) -> PartitionResult<usize> {
        let root = self.root_of_term(term)?;
        self.size
            .get(root)
            .copied()
            .ok_or(PartitionError::InvariantViolation("root has no class size"))
    }

    pub fn class_members(&self, term: TermId) -> PartitionResult<Vec<TermId>> {
        let wanted_root = self.root_of_term(term)?;
        let class_size = *self
            .size
            .get(wanted_root)
            .ok_or(PartitionError::InvariantViolation("root has no class size"))?;
        let mut members = Vec::new();
        members
            .try_reserve_exact(class_size)
            .map_err(|_| PartitionError::AllocationFailed)?;
        let mut current = wanted_root;
        for _ in 0..class_size {
            members.push(self.term_from_index(current)?);
            current = *self
                .next_member
                .get(current)
                .ok_or(PartitionError::InvariantViolation(
                    "class member link is out of range",
                ))?;
        }
        if current != wanted_root {
            return Err(PartitionError::InvariantViolation(
                "class member cycle does not match the stored class size",
            ));
        }
        Ok(members)
    }

    pub(crate) fn append_class_members(
        &self,
        term: TermId,
        members: &mut Vec<TermId>,
    ) -> PartitionResult<usize> {
        let wanted_root = self.root_of_term(term)?;
        let class_size = *self
            .size
            .get(wanted_root)
            .ok_or(PartitionError::InvariantViolation("root has no class size"))?;
        members
            .try_reserve(class_size)
            .map_err(|_| PartitionError::AllocationFailed)?;
        let original_len = members.len();
        let result =
            (|| {
                let mut current = wanted_root;
                for index in 0..class_size {
                    members.push(self.term_from_index(current)?);
                    current = *self.next_member.get(current).ok_or(
                        PartitionError::InvariantViolation("class member link is out of range"),
                    )?;
                    if current == wanted_root && index + 1 != class_size {
                        return Err(PartitionError::InvariantViolation(
                            "class member cycle does not match the stored class size",
                        ));
                    }
                }
                if current != wanted_root {
                    return Err(PartitionError::InvariantViolation(
                        "class member cycle does not match the stored class size",
                    ));
                }
                Ok(class_size)
            })();
        if result.is_err() {
            members.truncate(original_len);
        }
        result
    }

    pub(crate) fn class_members_by_scan(&self, term: TermId) -> PartitionResult<Vec<TermId>> {
        let wanted_root = self.root_of_term(term)?;
        let class_size = *self
            .size
            .get(wanted_root)
            .ok_or(PartitionError::InvariantViolation("root has no class size"))?;
        let mut members = Vec::with_capacity(class_size);
        for index in 0..self.term_count() {
            if self.root_index(index)? == wanted_root {
                members.push(self.term_from_index(index)?);
            }
        }
        Ok(members)
    }

    /// Returns a pre-merge incidence frontier for a currently distinct pair.
    /// Every relation changed by a successful merge has at least one endpoint
    /// in this set, so scanning source atoms incident to these terms is sound.
    pub(crate) fn prospective_merge_incidence_terms(
        &self,
        left: TermId,
        right: TermId,
        max_neighbor_classes: usize,
        max_terms: usize,
    ) -> PartitionResult<ProspectiveMergeIncidenceOutcome> {
        let left_root = self.root_of_term(left)?;
        let right_root = self.root_of_term(right)?;
        if left_root == right_root {
            return Ok(ProspectiveMergeIncidenceOutcome::Complete {
                kept: self.term_from_index(left_root)?,
                terms: Vec::new(),
            });
        }
        self.check_root_adjacency(left_root)?;
        self.check_root_adjacency(right_root)?;
        let (kept, removed) = self.choose_union_roots(left_root, right_root)?;
        let removed_size = *self
            .size
            .get(removed)
            .ok_or(PartitionError::InvariantViolation(
                "removed root has no class size",
            ))?;
        if removed_size > max_terms {
            return Ok(ProspectiveMergeIncidenceOutcome::LimitExceeded {
                resource: ProspectiveMergeIncidenceResource::Terms,
                attempted: removed_size,
                limit: max_terms,
            });
        }
        let mut terms = self.class_members(self.term_from_index(removed)?)?;
        let mut neighbor_classes = 0usize;
        for neighbor in self.logical_neighbors(removed)? {
            if neighbor == kept {
                continue;
            }
            neighbor_classes =
                neighbor_classes
                    .checked_add(1)
                    .ok_or(PartitionError::InvariantViolation(
                        "prospective merge neighbor count overflowed",
                    ))?;
            if neighbor_classes > max_neighbor_classes {
                return Ok(ProspectiveMergeIncidenceOutcome::LimitExceeded {
                    resource: ProspectiveMergeIncidenceResource::NeighborClasses,
                    attempted: neighbor_classes,
                    limit: max_neighbor_classes,
                });
            }
            let neighbor_size =
                *self
                    .size
                    .get(neighbor)
                    .ok_or(PartitionError::InvariantViolation(
                        "neighbor root has no class size",
                    ))?;
            let attempted = terms.len().checked_add(neighbor_size).ok_or(
                PartitionError::InvariantViolation("prospective merge frontier size overflowed"),
            )?;
            if attempted > max_terms {
                return Ok(ProspectiveMergeIncidenceOutcome::LimitExceeded {
                    resource: ProspectiveMergeIncidenceResource::Terms,
                    attempted,
                    limit: max_terms,
                });
            }
            terms
                .try_reserve(neighbor_size)
                .map_err(|_| PartitionError::AllocationFailed)?;
            self.append_class_members(self.term_from_index(neighbor)?, &mut terms)?;
        }
        terms.sort_unstable();
        terms.dedup();
        Ok(ProspectiveMergeIncidenceOutcome::Complete {
            kept: self.term_from_index(kept)?,
            terms,
        })
    }

    pub fn relation(&self, left: TermId, right: TermId) -> PartitionResult<Relation> {
        let left_root = self.root_of_term(left)?;
        let right_root = self.root_of_term(right)?;
        if left_root == right_root {
            return Ok(Relation::Equal);
        }
        if self.logical_ids(left_root, right_root)?.len() != 0 {
            Ok(Relation::Disequal)
        } else {
            Ok(Relation::Unknown)
        }
    }

    pub fn equality_truth(&self, left: TermId, right: TermId) -> PartitionResult<TruthValue> {
        Ok(match self.relation(left, right)? {
            Relation::Equal => TruthValue::True,
            Relation::Disequal => TruthValue::False,
            Relation::Unknown => TruthValue::Unknown,
        })
    }

    pub fn query_equality(&self, left: TermId, right: TermId) -> PartitionResult<TruthValue> {
        self.equality_truth(left, right)
    }

    pub fn disequality_truth(&self, left: TermId, right: TermId) -> PartitionResult<TruthValue> {
        Ok(self.equality_truth(left, right)?.negate())
    }

    pub fn query_disequality(&self, left: TermId, right: TermId) -> PartitionResult<TruthValue> {
        self.disequality_truth(left, right)
    }

    pub fn are_equal(&self, left: TermId, right: TermId) -> PartitionResult<bool> {
        Ok(matches!(self.relation(left, right)?, Relation::Equal))
    }

    pub fn are_disequal(&self, left: TermId, right: TermId) -> PartitionResult<bool> {
        Ok(matches!(self.relation(left, right)?, Relation::Disequal))
    }

    /// Returns a sound ordered path of merge reasons, or `None` if the terms
    /// are not equal. Reflexivity has an empty reason path.
    pub fn equality_reasons(
        &self,
        left: TermId,
        right: TermId,
    ) -> PartitionResult<Option<Vec<ReasonId>>> {
        let left_index = self.term_index(left)?;
        let right_index = self.term_index(right)?;
        if self.root_index(left_index)? != self.root_index(right_index)? {
            return Ok(None);
        }
        if left_index == right_index {
            return Ok(Some(Vec::new()));
        }

        let mut graph = Vec::<Vec<(usize, ReasonId)>>::new();
        graph
            .try_reserve_exact(self.term_count())
            .map_err(|_| PartitionError::AllocationFailed)?;
        graph.resize_with(self.term_count(), Vec::new);
        for record in &self.merge_records {
            let first = self.term_index(record.left)?;
            let second = self.term_index(record.right)?;
            graph[first].push((second, record.reason));
            graph[second].push((first, record.reason));
        }

        let mut predecessor = vec![None::<(usize, ReasonId)>; self.term_count()];
        let mut queue = VecDeque::new();
        predecessor[left_index] = Some((left_index, ReasonId::MIN));
        queue.push_back(left_index);
        while let Some(current) = queue.pop_front() {
            if current == right_index {
                break;
            }
            for &(next, reason) in &graph[current] {
                if predecessor[next].is_none() {
                    predecessor[next] = Some((current, reason));
                    queue.push_back(next);
                }
            }
        }

        if predecessor[right_index].is_none() {
            return Err(PartitionError::InvariantViolation(
                "equal terms have no merge-reason path",
            ));
        }
        let mut reasons = Vec::new();
        let mut current = right_index;
        while current != left_index {
            let (previous, reason) = predecessor[current].ok_or(
                PartitionError::InvariantViolation("broken merge-reason predecessor chain"),
            )?;
            reasons.push(reason);
            current = previous;
        }
        reasons.reverse();
        Ok(Some(reasons))
    }

    /// Returns all explicit assertions currently proving the terms disequal.
    pub fn separation_witnesses(
        &self,
        left: TermId,
        right: TermId,
    ) -> PartitionResult<Option<Vec<SeparationRecord>>> {
        let left_root = self.root_of_term(left)?;
        let right_root = self.root_of_term(right)?;
        if left_root == right_root {
            return Ok(None);
        }
        let edge_ids = self.logical_ids(left_root, right_root)?;
        if edge_ids.len() == 0 {
            return Ok(None);
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(edge_ids.len())
            .map_err(|_| PartitionError::AllocationFailed)?;
        for edge_id in edge_ids {
            records.push(self.checked_edge_record(left_root, right_root, edge_id)?.0);
        }
        Ok(Some(records))
    }

    pub(crate) fn minimum_separation_witness(
        &self,
        left: TermId,
        right: TermId,
    ) -> PartitionResult<Option<(SeparationRecord, bool)>> {
        let left_root = self.root_of_term(left)?;
        let right_root = self.root_of_term(right)?;
        if left_root == right_root {
            return Ok(None);
        }
        let mut minimum: Option<(SeparationRecord, bool)> = None;
        for edge_id in self.logical_ids(left_root, right_root)? {
            let (record, forward) = self.checked_edge_record(left_root, right_root, edge_id)?;
            if minimum.is_none_or(|(current, _)| {
                (record.reason, record.left, record.right)
                    < (current.reason, current.left, current.right)
            }) {
                minimum = Some((record, forward));
            }
        }
        Ok(minimum)
    }

    pub fn disequality_reasons(
        &self,
        left: TermId,
        right: TermId,
    ) -> PartitionResult<Option<Vec<ReasonId>>> {
        Ok(self
            .separation_witnesses(left, right)?
            .map(|records| records.into_iter().map(|record| record.reason).collect()))
    }

    pub fn merge_records(&self) -> &[MergeRecord] {
        &self.merge_records
    }

    pub fn separation_records(&self) -> Vec<SeparationRecord> {
        let mut records = self.row_entries()
            .collect::<Vec<_>>();
        records.sort_unstable_by_key(|&(edge_id, _)| edge_id);
        records.into_iter().map(|(_, record)| record).collect()
    }

    /// Enumerates classes by minimum term; members are in increasing term order.
    pub fn classes(&self) -> PartitionResult<Vec<CanonicalClass>> {
        let mut grouped = BTreeMap::<TermId, Vec<TermId>>::new();
        for index in 0..self.term_count() {
            let root = self.root_index(index)?;
            let representative =
                self.minimum
                    .get(root)
                    .copied()
                    .ok_or(PartitionError::InvariantViolation(
                        "root has no canonical minimum",
                    ))?;
            grouped
                .entry(representative)
                .or_default()
                .push(self.term_from_index(index)?);
        }

        let mut classes = Vec::new();
        classes
            .try_reserve_exact(grouped.len())
            .map_err(|_| PartitionError::AllocationFailed)?;
        for (representative, members) in grouped {
            if members.first().copied() != Some(representative) {
                return Err(PartitionError::InvariantViolation(
                    "stored canonical minimum is not the minimum class member",
                ));
            }
            classes.push(CanonicalClass {
                representative,
                members,
            });
        }
        if classes.len() != self.classes {
            return Err(PartitionError::InvariantViolation(
                "stored class count is incorrect",
            ));
        }
        Ok(classes)
    }

    pub fn canonical_classes(&self) -> PartitionResult<Vec<Vec<TermId>>> {
        Ok(self
            .classes()?
            .into_iter()
            .map(|class| class.members)
            .collect())
    }

    /// Enumerates current class disequalities by canonical endpoint pair.
    pub fn canonical_disequalities(&self) -> PartitionResult<Vec<DisequalityEdge>> {
        if self.disequalities.len() != self.term_count() || self.minimum.len() != self.term_count() {
            return Err(PartitionError::InvariantViolation("wrong adjacency universe"));
        }
        let mut result = BTreeMap::<(TermId, TermId), Vec<SeparationRecord>>::new();
        for left_root in 0..self.term_count() {
            if self.parent[left_root] != left_root {
                if !self.disequalities[left_root].is_empty() || self.virtual_member(left_root) {
                    return Err(PartitionError::InvariantViolation(
                        "non-root has disequality adjacency",
                    ));
                }
                continue;
            }
            self.check_root_adjacency(left_root)?;
            for right_root in self.logical_neighbors(left_root)? {
                if left_root >= right_root {
                    continue;
                }
                let pair = normalized_term_pair(self.minimum[left_root], self.minimum[right_root]);
                let edge_ids = self.logical_ids(left_root, right_root)?;
                let mut witnesses = Vec::new();
                witnesses
                    .try_reserve_exact(edge_ids.len())
                    .map_err(|_| PartitionError::AllocationFailed)?;
                for edge_id in edge_ids {
                    witnesses.push(self.checked_edge_record(left_root, right_root, edge_id)?.0);
                }
                if result.insert(pair, witnesses).is_some() {
                    return Err(PartitionError::InvariantViolation(
                        "duplicate canonical disequality pair",
                    ));
                }
            }
        }
        Ok(result
            .into_iter()
            .map(|((left, right), witnesses)| DisequalityEdge {
                left,
                right,
                witnesses,
            })
            .collect())
    }

    pub(crate) fn register_group_rows(&mut self,terms:&[TermId],bases:&[u32])->bool {
        #[cfg(all(test, feature = "fabric"))]
        if let Some(explicit) = crate::fabric::cadical_up::policy_ablation_review::forced() {
            return self.register_group_rows_with_representation(terms, bases, explicit);
        }
        self.register_rows_and_adjacency(terms,bases,None,None)
    }
    #[inline] fn row_singleton(&self,t:TermId)->bool{
        let i=t.index(); self.parent.get(i)==Some(&i) && self.size[i]==1
    }
    pub(crate) fn finish_group_rows(&mut self){self.group_rows.seal();}
    pub(crate) fn group_rows_has_atom(&self,atom:u32)->bool{
        self.group_rows.get().is_some_and(|c|c.has(atom))
    }
    pub(crate) fn group_rows_candidate_arity(&self,atom:u32)->Option<usize>{
        self.group_rows.get().and_then(|c|c.candidate_arity(atom))
    }
    pub(crate) fn group_rows_group_tracked_stats(&self)->Vec<(usize,usize)>{
        self.group_rows.get().map_or_else(Vec::new,|c|c.tracked_group_stats())
    }
    #[cfg(test)]
    pub(crate) fn register_group_rows_with_representation(&mut self,terms:&[TermId],bases:&[u32],explicit:bool)->bool{
        self.register_rows_and_adjacency(terms,bases,Some(explicit),None)
    }
    pub(crate) fn group_rows_accepts(&self,left:TermId,right:TermId,reason:ReasonId)->bool{
        self.group_rows.get().is_some_and(|c|c.accepts(self.next_state_id,SeparationRecord{left,right,reason},
            self.row_singleton(left) && self.row_singleton(right)))
    }
    pub(crate) fn group_rows_stats(&self)->GroupRowsStats{
        let mut s=GroupRowsStats{explicit_len:self.separation_records.len(),explicit_capacity:self.separation_records.capacity(),
            partition_slot_bytes:std::mem::size_of::<group_rows::Slot>(),explicit_backing_bytes:None,..Default::default()};
        if let Some(c)=self.group_rows.get(){c.add_stats(&mut s);} s
    }
    pub(crate) fn group_rows_group_stats(&self)->Vec<(usize,usize)>{
        self.group_rows.get().map_or_else(Vec::new,|c|c.group_stats())
    }
    #[inline] fn row_record(&self,id:&EdgeId)->Option<SeparationRecord>{
        if let Some(c)=self.group_rows.storage(){
            if let Some(r)=c.get(*id){return Some(r)}
        }
        self.separation_records.get(id).copied()
    }
    #[inline] fn row_exists(&self,id:EdgeId)->bool{
        self.group_rows.storage().is_some_and(|c|c.contains(id)) || self.separation_records.contains_key(&id)
    }
    fn row_entries(&self)->impl Iterator<Item=(EdgeId,SeparationRecord)>+'_ {
        self.separation_records.iter().map(|(&id,&r)|(id,r))
            .chain(self.group_rows.storage().into_iter().flat_map(|c|c.entries()))
    }
    fn row_insert(&mut self,edge_id:EdgeId,record:SeparationRecord)->bool{
        if self.group_rows.get().is_some(){
            let singleton=self.row_singleton(record.left) && self.row_singleton(record.right);
            let c=self.group_rows.get_mut().unwrap();
            if c.commit(edge_id,record,singleton) && !c.is_explicit(){return true}
        }
        self.separation_records.insert(edge_id, record);
        false
    }
    fn row_remove(&mut self,edge_id:EdgeId){
        if self.group_rows.get_mut().is_some_and(|c|c.remove(edge_id) && !c.is_explicit()){return}
        self.separation_records.remove(&edge_id);
    }

    /// Merges two classes unless an explicit disequality forbids it.
    pub fn merge(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
    ) -> PartitionResult<MergeOutcome> {
        let left_root = self.root_of_term(left)?;
        let right_root = self.root_of_term(right)?;
        if left_root == right_root {
            return Ok(MergeOutcome::AlreadyEqual {
                representative: self.minimum[left_root],
                size: self.size[left_root],
            });
        }

        if self.logical_ids(left_root, right_root)?.len() != 0 {
            let separations = self.separation_witnesses(left, right)?.ok_or(
                PartitionError::InvariantViolation("known disequality has no witnesses"),
            )?;
            return Err(PartitionError::Conflict(
                Conflict::EqualityAgainstDisequality {
                    equality: MergeRecord {
                        left,
                        right,
                        reason,
                    },
                    separations,
                },
            ));
        }

        self.check_root_adjacency(left_root)?;
        self.check_root_adjacency(right_root)?;
        let (kept, removed) = self.choose_union_roots(left_root, right_root)?;
        if let Some(labels) = &self.historical_union_labels {
            if labels.len() != self.term_count()
                || labels[kept].is_some()
                || labels[removed].is_some()
            {
                return Err(PartitionError::InvariantViolation(
                    "cannot merge inconsistent historical union roots",
                ));
            }
        }
        let kept_size = self.size[kept];
        let kept_minimum = self.minimum[kept];
        let new_size =
            kept_size
                .checked_add(self.size[removed])
                .ok_or(PartitionError::InvariantViolation(
                    "class size overflow during merge",
                ))?;
        let new_minimum = kept_minimum.min(self.minimum[removed]);
        let state_id = self.prepare_update(true)?;
        if self.virtual_rows.active() {
            let a = &self.disequalities[kept];
            let b = &self.disequalities[removed];
            // Only these maps and their direct neighbors participate in the rewrite.
            // Count shared keys twice; multiple witnesses behind one key cost one scan.
            const MAX_NEIGHBOR_KEYS: usize = 64;
            if self.virtual_member(kept) || self.virtual_member(removed)
                || a.len().saturating_add(b.len()) > MAX_NEIGHBOR_KEYS
                || a.keys().chain(b.keys()).any(|&root| self.virtual_member(root))
            {
                self.materialize_virtual(virtual_adjacency::Trigger::Merge)?;
            }
        }
        let kept_adjacency = self.disequalities[kept].clone();
        let removed_adjacency = std::mem::take(&mut self.disequalities[removed]);
        let record = MergeRecord {
            left,
            right,
            reason,
        };

        for (&neighbor, edge_ids) in &removed_adjacency {
            debug_assert_ne!(neighbor, kept);
            self.disequalities[neighbor].remove(&removed);
            self.disequalities[neighbor]
                .entry(kept)
                .or_default()
                .extend(edge_ids.iter().copied());
            self.disequalities[kept]
                .entry(neighbor)
                .or_default()
                .extend(edge_ids.iter().copied());
        }
        self.next_member.swap(kept, removed);
        self.parent[removed] = kept;
        if let Some(labels) = &mut self.historical_union_labels {
            labels[removed] = Some(HistoricalUnionLabel {
                merge_index: self.merge_records.len(),
                trail_index: self.trail.len(),
            });
        }
        self.size[kept] = new_size;
        self.minimum[kept] = new_minimum;
        self.classes -= 1;
        self.merge_records.push(record);
        self.trail.push(TrailEntry {
            state_id,
            undo: Undo::Merge {
                kept,
                removed,
                kept_size,
                kept_minimum,
                kept_adjacency,
                removed_adjacency,
                record,
            },
        });
        self.consume_state_id();

        debug_assert!(self.validate().is_ok());
        Ok(MergeOutcome::Merged {
            representative: new_minimum,
            size: new_size,
        })
    }

    pub fn union(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
    ) -> PartitionResult<MergeOutcome> {
        self.merge(left, right, reason)
    }

    pub fn assert_equal(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
    ) -> PartitionResult<MergeOutcome> {
        self.merge(left, right, reason)
    }

    pub fn assert_equality(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
    ) -> PartitionResult<MergeOutcome> {
        self.merge(left, right, reason)
    }

    /// Adds an explicit disequality between the current classes.
    pub fn separate(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
    ) -> PartitionResult<SeparationOutcome> {
        self.separate_impl(left, right, reason, None)
    }

    pub(crate) fn separate_in_checked_batch(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
        batch: &mut CheckedSeparationBatch,
    ) -> PartitionResult<SeparationOutcome> {
        self.separate_impl(left, right, reason, Some(batch))
    }

    fn separate_impl(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
        mut batch: Option<&mut CheckedSeparationBatch>,
    ) -> PartitionResult<SeparationOutcome> {
        if let Some(batch) = batch.as_mut() {
            batch.synchronize(self)?;
        }
        let left_root = self.root_of_term(left)?;
        let right_root = self.root_of_term(right)?;
        let record = SeparationRecord {
            left,
            right,
            reason,
        };
        if left_root == right_root {
            let equality_reasons =
                self.equality_reasons(left, right)?
                    .ok_or(PartitionError::InvariantViolation(
                        "equal terms have no equality reasons",
                    ))?;
            return Err(PartitionError::Conflict(
                Conflict::DisequalityAgainstEquality {
                    separation: record,
                    equality_reasons,
                },
            ));
        }

        let existing = self.logical_ids(left_root, right_root)?;
        let relation_was_known = existing.len() != 0;
        if relation_was_known {
            let normalized_requested = normalized_term_pair(left, right);
            for edge_id in existing {
                let (prior, _) = self.checked_edge_record(left_root, right_root, edge_id)?;
                if normalized_term_pair(prior.left, prior.right) == normalized_requested
                    && prior.reason == reason
                {
                    return Ok(SeparationOutcome::AlreadyPresent);
                }
            }
        }

        if let Some(batch) = batch.as_mut() {
            batch.check_root(self, left_root)?;
            batch.check_root(self, right_root)?;
        } else {
            self.check_root_adjacency(left_root)?;
            self.check_root_adjacency(right_root)?;
        }
        let state_id = self.prepare_update(false)?;
        let edge_id = state_id;
        if self.row_exists(edge_id) {
            return Err(PartitionError::InvariantViolation(
                "state ID reused as a separation edge ID",
            ));
        }

        let plan = self.virtual_rows.plan(left_root,right_root,edge_id,record,!relation_was_known);
        if plan.capacity_barrier(self,edge_id,record) {
            self.materialize_virtual(virtual_adjacency::Trigger::Capacity)?;
            if let Some(batch) = batch.as_mut() {
                batch.synchronize(self)?;
                batch.check_root(self,left_root)?;
                batch.check_root(self,right_root)?;
            } else {
                self.check_root_adjacency(left_root)?;
                self.check_root_adjacency(right_root)?;
            }
        }
        let compact = self.row_insert(edge_id,record);
        if !self.virtual_rows.commit(plan,compact,edge_id) {
        self.disequalities[left_root]
            .entry(right_root)
            .or_default()
            .insert(edge_id);
        self.disequalities[right_root]
            .entry(left_root)
            .or_default()
            .insert(edge_id);
        }
        self.trail.push(TrailEntry {
            state_id,
            undo: Undo::Separation {
                left_root,
                right_root,
                edge_id,
                record,
            },
        });
        self.consume_state_id();
        if let Some(batch) = batch {
            // The checked insertion changes only these two adjacency maps and
            // adds the same fresh witness to both, preserving every cached check.
            batch.bind(self);
        }

        debug_assert!(self.validate().is_ok());
        Ok(SeparationOutcome::Added { relation_was_known })
    }

    pub fn assert_disequal(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
    ) -> PartitionResult<SeparationOutcome> {
        self.separate(left, right, reason)
    }

    pub fn assert_disequality(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
    ) -> PartitionResult<SeparationOutcome> {
        self.separate(left, right, reason)
    }

    /// Performs a full internal consistency check without changing state.
    pub fn validate(&self) -> PartitionResult<()> {
        let term_count = self.term_count();
        if self.size.len() != term_count
            || self.minimum.len() != term_count
            || self.next_member.len() != term_count
            || self.disequalities.len() != term_count
        {
            return Err(PartitionError::InvariantViolation(
                "parallel term arrays have different lengths",
            ));
        }
        self.validate_virtual_descriptor()?;
        if let Some(labels) = &self.historical_union_labels {
            if labels.len() != term_count {
                return Err(PartitionError::InvariantViolation(
                    "historical union index has the wrong term count",
                ));
            }
            let mut merge_index = 0;
            for (trail_index, entry) in self.trail.iter().enumerate() {
                if let Undo::Merge { removed, .. } = &entry.undo {
                    if labels.get(*removed)
                        != Some(&Some(HistoricalUnionLabel {
                            merge_index,
                            trail_index,
                        }))
                    {
                        return Err(PartitionError::InvariantViolation(
                            "historical union label does not match merge chronology",
                        ));
                    }
                    merge_index += 1;
                }
            }
            if merge_index != self.merge_records.len() {
                return Err(PartitionError::InvariantViolation(
                    "historical union trail has the wrong merge count",
                ));
            }
            for index in 0..term_count {
                self.historical_union_link(self.term_from_index(index)?, merge_index)?;
            }
        }

        let mut actual_sizes = vec![0usize; term_count];
        let mut actual_minimum = vec![None::<TermId>; term_count];
        for index in 0..term_count {
            let root = self.root_index(index)?;
            actual_sizes[root] =
                actual_sizes[root]
                    .checked_add(1)
                    .ok_or(PartitionError::InvariantViolation(
                        "class size overflow during validation",
                    ))?;
            let term = self.term_from_index(index)?;
            actual_minimum[root] = Some(actual_minimum[root].map_or(term, |old| old.min(term)));
        }

        let mut actual_classes = 0usize;
        let mut covered_records = 0usize;
        let mut listed_members = vec![false; term_count];
        for index in 0..term_count {
            if self.parent[index] == index {
                actual_classes += 1;
                if self.size[index] != actual_sizes[index] {
                    return Err(PartitionError::InvariantViolation(
                        "root class size is incorrect",
                    ));
                }
                if Some(self.minimum[index]) != actual_minimum[index] {
                    return Err(PartitionError::InvariantViolation(
                        "root canonical minimum is incorrect",
                    ));
                }
                let mut current = index;
                for _ in 0..self.size[index] {
                    if current >= term_count
                        || listed_members[current]
                        || self.root_index(current)? != index
                    {
                        return Err(PartitionError::InvariantViolation(
                            "class member cycle contains an invalid member",
                        ));
                    }
                    listed_members[current] = true;
                    current = self.next_member[current];
                }
                if current != index {
                    return Err(PartitionError::InvariantViolation(
                        "class member cycle has the wrong length",
                    ));
                }
                let (_, records) = self.audit_logical_root::<true>(index)?;
                covered_records = covered_records.checked_add(records).ok_or(
                    PartitionError::InvariantViolation("logical witness count overflow"),
                )?;
            } else if !self.disequalities[index].is_empty() {
                return Err(PartitionError::InvariantViolation(
                    "non-root has disequality adjacency",
                ));
            }
        }
        if actual_classes != self.classes {
            return Err(PartitionError::InvariantViolation(
                "stored class count is incorrect",
            ));
        }
        if listed_members.iter().any(|listed| !listed) {
            return Err(PartitionError::InvariantViolation(
                "class member cycles do not cover every term",
            ));
        }

        if self.merge_records.len() != term_count.saturating_sub(actual_classes) {
            return Err(PartitionError::InvariantViolation(
                "merge record count does not describe a spanning forest",
            ));
        }
        self.validate_merge_forest()?;

        // Each covered ID was resolved to its actual source endpoints. It can
        // belong to only that root pair, where the ordered view forbids repeats.
        if covered_records != self.separation_count() || covered_records != self.row_entries().count() {
            return Err(PartitionError::InvariantViolation("separation record is missing from adjacency"));
        }

        if self.trail.len() != self.merge_records.len() + self.separation_count() {
            return Err(PartitionError::InvariantViolation(
                "trail length does not match active updates",
            ));
        }
        let mut previous_state_id = 0;
        for entry in &self.trail {
            if entry.state_id <= previous_state_id || entry.state_id >= self.next_state_id {
                return Err(PartitionError::InvariantViolation(
                    "trail state IDs are not strictly increasing",
                ));
            }
            previous_state_id = entry.state_id;
            if let Undo::Separation {
                edge_id, record, ..
            } = &entry.undo
            {
                if *edge_id != entry.state_id
                    || self.row_record(edge_id).as_ref() != Some(record)
                {
                    return Err(PartitionError::InvariantViolation(
                        "separation trail entry is inconsistent",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_snapshot(&self, snapshot: Snapshot) -> PartitionResult<()> {
        if snapshot.partition_id != self.partition_id {
            return Err(PartitionError::InvalidSnapshot(
                SnapshotError::ForeignPartition,
            ));
        }
        if snapshot.trail_len > self.trail.len() {
            return Err(PartitionError::InvalidSnapshot(SnapshotError::FutureState));
        }
        let expected_state_id = if snapshot.trail_len == 0 {
            0
        } else {
            self.trail[snapshot.trail_len - 1].state_id
        };
        if snapshot.state_id != expected_state_id {
            return Err(PartitionError::InvalidSnapshot(
                SnapshotError::DiscardedBranch,
            ));
        }
        Ok(())
    }

    fn term_index(&self, term: TermId) -> PartitionResult<usize> {
        let index = usize::try_from(term.raw()).map_err(|_| PartitionError::InvalidTerm {
            term,
            term_count: self.term_count(),
        })?;
        if index >= self.term_count() {
            return Err(PartitionError::InvalidTerm {
                term,
                term_count: self.term_count(),
            });
        }
        Ok(index)
    }

    fn term_from_index(&self, index: usize) -> PartitionResult<TermId> {
        if index >= self.term_count() {
            return Err(PartitionError::InvariantViolation(
                "internal term index is out of range",
            ));
        }
        TermId::try_from(index).map_err(|_| {
            PartitionError::InvariantViolation("internal term index cannot be represented")
        })
    }

    fn root_of_term(&self, term: TermId) -> PartitionResult<usize> {
        self.root_index(self.term_index(term)?)
    }

    /// Finds a root without mutating any parent pointer.
    fn root_index(&self, index: usize) -> PartitionResult<usize> {
        if index >= self.term_count() {
            return Err(PartitionError::InvariantViolation(
                "root lookup index is out of range",
            ));
        }
        let mut current = index;
        for _ in 0..=self.term_count() {
            let parent = *self
                .parent
                .get(current)
                .ok_or(PartitionError::InvariantViolation(
                    "parent pointer is out of range",
                ))?;
            if parent >= self.term_count() {
                return Err(PartitionError::InvariantViolation(
                    "parent pointer is out of range",
                ));
            }
            if parent == current {
                return Ok(current);
            }
            current = parent;
        }
        Err(PartitionError::InvariantViolation(
            "parent pointers contain a cycle",
        ))
    }

    #[inline]
    fn checked_edge_record(&self, left: usize, right: usize, id: EdgeId)
        -> PartitionResult<(SeparationRecord, bool)>
    {
        let record = self.row_record(&id).ok_or(
            PartitionError::InvariantViolation("disequality edge has no separation record"),
        )?;
        let a = self.root_of_term(record.left)?;
        let b = self.root_of_term(record.right)?;
        if normalized_index_pair(a, b) != normalized_index_pair(left, right) {
            return Err(PartitionError::InvariantViolation(
                "separation record does not induce its current edge",
            ));
        }
        Ok((record, a == left))
    }

    #[inline]
    fn physical_ids_between(
        &self,
        left_root: usize,
        right_root: usize,
    ) -> PartitionResult<Option<&BTreeSet<EdgeId>>> {
        if left_root >= self.term_count() || right_root >= self.term_count() {
            return Err(PartitionError::InvariantViolation(
                "disequality lookup root is out of range",
            ));
        }
        if self.parent[left_root] != left_root || self.parent[right_root] != right_root {
            return Err(PartitionError::InvariantViolation(
                "disequality lookup endpoint is not a root",
            ));
        }
        let missing = || PartitionError::InvariantViolation("class root has no disequality adjacency");
        let forward = self.disequalities.get(left_root).ok_or_else(missing)?.get(&right_root);
        let reverse = self.disequalities.get(right_root).ok_or_else(missing)?.get(&left_root);
        match (forward, reverse) {
            (None, None) => Ok(None),
            (Some(first), Some(second)) if !first.is_empty() && first == second => Ok(Some(first)),
            _ => Err(PartitionError::InvariantViolation(
                "disequality adjacency is asymmetric or empty",
            )),
        }
    }

    // Count each witness at its lower root only. For a whole-partition audit the
    // other visit still verifies the reverse edge, but need not decode it again.
    fn audit_logical_root<const WHOLE: bool>(&self, root: usize) -> PartitionResult<(usize, usize)> {
        self.single_walk::<WHOLE,false>(root,&mut single_audit::Walk::default())
    }

    fn single_walk<const WHOLE:bool,const COUNT:bool>(&self,root:usize,w:&mut single_audit::Walk)
        ->PartitionResult<(usize,usize)> {
        if self.parent.get(root) != Some(&root) {
            return Err(PartitionError::InvariantViolation("disequality adjacency owner is not a root"));
        }
        let mut degree = 0;
        let mut witnesses = 0usize;
        let mut previous = None;
        for neighbor in self.logical_neighbors(root)? {
            if root == neighbor || previous.is_some_and(|p| p >= neighbor) {
                return Err(PartitionError::InvariantViolation("invalid logical neighbor order"));
            }
            previous = Some(neighbor);
            let mut confirmed=None;
            let ids=self.logical_ids_counted::<COUNT>(root,neighbor,&mut w.first,&mut confirmed)?;
            let virtual_id=ids.single_virtual_id();
            if ids.len() == 0 {
                return Err(PartitionError::InvariantViolation("logical neighbor has no witnesses"));
            }
            degree += 1;
            if root < neighbor {
                witnesses = witnesses.checked_add(ids.len()).ok_or(
                    PartitionError::InvariantViolation("logical witness count overflow"),
                )?;
            }
            if !WHOLE || root < neighbor {
                let mut prior = None;
                for id in ids {
                    if prior.is_some_and(|p| p >= id) {
                        return Err(PartitionError::InvariantViolation("duplicate or unordered logical witness"));
                    }
                    self.checked_edge_record(root, neighbor, id)?;
                    if COUNT {w.second(id,virtual_id,&mut confirmed);}
                    prior = Some(id);
                }
            }
            if COUNT {w.end_pair(confirmed);w.neighbors+=1;}
        }
        Ok((degree, witnesses))
    }

    #[inline]
    fn check_root_adjacency(&self, root: usize) -> PartitionResult<()> {
        if let Some(o)=self.single_audit.get(){
            if self.has_virtual_adjacency(){
                let mut w=single_audit::Walk::default();
                let r=self.single_walk::<false,true>(root,&mut w);
                o.target(w,&r);
                return r.map(|_| ());
            }
        }
        self.checked_root_degree(root).map(|_| ())
    }

    #[inline]
    fn checked_root_degree(&self, root: usize) -> PartitionResult<usize> {
        if self.has_virtual_adjacency() {
            return self.audit_logical_root::<false>(root).map(|(degree, _)| degree);
        }
        if let Some(c)=self.group_rows.storage(){
            self.row_check_adjacency(root,|id|c.contains(*id) || self.separation_records.contains_key(id))
        }else{
            self.row_check_adjacency(root,|id|self.separation_records.contains_key(id))
        }?;
        Ok(self.disequalities[root].len())
    }
    #[inline(always)]
    fn row_check_adjacency(&self,root:usize,live:impl Fn(&EdgeId)->bool)->PartitionResult<()> {
        if root >= self.term_count() || self.parent[root] != root {
            return Err(PartitionError::InvariantViolation(
                "disequality adjacency owner is not a root",
            ));
        }
        let adjacency = self.disequalities.get(root).ok_or(
            PartitionError::InvariantViolation("class root has no disequality adjacency"),
        )?;
        for (&neighbor, edge_ids) in adjacency {
            if neighbor >= self.term_count()
                || neighbor == root
                || self.parent[neighbor] != neighbor
                || edge_ids.is_empty()
            {
                return Err(PartitionError::InvariantViolation(
                    "invalid disequality adjacency endpoint",
                ));
            }
            if self.disequalities.get(neighbor).and_then(|reverse| reverse.get(&root)) != Some(edge_ids) {
                return Err(PartitionError::InvariantViolation(
                    "disequality adjacency is not symmetric",
                ));
            }
            for edge_id in edge_ids {
                if !live(edge_id) {
                    return Err(PartitionError::InvariantViolation(
                        "disequality adjacency references no separation record",
                    ));
                }
            }
        }
        Ok(())
    }

    fn choose_union_roots(
        &self,
        left_root: usize,
        right_root: usize,
    ) -> PartitionResult<(usize, usize)> {
        let left_size = *self
            .size
            .get(left_root)
            .ok_or(PartitionError::InvariantViolation("left root has no size"))?;
        let right_size = *self
            .size
            .get(right_root)
            .ok_or(PartitionError::InvariantViolation("right root has no size"))?;
        if left_size > right_size {
            Ok((left_root, right_root))
        } else if right_size > left_size {
            Ok((right_root, left_root))
        } else if self.minimum[left_root] <= self.minimum[right_root] {
            Ok((left_root, right_root))
        } else {
            Ok((right_root, left_root))
        }
    }

    fn prepare_update(&mut self, adds_merge_record: bool) -> PartitionResult<u64> {
        if self.next_state_id == u64::MAX {
            return Err(PartitionError::StateIdExhausted);
        }
        self.trail
            .try_reserve(1)
            .map_err(|_| PartitionError::AllocationFailed)?;
        if adds_merge_record {
            self.merge_records
                .try_reserve(1)
                .map_err(|_| PartitionError::AllocationFailed)?;
        }
        Ok(self.next_state_id)
    }

    fn consume_state_id(&mut self) {
        self.next_state_id += 1;
    }

    fn undo_last(&mut self) -> PartitionResult<()> {
        let undo = &self
            .trail
            .last()
            .ok_or(PartitionError::InvariantViolation(
                "rollback trail is empty",
            ))?
            .undo;
        self.preflight_undo(undo)?;
        let undo = self
            .trail
            .pop()
            .ok_or(PartitionError::InvariantViolation(
                "rollback trail disappeared after validation",
            ))?
            .undo;
        match undo {
            Undo::Separation {
                left_root,
                right_root,
                edge_id,
                ..
            } => {
                self.remove_edge_id(left_root, right_root, edge_id);
                self.remove_edge_id(right_root, left_root, edge_id);
                self.row_remove(edge_id);
            }
            Undo::Merge {
                kept,
                removed,
                kept_size,
                kept_minimum,
                kept_adjacency,
                removed_adjacency,
                ..
            } => {
                for &neighbor in kept_adjacency.keys().chain(
                    removed_adjacency
                        .keys()
                        .filter(|neighbor| !kept_adjacency.contains_key(*neighbor)),
                ) {
                    self.disequalities[neighbor].remove(&kept);
                    self.disequalities[neighbor].remove(&removed);
                    if let Some(edge_ids) = kept_adjacency.get(&neighbor) {
                        self.disequalities[neighbor].insert(kept, edge_ids.clone());
                    }
                    if let Some(edge_ids) = removed_adjacency.get(&neighbor) {
                        self.disequalities[neighbor].insert(removed, edge_ids.clone());
                    }
                }
                self.disequalities[kept] = kept_adjacency;
                self.disequalities[removed] = removed_adjacency;
                self.next_member.swap(kept, removed);
                self.parent[removed] = removed;
                if let Some(labels) = &mut self.historical_union_labels {
                    labels[removed] = None;
                }
                self.size[kept] = kept_size;
                self.minimum[kept] = kept_minimum;
                self.classes += 1;
                self.merge_records.pop();
            }
        }
        Ok(())
    }

    fn preflight_undo(&self, undo: &Undo) -> PartitionResult<()> {
        match undo {
            Undo::Separation {
                left_root,
                right_root,
                edge_id,
                record,
            } => {
                if self.group_rows.get().is_some_and(|c|!c.can_undo(*edge_id))
                    || *left_root >= self.term_count()
                    || *right_root >= self.term_count()
                    || self.row_record(edge_id).as_ref() != Some(record)
                    || !self.disequalities[*left_root]
                        .get(right_root)
                        .is_some_and(|ids| ids.contains(edge_id))
                    || !self.disequalities[*right_root]
                        .get(left_root)
                        .is_some_and(|ids| ids.contains(edge_id))
                {
                    return Err(PartitionError::InvariantViolation(
                        "cannot undo inconsistent separation",
                    ));
                }
            }
            Undo::Merge {
                kept,
                removed,
                kept_adjacency,
                removed_adjacency,
                record,
                ..
            } => {
                if *kept >= self.term_count()
                    || *removed >= self.term_count()
                    || self.parent[*kept] != *kept
                    || self.parent[*removed] != *kept
                    || !self.disequalities[*removed].is_empty()
                    || self.merge_records.last() != Some(record)
                {
                    return Err(PartitionError::InvariantViolation(
                        "cannot undo inconsistent merge",
                    ));
                }
                if let Some(labels) = &self.historical_union_labels {
                    let expected = self
                        .merge_records
                        .len()
                        .checked_sub(1)
                        .zip(self.trail.len().checked_sub(1))
                        .map(|(merge_index, trail_index)| HistoricalUnionLabel {
                            merge_index,
                            trail_index,
                        });
                    if labels.len() != self.term_count()
                        || labels[*kept].is_some()
                        || expected.is_none()
                        || labels[*removed] != expected
                    {
                        return Err(PartitionError::InvariantViolation(
                            "cannot undo inconsistent historical union label",
                        ));
                    }
                }
                if kept_adjacency
                    .keys()
                    .chain(removed_adjacency.keys())
                    .any(|&neighbor| {
                        neighbor >= self.term_count() || neighbor == *kept || neighbor == *removed
                    })
                {
                    return Err(PartitionError::InvariantViolation(
                        "merge undo adjacency endpoint is invalid",
                    ));
                }
                let merged_adjacency = &self.disequalities[*kept];
                let has_unrecorded_edge = merged_adjacency.iter().any(|(&neighbor, edge_ids)| {
                    edge_ids.iter().any(|edge_id| {
                        !kept_adjacency
                            .get(&neighbor)
                            .is_some_and(|recorded| recorded.contains(edge_id))
                            && !removed_adjacency
                                .get(&neighbor)
                                .is_some_and(|recorded| recorded.contains(edge_id))
                    })
                });
                let has_missing_edge = kept_adjacency.iter().chain(removed_adjacency.iter()).any(
                    |(&neighbor, edge_ids)| {
                        !merged_adjacency.get(&neighbor).is_some_and(|actual| {
                            edge_ids.iter().all(|edge_id| actual.contains(edge_id))
                        })
                    },
                );
                if has_unrecorded_edge || has_missing_edge {
                    return Err(PartitionError::InvariantViolation(
                        "merged disequality adjacency does not match undo record",
                    ));
                }
                self.check_root_adjacency(*kept)?;
            }
        }
        Ok(())
    }

    fn remove_edge_id(&mut self, from: usize, to: usize, edge_id: EdgeId) {
        let remove_entry = if let Some(edge_ids) = self.disequalities[from].get_mut(&to) {
            edge_ids.remove(&edge_id);
            edge_ids.is_empty()
        } else {
            false
        };
        if remove_entry {
            self.disequalities[from].remove(&to);
        }
    }

    fn validate_merge_forest(&self) -> PartitionResult<()> {
        let mut proof_parent = (0..self.term_count()).collect::<Vec<_>>();
        for record in &self.merge_records {
            let left = self.term_index(record.left)?;
            let right = self.term_index(record.right)?;
            let left_root = proof_root(&proof_parent, left)?;
            let right_root = proof_root(&proof_parent, right)?;
            if left_root == right_root {
                return Err(PartitionError::InvariantViolation(
                    "merge records contain a cycle",
                ));
            }
            proof_parent[right_root] = left_root;
        }

        // Root labels may differ. Mutual functionality of these maps is
        // equivalent to agreement on every pair of terms.
        let mut partition_to_proof = vec![usize::MAX; self.term_count()];
        let mut proof_to_partition = vec![usize::MAX; self.term_count()];
        for term in 0..self.term_count() {
            let proof = proof_root(&proof_parent, term)?;
            let partition = self.root_index(term)?;
            if (partition_to_proof[partition] != usize::MAX
                && partition_to_proof[partition] != proof)
                || (proof_to_partition[proof] != usize::MAX
                    && proof_to_partition[proof] != partition)
            {
                return Err(PartitionError::InvariantViolation(
                    "merge records and union-find disagree",
                ));
            }
            partition_to_proof[partition] = proof;
            proof_to_partition[proof] = partition;
        }
        Ok(())
    }
}

fn normalized_term_pair(left: TermId, right: TermId) -> (TermId, TermId) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

fn normalized_index_pair(left: usize, right: usize) -> (usize, usize) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

fn proof_root(parent: &[usize], index: usize) -> PartitionResult<usize> {
    if index >= parent.len() {
        return Err(PartitionError::InvariantViolation(
            "proof forest index is out of range",
        ));
    }
    let mut current = index;
    for _ in 0..=parent.len() {
        let next = *parent
            .get(current)
            .ok_or(PartitionError::InvariantViolation(
                "proof forest parent is out of range",
            ))?;
        if next >= parent.len() {
            return Err(PartitionError::InvariantViolation(
                "proof forest parent is out of range",
            ));
        }
        if next == current {
            return Ok(current);
        }
        current = next;
    }
    Err(PartitionError::InvariantViolation(
        "proof forest contains a cycle",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn term(raw: u32) -> TermId {
        TermId::new(raw)
    }

    fn reason(raw: u64) -> ReasonId {
        ReasonId::new(raw)
    }

    const FOUR_PAIRS: [(u32, u32); 6] = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];

    fn four_term_partition(mut encoded: usize) -> Partition {
        let mut partition = Partition::new(4).unwrap();
        for (index, &(left, right)) in FOUR_PAIRS.iter().enumerate() {
            let action = encoded % 3;
            encoded /= 3;
            if partition.relation(term(left), term(right)).unwrap() != Relation::Unknown {
                continue;
            }
            match action {
                0 => {}
                1 => {
                    partition
                        .merge(term(left), term(right), reason(index as u64 + 1))
                        .unwrap();
                }
                2 => {
                    partition
                        .separate(term(left), term(right), reason(index as u64 + 1))
                        .unwrap();
                }
                _ => unreachable!(),
            }
        }
        partition
    }

    fn four_pair_relations(partition: &Partition) -> Vec<Relation> {
        FOUR_PAIRS
            .iter()
            .map(|&(left, right)| partition.relation(term(left), term(right)).unwrap())
            .collect()
    }

    #[test]
    fn checked_root_relations_reuse_checks_and_preserve_every_witness() {
        let mut checked = Partition::new(12).unwrap();
        let mut ordinary = Partition::new(12).unwrap();
        let mut batch = checked.checked_separation_batch().unwrap();
        for right in 1..12 {
            for why in [right as u64, 100 + right as u64, right as u64] {
                let actual = checked
                    .separate_in_checked_batch(term(0), term(right), reason(why), &mut batch)
                    .unwrap();
                let expected = ordinary
                    .separate(term(0), term(right), reason(why))
                    .unwrap();
                assert_eq!(actual, expected);
                assert_eq!(batch.epoch, 1);
                assert_eq!(batch.checked_roots[0], 1);
                assert_eq!(batch.checked_roots[right as usize], 1);
                assert_eq!(batch.snapshot, checked.snapshot());
                assert_eq!(batch.next_state_id, checked.next_state_id);
                assert_eq!(
                    checked.canonical_disequalities(),
                    ordinary.canonical_disequalities()
                );
                assert_eq!(checked.separation_records(), ordinary.separation_records());
                checked.validate().unwrap();
            }
        }
        assert_eq!(checked.separation_count(), 22);
    }

    #[test]
    fn checked_root_relations_invalidate_on_merge_rollback_and_rebranch() {
        let mut partition = Partition::new(6).unwrap();
        let mut batch = partition.checked_separation_batch().unwrap();
        partition
            .separate_in_checked_batch(term(0), term(5), reason(1), &mut batch)
            .unwrap();
        let first = partition.snapshot();
        partition.merge(term(0), term(1), reason(2)).unwrap();
        partition
            .separate_in_checked_batch(term(1), term(4), reason(3), &mut batch)
            .unwrap();
        assert_eq!(batch.epoch, 2);
        let discarded = partition.snapshot();
        partition.rollback(first).unwrap();
        partition
            .separate_in_checked_batch(term(0), term(3), reason(4), &mut batch)
            .unwrap();
        assert_eq!(batch.epoch, 3);
        assert!(partition.rollback(discarded).is_err());
        // An ordinary insertion also invalidates the cached state.
        partition.separate(term(0), term(2), reason(5)).unwrap();
        partition
            .separate_in_checked_batch(term(0), term(1), reason(6), &mut batch)
            .unwrap();
        assert_eq!(batch.epoch, 4);
        partition.validate().unwrap();
        assert_eq!(
            partition.relation(term(1), term(5)).unwrap(),
            Relation::Unknown
        );
    }

    #[test]
    fn checked_root_relations_use_physical_roots_and_invalidate_other_tokens() {
        let mut partition = Partition::new(6).unwrap();
        partition.merge(term(3), term(4), reason(10)).unwrap();
        partition.merge(term(3), term(2), reason(11)).unwrap();
        partition.merge(term(3), term(0), reason(12)).unwrap();
        assert_eq!(partition.root_of_term(term(0)).unwrap(), 3);
        assert_eq!(
            partition.canonical_representative(term(3)).unwrap(),
            term(0)
        );
        let mut first = partition.checked_separation_batch().unwrap();
        let mut second = partition.checked_separation_batch().unwrap();
        partition
            .separate_in_checked_batch(term(0), term(1), reason(1), &mut first)
            .unwrap();
        assert_eq!(first.checked_roots[0], 0);
        assert_eq!(first.checked_roots[3], 1);
        assert_eq!(
            partition.separate_in_checked_batch(term(4), term(1), reason(1), &mut second),
            Ok(SeparationOutcome::Added {
                relation_was_known: true
            })
        );
        assert_eq!(second.epoch, 2);
        partition
            .separate_in_checked_batch(term(0), term(5), reason(2), &mut first)
            .unwrap();
        assert_eq!(first.epoch, 2);
        assert_eq!(partition.separation_count(), 3);
        assert_eq!(
            partition
                .separation_witnesses(term(3), term(1))
                .unwrap()
                .unwrap()
                .len(),
            2
        );
        partition.validate().unwrap();
    }

    #[test]
    fn checked_root_relations_reject_foreign_invalid_and_exhausted_updates() {
        let mut partition = Partition::new(3).unwrap();
        let other = Partition::new(3).unwrap();
        let mut foreign = other.checked_separation_batch().unwrap();
        let initial = partition.snapshot();
        assert!(
            partition
                .separate_in_checked_batch(term(0), term(1), reason(1), &mut foreign)
                .is_err()
        );
        assert_eq!(partition.snapshot(), initial);
        let mut batch = partition.checked_separation_batch().unwrap();
        assert!(
            partition
                .separate_in_checked_batch(term(0), term(3), reason(1), &mut batch)
                .is_err()
        );
        assert_eq!(partition.snapshot(), initial);
        partition.next_state_id = u64::MAX;
        assert_eq!(
            partition.separate_in_checked_batch(term(0), term(1), reason(1), &mut batch),
            Err(PartitionError::StateIdExhausted)
        );
        assert_eq!(partition.snapshot(), initial);
        assert!(partition.canonical_disequalities().unwrap().is_empty());
        let mut empty = Partition::new(0).unwrap();
        let mut empty_batch = empty.checked_separation_batch().unwrap();
        assert!(
            empty
                .separate_in_checked_batch(term(0), term(0), reason(1), &mut empty_batch)
                .is_err()
        );
        let mut malformed = other.checked_separation_batch().unwrap();
        malformed.checked_roots.pop();
        assert!(malformed.synchronize(&other).is_err());
    }

    #[test]
    fn checked_root_relations_recheck_corrupt_adjacency_after_external_mutation() {
        for corruption in 0..3 {
            let mut partition = Partition::new(5).unwrap();
            let mut batch = partition.checked_separation_batch().unwrap();
            partition
                .separate_in_checked_batch(term(0), term(1), reason(1), &mut batch)
                .unwrap();
            partition.separate(term(2), term(3), reason(2)).unwrap();
            let edge = *partition.disequalities[0][&1].iter().next().unwrap();
            match corruption {
                0 => {
                    partition.disequalities[1].remove(&0);
                }
                1 => {
                    partition.separation_records.remove(&edge);
                }
                2 => {
                    partition.disequalities[0].insert(4, BTreeSet::new());
                }
                _ => unreachable!(),
            }
            let before = partition.snapshot();
            assert!(
                partition
                    .separate_in_checked_batch(term(0), term(4), reason(3), &mut batch)
                    .is_err()
            );
            assert_eq!(partition.snapshot(), before);
            assert_eq!(batch.epoch, 2);
        }
    }

    #[test]
    fn checked_root_relations_epoch_wrap_and_restored_snapshot_are_not_aba() {
        let mut partition = Partition::new(5).unwrap();
        let mut batch = partition.checked_separation_batch().unwrap();
        partition
            .separate_in_checked_batch(term(0), term(1), reason(1), &mut batch)
            .unwrap();
        let root = partition.snapshot();
        let issued = batch.next_state_id;
        batch.epoch = u64::MAX;
        batch.checked_roots.fill(u64::MAX);
        partition.merge(term(2), term(3), reason(2)).unwrap();
        partition.rollback(root).unwrap();
        assert_eq!(partition.snapshot(), batch.snapshot);
        assert!(partition.next_state_id > issued);
        partition
            .separate_in_checked_batch(term(0), term(2), reason(3), &mut batch)
            .unwrap();
        assert_eq!(batch.epoch, 1);
        assert_eq!(batch.checked_roots, vec![1, 0, 1, 0, 0]);
        partition.validate().unwrap();
    }

    #[test]
    fn checked_root_relations_exhaustive_partition_prefixes_match_sequential() {
        for encoded in 0..3usize.pow(6) {
            let mut checked = four_term_partition(encoded);
            let mut ordinary = four_term_partition(encoded);
            let mut batch = checked.checked_separation_batch().unwrap();
            for (index, &(left, right)) in FOUR_PAIRS.iter().enumerate() {
                for why in [1, index as u64 + 20] {
                    let actual = checked.separate_in_checked_batch(
                        term(left),
                        term(right),
                        reason(why),
                        &mut batch,
                    );
                    let expected = ordinary.separate(term(left), term(right), reason(why));
                    assert_eq!(actual, expected, "prefix={encoded}, pair={index}");
                    assert_eq!(
                        four_pair_relations(&checked),
                        four_pair_relations(&ordinary)
                    );
                    assert_eq!(checked.canonical_classes(), ordinary.canonical_classes());
                    assert_eq!(
                        checked.canonical_disequalities(),
                        ordinary.canonical_disequalities()
                    );
                    checked.validate().unwrap();
                }
            }
        }
    }

    fn partition_from_labels(labels: &[usize]) -> Partition {
        let mut partition = Partition::new(labels.len()).unwrap();
        for index in 0..labels.len() {
            if let Some(first) = labels[..index]
                .iter()
                .position(|&label| label == labels[index])
            {
                partition
                    .merge(
                        term(first as u32),
                        term(index as u32),
                        reason(index as u64 + 1),
                    )
                    .unwrap();
            }
        }
        partition
    }

    fn small_partition_labels(size: usize) -> Vec<Vec<usize>> {
        fn extend(size: usize, labels: &mut Vec<usize>, output: &mut Vec<Vec<usize>>) {
            if labels.len() == size {
                output.push(labels.clone());
                return;
            }
            let last = labels
                .iter()
                .copied()
                .max()
                .map_or(0, |maximum| maximum + 1);
            for label in 0..=last {
                labels.push(label);
                extend(size, labels, output);
                labels.pop();
            }
        }
        let mut output = Vec::new();
        extend(size, &mut Vec::new(), &mut output);
        output
    }

    #[test]
    fn merge_forest_bijection_matches_pairwise_oracle_on_all_small_partitions() {
        for (size, expected_count) in [1, 1, 2, 5, 15, 52].into_iter().enumerate() {
            let labels = small_partition_labels(size);
            assert_eq!(labels.len(), expected_count);
            for actual_labels in &labels {
                let mut actual = partition_from_labels(actual_labels);
                for proof_labels in &labels {
                    let proof = partition_from_labels(proof_labels);
                    actual.merge_records = proof.merge_records.clone();
                    let expected = (0..size).all(|left| {
                        (0..left).all(|right| {
                            (actual_labels[left] == actual_labels[right])
                                == (proof_labels[left] == proof_labels[right])
                        })
                    });
                    let observed = actual.validate_merge_forest();
                    assert_eq!(
                        observed.is_ok(),
                        expected,
                        "actual={actual_labels:?}, proof={proof_labels:?}: {observed:?}"
                    );
                    if !expected {
                        assert_eq!(
                            observed,
                            Err(PartitionError::InvariantViolation(
                                "merge records and union-find disagree",
                            ))
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn merge_forest_bijection_accepts_renamed_roots_and_rejects_both_refinements() {
        let mut actual = partition_from_labels(&[0, 0, 1, 1]);
        let mut renamed = actual.merge_records.clone();
        for record in &mut renamed {
            std::mem::swap(&mut record.left, &mut record.right);
        }
        actual.merge_records = renamed;
        let mut proof_parent = (0..actual.term_count()).collect::<Vec<_>>();
        for record in &actual.merge_records {
            let left = proof_root(&proof_parent, record.left.index()).unwrap();
            let right = proof_root(&proof_parent, record.right.index()).unwrap();
            proof_parent[right] = left;
        }
        assert!(
            (0..actual.term_count()).any(|index| proof_root(&proof_parent, index).unwrap()
                != actual.root_index(index).unwrap())
        );
        actual.validate_merge_forest().unwrap();
        for labels in [&[0, 1, 2, 3][..], &[0, 0, 0, 0][..], &[0, 1, 0, 1][..]] {
            actual.merge_records = partition_from_labels(labels).merge_records;
            assert_eq!(
                actual.validate_merge_forest(),
                Err(PartitionError::InvariantViolation(
                    "merge records and union-find disagree",
                ))
            );
        }
    }

    #[test]
    fn merge_forest_bijection_keeps_cycle_and_invalid_endpoint_checks() {
        let mut actual = partition_from_labels(&[0, 0, 1]);
        actual.merge_records.push(actual.merge_records[0].clone());
        assert_eq!(
            actual.validate_merge_forest(),
            Err(PartitionError::InvariantViolation(
                "merge records contain a cycle",
            ))
        );
        actual.merge_records.truncate(1);
        actual.merge_records[0].left = term(3);
        assert!(matches!(actual.validate_merge_forest(),
            Err(PartitionError::InvalidTerm { term: invalid, term_count: 3 }) if invalid == term(3)));
        let mut bad_parent = partition_from_labels(&[0, 0, 1]);
        bad_parent.parent[2] = 3;
        assert_eq!(
            bad_parent.validate_merge_forest(),
            Err(PartitionError::InvariantViolation(
                "parent pointer is out of range",
            ))
        );
        let mut parent_cycle = partition_from_labels(&[0, 1, 2]);
        parent_cycle.parent[0] = 1;
        parent_cycle.parent[1] = 0;
        assert_eq!(
            parent_cycle.validate_merge_forest(),
            Err(PartitionError::InvariantViolation(
                "parent pointers contain a cycle",
            ))
        );
    }

    #[test]
    fn historical_union_index_is_optional_and_uses_merge_not_update_depth() {
        let plain = Partition::new(6).unwrap();
        assert!(!plain.has_historical_union_index());
        assert!(plain.historical_union_labels.is_none());
        assert!(matches!(
            plain.historical_union_link(term(0), 0),
            Err(PartitionError::InvariantViolation(
                "historical union index is unavailable"
            ))
        ));
        let mut partition = Partition::with_historical_union_index(6, true).unwrap();
        let root = partition.snapshot();
        partition.separate(term(4), term(5), reason(7)).unwrap();
        partition.merge(term(0), term(1), reason(99)).unwrap();
        let first = partition.snapshot();
        partition.separate(term(0), term(5), reason(8)).unwrap();
        partition.merge(term(2), term(3), reason(1)).unwrap();
        partition.merge(term(0), term(2), reason(99)).unwrap();
        assert_eq!(partition.merge_count(), 3);
        assert_eq!(partition.update_count(), 5);
        assert_eq!(partition.historical_union_link(term(1), 0).unwrap(), None);
        assert_eq!(
            partition.historical_union_link(term(1), 1).unwrap(),
            Some((term(0), 0))
        );
        assert_eq!(
            partition.historical_union_link(term(3), 2).unwrap(),
            Some((term(2), 1))
        );
        assert_eq!(partition.historical_union_link(term(2), 2).unwrap(), None);
        assert_eq!(
            partition.historical_union_link(term(2), 3).unwrap(),
            Some((term(0), 2))
        );
        let labels = partition.historical_union_labels.as_ref().unwrap();
        assert_eq!(
            labels[1],
            Some(HistoricalUnionLabel {
                merge_index: 0,
                trail_index: 1
            })
        );
        assert_eq!(
            labels[3],
            Some(HistoricalUnionLabel {
                merge_index: 1,
                trail_index: 3
            })
        );
        assert_eq!(
            labels[2],
            Some(HistoricalUnionLabel {
                merge_index: 2,
                trail_index: 4
            })
        );
        partition.rollback(first).unwrap();
        assert_eq!(partition.historical_union_link(term(3), 1).unwrap(), None);
        partition.merge(term(3), term(0), reason(4)).unwrap();
        assert_eq!(
            partition.historical_union_link(term(3), 2).unwrap(),
            Some((term(0), 1))
        );
        partition.rollback(root).unwrap();
        assert!(
            partition
                .historical_union_labels
                .as_ref()
                .unwrap()
                .iter()
                .all(Option::is_none)
        );
        partition.validate().unwrap();
        Partition::with_historical_union_index(0, true)
            .unwrap()
            .validate()
            .unwrap();
    }

    #[test]
    fn historical_union_index_tracks_physical_roots_not_canonical_minima() {
        let mut partition = Partition::with_historical_union_index(5, true).unwrap();
        for (index, (left, right)) in [(2, 3), (2, 4), (0, 1), (0, 2)].into_iter().enumerate() {
            partition
                .merge(term(left), term(right), reason(index as u64))
                .unwrap();
        }
        assert_eq!(partition.representative(term(2)).unwrap(), term(0));
        assert_eq!(
            partition.historical_union_link(term(0), 4).unwrap(),
            Some((term(2), 3))
        );
        assert_eq!(partition.historical_union_link(term(0), 3).unwrap(), None);
        assert_eq!(partition.historical_union_link(term(2), 4).unwrap(), None);
        partition.validate().unwrap();
    }

    #[test]
    fn historical_union_index_rejects_invalid_labels_and_cutoffs() {
        let mut partition = Partition::with_historical_union_index(4, true).unwrap();
        for (index, (left, right)) in [(0, 1), (2, 3), (0, 2)].into_iter().enumerate() {
            partition
                .merge(term(left), term(right), reason(index as u64))
                .unwrap();
        }
        let original = partition.historical_union_labels.clone();
        for defect in 0..8 {
            partition.historical_union_labels = original.clone();
            let labels = partition.historical_union_labels.as_mut().unwrap();
            match defect {
                0 => labels[3] = None,
                1 => labels[3].as_mut().unwrap().merge_index = usize::MAX,
                2 => labels[3].as_mut().unwrap().trail_index = usize::MAX,
                3 => labels[3].as_mut().unwrap().merge_index = 0,
                4 => labels[3].as_mut().unwrap().trail_index = 0,
                5 => labels[0] = labels[1],
                6 => labels[2] = labels[1],
                7 => {
                    labels.pop();
                }
                _ => unreachable!(),
            }
            let checked_term = if defect == 5 { term(0) } else { term(3) };
            assert!(
                matches!(
                    partition.historical_union_link(checked_term, 3),
                    Err(PartitionError::InvariantViolation(_))
                ),
                "defect={defect}"
            );
            assert!(partition.validate().is_err(), "defect={defect}");
        }
        partition.historical_union_labels = original;
        assert!(matches!(
            partition.historical_union_link(term(4), 3),
            Err(PartitionError::InvalidTerm { .. })
        ));
        assert!(matches!(
            partition.historical_union_link(term(0), 4),
            Err(PartitionError::InvariantViolation(
                "historical union cutoff exceeds active merges"
            ))
        ));
        partition.validate().unwrap();
    }

    #[test]
    fn historical_union_index_preflights_undo_without_consuming_history() {
        let mut partition = Partition::with_historical_union_index(3, true).unwrap();
        partition.merge(term(0), term(1), reason(7)).unwrap();
        partition.merge(term(0), term(2), reason(8)).unwrap();
        let before = partition.snapshot();
        let original = partition.historical_union_labels.clone();
        partition.historical_union_labels.as_mut().unwrap()[2]
            .as_mut()
            .unwrap()
            .merge_index = 0;
        // Exercise the checked primitive directly: rollback's debug precondition
        // deliberately asserts full consistency before entering the undo loop.
        assert_eq!(
            partition.undo_last(),
            Err(PartitionError::InvariantViolation(
                "cannot undo inconsistent historical union label"
            ))
        );
        assert_eq!(partition.snapshot(), before);
        assert_eq!(partition.merge_count(), 2);
        partition.historical_union_labels = original;
        partition.undo_last().unwrap();
        assert_eq!(partition.historical_union_link(term(2), 1).unwrap(), None);
        partition.validate().unwrap();
    }

    #[test]
    fn historical_union_index_rejected_updates_preserve_labels() {
        let mut partition = Partition::with_historical_union_index(3, true).unwrap();
        partition.merge(term(0), term(1), reason(5)).unwrap();
        partition.separate(term(0), term(2), reason(6)).unwrap();
        let before = partition.snapshot();
        let labels = partition.historical_union_labels.clone();
        assert!(matches!(
            partition.merge(term(0), term(1), reason(9)).unwrap(),
            MergeOutcome::AlreadyEqual { .. }
        ));
        assert!(matches!(
            partition.merge(term(1), term(2), reason(9)),
            Err(PartitionError::Conflict(_))
        ));
        assert!(matches!(
            partition.merge(term(1), term(3), reason(9)),
            Err(PartitionError::InvalidTerm { .. })
        ));
        assert_eq!(partition.snapshot(), before);
        assert_eq!(partition.historical_union_labels, labels);

        let mut exhausted = Partition::with_historical_union_index(2, true).unwrap();
        exhausted.next_state_id = u64::MAX;
        let before = exhausted.snapshot();
        assert_eq!(
            exhausted.merge(term(0), term(1), reason(1)),
            Err(PartitionError::StateIdExhausted)
        );
        assert_eq!(exhausted.snapshot(), before);
        assert_eq!(exhausted.historical_union_labels, Some(vec![None, None]));

        let mut invalid_root = Partition::with_historical_union_index(3, true).unwrap();
        invalid_root.merge(term(0), term(1), reason(1)).unwrap();
        let before = invalid_root.snapshot();
        let labels = invalid_root.historical_union_labels.as_mut().unwrap();
        labels[0] = labels[1];
        assert!(matches!(
            invalid_root.merge(term(0), term(2), reason(2)),
            Err(PartitionError::InvariantViolation(
                "cannot merge inconsistent historical union roots"
            ))
        ));
        assert_eq!(invalid_root.snapshot(), before);
        assert_eq!(invalid_root.merge_count(), 1);
    }

    #[test]
    fn stable_ids_and_empty_partition_are_checked() {
        assert_eq!(TermId::new(17).raw(), 17);
        assert_eq!(ReasonId::new(23).raw(), 23);
        assert_eq!(TermId::try_from(42usize), Ok(term(42)));
        assert_eq!(term(42).to_string(), "42");
        assert_eq!(reason(23).to_string(), "23");

        if let Ok(too_large) = usize::try_from(u64::from(u32::MAX) + 1) {
            assert_eq!(
                TermId::try_from(too_large),
                Err(TermIdOverflow { value: too_large })
            );
        }

        let mut empty = Partition::new(0).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.class_count(), 0);
        assert_eq!(
            empty.canonical_classes().unwrap(),
            Vec::<Vec<TermId>>::new()
        );
        assert_eq!(empty.disequality_edge_count().unwrap(), 0);
        assert_eq!(empty.rollback(empty.snapshot()).unwrap(), 0);
        empty.validate().unwrap();
    }

    #[test]
    fn checked_term_apis_reject_without_mutating() {
        let mut partition = Partition::new(3).unwrap();
        let before = partition.snapshot();
        let invalid = term(3);
        let expected = PartitionError::InvalidTerm {
            term: invalid,
            term_count: 3,
        };

        assert_eq!(partition.representative(invalid), Err(expected.clone()));
        assert_eq!(partition.class_size(invalid), Err(expected.clone()));
        assert_eq!(partition.class_members(invalid), Err(expected.clone()));
        assert_eq!(
            partition.disequal_class_representatives(invalid),
            Err(expected.clone())
        );
        assert_eq!(partition.relation(term(0), invalid), Err(expected.clone()));
        assert_eq!(
            partition.equality_reasons(invalid, term(0)),
            Err(expected.clone())
        );
        assert_eq!(
            partition.separation_witnesses(term(0), invalid),
            Err(expected.clone())
        );
        assert_eq!(
            partition.merge(term(0), invalid, reason(1)),
            Err(expected.clone())
        );
        assert_eq!(
            partition.separate(invalid, term(0), reason(2)),
            Err(expected)
        );
        assert_eq!(partition.snapshot(), before);
        assert_eq!(partition.class_count(), 3);
        partition.validate().unwrap();
    }

    #[test]
    fn appended_class_members_preserve_prefix_order_and_rollback() {
        let mut partition = Partition::new(7).unwrap();
        partition.merge(term(5), term(2), reason(1)).unwrap();
        partition.merge(term(5), term(4), reason(2)).unwrap();
        let snapshot = partition.snapshot();
        let mut actual = vec![term(6), term(0)];
        let mut expected = actual.clone();
        expected.extend(partition.class_members(term(2)).unwrap());

        assert_eq!(partition.append_class_members(term(4), &mut actual), Ok(3));
        assert_eq!(actual, expected);
        assert_eq!(partition.snapshot(), snapshot);

        let before = actual.clone();
        assert_eq!(
            partition.append_class_members(term(7), &mut actual),
            Err(PartitionError::InvalidTerm {
                term: term(7),
                term_count: 7,
            })
        );
        assert_eq!(actual, before);

        let root = partition.root_of_term(term(2)).unwrap();
        partition.next_member[root] = partition.term_count();
        assert_eq!(
            partition.append_class_members(term(2), &mut actual),
            Err(PartitionError::InvariantViolation(
                "internal term index is out of range"
            ))
        );
        assert_eq!(actual, before);
    }

    #[test]
    fn appended_class_members_reject_a_short_cycle_transactionally() {
        let mut partition = Partition::new(4).unwrap();
        partition.merge(term(1), term(2), reason(1)).unwrap();
        let root = partition.root_of_term(term(1)).unwrap();
        partition.next_member[root] = root;
        let mut actual = vec![term(3)];
        let before = actual.clone();

        assert_eq!(
            partition.append_class_members(term(1), &mut actual),
            Err(PartitionError::InvariantViolation(
                "class member cycle does not match the stored class size"
            ))
        );
        assert_eq!(actual, before);
    }

    #[test]
    fn union_by_size_does_not_compress_paths() {
        let mut partition = Partition::new(8).unwrap();
        partition.merge(term(6), term(7), reason(1)).unwrap();
        partition.merge(term(4), term(5), reason(2)).unwrap();
        partition.merge(term(4), term(6), reason(3)).unwrap();

        assert_eq!(partition.parent[7], 6);
        assert_eq!(partition.parent[6], 4);
        assert_eq!(partition.representative(term(7)).unwrap(), term(4));
        assert!(partition.are_equal(term(5), term(7)).unwrap());
        assert_eq!(partition.parent[7], 6, "queries must not compress paths");

        partition.merge(term(0), term(1), reason(4)).unwrap();
        partition.merge(term(0), term(4), reason(5)).unwrap();
        assert_eq!(partition.parent[0], 4, "larger class must remain the root");
        assert_eq!(partition.representative(term(7)).unwrap(), term(0));
        assert_eq!(partition.class_size(term(1)).unwrap(), 6);
        partition.validate().unwrap();
    }

    #[test]
    fn classes_are_canonical_independently_of_root_and_merge_order() {
        let build = |reverse: bool| {
            let mut partition = Partition::new(6).unwrap();
            if reverse {
                partition.merge(term(5), term(4), reason(1)).unwrap();
                partition.merge(term(5), term(3), reason(2)).unwrap();
                partition.merge(term(2), term(0), reason(3)).unwrap();
            } else {
                partition.merge(term(4), term(5), reason(1)).unwrap();
                partition.merge(term(3), term(4), reason(2)).unwrap();
                partition.merge(term(0), term(2), reason(3)).unwrap();
            }
            partition
        };

        let first = build(false);
        let second = build(true);
        let expected = vec![
            vec![term(0), term(2)],
            vec![term(1)],
            vec![term(3), term(4), term(5)],
        ];
        assert_eq!(first.canonical_classes().unwrap(), expected);
        assert_eq!(second.canonical_classes().unwrap(), expected);
        assert_eq!(first.classes().unwrap()[2].representative, term(3));
        assert_eq!(second.representative(term(5)).unwrap(), term(3));
    }

    #[test]
    fn equality_reason_paths_use_original_merge_endpoints() {
        let mut partition = Partition::new(4).unwrap();
        partition.merge(term(0), term(1), reason(10)).unwrap();
        partition.merge(term(2), term(3), reason(20)).unwrap();
        partition.merge(term(1), term(3), reason(30)).unwrap();

        assert_eq!(
            partition.equality_reasons(term(0), term(2)).unwrap(),
            Some(vec![reason(10), reason(30), reason(20)])
        );
        assert_eq!(
            partition.equality_reasons(term(2), term(0)).unwrap(),
            Some(vec![reason(20), reason(30), reason(10)])
        );
        assert_eq!(
            partition.equality_reasons(term(3), term(3)).unwrap(),
            Some(Vec::new())
        );
        assert_eq!(partition.merge_records().len(), 3);
        partition.validate().unwrap();
    }

    #[test]
    fn disequality_edges_follow_representatives_and_conflicts_are_transactional() {
        let mut partition = Partition::new(5).unwrap();
        partition.separate(term(1), term(3), reason(70)).unwrap();
        partition.merge(term(0), term(1), reason(10)).unwrap();
        partition.merge(term(2), term(3), reason(20)).unwrap();

        assert_eq!(
            partition.relation(term(0), term(2)).unwrap(),
            Relation::Disequal
        );
        assert_eq!(
            partition.disequality_reasons(term(0), term(2)).unwrap(),
            Some(vec![reason(70)])
        );
        assert_eq!(
            partition.disequal_class_representatives(term(0)).unwrap(),
            vec![term(2)]
        );
        assert_eq!(
            partition.disequal_class_representatives(term(1)).unwrap(),
            vec![term(2)]
        );
        assert_eq!(
            partition.disequal_class_representatives(term(3)).unwrap(),
            vec![term(0)]
        );
        assert!(
            partition
                .disequal_class_representatives(term(4))
                .unwrap()
                .is_empty()
        );
        let edge = &partition.canonical_disequalities().unwrap()[0];
        assert_eq!((edge.left, edge.right), (term(0), term(2)));
        assert_eq!(edge.witnesses[0].left, term(1));
        assert_eq!(edge.witnesses[0].right, term(3));

        let before = partition.snapshot();
        assert_eq!(
            partition.merge(term(0), term(2), reason(99)),
            Err(PartitionError::Conflict(
                Conflict::EqualityAgainstDisequality {
                    equality: MergeRecord {
                        left: term(0),
                        right: term(2),
                        reason: reason(99),
                    },
                    separations: vec![SeparationRecord {
                        left: term(1),
                        right: term(3),
                        reason: reason(70),
                    }],
                }
            ))
        );
        assert_eq!(partition.snapshot(), before);

        assert_eq!(
            partition.separate(term(0), term(1), reason(100)),
            Err(PartitionError::Conflict(
                Conflict::DisequalityAgainstEquality {
                    separation: SeparationRecord {
                        left: term(0),
                        right: term(1),
                        reason: reason(100),
                    },
                    equality_reasons: vec![reason(10)],
                }
            ))
        );
        assert_eq!(partition.snapshot(), before);
        assert_eq!(
            partition.separate(term(4), term(4), reason(101)),
            Err(PartitionError::Conflict(
                Conflict::DisequalityAgainstEquality {
                    separation: SeparationRecord {
                        left: term(4),
                        right: term(4),
                        reason: reason(101),
                    },
                    equality_reasons: Vec::new(),
                }
            ))
        );
        assert_eq!(partition.snapshot(), before);
        partition.validate().unwrap();
    }

    #[test]
    fn duplicate_separations_preserve_distinct_reasons() {
        let mut partition = Partition::new(3).unwrap();
        assert_eq!(
            partition.separate(term(0), term(2), reason(1)).unwrap(),
            SeparationOutcome::Added {
                relation_was_known: false
            }
        );
        let one_reason = partition.snapshot();
        assert_eq!(
            partition.separate(term(2), term(0), reason(1)).unwrap(),
            SeparationOutcome::AlreadyPresent
        );
        assert_eq!(partition.snapshot(), one_reason);
        assert_eq!(
            partition.separate(term(0), term(2), reason(2)).unwrap(),
            SeparationOutcome::Added {
                relation_was_known: true
            }
        );
        assert_eq!(
            partition.disequality_reasons(term(2), term(0)).unwrap(),
            Some(vec![reason(1), reason(2)])
        );
        assert_eq!(partition.separation_count(), 2);
        assert_eq!(partition.disequality_edge_count().unwrap(), 1);

        assert_eq!(partition.rollback(one_reason).unwrap(), 1);
        assert_eq!(
            partition.disequality_reasons(term(0), term(2)).unwrap(),
            Some(vec![reason(1)])
        );
        partition.validate().unwrap();
    }

    #[test]
    fn minimum_separation_witness_matches_sorted_records_across_rollback() {
        let mut partition = Partition::new(6).unwrap();
        partition.separate(term(1), term(5), reason(30)).unwrap();
        partition.separate(term(0), term(4), reason(20)).unwrap();
        partition.separate(term(2), term(4), reason(20)).unwrap();
        partition.merge(term(0), term(1), reason(40)).unwrap();
        partition.merge(term(0), term(2), reason(41)).unwrap();
        partition.merge(term(4), term(5), reason(42)).unwrap();

        let expected = partition
            .separation_witnesses(term(2), term(5))
            .unwrap()
            .unwrap()
            .into_iter()
            .min_by_key(|record| (record.reason, record.left, record.right))
            .unwrap();
        assert_eq!(
            partition
                .minimum_separation_witness(term(2), term(5))
                .unwrap(),
            Some((expected, true))
        );
        assert_eq!(
            partition
                .minimum_separation_witness(term(5), term(2))
                .unwrap(),
            Some((expected, false))
        );
        assert_eq!(
            partition
                .minimum_separation_witness(term(0), term(1))
                .unwrap(),
            None
        );
        assert_eq!(
            partition
                .minimum_separation_witness(term(0), term(3))
                .unwrap(),
            None
        );

        let snapshot = partition.snapshot();
        partition.separate(term(1), term(4), reason(5)).unwrap();
        assert_eq!(
            partition
                .minimum_separation_witness(term(2), term(5))
                .unwrap()
                .unwrap()
                .0
                .reason,
            reason(5)
        );
        partition.rollback(snapshot).unwrap();
        assert_eq!(
            partition
                .minimum_separation_witness(term(2), term(5))
                .unwrap(),
            Some((expected, true))
        );
    }

    #[test]
    fn minimum_separation_witness_rejects_missing_and_misaligned_records() {
        for missing in [false, true] {
            let mut partition = Partition::new(4).unwrap();
            partition.separate(term(0), term(3), reason(10)).unwrap();
            let edge_id = *partition.disequalities[0][&3].iter().next().unwrap();
            if missing {
                partition.separation_records.remove(&edge_id);
            } else {
                partition.separation_records.insert(
                    edge_id,
                    SeparationRecord {
                        left: term(1),
                        right: term(2),
                        reason: reason(10),
                    },
                );
            }

            assert_eq!(
                partition.minimum_separation_witness(term(0), term(3)),
                Err(PartitionError::InvariantViolation(if missing {
                    "disequality edge has no separation record"
                } else {
                    "separation record does not induce its current edge"
                }))
            );
        }
    }

    #[test]
    fn rollback_restores_merged_adjacency_exactly() {
        let mut partition = Partition::new(6).unwrap();
        let root = partition.snapshot();
        partition.separate(term(0), term(4), reason(10)).unwrap();
        partition.separate(term(2), term(4), reason(11)).unwrap();
        let separated = partition.snapshot();

        partition.merge(term(0), term(1), reason(20)).unwrap();
        partition.merge(term(2), term(3), reason(21)).unwrap();
        partition.merge(term(1), term(3), reason(22)).unwrap();
        assert_eq!(partition.class_count(), 3);
        assert_eq!(
            partition.disequality_reasons(term(0), term(4)).unwrap(),
            Some(vec![reason(10), reason(11)])
        );
        let merged = partition.snapshot();

        partition.separate(term(0), term(5), reason(12)).unwrap();
        partition.merge(term(4), term(5), reason(23)).unwrap();
        assert_eq!(partition.disequality_edge_count().unwrap(), 1);
        assert_eq!(
            partition.disequality_reasons(term(3), term(5)).unwrap(),
            Some(vec![reason(10), reason(11), reason(12)])
        );

        assert_eq!(partition.rollback(merged).unwrap(), 2);
        assert_eq!(partition.class_count(), 3);
        assert_eq!(
            partition.relation(term(0), term(5)).unwrap(),
            Relation::Unknown
        );
        assert_eq!(
            partition.disequality_reasons(term(0), term(4)).unwrap(),
            Some(vec![reason(10), reason(11)])
        );

        assert_eq!(partition.rollback(separated).unwrap(), 3);
        assert_eq!(partition.class_count(), 6);
        assert_eq!(
            partition.disequality_reasons(term(0), term(4)).unwrap(),
            Some(vec![reason(10)])
        );
        assert_eq!(
            partition.disequality_reasons(term(2), term(4)).unwrap(),
            Some(vec![reason(11)])
        );

        assert_eq!(partition.rollback(root).unwrap(), 2);
        assert_eq!(partition.class_count(), 6);
        assert_eq!(partition.separation_count(), 0);
        assert_eq!(partition.disequality_edge_count().unwrap(), 0);
        partition.validate().unwrap();
    }

    #[test]
    fn rollback_rejects_missing_or_unrecorded_edges_without_consuming_history() {
        for remove_recorded in [false, true] {
            let mut partition = Partition::new(4).unwrap();
            partition.separate(term(0), term(3), reason(10)).unwrap();
            partition.separate(term(1), term(3), reason(11)).unwrap();
            let before_merge = partition.snapshot();
            partition.merge(term(0), term(1), reason(12)).unwrap();
            let merged = partition.snapshot();

            let changed_edge = if remove_recorded {
                *partition.disequalities[0][&3].iter().next().unwrap()
            } else {
                u64::MAX
            };
            for (owner, neighbor) in [(0usize, 3usize), (3, 0)] {
                let edges = partition.disequalities[owner].get_mut(&neighbor).unwrap();
                if remove_recorded {
                    assert!(edges.remove(&changed_edge));
                } else {
                    assert!(edges.insert(changed_edge));
                }
            }

            // Debug rollback asserts the complete pre-state. This deliberately
            // corrupt state instead probes its local undo guard in that profile.
            let rejected = if cfg!(debug_assertions) {
                partition.undo_last().map(|_| 1)
            } else {
                partition.rollback(before_merge)
            };
            assert_eq!(
                rejected,
                Err(PartitionError::InvariantViolation(
                    "merged disequality adjacency does not match undo record"
                ))
            );
            assert_eq!(partition.snapshot(), merged);

            for (owner, neighbor) in [(0usize, 3usize), (3, 0)] {
                let edges = partition.disequalities[owner].get_mut(&neighbor).unwrap();
                if remove_recorded {
                    assert!(edges.insert(changed_edge));
                } else {
                    assert!(edges.remove(&changed_edge));
                }
            }

            assert_eq!(partition.rollback(before_merge).unwrap(), 1);
            assert_eq!(
                partition.disequality_reasons(term(0), term(3)).unwrap(),
                Some(vec![reason(10)])
            );
            assert_eq!(
                partition.disequality_reasons(term(1), term(3)).unwrap(),
                Some(vec![reason(11)])
            );
            partition.validate().unwrap();
        }
    }

    #[test]
    fn snapshots_reject_foreign_future_and_discarded_states() {
        let mut first = Partition::new(3).unwrap();
        let second = Partition::new(3).unwrap();
        let root = first.snapshot();
        assert_eq!(
            first.rollback(second.snapshot()),
            Err(PartitionError::InvalidSnapshot(
                SnapshotError::ForeignPartition
            ))
        );

        first.merge(term(0), term(1), reason(1)).unwrap();
        let old_branch = first.snapshot();
        first.separate(term(1), term(2), reason(2)).unwrap();
        let future = first.snapshot();
        first.rollback(root).unwrap();
        assert_eq!(
            first.rollback(future),
            Err(PartitionError::InvalidSnapshot(SnapshotError::FutureState))
        );

        first.separate(term(0), term(2), reason(3)).unwrap();
        let replacement = first.snapshot();
        assert_eq!(old_branch.depth(), replacement.depth());
        assert_eq!(
            first.rollback(old_branch),
            Err(PartitionError::InvalidSnapshot(
                SnapshotError::DiscardedBranch
            ))
        );
        assert_eq!(first.snapshot(), replacement);
        first.rollback(root).unwrap();
        first.validate().unwrap();
    }

    #[test]
    fn literal_truth_is_three_valued_and_dual() {
        let mut partition = Partition::new(4).unwrap();
        partition.merge(term(0), term(1), reason(1)).unwrap();
        partition.separate(term(1), term(2), reason(2)).unwrap();

        let expected = [
            (term(0), term(1), TruthValue::True),
            (term(0), term(2), TruthValue::False),
            (term(0), term(3), TruthValue::Unknown),
        ];
        for (left, right, equality) in expected {
            assert_eq!(partition.equality_truth(left, right).unwrap(), equality);
            assert_eq!(
                partition.disequality_truth(left, right).unwrap(),
                equality.negate()
            );
        }
        assert!(TruthValue::True.is_decided());
        assert!(!TruthValue::Unknown.is_decided());
    }

    #[test]
    fn prospective_merge_frontier_touches_every_changed_relation() {
        for encoded in 0usize..3usize.pow(FOUR_PAIRS.len() as u32) {
            let partition = four_term_partition(encoded);
            let before = four_pair_relations(&partition);
            for &(left, right) in &FOUR_PAIRS {
                if partition.relation(term(left), term(right)).unwrap() != Relation::Unknown {
                    continue;
                }

                let forward = partition
                    .prospective_merge_incidence_terms(
                        term(left),
                        term(right),
                        usize::MAX,
                        usize::MAX,
                    )
                    .unwrap();
                let reverse = partition
                    .prospective_merge_incidence_terms(
                        term(right),
                        term(left),
                        usize::MAX,
                        usize::MAX,
                    )
                    .unwrap();
                assert_eq!(forward, reverse, "state {encoded}, pair ({left}, {right})");

                let ProspectiveMergeIncidenceOutcome::Complete { terms: forward, .. } = forward
                else {
                    unreachable!()
                };

                let mut merged = four_term_partition(encoded);
                merged.merge(term(left), term(right), reason(100)).unwrap();
                let after = four_pair_relations(&merged);
                for (index, (&old_relation, &new_relation)) in
                    before.iter().zip(after.iter()).enumerate()
                {
                    if old_relation == new_relation {
                        continue;
                    }
                    let (changed_left, changed_right) = FOUR_PAIRS[index];
                    assert!(
                        forward.contains(&term(changed_left))
                            || forward.contains(&term(changed_right)),
                        "state {encoded}, merge ({left}, {right}), changed relation \
                         ({changed_left}, {changed_right}), frontier {forward:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn prospective_merge_frontier_checks_limits_before_growth() {
        let mut partition = Partition::new(5).unwrap();
        partition.merge(term(1), term(2), reason(1)).unwrap();
        partition.separate(term(0), term(3), reason(2)).unwrap();
        partition.separate(term(0), term(4), reason(3)).unwrap();

        assert_eq!(
            partition
                .prospective_merge_incidence_terms(term(0), term(1), 1, usize::MAX)
                .unwrap(),
            ProspectiveMergeIncidenceOutcome::LimitExceeded {
                resource: ProspectiveMergeIncidenceResource::NeighborClasses,
                attempted: 2,
                limit: 1,
            }
        );
        assert_eq!(
            partition
                .prospective_merge_incidence_terms(term(0), term(1), usize::MAX, 2)
                .unwrap(),
            ProspectiveMergeIncidenceOutcome::LimitExceeded {
                resource: ProspectiveMergeIncidenceResource::Terms,
                attempted: 3,
                limit: 2,
            }
        );
    }

    #[test]
    fn exhaustive_four_term_partitions_and_disequality_graphs() {
        let partitions = restricted_growth_partitions(4);
        assert_eq!(partitions.len(), 15);
        let mut checked_states = 0usize;

        for labels in partitions {
            let class_count = labels.iter().copied().max().unwrap_or(0) + 1;
            let mut groups = vec![Vec::<TermId>::new(); class_count];
            for (index, &label) in labels.iter().enumerate() {
                groups[label].push(TermId::try_from(index).unwrap());
            }
            let mut class_pairs = Vec::new();
            let mut pair_bit = BTreeMap::new();
            for left in 0..class_count {
                for right in left + 1..class_count {
                    let bit = class_pairs.len();
                    class_pairs.push((left, right));
                    pair_bit.insert((left, right), bit);
                }
            }

            for mask in 0usize..(1usize << class_pairs.len()) {
                checked_states += 1;
                let mut partition = Partition::new(4).unwrap();
                let mut next_reason = 1u64;
                for group in &groups {
                    for &member in &group[1..] {
                        partition
                            .merge(group[0], member, reason(next_reason))
                            .unwrap();
                        next_reason += 1;
                    }
                }
                for (bit, &(left_class, right_class)) in class_pairs.iter().enumerate() {
                    if mask & (1usize << bit) != 0 {
                        partition
                            .separate(
                                groups[left_class][0],
                                groups[right_class][0],
                                reason(next_reason),
                            )
                            .unwrap();
                        next_reason += 1;
                    }
                }

                assert_eq!(partition.canonical_classes().unwrap(), groups);
                assert_eq!(
                    partition.disequality_edge_count().unwrap(),
                    mask.count_ones() as usize
                );
                let canonical_edges = partition.canonical_disequalities().unwrap();
                assert_eq!(canonical_edges.len(), mask.count_ones() as usize);
                assert!(canonical_edges.windows(2).all(|edges| {
                    (edges[0].left, edges[0].right) < (edges[1].left, edges[1].right)
                }));

                for left in 0..4usize {
                    for right in 0..4usize {
                        let expected = if labels[left] == labels[right] {
                            Relation::Equal
                        } else {
                            let class_pair = normalized_index_pair(labels[left], labels[right]);
                            let bit = pair_bit[&class_pair];
                            if mask & (1usize << bit) != 0 {
                                Relation::Disequal
                            } else {
                                Relation::Unknown
                            }
                        };
                        assert_eq!(
                            partition
                                .relation(
                                    TermId::try_from(left).unwrap(),
                                    TermId::try_from(right).unwrap()
                                )
                                .unwrap(),
                            expected
                        );
                    }
                }

                let before_conflicts = partition.snapshot();
                assert!(matches!(
                    partition.separate(groups[0][0], groups[0][0], reason(u64::MAX)),
                    Err(PartitionError::Conflict(
                        Conflict::DisequalityAgainstEquality { .. }
                    ))
                ));
                if let Some((bit, &(left_class, right_class))) = class_pairs
                    .iter()
                    .enumerate()
                    .find(|(bit, _)| mask & (1usize << bit) != 0)
                {
                    assert!(bit < class_pairs.len());
                    assert!(matches!(
                        partition.merge(
                            groups[left_class][0],
                            groups[right_class][0],
                            reason(u64::MAX - 1)
                        ),
                        Err(PartitionError::Conflict(
                            Conflict::EqualityAgainstDisequality { .. }
                        ))
                    ));
                }
                assert_eq!(partition.snapshot(), before_conflicts);
                partition.validate().unwrap();
            }
        }
        assert_eq!(checked_states, 127);
    }

    #[test]
    fn deterministic_mutation_trace_matches_slow_reference() {
        const TERM_COUNT: usize = 7;
        const STEPS: usize = 4_000;

        let mut partition = Partition::new(TERM_COUNT).unwrap();
        let mut model = SlowModel::new(TERM_COUNT);
        let mut checkpoints = vec![(partition.snapshot(), model.clone())];
        let mut random = XorShift64::new(0x9e37_79b9_7f4a_7c15);

        for step in 0..STEPS {
            let action = random.next() % 100;
            let left = term((random.next() as usize % TERM_COUNT) as u32);
            let right = term((random.next() as usize % TERM_COUNT) as u32);
            let why = reason((step % 29) as u64);

            if action < 38 {
                let expected = model.merge(left, right, why);
                let observed = partition.merge(left, right, why);
                match (expected, observed) {
                    (Ok(changed), Ok(outcome)) => assert_eq!(outcome.changed(), changed),
                    (Err(()), Err(PartitionError::Conflict(_))) => {}
                    pair => panic!("merge result mismatch at step {step}: {pair:?}"),
                }
            } else if action < 72 {
                let expected = model.separate(left, right, why);
                let observed = partition.separate(left, right, why);
                match (expected, observed) {
                    (Ok(changed), Ok(outcome)) => assert_eq!(outcome.changed(), changed),
                    (Err(()), Err(PartitionError::Conflict(_))) => {}
                    pair => panic!("separation result mismatch at step {step}: {pair:?}"),
                }
            } else if action < 86 {
                checkpoints.push((partition.snapshot(), model.clone()));
            } else {
                let selected = random.next() as usize % checkpoints.len();
                let (snapshot, saved) = checkpoints[selected].clone();
                partition.rollback(snapshot).unwrap();
                model = saved;
                checkpoints.truncate(selected + 1);
            }

            assert_partition_matches_model(&partition, &model, step);
        }
    }

    #[test]
    fn corrupted_private_state_fails_closed_in_tests() {
        let mut bad_parent = Partition::new(2).unwrap();
        bad_parent.parent[0] = 99;
        assert!(matches!(
            bad_parent.representative(term(0)),
            Err(PartitionError::InvariantViolation(_))
        ));
        assert!(matches!(
            bad_parent.validate(),
            Err(PartitionError::InvariantViolation(_))
        ));

        let mut bad_edge = Partition::new(2).unwrap();
        bad_edge.separate(term(0), term(1), reason(1)).unwrap();
        bad_edge.disequalities[1].clear();
        assert!(matches!(
            bad_edge.relation(term(0), term(1)),
            Err(PartitionError::InvariantViolation(_))
        ));
    }

    fn restricted_growth_partitions(term_count: usize) -> Vec<Vec<usize>> {
        if term_count == 0 {
            return vec![Vec::new()];
        }
        fn visit(
            position: usize,
            maximum: usize,
            labels: &mut [usize],
            output: &mut Vec<Vec<usize>>,
        ) {
            if position == labels.len() {
                output.push(labels.to_vec());
                return;
            }
            for label in 0..=maximum + 1 {
                labels[position] = label;
                visit(position + 1, maximum.max(label), labels, output);
            }
        }

        let mut labels = vec![0; term_count];
        let mut output = Vec::new();
        visit(1, 0, &mut labels, &mut output);
        output
    }

    #[derive(Debug, Clone)]
    struct SlowModel {
        term_count: usize,
        merges: Vec<MergeRecord>,
        separations: Vec<SeparationRecord>,
    }

    impl SlowModel {
        fn new(term_count: usize) -> Self {
            Self {
                term_count,
                merges: Vec::new(),
                separations: Vec::new(),
            }
        }

        fn roots(&self) -> Vec<usize> {
            let mut parent = (0..self.term_count).collect::<Vec<_>>();
            for record in &self.merges {
                let left = slow_root(&parent, record.left.raw() as usize);
                let right = slow_root(&parent, record.right.raw() as usize);
                assert_ne!(left, right);
                parent[right] = left;
            }
            (0..self.term_count)
                .map(|term| slow_root(&parent, term))
                .collect()
        }

        fn relation(&self, left: TermId, right: TermId) -> Relation {
            let roots = self.roots();
            let left_root = roots[left.raw() as usize];
            let right_root = roots[right.raw() as usize];
            if left_root == right_root {
                return Relation::Equal;
            }
            if self.separations.iter().any(|record| {
                normalized_index_pair(
                    roots[record.left.raw() as usize],
                    roots[record.right.raw() as usize],
                ) == normalized_index_pair(left_root, right_root)
            }) {
                Relation::Disequal
            } else {
                Relation::Unknown
            }
        }

        fn merge(&mut self, left: TermId, right: TermId, why: ReasonId) -> Result<bool, ()> {
            match self.relation(left, right) {
                Relation::Equal => Ok(false),
                Relation::Disequal => Err(()),
                Relation::Unknown => {
                    self.merges.push(MergeRecord {
                        left,
                        right,
                        reason: why,
                    });
                    Ok(true)
                }
            }
        }

        fn separate(&mut self, left: TermId, right: TermId, why: ReasonId) -> Result<bool, ()> {
            if self.relation(left, right) == Relation::Equal {
                return Err(());
            }
            let normalized = normalized_term_pair(left, right);
            if self.separations.iter().any(|record| {
                normalized_term_pair(record.left, record.right) == normalized
                    && record.reason == why
            }) {
                return Ok(false);
            }
            self.separations.push(SeparationRecord {
                left,
                right,
                reason: why,
            });
            Ok(true)
        }

        fn canonical_classes(&self) -> Vec<Vec<TermId>> {
            let roots = self.roots();
            let mut grouped = BTreeMap::<usize, Vec<TermId>>::new();
            for (index, &root) in roots.iter().enumerate() {
                grouped
                    .entry(root)
                    .or_default()
                    .push(TermId::try_from(index).unwrap());
            }
            let mut classes = grouped.into_values().collect::<Vec<_>>();
            classes.sort_by_key(|members| members[0]);
            classes
        }

        fn disequality_edge_count(&self) -> usize {
            let roots = self.roots();
            self.separations
                .iter()
                .map(|record| {
                    normalized_index_pair(
                        roots[record.left.raw() as usize],
                        roots[record.right.raw() as usize],
                    )
                })
                .collect::<BTreeSet<_>>()
                .len()
        }
    }

    fn slow_root(parent: &[usize], mut index: usize) -> usize {
        while parent[index] != index {
            index = parent[index];
        }
        index
    }

    fn assert_partition_matches_model(partition: &Partition, model: &SlowModel, step: usize) {
        partition
            .validate()
            .unwrap_or_else(|error| panic!("validation failed at step {step}: {error}"));
        assert_eq!(partition.merge_records(), model.merges, "step {step}");
        assert_eq!(
            partition.separation_records(),
            model.separations,
            "step {step}"
        );
        assert_eq!(
            partition.canonical_classes().unwrap(),
            model.canonical_classes(),
            "step {step}"
        );
        assert_eq!(
            partition.disequality_edge_count().unwrap(),
            model.disequality_edge_count(),
            "step {step}"
        );
        for left in 0..model.term_count {
            for right in 0..model.term_count {
                let left = TermId::try_from(left).unwrap();
                let right = TermId::try_from(right).unwrap();
                assert_eq!(
                    partition.relation(left, right).unwrap(),
                    model.relation(left, right),
                    "relation mismatch for ({left}, {right}) at step {step}"
                );
            }
        }
    }

    struct XorShift64(u64);

    impl XorShift64 {
        fn new(seed: u64) -> Self {
            assert_ne!(seed, 0);
            Self(seed)
        }

        fn next(&mut self) -> u64 {
            let mut value = self.0;
            value ^= value << 13;
            value ^= value >> 7;
            value ^= value << 17;
            self.0 = value;
            value
        }
    }
}

#[cfg(test)]
#[path="group_rows_tests.rs"] mod group_rows_tests;

#[cfg(test)]
#[path="row_representation_tests.rs"] mod row_representation_tests;

#[cfg(all(test, feature = "fabric"))]
#[path="policy_ablation_partition.rs"] mod policy_ablation_partition;
