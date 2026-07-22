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

/// A checked rollback equality partition over a fixed set of terms.
///
/// The type is not `Clone`: snapshots are meaningful only for the unique
/// history that created them.
#[derive(Debug)]
pub struct Partition {
    partition_id: u64,
    parent: Vec<usize>,
    size: Vec<usize>,
    minimum: Vec<TermId>,
    disequalities: Vec<Adjacency>,
    classes: usize,
    merge_records: Vec<MergeRecord>,
    separation_records: BTreeMap<EdgeId, SeparationRecord>,
    trail: Vec<TrailEntry>,
    next_state_id: u64,
}

pub type RollbackPartition = Partition;
pub type EqualityPartition = Partition;

impl Partition {
    /// Constructs an identity partition containing `term_count` stable terms.
    pub fn new(term_count: usize) -> PartitionResult<Self> {
        Self::try_new(term_count)
    }

    /// Fallible constructor; equivalent to [`Partition::new`].
    pub fn try_new(term_count: usize) -> PartitionResult<Self> {
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
        let mut disequalities = Vec::new();
        parent
            .try_reserve_exact(term_count)
            .map_err(|_| PartitionError::AllocationFailed)?;
        size.try_reserve_exact(term_count)
            .map_err(|_| PartitionError::AllocationFailed)?;
        minimum
            .try_reserve_exact(term_count)
            .map_err(|_| PartitionError::AllocationFailed)?;
        disequalities
            .try_reserve_exact(term_count)
            .map_err(|_| PartitionError::AllocationFailed)?;

        for index in 0..term_count {
            let term = TermId::try_from(index).map_err(|_| PartitionError::TooManyTerms {
                requested: term_count,
                maximum: MAX_TERMS,
            })?;
            parent.push(index);
            size.push(1);
            minimum.push(term);
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
            size,
            minimum,
            disequalities,
            classes: term_count,
            merge_records: Vec::new(),
            separation_records: BTreeMap::new(),
            trail: Vec::new(),
            next_state_id: 1,
        })
    }

    pub fn term_count(&self) -> usize {
        self.parent.len()
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
        self.separation_records.len()
    }

    /// Number of distinct current class-to-class disequality edges.
    pub fn disequality_edge_count(&self) -> PartitionResult<usize> {
        let mut directed = 0usize;
        for (root, adjacency) in self.disequalities.iter().enumerate() {
            if self.parent.get(root).copied() == Some(root) {
                self.check_root_adjacency(root)?;
            } else if !adjacency.is_empty() {
                return Err(PartitionError::InvariantViolation(
                    "non-root has disequality adjacency",
                ));
            }
            directed =
                directed
                    .checked_add(adjacency.len())
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
        let mut members = Vec::with_capacity(self.class_size(term)?);
        for index in 0..self.term_count() {
            if self.root_index(index)? == wanted_root {
                members.push(self.term_from_index(index)?);
            }
        }
        Ok(members)
    }

    pub fn relation(&self, left: TermId, right: TermId) -> PartitionResult<Relation> {
        let left_root = self.root_of_term(left)?;
        let right_root = self.root_of_term(right)?;
        if left_root == right_root {
            return Ok(Relation::Equal);
        }
        if self.edge_ids_between(left_root, right_root)?.is_some() {
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
        let Some(edge_ids) = self.edge_ids_between(left_root, right_root)? else {
            return Ok(None);
        };
        let mut records = Vec::new();
        records
            .try_reserve_exact(edge_ids.len())
            .map_err(|_| PartitionError::AllocationFailed)?;
        for edge_id in edge_ids {
            let record = self.separation_records.get(edge_id).copied().ok_or(
                PartitionError::InvariantViolation("disequality edge has no separation record"),
            )?;
            let record_left = self.root_of_term(record.left)?;
            let record_right = self.root_of_term(record.right)?;
            if normalized_index_pair(record_left, record_right)
                != normalized_index_pair(left_root, right_root)
            {
                return Err(PartitionError::InvariantViolation(
                    "separation record does not induce its current edge",
                ));
            }
            records.push(record);
        }
        Ok(Some(records))
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
        self.separation_records.values().copied().collect()
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
        let mut result = BTreeMap::<(TermId, TermId), Vec<SeparationRecord>>::new();
        for left_root in 0..self.term_count() {
            if self.parent[left_root] != left_root {
                if !self.disequalities[left_root].is_empty() {
                    return Err(PartitionError::InvariantViolation(
                        "non-root has disequality adjacency",
                    ));
                }
                continue;
            }
            self.check_root_adjacency(left_root)?;
            for (&right_root, edge_ids) in &self.disequalities[left_root] {
                if left_root >= right_root {
                    continue;
                }
                let pair = normalized_term_pair(self.minimum[left_root], self.minimum[right_root]);
                let mut witnesses = Vec::new();
                witnesses
                    .try_reserve_exact(edge_ids.len())
                    .map_err(|_| PartitionError::AllocationFailed)?;
                for edge_id in edge_ids {
                    witnesses.push(*self.separation_records.get(edge_id).ok_or(
                        PartitionError::InvariantViolation(
                            "disequality edge has no separation record",
                        ),
                    )?);
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

        if self.edge_ids_between(left_root, right_root)?.is_some() {
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
        let kept_adjacency = self.disequalities[kept].clone();
        let removed_adjacency = self.disequalities[removed].clone();
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
        self.disequalities[removed].clear();
        self.parent[removed] = kept;
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

        let existing = self.edge_ids_between(left_root, right_root)?;
        if let Some(edge_ids) = existing {
            let normalized_requested = normalized_term_pair(left, right);
            for edge_id in edge_ids {
                let prior = self.separation_records.get(edge_id).ok_or(
                    PartitionError::InvariantViolation("disequality edge has no separation record"),
                )?;
                if normalized_term_pair(prior.left, prior.right) == normalized_requested
                    && prior.reason == reason
                {
                    return Ok(SeparationOutcome::AlreadyPresent);
                }
            }
        }

        self.check_root_adjacency(left_root)?;
        self.check_root_adjacency(right_root)?;
        let relation_was_known = existing.is_some();
        let state_id = self.prepare_update(false)?;
        let edge_id = state_id;
        if self.separation_records.contains_key(&edge_id) {
            return Err(PartitionError::InvariantViolation(
                "state ID reused as a separation edge ID",
            ));
        }

        self.separation_records.insert(edge_id, record);
        self.disequalities[left_root]
            .entry(right_root)
            .or_default()
            .insert(edge_id);
        self.disequalities[right_root]
            .entry(left_root)
            .or_default()
            .insert(edge_id);
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
            || self.disequalities.len() != term_count
        {
            return Err(PartitionError::InvariantViolation(
                "parallel term arrays have different lengths",
            ));
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
                self.check_root_adjacency(index)?;
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

        if self.merge_records.len() != term_count.saturating_sub(actual_classes) {
            return Err(PartitionError::InvariantViolation(
                "merge record count does not describe a spanning forest",
            ));
        }
        self.validate_merge_forest()?;

        for (&edge_id, record) in &self.separation_records {
            let left_root = self.root_of_term(record.left)?;
            let right_root = self.root_of_term(record.right)?;
            if left_root == right_root {
                return Err(PartitionError::InvariantViolation(
                    "active separation has equal endpoints",
                ));
            }
            if !self.disequalities[left_root]
                .get(&right_root)
                .is_some_and(|ids| ids.contains(&edge_id))
                || !self.disequalities[right_root]
                    .get(&left_root)
                    .is_some_and(|ids| ids.contains(&edge_id))
            {
                return Err(PartitionError::InvariantViolation(
                    "separation record is missing from adjacency",
                ));
            }
        }

        if self.trail.len() != self.merge_records.len() + self.separation_records.len() {
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
                    || self.separation_records.get(edge_id) != Some(record)
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

    fn edge_ids_between(
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
        let forward = self.disequalities[left_root].get(&right_root);
        let reverse = self.disequalities[right_root].get(&left_root);
        match (forward, reverse) {
            (None, None) => Ok(None),
            (Some(first), Some(second)) if !first.is_empty() && first == second => Ok(Some(first)),
            _ => Err(PartitionError::InvariantViolation(
                "disequality adjacency is asymmetric or empty",
            )),
        }
    }

    fn check_root_adjacency(&self, root: usize) -> PartitionResult<()> {
        if root >= self.term_count() || self.parent[root] != root {
            return Err(PartitionError::InvariantViolation(
                "disequality adjacency owner is not a root",
            ));
        }
        for (&neighbor, edge_ids) in &self.disequalities[root] {
            if neighbor >= self.term_count()
                || neighbor == root
                || self.parent[neighbor] != neighbor
                || edge_ids.is_empty()
            {
                return Err(PartitionError::InvariantViolation(
                    "invalid disequality adjacency endpoint",
                ));
            }
            if self.disequalities[neighbor].get(&root) != Some(edge_ids) {
                return Err(PartitionError::InvariantViolation(
                    "disequality adjacency is not symmetric",
                ));
            }
            for edge_id in edge_ids {
                if !self.separation_records.contains_key(edge_id) {
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
        let undo = self
            .trail
            .last()
            .ok_or(PartitionError::InvariantViolation(
                "rollback trail is empty",
            ))?
            .undo
            .clone();
        self.preflight_undo(&undo)?;
        match undo {
            Undo::Separation {
                left_root,
                right_root,
                edge_id,
                ..
            } => {
                self.remove_edge_id(left_root, right_root, edge_id);
                self.remove_edge_id(right_root, left_root, edge_id);
                self.separation_records.remove(&edge_id);
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
                let mut affected = BTreeSet::new();
                affected.extend(self.disequalities[kept].keys().copied());
                affected.extend(kept_adjacency.keys().copied());
                affected.extend(removed_adjacency.keys().copied());
                for neighbor in affected {
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
                self.parent[removed] = removed;
                self.size[kept] = kept_size;
                self.minimum[kept] = kept_minimum;
                self.classes += 1;
                self.merge_records.pop();
            }
        }
        self.trail.pop();
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
                if *left_root >= self.term_count()
                    || *right_root >= self.term_count()
                    || self.separation_records.get(edge_id) != Some(record)
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
                let mut expected = kept_adjacency.clone();
                for (&neighbor, edge_ids) in removed_adjacency {
                    expected
                        .entry(neighbor)
                        .or_default()
                        .extend(edge_ids.iter().copied());
                }
                if self.disequalities[*kept] != expected {
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

        for left in 0..self.term_count() {
            for right in 0..left {
                let proof_equal =
                    proof_root(&proof_parent, left)? == proof_root(&proof_parent, right)?;
                let partition_equal = self.root_index(left)? == self.root_index(right)?;
                if proof_equal != partition_equal {
                    return Err(PartitionError::InvariantViolation(
                        "merge records and union-find disagree",
                    ));
                }
            }
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
