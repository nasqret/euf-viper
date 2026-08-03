//! Shared immutable data contracts for the T11 equality-resolution pipeline.
//!
//! This module intentionally contains no proof construction, scheduling,
//! canonicalization, subsumption, or checker replay logic. The compiler and
//! checker may exchange these records, but each must independently compute the
//! values stored in them.

use super::{BoolAtomKey, FlatClauses, FunDeclTable, SortTable, Term, TermId};
use rustc_hash::FxHashMap;
use std::fmt;

pub(crate) const EQRES_SCHEMA_VERSION: u32 = 1;
pub(crate) const EQRES_ENV: &str = "EUF_VIPER_T11_EQRES";

/// A read-only view of the exact in-memory direct-root baseline.
///
/// `ordered_applications` is the term-arena application order, not a rebuilt
/// or independently sorted list. `variable_atoms` and `atom_variables` are the
/// reciprocal baseline maps and therefore carry the baseline variable IDs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EqresInput<'a> {
    pub(crate) source_bytes: &'a [u8],
    pub(crate) root_cnf_mode: &'a [u8],
    pub(crate) sorts: &'a SortTable,
    pub(crate) declarations: &'a FunDeclTable,
    pub(crate) term_dag: &'a [Term],
    pub(crate) ordered_applications: &'a [TermId],
    pub(crate) baseline_clauses: &'a FlatClauses,
    pub(crate) variable_atoms: &'a [Option<BoolAtomKey>],
    pub(crate) atom_variables: &'a FxHashMap<BoolAtomKey, i32>,
    pub(crate) true_literal: Option<i32>,
    pub(crate) finite_equalities_complete: bool,
    pub(crate) finite_predicate_congruence_complete: bool,
}

macro_rules! define_u32_id {
    ($name:ident) => {
        #[repr(transparent)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "certificates", serde(transparent))]
        pub(crate) struct $name(u32);

        impl $name {
            pub(crate) const fn new(value: u32) -> Self {
                Self(value)
            }

            pub(crate) const fn get(self) -> u32 {
                self.0
            }
        }
    };
}

define_u32_id!(NodeId);
define_u32_id!(ClauseId);
define_u32_id!(EventId);
define_u32_id!(LiteralOffset);
define_u32_id!(ArgumentIndex);
define_u32_id!(ProofDepth);

/// An application ID is the existing term ID of an application node.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(transparent))]
pub(crate) struct ApplicationId(TermId);

impl ApplicationId {
    pub(crate) const fn new(term: TermId) -> Self {
        Self(term)
    }

    pub(crate) const fn term(self) -> TermId {
        self.0
    }
}

/// An unordered, normalized pair of existing term IDs.
///
/// Construction rejects reversed inputs instead of normalizing them. That
/// keeps normalization inside the compiler and checker independently while
/// making every stored key satisfy `left <= right`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct EqualityKey {
    left: TermId,
    right: TermId,
}

impl EqualityKey {
    pub(crate) const fn from_normalized(left: TermId, right: TermId) -> Option<Self> {
        if left <= right {
            Some(Self { left, right })
        } else {
            None
        }
    }

    pub(crate) const fn left(self) -> TermId {
        self.left
    }

    pub(crate) const fn right(self) -> TermId {
        self.right
    }

    pub(crate) const fn endpoints(self) -> (TermId, TermId) {
        (self.left, self.right)
    }

    pub(crate) const fn is_reflexive(self) -> bool {
        self.left == self.right
    }
}

#[cfg(feature = "certificates")]
impl<'de> serde::Deserialize<'de> for EqualityKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EqualityKeyWire {
            left: TermId,
            right: TermId,
        }

        let wire = EqualityKeyWire::deserialize(deserializer)?;
        Self::from_normalized(wire.left, wire.right)
            .ok_or_else(|| serde::de::Error::custom("equality key endpoints must be normalized"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CanonicalClauseError {
    ZeroLiteral,
    InvalidLiteral,
    NotStrictlySorted,
    ComplementaryLiterals,
}

impl fmt::Display for CanonicalClauseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroLiteral => "canonical clause contains literal zero",
            Self::InvalidLiteral => "canonical clause contains an invalid signed literal",
            Self::NotStrictlySorted => "canonical clause literals are not strictly sorted",
            Self::ComplementaryLiterals => "canonical clause contains complementary literals",
        })
    }
}

/// A side clause or conflict clause in frozen signed-`i32` order.
///
/// The boxed slice prevents capacity or insertion-order details from becoming
/// part of the shared representation. Construction validates but never sorts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
#[cfg_attr(feature = "certificates", serde(transparent))]
pub(crate) struct CanonicalClause(Box<[i32]>);

impl CanonicalClause {
    pub(crate) fn from_sorted(literals: Vec<i32>) -> Result<Self, CanonicalClauseError> {
        validate_canonical_clause_literals(&literals)?;

        Ok(Self(literals.into_boxed_slice()))
    }

    pub(crate) fn empty() -> Self {
        Self(Box::new([]))
    }

    pub(crate) fn as_slice(&self) -> &[i32] {
        &self.0
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn validate_canonical_clause_literals(literals: &[i32]) -> Result<(), CanonicalClauseError> {
    if literals.contains(&0) {
        return Err(CanonicalClauseError::ZeroLiteral);
    }
    if literals.contains(&i32::MIN) {
        return Err(CanonicalClauseError::InvalidLiteral);
    }
    if literals.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(CanonicalClauseError::NotStrictlySorted);
    }

    let first_positive = literals.partition_point(|&literal| literal < 0);
    let mut negative_end = first_positive;
    let mut positive = first_positive;
    while negative_end > 0 && positive < literals.len() {
        let negative_variable = literals[negative_end - 1].unsigned_abs();
        let positive_variable = literals[positive] as u32;
        match negative_variable.cmp(&positive_variable) {
            std::cmp::Ordering::Less => negative_end -= 1,
            std::cmp::Ordering::Greater => positive += 1,
            std::cmp::Ordering::Equal => {
                return Err(CanonicalClauseError::ComplementaryLiterals);
            }
        }
    }
    Ok(())
}

#[cfg(feature = "certificates")]
impl<'de> serde::Deserialize<'de> for CanonicalClause {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let literals = Vec::<i32>::deserialize(deserializer)?;
        Self::from_sorted(literals).map_err(serde::de::Error::custom)
    }
}

impl AsRef<[i32]> for CanonicalClause {
    fn as_ref(&self) -> &[i32] {
        self.as_slice()
    }
}

/// The frozen T11 resource table. These are associated constants rather than
/// mutable configuration so a candidate cannot silently run with test limits.
pub(crate) struct Limits;

impl Limits {
    pub(crate) const TERMS: u64 = 16_384;
    pub(crate) const BASELINE_VARIABLES: u64 = 50_000;
    pub(crate) const BASELINE_CLAUSES: u64 = 131_072;
    pub(crate) const BASELINE_LITERAL_SLOTS: u64 = 1_048_576;
    pub(crate) const APPLICATIONS: u64 = 256;
    pub(crate) const APPLICATION_PAIRS: u64 = 5_000;
    pub(crate) const MAXIMUM_ARITY: u64 = 64;
    pub(crate) const APPLICATION_ARGUMENT_SLOTS: u64 = 16_384;
    pub(crate) const EQUALITY_PROOF_NODES: u64 = 100_000;
    pub(crate) const PROOF_PARENT_REFERENCES: u64 = 300_000;
    pub(crate) const PROOF_DEPTH: u64 = 256;
    pub(crate) const UNIQUE_DERIVED_CLAUSES: u64 = 25_000;
    pub(crate) const RETAINED_SIDE_CLAUSES_PER_EQUALITY: u64 = 8;
    pub(crate) const CANONICAL_PROOF_WORK_LITERAL_CHARGE: u64 = 2_000_000;
    pub(crate) const WORKLIST_PUSHES: u64 = 250_000;
    pub(crate) const LIVE_WORKLIST_ENTRIES: u64 = 65_536;
    pub(crate) const ALL_DERIVED_LITERAL_SLOTS: u64 = 150_000;
    pub(crate) const EMITTED_LEMMAS: u64 = 8_192;
    pub(crate) const EMITTED_LEMMA_LITERAL_SLOTS: u64 = 65_536;
    pub(crate) const EMITTED_P95_WIDTH: u64 = 8;
    pub(crate) const EMITTED_MAXIMUM_WIDTH: u64 = 32;
    pub(crate) const LOGICAL_INCREMENTAL_MEMORY_BYTES: u64 = 16 * 1024 * 1024;
}

/// Coefficients of `M = 64N + 32C + 4P + 4S + 64Q + 16R + 16O + 32A + 4G`.
pub(crate) struct LogicalMemoryWeights;

impl LogicalMemoryWeights {
    pub(crate) const EQUALITY_NODE: u64 = 64;
    pub(crate) const CONFLICT_CLAUSE: u64 = 32;
    pub(crate) const PARENT_REFERENCE: u64 = 4;
    pub(crate) const TRACE_LITERAL_SLOT: u64 = 4;
    pub(crate) const DISTINCT_EVENT_KEY: u64 = 64;
    pub(crate) const RETAINED_ANTICHAIN_ENTRY: u64 = 16;
    pub(crate) const NEGATIVE_OCCURRENCE: u64 = 16;
    pub(crate) const APPLICATION_PAIR: u64 = 32;
    pub(crate) const APPLICATION_ARGUMENT_SLOT: u64 = 4;
}

/// Rule discriminants are the frozen event-key ranks.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(rename_all = "snake_case"))]
pub(crate) enum RuleKind {
    Seed = 0,
    Reflexivity = 1,
    Transitivity = 2,
    Congruence = 3,
    Conflict = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(rename_all = "snake_case"))]
pub(crate) enum ClauseOrigin {
    Baseline,
    Derived,
}

/// A clause ID is global; `origin` records which topological rule applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct ClauseRef {
    pub(crate) id: ClauseId,
    pub(crate) origin: ClauseOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct ClausePivot {
    pub(crate) clause: ClauseRef,
    pub(crate) literal_offset: LiteralOffset,
}

/// The complete frozen worklist ordering key. Parent IDs include multiplicity
/// and are stored in ascending order; Congruence's argument associations live
/// in its trace record and are deliberately not substituted for this sequence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct EventKey {
    pub(crate) resulting_clause_width: u32,
    pub(crate) proof_depth: ProofDepth,
    pub(crate) rule: RuleKind,
    pub(crate) conclusion: Option<EqualityKey>,
    pub(crate) clause: CanonicalClause,
    pub(crate) source: Option<ClausePivot>,
    pub(crate) parents: Box<[NodeId]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct SeedRecord {
    pub(crate) positive_source: ClausePivot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct ReflexivityRecord {
    pub(crate) term: TermId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct TransitivityRecord {
    /// Sorted ascending for the event key; endpoint orientation is recovered
    /// independently from the conclusions and `intermediate`.
    pub(crate) parents: [NodeId; 2],
    pub(crate) intermediate: TermId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct CongruenceArgumentParent {
    pub(crate) argument_index: ArgumentIndex,
    pub(crate) parent: NodeId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct CongruenceRecord {
    pub(crate) applications: [ApplicationId; 2],
    /// One entry for every differing argument, in increasing argument-index
    /// order. Parent IDs here retain their argument association.
    pub(crate) arguments: Box<[CongruenceArgumentParent]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct ConflictRecord {
    pub(crate) equality_parent: NodeId,
    pub(crate) negative_source: ClausePivot,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "certificates",
    serde(
        deny_unknown_fields,
        tag = "rule",
        content = "premises",
        rename_all = "snake_case"
    )
)]
pub(crate) enum EqualityRuleRecord {
    Seed(SeedRecord),
    Reflexivity(ReflexivityRecord),
    Transitivity(TransitivityRecord),
    Congruence(CongruenceRecord),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct EqualityTraceRecord {
    pub(crate) event_id: EventId,
    pub(crate) node_id: NodeId,
    pub(crate) depth: ProofDepth,
    pub(crate) conclusion: EqualityKey,
    pub(crate) side_clause: CanonicalClause,
    pub(crate) rule: EqualityRuleRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct ConflictTraceRecord {
    pub(crate) event_id: EventId,
    pub(crate) clause_id: ClauseId,
    pub(crate) depth: ProofDepth,
    pub(crate) clause: CanonicalClause,
    pub(crate) rule: ConflictRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "certificates",
    serde(
        deny_unknown_fields,
        tag = "record_kind",
        content = "record",
        rename_all = "snake_case"
    )
)]
pub(crate) enum TraceRecord {
    Equality(EqualityTraceRecord),
    Conflict(ConflictTraceRecord),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct EmittedLemma {
    pub(crate) source_clause_id: ClauseId,
    pub(crate) clause: CanonicalClause,
}

/// Successful terminal states. `Lemmas` is nonempty and contains no empty
/// clause; `TheoryEmpty` contains exactly the terminal empty Conflict lemma;
/// `NoLemmas` contains no lemma. The checker enforces those shape invariants.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "certificates",
    serde(
        deny_unknown_fields,
        tag = "outcome",
        content = "output",
        rename_all = "snake_case"
    )
)]
pub(crate) enum EqresOutput {
    Lemmas(Box<[EmittedLemma]>),
    TheoryEmpty {
        terminal_event_id: EventId,
        lemma: EmittedLemma,
    },
    NoLemmas,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum MaterializedClauseStoreError {
    MissingInitialOffset,
    NonMonotoneOffsets,
    FinalOffsetMismatch,
}

impl fmt::Display for MaterializedClauseStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingInitialOffset => "materialized clause offsets must start at zero",
            Self::NonMonotoneOffsets => "materialized clause offsets must be monotone",
            Self::FinalOffsetMismatch => {
                "materialized clause final offset must equal the literal count"
            }
        })
    }
}

/// Exact clause bytes exported by projection and consumed by a later SAT
/// loader. Construction validates the flat-store shape but deliberately does
/// not canonicalize, reorder, or deduplicate clauses.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct MaterializedClauseStore {
    end_offsets: Box<[u32]>,
    literals: Box<[i32]>,
}

impl MaterializedClauseStore {
    pub(crate) fn from_parts(
        end_offsets: Vec<u32>,
        literals: Vec<i32>,
    ) -> Result<Self, MaterializedClauseStoreError> {
        validate_materialized_clause_store_shape(&end_offsets, literals.len())?;
        Ok(Self {
            end_offsets: end_offsets.into_boxed_slice(),
            literals: literals.into_boxed_slice(),
        })
    }

    pub(crate) fn empty() -> Self {
        Self {
            end_offsets: Box::new([0]),
            literals: Box::new([]),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.end_offsets.len().saturating_sub(1)
    }

    pub(crate) fn end_offsets(&self) -> &[u32] {
        &self.end_offsets
    }

    pub(crate) fn literals(&self) -> &[i32] {
        &self.literals
    }

    pub(crate) fn clause(&self, index: usize) -> Option<&[i32]> {
        let start = *self.end_offsets.get(index)? as usize;
        let end = *self.end_offsets.get(index.checked_add(1)?)? as usize;
        self.literals.get(start..end)
    }

    #[cfg(test)]
    pub(crate) fn from_parts_unchecked_for_test(end_offsets: Vec<u32>, literals: Vec<i32>) -> Self {
        Self {
            end_offsets: end_offsets.into_boxed_slice(),
            literals: literals.into_boxed_slice(),
        }
    }
}

fn validate_materialized_clause_store_shape(
    end_offsets: &[u32],
    literal_count: usize,
) -> Result<(), MaterializedClauseStoreError> {
    if end_offsets.first() != Some(&0) {
        return Err(MaterializedClauseStoreError::MissingInitialOffset);
    }
    if end_offsets.windows(2).any(|bounds| bounds[0] > bounds[1]) {
        return Err(MaterializedClauseStoreError::NonMonotoneOffsets);
    }
    if end_offsets.last().copied().map(u64::from) != u64::try_from(literal_count).ok() {
        return Err(MaterializedClauseStoreError::FinalOffsetMismatch);
    }
    Ok(())
}

#[cfg(feature = "certificates")]
impl<'de> serde::Deserialize<'de> for MaterializedClauseStore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct MaterializedClauseStoreWire {
            end_offsets: Vec<u32>,
            literals: Vec<i32>,
        }

        let wire = MaterializedClauseStoreWire::deserialize(deserializer)?;
        Self::from_parts(wire.end_offsets, wire.literals).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct RuleCounters {
    pub(crate) seed: u64,
    pub(crate) reflexivity: u64,
    pub(crate) transitivity: u64,
    pub(crate) congruence: u64,
    pub(crate) conflict: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct InputCounters {
    pub(crate) terms: u64,
    pub(crate) baseline_variables: u64,
    pub(crate) baseline_atom_entries: u64,
    pub(crate) baseline_clauses: u64,
    pub(crate) baseline_literal_slots: u64,
    pub(crate) applications: u64,
    pub(crate) application_pairs: u64,
    pub(crate) maximum_arity: u64,
    pub(crate) application_argument_slots: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct SearchCounters {
    pub(crate) attempted_events: RuleCounters,
    pub(crate) accepted_events: RuleCounters,
    pub(crate) events_popped: u64,
    pub(crate) distinct_event_keys_inserted: u64,
    pub(crate) duplicate_event_keys: u64,
    pub(crate) worklist_pushes: u64,
    pub(crate) live_worklist_entries: u64,
    pub(crate) peak_live_worklist_entries: u64,
    pub(crate) queued_events_discarded_at_theory_empty: u64,
    pub(crate) accepted_equality_nodes: u64,
    pub(crate) accepted_conflict_clauses: u64,
    pub(crate) proof_parent_references: u64,
    pub(crate) maximum_proof_depth: u64,
    pub(crate) accepted_trace_literal_slots: u64,
    pub(crate) canonical_proof_work_literal_charge: u64,
    pub(crate) retained_antichain_entries: u64,
    pub(crate) peak_retained_antichain_entries: u64,
    pub(crate) registered_negative_equality_occurrences: u64,
    pub(crate) logical_incremental_memory_bytes: u64,
    pub(crate) suppressed_missing_equality_congruence_events: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct PruningCounters {
    pub(crate) support_subset_discards: u64,
    pub(crate) support_capacity_discards: u64,
    pub(crate) support_removed_supersets: u64,
    pub(crate) duplicate_derived_clauses: u64,
    pub(crate) tautological_derived_clauses: u64,
    pub(crate) final_base_subsumption_discards: u64,
    pub(crate) final_output_subsumption_discards: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct OutputCounters {
    pub(crate) emitted_lemmas: u64,
    pub(crate) emitted_literal_slots: u64,
    pub(crate) emitted_p95_width: u64,
    pub(crate) emitted_maximum_width: u64,
    pub(crate) emitted_with_missing_equality_congruence: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct DeterministicCounters {
    pub(crate) input: InputCounters,
    pub(crate) search: SearchCounters,
    pub(crate) pruning: PruningCounters,
    pub(crate) output: OutputCounters,
}

/// Variant order is the frozen hard-limit precedence. The eight-support
/// antichain threshold is intentionally absent because it prunes rather than
/// rejecting the projection.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(rename_all = "snake_case"))]
pub(crate) enum CapReason {
    Terms = 0,
    BaselineVariables = 1,
    BaselineClauses = 2,
    BaselineLiteralSlots = 3,
    Applications = 4,
    ApplicationPairs = 5,
    MaximumArity = 6,
    ApplicationArgumentSlots = 7,
    EqualityProofNodes = 8,
    ProofParentReferences = 9,
    ProofDepth = 10,
    UniqueDerivedClauses = 11,
    CanonicalProofWorkLiteralCharge = 12,
    WorklistPushes = 13,
    LiveWorklistEntries = 14,
    AllDerivedLiteralSlots = 15,
    EmittedLemmas = 16,
    EmittedLemmaLiteralSlots = 17,
    EmittedP95Width = 18,
    EmittedMaximumWidth = 19,
    LogicalIncrementalMemoryBytes = 20,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "certificates",
    serde(
        deny_unknown_fields,
        tag = "boundary",
        content = "context",
        rename_all = "snake_case"
    )
)]
pub(crate) enum CapBoundary {
    StaticInput,
    NegativeRegistration(ClausePivot),
    PoppedEventAcceptance(EventId),
    ChildInsertion {
        parent_event: Option<EventId>,
        rule: RuleKind,
    },
    FinalOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct CapAttempt {
    pub(crate) reason: CapReason,
    pub(crate) boundary: CapBoundary,
    pub(crate) pre_event_value: u64,
    pub(crate) prospective_value: u64,
    pub(crate) limit: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(rename_all = "snake_case"))]
pub(crate) enum InputFailure {
    InvalidClauseStore,
    InvalidClauseLiteral,
    InvalidAtomMap,
    InvalidAtomTerm,
    InvalidTerm,
    InvalidApplicationOrder,
    InvalidApplication,
    InvalidDeclaration,
    InvalidSort,
    UnsupportedBooleanApplicationPair,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(rename_all = "snake_case"))]
pub(crate) enum HashArtifact {
    Source,
    RootCnfMode,
    TermDag,
    AtomMap,
    BaselineCnf,
    BaselineProblem,
    Trace,
    LemmaSequence,
    MaterializedLemmas,
    MaterializedCandidate,
    CandidateBinary,
    Revision,
    CorpusManifest,
    ProjectionRecord,
    CheckerRecord,
    ObservationRecord,
    Dimacs,
    Invocation,
    Drat,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "certificates",
    serde(
        deny_unknown_fields,
        tag = "failure",
        content = "detail",
        rename_all = "snake_case"
    )
)]
pub(crate) enum CompilerFailure {
    Cap(CapAttempt),
    MalformedInput(InputFailure),
    IntegerOverflow { event_id: Option<EventId> },
    AllocationFailure { event_id: Option<EventId> },
    HashDrift(HashArtifact),
    InternalInvariant { event_id: Option<EventId> },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "certificates",
    serde(
        deny_unknown_fields,
        tag = "status",
        content = "detail",
        rename_all = "snake_case"
    )
)]
pub(crate) enum CompilerStatus {
    NotRun,
    Completed(EqresOutput),
    Rejected(CompilerFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(rename_all = "snake_case"))]
pub(crate) enum CompilerVariant {
    Ordinary,
    SuppressMissingEqualityCongruence,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(crate) struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub(crate) const ZERO: Self = Self([0; 32]);
    pub(crate) const EMPTY_BYTES: Self = Self([
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ]);

    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(feature = "certificates")]
impl serde::Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "certificates")]
impl<'de> serde::Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DigestVisitor;

        impl serde::de::Visitor<'_> for DigestVisitor {
            type Value = Sha256Digest;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("exactly 64 lowercase hexadecimal SHA-256 digits")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() != 64
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(E::custom(
                        "SHA-256 digest must contain 64 lowercase hexadecimal digits",
                    ));
                }
                let mut bytes = [0u8; 32];
                for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
                    let high = decode_lower_hex(pair[0]);
                    let low = decode_lower_hex(pair[1]);
                    bytes[index] = (high << 4) | low;
                }
                Ok(Sha256Digest::new(bytes))
            }
        }

        deserializer.deserialize_str(DigestVisitor)
    }
}

#[cfg(feature = "certificates")]
const fn decode_lower_hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

/// Required hash bindings use concrete digests rather than `Option`, so
/// theory-empty and no-lemma records still hash their exact empty byte streams.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct HashBindings {
    pub(crate) source_sha256: Sha256Digest,
    pub(crate) root_cnf_mode_sha256: Sha256Digest,
    pub(crate) term_dag_sha256: Sha256Digest,
    pub(crate) atom_map_sha256: Sha256Digest,
    pub(crate) baseline_cnf_sha256: Sha256Digest,
    pub(crate) baseline_problem_sha256: Sha256Digest,
    pub(crate) trace_sha256: Sha256Digest,
    pub(crate) lemma_sequence_sha256: Sha256Digest,
    pub(crate) materialized_lemmas_sha256: Sha256Digest,
    pub(crate) materialized_candidate_sha256: Sha256Digest,
    pub(crate) candidate_binary_sha256: Sha256Digest,
    pub(crate) revision_sha256: Sha256Digest,
    pub(crate) corpus_manifest_sha256: Sha256Digest,
    pub(crate) projection_record_sha256: Sha256Digest,
    pub(crate) checker_record_sha256: Sha256Digest,
    pub(crate) observation_record_sha256: Sha256Digest,
    pub(crate) dimacs_sha256: Sha256Digest,
    pub(crate) invocation_sha256: Sha256Digest,
    pub(crate) drat_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct CompilerResult {
    pub(crate) variant: CompilerVariant,
    pub(crate) status: CompilerStatus,
    /// Accepted records only, in topological acceptance order.
    pub(crate) trace: Box<[TraceRecord]>,
    pub(crate) counters: DeterministicCounters,
    pub(crate) hashes: HashBindings,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct CheckerCounters {
    pub(crate) replayed_equality_nodes: u64,
    pub(crate) replayed_conflict_clauses: u64,
    pub(crate) replayed_emitted_lemmas: u64,
    pub(crate) replay_failures: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(rename_all = "snake_case"))]
pub(crate) enum CheckerFailureKind {
    BaselineClauseReference,
    DerivedClauseReference,
    LiteralOffset,
    PivotSign,
    PivotKind,
    TermId,
    Sort,
    Function,
    Arity,
    ParentOrder,
    ParentNotEarlier,
    SourceNotEarlier,
    Conclusion,
    SideClause,
    TautologicalClause,
    ReflexivityOrder,
    TransitivityEndpoints,
    CongruenceApplicationOrder,
    CongruenceArgumentOrder,
    CongruenceArgumentAssociation,
    ConflictResolvent,
    TraceOrder,
    OutputOrder,
    OutputClause,
    OutcomeShape,
    HashMismatch,
    ArithmeticOverflow,
    MalformedTrace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct CheckerFailure {
    pub(crate) kind: CheckerFailureKind,
    pub(crate) event_id: Option<EventId>,
    pub(crate) artifact: Option<HashArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "certificates",
    serde(
        deny_unknown_fields,
        tag = "status",
        content = "failures",
        rename_all = "snake_case"
    )
)]
pub(crate) enum CheckerStatus {
    NotRun,
    Accepted,
    Rejected(Box<[CheckerFailure]>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct CheckerResult {
    pub(crate) status: CheckerStatus,
    pub(crate) counters: CheckerCounters,
    pub(crate) recomputed_hashes: HashBindings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(rename_all = "kebab-case"))]
pub(crate) enum EqresMode {
    Off,
    CliqueErAuto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(rename_all = "snake_case"))]
pub(crate) enum SolverBackend {
    Kissat,
    Cadical,
    CadicalRefine,
    Varisat,
    Fallback,
    Dpll,
}

/// Selector facts intentionally contain no source/path/family/result/timing
/// fields, preserving the preregistered information boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct SelectorFacts {
    pub(crate) finite_added_clauses: u64,
    pub(crate) covered_finite_terms: u64,
    pub(crate) closed_table_functions: u64,
    pub(crate) all_different_clique_lower_bound: u64,
    pub(crate) disequality_graph_edges: u64,
    pub(crate) equality_graph_vertices: u64,
    pub(crate) equality_graph_edges: u64,
    pub(crate) applications: u64,
    pub(crate) boolean_valued_application_pairs: u64,
    pub(crate) backend: SolverBackend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(rename_all = "snake_case"))]
pub(crate) enum SelectorRejection {
    ModeOff,
    MutuallyExclusiveOptIn,
    FiniteAddedNonzero,
    CoveredFiniteTermsNonzero,
    ClosedTableFunctionsNonzero,
    AllDifferentCliqueBelowMinimum,
    DisequalityCliqueArithmeticOverflow,
    DisequalityCliqueExcessEdges,
    EqualityGraphVerticesBelowMinimum,
    EqualityGraphEdgesBelowMinimum,
    ApplicationCountCap,
    BackendNotKissat,
    BooleanValuedApplicationPair,
    RuntimeFactMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "certificates",
    serde(
        deny_unknown_fields,
        tag = "decision",
        content = "reason",
        rename_all = "snake_case"
    )
)]
pub(crate) enum SelectorDecision {
    Selected,
    Rejected(SelectorRejection),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct SelectorReport {
    pub(crate) mode: EqresMode,
    pub(crate) facts: SelectorFacts,
    pub(crate) decision: SelectorDecision,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct ForbiddenGrowthCounters {
    pub(crate) added_terms: u64,
    pub(crate) added_atoms: u64,
    pub(crate) added_variables: u64,
    pub(crate) fill_edges: u64,
    pub(crate) generic_transitivity_clauses: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct IntegrityReport {
    pub(crate) baseline_unchanged: bool,
    pub(crate) trace_materialization_equal: bool,
    pub(crate) compiler_checker_agree: bool,
    pub(crate) output_canonical: bool,
    pub(crate) external_audit_accepted: bool,
    pub(crate) off_path_unchanged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(rename_all = "snake_case"))]
pub(crate) enum ReportOutcome {
    Off,
    Rejected,
    Lemmas,
    TheoryEmpty,
    NoLemmas,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(deny_unknown_fields))]
pub(crate) struct EqresReport {
    pub(crate) schema_version: u32,
    pub(crate) selector: SelectorReport,
    pub(crate) compiler_variant: CompilerVariant,
    pub(crate) outcome: ReportOutcome,
    pub(crate) counters: DeterministicCounters,
    pub(crate) checker_counters: CheckerCounters,
    pub(crate) cap_attempt: Option<CapAttempt>,
    pub(crate) forbidden_growth: ForbiddenGrowthCounters,
    pub(crate) integrity: IntegrityReport,
    pub(crate) sat_calls: u64,
    pub(crate) hashes: HashBindings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum EqresBundleStructureError {
    InvalidMaterializedStore(MaterializedClauseStoreError),
    InvalidSelectorState,
    InvalidCompilerState,
    InvalidCheckerState,
    NonCanonicalTrace,
    InvalidTraceOrder,
    TraceCounterMismatch,
    NonCanonicalOutput,
    InvalidOutputShape,
    OutputCounterMismatch,
    MaterializedOutputMismatch,
    CheckerReplayCountMismatch,
    ReportSchemaMismatch,
    ReportSelectorMismatch,
    ReportCompilerVariantMismatch,
    ReportCounterMismatch,
    ReportCheckerCounterMismatch,
    ReportCapAttemptMismatch,
    ReportOutcomeMismatch,
    ReportHashMismatch,
    CompilerCheckerHashMismatch,
    ReportIntegrityMismatch,
    CounterOverflow,
}

impl fmt::Display for EqresBundleStructureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMaterializedStore(error) => write!(formatter, "{error}"),
            Self::InvalidSelectorState => formatter.write_str("selector state is incoherent"),
            Self::InvalidCompilerState => formatter.write_str("compiler state is incoherent"),
            Self::InvalidCheckerState => formatter.write_str("checker state is incoherent"),
            Self::NonCanonicalTrace => {
                formatter.write_str("trace contains a noncanonical key or clause")
            }
            Self::InvalidTraceOrder => formatter.write_str("trace order is invalid"),
            Self::TraceCounterMismatch => {
                formatter.write_str("compiler trace counters do not match the sealed trace")
            }
            Self::NonCanonicalOutput => {
                formatter.write_str("compiler output is not in canonical order")
            }
            Self::InvalidOutputShape => formatter.write_str("compiler output shape is invalid"),
            Self::OutputCounterMismatch => {
                formatter.write_str("compiler output counters do not match the sealed output")
            }
            Self::MaterializedOutputMismatch => formatter
                .write_str("materialized clause store does not exactly match compiler output"),
            Self::CheckerReplayCountMismatch => {
                formatter.write_str("checker replay counters do not match trace and output")
            }
            Self::ReportSchemaMismatch => formatter.write_str("report schema version is invalid"),
            Self::ReportSelectorMismatch => {
                formatter.write_str("report selector does not match bundle selector")
            }
            Self::ReportCompilerVariantMismatch => {
                formatter.write_str("report compiler variant does not match compiler result")
            }
            Self::ReportCounterMismatch => {
                formatter.write_str("report compiler counters do not match compiler result")
            }
            Self::ReportCheckerCounterMismatch => {
                formatter.write_str("report checker counters do not match checker result")
            }
            Self::ReportCapAttemptMismatch => {
                formatter.write_str("report cap attempt does not match compiler status")
            }
            Self::ReportOutcomeMismatch => {
                formatter.write_str("report outcome does not match pipeline status")
            }
            Self::ReportHashMismatch => {
                formatter.write_str("report hashes do not match compiler hashes")
            }
            Self::CompilerCheckerHashMismatch => {
                formatter.write_str("accepted checker hashes do not match compiler hashes")
            }
            Self::ReportIntegrityMismatch => {
                formatter.write_str("report integrity flags contradict pipeline state")
            }
            Self::CounterOverflow => {
                formatter.write_str("decoded structure exceeds representable counters")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TraceStructureSummary {
    accepted_events: RuleCounters,
    equality_nodes: u64,
    conflict_clauses: u64,
    proof_parent_references: u64,
    maximum_proof_depth: u64,
    trace_literal_slots: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct OutputStructureSummary {
    emitted_lemmas: u64,
    emitted_literal_slots: u64,
    emitted_p95_width: u64,
    emitted_maximum_width: u64,
}

/// Compiler output and independent replay are kept side by side rather than
/// allowing the checker to mutate or replace compiler-owned records.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct EqresBundle {
    pub(crate) selector: SelectorReport,
    pub(crate) compiler: CompilerResult,
    materialized_lemmas: MaterializedClauseStore,
    pub(crate) checker: CheckerResult,
    pub(crate) report: EqresReport,
}

impl EqresBundle {
    pub(crate) fn new(
        selector: SelectorReport,
        compiler: CompilerResult,
        materialized_lemmas: MaterializedClauseStore,
        checker: CheckerResult,
        report: EqresReport,
    ) -> Self {
        Self {
            selector,
            compiler,
            materialized_lemmas,
            checker,
            report,
        }
    }

    pub(crate) fn materialized_lemmas(&self) -> &MaterializedClauseStore {
        &self.materialized_lemmas
    }

    pub(crate) fn validate_structure(&self) -> Result<(), EqresBundleStructureError> {
        validate_materialized_clause_store_shape(
            self.materialized_lemmas.end_offsets(),
            self.materialized_lemmas.literals().len(),
        )
        .map_err(EqresBundleStructureError::InvalidMaterializedStore)?;

        validate_selector_and_execution_state(self)?;
        let trace = validate_trace_structure(&self.compiler)?;
        let output = validate_output_structure(&self.compiler)?;
        validate_materialized_output(self)?;
        validate_checker_structure(self, trace, output)?;
        validate_report_structure(self)?;
        Ok(())
    }
}

fn validate_selector_and_execution_state(
    bundle: &EqresBundle,
) -> Result<(), EqresBundleStructureError> {
    match (bundle.selector.mode, bundle.selector.decision) {
        (EqresMode::Off, SelectorDecision::Rejected(SelectorRejection::ModeOff)) => {}
        (EqresMode::Off, _)
        | (EqresMode::CliqueErAuto, SelectorDecision::Rejected(SelectorRejection::ModeOff)) => {
            return Err(EqresBundleStructureError::InvalidSelectorState);
        }
        (EqresMode::CliqueErAuto, _) => {}
    }

    match (&bundle.selector.decision, &bundle.compiler.status) {
        (SelectorDecision::Selected, CompilerStatus::NotRun)
        | (SelectorDecision::Rejected(_), CompilerStatus::Completed(_))
        | (SelectorDecision::Rejected(_), CompilerStatus::Rejected(_)) => {
            return Err(EqresBundleStructureError::InvalidCompilerState);
        }
        _ => {}
    }

    if matches!(bundle.compiler.status, CompilerStatus::NotRun) {
        if !bundle.compiler.trace.is_empty()
            || bundle.compiler.counters != DeterministicCounters::default()
            || bundle.compiler.hashes != HashBindings::default()
            || !matches!(bundle.checker.status, CheckerStatus::NotRun)
            || bundle.checker.counters != CheckerCounters::default()
            || bundle.checker.recomputed_hashes != HashBindings::default()
            || bundle.materialized_lemmas.len() != 0
        {
            return Err(EqresBundleStructureError::InvalidCompilerState);
        }
    } else if matches!(bundle.checker.status, CheckerStatus::NotRun) {
        return Err(EqresBundleStructureError::InvalidCheckerState);
    }
    Ok(())
}

fn validate_trace_structure(
    compiler: &CompilerResult,
) -> Result<TraceStructureSummary, EqresBundleStructureError> {
    let mut summary = TraceStructureSummary::default();
    let mut previous_event_id = None;

    for record in &compiler.trace {
        let (event_id, depth, clause, parent_references) = match record {
            TraceRecord::Equality(record) => {
                if record.conclusion.left > record.conclusion.right
                    || validate_canonical_clause_literals(record.side_clause.as_slice()).is_err()
                {
                    return Err(EqresBundleStructureError::NonCanonicalTrace);
                }
                if record.node_id.get()
                    != u32::try_from(summary.equality_nodes)
                        .map_err(|_| EqresBundleStructureError::CounterOverflow)?
                {
                    return Err(EqresBundleStructureError::InvalidTraceOrder);
                }
                let (counter, parent_references) = match &record.rule {
                    EqualityRuleRecord::Seed(_) => (&mut summary.accepted_events.seed, 0u64),
                    EqualityRuleRecord::Reflexivity(_) => {
                        (&mut summary.accepted_events.reflexivity, 0u64)
                    }
                    EqualityRuleRecord::Transitivity(transitivity) => {
                        if transitivity.parents[0] > transitivity.parents[1] {
                            return Err(EqresBundleStructureError::InvalidTraceOrder);
                        }
                        (&mut summary.accepted_events.transitivity, 2u64)
                    }
                    EqualityRuleRecord::Congruence(congruence) => {
                        if congruence.applications[0].term() >= congruence.applications[1].term()
                            || congruence
                                .arguments
                                .windows(2)
                                .any(|pair| pair[0].argument_index >= pair[1].argument_index)
                        {
                            return Err(EqresBundleStructureError::InvalidTraceOrder);
                        }
                        (
                            &mut summary.accepted_events.congruence,
                            u64::try_from(congruence.arguments.len())
                                .map_err(|_| EqresBundleStructureError::CounterOverflow)?,
                        )
                    }
                };
                *counter = counter
                    .checked_add(1)
                    .ok_or(EqresBundleStructureError::CounterOverflow)?;
                summary.equality_nodes = summary
                    .equality_nodes
                    .checked_add(1)
                    .ok_or(EqresBundleStructureError::CounterOverflow)?;
                (
                    record.event_id,
                    record.depth,
                    &record.side_clause,
                    parent_references,
                )
            }
            TraceRecord::Conflict(record) => {
                if validate_canonical_clause_literals(record.clause.as_slice()).is_err() {
                    return Err(EqresBundleStructureError::NonCanonicalTrace);
                }
                summary.accepted_events.conflict = summary
                    .accepted_events
                    .conflict
                    .checked_add(1)
                    .ok_or(EqresBundleStructureError::CounterOverflow)?;
                summary.conflict_clauses = summary
                    .conflict_clauses
                    .checked_add(1)
                    .ok_or(EqresBundleStructureError::CounterOverflow)?;
                (record.event_id, record.depth, &record.clause, 1u64)
            }
        };

        if previous_event_id.is_some_and(|previous| previous >= event_id.get())
            || u64::from(event_id.get()) >= compiler.counters.search.events_popped
        {
            return Err(EqresBundleStructureError::InvalidTraceOrder);
        }
        previous_event_id = Some(event_id.get());
        summary.proof_parent_references = summary
            .proof_parent_references
            .checked_add(parent_references)
            .ok_or(EqresBundleStructureError::CounterOverflow)?;
        summary.maximum_proof_depth = summary.maximum_proof_depth.max(u64::from(depth.get()));
        summary.trace_literal_slots = summary
            .trace_literal_slots
            .checked_add(
                u64::try_from(clause.len())
                    .map_err(|_| EqresBundleStructureError::CounterOverflow)?,
            )
            .ok_or(EqresBundleStructureError::CounterOverflow)?;
    }

    let search = compiler.counters.search;
    if search.accepted_events != summary.accepted_events
        || search.accepted_equality_nodes != summary.equality_nodes
        || search.accepted_conflict_clauses != summary.conflict_clauses
        || search.proof_parent_references != summary.proof_parent_references
        || search.maximum_proof_depth != summary.maximum_proof_depth
        || search.accepted_trace_literal_slots != summary.trace_literal_slots
    {
        return Err(EqresBundleStructureError::TraceCounterMismatch);
    }
    Ok(summary)
}

fn validate_output_structure(
    compiler: &CompilerResult,
) -> Result<OutputStructureSummary, EqresBundleStructureError> {
    let CompilerStatus::Completed(output) = &compiler.status else {
        return Ok(OutputStructureSummary::default());
    };

    let mut summary = OutputStructureSummary::default();
    match output {
        EqresOutput::Lemmas(lemmas) => {
            if lemmas.is_empty() {
                return Err(EqresBundleStructureError::InvalidOutputShape);
            }
            for (index, lemma) in lemmas.iter().enumerate() {
                if lemma.clause.is_empty() {
                    return Err(EqresBundleStructureError::InvalidOutputShape);
                }
                if validate_canonical_clause_literals(lemma.clause.as_slice()).is_err() {
                    return Err(EqresBundleStructureError::NonCanonicalOutput);
                }
                if index > 0 {
                    let previous = &lemmas[index - 1].clause;
                    if (previous.len(), previous) >= (lemma.clause.len(), &lemma.clause) {
                        return Err(EqresBundleStructureError::NonCanonicalOutput);
                    }
                }
                summary.emitted_literal_slots = summary
                    .emitted_literal_slots
                    .checked_add(
                        u64::try_from(lemma.clause.len())
                            .map_err(|_| EqresBundleStructureError::CounterOverflow)?,
                    )
                    .ok_or(EqresBundleStructureError::CounterOverflow)?;
            }
            summary.emitted_lemmas = u64::try_from(lemmas.len())
                .map_err(|_| EqresBundleStructureError::CounterOverflow)?;
            summary.emitted_maximum_width = u64::try_from(
                lemmas
                    .last()
                    .ok_or(EqresBundleStructureError::InvalidOutputShape)?
                    .clause
                    .len(),
            )
            .map_err(|_| EqresBundleStructureError::CounterOverflow)?;
            let rank = summary
                .emitted_lemmas
                .checked_mul(95)
                .and_then(|value| value.checked_add(99))
                .ok_or(EqresBundleStructureError::CounterOverflow)?
                / 100;
            let percentile_index = usize::try_from(
                rank.checked_sub(1)
                    .ok_or(EqresBundleStructureError::CounterOverflow)?,
            )
            .map_err(|_| EqresBundleStructureError::CounterOverflow)?;
            summary.emitted_p95_width = u64::try_from(
                lemmas
                    .get(percentile_index)
                    .ok_or(EqresBundleStructureError::CounterOverflow)?
                    .clause
                    .len(),
            )
            .map_err(|_| EqresBundleStructureError::CounterOverflow)?;
        }
        EqresOutput::TheoryEmpty {
            terminal_event_id,
            lemma,
        } => {
            if !lemma.clause.is_empty() {
                return Err(EqresBundleStructureError::InvalidOutputShape);
            }
            let Some(TraceRecord::Conflict(terminal)) = compiler.trace.last() else {
                return Err(EqresBundleStructureError::InvalidOutputShape);
            };
            if terminal.event_id != *terminal_event_id
                || terminal.clause_id != lemma.source_clause_id
                || !terminal.clause.is_empty()
            {
                return Err(EqresBundleStructureError::InvalidOutputShape);
            }
            summary.emitted_lemmas = 1;
        }
        EqresOutput::NoLemmas => {}
    }

    let counters = compiler.counters.output;
    if counters.emitted_lemmas != summary.emitted_lemmas
        || counters.emitted_literal_slots != summary.emitted_literal_slots
        || counters.emitted_p95_width != summary.emitted_p95_width
        || counters.emitted_maximum_width != summary.emitted_maximum_width
        || counters.emitted_with_missing_equality_congruence > summary.emitted_lemmas
    {
        return Err(EqresBundleStructureError::OutputCounterMismatch);
    }
    Ok(summary)
}

fn validate_materialized_output(bundle: &EqresBundle) -> Result<(), EqresBundleStructureError> {
    let matches = match &bundle.compiler.status {
        CompilerStatus::Completed(EqresOutput::Lemmas(lemmas)) => {
            lemmas.len() == bundle.materialized_lemmas.len()
                && lemmas.iter().enumerate().all(|(index, lemma)| {
                    bundle.materialized_lemmas.clause(index) == Some(lemma.clause.as_slice())
                })
        }
        CompilerStatus::Completed(EqresOutput::TheoryEmpty { lemma, .. }) => {
            bundle.materialized_lemmas.len() == 1
                && bundle.materialized_lemmas.clause(0) == Some(lemma.clause.as_slice())
        }
        CompilerStatus::Completed(EqresOutput::NoLemmas)
        | CompilerStatus::NotRun
        | CompilerStatus::Rejected(_) => bundle.materialized_lemmas.len() == 0,
    };
    if !matches {
        return Err(EqresBundleStructureError::MaterializedOutputMismatch);
    }
    Ok(())
}

fn validate_checker_structure(
    bundle: &EqresBundle,
    trace: TraceStructureSummary,
    output: OutputStructureSummary,
) -> Result<(), EqresBundleStructureError> {
    let counters = bundle.checker.counters;
    let expected_emitted = if matches!(bundle.compiler.status, CompilerStatus::Completed(_)) {
        output.emitted_lemmas
    } else {
        0
    };
    if counters.replayed_equality_nodes != trace.equality_nodes
        || counters.replayed_conflict_clauses != trace.conflict_clauses
        || counters.replayed_emitted_lemmas != expected_emitted
    {
        return Err(EqresBundleStructureError::CheckerReplayCountMismatch);
    }

    match &bundle.checker.status {
        CheckerStatus::NotRun => {
            if !matches!(bundle.compiler.status, CompilerStatus::NotRun)
                || counters != CheckerCounters::default()
                || bundle.checker.recomputed_hashes != HashBindings::default()
            {
                return Err(EqresBundleStructureError::InvalidCheckerState);
            }
        }
        CheckerStatus::Accepted => {
            if !matches!(bundle.compiler.status, CompilerStatus::Completed(_))
                || counters.replay_failures != 0
            {
                return Err(EqresBundleStructureError::InvalidCheckerState);
            }
            if bundle.compiler.hashes != bundle.checker.recomputed_hashes {
                return Err(EqresBundleStructureError::CompilerCheckerHashMismatch);
            }
        }
        CheckerStatus::Rejected(failures) => {
            if failures.is_empty()
                || counters.replay_failures
                    != u64::try_from(failures.len())
                        .map_err(|_| EqresBundleStructureError::CounterOverflow)?
            {
                return Err(EqresBundleStructureError::InvalidCheckerState);
            }
        }
    }
    Ok(())
}

fn validate_report_structure(bundle: &EqresBundle) -> Result<(), EqresBundleStructureError> {
    if bundle.report.schema_version != EQRES_SCHEMA_VERSION {
        return Err(EqresBundleStructureError::ReportSchemaMismatch);
    }
    if bundle.report.selector != bundle.selector {
        return Err(EqresBundleStructureError::ReportSelectorMismatch);
    }
    if bundle.report.compiler_variant != bundle.compiler.variant {
        return Err(EqresBundleStructureError::ReportCompilerVariantMismatch);
    }
    if bundle.report.counters != bundle.compiler.counters {
        return Err(EqresBundleStructureError::ReportCounterMismatch);
    }
    if bundle.report.checker_counters != bundle.checker.counters {
        return Err(EqresBundleStructureError::ReportCheckerCounterMismatch);
    }
    if bundle.report.hashes != bundle.compiler.hashes {
        return Err(EqresBundleStructureError::ReportHashMismatch);
    }

    let compiler_cap = match &bundle.compiler.status {
        CompilerStatus::Rejected(CompilerFailure::Cap(attempt)) => Some(attempt),
        _ => None,
    };
    if bundle.report.cap_attempt.as_ref() != compiler_cap {
        return Err(EqresBundleStructureError::ReportCapAttemptMismatch);
    }

    let expected_outcome = if bundle.report.sat_calls != 0 {
        ReportOutcome::Rejected
    } else if bundle.selector.mode == EqresMode::Off {
        ReportOutcome::Off
    } else if bundle.selector.decision != SelectorDecision::Selected
        || !matches!(bundle.checker.status, CheckerStatus::Accepted)
    {
        ReportOutcome::Rejected
    } else {
        match bundle.compiler.status {
            CompilerStatus::Completed(EqresOutput::Lemmas(_)) => ReportOutcome::Lemmas,
            CompilerStatus::Completed(EqresOutput::TheoryEmpty { .. }) => {
                ReportOutcome::TheoryEmpty
            }
            CompilerStatus::Completed(EqresOutput::NoLemmas) => ReportOutcome::NoLemmas,
            CompilerStatus::NotRun | CompilerStatus::Rejected(_) => ReportOutcome::Rejected,
        }
    };
    if bundle.report.outcome != expected_outcome {
        return Err(EqresBundleStructureError::ReportOutcomeMismatch);
    }

    let checker_accepted = matches!(bundle.checker.status, CheckerStatus::Accepted);
    let hashes_agree = bundle.compiler.hashes == bundle.checker.recomputed_hashes;
    let expected_baseline_unchanged = checker_accepted
        && hashes_agree
        && bundle.compiler.hashes.baseline_cnf_sha256 != Sha256Digest::ZERO
        && bundle.compiler.hashes.atom_map_sha256 != Sha256Digest::ZERO
        && bundle.compiler.hashes.baseline_problem_sha256 != Sha256Digest::ZERO;
    let expected_trace_materialization = checker_accepted
        && hashes_agree
        && bundle.compiler.hashes.lemma_sequence_sha256
            == bundle.compiler.hashes.materialized_lemmas_sha256;
    let expected_compiler_checker_agree =
        checker_accepted && hashes_agree && bundle.report.sat_calls == 0;
    if bundle.report.integrity.baseline_unchanged != expected_baseline_unchanged
        || bundle.report.integrity.trace_materialization_equal != expected_trace_materialization
        || bundle.report.integrity.compiler_checker_agree != expected_compiler_checker_agree
        || bundle.report.integrity.output_canonical != checker_accepted
        || bundle.report.integrity.external_audit_accepted
        || (bundle.report.integrity.off_path_unchanged
            && (!matches!(bundle.compiler.status, CompilerStatus::NotRun)
                || bundle.selector.decision == SelectorDecision::Selected))
    {
        return Err(EqresBundleStructureError::ReportIntegrityMismatch);
    }
    Ok(())
}

#[cfg(feature = "certificates")]
impl<'de> serde::Deserialize<'de> for EqresBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EqresBundleWire {
            selector: SelectorReport,
            compiler: CompilerResult,
            materialized_lemmas: MaterializedClauseStore,
            checker: CheckerResult,
            report: EqresReport,
        }

        let wire = EqresBundleWire::deserialize(deserializer)?;
        let bundle = Self::new(
            wire.selector,
            wire.compiler,
            wire.materialized_lemmas,
            wire.checker,
            wire.report,
        );
        bundle
            .validate_structure()
            .map_err(serde::de::Error::custom)?;
        Ok(bundle)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SatComponentError {
    ResultBeforeChecker,
}

impl fmt::Display for SatComponentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResultBeforeChecker => {
                formatter.write_str("SAT result timestamp precedes checker completion")
            }
        }
    }
}

/// Exact no-SAT-session component for a checked theory-empty result.
///
/// The zero-valued fields are private and can only be created by `new`, making
/// `false/0/0/0/0` a representational invariant rather than a convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct TheoryEmptySatComponent {
    sat_session: bool,
    sat_calls: u64,
    sat_variables_loaded: u64,
    sat_clauses_loaded: u64,
    load_solve_ns: u64,
    checker_completed_ns: u64,
    result_timestamp_ns: u64,
}

impl TheoryEmptySatComponent {
    pub(crate) fn new(
        checker_completed_ns: u64,
        result_timestamp_ns: u64,
    ) -> Result<Self, SatComponentError> {
        if result_timestamp_ns < checker_completed_ns {
            return Err(SatComponentError::ResultBeforeChecker);
        }
        Ok(Self {
            sat_session: false,
            sat_calls: 0,
            sat_variables_loaded: 0,
            sat_clauses_loaded: 0,
            load_solve_ns: 0,
            checker_completed_ns,
            result_timestamp_ns,
        })
    }

    pub(crate) const fn sat_session(self) -> bool {
        self.sat_session
    }

    pub(crate) const fn sat_calls(self) -> u64 {
        self.sat_calls
    }

    pub(crate) const fn sat_variables_loaded(self) -> u64 {
        self.sat_variables_loaded
    }

    pub(crate) const fn sat_clauses_loaded(self) -> u64 {
        self.sat_clauses_loaded
    }

    pub(crate) const fn load_solve_ns(self) -> u64 {
        self.load_solve_ns
    }

    pub(crate) const fn checker_completed_ns(self) -> u64 {
        self.checker_completed_ns
    }

    pub(crate) const fn result_timestamp_ns(self) -> u64 {
        self.result_timestamp_ns
    }
}

#[cfg(feature = "certificates")]
impl<'de> serde::Deserialize<'de> for TheoryEmptySatComponent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct TheoryEmptySatComponentWire {
            sat_session: bool,
            sat_calls: u64,
            sat_variables_loaded: u64,
            sat_clauses_loaded: u64,
            load_solve_ns: u64,
            checker_completed_ns: u64,
            result_timestamp_ns: u64,
        }

        let wire = TheoryEmptySatComponentWire::deserialize(deserializer)?;
        if wire.sat_session
            || wire.sat_calls != 0
            || wire.sat_variables_loaded != 0
            || wire.sat_clauses_loaded != 0
            || wire.load_solve_ns != 0
        {
            return Err(serde::de::Error::custom(
                "theory-empty SAT component must contain exactly false/0/0/0/0",
            ));
        }
        Self::new(wire.checker_completed_ns, wire.result_timestamp_ns)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(rename_all = "snake_case"))]
pub(crate) enum SatKernelResult {
    Sat,
    Unsat,
    Interrupted,
    Error,
}

/// Exact fresh-session component for a nonempty checked lemma sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct FreshSatComponent {
    sat_session: bool,
    sat_calls: u64,
    sat_variables_loaded: u64,
    sat_clauses_loaded: u64,
    load_solve_ns: u64,
    result: SatKernelResult,
    checker_completed_ns: u64,
    result_timestamp_ns: u64,
}

impl FreshSatComponent {
    pub(crate) fn new(
        sat_variables_loaded: u64,
        sat_clauses_loaded: u64,
        load_solve_ns: u64,
        result: SatKernelResult,
        checker_completed_ns: u64,
        result_timestamp_ns: u64,
    ) -> Result<Self, SatComponentError> {
        if result_timestamp_ns < checker_completed_ns {
            return Err(SatComponentError::ResultBeforeChecker);
        }
        Ok(Self {
            sat_session: true,
            sat_calls: 1,
            sat_variables_loaded,
            sat_clauses_loaded,
            load_solve_ns,
            result,
            checker_completed_ns,
            result_timestamp_ns,
        })
    }

    pub(crate) const fn sat_session(self) -> bool {
        self.sat_session
    }

    pub(crate) const fn sat_calls(self) -> u64 {
        self.sat_calls
    }

    pub(crate) const fn sat_variables_loaded(self) -> u64 {
        self.sat_variables_loaded
    }

    pub(crate) const fn sat_clauses_loaded(self) -> u64 {
        self.sat_clauses_loaded
    }

    pub(crate) const fn load_solve_ns(self) -> u64 {
        self.load_solve_ns
    }

    pub(crate) const fn result(self) -> SatKernelResult {
        self.result
    }

    pub(crate) const fn checker_completed_ns(self) -> u64 {
        self.checker_completed_ns
    }

    pub(crate) const fn result_timestamp_ns(self) -> u64 {
        self.result_timestamp_ns
    }
}

#[cfg(feature = "certificates")]
impl<'de> serde::Deserialize<'de> for FreshSatComponent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct FreshSatComponentWire {
            sat_session: bool,
            sat_calls: u64,
            sat_variables_loaded: u64,
            sat_clauses_loaded: u64,
            load_solve_ns: u64,
            result: SatKernelResult,
            checker_completed_ns: u64,
            result_timestamp_ns: u64,
        }

        let wire = FreshSatComponentWire::deserialize(deserializer)?;
        if !wire.sat_session || wire.sat_calls != 1 {
            return Err(serde::de::Error::custom(
                "fresh SAT component must contain exactly true/1 session fields",
            ));
        }
        Self::new(
            wire.sat_variables_loaded,
            wire.sat_clauses_loaded,
            wire.load_solve_ns,
            wire.result,
            wire.checker_completed_ns,
            wire.result_timestamp_ns,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Disjoint SAT-layer states; neither variant contains nullable component
/// values. Stage records must choose the variant matching `EqresOutput`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
#[cfg_attr(
    feature = "certificates",
    serde(tag = "sat_layer", content = "component", rename_all = "snake_case")
)]
pub(crate) enum SatComponent {
    TheoryEmpty(TheoryEmptySatComponent),
    FreshSession(FreshSatComponent),
}

#[cfg(feature = "certificates")]
impl<'de> serde::Deserialize<'de> for SatComponent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(
            deny_unknown_fields,
            tag = "sat_layer",
            content = "component",
            rename_all = "snake_case"
        )]
        enum SatComponentWire {
            TheoryEmpty(TheoryEmptySatComponent),
            FreshSession(FreshSatComponent),
        }

        match SatComponentWire::deserialize(deserializer)? {
            SatComponentWire::TheoryEmpty(component) => Ok(Self::TheoryEmpty(component)),
            SatComponentWire::FreshSession(component) => Ok(Self::FreshSession(component)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clause(literals: &[i32]) -> CanonicalClause {
        CanonicalClause::from_sorted(literals.to_vec()).unwrap()
    }

    fn event_key(rule: RuleKind, width: u32) -> EventKey {
        EventKey {
            resulting_clause_width: width,
            proof_depth: ProofDepth::new(0),
            rule,
            conclusion: None,
            clause: CanonicalClause::empty(),
            source: None,
            parents: Box::new([]),
        }
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::new([byte; 32])
    }

    fn internal_bindings() -> HashBindings {
        let internal = digest(1);
        HashBindings {
            source_sha256: internal,
            root_cnf_mode_sha256: internal,
            term_dag_sha256: internal,
            atom_map_sha256: internal,
            baseline_cnf_sha256: internal,
            baseline_problem_sha256: internal,
            trace_sha256: internal,
            lemma_sequence_sha256: internal,
            materialized_lemmas_sha256: internal,
            materialized_candidate_sha256: internal,
            ..HashBindings::default()
        }
    }

    fn selected_selector() -> SelectorReport {
        SelectorReport {
            mode: EqresMode::CliqueErAuto,
            facts: SelectorFacts {
                finite_added_clauses: 0,
                covered_finite_terms: 0,
                closed_table_functions: 0,
                all_different_clique_lower_bound: 0,
                disequality_graph_edges: 0,
                equality_graph_vertices: 0,
                equality_graph_edges: 0,
                applications: 0,
                boolean_valued_application_pairs: 0,
                backend: SolverBackend::Kissat,
            },
            decision: SelectorDecision::Selected,
        }
    }

    fn accepted_bundle(theory_empty: bool) -> EqresBundle {
        let source_clause_id = ClauseId::new(11);
        let output_clause = if theory_empty {
            CanonicalClause::empty()
        } else {
            clause(&[2])
        };
        let trace: Box<[TraceRecord]> = Box::new([
            TraceRecord::Equality(EqualityTraceRecord {
                event_id: EventId::new(0),
                node_id: NodeId::new(0),
                depth: ProofDepth::new(0),
                conclusion: EqualityKey::from_normalized(0, 0).unwrap(),
                side_clause: CanonicalClause::empty(),
                rule: EqualityRuleRecord::Reflexivity(ReflexivityRecord { term: 0 }),
            }),
            TraceRecord::Conflict(ConflictTraceRecord {
                event_id: EventId::new(1),
                clause_id: source_clause_id,
                depth: ProofDepth::new(0),
                clause: output_clause.clone(),
                rule: ConflictRecord {
                    equality_parent: NodeId::new(0),
                    negative_source: ClausePivot {
                        clause: ClauseRef {
                            id: ClauseId::new(0),
                            origin: ClauseOrigin::Baseline,
                        },
                        literal_offset: LiteralOffset::new(0),
                    },
                },
            }),
        ]);
        let output = if theory_empty {
            EqresOutput::TheoryEmpty {
                terminal_event_id: EventId::new(1),
                lemma: EmittedLemma {
                    source_clause_id,
                    clause: output_clause.clone(),
                },
            }
        } else {
            EqresOutput::Lemmas(Box::new([EmittedLemma {
                source_clause_id,
                clause: output_clause.clone(),
            }]))
        };
        let width = u64::try_from(output_clause.len()).unwrap();
        let mut counters = DeterministicCounters::default();
        counters.input.baseline_variables = 7;
        counters.input.baseline_clauses = 11;
        counters.search.accepted_events.reflexivity = 1;
        counters.search.accepted_events.conflict = 1;
        counters.search.events_popped = 2;
        counters.search.accepted_equality_nodes = 1;
        counters.search.accepted_conflict_clauses = 1;
        counters.search.proof_parent_references = 1;
        counters.search.accepted_trace_literal_slots = width;
        counters.output = OutputCounters {
            emitted_lemmas: 1,
            emitted_literal_slots: width,
            emitted_p95_width: width,
            emitted_maximum_width: width,
            emitted_with_missing_equality_congruence: 1,
        };
        let hashes = internal_bindings();
        let selector = selected_selector();
        let compiler = CompilerResult {
            variant: CompilerVariant::Ordinary,
            status: CompilerStatus::Completed(output),
            trace,
            counters,
            hashes,
        };
        let checker = CheckerResult {
            status: CheckerStatus::Accepted,
            counters: CheckerCounters {
                replayed_equality_nodes: 1,
                replayed_conflict_clauses: 1,
                replayed_emitted_lemmas: 1,
                replay_failures: 0,
            },
            recomputed_hashes: hashes,
        };
        let materialized_lemmas = MaterializedClauseStore::from_parts(
            vec![0, u32::try_from(output_clause.len()).unwrap()],
            output_clause.as_slice().to_vec(),
        )
        .unwrap();
        let report = EqresReport {
            schema_version: EQRES_SCHEMA_VERSION,
            selector,
            compiler_variant: compiler.variant,
            outcome: if theory_empty {
                ReportOutcome::TheoryEmpty
            } else {
                ReportOutcome::Lemmas
            },
            counters,
            checker_counters: checker.counters,
            cap_attempt: None,
            forbidden_growth: ForbiddenGrowthCounters::default(),
            integrity: IntegrityReport {
                baseline_unchanged: true,
                trace_materialization_equal: true,
                compiler_checker_agree: true,
                output_canonical: true,
                external_audit_accepted: false,
                off_path_unchanged: false,
            },
            sat_calls: 0,
            hashes,
        };
        EqresBundle::new(selector, compiler, materialized_lemmas, checker, report)
    }

    #[cfg(feature = "certificates")]
    fn add_unknown_field(mut value: serde_json::Value, pointer: &str) -> serde_json::Value {
        let target = if pointer.is_empty() {
            &mut value
        } else {
            value
                .pointer_mut(pointer)
                .unwrap_or_else(|| panic!("missing JSON pointer {pointer}"))
        };
        target
            .as_object_mut()
            .unwrap_or_else(|| panic!("JSON pointer is not an object: {pointer}"))
            .insert("unexpected".to_owned(), serde_json::json!(true));
        value
    }

    #[cfg(feature = "certificates")]
    fn assert_bundle_decode_err(value: serde_json::Value, context: &str) {
        assert!(
            serde_json::from_value::<EqresBundle>(value.clone()).is_err(),
            "bundle mutation accepted from value: {context}"
        );
        assert!(
            serde_json::from_slice::<EqresBundle>(&serde_json::to_vec(&value).unwrap()).is_err(),
            "bundle mutation accepted from bytes: {context}"
        );
    }

    #[test]
    fn frozen_limits_match_preregistration() {
        assert_eq!(Limits::TERMS, 16_384);
        assert_eq!(Limits::BASELINE_VARIABLES, 50_000);
        assert_eq!(Limits::BASELINE_CLAUSES, 131_072);
        assert_eq!(Limits::BASELINE_LITERAL_SLOTS, 1_048_576);
        assert_eq!(Limits::APPLICATIONS, 256);
        assert_eq!(Limits::APPLICATION_PAIRS, 5_000);
        assert_eq!(Limits::MAXIMUM_ARITY, 64);
        assert_eq!(Limits::APPLICATION_ARGUMENT_SLOTS, 16_384);
        assert_eq!(Limits::EQUALITY_PROOF_NODES, 100_000);
        assert_eq!(Limits::PROOF_PARENT_REFERENCES, 300_000);
        assert_eq!(Limits::PROOF_DEPTH, 256);
        assert_eq!(Limits::UNIQUE_DERIVED_CLAUSES, 25_000);
        assert_eq!(Limits::RETAINED_SIDE_CLAUSES_PER_EQUALITY, 8);
        assert_eq!(Limits::CANONICAL_PROOF_WORK_LITERAL_CHARGE, 2_000_000);
        assert_eq!(Limits::WORKLIST_PUSHES, 250_000);
        assert_eq!(Limits::LIVE_WORKLIST_ENTRIES, 65_536);
        assert_eq!(Limits::ALL_DERIVED_LITERAL_SLOTS, 150_000);
        assert_eq!(Limits::EMITTED_LEMMAS, 8_192);
        assert_eq!(Limits::EMITTED_LEMMA_LITERAL_SLOTS, 65_536);
        assert_eq!(Limits::EMITTED_P95_WIDTH, 8);
        assert_eq!(Limits::EMITTED_MAXIMUM_WIDTH, 32);
        assert_eq!(Limits::LOGICAL_INCREMENTAL_MEMORY_BYTES, 16_777_216);
    }

    #[test]
    fn rule_and_cap_discriminants_freeze_precedence() {
        assert!(RuleKind::Seed < RuleKind::Reflexivity);
        assert!(RuleKind::Reflexivity < RuleKind::Transitivity);
        assert!(RuleKind::Transitivity < RuleKind::Congruence);
        assert!(RuleKind::Congruence < RuleKind::Conflict);
        assert!(CapReason::Terms < CapReason::BaselineVariables);
        assert!(CapReason::EmittedMaximumWidth < CapReason::LogicalIncrementalMemoryBytes);
    }

    #[test]
    fn equality_keys_accept_only_normalized_pairs() {
        let key = EqualityKey::from_normalized(3, 7).unwrap();
        assert_eq!(key.endpoints(), (3, 7));
        assert!(!key.is_reflexive());
        assert!(EqualityKey::from_normalized(7, 3).is_none());
        assert!(EqualityKey::from_normalized(4, 4).unwrap().is_reflexive());
    }

    #[test]
    fn canonical_clause_validates_without_reordering() {
        assert_eq!(clause(&[-7, -3, 2, 9]).as_slice(), &[-7, -3, 2, 9]);
        assert_eq!(
            CanonicalClause::from_sorted(vec![-2, 0, 3]),
            Err(CanonicalClauseError::ZeroLiteral)
        );
        assert_eq!(
            CanonicalClause::from_sorted(vec![i32::MIN]),
            Err(CanonicalClauseError::InvalidLiteral)
        );
        assert_eq!(
            CanonicalClause::from_sorted(vec![2, 1]),
            Err(CanonicalClauseError::NotStrictlySorted)
        );
        assert_eq!(
            CanonicalClause::from_sorted(vec![1, 1]),
            Err(CanonicalClauseError::NotStrictlySorted)
        );
        assert_eq!(
            CanonicalClause::from_sorted(vec![-9, -2, 2, 7]),
            Err(CanonicalClauseError::ComplementaryLiterals)
        );
    }

    #[test]
    fn event_key_orders_width_before_rule_rank() {
        assert!(event_key(RuleKind::Conflict, 1) < event_key(RuleKind::Seed, 2));
        assert!(event_key(RuleKind::Seed, 2) < event_key(RuleKind::Conflict, 2));
    }

    #[test]
    fn logical_memory_coefficients_match_frozen_formula() {
        let charge = LogicalMemoryWeights::EQUALITY_NODE
            + LogicalMemoryWeights::CONFLICT_CLAUSE
            + LogicalMemoryWeights::PARENT_REFERENCE
            + LogicalMemoryWeights::TRACE_LITERAL_SLOT
            + LogicalMemoryWeights::DISTINCT_EVENT_KEY
            + LogicalMemoryWeights::RETAINED_ANTICHAIN_ENTRY
            + LogicalMemoryWeights::NEGATIVE_OCCURRENCE
            + LogicalMemoryWeights::APPLICATION_PAIR
            + LogicalMemoryWeights::APPLICATION_ARGUMENT_SLOT;
        assert_eq!(charge, 236);
    }

    #[test]
    fn sha256_digest_renders_fixed_lower_hex() {
        assert_eq!(Sha256Digest::ZERO.to_string(), "0".repeat(64));
        assert_eq!(
            Sha256Digest::EMPTY_BYTES.to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[cfg(feature = "certificates")]
    #[test]
    fn sha256_digest_deserialization_is_exact_and_lowercase() {
        let encoded = serde_json::to_string(&Sha256Digest::EMPTY_BYTES).unwrap();
        let decoded: Sha256Digest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, Sha256Digest::EMPTY_BYTES);
        assert!(serde_json::from_str::<Sha256Digest>("\"ABCDEF\"").is_err());
        assert!(
            serde_json::from_str::<Sha256Digest>(
                "\"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855\""
            )
            .is_err()
        );
    }

    #[test]
    fn theory_empty_component_cannot_claim_a_sat_session() {
        let component = TheoryEmptySatComponent::new(100, 101).unwrap();
        assert!(!component.sat_session());
        assert_eq!(component.sat_calls(), 0);
        assert_eq!(component.sat_variables_loaded(), 0);
        assert_eq!(component.sat_clauses_loaded(), 0);
        assert_eq!(component.load_solve_ns(), 0);
        assert_eq!(component.checker_completed_ns(), 100);
        assert_eq!(component.result_timestamp_ns(), 101);
        assert_eq!(
            TheoryEmptySatComponent::new(101, 100),
            Err(SatComponentError::ResultBeforeChecker)
        );
    }

    #[test]
    fn successful_output_variants_remain_distinct() {
        let no_lemmas = EqresOutput::NoLemmas;
        let theory_empty = EqresOutput::TheoryEmpty {
            terminal_event_id: EventId::new(4),
            lemma: EmittedLemma {
                source_clause_id: ClauseId::new(8),
                clause: CanonicalClause::empty(),
            },
        };
        assert_ne!(no_lemmas, theory_empty);
    }

    #[test]
    fn materialized_store_preserves_empty_clause_identity() {
        let no_lemmas = MaterializedClauseStore::empty();
        let one_empty = MaterializedClauseStore::from_parts(vec![0, 0], Vec::new()).unwrap();
        assert_eq!(no_lemmas.len(), 0);
        assert_eq!(one_empty.len(), 1);
        assert_eq!(one_empty.clause(0), Some(&[][..]));
        assert_ne!(no_lemmas, one_empty);
        assert_eq!(
            MaterializedClauseStore::from_parts(vec![1], Vec::new()),
            Err(MaterializedClauseStoreError::MissingInitialOffset)
        );
        assert_eq!(
            MaterializedClauseStore::from_parts(vec![0, 2], vec![1]),
            Err(MaterializedClauseStoreError::FinalOffsetMismatch)
        );
    }

    #[test]
    fn bundle_structure_accepts_sealed_success_variants() {
        assert_eq!(accepted_bundle(true).validate_structure(), Ok(()));
        assert_eq!(accepted_bundle(false).validate_structure(), Ok(()));
    }

    #[test]
    fn bundle_structure_rejects_malformed_sealed_state() {
        let mut malformed_store = accepted_bundle(false);
        malformed_store.materialized_lemmas =
            MaterializedClauseStore::from_parts_unchecked_for_test(vec![1, 1], vec![2]);
        assert_eq!(
            malformed_store.validate_structure(),
            Err(EqresBundleStructureError::InvalidMaterializedStore(
                MaterializedClauseStoreError::MissingInitialOffset
            ))
        );

        let mut stale_report = accepted_bundle(false);
        stale_report.report.counters.search.events_popped += 1;
        assert_eq!(
            stale_report.validate_structure(),
            Err(EqresBundleStructureError::ReportCounterMismatch)
        );

        let mut stale_checker = accepted_bundle(false);
        stale_checker.checker.counters.replayed_conflict_clauses = 0;
        stale_checker.report.checker_counters = stale_checker.checker.counters;
        assert_eq!(
            stale_checker.validate_structure(),
            Err(EqresBundleStructureError::CheckerReplayCountMismatch)
        );

        let mut noncanonical_trace = accepted_bundle(false);
        let TraceRecord::Conflict(record) = &mut noncanonical_trace.compiler.trace[1] else {
            panic!("fixture conflict record missing");
        };
        record.clause = CanonicalClause(vec![2, 1].into_boxed_slice());
        assert_eq!(
            noncanonical_trace.validate_structure(),
            Err(EqresBundleStructureError::NonCanonicalTrace)
        );
    }

    #[cfg(feature = "certificates")]
    #[test]
    fn invariant_deserializers_reject_noncanonical_and_unknown_data() {
        let key: EqualityKey = serde_json::from_str(r#"{"left":3,"right":7}"#).unwrap();
        assert_eq!(key.endpoints(), (3, 7));
        assert!(serde_json::from_str::<EqualityKey>(r#"{"left":7,"right":3}"#).is_err());
        assert!(serde_json::from_str::<EqualityKey>(r#"{"left":3,"right":7,"extra":0}"#).is_err());

        for invalid in ["[0]", "[-2147483648]", "[2,1]", "[1,1]", "[-2,2]"] {
            assert!(serde_json::from_str::<CanonicalClause>(invalid).is_err());
        }
        let decoded: CanonicalClause = serde_json::from_str("[-3,2]").unwrap();
        assert_eq!(decoded.as_slice(), &[-3, 2]);

        assert!(
            serde_json::from_str::<MaterializedClauseStore>(r#"{"end_offsets":[1],"literals":[]}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<MaterializedClauseStore>(
                r#"{"end_offsets":[0],"literals":[],"extra":0}"#
            )
            .is_err()
        );

        let theory_empty = r#"{"sat_session":false,"sat_calls":0,"sat_variables_loaded":0,"sat_clauses_loaded":0,"load_solve_ns":0,"checker_completed_ns":100,"result_timestamp_ns":101}"#;
        serde_json::from_str::<TheoryEmptySatComponent>(theory_empty).unwrap();
        assert!(
            serde_json::from_str::<TheoryEmptySatComponent>(
                &theory_empty.replace("\"sat_calls\":0", "\"sat_calls\":1")
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<TheoryEmptySatComponent>(
                &theory_empty.replace("\"result_timestamp_ns\":101", "\"result_timestamp_ns\":99")
            )
            .is_err()
        );

        let fresh = r#"{"sat_session":true,"sat_calls":1,"sat_variables_loaded":7,"sat_clauses_loaded":12,"load_solve_ns":1,"result":"unsat","checker_completed_ns":100,"result_timestamp_ns":101}"#;
        serde_json::from_str::<FreshSatComponent>(fresh).unwrap();
        assert!(
            serde_json::from_str::<FreshSatComponent>(
                &fresh.replace("\"sat_session\":true", "\"sat_session\":false")
            )
            .is_err()
        );
    }

    #[cfg(feature = "certificates")]
    #[test]
    fn bundle_deserialization_rejects_malformed_and_unknown_nested_state() {
        let bundle = accepted_bundle(false);
        let encoded = serde_json::to_value(&bundle).unwrap();
        let decoded: EqresBundle = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(decoded, bundle);
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let decoded: EqresBundle = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, bundle);

        let mut stale_report = encoded.clone();
        stale_report["report"]["counters"]["search"]["events_popped"] = serde_json::json!(3);
        assert_bundle_decode_err(stale_report, "stale report counters");

        let mut malformed_store = encoded.clone();
        malformed_store["materialized_lemmas"]["end_offsets"] = serde_json::json!([1, 1]);
        assert_bundle_decode_err(malformed_store, "malformed materialized store");

        let mut noncanonical_clause = encoded.clone();
        noncanonical_clause["compiler"]["trace"][1]["record"]["clause"] = serde_json::json!([2, 1]);
        assert_bundle_decode_err(noncanonical_clause, "noncanonical trace clause");

        let mut reversed_key = encoded.clone();
        reversed_key["compiler"]["trace"][0]["record"]["conclusion"] =
            serde_json::json!({"left": 7, "right": 3});
        assert_bundle_decode_err(reversed_key, "reversed equality key");

        let mut unaudited_external_claim = encoded.clone();
        unaudited_external_claim["report"]["integrity"]["external_audit_accepted"] =
            serde_json::json!(true);
        assert_bundle_decode_err(unaudited_external_claim, "unreceipted external-audit claim");

        let theory_empty = serde_json::to_value(accepted_bundle(true)).unwrap();
        let unknown_theory_empty_output =
            add_unknown_field(theory_empty, "/compiler/status/detail/output");
        assert_bundle_decode_err(
            unknown_theory_empty_output,
            "unknown theory-empty output field",
        );

        for pointer in [
            "",
            "/selector",
            "/selector/facts",
            "/selector/decision",
            "/compiler",
            "/compiler/status",
            "/compiler/status/detail",
            "/compiler/status/detail/output/0",
            "/compiler/trace/0",
            "/compiler/trace/0/record",
            "/compiler/trace/0/record/rule",
            "/compiler/trace/0/record/rule/premises",
            "/compiler/trace/1/record",
            "/compiler/trace/1/record/rule",
            "/compiler/trace/1/record/rule/negative_source",
            "/compiler/trace/1/record/rule/negative_source/clause",
            "/compiler/counters",
            "/compiler/counters/input",
            "/compiler/counters/search",
            "/compiler/counters/search/attempted_events",
            "/compiler/counters/search/accepted_events",
            "/compiler/counters/pruning",
            "/compiler/counters/output",
            "/compiler/hashes",
            "/materialized_lemmas",
            "/checker",
            "/checker/status",
            "/checker/counters",
            "/checker/recomputed_hashes",
            "/report",
            "/report/selector",
            "/report/selector/facts",
            "/report/selector/decision",
            "/report/counters",
            "/report/counters/input",
            "/report/counters/search",
            "/report/counters/search/attempted_events",
            "/report/counters/search/accepted_events",
            "/report/counters/pruning",
            "/report/counters/output",
            "/report/checker_counters",
            "/report/forbidden_growth",
            "/report/integrity",
            "/report/hashes",
        ] {
            let mutated = add_unknown_field(encoded.clone(), pointer);
            assert_bundle_decode_err(mutated, &format!("unknown field at {pointer}"));
        }
    }

    #[cfg(feature = "certificates")]
    #[test]
    fn certificate_serialization_is_explicit_and_stable() {
        let component = SatComponent::TheoryEmpty(
            TheoryEmptySatComponent::new(100, 101).expect("ordered timestamps"),
        );
        assert_eq!(
            serde_json::to_string(&component).unwrap(),
            r#"{"sat_layer":"theory_empty","component":{"sat_session":false,"sat_calls":0,"sat_variables_loaded":0,"sat_clauses_loaded":0,"load_solve_ns":0,"checker_completed_ns":100,"result_timestamp_ns":101}}"#
        );
        assert_eq!(
            serde_json::to_string(&EqresMode::CliqueErAuto).unwrap(),
            r#""clique-er-auto""#
        );
        assert_eq!(
            serde_json::to_string(&Sha256Digest::EMPTY_BYTES).unwrap(),
            r#""e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855""#
        );
    }
}
