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
    pub(crate) sorts: &'a SortTable,
    pub(crate) declarations: &'a FunDeclTable,
    pub(crate) term_dag: &'a [Term],
    pub(crate) ordered_applications: &'a [TermId],
    pub(crate) baseline_clauses: &'a FlatClauses,
    pub(crate) variable_atoms: &'a [Option<BoolAtomKey>],
    pub(crate) atom_variables: &'a FxHashMap<BoolAtomKey, i32>,
}

macro_rules! define_u32_id {
    ($name:ident) => {
        #[repr(transparent)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "certificates", derive(serde::Serialize))]
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
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CanonicalClauseError {
    ZeroLiteral,
    NotStrictlySorted,
    ComplementaryLiterals,
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
        if literals.contains(&0) {
            return Err(CanonicalClauseError::ZeroLiteral);
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
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
#[cfg_attr(feature = "certificates", serde(rename_all = "snake_case"))]
pub(crate) enum RuleKind {
    Seed = 0,
    Reflexivity = 1,
    Transitivity = 2,
    Congruence = 3,
    Conflict = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
#[cfg_attr(feature = "certificates", serde(rename_all = "snake_case"))]
pub(crate) enum ClauseOrigin {
    Baseline,
    Derived,
}

/// A clause ID is global; `origin` records which topological rule applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct ClauseRef {
    pub(crate) id: ClauseId,
    pub(crate) origin: ClauseOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct ClausePivot {
    pub(crate) clause: ClauseRef,
    pub(crate) literal_offset: LiteralOffset,
}

/// The complete frozen worklist ordering key. Parent IDs include multiplicity
/// and are stored in ascending order; Congruence's argument associations live
/// in its trace record and are deliberately not substituted for this sequence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
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
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct SeedRecord {
    pub(crate) positive_source: ClausePivot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct ReflexivityRecord {
    pub(crate) term: TermId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct TransitivityRecord {
    /// Sorted ascending for the event key; endpoint orientation is recovered
    /// independently from the conclusions and `intermediate`.
    pub(crate) parents: [NodeId; 2],
    pub(crate) intermediate: TermId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct CongruenceArgumentParent {
    pub(crate) argument_index: ArgumentIndex,
    pub(crate) parent: NodeId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct CongruenceRecord {
    pub(crate) applications: [ApplicationId; 2],
    /// One entry for every differing argument, in increasing argument-index
    /// order. Parent IDs here retain their argument association.
    pub(crate) arguments: Box<[CongruenceArgumentParent]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct ConflictRecord {
    pub(crate) equality_parent: NodeId,
    pub(crate) negative_source: ClausePivot,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
#[cfg_attr(
    feature = "certificates",
    serde(tag = "rule", content = "premises", rename_all = "snake_case")
)]
pub(crate) enum EqualityRuleRecord {
    Seed(SeedRecord),
    Reflexivity(ReflexivityRecord),
    Transitivity(TransitivityRecord),
    Congruence(CongruenceRecord),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct EqualityTraceRecord {
    pub(crate) event_id: EventId,
    pub(crate) node_id: NodeId,
    pub(crate) depth: ProofDepth,
    pub(crate) conclusion: EqualityKey,
    pub(crate) side_clause: CanonicalClause,
    pub(crate) rule: EqualityRuleRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct ConflictTraceRecord {
    pub(crate) event_id: EventId,
    pub(crate) clause_id: ClauseId,
    pub(crate) depth: ProofDepth,
    pub(crate) clause: CanonicalClause,
    pub(crate) rule: ConflictRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
#[cfg_attr(
    feature = "certificates",
    serde(tag = "record_kind", content = "record", rename_all = "snake_case")
)]
pub(crate) enum TraceRecord {
    Equality(EqualityTraceRecord),
    Conflict(ConflictTraceRecord),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct EmittedLemma {
    pub(crate) source_clause_id: ClauseId,
    pub(crate) clause: CanonicalClause,
}

/// Successful terminal states. `Lemmas` is nonempty and contains no empty
/// clause; `TheoryEmpty` contains exactly the terminal empty Conflict lemma;
/// `NoLemmas` contains no lemma. The checker enforces those shape invariants.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
#[cfg_attr(
    feature = "certificates",
    serde(tag = "outcome", content = "output", rename_all = "snake_case")
)]
pub(crate) enum EqresOutput {
    Lemmas(Box<[EmittedLemma]>),
    TheoryEmpty {
        terminal_event_id: EventId,
        lemma: EmittedLemma,
    },
    NoLemmas,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct RuleCounters {
    pub(crate) seed: u64,
    pub(crate) reflexivity: u64,
    pub(crate) transitivity: u64,
    pub(crate) congruence: u64,
    pub(crate) conflict: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
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
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
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
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
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
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct OutputCounters {
    pub(crate) emitted_lemmas: u64,
    pub(crate) emitted_literal_slots: u64,
    pub(crate) emitted_p95_width: u64,
    pub(crate) emitted_maximum_width: u64,
    pub(crate) emitted_with_missing_equality_congruence: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
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
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
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
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
#[cfg_attr(
    feature = "certificates",
    serde(tag = "boundary", content = "context", rename_all = "snake_case")
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
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct CapAttempt {
    pub(crate) reason: CapReason,
    pub(crate) boundary: CapBoundary,
    pub(crate) pre_event_value: u64,
    pub(crate) prospective_value: u64,
    pub(crate) limit: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
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
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
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
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
#[cfg_attr(
    feature = "certificates",
    serde(tag = "failure", content = "detail", rename_all = "snake_case")
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
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
#[cfg_attr(
    feature = "certificates",
    serde(tag = "status", content = "detail", rename_all = "snake_case")
)]
pub(crate) enum CompilerStatus {
    Completed(EqresOutput),
    Rejected(CompilerFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
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

/// Required hash bindings use concrete digests rather than `Option`, so
/// theory-empty and no-lemma records still hash their exact empty byte streams.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
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
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct CompilerResult {
    pub(crate) variant: CompilerVariant,
    pub(crate) status: CompilerStatus,
    /// Accepted records only, in topological acceptance order.
    pub(crate) trace: Box<[TraceRecord]>,
    pub(crate) counters: DeterministicCounters,
    pub(crate) hashes: HashBindings,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct CheckerCounters {
    pub(crate) replayed_equality_nodes: u64,
    pub(crate) replayed_conflict_clauses: u64,
    pub(crate) replayed_emitted_lemmas: u64,
    pub(crate) replay_failures: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
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
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct CheckerFailure {
    pub(crate) kind: CheckerFailureKind,
    pub(crate) event_id: Option<EventId>,
    pub(crate) artifact: Option<HashArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
#[cfg_attr(
    feature = "certificates",
    serde(tag = "status", content = "failures", rename_all = "snake_case")
)]
pub(crate) enum CheckerStatus {
    Accepted,
    Rejected(Box<[CheckerFailure]>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct CheckerResult {
    pub(crate) status: CheckerStatus,
    pub(crate) counters: CheckerCounters,
    pub(crate) recomputed_hashes: HashBindings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
#[cfg_attr(feature = "certificates", serde(rename_all = "kebab-case"))]
pub(crate) enum EqresMode {
    Off,
    CliqueErAuto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
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
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
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
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
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
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
#[cfg_attr(
    feature = "certificates",
    serde(tag = "decision", content = "reason", rename_all = "snake_case")
)]
pub(crate) enum SelectorDecision {
    Selected,
    Rejected(SelectorRejection),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct SelectorReport {
    pub(crate) mode: EqresMode,
    pub(crate) facts: SelectorFacts,
    pub(crate) decision: SelectorDecision,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct ForbiddenGrowthCounters {
    pub(crate) added_terms: u64,
    pub(crate) added_atoms: u64,
    pub(crate) added_variables: u64,
    pub(crate) fill_edges: u64,
    pub(crate) generic_transitivity_clauses: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct IntegrityReport {
    pub(crate) baseline_unchanged: bool,
    pub(crate) trace_materialization_equal: bool,
    pub(crate) compiler_checker_agree: bool,
    pub(crate) output_canonical: bool,
    pub(crate) external_audit_accepted: bool,
    pub(crate) off_path_unchanged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
#[cfg_attr(feature = "certificates", serde(rename_all = "snake_case"))]
pub(crate) enum ReportOutcome {
    Off,
    Rejected,
    Lemmas,
    TheoryEmpty,
    NoLemmas,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
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

/// Compiler output and independent replay are kept side by side rather than
/// allowing the checker to mutate or replace compiler-owned records.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct EqresBundle {
    pub(crate) selector: SelectorReport,
    pub(crate) compiler: CompilerResult,
    pub(crate) checker: CheckerResult,
    pub(crate) report: EqresReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SatComponentError {
    ResultBeforeChecker,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
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
    pub(crate) sat_variables_loaded: u64,
    pub(crate) sat_clauses_loaded: u64,
    pub(crate) load_solve_ns: u64,
    pub(crate) result: SatKernelResult,
    pub(crate) checker_completed_ns: u64,
    pub(crate) result_timestamp_ns: u64,
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize))]
pub(crate) struct EqresRunRecord {
    pub(crate) bundle: EqresBundle,
    pub(crate) sat_component: SatComponent,
    pub(crate) hashes: HashBindings,
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
