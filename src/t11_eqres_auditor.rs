//! Independent deterministic scheduling and cap audit for T11 equality resolution.
//!
//! This module deliberately owns its validation, scheduling, accounting,
//! canonicalization, materialization, and hashing code. Production code here
//! must not call the T11 compiler or checker.

use super::t11_eqres_types::{
    ApplicationId, ArgumentIndex, CanonicalClause, CapAttempt, CapBoundary, CapReason,
    CheckerStatus, ClauseId, ClauseOrigin, ClausePivot, ClauseRef, CompilerFailure, CompilerStatus,
    CompilerVariant, ConflictRecord, ConflictTraceRecord, CongruenceArgumentParent,
    CongruenceRecord, DeterministicCounters, EQRES_SCHEMA_VERSION, EmittedLemma, EqresBundle,
    EqresInput, EqresOutput, EqualityKey, EqualityRuleRecord, EqualityTraceRecord, EventId,
    EventKey, HashArtifact, HashBindings, InputCounters, InputFailure, Limits, LiteralOffset,
    LogicalMemoryWeights, MaterializedClauseStore, NodeId, ProofDepth, ReflexivityRecord,
    ReportOutcome, RuleCounters, RuleKind, SeedRecord, SelectorDecision, Sha256Digest, TraceRecord,
    TransitivityRecord,
};
use super::{BOOL_SORT, BoolAtomKey, TermId};
use rustc_hash::{FxHashMap, FxHashSet};
use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;

pub(crate) const EQRES_AUDIT_RECEIPT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "certificates", serde(rename_all = "snake_case"))]
pub(crate) enum AuditFailureKind {
    MalformedInput,
    ArithmeticOverflow,
    AllocationFailure,
    InternalInvariant,
    SelectorMismatch,
    CompilerVariantMismatch,
    CompilerStatusMismatch,
    OutputMismatch,
    TraceMismatch,
    CounterMismatch,
    CapAttemptMismatch,
    MaterializedShapeMismatch,
    MaterializedOffsetsMismatch,
    MaterializedLiteralsMismatch,
    CompilerHashMismatch,
    CheckerStatusMismatch,
    CheckerHashMismatch,
    ReportSchemaMismatch,
    ReportSelectorMismatch,
    ReportVariantMismatch,
    ReportOutcomeMismatch,
    ReportCounterMismatch,
    ReportCapMismatch,
    ReportHashMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct AuditFailure {
    pub(crate) kind: AuditFailureKind,
    pub(crate) event_id: Option<EventId>,
    pub(crate) artifact: Option<HashArtifact>,
    pub(crate) input_failure: Option<InputFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NonEmptyAuditFailures(Box<[AuditFailure]>);

impl NonEmptyAuditFailures {
    fn from_vec(failures: Vec<AuditFailure>) -> Option<Self> {
        (!failures.is_empty()).then(|| Self(failures.into_boxed_slice()))
    }

    pub(crate) fn as_slice(&self) -> &[AuditFailure] {
        &self.0
    }
}

#[cfg(feature = "certificates")]
impl serde::Serialize for NonEmptyAuditFailures {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[cfg(feature = "certificates")]
impl<'de> serde::Deserialize<'de> for NonEmptyAuditFailures {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let failures = Vec::<AuditFailure>::deserialize(deserializer)?;
        Self::from_vec(failures)
            .ok_or_else(|| serde::de::Error::custom("audit rejection must contain a failure"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "certificates",
    serde(tag = "status", content = "failures", rename_all = "snake_case")
)]
pub(crate) enum AuditStatus {
    Accepted,
    Rejected(NonEmptyAuditFailures),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct AuditResult {
    pub(crate) status: AuditStatus,
    pub(crate) counters: DeterministicCounters,
    pub(crate) cap_attempt: Option<CapAttempt>,
    pub(crate) recomputed_hashes: HashBindings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "certificates", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct EqresAuditReceipt {
    pub(crate) schema_version: u32,
    pub(crate) exact_bundle_sha256: Sha256Digest,
    pub(crate) source_sha256: Sha256Digest,
    pub(crate) baseline_problem_sha256: Sha256Digest,
    pub(crate) trace_sha256: Sha256Digest,
    pub(crate) lemma_sequence_sha256: Sha256Digest,
    pub(crate) materialized_lemmas_sha256: Sha256Digest,
    pub(crate) materialized_candidate_sha256: Sha256Digest,
    pub(crate) result: AuditResult,
}

impl EqresAuditReceipt {
    pub(crate) fn new(
        bundle: &EqresBundle,
        exact_bundle_sha256: Sha256Digest,
        result: AuditResult,
    ) -> Self {
        let hashes = bundle.compiler.hashes;
        Self {
            schema_version: EQRES_AUDIT_RECEIPT_SCHEMA_VERSION,
            exact_bundle_sha256,
            source_sha256: hashes.source_sha256,
            baseline_problem_sha256: hashes.baseline_problem_sha256,
            trace_sha256: hashes.trace_sha256,
            lemma_sequence_sha256: hashes.lemma_sequence_sha256,
            materialized_lemmas_sha256: hashes.materialized_lemmas_sha256,
            materialized_candidate_sha256: hashes.materialized_candidate_sha256,
            result,
        }
    }

    pub(crate) fn accepted_for(
        &self,
        bundle: &EqresBundle,
        exact_bundle_sha256: Sha256Digest,
    ) -> bool {
        if self.schema_version != EQRES_AUDIT_RECEIPT_SCHEMA_VERSION
            || self.exact_bundle_sha256 == Sha256Digest::ZERO
            || self.exact_bundle_sha256 != exact_bundle_sha256
            || !matches!(self.result.status, AuditStatus::Accepted)
            || self.result.counters != bundle.compiler.counters
            || self.result.counters != bundle.report.counters
            || self.result.cap_attempt != bundle.report.cap_attempt
        {
            return false;
        }

        let compiler_cap = match &bundle.compiler.status {
            CompilerStatus::Rejected(CompilerFailure::Cap(attempt)) => Some(attempt),
            CompilerStatus::Completed(_) => None,
            CompilerStatus::NotRun | CompilerStatus::Rejected(_) => return false,
        };
        if self.result.cap_attempt.as_ref() != compiler_cap {
            return false;
        }

        let receipt = [
            self.source_sha256,
            self.baseline_problem_sha256,
            self.trace_sha256,
            self.lemma_sequence_sha256,
            self.materialized_lemmas_sha256,
            self.materialized_candidate_sha256,
        ];
        let compiler = [
            bundle.compiler.hashes.source_sha256,
            bundle.compiler.hashes.baseline_problem_sha256,
            bundle.compiler.hashes.trace_sha256,
            bundle.compiler.hashes.lemma_sequence_sha256,
            bundle.compiler.hashes.materialized_lemmas_sha256,
            bundle.compiler.hashes.materialized_candidate_sha256,
        ];
        let checker = [
            bundle.checker.recomputed_hashes.source_sha256,
            bundle.checker.recomputed_hashes.baseline_problem_sha256,
            bundle.checker.recomputed_hashes.trace_sha256,
            bundle.checker.recomputed_hashes.lemma_sequence_sha256,
            bundle.checker.recomputed_hashes.materialized_lemmas_sha256,
            bundle
                .checker
                .recomputed_hashes
                .materialized_candidate_sha256,
        ];
        let report = [
            bundle.report.hashes.source_sha256,
            bundle.report.hashes.baseline_problem_sha256,
            bundle.report.hashes.trace_sha256,
            bundle.report.hashes.lemma_sequence_sha256,
            bundle.report.hashes.materialized_lemmas_sha256,
            bundle.report.hashes.materialized_candidate_sha256,
        ];
        let reconstructed = [
            self.result.recomputed_hashes.source_sha256,
            self.result.recomputed_hashes.baseline_problem_sha256,
            self.result.recomputed_hashes.trace_sha256,
            self.result.recomputed_hashes.lemma_sequence_sha256,
            self.result.recomputed_hashes.materialized_lemmas_sha256,
            self.result.recomputed_hashes.materialized_candidate_sha256,
        ];
        receipt
            .iter()
            .zip(compiler)
            .zip(checker)
            .zip(report)
            .zip(reconstructed)
            .all(
                |((((receipt, compiler), checker), report), reconstructed)| {
                    *receipt != Sha256Digest::ZERO
                        && *receipt == compiler
                        && *receipt == checker
                        && *receipt == report
                        && *receipt == reconstructed
                },
            )
    }
}

#[derive(Debug, Clone)]
struct ApplicationPair {
    applications: [ApplicationId; 2],
    requirements: Vec<(ArgumentIndex, EqualityKey)>,
}

struct PreparedInput {
    counters: InputCounters,
    application_pairs: Vec<ApplicationPair>,
    initial_logical_memory: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NegativeOccurrence {
    source: ClausePivot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EndpointAssociation {
    node: NodeId,
    other: TermId,
    orientation: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ApplicationRequirement {
    pair_index: usize,
    argument_index: ArgumentIndex,
}

struct NodeMeta {
    trace_index: usize,
    conclusion: EqualityKey,
    depth: ProofDepth,
    active: bool,
    mechanism_dependency: bool,
}

struct DerivedClauseMeta {
    trace_index: usize,
    id: ClauseId,
    depth: ProofDepth,
    mechanism_dependency: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CongruenceTupleKey {
    pair_index: usize,
    parents: Box<[NodeId]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TransitivityJoinKey {
    parents: [NodeId; 2],
    intermediate: TermId,
}

enum PendingEvent {
    Equality {
        rule: EqualityRuleRecord,
        mechanism_dependency: bool,
    },
    Conflict {
        rule: ConflictRecord,
        mechanism_dependency: bool,
    },
}

struct QueuedEvent {
    key: EventKey,
    pending: PendingEvent,
}

impl PartialEq for QueuedEvent {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for QueuedEvent {}

impl PartialOrd for QueuedEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueuedEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

struct OutputCandidate {
    source_clause_id: ClauseId,
    clause: CanonicalClause,
    mechanism_dependency: bool,
}

struct TerminalEmpty {
    event_id: EventId,
    clause_id: ClauseId,
    mechanism_dependency: bool,
}

#[derive(Debug)]
enum ReconstructionError {
    Cap(CapAttempt),
    Malformed(InputFailure),
    Arithmetic(Option<EventId>),
    Allocation(Option<EventId>),
    Internal(Option<EventId>),
}

enum ReconstructionStatus {
    Completed(EqresOutput),
    Cap {
        attempt: CapAttempt,
        hashes_recorded: bool,
    },
    Fatal(ReconstructionError),
}

struct Reconstruction {
    status: ReconstructionStatus,
    trace: Vec<TraceRecord>,
    counters: DeterministicCounters,
}

struct Auditor<'a> {
    input: EqresInput<'a>,
    variant: CompilerVariant,
    counters: DeterministicCounters,
    application_pairs: Vec<ApplicationPair>,
    application_argument_index: FxHashMap<EqualityKey, Vec<ApplicationRequirement>>,
    congruence_tuples: FxHashSet<CongruenceTupleKey>,
    transitivity_joins: FxHashSet<TransitivityJoinKey>,
    worklist: BinaryHeap<Reverse<QueuedEvent>>,
    inserted_event_keys: FxHashSet<EventKey>,
    trace: Vec<TraceRecord>,
    nodes: Vec<NodeMeta>,
    derived_clauses: Vec<DerivedClauseMeta>,
    retained_supports: FxHashMap<EqualityKey, Vec<NodeId>>,
    endpoint_index: FxHashMap<TermId, Vec<EndpointAssociation>>,
    negative_index: FxHashMap<EqualityKey, Vec<NegativeOccurrence>>,
    base_canonical_clauses: Vec<CanonicalClause>,
    global_clauses: FxHashSet<CanonicalClause>,
    terminal_empty: Option<TerminalEmpty>,
}

fn reconstruct(input: EqresInput<'_>, variant: CompilerVariant) -> Reconstruction {
    let mut counters = DeterministicCounters::default();
    let prepared = match validate_and_prepare(input, &mut counters) {
        Ok(prepared) => prepared,
        Err(ReconstructionError::Cap(attempt)) => {
            return Reconstruction {
                status: ReconstructionStatus::Cap {
                    attempt,
                    hashes_recorded: false,
                },
                trace: Vec::new(),
                counters,
            };
        }
        Err(error) => {
            return Reconstruction {
                status: ReconstructionStatus::Fatal(error),
                trace: Vec::new(),
                counters,
            };
        }
    };

    let mut auditor = match Auditor::new(input, variant, prepared) {
        Ok(auditor) => auditor,
        Err(error) => {
            return Reconstruction {
                status: ReconstructionStatus::Fatal(error),
                trace: Vec::new(),
                counters,
            };
        }
    };
    let status = match auditor.run() {
        Ok(output) => ReconstructionStatus::Completed(output),
        Err(ReconstructionError::Cap(attempt)) => ReconstructionStatus::Cap {
            attempt,
            hashes_recorded: true,
        },
        Err(error) => ReconstructionStatus::Fatal(error),
    };
    Reconstruction {
        status,
        trace: auditor.trace,
        counters: auditor.counters,
    }
}

fn validate_and_prepare(
    input: EqresInput<'_>,
    counters: &mut DeterministicCounters,
) -> Result<PreparedInput, ReconstructionError> {
    let term_count = to_u64(input.term_dag.len(), None)?;
    let variable_count = input
        .variable_atoms
        .len()
        .checked_sub(1)
        .ok_or_else(|| malformed(InputFailure::InvalidAtomMap))?;
    let variable_count = to_u64(variable_count, None)?;
    let clause_count = input
        .baseline_clauses
        .end_offsets
        .len()
        .checked_sub(1)
        .ok_or_else(|| malformed(InputFailure::InvalidClauseStore))?;
    let clause_count = to_u64(clause_count, None)?;
    let literal_slots = to_u64(input.baseline_clauses.literals.len(), None)?;
    let application_count = to_u64(input.ordered_applications.len(), None)?;

    counters.input.terms = term_count;
    counters.input.baseline_variables = variable_count;
    counters.input.baseline_atom_entries = to_u64(input.atom_variables.len(), None)?;
    counters.input.baseline_clauses = clause_count;
    counters.input.baseline_literal_slots = literal_slots;
    counters.input.applications = application_count;

    // Frozen static-cap precedence is part of the certificate contract.
    check_static_cap(CapReason::Terms, term_count, Limits::TERMS)?;
    check_static_cap(
        CapReason::BaselineVariables,
        variable_count,
        Limits::BASELINE_VARIABLES,
    )?;
    check_static_cap(
        CapReason::BaselineClauses,
        clause_count,
        Limits::BASELINE_CLAUSES,
    )?;
    check_static_cap(
        CapReason::BaselineLiteralSlots,
        literal_slots,
        Limits::BASELINE_LITERAL_SLOTS,
    )?;
    check_static_cap(
        CapReason::Applications,
        application_count,
        Limits::APPLICATIONS,
    )?;

    validate_clause_store(input)?;
    validate_sorts_and_declarations(input)?;
    validate_terms_and_application_order(input)?;
    validate_atom_maps(input)?;
    validate_clause_literals(input)?;

    let mut application_pairs = Vec::new();
    application_pairs
        .try_reserve(input.ordered_applications.len())
        .map_err(|_| allocation(None))?;
    let mut maximum_arity = 0u64;
    let mut argument_slots = 0u64;
    for (left_position, &left_id) in input.ordered_applications.iter().enumerate() {
        let left = input
            .term_dag
            .get(left_id)
            .ok_or_else(|| malformed(InputFailure::InvalidApplication))?;
        maximum_arity = maximum_arity.max(to_u64(left.args.len(), None)?);
        for &right_id in &input.ordered_applications[(left_position + 1)..] {
            let right = input
                .term_dag
                .get(right_id)
                .ok_or_else(|| malformed(InputFailure::InvalidApplication))?;
            if left.fun != right.fun {
                continue;
            }
            if left.args.len() != right.args.len() || left.sort != right.sort {
                return Err(malformed(InputFailure::InvalidApplication));
            }
            if left.sort == BOOL_SORT {
                return Err(malformed(InputFailure::UnsupportedBooleanApplicationPair));
            }

            let mut requirements = Vec::new();
            requirements
                .try_reserve(left.args.len())
                .map_err(|_| allocation(None))?;
            for (index, (&left_arg, &right_arg)) in left.args.iter().zip(&right.args).enumerate() {
                if left_arg == right_arg {
                    continue;
                }
                requirements.push((
                    ArgumentIndex::new(to_u32(index, None)?),
                    normalized_equality(left_arg, right_arg)?,
                ));
            }
            if requirements.is_empty() {
                return Err(malformed(InputFailure::InvalidTerm));
            }
            argument_slots = checked_add(argument_slots, to_u64(requirements.len(), None)?, None)?;
            application_pairs
                .try_reserve(1)
                .map_err(|_| allocation(None))?;
            application_pairs.push(ApplicationPair {
                applications: [ApplicationId::new(left_id), ApplicationId::new(right_id)],
                requirements,
            });
        }
    }

    let pair_count = to_u64(application_pairs.len(), None)?;
    counters.input.application_pairs = pair_count;
    counters.input.maximum_arity = maximum_arity;
    counters.input.application_argument_slots = argument_slots;
    check_static_cap(
        CapReason::ApplicationPairs,
        pair_count,
        Limits::APPLICATION_PAIRS,
    )?;
    check_static_cap(
        CapReason::MaximumArity,
        maximum_arity,
        Limits::MAXIMUM_ARITY,
    )?;
    check_static_cap(
        CapReason::ApplicationArgumentSlots,
        argument_slots,
        Limits::APPLICATION_ARGUMENT_SLOTS,
    )?;

    let initial_logical_memory =
        logical_memory(0, 0, 0, 0, 0, 0, 0, pair_count, argument_slots, None)?;
    check_static_cap(
        CapReason::LogicalIncrementalMemoryBytes,
        initial_logical_memory,
        Limits::LOGICAL_INCREMENTAL_MEMORY_BYTES,
    )?;
    Ok(PreparedInput {
        counters: counters.input,
        application_pairs,
        initial_logical_memory,
    })
}

fn validate_clause_store(input: EqresInput<'_>) -> Result<(), ReconstructionError> {
    let offsets = &input.baseline_clauses.end_offsets;
    if offsets.first() != Some(&0)
        || offsets.windows(2).any(|window| window[0] > window[1])
        || offsets.last().copied().map(u64::from)
            != Some(to_u64(input.baseline_clauses.literals.len(), None)?)
    {
        return Err(malformed(InputFailure::InvalidClauseStore));
    }
    Ok(())
}

fn validate_sorts_and_declarations(input: EqresInput<'_>) -> Result<(), ReconstructionError> {
    if input.sorts.names.first().map(String::as_str) != Some("Bool")
        || input.sorts.names.len() > u32::MAX as usize
    {
        return Err(malformed(InputFailure::InvalidSort));
    }
    let mut seen_sort_ids = FxHashSet::default();
    seen_sort_ids
        .try_reserve(input.sorts.ids.len())
        .map_err(|_| allocation(None))?;
    for sort in input.sorts.ids.values() {
        let index = sort.0 as usize;
        if index == 0 || index >= input.sorts.names.len() || !seen_sort_ids.insert(sort.0) {
            return Err(malformed(InputFailure::InvalidSort));
        }
    }
    if input.sorts.ids.len() != input.sorts.names.len().saturating_sub(1) {
        return Err(malformed(InputFailure::InvalidSort));
    }
    for declaration in input.declarations.slots.iter().flatten() {
        if declaration.result_sort.0 as usize >= input.sorts.names.len()
            || declaration
                .arg_sorts
                .iter()
                .any(|sort| sort.0 as usize >= input.sorts.names.len())
        {
            return Err(malformed(InputFailure::InvalidDeclaration));
        }
    }
    Ok(())
}

fn validate_terms_and_application_order(input: EqresInput<'_>) -> Result<(), ReconstructionError> {
    let mut term_shapes = FxHashSet::default();
    term_shapes
        .try_reserve(input.term_dag.len())
        .map_err(|_| allocation(None))?;
    for (term_id, term) in input.term_dag.iter().enumerate() {
        if term.sort.0 as usize >= input.sorts.names.len() {
            return Err(malformed(InputFailure::InvalidSort));
        }
        let declaration = input
            .declarations
            .get(term.fun)
            .ok_or_else(|| malformed(InputFailure::InvalidDeclaration))?;
        if declaration.result_sort != term.sort || declaration.arg_sorts.len() != term.args.len() {
            return Err(malformed(InputFailure::InvalidTerm));
        }
        for (&argument, &sort) in term.args.iter().zip(&declaration.arg_sorts) {
            if argument >= term_id
                || input.term_dag.get(argument).map(|term| term.sort) != Some(sort)
            {
                return Err(malformed(InputFailure::InvalidTerm));
            }
        }
        if !term_shapes.insert((term.fun, term.args.as_slice())) {
            return Err(malformed(InputFailure::InvalidTerm));
        }
    }

    if input
        .ordered_applications
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(malformed(InputFailure::InvalidApplicationOrder));
    }
    let mut next_application = 0usize;
    for (term_id, term) in input.term_dag.iter().enumerate() {
        if term.args.is_empty() {
            continue;
        }
        if input.ordered_applications.get(next_application) != Some(&term_id) {
            return Err(malformed(InputFailure::InvalidApplicationOrder));
        }
        next_application = next_application
            .checked_add(1)
            .ok_or_else(|| arithmetic(None))?;
    }
    if next_application != input.ordered_applications.len()
        || input.ordered_applications.iter().any(|&term| {
            input
                .term_dag
                .get(term)
                .is_none_or(|term| term.args.is_empty())
        })
    {
        return Err(malformed(InputFailure::InvalidApplication));
    }
    Ok(())
}

fn validate_atom_maps(input: EqresInput<'_>) -> Result<(), ReconstructionError> {
    if input.variable_atoms.first() != Some(&None) {
        return Err(malformed(InputFailure::InvalidAtomMap));
    }
    let mut mapped = 0usize;
    for (variable, atom) in input.variable_atoms.iter().enumerate().skip(1) {
        let Some(atom) = atom else {
            continue;
        };
        mapped = mapped.checked_add(1).ok_or_else(|| arithmetic(None))?;
        validate_atom(input, atom)?;
        let variable = i32::try_from(variable).map_err(|_| arithmetic(None))?;
        if input.atom_variables.get(atom) != Some(&variable) {
            return Err(malformed(InputFailure::InvalidAtomMap));
        }
    }
    if mapped != input.atom_variables.len() {
        return Err(malformed(InputFailure::InvalidAtomMap));
    }
    for (atom, &variable) in input.atom_variables {
        validate_atom(input, atom)?;
        let index =
            usize::try_from(variable).map_err(|_| malformed(InputFailure::InvalidAtomMap))?;
        if variable <= 0 || input.variable_atoms.get(index).and_then(Option::as_ref) != Some(atom) {
            return Err(malformed(InputFailure::InvalidAtomMap));
        }
    }
    if let Some(literal) = input.true_literal {
        let variable =
            usize::try_from(literal).map_err(|_| malformed(InputFailure::InvalidAtomMap))?;
        if literal <= 0
            || input.variable_atoms.get(variable) != Some(&None)
            || !input
                .baseline_clauses
                .iter()
                .any(|clause| clause == [literal])
        {
            return Err(malformed(InputFailure::InvalidAtomMap));
        }
    }
    Ok(())
}

fn validate_atom(input: EqresInput<'_>, atom: &BoolAtomKey) -> Result<(), ReconstructionError> {
    match *atom {
        BoolAtomKey::Eq(left, right) => {
            let (Some(left_term), Some(right_term)) =
                (input.term_dag.get(left), input.term_dag.get(right))
            else {
                return Err(malformed(InputFailure::InvalidAtomTerm));
            };
            if left > right || left_term.sort != right_term.sort || left_term.sort == BOOL_SORT {
                return Err(malformed(InputFailure::InvalidAtomTerm));
            }
        }
        BoolAtomKey::BoolTerm(term) => {
            if input.term_dag.get(term).map(|term| term.sort) != Some(BOOL_SORT) {
                return Err(malformed(InputFailure::InvalidAtomTerm));
            }
        }
    }
    Ok(())
}

fn validate_clause_literals(input: EqresInput<'_>) -> Result<(), ReconstructionError> {
    let variable_count = input.variable_atoms.len().saturating_sub(1);
    for &literal in &input.baseline_clauses.literals {
        let variable = usize::try_from(literal.unsigned_abs()).map_err(|_| arithmetic(None))?;
        if literal == 0 || variable == 0 || variable > variable_count {
            return Err(malformed(InputFailure::InvalidClauseLiteral));
        }
        if let Some(BoolAtomKey::Eq(left, right)) = input.variable_atoms[variable].as_ref() {
            let left_sort = input.term_dag.get(*left).map(|term| term.sort);
            let right_sort = input.term_dag.get(*right).map(|term| term.sort);
            if left_sort.is_none() || left_sort != right_sort {
                return Err(malformed(InputFailure::InvalidClauseLiteral));
            }
        }
    }
    Ok(())
}

impl<'a> Auditor<'a> {
    fn new(
        input: EqresInput<'a>,
        variant: CompilerVariant,
        prepared: PreparedInput,
    ) -> Result<Self, ReconstructionError> {
        let mut counters = DeterministicCounters {
            input: prepared.counters,
            ..DeterministicCounters::default()
        };
        counters.search.canonical_proof_work_literal_charge = counters.input.baseline_literal_slots;
        counters.search.logical_incremental_memory_bytes = prepared.initial_logical_memory;

        let mut application_argument_index: FxHashMap<EqualityKey, Vec<ApplicationRequirement>> =
            FxHashMap::default();
        application_argument_index
            .try_reserve(prepared.application_pairs.len())
            .map_err(|_| allocation(None))?;
        for (pair_index, pair) in prepared.application_pairs.iter().enumerate() {
            for &(argument_index, equality) in &pair.requirements {
                ensure_vec_map_entry(&mut application_argument_index, equality, None)?;
                let entries = application_argument_index
                    .get_mut(&equality)
                    .ok_or_else(|| internal(None))?;
                entries.try_reserve(1).map_err(|_| allocation(None))?;
                entries.push(ApplicationRequirement {
                    pair_index,
                    argument_index,
                });
            }
        }
        for entries in application_argument_index.values_mut() {
            entries.sort_unstable_by_key(|entry| (entry.pair_index, entry.argument_index));
        }

        let mut base_canonical_clauses = Vec::new();
        base_canonical_clauses
            .try_reserve(input.baseline_clauses.len())
            .map_err(|_| allocation(None))?;
        let mut global_clauses = FxHashSet::default();
        global_clauses
            .try_reserve(input.baseline_clauses.len())
            .map_err(|_| allocation(None))?;
        for clause in input.baseline_clauses {
            if let Some(canonical) = canonicalize_one(clause, None)? {
                if !global_clauses.contains(&canonical) {
                    let set_clause = try_clone_clause(&canonical, None)?;
                    if !global_clauses.insert(set_clause) {
                        return Err(internal(None));
                    }
                    base_canonical_clauses.push(canonical);
                }
            }
        }

        Ok(Self {
            input,
            variant,
            counters,
            application_pairs: prepared.application_pairs,
            application_argument_index,
            congruence_tuples: FxHashSet::default(),
            transitivity_joins: FxHashSet::default(),
            worklist: BinaryHeap::new(),
            inserted_event_keys: FxHashSet::default(),
            trace: Vec::new(),
            nodes: Vec::new(),
            derived_clauses: Vec::new(),
            retained_supports: FxHashMap::default(),
            endpoint_index: FxHashMap::default(),
            negative_index: FxHashMap::default(),
            base_canonical_clauses,
            global_clauses,
            terminal_empty: None,
        })
    }

    fn run(&mut self) -> Result<EqresOutput, ReconstructionError> {
        self.initialize_base()?;
        for term in 0..self.input.term_dag.len() {
            self.attempt_reflexivity(term, None)?;
        }
        while let Some(Reverse(event)) = self.worklist.pop() {
            self.counters.search.live_worklist_entries = self
                .counters
                .search
                .live_worklist_entries
                .checked_sub(1)
                .ok_or_else(|| internal(None))?;
            let event_id = EventId::new(to_u32(self.counters.search.events_popped, None)?);
            self.counters.search.events_popped =
                checked_add(self.counters.search.events_popped, 1, Some(event_id))?;
            if self.accept_popped_event(event_id, event)? {
                break;
            }
        }
        self.final_output()
    }

    fn initialize_base(&mut self) -> Result<(), ReconstructionError> {
        for clause_index in 0..self.input.baseline_clauses.len() {
            let clause_ref = ClauseRef {
                id: ClauseId::new(to_u32(clause_index, None)?),
                origin: ClauseOrigin::Baseline,
            };
            let clause_len = self.input.baseline_clauses[clause_index].len();
            for offset in 0..clause_len {
                let literal = self.input.baseline_clauses[clause_index][offset];
                let Some((positive, equality)) = self.equality_literal(literal) else {
                    continue;
                };
                let pivot = ClausePivot {
                    clause: clause_ref,
                    literal_offset: LiteralOffset::new(to_u32(offset, None)?),
                };
                if positive {
                    self.attempt_seed(pivot, None)?;
                } else {
                    self.register_negative(equality, pivot, None)?;
                }
            }
        }
        Ok(())
    }

    fn equality_literal(&self, literal: i32) -> Option<(bool, EqualityKey)> {
        let variable = usize::try_from(literal.unsigned_abs()).ok()?;
        match self.input.variable_atoms.get(variable)?.as_ref()? {
            BoolAtomKey::Eq(left, right) => {
                Some((literal > 0, EqualityKey::from_normalized(*left, *right)?))
            }
            BoolAtomKey::BoolTerm(_) => None,
        }
    }

    fn clause_slice(&self, clause: ClauseRef) -> Result<&[i32], ReconstructionError> {
        let index = clause.id.get() as usize;
        match clause.origin {
            ClauseOrigin::Baseline => {
                if index >= self.input.baseline_clauses.len() {
                    return Err(internal(None));
                }
                Ok(&self.input.baseline_clauses[index])
            }
            ClauseOrigin::Derived => {
                let derived_index = index
                    .checked_sub(self.input.baseline_clauses.len())
                    .ok_or_else(|| internal(None))?;
                let meta = self
                    .derived_clauses
                    .get(derived_index)
                    .ok_or_else(|| internal(None))?;
                match self.trace.get(meta.trace_index) {
                    Some(TraceRecord::Conflict(record)) if record.clause_id == clause.id => {
                        Ok(record.clause.as_slice())
                    }
                    _ => Err(internal(None)),
                }
            }
        }
    }

    fn clause_depth_and_dependency(
        &self,
        clause: ClauseRef,
    ) -> Result<(ProofDepth, bool), ReconstructionError> {
        match clause.origin {
            ClauseOrigin::Baseline => Ok((ProofDepth::new(0), false)),
            ClauseOrigin::Derived => {
                let derived_index = (clause.id.get() as usize)
                    .checked_sub(self.input.baseline_clauses.len())
                    .ok_or_else(|| internal(None))?;
                let meta = self
                    .derived_clauses
                    .get(derived_index)
                    .ok_or_else(|| internal(None))?;
                if meta.id != clause.id {
                    return Err(internal(None));
                }
                Ok((meta.depth, meta.mechanism_dependency))
            }
        }
    }

    fn node_side(&self, node: NodeId) -> Result<&[i32], ReconstructionError> {
        let meta = self
            .nodes
            .get(node.get() as usize)
            .ok_or_else(|| internal(None))?;
        match self.trace.get(meta.trace_index) {
            Some(TraceRecord::Equality(record)) if record.node_id == node => {
                Ok(record.side_clause.as_slice())
            }
            _ => Err(internal(None)),
        }
    }

    fn attempt_seed(
        &mut self,
        source: ClausePivot,
        parent_event: Option<EventId>,
    ) -> Result<(), ReconstructionError> {
        let (side, conclusion, source_width) = {
            let clause = self.clause_slice(source.clause)?;
            let offset = source.literal_offset.get() as usize;
            let literal = *clause.get(offset).ok_or_else(|| internal(parent_event))?;
            let Some((true, conclusion)) = self.equality_literal(literal) else {
                return Err(internal(parent_event));
            };
            (
                canonicalize_without(clause, offset, parent_event)?,
                conclusion,
                to_u64(clause.len(), parent_event)?,
            )
        };
        let (depth, mechanism_dependency) = self.clause_depth_and_dependency(source.clause)?;
        self.insert_candidate(
            RuleKind::Seed,
            depth,
            Some(conclusion),
            side,
            Some(source),
            Vec::new(),
            PendingEvent::Equality {
                rule: EqualityRuleRecord::Seed(SeedRecord {
                    positive_source: source,
                }),
                mechanism_dependency,
            },
            source_width,
            parent_event,
        )
    }

    fn attempt_reflexivity(
        &mut self,
        term: TermId,
        parent_event: Option<EventId>,
    ) -> Result<(), ReconstructionError> {
        if self.input.term_dag.get(term).is_none() {
            return Err(internal(parent_event));
        }
        self.insert_candidate(
            RuleKind::Reflexivity,
            ProofDepth::new(0),
            Some(normalized_equality(term, term)?),
            Some(CanonicalClause::empty()),
            None,
            Vec::new(),
            PendingEvent::Equality {
                rule: EqualityRuleRecord::Reflexivity(ReflexivityRecord { term }),
                mechanism_dependency: false,
            },
            0,
            parent_event,
        )
    }

    fn attempt_transitivity(
        &mut self,
        first: NodeId,
        second: NodeId,
        intermediate: TermId,
        first_other: TermId,
        second_other: TermId,
        parent_event: EventId,
    ) -> Result<(), ReconstructionError> {
        let first_meta = self
            .nodes
            .get(first.get() as usize)
            .ok_or_else(|| internal(Some(parent_event)))?;
        let second_meta = self
            .nodes
            .get(second.get() as usize)
            .ok_or_else(|| internal(Some(parent_event)))?;
        if !contains_endpoint(first_meta.conclusion, intermediate)
            || !contains_endpoint(second_meta.conclusion, intermediate)
        {
            return Err(internal(Some(parent_event)));
        }
        let side_width_sum = checked_add(
            to_u64(self.node_side(first)?.len(), Some(parent_event))?,
            to_u64(self.node_side(second)?.len(), Some(parent_event))?,
            Some(parent_event),
        )?;
        let charge = checked_mul(side_width_sum, 2, Some(parent_event))?;
        let side = canonicalize_node_union(self, &[first, second], Some(parent_event))?;
        let parent_depth = first_meta.depth.get().max(second_meta.depth.get());
        let depth = ProofDepth::new(to_u32(
            checked_add(u64::from(parent_depth), 1, Some(parent_event))?,
            Some(parent_event),
        )?);
        let dependency = first_meta.mechanism_dependency || second_meta.mechanism_dependency;
        let mut parents = [first, second];
        parents.sort_unstable();
        self.insert_candidate(
            RuleKind::Transitivity,
            depth,
            Some(normalized_equality(first_other, second_other)?),
            side,
            None,
            parents.to_vec(),
            PendingEvent::Equality {
                rule: EqualityRuleRecord::Transitivity(TransitivityRecord {
                    parents,
                    intermediate,
                }),
                mechanism_dependency: dependency,
            },
            charge,
            Some(parent_event),
        )
    }

    fn attempt_congruence(
        &mut self,
        pair_index: usize,
        parent_tuple: &[NodeId],
        directly_missing: bool,
        parent_event: EventId,
    ) -> Result<(), ReconstructionError> {
        let pair = self
            .application_pairs
            .get(pair_index)
            .ok_or_else(|| internal(Some(parent_event)))?;
        if pair.requirements.len() != parent_tuple.len() {
            return Err(internal(Some(parent_event)));
        }
        let applications = pair.applications;
        let mut requirements = Vec::new();
        requirements
            .try_reserve_exact(pair.requirements.len())
            .map_err(|_| allocation(Some(parent_event)))?;
        requirements.extend_from_slice(&pair.requirements);

        let conclusion = normalized_equality(applications[0].term(), applications[1].term())?;
        let mut mechanism_dependency = false;
        let mut maximum_parent_depth = 0u32;
        let mut side_width_sum = 0u64;
        for ((_, required), &parent) in requirements.iter().zip(parent_tuple) {
            let meta = self
                .nodes
                .get(parent.get() as usize)
                .ok_or_else(|| internal(Some(parent_event)))?;
            if meta.conclusion != *required {
                return Err(internal(Some(parent_event)));
            }
            mechanism_dependency |= meta.mechanism_dependency;
            maximum_parent_depth = maximum_parent_depth.max(meta.depth.get());
            side_width_sum = checked_add(
                side_width_sum,
                to_u64(self.node_side(parent)?.len(), Some(parent_event))?,
                Some(parent_event),
            )?;
        }
        let side = canonicalize_node_union(self, parent_tuple, Some(parent_event))?;
        let charge = checked_mul(side_width_sum, 2, Some(parent_event))?;
        let depth = ProofDepth::new(to_u32(
            checked_add(u64::from(maximum_parent_depth), 1, Some(parent_event))?,
            Some(parent_event),
        )?);
        let mut associations = Vec::new();
        associations
            .try_reserve(parent_tuple.len())
            .map_err(|_| allocation(Some(parent_event)))?;
        for (&(argument_index, _), &parent) in requirements.iter().zip(parent_tuple) {
            associations.push(CongruenceArgumentParent {
                argument_index,
                parent,
            });
        }
        let mut key_parents = Vec::new();
        key_parents
            .try_reserve_exact(parent_tuple.len())
            .map_err(|_| allocation(Some(parent_event)))?;
        key_parents.extend_from_slice(parent_tuple);
        key_parents.sort_unstable();
        self.insert_candidate(
            RuleKind::Congruence,
            depth,
            Some(conclusion),
            side,
            None,
            key_parents,
            PendingEvent::Equality {
                rule: EqualityRuleRecord::Congruence(CongruenceRecord {
                    applications,
                    arguments: associations.into_boxed_slice(),
                }),
                mechanism_dependency: directly_missing || mechanism_dependency,
            },
            charge,
            Some(parent_event),
        )
    }

    fn classify_missing_congruence(
        &self,
        pair_index: usize,
        parent_event: EventId,
    ) -> Result<bool, ReconstructionError> {
        let pair = self
            .application_pairs
            .get(pair_index)
            .ok_or_else(|| internal(Some(parent_event)))?;
        let conclusion =
            normalized_equality(pair.applications[0].term(), pair.applications[1].term())?;
        let mut directly_missing = !self.baseline_has_equality(conclusion);
        for &(_, required) in &pair.requirements {
            directly_missing |= !self.baseline_has_equality(required);
        }
        Ok(directly_missing)
    }

    fn attempt_conflict(
        &mut self,
        equality_parent: NodeId,
        negative_source: ClausePivot,
        parent_event: Option<EventId>,
    ) -> Result<(), ReconstructionError> {
        let node = self
            .nodes
            .get(equality_parent.get() as usize)
            .ok_or_else(|| internal(parent_event))?;
        let node_conclusion = node.conclusion;
        let node_depth = node.depth;
        let node_dependency = node.mechanism_dependency;
        let (source_side, source_width_without_pivot, source_depth, source_dependency) = {
            let clause = self.clause_slice(negative_source.clause)?;
            let offset = negative_source.literal_offset.get() as usize;
            let literal = *clause.get(offset).ok_or_else(|| internal(parent_event))?;
            let Some((false, conclusion)) = self.equality_literal(literal) else {
                return Err(internal(parent_event));
            };
            if conclusion != node_conclusion {
                return Err(internal(parent_event));
            }
            let (depth, dependency) = self.clause_depth_and_dependency(negative_source.clause)?;
            (
                canonicalize_without(clause, offset, parent_event)?,
                to_u64(clause.len().saturating_sub(1), parent_event)?,
                depth,
                dependency,
            )
        };
        let equality_side_width = to_u64(self.node_side(equality_parent)?.len(), parent_event)?;
        let premise_width = checked_add(
            equality_side_width,
            source_width_without_pivot,
            parent_event,
        )?;
        let charge = checked_mul(premise_width, 2, parent_event)?;
        let side = match source_side {
            None => None,
            Some(source_side) => canonicalize_two(
                self.node_side(equality_parent)?,
                source_side.as_slice(),
                parent_event,
            )?,
        };
        let depth = ProofDepth::new(to_u32(
            checked_add(
                u64::from(node_depth.get().max(source_depth.get())),
                1,
                parent_event,
            )?,
            parent_event,
        )?);
        self.insert_candidate(
            RuleKind::Conflict,
            depth,
            None,
            side,
            Some(negative_source),
            vec![equality_parent],
            PendingEvent::Conflict {
                rule: ConflictRecord {
                    equality_parent,
                    negative_source,
                },
                mechanism_dependency: node_dependency || source_dependency,
            },
            charge,
            parent_event,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_candidate(
        &mut self,
        rule: RuleKind,
        depth: ProofDepth,
        conclusion: Option<EqualityKey>,
        clause: Option<CanonicalClause>,
        source: Option<ClausePivot>,
        parents: Vec<NodeId>,
        pending: PendingEvent,
        proof_work_charge: u64,
        parent_event: Option<EventId>,
    ) -> Result<(), ReconstructionError> {
        let boundary = CapBoundary::ChildInsertion { parent_event, rule };
        if u64::from(depth.get()) > Limits::PROOF_DEPTH {
            return Err(cap(
                CapReason::ProofDepth,
                boundary,
                self.counters.search.maximum_proof_depth,
                u64::from(depth.get()),
                Limits::PROOF_DEPTH,
            ));
        }
        let prospective_work = checked_add(
            self.counters.search.canonical_proof_work_literal_charge,
            proof_work_charge,
            parent_event,
        )?;
        if prospective_work > Limits::CANONICAL_PROOF_WORK_LITERAL_CHARGE {
            return Err(cap(
                CapReason::CanonicalProofWorkLiteralCharge,
                boundary,
                self.counters.search.canonical_proof_work_literal_charge,
                prospective_work,
                Limits::CANONICAL_PROOF_WORK_LITERAL_CHARGE,
            ));
        }

        increment_rule_counter(
            &mut self.counters.search.attempted_events,
            rule,
            parent_event,
        )?;
        self.counters.search.canonical_proof_work_literal_charge = prospective_work;
        let Some(clause) = clause else {
            if rule == RuleKind::Conflict {
                self.counters.pruning.tautological_derived_clauses = checked_add(
                    self.counters.pruning.tautological_derived_clauses,
                    1,
                    parent_event,
                )?;
            }
            return Ok(());
        };

        let key = EventKey {
            resulting_clause_width: to_u32(clause.len(), parent_event)?,
            proof_depth: depth,
            rule,
            conclusion,
            clause,
            source,
            parents: parents.into_boxed_slice(),
        };
        if self.inserted_event_keys.contains(&key) {
            self.counters.search.duplicate_event_keys =
                checked_add(self.counters.search.duplicate_event_keys, 1, parent_event)?;
            return Ok(());
        }
        let prospective_pushes =
            checked_add(self.counters.search.worklist_pushes, 1, parent_event)?;
        if prospective_pushes > Limits::WORKLIST_PUSHES {
            return Err(cap(
                CapReason::WorklistPushes,
                boundary,
                self.counters.search.worklist_pushes,
                prospective_pushes,
                Limits::WORKLIST_PUSHES,
            ));
        }
        let prospective_live =
            checked_add(self.counters.search.live_worklist_entries, 1, parent_event)?;
        if prospective_live > Limits::LIVE_WORKLIST_ENTRIES {
            return Err(cap(
                CapReason::LiveWorklistEntries,
                boundary,
                self.counters.search.live_worklist_entries,
                prospective_live,
                Limits::LIVE_WORKLIST_ENTRIES,
            ));
        }
        let prospective_keys = checked_add(
            self.counters.search.distinct_event_keys_inserted,
            1,
            parent_event,
        )?;
        let prospective_memory = self.logical_memory_with(
            self.counters.search.accepted_equality_nodes,
            self.counters.search.accepted_conflict_clauses,
            self.counters.search.proof_parent_references,
            self.counters.search.accepted_trace_literal_slots,
            prospective_keys,
            self.counters.search.peak_retained_antichain_entries,
            self.counters
                .search
                .registered_negative_equality_occurrences,
            parent_event,
        )?;
        if prospective_memory > Limits::LOGICAL_INCREMENTAL_MEMORY_BYTES {
            return Err(cap(
                CapReason::LogicalIncrementalMemoryBytes,
                boundary,
                self.counters.search.logical_incremental_memory_bytes,
                prospective_memory,
                Limits::LOGICAL_INCREMENTAL_MEMORY_BYTES,
            ));
        }

        self.inserted_event_keys
            .try_reserve(1)
            .map_err(|_| allocation(parent_event))?;
        self.worklist
            .try_reserve(1)
            .map_err(|_| allocation(parent_event))?;
        let set_key = try_clone_event_key(&key, parent_event)?;
        if !self.inserted_event_keys.insert(set_key) {
            return Err(internal(parent_event));
        }
        self.worklist.push(Reverse(QueuedEvent { key, pending }));
        self.counters.search.distinct_event_keys_inserted = prospective_keys;
        self.counters.search.worklist_pushes = prospective_pushes;
        self.counters.search.live_worklist_entries = prospective_live;
        self.counters.search.peak_live_worklist_entries = self
            .counters
            .search
            .peak_live_worklist_entries
            .max(prospective_live);
        self.counters.search.logical_incremental_memory_bytes = prospective_memory;
        Ok(())
    }

    fn accept_popped_event(
        &mut self,
        event_id: EventId,
        event: QueuedEvent,
    ) -> Result<bool, ReconstructionError> {
        match event.pending {
            PendingEvent::Equality {
                rule,
                mechanism_dependency,
            } => {
                self.accept_equality(event_id, event.key, rule, mechanism_dependency)?;
                Ok(false)
            }
            PendingEvent::Conflict {
                rule,
                mechanism_dependency,
            } => self.accept_conflict(event_id, event.key, rule, mechanism_dependency),
        }
    }

    fn accept_equality(
        &mut self,
        event_id: EventId,
        key: EventKey,
        rule: EqualityRuleRecord,
        mechanism_dependency: bool,
    ) -> Result<(), ReconstructionError> {
        let conclusion = key.conclusion.ok_or_else(|| internal(Some(event_id)))?;
        let mut retained = Vec::new();
        if let Some(existing) = self.retained_supports.get(&conclusion) {
            retained
                .try_reserve(existing.len())
                .map_err(|_| allocation(Some(event_id)))?;
            for &node in existing {
                if self
                    .nodes
                    .get(node.get() as usize)
                    .is_some_and(|node| node.active)
                {
                    self.node_side(node)?;
                    retained.push(node);
                }
            }
        }
        retained.sort_unstable_by(|left, right| {
            let left_clause = self.node_side(*left).unwrap_or(&[]);
            let right_clause = self.node_side(*right).unwrap_or(&[]);
            left_clause
                .len()
                .cmp(&right_clause.len())
                .then_with(|| left_clause.cmp(right_clause))
                .then_with(|| left.cmp(right))
        });

        let mut comparison_charge = 0u64;
        let mut existing_subset = false;
        let mut removed = Vec::new();
        removed
            .try_reserve(retained.len())
            .map_err(|_| allocation(Some(event_id)))?;
        for &retained_node in &retained {
            let retained_clause = self.node_side(retained_node)?;
            comparison_charge = checked_add(
                comparison_charge,
                checked_add(
                    to_u64(key.clause.len(), Some(event_id))?,
                    to_u64(retained_clause.len(), Some(event_id))?,
                    Some(event_id),
                )?,
                Some(event_id),
            )?;
            if sorted_subset(retained_clause, key.clause.as_slice()) {
                existing_subset = true;
            }
            if retained_clause.len() > key.clause.len()
                && sorted_subset(key.clause.as_slice(), retained_clause)
            {
                removed.push(retained_node);
            }
        }

        let prospective_work = checked_add(
            self.counters.search.canonical_proof_work_literal_charge,
            comparison_charge,
            Some(event_id),
        )?;
        let boundary = CapBoundary::PoppedEventAcceptance(event_id);
        if existing_subset {
            if prospective_work > Limits::CANONICAL_PROOF_WORK_LITERAL_CHARGE {
                return Err(cap(
                    CapReason::CanonicalProofWorkLiteralCharge,
                    boundary,
                    self.counters.search.canonical_proof_work_literal_charge,
                    prospective_work,
                    Limits::CANONICAL_PROOF_WORK_LITERAL_CHARGE,
                ));
            }
            self.counters.search.canonical_proof_work_literal_charge = prospective_work;
            self.counters.pruning.support_subset_discards = checked_add(
                self.counters.pruning.support_subset_discards,
                1,
                Some(event_id),
            )?;
            return Ok(());
        }
        let retained_after_removal = retained
            .len()
            .checked_sub(removed.len())
            .ok_or_else(|| internal(Some(event_id)))?;
        if to_u64(retained_after_removal, Some(event_id))?
            >= Limits::RETAINED_SIDE_CLAUSES_PER_EQUALITY
        {
            if prospective_work > Limits::CANONICAL_PROOF_WORK_LITERAL_CHARGE {
                return Err(cap(
                    CapReason::CanonicalProofWorkLiteralCharge,
                    boundary,
                    self.counters.search.canonical_proof_work_literal_charge,
                    prospective_work,
                    Limits::CANONICAL_PROOF_WORK_LITERAL_CHARGE,
                ));
            }
            self.counters.search.canonical_proof_work_literal_charge = prospective_work;
            self.counters.pruning.support_capacity_discards = checked_add(
                self.counters.pruning.support_capacity_discards,
                1,
                Some(event_id),
            )?;
            return Ok(());
        }

        let parent_references = equality_parent_references(&rule, Some(event_id))?;
        let prospective_nodes = checked_add(
            self.counters.search.accepted_equality_nodes,
            1,
            Some(event_id),
        )?;
        if prospective_nodes > Limits::EQUALITY_PROOF_NODES {
            return Err(cap(
                CapReason::EqualityProofNodes,
                boundary,
                self.counters.search.accepted_equality_nodes,
                prospective_nodes,
                Limits::EQUALITY_PROOF_NODES,
            ));
        }
        let prospective_parents = checked_add(
            self.counters.search.proof_parent_references,
            parent_references,
            Some(event_id),
        )?;
        if prospective_parents > Limits::PROOF_PARENT_REFERENCES {
            return Err(cap(
                CapReason::ProofParentReferences,
                boundary,
                self.counters.search.proof_parent_references,
                prospective_parents,
                Limits::PROOF_PARENT_REFERENCES,
            ));
        }
        let prospective_depth = self
            .counters
            .search
            .maximum_proof_depth
            .max(u64::from(key.proof_depth.get()));
        if prospective_depth > Limits::PROOF_DEPTH {
            return Err(cap(
                CapReason::ProofDepth,
                boundary,
                self.counters.search.maximum_proof_depth,
                prospective_depth,
                Limits::PROOF_DEPTH,
            ));
        }
        if prospective_work > Limits::CANONICAL_PROOF_WORK_LITERAL_CHARGE {
            return Err(cap(
                CapReason::CanonicalProofWorkLiteralCharge,
                boundary,
                self.counters.search.canonical_proof_work_literal_charge,
                prospective_work,
                Limits::CANONICAL_PROOF_WORK_LITERAL_CHARGE,
            ));
        }
        let prospective_slots = checked_add(
            self.counters.search.accepted_trace_literal_slots,
            to_u64(key.clause.len(), Some(event_id))?,
            Some(event_id),
        )?;
        if prospective_slots > Limits::ALL_DERIVED_LITERAL_SLOTS {
            return Err(cap(
                CapReason::AllDerivedLiteralSlots,
                boundary,
                self.counters.search.accepted_trace_literal_slots,
                prospective_slots,
                Limits::ALL_DERIVED_LITERAL_SLOTS,
            ));
        }
        let prospective_retained = checked_add(
            self.counters
                .search
                .retained_antichain_entries
                .checked_sub(to_u64(removed.len(), Some(event_id))?)
                .ok_or_else(|| internal(Some(event_id)))?,
            1,
            Some(event_id),
        )?;
        let prospective_peak_retained = self
            .counters
            .search
            .peak_retained_antichain_entries
            .max(prospective_retained);
        let prospective_memory = self.logical_memory_with(
            prospective_nodes,
            self.counters.search.accepted_conflict_clauses,
            prospective_parents,
            prospective_slots,
            self.counters.search.distinct_event_keys_inserted,
            prospective_peak_retained,
            self.counters
                .search
                .registered_negative_equality_occurrences,
            Some(event_id),
        )?;
        if prospective_memory > Limits::LOGICAL_INCREMENTAL_MEMORY_BYTES {
            return Err(cap(
                CapReason::LogicalIncrementalMemoryBytes,
                boundary,
                self.counters.search.logical_incremental_memory_bytes,
                prospective_memory,
                Limits::LOGICAL_INCREMENTAL_MEMORY_BYTES,
            ));
        }

        self.reserve_equality_acceptance(conclusion, Some(event_id))?;
        let node_id = NodeId::new(to_u32(self.nodes.len(), Some(event_id))?);
        for removed_node in &removed {
            self.nodes
                .get_mut(removed_node.get() as usize)
                .ok_or_else(|| internal(Some(event_id)))?
                .active = false;
        }
        let trace_index = self.trace.len();
        self.trace.push(TraceRecord::Equality(EqualityTraceRecord {
            event_id,
            node_id,
            depth: key.proof_depth,
            conclusion,
            side_clause: key.clause,
            rule,
        }));
        self.nodes.push(NodeMeta {
            trace_index,
            conclusion,
            depth: key.proof_depth,
            active: true,
            mechanism_dependency,
        });
        self.retained_supports
            .get_mut(&conclusion)
            .ok_or_else(|| internal(Some(event_id)))?
            .push(node_id);
        self.index_endpoint_node(node_id, conclusion, Some(event_id))?;

        self.counters.search.accepted_equality_nodes = prospective_nodes;
        self.counters.search.proof_parent_references = prospective_parents;
        self.counters.search.maximum_proof_depth = prospective_depth;
        self.counters.search.canonical_proof_work_literal_charge = prospective_work;
        self.counters.search.accepted_trace_literal_slots = prospective_slots;
        self.counters.search.retained_antichain_entries = prospective_retained;
        self.counters.search.peak_retained_antichain_entries = prospective_peak_retained;
        self.counters.search.logical_incremental_memory_bytes = prospective_memory;
        self.counters.pruning.support_removed_supersets = checked_add(
            self.counters.pruning.support_removed_supersets,
            to_u64(removed.len(), Some(event_id))?,
            Some(event_id),
        )?;
        increment_rule_counter(
            &mut self.counters.search.accepted_events,
            key.rule,
            Some(event_id),
        )?;

        self.generate_transitivity_children(node_id, event_id)?;
        self.generate_congruence_children(node_id, event_id)?;
        self.generate_conflict_children(node_id, event_id)
    }

    fn reserve_equality_acceptance(
        &mut self,
        conclusion: EqualityKey,
        event_id: Option<EventId>,
    ) -> Result<(), ReconstructionError> {
        self.trace
            .try_reserve(1)
            .map_err(|_| allocation(event_id))?;
        self.nodes
            .try_reserve(1)
            .map_err(|_| allocation(event_id))?;
        ensure_vec_map_entry(&mut self.retained_supports, conclusion, event_id)?;
        self.retained_supports
            .get_mut(&conclusion)
            .ok_or_else(|| internal(event_id))?
            .try_reserve(1)
            .map_err(|_| allocation(event_id))?;
        let (left, right) = conclusion.endpoints();
        ensure_vec_map_entry(&mut self.endpoint_index, left, event_id)?;
        self.endpoint_index
            .get_mut(&left)
            .ok_or_else(|| internal(event_id))?
            .try_reserve(if left == right { 1 } else { 2 })
            .map_err(|_| allocation(event_id))?;
        if left != right {
            ensure_vec_map_entry(&mut self.endpoint_index, right, event_id)?;
            self.endpoint_index
                .get_mut(&right)
                .ok_or_else(|| internal(event_id))?
                .try_reserve(1)
                .map_err(|_| allocation(event_id))?;
        }
        Ok(())
    }

    fn index_endpoint_node(
        &mut self,
        node: NodeId,
        conclusion: EqualityKey,
        event_id: Option<EventId>,
    ) -> Result<(), ReconstructionError> {
        let (left, right) = conclusion.endpoints();
        self.endpoint_index
            .get_mut(&left)
            .ok_or_else(|| internal(event_id))?
            .push(EndpointAssociation {
                node,
                other: right,
                orientation: 0,
            });
        if left != right {
            self.endpoint_index
                .get_mut(&right)
                .ok_or_else(|| internal(event_id))?
                .push(EndpointAssociation {
                    node,
                    other: left,
                    orientation: 1,
                });
        }
        Ok(())
    }

    fn accept_conflict(
        &mut self,
        event_id: EventId,
        key: EventKey,
        rule: ConflictRecord,
        mechanism_dependency: bool,
    ) -> Result<bool, ReconstructionError> {
        if key.conclusion.is_some() {
            return Err(internal(Some(event_id)));
        }
        if self.global_clauses.contains(&key.clause) {
            self.counters.pruning.duplicate_derived_clauses = checked_add(
                self.counters.pruning.duplicate_derived_clauses,
                1,
                Some(event_id),
            )?;
            return Ok(false);
        }

        let boundary = CapBoundary::PoppedEventAcceptance(event_id);
        let is_empty = key.clause.is_empty();
        let prospective_parents = checked_add(
            self.counters.search.proof_parent_references,
            1,
            Some(event_id),
        )?;
        if prospective_parents > Limits::PROOF_PARENT_REFERENCES {
            return Err(cap(
                CapReason::ProofParentReferences,
                boundary,
                self.counters.search.proof_parent_references,
                prospective_parents,
                Limits::PROOF_PARENT_REFERENCES,
            ));
        }
        let prospective_depth = self
            .counters
            .search
            .maximum_proof_depth
            .max(u64::from(key.proof_depth.get()));
        if prospective_depth > Limits::PROOF_DEPTH {
            return Err(cap(
                CapReason::ProofDepth,
                boundary,
                self.counters.search.maximum_proof_depth,
                prospective_depth,
                Limits::PROOF_DEPTH,
            ));
        }
        let prospective_clauses = checked_add(
            self.counters.search.accepted_conflict_clauses,
            1,
            Some(event_id),
        )?;
        if prospective_clauses > Limits::UNIQUE_DERIVED_CLAUSES {
            return Err(cap(
                CapReason::UniqueDerivedClauses,
                boundary,
                self.counters.search.accepted_conflict_clauses,
                prospective_clauses,
                Limits::UNIQUE_DERIVED_CLAUSES,
            ));
        }
        let index_charge = if is_empty {
            0
        } else {
            to_u64(key.clause.len(), Some(event_id))?
        };
        let prospective_work = checked_add(
            self.counters.search.canonical_proof_work_literal_charge,
            index_charge,
            Some(event_id),
        )?;
        if prospective_work > Limits::CANONICAL_PROOF_WORK_LITERAL_CHARGE {
            return Err(cap(
                CapReason::CanonicalProofWorkLiteralCharge,
                boundary,
                self.counters.search.canonical_proof_work_literal_charge,
                prospective_work,
                Limits::CANONICAL_PROOF_WORK_LITERAL_CHARGE,
            ));
        }
        let prospective_slots = checked_add(
            self.counters.search.accepted_trace_literal_slots,
            to_u64(key.clause.len(), Some(event_id))?,
            Some(event_id),
        )?;
        if prospective_slots > Limits::ALL_DERIVED_LITERAL_SLOTS {
            return Err(cap(
                CapReason::AllDerivedLiteralSlots,
                boundary,
                self.counters.search.accepted_trace_literal_slots,
                prospective_slots,
                Limits::ALL_DERIVED_LITERAL_SLOTS,
            ));
        }
        let prospective_memory = self.logical_memory_with(
            self.counters.search.accepted_equality_nodes,
            prospective_clauses,
            prospective_parents,
            prospective_slots,
            self.counters.search.distinct_event_keys_inserted,
            self.counters.search.peak_retained_antichain_entries,
            self.counters
                .search
                .registered_negative_equality_occurrences,
            Some(event_id),
        )?;
        if prospective_memory > Limits::LOGICAL_INCREMENTAL_MEMORY_BYTES {
            return Err(cap(
                CapReason::LogicalIncrementalMemoryBytes,
                boundary,
                self.counters.search.logical_incremental_memory_bytes,
                prospective_memory,
                Limits::LOGICAL_INCREMENTAL_MEMORY_BYTES,
            ));
        }

        self.trace
            .try_reserve(1)
            .map_err(|_| allocation(Some(event_id)))?;
        self.derived_clauses
            .try_reserve(1)
            .map_err(|_| allocation(Some(event_id)))?;
        self.global_clauses
            .try_reserve(1)
            .map_err(|_| allocation(Some(event_id)))?;
        let clause_number = self
            .input
            .baseline_clauses
            .len()
            .checked_add(self.derived_clauses.len())
            .ok_or_else(|| arithmetic(Some(event_id)))?;
        let clause_id = ClauseId::new(to_u32(clause_number, Some(event_id))?);
        let set_clause = try_clone_clause(&key.clause, Some(event_id))?;
        let trace_index = self.trace.len();
        self.trace.push(TraceRecord::Conflict(ConflictTraceRecord {
            event_id,
            clause_id,
            depth: key.proof_depth,
            clause: key.clause,
            rule,
        }));
        self.derived_clauses.push(DerivedClauseMeta {
            trace_index,
            id: clause_id,
            depth: key.proof_depth,
            mechanism_dependency,
        });
        if !self.global_clauses.insert(set_clause) {
            return Err(internal(Some(event_id)));
        }
        self.counters.search.accepted_conflict_clauses = prospective_clauses;
        self.counters.search.proof_parent_references = prospective_parents;
        self.counters.search.maximum_proof_depth = prospective_depth;
        self.counters.search.canonical_proof_work_literal_charge = prospective_work;
        self.counters.search.accepted_trace_literal_slots = prospective_slots;
        self.counters.search.logical_incremental_memory_bytes = prospective_memory;
        increment_rule_counter(
            &mut self.counters.search.accepted_events,
            RuleKind::Conflict,
            Some(event_id),
        )?;

        if is_empty {
            let discarded = self.counters.search.live_worklist_entries;
            self.counters.search.queued_events_discarded_at_theory_empty = checked_add(
                self.counters.search.queued_events_discarded_at_theory_empty,
                discarded,
                Some(event_id),
            )?;
            self.counters.search.live_worklist_entries = 0;
            self.worklist.clear();
            self.terminal_empty = Some(TerminalEmpty {
                event_id,
                clause_id,
                mechanism_dependency,
            });
            return Ok(true);
        }
        self.index_derived_clause(clause_id, event_id)?;
        Ok(false)
    }

    fn index_derived_clause(
        &mut self,
        clause_id: ClauseId,
        parent_event: EventId,
    ) -> Result<(), ReconstructionError> {
        let source = ClauseRef {
            id: clause_id,
            origin: ClauseOrigin::Derived,
        };
        let mut negatives = Vec::new();
        let mut positives = Vec::new();
        {
            let clause = self.clause_slice(source)?;
            negatives
                .try_reserve(clause.len())
                .map_err(|_| allocation(Some(parent_event)))?;
            positives
                .try_reserve(clause.len())
                .map_err(|_| allocation(Some(parent_event)))?;
            for (offset, &literal) in clause.iter().enumerate() {
                let Some((positive, equality)) = self.equality_literal(literal) else {
                    continue;
                };
                let pivot = ClausePivot {
                    clause: source,
                    literal_offset: LiteralOffset::new(to_u32(offset, Some(parent_event))?),
                };
                if positive {
                    positives.push(pivot);
                } else {
                    negatives.push((equality, pivot));
                }
            }
        }
        for (equality, pivot) in negatives {
            self.register_negative(equality, pivot, Some(parent_event))?;
        }
        for pivot in positives {
            self.attempt_seed(pivot, Some(parent_event))?;
        }
        Ok(())
    }

    fn register_negative(
        &mut self,
        equality: EqualityKey,
        source: ClausePivot,
        parent_event: Option<EventId>,
    ) -> Result<(), ReconstructionError> {
        let prospective_occurrences = checked_add(
            self.counters
                .search
                .registered_negative_equality_occurrences,
            1,
            parent_event,
        )?;
        let prospective_memory = self.logical_memory_with(
            self.counters.search.accepted_equality_nodes,
            self.counters.search.accepted_conflict_clauses,
            self.counters.search.proof_parent_references,
            self.counters.search.accepted_trace_literal_slots,
            self.counters.search.distinct_event_keys_inserted,
            self.counters.search.peak_retained_antichain_entries,
            prospective_occurrences,
            parent_event,
        )?;
        if prospective_memory > Limits::LOGICAL_INCREMENTAL_MEMORY_BYTES {
            return Err(cap(
                CapReason::LogicalIncrementalMemoryBytes,
                CapBoundary::NegativeRegistration(source),
                self.counters.search.logical_incremental_memory_bytes,
                prospective_memory,
                Limits::LOGICAL_INCREMENTAL_MEMORY_BYTES,
            ));
        }
        ensure_vec_map_entry(&mut self.negative_index, equality, parent_event)?;
        self.negative_index
            .get_mut(&equality)
            .ok_or_else(|| internal(parent_event))?
            .try_reserve(1)
            .map_err(|_| allocation(parent_event))?;
        self.negative_index
            .get_mut(&equality)
            .ok_or_else(|| internal(parent_event))?
            .push(NegativeOccurrence { source });
        self.counters
            .search
            .registered_negative_equality_occurrences = prospective_occurrences;
        self.counters.search.logical_incremental_memory_bytes = prospective_memory;

        let active_nodes = self.active_nodes_for(equality, parent_event)?;
        for node in active_nodes {
            self.attempt_conflict(node, source, parent_event)?;
        }
        Ok(())
    }

    fn active_nodes_for(
        &self,
        equality: EqualityKey,
        event_id: Option<EventId>,
    ) -> Result<Vec<NodeId>, ReconstructionError> {
        let mut nodes = Vec::new();
        if let Some(retained) = self.retained_supports.get(&equality) {
            nodes
                .try_reserve(retained.len())
                .map_err(|_| allocation(event_id))?;
            for &node in retained {
                if self
                    .nodes
                    .get(node.get() as usize)
                    .is_some_and(|node| node.active)
                {
                    nodes.push(node);
                }
            }
        }
        nodes.sort_unstable();
        Ok(nodes)
    }

    fn generate_transitivity_children(
        &mut self,
        new_node: NodeId,
        parent_event: EventId,
    ) -> Result<(), ReconstructionError> {
        let conclusion = self
            .nodes
            .get(new_node.get() as usize)
            .ok_or_else(|| internal(Some(parent_event)))?
            .conclusion;
        let (left, right) = conclusion.endpoints();
        let endpoints: &[TermId] = if left == right {
            std::slice::from_ref(&left)
        } else {
            &[left, right]
        };
        let mut joins = Vec::new();
        for &intermediate in endpoints {
            let new_other = if intermediate == left { right } else { left };
            let Some(associations) = self.endpoint_index.get(&intermediate) else {
                continue;
            };
            joins
                .try_reserve(associations.len())
                .map_err(|_| allocation(Some(parent_event)))?;
            for association in associations {
                let other_meta = self
                    .nodes
                    .get(association.node.get() as usize)
                    .ok_or_else(|| internal(Some(parent_event)))?;
                if !other_meta.active {
                    continue;
                }
                joins.push((
                    other_meta.conclusion,
                    association.node,
                    association.orientation,
                    intermediate,
                    new_other,
                    association.other,
                ));
            }
        }
        joins.sort_unstable_by(|first, second| {
            first
                .0
                .cmp(&second.0)
                .then_with(|| first.1.cmp(&second.1))
                .then_with(|| first.2.cmp(&second.2))
                .then_with(|| first.3.cmp(&second.3))
        });
        for (_, other_node, _, intermediate, new_other, other) in joins {
            let mut parents = [new_node, other_node];
            parents.sort_unstable();
            let join_key = TransitivityJoinKey {
                parents,
                intermediate,
            };
            if self.transitivity_joins.contains(&join_key) {
                continue;
            }
            self.transitivity_joins
                .try_reserve(1)
                .map_err(|_| allocation(Some(parent_event)))?;
            if !self.transitivity_joins.insert(join_key) {
                return Err(internal(Some(parent_event)));
            }
            self.attempt_transitivity(
                new_node,
                other_node,
                intermediate,
                new_other,
                other,
                parent_event,
            )?;
        }
        Ok(())
    }

    fn generate_congruence_children(
        &mut self,
        new_node: NodeId,
        parent_event: EventId,
    ) -> Result<(), ReconstructionError> {
        let conclusion = self
            .nodes
            .get(new_node.get() as usize)
            .ok_or_else(|| internal(Some(parent_event)))?
            .conclusion;
        let entry_count = self
            .application_argument_index
            .get(&conclusion)
            .map_or(0, Vec::len);
        let mut previous_pair = None;
        for entry_position in 0..entry_count {
            let pair_index = self
                .application_argument_index
                .get(&conclusion)
                .and_then(|entries| entries.get(entry_position))
                .map(|entry| entry.pair_index)
                .ok_or_else(|| internal(Some(parent_event)))?;
            if previous_pair == Some(pair_index) {
                continue;
            }
            previous_pair = Some(pair_index);

            // The ablation decision precedes every tuple-sized allocation and
            // every attempted-event or tuple-set mutation.
            let directly_missing = self.classify_missing_congruence(pair_index, parent_event)?;
            if directly_missing
                && self.variant == CompilerVariant::SuppressMissingEqualityCongruence
            {
                let suppressed =
                    self.count_congruence_tuples_containing(pair_index, new_node, parent_event)?;
                self.counters
                    .search
                    .suppressed_missing_equality_congruence_events = checked_add(
                    self.counters
                        .search
                        .suppressed_missing_equality_congruence_events,
                    suppressed,
                    Some(parent_event),
                )?;
                continue;
            }

            let requirement_count = self
                .application_pairs
                .get(pair_index)
                .map(|pair| pair.requirements.len())
                .ok_or_else(|| internal(Some(parent_event)))?;
            let mut choices = Vec::new();
            choices
                .try_reserve_exact(requirement_count)
                .map_err(|_| allocation(Some(parent_event)))?;
            let mut complete = true;
            for requirement_position in 0..requirement_count {
                let equality = self
                    .application_pairs
                    .get(pair_index)
                    .and_then(|pair| pair.requirements.get(requirement_position))
                    .map(|requirement| requirement.1)
                    .ok_or_else(|| internal(Some(parent_event)))?;
                let candidates = self.active_nodes_for(equality, Some(parent_event))?;
                if candidates.is_empty() {
                    complete = false;
                    break;
                }
                choices.push(candidates);
            }
            if !complete {
                continue;
            }
            let mut tuple = Vec::new();
            tuple
                .try_reserve(choices.len())
                .map_err(|_| allocation(Some(parent_event)))?;
            self.enumerate_congruence_tuples(
                pair_index,
                &choices,
                0,
                &mut tuple,
                new_node,
                directly_missing,
                parent_event,
            )?;
        }
        Ok(())
    }

    fn count_congruence_tuples_containing(
        &self,
        pair_index: usize,
        new_node: NodeId,
        parent_event: EventId,
    ) -> Result<u64, ReconstructionError> {
        let pair = self
            .application_pairs
            .get(pair_index)
            .ok_or_else(|| internal(Some(parent_event)))?;
        let new_conclusion = self
            .nodes
            .get(new_node.get() as usize)
            .filter(|node| node.active)
            .map(|node| node.conclusion)
            .ok_or_else(|| internal(Some(parent_event)))?;
        let mut all_tuples = 1u64;
        let mut tuples_without_new = 1u64;
        for &(_, requirement) in &pair.requirements {
            let mut active = 0u64;
            let mut contains_new = false;
            if let Some(nodes) = self.retained_supports.get(&requirement) {
                for &node_id in nodes {
                    if self
                        .nodes
                        .get(node_id.get() as usize)
                        .is_some_and(|node| node.active)
                    {
                        active = checked_add(active, 1, Some(parent_event))?;
                        contains_new |= node_id == new_node;
                    }
                }
            }
            if active == 0 {
                return Ok(0);
            }
            if contains_new != (requirement == new_conclusion) {
                return Err(internal(Some(parent_event)));
            }
            all_tuples = checked_mul(all_tuples, active, Some(parent_event))?;
            let without_new = active
                .checked_sub(u64::from(contains_new))
                .ok_or_else(|| internal(Some(parent_event)))?;
            tuples_without_new = checked_mul(tuples_without_new, without_new, Some(parent_event))?;
        }
        all_tuples
            .checked_sub(tuples_without_new)
            .ok_or_else(|| internal(Some(parent_event)))
    }

    #[allow(clippy::too_many_arguments)]
    fn enumerate_congruence_tuples(
        &mut self,
        pair_index: usize,
        choices: &[Vec<NodeId>],
        position: usize,
        tuple: &mut Vec<NodeId>,
        new_node: NodeId,
        directly_missing: bool,
        parent_event: EventId,
    ) -> Result<(), ReconstructionError> {
        if position == choices.len() {
            if !tuple.contains(&new_node) {
                return Ok(());
            }
            let mut tuple_parents = Vec::new();
            tuple_parents
                .try_reserve_exact(tuple.len())
                .map_err(|_| allocation(Some(parent_event)))?;
            tuple_parents.extend_from_slice(tuple);
            let tuple_key = CongruenceTupleKey {
                pair_index,
                parents: tuple_parents.into_boxed_slice(),
            };
            if self.congruence_tuples.contains(&tuple_key) {
                return Ok(());
            }
            self.congruence_tuples
                .try_reserve(1)
                .map_err(|_| allocation(Some(parent_event)))?;
            if !self.congruence_tuples.insert(tuple_key) {
                return Err(internal(Some(parent_event)));
            }
            return self.attempt_congruence(pair_index, tuple, directly_missing, parent_event);
        }
        for &parent in &choices[position] {
            tuple.push(parent);
            self.enumerate_congruence_tuples(
                pair_index,
                choices,
                position + 1,
                tuple,
                new_node,
                directly_missing,
                parent_event,
            )?;
            tuple.pop();
        }
        Ok(())
    }

    fn generate_conflict_children(
        &mut self,
        new_node: NodeId,
        parent_event: EventId,
    ) -> Result<(), ReconstructionError> {
        let conclusion = self
            .nodes
            .get(new_node.get() as usize)
            .ok_or_else(|| internal(Some(parent_event)))?
            .conclusion;
        let mut occurrences = Vec::new();
        if let Some(existing) = self.negative_index.get(&conclusion) {
            occurrences
                .try_reserve_exact(existing.len())
                .map_err(|_| allocation(Some(parent_event)))?;
            occurrences.extend_from_slice(existing);
        }
        for occurrence in occurrences {
            self.attempt_conflict(new_node, occurrence.source, Some(parent_event))?;
        }
        Ok(())
    }

    fn baseline_has_equality(&self, equality: EqualityKey) -> bool {
        self.input
            .atom_variables
            .contains_key(&BoolAtomKey::Eq(equality.left(), equality.right()))
    }

    #[allow(clippy::too_many_arguments)]
    fn logical_memory_with(
        &self,
        nodes: u64,
        conflicts: u64,
        parents: u64,
        slots: u64,
        event_keys: u64,
        retained_peak: u64,
        negative_occurrences: u64,
        event_id: Option<EventId>,
    ) -> Result<u64, ReconstructionError> {
        logical_memory(
            nodes,
            conflicts,
            parents,
            slots,
            event_keys,
            retained_peak,
            negative_occurrences,
            self.counters.input.application_pairs,
            self.counters.input.application_argument_slots,
            event_id,
        )
    }

    fn final_output(&mut self) -> Result<EqresOutput, ReconstructionError> {
        if let Some(terminal) = self.terminal_empty.take() {
            self.check_final_limits(1, 0, 0, 0)?;
            self.counters.output.emitted_lemmas = 1;
            self.counters.output.emitted_literal_slots = 0;
            self.counters.output.emitted_p95_width = 0;
            self.counters.output.emitted_maximum_width = 0;
            self.counters
                .output
                .emitted_with_missing_equality_congruence =
                u64::from(terminal.mechanism_dependency);
            return Ok(EqresOutput::TheoryEmpty {
                terminal_event_id: terminal.event_id,
                lemma: EmittedLemma {
                    source_clause_id: terminal.clause_id,
                    clause: CanonicalClause::empty(),
                },
            });
        }

        let mut candidates = Vec::new();
        candidates
            .try_reserve(self.derived_clauses.len())
            .map_err(|_| allocation(None))?;
        for meta in &self.derived_clauses {
            let Some(TraceRecord::Conflict(record)) = self.trace.get(meta.trace_index) else {
                return Err(internal(None));
            };
            if record.clause.is_empty() {
                return Err(internal(None));
            }
            candidates.push(OutputCandidate {
                source_clause_id: meta.id,
                clause: try_clone_clause(&record.clause, None)?,
                mechanism_dependency: meta.mechanism_dependency,
            });
        }
        candidates.sort_unstable_by(|left, right| {
            left.clause
                .len()
                .cmp(&right.clause.len())
                .then_with(|| left.clause.cmp(&right.clause))
        });

        let mut retained: Vec<OutputCandidate> = Vec::new();
        retained
            .try_reserve(candidates.len())
            .map_err(|_| allocation(None))?;
        for candidate in candidates {
            if self
                .base_canonical_clauses
                .iter()
                .any(|base| sorted_subset(base.as_slice(), candidate.clause.as_slice()))
            {
                self.counters.pruning.final_base_subsumption_discards = checked_add(
                    self.counters.pruning.final_base_subsumption_discards,
                    1,
                    None,
                )?;
                continue;
            }
            if retained.iter().any(|earlier| {
                sorted_subset(earlier.clause.as_slice(), candidate.clause.as_slice())
            }) {
                self.counters.pruning.final_output_subsumption_discards = checked_add(
                    self.counters.pruning.final_output_subsumption_discards,
                    1,
                    None,
                )?;
                continue;
            }
            retained.push(candidate);
        }

        let emitted = to_u64(retained.len(), None)?;
        let mut slots = 0u64;
        let mut widths = Vec::new();
        widths
            .try_reserve(retained.len())
            .map_err(|_| allocation(None))?;
        let mut mechanism_count = 0u64;
        for candidate in &retained {
            let width = to_u64(candidate.clause.len(), None)?;
            slots = checked_add(slots, width, None)?;
            widths.push(width);
            mechanism_count = checked_add(
                mechanism_count,
                u64::from(candidate.mechanism_dependency),
                None,
            )?;
        }
        let (p95, maximum) = if widths.is_empty() {
            (0, 0)
        } else {
            widths.sort_unstable();
            let numerator = checked_add(checked_mul(95, emitted, None)?, 99, None)?;
            let rank = numerator / 100;
            let index = usize::try_from(rank.checked_sub(1).ok_or_else(|| arithmetic(None))?)
                .map_err(|_| arithmetic(None))?;
            (
                *widths.get(index).ok_or_else(|| internal(None))?,
                *widths.last().ok_or_else(|| internal(None))?,
            )
        };
        self.check_final_limits(emitted, slots, p95, maximum)?;
        self.counters.output.emitted_lemmas = emitted;
        self.counters.output.emitted_literal_slots = slots;
        self.counters.output.emitted_p95_width = p95;
        self.counters.output.emitted_maximum_width = maximum;
        self.counters
            .output
            .emitted_with_missing_equality_congruence = mechanism_count;

        if retained.is_empty() {
            return Ok(EqresOutput::NoLemmas);
        }
        let mut lemmas = Vec::new();
        lemmas
            .try_reserve(retained.len())
            .map_err(|_| allocation(None))?;
        for candidate in retained {
            lemmas.push(EmittedLemma {
                source_clause_id: candidate.source_clause_id,
                clause: candidate.clause,
            });
        }
        Ok(EqresOutput::Lemmas(lemmas.into_boxed_slice()))
    }

    fn check_final_limits(
        &self,
        emitted: u64,
        slots: u64,
        p95: u64,
        maximum: u64,
    ) -> Result<(), ReconstructionError> {
        let boundary = CapBoundary::FinalOutput;
        if emitted > Limits::EMITTED_LEMMAS {
            return Err(cap(
                CapReason::EmittedLemmas,
                boundary,
                0,
                emitted,
                Limits::EMITTED_LEMMAS,
            ));
        }
        if slots > Limits::EMITTED_LEMMA_LITERAL_SLOTS {
            return Err(cap(
                CapReason::EmittedLemmaLiteralSlots,
                boundary,
                0,
                slots,
                Limits::EMITTED_LEMMA_LITERAL_SLOTS,
            ));
        }
        if p95 > Limits::EMITTED_P95_WIDTH {
            return Err(cap(
                CapReason::EmittedP95Width,
                boundary,
                0,
                p95,
                Limits::EMITTED_P95_WIDTH,
            ));
        }
        if maximum > Limits::EMITTED_MAXIMUM_WIDTH {
            return Err(cap(
                CapReason::EmittedMaximumWidth,
                boundary,
                0,
                maximum,
                Limits::EMITTED_MAXIMUM_WIDTH,
            ));
        }
        Ok(())
    }
}

fn contains_endpoint(equality: EqualityKey, term: TermId) -> bool {
    equality.left() == term || equality.right() == term
}

fn normalized_equality(left: TermId, right: TermId) -> Result<EqualityKey, ReconstructionError> {
    let (left, right) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    EqualityKey::from_normalized(left, right).ok_or_else(|| internal(None))
}

fn try_clone_clause(
    clause: &CanonicalClause,
    event_id: Option<EventId>,
) -> Result<CanonicalClause, ReconstructionError> {
    let mut literals = Vec::new();
    literals
        .try_reserve_exact(clause.len())
        .map_err(|_| allocation(event_id))?;
    literals.extend_from_slice(clause.as_slice());
    CanonicalClause::from_sorted(literals).map_err(|_| internal(event_id))
}

fn try_clone_event_key(
    key: &EventKey,
    event_id: Option<EventId>,
) -> Result<EventKey, ReconstructionError> {
    let mut parents = Vec::new();
    parents
        .try_reserve_exact(key.parents.len())
        .map_err(|_| allocation(event_id))?;
    parents.extend_from_slice(&key.parents);
    Ok(EventKey {
        resulting_clause_width: key.resulting_clause_width,
        proof_depth: key.proof_depth,
        rule: key.rule,
        conclusion: key.conclusion,
        clause: try_clone_clause(&key.clause, event_id)?,
        source: key.source,
        parents: parents.into_boxed_slice(),
    })
}

fn canonicalize_one(
    literals: &[i32],
    event_id: Option<EventId>,
) -> Result<Option<CanonicalClause>, ReconstructionError> {
    canonicalize_parts(&[literals], event_id)
}

fn canonicalize_two(
    first: &[i32],
    second: &[i32],
    event_id: Option<EventId>,
) -> Result<Option<CanonicalClause>, ReconstructionError> {
    canonicalize_parts(&[first, second], event_id)
}

fn canonicalize_without(
    literals: &[i32],
    removed_offset: usize,
    event_id: Option<EventId>,
) -> Result<Option<CanonicalClause>, ReconstructionError> {
    if removed_offset >= literals.len() {
        return Err(internal(event_id));
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(literals.len().saturating_sub(1))
        .map_err(|_| allocation(event_id))?;
    result.extend_from_slice(&literals[..removed_offset]);
    result.extend_from_slice(&literals[(removed_offset + 1)..]);
    finish_canonicalization(result, event_id)
}

fn canonicalize_parts(
    parts: &[&[i32]],
    event_id: Option<EventId>,
) -> Result<Option<CanonicalClause>, ReconstructionError> {
    let mut length = 0usize;
    for part in parts {
        length = length
            .checked_add(part.len())
            .ok_or_else(|| arithmetic(event_id))?;
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(length)
        .map_err(|_| allocation(event_id))?;
    for part in parts {
        result.extend_from_slice(part);
    }
    finish_canonicalization(result, event_id)
}

fn canonicalize_node_union(
    auditor: &Auditor<'_>,
    parents: &[NodeId],
    event_id: Option<EventId>,
) -> Result<Option<CanonicalClause>, ReconstructionError> {
    let mut length = 0usize;
    for &parent in parents {
        length = length
            .checked_add(auditor.node_side(parent)?.len())
            .ok_or_else(|| arithmetic(event_id))?;
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(length)
        .map_err(|_| allocation(event_id))?;
    for &parent in parents {
        result.extend_from_slice(auditor.node_side(parent)?);
    }
    finish_canonicalization(result, event_id)
}

fn finish_canonicalization(
    mut literals: Vec<i32>,
    event_id: Option<EventId>,
) -> Result<Option<CanonicalClause>, ReconstructionError> {
    literals.sort_unstable();
    literals.dedup();
    for &literal in &literals {
        let complement = literal.checked_neg().ok_or_else(|| internal(event_id))?;
        if literals.binary_search(&complement).is_ok() {
            return Ok(None);
        }
    }
    CanonicalClause::from_sorted(literals)
        .map(Some)
        .map_err(|_| internal(event_id))
}

fn sorted_subset(subset: &[i32], superset: &[i32]) -> bool {
    let mut left = 0usize;
    let mut right = 0usize;
    while left < subset.len() && right < superset.len() {
        match subset[left].cmp(&superset[right]) {
            Ordering::Less => return false,
            Ordering::Equal => {
                left += 1;
                right += 1;
            }
            Ordering::Greater => right += 1,
        }
    }
    left == subset.len()
}

fn equality_parent_references(
    rule: &EqualityRuleRecord,
    event_id: Option<EventId>,
) -> Result<u64, ReconstructionError> {
    match rule {
        EqualityRuleRecord::Seed(_) | EqualityRuleRecord::Reflexivity(_) => Ok(0),
        EqualityRuleRecord::Transitivity(_) => Ok(2),
        EqualityRuleRecord::Congruence(record) => to_u64(record.arguments.len(), event_id),
    }
}

fn increment_rule_counter(
    counters: &mut RuleCounters,
    rule: RuleKind,
    event_id: Option<EventId>,
) -> Result<(), ReconstructionError> {
    let counter = match rule {
        RuleKind::Seed => &mut counters.seed,
        RuleKind::Reflexivity => &mut counters.reflexivity,
        RuleKind::Transitivity => &mut counters.transitivity,
        RuleKind::Congruence => &mut counters.congruence,
        RuleKind::Conflict => &mut counters.conflict,
    };
    *counter = checked_add(*counter, 1, event_id)?;
    Ok(())
}

fn ensure_vec_map_entry<K, V>(
    map: &mut FxHashMap<K, Vec<V>>,
    key: K,
    event_id: Option<EventId>,
) -> Result<(), ReconstructionError>
where
    K: Copy + Eq + std::hash::Hash,
{
    if !map.contains_key(&key) {
        map.try_reserve(1).map_err(|_| allocation(event_id))?;
        map.insert(key, Vec::new());
    }
    Ok(())
}

fn check_static_cap(reason: CapReason, value: u64, limit: u64) -> Result<(), ReconstructionError> {
    if value > limit {
        return Err(cap(reason, CapBoundary::StaticInput, 0, value, limit));
    }
    Ok(())
}

fn malformed(failure: InputFailure) -> ReconstructionError {
    ReconstructionError::Malformed(failure)
}

fn allocation(event_id: Option<EventId>) -> ReconstructionError {
    ReconstructionError::Allocation(event_id)
}

fn arithmetic(event_id: Option<EventId>) -> ReconstructionError {
    ReconstructionError::Arithmetic(event_id)
}

fn internal(event_id: Option<EventId>) -> ReconstructionError {
    ReconstructionError::Internal(event_id)
}

fn cap(
    reason: CapReason,
    boundary: CapBoundary,
    pre_event_value: u64,
    prospective_value: u64,
    limit: u64,
) -> ReconstructionError {
    ReconstructionError::Cap(CapAttempt {
        reason,
        boundary,
        pre_event_value,
        prospective_value,
        limit,
    })
}

fn checked_add(
    left: u64,
    right: u64,
    event_id: Option<EventId>,
) -> Result<u64, ReconstructionError> {
    left.checked_add(right).ok_or_else(|| arithmetic(event_id))
}

fn checked_mul(
    left: u64,
    right: u64,
    event_id: Option<EventId>,
) -> Result<u64, ReconstructionError> {
    left.checked_mul(right).ok_or_else(|| arithmetic(event_id))
}

fn to_u64(value: usize, event_id: Option<EventId>) -> Result<u64, ReconstructionError> {
    u64::try_from(value).map_err(|_| arithmetic(event_id))
}

fn to_u32<T>(value: T, event_id: Option<EventId>) -> Result<u32, ReconstructionError>
where
    T: TryInto<u32>,
{
    value.try_into().map_err(|_| arithmetic(event_id))
}

#[allow(clippy::too_many_arguments)]
fn logical_memory(
    nodes: u64,
    conflicts: u64,
    parents: u64,
    slots: u64,
    event_keys: u64,
    retained_peak: u64,
    negative_occurrences: u64,
    application_pairs: u64,
    application_argument_slots: u64,
    event_id: Option<EventId>,
) -> Result<u64, ReconstructionError> {
    let terms = [
        checked_mul(nodes, LogicalMemoryWeights::EQUALITY_NODE, event_id)?,
        checked_mul(conflicts, LogicalMemoryWeights::CONFLICT_CLAUSE, event_id)?,
        checked_mul(parents, LogicalMemoryWeights::PARENT_REFERENCE, event_id)?,
        checked_mul(slots, LogicalMemoryWeights::TRACE_LITERAL_SLOT, event_id)?,
        checked_mul(
            event_keys,
            LogicalMemoryWeights::DISTINCT_EVENT_KEY,
            event_id,
        )?,
        checked_mul(
            retained_peak,
            LogicalMemoryWeights::RETAINED_ANTICHAIN_ENTRY,
            event_id,
        )?,
        checked_mul(
            negative_occurrences,
            LogicalMemoryWeights::NEGATIVE_OCCURRENCE,
            event_id,
        )?,
        checked_mul(
            application_pairs,
            LogicalMemoryWeights::APPLICATION_PAIR,
            event_id,
        )?,
        checked_mul(
            application_argument_slots,
            LogicalMemoryWeights::APPLICATION_ARGUMENT_SLOT,
            event_id,
        )?,
    ];
    terms
        .into_iter()
        .try_fold(0u64, |sum, term| checked_add(sum, term, event_id))
}

#[derive(Clone)]
struct LocalSha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    byte_len: u64,
    valid: bool,
}

impl LocalSha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffered: 0,
            byte_len: 0,
            valid: true,
        }
    }

    fn update(&mut self, mut bytes: &[u8]) -> bool {
        let Ok(length) = u64::try_from(bytes.len()) else {
            self.valid = false;
            return false;
        };
        let Some(byte_len) = self.byte_len.checked_add(length) else {
            self.valid = false;
            return false;
        };
        self.byte_len = byte_len;
        if self.buffered != 0 {
            let copied = (64 - self.buffered).min(bytes.len());
            self.buffer[self.buffered..self.buffered + copied].copy_from_slice(&bytes[..copied]);
            self.buffered += copied;
            bytes = &bytes[copied..];
            if self.buffered < 64 {
                return self.valid;
            }
            let block = self.buffer;
            self.compress(&block);
            self.buffered = 0;
        }
        while bytes.len() >= 64 {
            let Some(block) = bytes.get(..64).and_then(|slice| slice.try_into().ok()) else {
                self.valid = false;
                return false;
            };
            self.compress(block);
            bytes = &bytes[64..];
        }
        self.buffer[..bytes.len()].copy_from_slice(bytes);
        self.buffered = bytes.len();
        self.valid
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut schedule = [0u32; 64];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            let mut word = [0u8; 4];
            word.copy_from_slice(chunk);
            schedule[index] = u32::from_be_bytes(word);
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..64 {
            let big_s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let first = h
                .wrapping_add(big_s1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(schedule[index]);
            let big_s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let second = big_s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(first);
            d = c;
            c = b;
            b = a;
            a = first.wrapping_add(second);
        }
        for (state, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *state = state.wrapping_add(value);
        }
    }

    fn finalize(mut self) -> Option<Sha256Digest> {
        if !self.valid {
            return None;
        }
        let bit_len = self.byte_len.checked_mul(8)?;
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > 56 {
            self.buffer[self.buffered..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0; 64];
            self.buffered = 0;
        }
        self.buffer[self.buffered..56].fill(0);
        self.buffer[56..].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut digest = [0u8; 32];
        for (chunk, word) in digest.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        Some(Sha256Digest::new(digest))
    }
}

struct Encoder {
    hash: LocalSha256,
    valid: bool,
}

impl Encoder {
    fn new() -> Self {
        Self {
            hash: LocalSha256::new(),
            valid: true,
        }
    }

    fn raw(&mut self, bytes: &[u8]) -> bool {
        self.valid &= self.hash.update(bytes);
        self.valid
    }

    fn u8(&mut self, value: u8) -> bool {
        self.raw(&[value])
    }

    fn u32(&mut self, value: u32) -> bool {
        self.raw(&value.to_be_bytes())
    }

    fn i32(&mut self, value: i32) -> bool {
        self.raw(&value.to_be_bytes())
    }

    fn u64(&mut self, value: u64) -> bool {
        self.raw(&value.to_be_bytes())
    }

    fn usize(&mut self, value: usize) -> bool {
        match u64::try_from(value) {
            Ok(value) => self.u64(value),
            Err(_) => {
                self.valid = false;
                false
            }
        }
    }

    fn finish(self) -> Option<Sha256Digest> {
        self.valid.then_some(self.hash)?.finalize()
    }
}

fn digest_raw(bytes: &[u8]) -> Option<Sha256Digest> {
    let mut encoder = Encoder::new();
    encoder.raw(bytes);
    encoder.finish()
}

fn digest_with(encode: impl FnOnce(&mut Encoder) -> bool) -> Option<Sha256Digest> {
    let mut encoder = Encoder::new();
    if !encode(&mut encoder) {
        encoder.valid = false;
    }
    encoder.finish()
}

fn encode_atom(encoder: &mut Encoder, atom: &BoolAtomKey) -> bool {
    match atom {
        BoolAtomKey::Eq(left, right) => {
            encoder.u8(1) && encoder.usize(*left) && encoder.usize(*right)
        }
        BoolAtomKey::BoolTerm(term) => encoder.u8(2) && encoder.usize(*term),
    }
}

fn encode_atom_map_payload(encoder: &mut Encoder, input: EqresInput<'_>) -> bool {
    if !encoder.usize(input.variable_atoms.len()) {
        return false;
    }
    for atom in input.variable_atoms {
        match atom {
            None => {
                if !encoder.u8(0) {
                    return false;
                }
            }
            Some(atom) => {
                if !encoder.u8(1) || !encode_atom(encoder, atom) {
                    return false;
                }
                match input.atom_variables.get(atom) {
                    Some(&variable) => {
                        if !encoder.u8(1) || !encoder.i32(variable) {
                            return false;
                        }
                    }
                    None => {
                        if !encoder.u8(0) {
                            return false;
                        }
                    }
                }
            }
        }
    }
    if !encoder.usize(input.atom_variables.len()) {
        return false;
    }
    match input.true_literal {
        Some(literal) => {
            if !encoder.u8(1) || !encoder.i32(literal) {
                return false;
            }
        }
        None => {
            if !encoder.u8(0) {
                return false;
            }
        }
    }
    encoder.u8(u8::from(input.finite_equalities_complete))
        && encoder.u8(u8::from(input.finite_predicate_congruence_complete))
}

fn encode_flat_clause_store(encoder: &mut Encoder, input: EqresInput<'_>) -> bool {
    if !encoder.usize(input.baseline_clauses.end_offsets.len()) {
        return false;
    }
    for &offset in &input.baseline_clauses.end_offsets {
        if !encoder.u32(offset) {
            return false;
        }
    }
    if !encoder.usize(input.baseline_clauses.literals.len()) {
        return false;
    }
    input
        .baseline_clauses
        .literals
        .iter()
        .all(|&literal| encoder.i32(literal))
}

fn encode_clause(encoder: &mut Encoder, clause: &[i32]) -> bool {
    encoder.usize(clause.len()) && clause.iter().all(|&literal| encoder.i32(literal))
}

fn encode_pivot(encoder: &mut Encoder, pivot: ClausePivot) -> bool {
    encoder.u32(pivot.clause.id.get())
        && encoder.u8(match pivot.clause.origin {
            ClauseOrigin::Baseline => 0,
            ClauseOrigin::Derived => 1,
        })
        && encoder.u32(pivot.literal_offset.get())
}

fn encode_equality(encoder: &mut Encoder, equality: EqualityKey) -> bool {
    encoder.usize(equality.left()) && encoder.usize(equality.right())
}

fn encode_trace(encoder: &mut Encoder, trace: &[TraceRecord]) -> bool {
    if !encoder.raw(b"euf-viper-t11-trace-v1\0") || !encoder.usize(trace.len()) {
        return false;
    }
    for record in trace {
        match record {
            TraceRecord::Equality(record) => {
                if !encoder.u8(1)
                    || !encoder.u32(record.event_id.get())
                    || !encoder.u32(record.node_id.get())
                    || !encoder.u32(record.depth.get())
                    || !encode_equality(encoder, record.conclusion)
                    || !encode_clause(encoder, record.side_clause.as_slice())
                {
                    return false;
                }
                match &record.rule {
                    EqualityRuleRecord::Seed(seed) => {
                        if !encoder.u8(RuleKind::Seed as u8)
                            || !encode_pivot(encoder, seed.positive_source)
                        {
                            return false;
                        }
                    }
                    EqualityRuleRecord::Reflexivity(reflexivity) => {
                        if !encoder.u8(RuleKind::Reflexivity as u8)
                            || !encoder.usize(reflexivity.term)
                        {
                            return false;
                        }
                    }
                    EqualityRuleRecord::Transitivity(transitivity) => {
                        if !encoder.u8(RuleKind::Transitivity as u8)
                            || !encoder.u32(transitivity.parents[0].get())
                            || !encoder.u32(transitivity.parents[1].get())
                            || !encoder.usize(transitivity.intermediate)
                        {
                            return false;
                        }
                    }
                    EqualityRuleRecord::Congruence(congruence) => {
                        if !encoder.u8(RuleKind::Congruence as u8)
                            || !encoder.usize(congruence.applications[0].term())
                            || !encoder.usize(congruence.applications[1].term())
                            || !encoder.usize(congruence.arguments.len())
                        {
                            return false;
                        }
                        for argument in &congruence.arguments {
                            if !encoder.u32(argument.argument_index.get())
                                || !encoder.u32(argument.parent.get())
                            {
                                return false;
                            }
                        }
                    }
                }
            }
            TraceRecord::Conflict(record) => {
                if !encoder.u8(2)
                    || !encoder.u32(record.event_id.get())
                    || !encoder.u32(record.clause_id.get())
                    || !encoder.u32(record.depth.get())
                    || !encode_clause(encoder, record.clause.as_slice())
                    || !encoder.u32(record.rule.equality_parent.get())
                    || !encode_pivot(encoder, record.rule.negative_source)
                {
                    return false;
                }
            }
        }
    }
    true
}

fn output_lemmas(output: Option<&EqresOutput>) -> &[EmittedLemma] {
    match output {
        Some(EqresOutput::Lemmas(lemmas)) => lemmas,
        Some(EqresOutput::TheoryEmpty { lemma, .. }) => std::slice::from_ref(lemma),
        Some(EqresOutput::NoLemmas) | None => &[],
    }
}

fn encode_output_payload(encoder: &mut Encoder, output: Option<&EqresOutput>) -> bool {
    let lemmas = output_lemmas(output);
    encoder.usize(lemmas.len())
        && lemmas
            .iter()
            .all(|lemma| encode_clause(encoder, lemma.clause.as_slice()))
}

fn materialized_shape_valid(materialized: &MaterializedClauseStore) -> bool {
    materialized.end_offsets().first() == Some(&0)
        && materialized
            .end_offsets()
            .windows(2)
            .all(|bounds| bounds[0] <= bounds[1])
        && materialized.end_offsets().last().copied().map(u64::from)
            == u64::try_from(materialized.literals().len()).ok()
}

fn encode_materialized_payload(
    encoder: &mut Encoder,
    materialized: &MaterializedClauseStore,
) -> bool {
    if !materialized_shape_valid(materialized) || !encoder.usize(materialized.len()) {
        return false;
    }
    for index in 0..materialized.len() {
        let Some(clause) = materialized.clause(index) else {
            return false;
        };
        if !encode_clause(encoder, clause) {
            return false;
        }
    }
    true
}

fn recompute_hashes(
    input: EqresInput<'_>,
    trace: &[TraceRecord],
    output: Option<&EqresOutput>,
    materialized: &MaterializedClauseStore,
) -> HashBindings {
    let source_sha256 = digest_raw(input.source_bytes).unwrap_or(Sha256Digest::ZERO);
    let baseline_problem_sha256 = digest_with(|encoder| {
        encoder.raw(b"euf-viper-t10-baseline-problem-v1\0")
            && encode_flat_clause_store(encoder, input)
            && encode_atom_map_payload(encoder, input)
    })
    .unwrap_or(Sha256Digest::ZERO);
    let trace_sha256 =
        digest_with(|encoder| encode_trace(encoder, trace)).unwrap_or(Sha256Digest::ZERO);
    let lemma_sequence_sha256 = digest_with(|encoder| {
        encoder.raw(b"euf-viper-t11-lemma-clause-sequence-v1\0")
            && encode_output_payload(encoder, output)
    })
    .unwrap_or(Sha256Digest::ZERO);
    let materialized_lemmas_sha256 = digest_with(|encoder| {
        encoder.raw(b"euf-viper-t11-lemma-clause-sequence-v1\0")
            && encode_materialized_payload(encoder, materialized)
    })
    .unwrap_or(Sha256Digest::ZERO);
    let materialized_candidate_sha256 = digest_with(|encoder| {
        encoder.raw(b"euf-viper-t11-materialized-candidate-v1\0")
            && encode_flat_clause_store(encoder, input)
            && encode_materialized_payload(encoder, materialized)
            && encode_atom_map_payload(encoder, input)
    })
    .unwrap_or(Sha256Digest::ZERO);
    HashBindings {
        source_sha256,
        baseline_problem_sha256,
        trace_sha256,
        lemma_sequence_sha256,
        materialized_lemmas_sha256,
        materialized_candidate_sha256,
        ..HashBindings::default()
    }
}

struct FailureSink {
    failures: Vec<AuditFailure>,
}

impl FailureSink {
    fn new() -> Self {
        let mut failures = Vec::new();
        let _ = failures.try_reserve(32);
        Self { failures }
    }

    fn add(
        &mut self,
        kind: AuditFailureKind,
        event_id: Option<EventId>,
        artifact: Option<HashArtifact>,
        input_failure: Option<InputFailure>,
    ) {
        if self.failures.try_reserve(1).is_err() {
            if self.failures.is_empty() {
                self.failures.push(AuditFailure {
                    kind: AuditFailureKind::AllocationFailure,
                    event_id,
                    artifact: None,
                    input_failure: None,
                });
            }
            return;
        }
        self.failures.push(AuditFailure {
            kind,
            event_id,
            artifact,
            input_failure,
        });
    }

    fn plain(&mut self, kind: AuditFailureKind) {
        self.add(kind, None, None, None);
    }

    fn hash(&mut self, kind: AuditFailureKind, artifact: HashArtifact) {
        self.add(kind, None, Some(artifact), None);
    }

    fn fatal(&mut self, error: &ReconstructionError) {
        match error {
            ReconstructionError::Cap(_) => self.plain(AuditFailureKind::InternalInvariant),
            ReconstructionError::Malformed(input_failure) => self.add(
                AuditFailureKind::MalformedInput,
                None,
                None,
                Some(*input_failure),
            ),
            ReconstructionError::Arithmetic(event_id) => {
                self.add(AuditFailureKind::ArithmeticOverflow, *event_id, None, None)
            }
            ReconstructionError::Allocation(event_id) => {
                self.add(AuditFailureKind::AllocationFailure, *event_id, None, None)
            }
            ReconstructionError::Internal(event_id) => {
                self.add(AuditFailureKind::InternalInvariant, *event_id, None, None)
            }
        }
    }

    fn status(self) -> AuditStatus {
        match NonEmptyAuditFailures::from_vec(self.failures) {
            Some(failures) => AuditStatus::Rejected(failures),
            None => AuditStatus::Accepted,
        }
    }
}

fn expected_materialization(
    output: Option<&EqresOutput>,
) -> Result<(Vec<u32>, Vec<i32>), ReconstructionError> {
    let lemmas = output_lemmas(output);
    let literal_count = lemmas
        .iter()
        .try_fold(0usize, |total, lemma| total.checked_add(lemma.clause.len()));
    let literal_count = literal_count.ok_or_else(|| arithmetic(None))?;
    let offset_count = lemmas
        .len()
        .checked_add(1)
        .ok_or_else(|| arithmetic(None))?;
    let mut offsets = Vec::new();
    offsets
        .try_reserve_exact(offset_count)
        .map_err(|_| allocation(None))?;
    let mut literals = Vec::new();
    literals
        .try_reserve_exact(literal_count)
        .map_err(|_| allocation(None))?;
    offsets.push(0);
    for lemma in lemmas {
        literals.extend_from_slice(lemma.clause.as_slice());
        offsets.push(to_u32(literals.len(), None)?);
    }
    Ok((offsets, literals))
}

fn compare_hash_bindings(
    failures: &mut FailureSink,
    kind: AuditFailureKind,
    expected: &HashBindings,
    actual: &HashBindings,
) {
    let comparisons = [
        (
            HashArtifact::Source,
            expected.source_sha256,
            actual.source_sha256,
        ),
        (
            HashArtifact::BaselineProblem,
            expected.baseline_problem_sha256,
            actual.baseline_problem_sha256,
        ),
        (
            HashArtifact::Trace,
            expected.trace_sha256,
            actual.trace_sha256,
        ),
        (
            HashArtifact::LemmaSequence,
            expected.lemma_sequence_sha256,
            actual.lemma_sequence_sha256,
        ),
        (
            HashArtifact::MaterializedLemmas,
            expected.materialized_lemmas_sha256,
            actual.materialized_lemmas_sha256,
        ),
        (
            HashArtifact::MaterializedCandidate,
            expected.materialized_candidate_sha256,
            actual.materialized_candidate_sha256,
        ),
    ];
    for (artifact, expected, actual) in comparisons {
        if expected != actual {
            failures.hash(kind, artifact);
        }
    }
}

fn zero_audited_hashes() -> HashBindings {
    HashBindings::default()
}

/// Reconstruct and audit one selected T11 bundle without compiler/checker calls
/// or any file-system access.
pub(crate) fn audit(input: EqresInput<'_>, bundle: &EqresBundle) -> AuditResult {
    let reconstruction = reconstruct(input, bundle.compiler.variant);
    let mut failures = FailureSink::new();
    if bundle.selector.decision != SelectorDecision::Selected {
        failures.plain(AuditFailureKind::SelectorMismatch);
    }
    if bundle.report.schema_version != EQRES_SCHEMA_VERSION {
        failures.plain(AuditFailureKind::ReportSchemaMismatch);
    }
    if bundle.report.selector != bundle.selector {
        failures.plain(AuditFailureKind::ReportSelectorMismatch);
    }
    if bundle.report.compiler_variant != bundle.compiler.variant {
        failures.plain(AuditFailureKind::ReportVariantMismatch);
    }

    let (output, cap_attempt, hashes_recorded, expected_outcome) = match &reconstruction.status {
        ReconstructionStatus::Completed(output) => {
            let outcome = match output {
                EqresOutput::Lemmas(_) => ReportOutcome::Lemmas,
                EqresOutput::TheoryEmpty { .. } => ReportOutcome::TheoryEmpty,
                EqresOutput::NoLemmas => ReportOutcome::NoLemmas,
            };
            match &bundle.compiler.status {
                CompilerStatus::Completed(actual) if actual == output => {}
                CompilerStatus::Completed(_) => failures.plain(AuditFailureKind::OutputMismatch),
                CompilerStatus::Rejected(CompilerFailure::Cap(_)) => {
                    failures.plain(AuditFailureKind::CapAttemptMismatch)
                }
                CompilerStatus::NotRun | CompilerStatus::Rejected(_) => {
                    failures.plain(AuditFailureKind::CompilerStatusMismatch)
                }
            }
            (Some(output), None, true, outcome)
        }
        ReconstructionStatus::Cap {
            attempt,
            hashes_recorded,
        } => {
            match &bundle.compiler.status {
                CompilerStatus::Rejected(CompilerFailure::Cap(actual)) if actual == attempt => {}
                CompilerStatus::Rejected(CompilerFailure::Cap(_)) => {
                    failures.plain(AuditFailureKind::CapAttemptMismatch)
                }
                CompilerStatus::NotRun
                | CompilerStatus::Completed(_)
                | CompilerStatus::Rejected(_) => {
                    failures.plain(AuditFailureKind::CompilerStatusMismatch)
                }
            }
            (
                None,
                Some(attempt.clone()),
                *hashes_recorded,
                ReportOutcome::Rejected,
            )
        }
        ReconstructionStatus::Fatal(error) => {
            failures.fatal(error);
            (None, None, false, ReportOutcome::Rejected)
        }
    };

    if reconstruction.trace.as_slice() != bundle.compiler.trace.as_ref() {
        failures.plain(AuditFailureKind::TraceMismatch);
    }
    if reconstruction.counters != bundle.compiler.counters {
        failures.plain(AuditFailureKind::CounterMismatch);
    }
    if reconstruction.counters != bundle.report.counters {
        failures.plain(AuditFailureKind::ReportCounterMismatch);
    }
    if cap_attempt != bundle.report.cap_attempt {
        failures.plain(AuditFailureKind::ReportCapMismatch);
    }
    if bundle.report.outcome != expected_outcome {
        failures.plain(AuditFailureKind::ReportOutcomeMismatch);
    }

    let materialized = bundle.materialized_lemmas();
    if !materialized_shape_valid(materialized) {
        failures.plain(AuditFailureKind::MaterializedShapeMismatch);
    }
    match expected_materialization(output) {
        Ok((offsets, literals)) => {
            if offsets.as_slice() != materialized.end_offsets() {
                failures.plain(AuditFailureKind::MaterializedOffsetsMismatch);
            }
            if literals.as_slice() != materialized.literals() {
                failures.plain(AuditFailureKind::MaterializedLiteralsMismatch);
            }
        }
        Err(error) => failures.fatal(&error),
    }

    let recomputed_hashes = recompute_hashes(input, &reconstruction.trace, output, materialized);
    let expected_recorded_hashes = if hashes_recorded {
        recomputed_hashes
    } else {
        zero_audited_hashes()
    };
    compare_hash_bindings(
        &mut failures,
        AuditFailureKind::CompilerHashMismatch,
        &expected_recorded_hashes,
        &bundle.compiler.hashes,
    );
    compare_hash_bindings(
        &mut failures,
        AuditFailureKind::ReportHashMismatch,
        &expected_recorded_hashes,
        &bundle.report.hashes,
    );
    if matches!(&reconstruction.status, ReconstructionStatus::Completed(_)) {
        if !matches!(bundle.checker.status, CheckerStatus::Accepted) {
            failures.plain(AuditFailureKind::CheckerStatusMismatch);
        }
        compare_hash_bindings(
            &mut failures,
            AuditFailureKind::CheckerHashMismatch,
            &recomputed_hashes,
            &bundle.checker.recomputed_hashes,
        );
    }

    AuditResult {
        status: failures.status(),
        counters: reconstruction.counters,
        cap_attempt,
        recomputed_hashes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::t11_eqres_compiler;
    use crate::t11_eqres_types::{
        CheckerCounters, CheckerResult, EqresMode, EqresReport, ForbiddenGrowthCounters,
        IntegrityReport, SelectorFacts, SelectorReport, SolverBackend,
    };
    use crate::{FlatClauses, FunDecl, FunDeclTable, SortId, SortTable, Term};

    const DATA_SORT: SortId = SortId(1);

    struct FixtureBuilder {
        sorts: SortTable,
        declarations: FunDeclTable,
        terms: Vec<Term>,
        applications: Vec<TermId>,
        clauses: FlatClauses,
        variable_atoms: Vec<Option<BoolAtomKey>>,
        atom_variables: FxHashMap<BoolAtomKey, i32>,
    }

    impl FixtureBuilder {
        fn new() -> Self {
            let mut ids = FxHashMap::default();
            ids.insert(0, DATA_SORT);
            Self {
                sorts: SortTable {
                    ids,
                    names: vec!["Bool".to_owned(), "U".to_owned()],
                },
                declarations: FunDeclTable::default(),
                terms: Vec::new(),
                applications: Vec::new(),
                clauses: FlatClauses::new(),
                variable_atoms: vec![None],
                atom_variables: FxHashMap::default(),
            }
        }

        fn declaration(&mut self, argument_sorts: Vec<SortId>) -> u32 {
            let function = self.declarations.slots.len() as u32;
            self.declarations.insert(
                function,
                FunDecl {
                    arg_sorts: argument_sorts,
                    result_sort: DATA_SORT,
                },
            );
            function
        }

        fn constant(&mut self) -> TermId {
            let function = self.declaration(Vec::new());
            let term = self.terms.len();
            self.terms.push(Term {
                fun: function,
                args: Vec::new(),
                sort: DATA_SORT,
            });
            term
        }

        fn binary_pair(&mut self, left_arguments: [TermId; 2], right_arguments: [TermId; 2]) {
            let function = self.declaration(vec![DATA_SORT, DATA_SORT]);
            let left = self.terms.len();
            self.terms.push(Term {
                fun: function,
                args: left_arguments.to_vec(),
                sort: DATA_SORT,
            });
            self.applications.push(left);
            let right = self.terms.len();
            self.terms.push(Term {
                fun: function,
                args: right_arguments.to_vec(),
                sort: DATA_SORT,
            });
            self.applications.push(right);
        }

        fn equality(&mut self, left: TermId, right: TermId) -> i32 {
            let (left, right) = if left <= right {
                (left, right)
            } else {
                (right, left)
            };
            let atom = BoolAtomKey::Eq(left, right);
            if let Some(&variable) = self.atom_variables.get(&atom) {
                return variable;
            }
            let variable = self.variable_atoms.len() as i32;
            self.variable_atoms.push(Some(atom.clone()));
            self.atom_variables.insert(atom, variable);
            variable
        }

        fn auxiliary(&mut self) -> i32 {
            let variable = self.variable_atoms.len() as i32;
            self.variable_atoms.push(None);
            variable
        }

        fn clause(&mut self, literals: Vec<i32>) {
            self.clauses
                .try_push(literals)
                .expect("synthetic clause store should fit");
        }

        fn build(self) -> Fixture {
            Fixture {
                source: b"synthetic-t11-audit".to_vec(),
                root_mode: b"direct-root-test-v1".to_vec(),
                sorts: self.sorts,
                declarations: self.declarations,
                terms: self.terms,
                applications: self.applications,
                clauses: self.clauses,
                variable_atoms: self.variable_atoms,
                atom_variables: self.atom_variables,
            }
        }
    }

    struct Fixture {
        source: Vec<u8>,
        root_mode: Vec<u8>,
        sorts: SortTable,
        declarations: FunDeclTable,
        terms: Vec<Term>,
        applications: Vec<TermId>,
        clauses: FlatClauses,
        variable_atoms: Vec<Option<BoolAtomKey>>,
        atom_variables: FxHashMap<BoolAtomKey, i32>,
    }

    impl Fixture {
        fn input(&self) -> EqresInput<'_> {
            EqresInput {
                source_bytes: &self.source,
                root_cnf_mode: &self.root_mode,
                sorts: &self.sorts,
                declarations: &self.declarations,
                term_dag: &self.terms,
                ordered_applications: &self.applications,
                baseline_clauses: &self.clauses,
                variable_atoms: &self.variable_atoms,
                atom_variables: &self.atom_variables,
                true_literal: None,
                finite_equalities_complete: false,
                finite_predicate_congruence_complete: false,
            }
        }
    }

    fn selected_selector(applications: usize) -> SelectorReport {
        SelectorReport {
            mode: EqresMode::CliqueErAuto,
            facts: SelectorFacts {
                finite_added_clauses: 0,
                covered_finite_terms: 0,
                closed_table_functions: 0,
                all_different_clique_lower_bound: 8,
                disequality_graph_edges: 0,
                equality_graph_vertices: 8,
                equality_graph_edges: 1,
                applications: applications as u64,
                boolean_valued_application_pairs: 0,
                backend: SolverBackend::Kissat,
            },
            decision: SelectorDecision::Selected,
        }
    }

    fn materialize(
        compiler: &super::super::t11_eqres_types::CompilerResult,
    ) -> MaterializedClauseStore {
        let output = match &compiler.status {
            CompilerStatus::Completed(output) => Some(output),
            CompilerStatus::NotRun | CompilerStatus::Rejected(_) => None,
        };
        let (offsets, literals) = expected_materialization(output).expect("fixture materializes");
        MaterializedClauseStore::from_parts(offsets, literals).expect("valid materialization")
    }

    fn compiled_bundle(fixture: &Fixture, variant: CompilerVariant) -> EqresBundle {
        let compiler = t11_eqres_compiler::compile(fixture.input(), variant);
        assert!(matches!(compiler.status, CompilerStatus::Completed(_)));
        let materialized = materialize(&compiler);
        let selector = selected_selector(fixture.applications.len());
        let checker = CheckerResult {
            status: CheckerStatus::Accepted,
            counters: CheckerCounters::default(),
            recomputed_hashes: compiler.hashes,
        };
        let outcome = match &compiler.status {
            CompilerStatus::Completed(EqresOutput::Lemmas(_)) => ReportOutcome::Lemmas,
            CompilerStatus::Completed(EqresOutput::TheoryEmpty { .. }) => {
                ReportOutcome::TheoryEmpty
            }
            CompilerStatus::Completed(EqresOutput::NoLemmas) => ReportOutcome::NoLemmas,
            CompilerStatus::NotRun | CompilerStatus::Rejected(_) => ReportOutcome::Rejected,
        };
        let report = EqresReport {
            schema_version: EQRES_SCHEMA_VERSION,
            selector,
            compiler_variant: compiler.variant,
            outcome,
            counters: compiler.counters,
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
            hashes: compiler.hashes,
        };
        EqresBundle::new(selector, compiler, materialized, checker, report)
    }

    fn lemma_fixture() -> (Fixture, i32) {
        let mut builder = FixtureBuilder::new();
        let left = builder.constant();
        let right = builder.constant();
        let equality = builder.equality(left, right);
        let guard = builder.auxiliary();
        builder.clause(vec![equality]);
        builder.clause(vec![-equality, guard]);
        (builder.build(), guard)
    }

    fn assert_failure(result: &AuditResult, kind: AuditFailureKind) {
        let AuditStatus::Rejected(failures) = &result.status else {
            panic!("audit unexpectedly accepted mutation");
        };
        assert!(
            failures
                .as_slice()
                .iter()
                .any(|failure| failure.kind == kind)
        );
    }

    #[test]
    fn accepts_synthetic_compiler_bundle() {
        let (fixture, _) = lemma_fixture();
        let bundle = compiled_bundle(&fixture, CompilerVariant::Ordinary);
        let result = audit(fixture.input(), &bundle);
        assert_eq!(result.status, AuditStatus::Accepted);
        assert_eq!(result.counters, bundle.compiler.counters);
        assert_eq!(result.cap_attempt, None);
        assert_eq!(
            result.recomputed_hashes.trace_sha256,
            bundle.compiler.hashes.trace_sha256
        );
        assert_eq!(
            result.recomputed_hashes.materialized_candidate_sha256,
            bundle.compiler.hashes.materialized_candidate_sha256
        );
    }

    #[test]
    fn rejects_counter_mutation() {
        let (fixture, _) = lemma_fixture();
        let mut bundle = compiled_bundle(&fixture, CompilerVariant::Ordinary);
        bundle.compiler.counters.search.events_popped += 1;
        let result = audit(fixture.input(), &bundle);
        assert_failure(&result, AuditFailureKind::CounterMismatch);
    }

    #[test]
    fn rejects_trace_order_mutation() {
        let (fixture, _) = lemma_fixture();
        let mut bundle = compiled_bundle(&fixture, CompilerVariant::Ordinary);
        assert!(bundle.compiler.trace.len() >= 2);
        bundle.compiler.trace.swap(0, 1);
        let result = audit(fixture.input(), &bundle);
        assert_failure(&result, AuditFailureKind::TraceMismatch);
    }

    #[test]
    fn rejects_output_mutation() {
        let (fixture, _) = lemma_fixture();
        let mut bundle = compiled_bundle(&fixture, CompilerVariant::Ordinary);
        bundle.compiler.status = CompilerStatus::Completed(EqresOutput::NoLemmas);
        let result = audit(fixture.input(), &bundle);
        assert_failure(&result, AuditFailureKind::OutputMismatch);
    }

    #[test]
    fn rejects_exact_materialized_byte_mutation() {
        let (fixture, guard) = lemma_fixture();
        let bundle = compiled_bundle(&fixture, CompilerVariant::Ordinary);
        assert_eq!(bundle.materialized_lemmas().literals(), [guard]);
        let materialized = MaterializedClauseStore::from_parts(vec![0, 1], vec![-guard])
            .expect("mutated store remains structurally valid");
        let mutated = EqresBundle::new(
            bundle.selector,
            bundle.compiler.clone(),
            materialized,
            bundle.checker.clone(),
            bundle.report.clone(),
        );
        let result = audit(fixture.input(), &mutated);
        assert_failure(&result, AuditFailureKind::MaterializedLiteralsMismatch);
        assert_failure(&result, AuditFailureKind::CompilerHashMismatch);
    }

    #[test]
    fn suppression_precedes_tuple_allocation_and_attempt_accounting() {
        let mut builder = FixtureBuilder::new();
        let a = builder.constant();
        let b = builder.constant();
        let c = builder.constant();
        let d = builder.constant();
        builder.binary_pair([a, c], [b, d]);
        let ab = builder.equality(a, b);
        let cd = builder.equality(c, d);
        let guards = [
            builder.auxiliary(),
            builder.auxiliary(),
            builder.auxiliary(),
            builder.auxiliary(),
        ];
        builder.clause(vec![ab, guards[0]]);
        builder.clause(vec![ab, guards[1]]);
        builder.clause(vec![cd, guards[2]]);
        builder.clause(vec![cd, guards[3]]);
        let fixture = builder.build();
        let bundle = compiled_bundle(&fixture, CompilerVariant::SuppressMissingEqualityCongruence);
        let result = audit(fixture.input(), &bundle);
        assert_eq!(result.status, AuditStatus::Accepted);
        assert_eq!(
            result
                .counters
                .search
                .suppressed_missing_equality_congruence_events,
            bundle
                .compiler
                .counters
                .search
                .suppressed_missing_equality_congruence_events
        );
        assert!(
            result
                .counters
                .search
                .suppressed_missing_equality_congruence_events
                >= 4
        );
        assert_eq!(result.counters.search.attempted_events.congruence, 0);
        assert_eq!(result.counters.search.accepted_events.congruence, 0);
    }

    #[test]
    fn transitivity_join_identity_keeps_both_intermediates() {
        let mut builder = FixtureBuilder::new();
        let a = builder.constant();
        let b = builder.constant();
        let equality = builder.equality(a, b);
        let left_guard = builder.auxiliary();
        let right_guard = builder.auxiliary();
        builder.clause(vec![equality, left_guard]);
        builder.clause(vec![equality, right_guard]);
        let fixture = builder.build();
        let mut counters = DeterministicCounters::default();
        let prepared =
            validate_and_prepare(fixture.input(), &mut counters).expect("join fixture validates");
        let mut auditor = Auditor::new(fixture.input(), CompilerVariant::Ordinary, prepared)
            .expect("join auditor initializes");
        auditor.run().expect("join fixture reconstructs");
        let mut seed_nodes = Vec::new();
        for record in &auditor.trace {
            if let TraceRecord::Equality(record) = record
                && record.conclusion
                    == EqualityKey::from_normalized(a, b).expect("ordered fixture terms")
                && matches!(record.rule, EqualityRuleRecord::Seed(_))
            {
                seed_nodes.push(record.node_id);
            }
        }
        seed_nodes.sort_unstable();
        assert_eq!(seed_nodes.len(), 2);
        let parents = [seed_nodes[0], seed_nodes[1]];
        let mut intermediates = auditor
            .transitivity_joins
            .iter()
            .filter_map(|join| (join.parents == parents).then_some(join.intermediate))
            .collect::<Vec<_>>();
        intermediates.sort_unstable();
        intermediates.dedup();
        assert_eq!(intermediates, vec![a, b]);
    }

    #[test]
    fn rejects_cap_mismatch() {
        let (fixture, _) = lemma_fixture();
        let mut bundle = compiled_bundle(&fixture, CompilerVariant::Ordinary);
        let fake = CapAttempt {
            reason: CapReason::Terms,
            boundary: CapBoundary::StaticInput,
            pre_event_value: 0,
            prospective_value: Limits::TERMS + 1,
            limit: Limits::TERMS,
        };
        bundle.compiler.status = CompilerStatus::Rejected(CompilerFailure::Cap(fake.clone()));
        bundle.report.cap_attempt = Some(fake);
        bundle.report.outcome = ReportOutcome::Rejected;
        let result = audit(fixture.input(), &bundle);
        assert_failure(&result, AuditFailureKind::CapAttemptMismatch);
    }

    #[cfg(feature = "certificates")]
    #[test]
    fn receipt_round_trips_and_binds_exact_bundle_digest() {
        let (fixture, _) = lemma_fixture();
        let bundle = compiled_bundle(&fixture, CompilerVariant::Ordinary);
        let result = audit(fixture.input(), &bundle);
        let exact = Sha256Digest::new([0x5a; 32]);
        let receipt = EqresAuditReceipt::new(&bundle, exact, result);
        assert!(receipt.accepted_for(&bundle, exact));

        let bytes = serde_json::to_vec(&receipt).expect("serialize audit receipt");
        let decoded: EqresAuditReceipt =
            serde_json::from_slice(&bytes).expect("deserialize audit receipt");
        assert!(decoded.accepted_for(&bundle, exact));
        assert!(!decoded.accepted_for(&bundle, Sha256Digest::new([0x6b; 32])));

        let mut zeroed = decoded;
        zeroed.trace_sha256 = Sha256Digest::ZERO;
        assert!(!zeroed.accepted_for(&bundle, exact));
    }
}
