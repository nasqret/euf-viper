//! Deterministic bounded clause-level equality-resolution compiler.
//!
//! This module intentionally owns its validation, canonicalization, scheduling,
//! subsumption, accounting, and hashing implementations.  The independent T11
//! checker must not call any helper defined here.

use super::t11_eqres_types::{
    ApplicationId, ArgumentIndex, CanonicalClause, CapAttempt, CapBoundary, CapReason, ClauseId,
    ClauseOrigin, ClausePivot, ClauseRef, CompilerFailure, CompilerResult, CompilerStatus,
    CompilerVariant, ConflictRecord, ConflictTraceRecord, CongruenceArgumentParent,
    CongruenceRecord, DeterministicCounters, EmittedLemma, EqresInput, EqresOutput, EqualityKey,
    EqualityRuleRecord, EqualityTraceRecord, EventId, EventKey, HashArtifact, HashBindings,
    InputCounters, InputFailure, Limits, LiteralOffset, LogicalMemoryWeights, NodeId, ProofDepth,
    ReflexivityRecord, RuleCounters, RuleKind, SeedRecord, Sha256Digest, TraceRecord,
    TransitivityRecord,
};
use super::{BOOL_SORT, BoolAtomKey, TermId};
use rustc_hash::{FxHashMap, FxHashSet};
use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;

#[derive(Clone, Copy)]
struct CompilerLimits {
    terms: u64,
    baseline_variables: u64,
    baseline_clauses: u64,
    baseline_literal_slots: u64,
    applications: u64,
    application_pairs: u64,
    maximum_arity: u64,
    application_argument_slots: u64,
    equality_proof_nodes: u64,
    proof_parent_references: u64,
    proof_depth: u64,
    unique_derived_clauses: u64,
    retained_side_clauses_per_equality: u64,
    canonical_proof_work_literal_charge: u64,
    worklist_pushes: u64,
    live_worklist_entries: u64,
    all_derived_literal_slots: u64,
    emitted_lemmas: u64,
    emitted_lemma_literal_slots: u64,
    emitted_p95_width: u64,
    emitted_maximum_width: u64,
    logical_incremental_memory_bytes: u64,
}

impl CompilerLimits {
    const FROZEN: Self = Self {
        terms: Limits::TERMS,
        baseline_variables: Limits::BASELINE_VARIABLES,
        baseline_clauses: Limits::BASELINE_CLAUSES,
        baseline_literal_slots: Limits::BASELINE_LITERAL_SLOTS,
        applications: Limits::APPLICATIONS,
        application_pairs: Limits::APPLICATION_PAIRS,
        maximum_arity: Limits::MAXIMUM_ARITY,
        application_argument_slots: Limits::APPLICATION_ARGUMENT_SLOTS,
        equality_proof_nodes: Limits::EQUALITY_PROOF_NODES,
        proof_parent_references: Limits::PROOF_PARENT_REFERENCES,
        proof_depth: Limits::PROOF_DEPTH,
        unique_derived_clauses: Limits::UNIQUE_DERIVED_CLAUSES,
        retained_side_clauses_per_equality: Limits::RETAINED_SIDE_CLAUSES_PER_EQUALITY,
        canonical_proof_work_literal_charge: Limits::CANONICAL_PROOF_WORK_LITERAL_CHARGE,
        worklist_pushes: Limits::WORKLIST_PUSHES,
        live_worklist_entries: Limits::LIVE_WORKLIST_ENTRIES,
        all_derived_literal_slots: Limits::ALL_DERIVED_LITERAL_SLOTS,
        emitted_lemmas: Limits::EMITTED_LEMMAS,
        emitted_lemma_literal_slots: Limits::EMITTED_LEMMA_LITERAL_SLOTS,
        emitted_p95_width: Limits::EMITTED_P95_WIDTH,
        emitted_maximum_width: Limits::EMITTED_MAXIMUM_WIDTH,
        logical_incremental_memory_bytes: Limits::LOGICAL_INCREMENTAL_MEMORY_BYTES,
    };
}

#[derive(Debug, Clone)]
struct ApplicationPair {
    applications: [ApplicationId; 2],
    requirements: Vec<(ArgumentIndex, EqualityKey)>,
}

#[derive(Debug)]
struct PreparedInput {
    counters: InputCounters,
    application_pairs: Vec<ApplicationPair>,
    initial_logical_memory: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ApplicationShape {
    pair_count: u64,
    maximum_arity: u64,
    argument_slots: u64,
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

#[derive(Debug)]
struct NodeMeta {
    trace_index: usize,
    conclusion: EqualityKey,
    depth: ProofDepth,
    active: bool,
    mechanism_dependency: bool,
}

#[derive(Debug)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransitivityJoinCandidate {
    other_conclusion: EqualityKey,
    other_node: NodeId,
    orientation: u8,
    intermediate: TermId,
    new_other: TermId,
    other: TermId,
}

#[derive(Debug)]
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

#[derive(Debug)]
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

#[derive(Debug)]
struct OutputCandidate {
    source_clause_id: ClauseId,
    clause: CanonicalClause,
    mechanism_dependency: bool,
}

#[derive(Debug)]
struct TerminalEmpty {
    event_id: EventId,
    clause_id: ClauseId,
    mechanism_dependency: bool,
}

struct Compiler<'a> {
    input: EqresInput<'a>,
    variant: CompilerVariant,
    limits: CompilerLimits,
    counters: DeterministicCounters,
    input_hashes: HashBindings,
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

/// Compile one already-selected T11 input without invoking SAT or inspecting
/// any source identity beyond the supplied immutable bytes.
pub(crate) fn compile(input: EqresInput<'_>, variant: CompilerVariant) -> CompilerResult {
    compile_internal(input, variant, CompilerLimits::FROZEN)
}

fn compile_internal(
    input: EqresInput<'_>,
    variant: CompilerVariant,
    limits: CompilerLimits,
) -> CompilerResult {
    let mut counters = DeterministicCounters::default();
    let prepared = match validate_and_prepare(input, limits, &mut counters) {
        Ok(prepared) => prepared,
        Err(failure) => {
            return CompilerResult {
                variant,
                status: CompilerStatus::Rejected(failure),
                trace: Box::new([]),
                counters,
                hashes: HashBindings::default(),
            };
        }
    };

    let input_hashes = match compute_input_hashes(input) {
        Ok(hashes) => hashes,
        Err(failure) => {
            return CompilerResult {
                variant,
                status: CompilerStatus::Rejected(failure),
                trace: Box::new([]),
                counters,
                hashes: HashBindings::default(),
            };
        }
    };

    let mut compiler = match Compiler::new(input, variant, limits, prepared, input_hashes) {
        Ok(compiler) => compiler,
        Err(failure) => {
            return CompilerResult {
                variant,
                status: CompilerStatus::Rejected(failure),
                trace: Box::new([]),
                counters,
                hashes: input_hashes,
            };
        }
    };

    let mut status = match compiler.run() {
        Ok(output) => CompilerStatus::Completed(output),
        Err(failure) => CompilerStatus::Rejected(failure),
    };

    if let Err(failure) = compiler.verify_input_hashes() {
        status = CompilerStatus::Rejected(failure);
    }
    compiler.finish(status)
}

#[cfg(test)]
fn compile_with_test_limits(
    input: EqresInput<'_>,
    variant: CompilerVariant,
    limits: CompilerLimits,
) -> CompilerResult {
    compile_internal(input, variant, limits)
}

fn validate_and_prepare(
    input: EqresInput<'_>,
    limits: CompilerLimits,
    counters: &mut DeterministicCounters,
) -> Result<PreparedInput, CompilerFailure> {
    validate_and_prepare_with(input, limits, counters, materialize_application_pairs)
}

fn validate_and_prepare_with<F>(
    input: EqresInput<'_>,
    limits: CompilerLimits,
    counters: &mut DeterministicCounters,
    materialize: F,
) -> Result<PreparedInput, CompilerFailure>
where
    F: FnOnce(EqresInput<'_>, u64) -> Result<Vec<ApplicationPair>, CompilerFailure>,
{
    let term_count = to_u64(input.term_dag.len(), None)?;
    let variable_count =
        input
            .variable_atoms
            .len()
            .checked_sub(1)
            .ok_or(CompilerFailure::MalformedInput(
                InputFailure::InvalidAtomMap,
            ))?;
    let variable_count = to_u64(variable_count, None)?;
    let clause_count = input
        .baseline_clauses
        .end_offsets
        .len()
        .checked_sub(1)
        .ok_or(CompilerFailure::MalformedInput(
            InputFailure::InvalidClauseStore,
        ))?;
    let clause_count = to_u64(clause_count, None)?;
    let literal_slots = to_u64(input.baseline_clauses.literals.len(), None)?;
    let application_count = to_u64(input.ordered_applications.len(), None)?;

    counters.input.terms = term_count;
    counters.input.baseline_variables = variable_count;
    counters.input.baseline_atom_entries = to_u64(input.atom_variables.len(), None)?;
    counters.input.baseline_clauses = clause_count;
    counters.input.baseline_literal_slots = literal_slots;
    counters.input.applications = application_count;

    check_static_cap(CapReason::Terms, term_count, limits.terms)?;
    check_static_cap(
        CapReason::BaselineVariables,
        variable_count,
        limits.baseline_variables,
    )?;
    check_static_cap(
        CapReason::BaselineClauses,
        clause_count,
        limits.baseline_clauses,
    )?;
    check_static_cap(
        CapReason::BaselineLiteralSlots,
        literal_slots,
        limits.baseline_literal_slots,
    )?;
    check_static_cap(
        CapReason::Applications,
        application_count,
        limits.applications,
    )?;

    validate_clause_store(input)?;
    validate_sorts_and_declarations(input)?;
    validate_terms_and_application_order(input)?;
    validate_atom_maps(input)?;
    validate_clause_literals(input)?;

    let shape = summarize_application_pairs(input)?;
    counters.input.application_pairs = shape.pair_count;
    counters.input.maximum_arity = shape.maximum_arity;
    counters.input.application_argument_slots = shape.argument_slots;

    check_static_cap(
        CapReason::ApplicationPairs,
        shape.pair_count,
        limits.application_pairs,
    )?;
    check_static_cap(
        CapReason::MaximumArity,
        shape.maximum_arity,
        limits.maximum_arity,
    )?;
    check_static_cap(
        CapReason::ApplicationArgumentSlots,
        shape.argument_slots,
        limits.application_argument_slots,
    )?;

    let initial_logical_memory = logical_memory(
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        shape.pair_count,
        shape.argument_slots,
        None,
    )?;
    check_static_cap(
        CapReason::LogicalIncrementalMemoryBytes,
        initial_logical_memory,
        limits.logical_incremental_memory_bytes,
    )?;

    let application_pairs = materialize(input, shape.pair_count)?;
    if to_u64(application_pairs.len(), None)? != shape.pair_count {
        return Err(internal_invariant(None));
    }

    Ok(PreparedInput {
        counters: counters.input,
        application_pairs,
        initial_logical_memory,
    })
}

fn summarize_application_pairs(input: EqresInput<'_>) -> Result<ApplicationShape, CompilerFailure> {
    let mut pair_count = 0u64;
    let mut maximum_arity = 0u64;
    let mut argument_slots = 0u64;

    for (left_position, &left_id) in input.ordered_applications.iter().enumerate() {
        let left = &input.term_dag[left_id];
        maximum_arity = maximum_arity.max(to_u64(left.args.len(), None)?);
        for &right_id in &input.ordered_applications[(left_position + 1)..] {
            let right = &input.term_dag[right_id];
            if left.fun != right.fun {
                continue;
            }
            if left.args.len() != right.args.len() || left.sort != right.sort {
                return Err(CompilerFailure::MalformedInput(
                    InputFailure::InvalidApplication,
                ));
            }
            if left.sort == BOOL_SORT {
                return Err(CompilerFailure::MalformedInput(
                    InputFailure::UnsupportedBooleanApplicationPair,
                ));
            }

            let requirements = left
                .args
                .iter()
                .zip(&right.args)
                .filter(|(left_arg, right_arg)| left_arg != right_arg)
                .count();
            if requirements == 0 {
                return Err(CompilerFailure::MalformedInput(InputFailure::InvalidTerm));
            }
            pair_count = checked_add(pair_count, 1, None)?;
            argument_slots = checked_add(argument_slots, to_u64(requirements, None)?, None)?;
        }
    }

    Ok(ApplicationShape {
        pair_count,
        maximum_arity,
        argument_slots,
    })
}

fn materialize_application_pairs(
    input: EqresInput<'_>,
    pair_count: u64,
) -> Result<Vec<ApplicationPair>, CompilerFailure> {
    let pair_capacity = usize::try_from(pair_count).map_err(|_| integer_overflow(None))?;
    let mut application_pairs = Vec::new();
    application_pairs
        .try_reserve_exact(pair_capacity)
        .map_err(|_| allocation_failure(None))?;

    for (left_position, &left_id) in input.ordered_applications.iter().enumerate() {
        let left = &input.term_dag[left_id];
        for &right_id in &input.ordered_applications[(left_position + 1)..] {
            let right = &input.term_dag[right_id];
            if left.fun != right.fun {
                continue;
            }
            let requirement_count = left
                .args
                .iter()
                .zip(&right.args)
                .filter(|(left_arg, right_arg)| left_arg != right_arg)
                .count();
            let mut requirements = Vec::new();
            requirements
                .try_reserve_exact(requirement_count)
                .map_err(|_| allocation_failure(None))?;
            for (index, (&left_arg, &right_arg)) in left.args.iter().zip(&right.args).enumerate() {
                if left_arg != right_arg {
                    requirements.push((
                        ArgumentIndex::new(to_u32(index, None)?),
                        normalized_equality(left_arg, right_arg),
                    ));
                }
            }
            if requirements.len() != requirement_count || requirements.is_empty() {
                return Err(internal_invariant(None));
            }
            application_pairs.push(ApplicationPair {
                applications: [ApplicationId::new(left_id), ApplicationId::new(right_id)],
                requirements,
            });
        }
    }
    Ok(application_pairs)
}

fn validate_clause_store(input: EqresInput<'_>) -> Result<(), CompilerFailure> {
    let offsets = &input.baseline_clauses.end_offsets;
    if offsets.first() != Some(&0)
        || offsets.windows(2).any(|window| window[0] > window[1])
        || offsets.last().copied().map(u64::from)
            != Some(to_u64(input.baseline_clauses.literals.len(), None)?)
    {
        return Err(CompilerFailure::MalformedInput(
            InputFailure::InvalidClauseStore,
        ));
    }
    Ok(())
}

fn validate_sorts_and_declarations(input: EqresInput<'_>) -> Result<(), CompilerFailure> {
    if input.sorts.names.first().map(String::as_str) != Some("Bool")
        || input.sorts.names.len() > u32::MAX as usize
    {
        return Err(CompilerFailure::MalformedInput(InputFailure::InvalidSort));
    }

    let mut seen_sort_ids = FxHashSet::default();
    seen_sort_ids
        .try_reserve(input.sorts.ids.len())
        .map_err(|_| allocation_failure(None))?;
    for sort in input.sorts.ids.values() {
        let index = sort.0 as usize;
        if index == 0 || index >= input.sorts.names.len() || !seen_sort_ids.insert(sort.0) {
            return Err(CompilerFailure::MalformedInput(InputFailure::InvalidSort));
        }
    }
    if input.sorts.ids.len() != input.sorts.names.len().saturating_sub(1) {
        return Err(CompilerFailure::MalformedInput(InputFailure::InvalidSort));
    }

    for declaration in input.declarations.slots.iter().flatten() {
        if declaration.result_sort.0 as usize >= input.sorts.names.len()
            || declaration
                .arg_sorts
                .iter()
                .any(|sort| sort.0 as usize >= input.sorts.names.len())
        {
            return Err(CompilerFailure::MalformedInput(
                InputFailure::InvalidDeclaration,
            ));
        }
    }
    Ok(())
}

fn validate_terms_and_application_order(input: EqresInput<'_>) -> Result<(), CompilerFailure> {
    let mut term_shapes = FxHashSet::default();
    term_shapes
        .try_reserve(input.term_dag.len())
        .map_err(|_| allocation_failure(None))?;
    for (term_id, term) in input.term_dag.iter().enumerate() {
        if term.sort.0 as usize >= input.sorts.names.len() {
            return Err(CompilerFailure::MalformedInput(InputFailure::InvalidSort));
        }
        let Some(declaration) = input.declarations.get(term.fun) else {
            return Err(CompilerFailure::MalformedInput(
                InputFailure::InvalidDeclaration,
            ));
        };
        if declaration.result_sort != term.sort || declaration.arg_sorts.len() != term.args.len() {
            return Err(CompilerFailure::MalformedInput(InputFailure::InvalidTerm));
        }
        for (&argument, &sort) in term.args.iter().zip(&declaration.arg_sorts) {
            if argument >= term_id
                || input.term_dag.get(argument).map(|term| term.sort) != Some(sort)
            {
                return Err(CompilerFailure::MalformedInput(InputFailure::InvalidTerm));
            }
        }
        if !term_shapes.insert((term.fun, term.args.as_slice())) {
            return Err(CompilerFailure::MalformedInput(InputFailure::InvalidTerm));
        }
    }

    if input
        .ordered_applications
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(CompilerFailure::MalformedInput(
            InputFailure::InvalidApplicationOrder,
        ));
    }
    let mut next_application = 0usize;
    for (term_id, term) in input.term_dag.iter().enumerate() {
        if term.args.is_empty() {
            continue;
        }
        if input.ordered_applications.get(next_application) != Some(&term_id) {
            return Err(CompilerFailure::MalformedInput(
                InputFailure::InvalidApplicationOrder,
            ));
        }
        next_application = next_application
            .checked_add(1)
            .ok_or_else(|| integer_overflow(None))?;
    }
    if next_application != input.ordered_applications.len()
        || input.ordered_applications.iter().any(|&term| {
            input
                .term_dag
                .get(term)
                .is_none_or(|term| term.args.is_empty())
        })
    {
        return Err(CompilerFailure::MalformedInput(
            InputFailure::InvalidApplication,
        ));
    }
    Ok(())
}

fn validate_atom_maps(input: EqresInput<'_>) -> Result<(), CompilerFailure> {
    if input.variable_atoms.first() != Some(&None) {
        return Err(CompilerFailure::MalformedInput(
            InputFailure::InvalidAtomMap,
        ));
    }
    let mut mapped = 0usize;
    for (variable, atom) in input.variable_atoms.iter().enumerate().skip(1) {
        let Some(atom) = atom else {
            continue;
        };
        mapped = mapped
            .checked_add(1)
            .ok_or_else(|| integer_overflow(None))?;
        validate_atom(input, atom)?;
        if input.atom_variables.get(atom) != Some(&(variable as i32)) {
            return Err(CompilerFailure::MalformedInput(
                InputFailure::InvalidAtomMap,
            ));
        }
    }
    if mapped != input.atom_variables.len() {
        return Err(CompilerFailure::MalformedInput(
            InputFailure::InvalidAtomMap,
        ));
    }
    for (atom, &variable) in input.atom_variables {
        validate_atom(input, atom)?;
        let Ok(index) = usize::try_from(variable) else {
            return Err(CompilerFailure::MalformedInput(
                InputFailure::InvalidAtomMap,
            ));
        };
        if variable <= 0 || input.variable_atoms.get(index).and_then(Option::as_ref) != Some(atom) {
            return Err(CompilerFailure::MalformedInput(
                InputFailure::InvalidAtomMap,
            ));
        }
    }

    if let Some(literal) = input.true_literal {
        let Ok(variable) = usize::try_from(literal) else {
            return Err(CompilerFailure::MalformedInput(
                InputFailure::InvalidAtomMap,
            ));
        };
        if literal <= 0
            || input.variable_atoms.get(variable) != Some(&None)
            || !input
                .baseline_clauses
                .iter()
                .any(|clause| clause == [literal])
        {
            return Err(CompilerFailure::MalformedInput(
                InputFailure::InvalidAtomMap,
            ));
        }
    }
    Ok(())
}

fn validate_atom(input: EqresInput<'_>, atom: &BoolAtomKey) -> Result<(), CompilerFailure> {
    match *atom {
        BoolAtomKey::Eq(left, right) => {
            let (Some(left_term), Some(right_term)) =
                (input.term_dag.get(left), input.term_dag.get(right))
            else {
                return Err(CompilerFailure::MalformedInput(
                    InputFailure::InvalidAtomTerm,
                ));
            };
            if left > right || left_term.sort != right_term.sort || left_term.sort == BOOL_SORT {
                return Err(CompilerFailure::MalformedInput(
                    InputFailure::InvalidAtomTerm,
                ));
            }
        }
        BoolAtomKey::BoolTerm(term) => {
            if input.term_dag.get(term).map(|term| term.sort) != Some(BOOL_SORT) {
                return Err(CompilerFailure::MalformedInput(
                    InputFailure::InvalidAtomTerm,
                ));
            }
        }
    }
    Ok(())
}

fn validate_clause_literals(input: EqresInput<'_>) -> Result<(), CompilerFailure> {
    let variable_count = input.variable_atoms.len().saturating_sub(1);
    for &literal in &input.baseline_clauses.literals {
        let variable = literal.unsigned_abs() as usize;
        if literal == 0 || variable == 0 || variable > variable_count {
            return Err(CompilerFailure::MalformedInput(
                InputFailure::InvalidClauseLiteral,
            ));
        }
        if let Some(BoolAtomKey::Eq(left, right)) = input.variable_atoms[variable].as_ref() {
            let left_sort = input.term_dag.get(*left).map(|term| term.sort);
            let right_sort = input.term_dag.get(*right).map(|term| term.sort);
            if left_sort.is_none() || left_sort != right_sort {
                return Err(CompilerFailure::MalformedInput(
                    InputFailure::InvalidClauseLiteral,
                ));
            }
        }
    }
    Ok(())
}

impl<'a> Compiler<'a> {
    fn new(
        input: EqresInput<'a>,
        variant: CompilerVariant,
        limits: CompilerLimits,
        prepared: PreparedInput,
        input_hashes: HashBindings,
    ) -> Result<Self, CompilerFailure> {
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
            .map_err(|_| allocation_failure(None))?;
        for (pair_index, pair) in prepared.application_pairs.iter().enumerate() {
            for &(argument_index, equality) in &pair.requirements {
                if !application_argument_index.contains_key(&equality) {
                    application_argument_index
                        .try_reserve(1)
                        .map_err(|_| allocation_failure(None))?;
                    application_argument_index.insert(equality, Vec::new());
                }
                let entries = application_argument_index
                    .get_mut(&equality)
                    .ok_or_else(|| internal_invariant(None))?;
                entries
                    .try_reserve(1)
                    .map_err(|_| allocation_failure(None))?;
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
            .map_err(|_| allocation_failure(None))?;
        let mut global_clauses = FxHashSet::default();
        global_clauses
            .try_reserve(input.baseline_clauses.len())
            .map_err(|_| allocation_failure(None))?;
        for clause in input.baseline_clauses {
            if let Some(canonical) = canonicalize_one(clause, None)? {
                let canonical_for_set = clone_canonical_clause(&canonical, None)?;
                if global_clauses.insert(canonical_for_set) {
                    base_canonical_clauses.push(canonical);
                }
            }
        }

        Ok(Self {
            input,
            variant,
            limits,
            counters,
            input_hashes,
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

    fn run(&mut self) -> Result<EqresOutput, CompilerFailure> {
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
                .ok_or_else(|| internal_invariant(None))?;
            let event_id = EventId::new(to_u32(self.counters.search.events_popped, None)?);
            self.counters.search.events_popped =
                checked_add(self.counters.search.events_popped, 1, Some(event_id))?;
            if self.accept_popped_event(event_id, event)? {
                break;
            }
        }
        self.final_output()
    }

    fn initialize_base(&mut self) -> Result<(), CompilerFailure> {
        for clause_index in 0..self.input.baseline_clauses.len() {
            let clause_id = ClauseId::new(to_u32(clause_index, None)?);
            let clause_ref = ClauseRef {
                id: clause_id,
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
        let variable = literal.unsigned_abs() as usize;
        match self.input.variable_atoms.get(variable)?.as_ref()? {
            BoolAtomKey::Eq(left, right) => {
                Some((literal > 0, EqualityKey::from_normalized(*left, *right)?))
            }
            BoolAtomKey::BoolTerm(_) => None,
        }
    }

    fn clause_slice(&self, clause: ClauseRef) -> Result<&[i32], CompilerFailure> {
        let index = clause.id.get() as usize;
        match clause.origin {
            ClauseOrigin::Baseline => {
                if index >= self.input.baseline_clauses.len() {
                    return Err(internal_invariant(None));
                }
                Ok(&self.input.baseline_clauses[index])
            }
            ClauseOrigin::Derived => {
                let base_count = self.input.baseline_clauses.len();
                let derived_index = index
                    .checked_sub(base_count)
                    .ok_or_else(|| internal_invariant(None))?;
                let meta = self
                    .derived_clauses
                    .get(derived_index)
                    .ok_or_else(|| internal_invariant(None))?;
                match self.trace.get(meta.trace_index) {
                    Some(TraceRecord::Conflict(record)) if record.clause_id == clause.id => {
                        Ok(record.clause.as_slice())
                    }
                    _ => Err(internal_invariant(None)),
                }
            }
        }
    }

    fn clause_depth_and_dependency(
        &self,
        clause: ClauseRef,
    ) -> Result<(ProofDepth, bool), CompilerFailure> {
        match clause.origin {
            ClauseOrigin::Baseline => Ok((ProofDepth::new(0), false)),
            ClauseOrigin::Derived => {
                let derived_index = (clause.id.get() as usize)
                    .checked_sub(self.input.baseline_clauses.len())
                    .ok_or_else(|| internal_invariant(None))?;
                let meta = self
                    .derived_clauses
                    .get(derived_index)
                    .ok_or_else(|| internal_invariant(None))?;
                if meta.id != clause.id {
                    return Err(internal_invariant(None));
                }
                Ok((meta.depth, meta.mechanism_dependency))
            }
        }
    }

    fn node_side(&self, node: NodeId) -> Result<&[i32], CompilerFailure> {
        let meta = self
            .nodes
            .get(node.get() as usize)
            .ok_or_else(|| internal_invariant(None))?;
        match self.trace.get(meta.trace_index) {
            Some(TraceRecord::Equality(record)) if record.node_id == node => {
                Ok(record.side_clause.as_slice())
            }
            _ => Err(internal_invariant(None)),
        }
    }

    fn attempt_seed(
        &mut self,
        source: ClausePivot,
        parent_event: Option<EventId>,
    ) -> Result<(), CompilerFailure> {
        let (side, conclusion, source_width) = {
            let clause = self.clause_slice(source.clause)?;
            let offset = source.literal_offset.get() as usize;
            let &literal = clause
                .get(offset)
                .ok_or_else(|| internal_invariant(parent_event))?;
            let Some((true, conclusion)) = self.equality_literal(literal) else {
                return Err(internal_invariant(parent_event));
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
    ) -> Result<(), CompilerFailure> {
        if self.input.term_dag.get(term).is_none() {
            return Err(internal_invariant(parent_event));
        }
        self.insert_candidate(
            RuleKind::Reflexivity,
            ProofDepth::new(0),
            Some(normalized_equality(term, term)),
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
    ) -> Result<(), CompilerFailure> {
        let first_meta = self
            .nodes
            .get(first.get() as usize)
            .ok_or_else(|| internal_invariant(Some(parent_event)))?;
        let second_meta = self
            .nodes
            .get(second.get() as usize)
            .ok_or_else(|| internal_invariant(Some(parent_event)))?;
        if !contains_endpoint(first_meta.conclusion, intermediate)
            || !contains_endpoint(second_meta.conclusion, intermediate)
        {
            return Err(internal_invariant(Some(parent_event)));
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
        let mut parents = [first, second];
        parents.sort_unstable();
        let key_parents = fallible_copy_slice(&parents, Some(parent_event))?;
        self.insert_candidate(
            RuleKind::Transitivity,
            depth,
            Some(normalized_equality(first_other, second_other)),
            side,
            None,
            key_parents,
            PendingEvent::Equality {
                rule: EqualityRuleRecord::Transitivity(TransitivityRecord {
                    parents,
                    intermediate,
                }),
                mechanism_dependency: first_meta.mechanism_dependency
                    || second_meta.mechanism_dependency,
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
    ) -> Result<(), CompilerFailure> {
        let (applications, requirement_count) = {
            let pair = self
                .application_pairs
                .get(pair_index)
                .ok_or_else(|| internal_invariant(Some(parent_event)))?;
            if pair.requirements.len() != parent_tuple.len() {
                return Err(internal_invariant(Some(parent_event)));
            }
            (pair.applications, pair.requirements.len())
        };
        let left = applications[0].term();
        let right = applications[1].term();
        let conclusion = normalized_equality(left, right);
        let mut mechanism_dependency = false;
        let mut maximum_parent_depth = 0u32;
        let mut side_width_sum = 0u64;
        for (position, &parent) in parent_tuple.iter().enumerate() {
            let required = self
                .application_pairs
                .get(pair_index)
                .and_then(|pair| pair.requirements.get(position))
                .map(|requirement| requirement.1)
                .ok_or_else(|| internal_invariant(Some(parent_event)))?;
            let meta = self
                .nodes
                .get(parent.get() as usize)
                .ok_or_else(|| internal_invariant(Some(parent_event)))?;
            if meta.conclusion != required {
                return Err(internal_invariant(Some(parent_event)));
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
            .try_reserve_exact(requirement_count)
            .map_err(|_| allocation_failure(Some(parent_event)))?;
        for (position, &parent) in parent_tuple.iter().enumerate() {
            let argument_index = self
                .application_pairs
                .get(pair_index)
                .and_then(|pair| pair.requirements.get(position))
                .map(|requirement| requirement.0)
                .ok_or_else(|| internal_invariant(Some(parent_event)))?;
            associations.push(CongruenceArgumentParent {
                argument_index,
                parent,
            });
        }
        let mut key_parents = Vec::new();
        key_parents
            .try_reserve_exact(parent_tuple.len())
            .map_err(|_| allocation_failure(Some(parent_event)))?;
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
    ) -> Result<bool, CompilerFailure> {
        let pair = self
            .application_pairs
            .get(pair_index)
            .ok_or_else(|| internal_invariant(Some(parent_event)))?;
        let conclusion =
            normalized_equality(pair.applications[0].term(), pair.applications[1].term());
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
    ) -> Result<(), CompilerFailure> {
        let node = self
            .nodes
            .get(equality_parent.get() as usize)
            .ok_or_else(|| internal_invariant(parent_event))?;
        let (source_side, source_width_without_pivot, source_depth, source_dependency) = {
            let clause = self.clause_slice(negative_source.clause)?;
            let offset = negative_source.literal_offset.get() as usize;
            let &literal = clause
                .get(offset)
                .ok_or_else(|| internal_invariant(parent_event))?;
            let Some((false, conclusion)) = self.equality_literal(literal) else {
                return Err(internal_invariant(parent_event));
            };
            if conclusion != node.conclusion {
                return Err(internal_invariant(parent_event));
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
                u64::from(node.depth.get().max(source_depth.get())),
                1,
                parent_event,
            )?,
            parent_event,
        )?);
        let key_parents =
            fallible_copy_slice(std::slice::from_ref(&equality_parent), parent_event)?;
        self.insert_candidate(
            RuleKind::Conflict,
            depth,
            None,
            side,
            Some(negative_source),
            key_parents,
            PendingEvent::Conflict {
                rule: ConflictRecord {
                    equality_parent,
                    negative_source,
                },
                mechanism_dependency: node.mechanism_dependency || source_dependency,
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
    ) -> Result<(), CompilerFailure> {
        let boundary = CapBoundary::ChildInsertion { parent_event, rule };
        if u64::from(depth.get()) > self.limits.proof_depth {
            return Err(cap_failure(
                CapReason::ProofDepth,
                boundary,
                self.counters.search.maximum_proof_depth,
                u64::from(depth.get()),
                self.limits.proof_depth,
            ));
        }
        let prospective_work = checked_add(
            self.counters.search.canonical_proof_work_literal_charge,
            proof_work_charge,
            parent_event,
        )?;
        if prospective_work > self.limits.canonical_proof_work_literal_charge {
            return Err(cap_failure(
                CapReason::CanonicalProofWorkLiteralCharge,
                boundary,
                self.counters.search.canonical_proof_work_literal_charge,
                prospective_work,
                self.limits.canonical_proof_work_literal_charge,
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
        let resulting_clause_width = to_u32(clause.len(), parent_event)?;
        let key = EventKey {
            resulting_clause_width,
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
        if prospective_pushes > self.limits.worklist_pushes {
            return Err(cap_failure(
                CapReason::WorklistPushes,
                boundary,
                self.counters.search.worklist_pushes,
                prospective_pushes,
                self.limits.worklist_pushes,
            ));
        }
        let prospective_live =
            checked_add(self.counters.search.live_worklist_entries, 1, parent_event)?;
        if prospective_live > self.limits.live_worklist_entries {
            return Err(cap_failure(
                CapReason::LiveWorklistEntries,
                boundary,
                self.counters.search.live_worklist_entries,
                prospective_live,
                self.limits.live_worklist_entries,
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
        if prospective_memory > self.limits.logical_incremental_memory_bytes {
            return Err(cap_failure(
                CapReason::LogicalIncrementalMemoryBytes,
                boundary,
                self.counters.search.logical_incremental_memory_bytes,
                prospective_memory,
                self.limits.logical_incremental_memory_bytes,
            ));
        }

        self.inserted_event_keys
            .try_reserve(1)
            .map_err(|_| allocation_failure(parent_event))?;
        self.worklist
            .try_reserve(1)
            .map_err(|_| allocation_failure(parent_event))?;
        let key_for_set = clone_event_key(&key, parent_event)?;
        if !self.inserted_event_keys.insert(key_for_set) {
            return Err(internal_invariant(parent_event));
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
    ) -> Result<bool, CompilerFailure> {
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
    ) -> Result<(), CompilerFailure> {
        let conclusion = key
            .conclusion
            .ok_or_else(|| internal_invariant(Some(event_id)))?;
        let mut retained = match self.retained_supports.get(&conclusion) {
            Some(nodes) => fallible_copy_slice(nodes, Some(event_id))?,
            None => Vec::new(),
        };
        retained.retain(|node| {
            self.nodes
                .get(node.get() as usize)
                .is_some_and(|node| node.active)
        });
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
            .map_err(|_| allocation_failure(Some(event_id)))?;
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
            if prospective_work > self.limits.canonical_proof_work_literal_charge {
                return Err(cap_failure(
                    CapReason::CanonicalProofWorkLiteralCharge,
                    boundary,
                    self.counters.search.canonical_proof_work_literal_charge,
                    prospective_work,
                    self.limits.canonical_proof_work_literal_charge,
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
            .ok_or_else(|| internal_invariant(Some(event_id)))?;
        if to_u64(retained_after_removal, Some(event_id))?
            >= self.limits.retained_side_clauses_per_equality
        {
            if prospective_work > self.limits.canonical_proof_work_literal_charge {
                return Err(cap_failure(
                    CapReason::CanonicalProofWorkLiteralCharge,
                    boundary,
                    self.counters.search.canonical_proof_work_literal_charge,
                    prospective_work,
                    self.limits.canonical_proof_work_literal_charge,
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
        if prospective_nodes > self.limits.equality_proof_nodes {
            return Err(cap_failure(
                CapReason::EqualityProofNodes,
                boundary,
                self.counters.search.accepted_equality_nodes,
                prospective_nodes,
                self.limits.equality_proof_nodes,
            ));
        }
        let prospective_parents = checked_add(
            self.counters.search.proof_parent_references,
            parent_references,
            Some(event_id),
        )?;
        if prospective_parents > self.limits.proof_parent_references {
            return Err(cap_failure(
                CapReason::ProofParentReferences,
                boundary,
                self.counters.search.proof_parent_references,
                prospective_parents,
                self.limits.proof_parent_references,
            ));
        }
        let prospective_depth = self
            .counters
            .search
            .maximum_proof_depth
            .max(u64::from(key.proof_depth.get()));
        if prospective_depth > self.limits.proof_depth {
            return Err(cap_failure(
                CapReason::ProofDepth,
                boundary,
                self.counters.search.maximum_proof_depth,
                prospective_depth,
                self.limits.proof_depth,
            ));
        }
        if prospective_work > self.limits.canonical_proof_work_literal_charge {
            return Err(cap_failure(
                CapReason::CanonicalProofWorkLiteralCharge,
                boundary,
                self.counters.search.canonical_proof_work_literal_charge,
                prospective_work,
                self.limits.canonical_proof_work_literal_charge,
            ));
        }
        let prospective_slots = checked_add(
            self.counters.search.accepted_trace_literal_slots,
            to_u64(key.clause.len(), Some(event_id))?,
            Some(event_id),
        )?;
        if prospective_slots > self.limits.all_derived_literal_slots {
            return Err(cap_failure(
                CapReason::AllDerivedLiteralSlots,
                boundary,
                self.counters.search.accepted_trace_literal_slots,
                prospective_slots,
                self.limits.all_derived_literal_slots,
            ));
        }
        let prospective_retained = checked_add(
            self.counters
                .search
                .retained_antichain_entries
                .checked_sub(to_u64(removed.len(), Some(event_id))?)
                .ok_or_else(|| internal_invariant(Some(event_id)))?,
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
        if prospective_memory > self.limits.logical_incremental_memory_bytes {
            return Err(cap_failure(
                CapReason::LogicalIncrementalMemoryBytes,
                boundary,
                self.counters.search.logical_incremental_memory_bytes,
                prospective_memory,
                self.limits.logical_incremental_memory_bytes,
            ));
        }

        self.reserve_equality_acceptance(conclusion, &removed, Some(event_id))?;
        let node_id = NodeId::new(to_u32(self.nodes.len(), Some(event_id))?);
        for removed_node in &removed {
            self.nodes
                .get_mut(removed_node.get() as usize)
                .ok_or_else(|| internal_invariant(Some(event_id)))?
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
            .ok_or_else(|| internal_invariant(Some(event_id)))?
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
        _removed: &[NodeId],
        event_id: Option<EventId>,
    ) -> Result<(), CompilerFailure> {
        self.trace
            .try_reserve(1)
            .map_err(|_| allocation_failure(event_id))?;
        self.nodes
            .try_reserve(1)
            .map_err(|_| allocation_failure(event_id))?;
        ensure_vec_map_entry(&mut self.retained_supports, conclusion, event_id)?;
        self.retained_supports
            .get_mut(&conclusion)
            .ok_or_else(|| internal_invariant(event_id))?
            .try_reserve(1)
            .map_err(|_| allocation_failure(event_id))?;
        let (left, right) = conclusion.endpoints();
        ensure_vec_map_entry(&mut self.endpoint_index, left, event_id)?;
        self.endpoint_index
            .get_mut(&left)
            .ok_or_else(|| internal_invariant(event_id))?
            .try_reserve(if left == right { 1 } else { 2 })
            .map_err(|_| allocation_failure(event_id))?;
        if left != right {
            ensure_vec_map_entry(&mut self.endpoint_index, right, event_id)?;
            self.endpoint_index
                .get_mut(&right)
                .ok_or_else(|| internal_invariant(event_id))?
                .try_reserve(1)
                .map_err(|_| allocation_failure(event_id))?;
        }
        Ok(())
    }

    fn index_endpoint_node(
        &mut self,
        node: NodeId,
        conclusion: EqualityKey,
        event_id: Option<EventId>,
    ) -> Result<(), CompilerFailure> {
        let (left, right) = conclusion.endpoints();
        self.endpoint_index
            .get_mut(&left)
            .ok_or_else(|| internal_invariant(event_id))?
            .push(EndpointAssociation {
                node,
                other: right,
                orientation: 0,
            });
        if left != right {
            self.endpoint_index
                .get_mut(&right)
                .ok_or_else(|| internal_invariant(event_id))?
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
    ) -> Result<bool, CompilerFailure> {
        if key.conclusion.is_some() {
            return Err(internal_invariant(Some(event_id)));
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
        if prospective_parents > self.limits.proof_parent_references {
            return Err(cap_failure(
                CapReason::ProofParentReferences,
                boundary,
                self.counters.search.proof_parent_references,
                prospective_parents,
                self.limits.proof_parent_references,
            ));
        }
        let prospective_depth = self
            .counters
            .search
            .maximum_proof_depth
            .max(u64::from(key.proof_depth.get()));
        if prospective_depth > self.limits.proof_depth {
            return Err(cap_failure(
                CapReason::ProofDepth,
                boundary,
                self.counters.search.maximum_proof_depth,
                prospective_depth,
                self.limits.proof_depth,
            ));
        }
        let prospective_clauses = checked_add(
            self.counters.search.accepted_conflict_clauses,
            1,
            Some(event_id),
        )?;
        if prospective_clauses > self.limits.unique_derived_clauses {
            return Err(cap_failure(
                CapReason::UniqueDerivedClauses,
                boundary,
                self.counters.search.accepted_conflict_clauses,
                prospective_clauses,
                self.limits.unique_derived_clauses,
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
        if prospective_work > self.limits.canonical_proof_work_literal_charge {
            return Err(cap_failure(
                CapReason::CanonicalProofWorkLiteralCharge,
                boundary,
                self.counters.search.canonical_proof_work_literal_charge,
                prospective_work,
                self.limits.canonical_proof_work_literal_charge,
            ));
        }
        let prospective_slots = checked_add(
            self.counters.search.accepted_trace_literal_slots,
            to_u64(key.clause.len(), Some(event_id))?,
            Some(event_id),
        )?;
        if prospective_slots > self.limits.all_derived_literal_slots {
            return Err(cap_failure(
                CapReason::AllDerivedLiteralSlots,
                boundary,
                self.counters.search.accepted_trace_literal_slots,
                prospective_slots,
                self.limits.all_derived_literal_slots,
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
        if prospective_memory > self.limits.logical_incremental_memory_bytes {
            return Err(cap_failure(
                CapReason::LogicalIncrementalMemoryBytes,
                boundary,
                self.counters.search.logical_incremental_memory_bytes,
                prospective_memory,
                self.limits.logical_incremental_memory_bytes,
            ));
        }

        self.trace
            .try_reserve(1)
            .map_err(|_| allocation_failure(Some(event_id)))?;
        self.derived_clauses
            .try_reserve(1)
            .map_err(|_| allocation_failure(Some(event_id)))?;
        self.global_clauses
            .try_reserve(1)
            .map_err(|_| allocation_failure(Some(event_id)))?;
        let clause_number = self
            .input
            .baseline_clauses
            .len()
            .checked_add(self.derived_clauses.len())
            .ok_or_else(|| integer_overflow(Some(event_id)))?;
        let clause_id = ClauseId::new(to_u32(clause_number, Some(event_id))?);
        let clause_for_set = clone_canonical_clause(&key.clause, Some(event_id))?;
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
        if !self.global_clauses.insert(clause_for_set) {
            return Err(internal_invariant(Some(event_id)));
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
    ) -> Result<(), CompilerFailure> {
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
                .map_err(|_| allocation_failure(Some(parent_event)))?;
            positives
                .try_reserve(clause.len())
                .map_err(|_| allocation_failure(Some(parent_event)))?;
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
    ) -> Result<(), CompilerFailure> {
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
        let boundary = CapBoundary::NegativeRegistration(source);
        if prospective_memory > self.limits.logical_incremental_memory_bytes {
            return Err(cap_failure(
                CapReason::LogicalIncrementalMemoryBytes,
                boundary,
                self.counters.search.logical_incremental_memory_bytes,
                prospective_memory,
                self.limits.logical_incremental_memory_bytes,
            ));
        }
        ensure_vec_map_entry(&mut self.negative_index, equality, parent_event)?;
        self.negative_index
            .get_mut(&equality)
            .ok_or_else(|| internal_invariant(parent_event))?
            .try_reserve(1)
            .map_err(|_| allocation_failure(parent_event))?;
        self.negative_index
            .get_mut(&equality)
            .ok_or_else(|| internal_invariant(parent_event))?
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
    ) -> Result<Vec<NodeId>, CompilerFailure> {
        let mut nodes = Vec::new();
        if let Some(retained) = self.retained_supports.get(&equality) {
            nodes
                .try_reserve(retained.len())
                .map_err(|_| allocation_failure(event_id))?;
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
    ) -> Result<(), CompilerFailure> {
        let joins = self.ordered_transitivity_candidates(new_node, parent_event)?;
        for join in joins {
            let other_node = join.other_node;
            let intermediate = join.intermediate;
            let conclusion = self
                .nodes
                .get(other_node.get() as usize)
                .ok_or_else(|| internal_invariant(Some(parent_event)))?
                .conclusion;
            if conclusion != join.other_conclusion {
                return Err(internal_invariant(Some(parent_event)));
            }
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
                .map_err(|_| allocation_failure(Some(parent_event)))?;
            if !self.transitivity_joins.insert(join_key) {
                return Err(internal_invariant(Some(parent_event)));
            }
            self.attempt_transitivity(
                new_node,
                other_node,
                intermediate,
                join.new_other,
                join.other,
                parent_event,
            )?;
        }
        Ok(())
    }

    fn ordered_transitivity_candidates(
        &self,
        new_node: NodeId,
        parent_event: EventId,
    ) -> Result<Vec<TransitivityJoinCandidate>, CompilerFailure> {
        let conclusion = self
            .nodes
            .get(new_node.get() as usize)
            .ok_or_else(|| internal_invariant(Some(parent_event)))?
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
                .map_err(|_| allocation_failure(Some(parent_event)))?;
            for association in associations {
                let Some(other_meta) = self.nodes.get(association.node.get() as usize) else {
                    return Err(internal_invariant(Some(parent_event)));
                };
                if !other_meta.active {
                    continue;
                }
                joins.push(TransitivityJoinCandidate {
                    other_conclusion: other_meta.conclusion,
                    other_node: association.node,
                    orientation: association.orientation,
                    intermediate,
                    new_other,
                    other: association.other,
                });
            }
        }
        joins.sort_unstable_by(|first, second| {
            first
                .other_conclusion
                .cmp(&second.other_conclusion)
                .then_with(|| first.other_node.cmp(&second.other_node))
                .then_with(|| first.orientation.cmp(&second.orientation))
                .then_with(|| first.intermediate.cmp(&second.intermediate))
        });
        Ok(joins)
    }

    fn generate_congruence_children(
        &mut self,
        new_node: NodeId,
        parent_event: EventId,
    ) -> Result<(), CompilerFailure> {
        let conclusion = self
            .nodes
            .get(new_node.get() as usize)
            .ok_or_else(|| internal_invariant(Some(parent_event)))?
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
                .ok_or_else(|| internal_invariant(Some(parent_event)))?;
            if previous_pair == Some(pair_index) {
                continue;
            }
            previous_pair = Some(pair_index);

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
                .ok_or_else(|| internal_invariant(Some(parent_event)))?;
            let mut choices = Vec::new();
            choices
                .try_reserve_exact(requirement_count)
                .map_err(|_| allocation_failure(Some(parent_event)))?;
            let mut complete = true;
            for requirement_position in 0..requirement_count {
                let equality = self
                    .application_pairs
                    .get(pair_index)
                    .and_then(|pair| pair.requirements.get(requirement_position))
                    .map(|requirement| requirement.1)
                    .ok_or_else(|| internal_invariant(Some(parent_event)))?;
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
                .map_err(|_| allocation_failure(Some(parent_event)))?;
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
    ) -> Result<u64, CompilerFailure> {
        let pair = self
            .application_pairs
            .get(pair_index)
            .ok_or_else(|| internal_invariant(Some(parent_event)))?;
        let new_conclusion = self
            .nodes
            .get(new_node.get() as usize)
            .filter(|node| node.active)
            .map(|node| node.conclusion)
            .ok_or_else(|| internal_invariant(Some(parent_event)))?;
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
                return Err(internal_invariant(Some(parent_event)));
            }
            all_tuples = checked_mul(all_tuples, active, Some(parent_event))?;
            tuples_without_new = checked_mul(
                tuples_without_new,
                active - u64::from(contains_new),
                Some(parent_event),
            )?;
        }
        all_tuples
            .checked_sub(tuples_without_new)
            .ok_or_else(|| internal_invariant(Some(parent_event)))
    }

    fn enumerate_congruence_tuples(
        &mut self,
        pair_index: usize,
        choices: &[Vec<NodeId>],
        position: usize,
        tuple: &mut Vec<NodeId>,
        new_node: NodeId,
        directly_missing: bool,
        parent_event: EventId,
    ) -> Result<(), CompilerFailure> {
        if position == choices.len() {
            if !tuple.contains(&new_node) {
                return Ok(());
            }
            let mut tuple_parents = Vec::new();
            tuple_parents
                .try_reserve_exact(tuple.len())
                .map_err(|_| allocation_failure(Some(parent_event)))?;
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
                .map_err(|_| allocation_failure(Some(parent_event)))?;
            if !self.congruence_tuples.insert(tuple_key) {
                return Err(internal_invariant(Some(parent_event)));
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
    ) -> Result<(), CompilerFailure> {
        let conclusion = self
            .nodes
            .get(new_node.get() as usize)
            .ok_or_else(|| internal_invariant(Some(parent_event)))?
            .conclusion;
        let occurrences = match self.negative_index.get(&conclusion) {
            Some(occurrences) => fallible_copy_slice(occurrences, Some(parent_event))?,
            None => Vec::new(),
        };
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
    ) -> Result<u64, CompilerFailure> {
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

    fn final_output(&mut self) -> Result<EqresOutput, CompilerFailure> {
        if let Some(terminal) = self.terminal_empty.take() {
            let emitted = 1;
            self.check_final_limits(emitted, 0, 0, 0)?;
            self.counters.output.emitted_lemmas = emitted;
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
            .map_err(|_| allocation_failure(None))?;
        for meta in &self.derived_clauses {
            let Some(TraceRecord::Conflict(record)) = self.trace.get(meta.trace_index) else {
                return Err(internal_invariant(None));
            };
            if record.clause.is_empty() {
                return Err(internal_invariant(None));
            }
            candidates.push(OutputCandidate {
                source_clause_id: meta.id,
                clause: clone_canonical_clause(&record.clause, None)?,
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
            .map_err(|_| allocation_failure(None))?;
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
            .map_err(|_| allocation_failure(None))?;
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
            let index = usize::try_from(rank.checked_sub(1).ok_or_else(|| integer_overflow(None))?)
                .map_err(|_| integer_overflow(None))?;
            (
                *widths.get(index).ok_or_else(|| internal_invariant(None))?,
                *widths.last().ok_or_else(|| internal_invariant(None))?,
            )
        };
        self.check_final_limits(emitted, slots, p95, maximum)?;
        self.commit_final_output_with(
            retained,
            emitted,
            slots,
            p95,
            maximum,
            mechanism_count,
            materialize_output_candidates,
        )
    }

    fn commit_final_output_with<F>(
        &mut self,
        retained: Vec<OutputCandidate>,
        emitted: u64,
        slots: u64,
        p95: u64,
        maximum: u64,
        mechanism_count: u64,
        materialize: F,
    ) -> Result<EqresOutput, CompilerFailure>
    where
        F: FnOnce(Vec<OutputCandidate>) -> Result<EqresOutput, CompilerFailure>,
    {
        let output = materialize(retained)?;
        self.counters.output.emitted_lemmas = emitted;
        self.counters.output.emitted_literal_slots = slots;
        self.counters.output.emitted_p95_width = p95;
        self.counters.output.emitted_maximum_width = maximum;
        self.counters
            .output
            .emitted_with_missing_equality_congruence = mechanism_count;
        Ok(output)
    }

    fn check_final_limits(
        &self,
        emitted: u64,
        slots: u64,
        p95: u64,
        maximum: u64,
    ) -> Result<(), CompilerFailure> {
        let boundary = CapBoundary::FinalOutput;
        if emitted > self.limits.emitted_lemmas {
            return Err(cap_failure(
                CapReason::EmittedLemmas,
                boundary,
                0,
                emitted,
                self.limits.emitted_lemmas,
            ));
        }
        if slots > self.limits.emitted_lemma_literal_slots {
            return Err(cap_failure(
                CapReason::EmittedLemmaLiteralSlots,
                boundary,
                0,
                slots,
                self.limits.emitted_lemma_literal_slots,
            ));
        }
        if p95 > self.limits.emitted_p95_width {
            return Err(cap_failure(
                CapReason::EmittedP95Width,
                boundary,
                0,
                p95,
                self.limits.emitted_p95_width,
            ));
        }
        if maximum > self.limits.emitted_maximum_width {
            return Err(cap_failure(
                CapReason::EmittedMaximumWidth,
                boundary,
                0,
                maximum,
                self.limits.emitted_maximum_width,
            ));
        }
        Ok(())
    }

    fn verify_input_hashes(&self) -> Result<(), CompilerFailure> {
        let current = compute_input_hashes(self.input)?;
        let comparisons = [
            (
                self.input_hashes.source_sha256,
                current.source_sha256,
                HashArtifact::Source,
            ),
            (
                self.input_hashes.root_cnf_mode_sha256,
                current.root_cnf_mode_sha256,
                HashArtifact::RootCnfMode,
            ),
            (
                self.input_hashes.term_dag_sha256,
                current.term_dag_sha256,
                HashArtifact::TermDag,
            ),
            (
                self.input_hashes.atom_map_sha256,
                current.atom_map_sha256,
                HashArtifact::AtomMap,
            ),
            (
                self.input_hashes.baseline_cnf_sha256,
                current.baseline_cnf_sha256,
                HashArtifact::BaselineCnf,
            ),
            (
                self.input_hashes.baseline_problem_sha256,
                current.baseline_problem_sha256,
                HashArtifact::BaselineProblem,
            ),
        ];
        for (before, after, artifact) in comparisons {
            if before != after {
                return Err(CompilerFailure::HashDrift(artifact));
            }
        }
        Ok(())
    }

    fn finish(mut self, status: CompilerStatus) -> CompilerResult {
        self.input_hashes.trace_sha256 = hash_trace(&self.trace);
        let clause_sequence_hash = hash_status_clause_sequence(&status);
        self.input_hashes.lemma_sequence_sha256 = clause_sequence_hash;
        self.input_hashes.materialized_lemmas_sha256 = clause_sequence_hash;
        self.input_hashes.materialized_candidate_sha256 =
            hash_materialized_candidate(self.input, &status);
        CompilerResult {
            variant: self.variant,
            status,
            trace: self.trace.into_boxed_slice(),
            counters: self.counters,
            hashes: self.input_hashes,
        }
    }
}

fn materialize_output_candidates(
    retained: Vec<OutputCandidate>,
) -> Result<EqresOutput, CompilerFailure> {
    if retained.is_empty() {
        return Ok(EqresOutput::NoLemmas);
    }
    let mut lemmas = Vec::new();
    lemmas
        .try_reserve_exact(retained.len())
        .map_err(|_| allocation_failure(None))?;
    for candidate in retained {
        lemmas.push(EmittedLemma {
            source_clause_id: candidate.source_clause_id,
            clause: candidate.clause,
        });
    }
    Ok(EqresOutput::Lemmas(lemmas.into_boxed_slice()))
}

fn contains_endpoint(equality: EqualityKey, term: TermId) -> bool {
    equality.left() == term || equality.right() == term
}

fn normalized_equality(left: TermId, right: TermId) -> EqualityKey {
    let (left, right) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    EqualityKey::from_normalized(left, right).expect("locally normalized equality")
}

fn fallible_copy_slice<T: Copy>(
    source: &[T],
    event_id: Option<EventId>,
) -> Result<Vec<T>, CompilerFailure> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(source.len())
        .map_err(|_| allocation_failure(event_id))?;
    copy.extend_from_slice(source);
    Ok(copy)
}

fn clone_canonical_clause(
    clause: &CanonicalClause,
    event_id: Option<EventId>,
) -> Result<CanonicalClause, CompilerFailure> {
    CanonicalClause::from_sorted(fallible_copy_slice(clause.as_slice(), event_id)?)
        .map_err(|_| internal_invariant(event_id))
}

fn clone_event_key(key: &EventKey, event_id: Option<EventId>) -> Result<EventKey, CompilerFailure> {
    Ok(EventKey {
        resulting_clause_width: key.resulting_clause_width,
        proof_depth: key.proof_depth,
        rule: key.rule,
        conclusion: key.conclusion,
        clause: clone_canonical_clause(&key.clause, event_id)?,
        source: key.source,
        parents: fallible_copy_slice(&key.parents, event_id)?.into_boxed_slice(),
    })
}

fn canonicalize_one(
    literals: &[i32],
    event_id: Option<EventId>,
) -> Result<Option<CanonicalClause>, CompilerFailure> {
    canonicalize_parts(&[literals], event_id)
}

fn canonicalize_two(
    first: &[i32],
    second: &[i32],
    event_id: Option<EventId>,
) -> Result<Option<CanonicalClause>, CompilerFailure> {
    canonicalize_parts(&[first, second], event_id)
}

fn canonicalize_without(
    literals: &[i32],
    removed_offset: usize,
    event_id: Option<EventId>,
) -> Result<Option<CanonicalClause>, CompilerFailure> {
    if removed_offset >= literals.len() {
        return Err(internal_invariant(event_id));
    }
    let mut result = Vec::new();
    result
        .try_reserve(literals.len().saturating_sub(1))
        .map_err(|_| allocation_failure(event_id))?;
    result.extend_from_slice(&literals[..removed_offset]);
    result.extend_from_slice(&literals[(removed_offset + 1)..]);
    finish_canonicalization(result, event_id)
}

fn canonicalize_parts(
    parts: &[&[i32]],
    event_id: Option<EventId>,
) -> Result<Option<CanonicalClause>, CompilerFailure> {
    let mut length = 0usize;
    for part in parts {
        length = length
            .checked_add(part.len())
            .ok_or_else(|| integer_overflow(event_id))?;
    }
    let mut result = Vec::new();
    result
        .try_reserve(length)
        .map_err(|_| allocation_failure(event_id))?;
    for part in parts {
        result.extend_from_slice(part);
    }
    finish_canonicalization(result, event_id)
}

fn canonicalize_node_union(
    compiler: &Compiler<'_>,
    parents: &[NodeId],
    event_id: Option<EventId>,
) -> Result<Option<CanonicalClause>, CompilerFailure> {
    let mut length = 0usize;
    for &parent in parents {
        length = length
            .checked_add(compiler.node_side(parent)?.len())
            .ok_or_else(|| integer_overflow(event_id))?;
    }
    let mut result = Vec::new();
    result
        .try_reserve(length)
        .map_err(|_| allocation_failure(event_id))?;
    for &parent in parents {
        result.extend_from_slice(compiler.node_side(parent)?);
    }
    finish_canonicalization(result, event_id)
}

fn finish_canonicalization(
    mut literals: Vec<i32>,
    event_id: Option<EventId>,
) -> Result<Option<CanonicalClause>, CompilerFailure> {
    literals.sort_unstable();
    literals.dedup();
    if literals
        .iter()
        .any(|literal| literals.binary_search(&-*literal).is_ok())
    {
        return Ok(None);
    }
    CanonicalClause::from_sorted(literals)
        .map(Some)
        .map_err(|_| internal_invariant(event_id))
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
) -> Result<u64, CompilerFailure> {
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
) -> Result<(), CompilerFailure> {
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
) -> Result<(), CompilerFailure>
where
    K: Copy + Eq + std::hash::Hash,
{
    if !map.contains_key(&key) {
        map.try_reserve(1)
            .map_err(|_| allocation_failure(event_id))?;
        map.insert(key, Vec::new());
    }
    Ok(())
}

fn check_static_cap(reason: CapReason, value: u64, limit: u64) -> Result<(), CompilerFailure> {
    if value > limit {
        return Err(cap_failure(
            reason,
            CapBoundary::StaticInput,
            0,
            value,
            limit,
        ));
    }
    Ok(())
}

fn cap_failure(
    reason: CapReason,
    boundary: CapBoundary,
    pre_event_value: u64,
    prospective_value: u64,
    limit: u64,
) -> CompilerFailure {
    CompilerFailure::Cap(CapAttempt {
        reason,
        boundary,
        pre_event_value,
        prospective_value,
        limit,
    })
}

fn allocation_failure(event_id: Option<EventId>) -> CompilerFailure {
    CompilerFailure::AllocationFailure { event_id }
}

fn integer_overflow(event_id: Option<EventId>) -> CompilerFailure {
    CompilerFailure::IntegerOverflow { event_id }
}

fn internal_invariant(event_id: Option<EventId>) -> CompilerFailure {
    CompilerFailure::InternalInvariant { event_id }
}

fn checked_add(left: u64, right: u64, event_id: Option<EventId>) -> Result<u64, CompilerFailure> {
    left.checked_add(right)
        .ok_or_else(|| integer_overflow(event_id))
}

fn checked_mul(left: u64, right: u64, event_id: Option<EventId>) -> Result<u64, CompilerFailure> {
    left.checked_mul(right)
        .ok_or_else(|| integer_overflow(event_id))
}

fn to_u64(value: usize, event_id: Option<EventId>) -> Result<u64, CompilerFailure> {
    u64::try_from(value).map_err(|_| integer_overflow(event_id))
}

fn to_u32<T>(value: T, event_id: Option<EventId>) -> Result<u32, CompilerFailure>
where
    T: TryInto<u32>,
{
    value.try_into().map_err(|_| integer_overflow(event_id))
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
) -> Result<u64, CompilerFailure> {
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

// Compiler-local SHA-256.  The checker must implement its own encoder and hash.
#[derive(Clone)]
struct LocalSha256 {
    state: [u32; 8],
    length_bytes: u64,
    buffer: [u8; 64],
    buffer_len: usize,
}

impl LocalSha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            length_bytes: 0,
            buffer: [0; 64],
            buffer_len: 0,
        }
    }

    fn update(&mut self, mut bytes: &[u8]) {
        self.length_bytes = self
            .length_bytes
            .checked_add(bytes.len() as u64)
            .expect("validated T11 hash input length");
        if self.buffer_len != 0 {
            let copied = (64 - self.buffer_len).min(bytes.len());
            self.buffer[self.buffer_len..self.buffer_len + copied]
                .copy_from_slice(&bytes[..copied]);
            self.buffer_len += copied;
            bytes = &bytes[copied..];
            if self.buffer_len < 64 {
                return;
            }
            let block = self.buffer;
            self.compress(&block);
            self.buffer_len = 0;
        }
        while bytes.len() >= 64 {
            let block: &[u8; 64] = bytes[..64].try_into().expect("64-byte SHA-256 block");
            self.compress(block);
            bytes = &bytes[64..];
        }
        self.buffer[..bytes.len()].copy_from_slice(bytes);
        self.buffer_len = bytes.len();
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
            schedule[index] = u32::from_be_bytes(chunk.try_into().expect("four-byte word"));
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

    fn finalize(mut self) -> Sha256Digest {
        let bit_length = self
            .length_bytes
            .checked_mul(8)
            .expect("SHA-256 bit length");
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0; 64];
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..].copy_from_slice(&bit_length.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut bytes = [0u8; 32];
        for (chunk, word) in bytes.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        Sha256Digest::new(bytes)
    }
}

fn hash_u8(hash: &mut LocalSha256, value: u8) {
    hash.update(&[value]);
}

fn hash_u32(hash: &mut LocalSha256, value: u32) {
    hash.update(&value.to_be_bytes());
}

fn hash_u64(hash: &mut LocalSha256, value: u64) {
    hash.update(&value.to_be_bytes());
}

fn hash_i32(hash: &mut LocalSha256, value: i32) {
    hash.update(&value.to_be_bytes());
}

fn hash_usize(hash: &mut LocalSha256, value: usize) {
    hash_u64(hash, value as u64);
}

fn hash_bytes(hash: &mut LocalSha256, bytes: &[u8]) {
    hash_usize(hash, bytes.len());
    hash.update(bytes);
}

fn domain_hash(domain: &[u8], encode: impl FnOnce(&mut LocalSha256)) -> Sha256Digest {
    let mut hash = LocalSha256::new();
    hash.update(domain);
    encode(&mut hash);
    hash.finalize()
}

fn raw_hash(bytes: &[u8]) -> Sha256Digest {
    let mut hash = LocalSha256::new();
    hash.update(bytes);
    hash.finalize()
}

fn compute_input_hashes(input: EqresInput<'_>) -> Result<HashBindings, CompilerFailure> {
    let source_sha256 = raw_hash(input.source_bytes);
    let root_cnf_mode_sha256 = raw_hash(input.root_cnf_mode);
    let term_dag_sha256 = hash_term_dag(input)?;
    let atom_map_sha256 = domain_hash(b"euf-viper-t10-baseline-atom-map-v1\0", |hash| {
        encode_atom_map(hash, input)
    });
    let baseline_cnf_sha256 = domain_hash(b"euf-viper-t10-baseline-cnf-v1\0", |hash| {
        encode_flat_clause_store(hash, input)
    });
    let baseline_problem_sha256 = domain_hash(b"euf-viper-t10-baseline-problem-v1\0", |hash| {
        encode_flat_clause_store(hash, input);
        encode_atom_map(hash, input);
    });
    Ok(HashBindings {
        source_sha256,
        root_cnf_mode_sha256,
        term_dag_sha256,
        atom_map_sha256,
        baseline_cnf_sha256,
        baseline_problem_sha256,
        ..HashBindings::default()
    })
}

fn hash_term_dag(input: EqresInput<'_>) -> Result<Sha256Digest, CompilerFailure> {
    let mut sort_ids = Vec::new();
    sort_ids
        .try_reserve(input.sorts.ids.len())
        .map_err(|_| allocation_failure(None))?;
    sort_ids.extend(
        input
            .sorts
            .ids
            .iter()
            .map(|(&symbol, &sort)| (symbol, sort.0)),
    );
    sort_ids.sort_unstable();
    Ok(domain_hash(b"euf-viper-t11-term-dag-v1\0", |hash| {
        hash_usize(hash, input.sorts.names.len());
        for name in &input.sorts.names {
            hash_bytes(hash, name.as_bytes());
        }
        hash_usize(hash, sort_ids.len());
        for &(symbol, sort) in &sort_ids {
            hash_u32(hash, symbol);
            hash_u32(hash, sort);
        }
        hash_usize(hash, input.declarations.slots.len());
        for declaration in &input.declarations.slots {
            match declaration {
                None => hash_u8(hash, 0),
                Some(declaration) => {
                    hash_u8(hash, 1);
                    hash_u32(hash, declaration.result_sort.0);
                    hash_usize(hash, declaration.arg_sorts.len());
                    for sort in &declaration.arg_sorts {
                        hash_u32(hash, sort.0);
                    }
                }
            }
        }
        hash_usize(hash, input.term_dag.len());
        for (term_id, term) in input.term_dag.iter().enumerate() {
            hash_usize(hash, term_id);
            hash_u32(hash, term.fun);
            hash_u32(hash, term.sort.0);
            hash_usize(hash, term.args.len());
            for &argument in &term.args {
                hash_usize(hash, argument);
            }
        }
        hash_usize(hash, input.ordered_applications.len());
        for &application in input.ordered_applications {
            hash_usize(hash, application);
        }
    }))
}

fn encode_atom(hash: &mut LocalSha256, atom: &BoolAtomKey) {
    match atom {
        BoolAtomKey::Eq(left, right) => {
            hash_u8(hash, 1);
            hash_usize(hash, *left);
            hash_usize(hash, *right);
        }
        BoolAtomKey::BoolTerm(term) => {
            hash_u8(hash, 2);
            hash_usize(hash, *term);
        }
    }
}

fn encode_atom_map(hash: &mut LocalSha256, input: EqresInput<'_>) {
    hash_usize(hash, input.variable_atoms.len());
    for atom in input.variable_atoms {
        match atom {
            None => hash_u8(hash, 0),
            Some(atom) => {
                hash_u8(hash, 1);
                encode_atom(hash, atom);
                match input.atom_variables.get(atom) {
                    Some(&reverse) => {
                        hash_u8(hash, 1);
                        hash_i32(hash, reverse);
                    }
                    None => hash_u8(hash, 0),
                }
            }
        }
    }
    hash_usize(hash, input.atom_variables.len());
    match input.true_literal {
        Some(literal) => {
            hash_u8(hash, 1);
            hash_i32(hash, literal);
        }
        None => hash_u8(hash, 0),
    }
    hash_u8(hash, u8::from(input.finite_equalities_complete));
    hash_u8(hash, u8::from(input.finite_predicate_congruence_complete));
}

fn encode_flat_clause_store(hash: &mut LocalSha256, input: EqresInput<'_>) {
    hash_usize(hash, input.baseline_clauses.end_offsets.len());
    for &offset in &input.baseline_clauses.end_offsets {
        hash_u32(hash, offset);
    }
    hash_usize(hash, input.baseline_clauses.literals.len());
    for &literal in &input.baseline_clauses.literals {
        hash_i32(hash, literal);
    }
}

fn hash_clause(hash: &mut LocalSha256, clause: &CanonicalClause) {
    hash_usize(hash, clause.len());
    for &literal in clause.as_slice() {
        hash_i32(hash, literal);
    }
}

fn hash_equality(hash: &mut LocalSha256, equality: EqualityKey) {
    hash_usize(hash, equality.left());
    hash_usize(hash, equality.right());
}

fn hash_clause_ref(hash: &mut LocalSha256, source: ClausePivot) {
    hash_u32(hash, source.clause.id.get());
    hash_u8(
        hash,
        match source.clause.origin {
            ClauseOrigin::Baseline => 0,
            ClauseOrigin::Derived => 1,
        },
    );
    hash_u32(hash, source.literal_offset.get());
}

fn hash_trace(trace: &[TraceRecord]) -> Sha256Digest {
    domain_hash(b"euf-viper-t11-trace-v1\0", |hash| {
        hash_usize(hash, trace.len());
        for record in trace {
            match record {
                TraceRecord::Equality(record) => {
                    hash_u8(hash, 1);
                    hash_u32(hash, record.event_id.get());
                    hash_u32(hash, record.node_id.get());
                    hash_u32(hash, record.depth.get());
                    hash_equality(hash, record.conclusion);
                    hash_clause(hash, &record.side_clause);
                    match &record.rule {
                        EqualityRuleRecord::Seed(seed) => {
                            hash_u8(hash, RuleKind::Seed as u8);
                            hash_clause_ref(hash, seed.positive_source);
                        }
                        EqualityRuleRecord::Reflexivity(reflexivity) => {
                            hash_u8(hash, RuleKind::Reflexivity as u8);
                            hash_usize(hash, reflexivity.term);
                        }
                        EqualityRuleRecord::Transitivity(transitivity) => {
                            hash_u8(hash, RuleKind::Transitivity as u8);
                            for parent in transitivity.parents {
                                hash_u32(hash, parent.get());
                            }
                            hash_usize(hash, transitivity.intermediate);
                        }
                        EqualityRuleRecord::Congruence(congruence) => {
                            hash_u8(hash, RuleKind::Congruence as u8);
                            for application in congruence.applications {
                                hash_usize(hash, application.term());
                            }
                            hash_usize(hash, congruence.arguments.len());
                            for argument in &congruence.arguments {
                                hash_u32(hash, argument.argument_index.get());
                                hash_u32(hash, argument.parent.get());
                            }
                        }
                    }
                }
                TraceRecord::Conflict(record) => {
                    hash_u8(hash, 2);
                    hash_u32(hash, record.event_id.get());
                    hash_u32(hash, record.clause_id.get());
                    hash_u32(hash, record.depth.get());
                    hash_clause(hash, &record.clause);
                    hash_u8(hash, RuleKind::Conflict as u8);
                    hash_u32(hash, record.rule.equality_parent.get());
                    hash_clause_ref(hash, record.rule.negative_source);
                }
            }
        }
    })
}

fn encode_status_clause_sequence(hash: &mut LocalSha256, status: &CompilerStatus) {
    match status {
        CompilerStatus::NotRun | CompilerStatus::Rejected(_) => hash_usize(hash, 0),
        CompilerStatus::Completed(EqresOutput::NoLemmas) => hash_usize(hash, 0),
        CompilerStatus::Completed(EqresOutput::Lemmas(lemmas)) => {
            hash_usize(hash, lemmas.len());
            for lemma in lemmas {
                hash_clause(hash, &lemma.clause);
            }
        }
        CompilerStatus::Completed(EqresOutput::TheoryEmpty { lemma, .. }) => {
            hash_usize(hash, 1);
            hash_clause(hash, &lemma.clause);
        }
    }
}

fn hash_status_clause_sequence(status: &CompilerStatus) -> Sha256Digest {
    domain_hash(b"euf-viper-t11-lemma-clause-sequence-v1\0", |hash| {
        encode_status_clause_sequence(hash, status)
    })
}

fn hash_materialized_candidate(input: EqresInput<'_>, status: &CompilerStatus) -> Sha256Digest {
    domain_hash(b"euf-viper-t11-materialized-candidate-v1\0", |hash| {
        encode_flat_clause_store(hash, input);
        encode_status_clause_sequence(hash, status);
        encode_atom_map(hash, input);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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
            let mut sort_ids = FxHashMap::default();
            sort_ids.insert(0, DATA_SORT);
            Self {
                sorts: SortTable {
                    ids: sort_ids,
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

        fn declaration(&mut self, arguments: Vec<SortId>) -> u32 {
            let function = self.declarations.slots.len() as u32;
            self.declarations.insert(
                function,
                FunDecl {
                    arg_sorts: arguments,
                    result_sort: DATA_SORT,
                },
            );
            function
        }

        fn constant(&mut self) -> TermId {
            let function = self.declaration(Vec::new());
            let id = self.terms.len();
            self.terms.push(Term {
                fun: function,
                args: Vec::new(),
                sort: DATA_SORT,
            });
            id
        }

        fn unary_pair(
            &mut self,
            left_argument: TermId,
            right_argument: TermId,
        ) -> (TermId, TermId) {
            let function = self.declaration(vec![DATA_SORT]);
            let left = self.terms.len();
            self.terms.push(Term {
                fun: function,
                args: vec![left_argument],
                sort: DATA_SORT,
            });
            self.applications.push(left);
            let right = self.terms.len();
            self.terms.push(Term {
                fun: function,
                args: vec![right_argument],
                sort: DATA_SORT,
            });
            self.applications.push(right);
            (left, right)
        }

        fn repeated_binary_pair(
            &mut self,
            left_argument: TermId,
            right_argument: TermId,
        ) -> (TermId, TermId) {
            let function = self.declaration(vec![DATA_SORT, DATA_SORT]);
            let left = self.terms.len();
            self.terms.push(Term {
                fun: function,
                args: vec![left_argument, left_argument],
                sort: DATA_SORT,
            });
            self.applications.push(left);
            let right = self.terms.len();
            self.terms.push(Term {
                fun: function,
                args: vec![right_argument, right_argument],
                sort: DATA_SORT,
            });
            self.applications.push(right);
            (left, right)
        }

        fn equality(&mut self, left: TermId, right: TermId) -> i32 {
            let equality = normalized_equality(left, right);
            let atom = BoolAtomKey::Eq(equality.left(), equality.right());
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
            self.clauses.push(literals);
        }

        fn build(self) -> Fixture {
            Fixture {
                source: b"synthetic-t11".to_vec(),
                root_mode: b"direct-root-test-v1".to_vec(),
                sorts: self.sorts,
                declarations: self.declarations,
                terms: self.terms,
                applications: self.applications,
                clauses: self.clauses,
                variable_atoms: self.variable_atoms,
                atom_variables: self.atom_variables,
                true_literal: None,
                finite_equalities_complete: false,
                finite_predicate_congruence_complete: false,
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
        true_literal: Option<i32>,
        finite_equalities_complete: bool,
        finite_predicate_congruence_complete: bool,
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
                true_literal: self.true_literal,
                finite_equalities_complete: self.finite_equalities_complete,
                finite_predicate_congruence_complete: self.finite_predicate_congruence_complete,
            }
        }
    }

    fn completed_output(result: &CompilerResult) -> &EqresOutput {
        match &result.status {
            CompilerStatus::Completed(output) => output,
            CompilerStatus::NotRun => panic!("compiler unexpectedly did not run"),
            CompilerStatus::Rejected(failure) => panic!("compiler rejected: {failure:?}"),
        }
    }

    fn equality_records(result: &CompilerResult) -> impl Iterator<Item = &EqualityTraceRecord> {
        result.trace.iter().filter_map(|record| match record {
            TraceRecord::Equality(record) => Some(record),
            TraceRecord::Conflict(_) => None,
        })
    }

    fn conflict_records(result: &CompilerResult) -> impl Iterator<Item = &ConflictTraceRecord> {
        result.trace.iter().filter_map(|record| match record {
            TraceRecord::Equality(_) => None,
            TraceRecord::Conflict(record) => Some(record),
        })
    }

    fn compiler_for<'a>(fixture: &'a Fixture, variant: CompilerVariant) -> Compiler<'a> {
        let input = fixture.input();
        let mut counters = DeterministicCounters::default();
        let prepared = validate_and_prepare(input, CompilerLimits::FROZEN, &mut counters)
            .expect("fixture input should validate");
        let hashes = compute_input_hashes(input).expect("fixture hashes should compute");
        Compiler::new(input, variant, CompilerLimits::FROZEN, prepared, hashes)
            .expect("fixture compiler should initialize")
    }

    #[test]
    fn all_five_rules_reach_mechanism_bound_empty() {
        let mut builder = FixtureBuilder::new();
        let a = builder.constant();
        let b = builder.constant();
        let c = builder.constant();
        let (fa, fc) = builder.unary_pair(a, c);
        let ab = builder.equality(a, b);
        let bc = builder.equality(b, c);
        let result_equality = builder.equality(fa, fc);
        builder.clause(vec![ab]);
        builder.clause(vec![bc]);
        builder.clause(vec![-result_equality]);
        let fixture = builder.build();

        let result = compile(fixture.input(), CompilerVariant::Ordinary);
        assert!(matches!(
            completed_output(&result),
            EqresOutput::TheoryEmpty { .. }
        ));
        let accepted = result.counters.search.accepted_events;
        assert!(accepted.seed >= 2);
        assert!(accepted.reflexivity >= fixture.terms.len() as u64);
        assert!(accepted.transitivity >= 1);
        assert!(accepted.congruence >= 1);
        assert_eq!(accepted.conflict, 1);
        assert_eq!(result.counters.input.application_pairs, 1);
        assert_eq!(result.counters.input.application_argument_slots, 1);
        assert_eq!(
            result
                .counters
                .output
                .emitted_with_missing_equality_congruence,
            1
        );
    }

    #[test]
    fn conflict_clause_reseeds_a_positive_equality() {
        let mut builder = FixtureBuilder::new();
        let a = builder.constant();
        let b = builder.constant();
        let c = builder.constant();
        let d = builder.constant();
        let ab = builder.equality(a, b);
        let cd = builder.equality(c, d);
        let guard = builder.auxiliary();
        builder.clause(vec![ab]);
        builder.clause(vec![-ab, guard, cd]);
        builder.clause(vec![-cd]);
        let fixture = builder.build();

        let result = compile(fixture.input(), CompilerVariant::Ordinary);
        assert!(matches!(completed_output(&result), EqresOutput::Lemmas(_)));
        assert!(equality_records(&result).any(|record| {
            matches!(
                record.rule,
                EqualityRuleRecord::Seed(SeedRecord {
                    positive_source: ClausePivot {
                        clause: ClauseRef {
                            origin: ClauseOrigin::Derived,
                            ..
                        },
                        ..
                    }
                })
            )
        }));
    }

    #[test]
    fn global_minimum_orders_zero_width_reflexivity_before_wider_seed() {
        let mut builder = FixtureBuilder::new();
        let a = builder.constant();
        let b = builder.constant();
        let equality = builder.equality(a, b);
        let guard = builder.auxiliary();
        builder.clause(vec![guard, equality]);
        let fixture = builder.build();

        let result = compile(fixture.input(), CompilerVariant::Ordinary);
        completed_output(&result);
        let Some(TraceRecord::Equality(first)) = result.trace.first() else {
            panic!("expected an equality trace record");
        };
        assert!(matches!(first.rule, EqualityRuleRecord::Reflexivity(_)));
        let event_ids = result
            .trace
            .iter()
            .map(|record| match record {
                TraceRecord::Equality(record) => record.event_id.get(),
                TraceRecord::Conflict(record) => record.event_id.get(),
            })
            .collect::<Vec<_>>();
        assert!(event_ids.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn antichain_discards_the_ninth_incomparable_support() {
        let mut builder = FixtureBuilder::new();
        let a = builder.constant();
        let b = builder.constant();
        let equality = builder.equality(a, b);
        for _ in 0..9 {
            let guard = builder.auxiliary();
            builder.clause(vec![guard, equality]);
        }
        let fixture = builder.build();

        let result = compile(fixture.input(), CompilerVariant::Ordinary);
        completed_output(&result);
        assert!(result.counters.pruning.support_capacity_discards >= 1);
        let retained_for_equality = equality_records(&result)
            .filter(|record| record.conclusion == normalized_equality(a, b))
            .count();
        assert_eq!(retained_for_equality, 8);
    }

    #[test]
    fn removed_support_stops_new_work_but_its_queued_conflict_survives() {
        let mut builder = FixtureBuilder::new();
        let a = builder.constant();
        let b = builder.constant();
        let c = builder.constant();
        let d = builder.constant();
        let target = builder.equality(a, b);
        let trigger = builder.equality(c, d);
        let x = builder.auxiliary();
        let y = builder.auxiliary();
        builder.clause(vec![x, y, target]);
        builder.clause(vec![trigger]);
        builder.clause(vec![-trigger, x, target]);
        builder.clause(vec![-target]);
        let fixture = builder.build();

        let result = compile(fixture.input(), CompilerVariant::Ordinary);
        completed_output(&result);
        assert!(result.counters.pruning.support_removed_supersets >= 2);

        let target_key = normalized_equality(a, b);
        let large_nodes = equality_records(&result)
            .filter(|record| record.conclusion == target_key && record.side_clause.len() == 2)
            .map(|record| record.node_id)
            .collect::<Vec<_>>();
        let smaller_event = equality_records(&result)
            .find(|record| record.conclusion == target_key && record.side_clause.as_slice() == [x])
            .expect("derived strict-subset support")
            .event_id;
        assert!(conflict_records(&result).any(|record| {
            large_nodes.contains(&record.rule.equality_parent)
                && record.event_id > smaller_event
                && record.clause.len() == 2
        }));
    }

    #[test]
    fn missing_congruence_is_suppressed_before_attempt_accounting() {
        let mut builder = FixtureBuilder::new();
        let a = builder.constant();
        let b = builder.constant();
        builder.unary_pair(a, b);
        let equality = builder.equality(a, b);
        builder.clause(vec![equality]);
        let fixture = builder.build();

        let ordinary = compile(fixture.input(), CompilerVariant::Ordinary);
        let mut suppressed =
            compiler_for(&fixture, CompilerVariant::SuppressMissingEqualityCongruence);
        let suppressed_output = suppressed.run().expect("suppressed compiler should run");
        completed_output(&ordinary);
        assert_eq!(suppressed_output, EqresOutput::NoLemmas);
        assert!(ordinary.counters.search.accepted_events.congruence >= 1);
        assert_eq!(suppressed.counters.search.attempted_events.congruence, 0);
        assert_eq!(suppressed.counters.search.accepted_events.congruence, 0);
        assert!(
            suppressed
                .counters
                .search
                .suppressed_missing_equality_congruence_events
                >= 1
        );
        assert!(suppressed.congruence_tuples.is_empty());

        let equality_key = normalized_equality(a, b);
        let parent = suppressed
            .nodes
            .iter()
            .enumerate()
            .find(|(_, node)| node.active && node.conclusion == equality_key)
            .map(|(index, _)| NodeId::new(index as u32))
            .expect("active argument-equality support");
        let suppressed_before = suppressed
            .counters
            .search
            .suppressed_missing_equality_congruence_events;
        let attempts_before = suppressed.counters.search.attempted_events.congruence;
        let tuple_count_before = suppressed.congruence_tuples.len();
        suppressed
            .generate_congruence_children(parent, EventId::new(10_000))
            .expect("repeated suppressed enumeration should remain valid");
        assert!(
            suppressed
                .counters
                .search
                .suppressed_missing_equality_congruence_events
                > suppressed_before
        );
        assert_eq!(
            suppressed.counters.search.attempted_events.congruence,
            attempts_before
        );
        assert_eq!(suppressed.congruence_tuples.len(), tuple_count_before);
    }

    #[test]
    fn suppressed_tuple_count_handles_repeated_argument_equalities_without_allocation_history() {
        let mut builder = FixtureBuilder::new();
        let a = builder.constant();
        let b = builder.constant();
        builder.repeated_binary_pair(a, b);
        let equality = builder.equality(a, b);
        let first_guard = builder.auxiliary();
        let second_guard = builder.auxiliary();
        builder.clause(vec![first_guard, equality]);
        builder.clause(vec![second_guard, equality]);
        let fixture = builder.build();

        let mut compiler =
            compiler_for(&fixture, CompilerVariant::SuppressMissingEqualityCongruence);
        assert_eq!(compiler.run().unwrap(), EqresOutput::NoLemmas);
        assert_eq!(
            compiler
                .counters
                .search
                .suppressed_missing_equality_congruence_events,
            4
        );
        assert_eq!(compiler.counters.search.attempted_events.congruence, 0);
        assert!(compiler.congruence_tuples.is_empty());
    }

    #[test]
    fn transitivity_join_identity_includes_the_shared_intermediate() {
        let mut builder = FixtureBuilder::new();
        let a = builder.constant();
        let b = builder.constant();
        let equality = builder.equality(a, b);
        let left_guard = builder.auxiliary();
        let right_guard = builder.auxiliary();
        builder.clause(vec![left_guard, equality]);
        builder.clause(vec![right_guard, equality]);
        let fixture = builder.build();

        let mut compiler = compiler_for(&fixture, CompilerVariant::Ordinary);
        compiler.run().expect("compiler should run");
        let equality_key = normalized_equality(a, b);
        let mut seed_parents = compiler
            .trace
            .iter()
            .filter_map(|record| match record {
                TraceRecord::Equality(record)
                    if record.conclusion == equality_key
                        && matches!(record.rule, EqualityRuleRecord::Seed(_)) =>
                {
                    Some(record.node_id)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        seed_parents.sort_unstable();
        assert_eq!(seed_parents.len(), 2);
        let parents = [seed_parents[0], seed_parents[1]];
        let mut intermediates = compiler
            .transitivity_joins
            .iter()
            .filter_map(|join| (join.parents == parents).then_some(join.intermediate))
            .collect::<Vec<_>>();
        intermediates.sort_unstable();
        assert_eq!(intermediates, vec![a, b]);
    }

    #[test]
    fn transitivity_candidates_are_globally_ordered_across_endpoints() {
        let mut builder = FixtureBuilder::new();
        let c = builder.constant();
        builder.constant();
        let a = builder.constant();
        let b = builder.constant();
        let z = builder.constant();
        let cb = builder.equality(c, b);
        let az = builder.equality(a, z);
        let ab = builder.equality(a, b);
        let guard = builder.auxiliary();
        builder.clause(vec![cb]);
        builder.clause(vec![az]);
        builder.clause(vec![guard, ab]);
        let fixture = builder.build();

        let mut compiler = compiler_for(&fixture, CompilerVariant::Ordinary);
        compiler.run().expect("compiler should run");
        let node_for = |wanted: EqualityKey| {
            compiler
                .trace
                .iter()
                .find_map(|record| match record {
                    TraceRecord::Equality(record)
                        if record.conclusion == wanted
                            && matches!(record.rule, EqualityRuleRecord::Seed(_)) =>
                    {
                        Some(record.node_id)
                    }
                    _ => None,
                })
                .expect("seed node should exist")
        };
        let new_node = node_for(normalized_equality(a, b));
        let right_endpoint_node = node_for(normalized_equality(c, b));
        let left_endpoint_node = node_for(normalized_equality(a, z));
        let candidates = compiler
            .ordered_transitivity_candidates(new_node, EventId::new(20_000))
            .expect("candidate ordering should reconstruct");
        let position_of = |node| {
            candidates
                .iter()
                .position(|candidate| candidate.other_node == node)
                .expect("endpoint candidate should exist")
        };
        assert!(position_of(right_endpoint_node) < position_of(left_endpoint_node));
    }

    #[test]
    fn cap_precedence_reports_terms_before_baseline_variables() {
        let mut builder = FixtureBuilder::new();
        let a = builder.constant();
        let b = builder.constant();
        let equality = builder.equality(a, b);
        builder.clause(vec![equality]);
        let fixture = builder.build();
        let mut limits = CompilerLimits::FROZEN;
        limits.terms = 1;
        limits.baseline_variables = 0;

        let result = compile_with_test_limits(fixture.input(), CompilerVariant::Ordinary, limits);
        match result.status {
            CompilerStatus::Rejected(CompilerFailure::Cap(attempt)) => {
                assert_eq!(attempt.reason, CapReason::Terms);
                assert_eq!(attempt.boundary, CapBoundary::StaticInput);
            }
            CompilerStatus::NotRun => panic!("compiler unexpectedly did not run"),
            CompilerStatus::Completed(output) => panic!("unexpected completion: {output:?}"),
            CompilerStatus::Rejected(failure) => panic!("unexpected failure: {failure:?}"),
        }
    }

    #[test]
    fn static_application_caps_precede_pair_materialization() {
        use std::cell::Cell;

        let mut builder = FixtureBuilder::new();
        let left = builder.constant();
        let right = builder.constant();
        builder.unary_pair(left, right);
        let fixture = builder.build();

        for (configure, expected) in [
            (
                (
                    0,
                    CompilerLimits::FROZEN.maximum_arity,
                    CompilerLimits::FROZEN.application_argument_slots,
                ),
                CapReason::ApplicationPairs,
            ),
            (
                (
                    CompilerLimits::FROZEN.application_pairs,
                    0,
                    CompilerLimits::FROZEN.application_argument_slots,
                ),
                CapReason::MaximumArity,
            ),
            (
                (
                    CompilerLimits::FROZEN.application_pairs,
                    CompilerLimits::FROZEN.maximum_arity,
                    0,
                ),
                CapReason::ApplicationArgumentSlots,
            ),
        ] {
            let mut limits = CompilerLimits::FROZEN;
            limits.application_pairs = configure.0;
            limits.maximum_arity = configure.1;
            limits.application_argument_slots = configure.2;
            let materializer_called = Cell::new(false);
            let mut counters = DeterministicCounters::default();
            let result =
                validate_and_prepare_with(fixture.input(), limits, &mut counters, |_, _| {
                    materializer_called.set(true);
                    Err(allocation_failure(None))
                });
            assert!(!materializer_called.get());
            assert_eq!(counters.input.application_pairs, 1);
            assert_eq!(counters.input.maximum_arity, 1);
            assert_eq!(counters.input.application_argument_slots, 1);
            match result {
                Err(CompilerFailure::Cap(attempt)) => {
                    assert_eq!(attempt.reason, expected);
                    assert_eq!(attempt.boundary, CapBoundary::StaticInput);
                }
                other => panic!("unexpected static application result: {other:?}"),
            }
        }
    }

    #[test]
    fn failed_final_materialization_does_not_commit_output_counters() {
        let mut builder = FixtureBuilder::new();
        builder.constant();
        let fixture = builder.build();
        let mut compiler = compiler_for(&fixture, CompilerVariant::Ordinary);
        let before = compiler.counters.output;

        let result = compiler
            .commit_final_output_with(Vec::new(), 0, 0, 0, 0, 0, |_| Err(allocation_failure(None)));
        assert!(matches!(
            result,
            Err(CompilerFailure::AllocationFailure { event_id: None })
        ));
        assert_eq!(compiler.counters.output, before);
    }

    #[test]
    fn equality_node_cap_precedes_later_acceptance_caps() {
        let mut builder = FixtureBuilder::new();
        builder.constant();
        let fixture = builder.build();
        let mut limits = CompilerLimits::FROZEN;
        limits.equality_proof_nodes = 0;
        limits.all_derived_literal_slots = 0;

        let result = compile_with_test_limits(fixture.input(), CompilerVariant::Ordinary, limits);
        match result.status {
            CompilerStatus::Rejected(CompilerFailure::Cap(attempt)) => {
                assert_eq!(attempt.reason, CapReason::EqualityProofNodes);
                assert!(matches!(
                    attempt.boundary,
                    CapBoundary::PoppedEventAcceptance(_)
                ));
            }
            CompilerStatus::NotRun => panic!("compiler unexpectedly did not run"),
            CompilerStatus::Completed(output) => panic!("unexpected completion: {output:?}"),
            CompilerStatus::Rejected(failure) => panic!("unexpected failure: {failure:?}"),
        }
    }

    #[test]
    fn no_conflict_produces_explicit_no_lemmas() {
        let mut builder = FixtureBuilder::new();
        builder.constant();
        builder.constant();
        let fixture = builder.build();

        let result = compile(fixture.input(), CompilerVariant::Ordinary);
        assert_eq!(completed_output(&result), &EqresOutput::NoLemmas);
        assert_eq!(result.counters.output.emitted_lemmas, 0);
        assert_eq!(result.counters.output.emitted_literal_slots, 0);
        assert_eq!(result.counters.output.emitted_p95_width, 0);
        assert_eq!(result.counters.output.emitted_maximum_width, 0);
    }

    #[test]
    fn exact_derived_clause_dedup_and_final_output_are_deterministic() {
        let mut builder = FixtureBuilder::new();
        let a = builder.constant();
        let b = builder.constant();
        let equality = builder.equality(a, b);
        let guard = builder.auxiliary();
        builder.clause(vec![equality]);
        builder.clause(vec![-equality, guard]);
        builder.clause(vec![-equality, guard]);
        let fixture = builder.build();

        let first = compile(fixture.input(), CompilerVariant::Ordinary);
        let second = compile(fixture.input(), CompilerVariant::Ordinary);
        assert_eq!(first, second);
        assert!(first.counters.pruning.duplicate_derived_clauses >= 1);
        let EqresOutput::Lemmas(lemmas) = completed_output(&first) else {
            panic!("expected one nonempty lemma");
        };
        assert_eq!(lemmas.len(), 1);
        assert_eq!(lemmas[0].clause.as_slice(), [guard]);
        assert_ne!(first.hashes.trace_sha256, Sha256Digest::ZERO);
        assert_ne!(first.hashes.lemma_sequence_sha256, Sha256Digest::ZERO);
        assert_eq!(
            first.hashes.lemma_sequence_sha256,
            first.hashes.materialized_lemmas_sha256
        );
    }

    #[test]
    fn canonical_union_deduplicates_and_rejects_tautologies() {
        assert_eq!(
            canonicalize_two(&[1, 3], &[1, 2], None)
                .unwrap()
                .unwrap()
                .as_slice(),
            [1, 2, 3]
        );
        assert_eq!(canonicalize_two(&[-2, 1], &[2, 3], None).unwrap(), None);
    }

    #[test]
    fn schema_fields_participate_in_independent_hashes() {
        let mut builder = FixtureBuilder::new();
        builder.constant();
        let true_literal = builder.auxiliary();
        builder.clause(vec![true_literal]);
        let mut fixture = builder.build();

        let baseline = compile(fixture.input(), CompilerVariant::Ordinary);
        fixture.source.push(b'!');
        let changed_source = compile(fixture.input(), CompilerVariant::Ordinary);
        assert_ne!(
            baseline.hashes.source_sha256,
            changed_source.hashes.source_sha256
        );

        fixture.root_mode.push(b'!');
        let changed_mode = compile(fixture.input(), CompilerVariant::Ordinary);
        assert_ne!(
            changed_source.hashes.root_cnf_mode_sha256,
            changed_mode.hashes.root_cnf_mode_sha256
        );

        fixture.true_literal = Some(true_literal);
        fixture.finite_equalities_complete = true;
        fixture.finite_predicate_congruence_complete = true;
        let changed_flags = compile(fixture.input(), CompilerVariant::Ordinary);
        completed_output(&changed_flags);
        assert_ne!(
            changed_mode.hashes.atom_map_sha256,
            changed_flags.hashes.atom_map_sha256
        );
        assert_ne!(
            changed_mode.hashes.baseline_problem_sha256,
            changed_flags.hashes.baseline_problem_sha256
        );
    }

    #[test]
    fn compiler_local_sha256_matches_standard_vector() {
        let mut hash = LocalSha256::new();
        hash.update(b"abc");
        assert_eq!(
            hash.finalize().to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
