//! Independent logical replay for the T11 equality-resolution compiler.
//!
//! This module deliberately owns its normalization, subsumption, encoding, and
//! SHA-256 implementation. It shares only immutable records and the baseline
//! data model with the compiler.

use super::{
    BOOL_SORT, BoolAtomKey, FlatClauses, SortId, TermId,
    t11_eqres_types::{
        CanonicalClause, CheckerCounters, CheckerFailure, CheckerFailureKind, CheckerResult,
        CheckerStatus, ClauseOrigin, ClausePivot, ClauseRef, CompilerResult, CompilerStatus,
        CompilerVariant, CongruenceRecord, EmittedLemma, EqresInput, EqresOutput, EqualityKey,
        EqualityRuleRecord, EqualityTraceRecord, EventId, HashArtifact, HashBindings,
        InputCounters, MaterializedClauseStore, NodeId, OutputCounters, RuleCounters, Sha256Digest,
        TraceRecord,
    },
};
use std::collections::{BTreeMap, BTreeSet};

const ROOT_CNF_MODE: &[u8] = b"direct-root;negated-root=false;v1";

#[derive(Clone)]
struct ReplayedNode {
    conclusion: (TermId, TermId),
    side_clause: Vec<i32>,
    depth: u32,
    contains_missing_congruence: bool,
}

#[derive(Clone)]
struct ReplayedClause {
    id: u32,
    event_id: EventId,
    literals: Vec<i32>,
    depth: u32,
    contains_missing_congruence: bool,
    trace_index: usize,
}

#[derive(Clone)]
struct ResolvedClause {
    literals: Vec<i32>,
    depth: u32,
    contains_missing_congruence: bool,
}

#[derive(Clone)]
struct ResolvedPivot {
    source: ResolvedClause,
    offset: usize,
    equality: (TermId, TermId),
}

#[derive(Default)]
struct FailureSink {
    failures: Vec<CheckerFailure>,
}

impl FailureSink {
    fn add(
        &mut self,
        kind: CheckerFailureKind,
        event_id: Option<EventId>,
        artifact: Option<HashArtifact>,
    ) {
        self.failures.push(CheckerFailure {
            kind,
            event_id,
            artifact,
        });
    }

    fn event(&mut self, kind: CheckerFailureKind, event_id: EventId) {
        self.add(kind, Some(event_id), None);
    }

    fn input(&mut self, kind: CheckerFailureKind) {
        self.add(kind, None, None);
    }

    fn hash(&mut self, artifact: HashArtifact) {
        self.add(CheckerFailureKind::HashMismatch, None, Some(artifact));
    }

    fn len(&self) -> usize {
        self.failures.len()
    }
}

enum Canonicalized {
    Clause(Vec<i32>),
    Tautology,
    Invalid,
}

#[derive(Clone)]
struct ExpectedLemma {
    source_clause_id: u32,
    clause: Vec<i32>,
    contains_missing_congruence: bool,
}

#[derive(Clone)]
enum ExpectedOutput {
    Lemmas(Vec<ExpectedLemma>),
    TheoryEmpty {
        terminal_event_id: EventId,
        lemma: ExpectedLemma,
    },
    NoLemmas,
}

impl ExpectedOutput {
    fn lemmas(&self) -> Vec<&ExpectedLemma> {
        match self {
            Self::Lemmas(lemmas) => lemmas.iter().collect(),
            Self::TheoryEmpty { lemma, .. } => vec![lemma],
            Self::NoLemmas => Vec::new(),
        }
    }
}

struct Checker<'a> {
    input: EqresInput<'a>,
    compiler: &'a CompilerResult,
    materialized: &'a MaterializedClauseStore,
    failures: FailureSink,
    base_ranges: Vec<Option<(usize, usize)>>,
    normalized_base_clauses: Vec<Option<Vec<i32>>>,
    valid_terms: Vec<bool>,
    node_positions: BTreeMap<u32, usize>,
    clause_positions: BTreeMap<u32, usize>,
    replayed_nodes: BTreeMap<u32, ReplayedNode>,
    replayed_clauses: BTreeMap<u32, ReplayedClause>,
    seen_derived_clauses: BTreeSet<Vec<i32>>,
    reflexivity_records: Vec<(EventId, TermId)>,
    equality_records: u64,
    conflict_records: u64,
    replayed_emitted_lemmas: u64,
    expected_input_counters: InputCounters,
    expected_output: ExpectedOutput,
    expected_output_counters: OutputCounters,
    final_base_discards: u64,
    final_output_discards: u64,
}

/// Replays a compiler result without using compiler code or mutable state.
pub(crate) fn check(
    input: EqresInput<'_>,
    compiler: &CompilerResult,
    materialized: &MaterializedClauseStore,
) -> CheckerResult {
    if matches!(compiler.status, CompilerStatus::NotRun) {
        return CheckerResult {
            status: CheckerStatus::NotRun,
            counters: CheckerCounters::default(),
            recomputed_hashes: HashBindings::default(),
        };
    }

    let mut checker = Checker {
        input,
        compiler,
        materialized,
        failures: FailureSink::default(),
        base_ranges: Vec::new(),
        normalized_base_clauses: Vec::new(),
        valid_terms: vec![false; input.term_dag.len()],
        node_positions: BTreeMap::new(),
        clause_positions: BTreeMap::new(),
        replayed_nodes: BTreeMap::new(),
        replayed_clauses: BTreeMap::new(),
        seen_derived_clauses: BTreeSet::new(),
        reflexivity_records: Vec::new(),
        equality_records: 0,
        conflict_records: 0,
        replayed_emitted_lemmas: 0,
        expected_input_counters: InputCounters::default(),
        expected_output: ExpectedOutput::NoLemmas,
        expected_output_counters: OutputCounters::default(),
        final_base_discards: 0,
        final_output_discards: 0,
    };

    checker.validate_input();
    checker.index_trace();
    checker.replay_trace();
    checker.verify_compiler_trace_counters();
    checker.verify_reflexivity_sequence();
    checker.reconstruct_and_verify_output();
    checker.verify_materialized_output();
    let recomputed_hashes = checker.recompute_and_verify_hashes();
    checker.finish(recomputed_hashes)
}

impl<'a> Checker<'a> {
    fn finish(mut self, recomputed_hashes: HashBindings) -> CheckerResult {
        let replay_failures = match u64::try_from(self.failures.len()) {
            Ok(value) => value,
            Err(_) => {
                self.failures.input(CheckerFailureKind::ArithmeticOverflow);
                u64::MAX
            }
        };
        let counters = CheckerCounters {
            replayed_equality_nodes: self.equality_records,
            replayed_conflict_clauses: self.conflict_records,
            replayed_emitted_lemmas: self.replayed_emitted_lemmas,
            replay_failures,
        };
        let status = if self.failures.failures.is_empty() {
            CheckerStatus::Accepted
        } else {
            CheckerStatus::Rejected(self.failures.failures.into_boxed_slice())
        };
        CheckerResult {
            status,
            counters,
            recomputed_hashes,
        }
    }

    fn validate_input(&mut self) {
        if self.input.root_cnf_mode != ROOT_CNF_MODE {
            self.failures.hash(HashArtifact::RootCnfMode);
        }
        self.validate_sorts();
        self.validate_declarations();
        self.validate_terms_and_applications();
        self.validate_clause_store();
        self.validate_atom_map();
        self.compute_and_verify_input_counters();
    }

    fn validate_sorts(&mut self) {
        let names = &self.input.sorts.names;
        if names.first().map(String::as_str) != Some("Bool") {
            self.failures.input(CheckerFailureKind::Sort);
        }

        let mut unique_names = BTreeSet::new();
        for name in names {
            if name.is_empty() || !unique_names.insert(name.as_str()) {
                self.failures.input(CheckerFailureKind::Sort);
            }
        }

        let mut declared_ids = BTreeSet::new();
        for sort in self.input.sorts.ids.values() {
            let index = sort.0 as usize;
            if index == 0 || index >= names.len() || !declared_ids.insert(index) {
                self.failures.input(CheckerFailureKind::Sort);
            }
        }
        if names.len().saturating_sub(1) != declared_ids.len()
            || (1..names.len()).any(|index| !declared_ids.contains(&index))
        {
            self.failures.input(CheckerFailureKind::Sort);
        }
    }

    fn validate_declarations(&mut self) {
        for declaration in self.input.declarations.slots.iter().flatten() {
            if !self.sort_exists(declaration.result_sort) {
                self.failures.input(CheckerFailureKind::Sort);
            }
            if declaration
                .arg_sorts
                .iter()
                .any(|&sort| !self.sort_exists(sort))
            {
                self.failures.input(CheckerFailureKind::Sort);
            }
        }
    }

    fn validate_terms_and_applications(&mut self) {
        let mut term_keys = BTreeSet::<(u32, Vec<TermId>)>::new();
        for (term_id, term) in self.input.term_dag.iter().enumerate() {
            let mut valid = true;
            if !self.sort_exists(term.sort) {
                self.failures.input(CheckerFailureKind::Sort);
                valid = false;
            }
            let declaration = self.input.declarations.get(term.fun);
            let Some(declaration) = declaration else {
                self.failures.input(CheckerFailureKind::Function);
                self.valid_terms[term_id] = false;
                continue;
            };
            if declaration.result_sort != term.sort {
                self.failures.input(CheckerFailureKind::Sort);
                valid = false;
            }
            if declaration.arg_sorts.len() != term.args.len() {
                self.failures.input(CheckerFailureKind::Arity);
                valid = false;
            }
            for (argument_index, &argument) in term.args.iter().enumerate() {
                if argument >= term_id {
                    self.failures.input(CheckerFailureKind::TermId);
                    valid = false;
                    continue;
                }
                let Some(argument_term) = self.input.term_dag.get(argument) else {
                    self.failures.input(CheckerFailureKind::TermId);
                    valid = false;
                    continue;
                };
                if declaration.arg_sorts.get(argument_index) != Some(&argument_term.sort) {
                    self.failures.input(CheckerFailureKind::Sort);
                    valid = false;
                }
            }
            if !term_keys.insert((term.fun, term.args.clone())) {
                self.failures.input(CheckerFailureKind::TermId);
                valid = false;
            }
            self.valid_terms[term_id] = valid;
        }

        let expected_applications: Vec<_> = self
            .input
            .term_dag
            .iter()
            .enumerate()
            .filter_map(|(term_id, term)| (!term.args.is_empty()).then_some(term_id))
            .collect();
        if expected_applications != self.input.ordered_applications {
            self.failures
                .input(CheckerFailureKind::CongruenceApplicationOrder);
        }

        let mut seen = BTreeSet::new();
        let mut boolean_per_function = BTreeMap::<u32, u64>::new();
        for &application in self.input.ordered_applications {
            if !seen.insert(application) {
                self.failures
                    .input(CheckerFailureKind::CongruenceApplicationOrder);
            }
            let Some(term) = self.input.term_dag.get(application) else {
                self.failures.input(CheckerFailureKind::TermId);
                continue;
            };
            if term.args.is_empty() {
                self.failures.input(CheckerFailureKind::Arity);
            }
            if term.sort == BOOL_SORT {
                let count = boolean_per_function.entry(term.fun).or_default();
                match count.checked_add(1) {
                    Some(next) => *count = next,
                    None => self.failures.input(CheckerFailureKind::ArithmeticOverflow),
                }
            }
        }
        if boolean_per_function.values().any(|&count| count > 1) {
            self.failures
                .input(CheckerFailureKind::CongruenceApplicationOrder);
        }
    }

    fn validate_clause_store(&mut self) {
        let clauses = self.input.baseline_clauses;
        if clauses.end_offsets.is_empty() || clauses.end_offsets.first() != Some(&0) {
            self.failures.input(CheckerFailureKind::MalformedTrace);
        }

        self.base_ranges
            .reserve(clauses.end_offsets.len().saturating_sub(1));
        self.normalized_base_clauses
            .reserve(clauses.end_offsets.len().saturating_sub(1));
        for bounds in clauses.end_offsets.windows(2) {
            let start = bounds[0] as usize;
            let end = bounds[1] as usize;
            let range = if start <= end && end <= clauses.literals.len() {
                Some((start, end))
            } else {
                self.failures.input(CheckerFailureKind::MalformedTrace);
                None
            };
            self.base_ranges.push(range);
            let normalized = range.and_then(|(start, end)| {
                match canonicalize_slices([&clauses.literals[start..end]]) {
                    Canonicalized::Clause(clause) => Some(clause),
                    Canonicalized::Tautology => None,
                    Canonicalized::Invalid => {
                        self.failures.input(CheckerFailureKind::MalformedTrace);
                        None
                    }
                }
            });
            self.normalized_base_clauses.push(normalized);
        }
        if clauses.end_offsets.last().copied().map(u64::from)
            != u64::try_from(clauses.literals.len()).ok()
        {
            self.failures.input(CheckerFailureKind::MalformedTrace);
        }

        for &literal in &clauses.literals {
            if literal == 0 {
                self.failures.input(CheckerFailureKind::MalformedTrace);
                continue;
            }
            let variable = literal.unsigned_abs() as usize;
            if variable == 0 || variable >= self.input.variable_atoms.len() {
                self.failures.input(CheckerFailureKind::MalformedTrace);
            }
        }
    }

    fn validate_atom_map(&mut self) {
        if self.input.variable_atoms.first() != Some(&None) {
            self.failures.input(CheckerFailureKind::MalformedTrace);
        }

        let mut atom_entries = 0usize;
        for (variable, atom) in self.input.variable_atoms.iter().enumerate().skip(1) {
            let Some(atom) = atom else {
                continue;
            };
            atom_entries = atom_entries.saturating_add(1);
            self.validate_atom(atom);
            let expected_variable = i32::try_from(variable).ok();
            if expected_variable.is_none()
                || self.input.atom_variables.get(atom).copied() != expected_variable
            {
                self.failures.input(CheckerFailureKind::MalformedTrace);
            }
        }
        if atom_entries != self.input.atom_variables.len() {
            self.failures.input(CheckerFailureKind::MalformedTrace);
        }

        for (atom, &variable) in self.input.atom_variables {
            self.validate_atom(atom);
            let variable_index = match usize::try_from(variable) {
                Ok(index) if variable > 0 => index,
                _ => {
                    self.failures.input(CheckerFailureKind::MalformedTrace);
                    continue;
                }
            };
            if self
                .input
                .variable_atoms
                .get(variable_index)
                .and_then(Option::as_ref)
                != Some(atom)
            {
                self.failures.input(CheckerFailureKind::MalformedTrace);
            }
        }

        if let Some(true_literal) = self.input.true_literal {
            let variable = match usize::try_from(true_literal) {
                Ok(variable) if true_literal > 0 => variable,
                _ => {
                    self.failures.input(CheckerFailureKind::MalformedTrace);
                    return;
                }
            };
            if self.input.variable_atoms.get(variable) != Some(&None) {
                self.failures.input(CheckerFailureKind::MalformedTrace);
            }
            let has_unit = self.base_ranges.iter().flatten().any(|&(start, end)| {
                end == start.saturating_add(1)
                    && self.input.baseline_clauses.literals.get(start) == Some(&true_literal)
            });
            if !has_unit {
                self.failures.input(CheckerFailureKind::MalformedTrace);
            }
        }
    }

    fn validate_atom(&mut self, atom: &BoolAtomKey) {
        match atom {
            BoolAtomKey::Eq(left, right) => {
                if left > right {
                    self.failures.input(CheckerFailureKind::Conclusion);
                }
                let Some(left_term) = self.input.term_dag.get(*left) else {
                    self.failures.input(CheckerFailureKind::TermId);
                    return;
                };
                let Some(right_term) = self.input.term_dag.get(*right) else {
                    self.failures.input(CheckerFailureKind::TermId);
                    return;
                };
                if left_term.sort != right_term.sort {
                    self.failures.input(CheckerFailureKind::Sort);
                }
            }
            BoolAtomKey::BoolTerm(term) => {
                let Some(term) = self.input.term_dag.get(*term) else {
                    self.failures.input(CheckerFailureKind::TermId);
                    return;
                };
                if term.sort != BOOL_SORT {
                    self.failures.input(CheckerFailureKind::Sort);
                }
            }
        }
    }

    fn compute_and_verify_input_counters(&mut self) {
        let terms = checked_usize_to_u64(self.input.term_dag.len(), &mut self.failures);
        let variables = checked_usize_to_u64(
            self.input.variable_atoms.len().saturating_sub(1),
            &mut self.failures,
        );
        let atom_entries =
            checked_usize_to_u64(self.input.atom_variables.len(), &mut self.failures);
        let clauses = checked_usize_to_u64(self.base_ranges.len(), &mut self.failures);
        let literal_slots = checked_usize_to_u64(
            self.input.baseline_clauses.literals.len(),
            &mut self.failures,
        );
        let applications =
            checked_usize_to_u64(self.input.ordered_applications.len(), &mut self.failures);

        let mut maximum_arity = 0u64;
        let mut argument_slots = 0u64;
        let mut application_pairs = 0u64;
        for (left_position, &left_id) in self.input.ordered_applications.iter().enumerate() {
            let Some(left) = self.input.term_dag.get(left_id) else {
                continue;
            };
            let arity = checked_usize_to_u64(left.args.len(), &mut self.failures);
            maximum_arity = maximum_arity.max(arity);
            let Some(right_ids) = self
                .input
                .ordered_applications
                .get(left_position.saturating_add(1)..)
            else {
                self.failures.input(CheckerFailureKind::ArithmeticOverflow);
                continue;
            };
            for &right_id in right_ids {
                let Some(right) = self.input.term_dag.get(right_id) else {
                    continue;
                };
                if left.fun != right.fun {
                    continue;
                }
                if left.args.len() != right.args.len() {
                    self.failures.input(CheckerFailureKind::Arity);
                    continue;
                }
                if left.sort != right.sort {
                    self.failures.input(CheckerFailureKind::Sort);
                    continue;
                }
                if left.sort == BOOL_SORT {
                    self.failures
                        .input(CheckerFailureKind::CongruenceApplicationOrder);
                    continue;
                }
                let requirements = left
                    .args
                    .iter()
                    .zip(&right.args)
                    .filter(|(left_argument, right_argument)| left_argument != right_argument)
                    .count();
                if requirements == 0 {
                    self.failures.input(CheckerFailureKind::TermId);
                    continue;
                }
                application_pairs = checked_add_counter(application_pairs, 1, &mut self.failures);
                let requirements = checked_usize_to_u64(requirements, &mut self.failures);
                argument_slots =
                    checked_add_counter(argument_slots, requirements, &mut self.failures);
            }
        }

        self.expected_input_counters = InputCounters {
            terms,
            baseline_variables: variables,
            baseline_atom_entries: atom_entries,
            baseline_clauses: clauses,
            baseline_literal_slots: literal_slots,
            applications,
            application_pairs,
            maximum_arity,
            application_argument_slots: argument_slots,
        };
        if self.compiler.counters.input != self.expected_input_counters {
            self.failures.input(CheckerFailureKind::MalformedTrace);
        }
    }

    fn index_trace(&mut self) {
        let mut events = BTreeSet::new();
        let mut previous_event = None;
        for (trace_index, record) in self.compiler.trace.iter().enumerate() {
            let (event_id, node_id, clause_id) = match record {
                TraceRecord::Equality(record) => {
                    (record.event_id, Some(record.node_id.get()), None)
                }
                TraceRecord::Conflict(record) => {
                    (record.event_id, None, Some(record.clause_id.get()))
                }
            };
            if previous_event.is_some_and(|previous| previous >= event_id.get()) {
                self.failures
                    .event(CheckerFailureKind::TraceOrder, event_id);
            }
            previous_event = Some(event_id.get());
            if !events.insert(event_id.get()) {
                self.failures
                    .event(CheckerFailureKind::TraceOrder, event_id);
            }
            if let Some(node_id) = node_id {
                if self.node_positions.insert(node_id, trace_index).is_some() {
                    self.failures
                        .event(CheckerFailureKind::TraceOrder, event_id);
                }
            }
            if let Some(clause_id) = clause_id {
                if self
                    .clause_positions
                    .insert(clause_id, trace_index)
                    .is_some()
                {
                    self.failures
                        .event(CheckerFailureKind::TraceOrder, event_id);
                }
            }
        }
    }

    fn verify_compiler_trace_counters(&mut self) {
        let mut accepted_events = RuleCounters::default();
        let mut proof_parent_references = 0u64;
        let mut maximum_proof_depth = 0u64;
        let mut accepted_trace_literal_slots = 0u64;

        for record in &self.compiler.trace {
            let (counter, depth, literal_slots, parent_references) = match record {
                TraceRecord::Equality(record) => {
                    let (counter, parent_references) = match &record.rule {
                        EqualityRuleRecord::Seed(_) => (&mut accepted_events.seed, 0),
                        EqualityRuleRecord::Reflexivity(_) => (&mut accepted_events.reflexivity, 0),
                        EqualityRuleRecord::Transitivity(_) => {
                            (&mut accepted_events.transitivity, 2)
                        }
                        EqualityRuleRecord::Congruence(congruence) => (
                            &mut accepted_events.congruence,
                            checked_usize_to_u64(congruence.arguments.len(), &mut self.failures),
                        ),
                    };
                    (
                        counter,
                        record.depth.get(),
                        record.side_clause.len(),
                        parent_references,
                    )
                }
                TraceRecord::Conflict(record) => (
                    &mut accepted_events.conflict,
                    record.depth.get(),
                    record.clause.len(),
                    1,
                ),
            };
            *counter = checked_add_counter(*counter, 1, &mut self.failures);
            maximum_proof_depth = maximum_proof_depth.max(u64::from(depth));
            accepted_trace_literal_slots = checked_add_counter(
                accepted_trace_literal_slots,
                checked_usize_to_u64(literal_slots, &mut self.failures),
                &mut self.failures,
            );
            proof_parent_references = checked_add_counter(
                proof_parent_references,
                parent_references,
                &mut self.failures,
            );
        }

        let search = &self.compiler.counters.search;
        let event_ids_fit_popped_count = self.compiler.trace.iter().all(|record| {
            let event_id = match record {
                TraceRecord::Equality(record) => record.event_id,
                TraceRecord::Conflict(record) => record.event_id,
            };
            u64::from(event_id.get()) < search.events_popped
        });
        if search.accepted_events != accepted_events
            || search.accepted_equality_nodes != self.equality_records
            || search.accepted_conflict_clauses != self.conflict_records
            || search.proof_parent_references != proof_parent_references
            || search.maximum_proof_depth != maximum_proof_depth
            || search.accepted_trace_literal_slots != accepted_trace_literal_slots
            || !event_ids_fit_popped_count
        {
            self.failures.input(CheckerFailureKind::MalformedTrace);
        }
    }

    fn replay_trace(&mut self) {
        for (trace_index, record) in self.compiler.trace.iter().enumerate() {
            match record {
                TraceRecord::Equality(record) => {
                    self.equality_records =
                        checked_add_counter(self.equality_records, 1, &mut self.failures);
                    self.replay_equality(trace_index, record);
                }
                TraceRecord::Conflict(record) => {
                    self.conflict_records =
                        checked_add_counter(self.conflict_records, 1, &mut self.failures);
                    self.replay_conflict(trace_index, record);
                }
            }
        }
    }

    fn replay_equality(&mut self, trace_index: usize, record: &EqualityTraceRecord) {
        let event_id = record.event_id;
        let failures_before = self.failures.len();
        let expected_node_id = self.equality_records.saturating_sub(1);
        if u64::from(record.node_id.get()) != expected_node_id {
            self.failures
                .event(CheckerFailureKind::TraceOrder, event_id);
        }

        let stored_conclusion = self.validate_equality_key(record.conclusion, event_id);
        let stored_side = self.validate_stored_clause(
            &record.side_clause,
            event_id,
            CheckerFailureKind::SideClause,
        );

        let expected = match &record.rule {
            EqualityRuleRecord::Seed(seed) => {
                let pivot = self.resolve_pivot(
                    seed.positive_source,
                    trace_index,
                    event_id,
                    PivotSign::Positive,
                );
                pivot.and_then(|pivot| {
                    let support = self.remove_pivot_and_union(&pivot, &[], event_id)?;
                    Some(ReplayedNode {
                        conclusion: pivot.equality,
                        side_clause: support,
                        depth: pivot.source.depth,
                        contains_missing_congruence: pivot.source.contains_missing_congruence,
                    })
                })
            }
            EqualityRuleRecord::Reflexivity(reflexivity) => {
                self.reflexivity_records.push((event_id, reflexivity.term));
                if self.input.term_dag.get(reflexivity.term).is_none() {
                    self.failures.event(CheckerFailureKind::TermId, event_id);
                    None
                } else {
                    Some(ReplayedNode {
                        conclusion: (reflexivity.term, reflexivity.term),
                        side_clause: Vec::new(),
                        depth: 0,
                        contains_missing_congruence: false,
                    })
                }
            }
            EqualityRuleRecord::Transitivity(transitivity) => {
                if transitivity.parents[0] > transitivity.parents[1] {
                    self.failures
                        .event(CheckerFailureKind::ParentOrder, event_id);
                }
                let left = self.resolve_parent(transitivity.parents[0], trace_index, event_id);
                let right = self.resolve_parent(transitivity.parents[1], trace_index, event_id);
                let intermediate_valid =
                    self.input.term_dag.get(transitivity.intermediate).is_some();
                if !intermediate_valid {
                    self.failures.event(CheckerFailureKind::TermId, event_id);
                }
                match (left, right, intermediate_valid) {
                    (Some(left), Some(right), true) => (|| {
                        let left_outer = other_endpoint(left.conclusion, transitivity.intermediate);
                        let right_outer =
                            other_endpoint(right.conclusion, transitivity.intermediate);
                        let (Some(left_outer), Some(right_outer)) = (left_outer, right_outer)
                        else {
                            self.failures
                                .event(CheckerFailureKind::TransitivityEndpoints, event_id);
                            return None;
                        };
                        let Some(conclusion) =
                            self.normalize_pair(left_outer, right_outer, event_id)
                        else {
                            return None;
                        };
                        let support = self.union_supports(
                            [&left.side_clause[..], &right.side_clause[..]],
                            event_id,
                        )?;
                        let depth = self.increment_depth(left.depth.max(right.depth), event_id)?;
                        Some(ReplayedNode {
                            conclusion,
                            side_clause: support,
                            depth,
                            contains_missing_congruence: left.contains_missing_congruence
                                || right.contains_missing_congruence,
                        })
                    })(),
                    _ => None,
                }
            }
            EqualityRuleRecord::Congruence(congruence) => {
                self.replay_congruence(trace_index, event_id, congruence)
            }
        };

        let Some(expected) = expected else {
            return;
        };
        if stored_conclusion != Some(expected.conclusion) {
            self.failures
                .event(CheckerFailureKind::Conclusion, event_id);
        }
        if stored_side.as_deref() != Some(expected.side_clause.as_slice()) {
            self.failures
                .event(CheckerFailureKind::SideClause, event_id);
        }
        if record.depth.get() != expected.depth {
            self.failures
                .event(CheckerFailureKind::MalformedTrace, event_id);
        }
        if self.failures.len() == failures_before
            && self
                .replayed_nodes
                .insert(record.node_id.get(), expected)
                .is_some()
        {
            self.failures
                .event(CheckerFailureKind::TraceOrder, event_id);
        }
    }

    fn replay_congruence(
        &mut self,
        trace_index: usize,
        event_id: EventId,
        congruence: &CongruenceRecord,
    ) -> Option<ReplayedNode> {
        let left_id = congruence.applications[0].term();
        let right_id = congruence.applications[1].term();
        if left_id >= right_id {
            self.failures
                .event(CheckerFailureKind::CongruenceApplicationOrder, event_id);
        }
        let Some(left) = self.input.term_dag.get(left_id) else {
            self.failures.event(CheckerFailureKind::TermId, event_id);
            return None;
        };
        let Some(right) = self.input.term_dag.get(right_id) else {
            self.failures.event(CheckerFailureKind::TermId, event_id);
            return None;
        };
        if left.args.is_empty() || right.args.is_empty() {
            self.failures.event(CheckerFailureKind::Arity, event_id);
            return None;
        }
        if left.fun != right.fun {
            self.failures.event(CheckerFailureKind::Function, event_id);
        }
        if left.args.len() != right.args.len() {
            self.failures.event(CheckerFailureKind::Arity, event_id);
            return None;
        }
        if left.sort != right.sort {
            self.failures.event(CheckerFailureKind::Sort, event_id);
        }
        if left.sort == BOOL_SORT {
            self.failures.event(CheckerFailureKind::Sort, event_id);
        }

        let differing: Vec<_> = left
            .args
            .iter()
            .zip(&right.args)
            .enumerate()
            .filter_map(|(index, (&left, &right))| (left != right).then_some((index, left, right)))
            .collect();
        if differing.len() != congruence.arguments.len() {
            self.failures
                .event(CheckerFailureKind::CongruenceArgumentAssociation, event_id);
        }
        if congruence
            .arguments
            .windows(2)
            .any(|pair| pair[0].argument_index >= pair[1].argument_index)
        {
            self.failures
                .event(CheckerFailureKind::CongruenceArgumentOrder, event_id);
        }

        let mut parents = Vec::new();
        if parents.try_reserve(differing.len()).is_err() {
            self.failures
                .event(CheckerFailureKind::ArithmeticOverflow, event_id);
            return None;
        }
        for (position, &(argument_index, left_argument, right_argument)) in
            differing.iter().enumerate()
        {
            let Some(association) = congruence.arguments.get(position) else {
                continue;
            };
            if association.argument_index.get() as usize != argument_index {
                self.failures
                    .event(CheckerFailureKind::CongruenceArgumentAssociation, event_id);
            }
            let Some(parent) = self.resolve_parent(association.parent, trace_index, event_id)
            else {
                continue;
            };
            let expected = normalized_pair(left_argument, right_argument);
            if parent.conclusion != expected {
                self.failures
                    .event(CheckerFailureKind::CongruenceArgumentAssociation, event_id);
            }
            parents.push(parent);
        }
        if parents.len() != differing.len() || differing.is_empty() {
            if differing.is_empty() {
                self.failures
                    .event(CheckerFailureKind::CongruenceArgumentAssociation, event_id);
            }
            return None;
        }

        let conclusion = self.normalize_pair(left_id, right_id, event_id)?;
        let own_missing = !self.equality_is_materialized(conclusion)
            || parents
                .iter()
                .any(|parent| !self.equality_is_materialized(parent.conclusion));
        if self.compiler.variant == CompilerVariant::SuppressMissingEqualityCongruence
            && own_missing
        {
            self.failures
                .event(CheckerFailureKind::MalformedTrace, event_id);
        }
        let support_slices: Vec<_> = parents
            .iter()
            .map(|parent| parent.side_clause.as_slice())
            .collect();
        let support = self.union_supports(support_slices, event_id)?;
        let maximum_parent_depth = parents.iter().map(|parent| parent.depth).max()?;
        let depth = self.increment_depth(maximum_parent_depth, event_id)?;
        let inherited_missing = parents
            .iter()
            .any(|parent| parent.contains_missing_congruence);
        Some(ReplayedNode {
            conclusion,
            side_clause: support,
            depth,
            contains_missing_congruence: own_missing || inherited_missing,
        })
    }

    fn replay_conflict(
        &mut self,
        trace_index: usize,
        record: &super::t11_eqres_types::ConflictTraceRecord,
    ) {
        let event_id = record.event_id;
        let failures_before = self.failures.len();
        let expected_id = checked_add_counter(
            checked_usize_to_u64(self.base_ranges.len(), &mut self.failures),
            self.conflict_records.saturating_sub(1),
            &mut self.failures,
        );
        if u64::from(record.clause_id.get()) != expected_id {
            self.failures
                .event(CheckerFailureKind::TraceOrder, event_id);
        }
        let stored_clause = self.validate_stored_clause(
            &record.clause,
            event_id,
            CheckerFailureKind::ConflictResolvent,
        );
        let parent = self.resolve_parent(record.rule.equality_parent, trace_index, event_id);
        let pivot = self.resolve_pivot(
            record.rule.negative_source,
            trace_index,
            event_id,
            PivotSign::Negative,
        );
        let (Some(parent), Some(pivot)) = (parent, pivot) else {
            return;
        };
        if parent.conclusion != pivot.equality {
            self.failures
                .event(CheckerFailureKind::Conclusion, event_id);
        }
        let resolvent =
            self.remove_pivot_and_union(&pivot, &[parent.side_clause.as_slice()], event_id);
        let Some(resolvent) = resolvent else {
            return;
        };
        if stored_clause.as_deref() != Some(resolvent.as_slice()) {
            self.failures
                .event(CheckerFailureKind::ConflictResolvent, event_id);
        }
        let maximum_depth = parent.depth.max(pivot.source.depth);
        let Some(depth) = self.increment_depth(maximum_depth, event_id) else {
            return;
        };
        if record.depth.get() != depth {
            self.failures
                .event(CheckerFailureKind::MalformedTrace, event_id);
        }
        if !self.seen_derived_clauses.insert(resolvent.clone()) {
            self.failures
                .event(CheckerFailureKind::MalformedTrace, event_id);
        }
        if resolvent.is_empty() && trace_index + 1 != self.compiler.trace.len() {
            self.failures
                .event(CheckerFailureKind::TraceOrder, event_id);
        }
        if self.failures.len() == failures_before {
            let replayed = ReplayedClause {
                id: record.clause_id.get(),
                event_id,
                literals: resolvent,
                depth,
                contains_missing_congruence: parent.contains_missing_congruence
                    || pivot.source.contains_missing_congruence,
                trace_index,
            };
            if self
                .replayed_clauses
                .insert(record.clause_id.get(), replayed)
                .is_some()
            {
                self.failures
                    .event(CheckerFailureKind::TraceOrder, event_id);
            }
        }
    }

    fn verify_reflexivity_sequence(&mut self) {
        let mut previous = None;
        for &(event_id, term) in &self.reflexivity_records {
            if term >= self.input.term_dag.len()
                || previous.is_some_and(|previous| previous >= term)
            {
                self.failures
                    .event(CheckerFailureKind::ReflexivityOrder, event_id);
            }
            previous = Some(term);
        }
    }

    fn resolve_parent(
        &mut self,
        node_id: NodeId,
        trace_index: usize,
        event_id: EventId,
    ) -> Option<ReplayedNode> {
        let Some(&parent_position) = self.node_positions.get(&node_id.get()) else {
            self.failures
                .event(CheckerFailureKind::ParentNotEarlier, event_id);
            return None;
        };
        if parent_position >= trace_index {
            self.failures
                .event(CheckerFailureKind::ParentNotEarlier, event_id);
            return None;
        }
        let Some(parent) = self.replayed_nodes.get(&node_id.get()) else {
            self.failures
                .event(CheckerFailureKind::MalformedTrace, event_id);
            return None;
        };
        Some(parent.clone())
    }

    fn resolve_pivot(
        &mut self,
        pivot: ClausePivot,
        trace_index: usize,
        event_id: EventId,
        sign: PivotSign,
    ) -> Option<ResolvedPivot> {
        let source = self.resolve_clause(pivot.clause, trace_index, event_id)?;
        let offset = pivot.literal_offset.get() as usize;
        let Some(&literal) = source.literals.get(offset) else {
            self.failures
                .event(CheckerFailureKind::LiteralOffset, event_id);
            return None;
        };
        let sign_matches = match sign {
            PivotSign::Positive => literal > 0,
            PivotSign::Negative => literal < 0,
        };
        if !sign_matches {
            self.failures.event(CheckerFailureKind::PivotSign, event_id);
            return None;
        }
        let variable = literal.unsigned_abs() as usize;
        let Some(atom) = self
            .input
            .variable_atoms
            .get(variable)
            .and_then(Option::as_ref)
        else {
            self.failures.event(CheckerFailureKind::PivotKind, event_id);
            return None;
        };
        let BoolAtomKey::Eq(left, right) = atom else {
            self.failures.event(CheckerFailureKind::PivotKind, event_id);
            return None;
        };
        let equality = self.normalize_pair(*left, *right, event_id)?;
        Some(ResolvedPivot {
            source,
            offset,
            equality,
        })
    }

    fn resolve_clause(
        &mut self,
        reference: ClauseRef,
        trace_index: usize,
        event_id: EventId,
    ) -> Option<ResolvedClause> {
        match reference.origin {
            ClauseOrigin::Baseline => {
                let clause_index = reference.id.get() as usize;
                let Some(Some((start, end))) = self.base_ranges.get(clause_index).copied() else {
                    self.failures
                        .event(CheckerFailureKind::BaselineClauseReference, event_id);
                    return None;
                };
                let Some(literals) = self
                    .input
                    .baseline_clauses
                    .literals
                    .get(start..end)
                    .map(<[i32]>::to_vec)
                else {
                    self.failures
                        .event(CheckerFailureKind::BaselineClauseReference, event_id);
                    return None;
                };
                Some(ResolvedClause {
                    literals,
                    depth: 0,
                    contains_missing_congruence: false,
                })
            }
            ClauseOrigin::Derived => {
                let Some(&source_position) = self.clause_positions.get(&reference.id.get()) else {
                    self.failures
                        .event(CheckerFailureKind::DerivedClauseReference, event_id);
                    return None;
                };
                if source_position >= trace_index {
                    self.failures
                        .event(CheckerFailureKind::SourceNotEarlier, event_id);
                    return None;
                }
                let Some(clause) = self.replayed_clauses.get(&reference.id.get()) else {
                    self.failures
                        .event(CheckerFailureKind::MalformedTrace, event_id);
                    return None;
                };
                Some(ResolvedClause {
                    literals: clause.literals.clone(),
                    depth: clause.depth,
                    contains_missing_congruence: clause.contains_missing_congruence,
                })
            }
        }
    }

    fn validate_equality_key(
        &mut self,
        key: EqualityKey,
        event_id: EventId,
    ) -> Option<(TermId, TermId)> {
        let (left, right) = key.endpoints();
        if left > right {
            self.failures
                .event(CheckerFailureKind::Conclusion, event_id);
            return None;
        }
        let Some(left_term) = self.input.term_dag.get(left) else {
            self.failures.event(CheckerFailureKind::TermId, event_id);
            return None;
        };
        let Some(right_term) = self.input.term_dag.get(right) else {
            self.failures.event(CheckerFailureKind::TermId, event_id);
            return None;
        };
        if left_term.sort != right_term.sort {
            self.failures.event(CheckerFailureKind::Sort, event_id);
            return None;
        }
        Some((left, right))
    }

    fn validate_stored_clause(
        &mut self,
        clause: &CanonicalClause,
        event_id: EventId,
        mismatch_kind: CheckerFailureKind,
    ) -> Option<Vec<i32>> {
        match inspect_canonical(clause.as_slice()) {
            Canonicalized::Clause(literals) => Some(literals),
            Canonicalized::Tautology => {
                self.failures
                    .event(CheckerFailureKind::TautologicalClause, event_id);
                None
            }
            Canonicalized::Invalid => {
                self.failures.event(mismatch_kind, event_id);
                None
            }
        }
    }

    fn remove_pivot_and_union(
        &mut self,
        pivot: &ResolvedPivot,
        additional: &[&[i32]],
        event_id: EventId,
    ) -> Option<Vec<i32>> {
        let before = pivot.source.literals.get(..pivot.offset)?;
        let after = pivot
            .source
            .literals
            .get(pivot.offset.saturating_add(1)..)?;
        let mut slices = Vec::new();
        if slices
            .try_reserve(additional.len().saturating_add(2))
            .is_err()
        {
            self.failures
                .event(CheckerFailureKind::ArithmeticOverflow, event_id);
            return None;
        }
        slices.push(before);
        slices.push(after);
        slices.extend_from_slice(additional);
        self.union_supports(slices, event_id)
    }

    fn union_supports<'b>(
        &mut self,
        supports: impl IntoIterator<Item = &'b [i32]>,
        event_id: EventId,
    ) -> Option<Vec<i32>> {
        match canonicalize_slices(supports) {
            Canonicalized::Clause(clause) => Some(clause),
            Canonicalized::Tautology => {
                self.failures
                    .event(CheckerFailureKind::TautologicalClause, event_id);
                None
            }
            Canonicalized::Invalid => {
                self.failures
                    .event(CheckerFailureKind::SideClause, event_id);
                None
            }
        }
    }

    fn normalize_pair(
        &mut self,
        left: TermId,
        right: TermId,
        event_id: EventId,
    ) -> Option<(TermId, TermId)> {
        let Some(left_term) = self.input.term_dag.get(left) else {
            self.failures.event(CheckerFailureKind::TermId, event_id);
            return None;
        };
        let Some(right_term) = self.input.term_dag.get(right) else {
            self.failures.event(CheckerFailureKind::TermId, event_id);
            return None;
        };
        if left_term.sort != right_term.sort {
            self.failures.event(CheckerFailureKind::Sort, event_id);
            return None;
        }
        Some(normalized_pair(left, right))
    }

    fn increment_depth(&mut self, depth: u32, event_id: EventId) -> Option<u32> {
        match depth.checked_add(1) {
            Some(depth) => Some(depth),
            None => {
                self.failures
                    .event(CheckerFailureKind::ArithmeticOverflow, event_id);
                None
            }
        }
    }

    fn equality_is_materialized(&self, equality: (TermId, TermId)) -> bool {
        self.input
            .atom_variables
            .contains_key(&BoolAtomKey::Eq(equality.0, equality.1))
    }

    fn sort_exists(&self, sort: SortId) -> bool {
        (sort.0 as usize) < self.input.sorts.names.len()
    }

    fn reconstruct_and_verify_output(&mut self) {
        let mut derived: Vec<_> = self.replayed_clauses.values().cloned().collect();
        derived.sort_by_key(|clause| clause.trace_index);
        let empty_clauses: Vec<_> = derived
            .iter()
            .filter(|clause| clause.literals.is_empty())
            .cloned()
            .collect();

        self.expected_output = if let Some(terminal) = empty_clauses.first() {
            if empty_clauses.len() != 1
                || terminal.trace_index.saturating_add(1) != self.compiler.trace.len()
            {
                self.failures.input(CheckerFailureKind::OutcomeShape);
            }
            ExpectedOutput::TheoryEmpty {
                terminal_event_id: terminal.event_id,
                lemma: ExpectedLemma {
                    source_clause_id: terminal.id,
                    clause: Vec::new(),
                    contains_missing_congruence: terminal.contains_missing_congruence,
                },
            }
        } else {
            derived.sort_by(|left, right| {
                (left.literals.len(), left.literals.as_slice(), left.id).cmp(&(
                    right.literals.len(),
                    right.literals.as_slice(),
                    right.id,
                ))
            });
            let mut retained = Vec::<ExpectedLemma>::new();
            for clause in derived {
                if self
                    .normalized_base_clauses
                    .iter()
                    .flatten()
                    .any(|base| is_subset(base, &clause.literals))
                {
                    self.final_base_discards =
                        checked_add_counter(self.final_base_discards, 1, &mut self.failures);
                    continue;
                }
                if retained
                    .iter()
                    .any(|earlier| is_subset(&earlier.clause, &clause.literals))
                {
                    self.final_output_discards =
                        checked_add_counter(self.final_output_discards, 1, &mut self.failures);
                    continue;
                }
                retained.push(ExpectedLemma {
                    source_clause_id: clause.id,
                    clause: clause.literals,
                    contains_missing_congruence: clause.contains_missing_congruence,
                });
            }
            if retained.is_empty() {
                ExpectedOutput::NoLemmas
            } else {
                ExpectedOutput::Lemmas(retained)
            }
        };

        self.expected_output_counters =
            compute_output_counters(&self.expected_output, &mut self.failures);
        if self.compiler.counters.output != self.expected_output_counters {
            self.failures.input(CheckerFailureKind::OutcomeShape);
        }
        if self
            .compiler
            .counters
            .pruning
            .final_base_subsumption_discards
            != self.final_base_discards
            || self
                .compiler
                .counters
                .pruning
                .final_output_subsumption_discards
                != self.final_output_discards
        {
            self.failures.input(CheckerFailureKind::OutcomeShape);
        }

        match self.compiler.status.clone() {
            CompilerStatus::Completed(output) => self.verify_actual_output(&output),
            CompilerStatus::NotRun | CompilerStatus::Rejected(_) => {
                self.failures.input(CheckerFailureKind::OutcomeShape);
            }
        }
    }

    fn recompute_and_verify_hashes(&mut self) -> HashBindings {
        let mut hashes = HashBindings::default();

        hashes.source_sha256 = self.digest_raw(self.input.source_bytes);
        self.compare_hash(
            hashes.source_sha256,
            self.compiler.hashes.source_sha256,
            HashArtifact::Source,
        );
        hashes.root_cnf_mode_sha256 = self.digest_raw(self.input.root_cnf_mode);
        self.compare_hash(
            hashes.root_cnf_mode_sha256,
            self.compiler.hashes.root_cnf_mode_sha256,
            HashArtifact::RootCnfMode,
        );
        hashes.term_dag_sha256 = self.digest_encoded(encode_term_dag);
        self.compare_hash(
            hashes.term_dag_sha256,
            self.compiler.hashes.term_dag_sha256,
            HashArtifact::TermDag,
        );
        hashes.atom_map_sha256 = self.digest_encoded(encode_atom_map);
        self.compare_hash(
            hashes.atom_map_sha256,
            self.compiler.hashes.atom_map_sha256,
            HashArtifact::AtomMap,
        );
        hashes.baseline_cnf_sha256 = self.digest_encoded(encode_baseline_cnf);
        self.compare_hash(
            hashes.baseline_cnf_sha256,
            self.compiler.hashes.baseline_cnf_sha256,
            HashArtifact::BaselineCnf,
        );
        hashes.baseline_problem_sha256 = self.digest_encoded(encode_baseline_problem);
        self.compare_hash(
            hashes.baseline_problem_sha256,
            self.compiler.hashes.baseline_problem_sha256,
            HashArtifact::BaselineProblem,
        );
        hashes.trace_sha256 =
            digest_with(|encoder| encode_compiler_trace(encoder, &self.compiler.trace))
                .unwrap_or_else(|| {
                    self.failures.input(CheckerFailureKind::ArithmeticOverflow);
                    Sha256Digest::ZERO
                });
        self.compare_hash(
            hashes.trace_sha256,
            self.compiler.hashes.trace_sha256,
            HashArtifact::Trace,
        );

        let expected_output = self.expected_output.clone();
        hashes.lemma_sequence_sha256 =
            digest_with(|encoder| encode_lemma_sequence(encoder, &expected_output)).unwrap_or_else(
                || {
                    self.failures.input(CheckerFailureKind::ArithmeticOverflow);
                    Sha256Digest::ZERO
                },
            );
        self.compare_hash(
            hashes.lemma_sequence_sha256,
            self.compiler.hashes.lemma_sequence_sha256,
            HashArtifact::LemmaSequence,
        );
        let materialized_shape_valid = materialized_store_has_valid_shape(self.materialized);
        hashes.materialized_lemmas_sha256 =
            digest_with(|encoder| encode_materialized_lemmas(encoder, self.materialized))
                .unwrap_or_else(|| {
                    if materialized_shape_valid {
                        self.failures.input(CheckerFailureKind::ArithmeticOverflow);
                    }
                    Sha256Digest::ZERO
                });
        self.compare_hash(
            hashes.materialized_lemmas_sha256,
            self.compiler.hashes.materialized_lemmas_sha256,
            HashArtifact::MaterializedLemmas,
        );
        hashes.materialized_candidate_sha256 = digest_with(|encoder| {
            encode_materialized_candidate(encoder, self.input, self.materialized)
        })
        .unwrap_or_else(|| {
            if materialized_shape_valid {
                self.failures.input(CheckerFailureKind::ArithmeticOverflow);
            }
            Sha256Digest::ZERO
        });
        self.compare_hash(
            hashes.materialized_candidate_sha256,
            self.compiler.hashes.materialized_candidate_sha256,
            HashArtifact::MaterializedCandidate,
        );
        hashes
    }

    fn verify_materialized_output(&mut self) {
        if !materialized_store_has_valid_shape(self.materialized) {
            self.failures.input(CheckerFailureKind::OutcomeShape);
            return;
        }

        let expected = self.expected_output.lemmas();
        if expected.len() != self.materialized.len() {
            self.failures.input(CheckerFailureKind::OutcomeShape);
        }
        for (index, expected_lemma) in expected.iter().enumerate() {
            let Some(actual_clause) = self.materialized.clause(index) else {
                break;
            };
            if expected_lemma.clause.as_slice() == actual_clause {
                continue;
            }
            let belongs_elsewhere = expected.iter().enumerate().any(|(other_index, candidate)| {
                other_index != index && candidate.clause.as_slice() == actual_clause
            });
            if belongs_elsewhere {
                self.failures.input(CheckerFailureKind::OutputOrder);
            } else {
                self.failures.input(CheckerFailureKind::OutputClause);
            }
        }
    }

    fn verify_actual_output(&mut self, output: &EqresOutput) {
        let expected_output = self.expected_output.clone();
        match (&expected_output, output) {
            (ExpectedOutput::NoLemmas, EqresOutput::NoLemmas) => {
                self.replayed_emitted_lemmas = 0;
            }
            (ExpectedOutput::Lemmas(expected), EqresOutput::Lemmas(actual)) => {
                self.replayed_emitted_lemmas =
                    checked_usize_to_u64(actual.len(), &mut self.failures);
                self.verify_lemma_list(expected, actual);
            }
            (
                ExpectedOutput::TheoryEmpty {
                    terminal_event_id,
                    lemma,
                },
                EqresOutput::TheoryEmpty {
                    terminal_event_id: actual_event,
                    lemma: actual_lemma,
                },
            ) => {
                self.replayed_emitted_lemmas = 1;
                if terminal_event_id != actual_event {
                    self.failures.input(CheckerFailureKind::OutcomeShape);
                }
                self.verify_lemma_list(
                    std::slice::from_ref(lemma),
                    std::slice::from_ref(actual_lemma),
                );
                if !actual_lemma.clause.is_empty() {
                    self.failures.input(CheckerFailureKind::OutcomeShape);
                }
            }
            (_, EqresOutput::Lemmas(actual)) => {
                self.replayed_emitted_lemmas =
                    checked_usize_to_u64(actual.len(), &mut self.failures);
                self.failures.input(CheckerFailureKind::OutcomeShape);
            }
            (_, EqresOutput::TheoryEmpty { .. }) => {
                self.replayed_emitted_lemmas = 1;
                self.failures.input(CheckerFailureKind::OutcomeShape);
            }
            (_, EqresOutput::NoLemmas) => {
                self.replayed_emitted_lemmas = 0;
                self.failures.input(CheckerFailureKind::OutcomeShape);
            }
        }
    }

    fn verify_lemma_list(&mut self, expected: &[ExpectedLemma], actual: &[EmittedLemma]) {
        if expected.len() != actual.len() {
            self.failures.input(CheckerFailureKind::OutcomeShape);
        }
        for actual_lemma in actual {
            match inspect_canonical(actual_lemma.clause.as_slice()) {
                Canonicalized::Clause(_) => {}
                Canonicalized::Tautology => {
                    self.failures.input(CheckerFailureKind::TautologicalClause)
                }
                Canonicalized::Invalid => self.failures.input(CheckerFailureKind::OutputClause),
            }
        }
        for (index, (expected_lemma, actual_lemma)) in expected.iter().zip(actual).enumerate() {
            let matches = expected_lemma.source_clause_id == actual_lemma.source_clause_id.get()
                && expected_lemma.clause.as_slice() == actual_lemma.clause.as_slice();
            if matches {
                continue;
            }
            let belongs_elsewhere = actual.iter().enumerate().any(|(other_index, _candidate)| {
                other_index != index
                    && expected.get(other_index).is_some_and(|expected_at_other| {
                        expected_at_other.source_clause_id == actual_lemma.source_clause_id.get()
                            && expected_at_other.clause.as_slice() == actual_lemma.clause.as_slice()
                    })
            });
            if belongs_elsewhere {
                self.failures.input(CheckerFailureKind::OutputOrder);
            } else {
                self.failures.input(CheckerFailureKind::OutputClause);
            }
        }
    }

    fn digest_raw(&mut self, bytes: &[u8]) -> Sha256Digest {
        digest_bytes(bytes).unwrap_or_else(|| {
            self.failures.input(CheckerFailureKind::ArithmeticOverflow);
            Sha256Digest::ZERO
        })
    }

    fn digest_encoded(&mut self, encode: fn(&mut Encoder, EqresInput<'_>) -> bool) -> Sha256Digest {
        digest_with(|encoder| encode(encoder, self.input)).unwrap_or_else(|| {
            self.failures.input(CheckerFailureKind::ArithmeticOverflow);
            Sha256Digest::ZERO
        })
    }

    fn compare_hash(
        &mut self,
        recomputed: Sha256Digest,
        recorded: Sha256Digest,
        artifact: HashArtifact,
    ) {
        if recomputed != recorded {
            self.failures.hash(artifact);
        }
    }
}

#[derive(Clone, Copy)]
enum PivotSign {
    Positive,
    Negative,
}

fn normalized_pair(left: TermId, right: TermId) -> (TermId, TermId) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

fn other_endpoint(pair: (TermId, TermId), intermediate: TermId) -> Option<TermId> {
    if pair.0 == intermediate {
        Some(pair.1)
    } else if pair.1 == intermediate {
        Some(pair.0)
    } else {
        None
    }
}

fn inspect_canonical(literals: &[i32]) -> Canonicalized {
    if literals.iter().any(|&literal| literal == 0)
        || literals.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Canonicalized::Invalid;
    }
    if has_complementary_literals(literals) {
        return Canonicalized::Tautology;
    }
    Canonicalized::Clause(literals.to_vec())
}

fn canonicalize_slices<'a>(slices: impl IntoIterator<Item = &'a [i32]>) -> Canonicalized {
    let slices: Vec<_> = slices.into_iter().collect();
    let Some(total) = slices
        .iter()
        .try_fold(0usize, |total, slice| total.checked_add(slice.len()))
    else {
        return Canonicalized::Invalid;
    };
    let mut literals = Vec::new();
    if literals.try_reserve(total).is_err() {
        return Canonicalized::Invalid;
    }
    for slice in slices {
        if slice.iter().any(|&literal| literal == 0) {
            return Canonicalized::Invalid;
        }
        literals.extend_from_slice(slice);
    }
    literals.sort_unstable();
    literals.dedup();
    if has_complementary_literals(&literals) {
        Canonicalized::Tautology
    } else {
        Canonicalized::Clause(literals)
    }
}

fn has_complementary_literals(literals: &[i32]) -> bool {
    literals.iter().any(|&literal| {
        literal
            .checked_neg()
            .is_some_and(|complement| literals.binary_search(&complement).is_ok())
    })
}

fn checked_usize_to_u64(value: usize, failures: &mut FailureSink) -> u64 {
    match u64::try_from(value) {
        Ok(value) => value,
        Err(_) => {
            failures.input(CheckerFailureKind::ArithmeticOverflow);
            u64::MAX
        }
    }
}

fn checked_add_counter(left: u64, right: u64, failures: &mut FailureSink) -> u64 {
    match left.checked_add(right) {
        Some(value) => value,
        None => {
            failures.input(CheckerFailureKind::ArithmeticOverflow);
            u64::MAX
        }
    }
}

fn is_subset(subset: &[i32], superset: &[i32]) -> bool {
    let mut left = 0usize;
    let mut right = 0usize;
    while left < subset.len() && right < superset.len() {
        match subset[left].cmp(&superset[right]) {
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => {
                left += 1;
                right += 1;
            }
            std::cmp::Ordering::Greater => right += 1,
        }
    }
    left == subset.len()
}

fn compute_output_counters(output: &ExpectedOutput, failures: &mut FailureSink) -> OutputCounters {
    let lemmas = output.lemmas();
    let emitted_lemmas = checked_usize_to_u64(lemmas.len(), failures);
    let mut emitted_literal_slots = 0u64;
    let mut emitted_maximum_width = 0u64;
    let mut emitted_with_missing_equality_congruence = 0u64;
    let mut widths = Vec::new();
    if widths.try_reserve(lemmas.len()).is_err() {
        failures.input(CheckerFailureKind::ArithmeticOverflow);
    }
    for lemma in lemmas {
        let width = checked_usize_to_u64(lemma.clause.len(), failures);
        emitted_literal_slots = checked_add_counter(emitted_literal_slots, width, failures);
        emitted_maximum_width = emitted_maximum_width.max(width);
        if lemma.contains_missing_congruence {
            emitted_with_missing_equality_congruence =
                checked_add_counter(emitted_with_missing_equality_congruence, 1, failures);
        }
        widths.push(width);
    }
    widths.sort_unstable();
    let emitted_p95_width = if widths.is_empty() {
        0
    } else {
        let count = checked_usize_to_u64(widths.len(), failures);
        let rank = count
            .checked_mul(95)
            .and_then(|value| value.checked_add(99))
            .and_then(|value| value.checked_div(100));
        match rank
            .and_then(|rank| rank.checked_sub(1))
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| widths.get(index).copied())
        {
            Some(width) => width,
            None => {
                failures.input(CheckerFailureKind::ArithmeticOverflow);
                0
            }
        }
    };
    OutputCounters {
        emitted_lemmas,
        emitted_literal_slots,
        emitted_p95_width,
        emitted_maximum_width,
        emitted_with_missing_equality_congruence,
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
        if self.valid && !self.hash.update(bytes) {
            self.valid = false;
        }
        self.valid
    }

    fn domain(&mut self, domain: &[u8]) -> bool {
        self.raw(domain)
    }

    fn u8(&mut self, value: u8) -> bool {
        self.raw(&[value])
    }

    fn bool(&mut self, value: bool) -> bool {
        self.u8(u8::from(value))
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

    fn bytes(&mut self, bytes: &[u8]) -> bool {
        self.usize(bytes.len()) && self.raw(bytes)
    }

    fn finish(self) -> Option<Sha256Digest> {
        self.valid
            .then_some(self.hash)
            .and_then(LocalSha256::finalize)
            .map(Sha256Digest::new)
    }
}

fn digest_bytes(bytes: &[u8]) -> Option<Sha256Digest> {
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

fn encode_term_dag(encoder: &mut Encoder, input: EqresInput<'_>) -> bool {
    if !encoder.domain(b"euf-viper-t11-term-dag-v1\0") || !encoder.usize(input.sorts.names.len()) {
        return false;
    }
    for name in &input.sorts.names {
        if !encoder.bytes(name.as_bytes()) {
            return false;
        }
    }

    let mut sort_ids: Vec<_> = input
        .sorts
        .ids
        .iter()
        .map(|(&symbol, &sort)| (symbol, sort.0))
        .collect();
    sort_ids.sort_unstable();
    if !encoder.usize(sort_ids.len()) {
        return false;
    }
    for (symbol, sort) in sort_ids {
        if !encoder.u32(symbol) || !encoder.u32(sort) {
            return false;
        }
    }

    if !encoder.usize(input.declarations.slots.len()) {
        return false;
    }
    for declaration in &input.declarations.slots {
        match declaration {
            None => {
                if !encoder.u8(0) {
                    return false;
                }
            }
            Some(declaration) => {
                if !encoder.u8(1)
                    || !encoder.u32(declaration.result_sort.0)
                    || !encoder.usize(declaration.arg_sorts.len())
                {
                    return false;
                }
                for sort in &declaration.arg_sorts {
                    if !encoder.u32(sort.0) {
                        return false;
                    }
                }
            }
        }
    }

    if !encoder.usize(input.term_dag.len()) {
        return false;
    }
    for (term_id, term) in input.term_dag.iter().enumerate() {
        if !encoder.usize(term_id)
            || !encoder.u32(term.fun)
            || !encoder.u32(term.sort.0)
            || !encoder.usize(term.args.len())
        {
            return false;
        }
        for &argument in &term.args {
            if !encoder.usize(argument) {
                return false;
            }
        }
    }
    if !encoder.usize(input.ordered_applications.len()) {
        return false;
    }
    for &application in input.ordered_applications {
        if !encoder.usize(application) {
            return false;
        }
    }
    true
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
    encoder.bool(input.finite_equalities_complete)
        && encoder.bool(input.finite_predicate_congruence_complete)
}

fn encode_atom_map(encoder: &mut Encoder, input: EqresInput<'_>) -> bool {
    encoder.domain(b"euf-viper-t10-baseline-atom-map-v1\0")
        && encode_atom_map_payload(encoder, input)
}

fn encode_flat_clause_store(encoder: &mut Encoder, clauses: &FlatClauses) -> bool {
    if !encoder.usize(clauses.end_offsets.len()) {
        return false;
    }
    for &offset in &clauses.end_offsets {
        if !encoder.u32(offset) {
            return false;
        }
    }
    if !encoder.usize(clauses.literals.len()) {
        return false;
    }
    for &literal in &clauses.literals {
        if !encoder.i32(literal) {
            return false;
        }
    }
    true
}

fn encode_baseline_cnf(encoder: &mut Encoder, input: EqresInput<'_>) -> bool {
    encoder.domain(b"euf-viper-t10-baseline-cnf-v1\0")
        && encode_flat_clause_store(encoder, input.baseline_clauses)
}

fn encode_baseline_problem(encoder: &mut Encoder, input: EqresInput<'_>) -> bool {
    encoder.domain(b"euf-viper-t10-baseline-problem-v1\0")
        && encode_flat_clause_store(encoder, input.baseline_clauses)
        && encode_atom_map_payload(encoder, input)
}

fn encode_clause(encoder: &mut Encoder, clause: &[i32]) -> bool {
    if !encoder.usize(clause.len()) {
        return false;
    }
    clause.iter().all(|&literal| encoder.i32(literal))
}

fn encode_clause_ref(encoder: &mut Encoder, reference: ClauseRef) -> bool {
    let origin = match reference.origin {
        ClauseOrigin::Baseline => 0,
        ClauseOrigin::Derived => 1,
    };
    encoder.u32(reference.id.get()) && encoder.u8(origin)
}

fn encode_pivot(encoder: &mut Encoder, pivot: ClausePivot) -> bool {
    encode_clause_ref(encoder, pivot.clause) && encoder.u32(pivot.literal_offset.get())
}

fn encode_equality(encoder: &mut Encoder, equality: EqualityKey) -> bool {
    let (left, right) = equality.endpoints();
    encoder.usize(left) && encoder.usize(right)
}

fn encode_compiler_trace(encoder: &mut Encoder, trace: &[TraceRecord]) -> bool {
    if !encoder.domain(b"euf-viper-t11-trace-v1\0") || !encoder.usize(trace.len()) {
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
                        if !encoder.u8(0) || !encode_pivot(encoder, seed.positive_source) {
                            return false;
                        }
                    }
                    EqualityRuleRecord::Reflexivity(reflexivity) => {
                        if !encoder.u8(1) || !encoder.usize(reflexivity.term) {
                            return false;
                        }
                    }
                    EqualityRuleRecord::Transitivity(transitivity) => {
                        if !encoder.u8(2)
                            || !encoder.u32(transitivity.parents[0].get())
                            || !encoder.u32(transitivity.parents[1].get())
                            || !encoder.usize(transitivity.intermediate)
                        {
                            return false;
                        }
                    }
                    EqualityRuleRecord::Congruence(congruence) => {
                        if !encoder.u8(3)
                            || !encoder.usize(congruence.applications[0].term())
                            || !encoder.usize(congruence.applications[1].term())
                            || !encoder.usize(congruence.arguments.len())
                        {
                            return false;
                        }
                        for association in &congruence.arguments {
                            if !encoder.u32(association.argument_index.get())
                                || !encoder.u32(association.parent.get())
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
                    || !encoder.u8(4)
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

fn encode_lemma_sequence(encoder: &mut Encoder, output: &ExpectedOutput) -> bool {
    encoder.domain(b"euf-viper-t11-lemma-clause-sequence-v1\0")
        && encode_emitted_clause_payload(encoder, output)
}

fn encode_emitted_clause_payload(encoder: &mut Encoder, output: &ExpectedOutput) -> bool {
    let lemmas = output.lemmas();
    if !encoder.usize(lemmas.len()) {
        return false;
    }
    for lemma in lemmas {
        if !encode_clause(encoder, &lemma.clause) {
            return false;
        }
    }
    true
}

fn materialized_store_has_valid_shape(materialized: &MaterializedClauseStore) -> bool {
    materialized.end_offsets().first() == Some(&0)
        && materialized
            .end_offsets()
            .windows(2)
            .all(|bounds| bounds[0] <= bounds[1])
        && materialized.end_offsets().last().copied().map(u64::from)
            == u64::try_from(materialized.literals().len()).ok()
}

fn encode_materialized_clause_payload(
    encoder: &mut Encoder,
    materialized: &MaterializedClauseStore,
) -> bool {
    if !materialized_store_has_valid_shape(materialized) || !encoder.usize(materialized.len()) {
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

fn encode_materialized_lemmas(
    encoder: &mut Encoder,
    materialized: &MaterializedClauseStore,
) -> bool {
    encoder.domain(b"euf-viper-t11-lemma-clause-sequence-v1\0")
        && encode_materialized_clause_payload(encoder, materialized)
}

fn encode_materialized_candidate(
    encoder: &mut Encoder,
    input: EqresInput<'_>,
    materialized: &MaterializedClauseStore,
) -> bool {
    encoder.domain(b"euf-viper-t11-materialized-candidate-v1\0")
        && encode_flat_clause_store(encoder, input.baseline_clauses)
        && encode_materialized_clause_payload(encoder, materialized)
        && encode_atom_map_payload(encoder, input)
}

const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

struct LocalSha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    byte_len: u64,
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
        }
    }

    fn update(&mut self, mut bytes: &[u8]) -> bool {
        let Ok(length) = u64::try_from(bytes.len()) else {
            return false;
        };
        let Some(byte_len) = self.byte_len.checked_add(length) else {
            return false;
        };
        self.byte_len = byte_len;

        if self.buffered != 0 {
            let available = 64usize.saturating_sub(self.buffered);
            let take = available.min(bytes.len());
            let Some(destination) = self
                .buffer
                .get_mut(self.buffered..self.buffered.saturating_add(take))
            else {
                return false;
            };
            let Some(source) = bytes.get(..take) else {
                return false;
            };
            destination.copy_from_slice(source);
            self.buffered = self.buffered.saturating_add(take);
            bytes = &bytes[take..];
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            } else {
                return true;
            }
        }

        while bytes.len() >= 64 {
            let mut block = [0u8; 64];
            let Some(source) = bytes.get(..64) else {
                return false;
            };
            block.copy_from_slice(source);
            self.compress(&block);
            bytes = &bytes[64..];
        }
        let Some(destination) = self.buffer.get_mut(..bytes.len()) else {
            return false;
        };
        destination.copy_from_slice(bytes);
        self.buffered = bytes.len();
        true
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut schedule = [0u32; 64];
        for (index, word) in schedule.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }
        for index in 16..64 {
            let lower = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let upper = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(lower)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(upper);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..64 {
            let upper = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ (!e & g);
            let first = h
                .wrapping_add(upper)
                .wrapping_add(choice)
                .wrapping_add(SHA256_ROUND_CONSTANTS[index])
                .wrapping_add(schedule[index]);
            let lower = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let second = lower.wrapping_add(majority);
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

    fn finalize(mut self) -> Option<[u8; 32]> {
        let bit_len = self.byte_len.checked_mul(8)?;
        *self.buffer.get_mut(self.buffered)? = 0x80;
        self.buffered = self.buffered.checked_add(1)?;
        if self.buffered > 56 {
            self.buffer.get_mut(self.buffered..)?.fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0; 64];
            self.buffered = 0;
        }
        self.buffer.get_mut(self.buffered..56)?.fill(0);
        self.buffer
            .get_mut(56..64)?
            .copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);

        let mut output = [0u8; 32];
        for (index, value) in self.state.iter().copied().enumerate() {
            let offset = index * 4;
            output
                .get_mut(offset..offset + 4)?
                .copy_from_slice(&value.to_be_bytes());
        }
        Some(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FunDecl, FunDeclTable, SortTable, Term};
    use rustc_hash::FxHashMap;

    use crate::t11_eqres_types::{
        ApplicationId, ArgumentIndex, ClauseId, CompilerStatus, ConflictRecord,
        ConflictTraceRecord, CongruenceArgumentParent, DeterministicCounters, EqualityTraceRecord,
        LiteralOffset, ProofDepth, ReflexivityRecord, SeedRecord, TransitivityRecord,
    };

    const DATA_SORT: SortId = SortId(1);

    struct Fixture {
        source: Vec<u8>,
        root_cnf_mode: Vec<u8>,
        sorts: SortTable,
        declarations: FunDeclTable,
        terms: Vec<Term>,
        applications: Vec<TermId>,
        clauses: FlatClauses,
        variable_atoms: Vec<Option<BoolAtomKey>>,
        atom_variables: FxHashMap<BoolAtomKey, i32>,
        compiler: CompilerResult,
        materialized: MaterializedClauseStore,
    }

    impl Fixture {
        fn input(&self) -> EqresInput<'_> {
            EqresInput {
                source_bytes: &self.source,
                root_cnf_mode: &self.root_cnf_mode,
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

        fn run(&self) -> CheckerResult {
            check(self.input(), &self.compiler, &self.materialized)
        }

        fn reseal(&mut self) {
            let hashes = self.run().recomputed_hashes;
            self.compiler.hashes = hashes;
        }
    }

    fn canonical(literals: &[i32]) -> CanonicalClause {
        CanonicalClause::from_sorted(literals.to_vec()).expect("test clause is canonical")
    }

    fn equality(left: TermId, right: TermId) -> EqualityKey {
        EqualityKey::from_normalized(left, right).expect("test equality is normalized")
    }

    fn baseline_pivot(clause: u32, offset: u32) -> ClausePivot {
        ClausePivot {
            clause: ClauseRef {
                id: ClauseId::new(clause),
                origin: ClauseOrigin::Baseline,
            },
            literal_offset: LiteralOffset::new(offset),
        }
    }

    fn equality_record(
        event: u32,
        node: u32,
        depth: u32,
        conclusion: (TermId, TermId),
        side_clause: &[i32],
        rule: EqualityRuleRecord,
    ) -> TraceRecord {
        TraceRecord::Equality(EqualityTraceRecord {
            event_id: EventId::new(event),
            node_id: NodeId::new(node),
            depth: ProofDepth::new(depth),
            conclusion: equality(conclusion.0, conclusion.1),
            side_clause: canonical(side_clause),
            rule,
        })
    }

    fn fixture() -> Fixture {
        let sorts = SortTable {
            ids: FxHashMap::from_iter([(50, DATA_SORT)]),
            names: vec!["Bool".to_owned(), "U".to_owned()],
        };
        let constant = || FunDecl {
            arg_sorts: Vec::new(),
            result_sort: DATA_SORT,
        };
        let binary = || FunDecl {
            arg_sorts: vec![DATA_SORT, DATA_SORT],
            result_sort: DATA_SORT,
        };
        let declarations = FunDeclTable {
            slots: vec![
                Some(constant()),
                Some(constant()),
                Some(constant()),
                Some(binary()),
                Some(binary()),
            ],
        };
        let terms = vec![
            Term {
                fun: 0,
                args: Vec::new(),
                sort: DATA_SORT,
            },
            Term {
                fun: 1,
                args: Vec::new(),
                sort: DATA_SORT,
            },
            Term {
                fun: 2,
                args: Vec::new(),
                sort: DATA_SORT,
            },
            Term {
                fun: 3,
                args: vec![0, 0],
                sort: DATA_SORT,
            },
            Term {
                fun: 3,
                args: vec![2, 0],
                sort: DATA_SORT,
            },
        ];
        let clauses = FlatClauses {
            literals: vec![1, 6, 2, 7, -1, 8, -3, 9],
            end_offsets: vec![0, 2, 4, 6, 8],
        };
        let variable_atoms = vec![
            None,
            Some(BoolAtomKey::Eq(0, 1)),
            Some(BoolAtomKey::Eq(1, 2)),
            Some(BoolAtomKey::Eq(3, 4)),
            None,
            None,
            None,
            None,
            None,
            None,
        ];
        let atom_variables = FxHashMap::from_iter([
            (BoolAtomKey::Eq(0, 1), 1),
            (BoolAtomKey::Eq(1, 2), 2),
            (BoolAtomKey::Eq(3, 4), 3),
        ]);

        let mut trace = Vec::new();
        for term in 0..5 {
            trace.push(equality_record(
                term as u32,
                term as u32,
                0,
                (term, term),
                &[],
                EqualityRuleRecord::Reflexivity(ReflexivityRecord { term }),
            ));
        }
        trace.push(equality_record(
            5,
            5,
            0,
            (0, 1),
            &[6],
            EqualityRuleRecord::Seed(SeedRecord {
                positive_source: baseline_pivot(0, 0),
            }),
        ));
        trace.push(equality_record(
            6,
            6,
            0,
            (1, 2),
            &[7],
            EqualityRuleRecord::Seed(SeedRecord {
                positive_source: baseline_pivot(1, 0),
            }),
        ));
        trace.push(equality_record(
            7,
            7,
            1,
            (0, 2),
            &[6, 7],
            EqualityRuleRecord::Transitivity(TransitivityRecord {
                parents: [NodeId::new(5), NodeId::new(6)],
                intermediate: 1,
            }),
        ));
        trace.push(equality_record(
            8,
            8,
            2,
            (3, 4),
            &[6, 7],
            EqualityRuleRecord::Congruence(CongruenceRecord {
                applications: [ApplicationId::new(3), ApplicationId::new(4)],
                arguments: vec![CongruenceArgumentParent {
                    argument_index: ArgumentIndex::new(0),
                    parent: NodeId::new(7),
                }]
                .into_boxed_slice(),
            }),
        ));
        trace.push(TraceRecord::Conflict(ConflictTraceRecord {
            event_id: EventId::new(9),
            clause_id: ClauseId::new(4),
            depth: ProofDepth::new(1),
            clause: canonical(&[6, 8]),
            rule: ConflictRecord {
                equality_parent: NodeId::new(5),
                negative_source: baseline_pivot(2, 0),
            },
        }));
        trace.push(TraceRecord::Conflict(ConflictTraceRecord {
            event_id: EventId::new(10),
            clause_id: ClauseId::new(5),
            depth: ProofDepth::new(3),
            clause: canonical(&[6, 7, 9]),
            rule: ConflictRecord {
                equality_parent: NodeId::new(8),
                negative_source: baseline_pivot(3, 0),
            },
        }));

        let mut counters = DeterministicCounters::default();
        counters.input = InputCounters {
            terms: 5,
            baseline_variables: 9,
            baseline_atom_entries: 3,
            baseline_clauses: 4,
            baseline_literal_slots: 8,
            applications: 2,
            application_pairs: 1,
            maximum_arity: 2,
            application_argument_slots: 1,
        };
        counters.search.accepted_events = RuleCounters {
            seed: 2,
            reflexivity: 5,
            transitivity: 1,
            congruence: 1,
            conflict: 2,
        };
        counters.search.events_popped = 11;
        counters.search.accepted_equality_nodes = 9;
        counters.search.accepted_conflict_clauses = 2;
        counters.search.proof_parent_references = 5;
        counters.search.maximum_proof_depth = 3;
        counters.search.accepted_trace_literal_slots = 11;
        counters.output = OutputCounters {
            emitted_lemmas: 2,
            emitted_literal_slots: 5,
            emitted_p95_width: 3,
            emitted_maximum_width: 3,
            emitted_with_missing_equality_congruence: 1,
        };
        let output = EqresOutput::Lemmas(
            vec![
                EmittedLemma {
                    source_clause_id: ClauseId::new(4),
                    clause: canonical(&[6, 8]),
                },
                EmittedLemma {
                    source_clause_id: ClauseId::new(5),
                    clause: canonical(&[6, 7, 9]),
                },
            ]
            .into_boxed_slice(),
        );
        let compiler = CompilerResult {
            variant: CompilerVariant::Ordinary,
            status: CompilerStatus::Completed(output),
            trace: trace.into_boxed_slice(),
            counters,
            hashes: HashBindings::default(),
        };
        let materialized = MaterializedClauseStore::from_parts(vec![0, 2, 5], vec![6, 8, 6, 7, 9])
            .expect("test materialization is a valid flat store");
        let mut fixture = Fixture {
            source: b"(set-logic QF_UF)\n".to_vec(),
            root_cnf_mode: ROOT_CNF_MODE.to_vec(),
            sorts,
            declarations,
            terms,
            applications: vec![3, 4],
            clauses,
            variable_atoms,
            atom_variables,
            compiler,
            materialized,
        };
        fixture.reseal();
        fixture
    }

    fn failures(result: &CheckerResult) -> &[CheckerFailure] {
        match &result.status {
            CheckerStatus::Rejected(failures) => failures,
            CheckerStatus::NotRun => panic!("checker unexpectedly did not run"),
            CheckerStatus::Accepted => panic!("checker unexpectedly accepted mutation"),
        }
    }

    fn assert_rejects(fixture: &Fixture, kind: CheckerFailureKind) {
        let result = fixture.run();
        assert!(
            failures(&result).iter().any(|failure| failure.kind == kind),
            "missing {kind:?}: {:?}",
            result.status
        );
    }

    fn assert_rejects_with(
        fixture: &Fixture,
        kind: CheckerFailureKind,
        event_id: Option<u32>,
        artifact: Option<HashArtifact>,
    ) {
        let result = fixture.run();
        let expected_event = event_id.map(EventId::new);
        assert!(
            failures(&result).iter().any(|failure| {
                failure.kind == kind
                    && failure.event_id == expected_event
                    && failure.artifact == artifact
            }),
            "missing {kind:?} at {expected_event:?} for {artifact:?}: {:?}",
            result.status
        );
    }

    fn trace_equality_mut(compiler: &mut CompilerResult, index: usize) -> &mut EqualityTraceRecord {
        match compiler.trace.get_mut(index) {
            Some(TraceRecord::Equality(record)) => record,
            _ => panic!("fixture trace entry is not equality"),
        }
    }

    fn trace_conflict_mut(compiler: &mut CompilerResult, index: usize) -> &mut ConflictTraceRecord {
        match compiler.trace.get_mut(index) {
            Some(TraceRecord::Conflict(record)) => record,
            _ => panic!("fixture trace entry is not conflict"),
        }
    }

    fn two_argument_congruence_fixture() -> Fixture {
        let mut fixture = fixture();
        fixture.terms[4].args[1] = 1;
        let record = trace_equality_mut(&mut fixture.compiler, 8);
        let EqualityRuleRecord::Congruence(congruence) = &mut record.rule else {
            panic!("fixture rule is not congruence");
        };
        congruence.arguments = vec![
            CongruenceArgumentParent {
                argument_index: ArgumentIndex::new(0),
                parent: NodeId::new(7),
            },
            CongruenceArgumentParent {
                argument_index: ArgumentIndex::new(1),
                parent: NodeId::new(5),
            },
        ]
        .into_boxed_slice();
        fixture.compiler.counters.input.application_argument_slots = 2;
        fixture.compiler.counters.search.proof_parent_references = 6;
        fixture.reseal();
        fixture
    }

    #[test]
    fn accepts_independently_replayed_fixture() {
        let fixture = fixture();
        assert_eq!(
            fixture.compiler.hashes.trace_sha256.to_string(),
            "d224d4d1a3a7d8dfb714020b0448363d77e46cc76f822a2e250a02c5129be180"
        );
        let result = fixture.run();
        assert_eq!(result.status, CheckerStatus::Accepted);
        assert_eq!(result.counters.replayed_equality_nodes, 9);
        assert_eq!(result.counters.replayed_conflict_clauses, 2);
        assert_eq!(result.counters.replayed_emitted_lemmas, 2);
        assert_eq!(result.counters.replay_failures, 0);
    }

    #[test]
    fn accepts_unit_reflexive_seed_that_prunes_reflexivity() {
        let sorts = SortTable {
            ids: FxHashMap::from_iter([(50, DATA_SORT)]),
            names: vec!["Bool".to_owned(), "U".to_owned()],
        };
        let mut declarations = FunDeclTable::default();
        declarations.insert(
            0,
            FunDecl {
                arg_sorts: Vec::new(),
                result_sort: DATA_SORT,
            },
        );
        let terms = vec![Term {
            fun: 0,
            args: Vec::new(),
            sort: DATA_SORT,
        }];
        let mut clauses = FlatClauses::new();
        clauses.push(vec![1]);
        let equality_atom = BoolAtomKey::Eq(0, 0);
        let variable_atoms = vec![None, Some(equality_atom.clone())];
        let atom_variables = FxHashMap::from_iter([(equality_atom, 1)]);
        let input = EqresInput {
            source_bytes: b"unit-reflexive-seed",
            root_cnf_mode: ROOT_CNF_MODE,
            sorts: &sorts,
            declarations: &declarations,
            term_dag: &terms,
            ordered_applications: &[],
            baseline_clauses: &clauses,
            variable_atoms: &variable_atoms,
            atom_variables: &atom_variables,
            true_literal: None,
            finite_equalities_complete: false,
            finite_predicate_congruence_complete: false,
        };
        let compiler = crate::t11_eqres_compiler::compile(input, CompilerVariant::Ordinary);
        assert!(matches!(
            compiler.status,
            CompilerStatus::Completed(EqresOutput::NoLemmas)
        ));
        assert_eq!(compiler.trace.len(), 1);
        assert!(matches!(
            &compiler.trace[0],
            TraceRecord::Equality(EqualityTraceRecord {
                rule: EqualityRuleRecord::Seed(_),
                ..
            })
        ));
        assert_eq!(compiler.counters.search.accepted_events.reflexivity, 0);

        let result = check(input, &compiler, &MaterializedClauseStore::empty());
        assert_eq!(result.status, CheckerStatus::Accepted);
        assert_eq!(result.counters.replayed_equality_nodes, 1);
        assert_eq!(result.counters.replay_failures, 0);
    }

    #[test]
    fn local_sha256_matches_standard_vectors() {
        assert_eq!(digest_bytes(b"").unwrap(), Sha256Digest::EMPTY_BYTES);
        assert_eq!(
            digest_bytes(b"abc").unwrap().to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn raw_identity_and_common_emitted_clause_hashes_are_frozen() {
        let fixture = fixture();
        assert_eq!(
            fixture.compiler.hashes.source_sha256,
            digest_bytes(&fixture.source).unwrap()
        );
        assert_eq!(
            fixture.compiler.hashes.root_cnf_mode_sha256,
            digest_bytes(&fixture.root_cnf_mode).unwrap()
        );
        assert_eq!(
            fixture.compiler.hashes.lemma_sequence_sha256,
            fixture.compiler.hashes.materialized_lemmas_sha256
        );

        let no_lemmas = ExpectedOutput::NoLemmas;
        let one_empty = ExpectedOutput::TheoryEmpty {
            terminal_event_id: EventId::new(1),
            lemma: ExpectedLemma {
                source_clause_id: 0,
                clause: Vec::new(),
                contains_missing_congruence: false,
            },
        };
        let no_lemmas_hash = digest_with(|encoder| encode_lemma_sequence(encoder, &no_lemmas))
            .expect("zero-clause plan hash");
        let no_lemmas_store = MaterializedClauseStore::empty();
        let no_lemmas_materialized =
            digest_with(|encoder| encode_materialized_lemmas(encoder, &no_lemmas_store))
                .expect("zero-clause materialized hash");
        let empty_hash = digest_with(|encoder| encode_lemma_sequence(encoder, &one_empty))
            .expect("empty-clause plan hash");
        let one_empty_store = MaterializedClauseStore::from_parts(vec![0, 0], Vec::new())
            .expect("one empty clause is a valid flat store");
        let empty_materialized =
            digest_with(|encoder| encode_materialized_lemmas(encoder, &one_empty_store))
                .expect("empty-clause materialized hash");
        assert_eq!(no_lemmas_hash, no_lemmas_materialized);
        assert_eq!(empty_hash, empty_materialized);
        assert_ne!(no_lemmas_hash, empty_hash);
    }

    #[test]
    fn branch_rich_t10_baseline_digest_golden_vector_is_frozen() {
        const ATOM_MAP_SHA256: &str =
            "5319532aeb09a285c1942f512bae996a26e057572a1fa11cfd8b0d7049ac9394";
        const BASELINE_CNF_SHA256: &str =
            "f157b0ab3c4965ec61baee9148b826648ff0a5677851dd51d1413e1256b8af1f";
        const BASELINE_PROBLEM_SHA256: &str =
            "51069ecb85de9fc4385604a8eec07111dac65e5a758901fda45119625fbd4f33";

        let fixture = fixture();
        let clauses = FlatClauses {
            literals: vec![-6, 2, -4, 3, 7, -1],
            end_offsets: vec![0, 0, 2, 5, 6],
        };
        let variable_atoms = vec![
            None,
            Some(BoolAtomKey::Eq(0, 2)),
            None,
            Some(BoolAtomKey::BoolTerm(5)),
            Some(BoolAtomKey::Eq(1, 1)),
            None,
            Some(BoolAtomKey::Eq(3, 4)),
            None,
        ];
        // The missing BoolTerm reverse entry freezes the payload's explicit absence branch.
        let atom_variables = FxHashMap::from_iter([
            (BoolAtomKey::Eq(0, 2), 1),
            (BoolAtomKey::Eq(1, 1), 4),
            (BoolAtomKey::Eq(3, 4), 6),
        ]);
        let input = EqresInput {
            baseline_clauses: &clauses,
            variable_atoms: &variable_atoms,
            atom_variables: &atom_variables,
            true_literal: Some(2),
            finite_equalities_complete: true,
            finite_predicate_congruence_complete: false,
            ..fixture.input()
        };

        assert_eq!(
            digest_with(|encoder| encode_atom_map(encoder, input))
                .unwrap()
                .to_string(),
            ATOM_MAP_SHA256
        );
        assert_eq!(
            digest_with(|encoder| encode_baseline_cnf(encoder, input))
                .unwrap()
                .to_string(),
            BASELINE_CNF_SHA256
        );
        assert_eq!(
            digest_with(|encoder| encode_baseline_problem(encoder, input))
                .unwrap()
                .to_string(),
            BASELINE_PROBLEM_SHA256
        );
    }

    #[test]
    fn compiler_not_run_maps_to_checker_not_run() {
        let mut fixture = fixture();
        fixture.compiler.status = CompilerStatus::NotRun;
        assert_eq!(fixture.run().status, CheckerStatus::NotRun);
    }

    #[test]
    fn rejects_unique_out_of_order_event_id_mutation() {
        let mut fixture = fixture();
        trace_equality_mut(&mut fixture.compiler, 5).event_id = EventId::new(100);
        fixture.compiler.counters.search.events_popped = 101;
        fixture.reseal();
        assert_rejects_with(&fixture, CheckerFailureKind::TraceOrder, Some(6), None);
    }

    #[test]
    fn rejects_node_id_mutation() {
        let mut fixture = fixture();
        trace_equality_mut(&mut fixture.compiler, 5).node_id = NodeId::new(50);
        fixture.reseal();
        assert_rejects_with(&fixture, CheckerFailureKind::TraceOrder, Some(5), None);
    }

    #[test]
    fn rejects_conflict_clause_id_mutation() {
        let mut fixture = fixture();
        trace_conflict_mut(&mut fixture.compiler, 9).clause_id = ClauseId::new(50);
        fixture.reseal();
        assert_rejects_with(&fixture, CheckerFailureKind::TraceOrder, Some(9), None);
    }

    #[test]
    fn rejects_proof_depth_mutation() {
        let mut fixture = fixture();
        trace_equality_mut(&mut fixture.compiler, 5).depth = ProofDepth::new(1);
        fixture.reseal();
        assert_rejects_with(&fixture, CheckerFailureKind::MalformedTrace, Some(5), None);
    }

    #[test]
    fn rejects_equality_conclusion_mutation() {
        let mut fixture = fixture();
        trace_equality_mut(&mut fixture.compiler, 5).conclusion = equality(0, 2);
        fixture.reseal();
        assert_rejects_with(&fixture, CheckerFailureKind::Conclusion, Some(5), None);
    }

    #[test]
    fn rejects_baseline_missing_initial_flat_offset() {
        let mut fixture = fixture();
        fixture.clauses.end_offsets[0] = 1;
        fixture.reseal();
        assert_rejects_with(&fixture, CheckerFailureKind::MalformedTrace, None, None);
    }

    #[test]
    fn rejects_baseline_nonmonotone_flat_offsets() {
        let mut fixture = fixture();
        fixture.clauses.end_offsets[2] = 1;
        fixture.reseal();
        assert_rejects_with(&fixture, CheckerFailureKind::MalformedTrace, None, None);
    }

    #[test]
    fn rejects_baseline_final_flat_offset_mismatch() {
        let mut fixture = fixture();
        fixture.clauses.end_offsets[4] = 7;
        fixture.reseal();
        assert_rejects_with(&fixture, CheckerFailureKind::MalformedTrace, None, None);
    }

    #[test]
    fn rejects_forward_atom_presence_without_reverse_mapping() {
        let mut fixture = fixture();
        fixture.variable_atoms[4] = Some(BoolAtomKey::Eq(0, 2));
        fixture.reseal();
        assert_rejects_with(&fixture, CheckerFailureKind::MalformedTrace, None, None);
    }

    #[test]
    fn rejects_reverse_atom_mapping_without_forward_presence() {
        let mut fixture = fixture();
        fixture.atom_variables.insert(BoolAtomKey::Eq(0, 2), 4);
        fixture.compiler.counters.input.baseline_atom_entries = 4;
        fixture.reseal();
        assert_rejects_with(&fixture, CheckerFailureKind::MalformedTrace, None, None);
    }

    #[test]
    fn rejects_sign_mutation() {
        let mut fixture = fixture();
        fixture.clauses.literals[0] = -1;
        fixture.reseal();
        assert_rejects(&fixture, CheckerFailureKind::PivotSign);
    }

    #[test]
    fn rejects_literal_offset_mutation() {
        let mut fixture = fixture();
        let record = trace_equality_mut(&mut fixture.compiler, 5);
        let EqualityRuleRecord::Seed(seed) = &mut record.rule else {
            panic!("fixture rule is not seed");
        };
        seed.positive_source.literal_offset = LiteralOffset::new(99);
        fixture.reseal();
        assert_rejects(&fixture, CheckerFailureKind::LiteralOffset);
    }

    #[test]
    fn rejects_future_derived_source_mutation() {
        let mut fixture = fixture();
        let record = trace_equality_mut(&mut fixture.compiler, 5);
        let EqualityRuleRecord::Seed(seed) = &mut record.rule else {
            panic!("fixture rule is not seed");
        };
        seed.positive_source.clause = ClauseRef {
            id: ClauseId::new(4),
            origin: ClauseOrigin::Derived,
        };
        fixture.reseal();
        assert_rejects(&fixture, CheckerFailureKind::SourceNotEarlier);
    }

    #[test]
    fn rejects_reflexivity_sequence_mutation() {
        let mut fixture = fixture();
        for (trace_index, term) in [(0, 1), (1, 0)] {
            let record = trace_equality_mut(&mut fixture.compiler, trace_index);
            record.conclusion = equality(term, term);
            let EqualityRuleRecord::Reflexivity(reflexivity) = &mut record.rule else {
                panic!("fixture rule is not reflexivity");
            };
            reflexivity.term = term;
        }
        fixture.reseal();
        assert_rejects_with(
            &fixture,
            CheckerFailureKind::ReflexivityOrder,
            Some(1),
            None,
        );
    }

    #[test]
    fn rejects_reflexivity_term_mutation() {
        let mut fixture = fixture();
        let record = trace_equality_mut(&mut fixture.compiler, 0);
        let EqualityRuleRecord::Reflexivity(reflexivity) = &mut record.rule else {
            panic!("fixture rule is not reflexivity");
        };
        reflexivity.term = 99;
        fixture.reseal();
        assert_rejects_with(&fixture, CheckerFailureKind::TermId, Some(0), None);
    }

    #[test]
    fn rejects_term_id_mutation() {
        let mut fixture = fixture();
        let record = trace_equality_mut(&mut fixture.compiler, 7);
        let EqualityRuleRecord::Transitivity(transitivity) = &mut record.rule else {
            panic!("fixture rule is not transitivity");
        };
        transitivity.intermediate = 99;
        fixture.reseal();
        assert_rejects(&fixture, CheckerFailureKind::TermId);
    }

    #[test]
    fn rejects_transitivity_intermediate_endpoint_mutation() {
        let mut fixture = fixture();
        let record = trace_equality_mut(&mut fixture.compiler, 7);
        let EqualityRuleRecord::Transitivity(transitivity) = &mut record.rule else {
            panic!("fixture rule is not transitivity");
        };
        transitivity.intermediate = 0;
        fixture.reseal();
        assert_rejects_with(
            &fixture,
            CheckerFailureKind::TransitivityEndpoints,
            Some(7),
            None,
        );
    }

    #[test]
    fn rejects_transitivity_parent_order_mutation() {
        let mut fixture = fixture();
        let record = trace_equality_mut(&mut fixture.compiler, 7);
        let EqualityRuleRecord::Transitivity(transitivity) = &mut record.rule else {
            panic!("fixture rule is not transitivity");
        };
        transitivity.parents.swap(0, 1);
        fixture.reseal();
        assert_rejects(&fixture, CheckerFailureKind::ParentOrder);
    }

    #[test]
    fn rejects_application_function_mutation() {
        let mut fixture = fixture();
        fixture.terms[4].fun = 4;
        fixture.reseal();
        assert_rejects(&fixture, CheckerFailureKind::Function);
    }

    #[test]
    fn rejects_application_sort_mutation() {
        let mut fixture = fixture();
        fixture.terms[4].sort = BOOL_SORT;
        fixture.reseal();
        assert_rejects(&fixture, CheckerFailureKind::Sort);
    }

    #[test]
    fn rejects_congruence_argument_association_mutation() {
        let mut fixture = fixture();
        let record = trace_equality_mut(&mut fixture.compiler, 8);
        let EqualityRuleRecord::Congruence(congruence) = &mut record.rule else {
            panic!("fixture rule is not congruence");
        };
        congruence.arguments[0].parent = NodeId::new(5);
        fixture.reseal();
        assert_rejects(&fixture, CheckerFailureKind::CongruenceArgumentAssociation);
    }

    #[test]
    fn rejects_congruence_application_order_mutation() {
        let mut fixture = fixture();
        let record = trace_equality_mut(&mut fixture.compiler, 8);
        let EqualityRuleRecord::Congruence(congruence) = &mut record.rule else {
            panic!("fixture rule is not congruence");
        };
        congruence.applications.swap(0, 1);
        fixture.reseal();
        assert_rejects_with(
            &fixture,
            CheckerFailureKind::CongruenceApplicationOrder,
            Some(8),
            None,
        );
    }

    #[test]
    fn rejects_congruence_argument_index_order_mutation() {
        let mut fixture = two_argument_congruence_fixture();
        assert_eq!(fixture.run().status, CheckerStatus::Accepted);
        let record = trace_equality_mut(&mut fixture.compiler, 8);
        let EqualityRuleRecord::Congruence(congruence) = &mut record.rule else {
            panic!("fixture rule is not congruence");
        };
        congruence.arguments.swap(0, 1);
        fixture.reseal();
        assert_rejects_with(
            &fixture,
            CheckerFailureKind::CongruenceArgumentOrder,
            Some(8),
            None,
        );
    }

    #[test]
    fn rejects_support_literal_mutation() {
        let mut fixture = fixture();
        trace_equality_mut(&mut fixture.compiler, 7).side_clause = canonical(&[6, 8]);
        fixture.reseal();
        assert_rejects(&fixture, CheckerFailureKind::SideClause);
    }

    #[test]
    fn rejects_conflict_equality_parent_mutation() {
        let mut fixture = fixture();
        trace_conflict_mut(&mut fixture.compiler, 9)
            .rule
            .equality_parent = NodeId::new(6);
        fixture.reseal();
        assert_rejects_with(&fixture, CheckerFailureKind::Conclusion, Some(9), None);
    }

    #[test]
    fn rejects_conflict_negative_source_mutation() {
        let mut fixture = fixture();
        trace_conflict_mut(&mut fixture.compiler, 9)
            .rule
            .negative_source
            .clause
            .id = ClauseId::new(99);
        fixture.reseal();
        assert_rejects_with(
            &fixture,
            CheckerFailureKind::BaselineClauseReference,
            Some(9),
            None,
        );
    }

    #[test]
    fn rejects_emitted_source_clause_id_mutation() {
        let mut fixture = fixture();
        let CompilerStatus::Completed(EqresOutput::Lemmas(lemmas)) = &mut fixture.compiler.status
        else {
            panic!("fixture output is not lemmas");
        };
        lemmas[0].source_clause_id = ClauseId::new(5);
        fixture.reseal();
        assert_rejects_with(&fixture, CheckerFailureKind::OutputClause, None, None);
    }

    #[test]
    fn rejects_output_order_mutation() {
        let mut fixture = fixture();
        let CompilerStatus::Completed(EqresOutput::Lemmas(lemmas)) = &mut fixture.compiler.status
        else {
            panic!("fixture output is not lemmas");
        };
        lemmas.swap(0, 1);
        fixture.reseal();
        assert_rejects(&fixture, CheckerFailureKind::OutputOrder);
    }

    #[test]
    fn rejects_outcome_mutation() {
        let mut fixture = fixture();
        fixture.compiler.status = CompilerStatus::Completed(EqresOutput::NoLemmas);
        fixture.reseal();
        assert_rejects(&fixture, CheckerFailureKind::OutcomeShape);
    }

    #[test]
    fn rejects_compiler_input_counter_mutation() {
        let mut fixture = fixture();
        fixture.compiler.counters.input.terms += 1;
        fixture.reseal();
        assert_rejects_with(&fixture, CheckerFailureKind::MalformedTrace, None, None);
    }

    #[test]
    fn rejects_compiler_trace_counter_mutation() {
        let mut fixture = fixture();
        fixture.compiler.counters.search.accepted_events.seed += 1;
        fixture.reseal();
        assert_rejects_with(&fixture, CheckerFailureKind::MalformedTrace, None, None);
    }

    #[test]
    fn rejects_compiler_output_counter_mutation() {
        let mut fixture = fixture();
        fixture.compiler.counters.output.emitted_lemmas += 1;
        fixture.reseal();
        assert_rejects_with(&fixture, CheckerFailureKind::OutcomeShape, None, None);
    }

    #[test]
    fn rejects_compiler_final_pruning_counter_mutation() {
        let mut fixture = fixture();
        fixture
            .compiler
            .counters
            .pruning
            .final_base_subsumption_discards += 1;
        fixture.reseal();
        assert_rejects_with(&fixture, CheckerFailureKind::OutcomeShape, None, None);
    }

    #[test]
    fn rejects_materialized_literal_mutation_and_hashes_supplied_bytes() {
        let mut fixture = fixture();
        let end_offsets = fixture.materialized.end_offsets().to_vec();
        let mut literals = fixture.materialized.literals().to_vec();
        literals[0] = 7;
        fixture.materialized = MaterializedClauseStore::from_parts(end_offsets, literals).unwrap();
        let result = fixture.run();
        assert!(
            failures(&result)
                .iter()
                .any(|failure| failure.kind == CheckerFailureKind::OutputClause)
        );
        assert_ne!(
            result.recomputed_hashes.materialized_lemmas_sha256,
            fixture.compiler.hashes.materialized_lemmas_sha256
        );
        assert_ne!(
            result.recomputed_hashes.materialized_candidate_sha256,
            fixture.compiler.hashes.materialized_candidate_sha256
        );
    }

    #[test]
    fn rejects_resealed_post_check_materialization_replacement() {
        let mut fixture = fixture();
        assert_eq!(fixture.run().status, CheckerStatus::Accepted);

        let end_offsets = fixture.materialized.end_offsets().to_vec();
        let mut literals = fixture.materialized.literals().to_vec();
        literals[0] = 7;
        fixture.materialized = MaterializedClauseStore::from_parts(end_offsets, literals)
            .expect("replacement materialization has valid flat shape");
        fixture.reseal();

        let result = fixture.run();
        let rejected = failures(&result);
        assert!(rejected.iter().any(|failure| {
            failure.kind == CheckerFailureKind::OutputClause
                && failure.event_id.is_none()
                && failure.artifact.is_none()
        }));
        assert!(
            !rejected
                .iter()
                .any(|failure| failure.kind == CheckerFailureKind::HashMismatch)
        );
    }

    #[test]
    fn rejects_reordered_materialized_clauses() {
        let mut fixture = fixture();
        fixture.materialized =
            MaterializedClauseStore::from_parts(vec![0, 3, 5], vec![6, 7, 9, 6, 8])
                .expect("reordered test store has valid flat shape");
        assert_rejects(&fixture, CheckerFailureKind::OutputOrder);
    }

    #[test]
    fn rejects_extra_materialized_clause() {
        let mut fixture = fixture();
        fixture.materialized =
            MaterializedClauseStore::from_parts(vec![0, 2, 5, 6], vec![6, 8, 6, 7, 9, 10])
                .expect("extra-clause test store has valid flat shape");
        assert_rejects(&fixture, CheckerFailureKind::OutcomeShape);
    }

    #[test]
    fn rejects_malformed_materialized_flat_shape() {
        let mut fixture = fixture();
        fixture.materialized = MaterializedClauseStore::from_parts_unchecked_for_test(
            vec![1, 2, 5],
            vec![6, 8, 6, 7, 9],
        );
        assert_rejects(&fixture, CheckerFailureKind::OutcomeShape);
    }

    #[test]
    fn recomputed_hashes_do_not_inherit_external_bindings() {
        let mut fixture = fixture();
        fixture.compiler.hashes.candidate_binary_sha256 = Sha256Digest::new([0x5a; 32]);
        let result = fixture.run();
        assert_eq!(
            result.recomputed_hashes.candidate_binary_sha256,
            Sha256Digest::ZERO
        );
        assert_ne!(result.recomputed_hashes, fixture.compiler.hashes);
    }

    #[test]
    fn repeated_identical_failures_are_counted_in_order() {
        let mut fixture = fixture();
        fixture.root_cnf_mode[0] ^= 1;
        let result = fixture.run();
        let rejected = failures(&result);
        let root_failures: Vec<_> = rejected
            .iter()
            .filter(|failure| {
                failure.kind == CheckerFailureKind::HashMismatch
                    && failure.artifact == Some(HashArtifact::RootCnfMode)
            })
            .collect();
        assert_eq!(root_failures.len(), 2);
        assert_eq!(result.counters.replay_failures, rejected.len() as u64);
    }

    #[test]
    fn materialized_candidate_hash_has_distinct_artifact() {
        let mut fixture = fixture();
        let mut bytes = *fixture
            .compiler
            .hashes
            .materialized_candidate_sha256
            .as_bytes();
        bytes[0] ^= 0x80;
        fixture.compiler.hashes.materialized_candidate_sha256 = Sha256Digest::new(bytes);
        let result = fixture.run();
        let rejected = failures(&result);
        assert!(rejected.iter().any(|failure| {
            failure.kind == CheckerFailureKind::HashMismatch
                && failure.artifact == Some(HashArtifact::MaterializedCandidate)
        }));
        assert!(!rejected.iter().any(|failure| {
            failure.kind == CheckerFailureKind::HashMismatch
                && failure.artifact == Some(HashArtifact::MaterializedLemmas)
        }));
    }

    #[test]
    fn rejects_hash_mutation() {
        let mut fixture = fixture();
        let mut bytes = *fixture.compiler.hashes.trace_sha256.as_bytes();
        bytes[0] ^= 0x80;
        fixture.compiler.hashes.trace_sha256 = Sha256Digest::new(bytes);
        let result = fixture.run();
        assert!(failures(&result).iter().any(|failure| {
            failure.kind == CheckerFailureKind::HashMismatch
                && failure.artifact == Some(HashArtifact::Trace)
        }));
    }
}
