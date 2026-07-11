#![cfg(test)]
#![allow(dead_code)]

//! Exact, deliberately small bounded-model reference search for parsed ground QF_UF.
//!
//! This module is test-only and is not routed through the production solver. It searches
//! finite interpretations directly; it does not encode SAT and it is not DPLL(T). Values of
//! each uninterpreted sort are introduced canonically, so globally permuting an as-yet-unused
//! value does not create another branch.
//!
//! `Problem` does not retain source-level `distinct` groups. Consequently, all-different
//! groups are recovered only when the mandatory disequality graph proves a clique. Missing a
//! clique can only lose Hall propagation: the pairwise constraints and exhaustive search remain
//! exact. Symbol names are likewise not retained, so total model tables are keyed by `SymId`.

use super::{BOOL_SORT, BoolAtomKey, BoolExpr, Problem, SortId, SymId, TermId};
use std::collections::{BTreeMap, BTreeSet};

const HARD_MAX_DOMAIN_SIZE: usize = u64::BITS as usize;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QuotientCaps {
    pub max_terms: usize,
    pub max_sorts: usize,
    pub max_functions: usize,
    pub max_domain_size: usize,
    pub max_bool_nodes: usize,
    pub max_bool_depth: usize,
    pub max_total_function_cells: usize,
    pub max_search_nodes: usize,
    pub max_propagation_rounds: usize,
    pub max_all_different_groups: usize,
    pub max_hall_group_size: usize,
    pub max_hall_subsets_per_round: usize,
    pub max_forbidden_tables: usize,
    pub max_forbidden_table_cells: usize,
    pub max_orbit_permutations: usize,
    pub max_totalization_attempts: usize,
}

impl Default for QuotientCaps {
    fn default() -> Self {
        Self {
            max_terms: 96,
            max_sorts: 8,
            max_functions: 64,
            max_domain_size: 8,
            max_bool_nodes: 4_096,
            max_bool_depth: 256,
            max_total_function_cells: 16_384,
            max_search_nodes: 1_000_000,
            max_propagation_rounds: 5_000_000,
            max_all_different_groups: 256,
            max_hall_group_size: 12,
            max_hall_subsets_per_round: 8_192,
            max_forbidden_tables: 10_000,
            max_forbidden_table_cells: 500_000,
            max_orbit_permutations: 10_000,
            max_totalization_attempts: 20_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum QuotientAbstain {
    Unsupported(Vec<String>),
    InvalidProblem(String),
    InvalidBounds(String),
    StructuralCap {
        resource: &'static str,
        limit: usize,
        actual: usize,
    },
    SearchCap {
        resource: &'static str,
        limit: usize,
    },
    ValidatorRejected(String),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct QuotientTelemetry {
    pub input_terms: usize,
    pub input_sorts: usize,
    pub declared_functions: usize,
    pub total_function_cells: usize,
    pub mandatory_equalities: usize,
    pub mandatory_disequalities: usize,
    pub all_different_groups: usize,
    pub all_different_groups_skipped: usize,
    pub search_nodes: usize,
    pub decisions: usize,
    pub branch_attempts: usize,
    pub backtracks: usize,
    pub max_depth: usize,
    pub propagation_rounds: usize,
    pub domain_updates: usize,
    pub domain_values_removed: usize,
    pub equality_checks: usize,
    pub equality_reductions: usize,
    pub disequality_checks: usize,
    pub disequality_reductions: usize,
    pub formula_visits: usize,
    pub formula_forced_atoms: usize,
    pub congruence_signatures: usize,
    pub congruence_collisions: usize,
    pub congruence_reductions: usize,
    pub congruence_conflicts: usize,
    pub hall_subsets_checked: usize,
    pub hall_reductions: usize,
    pub hall_values_removed: usize,
    pub hall_conflicts: usize,
    pub symmetry_existing_branches: usize,
    pub symmetry_new_value_branches: usize,
    pub symmetry_values_skipped: usize,
    pub complete_assignments: usize,
    pub candidate_models_built: usize,
    pub validator_calls: usize,
    pub validator_rejections: usize,
    pub forbidden_table_constraints: usize,
    pub forbidden_tables: usize,
    pub generated_orbit_tables: usize,
    pub symmetry_disabled_sorts: usize,
    pub forbidden_table_checks: usize,
    pub forbidden_table_rejections: usize,
    pub totalization_attempts: usize,
    pub decision_trace_hash: u64,
}

impl QuotientTelemetry {
    fn new(problem: &Problem) -> Self {
        Self {
            input_terms: problem.arena.terms.len(),
            input_sorts: problem.sorts.names.len(),
            decision_trace_hash: FNV_OFFSET,
            ..Self::default()
        }
    }

    fn trace_decision(&mut self, depth: usize, term: TermId, value: usize, is_new: bool) {
        for word in [depth, term, value, usize::from(is_new)] {
            self.decision_trace_hash ^= word as u64;
            self.decision_trace_hash = self.decision_trace_hash.wrapping_mul(FNV_PRIME);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FunctionInterpretation {
    pub arg_sorts: Vec<usize>,
    pub result_sort: usize,
    /// Row-major over argument tuples; the final argument varies fastest.
    pub values: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QuotientModel {
    pub domain_sizes: Vec<usize>,
    pub term_values: Vec<u8>,
    /// Indexed by `SymId`; undeclared interner slots are `None`.
    pub functions: Vec<Option<FunctionInterpretation>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct QuotientConstraints {
    /// Arbitrary label-sensitive tables. Symmetry is disabled on every sort in the signature.
    pub forbidden_complete_tables: Vec<ForbiddenCompleteTables>,
    /// Compact symmetry-safe `S_n` conjugacy orbits for homogeneous binary operations.
    pub forbidden_conjugacy_orbits: Vec<ForbiddenConjugacyOrbit>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ForbiddenCompleteTables {
    pub fun: SymId,
    pub tables: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ForbiddenConjugacyOrbit {
    pub fun: SymId,
    /// Row-major representative `table[left * n + right]`.
    pub representative: Vec<u8>,
}

impl QuotientModel {
    pub(crate) fn term_value(&self, term: TermId) -> Option<usize> {
        self.term_values.get(term).map(|value| *value as usize)
    }

    pub(crate) fn function_value(&self, fun: SymId, args: &[usize]) -> Option<usize> {
        let interpretation = self.functions.get(fun as usize)?.as_ref()?;
        let index = tuple_index(args, &interpretation.arg_sorts, &self.domain_sizes).ok()?;
        interpretation
            .values
            .get(index)
            .map(|value| *value as usize)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum QuotientResult {
    Sat {
        model: QuotientModel,
        telemetry: QuotientTelemetry,
    },
    Unsat {
        telemetry: QuotientTelemetry,
    },
    Abstain {
        reason: QuotientAbstain,
        telemetry: QuotientTelemetry,
    },
}

impl QuotientResult {
    pub(crate) fn telemetry(&self) -> &QuotientTelemetry {
        match self {
            Self::Sat { telemetry, .. }
            | Self::Unsat { telemetry }
            | Self::Abstain { telemetry, .. } => telemetry,
        }
    }
}

#[derive(Debug)]
struct Prepared<'a> {
    problem: &'a Problem,
    bounds: Vec<usize>,
    equalities: Vec<(TermId, TermId)>,
    disequalities: Vec<(TermId, TermId)>,
    all_different: Vec<Vec<TermId>>,
    fixed_values: Vec<(TermId, usize)>,
    forbidden_tables: BTreeMap<SymId, BTreeSet<Vec<u8>>>,
    symmetry_disabled_sorts: BTreeSet<usize>,
}

#[derive(Clone, Debug)]
struct SearchState {
    domains: Vec<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Truth {
    False,
    Unknown,
    True,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PropagationStop {
    Conflict,
    Cap,
}

#[derive(Debug)]
enum SearchOutcome {
    Found(QuotientModel),
    Exhausted,
    Abstain(QuotientAbstain),
}

#[derive(Debug)]
enum ModelBuildError {
    NoAllowedCompletion,
    Cap,
    Invalid(String),
}

pub(crate) fn solve_bounded_quotient(
    problem: &Problem,
    domain_sizes: &[usize],
    caps: &QuotientCaps,
) -> QuotientResult {
    solve_bounded_quotient_with_constraints(
        problem,
        domain_sizes,
        caps,
        &QuotientConstraints::default(),
    )
}

pub(crate) fn solve_bounded_quotient_with_constraints(
    problem: &Problem,
    domain_sizes: &[usize],
    caps: &QuotientCaps,
    constraints: &QuotientConstraints,
) -> QuotientResult {
    let mut telemetry = QuotientTelemetry::new(problem);
    let prepared = match prepare(problem, domain_sizes, caps, constraints, &mut telemetry) {
        Ok(prepared) => prepared,
        Err(reason) => return QuotientResult::Abstain { reason, telemetry },
    };

    let domains = problem
        .arena
        .terms
        .iter()
        .map(|term| full_mask(prepared.bounds[term.sort.0 as usize]))
        .collect();
    let mut search = Search {
        prepared: &prepared,
        caps,
        telemetry: &mut telemetry,
    };
    let result = search.dfs(SearchState { domains }, 0);
    match result {
        SearchOutcome::Found(model) => QuotientResult::Sat { model, telemetry },
        SearchOutcome::Exhausted => QuotientResult::Unsat { telemetry },
        SearchOutcome::Abstain(reason) => QuotientResult::Abstain { reason, telemetry },
    }
}

fn prepare<'a>(
    problem: &'a Problem,
    domain_sizes: &[usize],
    caps: &QuotientCaps,
    constraints: &QuotientConstraints,
    telemetry: &mut QuotientTelemetry,
) -> Result<Prepared<'a>, QuotientAbstain> {
    validate_caps(caps)?;
    validate_bounds(problem, domain_sizes, caps)?;
    validate_problem(problem, caps)?;

    let unsupported = unsupported_reasons(problem);
    if !unsupported.is_empty() {
        return Err(QuotientAbstain::Unsupported(unsupported));
    }

    let declared_functions = problem
        .fun_decls
        .slots
        .iter()
        .filter(|slot| slot.is_some())
        .count();
    telemetry.declared_functions = declared_functions;
    if declared_functions > caps.max_functions {
        return Err(QuotientAbstain::StructuralCap {
            resource: "declared functions",
            limit: caps.max_functions,
            actual: declared_functions,
        });
    }

    let mut total_function_cells = 0usize;
    for decl in problem.fun_decls.slots.iter().flatten() {
        let cells = checked_tuple_count(&decl.arg_sorts, domain_sizes).ok_or_else(|| {
            QuotientAbstain::StructuralCap {
                resource: "function table entries",
                limit: caps.max_total_function_cells,
                actual: usize::MAX,
            }
        })?;
        total_function_cells =
            total_function_cells
                .checked_add(cells)
                .ok_or(QuotientAbstain::StructuralCap {
                    resource: "function table entries",
                    limit: caps.max_total_function_cells,
                    actual: usize::MAX,
                })?;
    }
    telemetry.total_function_cells = total_function_cells;
    if total_function_cells > caps.max_total_function_cells {
        return Err(QuotientAbstain::StructuralCap {
            resource: "function table entries",
            limit: caps.max_total_function_cells,
            actual: total_function_cells,
        });
    }
    let (forbidden_tables, symmetry_disabled_sorts) =
        prepare_table_constraints(problem, domain_sizes, constraints, caps, telemetry)?;

    let mut equalities = BTreeSet::new();
    let mut disequalities = BTreeSet::new();
    for &(left, right) in &problem.eqs {
        equalities.insert(normalized_pair(left, right));
    }
    for &(left, right) in &problem.diseqs {
        disequalities.insert(normalized_pair(left, right));
    }
    if let Some(bool_problem) = &problem.bool_problem {
        for assertion in &bool_problem.assertions {
            collect_forced_relations(assertion, true, &mut equalities, &mut disequalities);
        }
    }

    let equalities = equalities.into_iter().collect::<Vec<_>>();
    let disequalities = disequalities.into_iter().collect::<Vec<_>>();
    telemetry.mandatory_equalities = equalities.len();
    telemetry.mandatory_disequalities = disequalities.len();
    let all_different = detect_all_different_groups(
        problem,
        &disequalities,
        caps.max_all_different_groups,
        telemetry,
    );

    let mut fixed_values = Vec::new();
    if let Some(bool_problem) = &problem.bool_problem {
        fixed_values.push((bool_problem.false_term, 0));
        fixed_values.push((bool_problem.true_term, 1));
    }
    fixed_values.sort_unstable();

    Ok(Prepared {
        problem,
        bounds: domain_sizes.to_vec(),
        equalities,
        disequalities,
        all_different,
        fixed_values,
        forbidden_tables,
        symmetry_disabled_sorts,
    })
}

fn validate_caps(caps: &QuotientCaps) -> Result<(), QuotientAbstain> {
    if caps.max_domain_size == 0 || caps.max_domain_size > HARD_MAX_DOMAIN_SIZE {
        return Err(QuotientAbstain::InvalidBounds(format!(
            "max_domain_size must be in 1..={HARD_MAX_DOMAIN_SIZE}"
        )));
    }
    if caps.max_bool_depth == 0 {
        return Err(QuotientAbstain::InvalidProblem(
            "max_bool_depth must be positive".to_owned(),
        ));
    }
    if caps.max_hall_group_size >= usize::BITS as usize {
        return Err(QuotientAbstain::InvalidProblem(format!(
            "max_hall_group_size must be less than {}",
            usize::BITS
        )));
    }
    Ok(())
}

fn validate_bounds(
    problem: &Problem,
    domain_sizes: &[usize],
    caps: &QuotientCaps,
) -> Result<(), QuotientAbstain> {
    let sort_count = problem.sorts.names.len();
    if sort_count == 0 || problem.sorts.names.first().map(String::as_str) != Some("Bool") {
        return Err(QuotientAbstain::InvalidProblem(
            "sort 0 must be the built-in Bool sort".to_owned(),
        ));
    }
    if sort_count > caps.max_sorts {
        return Err(QuotientAbstain::StructuralCap {
            resource: "sorts",
            limit: caps.max_sorts,
            actual: sort_count,
        });
    }
    if domain_sizes.len() != sort_count {
        return Err(QuotientAbstain::InvalidBounds(format!(
            "expected {sort_count} per-sort bounds, found {}",
            domain_sizes.len()
        )));
    }
    for (sort, &size) in domain_sizes.iter().enumerate() {
        if size == 0 {
            return Err(QuotientAbstain::InvalidBounds(format!(
                "sort `{}` has an empty domain",
                problem.sorts.names[sort]
            )));
        }
        if size > HARD_MAX_DOMAIN_SIZE || size > caps.max_domain_size {
            return Err(QuotientAbstain::StructuralCap {
                resource: "domain size",
                limit: caps.max_domain_size.min(HARD_MAX_DOMAIN_SIZE),
                actual: size,
            });
        }
    }
    if domain_sizes[BOOL_SORT.0 as usize] != 2 {
        return Err(QuotientAbstain::InvalidBounds(format!(
            "Bool has fixed domain size 2, found {}",
            domain_sizes[BOOL_SORT.0 as usize]
        )));
    }
    Ok(())
}

fn validate_problem(problem: &Problem, caps: &QuotientCaps) -> Result<(), QuotientAbstain> {
    let term_count = problem.arena.terms.len();
    if term_count > caps.max_terms {
        return Err(QuotientAbstain::StructuralCap {
            resource: "ground terms",
            limit: caps.max_terms,
            actual: term_count,
        });
    }
    let sort_count = problem.sorts.names.len();
    for (term_id, term) in problem.arena.terms.iter().enumerate() {
        if term.sort.0 as usize >= sort_count {
            return Err(QuotientAbstain::InvalidProblem(format!(
                "term {term_id} has invalid result sort {}",
                term.sort.0
            )));
        }
        let Some(decl) = problem.fun_decls.get(term.fun) else {
            return Err(QuotientAbstain::InvalidProblem(format!(
                "term {term_id} uses undeclared symbol {}",
                term.fun
            )));
        };
        if decl.result_sort != term.sort || decl.arg_sorts.len() != term.args.len() {
            return Err(QuotientAbstain::InvalidProblem(format!(
                "term {term_id} disagrees with its function declaration"
            )));
        }
        for (position, (&arg, &sort)) in term.args.iter().zip(&decl.arg_sorts).enumerate() {
            let Some(arg_term) = problem.arena.terms.get(arg) else {
                return Err(QuotientAbstain::InvalidProblem(format!(
                    "term {term_id} argument {position} references missing term {arg}"
                )));
            };
            if arg_term.sort != sort {
                return Err(QuotientAbstain::InvalidProblem(format!(
                    "term {term_id} argument {position} has the wrong sort"
                )));
            }
        }
    }
    for (sym, decl) in problem.fun_decls.slots.iter().enumerate() {
        let Some(decl) = decl else { continue };
        if decl.result_sort.0 as usize >= sort_count
            || decl
                .arg_sorts
                .iter()
                .any(|sort| sort.0 as usize >= sort_count)
        {
            return Err(QuotientAbstain::InvalidProblem(format!(
                "function symbol {sym} has an invalid sort"
            )));
        }
    }
    for &(left, right) in problem.eqs.iter().chain(&problem.diseqs) {
        validate_relation(problem, left, right)?;
    }

    let mut bool_nodes = 0usize;
    if let Some(bool_problem) = &problem.bool_problem {
        validate_bool_term(problem, bool_problem.true_term, "true")?;
        validate_bool_term(problem, bool_problem.false_term, "false")?;
        if bool_problem.true_term == bool_problem.false_term {
            return Err(QuotientAbstain::InvalidProblem(
                "true and false use the same ground term".to_owned(),
            ));
        }
        for &term in &bool_problem.data_terms {
            validate_bool_term(problem, term, "Boolean data")?;
        }
        for assertion in &bool_problem.assertions {
            validate_bool_expr(problem, assertion, 1, caps, &mut bool_nodes)?;
        }
    }
    Ok(())
}

fn validate_relation(
    problem: &Problem,
    left: TermId,
    right: TermId,
) -> Result<(), QuotientAbstain> {
    let Some(left_term) = problem.arena.terms.get(left) else {
        return Err(QuotientAbstain::InvalidProblem(format!(
            "relation references missing term {left}"
        )));
    };
    let Some(right_term) = problem.arena.terms.get(right) else {
        return Err(QuotientAbstain::InvalidProblem(format!(
            "relation references missing term {right}"
        )));
    };
    if left_term.sort != right_term.sort {
        return Err(QuotientAbstain::InvalidProblem(format!(
            "relation crosses sorts at terms {left} and {right}"
        )));
    }
    Ok(())
}

fn validate_bool_term(
    problem: &Problem,
    term: TermId,
    context: &str,
) -> Result<(), QuotientAbstain> {
    match problem.arena.terms.get(term) {
        Some(value) if value.sort == BOOL_SORT => Ok(()),
        Some(_) => Err(QuotientAbstain::InvalidProblem(format!(
            "{context} term {term} is not Bool"
        ))),
        None => Err(QuotientAbstain::InvalidProblem(format!(
            "{context} references missing term {term}"
        ))),
    }
}

fn validate_bool_expr(
    problem: &Problem,
    expr: &BoolExpr,
    depth: usize,
    caps: &QuotientCaps,
    nodes: &mut usize,
) -> Result<(), QuotientAbstain> {
    *nodes += 1;
    if *nodes > caps.max_bool_nodes {
        return Err(QuotientAbstain::StructuralCap {
            resource: "Boolean expression nodes",
            limit: caps.max_bool_nodes,
            actual: *nodes,
        });
    }
    if depth > caps.max_bool_depth {
        return Err(QuotientAbstain::StructuralCap {
            resource: "Boolean expression depth",
            limit: caps.max_bool_depth,
            actual: depth,
        });
    }
    match expr {
        BoolExpr::Const(_) => Ok(()),
        BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => validate_relation(problem, *left, *right),
        BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => {
            validate_bool_term(problem, *term, "Boolean atom")
        }
        BoolExpr::Not(child) => validate_bool_expr(problem, child, depth + 1, caps, nodes),
        BoolExpr::And(children) | BoolExpr::Or(children) | BoolExpr::Iff(children) => {
            for child in children {
                validate_bool_expr(problem, child, depth + 1, caps, nodes)?;
            }
            Ok(())
        }
        BoolExpr::Ite(condition, then_expr, else_expr) => {
            validate_bool_expr(problem, condition, depth + 1, caps, nodes)?;
            validate_bool_expr(problem, then_expr, depth + 1, caps, nodes)?;
            validate_bool_expr(problem, else_expr, depth + 1, caps, nodes)
        }
    }
}

fn unsupported_reasons(problem: &Problem) -> Vec<String> {
    let has_complete_bool_ast = problem
        .bool_problem
        .as_ref()
        .is_some_and(|bool_problem| bool_problem.unsupported.is_empty());
    let mut reasons = problem
        .unsupported
        .iter()
        .filter(|message| !(has_complete_bool_ast && is_legacy_route_warning(message)))
        .cloned()
        .collect::<Vec<_>>();
    if let Some(bool_problem) = &problem.bool_problem {
        reasons.extend(bool_problem.unsupported.iter().cloned());
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

fn is_legacy_route_warning(message: &str) -> bool {
    message.starts_with("positive or needs DPLL(T)")
        || message.starts_with("Boolean connective `")
        || message.starts_with("Boolean atom `")
        || message.starts_with("formula headed by `")
}

fn prepare_table_constraints(
    problem: &Problem,
    bounds: &[usize],
    constraints: &QuotientConstraints,
    caps: &QuotientCaps,
    telemetry: &mut QuotientTelemetry,
) -> Result<(BTreeMap<SymId, BTreeSet<Vec<u8>>>, BTreeSet<usize>), QuotientAbstain> {
    telemetry.forbidden_table_constraints =
        constraints.forbidden_complete_tables.len() + constraints.forbidden_conjugacy_orbits.len();
    let mut forbidden = BTreeMap::<SymId, BTreeSet<Vec<u8>>>::new();
    let mut symmetry_disabled_sorts = BTreeSet::new();
    let mut table_count = 0usize;
    let mut table_cells = 0usize;

    for constraint in &constraints.forbidden_complete_tables {
        let declaration = constraint_declaration(problem, constraint.fun)?;
        let expected_cells = checked_tuple_count(&declaration.arg_sorts, bounds).ok_or(
            QuotientAbstain::StructuralCap {
                resource: "forbidden table cells",
                limit: caps.max_forbidden_table_cells,
                actual: usize::MAX,
            },
        )?;
        let result_bound = bounds[declaration.result_sort.0 as usize];
        if !constraint.tables.is_empty() {
            for sort in declaration
                .arg_sorts
                .iter()
                .copied()
                .chain(std::iter::once(declaration.result_sort))
            {
                symmetry_disabled_sorts.insert(sort.0 as usize);
            }
        }
        for table in &constraint.tables {
            validate_forbidden_table(constraint.fun, table, expected_cells, result_bound)?;
            if forbidden
                .entry(constraint.fun)
                .or_default()
                .insert(table.clone())
            {
                account_forbidden_table(table.len(), &mut table_count, &mut table_cells, caps)?;
            }
        }
    }

    for constraint in &constraints.forbidden_conjugacy_orbits {
        let declaration = constraint_declaration(problem, constraint.fun)?;
        if declaration.arg_sorts.len() != 2
            || declaration.arg_sorts[0] != declaration.result_sort
            || declaration.arg_sorts[1] != declaration.result_sort
        {
            return Err(QuotientAbstain::InvalidProblem(format!(
                "conjugacy-orbit constraint for symbol {} requires S x S -> S",
                constraint.fun
            )));
        }
        let sort = declaration.result_sort.0 as usize;
        let size = bounds[sort];
        let expected_cells = size
            .checked_mul(size)
            .ok_or(QuotientAbstain::StructuralCap {
                resource: "forbidden table cells",
                limit: caps.max_forbidden_table_cells,
                actual: usize::MAX,
            })?;
        validate_forbidden_table(
            constraint.fun,
            &constraint.representative,
            expected_cells,
            size,
        )?;

        let mut permutation = (0..size).collect::<Vec<_>>();
        let mut generated = 0usize;
        loop {
            if generated >= caps.max_orbit_permutations {
                return Err(QuotientAbstain::StructuralCap {
                    resource: "orbit permutations",
                    limit: caps.max_orbit_permutations,
                    actual: generated + 1,
                });
            }
            let table = conjugate_binary_table(&constraint.representative, &permutation);
            generated += 1;
            telemetry.generated_orbit_tables += 1;
            if forbidden.entry(constraint.fun).or_default().insert(table) {
                account_forbidden_table(expected_cells, &mut table_count, &mut table_cells, caps)?;
            }
            if !next_permutation(&mut permutation) {
                break;
            }
        }
    }

    telemetry.forbidden_tables = table_count;
    telemetry.symmetry_disabled_sorts = symmetry_disabled_sorts.len();
    Ok((forbidden, symmetry_disabled_sorts))
}

fn constraint_declaration(
    problem: &Problem,
    fun: SymId,
) -> Result<&super::FunDecl, QuotientAbstain> {
    problem.fun_decls.get(fun).ok_or_else(|| {
        QuotientAbstain::InvalidProblem(format!(
            "forbidden-table constraint references undeclared symbol {fun}"
        ))
    })
}

fn validate_forbidden_table(
    fun: SymId,
    table: &[u8],
    expected_cells: usize,
    result_bound: usize,
) -> Result<(), QuotientAbstain> {
    if table.len() != expected_cells {
        return Err(QuotientAbstain::InvalidProblem(format!(
            "forbidden table for symbol {fun} has {} rows, expected {expected_cells}",
            table.len()
        )));
    }
    if let Some(value) = table.iter().find(|value| **value as usize >= result_bound) {
        return Err(QuotientAbstain::InvalidProblem(format!(
            "forbidden table for symbol {fun} contains out-of-domain value {value}"
        )));
    }
    Ok(())
}

fn account_forbidden_table(
    cells: usize,
    table_count: &mut usize,
    table_cells: &mut usize,
    caps: &QuotientCaps,
) -> Result<(), QuotientAbstain> {
    *table_count = table_count
        .checked_add(1)
        .ok_or(QuotientAbstain::StructuralCap {
            resource: "forbidden tables",
            limit: caps.max_forbidden_tables,
            actual: usize::MAX,
        })?;
    *table_cells = table_cells
        .checked_add(cells)
        .ok_or(QuotientAbstain::StructuralCap {
            resource: "forbidden table cells",
            limit: caps.max_forbidden_table_cells,
            actual: usize::MAX,
        })?;
    if *table_count > caps.max_forbidden_tables {
        return Err(QuotientAbstain::StructuralCap {
            resource: "forbidden tables",
            limit: caps.max_forbidden_tables,
            actual: *table_count,
        });
    }
    if *table_cells > caps.max_forbidden_table_cells {
        return Err(QuotientAbstain::StructuralCap {
            resource: "forbidden table cells",
            limit: caps.max_forbidden_table_cells,
            actual: *table_cells,
        });
    }
    Ok(())
}

fn conjugate_binary_table(table: &[u8], permutation: &[usize]) -> Vec<u8> {
    let size = permutation.len();
    let mut conjugate = vec![0u8; table.len()];
    for left in 0..size {
        for right in 0..size {
            let output = table[left * size + right] as usize;
            let new_left = permutation[left];
            let new_right = permutation[right];
            conjugate[new_left * size + new_right] = permutation[output] as u8;
        }
    }
    conjugate
}

fn next_permutation(values: &mut [usize]) -> bool {
    let Some(pivot) = (0..values.len().saturating_sub(1))
        .rev()
        .find(|index| values[*index] < values[*index + 1])
    else {
        return false;
    };
    let successor = (pivot + 1..values.len())
        .rev()
        .find(|index| values[*index] > values[pivot])
        .expect("a permutation pivot has a successor");
    values.swap(pivot, successor);
    values[pivot + 1..].reverse();
    true
}

fn collect_forced_relations(
    expr: &BoolExpr,
    required: bool,
    equalities: &mut BTreeSet<(TermId, TermId)>,
    disequalities: &mut BTreeSet<(TermId, TermId)>,
) {
    match (expr, required) {
        (BoolExpr::Atom(BoolAtomKey::Eq(left, right)), true) => {
            equalities.insert(normalized_pair(*left, *right));
        }
        (BoolExpr::Atom(BoolAtomKey::Eq(left, right)), false) => {
            disequalities.insert(normalized_pair(*left, *right));
        }
        (BoolExpr::Not(child), required) => {
            collect_forced_relations(child, !required, equalities, disequalities);
        }
        (BoolExpr::And(children), true) | (BoolExpr::Or(children), false) => {
            for child in children {
                collect_forced_relations(child, required, equalities, disequalities);
            }
        }
        _ => {}
    }
}

fn detect_all_different_groups(
    problem: &Problem,
    disequalities: &[(TermId, TermId)],
    limit: usize,
    telemetry: &mut QuotientTelemetry,
) -> Vec<Vec<TermId>> {
    let mut adjacency = vec![BTreeSet::<TermId>::new(); problem.arena.terms.len()];
    for &(left, right) in disequalities {
        if left != right {
            adjacency[left].insert(right);
            adjacency[right].insert(left);
        }
    }

    let mut groups = BTreeSet::new();
    for seed in 0..problem.arena.terms.len() {
        if adjacency[seed].len() < 2 {
            continue;
        }
        let sort = problem.arena.terms[seed].sort;
        let mut clique = vec![seed];
        for candidate in 0..problem.arena.terms.len() {
            if candidate == seed || problem.arena.terms[candidate].sort != sort {
                continue;
            }
            if clique
                .iter()
                .all(|member| adjacency[*member].contains(&candidate))
            {
                clique.push(candidate);
            }
        }
        clique.sort_unstable();
        clique.dedup();
        if clique.len() >= 3 {
            debug_assert!(clique.iter().enumerate().all(|(index, left)| {
                clique
                    .iter()
                    .skip(index + 1)
                    .all(|right| adjacency[*left].contains(right))
            }));
            groups.insert(clique);
        }
    }

    let detected = groups.len();
    telemetry.all_different_groups = detected.min(limit);
    telemetry.all_different_groups_skipped = detected.saturating_sub(limit);
    groups.into_iter().take(limit).collect()
}

fn normalized_pair(left: TermId, right: TermId) -> (TermId, TermId) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

fn full_mask(size: usize) -> u64 {
    if size == HARD_MAX_DOMAIN_SIZE {
        u64::MAX
    } else {
        (1u64 << size) - 1
    }
}

fn singleton_value(mask: u64) -> Option<usize> {
    (mask.count_ones() == 1).then(|| mask.trailing_zeros() as usize)
}

fn checked_tuple_count(arg_sorts: &[SortId], bounds: &[usize]) -> Option<usize> {
    arg_sorts.iter().try_fold(1usize, |product, sort| {
        product.checked_mul(bounds[sort.0 as usize])
    })
}

fn tuple_index(args: &[usize], arg_sorts: &[usize], bounds: &[usize]) -> Result<usize, String> {
    if args.len() != arg_sorts.len() {
        return Err(format!(
            "expected {} arguments, found {}",
            arg_sorts.len(),
            args.len()
        ));
    }
    let mut index = 0usize;
    for (&value, &sort) in args.iter().zip(arg_sorts) {
        let Some(&size) = bounds.get(sort) else {
            return Err(format!("invalid argument sort {sort}"));
        };
        if value >= size {
            return Err(format!("argument value {value} is outside sort {sort}"));
        }
        index = index
            .checked_mul(size)
            .and_then(|prefix| prefix.checked_add(value))
            .ok_or_else(|| "function table index overflow".to_owned())?;
    }
    Ok(index)
}

struct Search<'a, 'problem> {
    prepared: &'a Prepared<'problem>,
    caps: &'a QuotientCaps,
    telemetry: &'a mut QuotientTelemetry,
}

impl Search<'_, '_> {
    fn dfs(&mut self, mut state: SearchState, depth: usize) -> SearchOutcome {
        if self.telemetry.search_nodes >= self.caps.max_search_nodes {
            return SearchOutcome::Abstain(QuotientAbstain::SearchCap {
                resource: "search nodes",
                limit: self.caps.max_search_nodes,
            });
        }
        self.telemetry.search_nodes += 1;
        self.telemetry.max_depth = self.telemetry.max_depth.max(depth);

        match self.propagate(&mut state) {
            Ok(()) => {}
            Err(PropagationStop::Conflict) => return SearchOutcome::Exhausted,
            Err(PropagationStop::Cap) => {
                return SearchOutcome::Abstain(QuotientAbstain::SearchCap {
                    resource: "propagation rounds",
                    limit: self.caps.max_propagation_rounds,
                });
            }
        }

        let Some(term) = self.select_branch_term(&state) else {
            self.telemetry.complete_assignments += 1;
            let model = match build_total_model(self.prepared, &state, self.caps, self.telemetry) {
                Ok(model) => model,
                Err(ModelBuildError::NoAllowedCompletion) => {
                    self.telemetry.forbidden_table_rejections += 1;
                    return SearchOutcome::Exhausted;
                }
                Err(ModelBuildError::Cap) => {
                    return SearchOutcome::Abstain(QuotientAbstain::SearchCap {
                        resource: "total model completions",
                        limit: self.caps.max_totalization_attempts,
                    });
                }
                Err(ModelBuildError::Invalid(message)) => {
                    return SearchOutcome::Abstain(QuotientAbstain::ValidatorRejected(message));
                }
            };
            self.telemetry.candidate_models_built += 1;
            self.telemetry.validator_calls += 1;
            match validate_bounded_model(self.prepared.problem, &model) {
                Ok(()) => {
                    if let Err(message) = validate_prepared_table_constraints(self.prepared, &model)
                    {
                        self.telemetry.validator_rejections += 1;
                        return SearchOutcome::Abstain(QuotientAbstain::ValidatorRejected(message));
                    }
                    return SearchOutcome::Found(model);
                }
                Err(message) => {
                    self.telemetry.validator_rejections += 1;
                    return SearchOutcome::Abstain(QuotientAbstain::ValidatorRejected(message));
                }
            }
        };

        self.telemetry.decisions += 1;
        let sort = self.prepared.problem.arena.terms[term].sort;
        let domain = state.domains[term];
        let (candidates, introduced) = match self.canonical_candidates(&state, sort, domain) {
            Ok(values) => values,
            Err(message) => {
                return SearchOutcome::Abstain(QuotientAbstain::ValidatorRejected(message));
            }
        };
        self.telemetry.symmetry_values_skipped += domain.count_ones() as usize - candidates.len();
        if candidates.is_empty() {
            return SearchOutcome::Abstain(QuotientAbstain::ValidatorRejected(format!(
                "term {term} has no canonical branch value"
            )));
        }

        for value in candidates {
            let is_new = sort != BOOL_SORT && value == introduced;
            self.telemetry.branch_attempts += 1;
            if is_new {
                self.telemetry.symmetry_new_value_branches += 1;
            } else if sort != BOOL_SORT {
                self.telemetry.symmetry_existing_branches += 1;
            }
            self.telemetry.trace_decision(depth, term, value, is_new);

            let mut child = state.clone();
            let previous = child.domains[term];
            child.domains[term] = 1u64 << value;
            self.telemetry.domain_updates += 1;
            self.telemetry.domain_values_removed +=
                previous.count_ones() as usize - child.domains[term].count_ones() as usize;
            match self.dfs(child, depth + 1) {
                SearchOutcome::Found(model) => return SearchOutcome::Found(model),
                SearchOutcome::Abstain(reason) => return SearchOutcome::Abstain(reason),
                SearchOutcome::Exhausted => {
                    self.telemetry.backtracks += 1;
                }
            }
        }
        SearchOutcome::Exhausted
    }

    fn select_branch_term(&self, state: &SearchState) -> Option<TermId> {
        state
            .domains
            .iter()
            .enumerate()
            .filter_map(|(term, domain)| {
                let size = domain.count_ones() as usize;
                (size > 1).then_some((size, term))
            })
            .min()
            .map(|(_, term)| term)
    }

    fn canonical_candidates(
        &self,
        state: &SearchState,
        sort: SortId,
        domain: u64,
    ) -> Result<(Vec<usize>, usize), String> {
        let bound = self.prepared.bounds[sort.0 as usize];
        if sort == BOOL_SORT
            || self
                .prepared
                .symmetry_disabled_sorts
                .contains(&(sort.0 as usize))
        {
            let values = (0..bound)
                .filter(|value| domain & (1u64 << value) != 0)
                .collect();
            return Ok((values, bound));
        }

        let mut used = 0u64;
        for (term, term_domain) in state.domains.iter().enumerate() {
            if self.prepared.problem.arena.terms[term].sort == sort {
                if let Some(value) = singleton_value(*term_domain) {
                    used |= 1u64 << value;
                }
            }
        }
        let introduced = used.count_ones() as usize;
        if used != full_mask(introduced) {
            return Err(format!(
                "sort {} violated canonical value-introduction order: mask {used:#x}",
                sort.0
            ));
        }
        let mut values = (0..introduced)
            .filter(|value| domain & (1u64 << value) != 0)
            .collect::<Vec<_>>();
        if introduced < bound && domain & (1u64 << introduced) != 0 {
            values.push(introduced);
        }
        Ok((values, introduced))
    }

    fn propagate(&mut self, state: &mut SearchState) -> Result<(), PropagationStop> {
        if self.prepared.problem.contradiction {
            return Err(PropagationStop::Conflict);
        }
        loop {
            if self.telemetry.propagation_rounds >= self.caps.max_propagation_rounds {
                return Err(PropagationStop::Cap);
            }
            self.telemetry.propagation_rounds += 1;
            let mut changed = false;

            for &(term, value) in &self.prepared.fixed_values {
                changed |= self.narrow(state, term, 1u64 << value)?;
            }
            for &(left, right) in &self.prepared.equalities {
                changed |= self.apply_equality(state, left, right)?;
            }
            for &(left, right) in &self.prepared.disequalities {
                changed |= self.apply_disequality(state, left, right)?;
            }
            if let Some(bool_problem) = &self.prepared.problem.bool_problem {
                for assertion in &bool_problem.assertions {
                    changed |= self.enforce_bool(state, assertion, true)?;
                }
            }
            changed |= self.propagate_hall(state)?;
            changed |= self.propagate_congruence(state)?;

            if !changed {
                return Ok(());
            }
        }
    }

    fn narrow(
        &mut self,
        state: &mut SearchState,
        term: TermId,
        allowed: u64,
    ) -> Result<bool, PropagationStop> {
        let previous = state.domains[term];
        let next = previous & allowed;
        if next == 0 {
            return Err(PropagationStop::Conflict);
        }
        if next == previous {
            return Ok(false);
        }
        state.domains[term] = next;
        self.telemetry.domain_updates += 1;
        self.telemetry.domain_values_removed +=
            previous.count_ones() as usize - next.count_ones() as usize;
        Ok(true)
    }

    fn apply_equality(
        &mut self,
        state: &mut SearchState,
        left: TermId,
        right: TermId,
    ) -> Result<bool, PropagationStop> {
        self.telemetry.equality_checks += 1;
        let common = state.domains[left] & state.domains[right];
        if common == 0 {
            return Err(PropagationStop::Conflict);
        }
        let mut changed = false;
        changed |= self.narrow(state, left, common)?;
        changed |= self.narrow(state, right, common)?;
        if changed {
            self.telemetry.equality_reductions += 1;
        }
        Ok(changed)
    }

    fn apply_disequality(
        &mut self,
        state: &mut SearchState,
        left: TermId,
        right: TermId,
    ) -> Result<bool, PropagationStop> {
        self.telemetry.disequality_checks += 1;
        if left == right {
            return Err(PropagationStop::Conflict);
        }
        let left_value = singleton_value(state.domains[left]);
        let right_value = singleton_value(state.domains[right]);
        if left_value.is_some() && left_value == right_value {
            return Err(PropagationStop::Conflict);
        }
        let mut changed = false;
        if let Some(value) = left_value {
            changed |= self.narrow(state, right, !(1u64 << value))?;
        }
        if let Some(value) = right_value {
            changed |= self.narrow(state, left, !(1u64 << value))?;
        }
        if changed {
            self.telemetry.disequality_reductions += 1;
        }
        Ok(changed)
    }

    fn propagate_congruence(&mut self, state: &mut SearchState) -> Result<bool, PropagationStop> {
        let mut signatures = BTreeMap::<(SymId, Vec<usize>), TermId>::new();
        let mut changed = false;
        for (term_id, term) in self.prepared.problem.arena.terms.iter().enumerate() {
            let Some(args) = term
                .args
                .iter()
                .map(|arg| singleton_value(state.domains[*arg]))
                .collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            self.telemetry.congruence_signatures += 1;
            let signature = (term.fun, args);
            let Some(&canonical) = signatures.get(&signature) else {
                signatures.insert(signature, term_id);
                continue;
            };
            self.telemetry.congruence_collisions += 1;
            let common = state.domains[canonical] & state.domains[term_id];
            if common == 0 {
                self.telemetry.congruence_conflicts += 1;
                return Err(PropagationStop::Conflict);
            }
            let reduced =
                self.narrow(state, canonical, common)? | self.narrow(state, term_id, common)?;
            if reduced {
                self.telemetry.congruence_reductions += 1;
                changed = true;
            }
        }
        Ok(changed)
    }

    fn propagate_hall(&mut self, state: &mut SearchState) -> Result<bool, PropagationStop> {
        let mut changed = false;
        let mut checked_this_round = 0usize;
        'groups: for group in &self.prepared.all_different {
            let size = group.len();
            if size < 2 || size > self.caps.max_hall_group_size {
                continue;
            }
            let subset_limit = 1usize << size;
            for subset in 1usize..subset_limit {
                let cardinality = subset.count_ones() as usize;
                if cardinality < 2 {
                    continue;
                }
                if checked_this_round >= self.caps.max_hall_subsets_per_round {
                    break 'groups;
                }
                checked_this_round += 1;
                self.telemetry.hall_subsets_checked += 1;

                let mut union = 0u64;
                for (index, &term) in group.iter().enumerate() {
                    if subset & (1usize << index) != 0 {
                        union |= state.domains[term];
                    }
                }
                let values = union.count_ones() as usize;
                if values < cardinality {
                    self.telemetry.hall_conflicts += 1;
                    return Err(PropagationStop::Conflict);
                }
                if values != cardinality || cardinality == size {
                    continue;
                }
                for (index, &term) in group.iter().enumerate() {
                    if subset & (1usize << index) != 0 {
                        continue;
                    }
                    let previous = state.domains[term];
                    match self.narrow(state, term, !union) {
                        Ok(reduced) => {
                            if reduced {
                                self.telemetry.hall_reductions += 1;
                                self.telemetry.hall_values_removed += previous.count_ones()
                                    as usize
                                    - state.domains[term].count_ones() as usize;
                                changed = true;
                            }
                        }
                        Err(PropagationStop::Conflict) => {
                            self.telemetry.hall_conflicts += 1;
                            return Err(PropagationStop::Conflict);
                        }
                        Err(PropagationStop::Cap) => return Err(PropagationStop::Cap),
                    }
                }
            }
        }
        Ok(changed)
    }

    fn eval_bool(&mut self, state: &SearchState, expr: &BoolExpr) -> Truth {
        self.telemetry.formula_visits += 1;
        match expr {
            BoolExpr::Const(value) => truth(*value),
            BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
                if left == right {
                    Truth::True
                } else {
                    let common = state.domains[*left] & state.domains[*right];
                    if common == 0 {
                        Truth::False
                    } else {
                        match (
                            singleton_value(state.domains[*left]),
                            singleton_value(state.domains[*right]),
                        ) {
                            (Some(left), Some(right)) => truth(left == right),
                            _ => Truth::Unknown,
                        }
                    }
                }
            }
            BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => {
                match singleton_value(state.domains[*term]) {
                    Some(0) => Truth::False,
                    Some(1) => Truth::True,
                    _ => Truth::Unknown,
                }
            }
            BoolExpr::Not(child) => negate(self.eval_bool(state, child)),
            BoolExpr::And(children) => {
                let mut unknown = false;
                for child in children {
                    match self.eval_bool(state, child) {
                        Truth::False => return Truth::False,
                        Truth::Unknown => unknown = true,
                        Truth::True => {}
                    }
                }
                if unknown { Truth::Unknown } else { Truth::True }
            }
            BoolExpr::Or(children) => {
                let mut unknown = false;
                for child in children {
                    match self.eval_bool(state, child) {
                        Truth::True => return Truth::True,
                        Truth::Unknown => unknown = true,
                        Truth::False => {}
                    }
                }
                if unknown {
                    Truth::Unknown
                } else {
                    Truth::False
                }
            }
            BoolExpr::Iff(children) => {
                let mut seen_true = false;
                let mut seen_false = false;
                let mut unknown = false;
                for child in children {
                    match self.eval_bool(state, child) {
                        Truth::True => seen_true = true,
                        Truth::False => seen_false = true,
                        Truth::Unknown => unknown = true,
                    }
                }
                if seen_true && seen_false {
                    Truth::False
                } else if unknown {
                    Truth::Unknown
                } else {
                    Truth::True
                }
            }
            BoolExpr::Ite(condition, then_expr, else_expr) => {
                match self.eval_bool(state, condition) {
                    Truth::True => self.eval_bool(state, then_expr),
                    Truth::False => self.eval_bool(state, else_expr),
                    Truth::Unknown => {
                        let then_value = self.eval_bool(state, then_expr);
                        let else_value = self.eval_bool(state, else_expr);
                        if then_value == else_value {
                            then_value
                        } else {
                            Truth::Unknown
                        }
                    }
                }
            }
        }
    }

    fn enforce_bool(
        &mut self,
        state: &mut SearchState,
        expr: &BoolExpr,
        required: bool,
    ) -> Result<bool, PropagationStop> {
        match self.eval_bool(state, expr) {
            Truth::True if required => return Ok(false),
            Truth::False if !required => return Ok(false),
            Truth::True | Truth::False => return Err(PropagationStop::Conflict),
            Truth::Unknown => {}
        }

        match expr {
            BoolExpr::Const(_) => unreachable!("constants evaluate to a known truth value"),
            BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
                self.telemetry.formula_forced_atoms += 1;
                if required {
                    self.apply_equality(state, *left, *right)
                } else {
                    self.apply_disequality(state, *left, *right)
                }
            }
            BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => {
                self.telemetry.formula_forced_atoms += 1;
                self.narrow(state, *term, 1u64 << usize::from(required))
            }
            BoolExpr::Not(child) => self.enforce_bool(state, child, !required),
            BoolExpr::And(children) if required => {
                let mut changed = false;
                for child in children {
                    changed |= self.enforce_bool(state, child, true)?;
                }
                Ok(changed)
            }
            BoolExpr::Or(children) if !required => {
                let mut changed = false;
                for child in children {
                    changed |= self.enforce_bool(state, child, false)?;
                }
                Ok(changed)
            }
            BoolExpr::And(children) | BoolExpr::Or(children) => {
                let child_required = matches!(expr, BoolExpr::Or(_));
                let mut unknown = None;
                let mut unknown_count = 0usize;
                for child in children {
                    if self.eval_bool(state, child) == Truth::Unknown {
                        unknown = Some(child);
                        unknown_count += 1;
                    }
                }
                if unknown_count == 1 {
                    self.enforce_bool(
                        state,
                        unknown.expect("counted one unknown child"),
                        child_required,
                    )
                } else {
                    Ok(false)
                }
            }
            BoolExpr::Iff(children) => {
                let values = children
                    .iter()
                    .map(|child| self.eval_bool(state, child))
                    .collect::<Vec<_>>();
                if required {
                    let known = values.iter().find_map(|value| match value {
                        Truth::False => Some(false),
                        Truth::True => Some(true),
                        Truth::Unknown => None,
                    });
                    let Some(known) = known else {
                        return Ok(false);
                    };
                    let mut changed = false;
                    for (child, value) in children.iter().zip(values) {
                        if value == Truth::Unknown {
                            changed |= self.enforce_bool(state, child, known)?;
                        }
                    }
                    Ok(changed)
                } else {
                    let unknown = values
                        .iter()
                        .enumerate()
                        .filter_map(|(index, value)| (*value == Truth::Unknown).then_some(index))
                        .collect::<Vec<_>>();
                    if unknown.len() != 1 {
                        return Ok(false);
                    }
                    let known = values.iter().find_map(|value| match value {
                        Truth::False => Some(false),
                        Truth::True => Some(true),
                        Truth::Unknown => None,
                    });
                    match known {
                        Some(known) => self.enforce_bool(state, &children[unknown[0]], !known),
                        None => Ok(false),
                    }
                }
            }
            BoolExpr::Ite(condition, then_expr, else_expr) => {
                match self.eval_bool(state, condition) {
                    Truth::True => return self.enforce_bool(state, then_expr, required),
                    Truth::False => return self.enforce_bool(state, else_expr, required),
                    Truth::Unknown => {}
                }
                let then_value = self.eval_bool(state, then_expr);
                let else_value = self.eval_bool(state, else_expr);
                let impossible = truth(!required);
                if then_value == impossible {
                    let changed_condition = self.enforce_bool(state, condition, false)?;
                    let changed_branch = self.enforce_bool(state, else_expr, required)?;
                    Ok(changed_condition | changed_branch)
                } else if else_value == impossible {
                    let changed_condition = self.enforce_bool(state, condition, true)?;
                    let changed_branch = self.enforce_bool(state, then_expr, required)?;
                    Ok(changed_condition | changed_branch)
                } else {
                    Ok(false)
                }
            }
        }
    }
}

fn truth(value: bool) -> Truth {
    if value { Truth::True } else { Truth::False }
}

fn negate(value: Truth) -> Truth {
    match value {
        Truth::False => Truth::True,
        Truth::Unknown => Truth::Unknown,
        Truth::True => Truth::False,
    }
}

fn build_total_model(
    prepared: &Prepared<'_>,
    state: &SearchState,
    caps: &QuotientCaps,
    telemetry: &mut QuotientTelemetry,
) -> Result<QuotientModel, ModelBuildError> {
    let term_values = state
        .domains
        .iter()
        .enumerate()
        .map(|(term, domain)| {
            singleton_value(*domain)
                .map(|value| value as u8)
                .ok_or_else(|| {
                    ModelBuildError::Invalid(format!(
                        "term {term} is not fixed in a candidate model"
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut functions = Vec::with_capacity(prepared.problem.fun_decls.slots.len());
    let mut assigned = Vec::with_capacity(prepared.problem.fun_decls.slots.len());
    for declaration in &prepared.problem.fun_decls.slots {
        match declaration {
            None => {
                functions.push(None);
                assigned.push(Vec::new());
            }
            Some(declaration) => {
                let cells = checked_tuple_count(&declaration.arg_sorts, &prepared.bounds)
                    .ok_or_else(|| {
                        ModelBuildError::Invalid(
                            "function table size overflow while building model".to_owned(),
                        )
                    })?;
                functions.push(Some(FunctionInterpretation {
                    arg_sorts: declaration
                        .arg_sorts
                        .iter()
                        .map(|sort| sort.0 as usize)
                        .collect(),
                    result_sort: declaration.result_sort.0 as usize,
                    values: vec![0; cells],
                }));
                assigned.push(vec![false; cells]);
            }
        }
    }

    for (term_id, term) in prepared.problem.arena.terms.iter().enumerate() {
        let args = term
            .args
            .iter()
            .map(|arg| term_values[*arg] as usize)
            .collect::<Vec<_>>();
        let interpretation = functions[term.fun as usize].as_mut().ok_or_else(|| {
            ModelBuildError::Invalid(format!("term {term_id} has no function interpretation"))
        })?;
        let index = tuple_index(&args, &interpretation.arg_sorts, &prepared.bounds)
            .map_err(ModelBuildError::Invalid)?;
        let output = term_values[term_id];
        if assigned[term.fun as usize][index] && interpretation.values[index] != output {
            return Err(ModelBuildError::Invalid(format!(
                "terms with symbol {} and table row {index} disagree on outputs {} and {output}",
                term.fun, interpretation.values[index]
            )));
        }
        assigned[term.fun as usize][index] = true;
        interpretation.values[index] = output;
    }

    let mut attempts = 0usize;
    for (&fun, forbidden) in &prepared.forbidden_tables {
        let interpretation = functions[fun as usize]
            .as_mut()
            .expect("constraint preparation checked the declaration");
        let unassigned = assigned[fun as usize]
            .iter()
            .enumerate()
            .filter_map(|(row, is_assigned)| (!*is_assigned).then_some(row))
            .collect::<Vec<_>>();
        let result_bound = prepared.bounds[interpretation.result_sort];
        loop {
            if attempts >= caps.max_totalization_attempts {
                return Err(ModelBuildError::Cap);
            }
            attempts += 1;
            telemetry.totalization_attempts += 1;
            telemetry.forbidden_table_checks += 1;
            if !forbidden.contains(&interpretation.values) {
                break;
            }
            if !increment_unassigned_rows(&mut interpretation.values, &unassigned, result_bound) {
                return Err(ModelBuildError::NoAllowedCompletion);
            }
        }
    }

    Ok(QuotientModel {
        domain_sizes: prepared.bounds.clone(),
        term_values,
        functions,
    })
}

fn increment_unassigned_rows(values: &mut [u8], rows: &[usize], radix: usize) -> bool {
    for &row in rows.iter().rev() {
        let next = values[row] as usize + 1;
        if next < radix {
            values[row] = next as u8;
            return true;
        }
        values[row] = 0;
    }
    false
}

fn validate_prepared_table_constraints(
    prepared: &Prepared<'_>,
    model: &QuotientModel,
) -> Result<(), String> {
    for (&fun, forbidden) in &prepared.forbidden_tables {
        let table = &model.functions[fun as usize]
            .as_ref()
            .ok_or_else(|| format!("model omits constrained symbol {fun}"))?
            .values;
        if forbidden.contains(table) {
            return Err(format!(
                "model uses a forbidden complete table for symbol {fun}"
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_bounded_model_with_constraints(
    problem: &Problem,
    model: &QuotientModel,
    constraints: &QuotientConstraints,
    caps: &QuotientCaps,
) -> Result<(), String> {
    validate_bounded_model(problem, model)?;
    let mut telemetry = QuotientTelemetry::new(problem);
    let (forbidden, _) = prepare_table_constraints(
        problem,
        &model.domain_sizes,
        constraints,
        caps,
        &mut telemetry,
    )
    .map_err(|reason| format!("invalid table constraints: {reason:?}"))?;
    for (fun, tables) in forbidden {
        let table = &model.functions[fun as usize]
            .as_ref()
            .ok_or_else(|| format!("model omits constrained symbol {fun}"))?
            .values;
        if tables.contains(table) {
            return Err(format!(
                "model uses a forbidden complete table for symbol {fun}"
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_bounded_model(
    problem: &Problem,
    model: &QuotientModel,
) -> Result<(), String> {
    let unsupported = unsupported_reasons(problem);
    if !unsupported.is_empty() {
        return Err(format!(
            "cannot validate unsupported input: {}",
            unsupported.join("; ")
        ));
    }
    if problem.contradiction {
        return Err("parsed problem carries an explicit contradiction".to_owned());
    }
    if model.domain_sizes.len() != problem.sorts.names.len() {
        return Err(format!(
            "model has {} sort domains, expected {}",
            model.domain_sizes.len(),
            problem.sorts.names.len()
        ));
    }
    if model.domain_sizes.first().copied() != Some(2) {
        return Err("model Bool domain must have size 2".to_owned());
    }
    if model.domain_sizes.contains(&0) {
        return Err("model contains an empty sort domain".to_owned());
    }
    if model.term_values.len() != problem.arena.terms.len() {
        return Err(format!(
            "model has {} term values, expected {}",
            model.term_values.len(),
            problem.arena.terms.len()
        ));
    }
    if model.functions.len() != problem.fun_decls.slots.len() {
        return Err(format!(
            "model has {} function slots, expected {}",
            model.functions.len(),
            problem.fun_decls.slots.len()
        ));
    }

    for (sym, (declaration, interpretation)) in problem
        .fun_decls
        .slots
        .iter()
        .zip(&model.functions)
        .enumerate()
    {
        match (declaration, interpretation) {
            (None, None) => {}
            (None, Some(_)) => {
                return Err(format!("model interprets undeclared symbol {sym}"));
            }
            (Some(_), None) => {
                return Err(format!("model omits declared symbol {sym}"));
            }
            (Some(declaration), Some(interpretation)) => {
                let arg_sorts = declaration
                    .arg_sorts
                    .iter()
                    .map(|sort| sort.0 as usize)
                    .collect::<Vec<_>>();
                if interpretation.arg_sorts != arg_sorts
                    || interpretation.result_sort != declaration.result_sort.0 as usize
                {
                    return Err(format!("model signature for symbol {sym} is incorrect"));
                }
                let expected_cells =
                    checked_tuple_count(&declaration.arg_sorts, &model.domain_sizes)
                        .ok_or_else(|| format!("model table size for symbol {sym} overflows"))?;
                if interpretation.values.len() != expected_cells {
                    return Err(format!(
                        "symbol {sym} has {} table rows, expected {expected_cells}",
                        interpretation.values.len()
                    ));
                }
                let result_bound = model.domain_sizes[interpretation.result_sort];
                if let Some(value) = interpretation
                    .values
                    .iter()
                    .find(|value| **value as usize >= result_bound)
                {
                    return Err(format!(
                        "symbol {sym} table contains out-of-domain result {value}"
                    ));
                }
            }
        }
    }

    let mut memo = vec![None; problem.arena.terms.len()];
    let mut visiting = vec![false; problem.arena.terms.len()];
    for term in 0..problem.arena.terms.len() {
        let evaluated = evaluate_model_term(problem, model, term, &mut memo, &mut visiting)?;
        let recorded = model.term_values[term] as usize;
        if evaluated != recorded {
            return Err(format!(
                "term {term} records value {recorded}, but its function table evaluates to {evaluated}"
            ));
        }
    }

    for &(left, right) in &problem.eqs {
        if memo[left] != memo[right] {
            return Err(format!("mandatory equality ({left}, {right}) is false"));
        }
    }
    for &(left, right) in &problem.diseqs {
        if memo[left] == memo[right] {
            return Err(format!("mandatory disequality ({left}, {right}) is false"));
        }
    }
    if let Some(bool_problem) = &problem.bool_problem {
        if memo[bool_problem.false_term] != Some(0) {
            return Err("distinguished false term does not denote 0".to_owned());
        }
        if memo[bool_problem.true_term] != Some(1) {
            return Err("distinguished true term does not denote 1".to_owned());
        }
        for (index, assertion) in bool_problem.assertions.iter().enumerate() {
            if !evaluate_model_bool(assertion, &memo)? {
                return Err(format!("Boolean assertion {index} evaluates to false"));
            }
        }
    }
    Ok(())
}

fn evaluate_model_term(
    problem: &Problem,
    model: &QuotientModel,
    term_id: TermId,
    memo: &mut [Option<usize>],
    visiting: &mut [bool],
) -> Result<usize, String> {
    if let Some(value) = memo
        .get(term_id)
        .ok_or_else(|| format!("missing term {term_id}"))?
    {
        return Ok(*value);
    }
    if visiting[term_id] {
        return Err(format!("term graph contains a cycle at term {term_id}"));
    }
    visiting[term_id] = true;
    let term = &problem.arena.terms[term_id];
    let mut args = Vec::with_capacity(term.args.len());
    for &arg in &term.args {
        args.push(evaluate_model_term(problem, model, arg, memo, visiting)?);
    }
    let interpretation = model
        .functions
        .get(term.fun as usize)
        .and_then(Option::as_ref)
        .ok_or_else(|| format!("term {term_id} uses missing symbol {}", term.fun))?;
    let index = tuple_index(&args, &interpretation.arg_sorts, &model.domain_sizes)?;
    let value = *interpretation
        .values
        .get(index)
        .ok_or_else(|| format!("symbol {} is missing table row {index}", term.fun))?
        as usize;
    visiting[term_id] = false;
    memo[term_id] = Some(value);
    Ok(value)
}

fn evaluate_model_bool(expr: &BoolExpr, term_values: &[Option<usize>]) -> Result<bool, String> {
    match expr {
        BoolExpr::Const(value) => Ok(*value),
        BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
            let left = term_values
                .get(*left)
                .and_then(|value| *value)
                .ok_or_else(|| format!("Boolean equality references missing term {left}"))?;
            let right = term_values
                .get(*right)
                .and_then(|value| *value)
                .ok_or_else(|| format!("Boolean equality references missing term {right}"))?;
            Ok(left == right)
        }
        BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => {
            let value = term_values
                .get(*term)
                .and_then(|value| *value)
                .ok_or_else(|| format!("Boolean atom references missing term {term}"))?;
            match value {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(format!("Boolean term {term} has non-Boolean value {value}")),
            }
        }
        BoolExpr::Not(child) => Ok(!evaluate_model_bool(child, term_values)?),
        BoolExpr::And(children) => {
            for child in children {
                if !evaluate_model_bool(child, term_values)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        BoolExpr::Or(children) => {
            for child in children {
                if evaluate_model_bool(child, term_values)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        BoolExpr::Iff(children) => {
            let Some((first, rest)) = children.split_first() else {
                return Ok(true);
            };
            let first = evaluate_model_bool(first, term_values)?;
            for child in rest {
                if evaluate_model_bool(child, term_values)? != first {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        BoolExpr::Ite(condition, then_expr, else_expr) => {
            if evaluate_model_bool(condition, term_values)? {
                evaluate_model_bool(then_expr, term_values)
            } else {
                evaluate_model_bool(else_expr, term_values)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ScopedLetMode, parse_problem_with_scoped_let_mode};

    fn parse(input: &str) -> Problem {
        parse_problem_with_scoped_let_mode(input, ScopedLetMode::Off).unwrap()
    }

    fn solve(problem: &Problem, bounds: &[usize]) -> QuotientResult {
        solve_bounded_quotient(problem, bounds, &QuotientCaps::default())
    }

    fn unique_function_with_arity(problem: &Problem, arity: usize) -> SymId {
        let matches = problem
            .fun_decls
            .slots
            .iter()
            .enumerate()
            .filter_map(|(fun, declaration)| {
                declaration
                    .as_ref()
                    .is_some_and(|declaration| declaration.arg_sorts.len() == arity)
                    .then_some(fun as SymId)
            })
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "expected one function of arity {arity}");
        matches[0]
    }

    fn expect_sat(result: QuotientResult) -> (QuotientModel, QuotientTelemetry) {
        match result {
            QuotientResult::Sat { model, telemetry } => (model, telemetry),
            other => panic!("expected SAT, found {other:?}"),
        }
    }

    fn expect_unsat(result: QuotientResult) -> QuotientTelemetry {
        match result {
            QuotientResult::Unsat { telemetry } => telemetry,
            other => panic!("expected UNSAT, found {other:?}"),
        }
    }

    fn result_is_sat(result: QuotientResult) -> bool {
        match result {
            QuotientResult::Sat { .. } => true,
            QuotientResult::Unsat { .. } => false,
            QuotientResult::Abstain { reason, .. } => {
                panic!("reference solver unexpectedly abstained: {reason:?}")
            }
        }
    }

    fn brute_force_sat(problem: &Problem, bounds: &[usize]) -> bool {
        let mut functions = Vec::with_capacity(problem.fun_decls.slots.len());
        let mut cells = Vec::new();
        let mut interpretation_count = 1usize;
        for (sym, declaration) in problem.fun_decls.slots.iter().enumerate() {
            match declaration {
                None => functions.push(None),
                Some(declaration) => {
                    let row_count = checked_tuple_count(&declaration.arg_sorts, bounds).unwrap();
                    let result_bound = bounds[declaration.result_sort.0 as usize];
                    for row in 0..row_count {
                        cells.push((sym, row, result_bound));
                        interpretation_count = interpretation_count
                            .checked_mul(result_bound)
                            .expect("tiny brute-force test space must fit usize");
                    }
                    functions.push(Some(FunctionInterpretation {
                        arg_sorts: declaration
                            .arg_sorts
                            .iter()
                            .map(|sort| sort.0 as usize)
                            .collect(),
                        result_sort: declaration.result_sort.0 as usize,
                        values: vec![0; row_count],
                    }));
                }
            }
        }
        assert!(
            interpretation_count <= 1_000_000,
            "brute-force test accidentally requested {interpretation_count} interpretations"
        );
        let mut model = QuotientModel {
            domain_sizes: bounds.to_vec(),
            term_values: vec![0; problem.arena.terms.len()],
            functions,
        };
        brute_assign(problem, &mut model, &cells, 0)
    }

    fn brute_assign(
        problem: &Problem,
        model: &mut QuotientModel,
        cells: &[(usize, usize, usize)],
        index: usize,
    ) -> bool {
        if index == cells.len() {
            return brute_candidate_satisfies(problem, model);
        }
        let (sym, row, result_bound) = cells[index];
        for value in 0..result_bound {
            model.functions[sym].as_mut().unwrap().values[row] = value as u8;
            if brute_assign(problem, model, cells, index + 1) {
                return true;
            }
        }
        false
    }

    fn brute_candidate_satisfies(problem: &Problem, model: &QuotientModel) -> bool {
        if problem.contradiction {
            return false;
        }
        let mut memo = vec![None; problem.arena.terms.len()];
        let mut visiting = vec![false; problem.arena.terms.len()];
        for term in 0..problem.arena.terms.len() {
            if evaluate_model_term(problem, model, term, &mut memo, &mut visiting).is_err() {
                return false;
            }
        }
        if problem
            .eqs
            .iter()
            .any(|(left, right)| memo[*left] != memo[*right])
            || problem
                .diseqs
                .iter()
                .any(|(left, right)| memo[*left] == memo[*right])
        {
            return false;
        }
        let Some(bool_problem) = &problem.bool_problem else {
            return true;
        };
        if memo[bool_problem.false_term] != Some(0) || memo[bool_problem.true_term] != Some(1) {
            return false;
        }
        bool_problem
            .assertions
            .iter()
            .all(|assertion| evaluate_model_bool(assertion, &memo) == Ok(true))
    }

    #[test]
    fn exhaustive_small_generated_instances_match_total_function_enumeration() {
        let atoms = ["(= a b)", "(= (f a) b)", "(= (f a) (f b))"];
        for code in 0..27usize {
            let mut input = String::from(
                "(set-logic QF_UF)\n\
                 (declare-sort U 0)\n\
                 (declare-fun a () U)\n\
                 (declare-fun b () U)\n\
                 (declare-fun f (U) U)\n",
            );
            let mut choices = code;
            for atom in atoms {
                match choices % 3 {
                    0 => {}
                    1 => input.push_str(&format!("(assert {atom})\n")),
                    2 => input.push_str(&format!("(assert (not {atom}))\n")),
                    _ => unreachable!(),
                }
                choices /= 3;
            }
            input.push_str("(check-sat)\n");
            let problem = parse(&input);
            let expected = brute_force_sat(&problem, &[2, 2]);
            let actual = result_is_sat(solve(&problem, &[2, 2]));
            assert_eq!(actual, expected, "generated case {code}:\n{input}");
        }
    }

    #[test]
    fn boolean_as_data_is_exact_in_sat_and_congruence_unsat_cases() {
        let sat_problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun p () Bool)
             (declare-fun q () Bool)
             (declare-fun f (Bool) U)
             (declare-fun h (U) Bool)
             (assert p)
             (assert (not q))
             (assert (distinct (f p) (f q)))
             (assert (h (f p)))
             (check-sat)",
        );
        let (model, _) = expect_sat(solve(&sat_problem, &[2, 2]));
        validate_bounded_model(&sat_problem, &model).unwrap();

        let unsat_problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun p () Bool)
             (declare-fun f (Bool) U)
             (assert p)
             (assert (distinct (f p) (f true)))
             (check-sat)",
        );
        let telemetry = expect_unsat(solve(&unsat_problem, &[2, 2]));
        assert!(telemetry.congruence_collisions > 0);
    }

    #[test]
    fn nested_ufs_propagate_congruence_signatures() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun a () U)
             (declare-fun b () U)
             (declare-fun f (U) U)
             (declare-fun g (U) U)
             (declare-fun h (U) U)
             (assert (= a b))
             (assert (distinct (h (g (f a))) (h (g (f b)))))
             (check-sat)",
        );
        let telemetry = expect_unsat(solve(&problem, &[2, 2]));
        assert!(telemetry.congruence_collisions >= 3);
        assert!(telemetry.congruence_conflicts > 0);
    }

    #[test]
    fn pigeonhole_unsat_is_found_by_a_hall_conflict() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun a () U)
             (declare-fun b () U)
             (declare-fun c () U)
             (assert (distinct a b c))
             (check-sat)",
        );
        let telemetry = expect_unsat(solve(&problem, &[2, 2]));
        assert!(telemetry.all_different_groups > 0);
        assert!(telemetry.hall_conflicts > 0);
        assert_eq!(telemetry.decisions, 0);
    }

    #[test]
    fn hall_subset_prunes_values_in_a_satisfiable_instance() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun z () U)
             (declare-fun a () U)
             (declare-fun b () U)
             (declare-fun c () U)
             (assert (and (distinct z a) (distinct z b) (distinct a b c)))
             (check-sat)",
        );
        let (model, telemetry) = expect_sat(solve(&problem, &[2, 3]));
        validate_bounded_model(&problem, &model).unwrap();
        assert!(telemetry.hall_reductions > 0);
        assert!(telemetry.hall_values_removed > 0);
    }

    #[test]
    fn sat_witness_has_total_tables_and_survives_independent_validation() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun unused (U U) U)
             (declare-fun a () U)
             (declare-fun b () U)
             (declare-fun f (U) U)
             (assert (distinct a b))
             (assert (= (f a) b))
             (assert (= (f b) a))
             (check-sat)",
        );
        let (model, telemetry) = expect_sat(solve(&problem, &[2, 2]));
        validate_bounded_model(&problem, &model).unwrap();
        assert_eq!(telemetry.validator_calls, 1);
        for (declaration, interpretation) in problem.fun_decls.slots.iter().zip(&model.functions) {
            if let Some(declaration) = declaration {
                let expected = checked_tuple_count(&declaration.arg_sorts, &[2, 2]).unwrap();
                assert_eq!(interpretation.as_ref().unwrap().values.len(), expected);
            }
        }
    }

    #[test]
    fn multiple_sorts_use_independent_bounds() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-sort V 0)
             (declare-fun a () U)
             (declare-fun b () V)
             (declare-fun c () V)
             (declare-fun f (U) V)
             (declare-fun g (V) U)
             (assert (distinct b c))
             (assert (= (g (f a)) a))
             (check-sat)",
        );
        let (model, _) = expect_sat(solve(&problem, &[2, 1, 2]));
        validate_bounded_model(&problem, &model).unwrap();
        assert_eq!(model.domain_sizes, vec![2, 1, 2]);

        let unsat = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-sort V 0)
             (declare-fun a () U)
             (declare-fun d () U)
             (declare-fun b () V)
             (assert (distinct a d))
             (check-sat)",
        );
        expect_unsat(solve(&unsat, &[2, 1, 2]));
    }

    #[test]
    fn symmetry_quotient_is_deterministic() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun a () U)
             (declare-fun b () U)
             (declare-fun c () U)
             (declare-fun f (U) U)
             (assert (distinct a b))
             (assert (distinct (f a) c))
             (check-sat)",
        );
        let first = solve(&problem, &[2, 3]);
        let second = solve(&problem, &[2, 3]);
        assert_eq!(first, second);
        let (model, telemetry) = expect_sat(first);
        assert!(telemetry.symmetry_new_value_branches > 0);
        assert!(telemetry.symmetry_values_skipped > 0);
        validate_bounded_model(&problem, &model).unwrap();
    }

    #[test]
    fn search_cap_abstains_instead_of_claiming_unsat() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun a () U)
             (assert (= a a))
             (check-sat)",
        );
        let caps = QuotientCaps {
            max_search_nodes: 1,
            ..QuotientCaps::default()
        };
        match solve_bounded_quotient(&problem, &[2, 3], &caps) {
            QuotientResult::Abstain {
                reason:
                    QuotientAbstain::SearchCap {
                        resource: "search nodes",
                        limit: 1,
                    },
                telemetry,
            } => assert_eq!(telemetry.search_nodes, 1),
            other => panic!("expected deterministic cap abstention, found {other:?}"),
        }
    }

    #[test]
    fn invalid_bounds_and_unsupported_commands_fail_closed() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun a () U)
             (check-sat)",
        );
        assert!(matches!(
            solve(&problem, &[1, 2]),
            QuotientResult::Abstain {
                reason: QuotientAbstain::InvalidBounds(_),
                ..
            }
        ));
        assert!(matches!(
            solve(&problem, &[2]),
            QuotientResult::Abstain {
                reason: QuotientAbstain::InvalidBounds(_),
                ..
            }
        ));

        let unsupported = parse(
            "(set-logic QF_UF)
             (set-feature mystery)
             (check-sat)",
        );
        assert!(matches!(
            solve(&unsupported, &[2]),
            QuotientResult::Abstain {
                reason: QuotientAbstain::Unsupported(_),
                ..
            }
        ));
    }

    #[test]
    fn independent_validator_rejects_a_tampered_witness() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun a () U)
             (declare-fun f (U) U)
             (assert (= (f a) a))
             (check-sat)",
        );
        let (mut model, _) = expect_sat(solve(&problem, &[2, 2]));
        let application = problem
            .arena
            .terms
            .iter()
            .enumerate()
            .find(|(_, term)| !term.args.is_empty())
            .map(|(term, _)| term)
            .unwrap();
        model.term_values[application] ^= 1;
        assert!(validate_bounded_model(&problem, &model).is_err());
    }

    #[test]
    fn raw_forbidden_tables_disable_unsafe_value_symmetry() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun a () U)
             (assert (= a a))
             (check-sat)",
        );
        let fun = problem
            .arena
            .terms
            .iter()
            .find(|term| term.sort != BOOL_SORT)
            .unwrap()
            .fun;
        let constraints = QuotientConstraints {
            forbidden_complete_tables: vec![ForbiddenCompleteTables {
                fun,
                tables: vec![vec![0]],
            }],
            ..QuotientConstraints::default()
        };
        let result = solve_bounded_quotient_with_constraints(
            &problem,
            &[2, 2],
            &QuotientCaps::default(),
            &constraints,
        );
        let (model, telemetry) = expect_sat(result);
        assert_eq!(model.functions[fun as usize].as_ref().unwrap().values, [1]);
        assert_eq!(telemetry.symmetry_disabled_sorts, 1);
        assert!(telemetry.forbidden_table_rejections > 0);
        validate_bounded_model_with_constraints(
            &problem,
            &model,
            &constraints,
            &QuotientCaps::default(),
        )
        .unwrap();
    }

    #[test]
    fn forbidden_orbit_totalizes_unobserved_rows_to_an_allowed_table() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun mul (U U) U)
             (check-sat)",
        );
        let fun = unique_function_with_arity(&problem, 2);
        let constraints = QuotientConstraints {
            forbidden_conjugacy_orbits: vec![ForbiddenConjugacyOrbit {
                fun,
                representative: vec![0, 0, 0, 0],
            }],
            ..QuotientConstraints::default()
        };
        let result = solve_bounded_quotient_with_constraints(
            &problem,
            &[2, 2],
            &QuotientCaps::default(),
            &constraints,
        );
        let (model, telemetry) = expect_sat(result);
        assert_eq!(telemetry.generated_orbit_tables, 2);
        assert_eq!(telemetry.forbidden_tables, 2);
        assert_eq!(telemetry.symmetry_disabled_sorts, 0);
        assert!(telemetry.totalization_attempts >= 2);
        validate_bounded_model_with_constraints(
            &problem,
            &model,
            &constraints,
            &QuotientCaps::default(),
        )
        .unwrap();
    }

    #[test]
    fn forbidden_singleton_orbit_can_prove_bounded_unsat() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-sort U 0)
             (declare-fun mul (U U) U)
             (check-sat)",
        );
        let fun = unique_function_with_arity(&problem, 2);
        let constraints = QuotientConstraints {
            forbidden_conjugacy_orbits: vec![ForbiddenConjugacyOrbit {
                fun,
                representative: vec![0],
            }],
            ..QuotientConstraints::default()
        };
        let telemetry = expect_unsat(solve_bounded_quotient_with_constraints(
            &problem,
            &[2, 1],
            &QuotientCaps::default(),
            &constraints,
        ));
        assert_eq!(telemetry.forbidden_table_rejections, 1);
    }

    #[test]
    fn orbit_generation_has_the_expected_s7_permutation_count() {
        let mut permutation = (0..7).collect::<Vec<_>>();
        let mut count = 1usize;
        while next_permutation(&mut permutation) {
            count += 1;
        }
        assert_eq!(count, 5_040);
    }
}
