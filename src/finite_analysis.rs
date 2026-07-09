use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::{env, fmt};

use super::{
    BoolAtomKey, BoolExpr, BoolProblem, CnfProblem, SymId, TermArena, TermId,
    collect_mandatory_coverages, collect_mandatory_disequalities, largest_small_disequality_clique,
    normalized_pair,
};

const DENSITY_SCALE: u128 = 1_000_000;
const GUARDED_CLIQUE_SEED_LIMIT: usize = 32;
const DEFAULT_PERMUTATION_CLIQUE_LIMIT: usize = 4_096;
const MAX_PERMUTATION_CLIQUE_LIMIT: usize = 65_536;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PermutationSupportStats {
    pub(crate) direct_edges: usize,
    pub(crate) guarded_edges: usize,
    pub(crate) candidate_edges: usize,
    pub(crate) cliques: usize,
    pub(crate) clauses: usize,
    pub(crate) truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FiniteAnalysis {
    pub(crate) discovered_domain_size: usize,
    pub(crate) covered_finite_terms: usize,
    pub(crate) recognized_finite_terms: usize,
    pub(crate) distinct_constants: usize,
    pub(crate) closed_table_functions: usize,
    pub(crate) unary_table_applications: usize,
    pub(crate) binary_table_applications: usize,
    pub(crate) higher_arity_table_applications: usize,
    pub(crate) equality_graph_vertices: usize,
    pub(crate) equality_graph_edges: usize,
    pub(crate) equality_graph_density_ppm: u32,
    pub(crate) disequality_graph_edges: usize,
    pub(crate) disequality_graph_density_ppm: u32,
    pub(crate) guarded_disequality_clauses: usize,
    pub(crate) guarded_disequality_edges: usize,
    pub(crate) guarded_disequality_vertices: usize,
    pub(crate) guarded_disequality_density_ppm: u32,
    pub(crate) guarded_disequality_clique_lower_bound: usize,
    pub(crate) all_different_clique_lower_bound: usize,
    pub(crate) estimated_one_hot_variables: usize,
    pub(crate) estimated_one_hot_clauses: usize,
}

impl fmt::Display for FiniteAnalysis {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            concat!(
                "domain_size={} covered_finite_terms={} recognized_finite_terms={} ",
                "distinct_constants={} closed_table_functions={} unary_table_apps={} ",
                "binary_table_apps={} higher_arity_table_apps={} equality_graph_vertices={} ",
                "equality_graph_edges={} equality_graph_density_ppm={} ",
                "disequality_graph_edges={} disequality_graph_density_ppm={} ",
                "guarded_disequality_clauses={} guarded_disequality_edges={} ",
                "guarded_disequality_vertices={} guarded_disequality_density_ppm={} ",
                "guarded_disequality_clique_lb={} ",
                "all_different_clique_lb={} one_hot_variables_est={} one_hot_clauses_est={}"
            ),
            self.discovered_domain_size,
            self.covered_finite_terms,
            self.recognized_finite_terms,
            self.distinct_constants,
            self.closed_table_functions,
            self.unary_table_applications,
            self.binary_table_applications,
            self.higher_arity_table_applications,
            self.equality_graph_vertices,
            self.equality_graph_edges,
            self.equality_graph_density_ppm,
            self.disequality_graph_edges,
            self.disequality_graph_density_ppm,
            self.guarded_disequality_clauses,
            self.guarded_disequality_edges,
            self.guarded_disequality_vertices,
            self.guarded_disequality_density_ppm,
            self.guarded_disequality_clique_lower_bound,
            self.all_different_clique_lower_bound,
            self.estimated_one_hot_variables,
            self.estimated_one_hot_clauses,
        )
    }
}

pub(crate) fn analyze(arena: &TermArena, bool_problem: &BoolProblem) -> FiniteAnalysis {
    let mut disequality_edges = HashSet::default();
    for assertion in &bool_problem.assertions {
        collect_mandatory_disequalities(assertion, &mut disequality_edges);
    }

    let domain = largest_small_disequality_clique(&disequality_edges, arena);
    let domain_set = domain.iter().copied().collect::<HashSet<_>>();

    let mut covered_terms = HashSet::default();
    for assertion in &bool_problem.assertions {
        collect_mandatory_coverages(assertion, &domain_set, &mut covered_terms);
    }

    let closed_functions = closed_table_functions(arena, &domain, &domain_set, &covered_terms);
    let finite_terms = close_finite_terms(arena, &domain_set, &covered_terms, &closed_functions);

    let mut unary_table_applications = 0;
    let mut binary_table_applications = 0;
    let mut higher_arity_table_applications = 0;
    for &term_id in &arena.apps {
        let term = &arena.terms[term_id];
        if !finite_terms.contains(&term_id) || !closed_functions.contains(&term.fun) {
            continue;
        }
        match term.args.len() {
            1 => unary_table_applications += 1,
            2 => binary_table_applications += 1,
            3.. => higher_arity_table_applications += 1,
            0 => {}
        }
    }

    let mut equality_edges = HashSet::default();
    let mut equality_vertices = HashSet::default();
    for assertion in &bool_problem.assertions {
        collect_equality_graph(assertion, &mut equality_vertices, &mut equality_edges);
    }
    let equality_graph_vertices = equality_vertices.len();

    // A shared vertex universe keeps the equality and disequality densities comparable.
    let equality_graph_density_ppm =
        graph_density_ppm(equality_edges.len(), equality_graph_vertices);
    let disequality_graph_density_ppm =
        graph_density_ppm(disequality_edges.len(), equality_graph_vertices);
    let mut guarded_disequality_clauses = 0;
    let mut guarded_disequality_edges = HashSet::default();
    for assertion in &bool_problem.assertions {
        collect_guarded_disequalities(
            assertion,
            &domain_set,
            &disequality_edges,
            &mut guarded_disequality_clauses,
            &mut guarded_disequality_edges,
        );
    }
    let guarded_disequality_vertices = edge_vertices(&guarded_disequality_edges);
    let guarded_disequality_density_ppm = graph_density_ppm(
        guarded_disequality_edges.len(),
        guarded_disequality_vertices,
    );
    let guarded_disequality_clique_lower_bound =
        greedy_clique_lower_bound(&guarded_disequality_edges);
    let (estimated_one_hot_variables, estimated_one_hot_clauses) = estimate_one_hot_pressure(
        domain.len(),
        finite_terms.len().saturating_sub(domain.len()),
    );

    FiniteAnalysis {
        discovered_domain_size: domain.len(),
        covered_finite_terms: covered_terms.len(),
        recognized_finite_terms: finite_terms.len(),
        distinct_constants: arena
            .terms
            .iter()
            .enumerate()
            .filter(|(term_id, term)| {
                term.args.is_empty()
                    && *term_id != bool_problem.true_term
                    && *term_id != bool_problem.false_term
            })
            .count(),
        closed_table_functions: closed_functions.len(),
        unary_table_applications,
        binary_table_applications,
        higher_arity_table_applications,
        equality_graph_vertices,
        equality_graph_edges: equality_edges.len(),
        equality_graph_density_ppm,
        disequality_graph_edges: disequality_edges.len(),
        disequality_graph_density_ppm,
        guarded_disequality_clauses,
        guarded_disequality_edges: guarded_disequality_edges.len(),
        guarded_disequality_vertices,
        guarded_disequality_density_ppm,
        guarded_disequality_clique_lower_bound,
        all_different_clique_lower_bound: domain.len(),
        estimated_one_hot_variables,
        estimated_one_hot_clauses,
    }
}

pub(crate) fn profile_if_enabled(arena: &TermArena, bool_problem: &BoolProblem) {
    if env::var_os("EUF_VIPER_PROFILE").is_none() {
        return;
    }
    eprintln!("profile_finite_analysis {}", analyze(arena, bool_problem));
}

/// Adds the dual support side of a permutation-matrix encoding.
///
/// If `n` pairwise-disequal terms are each ranged over the same `n` values,
/// injectivity implies that every value occurs.  The existing finite encoding
/// already contains the row constraints and the pairwise disequalities; these
/// clauses state the implied column support without changing the model set.
pub(crate) fn add_permutation_support(
    cnf: &mut CnfProblem,
    bool_problem: &BoolProblem,
    domain: &[TermId],
    domain_set: &HashSet<TermId>,
    finite_terms: &HashSet<TermId>,
    mandatory_disequalities: &HashSet<(TermId, TermId)>,
    membership: &HashMap<(TermId, TermId), i32>,
) -> PermutationSupportStats {
    if domain.len() < 2 {
        return PermutationSupportStats::default();
    }

    let mut guarded_edges = HashSet::default();
    let mut guarded_clause_count = 0;
    for assertion in &bool_problem.assertions {
        collect_guarded_disequalities(
            assertion,
            domain_set,
            mandatory_disequalities,
            &mut guarded_clause_count,
            &mut guarded_edges,
        );
    }

    let mut candidate_edges = mandatory_disequalities.clone();
    candidate_edges.extend(guarded_edges.iter().copied());
    candidate_edges.retain(|(left, right)| {
        finite_terms.contains(left)
            && finite_terms.contains(right)
            && !domain_set.contains(left)
            && !domain_set.contains(right)
            && membership.contains_key(&(*left, domain[0]))
            && membership.contains_key(&(*right, domain[0]))
    });

    let clique_limit = env::var("EUF_VIPER_FINITE_PERMUTATION_CLIQUE_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_PERMUTATION_CLIQUE_LIMIT)
        .min(MAX_PERMUTATION_CLIQUE_LIMIT);
    let (cliques, truncated) = cliques_of_size(&candidate_edges, domain.len(), clique_limit);
    let start_clause_count = cnf.clauses.len();
    for clique in &cliques {
        for &value in domain {
            cnf.clauses.push(
                clique
                    .iter()
                    .map(|term| membership[&(*term, value)])
                    .collect(),
            );
        }
    }

    PermutationSupportStats {
        direct_edges: mandatory_disequalities.len(),
        guarded_edges: guarded_edges.len(),
        candidate_edges: candidate_edges.len(),
        cliques: cliques.len(),
        clauses: cnf.clauses.len() - start_clause_count,
        truncated,
    }
}

fn cliques_of_size(
    edges: &HashSet<(TermId, TermId)>,
    target_size: usize,
    limit: usize,
) -> (Vec<Vec<TermId>>, bool) {
    if target_size < 2 || limit == 0 {
        return (Vec::new(), !edges.is_empty() && limit == 0);
    }

    let mut adjacency = HashMap::<TermId, HashSet<TermId>>::default();
    for &(left, right) in edges {
        adjacency.entry(left).or_default().insert(right);
        adjacency.entry(right).or_default().insert(left);
    }
    let mut candidates = adjacency.keys().copied().collect::<Vec<_>>();
    candidates.sort_unstable();

    fn search(
        adjacency: &HashMap<TermId, HashSet<TermId>>,
        target_size: usize,
        limit: usize,
        current: &mut Vec<TermId>,
        candidates: &[TermId],
        output: &mut Vec<Vec<TermId>>,
        truncated: &mut bool,
    ) {
        if current.len() == target_size {
            if output.len() == limit {
                *truncated = true;
            } else {
                output.push(current.clone());
            }
            return;
        }
        let needed = target_size - current.len();
        if candidates.len() < needed || *truncated {
            return;
        }

        for index in 0..=(candidates.len() - needed) {
            let vertex = candidates[index];
            let Some(neighbors) = adjacency.get(&vertex) else {
                continue;
            };
            let next = candidates[(index + 1)..]
                .iter()
                .copied()
                .filter(|candidate| neighbors.contains(candidate))
                .collect::<Vec<_>>();
            current.push(vertex);
            search(
                adjacency,
                target_size,
                limit,
                current,
                &next,
                output,
                truncated,
            );
            current.pop();
            if *truncated {
                return;
            }
        }
    }

    let mut output = Vec::new();
    let mut truncated = false;
    search(
        &adjacency,
        target_size,
        limit,
        &mut Vec::with_capacity(target_size),
        &candidates,
        &mut output,
        &mut truncated,
    );
    (output, truncated)
}

fn closed_table_functions(
    arena: &TermArena,
    domain: &[TermId],
    domain_set: &HashSet<TermId>,
    covered_terms: &HashSet<TermId>,
) -> HashSet<SymId> {
    let mut function_arities: HashMap<SymId, usize> = HashMap::default();
    for &term_id in covered_terms {
        let term = &arena.terms[term_id];
        if !term.args.is_empty() && term.args.iter().all(|arg| domain_set.contains(arg)) {
            function_arities.insert(term.fun, term.args.len());
        }
    }

    let mut closed_functions = HashSet::default();
    for (function, arity) in function_arities {
        let Some(expected) = domain.len().checked_pow(arity as u32) else {
            continue;
        };
        let covered = covered_terms
            .iter()
            .filter(|&&term_id| {
                let term = &arena.terms[term_id];
                term.fun == function
                    && term.args.len() == arity
                    && term.args.iter().all(|arg| domain_set.contains(arg))
            })
            .count();
        if covered == expected {
            closed_functions.insert(function);
        }
    }
    closed_functions
}

fn close_finite_terms(
    arena: &TermArena,
    domain: &HashSet<TermId>,
    covered_terms: &HashSet<TermId>,
    closed_functions: &HashSet<SymId>,
) -> HashSet<TermId> {
    let mut finite_terms = domain.clone();
    finite_terms.extend(covered_terms.iter().copied());
    loop {
        let mut changed = false;
        for &term_id in &arena.apps {
            let term = &arena.terms[term_id];
            if closed_functions.contains(&term.fun)
                && term.args.iter().all(|arg| finite_terms.contains(arg))
            {
                changed |= finite_terms.insert(term_id);
            }
        }
        if !changed {
            return finite_terms;
        }
    }
}

fn collect_equality_graph(
    expression: &BoolExpr,
    vertices: &mut HashSet<TermId>,
    edges: &mut HashSet<(TermId, TermId)>,
) {
    match expression {
        BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
            vertices.insert(*left);
            vertices.insert(*right);
            if left != right {
                edges.insert(normalized_pair(*left, *right));
            }
        }
        BoolExpr::Not(child) => collect_equality_graph(child, vertices, edges),
        BoolExpr::And(children) | BoolExpr::Or(children) | BoolExpr::Iff(children) => {
            for child in children {
                collect_equality_graph(child, vertices, edges);
            }
        }
        BoolExpr::Ite(condition, then_expression, else_expression) => {
            collect_equality_graph(condition, vertices, edges);
            collect_equality_graph(then_expression, vertices, edges);
            collect_equality_graph(else_expression, vertices, edges);
        }
        BoolExpr::Const(_) | BoolExpr::Atom(BoolAtomKey::BoolTerm(_)) => {}
    }
}

fn collect_guarded_disequalities(
    expression: &BoolExpr,
    domain: &HashSet<TermId>,
    verified_disequalities: &HashSet<(TermId, TermId)>,
    clause_count: &mut usize,
    implied_edges: &mut HashSet<(TermId, TermId)>,
) {
    if let BoolExpr::And(children) = expression {
        for child in children {
            collect_guarded_disequalities(
                child,
                domain,
                verified_disequalities,
                clause_count,
                implied_edges,
            );
        }
        return;
    }

    let Some(edge) = guarded_disequality_edge(expression, domain, verified_disequalities) else {
        return;
    };
    *clause_count += 1;
    implied_edges.insert(edge);
}

fn guarded_disequality_edge(
    expression: &BoolExpr,
    domain: &HashSet<TermId>,
    verified_disequalities: &HashSet<(TermId, TermId)>,
) -> Option<(TermId, TermId)> {
    let BoolExpr::Or(children) = expression else {
        return None;
    };
    let [first, second] = children.as_slice() else {
        return None;
    };

    guarded_disequality_edge_in_order(first, second, domain, verified_disequalities).or_else(|| {
        guarded_disequality_edge_in_order(second, first, domain, verified_disequalities)
    })
}

fn guarded_disequality_edge_in_order(
    guard: &BoolExpr,
    consequence: &BoolExpr,
    domain: &HashSet<TermId>,
    verified_disequalities: &HashSet<(TermId, TermId)>,
) -> Option<(TermId, TermId)> {
    let BoolExpr::Atom(BoolAtomKey::Eq(guard_left, guard_right)) = guard else {
        return None;
    };
    let BoolExpr::Not(consequence) = consequence else {
        return None;
    };
    let BoolExpr::Atom(BoolAtomKey::Eq(left, right)) = consequence.as_ref() else {
        return None;
    };
    let guard_edge = normalized_pair(*guard_left, *guard_right);
    if !domain.contains(guard_left)
        || !domain.contains(guard_right)
        || !verified_disequalities.contains(&guard_edge)
        || left == right
    {
        return None;
    }
    Some(normalized_pair(*left, *right))
}

fn edge_vertices(edges: &HashSet<(TermId, TermId)>) -> usize {
    edges
        .iter()
        .flat_map(|&(left, right)| [left, right])
        .collect::<HashSet<_>>()
        .len()
}

fn greedy_clique_lower_bound(edges: &HashSet<(TermId, TermId)>) -> usize {
    let mut degrees = HashMap::<TermId, usize>::default();
    for &(left, right) in edges {
        *degrees.entry(left).or_default() += 1;
        *degrees.entry(right).or_default() += 1;
    }
    let mut vertices = degrees.keys().copied().collect::<Vec<_>>();
    vertices.sort_unstable_by_key(|vertex| (std::cmp::Reverse(degrees[vertex]), *vertex));

    let mut best = 0;
    for &seed in vertices.iter().take(GUARDED_CLIQUE_SEED_LIMIT) {
        let mut clique = vec![seed];
        for &candidate in &vertices {
            if candidate != seed
                && clique
                    .iter()
                    .all(|member| edges.contains(&normalized_pair(*member, candidate)))
            {
                clique.push(candidate);
            }
        }
        best = best.max(clique.len());
    }
    best
}

fn graph_density_ppm(edges: usize, vertices: usize) -> u32 {
    let vertices = vertices as u128;
    let possible_edges = vertices.saturating_mul(vertices.saturating_sub(1)) / 2;
    if possible_edges == 0 {
        return 0;
    }
    ((edges as u128)
        .saturating_mul(DENSITY_SCALE)
        .checked_div(possible_edges)
        .unwrap_or(0)
        .min(DENSITY_SCALE)) as u32
}

fn estimate_one_hot_pressure(domain_size: usize, non_domain_finite_terms: usize) -> (usize, usize) {
    let domain_size = domain_size as u128;
    let non_domain_finite_terms = non_domain_finite_terms as u128;
    // Domain-to-domain membership atoms normalize to symmetric equality variables.
    let domain_membership_variables = domain_size.saturating_mul(domain_size + 1) / 2;
    let term_membership_variables = non_domain_finite_terms.saturating_mul(domain_size);
    let pairwise_at_most_one = domain_size.saturating_mul(domain_size.saturating_sub(1)) / 2;
    let domain_unit_clauses = domain_size.saturating_mul(domain_size);
    let term_one_hot_clauses = non_domain_finite_terms.saturating_mul(1 + pairwise_at_most_one);

    (
        as_saturating_usize(domain_membership_variables.saturating_add(term_membership_variables)),
        as_saturating_usize(domain_unit_clauses.saturating_add(term_one_hot_clauses)),
    )
}

fn as_saturating_usize(value: u128) -> usize {
    value.min(usize::MAX as u128) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_problem;

    fn equality(left: TermId, right: TermId) -> BoolExpr {
        BoolExpr::Atom(BoolAtomKey::Eq(left, right))
    }

    fn coverage(term: TermId, domain: &[TermId]) -> BoolExpr {
        BoolExpr::Or(domain.iter().map(|&value| equality(term, value)).collect())
    }

    #[test]
    fn recognizes_complete_tables_and_finite_closure_by_arity() {
        let mut arena = TermArena::default();
        let domain = (0..3)
            .map(|symbol| arena.intern(symbol, vec![]))
            .collect::<Vec<_>>();
        let true_term = arena.intern(100, vec![]);
        let false_term = arena.intern(101, vec![]);
        let mut assertions = vec![BoolExpr::And(vec![
            BoolExpr::Not(Box::new(equality(domain[0], domain[1]))),
            BoolExpr::Not(Box::new(equality(domain[0], domain[2]))),
            BoolExpr::Not(Box::new(equality(domain[1], domain[2]))),
        ])];

        let unary = domain
            .iter()
            .map(|&first| arena.intern(10, vec![first]))
            .collect::<Vec<_>>();
        assertions.extend(unary.iter().map(|&term| coverage(term, &domain)));
        for &first in &domain {
            for &second in &domain {
                let term = arena.intern(11, vec![first, second]);
                assertions.push(coverage(term, &domain));
            }
        }
        for &first in &domain {
            for &second in &domain {
                for &third in &domain {
                    let term = arena.intern(12, vec![first, second, third]);
                    assertions.push(coverage(term, &domain));
                }
            }
        }
        arena.intern(10, vec![unary[0]]);

        let metrics = analyze(
            &arena,
            &BoolProblem {
                assertions,
                unsupported: Vec::new(),
                true_term,
                false_term,
            },
        );

        assert_eq!(metrics.discovered_domain_size, 3);
        assert_eq!(metrics.covered_finite_terms, 39);
        assert_eq!(metrics.recognized_finite_terms, 43);
        assert_eq!(metrics.distinct_constants, 3);
        assert_eq!(metrics.closed_table_functions, 3);
        assert_eq!(metrics.unary_table_applications, 4);
        assert_eq!(metrics.binary_table_applications, 9);
        assert_eq!(metrics.higher_arity_table_applications, 27);
        assert_eq!(metrics.equality_graph_vertices, 42);
        assert_eq!(metrics.equality_graph_edges, 120);
        assert_eq!(metrics.equality_graph_density_ppm, 139_372);
        assert_eq!(metrics.disequality_graph_edges, 3);
        assert_eq!(metrics.disequality_graph_density_ppm, 3_484);
        assert_eq!(metrics.guarded_disequality_clauses, 0);
        assert_eq!(metrics.guarded_disequality_edges, 0);
        assert_eq!(metrics.guarded_disequality_clique_lower_bound, 0);
        assert_eq!(metrics.all_different_clique_lower_bound, 3);
        assert_eq!(metrics.estimated_one_hot_variables, 126);
        assert_eq!(metrics.estimated_one_hot_clauses, 169);
    }

    #[test]
    fn reports_dense_all_different_coverage_without_mutating_the_problem() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun d () U)
            (declare-fun x () U)
            (assert (distinct a b c d))
            (assert (or (= x a) (= x b) (= x c) (= x d)))
            (assert (= x a))
            (check-sat)
        ";
        let problem = parse_problem(input).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        let assertions_before = bool_problem.assertions.clone();

        let metrics = analyze(&problem.arena, bool_problem);

        assert_eq!(bool_problem.assertions, assertions_before);
        assert_eq!(metrics.discovered_domain_size, 4);
        assert_eq!(metrics.covered_finite_terms, 1);
        assert_eq!(metrics.recognized_finite_terms, 5);
        assert_eq!(metrics.distinct_constants, 5);
        assert_eq!(metrics.closed_table_functions, 0);
        assert_eq!(metrics.equality_graph_vertices, 5);
        assert_eq!(metrics.equality_graph_edges, 10);
        assert_eq!(metrics.equality_graph_density_ppm, 1_000_000);
        assert_eq!(metrics.disequality_graph_edges, 6);
        assert_eq!(metrics.disequality_graph_density_ppm, 600_000);
        assert_eq!(metrics.guarded_disequality_clauses, 0);
        assert_eq!(metrics.all_different_clique_lower_bound, 4);
        assert_eq!(metrics.estimated_one_hot_variables, 14);
        assert_eq!(metrics.estimated_one_hot_clauses, 23);

        let rendered = metrics.to_string();
        assert!(rendered.contains("domain_size=4"));
        assert!(rendered.contains("all_different_clique_lb=4"));
        assert!(rendered.contains("one_hot_variables_est=14"));
    }

    #[test]
    fn recognizes_only_verified_domain_guarded_disequalities() {
        let input = "
            (set-logic QF_UF)
            (declare-sort U 0)
            (declare-fun a () U)
            (declare-fun b () U)
            (declare-fun c () U)
            (declare-fun w () U)
            (declare-fun x () U)
            (declare-fun y () U)
            (declare-fun z () U)
            (assert (distinct a b c))
            (assert (or (= a b) (not (= x y))))
            (assert (or (not (= x z)) (= a c)))
            (assert (or (= b c) (not (= y z))))
            (assert (or (= a b) (not (= x y))))
            (assert (or (= a a) (not (= x w))))
            (assert (or (= a x) (not (= z w))))
            (check-sat)
        ";
        let problem = parse_problem(input).unwrap();
        let metrics = analyze(&problem.arena, problem.bool_problem.as_ref().unwrap());

        assert_eq!(metrics.discovered_domain_size, 3);
        assert_eq!(metrics.guarded_disequality_clauses, 4);
        assert_eq!(metrics.guarded_disequality_edges, 3);
        assert_eq!(metrics.guarded_disequality_vertices, 3);
        assert_eq!(metrics.guarded_disequality_density_ppm, 1_000_000);
        assert_eq!(metrics.guarded_disequality_clique_lower_bound, 3);

        let rendered = metrics.to_string();
        assert!(rendered.contains("guarded_disequality_edges=3"));
        assert!(rendered.contains("guarded_disequality_clique_lb=3"));
    }

    #[test]
    fn enumerates_verified_cliques_deterministically_and_honors_the_cap() {
        let triangle = [(3, 4), (3, 5), (4, 5)].into_iter().collect::<HashSet<_>>();
        assert_eq!(
            cliques_of_size(&triangle, 3, 10),
            (vec![vec![3, 4, 5]], false)
        );

        let complete_four = [(3, 4), (3, 5), (3, 6), (4, 5), (4, 6), (5, 6)]
            .into_iter()
            .collect::<HashSet<_>>();
        let (cliques, truncated) = cliques_of_size(&complete_four, 3, 2);
        assert_eq!(cliques, vec![vec![3, 4, 5], vec![3, 4, 6]]);
        assert!(truncated);
    }

    #[test]
    fn adds_dual_value_support_for_a_verified_finite_injection() {
        let domain = vec![0, 1, 2];
        let domain_set = domain.iter().copied().collect::<HashSet<_>>();
        let outputs = [3, 4, 5];
        let finite_terms = domain
            .iter()
            .copied()
            .chain(outputs)
            .collect::<HashSet<_>>();
        let mandatory_disequalities = [(0, 1), (0, 2), (1, 2)].into_iter().collect::<HashSet<_>>();
        let guarded = |guard_left, guard_right, left, right| {
            BoolExpr::Or(vec![
                equality(guard_left, guard_right),
                BoolExpr::Not(Box::new(equality(left, right))),
            ])
        };
        let bool_problem = BoolProblem {
            assertions: vec![BoolExpr::And(vec![
                guarded(0, 1, 3, 4),
                guarded(0, 2, 3, 5),
                guarded(1, 2, 4, 5),
            ])],
            unsupported: Vec::new(),
            true_term: 6,
            false_term: 7,
        };

        let mut cnf = CnfProblem::new();
        let mut membership = HashMap::default();
        for term in outputs {
            for &value in &domain {
                membership.insert((term, value), cnf.atom_lit(BoolAtomKey::Eq(term, value)));
            }
        }
        let stats = add_permutation_support(
            &mut cnf,
            &bool_problem,
            &domain,
            &domain_set,
            &finite_terms,
            &mandatory_disequalities,
            &membership,
        );

        assert_eq!(
            stats,
            PermutationSupportStats {
                direct_edges: 3,
                guarded_edges: 3,
                candidate_edges: 3,
                cliques: 1,
                clauses: 3,
                truncated: false,
            }
        );
        assert_eq!(
            cnf.clauses,
            vec![vec![1, 4, 7], vec![2, 5, 8], vec![3, 6, 9]]
        );
    }
}
