use super::{
    BoolAtomKey, BoolExpr, Problem, SymId, TermId, finite_analysis::FiniteAnalysisContext,
};
use crate::orbit_canon::{BinaryTable, LexicographicPermutations};
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProbeError {
    MissingBooleanProblem,
    MissingFiniteDomain,
    DomainTooLarge(usize),
    NoCompleteExclusions,
    PermutationEnumeration,
    TableAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExtractedTable {
    pub(crate) function: SymId,
    pub(crate) table: BinaryTable,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ExtractionTelemetry {
    pub(crate) negated_conjunctions: usize,
    pub(crate) table_shaped_conjunctions: usize,
    pub(crate) malformed_table_candidates: usize,
    pub(crate) complete_exclusions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OrbitReport {
    pub(crate) degree: usize,
    pub(crate) function: SymId,
    pub(crate) exclusion_records: usize,
    pub(crate) unique_exclusions: usize,
    pub(crate) duplicate_exclusions: usize,
    pub(crate) permutations_enumerated: usize,
    pub(crate) first_table_orbit_size: usize,
    pub(crate) exclusions_in_first_orbit: usize,
    pub(crate) missing_orbit_members: usize,
    pub(crate) out_of_orbit_exclusions: usize,
    pub(crate) exact_first_orbit_cover: bool,
    pub(crate) extraction: ExtractionTelemetry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateShape {
    NotCandidate,
    Malformed,
}

pub(crate) fn analyze_forbidden_table_orbit(problem: &Problem) -> Result<OrbitReport, ProbeError> {
    let bool_problem = problem
        .bool_problem
        .as_ref()
        .ok_or(ProbeError::MissingBooleanProblem)?;
    let mut finite = FiniteAnalysisContext::default();
    let domain = finite
        .domain_analysis(&problem.arena, bool_problem)
        .domain
        .clone();
    if domain.len() < 2 {
        return Err(ProbeError::MissingFiniteDomain);
    }
    if domain.len() > crate::orbit_canon::MAX_EXHAUSTIVE_DEGREE {
        return Err(ProbeError::DomainTooLarge(domain.len()));
    }

    let domain_positions = domain
        .iter()
        .enumerate()
        .map(|(position, &term)| (term, position))
        .collect::<HashMap<_, _>>();
    let mut telemetry = ExtractionTelemetry::default();
    let mut extracted = Vec::new();
    for assertion in &bool_problem.assertions {
        let BoolExpr::Not(inner) = assertion else {
            continue;
        };
        telemetry.negated_conjunctions += 1;
        let mut equalities = Vec::new();
        if !collect_conjunctive_equalities(inner, &mut equalities) {
            continue;
        }
        match extract_complete_table(&problem.arena, &domain_positions, domain.len(), &equalities) {
            Ok(table) => {
                telemetry.table_shaped_conjunctions += 1;
                telemetry.complete_exclusions += 1;
                extracted.push(table);
            }
            Err(CandidateShape::Malformed) => {
                telemetry.table_shaped_conjunctions += 1;
                telemetry.malformed_table_candidates += 1;
            }
            Err(CandidateShape::NotCandidate) => {}
        }
    }
    if extracted.is_empty() {
        return Err(ProbeError::NoCompleteExclusions);
    }

    let mut by_function: HashMap<SymId, Vec<BinaryTable>> = HashMap::default();
    for exclusion in extracted {
        by_function
            .entry(exclusion.function)
            .or_default()
            .push(exclusion.table);
    }
    let (&function, tables) = by_function
        .iter()
        .max_by_key(|(function, tables)| (tables.len(), std::cmp::Reverse(**function)))
        .expect("nonempty extraction has a function group");

    report_for_tables(domain.len(), function, tables, telemetry)
}

fn collect_conjunctive_equalities<'a>(
    expression: &'a BoolExpr,
    output: &mut Vec<(TermId, TermId)>,
) -> bool {
    match expression {
        BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
            output.push((*left, *right));
            true
        }
        BoolExpr::And(children) => children
            .iter()
            .all(|child| collect_conjunctive_equalities(child, output)),
        _ => false,
    }
}

fn extract_complete_table(
    arena: &super::TermArena,
    domain_positions: &HashMap<TermId, usize>,
    degree: usize,
    equalities: &[(TermId, TermId)],
) -> Result<ExtractedTable, CandidateShape> {
    let table_size = degree
        .checked_mul(degree)
        .ok_or(CandidateShape::Malformed)?;
    let mut entries = vec![None; table_size];
    let mut function = None;
    let mut saw_table_equality = false;

    for &(left, right) in equalities {
        let oriented = table_cell(arena, domain_positions, left, right)
            .or_else(|| table_cell(arena, domain_positions, right, left));
        let Some((candidate_function, row, column, value)) = oriented else {
            if term_mentions_domain_table(arena, domain_positions, left)
                || term_mentions_domain_table(arena, domain_positions, right)
            {
                return Err(CandidateShape::Malformed);
            }
            return Err(if saw_table_equality {
                CandidateShape::Malformed
            } else {
                CandidateShape::NotCandidate
            });
        };
        saw_table_equality = true;
        if function.is_some_and(|prior| prior != candidate_function) {
            return Err(CandidateShape::Malformed);
        }
        function = Some(candidate_function);
        let slot = row * degree + column;
        if entries[slot].replace(value).is_some() {
            return Err(CandidateShape::Malformed);
        }
    }

    if !saw_table_equality {
        return Err(CandidateShape::NotCandidate);
    }
    if equalities.len() != table_size || entries.iter().any(Option::is_none) {
        return Err(CandidateShape::Malformed);
    }
    let table = BinaryTable::new(degree, entries.into_iter().flatten().collect())
        .map_err(|_| CandidateShape::Malformed)?;
    Ok(ExtractedTable {
        function: function.expect("a table equality records a function"),
        table,
    })
}

fn table_cell(
    arena: &super::TermArena,
    domain_positions: &HashMap<TermId, usize>,
    application: TermId,
    value: TermId,
) -> Option<(SymId, usize, usize, usize)> {
    let value = *domain_positions.get(&value)?;
    let term = arena.terms.get(application)?;
    let [left, right] = term.args.as_slice() else {
        return None;
    };
    Some((
        term.fun,
        *domain_positions.get(left)?,
        *domain_positions.get(right)?,
        value,
    ))
}

fn term_mentions_domain_table(
    arena: &super::TermArena,
    domain_positions: &HashMap<TermId, usize>,
    term: TermId,
) -> bool {
    arena.terms.get(term).is_some_and(|term| {
        term.args.len() == 2
            && term
                .args
                .iter()
                .all(|argument| domain_positions.contains_key(argument))
    })
}

fn report_for_tables(
    degree: usize,
    function: SymId,
    tables: &[BinaryTable],
    extraction: ExtractionTelemetry,
) -> Result<OrbitReport, ProbeError> {
    let first = tables.first().ok_or(ProbeError::NoCompleteExclusions)?;
    let unique_exclusions = tables.iter().cloned().collect::<HashSet<_>>();
    let mut first_orbit = HashSet::default();
    let permutations =
        LexicographicPermutations::new(degree).map_err(|_| ProbeError::PermutationEnumeration)?;
    let mut permutations_enumerated = 0;
    for permutation in permutations {
        permutations_enumerated += 1;
        first_orbit.insert(
            first
                .conjugated_by(&permutation)
                .map_err(|_| ProbeError::TableAction)?,
        );
    }
    let exclusions_in_first_orbit = unique_exclusions.intersection(&first_orbit).count();
    let missing_orbit_members = first_orbit.difference(&unique_exclusions).count();
    let out_of_orbit_exclusions = unique_exclusions.difference(&first_orbit).count();
    let unique_count = unique_exclusions.len();
    let orbit_size = first_orbit.len();
    Ok(OrbitReport {
        degree,
        function,
        exclusion_records: tables.len(),
        unique_exclusions: unique_count,
        duplicate_exclusions: tables.len() - unique_count,
        permutations_enumerated,
        first_table_orbit_size: orbit_size,
        exclusions_in_first_orbit,
        missing_orbit_members,
        out_of_orbit_exclusions,
        exact_first_orbit_cover: unique_exclusions == first_orbit,
        extraction,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forbidden_table_mdd::{
        ConstructionCap as BooleanConstructionCap, Telemetry as BooleanTelemetry,
        compile_forbidden_table_mdd,
    };
    use crate::forbidden_table_mvdd::{
        ConstructionCap as MultiValuedConstructionCap, Telemetry as MultiValuedTelemetry,
        compile_forbidden_table_mvdd,
    };
    use crate::{ScopedLetMode, parse_problem_with_scoped_let_mode};
    use std::{env, fs};

    fn parse(source: &str) -> Problem {
        parse_problem_with_scoped_let_mode(source, ScopedLetMode::Off).unwrap()
    }

    fn degree_three_source(last_cell: bool) -> String {
        let mut equalities = vec![
            "(= (op e0 e0) e0)",
            "(= (op e0 e1) e1)",
            "(= (op e0 e2) e2)",
            "(= (op e1 e0) e1)",
            "(= (op e1 e1) e2)",
            "(= (op e1 e2) e0)",
            "(= (op e2 e0) e2)",
            "(= (op e2 e1) e0)",
        ];
        if last_cell {
            equalities.push("(= (op e2 e2) e1)");
        }
        format!(
            "(set-logic QF_UF)\n\
             (declare-sort I 0)\n\
             (declare-fun e0 () I)\n\
             (declare-fun e1 () I)\n\
             (declare-fun e2 () I)\n\
             (declare-fun op (I I) I)\n\
             (assert (distinct e0 e1 e2))\n\
             (assert (not (and {})))\n\
             (check-sat)\n",
            equalities.join(" ")
        )
    }

    fn dominant_table_exclusions(problem: &Problem) -> (usize, SymId, Vec<BinaryTable>) {
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        let mut finite = FiniteAnalysisContext::default();
        let domain = finite
            .domain_analysis(&problem.arena, bool_problem)
            .domain
            .clone();
        let domain_positions = domain
            .iter()
            .enumerate()
            .map(|(position, &term)| (term, position))
            .collect::<HashMap<_, _>>();
        let mut by_function: HashMap<SymId, Vec<BinaryTable>> = HashMap::default();
        for assertion in &bool_problem.assertions {
            let BoolExpr::Not(inner) = assertion else {
                continue;
            };
            let mut equalities = Vec::new();
            if !collect_conjunctive_equalities(inner, &mut equalities) {
                continue;
            }
            if let Ok(extracted) =
                extract_complete_table(&problem.arena, &domain_positions, domain.len(), &equalities)
            {
                by_function
                    .entry(extracted.function)
                    .or_default()
                    .push(extracted.table);
            }
        }
        let (function, tables) = by_function
            .into_iter()
            .max_by_key(|(function, tables)| (tables.len(), std::cmp::Reverse(*function)))
            .unwrap();
        (domain.len(), function, tables)
    }

    fn one_hot_assignments(degree: usize, tables: &[BinaryTable]) -> Vec<Vec<i32>> {
        tables
            .iter()
            .map(|table| {
                table
                    .entries()
                    .iter()
                    .enumerate()
                    .flat_map(|(cell, &selected)| {
                        (0..degree).map(move |value| {
                            let atom = i32::try_from(cell * degree + value + 1).unwrap();
                            if value == selected { atom } else { -atom }
                        })
                    })
                    .collect()
            })
            .collect()
    }

    fn print_mdd_telemetry(label: &str, telemetry: &BooleanTelemetry) {
        println!(
            concat!(
                "{{\"label\":\"{}\",\"variables\":{},",
                "\"forbidden_assignments\":{},\"raw_forbidden_clauses\":{},",
                "\"raw_forbidden_literals\":{},\"trie_nodes\":{},",
                "\"mdd_nodes\":{},\"mdd_edges\":{},\"hash_cons_hits\":{},",
                "\"cnf_clauses\":{},\"cnf_literals\":{}}}"
            ),
            label,
            telemetry.variables,
            telemetry.forbidden_assignments,
            telemetry.raw_forbidden_clauses,
            telemetry.raw_forbidden_literals,
            telemetry.trie_nodes,
            telemetry.mdd_nodes,
            telemetry.mdd_edges,
            telemetry.hash_cons_hits,
            telemetry.cnf_clauses,
            telemetry.cnf_literals,
        );
    }

    fn multi_valued_rows(tables: &[BinaryTable]) -> Vec<Vec<u8>> {
        tables
            .iter()
            .map(|table| {
                table
                    .entries()
                    .iter()
                    .map(|&value| u8::try_from(value).unwrap())
                    .collect()
            })
            .collect()
    }

    fn one_hot_atom_mapping(degree: usize) -> Vec<Vec<u32>> {
        (0..degree * degree)
            .map(|cell| {
                (0..degree)
                    .map(|value| u32::try_from(cell * degree + value + 1).unwrap())
                    .collect()
            })
            .collect()
    }

    fn print_mvdd_telemetry(label: &str, telemetry: &MultiValuedTelemetry) {
        println!(
            concat!(
                "{{\"label\":\"{}\",\"cells\":{},\"degree\":{},",
                "\"forbidden_rows\":{},\"raw_forbidden_clauses\":{},",
                "\"raw_forbidden_literals\":{},\"trie_nodes\":{},",
                "\"mvdd_nodes\":{},\"mvdd_edges\":{},",
                "\"eliminated_tests\":{},\"hash_cons_hits\":{},",
                "\"cnf_clauses\":{},\"cnf_literals\":{}}}"
            ),
            label,
            telemetry.cells,
            telemetry.degree,
            telemetry.forbidden_rows,
            telemetry.raw_forbidden_clauses,
            telemetry.raw_forbidden_literals,
            telemetry.trie_nodes,
            telemetry.mvdd_nodes,
            telemetry.mvdd_edges,
            telemetry.eliminated_tests,
            telemetry.hash_cons_hits,
            telemetry.cnf_clauses,
            telemetry.cnf_literals,
        );
    }

    #[test]
    fn extracts_a_typed_complete_binary_table() {
        let problem = parse(&degree_three_source(true));
        let report = analyze_forbidden_table_orbit(&problem).unwrap();
        assert_eq!(report.degree, 3);
        assert_eq!(report.exclusion_records, 1);
        assert_eq!(report.unique_exclusions, 1);
        assert_eq!(report.extraction.complete_exclusions, 1);
        assert_eq!(report.extraction.malformed_table_candidates, 0);
        assert_eq!(report.permutations_enumerated, 6);
    }

    #[test]
    fn incomplete_table_is_fail_closed() {
        let problem = parse(&degree_three_source(false));
        assert_eq!(
            analyze_forbidden_table_orbit(&problem),
            Err(ProbeError::NoCompleteExclusions)
        );
    }

    #[test]
    fn exact_orbit_cover_and_duplicates_are_counted() {
        let first = BinaryTable::new(3, vec![0, 0, 0, 0, 0, 1, 0, 2, 0]).unwrap();
        let orbit = LexicographicPermutations::new(3)
            .unwrap()
            .map(|permutation| first.conjugated_by(&permutation).unwrap())
            .collect::<HashSet<_>>();
        let mut tables = orbit.iter().cloned().collect::<Vec<_>>();
        tables.sort();
        tables.push(tables[0].clone());
        let report = report_for_tables(
            3,
            7,
            &tables,
            ExtractionTelemetry {
                complete_exclusions: tables.len(),
                ..ExtractionTelemetry::default()
            },
        )
        .unwrap();
        assert!(report.exact_first_orbit_cover);
        assert_eq!(report.duplicate_exclusions, 1);
        assert_eq!(report.missing_orbit_members, 0);
        assert_eq!(report.out_of_orbit_exclusions, 0);
    }

    #[test]
    fn partial_orbit_is_reported_without_upgrading_the_claim() {
        let first = BinaryTable::new(3, vec![0, 0, 0, 0, 0, 1, 0, 2, 0]).unwrap();
        let report = report_for_tables(
            3,
            7,
            &[first],
            ExtractionTelemetry {
                complete_exclusions: 1,
                ..ExtractionTelemetry::default()
            },
        )
        .unwrap();
        assert!(!report.exact_first_orbit_cover);
        assert!(report.missing_orbit_members > 0);
    }

    #[test]
    fn one_hot_projection_is_complete_and_order_independent() {
        let table = BinaryTable::new(3, vec![0, 1, 2, 1, 2, 0, 2, 0, 1]).unwrap();
        let assignments = one_hot_assignments(3, &[table]);
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].len(), 27);
        assert_eq!(
            assignments[0]
                .iter()
                .map(|literal| literal.unsigned_abs())
                .collect::<Vec<_>>(),
            (1..=27).collect::<Vec<_>>()
        );
        assert_eq!(
            assignments[0]
                .iter()
                .filter(|literal| **literal > 0)
                .count(),
            9
        );
        let cell_major = (1..=27).collect::<Vec<_>>();
        let value_major = (0..3)
            .flat_map(|value| (0..9).map(move |cell| cell * 3 + value + 1))
            .collect::<Vec<_>>();
        for order in [cell_major, value_major] {
            let compiled = compile_forbidden_table_mdd(
                &assignments,
                &order,
                28,
                BooleanConstructionCap::default(),
            )
            .unwrap();
            assert_eq!(compiled.telemetry.variables, 27);
            assert_eq!(compiled.telemetry.forbidden_assignments, 1);
        }
    }

    #[test]
    #[ignore = "requires EUF_VIPER_ORBIT_PROBE_CASE"]
    fn probe_external_formula() {
        let path = env::var("EUF_VIPER_ORBIT_PROBE_CASE").unwrap();
        let source = fs::read_to_string(path).unwrap();
        let problem = parse_problem_with_scoped_let_mode(&source, ScopedLetMode::Auto).unwrap();
        let report = analyze_forbidden_table_orbit(&problem).unwrap();
        println!(
            concat!(
                "{{\"degree\":{},\"function\":{},\"exclusion_records\":{},",
                "\"unique_exclusions\":{},\"duplicate_exclusions\":{},",
                "\"permutations_enumerated\":{},\"first_table_orbit_size\":{},",
                "\"exclusions_in_first_orbit\":{},\"missing_orbit_members\":{},",
                "\"out_of_orbit_exclusions\":{},\"exact_first_orbit_cover\":{},",
                "\"malformed_table_candidates\":{}}}"
            ),
            report.degree,
            report.function,
            report.exclusion_records,
            report.unique_exclusions,
            report.duplicate_exclusions,
            report.permutations_enumerated,
            report.first_table_orbit_size,
            report.exclusions_in_first_orbit,
            report.missing_orbit_members,
            report.out_of_orbit_exclusions,
            report.exact_first_orbit_cover,
            report.extraction.malformed_table_candidates,
        );
    }

    #[cfg(feature = "finite-symmetry")]
    #[test]
    #[ignore = "requires EUF_VIPER_ORBIT_PROBE_CASE"]
    fn probe_external_separated_base_symmetry() {
        let path = env::var("EUF_VIPER_ORBIT_PROBE_CASE").unwrap();
        let source = fs::read_to_string(path).unwrap();
        let problem = parse_problem_with_scoped_let_mode(&source, ScopedLetMode::Auto).unwrap();
        let (degree, function, _) = dominant_table_exclusions(&problem);
        let mut bool_problem = problem.bool_problem.clone().unwrap();
        let mut finite = FiniteAnalysisContext::default();
        let domain = finite
            .domain_analysis(&problem.arena, &bool_problem)
            .domain
            .clone();
        let domain_positions = domain
            .iter()
            .enumerate()
            .map(|(position, &term)| (term, position))
            .collect::<HashMap<_, _>>();
        let before = bool_problem.assertions.len();
        bool_problem.assertions.retain(|assertion| {
            let BoolExpr::Not(inner) = assertion else {
                return true;
            };
            let mut equalities = Vec::new();
            if !collect_conjunctive_equalities(inner, &mut equalities) {
                return true;
            }
            !matches!(
                extract_complete_table(&problem.arena, &domain_positions, degree, &equalities),
                Ok(extracted) if extracted.function == function
            )
        });
        let removed = before - bool_problem.assertions.len();
        let identity = (0..problem.arena.terms.len()).collect::<Vec<_>>();
        let mut interner = crate::CanonicalBoolInterner::default();
        let baseline = crate::canonical_assertion_ids(&bool_problem, &identity, &mut interner);
        let mut verified_transpositions = Vec::new();
        for left in 0..degree {
            for right in (left + 1)..degree {
                let verified =
                    crate::term_map_under_swap(&problem.arena, domain[left], domain[right])
                        .is_some_and(|term_map| {
                            crate::canonical_assertion_ids(&bool_problem, &term_map, &mut interner)
                                == baseline
                        });
                if verified {
                    verified_transpositions.push((left, right));
                }
            }
        }
        println!(
            "{{\"degree\":{degree},\"base_assertions\":{},\"removed_exclusions\":{removed},\"verified_transpositions\":{verified_transpositions:?}}}",
            bool_problem.assertions.len(),
        );
        assert_eq!(removed, 5_040);
    }

    #[test]
    #[ignore = "requires EUF_VIPER_MDD_PROBE_CASE"]
    fn probe_external_forbidden_table_mdd() {
        let path = env::var("EUF_VIPER_MDD_PROBE_CASE").unwrap();
        let source = fs::read_to_string(path).unwrap();
        let problem = parse_problem_with_scoped_let_mode(&source, ScopedLetMode::Auto).unwrap();
        let orbit = analyze_forbidden_table_orbit(&problem).unwrap();
        assert!(orbit.exact_first_orbit_cover);
        let (degree, function, tables) = dominant_table_exclusions(&problem);
        assert_eq!(degree, orbit.degree);
        assert_eq!(function, orbit.function);
        let assignments = one_hot_assignments(degree, &tables);
        let variables = u32::try_from(degree * degree * degree).unwrap();
        let cell_major = (1..=variables).collect::<Vec<_>>();
        let value_major = (0..degree)
            .flat_map(|value| {
                (0..degree * degree)
                    .map(move |cell| u32::try_from(cell * degree + value + 1).unwrap())
            })
            .collect::<Vec<_>>();
        let first_auxiliary = variables + 1;
        let cell = compile_forbidden_table_mdd(
            &assignments,
            &cell_major,
            first_auxiliary,
            BooleanConstructionCap::default(),
        )
        .unwrap();
        let value = compile_forbidden_table_mdd(
            &assignments,
            &value_major,
            first_auxiliary,
            BooleanConstructionCap::default(),
        )
        .unwrap();
        print_mdd_telemetry("cell_major", &cell.telemetry);
        print_mdd_telemetry("value_major", &value.telemetry);
    }

    #[test]
    #[ignore = "requires EUF_VIPER_MDD_PROBE_CASE"]
    fn probe_external_forbidden_table_mvdd() {
        let path = env::var("EUF_VIPER_MDD_PROBE_CASE").unwrap();
        let source = fs::read_to_string(path).unwrap();
        let problem = parse_problem_with_scoped_let_mode(&source, ScopedLetMode::Auto).unwrap();
        let orbit = analyze_forbidden_table_orbit(&problem).unwrap();
        assert!(orbit.exact_first_orbit_cover);
        let (degree, function, tables) = dominant_table_exclusions(&problem);
        assert_eq!(degree, orbit.degree);
        assert_eq!(function, orbit.function);

        let rows = multi_valued_rows(&tables);
        let mapping = one_hot_atom_mapping(degree);
        let cells = degree * degree;
        let first_auxiliary = u32::try_from(cells * degree + 1).unwrap();
        let row_major = (0..cells).collect::<Vec<_>>();
        let column_major = (0..degree)
            .flat_map(|column| (0..degree).map(move |row| row * degree + column))
            .collect::<Vec<_>>();

        let row = compile_forbidden_table_mvdd(
            &rows,
            cells,
            degree,
            &row_major,
            &mapping,
            first_auxiliary,
            MultiValuedConstructionCap::default(),
        )
        .unwrap();
        let column = compile_forbidden_table_mvdd(
            &rows,
            cells,
            degree,
            &column_major,
            &mapping,
            first_auxiliary,
            MultiValuedConstructionCap::default(),
        )
        .unwrap();
        print_mvdd_telemetry("row_major", &row.telemetry);
        print_mvdd_telemetry("column_major", &column.telemetry);
    }
}
