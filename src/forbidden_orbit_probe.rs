use super::{
    BoolAtomKey, BoolExpr, Problem, SymId, TermId, finite_analysis::FiniteAnalysisContext,
};
use crate::orbit_canon::{
    BinaryTable, CheckedPermutation, LexicographicPermutations, MAX_EXHAUSTIVE_DEGREE,
};
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProbeError {
    MissingBooleanProblem,
    MissingFiniteDomain,
    DomainTooLarge(usize),
    NoCompleteExclusions,
    NoExactPatterns,
    PermutationEnumeration,
    TableAction,
    Pattern(PatternError),
    OrbitStabilizerMismatch,
    NonuniformPatternWidth { expected: usize, actual: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CellAssignment {
    pub(crate) row: usize,
    pub(crate) column: usize,
    pub(crate) value: usize,
}

impl CellAssignment {
    fn relabeled_by(self, permutation: &CheckedPermutation) -> Option<Self> {
        Some(Self {
            row: permutation.image(self.row)?,
            column: permutation.image(self.column)?,
            value: permutation.image(self.value)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PartialTablePattern {
    degree: usize,
    assignments: Box<[CellAssignment]>,
}

impl PartialTablePattern {
    pub(crate) fn new(
        degree: usize,
        mut assignments: Vec<CellAssignment>,
    ) -> Result<Self, PatternError> {
        if degree == 0 {
            return Err(PatternError::EmptyDomain);
        }
        if assignments.is_empty() {
            return Err(PatternError::EmptyPattern);
        }
        for &assignment in &assignments {
            if assignment.row >= degree || assignment.column >= degree || assignment.value >= degree
            {
                return Err(PatternError::AssignmentOutOfRange { assignment, degree });
            }
        }
        assignments.sort_unstable();
        let mut normalized: Vec<CellAssignment> = Vec::with_capacity(assignments.len());
        for assignment in assignments {
            if let Some(previous) = normalized.last() {
                if previous.row == assignment.row && previous.column == assignment.column {
                    if previous.value != assignment.value {
                        return Err(PatternError::ConflictingCell {
                            row: assignment.row,
                            column: assignment.column,
                            first_value: previous.value,
                            second_value: assignment.value,
                        });
                    }
                    continue;
                }
            }
            normalized.push(assignment);
        }
        Ok(Self {
            degree,
            assignments: normalized.into_boxed_slice(),
        })
    }

    pub(crate) fn degree(&self) -> usize {
        self.degree
    }

    pub(crate) fn width(&self) -> usize {
        self.assignments.len()
    }

    pub(crate) fn assignments(&self) -> &[CellAssignment] {
        &self.assignments
    }

    pub(crate) fn conjugated_by(
        &self,
        permutation: &CheckedPermutation,
    ) -> Result<Self, PatternError> {
        if self.degree != permutation.degree() {
            return Err(PatternError::DegreeMismatch {
                pattern_degree: self.degree,
                permutation_degree: permutation.degree(),
            });
        }
        let assignments = self
            .assignments
            .iter()
            .copied()
            .map(|assignment| {
                assignment
                    .relabeled_by(permutation)
                    .expect("checked assignments are inside the permutation domain")
            })
            .collect();
        Self::new(self.degree, assignments)
    }

    pub(crate) fn canonicalize_exact(&self) -> Result<PartialCanonicalForm, ProbeError> {
        let mut permutations = LexicographicPermutations::new(self.degree)
            .map_err(|_| ProbeError::PermutationEnumeration)?;
        let identity = permutations
            .next()
            .expect("permutation enumeration contains the identity");
        let mut representative = self.clone();
        let mut witness = identity;
        for permutation in permutations {
            let image = self
                .conjugated_by(&permutation)
                .map_err(ProbeError::Pattern)?;
            let replace = match image.cmp(&representative) {
                Ordering::Less => true,
                Ordering::Equal => permutation < witness,
                Ordering::Greater => false,
            };
            if replace {
                representative = image;
                witness = permutation;
            }
        }
        Ok(PartialCanonicalForm {
            representative,
            witness,
        })
    }

    fn as_complete_table(&self) -> Result<BinaryTable, PatternError> {
        let table_size =
            self.degree
                .checked_mul(self.degree)
                .ok_or(PatternError::SizeOverflow {
                    degree: self.degree,
                })?;
        if self.width() != table_size {
            return Err(PatternError::Incomplete {
                expected: table_size,
                actual: self.width(),
            });
        }
        let mut entries = vec![0; table_size];
        for assignment in &self.assignments {
            entries[assignment.row * self.degree + assignment.column] = assignment.value;
        }
        BinaryTable::new(self.degree, entries).map_err(|_| PatternError::InvalidCompleteTable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PatternError {
    EmptyDomain,
    EmptyPattern,
    SizeOverflow {
        degree: usize,
    },
    AssignmentOutOfRange {
        assignment: CellAssignment,
        degree: usize,
    },
    ConflictingCell {
        row: usize,
        column: usize,
        first_value: usize,
        second_value: usize,
    },
    DegreeMismatch {
        pattern_degree: usize,
        permutation_degree: usize,
    },
    Incomplete {
        expected: usize,
        actual: usize,
    },
    InvalidCompleteTable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PartialCanonicalForm {
    pub(crate) representative: PartialTablePattern,
    pub(crate) witness: CheckedPermutation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExtractedPattern {
    pub(crate) function: SymId,
    pub(crate) pattern: PartialTablePattern,
    source_equalities: usize,
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
    pub(crate) exact_patterns: usize,
    pub(crate) malformed_pattern_candidates: usize,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PatternOrbitReport {
    pub(crate) degree: usize,
    pub(crate) function: SymId,
    pub(crate) pattern_width: usize,
    pub(crate) exclusion_records: usize,
    pub(crate) unique_exclusions: usize,
    pub(crate) duplicate_exclusions: usize,
    pub(crate) permutations_enumerated: usize,
    pub(crate) first_pattern_orbit_size: usize,
    pub(crate) first_pattern_stabilizer_size: usize,
    pub(crate) orbit_stabilizer_verified: bool,
    pub(crate) exclusions_in_first_orbit: usize,
    pub(crate) missing_orbit_members: usize,
    pub(crate) out_of_orbit_exclusions: usize,
    pub(crate) exact_first_orbit_cover: bool,
    pub(crate) canonical_first_pattern: PartialCanonicalForm,
    pub(crate) extraction: ExtractionTelemetry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateShape {
    NotCandidate,
    Malformed,
}

pub(crate) fn analyze_forbidden_table_orbit(problem: &Problem) -> Result<OrbitReport, ProbeError> {
    let (degree, patterns, mut telemetry) = extract_exact_patterns(problem)?;
    let mut extracted = Vec::new();
    for exclusion in patterns {
        let expected_equalities = degree.checked_mul(degree).ok_or(ProbeError::TableAction)?;
        if exclusion.source_equalities != expected_equalities {
            telemetry.malformed_table_candidates += 1;
            continue;
        }
        match exclusion.pattern.as_complete_table() {
            Ok(table) => {
                telemetry.complete_exclusions += 1;
                extracted.push(ExtractedTable {
                    function: exclusion.function,
                    table,
                });
            }
            Err(PatternError::Incomplete { .. }) => {
                telemetry.malformed_table_candidates += 1;
            }
            Err(_) => return Err(ProbeError::TableAction),
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

    report_for_tables(degree, function, tables, telemetry)
}

pub(crate) fn analyze_forbidden_pattern_orbit(
    problem: &Problem,
) -> Result<PatternOrbitReport, ProbeError> {
    let (degree, extracted, telemetry) = extract_exact_patterns(problem)?;
    if extracted.is_empty() {
        return Err(ProbeError::NoExactPatterns);
    }
    let mut by_function: HashMap<SymId, Vec<PartialTablePattern>> = HashMap::default();
    for exclusion in extracted {
        by_function
            .entry(exclusion.function)
            .or_default()
            .push(exclusion.pattern);
    }
    let (&function, patterns) = by_function
        .iter()
        .max_by_key(|(function, patterns)| (patterns.len(), std::cmp::Reverse(**function)))
        .expect("nonempty extraction has a function group");
    report_for_patterns(degree, function, patterns, telemetry)
}

fn extract_exact_patterns(
    problem: &Problem,
) -> Result<(usize, Vec<ExtractedPattern>, ExtractionTelemetry), ProbeError> {
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
    if domain.len() > MAX_EXHAUSTIVE_DEGREE {
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
        match extract_partial_pattern(&problem.arena, &domain_positions, domain.len(), &equalities)
        {
            Ok(pattern) => {
                telemetry.table_shaped_conjunctions += 1;
                telemetry.exact_patterns += 1;
                extracted.push(pattern);
            }
            Err(CandidateShape::Malformed) => {
                telemetry.table_shaped_conjunctions += 1;
                telemetry.malformed_pattern_candidates += 1;
                telemetry.malformed_table_candidates += 1;
            }
            Err(CandidateShape::NotCandidate) => {}
        }
    }
    Ok((domain.len(), extracted, telemetry))
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
    if equalities.len() != table_size {
        return Err(CandidateShape::Malformed);
    }
    let extracted = extract_partial_pattern(arena, domain_positions, degree, equalities)?;
    let table = extracted
        .pattern
        .as_complete_table()
        .map_err(|_| CandidateShape::Malformed)?;
    Ok(ExtractedTable {
        function: extracted.function,
        table,
    })
}

fn extract_partial_pattern(
    arena: &super::TermArena,
    domain_positions: &HashMap<TermId, usize>,
    degree: usize,
    equalities: &[(TermId, TermId)],
) -> Result<ExtractedPattern, CandidateShape> {
    let mut assignments = Vec::with_capacity(equalities.len());
    let mut function = None;
    let mut saw_table_equality = false;
    let mut saw_malformed_equality = false;

    for &(left, right) in equalities {
        let oriented = table_cell(arena, domain_positions, left, right)
            .or_else(|| table_cell(arena, domain_positions, right, left));
        let Some((candidate_function, row, column, value)) = oriented else {
            if term_mentions_domain_table(arena, domain_positions, left)
                || term_mentions_domain_table(arena, domain_positions, right)
            {
                saw_malformed_equality = true;
                continue;
            }
            saw_malformed_equality = true;
            continue;
        };
        saw_table_equality = true;
        if function.is_some_and(|prior| prior != candidate_function) {
            return Err(CandidateShape::Malformed);
        }
        function = Some(candidate_function);
        assignments.push(CellAssignment { row, column, value });
    }

    if !saw_table_equality {
        return Err(
            if saw_malformed_equality
                && equalities.iter().any(|&(left, right)| {
                    term_mentions_domain_table(arena, domain_positions, left)
                        || term_mentions_domain_table(arena, domain_positions, right)
                })
            {
                CandidateShape::Malformed
            } else {
                CandidateShape::NotCandidate
            },
        );
    }
    if saw_malformed_equality {
        return Err(CandidateShape::Malformed);
    }
    let pattern =
        PartialTablePattern::new(degree, assignments).map_err(|_| CandidateShape::Malformed)?;
    Ok(ExtractedPattern {
        function: function.expect("a table equality records a function"),
        pattern,
        source_equalities: equalities.len(),
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

fn report_for_patterns(
    degree: usize,
    function: SymId,
    patterns: &[PartialTablePattern],
    extraction: ExtractionTelemetry,
) -> Result<PatternOrbitReport, ProbeError> {
    let first = patterns.first().ok_or(ProbeError::NoExactPatterns)?;
    if first.degree() != degree {
        return Err(ProbeError::Pattern(PatternError::DegreeMismatch {
            pattern_degree: first.degree(),
            permutation_degree: degree,
        }));
    }
    let pattern_width = first.width();
    for pattern in patterns {
        if pattern.degree() != degree {
            return Err(ProbeError::Pattern(PatternError::DegreeMismatch {
                pattern_degree: pattern.degree(),
                permutation_degree: degree,
            }));
        }
        if pattern.width() != pattern_width {
            return Err(ProbeError::NonuniformPatternWidth {
                expected: pattern_width,
                actual: pattern.width(),
            });
        }
    }

    let unique_exclusions = patterns.iter().cloned().collect::<HashSet<_>>();
    let mut first_orbit = HashSet::default();
    let permutations =
        LexicographicPermutations::new(degree).map_err(|_| ProbeError::PermutationEnumeration)?;
    let mut permutations_enumerated = 0;
    let mut stabilizer_size = 0;
    for permutation in permutations {
        permutations_enumerated += 1;
        let image = first
            .conjugated_by(&permutation)
            .map_err(ProbeError::Pattern)?;
        if image == *first {
            stabilizer_size += 1;
        }
        first_orbit.insert(image);
    }
    let orbit_stabilizer_verified = first_orbit
        .len()
        .checked_mul(stabilizer_size)
        .is_some_and(|product| product == permutations_enumerated);
    if !orbit_stabilizer_verified {
        return Err(ProbeError::OrbitStabilizerMismatch);
    }

    let exclusions_in_first_orbit = unique_exclusions.intersection(&first_orbit).count();
    let missing_orbit_members = first_orbit.difference(&unique_exclusions).count();
    let out_of_orbit_exclusions = unique_exclusions.difference(&first_orbit).count();
    let unique_count = unique_exclusions.len();
    let orbit_size = first_orbit.len();
    Ok(PatternOrbitReport {
        degree,
        function,
        pattern_width,
        exclusion_records: patterns.len(),
        unique_exclusions: unique_count,
        duplicate_exclusions: patterns.len() - unique_count,
        permutations_enumerated,
        first_pattern_orbit_size: orbit_size,
        first_pattern_stabilizer_size: stabilizer_size,
        orbit_stabilizer_verified,
        exclusions_in_first_orbit,
        missing_orbit_members,
        out_of_orbit_exclusions,
        exact_first_orbit_cover: unique_exclusions == first_orbit,
        canonical_first_pattern: first.canonicalize_exact()?,
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

    fn pattern(degree: usize, assignments: &[(usize, usize, usize)]) -> PartialTablePattern {
        PartialTablePattern::new(
            degree,
            assignments
                .iter()
                .map(|&(row, column, value)| CellAssignment { row, column, value })
                .collect(),
        )
        .unwrap()
    }

    fn pattern_orbit(pattern: &PartialTablePattern) -> Vec<PartialTablePattern> {
        let mut orbit = LexicographicPermutations::new(pattern.degree())
            .unwrap()
            .map(|permutation| pattern.conjugated_by(&permutation).unwrap())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        orbit.sort();
        orbit
    }

    fn partial_source(equalities: &[&str], declarations: &str) -> String {
        format!(
            "(set-logic QF_UF)\n\
             (declare-sort I 0)\n\
             (declare-fun e0 () I)\n\
             (declare-fun e1 () I)\n\
             (declare-fun e2 () I)\n\
             (declare-fun op (I I) I)\n\
             {declarations}\n\
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

        let partial = analyze_forbidden_pattern_orbit(&problem).unwrap();
        assert_eq!(partial.pattern_width, 9);
        assert_eq!(partial.extraction.exact_patterns, 1);
        assert_eq!(partial.canonical_first_pattern.representative.width(), 9);
    }

    #[test]
    fn exact_patterns_are_sorted_unique_and_reject_conflicting_cells() {
        let normalized = PartialTablePattern::new(
            3,
            vec![
                CellAssignment {
                    row: 2,
                    column: 1,
                    value: 0,
                },
                CellAssignment {
                    row: 0,
                    column: 2,
                    value: 1,
                },
                CellAssignment {
                    row: 2,
                    column: 1,
                    value: 0,
                },
            ],
        )
        .unwrap();
        assert_eq!(normalized.width(), 2);
        assert_eq!(
            normalized.assignments(),
            &[
                CellAssignment {
                    row: 0,
                    column: 2,
                    value: 1,
                },
                CellAssignment {
                    row: 2,
                    column: 1,
                    value: 0,
                },
            ]
        );

        assert!(matches!(
            PartialTablePattern::new(
                3,
                vec![
                    CellAssignment {
                        row: 0,
                        column: 1,
                        value: 1,
                    },
                    CellAssignment {
                        row: 0,
                        column: 1,
                        value: 2,
                    },
                ],
            ),
            Err(PatternError::ConflictingCell { .. })
        ));
        assert!(matches!(
            PartialTablePattern::new(
                3,
                vec![CellAssignment {
                    row: 0,
                    column: 1,
                    value: 3,
                }],
            ),
            Err(PatternError::AssignmentOutOfRange { .. })
        ));
    }

    #[test]
    fn five_and_six_cell_rigid_patterns_have_all_s7_embeddings() {
        for rigid in [
            pattern(7, &[(0, 6, 4), (1, 6, 0), (2, 4, 6), (3, 5, 5), (4, 2, 2)]),
            pattern(
                7,
                &[
                    (1, 5, 6),
                    (1, 6, 2),
                    (4, 6, 6),
                    (5, 0, 2),
                    (5, 2, 3),
                    (6, 0, 5),
                ],
            ),
        ] {
            let report = report_for_patterns(
                7,
                11,
                std::slice::from_ref(&rigid),
                ExtractionTelemetry::default(),
            )
            .unwrap();
            assert_eq!(report.permutations_enumerated, 5_040);
            assert_eq!(report.first_pattern_orbit_size, 5_040);
            assert_eq!(report.first_pattern_stabilizer_size, 1);
            assert!(report.orbit_stabilizer_verified);
            assert_eq!(
                rigid
                    .conjugated_by(&report.canonical_first_pattern.witness)
                    .unwrap(),
                report.canonical_first_pattern.representative
            );
        }
    }

    #[test]
    fn exact_orbit_report_measures_a_nontrivial_stabilizer() {
        let symmetric = pattern(4, &[(0, 0, 0)]);
        let report =
            report_for_patterns(4, 3, &[symmetric], ExtractionTelemetry::default()).unwrap();
        assert_eq!(report.permutations_enumerated, 24);
        assert_eq!(report.first_pattern_orbit_size, 4);
        assert_eq!(report.first_pattern_stabilizer_size, 6);
        assert!(report.orbit_stabilizer_verified);
    }

    #[test]
    fn duplicate_cannot_replace_a_missing_orbit_member() {
        let seed = pattern(3, &[(0, 0, 0), (0, 1, 2)]);
        let mut exclusions = pattern_orbit(&seed);
        assert_eq!(exclusions.len(), 6);
        exclusions.pop();
        exclusions.push(exclusions[0].clone());
        let report =
            report_for_patterns(3, 5, &exclusions, ExtractionTelemetry::default()).unwrap();
        assert_eq!(report.exclusion_records, 6);
        assert_eq!(report.unique_exclusions, 5);
        assert_eq!(report.duplicate_exclusions, 1);
        assert_eq!(report.missing_orbit_members, 1);
        assert_eq!(report.out_of_orbit_exclusions, 0);
        assert!(!report.exact_first_orbit_cover);
    }

    #[test]
    fn one_out_of_orbit_pattern_is_detected_exactly() {
        let seed = pattern(3, &[(0, 0, 0), (0, 1, 2)]);
        let mut exclusions = pattern_orbit(&seed);
        exclusions.pop();
        exclusions.push(pattern(3, &[(0, 0, 0), (0, 1, 1)]));
        let report =
            report_for_patterns(3, 5, &exclusions, ExtractionTelemetry::default()).unwrap();
        assert_eq!(report.missing_orbit_members, 1);
        assert_eq!(report.out_of_orbit_exclusions, 1);
        assert!(!report.exact_first_orbit_cover);
    }

    #[test]
    fn swapped_equality_orientation_extracts_the_same_partial_pattern() {
        let swapped = partial_source(&["(= e0 (op e0 e1))", "(= (op e2 e0) e1)"], "");
        let normal = partial_source(&["(= (op e0 e1) e0)", "(= (op e2 e0) e1)"], "");
        let swapped_report = analyze_forbidden_pattern_orbit(&parse(&swapped)).unwrap();
        let normal_report = analyze_forbidden_pattern_orbit(&parse(&normal)).unwrap();
        assert_eq!(swapped_report.pattern_width, 2);
        assert_eq!(swapped_report.exclusion_records, 1);
        assert_eq!(swapped_report.extraction.malformed_pattern_candidates, 0);
        assert_eq!(
            swapped_report.canonical_first_pattern,
            normal_report.canonical_first_pattern
        );
    }

    #[test]
    fn malformed_partial_candidates_fail_closed() {
        let cases = [
            partial_source(&["(= (op e0 e0) e0)", "(= (op e0 e0) e1)"], ""),
            partial_source(&["(= (op e0 e0) e0)", "(= (op e0 e1) (op e1 e0))"], ""),
            partial_source(
                &["(= (op e0 e0) e0)", "(= (alt e0 e1) e2)"],
                "(declare-fun alt (I I) I)",
            ),
            partial_source(
                &["(= (op e0 e0) e0)", "(= (foreign j0 j1) j0)"],
                "(declare-sort J 0)\n\
                 (declare-fun j0 () J)\n\
                 (declare-fun j1 () J)\n\
                 (declare-fun foreign (J J) J)",
            ),
            partial_source(&["(= (op e0 e0) e3)"], "(declare-fun e3 () I)"),
        ];
        for source in cases {
            assert_eq!(
                analyze_forbidden_pattern_orbit(&parse(&source)),
                Err(ProbeError::NoExactPatterns)
            );
        }
    }

    #[test]
    fn nonuniform_pattern_width_is_rejected() {
        let patterns = [
            pattern(3, &[(0, 0, 0)]),
            pattern(3, &[(0, 0, 0), (0, 1, 2)]),
        ];
        assert_eq!(
            report_for_patterns(3, 8, &patterns, ExtractionTelemetry::default()),
            Err(ProbeError::NonuniformPatternWidth {
                expected: 1,
                actual: 2,
            })
        );
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
    #[ignore = "requires EUF_VIPER_QG7_CENSUS_DIR; bounded to at most 16 files"]
    fn bounded_qg7_partial_pattern_census() {
        let directory = env::var("EUF_VIPER_QG7_CENSUS_DIR").unwrap();
        let requested = env::var("EUF_VIPER_QG7_CENSUS_LIMIT")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(4);
        let limit = requested.clamp(1, 16);
        let mut paths = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "smt2")
            })
            .collect::<Vec<_>>();
        paths.sort();
        assert!(!paths.is_empty(), "qg7 census directory has no SMT2 files");

        for path in paths.into_iter().take(limit) {
            let source = fs::read_to_string(&path).unwrap();
            let problem = parse_problem_with_scoped_let_mode(&source, ScopedLetMode::Auto).unwrap();
            let report = analyze_forbidden_pattern_orbit(&problem).unwrap();
            println!(
                concat!(
                    "{{\"path\":\"{}\",\"degree\":{},\"width\":{},",
                    "\"records\":{},\"unique\":{},\"orbit_size\":{},",
                    "\"stabilizer_size\":{},\"exact_cover\":{},",
                    "\"malformed\":{}}}"
                ),
                path.display(),
                report.degree,
                report.pattern_width,
                report.exclusion_records,
                report.unique_exclusions,
                report.first_pattern_orbit_size,
                report.first_pattern_stabilizer_size,
                report.exact_first_orbit_cover,
                report.extraction.malformed_pattern_candidates,
            );
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
