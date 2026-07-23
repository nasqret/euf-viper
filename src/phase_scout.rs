#![forbid(unsafe_code)]

//! Deterministic phase repairs from first-model theory conflicts.
//!
//! The caller supplies only captured CNF evidence. This module does not call a
//! solver or retain any process state. Every conflict must be a nonempty clause
//! that is false under the complete captured assignment. On success, the
//! returned literals form a greedy hitting set: setting them true repairs every
//! supplied conflict.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

/// One bit per conflict is used by the greedy cover.
pub const MAX_THEORY_CONFLICT_CLAUSES: usize = u32::BITS as usize;

/// Raw conflict literals accepted in one scout invocation, before deduplication.
pub const MAX_THEORY_CONFLICT_LITERALS: usize = 4_096;

/// DIMACS literals use nonzero signed `i32` variable identifiers.
pub const MAX_DIMACS_VARIABLES: usize = i32::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseScoutError {
    VariableCountTooLarge {
        actual: usize,
        maximum: usize,
    },
    AssignmentLength {
        expected: usize,
        actual: usize,
    },
    AssignmentSentinel {
        actual: i8,
    },
    InvalidAssignmentValue {
        variable: usize,
        actual: i8,
    },
    BaseOccurrenceLength {
        expected: usize,
        actual: usize,
    },
    BaseOccurrenceSentinel {
        actual: usize,
    },
    TooManyConflictClauses {
        actual: usize,
        maximum: usize,
    },
    TooManyConflictLiterals {
        actual: usize,
        maximum: usize,
    },
    EmptyConflictClause {
        clause: usize,
    },
    ZeroConflictLiteral {
        clause: usize,
        offset: usize,
    },
    ConflictVariableOutOfRange {
        clause: usize,
        offset: usize,
        literal: i32,
        variable_count: usize,
    },
    ConflictLiteralNotFalsified {
        clause: usize,
        offset: usize,
        literal: i32,
    },
    NoRepairLiteral {
        uncovered_conflicts: u32,
    },
}

impl fmt::Display for PhaseScoutError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VariableCountTooLarge { actual, maximum } => write!(
                output,
                "CNF variable count {actual} exceeds DIMACS limit {maximum}"
            ),
            Self::AssignmentLength { expected, actual } => write!(
                output,
                "captured assignment has length {actual}, expected {expected}"
            ),
            Self::AssignmentSentinel { actual } => write!(
                output,
                "captured assignment index zero is {actual}, expected 0"
            ),
            Self::InvalidAssignmentValue { variable, actual } => write!(
                output,
                "captured assignment for variable {variable} is {actual}, expected -1 or 1"
            ),
            Self::BaseOccurrenceLength { expected, actual } => write!(
                output,
                "base occurrence array has length {actual}, expected {expected}"
            ),
            Self::BaseOccurrenceSentinel { actual } => write!(
                output,
                "base occurrence count at index zero is {actual}, expected 0"
            ),
            Self::TooManyConflictClauses { actual, maximum } => write!(
                output,
                "theory evidence has {actual} conflict clauses, maximum is {maximum}"
            ),
            Self::TooManyConflictLiterals { actual, maximum } => write!(
                output,
                "theory evidence has {actual} raw conflict literals, maximum is {maximum}"
            ),
            Self::EmptyConflictClause { clause } => {
                write!(output, "theory conflict clause {clause} is empty")
            }
            Self::ZeroConflictLiteral { clause, offset } => write!(
                output,
                "theory conflict clause {clause} has zero at literal offset {offset}"
            ),
            Self::ConflictVariableOutOfRange {
                clause,
                offset,
                literal,
                variable_count,
            } => write!(
                output,
                "theory conflict clause {clause} literal {offset} ({literal}) is outside variables 1..={variable_count}"
            ),
            Self::ConflictLiteralNotFalsified {
                clause,
                offset,
                literal,
            } => write!(
                output,
                "theory conflict clause {clause} literal {offset} ({literal}) is not false under the captured assignment"
            ),
            Self::NoRepairLiteral {
                uncovered_conflicts,
            } => write!(
                output,
                "validated evidence left conflict mask {uncovered_conflicts:#010x} without a repair literal"
            ),
        }
    }
}

impl Error for PhaseScoutError {}

/// Computes deterministic phase-repair literals for captured first-model conflicts.
///
/// `assignment` and `base_variable_occurrences` must both be indexed by DIMACS
/// variable, with exactly `var_count + 1` entries and a zero sentinel at index
/// zero. Assignment entries `1..=var_count` must be exactly `-1` or `1`.
/// Base occurrences count both polarities of each variable.
///
/// The greedy choice maximizes newly covered conflicts, then minimizes the
/// selected variable's base occurrence count, then uses canonical signed
/// DIMACS order `(variable, polarity)`, with negative before positive. The
/// output preserves greedy selection order. Empty conflict evidence produces
/// an empty output. Any malformed evidence returns an error before a result is
/// exposed.
pub fn scout_first_model_phases(
    var_count: usize,
    assignment: &[i8],
    base_variable_occurrences: &[usize],
    theory_conflicts: &[Vec<i32>],
) -> Result<Vec<i32>, PhaseScoutError> {
    validate_indexed_inputs(var_count, assignment, base_variable_occurrences)?;

    if theory_conflicts.len() > MAX_THEORY_CONFLICT_CLAUSES {
        return Err(PhaseScoutError::TooManyConflictClauses {
            actual: theory_conflicts.len(),
            maximum: MAX_THEORY_CONFLICT_CLAUSES,
        });
    }

    let mut raw_literal_count = 0usize;
    let mut coverages = BTreeMap::<i32, u32>::new();
    for (clause_index, clause) in theory_conflicts.iter().enumerate() {
        if clause.is_empty() {
            return Err(PhaseScoutError::EmptyConflictClause {
                clause: clause_index,
            });
        }
        let next_literal_count = raw_literal_count.saturating_add(clause.len());
        if next_literal_count > MAX_THEORY_CONFLICT_LITERALS {
            return Err(PhaseScoutError::TooManyConflictLiterals {
                actual: next_literal_count,
                maximum: MAX_THEORY_CONFLICT_LITERALS,
            });
        }
        raw_literal_count = next_literal_count;

        let conflict_bit = 1u32 << clause_index;
        for (offset, &literal) in clause.iter().enumerate() {
            let variable =
                validate_conflict_literal(var_count, assignment, clause_index, offset, literal)?;
            debug_assert!(variable < assignment.len());
            coverages
                .entry(literal)
                .and_modify(|mask| *mask |= conflict_bit)
                .or_insert(conflict_bit);
        }
    }

    let mut uncovered = match theory_conflicts.len() {
        0 => 0,
        MAX_THEORY_CONFLICT_CLAUSES => u32::MAX,
        count => (1u32 << count) - 1,
    };
    let mut selected = Vec::with_capacity(theory_conflicts.len());

    while uncovered != 0 {
        let mut best: Option<(i32, u32, usize)> = None;
        for (&literal, &coverage_mask) in &coverages {
            let newly_covered = (coverage_mask & uncovered).count_ones();
            if newly_covered == 0 {
                continue;
            }
            let variable = literal.unsigned_abs() as usize;
            let base_occurrences = base_variable_occurrences[variable];
            if best.is_none_or(|(best_literal, best_coverage, best_occurrences)| {
                newly_covered > best_coverage
                    || (newly_covered == best_coverage
                        && (base_occurrences < best_occurrences
                            || (base_occurrences == best_occurrences
                                && canonical_dimacs_key(literal)
                                    < canonical_dimacs_key(best_literal))))
            }) {
                best = Some((literal, newly_covered, base_occurrences));
            }
        }

        let Some((literal, newly_covered, _)) = best else {
            return Err(PhaseScoutError::NoRepairLiteral {
                uncovered_conflicts: uncovered,
            });
        };
        debug_assert!(newly_covered > 0);
        selected.push(literal);
        uncovered &= !coverages[&literal];
    }

    Ok(selected)
}

fn validate_indexed_inputs(
    var_count: usize,
    assignment: &[i8],
    base_variable_occurrences: &[usize],
) -> Result<(), PhaseScoutError> {
    if var_count > MAX_DIMACS_VARIABLES {
        return Err(PhaseScoutError::VariableCountTooLarge {
            actual: var_count,
            maximum: MAX_DIMACS_VARIABLES,
        });
    }
    let expected_len = var_count + 1;
    if assignment.len() != expected_len {
        return Err(PhaseScoutError::AssignmentLength {
            expected: expected_len,
            actual: assignment.len(),
        });
    }
    if assignment[0] != 0 {
        return Err(PhaseScoutError::AssignmentSentinel {
            actual: assignment[0],
        });
    }
    for (variable, &value) in assignment.iter().enumerate().skip(1) {
        if !matches!(value, -1 | 1) {
            return Err(PhaseScoutError::InvalidAssignmentValue {
                variable,
                actual: value,
            });
        }
    }
    if base_variable_occurrences.len() != expected_len {
        return Err(PhaseScoutError::BaseOccurrenceLength {
            expected: expected_len,
            actual: base_variable_occurrences.len(),
        });
    }
    if base_variable_occurrences[0] != 0 {
        return Err(PhaseScoutError::BaseOccurrenceSentinel {
            actual: base_variable_occurrences[0],
        });
    }
    Ok(())
}

fn validate_conflict_literal(
    var_count: usize,
    assignment: &[i8],
    clause: usize,
    offset: usize,
    literal: i32,
) -> Result<usize, PhaseScoutError> {
    if literal == 0 {
        return Err(PhaseScoutError::ZeroConflictLiteral { clause, offset });
    }
    let variable = literal.unsigned_abs() as usize;
    if variable == 0 || variable > var_count {
        return Err(PhaseScoutError::ConflictVariableOutOfRange {
            clause,
            offset,
            literal,
            variable_count: var_count,
        });
    }
    let literal_is_false = matches!(
        (literal.is_positive(), assignment[variable]),
        (true, -1) | (false, 1)
    );
    if !literal_is_false {
        return Err(PhaseScoutError::ConflictLiteralNotFalsified {
            clause,
            offset,
            literal,
        });
    }
    Ok(variable)
}

fn canonical_dimacs_key(literal: i32) -> (u32, u8) {
    (literal.unsigned_abs(), u8::from(literal.is_positive()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn run(assignment: &[i8], base_occurrences: &[usize], conflicts: &[Vec<i32>]) -> Vec<i32> {
        scout_first_model_phases(
            assignment.len() - 1,
            assignment,
            base_occurrences,
            conflicts,
        )
        .unwrap()
    }

    fn assert_progressing_cover(conflicts: &[Vec<i32>], selected: &[i32]) {
        let mut covered = vec![false; conflicts.len()];
        for &literal in selected {
            let mut newly_covered = 0usize;
            for (index, conflict) in conflicts.iter().enumerate() {
                if !covered[index] && conflict.contains(&literal) {
                    covered[index] = true;
                    newly_covered += 1;
                }
            }
            assert!(
                newly_covered > 0,
                "selected literal {literal} did not repair an uncovered conflict"
            );
        }
        assert!(covered.into_iter().all(|is_covered| is_covered));
    }

    fn reference_greedy(base_occurrences: &[usize], conflicts: &[Vec<i32>]) -> Vec<i32> {
        let mut uncovered = vec![true; conflicts.len()];
        let mut selected = Vec::new();
        while uncovered.iter().any(|&value| value) {
            let mut candidates = BTreeSet::new();
            for (is_uncovered, conflict) in uncovered.iter().zip(conflicts) {
                if *is_uncovered {
                    candidates.extend(conflict.iter().copied());
                }
            }
            let mut candidates = candidates.into_iter().collect::<Vec<_>>();
            candidates.sort_by_key(|&literal| canonical_dimacs_key(literal));

            let mut best_literal = None;
            let mut best_coverage = 0usize;
            let mut best_occurrences = usize::MAX;
            for literal in candidates {
                let coverage = conflicts
                    .iter()
                    .zip(&uncovered)
                    .filter(|(conflict, is_uncovered)| {
                        **is_uncovered && conflict.contains(&literal)
                    })
                    .count();
                let occurrences = base_occurrences[literal.unsigned_abs() as usize];
                if coverage > best_coverage
                    || (coverage == best_coverage && occurrences < best_occurrences)
                {
                    best_literal = Some(literal);
                    best_coverage = coverage;
                    best_occurrences = occurrences;
                }
            }

            let literal = best_literal.expect("a nonempty uncovered clause has a candidate");
            selected.push(literal);
            for (is_uncovered, conflict) in uncovered.iter_mut().zip(conflicts) {
                if conflict.contains(&literal) {
                    *is_uncovered = false;
                }
            }
        }
        selected
    }

    fn permutations<T: Clone>(values: &[T]) -> Vec<Vec<T>> {
        fn visit<T: Clone>(remaining: &mut Vec<T>, prefix: &mut Vec<T>, output: &mut Vec<Vec<T>>) {
            if remaining.is_empty() {
                output.push(prefix.clone());
                return;
            }
            for index in 0..remaining.len() {
                let value = remaining.remove(index);
                prefix.push(value.clone());
                visit(remaining, prefix, output);
                prefix.pop();
                remaining.insert(index, value);
            }
        }

        let mut output = Vec::new();
        visit(&mut values.to_vec(), &mut Vec::new(), &mut output);
        output
    }

    #[test]
    fn greedy_priorities_are_coverage_then_occurrence_then_dimacs() {
        let assignment = [0, -1, -1, -1, -1];

        let conflicts = vec![vec![1, 2], vec![1, 3], vec![1, 4], vec![2, 3]];
        let selected = run(&assignment, &[0, 100, 0, 0, 0], &conflicts);
        assert_eq!(selected, vec![1, 2]);
        assert_progressing_cover(&conflicts, &selected);

        assert_eq!(run(&assignment, &[0, 9, 1, 0, 0], &[vec![1, 2]]), vec![2]);

        let negative_assignment = [0, 1, 1];
        assert_eq!(
            run(&negative_assignment, &[0, 3, 3], &[vec![-2, -1]]),
            vec![-1]
        );
    }

    #[test]
    fn duplicate_literals_do_not_inflate_conflict_coverage() {
        let conflicts = vec![vec![1, 1, 1, 2], vec![2]];
        let selected = run(&[0, -1, -1], &[0, 0, 0], &conflicts);
        assert_eq!(selected, vec![2]);
        assert_progressing_cover(&conflicts, &selected);
    }

    #[test]
    fn empty_conflict_evidence_needs_no_repairs() {
        assert!(run(&[0, -1], &[0, 4], &[]).is_empty());
    }

    #[test]
    fn exhaustive_small_instances_match_independent_reference() {
        for var_count in 1..=3usize {
            let all_clause_masks = 1usize << var_count;
            for assignment_bits in 0..all_clause_masks {
                let mut assignment = vec![0i8; var_count + 1];
                let mut false_literals = vec![0i32; var_count + 1];
                for variable in 1..=var_count {
                    let is_true = assignment_bits & (1usize << (variable - 1)) != 0;
                    assignment[variable] = if is_true { 1 } else { -1 };
                    false_literals[variable] = if is_true {
                        -(variable as i32)
                    } else {
                        variable as i32
                    };
                }

                let possible_conflicts = (1..all_clause_masks)
                    .map(|clause_mask| {
                        (1..=var_count)
                            .filter(|variable| clause_mask & (1usize << (variable - 1)) != 0)
                            .map(|variable| false_literals[variable])
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();

                for family_mask in 0..(1usize << possible_conflicts.len()) {
                    let conflicts = possible_conflicts
                        .iter()
                        .enumerate()
                        .filter(|(index, _)| family_mask & (1usize << index) != 0)
                        .map(|(_, conflict)| conflict.clone())
                        .collect::<Vec<_>>();

                    for mut occurrence_code in 0..3usize.pow(var_count as u32) {
                        let mut base_occurrences = vec![0usize; var_count + 1];
                        for count in base_occurrences.iter_mut().skip(1) {
                            *count = occurrence_code % 3;
                            occurrence_code /= 3;
                        }
                        let expected = reference_greedy(&base_occurrences, &conflicts);
                        let actual = scout_first_model_phases(
                            var_count,
                            &assignment,
                            &base_occurrences,
                            &conflicts,
                        )
                        .unwrap();
                        assert_eq!(actual, expected);
                        assert_progressing_cover(&conflicts, &actual);
                    }
                }
            }
        }
    }

    #[test]
    fn clause_and_literal_permutations_do_not_change_selection() {
        let assignment = [0, -1, 1, -1, 1];
        let base_occurrences = [0, 7, 2, 2, 5];
        let conflicts = vec![vec![3, 1, -2], vec![-4, -2], vec![1, -4], vec![3, -2]];
        let expected = run(&assignment, &base_occurrences, &conflicts);

        for reordered_conflicts in permutations(&conflicts) {
            assert_eq!(
                run(&assignment, &base_occurrences, &reordered_conflicts),
                expected
            );
        }
        for clause_index in 0..conflicts.len() {
            for reordered_clause in permutations(&conflicts[clause_index]) {
                let mut reordered_conflicts = conflicts.clone();
                reordered_conflicts[clause_index] = reordered_clause;
                assert_eq!(
                    run(&assignment, &base_occurrences, &reordered_conflicts),
                    expected
                );
            }
        }
    }

    #[test]
    fn malformed_indexed_inputs_fail_closed() {
        let no_conflicts = Vec::<Vec<i32>>::new();
        assert_eq!(
            scout_first_model_phases(MAX_DIMACS_VARIABLES + 1, &[0], &[0], &no_conflicts),
            Err(PhaseScoutError::VariableCountTooLarge {
                actual: MAX_DIMACS_VARIABLES + 1,
                maximum: MAX_DIMACS_VARIABLES,
            })
        );
        assert_eq!(
            scout_first_model_phases(2, &[0, -1], &[0, 0, 0], &no_conflicts),
            Err(PhaseScoutError::AssignmentLength {
                expected: 3,
                actual: 2,
            })
        );
        assert_eq!(
            scout_first_model_phases(1, &[1, -1], &[0, 0], &no_conflicts),
            Err(PhaseScoutError::AssignmentSentinel { actual: 1 })
        );
        assert_eq!(
            scout_first_model_phases(1, &[0, 0], &[0, 0], &no_conflicts),
            Err(PhaseScoutError::InvalidAssignmentValue {
                variable: 1,
                actual: 0,
            })
        );
        assert_eq!(
            scout_first_model_phases(1, &[0, -1], &[0], &no_conflicts),
            Err(PhaseScoutError::BaseOccurrenceLength {
                expected: 2,
                actual: 1,
            })
        );
        assert_eq!(
            scout_first_model_phases(1, &[0, -1], &[1, 0], &no_conflicts),
            Err(PhaseScoutError::BaseOccurrenceSentinel { actual: 1 })
        );
    }

    #[test]
    fn malformed_conflict_clauses_fail_closed() {
        let assignment = [0, -1, 1];
        let base_occurrences = [0, 0, 0];
        assert_eq!(
            scout_first_model_phases(2, &assignment, &base_occurrences, &[vec![]]),
            Err(PhaseScoutError::EmptyConflictClause { clause: 0 })
        );
        assert_eq!(
            scout_first_model_phases(2, &assignment, &base_occurrences, &[vec![1, 0]]),
            Err(PhaseScoutError::ZeroConflictLiteral {
                clause: 0,
                offset: 1,
            })
        );
        assert_eq!(
            scout_first_model_phases(2, &assignment, &base_occurrences, &[vec![3]]),
            Err(PhaseScoutError::ConflictVariableOutOfRange {
                clause: 0,
                offset: 0,
                literal: 3,
                variable_count: 2,
            })
        );
        assert_eq!(
            scout_first_model_phases(2, &assignment, &base_occurrences, &[vec![i32::MIN]]),
            Err(PhaseScoutError::ConflictVariableOutOfRange {
                clause: 0,
                offset: 0,
                literal: i32::MIN,
                variable_count: 2,
            })
        );
        assert_eq!(
            scout_first_model_phases(2, &assignment, &base_occurrences, &[vec![-1]]),
            Err(PhaseScoutError::ConflictLiteralNotFalsified {
                clause: 0,
                offset: 0,
                literal: -1,
            })
        );
    }

    #[test]
    fn conflict_clause_and_literal_caps_are_exact() {
        let assignment = [0, -1];
        let base_occurrences = [0, 0];

        let at_clause_cap = vec![vec![1]; MAX_THEORY_CONFLICT_CLAUSES];
        assert_eq!(
            scout_first_model_phases(1, &assignment, &base_occurrences, &at_clause_cap),
            Ok(vec![1])
        );
        let over_clause_cap = vec![vec![1]; MAX_THEORY_CONFLICT_CLAUSES + 1];
        assert_eq!(
            scout_first_model_phases(1, &assignment, &base_occurrences, &over_clause_cap),
            Err(PhaseScoutError::TooManyConflictClauses {
                actual: MAX_THEORY_CONFLICT_CLAUSES + 1,
                maximum: MAX_THEORY_CONFLICT_CLAUSES,
            })
        );

        let at_literal_cap = vec![vec![1; MAX_THEORY_CONFLICT_LITERALS]];
        assert_eq!(
            scout_first_model_phases(1, &assignment, &base_occurrences, &at_literal_cap),
            Ok(vec![1])
        );
        let over_literal_cap = vec![vec![1; MAX_THEORY_CONFLICT_LITERALS + 1]];
        assert_eq!(
            scout_first_model_phases(1, &assignment, &base_occurrences, &over_literal_cap),
            Err(PhaseScoutError::TooManyConflictLiterals {
                actual: MAX_THEORY_CONFLICT_LITERALS + 1,
                maximum: MAX_THEORY_CONFLICT_LITERALS,
            })
        );
    }
}
