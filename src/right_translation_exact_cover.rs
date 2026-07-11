//! Test-only reference search for Latin tables by right translations.
//!
//! Each selected column is a permutation, while per-row value masks enforce
//! the remaining exact-cover condition. Bounded runs report non-exhaustion
//! explicitly and therefore never promote a partial search to SAT or UNSAT.

const MAX_DEGREE: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExactCoverError {
    EmptyDegree,
    DegreeTooLarge { degree: usize, maximum: usize },
    WrongCellCount { expected: usize, actual: usize },
    EmptyCellDomain { row: usize, column: usize },
    ValueMaskOutOfRange { row: usize, column: usize },
    ZeroSolutionLimit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RightTranslationProblem {
    degree: usize,
    allowed_values: Box<[u8]>,
}

impl RightTranslationProblem {
    pub(crate) fn unconstrained(degree: usize) -> Result<Self, ExactCoverError> {
        check_degree(degree)?;
        let all_values = (1_u16 << degree) as u8 - 1;
        Ok(Self {
            degree,
            allowed_values: vec![all_values; degree * degree].into_boxed_slice(),
        })
    }

    pub(crate) fn new(degree: usize, allowed_values: Vec<u8>) -> Result<Self, ExactCoverError> {
        check_degree(degree)?;
        let expected = degree * degree;
        if allowed_values.len() != expected {
            return Err(ExactCoverError::WrongCellCount {
                expected,
                actual: allowed_values.len(),
            });
        }
        let all_values = (1_u16 << degree) as u8 - 1;
        for (cell, &mask) in allowed_values.iter().enumerate() {
            let row = cell / degree;
            let column = cell % degree;
            if mask == 0 {
                return Err(ExactCoverError::EmptyCellDomain { row, column });
            }
            if mask & !all_values != 0 {
                return Err(ExactCoverError::ValueMaskOutOfRange { row, column });
            }
        }
        Ok(Self {
            degree,
            allowed_values: allowed_values.into_boxed_slice(),
        })
    }

    pub(crate) fn degree(&self) -> usize {
        self.degree
    }

    pub(crate) fn allowed_values(&self) -> &[u8] {
        &self.allowed_values
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SearchSummary {
    pub(crate) solutions_found: usize,
    pub(crate) exhaustive: bool,
    pub(crate) column_nodes: usize,
    pub(crate) first_solution: Option<Box<[u8]>>,
}

pub(crate) fn search_right_translations(
    problem: &RightTranslationProblem,
    solution_limit: Option<usize>,
) -> Result<SearchSummary, ExactCoverError> {
    if solution_limit == Some(0) {
        return Err(ExactCoverError::ZeroSolutionLimit);
    }
    let permutations = permutations(problem.degree);
    let mut state = SearchState {
        problem,
        permutations: &permutations,
        solution_limit,
        row_used: vec![0; problem.degree],
        table: vec![0; problem.degree * problem.degree],
        summary: SearchSummary {
            solutions_found: 0,
            exhaustive: true,
            column_nodes: 0,
            first_solution: None,
        },
    };
    state.visit_column(0);
    Ok(state.summary)
}

struct SearchState<'a> {
    problem: &'a RightTranslationProblem,
    permutations: &'a [Box<[u8]>],
    solution_limit: Option<usize>,
    row_used: Vec<u8>,
    table: Vec<u8>,
    summary: SearchSummary,
}

impl SearchState<'_> {
    fn visit_column(&mut self, column: usize) -> bool {
        if column == self.problem.degree {
            self.summary.solutions_found += 1;
            if self.summary.first_solution.is_none() {
                self.summary.first_solution = Some(self.table.clone().into_boxed_slice());
            }
            if self
                .solution_limit
                .is_some_and(|limit| self.summary.solutions_found >= limit)
            {
                self.summary.exhaustive = false;
                return false;
            }
            return true;
        }

        for permutation in self.permutations {
            self.summary.column_nodes += 1;
            if !self.column_fits(column, permutation) {
                continue;
            }
            self.select_column(column, permutation);
            let should_continue = self.visit_column(column + 1);
            self.unselect_column(column, permutation);
            if !should_continue {
                return false;
            }
        }
        true
    }

    fn column_fits(&self, column: usize, permutation: &[u8]) -> bool {
        permutation.iter().enumerate().all(|(row, &value)| {
            let bit = 1_u8 << value;
            self.row_used[row] & bit == 0
                && self.problem.allowed_values[row * self.problem.degree + column] & bit != 0
        })
    }

    fn select_column(&mut self, column: usize, permutation: &[u8]) {
        for (row, &value) in permutation.iter().enumerate() {
            self.row_used[row] |= 1_u8 << value;
            self.table[row * self.problem.degree + column] = value;
        }
    }

    fn unselect_column(&mut self, column: usize, permutation: &[u8]) {
        for (row, &value) in permutation.iter().enumerate() {
            self.row_used[row] &= !(1_u8 << value);
            self.table[row * self.problem.degree + column] = 0;
        }
    }
}

fn check_degree(degree: usize) -> Result<(), ExactCoverError> {
    if degree == 0 {
        return Err(ExactCoverError::EmptyDegree);
    }
    if degree > MAX_DEGREE {
        return Err(ExactCoverError::DegreeTooLarge {
            degree,
            maximum: MAX_DEGREE,
        });
    }
    Ok(())
}

fn permutations(degree: usize) -> Vec<Box<[u8]>> {
    let mut images = (0..degree)
        .map(|value| u8::try_from(value).expect("degree is at most five"))
        .collect::<Vec<_>>();
    let mut output = Vec::new();
    loop {
        output.push(images.clone().into_boxed_slice());
        if !advance_permutation(&mut images) {
            return output;
        }
    }
}

fn advance_permutation(values: &mut [u8]) -> bool {
    let Some(pivot) = (1..values.len())
        .rev()
        .find(|&index| values[index - 1] < values[index])
        .map(|index| index - 1)
    else {
        return false;
    };
    let successor = (pivot + 1..values.len())
        .rev()
        .find(|&index| values[pivot] < values[index])
        .expect("a permutation pivot has a successor");
    values.swap(pivot, successor);
    values[pivot + 1..].reverse();
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn brute_force_count(problem: &RightTranslationProblem) -> usize {
        assert!(problem.degree() <= 3, "tiny-degree checker only");
        let cells = problem.degree() * problem.degree();
        let tables = problem.degree().pow(u32::try_from(cells).unwrap());
        let mut entries = vec![0_u8; cells];
        let mut count = 0;
        for mut encoding in 0..tables {
            for entry in &mut entries {
                *entry = u8::try_from(encoding % problem.degree()).unwrap();
                encoding /= problem.degree();
            }
            if is_allowed_latin_table(problem, &entries) {
                count += 1;
            }
        }
        count
    }

    fn is_allowed_latin_table(problem: &RightTranslationProblem, entries: &[u8]) -> bool {
        let degree = problem.degree();
        let all_values = (1_u16 << degree) as u8 - 1;
        for (cell, &value) in entries.iter().enumerate() {
            if problem.allowed_values()[cell] & (1_u8 << value) == 0 {
                return false;
            }
        }
        for row in 0..degree {
            let mut seen = 0_u8;
            for column in 0..degree {
                seen |= 1_u8 << entries[row * degree + column];
            }
            if seen != all_values {
                return false;
            }
        }
        for column in 0..degree {
            let mut seen = 0_u8;
            for row in 0..degree {
                seen |= 1_u8 << entries[row * degree + column];
            }
            if seen != all_values {
                return false;
            }
        }
        true
    }

    #[test]
    fn exact_cover_matches_independent_brute_force_on_tiny_degrees() {
        for (degree, known_count) in [(1, 1), (2, 2), (3, 12)] {
            let problem = RightTranslationProblem::unconstrained(degree).unwrap();
            let exact = search_right_translations(&problem, None).unwrap();
            assert!(exact.exhaustive);
            assert_eq!(exact.solutions_found, known_count);
            assert_eq!(exact.solutions_found, brute_force_count(&problem));
        }
    }

    #[test]
    fn constrained_counts_match_independent_brute_force() {
        let mut masks = vec![0b111; 9];
        masks[0] = 0b001;
        masks[5] = 0b110;
        masks[7] = 0b010;
        let problem = RightTranslationProblem::new(3, masks).unwrap();
        let exact = search_right_translations(&problem, None).unwrap();
        assert!(exact.exhaustive);
        assert_eq!(exact.solutions_found, brute_force_count(&problem));
    }

    #[test]
    fn exhaustive_zero_count_is_distinct_from_a_bounded_search() {
        let problem = RightTranslationProblem::new(2, vec![0b01, 0b01, 0b11, 0b11]).unwrap();
        let exact = search_right_translations(&problem, None).unwrap();
        assert!(exact.exhaustive);
        assert_eq!(exact.solutions_found, 0);

        let degree_five = RightTranslationProblem::unconstrained(5).unwrap();
        let bounded = search_right_translations(&degree_five, Some(8)).unwrap();
        assert!(!bounded.exhaustive);
        assert_eq!(bounded.solutions_found, 8);
        assert!(bounded.first_solution.is_some());
    }

    #[test]
    fn malformed_domains_and_unsupported_degrees_are_rejected() {
        assert_eq!(
            RightTranslationProblem::unconstrained(0),
            Err(ExactCoverError::EmptyDegree)
        );
        assert_eq!(
            RightTranslationProblem::unconstrained(6),
            Err(ExactCoverError::DegreeTooLarge {
                degree: 6,
                maximum: 5,
            })
        );
        assert!(matches!(
            RightTranslationProblem::new(3, vec![0b111; 8]),
            Err(ExactCoverError::WrongCellCount { .. })
        ));
        assert!(matches!(
            RightTranslationProblem::new(3, vec![0; 9]),
            Err(ExactCoverError::EmptyCellDomain { .. })
        ));
        assert!(matches!(
            RightTranslationProblem::new(3, vec![0b1000; 9]),
            Err(ExactCoverError::ValueMaskOutOfRange { .. })
        ));
        let problem = RightTranslationProblem::unconstrained(3).unwrap();
        assert_eq!(
            search_right_translations(&problem, Some(0)),
            Err(ExactCoverError::ZeroSolutionLimit)
        );
    }
}
