//! Test-only reference search for Latin tables by right translations.
//!
//! Each selected column is a permutation, while per-row value masks enforce
//! the remaining exact-cover condition. Bounded runs report non-exhaustion
//! explicitly and therefore never promote a partial search to SAT or UNSAT.

use crate::forbidden_orbit_probe::{PartialTablePattern, QgColumnFilter, QgReduction};

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

const MAX_SHADOW_DEGREE: usize = 7;
const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ShadowCaps {
    pub(crate) max_patterns: usize,
    pub(crate) max_pattern_cells: usize,
    pub(crate) max_permutations: usize,
    pub(crate) max_bitset_words: usize,
    pub(crate) max_preparation_word_ops: usize,
    pub(crate) max_preparation_pattern_checks: usize,
    pub(crate) max_search_nodes: usize,
    pub(crate) max_candidate_checks: usize,
    pub(crate) max_bitset_word_ops: usize,
}

impl Default for ShadowCaps {
    fn default() -> Self {
        Self {
            max_patterns: 6_000,
            max_pattern_cells: 300_000,
            max_permutations: 5_040,
            max_bitset_words: 3_200_000,
            max_preparation_word_ops: 30_000_000,
            max_preparation_pattern_checks: 1_000_000,
            max_search_nodes: 1_000_000,
            max_candidate_checks: 50_000_000,
            max_bitset_word_ops: 100_000_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ShadowAbstainReason {
    UnsupportedStructure(&'static str),
    StructuralCap {
        resource: &'static str,
        limit: usize,
        actual: usize,
    },
    PreparationCap {
        resource: &'static str,
        limit: usize,
    },
    SearchCap {
        resource: &'static str,
        limit: usize,
    },
    ArithmeticOverflow,
    AllocationFailed,
    SourceAudit(&'static str),
    SourcePredicateRejected {
        assertion: usize,
    },
    WitnessRejected(WitnessError),
}

impl ShadowAbstainReason {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedStructure(_) => "unsupported_structure",
            Self::StructuralCap { .. } => "structural_cap",
            Self::PreparationCap { .. } => "preparation_cap",
            Self::SearchCap { .. } => "search_cap",
            Self::ArithmeticOverflow => "arithmetic_overflow",
            Self::AllocationFailed => "allocation_failed",
            Self::SourceAudit(_) => "source_audit",
            Self::SourcePredicateRejected { .. } => "source_predicate_rejected",
            Self::WitnessRejected(_) => "witness_rejected",
        }
    }

    pub(crate) fn resource(&self) -> &'static str {
        match self {
            Self::UnsupportedStructure(resource)
            | Self::StructuralCap { resource, .. }
            | Self::PreparationCap { resource, .. }
            | Self::SearchCap { resource, .. } => resource,
            Self::ArithmeticOverflow => "arithmetic",
            Self::AllocationFailed => "allocation",
            Self::SourceAudit(resource) => resource,
            Self::SourcePredicateRejected { .. } => "source_predicate",
            Self::WitnessRejected(error) => error.code(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ShadowTelemetry {
    pub(crate) patterns: usize,
    pub(crate) pattern_cells: usize,
    pub(crate) permutations: usize,
    pub(crate) column_candidates: usize,
    pub(crate) min_column_candidates: usize,
    pub(crate) max_column_candidates: usize,
    pub(crate) bitset_words: usize,
    pub(crate) preparation_word_ops: usize,
    pub(crate) preparation_pattern_checks: usize,
    pub(crate) preparation_cell_updates: usize,
    pub(crate) search_nodes: usize,
    pub(crate) candidate_checks: usize,
    pub(crate) exact_cover_rejections: usize,
    pub(crate) forbidden_rejections: usize,
    pub(crate) bitset_word_ops: usize,
    pub(crate) branch_attempts: usize,
    pub(crate) witness_checks: usize,
    pub(crate) max_depth: usize,
    pub(crate) trace_hash: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShadowWitness {
    degree: usize,
    table: Vec<u8>,
}

impl ShadowWitness {
    pub(crate) fn degree(&self) -> usize {
        self.degree
    }

    pub(crate) fn table(&self) -> &[u8] {
        &self.table
    }
}

/// Outcome for the Latin-table pattern-avoidance abstraction only.
///
/// `Unsat` is emitted only after exhaustive search. This test-only result is
/// never an answer for the source SMT problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ShadowOutcome {
    Sat {
        witness: ShadowWitness,
        telemetry: ShadowTelemetry,
    },
    Unsat {
        telemetry: ShadowTelemetry,
    },
    Abstain {
        reason: ShadowAbstainReason,
        telemetry: ShadowTelemetry,
    },
}

impl ShadowOutcome {
    pub(crate) fn telemetry(&self) -> &ShadowTelemetry {
        match self {
            Self::Sat { telemetry, .. }
            | Self::Unsat { telemetry }
            | Self::Abstain { telemetry, .. } => telemetry,
        }
    }

    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Sat { .. } => "shadow_witness",
            Self::Unsat { .. } => "shadow_exhausted",
            Self::Abstain { .. } => "abstain",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WitnessError {
    DegreeOutOfRange,
    WrongTableSize { expected: usize, actual: usize },
    ValueOutOfRange { cell: usize, value: u8 },
    RowIsNotPermutation { row: usize },
    ColumnIsNotPermutation { column: usize },
    PatternDegreeMismatch { pattern: usize },
    ForbiddenPatternMatched { pattern: usize },
}

impl WitnessError {
    fn code(&self) -> &'static str {
        match self {
            Self::DegreeOutOfRange => "witness_degree",
            Self::WrongTableSize { .. } => "witness_table_size",
            Self::ValueOutOfRange { .. } => "witness_value",
            Self::RowIsNotPermutation { .. } => "witness_row",
            Self::ColumnIsNotPermutation { .. } => "witness_column",
            Self::PatternDegreeMismatch { .. } => "witness_pattern_degree",
            Self::ForbiddenPatternMatched { .. } => "witness_forbidden_pattern",
        }
    }
}

pub(crate) fn search_exact_pattern_shadow(
    forbidden_patterns: &[PartialTablePattern],
    caps: &ShadowCaps,
) -> ShadowOutcome {
    search_exact_pattern_shadow_with_filters(forbidden_patterns, None, caps)
}

/// Runs only after the source assertion audit has accounted for every assertion.
///
/// The result remains test-only shadow evidence. In particular, exhaustion and
/// witnesses are not SMT answers for the source file.
pub(crate) fn search_qg_reduction_shadow(
    reduction: &QgReduction,
    caps: &ShadowCaps,
) -> ShadowOutcome {
    if !reduction.eligible() {
        return ShadowOutcome::Abstain {
            reason: ShadowAbstainReason::SourceAudit(reduction.first_ineligibility_code()),
            telemetry: ShadowTelemetry {
                trace_hash: FNV_OFFSET,
                ..ShadowTelemetry::default()
            },
        };
    }
    let outcome = search_exact_pattern_shadow_with_filters(
        reduction.patterns(),
        Some(reduction.column_filters()),
        caps,
    );
    match outcome {
        ShadowOutcome::Sat { witness, telemetry } => {
            match reduction.validate_local_constraints(witness.table()) {
                Ok(()) => ShadowOutcome::Sat { witness, telemetry },
                Err(assertion) => ShadowOutcome::Abstain {
                    reason: ShadowAbstainReason::SourcePredicateRejected {
                        assertion: assertion.ordinal,
                    },
                    telemetry,
                },
            }
        }
        outcome => outcome,
    }
}

fn search_exact_pattern_shadow_with_filters(
    forbidden_patterns: &[PartialTablePattern],
    column_filters: Option<&[QgColumnFilter]>,
    caps: &ShadowCaps,
) -> ShadowOutcome {
    let mut telemetry = ShadowTelemetry {
        trace_hash: FNV_OFFSET,
        ..ShadowTelemetry::default()
    };
    let prepared =
        match PreparedShadow::new(forbidden_patterns, column_filters, caps, &mut telemetry) {
            Ok(prepared) => prepared,
            Err(reason) => return ShadowOutcome::Abstain { reason, telemetry },
        };
    let live_words = match prepared
        .degree
        .checked_add(1)
        .and_then(|depths| depths.checked_mul(prepared.words))
    {
        Some(words) => words,
        None => {
            return ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::ArithmeticOverflow,
                telemetry,
            };
        }
    };
    let mut live_stack = match zeroed_words(live_words) {
        Ok(words) => words,
        Err(reason) => return ShadowOutcome::Abstain { reason, telemetry },
    };
    live_stack[..prepared.words].fill(u64::MAX);
    live_stack[prepared.words - 1] = prepared.last_word_mask;
    let table_size = match prepared.degree.checked_mul(prepared.degree) {
        Some(size) => size,
        None => {
            return ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::ArithmeticOverflow,
                telemetry,
            };
        }
    };
    let table = match zeroed_bytes(table_size) {
        Ok(table) => table,
        Err(reason) => return ShadowOutcome::Abstain { reason, telemetry },
    };

    let mut search = ShadowSearch {
        prepared: &prepared,
        caps,
        telemetry,
        live_stack,
        table,
    };
    let result = search.dfs(0, 0, 0);
    let mut telemetry = search.telemetry;
    match result {
        ShadowDfsResult::Sat(table) => {
            telemetry.witness_checks += 1;
            match validate_shadow_witness(prepared.degree, forbidden_patterns, &table) {
                Ok(()) => ShadowOutcome::Sat {
                    witness: ShadowWitness {
                        degree: prepared.degree,
                        table,
                    },
                    telemetry,
                },
                Err(error) => ShadowOutcome::Abstain {
                    reason: ShadowAbstainReason::WitnessRejected(error),
                    telemetry,
                },
            }
        }
        ShadowDfsResult::Unsat => ShadowOutcome::Unsat { telemetry },
        ShadowDfsResult::Abstain(reason) => ShadowOutcome::Abstain { reason, telemetry },
    }
}

pub(crate) fn validate_shadow_witness(
    degree: usize,
    forbidden_patterns: &[PartialTablePattern],
    table: &[u8],
) -> Result<(), WitnessError> {
    if degree == 0 || degree > MAX_SHADOW_DEGREE {
        return Err(WitnessError::DegreeOutOfRange);
    }
    let expected = degree * degree;
    if table.len() != expected {
        return Err(WitnessError::WrongTableSize {
            expected,
            actual: table.len(),
        });
    }
    let all_values = (1_u16 << degree) as u8 - 1;
    for (cell, &value) in table.iter().enumerate() {
        if usize::from(value) >= degree {
            return Err(WitnessError::ValueOutOfRange { cell, value });
        }
    }
    for row in 0..degree {
        let mut values = 0_u8;
        for column in 0..degree {
            values |= 1_u8 << table[row * degree + column];
        }
        if values != all_values {
            return Err(WitnessError::RowIsNotPermutation { row });
        }
    }
    for column in 0..degree {
        let mut values = 0_u8;
        for row in 0..degree {
            values |= 1_u8 << table[row * degree + column];
        }
        if values != all_values {
            return Err(WitnessError::ColumnIsNotPermutation { column });
        }
    }
    for (index, pattern) in forbidden_patterns.iter().enumerate() {
        if pattern.degree() != degree {
            return Err(WitnessError::PatternDegreeMismatch { pattern: index });
        }
        if pattern.assignments().iter().all(|assignment| {
            table[assignment.row * degree + assignment.column]
                == u8::try_from(assignment.value).expect("degree is at most seven")
        }) {
            return Err(WitnessError::ForbiddenPatternMatched { pattern: index });
        }
    }
    Ok(())
}

#[derive(Debug)]
struct ShadowPermutation {
    values: [u8; MAX_SHADOW_DEGREE],
    row_value_bits: u64,
}

struct PreparedShadow {
    degree: usize,
    permutations: Vec<ShadowPermutation>,
    column_candidates: Vec<Vec<usize>>,
    column_candidate_starts: [usize; MAX_SHADOW_DEGREE + 1],
    words: usize,
    last_word_mask: u64,
    compatibility: Vec<u64>,
    completed_patterns: Vec<u64>,
    completed_nonempty: Vec<bool>,
}

impl PreparedShadow {
    fn new(
        forbidden_patterns: &[PartialTablePattern],
        column_filters: Option<&[QgColumnFilter]>,
        caps: &ShadowCaps,
        telemetry: &mut ShadowTelemetry,
    ) -> Result<Self, ShadowAbstainReason> {
        let first = forbidden_patterns
            .first()
            .ok_or(ShadowAbstainReason::UnsupportedStructure(
                "empty forbidden pattern family",
            ))?;
        let degree = first.degree();
        if degree == 0 || degree > MAX_SHADOW_DEGREE {
            return Err(ShadowAbstainReason::UnsupportedStructure(
                "shadow degree outside 1..=7",
            ));
        }
        if column_filters.is_some_and(|filters| {
            filters.len() != degree
                || filters
                    .iter()
                    .enumerate()
                    .any(|(column, filter)| filter.column != column)
        }) {
            return Err(ShadowAbstainReason::UnsupportedStructure(
                "invalid qg column filters",
            ));
        }
        let width = first.width();
        telemetry.patterns = forbidden_patterns.len();
        if telemetry.patterns > caps.max_patterns {
            return Err(ShadowAbstainReason::StructuralCap {
                resource: "patterns",
                limit: caps.max_patterns,
                actual: telemetry.patterns,
            });
        }
        telemetry.pattern_cells = 0;
        for pattern in forbidden_patterns {
            if pattern.degree() != degree {
                return Err(ShadowAbstainReason::UnsupportedStructure(
                    "mixed pattern degrees",
                ));
            }
            if pattern.width() != width {
                return Err(ShadowAbstainReason::UnsupportedStructure(
                    "nonuniform pattern width",
                ));
            }
            telemetry.pattern_cells = telemetry
                .pattern_cells
                .checked_add(pattern.width())
                .ok_or(ShadowAbstainReason::ArithmeticOverflow)?;
        }
        if telemetry.pattern_cells > caps.max_pattern_cells {
            return Err(ShadowAbstainReason::StructuralCap {
                resource: "pattern_cells",
                limit: caps.max_pattern_cells,
                actual: telemetry.pattern_cells,
            });
        }
        let mut patterns = reserved_vec(forbidden_patterns.len())?;
        for pattern in forbidden_patterns {
            patterns.push(pattern);
        }
        patterns.sort_unstable();
        if patterns.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ShadowAbstainReason::UnsupportedStructure(
                "duplicate forbidden patterns",
            ));
        }

        let factorial = checked_factorial(degree)?;
        let (permutation_count, candidate_capacities) =
            count_filtered_shadow_permutations(degree, factorial, column_filters);
        telemetry.permutations = permutation_count;
        telemetry.column_candidates = candidate_capacities[..degree]
            .iter()
            .try_fold(0_usize, |total, &candidates| total.checked_add(candidates))
            .ok_or(ShadowAbstainReason::ArithmeticOverflow)?;
        telemetry.min_column_candidates = candidate_capacities[..degree]
            .iter()
            .copied()
            .min()
            .unwrap_or(0);
        telemetry.max_column_candidates = candidate_capacities[..degree]
            .iter()
            .copied()
            .max()
            .unwrap_or(0);
        if permutation_count > caps.max_permutations {
            return Err(ShadowAbstainReason::StructuralCap {
                resource: "permutations",
                limit: caps.max_permutations,
                actual: permutation_count,
            });
        }
        let (permutations, column_candidates) = shadow_permutations(
            degree,
            permutation_count,
            &candidate_capacities,
            column_filters,
        )?;
        debug_assert_eq!(permutations.len(), permutation_count);

        let words = patterns
            .len()
            .checked_add(63)
            .ok_or(ShadowAbstainReason::ArithmeticOverflow)?
            / 64;
        let last_word_mask = if patterns.len() % 64 == 0 {
            u64::MAX
        } else {
            (1_u64 << (patterns.len() % 64)) - 1
        };
        let compatibility_words = telemetry
            .column_candidates
            .checked_mul(words)
            .ok_or(ShadowAbstainReason::ArithmeticOverflow)?;
        let mut column_candidate_starts = [0_usize; MAX_SHADOW_DEGREE + 1];
        for column in 0..degree {
            column_candidate_starts[column + 1] = column_candidate_starts[column]
                .checked_add(column_candidates[column].len())
                .ok_or(ShadowAbstainReason::ArithmeticOverflow)?;
        }
        debug_assert_eq!(column_candidate_starts[degree], telemetry.column_candidates);
        let cell_compatibility_words = degree
            .checked_mul(degree)
            .and_then(|value| value.checked_mul(degree))
            .and_then(|value| value.checked_mul(words))
            .ok_or(ShadowAbstainReason::ArithmeticOverflow)?;
        let subset_count = 1_usize
            .checked_shl(u32::try_from(degree).expect("degree is at most seven"))
            .ok_or(ShadowAbstainReason::ArithmeticOverflow)?;
        let completed_words = subset_count
            .checked_mul(words)
            .ok_or(ShadowAbstainReason::ArithmeticOverflow)?;
        let live_words = degree
            .checked_add(1)
            .and_then(|depths| depths.checked_mul(words))
            .ok_or(ShadowAbstainReason::ArithmeticOverflow)?;
        telemetry.bitset_words = compatibility_words
            .checked_add(cell_compatibility_words)
            .and_then(|value| value.checked_add(completed_words))
            .and_then(|value| value.checked_add(live_words))
            .ok_or(ShadowAbstainReason::ArithmeticOverflow)?;
        if telemetry.bitset_words > caps.max_bitset_words {
            return Err(ShadowAbstainReason::StructuralCap {
                resource: "bitset_words",
                limit: caps.max_bitset_words,
                actual: telemetry.bitset_words,
            });
        }

        let mut cell_compatibility = zeroed_words(cell_compatibility_words)?;
        for block in cell_compatibility.chunks_exact_mut(words) {
            block.fill(u64::MAX);
            block[words - 1] = last_word_mask;
        }
        let mut supports = zeroed_bytes(patterns.len())?;
        for (pattern_index, pattern) in patterns.iter().enumerate() {
            let pattern_word = pattern_index / 64;
            let pattern_bit = 1_u64 << (pattern_index % 64);
            for assignment in pattern.assignments() {
                supports[pattern_index] |= 1_u8 << assignment.column;
                for selected in 0..degree {
                    if selected == assignment.value {
                        continue;
                    }
                    telemetry.preparation_cell_updates = telemetry
                        .preparation_cell_updates
                        .checked_add(1)
                        .ok_or(ShadowAbstainReason::ArithmeticOverflow)?;
                    let offset = cell_compatibility_offset(
                        degree,
                        words,
                        assignment.column,
                        assignment.row,
                        selected,
                    );
                    cell_compatibility[offset + pattern_word] &= !pattern_bit;
                }
            }
        }

        let mut compatibility = zeroed_words(compatibility_words)?;
        for column in 0..degree {
            for (candidate_index, &permutation_index) in
                column_candidates[column].iter().enumerate()
            {
                let permutation = &permutations[permutation_index];
                let output = (column_candidate_starts[column] + candidate_index) * words;
                for word in 0..words {
                    let mut compatible = if word + 1 == words {
                        last_word_mask
                    } else {
                        u64::MAX
                    };
                    for row in 0..degree {
                        add_preparation_work(
                            &mut telemetry.preparation_word_ops,
                            1,
                            caps.max_preparation_word_ops,
                            "preparation_word_ops",
                        )?;
                        let input = cell_compatibility_offset(
                            degree,
                            words,
                            column,
                            row,
                            usize::from(permutation.values[row]),
                        );
                        compatible &= cell_compatibility[input + word];
                    }
                    compatibility[output + word] = compatible;
                }
            }
        }
        drop(cell_compatibility);

        let mut completed_patterns = zeroed_words(completed_words)?;
        let mut completed_nonempty = zeroed_bools(subset_count)?;
        for subset in 0..subset_count {
            let subset_mask = u8::try_from(subset).expect("degree is at most seven");
            let output = subset * words;
            for (pattern_index, &support) in supports.iter().enumerate() {
                add_preparation_pattern_check(
                    &mut telemetry.preparation_pattern_checks,
                    caps.max_preparation_pattern_checks,
                )?;
                if support & !subset_mask == 0 {
                    completed_patterns[output + pattern_index / 64] |=
                        1_u64 << (pattern_index % 64);
                    completed_nonempty[subset] = true;
                }
            }
        }

        Ok(Self {
            degree,
            permutations,
            column_candidates,
            column_candidate_starts,
            words,
            last_word_mask,
            compatibility,
            completed_patterns,
            completed_nonempty,
        })
    }

    fn compatibility_offset(&self, column: usize, candidate: usize) -> usize {
        (self.column_candidate_starts[column] + candidate) * self.words
    }
}

fn cell_compatibility_offset(
    degree: usize,
    words: usize,
    column: usize,
    row: usize,
    value: usize,
) -> usize {
    ((column * degree * degree + row * degree + value) * words) as usize
}

fn shadow_permutations(
    degree: usize,
    permutation_count: usize,
    candidate_capacities: &[usize; MAX_SHADOW_DEGREE],
    column_filters: Option<&[QgColumnFilter]>,
) -> Result<(Vec<ShadowPermutation>, Vec<Vec<usize>>), ShadowAbstainReason> {
    let mut output = reserved_vec(permutation_count)?;
    let mut column_candidates = reserved_vec(degree)?;
    for &capacity in &candidate_capacities[..degree] {
        column_candidates.push(reserved_vec(capacity)?);
    }
    let mut values = [0_u8; MAX_SHADOW_DEGREE];
    for (value, slot) in values[..degree].iter_mut().enumerate() {
        *slot = u8::try_from(value).expect("shadow degree is at most seven");
    }
    loop {
        let mut allowed_columns = [false; MAX_SHADOW_DEGREE];
        for column in 0..degree {
            allowed_columns[column] =
                column_filters.is_none_or(|filters| filters[column].allows(&values[..degree]));
        }
        if allowed_columns[..degree].iter().any(|allowed| *allowed) {
            let permutation_index = output.len();
            let row_value_bits = values[..degree]
                .iter()
                .enumerate()
                .fold(0_u64, |bits, (row, &value)| {
                    bits | (1_u64 << (row * degree + usize::from(value)))
                });
            output.push(ShadowPermutation {
                values,
                row_value_bits,
            });
            for column in 0..degree {
                if allowed_columns[column] {
                    column_candidates[column].push(permutation_index);
                }
            }
        }
        if !advance_permutation(&mut values[..degree]) {
            break;
        }
    }
    Ok((output, column_candidates))
}

fn count_filtered_shadow_permutations(
    degree: usize,
    factorial: usize,
    column_filters: Option<&[QgColumnFilter]>,
) -> (usize, [usize; MAX_SHADOW_DEGREE]) {
    let Some(filters) = column_filters else {
        let mut candidates = [0; MAX_SHADOW_DEGREE];
        candidates[..degree].fill(factorial);
        return (factorial, candidates);
    };
    let mut values = [0_u8; MAX_SHADOW_DEGREE];
    for (value, slot) in values[..degree].iter_mut().enumerate() {
        *slot = u8::try_from(value).expect("shadow degree is at most seven");
    }
    let mut retained = 0;
    let mut candidates = [0; MAX_SHADOW_DEGREE];
    loop {
        let mut used = false;
        for column in 0..degree {
            if filters[column].allows(&values[..degree]) {
                candidates[column] += 1;
                used = true;
            }
        }
        retained += usize::from(used);
        if !advance_permutation(&mut values[..degree]) {
            return (retained, candidates);
        }
    }
}

fn reserved_vec<T>(capacity: usize) -> Result<Vec<T>, ShadowAbstainReason> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| ShadowAbstainReason::AllocationFailed)?;
    Ok(values)
}

fn zeroed_words(length: usize) -> Result<Vec<u64>, ShadowAbstainReason> {
    let mut words = reserved_vec(length)?;
    words.resize(length, 0);
    Ok(words)
}

fn zeroed_bytes(length: usize) -> Result<Vec<u8>, ShadowAbstainReason> {
    let mut bytes = reserved_vec(length)?;
    bytes.resize(length, 0);
    Ok(bytes)
}

fn zeroed_bools(length: usize) -> Result<Vec<bool>, ShadowAbstainReason> {
    let mut values = reserved_vec(length)?;
    values.resize(length, false);
    Ok(values)
}

fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, ShadowAbstainReason> {
    let mut copy = reserved_vec(bytes.len())?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

fn checked_factorial(degree: usize) -> Result<usize, ShadowAbstainReason> {
    (1..=degree).try_fold(1_usize, |product, value| {
        product
            .checked_mul(value)
            .ok_or(ShadowAbstainReason::ArithmeticOverflow)
    })
}

fn add_preparation_work(
    counter: &mut usize,
    amount: usize,
    limit: usize,
    resource: &'static str,
) -> Result<(), ShadowAbstainReason> {
    let next = counter
        .checked_add(amount)
        .ok_or(ShadowAbstainReason::ArithmeticOverflow)?;
    if next > limit {
        return Err(ShadowAbstainReason::PreparationCap { resource, limit });
    }
    *counter = next;
    Ok(())
}

fn add_preparation_pattern_check(
    counter: &mut usize,
    limit: usize,
) -> Result<(), ShadowAbstainReason> {
    add_preparation_work(counter, 1, limit, "preparation_pattern_checks")
}

enum ShadowDfsResult {
    Sat(Vec<u8>),
    Unsat,
    Abstain(ShadowAbstainReason),
}

struct ShadowSearch<'a> {
    prepared: &'a PreparedShadow,
    caps: &'a ShadowCaps,
    telemetry: ShadowTelemetry,
    live_stack: Vec<u64>,
    table: Vec<u8>,
}

impl ShadowSearch<'_> {
    fn dfs(&mut self, depth: usize, assigned_columns: u8, used_row_values: u64) -> ShadowDfsResult {
        if self.telemetry.search_nodes >= self.caps.max_search_nodes {
            return ShadowDfsResult::Abstain(ShadowAbstainReason::SearchCap {
                resource: "search_nodes",
                limit: self.caps.max_search_nodes,
            });
        }
        self.telemetry.search_nodes += 1;
        self.telemetry.max_depth = self.telemetry.max_depth.max(depth);
        if depth == self.prepared.degree {
            return match copy_bytes(&self.table) {
                Ok(table) => ShadowDfsResult::Sat(table),
                Err(reason) => ShadowDfsResult::Abstain(reason),
            };
        }

        let mut best_column = None;
        let mut best_count = usize::MAX;
        for column in 0..self.prepared.degree {
            if assigned_columns & (1_u8 << column) != 0 {
                continue;
            }
            let next_columns = assigned_columns | (1_u8 << column);
            let mut viable = 0;
            for (candidate, &permutation) in
                self.prepared.column_candidates[column].iter().enumerate()
            {
                match self.candidate_is_viable(
                    depth,
                    column,
                    candidate,
                    permutation,
                    next_columns,
                    used_row_values,
                ) {
                    Ok(true) => viable += 1,
                    Ok(false) => {}
                    Err(reason) => return ShadowDfsResult::Abstain(reason),
                }
            }
            if viable == 0 {
                return ShadowDfsResult::Unsat;
            }
            if viable < best_count {
                best_count = viable;
                best_column = Some(column);
            }
        }
        let column = best_column.expect("an incomplete search has an unassigned column");
        let next_columns = assigned_columns | (1_u8 << column);
        for (candidate_index, &permutation_index) in
            self.prepared.column_candidates[column].iter().enumerate()
        {
            match self.candidate_is_viable(
                depth,
                column,
                candidate_index,
                permutation_index,
                next_columns,
                used_row_values,
            ) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(reason) => return ShadowDfsResult::Abstain(reason),
            }
            let row_value_bits = self.prepared.permutations[permutation_index].row_value_bits;
            if let Err(reason) = self.write_child_live(depth, column, candidate_index) {
                return ShadowDfsResult::Abstain(reason);
            }
            for (row, &value) in self.prepared.permutations[permutation_index].values
                [..self.prepared.degree]
                .iter()
                .enumerate()
            {
                self.table[row * self.prepared.degree + column] = value;
            }
            self.telemetry.branch_attempts += 1;
            self.record_trace(column, permutation_index);
            match self.dfs(depth + 1, next_columns, used_row_values | row_value_bits) {
                ShadowDfsResult::Sat(table) => return ShadowDfsResult::Sat(table),
                ShadowDfsResult::Unsat => {}
                ShadowDfsResult::Abstain(reason) => return ShadowDfsResult::Abstain(reason),
            }
        }
        ShadowDfsResult::Unsat
    }

    fn candidate_is_viable(
        &mut self,
        depth: usize,
        column: usize,
        candidate: usize,
        permutation: usize,
        next_columns: u8,
        used_row_values: u64,
    ) -> Result<bool, ShadowAbstainReason> {
        if self.telemetry.candidate_checks >= self.caps.max_candidate_checks {
            return Err(ShadowAbstainReason::SearchCap {
                resource: "candidate_checks",
                limit: self.caps.max_candidate_checks,
            });
        }
        self.telemetry.candidate_checks += 1;
        if self.prepared.permutations[permutation].row_value_bits & used_row_values != 0 {
            self.telemetry.exact_cover_rejections += 1;
            return Ok(false);
        }
        if !self.prepared.completed_nonempty[usize::from(next_columns)] {
            return Ok(true);
        }
        let live = depth * self.prepared.words;
        let compatible = self.prepared.compatibility_offset(column, candidate);
        let completed = usize::from(next_columns) * self.prepared.words;
        for word in 0..self.prepared.words {
            self.record_bitset_word_op()?;
            if self.live_stack[live + word]
                & self.prepared.compatibility[compatible + word]
                & self.prepared.completed_patterns[completed + word]
                != 0
            {
                self.telemetry.forbidden_rejections += 1;
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn write_child_live(
        &mut self,
        depth: usize,
        column: usize,
        candidate: usize,
    ) -> Result<(), ShadowAbstainReason> {
        let parent = depth * self.prepared.words;
        let child = (depth + 1) * self.prepared.words;
        let compatible = self.prepared.compatibility_offset(column, candidate);
        for word in 0..self.prepared.words {
            self.record_bitset_word_op()?;
            self.live_stack[child + word] =
                self.live_stack[parent + word] & self.prepared.compatibility[compatible + word];
        }
        Ok(())
    }

    fn record_bitset_word_op(&mut self) -> Result<(), ShadowAbstainReason> {
        if self.telemetry.bitset_word_ops >= self.caps.max_bitset_word_ops {
            return Err(ShadowAbstainReason::SearchCap {
                resource: "bitset_word_ops",
                limit: self.caps.max_bitset_word_ops,
            });
        }
        self.telemetry.bitset_word_ops += 1;
        Ok(())
    }

    fn record_trace(&mut self, column: usize, permutation: usize) {
        for word in [column, permutation] {
            for byte in word.to_le_bytes() {
                self.telemetry.trace_hash ^= u64::from(byte);
                self.telemetry.trace_hash = self.telemetry.trace_hash.wrapping_mul(FNV_PRIME);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forbidden_orbit_probe::{CellAssignment, QgReduction};
    use crate::{ScopedLetMode, parse_problem_with_scoped_let_mode};

    fn audited_qg7_fixture() -> QgReduction {
        let source = include_str!("../tests/fixtures/qg7_reduction_phase1.smt2");
        let problem = parse_problem_with_scoped_let_mode(source, ScopedLetMode::Off).unwrap();
        QgReduction::audit(source, &problem)
    }

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

    fn forbidden_pattern(
        degree: usize,
        assignments: &[(usize, usize, usize)],
    ) -> PartialTablePattern {
        PartialTablePattern::new(
            degree,
            assignments
                .iter()
                .map(|&(row, column, value)| CellAssignment { row, column, value })
                .collect(),
        )
        .unwrap()
    }

    fn complete_pattern(degree: usize, table: &[u8]) -> PartialTablePattern {
        forbidden_pattern(
            degree,
            &table
                .iter()
                .enumerate()
                .map(|(cell, &value)| (cell / degree, cell % degree, usize::from(value)))
                .collect::<Vec<_>>(),
        )
    }

    fn brute_force_shadow_witness(
        degree: usize,
        forbidden_patterns: &[PartialTablePattern],
    ) -> Option<Vec<u8>> {
        assert!(degree <= 3, "independent checker is intentionally tiny");
        let cells = degree * degree;
        let tables = degree.pow(u32::try_from(cells).unwrap());
        let mut table = vec![0_u8; cells];
        for mut encoding in 0..tables {
            for value in &mut table {
                *value = u8::try_from(encoding % degree).unwrap();
                encoding /= degree;
            }
            if independently_is_latin(degree, &table)
                && forbidden_patterns.iter().all(|pattern| {
                    pattern.assignments().iter().any(|assignment| {
                        table[assignment.row * degree + assignment.column]
                            != u8::try_from(assignment.value).unwrap()
                    })
                })
            {
                return Some(table.clone());
            }
        }
        None
    }

    fn independently_is_latin(degree: usize, table: &[u8]) -> bool {
        for row in 0..degree {
            let mut counts = vec![0; degree];
            for column in 0..degree {
                counts[usize::from(table[row * degree + column])] += 1;
            }
            if counts.iter().any(|&count| count != 1) {
                return false;
            }
        }
        for column in 0..degree {
            let mut counts = vec![0; degree];
            for row in 0..degree {
                counts[usize::from(table[row * degree + column])] += 1;
            }
            if counts.iter().any(|&count| count != 1) {
                return false;
            }
        }
        true
    }

    #[test]
    fn shadow_sat_and_unsat_match_independent_tiny_table_enumeration() {
        let first = complete_pattern(2, &[0, 1, 1, 0]);
        let second = complete_pattern(2, &[1, 0, 0, 1]);
        let cases = [
            vec![first.clone()],
            vec![first, second],
            vec![forbidden_pattern(2, &[(0, 0, 0), (1, 0, 0)])],
        ];
        for patterns in cases {
            let expected = brute_force_shadow_witness(2, &patterns);
            let outcome = search_exact_pattern_shadow(&patterns, &ShadowCaps::default());
            match (expected, outcome) {
                (Some(_), ShadowOutcome::Sat { witness, .. }) => {
                    validate_shadow_witness(2, &patterns, witness.table()).unwrap();
                }
                (None, ShadowOutcome::Unsat { .. }) => {}
                (expected, actual) => {
                    panic!("independent result {expected:?} disagrees with {actual:?}")
                }
            }
        }

        let degree_three = [forbidden_pattern(3, &[(0, 0, 0), (1, 1, 1)])];
        assert!(brute_force_shadow_witness(3, &degree_three).is_some());
        assert!(matches!(
            search_exact_pattern_shadow(&degree_three, &ShadowCaps::default()),
            ShadowOutcome::Sat { .. }
        ));
    }

    #[test]
    fn shadow_sat_witness_replay_rejects_mutations() {
        let patterns = [complete_pattern(2, &[0, 1, 1, 0])];
        let ShadowOutcome::Sat { witness, .. } =
            search_exact_pattern_shadow(&patterns, &ShadowCaps::default())
        else {
            panic!("one forbidden degree-two Latin table leaves a model");
        };
        assert_eq!(witness.degree(), 2);
        validate_shadow_witness(2, &patterns, witness.table()).unwrap();

        let mut non_latin = witness.table().to_vec();
        non_latin[0] = non_latin[1];
        assert!(matches!(
            validate_shadow_witness(2, &patterns, &non_latin),
            Err(WitnessError::RowIsNotPermutation { .. })
        ));
        assert!(matches!(
            validate_shadow_witness(2, &patterns, &[0, 1, 1]),
            Err(WitnessError::WrongTableSize { .. })
        ));

        let forbidden_witness = [complete_pattern(2, witness.table())];
        assert_eq!(
            validate_shadow_witness(2, &forbidden_witness, witness.table()),
            Err(WitnessError::ForbiddenPatternMatched { pattern: 0 })
        );
    }

    #[test]
    fn multiword_pattern_bitsets_match_independent_enumeration() {
        let patterns = (0..65)
            .map(|mut encoding| {
                let mut table = vec![0_u8; 9];
                for value in &mut table {
                    *value = u8::try_from(encoding % 3).unwrap();
                    encoding /= 3;
                }
                complete_pattern(3, &table)
            })
            .collect::<Vec<_>>();
        let expected = brute_force_shadow_witness(3, &patterns);
        let outcome = search_exact_pattern_shadow(&patterns, &ShadowCaps::default());
        assert_eq!(outcome.telemetry().patterns, 65);
        assert!(outcome.telemetry().bitset_words > 64);
        match (expected, outcome) {
            (Some(_), ShadowOutcome::Sat { witness, .. }) => {
                validate_shadow_witness(3, &patterns, witness.table()).unwrap();
            }
            (None, ShadowOutcome::Unsat { .. }) => {}
            (expected, actual) => {
                panic!("independent result {expected:?} disagrees with {actual:?}")
            }
        }
    }

    #[test]
    fn every_shadow_cap_abstains_without_an_unsat_claim() {
        let patterns = [complete_pattern(2, &[0, 1, 1, 0])];

        let mut caps = ShadowCaps::default();
        caps.max_patterns = 0;
        assert!(matches!(
            search_exact_pattern_shadow(&patterns, &caps),
            ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::StructuralCap {
                    resource: "patterns",
                    ..
                },
                ..
            }
        ));

        caps = ShadowCaps::default();
        caps.max_pattern_cells = 0;
        assert!(matches!(
            search_exact_pattern_shadow(&patterns, &caps),
            ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::StructuralCap {
                    resource: "pattern_cells",
                    ..
                },
                ..
            }
        ));

        caps = ShadowCaps::default();
        caps.max_permutations = 1;
        assert!(matches!(
            search_exact_pattern_shadow(&patterns, &caps),
            ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::StructuralCap {
                    resource: "permutations",
                    ..
                },
                ..
            }
        ));

        caps = ShadowCaps::default();
        caps.max_bitset_words = 0;
        assert!(matches!(
            search_exact_pattern_shadow(&patterns, &caps),
            ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::StructuralCap {
                    resource: "bitset_words",
                    ..
                },
                ..
            }
        ));

        caps = ShadowCaps::default();
        caps.max_preparation_word_ops = 0;
        assert!(matches!(
            search_exact_pattern_shadow(&patterns, &caps),
            ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::PreparationCap {
                    resource: "preparation_word_ops",
                    ..
                },
                ..
            }
        ));

        caps = ShadowCaps::default();
        caps.max_preparation_pattern_checks = 0;
        assert!(matches!(
            search_exact_pattern_shadow(&patterns, &caps),
            ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::PreparationCap {
                    resource: "preparation_pattern_checks",
                    ..
                },
                ..
            }
        ));

        caps = ShadowCaps::default();
        caps.max_search_nodes = 0;
        assert!(matches!(
            search_exact_pattern_shadow(&patterns, &caps),
            ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::SearchCap {
                    resource: "search_nodes",
                    ..
                },
                ..
            }
        ));

        caps = ShadowCaps::default();
        caps.max_candidate_checks = 0;
        assert!(matches!(
            search_exact_pattern_shadow(&patterns, &caps),
            ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::SearchCap {
                    resource: "candidate_checks",
                    ..
                },
                ..
            }
        ));

        caps = ShadowCaps::default();
        caps.max_bitset_word_ops = 0;
        assert!(matches!(
            search_exact_pattern_shadow(&patterns, &caps),
            ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::SearchCap {
                    resource: "bitset_word_ops",
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn structural_caps_precede_shadow_buffer_allocation() {
        let patterns = [complete_pattern(2, &[0, 1, 1, 0])];

        let mut caps = ShadowCaps::default();
        caps.max_patterns = 0;
        let pattern_capped = search_exact_pattern_shadow(&patterns, &caps);
        assert_eq!(pattern_capped.telemetry().patterns, 1);
        assert_eq!(pattern_capped.telemetry().pattern_cells, 0);
        assert_eq!(pattern_capped.telemetry().permutations, 0);
        assert_eq!(pattern_capped.telemetry().bitset_words, 0);

        caps = ShadowCaps::default();
        caps.max_pattern_cells = 3;
        let cell_capped = search_exact_pattern_shadow(&patterns, &caps);
        assert_eq!(cell_capped.telemetry().patterns, 1);
        assert_eq!(cell_capped.telemetry().pattern_cells, 4);
        assert_eq!(cell_capped.telemetry().permutations, 0);
        assert_eq!(cell_capped.telemetry().bitset_words, 0);

        caps = ShadowCaps::default();
        caps.max_permutations = 1;
        let permutation_capped = search_exact_pattern_shadow(&patterns, &caps);
        assert_eq!(permutation_capped.telemetry().permutations, 2);
        assert_eq!(permutation_capped.telemetry().bitset_words, 0);

        caps = ShadowCaps::default();
        caps.max_patterns = 1;
        caps.max_pattern_cells = 4;
        caps.max_permutations = 2;
        caps.max_search_nodes = 0;
        let exact_boundaries = search_exact_pattern_shadow(&patterns, &caps);
        assert!(matches!(
            exact_boundaries,
            ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::SearchCap {
                    resource: "search_nodes",
                    ..
                },
                ..
            }
        ));
        assert!(exact_boundaries.telemetry().bitset_words > 0);
    }

    #[test]
    fn checked_allocation_helpers_map_capacity_overflow_to_abstain() {
        assert!(matches!(
            reserved_vec::<u64>(usize::MAX),
            Err(ShadowAbstainReason::AllocationFailed)
        ));
        assert!(matches!(
            zeroed_words(usize::MAX),
            Err(ShadowAbstainReason::AllocationFailed)
        ));
        assert!(matches!(
            zeroed_bytes(usize::MAX),
            Err(ShadowAbstainReason::AllocationFailed)
        ));
        assert!(matches!(
            zeroed_bools(usize::MAX),
            Err(ShadowAbstainReason::AllocationFailed)
        ));
    }

    #[test]
    fn shadow_rejects_unsupported_families_and_is_deterministic() {
        let first = complete_pattern(2, &[0, 1, 1, 0]);
        assert!(matches!(
            search_exact_pattern_shadow(&[first.clone(), first], &ShadowCaps::default()),
            ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::UnsupportedStructure("duplicate forbidden patterns"),
                ..
            }
        ));
        assert!(matches!(
            search_exact_pattern_shadow(
                &[
                    forbidden_pattern(2, &[(0, 0, 0)]),
                    forbidden_pattern(2, &[(0, 0, 0), (1, 1, 1)]),
                ],
                &ShadowCaps::default(),
            ),
            ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::UnsupportedStructure("nonuniform pattern width"),
                ..
            }
        ));

        let patterns = [forbidden_pattern(3, &[(0, 0, 0), (1, 1, 1)])];
        let first = search_exact_pattern_shadow(&patterns, &ShadowCaps::default());
        let second = search_exact_pattern_shadow(&patterns, &ShadowCaps::default());
        assert_eq!(first, second);
        assert_ne!(first.telemetry().trace_hash, FNV_OFFSET);
    }

    #[test]
    fn degree_seven_shadow_preparation_is_bounded_before_search() {
        let patterns = [forbidden_pattern(
            7,
            &[(0, 6, 4), (1, 6, 0), (2, 4, 6), (3, 5, 5), (4, 2, 2)],
        )];
        let mut caps = ShadowCaps::default();
        caps.max_search_nodes = 0;
        let outcome = search_exact_pattern_shadow(&patterns, &caps);
        assert!(matches!(
            outcome,
            ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::SearchCap {
                    resource: "search_nodes",
                    ..
                },
                ..
            }
        ));
        assert_eq!(outcome.telemetry().permutations, 5_040);
    }

    #[test]
    fn audited_qg7_preparation_uses_240_candidates_per_column() {
        let reduction = audited_qg7_fixture();
        assert!(reduction.eligible());

        let mut caps = ShadowCaps::default();
        caps.max_search_nodes = 0;
        let outcome = search_qg_reduction_shadow(&reduction, &caps);
        assert!(matches!(
            outcome,
            ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::SearchCap {
                    resource: "search_nodes",
                    ..
                },
                ..
            }
        ));
        assert_eq!(outcome.telemetry().permutations, 280);
        assert_eq!(outcome.telemetry().column_candidates, 7 * 240);
        assert_eq!(outcome.telemetry().min_column_candidates, 240);
        assert_eq!(outcome.telemetry().max_column_candidates, 240);
        assert_eq!(outcome.telemetry().preparation_word_ops, 7 * 240 * 7);

        caps = ShadowCaps::default();
        caps.max_permutations = 279;
        let capped = search_qg_reduction_shadow(&reduction, &caps);
        assert!(matches!(
            capped,
            ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::StructuralCap {
                    resource: "permutations",
                    limit: 279,
                    actual: 280,
                },
                ..
            }
        ));
        assert_eq!(capped.telemetry().column_candidates, 7 * 240);
    }
}
