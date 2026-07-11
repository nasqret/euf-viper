use super::{
    BoolAtomKey, BoolExpr, Problem, SymId, TermId, finite_analysis::FiniteAnalysisContext,
};
use crate::orbit_canon::{
    BinaryTable, CheckedPermutation, LexicographicPermutations, MAX_EXHAUSTIVE_DEGREE,
};
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use sha2::{Digest, Sha256};
use std::{cmp::Ordering, fmt};

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
    MalformedPatternCandidates(usize),
    MultiplePatternFunctions(usize),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExactPatternFamily {
    pub(crate) report: PatternOrbitReport,
    pub(crate) patterns: Box<[PartialTablePattern]>,
}

/// Identity inside one SHA-256-bound parsed assertion sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SourceAssertionId {
    pub(crate) ordinal: usize,
    pub(crate) fingerprint: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QgAssertionKind {
    CarrierDistinct,
    TableClosure,
    LatinCoverage,
    LatinPairwiseDistinct,
    RightTranslationCube,
    ForbiddenPattern { pattern: usize },
    LocalConstraint { constraint: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnconsumedAssertionReason {
    UnrecognizedShape,
    PatternFunctionMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssertionDisposition {
    Consumed(QgAssertionKind),
    Unconsumed(UnconsumedAssertionReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AssertionLedgerEntry {
    pub(crate) identity: SourceAssertionId,
    pub(crate) disposition: AssertionDisposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CarrierMapping {
    pub(crate) position: usize,
    pub(crate) term: TermId,
    pub(crate) symbol: SymId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FunctionRole {
    CarrierConstant,
    TableOperation,
    Unused,
    Unrecognized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FunctionUsage {
    pub(crate) function: SymId,
    pub(crate) declared_arity: usize,
    pub(crate) occurrences: usize,
    pub(crate) application_occurrences: usize,
    pub(crate) role: FunctionRole,
}

/// Canonical Boolean formula over concrete carrier table cells.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum NormalizedLocalExpr {
    Const(bool),
    CellEquals(CellAssignment),
    Not(Box<NormalizedLocalExpr>),
    And(Box<[NormalizedLocalExpr]>),
    Or(Box<[NormalizedLocalExpr]>),
    Iff(Box<[NormalizedLocalExpr]>),
    Ite(
        Box<NormalizedLocalExpr>,
        Box<NormalizedLocalExpr>,
        Box<NormalizedLocalExpr>,
    ),
}

impl NormalizedLocalExpr {
    fn evaluate(&self, degree: usize, table: &[u8]) -> bool {
        match self {
            Self::Const(value) => *value,
            Self::CellEquals(assignment) => {
                table[assignment.row * degree + assignment.column]
                    == u8::try_from(assignment.value).expect("qg degree is at most seven")
            }
            Self::Not(inner) => !inner.evaluate(degree, table),
            Self::And(children) => children.iter().all(|child| child.evaluate(degree, table)),
            Self::Or(children) => children.iter().any(|child| child.evaluate(degree, table)),
            Self::Iff(children) => children.first().is_none_or(|first| {
                let value = first.evaluate(degree, table);
                children
                    .iter()
                    .skip(1)
                    .all(|child| child.evaluate(degree, table) == value)
            }),
            Self::Ite(condition, then_branch, else_branch) => {
                if condition.evaluate(degree, table) {
                    then_branch.evaluate(degree, table)
                } else {
                    else_branch.evaluate(degree, table)
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DirectCellConstraint {
    pub(crate) row: usize,
    pub(crate) value: usize,
    pub(crate) equal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalConstraintEnforcement {
    CandidateFilter,
    Residual,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedLocalConstraint {
    pub(crate) assertion: SourceAssertionId,
    pub(crate) formula: NormalizedLocalExpr,
    pub(crate) enforcement: LocalConstraintEnforcement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QgColumnFilter {
    pub(crate) column: usize,
    pub(crate) require_cube_identity: bool,
    pub(crate) exact_fixed_points: Option<usize>,
    pub(crate) direct: Box<[DirectCellConstraint]>,
}

impl QgColumnFilter {
    pub(crate) fn allows(&self, permutation: &[u8]) -> bool {
        if self.require_cube_identity
            && (0..permutation.len()).any(|point| {
                let once = usize::from(permutation[point]);
                let twice = usize::from(permutation[once]);
                usize::from(permutation[twice]) != point
            })
        {
            return false;
        }
        if self.exact_fixed_points.is_some_and(|expected| {
            permutation
                .iter()
                .enumerate()
                .filter(|&(point, &image)| point == usize::from(image))
                .count()
                != expected
        }) {
            return false;
        }
        self.direct.iter().all(|constraint| {
            let matches = usize::from(permutation[constraint.row]) == constraint.value;
            matches == constraint.equal
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QgIneligibility {
    MissingBooleanProblem,
    UnsupportedSource,
    CarrierOutsideSupportedRange,
    MissingTableOperation,
    PatternFamilyRejected,
    PatternOrbitNotExact,
    DuplicateForbiddenPatterns,
    MissingCarrierDistinct,
    MissingTableClosure,
    MissingLatinConstraint,
    UnrecognizedFunctionUsage,
    UnconsumedAssertions,
}

impl QgIneligibility {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::MissingBooleanProblem => "missing_boolean_problem",
            Self::UnsupportedSource => "unsupported_source",
            Self::CarrierOutsideSupportedRange => "carrier_outside_supported_range",
            Self::MissingTableOperation => "missing_table_operation",
            Self::PatternFamilyRejected => "pattern_family_rejected",
            Self::PatternOrbitNotExact => "pattern_orbit_not_exact",
            Self::DuplicateForbiddenPatterns => "duplicate_forbidden_patterns",
            Self::MissingCarrierDistinct => "missing_carrier_distinct",
            Self::MissingTableClosure => "missing_table_closure",
            Self::MissingLatinConstraint => "missing_latin_constraint",
            Self::UnrecognizedFunctionUsage => "unrecognized_function_usage",
            Self::UnconsumedAssertions => "unconsumed_assertions",
        }
    }
}

/// Test-only, source-bound reduction ledger for the qg shadow search.
///
/// Eligibility requires an exact carrier/Latin basis, an exact forbidden
/// orbit, known function usage, and a disposition for every parsed assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QgReduction {
    source_sha256: [u8; 32],
    carrier: Box<[CarrierMapping]>,
    operation: Option<SymId>,
    function_usage: Box<[FunctionUsage]>,
    assertion_ledger: Box<[AssertionLedgerEntry]>,
    local_constraints: Box<[NormalizedLocalConstraint]>,
    column_filters: Box<[QgColumnFilter]>,
    candidate_counts: Box<[usize]>,
    patterns: Box<[PartialTablePattern]>,
    pattern_report: Option<PatternOrbitReport>,
    pattern_error: Option<ProbeError>,
    ineligibility: Box<[QgIneligibility]>,
}

impl QgReduction {
    pub(crate) fn audit(source: &str, problem: &Problem) -> Self {
        audit_qg_reduction(source, problem)
    }

    pub(crate) fn source_sha256(&self) -> &[u8; 32] {
        &self.source_sha256
    }

    pub(crate) fn source_sha256_hex(&self) -> String {
        let mut output = String::with_capacity(64);
        for byte in self.source_sha256 {
            use fmt::Write;
            write!(&mut output, "{byte:02x}").expect("writing to a string cannot fail");
        }
        output
    }

    pub(crate) fn carrier(&self) -> &[CarrierMapping] {
        &self.carrier
    }

    pub(crate) fn degree(&self) -> usize {
        self.carrier.len()
    }

    pub(crate) fn operation(&self) -> Option<SymId> {
        self.operation
    }

    pub(crate) fn function_usage(&self) -> &[FunctionUsage] {
        &self.function_usage
    }

    pub(crate) fn assertion_ledger(&self) -> &[AssertionLedgerEntry] {
        &self.assertion_ledger
    }

    pub(crate) fn consumed_assertions(&self) -> impl Iterator<Item = SourceAssertionId> + '_ {
        self.assertion_ledger.iter().filter_map(|entry| {
            matches!(entry.disposition, AssertionDisposition::Consumed(_)).then_some(entry.identity)
        })
    }

    pub(crate) fn unconsumed_assertions(&self) -> impl Iterator<Item = SourceAssertionId> + '_ {
        self.assertion_ledger.iter().filter_map(|entry| {
            matches!(entry.disposition, AssertionDisposition::Unconsumed(_))
                .then_some(entry.identity)
        })
    }

    pub(crate) fn local_constraints(&self) -> &[NormalizedLocalConstraint] {
        &self.local_constraints
    }

    pub(crate) fn remaining_predicates(&self) -> impl Iterator<Item = &NormalizedLocalConstraint> {
        self.local_constraints
            .iter()
            .filter(|constraint| constraint.enforcement == LocalConstraintEnforcement::Residual)
    }

    pub(crate) fn column_filters(&self) -> &[QgColumnFilter] {
        &self.column_filters
    }

    pub(crate) fn candidate_counts(&self) -> &[usize] {
        &self.candidate_counts
    }

    pub(crate) fn patterns(&self) -> &[PartialTablePattern] {
        &self.patterns
    }

    pub(crate) fn pattern_report(&self) -> Option<&PatternOrbitReport> {
        self.pattern_report.as_ref()
    }

    pub(crate) fn pattern_error(&self) -> Option<&ProbeError> {
        self.pattern_error.as_ref()
    }

    pub(crate) fn ineligibility(&self) -> &[QgIneligibility] {
        &self.ineligibility
    }

    pub(crate) fn eligible(&self) -> bool {
        self.ineligibility.is_empty()
    }

    pub(crate) fn first_ineligibility_code(&self) -> &'static str {
        self.ineligibility
            .first()
            .copied()
            .map(QgIneligibility::code)
            .unwrap_or("none")
    }

    pub(crate) fn validate_local_constraints(&self, table: &[u8]) -> Result<(), SourceAssertionId> {
        let expected = self.degree().checked_mul(self.degree());
        if expected != Some(table.len()) {
            return Err(SourceAssertionId {
                ordinal: usize::MAX,
                fingerprint: 0,
            });
        }
        for constraint in &self.local_constraints {
            if !constraint.formula.evaluate(self.degree(), table) {
                return Err(constraint.assertion);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateShape {
    NotCandidate,
    Malformed,
}

const QG_MAX_DEGREE: usize = 7;
const ASSERTION_FNV_OFFSET: u64 = 0xcbf29ce484222325;
const ASSERTION_FNV_PRIME: u64 = 0x100000001b3;

fn audit_qg_reduction(source: &str, problem: &Problem) -> QgReduction {
    let source_sha256: [u8; 32] = Sha256::digest(source.as_bytes()).into();
    let mut ineligibility = Vec::new();
    let Some(bool_problem) = problem.bool_problem.as_ref() else {
        return QgReduction {
            source_sha256,
            carrier: Box::new([]),
            operation: None,
            function_usage: Box::new([]),
            assertion_ledger: Box::new([]),
            local_constraints: Box::new([]),
            column_filters: Box::new([]),
            candidate_counts: Box::new([]),
            patterns: Box::new([]),
            pattern_report: None,
            pattern_error: None,
            ineligibility: Box::new([QgIneligibility::MissingBooleanProblem]),
        };
    };
    if !problem.unsupported.is_empty()
        || !bool_problem.unsupported.is_empty()
        || problem.contradiction
    {
        push_ineligibility(&mut ineligibility, QgIneligibility::UnsupportedSource);
    }

    let mut finite = FiniteAnalysisContext::default();
    let domain = finite
        .domain_analysis(&problem.arena, bool_problem)
        .domain
        .clone();
    if !(2..=QG_MAX_DEGREE).contains(&domain.len()) {
        push_ineligibility(
            &mut ineligibility,
            QgIneligibility::CarrierOutsideSupportedRange,
        );
    }
    let domain_positions = domain
        .iter()
        .enumerate()
        .map(|(position, &term)| (term, position))
        .collect::<HashMap<_, _>>();
    let carrier = domain
        .iter()
        .enumerate()
        .filter_map(|(position, &term)| {
            problem
                .arena
                .terms
                .get(term)
                .map(|term_data| CarrierMapping {
                    position,
                    term,
                    symbol: term_data.fun,
                })
        })
        .collect::<Vec<_>>();
    if carrier.len() != domain.len()
        || carrier.iter().any(|mapping| {
            problem.arena.terms[mapping.term].args.len() != 0
                || problem.arena.terms[mapping.term].fun != mapping.symbol
        })
    {
        push_ineligibility(
            &mut ineligibility,
            QgIneligibility::CarrierOutsideSupportedRange,
        );
    }

    let family_result = extract_forbidden_pattern_family(problem);
    let (patterns, pattern_report, pattern_error, family_operation) = match family_result {
        Ok(family) => {
            if !family.report.exact_first_orbit_cover {
                push_ineligibility(&mut ineligibility, QgIneligibility::PatternOrbitNotExact);
            }
            if family.report.duplicate_exclusions != 0 {
                push_ineligibility(
                    &mut ineligibility,
                    QgIneligibility::DuplicateForbiddenPatterns,
                );
            }
            let operation = Some(family.report.function);
            (family.patterns, Some(family.report), None, operation)
        }
        Err(error) => {
            push_ineligibility(&mut ineligibility, QgIneligibility::PatternFamilyRejected);
            (
                Vec::<PartialTablePattern>::new().into_boxed_slice(),
                None,
                Some(error),
                None,
            )
        }
    };
    let operation = family_operation
        .or_else(|| infer_unique_table_operation(&problem.arena, &domain_positions));
    if operation.is_none() {
        push_ineligibility(&mut ineligibility, QgIneligibility::MissingTableOperation);
    }

    let mut assertion_ledger = Vec::with_capacity(bool_problem.assertions.len());
    let mut local_constraints = Vec::new();
    let mut direct_by_column = vec![Vec::new(); domain.len()];
    let mut pattern_index = 0;
    let mut saw_carrier_distinct = false;
    let mut saw_closure = false;
    let mut saw_latin = false;
    let mut saw_cube = false;

    for (ordinal, assertion) in bool_problem.assertions.iter().enumerate() {
        let identity = SourceAssertionId {
            ordinal,
            fingerprint: assertion_fingerprint(assertion, &problem.arena),
        };
        let mut disposition = None;
        if let Some(operation) = operation {
            if let Some(pattern) =
                pattern_from_assertion(assertion, &problem.arena, &domain_positions, domain.len())
            {
                disposition = Some(if pattern.function == operation {
                    let index = pattern_index;
                    pattern_index += 1;
                    AssertionDisposition::Consumed(QgAssertionKind::ForbiddenPattern {
                        pattern: index,
                    })
                } else {
                    AssertionDisposition::Unconsumed(
                        UnconsumedAssertionReason::PatternFunctionMismatch,
                    )
                });
            } else if is_exact_carrier_distinct(assertion, &domain_positions) {
                saw_carrier_distinct = true;
                disposition = Some(AssertionDisposition::Consumed(
                    QgAssertionKind::CarrierDistinct,
                ));
            } else if is_exact_table_closure(
                assertion,
                &problem.arena,
                &domain_positions,
                domain.len(),
                operation,
            ) {
                saw_closure = true;
                disposition = Some(AssertionDisposition::Consumed(
                    QgAssertionKind::TableClosure,
                ));
            } else if is_exact_latin_coverage(
                assertion,
                &problem.arena,
                &domain_positions,
                domain.len(),
                operation,
            ) {
                saw_latin = true;
                disposition = Some(AssertionDisposition::Consumed(
                    QgAssertionKind::LatinCoverage,
                ));
            } else if is_exact_latin_pairwise(
                assertion,
                &problem.arena,
                &domain_positions,
                domain.len(),
                operation,
            ) {
                saw_latin = true;
                disposition = Some(AssertionDisposition::Consumed(
                    QgAssertionKind::LatinPairwiseDistinct,
                ));
            } else if is_exact_right_translation_cube(
                assertion,
                &problem.arena,
                &domain_positions,
                domain.len(),
                operation,
            ) {
                saw_cube = true;
                disposition = Some(AssertionDisposition::Consumed(
                    QgAssertionKind::RightTranslationCube,
                ));
            } else if let Some(formula) =
                normalize_local_expression(assertion, &problem.arena, &domain_positions, operation)
            {
                let mut direct = Vec::new();
                let fully_filtered = collect_conjunctive_direct_constraints(&formula, &mut direct);
                direct.sort_unstable();
                direct.dedup();
                for &(assignment, equal) in &direct {
                    direct_by_column[assignment.column].push(DirectCellConstraint {
                        row: assignment.row,
                        value: assignment.value,
                        equal,
                    });
                }
                let constraint = local_constraints.len();
                local_constraints.push(NormalizedLocalConstraint {
                    assertion: identity,
                    formula,
                    enforcement: if fully_filtered {
                        LocalConstraintEnforcement::CandidateFilter
                    } else {
                        LocalConstraintEnforcement::Residual
                    },
                });
                disposition = Some(AssertionDisposition::Consumed(
                    QgAssertionKind::LocalConstraint { constraint },
                ));
            }
        }
        assertion_ledger.push(AssertionLedgerEntry {
            identity,
            disposition: disposition.unwrap_or(AssertionDisposition::Unconsumed(
                UnconsumedAssertionReason::UnrecognizedShape,
            )),
        });
    }

    if !saw_carrier_distinct {
        push_ineligibility(&mut ineligibility, QgIneligibility::MissingCarrierDistinct);
    }
    if !saw_closure {
        push_ineligibility(&mut ineligibility, QgIneligibility::MissingTableClosure);
    }
    if !saw_latin {
        push_ineligibility(&mut ineligibility, QgIneligibility::MissingLatinConstraint);
    }
    if assertion_ledger
        .iter()
        .any(|entry| matches!(entry.disposition, AssertionDisposition::Unconsumed(_)))
    {
        push_ineligibility(&mut ineligibility, QgIneligibility::UnconsumedAssertions);
    }
    if pattern_index != patterns.len() {
        push_ineligibility(&mut ineligibility, QgIneligibility::PatternFamilyRejected);
    }

    let function_usage = collect_function_usage(problem, &carrier, operation, bool_problem);
    if function_usage
        .iter()
        .any(|usage| usage.occurrences != 0 && usage.role == FunctionRole::Unrecognized)
    {
        push_ineligibility(
            &mut ineligibility,
            QgIneligibility::UnrecognizedFunctionUsage,
        );
    }

    let mut column_filters = Vec::new();
    let mut candidate_counts = Vec::new();
    if (2..=QG_MAX_DEGREE).contains(&domain.len()) {
        // Seven order-three permutations have at least one fixed point each.
        // Latin rows make their total fixed-point count exactly seven.
        let exact_one_fixed_point = domain.len() == 7 && saw_latin && saw_cube;
        column_filters.reserve(domain.len());
        candidate_counts.reserve(domain.len());
        for column in 0..domain.len() {
            direct_by_column[column].sort_unstable();
            direct_by_column[column].dedup();
            let filter = QgColumnFilter {
                column,
                require_cube_identity: saw_cube,
                exact_fixed_points: exact_one_fixed_point.then_some(1),
                direct: std::mem::take(&mut direct_by_column[column]).into_boxed_slice(),
            };
            candidate_counts.push(count_filter_candidates(domain.len(), &filter));
            column_filters.push(filter);
        }
    }

    QgReduction {
        source_sha256,
        carrier: carrier.into_boxed_slice(),
        operation,
        function_usage: function_usage.into_boxed_slice(),
        assertion_ledger: assertion_ledger.into_boxed_slice(),
        local_constraints: local_constraints.into_boxed_slice(),
        column_filters: column_filters.into_boxed_slice(),
        candidate_counts: candidate_counts.into_boxed_slice(),
        patterns,
        pattern_report,
        pattern_error,
        ineligibility: ineligibility.into_boxed_slice(),
    }
}

fn push_ineligibility(reasons: &mut Vec<QgIneligibility>, reason: QgIneligibility) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

fn infer_unique_table_operation(
    arena: &super::TermArena,
    domain_positions: &HashMap<TermId, usize>,
) -> Option<SymId> {
    let operations = arena
        .terms
        .iter()
        .filter(|term| {
            term.args.len() == 2
                && term
                    .args
                    .iter()
                    .all(|argument| domain_positions.contains_key(argument))
        })
        .map(|term| term.fun)
        .collect::<HashSet<_>>();
    (operations.len() == 1).then(|| *operations.iter().next().unwrap())
}

fn pattern_from_assertion(
    assertion: &BoolExpr,
    arena: &super::TermArena,
    domain_positions: &HashMap<TermId, usize>,
    degree: usize,
) -> Option<ExtractedPattern> {
    let BoolExpr::Not(inner) = assertion else {
        return None;
    };
    let mut equalities = Vec::new();
    collect_conjunctive_equalities(inner, &mut equalities)
        .then(|| extract_partial_pattern(arena, domain_positions, degree, &equalities).ok())
        .flatten()
}

fn collect_and_leaves<'a>(expression: &'a BoolExpr, output: &mut Vec<&'a BoolExpr>) {
    match expression {
        BoolExpr::And(children) => {
            for child in children {
                collect_and_leaves(child, output);
            }
        }
        expression => output.push(expression),
    }
}

fn collect_or_leaves<'a>(expression: &'a BoolExpr, output: &mut Vec<&'a BoolExpr>) {
    match expression {
        BoolExpr::Or(children) => {
            for child in children {
                collect_or_leaves(child, output);
            }
        }
        expression => output.push(expression),
    }
}

fn negative_equality(expression: &BoolExpr) -> Option<(TermId, TermId)> {
    let BoolExpr::Not(inner) = expression else {
        return None;
    };
    let BoolExpr::Atom(BoolAtomKey::Eq(left, right)) = inner.as_ref() else {
        return None;
    };
    Some((*left, *right))
}

fn positive_equality(expression: &BoolExpr) -> Option<(TermId, TermId)> {
    let BoolExpr::Atom(BoolAtomKey::Eq(left, right)) = expression else {
        return None;
    };
    Some((*left, *right))
}

fn is_exact_carrier_distinct(
    assertion: &BoolExpr,
    domain_positions: &HashMap<TermId, usize>,
) -> bool {
    let degree = domain_positions.len();
    let mut leaves = Vec::new();
    collect_and_leaves(assertion, &mut leaves);
    if leaves.len() != degree.saturating_mul(degree.saturating_sub(1)) / 2 {
        return false;
    }
    let mut pairs = HashSet::default();
    for leaf in leaves {
        let Some((left, right)) = negative_equality(leaf) else {
            return false;
        };
        let (Some(&left), Some(&right)) =
            (domain_positions.get(&left), domain_positions.get(&right))
        else {
            return false;
        };
        if left == right {
            return false;
        }
        pairs.insert(if left < right {
            (left, right)
        } else {
            (right, left)
        });
    }
    pairs.len() == leaves_pair_count(degree)
}

fn leaves_pair_count(degree: usize) -> usize {
    degree.saturating_mul(degree.saturating_sub(1)) / 2
}

fn direct_cell_assignment(
    expression: &BoolExpr,
    arena: &super::TermArena,
    domain_positions: &HashMap<TermId, usize>,
    operation: SymId,
) -> Option<CellAssignment> {
    let (left, right) = positive_equality(expression)?;
    let (function, row, column, value) = table_cell(arena, domain_positions, left, right)
        .or_else(|| table_cell(arena, domain_positions, right, left))?;
    (function == operation).then_some(CellAssignment { row, column, value })
}

fn is_exact_table_closure(
    assertion: &BoolExpr,
    arena: &super::TermArena,
    domain_positions: &HashMap<TermId, usize>,
    degree: usize,
    operation: SymId,
) -> bool {
    let mut conjuncts = Vec::new();
    collect_and_leaves(assertion, &mut conjuncts);
    if conjuncts.len() != degree.saturating_mul(degree) {
        return false;
    }
    let mut cells = HashSet::default();
    for conjunct in conjuncts {
        let mut disjuncts = Vec::new();
        collect_or_leaves(conjunct, &mut disjuncts);
        if disjuncts.len() != degree {
            return false;
        }
        let Some(first) = direct_cell_assignment(disjuncts[0], arena, domain_positions, operation)
        else {
            return false;
        };
        let mut values = HashSet::default();
        for disjunct in disjuncts {
            let Some(assignment) =
                direct_cell_assignment(disjunct, arena, domain_positions, operation)
            else {
                return false;
            };
            if assignment.row != first.row || assignment.column != first.column {
                return false;
            }
            values.insert(assignment.value);
        }
        if values.len() != degree {
            return false;
        }
        cells.insert((first.row, first.column));
    }
    cells.len() == degree.saturating_mul(degree)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum LatinCoverageGroup {
    RowValue { row: usize, value: usize },
    ColumnValue { column: usize, value: usize },
}

fn is_exact_latin_coverage(
    assertion: &BoolExpr,
    arena: &super::TermArena,
    domain_positions: &HashMap<TermId, usize>,
    degree: usize,
    operation: SymId,
) -> bool {
    let mut conjuncts = Vec::new();
    collect_and_leaves(assertion, &mut conjuncts);
    if conjuncts.len() != 2_usize.saturating_mul(degree).saturating_mul(degree) {
        return false;
    }
    let mut groups = HashSet::default();
    for conjunct in conjuncts {
        let mut disjuncts = Vec::new();
        collect_or_leaves(conjunct, &mut disjuncts);
        if disjuncts.len() != degree {
            return false;
        }
        let assignments = disjuncts
            .iter()
            .map(|expression| {
                direct_cell_assignment(expression, arena, domain_positions, operation)
            })
            .collect::<Option<Vec<_>>>();
        let Some(assignments) = assignments else {
            return false;
        };
        let first = assignments[0];
        if assignments
            .iter()
            .all(|assignment| assignment.row == first.row && assignment.value == first.value)
            && assignments
                .iter()
                .map(|assignment| assignment.column)
                .collect::<HashSet<_>>()
                .len()
                == degree
        {
            groups.insert(LatinCoverageGroup::RowValue {
                row: first.row,
                value: first.value,
            });
        } else if assignments
            .iter()
            .all(|assignment| assignment.column == first.column && assignment.value == first.value)
            && assignments
                .iter()
                .map(|assignment| assignment.row)
                .collect::<HashSet<_>>()
                .len()
                == degree
        {
            groups.insert(LatinCoverageGroup::ColumnValue {
                column: first.column,
                value: first.value,
            });
        } else {
            return false;
        }
    }
    groups.len() == 2 * degree * degree
}

fn direct_table_cell(
    arena: &super::TermArena,
    domain_positions: &HashMap<TermId, usize>,
    operation: SymId,
    term: TermId,
) -> Option<(usize, usize)> {
    let term = arena.terms.get(term)?;
    let [row, column] = term.args.as_slice() else {
        return None;
    };
    (term.fun == operation).then_some((*domain_positions.get(row)?, *domain_positions.get(column)?))
}

fn is_exact_latin_pairwise(
    assertion: &BoolExpr,
    arena: &super::TermArena,
    domain_positions: &HashMap<TermId, usize>,
    degree: usize,
    operation: SymId,
) -> bool {
    let mut leaves = Vec::new();
    collect_and_leaves(assertion, &mut leaves);
    let expected = 2_usize
        .saturating_mul(degree)
        .saturating_mul(leaves_pair_count(degree));
    if leaves.len() != expected {
        return false;
    }
    let mut pairs = HashSet::default();
    for leaf in leaves {
        let Some((left, right)) = negative_equality(leaf) else {
            return false;
        };
        let (Some(left), Some(right)) = (
            direct_table_cell(arena, domain_positions, operation, left),
            direct_table_cell(arena, domain_positions, operation, right),
        ) else {
            return false;
        };
        if left == right || (left.0 != right.0 && left.1 != right.1) {
            return false;
        }
        pairs.insert(if left < right {
            (left, right)
        } else {
            (right, left)
        });
    }
    pairs.len() == expected
}

fn cube_identity_cell(
    expression: &BoolExpr,
    arena: &super::TermArena,
    domain_positions: &HashMap<TermId, usize>,
    operation: SymId,
) -> Option<(usize, usize)> {
    let (left, right) = positive_equality(expression)?;
    cube_identity_terms(arena, domain_positions, operation, left, right)
        .or_else(|| cube_identity_terms(arena, domain_positions, operation, right, left))
}

fn cube_identity_terms(
    arena: &super::TermArena,
    domain_positions: &HashMap<TermId, usize>,
    operation: SymId,
    cube: TermId,
    original: TermId,
) -> Option<(usize, usize)> {
    let row = *domain_positions.get(&original)?;
    let outer = arena.terms.get(cube)?;
    let [square, outer_column] = outer.args.as_slice() else {
        return None;
    };
    if outer.fun != operation {
        return None;
    }
    let middle = arena.terms.get(*square)?;
    let [once, middle_column] = middle.args.as_slice() else {
        return None;
    };
    if middle.fun != operation {
        return None;
    }
    let inner = arena.terms.get(*once)?;
    let [inner_row, inner_column] = inner.args.as_slice() else {
        return None;
    };
    if inner.fun != operation || *inner_row != original {
        return None;
    }
    let column = *domain_positions.get(inner_column)?;
    (*domain_positions.get(middle_column)? == column
        && *domain_positions.get(outer_column)? == column)
        .then_some((row, column))
}

fn is_exact_right_translation_cube(
    assertion: &BoolExpr,
    arena: &super::TermArena,
    domain_positions: &HashMap<TermId, usize>,
    degree: usize,
    operation: SymId,
) -> bool {
    let mut leaves = Vec::new();
    collect_and_leaves(assertion, &mut leaves);
    if leaves.len() != degree.saturating_mul(degree) {
        return false;
    }
    let cells = leaves
        .into_iter()
        .map(|leaf| cube_identity_cell(leaf, arena, domain_positions, operation))
        .collect::<Option<HashSet<_>>>();
    cells.is_some_and(|cells| cells.len() == degree * degree)
}

fn normalize_local_expression(
    expression: &BoolExpr,
    arena: &super::TermArena,
    domain_positions: &HashMap<TermId, usize>,
    operation: SymId,
) -> Option<NormalizedLocalExpr> {
    match expression {
        BoolExpr::Const(value) => Some(NormalizedLocalExpr::Const(*value)),
        BoolExpr::Atom(BoolAtomKey::Eq(_, _)) => {
            direct_cell_assignment(expression, arena, domain_positions, operation)
                .map(NormalizedLocalExpr::CellEquals)
        }
        BoolExpr::Atom(BoolAtomKey::BoolTerm(_)) => None,
        BoolExpr::Not(inner) => {
            let inner = normalize_local_expression(inner, arena, domain_positions, operation)?;
            Some(match inner {
                NormalizedLocalExpr::Const(value) => NormalizedLocalExpr::Const(!value),
                NormalizedLocalExpr::Not(grandchild) => *grandchild,
                inner => NormalizedLocalExpr::Not(Box::new(inner)),
            })
        }
        BoolExpr::And(children) => {
            normalize_local_variadic(children, arena, domain_positions, operation, true)
        }
        BoolExpr::Or(children) => {
            normalize_local_variadic(children, arena, domain_positions, operation, false)
        }
        BoolExpr::Iff(children) => {
            let mut normalized = children
                .iter()
                .map(|child| normalize_local_expression(child, arena, domain_positions, operation))
                .collect::<Option<Vec<_>>>()?;
            normalized.sort_unstable();
            normalized.dedup();
            Some(NormalizedLocalExpr::Iff(normalized.into_boxed_slice()))
        }
        BoolExpr::Ite(condition, then_branch, else_branch) => Some(NormalizedLocalExpr::Ite(
            Box::new(normalize_local_expression(
                condition,
                arena,
                domain_positions,
                operation,
            )?),
            Box::new(normalize_local_expression(
                then_branch,
                arena,
                domain_positions,
                operation,
            )?),
            Box::new(normalize_local_expression(
                else_branch,
                arena,
                domain_positions,
                operation,
            )?),
        )),
    }
}

fn normalize_local_variadic(
    children: &[BoolExpr],
    arena: &super::TermArena,
    domain_positions: &HashMap<TermId, usize>,
    operation: SymId,
    conjunction: bool,
) -> Option<NormalizedLocalExpr> {
    let mut normalized = Vec::new();
    for child in children {
        let child = normalize_local_expression(child, arena, domain_positions, operation)?;
        match (conjunction, child) {
            (true, NormalizedLocalExpr::And(grandchildren))
            | (false, NormalizedLocalExpr::Or(grandchildren)) => {
                normalized.extend(grandchildren.into_vec());
            }
            (_, child) => normalized.push(child),
        }
    }
    normalized.sort_unstable();
    normalized.dedup();
    Some(if conjunction {
        NormalizedLocalExpr::And(normalized.into_boxed_slice())
    } else {
        NormalizedLocalExpr::Or(normalized.into_boxed_slice())
    })
}

fn collect_conjunctive_direct_constraints(
    expression: &NormalizedLocalExpr,
    output: &mut Vec<(CellAssignment, bool)>,
) -> bool {
    match expression {
        NormalizedLocalExpr::CellEquals(assignment) => {
            output.push((*assignment, true));
            true
        }
        NormalizedLocalExpr::Not(inner) => {
            let NormalizedLocalExpr::CellEquals(assignment) = inner.as_ref() else {
                return false;
            };
            output.push((*assignment, false));
            true
        }
        NormalizedLocalExpr::And(children) => children
            .iter()
            .all(|child| collect_conjunctive_direct_constraints(child, output)),
        _ => false,
    }
}

fn assertion_fingerprint(expression: &BoolExpr, arena: &super::TermArena) -> u64 {
    let mut hash = ASSERTION_FNV_OFFSET;
    hash_boolean_expression(&mut hash, expression, arena);
    hash
}

fn hash_byte(hash: &mut u64, byte: u8) {
    *hash ^= u64::from(byte);
    *hash = hash.wrapping_mul(ASSERTION_FNV_PRIME);
}

fn hash_usize(hash: &mut u64, value: usize) {
    for byte in value.to_le_bytes() {
        hash_byte(hash, byte);
    }
}

fn hash_u32(hash: &mut u64, value: u32) {
    for byte in value.to_le_bytes() {
        hash_byte(hash, byte);
    }
}

fn hash_boolean_expression(hash: &mut u64, expression: &BoolExpr, arena: &super::TermArena) {
    match expression {
        BoolExpr::Const(value) => {
            hash_byte(hash, 0);
            hash_byte(hash, u8::from(*value));
        }
        BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
            hash_byte(hash, 1);
            hash_term(hash, *left, arena);
            hash_term(hash, *right, arena);
        }
        BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => {
            hash_byte(hash, 2);
            hash_term(hash, *term, arena);
        }
        BoolExpr::Not(inner) => {
            hash_byte(hash, 3);
            hash_boolean_expression(hash, inner, arena);
        }
        BoolExpr::And(children) => {
            hash_byte(hash, 4);
            hash_usize(hash, children.len());
            for child in children {
                hash_boolean_expression(hash, child, arena);
            }
        }
        BoolExpr::Or(children) => {
            hash_byte(hash, 5);
            hash_usize(hash, children.len());
            for child in children {
                hash_boolean_expression(hash, child, arena);
            }
        }
        BoolExpr::Iff(children) => {
            hash_byte(hash, 6);
            hash_usize(hash, children.len());
            for child in children {
                hash_boolean_expression(hash, child, arena);
            }
        }
        BoolExpr::Ite(condition, then_branch, else_branch) => {
            hash_byte(hash, 7);
            hash_boolean_expression(hash, condition, arena);
            hash_boolean_expression(hash, then_branch, arena);
            hash_boolean_expression(hash, else_branch, arena);
        }
    }
}

fn hash_term(hash: &mut u64, term_id: TermId, arena: &super::TermArena) {
    let Some(term) = arena.terms.get(term_id) else {
        hash_byte(hash, u8::MAX);
        hash_usize(hash, term_id);
        return;
    };
    hash_u32(hash, term.fun);
    hash_u32(hash, term.sort.0);
    hash_usize(hash, term.args.len());
    for argument in &term.args {
        hash_term(hash, *argument, arena);
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct FunctionOccurrenceCount {
    occurrences: usize,
    application_occurrences: usize,
}

fn collect_function_usage(
    problem: &Problem,
    carrier: &[CarrierMapping],
    operation: Option<SymId>,
    bool_problem: &super::BoolProblem,
) -> Vec<FunctionUsage> {
    let mut counts: HashMap<SymId, FunctionOccurrenceCount> = HashMap::default();
    for assertion in &bool_problem.assertions {
        count_expression_functions(assertion, &problem.arena, &mut counts);
    }
    let carrier_symbols = carrier
        .iter()
        .map(|mapping| mapping.symbol)
        .collect::<HashSet<_>>();
    let mut usages = problem
        .fun_decls
        .slots
        .iter()
        .enumerate()
        .filter_map(|(index, declaration)| {
            let declaration = declaration.as_ref()?;
            let function = SymId::try_from(index).ok()?;
            let count = counts.get(&function).copied().unwrap_or_default();
            let role = if carrier_symbols.contains(&function) {
                FunctionRole::CarrierConstant
            } else if operation == Some(function) {
                FunctionRole::TableOperation
            } else if count.occurrences == 0 {
                FunctionRole::Unused
            } else {
                FunctionRole::Unrecognized
            };
            Some(FunctionUsage {
                function,
                declared_arity: declaration.arg_sorts.len(),
                occurrences: count.occurrences,
                application_occurrences: count.application_occurrences,
                role,
            })
        })
        .collect::<Vec<_>>();
    usages.sort_unstable_by_key(|usage| usage.function);
    usages
}

fn count_expression_functions(
    expression: &BoolExpr,
    arena: &super::TermArena,
    counts: &mut HashMap<SymId, FunctionOccurrenceCount>,
) {
    match expression {
        BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
            count_term_functions(*left, arena, counts);
            count_term_functions(*right, arena, counts);
        }
        BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => {
            count_term_functions(*term, arena, counts);
        }
        BoolExpr::Not(inner) => count_expression_functions(inner, arena, counts),
        BoolExpr::And(children) | BoolExpr::Or(children) | BoolExpr::Iff(children) => {
            for child in children {
                count_expression_functions(child, arena, counts);
            }
        }
        BoolExpr::Ite(condition, then_branch, else_branch) => {
            count_expression_functions(condition, arena, counts);
            count_expression_functions(then_branch, arena, counts);
            count_expression_functions(else_branch, arena, counts);
        }
        BoolExpr::Const(_) => {}
    }
}

fn count_term_functions(
    term_id: TermId,
    arena: &super::TermArena,
    counts: &mut HashMap<SymId, FunctionOccurrenceCount>,
) {
    let Some(term) = arena.terms.get(term_id) else {
        return;
    };
    let count = counts.entry(term.fun).or_default();
    count.occurrences = count.occurrences.saturating_add(1);
    if !term.args.is_empty() {
        count.application_occurrences = count.application_occurrences.saturating_add(1);
    }
    for argument in &term.args {
        count_term_functions(*argument, arena, counts);
    }
}

fn count_filter_candidates(degree: usize, filter: &QgColumnFilter) -> usize {
    if degree == 0 {
        return 0;
    }
    let mut permutation = (0..degree)
        .map(|value| u8::try_from(value).expect("qg degree is at most seven"))
        .collect::<Vec<_>>();
    let mut count = 0;
    loop {
        count += usize::from(filter.allows(&permutation));
        if !advance_u8_permutation(&mut permutation) {
            return count;
        }
    }
}

fn advance_u8_permutation(values: &mut [u8]) -> bool {
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
    extract_forbidden_pattern_family(problem).map(|family| family.report)
}

pub(crate) fn extract_forbidden_pattern_family(
    problem: &Problem,
) -> Result<ExactPatternFamily, ProbeError> {
    let (degree, extracted, telemetry) = extract_exact_patterns(problem)?;
    if telemetry.malformed_pattern_candidates != 0 {
        return Err(ProbeError::MalformedPatternCandidates(
            telemetry.malformed_pattern_candidates,
        ));
    }
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
    if by_function.len() != 1 {
        return Err(ProbeError::MultiplePatternFunctions(by_function.len()));
    }
    let (function, patterns) = by_function
        .into_iter()
        .next()
        .expect("nonempty single-function extraction has one group");
    let report = report_for_patterns(degree, function, &patterns, telemetry)?;
    Ok(ExactPatternFamily {
        report,
        patterns: patterns.into_boxed_slice(),
    })
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
            if expression_mentions_domain_table_equality(inner, &problem.arena, &domain_positions) {
                telemetry.table_shaped_conjunctions += 1;
                telemetry.malformed_pattern_candidates += 1;
                telemetry.malformed_table_candidates += 1;
            }
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

fn expression_mentions_domain_table_equality(
    expression: &BoolExpr,
    arena: &super::TermArena,
    domain_positions: &HashMap<TermId, usize>,
) -> bool {
    match expression {
        BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
            term_contains_domain_table(arena, domain_positions, *left)
                || term_contains_domain_table(arena, domain_positions, *right)
        }
        BoolExpr::Not(inner) => {
            expression_mentions_domain_table_equality(inner, arena, domain_positions)
        }
        BoolExpr::And(children) | BoolExpr::Or(children) | BoolExpr::Iff(children) => children
            .iter()
            .any(|child| expression_mentions_domain_table_equality(child, arena, domain_positions)),
        BoolExpr::Ite(condition, then_branch, else_branch) => {
            expression_mentions_domain_table_equality(condition, arena, domain_positions)
                || expression_mentions_domain_table_equality(then_branch, arena, domain_positions)
                || expression_mentions_domain_table_equality(else_branch, arena, domain_positions)
        }
        BoolExpr::Const(_) | BoolExpr::Atom(BoolAtomKey::BoolTerm(_)) => false,
    }
}

fn term_contains_domain_table(
    arena: &super::TermArena,
    domain_positions: &HashMap<TermId, usize>,
    term_id: TermId,
) -> bool {
    let Some(term) = arena.terms.get(term_id) else {
        return false;
    };
    term_mentions_domain_table(arena, domain_positions, term_id)
        || term
            .args
            .iter()
            .any(|argument| term_contains_domain_table(arena, domain_positions, *argument))
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
    use crate::right_translation_exact_cover::{
        ShadowAbstainReason, ShadowCaps, ShadowOutcome, search_qg_reduction_shadow,
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

    fn pattern_family_source(patterns: &[PartialTablePattern], extra_assertions: &str) -> String {
        let exclusions = patterns
            .iter()
            .map(|pattern| {
                let equalities = pattern
                    .assignments()
                    .iter()
                    .map(|assignment| {
                        format!(
                            "(= (op e{} e{}) e{})",
                            assignment.row, assignment.column, assignment.value
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("(assert (not (and {equalities})))")
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "(set-logic QF_UF)\n\
             (declare-sort I 0)\n\
             (declare-fun e0 () I)\n\
             (declare-fun e1 () I)\n\
             (declare-fun e2 () I)\n\
             (declare-fun op (I I) I)\n\
             (assert (distinct e0 e1 e2))\n\
             {exclusions}\n\
             {extra_assertions}\n\
             (check-sat)\n"
        )
    }

    fn qg7_reduction_fixture() -> &'static str {
        include_str!("../tests/fixtures/qg7_reduction_phase1.smt2")
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

    fn env_usize(name: &str, default: usize) -> usize {
        match env::var(name) {
            Ok(value) => value
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("{name} must be a nonnegative integer, got {value:?}")),
            Err(env::VarError::NotPresent) => default,
            Err(error) => panic!("failed to read {name}: {error}"),
        }
    }

    fn qg7_shadow_caps_from_env() -> ShadowCaps {
        let defaults = ShadowCaps::default();
        ShadowCaps {
            max_patterns: env_usize("EUF_VIPER_QG7_RTXC_MAX_PATTERNS", defaults.max_patterns),
            max_pattern_cells: env_usize(
                "EUF_VIPER_QG7_RTXC_MAX_PATTERN_CELLS",
                defaults.max_pattern_cells,
            ),
            max_permutations: env_usize(
                "EUF_VIPER_QG7_RTXC_MAX_PERMUTATIONS",
                defaults.max_permutations,
            ),
            max_bitset_words: env_usize(
                "EUF_VIPER_QG7_RTXC_MAX_BITSET_WORDS",
                defaults.max_bitset_words,
            ),
            max_preparation_word_ops: env_usize(
                "EUF_VIPER_QG7_RTXC_MAX_PREPARATION_WORD_OPS",
                defaults.max_preparation_word_ops,
            ),
            max_preparation_pattern_checks: env_usize(
                "EUF_VIPER_QG7_RTXC_MAX_PREPARATION_PATTERN_CHECKS",
                defaults.max_preparation_pattern_checks,
            ),
            max_search_nodes: env_usize(
                "EUF_VIPER_QG7_RTXC_MAX_SEARCH_NODES",
                defaults.max_search_nodes,
            ),
            max_candidate_checks: env_usize(
                "EUF_VIPER_QG7_RTXC_MAX_CANDIDATE_CHECKS",
                defaults.max_candidate_checks,
            ),
            max_bitset_word_ops: env_usize(
                "EUF_VIPER_QG7_RTXC_MAX_SEARCH_BITSET_WORD_OPS",
                defaults.max_bitset_word_ops,
            ),
        }
    }

    fn json_escape(text: &str) -> String {
        let mut escaped = String::with_capacity(text.len());
        for character in text.chars() {
            match character {
                '"' => escaped.push_str("\\\""),
                '\\' => escaped.push_str("\\\\"),
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                '\t' => escaped.push_str("\\t"),
                character if character.is_control() => {
                    use std::fmt::Write;
                    write!(&mut escaped, "\\u{:04x}", u32::from(character)).unwrap();
                }
                character => escaped.push(character),
            }
        }
        escaped
    }

    fn shadow_ineligibility(report: &PatternOrbitReport) -> Option<&'static str> {
        if report.degree != 7 {
            return Some("degree_not_seven");
        }
        if report.extraction.malformed_pattern_candidates != 0 {
            return Some("malformed_pattern_candidates");
        }
        if report.duplicate_exclusions != 0 {
            return Some("duplicate_pattern_records");
        }
        if !report.exact_first_orbit_cover {
            return Some("non_exact_first_orbit_cover");
        }
        None
    }

    fn print_qg7_shadow_record(
        path: &std::path::Path,
        reduction: &QgReduction,
        caps: &ShadowCaps,
        outcome: &ShadowOutcome,
    ) {
        let report = reduction
            .pattern_report()
            .expect("an eligible qg reduction has a pattern report");
        let telemetry = outcome.telemetry();
        let (abstain_reason, abstain_resource) = match outcome {
            ShadowOutcome::Abstain { reason, .. } => (reason.code(), reason.resource()),
            ShadowOutcome::Sat { .. } | ShadowOutcome::Unsat { .. } => ("none", "none"),
        };
        println!(
            concat!(
                "{{\"path\":\"{}\",\"status\":\"eligible\",",
                "\"semantics\":\"audited_qg_reduction_shadow\",",
                "\"production_routing\":false,",
                "\"source_sha256\":\"{}\",\"assertions\":{},",
                "\"consumed_assertions\":{},\"unconsumed_assertions\":{},",
                "\"remaining_predicates\":{},",
                "\"degree\":{},\"width\":{},\"records\":{},\"unique\":{},",
                "\"orbit_size\":{},\"stabilizer_size\":{},",
                "\"outcome\":\"{}\",\"abstain_reason\":\"{}\",",
                "\"abstain_resource\":\"{}\",\"patterns\":{},",
                "\"pattern_cells\":{},\"permutations\":{},",
                "\"column_candidates\":{},\"min_column_candidates\":{},",
                "\"max_column_candidates\":{},\"bitset_words\":{},",
                "\"preparation_word_ops\":{},\"preparation_pattern_checks\":{},",
                "\"preparation_cell_updates\":{},\"search_nodes\":{},",
                "\"candidate_checks\":{},\"exact_cover_rejections\":{},",
                "\"forbidden_rejections\":{},\"search_bitset_word_ops\":{},",
                "\"branch_attempts\":{},\"witness_checks\":{},\"max_depth\":{},",
                "\"trace_hash\":\"{:016x}\",\"cap_patterns\":{},",
                "\"cap_pattern_cells\":{},\"cap_permutations\":{},",
                "\"cap_bitset_words\":{},\"cap_preparation_word_ops\":{},",
                "\"cap_preparation_pattern_checks\":{},\"cap_search_nodes\":{},",
                "\"cap_candidate_checks\":{},\"cap_search_bitset_word_ops\":{}}}"
            ),
            json_escape(&path.display().to_string()),
            reduction.source_sha256_hex(),
            reduction.assertion_ledger().len(),
            reduction.consumed_assertions().count(),
            reduction.unconsumed_assertions().count(),
            reduction.remaining_predicates().count(),
            report.degree,
            report.pattern_width,
            report.exclusion_records,
            report.unique_exclusions,
            report.first_pattern_orbit_size,
            report.first_pattern_stabilizer_size,
            outcome.label(),
            abstain_reason,
            abstain_resource,
            telemetry.patterns,
            telemetry.pattern_cells,
            telemetry.permutations,
            telemetry.column_candidates,
            telemetry.min_column_candidates,
            telemetry.max_column_candidates,
            telemetry.bitset_words,
            telemetry.preparation_word_ops,
            telemetry.preparation_pattern_checks,
            telemetry.preparation_cell_updates,
            telemetry.search_nodes,
            telemetry.candidate_checks,
            telemetry.exact_cover_rejections,
            telemetry.forbidden_rejections,
            telemetry.bitset_word_ops,
            telemetry.branch_attempts,
            telemetry.witness_checks,
            telemetry.max_depth,
            telemetry.trace_hash,
            caps.max_patterns,
            caps.max_pattern_cells,
            caps.max_permutations,
            caps.max_bitset_words,
            caps.max_preparation_word_ops,
            caps.max_preparation_pattern_checks,
            caps.max_search_nodes,
            caps.max_candidate_checks,
            caps.max_bitset_word_ops,
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
        let family = extract_forbidden_pattern_family(&problem).unwrap();
        assert_eq!(family.report, partial);
        assert_eq!(family.patterns.len(), 1);
    }

    #[test]
    fn qg7_fixture_ledger_consumes_every_assertion_and_uses_240_candidates() {
        let source = qg7_reduction_fixture();
        let problem = parse(source);
        let reduction = QgReduction::audit(source, &problem);
        assert_eq!(reduction, QgReduction::audit(source, &parse(source)));

        assert!(reduction.eligible(), "{:?}", reduction.ineligibility());
        assert_eq!(reduction.degree(), 7);
        assert_eq!(reduction.carrier().len(), 7);
        assert!(
            reduction
                .carrier()
                .iter()
                .enumerate()
                .all(|(position, mapping)| mapping.position == position)
        );
        assert!(reduction.operation().is_some());
        assert_eq!(
            reduction.source_sha256_hex(),
            "8036e595e43a208f8d9b09eec8f59190e994efe29cdd9cd8b27ced162ff92672"
        );
        let expected_source_hash: [u8; 32] = Sha256::digest(source.as_bytes()).into();
        assert_eq!(reduction.source_sha256(), &expected_source_hash);

        assert_eq!(
            reduction.assertion_ledger().len(),
            problem.bool_problem.as_ref().unwrap().assertions.len()
        );
        assert_eq!(
            reduction.consumed_assertions().count(),
            reduction.assertion_ledger().len()
        );
        assert_eq!(reduction.unconsumed_assertions().count(), 0);
        let identities = reduction
            .assertion_ledger()
            .iter()
            .map(|entry| entry.identity)
            .collect::<HashSet<_>>();
        assert_eq!(identities.len(), reduction.assertion_ledger().len());
        assert!(identities.iter().all(|identity| identity.fingerprint != 0));

        assert_eq!(reduction.patterns().len(), 7);
        let report = reduction.pattern_report().unwrap();
        assert!(report.exact_first_orbit_cover);
        assert_eq!(report.first_pattern_orbit_size, 7);
        assert_eq!(report.first_pattern_stabilizer_size, 720);
        assert!(reduction.pattern_error().is_none());

        assert_eq!(reduction.local_constraints().len(), 2);
        assert_eq!(reduction.remaining_predicates().count(), 1);
        assert_eq!(reduction.candidate_counts(), &[240; 7]);
        for (column, filter) in reduction.column_filters().iter().enumerate() {
            assert_eq!(filter.column, column);
            assert!(filter.require_cube_identity);
            assert_eq!(filter.exact_fixed_points, Some(1));
            assert!(filter.direct.contains(&DirectCellConstraint {
                row: column,
                value: column,
                equal: false,
            }));
        }

        let operation = reduction.operation().unwrap();
        assert!(reduction.function_usage().iter().any(|usage| {
            usage.function == operation
                && usage.role == FunctionRole::TableOperation
                && usage.application_occurrences > 0
        }));
        assert!(reduction.function_usage().iter().any(|usage| {
            usage.declared_arity == 2
                && usage.role == FunctionRole::Unused
                && usage.occurrences == 0
        }));
    }

    #[test]
    fn qg7_candidate_filter_matches_independent_cycle_type_enumeration() {
        let source = qg7_reduction_fixture();
        let reduction = QgReduction::audit(source, &parse(source));
        let mut permutation = (0_u8..7).collect::<Vec<_>>();
        let mut independent_counts = [0_usize; 7];
        loop {
            let fixed_points = permutation
                .iter()
                .enumerate()
                .filter(|&(point, &image)| point == usize::from(image))
                .count();
            let cube_identity = (0..7).all(|point| {
                let once = usize::from(permutation[point]);
                let twice = usize::from(permutation[once]);
                usize::from(permutation[twice]) == point
            });
            for column in 0..7 {
                let independent = cube_identity
                    && fixed_points == 1
                    && usize::from(permutation[column]) != column;
                assert_eq!(
                    reduction.column_filters()[column].allows(&permutation),
                    independent
                );
                independent_counts[column] += usize::from(independent);
            }
            if !advance_u8_permutation(&mut permutation) {
                break;
            }
        }
        assert_eq!(independent_counts, [240; 7]);
    }

    #[test]
    fn qg7_filter_strength_is_monotone_and_audit_gated() {
        let diagonal = DirectCellConstraint {
            row: 0,
            value: 0,
            equal: false,
        };
        let cases = [
            (
                QgColumnFilter {
                    column: 0,
                    require_cube_identity: false,
                    exact_fixed_points: None,
                    direct: Box::new([]),
                },
                5_040,
            ),
            (
                QgColumnFilter {
                    column: 0,
                    require_cube_identity: false,
                    exact_fixed_points: None,
                    direct: Box::new([diagonal]),
                },
                4_320,
            ),
            (
                QgColumnFilter {
                    column: 0,
                    require_cube_identity: true,
                    exact_fixed_points: None,
                    direct: Box::new([diagonal]),
                },
                270,
            ),
            (
                QgColumnFilter {
                    column: 0,
                    require_cube_identity: true,
                    exact_fixed_points: Some(1),
                    direct: Box::new([diagonal]),
                },
                240,
            ),
        ];
        for (filter, expected) in cases {
            assert_eq!(count_filter_candidates(7, &filter), expected);
        }

        let malformed_cube =
            qg7_reduction_fixture().replacen("(op (op (op e0 e0) e0) e0)", "(op (op e0 e0) e0)", 1);
        let malformed_cube = QgReduction::audit(&malformed_cube, &parse(&malformed_cube));
        assert!(!malformed_cube.eligible());
        assert!(
            malformed_cube
                .ineligibility()
                .contains(&QgIneligibility::UnconsumedAssertions)
        );
    }

    #[test]
    fn direct_fixed_point_literals_narrow_only_their_column() {
        let source = qg7_reduction_fixture().replace(
            "(check-sat)",
            concat!(
                "(assert (and (= (op e0 e1) e0) ",
                "(not (= (op e2 e1) e2))))\n(check-sat)"
            ),
        );
        let reduction = QgReduction::audit(&source, &parse(&source));
        assert!(reduction.eligible(), "{:?}", reduction.ineligibility());
        assert_eq!(
            reduction.candidate_counts(),
            &[240, 40, 240, 240, 240, 240, 240]
        );
        assert_eq!(
            reduction
                .local_constraints()
                .iter()
                .filter(|constraint| {
                    constraint.enforcement == LocalConstraintEnforcement::CandidateFilter
                })
                .count(),
            2
        );
        assert!(
            reduction.column_filters()[1]
                .direct
                .contains(&DirectCellConstraint {
                    row: 0,
                    value: 0,
                    equal: true,
                })
        );
        assert!(
            reduction.column_filters()[1]
                .direct
                .contains(&DirectCellConstraint {
                    row: 2,
                    value: 2,
                    equal: false,
                })
        );
    }

    #[test]
    fn qg_source_audit_abstains_on_unconsumed_or_foreign_assertions() {
        let source =
            qg7_reduction_fixture().replace("(check-sat)", "(assert (= e0 e0))\n(check-sat)");
        let reduction = QgReduction::audit(&source, &parse(&source));
        assert!(!reduction.eligible());
        assert_eq!(reduction.unconsumed_assertions().count(), 1);
        assert!(
            reduction
                .ineligibility()
                .contains(&QgIneligibility::UnconsumedAssertions)
        );
        assert!(matches!(
            search_qg_reduction_shadow(&reduction, &ShadowCaps::default()),
            ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::SourceAudit("unconsumed_assertions"),
                ..
            }
        ));

        let foreign = qg7_reduction_fixture().replace(
            "(check-sat)",
            "(assert (= (unused-op e0 e0) e0))\n(check-sat)",
        );
        let foreign = QgReduction::audit(&foreign, &parse(&foreign));
        assert!(!foreign.eligible());
        assert_eq!(foreign.unconsumed_assertions().count(), 1);
        assert!(
            foreign
                .ineligibility()
                .contains(&QgIneligibility::UnrecognizedFunctionUsage)
        );
        assert!(
            foreign
                .function_usage()
                .iter()
                .any(|usage| { usage.role == FunctionRole::Unrecognized && usage.occurrences > 0 })
        );
    }

    #[test]
    fn residual_source_predicate_rejects_a_shadow_witness_as_abstain() {
        let source = concat!(
            "(set-logic QF_UF)\n",
            "(declare-sort I 0)\n",
            "(declare-fun e0 () I)\n",
            "(declare-fun e1 () I)\n",
            "(declare-fun op (I I) I)\n",
            "(assert (distinct e0 e1))\n",
            "(assert (and ",
            "(or (= (op e0 e0) e0) (= (op e0 e0) e1)) ",
            "(or (= (op e0 e1) e0) (= (op e0 e1) e1)) ",
            "(or (= (op e1 e0) e0) (= (op e1 e0) e1)) ",
            "(or (= (op e1 e1) e0) (= (op e1 e1) e1))))\n",
            "(assert (and ",
            "(distinct (op e0 e0) (op e0 e1)) ",
            "(distinct (op e1 e0) (op e1 e1)) ",
            "(distinct (op e0 e0) (op e1 e0)) ",
            "(distinct (op e0 e1) (op e1 e1))))\n",
            "(assert false)\n",
            "(assert (not (and ",
            "(= (op e0 e0) e0) (= (op e0 e1) e0) ",
            "(= (op e1 e0) e0) (= (op e1 e1) e0))))\n",
            "(assert (not (and ",
            "(= (op e0 e0) e1) (= (op e0 e1) e1) ",
            "(= (op e1 e0) e1) (= (op e1 e1) e1))))\n",
            "(check-sat)\n",
        );
        let reduction = QgReduction::audit(source, &parse(source));
        assert!(reduction.eligible(), "{:?}", reduction.ineligibility());
        let residual = reduction.remaining_predicates().next().unwrap();
        assert_eq!(residual.formula, NormalizedLocalExpr::Const(false));
        assert!(matches!(
            search_qg_reduction_shadow(&reduction, &ShadowCaps::default()),
            ShadowOutcome::Abstain {
                reason: ShadowAbstainReason::SourcePredicateRejected { assertion: 3 },
                ..
            }
        ));
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
                shadow_ineligibility(&report),
                Some("non_exact_first_orbit_cover")
            );
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
    fn transparent_wrapper_cannot_hide_a_table_restriction() {
        let orbit = pattern_orbit(&pattern(3, &[(0, 0, 0), (0, 1, 2)]));
        let unrelated = pattern_family_source(&orbit, "(assert (not (and true (= e0 e1))))");
        let family = extract_forbidden_pattern_family(&parse(&unrelated)).unwrap();
        assert!(family.report.exact_first_orbit_cover);
        assert_eq!(family.report.extraction.malformed_pattern_candidates, 0);

        let table_restricting =
            pattern_family_source(&orbit, "(assert (not (and true (= (op e0 e0) e0))))");
        assert_eq!(
            extract_forbidden_pattern_family(&parse(&table_restricting)),
            Err(ProbeError::MalformedPatternCandidates(1))
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
                Err(ProbeError::MalformedPatternCandidates(1))
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
    fn separate_patterned_operations_are_rejected() {
        let source = partial_source(
            &["(= (op e0 e1) e0)"],
            "(declare-fun alt (I I) I)\n\
             (assert (not (= (alt e1 e2) e0)))",
        );
        assert_eq!(
            analyze_forbidden_pattern_orbit(&parse(&source)),
            Err(ProbeError::MultiplePatternFunctions(2))
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
    #[ignore = "requires EUF_VIPER_QG7_CENSUS_DIR; bounded to at most 512 files"]
    fn bounded_qg7_partial_pattern_census() {
        let directory = env::var("EUF_VIPER_QG7_CENSUS_DIR").unwrap();
        let requested = env_usize("EUF_VIPER_QG7_CENSUS_LIMIT", 4);
        let limit = requested.clamp(1, 512);
        let offset = env_usize("EUF_VIPER_QG7_CENSUS_OFFSET", 0);
        let caps = qg7_shadow_caps_from_env();
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

        for path in paths.into_iter().skip(offset).take(limit) {
            let source = fs::read_to_string(&path).unwrap();
            let problem = parse_problem_with_scoped_let_mode(&source, ScopedLetMode::Auto).unwrap();
            let reduction = QgReduction::audit(&source, &problem);
            if reduction.eligible() {
                let outcome = search_qg_reduction_shadow(&reduction, &caps);
                print_qg7_shadow_record(&path, &reduction, &caps, &outcome);
            } else {
                let unconsumed = reduction
                    .unconsumed_assertions()
                    .map(|identity| identity.ordinal.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    concat!(
                        "{{\"path\":\"{}\",\"status\":\"ineligible\",",
                        "\"reason\":\"{}\",\"source_sha256\":\"{}\",",
                        "\"degree\":{},\"assertions\":{},",
                        "\"consumed_assertions\":{},",
                        "\"unconsumed_assertions\":[{}],",
                        "\"pattern_error\":\"{}\"}}"
                    ),
                    json_escape(&path.display().to_string()),
                    reduction.first_ineligibility_code(),
                    reduction.source_sha256_hex(),
                    reduction.degree(),
                    reduction.assertion_ledger().len(),
                    reduction.consumed_assertions().count(),
                    unconsumed,
                    json_escape(&format!("{:?}", reduction.pattern_error())),
                );
            }
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
