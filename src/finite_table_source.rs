#![cfg(test)]
#![allow(dead_code)]

//! Fail-closed source evaluator for the finite, one-binary-operation fragment.
//!
//! This module is deliberately test-only. It recognizes its fragment from the
//! parsed assertion graph, never from benchmark metadata, and it does not
//! participate in the production solving route.

use super::{
    BOOL_SORT, BoolAtomKey, BoolExpr, Problem, SortId, SymId, TermId, TermKey,
    finite_analysis::FiniteAnalysisContext, normalized_pair,
};
use crate::orbit_canon::{
    BinaryTable, CheckedPermutation, LexicographicPermutations, MAX_EXHAUSTIVE_DEGREE,
};
use crate::orbit_cover::{
    BaseActionVerifier, BaseFingerprint, BaseInvarianceClaim, BasePermutationWitness,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

const MIN_DOMAIN_SIZE: usize = 2;
const MAX_DOMAIN_SIZE: usize = 8;
const MAX_SOURCE_ASSERTIONS: usize = 20_000;
const MAX_BOOLEAN_NODES: usize = 2_000_000;
const MAX_BOOLEAN_DEPTH: usize = 1_024;
const MAX_ARENA_TERMS: usize = 100_000;
const MAX_ARENA_APPLICATIONS: usize = 100_000;
const MAX_LIVE_TERMS: usize = 32_768;
const MAX_TERM_DEPTH: usize = 64;
const MAX_FORBIDDEN_TABLES: usize = 20_000;
const MAX_RELABELING_PERMUTATIONS: usize = 40_320;
const MAX_RELABELING_ASSERTION_IMAGES: usize = 2_000_000;
const MAX_RELABELING_NORMALIZED_NODES: usize = 250_000;
const MAX_RELABELING_NODE_VISITS: usize = 500_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DomainTermError {
    Missing,
    Boolean,
    NotNullary,
    MissingDeclaration,
    DeclarationMismatch,
    NotInternedAsNamedNullary,
    DuplicateSymbol,
    SortMismatch,
    NotLive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AssertionError {
    MissingTerm(TermId),
    CyclicTerm(TermId),
    InvalidTermSort {
        term: TermId,
        sort: SortId,
    },
    MissingDeclaration {
        term: TermId,
        fun: SymId,
    },
    DeclarationMismatch(TermId),
    MissingArgument {
        term: TermId,
        position: usize,
        argument: TermId,
    },
    ArgumentSortMismatch {
        term: TermId,
        position: usize,
    },
    EqualitySortMismatch {
        left: TermId,
        right: TermId,
    },
    UndeterminedBooleanTerm(TermId),
    BooleanAnchorsAlias(TermId),
    InvalidBooleanAnchor(TermId),
    NonDomainNullaryTerm(TermId),
    NonHomogeneousBinaryTerm {
        term: TermId,
        fun: SymId,
    },
    NonFiniteTerm(TermId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MalformedForbiddenTableError {
    NonEqualityLeaf,
    WrongEqualityCount {
        expected: usize,
        actual: usize,
    },
    NonCellEquality {
        equality_index: usize,
    },
    DuplicateCell {
        equality_index: usize,
        row: usize,
        column: usize,
    },
    MissingCell {
        row: usize,
        column: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceCompileError {
    MissingBooleanProblem,
    UnsupportedSource(Vec<String>),
    StructuralCap {
        resource: &'static str,
        limit: usize,
        actual: usize,
        assertion_ordinal: Option<usize>,
    },
    InvalidArenaApplication {
        application_index: usize,
        term: TermId,
    },
    InvalidDomainSize {
        actual: usize,
    },
    InvalidDomainTerm {
        term: TermId,
        reason: DomainTermError,
    },
    DomainTermsNotPairwiseDistinct {
        left: TermId,
        right: TermId,
    },
    InvalidAssertion {
        assertion_ordinal: usize,
        reason: AssertionError,
    },
    MissingBinaryOperation,
    MultipleBinaryOperations {
        assertion_ordinal: usize,
        expected: SymId,
        found: SymId,
    },
    MalformedForbiddenTable {
        assertion_ordinal: usize,
        reason: MalformedForbiddenTableError,
    },
}

impl fmt::Display for SourceCompileError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingBooleanProblem => write!(output, "source has no represented assertions"),
            Self::UnsupportedSource(messages) => {
                write!(
                    output,
                    "source representation is incomplete: {}",
                    messages.join("; ")
                )
            }
            Self::StructuralCap {
                resource,
                limit,
                actual,
                assertion_ordinal,
            } => {
                if let Some(ordinal) = assertion_ordinal {
                    write!(
                        output,
                        "assertion {ordinal} exceeds the {resource} cap: {actual} > {limit}"
                    )
                } else {
                    write!(
                        output,
                        "source exceeds the {resource} cap: {actual} > {limit}"
                    )
                }
            }
            Self::InvalidArenaApplication {
                application_index,
                term,
            } => write!(
                output,
                "arena application slot {application_index} references missing term {term}"
            ),
            Self::InvalidDomainSize { actual } => write!(
                output,
                "finite analysis derived domain size {actual}, expected {MIN_DOMAIN_SIZE}..={MAX_DOMAIN_SIZE}"
            ),
            Self::InvalidDomainTerm { term, reason } => {
                write!(output, "derived domain term {term} is invalid: {reason:?}")
            }
            Self::DomainTermsNotPairwiseDistinct { left, right } => write!(
                output,
                "derived domain terms {left} and {right} lack a mandatory source disequality"
            ),
            Self::InvalidAssertion {
                assertion_ordinal,
                reason,
            } => write!(
                output,
                "assertion {assertion_ordinal} is outside the fragment: {reason:?}"
            ),
            Self::MissingBinaryOperation => {
                write!(
                    output,
                    "represented assertions have no live binary operation"
                )
            }
            Self::MultipleBinaryOperations {
                assertion_ordinal,
                expected,
                found,
            } => write!(
                output,
                "assertion {assertion_ordinal} uses operation {found}, after operation {expected} was selected"
            ),
            Self::MalformedForbiddenTable {
                assertion_ordinal,
                reason,
            } => write!(
                output,
                "assertion {assertion_ordinal} is a malformed forbidden-table candidate: {reason:?}"
            ),
        }
    }
}

impl Error for SourceCompileError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EvaluationError {
    WrongTableDegree {
        expected: usize,
        actual: usize,
    },
    TermNotLive(TermId),
    MissingTerm(TermId),
    CyclicTerm(TermId),
    UnsupportedTerm(TermId),
    ExpectedDomainValue(TermId),
    ExpectedBooleanValue(TermId),
    MissingTableCell {
        term: TermId,
        left: usize,
        right: usize,
    },
}

impl fmt::Display for EvaluationError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "{self:?}")
    }
}

impl Error for EvaluationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PartialTruth {
    False,
    Unknown,
    True,
}

impl PartialTruth {
    fn not(self) -> Self {
        match self {
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
            Self::True => Self::False,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PartialTableError {
    WrongCellCount {
        expected: usize,
        actual: usize,
    },
    EmptyCellDomain {
        cell: usize,
        row: usize,
        column: usize,
    },
    CellDomainOutOfRange {
        cell: usize,
        row: usize,
        column: usize,
        mask: u8,
        allowed_mask: u8,
    },
    Evaluation(EvaluationError),
    BaseAssertionEvaluation {
        assertion_ordinal: usize,
        error: EvaluationError,
    },
}

impl fmt::Display for PartialTableError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongCellCount { expected, actual } => write!(
                output,
                "partial table has {actual} cells, expected exactly {expected}"
            ),
            Self::EmptyCellDomain { cell, row, column } => write!(
                output,
                "partial table cell {cell} at ({row}, {column}) has an empty domain"
            ),
            Self::CellDomainOutOfRange {
                cell,
                row,
                column,
                mask,
                allowed_mask,
            } => write!(
                output,
                "partial table cell {cell} at ({row}, {column}) has mask {mask:#04x} outside {allowed_mask:#04x}"
            ),
            Self::Evaluation(error) => write!(output, "partial evaluation failed: {error}"),
            Self::BaseAssertionEvaluation {
                assertion_ordinal,
                error,
            } => write!(
                output,
                "base assertion {assertion_ordinal} could not be partially evaluated: {error}"
            ),
        }
    }
}

impl Error for PartialTableError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceTableValidationError {
    WrongTableDegree {
        expected: usize,
        actual: usize,
    },
    Evaluation {
        assertion_ordinal: usize,
        error: EvaluationError,
    },
    BaseAssertionFalse {
        assertion_ordinal: usize,
    },
    ForbiddenTable {
        assertion_ordinals: Vec<usize>,
    },
}

impl fmt::Display for SourceTableValidationError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongTableDegree { expected, actual } => {
                write!(
                    output,
                    "table degree {actual} does not match source degree {expected}"
                )
            }
            Self::Evaluation {
                assertion_ordinal,
                error,
            } => write!(
                output,
                "assertion {assertion_ordinal} could not be evaluated: {error}"
            ),
            Self::BaseAssertionFalse { assertion_ordinal } => {
                write!(
                    output,
                    "base assertion {assertion_ordinal} evaluates to false"
                )
            }
            Self::ForbiddenTable { assertion_ordinals } => write!(
                output,
                "table is forbidden by source assertion ordinal(s) {assertion_ordinals:?}"
            ),
        }
    }
}

impl Error for SourceTableValidationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForbiddenTableRecord {
    pub(crate) assertion_ordinal: usize,
    pub(crate) table: BinaryTable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourceTableCounts {
    pub(crate) total_assertions: usize,
    pub(crate) base_assertions: usize,
    pub(crate) exclusion_assertions: usize,
    pub(crate) unique_forbidden_tables: usize,
    pub(crate) max_term_depth: usize,
}

/// Separates sampled semantic observations from a replayable source proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelabelingEvidenceKind {
    EmpiricalCheck,
    StructuralProof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BaseRelabelingCaps {
    max_permutations: usize,
    max_assertion_images: usize,
    max_normalized_nodes: usize,
    max_node_visits: usize,
}

impl BaseRelabelingCaps {
    pub(crate) const fn exhaustive_supported() -> Self {
        Self {
            max_permutations: MAX_RELABELING_PERMUTATIONS,
            max_assertion_images: MAX_RELABELING_ASSERTION_IMAGES,
            max_normalized_nodes: MAX_RELABELING_NORMALIZED_NODES,
            max_node_visits: MAX_RELABELING_NODE_VISITS,
        }
    }

    #[cfg(test)]
    const fn with_limits(
        max_permutations: usize,
        max_assertion_images: usize,
        max_normalized_nodes: usize,
        max_node_visits: usize,
    ) -> Self {
        Self {
            max_permutations,
            max_assertion_images,
            max_normalized_nodes,
            max_node_visits,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BaseRelabelingError {
    DegreeTooLarge {
        degree: usize,
        maximum: usize,
    },
    PermutationEnumeration,
    StructuralCap {
        resource: &'static str,
        limit: usize,
        actual: usize,
    },
    Canonicalization {
        assertion_ordinal: usize,
        detail: String,
    },
    AllocationFailure {
        resource: &'static str,
        requested: usize,
    },
    NotInvariant {
        permutation: CheckedPermutation,
        source_base_assertion: usize,
        source_assertion_ordinal: usize,
    },
    CertificateMismatch(&'static str),
}

impl fmt::Display for BaseRelabelingError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DegreeTooLarge { degree, maximum } => write!(
                output,
                "structural relabeling supports degree at most {maximum}, not {degree}"
            ),
            Self::PermutationEnumeration => {
                write!(output, "failed to enumerate the complete permutation group")
            }
            Self::StructuralCap {
                resource,
                limit,
                actual,
            } => write!(
                output,
                "structural relabeling exceeds the {resource} cap: {actual} > {limit}"
            ),
            Self::Canonicalization {
                assertion_ordinal,
                detail,
            } => write!(
                output,
                "base assertion {assertion_ordinal} cannot be structurally normalized: {detail}"
            ),
            Self::AllocationFailure {
                resource,
                requested,
            } => write!(
                output,
                "structural relabeling could not allocate {requested} {resource}"
            ),
            Self::NotInvariant {
                permutation,
                source_base_assertion,
                source_assertion_ordinal,
            } => write!(
                output,
                "base assertion index {source_base_assertion} (source ordinal {source_assertion_ordinal}) has no image under permutation {:?}",
                permutation.images()
            ),
            Self::CertificateMismatch(detail) => {
                write!(
                    output,
                    "structural relabeling certificate mismatch: {detail}"
                )
            }
        }
    }
}

impl Error for BaseRelabelingError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StructuralBaseRelabelingTelemetry {
    pub(crate) evidence_kind: RelabelingEvidenceKind,
    pub(crate) degree: usize,
    pub(crate) base_assertions: usize,
    pub(crate) normalized_nodes: usize,
    pub(crate) permutations_checked: usize,
    pub(crate) assertion_images_checked: usize,
}

/// Exhaustive proof that the normalized base-assertion multiset is closed
/// under simultaneous relabeling. This proves base-conjunction invariance; it
/// does not prove a canonical-augmentation rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StructuralBaseRelabelingCertificate {
    claim: BaseInvarianceClaim,
    telemetry: StructuralBaseRelabelingTelemetry,
}

impl StructuralBaseRelabelingCertificate {
    pub(crate) fn claim(&self) -> &BaseInvarianceClaim {
        &self.claim
    }

    pub(crate) fn telemetry(&self) -> StructuralBaseRelabelingTelemetry {
        self.telemetry
    }
}

#[derive(Debug)]
pub(crate) struct FiniteTableSource<'a> {
    problem: &'a Problem,
    domain: Vec<TermId>,
    domain_positions: BTreeMap<TermId, usize>,
    operation: SymId,
    live_terms: BTreeSet<TermId>,
    base_assertion_ordinals: Vec<usize>,
    forbidden_records: Vec<ForbiddenTableRecord>,
    forbidden_by_table: BTreeMap<BinaryTable, Vec<usize>>,
    max_term_depth: usize,
}

impl<'a> FiniteTableSource<'a> {
    pub(crate) fn domain(&self) -> &[TermId] {
        &self.domain
    }

    pub(crate) fn operation(&self) -> SymId {
        self.operation
    }

    pub(crate) fn base_assertion_ordinals(&self) -> &[usize] {
        &self.base_assertion_ordinals
    }

    pub(crate) fn forbidden_records(&self) -> &[ForbiddenTableRecord] {
        &self.forbidden_records
    }

    pub(crate) fn unique_forbidden_tables(&self) -> impl ExactSizeIterator<Item = &BinaryTable> {
        self.forbidden_by_table.keys()
    }

    pub(crate) fn counts(&self) -> SourceTableCounts {
        SourceTableCounts {
            total_assertions: self
                .problem
                .bool_problem
                .as_ref()
                .expect("compiled source retains its Boolean problem")
                .assertions
                .len(),
            base_assertions: self.base_assertion_ordinals.len(),
            exclusion_assertions: self.forbidden_records.len(),
            unique_forbidden_tables: self.forbidden_by_table.len(),
            max_term_depth: self.max_term_depth,
        }
    }

    pub(crate) fn certify_structural_base_relabeling(
        &self,
    ) -> Result<StructuralBaseRelabelingCertificate, BaseRelabelingError> {
        self.certify_structural_base_relabeling_with_caps(
            BaseRelabelingCaps::exhaustive_supported(),
        )
    }

    fn certify_structural_base_relabeling_with_caps(
        &self,
        caps: BaseRelabelingCaps,
    ) -> Result<StructuralBaseRelabelingCertificate, BaseRelabelingError> {
        let verifier = self.source_base_action_verifier_with_caps(caps)?;
        let claim = build_base_invariance_claim(&verifier, caps)?;
        let telemetry = replay_base_invariance_claim(&verifier, &claim, caps)?;
        Ok(StructuralBaseRelabelingCertificate { claim, telemetry })
    }

    pub(crate) fn verify_structural_base_relabeling(
        &self,
        certificate: &StructuralBaseRelabelingCertificate,
    ) -> Result<StructuralBaseRelabelingTelemetry, BaseRelabelingError> {
        let caps = BaseRelabelingCaps::exhaustive_supported();
        let verifier = self.source_base_action_verifier_with_caps(caps)?;
        let telemetry = replay_base_invariance_claim(&verifier, &certificate.claim, caps)?;
        if telemetry != certificate.telemetry {
            return Err(BaseRelabelingError::CertificateMismatch(
                "stored telemetry differs from independent replay",
            ));
        }
        Ok(telemetry)
    }

    pub(crate) fn source_base_action_verifier(
        &self,
    ) -> Result<SourceBaseActionVerifier, BaseRelabelingError> {
        self.source_base_action_verifier_with_caps(BaseRelabelingCaps::exhaustive_supported())
    }

    fn source_base_action_verifier_with_caps(
        &self,
        caps: BaseRelabelingCaps,
    ) -> Result<SourceBaseActionVerifier, BaseRelabelingError> {
        SourceBaseActionVerifier::from_source(self, caps)
    }

    pub(crate) fn base_assertion_atom_samples(
        &self,
        assertion_ordinal: usize,
        limit: usize,
    ) -> Option<Vec<String>> {
        if !self.base_assertion_ordinals.contains(&assertion_ordinal) {
            return None;
        }
        let assertion = self
            .problem
            .bool_problem
            .as_ref()
            .expect("compiled source retains its Boolean problem")
            .assertions
            .get(assertion_ordinal)?;
        let mut output = Vec::new();
        self.collect_atom_samples(assertion, limit, &mut output);
        Some(output)
    }

    fn collect_atom_samples(&self, expression: &BoolExpr, limit: usize, output: &mut Vec<String>) {
        if output.len() >= limit {
            return;
        }
        match expression {
            BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => output.push(format!(
                "{} = {}",
                self.render_term_for_diagnostics(*left),
                self.render_term_for_diagnostics(*right)
            )),
            BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => {
                output.push(self.render_term_for_diagnostics(*term));
            }
            BoolExpr::Not(child) => self.collect_atom_samples(child, limit, output),
            BoolExpr::And(children) | BoolExpr::Or(children) | BoolExpr::Iff(children) => {
                for child in children {
                    self.collect_atom_samples(child, limit, output);
                    if output.len() >= limit {
                        break;
                    }
                }
            }
            BoolExpr::Ite(condition, then_expression, else_expression) => {
                for child in [
                    condition.as_ref(),
                    then_expression.as_ref(),
                    else_expression.as_ref(),
                ] {
                    self.collect_atom_samples(child, limit, output);
                    if output.len() >= limit {
                        break;
                    }
                }
            }
            BoolExpr::Const(_) => {}
        }
    }

    fn render_term_for_diagnostics(&self, term_id: TermId) -> String {
        if let Some(position) = self.domain_positions.get(&term_id) {
            return format!("e{position}");
        }
        let Some(term) = self.problem.arena.terms.get(term_id) else {
            return format!("missing_term_{term_id}");
        };
        let arguments = term
            .args
            .iter()
            .map(|argument| self.render_term_for_diagnostics(*argument))
            .collect::<Vec<_>>()
            .join(",");
        let name = if term.fun == self.operation {
            "op".to_owned()
        } else {
            format!("f{}", term.fun)
        };
        format!("{name}({arguments})")
    }

    pub(crate) fn evaluate_term(
        &self,
        table: &BinaryTable,
        term: TermId,
    ) -> Result<usize, EvaluationError> {
        self.check_table_degree_for_evaluation(table)?;
        let mut evaluator = CompleteTableEvaluator::new(self, table);
        match evaluator.term(term)? {
            TermValue::Domain(value) => Ok(value),
            TermValue::Bool(_) => Err(EvaluationError::ExpectedDomainValue(term)),
        }
    }

    pub(crate) fn evaluate_bool_expr(
        &self,
        table: &BinaryTable,
        expression: &BoolExpr,
    ) -> Result<bool, EvaluationError> {
        self.check_table_degree_for_evaluation(table)?;
        CompleteTableEvaluator::new(self, table).bool_expr(expression)
    }

    /// Returns the possible values of a live non-Boolean term as a domain bit mask.
    pub(crate) fn partial_term_mask(
        &self,
        cell_domains: &[u8],
        term: TermId,
    ) -> Result<u8, PartialTableError> {
        self.validate_partial_cell_domains(cell_domains)?;
        let mut evaluator = PartialTableEvaluator::new(self, cell_domains);
        match evaluator
            .term(term)
            .map_err(PartialTableError::Evaluation)?
        {
            PartialTermValue::Domain(mask) => Ok(mask),
            PartialTermValue::Bool(_) => Err(PartialTableError::Evaluation(
                EvaluationError::ExpectedDomainValue(term),
            )),
        }
    }

    /// Evaluates a represented Boolean expression with sound strong-Kleene semantics.
    pub(crate) fn partial_bool_truth(
        &self,
        cell_domains: &[u8],
        expression: &BoolExpr,
    ) -> Result<PartialTruth, PartialTableError> {
        self.validate_partial_cell_domains(cell_domains)?;
        PartialTableEvaluator::new(self, cell_domains)
            .bool_expr(expression)
            .map_err(PartialTableError::Evaluation)
    }

    /// Returns the first base assertion proved false by the partial table.
    pub(crate) fn first_definitely_false_base_assertion(
        &self,
        cell_domains: &[u8],
    ) -> Result<Option<usize>, PartialTableError> {
        self.validate_partial_cell_domains(cell_domains)?;
        let assertions = &self
            .problem
            .bool_problem
            .as_ref()
            .expect("compiled source retains its Boolean problem")
            .assertions;
        let mut evaluator = PartialTableEvaluator::new(self, cell_domains);
        for &assertion_ordinal in &self.base_assertion_ordinals {
            let truth = evaluator
                .bool_expr(&assertions[assertion_ordinal])
                .map_err(|error| PartialTableError::BaseAssertionEvaluation {
                    assertion_ordinal,
                    error,
                })?;
            if truth == PartialTruth::False {
                return Ok(Some(assertion_ordinal));
            }
        }
        Ok(None)
    }

    /// A false result is a sound rejection; true permits both feasible and
    /// currently unresolved partial tables.
    pub(crate) fn base_could_hold(&self, cell_domains: &[u8]) -> Result<bool, PartialTableError> {
        Ok(self
            .first_definitely_false_base_assertion(cell_domains)?
            .is_none())
    }

    pub(crate) fn validate_partial_cell_domains(
        &self,
        cell_domains: &[u8],
    ) -> Result<(), PartialTableError> {
        let degree = self.domain.len();
        let expected = degree * degree;
        if cell_domains.len() != expected {
            return Err(PartialTableError::WrongCellCount {
                expected,
                actual: cell_domains.len(),
            });
        }
        let allowed_mask = if degree == u8::BITS as usize {
            u8::MAX
        } else {
            (1u8 << degree) - 1
        };
        for (cell, &mask) in cell_domains.iter().enumerate() {
            let row = cell / degree;
            let column = cell % degree;
            if mask == 0 {
                return Err(PartialTableError::EmptyCellDomain { cell, row, column });
            }
            if mask & !allowed_mask != 0 {
                return Err(PartialTableError::CellDomainOutOfRange {
                    cell,
                    row,
                    column,
                    mask,
                    allowed_mask,
                });
            }
        }
        Ok(())
    }

    pub(crate) fn base_assertions_hold(
        &self,
        table: &BinaryTable,
    ) -> Result<bool, SourceTableValidationError> {
        Ok(self.first_false_base_assertion(table)?.is_none())
    }

    pub(crate) fn base_satisfying_forbidden_table_count(
        &self,
    ) -> Result<usize, SourceTableValidationError> {
        let mut count = 0;
        for table in self.forbidden_by_table.keys() {
            if self.base_assertions_hold(table)? {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Accepts exactly the complete tables satisfying every retained source
    /// assertion and differing from every extracted forbidden record.
    pub(crate) fn validate_source_table(
        &self,
        table: &BinaryTable,
    ) -> Result<(), SourceTableValidationError> {
        if let Some(assertion_ordinal) = self.first_false_base_assertion(table)? {
            return Err(SourceTableValidationError::BaseAssertionFalse { assertion_ordinal });
        }
        if let Some(assertion_ordinals) = self.forbidden_by_table.get(table) {
            return Err(SourceTableValidationError::ForbiddenTable {
                assertion_ordinals: assertion_ordinals.clone(),
            });
        }
        Ok(())
    }

    fn first_false_base_assertion(
        &self,
        table: &BinaryTable,
    ) -> Result<Option<usize>, SourceTableValidationError> {
        self.check_table_degree_for_validation(table)?;
        let assertions = &self
            .problem
            .bool_problem
            .as_ref()
            .expect("compiled source retains its Boolean problem")
            .assertions;
        let mut evaluator = CompleteTableEvaluator::new(self, table);
        for &assertion_ordinal in &self.base_assertion_ordinals {
            let value = evaluator
                .bool_expr(&assertions[assertion_ordinal])
                .map_err(|error| SourceTableValidationError::Evaluation {
                    assertion_ordinal,
                    error,
                })?;
            if !value {
                return Ok(Some(assertion_ordinal));
            }
        }
        Ok(None)
    }

    fn check_table_degree_for_evaluation(
        &self,
        table: &BinaryTable,
    ) -> Result<(), EvaluationError> {
        if table.degree() != self.domain.len() {
            return Err(EvaluationError::WrongTableDegree {
                expected: self.domain.len(),
                actual: table.degree(),
            });
        }
        Ok(())
    }

    fn check_table_degree_for_validation(
        &self,
        table: &BinaryTable,
    ) -> Result<(), SourceTableValidationError> {
        if table.degree() != self.domain.len() {
            return Err(SourceTableValidationError::WrongTableDegree {
                expected: self.domain.len(),
                actual: table.degree(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum StructuralTerm {
    Domain(usize),
    Bool(bool),
    Operation(Box<StructuralTerm>, Box<StructuralTerm>),
}

impl StructuralTerm {
    fn relabeled(&self, permutation: &CheckedPermutation) -> Self {
        match self {
            Self::Domain(value) => Self::Domain(
                permutation
                    .image(*value)
                    .expect("typed structural terms stay inside the carrier"),
            ),
            Self::Bool(value) => Self::Bool(*value),
            Self::Operation(left, right) => Self::Operation(
                Box::new(left.relabeled(permutation)),
                Box::new(right.relabeled(permutation)),
            ),
        }
    }

    fn count_nodes(&self, total: &mut usize, limit: usize) -> Result<(), BaseRelabelingError> {
        add_normalized_node(total, limit)?;
        if let Self::Operation(left, right) = self {
            left.count_nodes(total, limit)?;
            right.count_nodes(total, limit)?;
        }
        Ok(())
    }

    fn fingerprint(&self, fingerprint: &mut DeterministicFingerprint) {
        match self {
            Self::Domain(value) => {
                fingerprint.word(0);
                fingerprint.word(*value);
            }
            Self::Bool(value) => {
                fingerprint.word(1);
                fingerprint.word(usize::from(*value));
            }
            Self::Operation(left, right) => {
                fingerprint.word(2);
                left.fingerprint(fingerprint);
                right.fingerprint(fingerprint);
            }
        }
    }
}

/// Canonical only under directly justified identities: equality symmetry;
/// associative, commutative, idempotent And/Or with constants; symmetric,
/// idempotent n-ary Iff; double negation; and constant/trivial Ite reduction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum StructuralBoolExpr {
    Const(bool),
    Eq(StructuralTerm, StructuralTerm),
    Not(Box<StructuralBoolExpr>),
    And(Vec<StructuralBoolExpr>),
    Or(Vec<StructuralBoolExpr>),
    Iff(Vec<StructuralBoolExpr>),
    Ite(
        Box<StructuralBoolExpr>,
        Box<StructuralBoolExpr>,
        Box<StructuralBoolExpr>,
    ),
}

impl StructuralBoolExpr {
    fn equality(mut left: StructuralTerm, mut right: StructuralTerm) -> Self {
        if right < left {
            std::mem::swap(&mut left, &mut right);
        }
        Self::Eq(left, right)
    }

    fn negate(child: Self) -> Self {
        match child {
            Self::Const(value) => Self::Const(!value),
            Self::Not(grandchild) => *grandchild,
            child => Self::Not(Box::new(child)),
        }
    }

    fn conjunction(children: Vec<Self>) -> Self {
        let mut flattened = Vec::new();
        for child in children {
            match child {
                Self::Const(false) => return Self::Const(false),
                Self::Const(true) => {}
                Self::And(mut nested) => flattened.append(&mut nested),
                child => flattened.push(child),
            }
        }
        flattened.sort_unstable();
        flattened.dedup();
        match flattened.len() {
            0 => Self::Const(true),
            1 => flattened.pop().expect("singleton conjunction has a child"),
            _ => Self::And(flattened),
        }
    }

    fn disjunction(children: Vec<Self>) -> Self {
        let mut flattened = Vec::new();
        for child in children {
            match child {
                Self::Const(true) => return Self::Const(true),
                Self::Const(false) => {}
                Self::Or(mut nested) => flattened.append(&mut nested),
                child => flattened.push(child),
            }
        }
        flattened.sort_unstable();
        flattened.dedup();
        match flattened.len() {
            0 => Self::Const(false),
            1 => flattened.pop().expect("singleton disjunction has a child"),
            _ => Self::Or(flattened),
        }
    }

    fn equivalence(mut children: Vec<Self>) -> Self {
        children.sort_unstable();
        children.dedup();
        if children.len() <= 1 {
            Self::Const(true)
        } else {
            Self::Iff(children)
        }
    }

    fn conditional(condition: Self, then_expression: Self, else_expression: Self) -> Self {
        match condition {
            Self::Const(true) => then_expression,
            Self::Const(false) => else_expression,
            condition if then_expression == else_expression => then_expression,
            condition => Self::Ite(
                Box::new(condition),
                Box::new(then_expression),
                Box::new(else_expression),
            ),
        }
    }

    fn relabeled(&self, permutation: &CheckedPermutation) -> Self {
        match self {
            Self::Const(value) => Self::Const(*value),
            Self::Eq(left, right) => {
                Self::equality(left.relabeled(permutation), right.relabeled(permutation))
            }
            Self::Not(child) => Self::negate(child.relabeled(permutation)),
            Self::And(children) => Self::conjunction(
                children
                    .iter()
                    .map(|child| child.relabeled(permutation))
                    .collect(),
            ),
            Self::Or(children) => Self::disjunction(
                children
                    .iter()
                    .map(|child| child.relabeled(permutation))
                    .collect(),
            ),
            Self::Iff(children) => Self::equivalence(
                children
                    .iter()
                    .map(|child| child.relabeled(permutation))
                    .collect(),
            ),
            Self::Ite(condition, then_expression, else_expression) => Self::conditional(
                condition.relabeled(permutation),
                then_expression.relabeled(permutation),
                else_expression.relabeled(permutation),
            ),
        }
    }

    fn count_nodes(&self, total: &mut usize, limit: usize) -> Result<(), BaseRelabelingError> {
        add_normalized_node(total, limit)?;
        match self {
            Self::Const(_) => Ok(()),
            Self::Eq(left, right) => {
                left.count_nodes(total, limit)?;
                right.count_nodes(total, limit)
            }
            Self::Not(child) => child.count_nodes(total, limit),
            Self::And(children) | Self::Or(children) | Self::Iff(children) => {
                for child in children {
                    child.count_nodes(total, limit)?;
                }
                Ok(())
            }
            Self::Ite(condition, then_expression, else_expression) => {
                condition.count_nodes(total, limit)?;
                then_expression.count_nodes(total, limit)?;
                else_expression.count_nodes(total, limit)
            }
        }
    }

    fn fingerprint(&self, fingerprint: &mut DeterministicFingerprint) {
        match self {
            Self::Const(value) => {
                fingerprint.word(0);
                fingerprint.word(usize::from(*value));
            }
            Self::Eq(left, right) => {
                fingerprint.word(1);
                left.fingerprint(fingerprint);
                right.fingerprint(fingerprint);
            }
            Self::Not(child) => {
                fingerprint.word(2);
                child.fingerprint(fingerprint);
            }
            Self::And(children) => {
                fingerprint.word(3);
                fingerprint.word(children.len());
                for child in children {
                    child.fingerprint(fingerprint);
                }
            }
            Self::Or(children) => {
                fingerprint.word(4);
                fingerprint.word(children.len());
                for child in children {
                    child.fingerprint(fingerprint);
                }
            }
            Self::Iff(children) => {
                fingerprint.word(5);
                fingerprint.word(children.len());
                for child in children {
                    child.fingerprint(fingerprint);
                }
            }
            Self::Ite(condition, then_expression, else_expression) => {
                fingerprint.word(6);
                condition.fingerprint(fingerprint);
                then_expression.fingerprint(fingerprint);
                else_expression.fingerprint(fingerprint);
            }
        }
    }
}

fn add_normalized_node(total: &mut usize, limit: usize) -> Result<(), BaseRelabelingError> {
    *total = total
        .checked_add(1)
        .ok_or(BaseRelabelingError::StructuralCap {
            resource: "normalized-node count",
            limit,
            actual: usize::MAX,
        })?;
    if *total > limit {
        return Err(BaseRelabelingError::StructuralCap {
            resource: "normalized-node count",
            limit,
            actual: *total,
        });
    }
    Ok(())
}

struct StructuralCanonicalizer<'source, 'problem> {
    source: &'source FiniteTableSource<'problem>,
    term_memo: Vec<Option<StructuralTerm>>,
    visiting: Vec<bool>,
}

impl<'source, 'problem> StructuralCanonicalizer<'source, 'problem> {
    fn new(source: &'source FiniteTableSource<'problem>) -> Self {
        let term_count = source.problem.arena.terms.len();
        Self {
            source,
            term_memo: vec![None; term_count],
            visiting: vec![false; term_count],
        }
    }

    fn bool_expr(&mut self, expression: &BoolExpr) -> Result<StructuralBoolExpr, String> {
        match expression {
            BoolExpr::Const(value) => Ok(StructuralBoolExpr::Const(*value)),
            BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => Ok(StructuralBoolExpr::equality(
                self.term(*left)?,
                self.term(*right)?,
            )),
            BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => match self.term(*term)? {
                StructuralTerm::Bool(value) => Ok(StructuralBoolExpr::Const(value)),
                _ => Err(format!("Boolean atom {term} normalized to a domain term")),
            },
            BoolExpr::Not(child) => Ok(StructuralBoolExpr::negate(self.bool_expr(child)?)),
            BoolExpr::And(children) => Ok(StructuralBoolExpr::conjunction(
                children
                    .iter()
                    .map(|child| self.bool_expr(child))
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            BoolExpr::Or(children) => Ok(StructuralBoolExpr::disjunction(
                children
                    .iter()
                    .map(|child| self.bool_expr(child))
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            BoolExpr::Iff(children) => Ok(StructuralBoolExpr::equivalence(
                children
                    .iter()
                    .map(|child| self.bool_expr(child))
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            BoolExpr::Ite(condition, then_expression, else_expression) => {
                Ok(StructuralBoolExpr::conditional(
                    self.bool_expr(condition)?,
                    self.bool_expr(then_expression)?,
                    self.bool_expr(else_expression)?,
                ))
            }
        }
    }

    fn term(&mut self, term_id: TermId) -> Result<StructuralTerm, String> {
        let Some(term) = self.source.problem.arena.terms.get(term_id) else {
            return Err(format!("term {term_id} is missing"));
        };
        if let Some(value) = &self.term_memo[term_id] {
            return Ok(value.clone());
        }
        if self.visiting[term_id] {
            return Err(format!("term {term_id} is cyclic"));
        }
        self.visiting[term_id] = true;
        let normalized = if let Some(&position) = self.source.domain_positions.get(&term_id) {
            StructuralTerm::Domain(position)
        } else {
            let bool_problem = self
                .source
                .problem
                .bool_problem
                .as_ref()
                .expect("compiled source retains its Boolean problem");
            if term_id == bool_problem.true_term {
                StructuralTerm::Bool(true)
            } else if term_id == bool_problem.false_term {
                StructuralTerm::Bool(false)
            } else if term.fun == self.source.operation {
                let [left, right] = term.args.as_slice() else {
                    self.visiting[term_id] = false;
                    return Err(format!("operation term {term_id} is not binary"));
                };
                StructuralTerm::Operation(Box::new(self.term(*left)?), Box::new(self.term(*right)?))
            } else {
                self.visiting[term_id] = false;
                return Err(format!(
                    "term {term_id} is outside the typed carrier action"
                ));
            }
        };
        self.visiting[term_id] = false;
        self.term_memo[term_id] = Some(normalized.clone());
        Ok(normalized)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SourceBaseActionVerifier {
    degree: usize,
    fingerprint: BaseFingerprint,
    source_ordinals: Vec<usize>,
    assertions: Vec<StructuralBoolExpr>,
    target_classes: BTreeMap<StructuralBoolExpr, usize>,
    targets_by_class: Vec<Vec<usize>>,
    normalized_nodes: usize,
}

impl SourceBaseActionVerifier {
    fn from_source(
        source: &FiniteTableSource<'_>,
        caps: BaseRelabelingCaps,
    ) -> Result<Self, BaseRelabelingError> {
        let degree = source.domain.len();
        let mut canonicalizer = StructuralCanonicalizer::new(source);
        let bool_problem = source
            .problem
            .bool_problem
            .as_ref()
            .expect("compiled source retains its Boolean problem");
        let mut assertions = Vec::with_capacity(source.base_assertion_ordinals.len());
        let mut normalized_nodes = 0usize;
        for &assertion_ordinal in &source.base_assertion_ordinals {
            let normalized = canonicalizer
                .bool_expr(&bool_problem.assertions[assertion_ordinal])
                .map_err(|detail| BaseRelabelingError::Canonicalization {
                    assertion_ordinal,
                    detail,
                })?;
            normalized.count_nodes(&mut normalized_nodes, caps.max_normalized_nodes)?;
            assertions.push(normalized);
        }
        relabeling_dimensions(degree, assertions.len(), normalized_nodes, caps)?;

        let fingerprint = base_fingerprint(source, &assertions);
        let mut target_classes = BTreeMap::new();
        let mut targets_by_class = Vec::<Vec<usize>>::new();
        for (assertion, normalized) in assertions.iter().cloned().enumerate() {
            let class = if let Some(&class) = target_classes.get(&normalized) {
                class
            } else {
                let class = targets_by_class.len();
                target_classes.insert(normalized, class);
                targets_by_class.push(Vec::new());
                class
            };
            targets_by_class[class].push(assertion);
        }

        Ok(Self {
            degree,
            fingerprint,
            source_ordinals: source.base_assertion_ordinals.clone(),
            assertions,
            target_classes,
            targets_by_class,
            normalized_nodes,
        })
    }

    fn assertion_images(
        &self,
        permutation: &CheckedPermutation,
    ) -> Result<Vec<usize>, BaseRelabelingError> {
        if permutation.degree() != self.degree {
            return Err(BaseRelabelingError::CertificateMismatch(
                "witness permutation has the wrong degree",
            ));
        }
        let mut class_uses = vec![0usize; self.targets_by_class.len()];
        let mut images = Vec::with_capacity(self.assertions.len());
        for (source_base_assertion, assertion) in self.assertions.iter().enumerate() {
            let transformed = assertion.relabeled(permutation);
            let Some(&class) = self.target_classes.get(&transformed) else {
                return Err(BaseRelabelingError::NotInvariant {
                    permutation: permutation.clone(),
                    source_base_assertion,
                    source_assertion_ordinal: self.source_ordinals[source_base_assertion],
                });
            };
            let occurrence = class_uses[class];
            let Some(&target) = self.targets_by_class[class].get(occurrence) else {
                return Err(BaseRelabelingError::NotInvariant {
                    permutation: permutation.clone(),
                    source_base_assertion,
                    source_assertion_ordinal: self.source_ordinals[source_base_assertion],
                });
            };
            class_uses[class] += 1;
            images.push(target);
        }
        if class_uses
            .iter()
            .zip(&self.targets_by_class)
            .any(|(&used, targets)| used != targets.len())
        {
            return Err(BaseRelabelingError::CertificateMismatch(
                "transformed assertion multiset is not bijective",
            ));
        }
        Ok(images)
    }
}

impl BaseActionVerifier for SourceBaseActionVerifier {
    fn degree(&self) -> usize {
        self.degree
    }

    fn fingerprint(&self) -> BaseFingerprint {
        self.fingerprint
    }

    fn assertion_count(&self) -> usize {
        self.assertions.len()
    }

    fn transformed_assertion_matches(
        &self,
        permutation: &CheckedPermutation,
        source_assertion: usize,
        target_assertion: usize,
    ) -> bool {
        if permutation.degree() != self.degree {
            return false;
        }
        let Some(source) = self.assertions.get(source_assertion) else {
            return false;
        };
        let Some(target) = self.assertions.get(target_assertion) else {
            return false;
        };
        source.relabeled(permutation) == *target
    }
}

fn build_base_invariance_claim(
    verifier: &SourceBaseActionVerifier,
    caps: BaseRelabelingCaps,
) -> Result<BaseInvarianceClaim, BaseRelabelingError> {
    let expected = relabeling_dimensions(
        verifier.degree,
        verifier.assertions.len(),
        verifier.normalized_nodes,
        caps,
    )?;
    let permutations = LexicographicPermutations::new(verifier.degree)
        .map_err(|_| BaseRelabelingError::PermutationEnumeration)?;
    let mut witnesses = Vec::new();
    witnesses
        .try_reserve_exact(expected)
        .map_err(|_| BaseRelabelingError::AllocationFailure {
            resource: "permutation witnesses",
            requested: expected,
        })?;
    for permutation in permutations {
        let assertion_images = verifier.assertion_images(&permutation)?;
        witnesses.push(BasePermutationWitness::new(permutation, assertion_images));
    }
    if witnesses.len() != expected {
        return Err(BaseRelabelingError::CertificateMismatch(
            "permutation enumeration has the wrong cardinality",
        ));
    }
    Ok(BaseInvarianceClaim::new(
        verifier.degree,
        verifier.fingerprint,
        verifier.assertions.len(),
        witnesses,
    ))
}

fn replay_base_invariance_claim(
    verifier: &SourceBaseActionVerifier,
    claim: &BaseInvarianceClaim,
    caps: BaseRelabelingCaps,
) -> Result<StructuralBaseRelabelingTelemetry, BaseRelabelingError> {
    let expected = relabeling_dimensions(
        verifier.degree,
        verifier.assertions.len(),
        verifier.normalized_nodes,
        caps,
    )?;
    if claim.degree() != verifier.degree {
        return Err(BaseRelabelingError::CertificateMismatch(
            "claim degree differs from the typed source",
        ));
    }
    if claim.fingerprint() != verifier.fingerprint {
        return Err(BaseRelabelingError::CertificateMismatch(
            "claim fingerprint differs from the typed source",
        ));
    }
    if claim.assertion_count() != verifier.assertions.len() {
        return Err(BaseRelabelingError::CertificateMismatch(
            "claim assertion count differs from the typed source",
        ));
    }
    if claim.witnesses().len() != expected {
        return Err(BaseRelabelingError::CertificateMismatch(
            "claim does not contain one witness per permutation",
        ));
    }

    let permutations = LexicographicPermutations::new(verifier.degree)
        .map_err(|_| BaseRelabelingError::PermutationEnumeration)?;
    let mut permutations_checked = 0usize;
    let mut assertion_images_checked = 0usize;
    for (expected_permutation, witness) in permutations.zip(claim.witnesses()) {
        if witness.permutation() != &expected_permutation {
            return Err(BaseRelabelingError::CertificateMismatch(
                "permutation witnesses are missing, duplicated, or out of order",
            ));
        }
        if witness.assertion_images().len() != verifier.assertions.len() {
            return Err(BaseRelabelingError::CertificateMismatch(
                "an assertion-image vector has the wrong length",
            ));
        }
        let mut seen = vec![false; verifier.assertions.len()];
        for (source_assertion, &target_assertion) in witness.assertion_images().iter().enumerate() {
            let Some(seen_target) = seen.get_mut(target_assertion) else {
                return Err(BaseRelabelingError::CertificateMismatch(
                    "an assertion image is out of range",
                ));
            };
            if *seen_target {
                return Err(BaseRelabelingError::CertificateMismatch(
                    "an assertion-image vector is not bijective",
                ));
            }
            *seen_target = true;
            if !verifier.transformed_assertion_matches(
                witness.permutation(),
                source_assertion,
                target_assertion,
            ) {
                return Err(BaseRelabelingError::CertificateMismatch(
                    "independent transformed-assertion replay failed",
                ));
            }
            assertion_images_checked += 1;
        }
        permutations_checked += 1;
    }
    if permutations_checked != expected {
        return Err(BaseRelabelingError::CertificateMismatch(
            "independent replay checked the wrong number of permutations",
        ));
    }
    Ok(StructuralBaseRelabelingTelemetry {
        evidence_kind: RelabelingEvidenceKind::StructuralProof,
        degree: verifier.degree,
        base_assertions: verifier.assertions.len(),
        normalized_nodes: verifier.normalized_nodes,
        permutations_checked,
        assertion_images_checked,
    })
}

fn relabeling_dimensions(
    degree: usize,
    assertion_count: usize,
    normalized_nodes: usize,
    caps: BaseRelabelingCaps,
) -> Result<usize, BaseRelabelingError> {
    if degree > MAX_EXHAUSTIVE_DEGREE {
        return Err(BaseRelabelingError::DegreeTooLarge {
            degree,
            maximum: MAX_EXHAUSTIVE_DEGREE,
        });
    }
    let permutations = (1..=degree).try_fold(1usize, |product, factor| product.checked_mul(factor));
    let Some(permutations) = permutations else {
        return Err(BaseRelabelingError::PermutationEnumeration);
    };
    enforce_relabeling_cap("permutation count", permutations, caps.max_permutations)?;
    let assertion_images = permutations
        .checked_mul(assertion_count)
        .unwrap_or(usize::MAX);
    enforce_relabeling_cap(
        "assertion-image count",
        assertion_images,
        caps.max_assertion_images,
    )?;
    enforce_relabeling_cap(
        "normalized-node count",
        normalized_nodes,
        caps.max_normalized_nodes,
    )?;
    let node_visits = permutations
        .checked_mul(normalized_nodes)
        .unwrap_or(usize::MAX);
    enforce_relabeling_cap("normalized-node visits", node_visits, caps.max_node_visits)?;
    Ok(permutations)
}

fn enforce_relabeling_cap(
    resource: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), BaseRelabelingError> {
    if actual > limit {
        return Err(BaseRelabelingError::StructuralCap {
            resource,
            limit,
            actual,
        });
    }
    Ok(())
}

fn base_fingerprint(
    source: &FiniteTableSource<'_>,
    assertions: &[StructuralBoolExpr],
) -> BaseFingerprint {
    let mut fingerprint = DeterministicFingerprint::new();
    fingerprint.bytes(b"euf-viper.typed-base-relabeling.v1");
    fingerprint.word(source.domain.len());
    fingerprint.word(source.operation as usize);
    for &term_id in &source.domain {
        let term = &source.problem.arena.terms[term_id];
        fingerprint.word(term_id);
        fingerprint.word(term.fun as usize);
        fingerprint.word(term.sort.0 as usize);
    }
    fingerprint.word(assertions.len());
    for (&assertion_ordinal, assertion) in source.base_assertion_ordinals.iter().zip(assertions) {
        fingerprint.word(assertion_ordinal);
        assertion.fingerprint(&mut fingerprint);
    }
    BaseFingerprint::new(fingerprint.finish())
}

struct DeterministicFingerprint {
    lanes: [u64; 4],
    bytes: u64,
}

impl DeterministicFingerprint {
    const SEEDS: [u64; 4] = [
        0xcbf2_9ce4_8422_2325,
        0x8422_2325_cbf2_9ce4,
        0x9e37_79b9_7f4a_7c15,
        0x6a09_e667_f3bc_c909,
    ];
    const PRIMES: [u64; 4] = [
        0x0000_0100_0000_01b3,
        0x9e37_79b1_85eb_ca87,
        0xc2b2_ae3d_27d4_eb4f,
        0x1656_67b1_9e37_79f9,
    ];

    fn new() -> Self {
        Self {
            lanes: Self::SEEDS,
            bytes: 0,
        }
    }

    fn word(&mut self, value: usize) {
        self.bytes(&(value as u64).to_le_bytes());
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.word_length(bytes.len());
        for &byte in bytes {
            self.byte(byte);
        }
    }

    fn word_length(&mut self, value: usize) {
        for byte in (value as u64).to_le_bytes() {
            self.byte(byte);
        }
    }

    fn byte(&mut self, byte: u8) {
        self.bytes = self.bytes.wrapping_add(1);
        for lane in 0..self.lanes.len() {
            self.lanes[lane] ^= u64::from(byte).wrapping_add((lane as u64) << 8);
            self.lanes[lane] = self.lanes[lane].wrapping_mul(Self::PRIMES[lane]);
            self.lanes[lane] = self.lanes[lane].rotate_left((lane as u32) * 7 + 5);
        }
    }

    fn finish(mut self) -> [u8; 32] {
        let mut output = [0u8; 32];
        for (lane, value) in self.lanes.iter_mut().enumerate() {
            *value ^= self.bytes.wrapping_mul(Self::PRIMES[(lane + 1) % 4]);
            *value ^= *value >> 30;
            *value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
            *value ^= *value >> 27;
            *value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
            *value ^= *value >> 31;
            output[lane * 8..(lane + 1) * 8].copy_from_slice(&value.to_le_bytes());
        }
        output
    }
}

#[derive(Debug)]
struct AssertionScan {
    live_terms: BTreeSet<TermId>,
    first_assertion: BTreeMap<TermId, usize>,
    term_depths: Vec<Option<usize>>,
    visiting_terms: Vec<bool>,
    boolean_nodes: usize,
    max_term_depth: usize,
}

impl AssertionScan {
    fn new(term_count: usize) -> Self {
        Self {
            live_terms: BTreeSet::new(),
            first_assertion: BTreeMap::new(),
            term_depths: vec![None; term_count],
            visiting_terms: vec![false; term_count],
            boolean_nodes: 0,
            max_term_depth: 0,
        }
    }

    fn bool_expr(
        &mut self,
        problem: &Problem,
        expression: &BoolExpr,
        assertion_ordinal: usize,
        depth: usize,
    ) -> Result<(), SourceCompileError> {
        if depth > MAX_BOOLEAN_DEPTH {
            return Err(SourceCompileError::StructuralCap {
                resource: "Boolean depth",
                limit: MAX_BOOLEAN_DEPTH,
                actual: depth,
                assertion_ordinal: Some(assertion_ordinal),
            });
        }
        self.boolean_nodes =
            self.boolean_nodes
                .checked_add(1)
                .ok_or(SourceCompileError::StructuralCap {
                    resource: "Boolean nodes",
                    limit: MAX_BOOLEAN_NODES,
                    actual: usize::MAX,
                    assertion_ordinal: Some(assertion_ordinal),
                })?;
        if self.boolean_nodes > MAX_BOOLEAN_NODES {
            return Err(SourceCompileError::StructuralCap {
                resource: "Boolean nodes",
                limit: MAX_BOOLEAN_NODES,
                actual: self.boolean_nodes,
                assertion_ordinal: Some(assertion_ordinal),
            });
        }

        match expression {
            BoolExpr::Const(_) => Ok(()),
            BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
                self.term(problem, *left, assertion_ordinal)?;
                self.term(problem, *right, assertion_ordinal)?;
                let left_sort = problem.arena.terms[*left].sort;
                let right_sort = problem.arena.terms[*right].sort;
                if left_sort != right_sort {
                    return Err(SourceCompileError::InvalidAssertion {
                        assertion_ordinal,
                        reason: AssertionError::EqualitySortMismatch {
                            left: *left,
                            right: *right,
                        },
                    });
                }
                Ok(())
            }
            BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => {
                self.term(problem, *term, assertion_ordinal)?;
                if problem.arena.terms[*term].sort != BOOL_SORT {
                    return Err(SourceCompileError::InvalidAssertion {
                        assertion_ordinal,
                        reason: AssertionError::UndeterminedBooleanTerm(*term),
                    });
                }
                Ok(())
            }
            BoolExpr::Not(child) => self.bool_expr(problem, child, assertion_ordinal, depth + 1),
            BoolExpr::And(children) | BoolExpr::Or(children) | BoolExpr::Iff(children) => {
                for child in children {
                    self.bool_expr(problem, child, assertion_ordinal, depth + 1)?;
                }
                Ok(())
            }
            BoolExpr::Ite(condition, then_expression, else_expression) => {
                self.bool_expr(problem, condition, assertion_ordinal, depth + 1)?;
                self.bool_expr(problem, then_expression, assertion_ordinal, depth + 1)?;
                self.bool_expr(problem, else_expression, assertion_ordinal, depth + 1)
            }
        }
    }

    fn term(
        &mut self,
        problem: &Problem,
        term_id: TermId,
        assertion_ordinal: usize,
    ) -> Result<usize, SourceCompileError> {
        let Some(term) = problem.arena.terms.get(term_id) else {
            return Err(SourceCompileError::InvalidAssertion {
                assertion_ordinal,
                reason: AssertionError::MissingTerm(term_id),
            });
        };
        if self.live_terms.insert(term_id) {
            self.first_assertion.insert(term_id, assertion_ordinal);
            if self.live_terms.len() > MAX_LIVE_TERMS {
                return Err(SourceCompileError::StructuralCap {
                    resource: "live terms",
                    limit: MAX_LIVE_TERMS,
                    actual: self.live_terms.len(),
                    assertion_ordinal: Some(assertion_ordinal),
                });
            }
        }
        if let Some(depth) = self.term_depths[term_id] {
            return Ok(depth);
        }
        if self.visiting_terms[term_id] {
            return Err(SourceCompileError::InvalidAssertion {
                assertion_ordinal,
                reason: AssertionError::CyclicTerm(term_id),
            });
        }
        if term.sort.0 as usize >= problem.sorts.names.len() {
            return Err(SourceCompileError::InvalidAssertion {
                assertion_ordinal,
                reason: AssertionError::InvalidTermSort {
                    term: term_id,
                    sort: term.sort,
                },
            });
        }
        let Some(declaration) = problem.fun_decls.get(term.fun) else {
            return Err(SourceCompileError::InvalidAssertion {
                assertion_ordinal,
                reason: AssertionError::MissingDeclaration {
                    term: term_id,
                    fun: term.fun,
                },
            });
        };
        if declaration.result_sort != term.sort || declaration.arg_sorts.len() != term.args.len() {
            return Err(SourceCompileError::InvalidAssertion {
                assertion_ordinal,
                reason: AssertionError::DeclarationMismatch(term_id),
            });
        }

        self.visiting_terms[term_id] = true;
        let mut max_argument_depth = 0;
        for (position, (&argument, &expected_sort)) in
            term.args.iter().zip(&declaration.arg_sorts).enumerate()
        {
            let Some(argument_term) = problem.arena.terms.get(argument) else {
                return Err(SourceCompileError::InvalidAssertion {
                    assertion_ordinal,
                    reason: AssertionError::MissingArgument {
                        term: term_id,
                        position,
                        argument,
                    },
                });
            };
            if argument_term.sort != expected_sort {
                return Err(SourceCompileError::InvalidAssertion {
                    assertion_ordinal,
                    reason: AssertionError::ArgumentSortMismatch {
                        term: term_id,
                        position,
                    },
                });
            }
            max_argument_depth =
                max_argument_depth.max(self.term(problem, argument, assertion_ordinal)?);
        }
        let depth = if term.args.is_empty() {
            0
        } else {
            max_argument_depth.saturating_add(1)
        };
        if depth > MAX_TERM_DEPTH {
            return Err(SourceCompileError::StructuralCap {
                resource: "term depth",
                limit: MAX_TERM_DEPTH,
                actual: depth,
                assertion_ordinal: Some(assertion_ordinal),
            });
        }
        self.visiting_terms[term_id] = false;
        self.term_depths[term_id] = Some(depth);
        self.max_term_depth = self.max_term_depth.max(depth);
        Ok(depth)
    }
}

pub(crate) fn compile_finite_table_source(
    problem: &Problem,
) -> Result<FiniteTableSource<'_>, SourceCompileError> {
    let bool_problem = problem
        .bool_problem
        .as_ref()
        .ok_or(SourceCompileError::MissingBooleanProblem)?;
    let unsupported = source_unsupported_reasons(problem);
    if !unsupported.is_empty() {
        return Err(SourceCompileError::UnsupportedSource(unsupported));
    }
    enforce_global_caps(problem, bool_problem.assertions.len())?;

    let mut scan = AssertionScan::new(problem.arena.terms.len());
    for (assertion_ordinal, assertion) in bool_problem.assertions.iter().enumerate() {
        scan.bool_expr(problem, assertion, assertion_ordinal, 1)?;
    }
    validate_live_boolean_terms(problem, &scan)?;

    let mut finite = FiniteAnalysisContext::default();
    let domain_analysis = finite.domain_analysis(&problem.arena, bool_problem);
    let domain = domain_analysis.domain.clone();
    let mandatory_disequalities = domain_analysis.mandatory_disequalities.clone();
    let finite_terms = finite
        .finite_closure(&problem.arena, bool_problem)
        .finite_terms
        .clone();

    let (domain_positions, domain_sort) = validate_domain(
        problem,
        &scan,
        &domain,
        &mandatory_disequalities,
        &finite_terms,
    )?;
    let operation = validate_live_non_boolean_terms(
        problem,
        &scan,
        &domain_positions,
        domain_sort,
        &finite_terms,
    )?;

    let mut base_assertion_ordinals = Vec::new();
    let mut forbidden_records = Vec::new();
    let mut forbidden_by_table = BTreeMap::<BinaryTable, Vec<usize>>::new();
    for (assertion_ordinal, assertion) in bool_problem.assertions.iter().enumerate() {
        match extract_forbidden_table(problem, assertion, &domain_positions, operation) {
            Ok(Some(table)) => {
                if forbidden_records.len() == MAX_FORBIDDEN_TABLES {
                    return Err(SourceCompileError::StructuralCap {
                        resource: "forbidden-table records",
                        limit: MAX_FORBIDDEN_TABLES,
                        actual: forbidden_records.len() + 1,
                        assertion_ordinal: Some(assertion_ordinal),
                    });
                }
                forbidden_by_table
                    .entry(table.clone())
                    .or_default()
                    .push(assertion_ordinal);
                forbidden_records.push(ForbiddenTableRecord {
                    assertion_ordinal,
                    table,
                });
            }
            Ok(None) => base_assertion_ordinals.push(assertion_ordinal),
            Err(reason) => {
                return Err(SourceCompileError::MalformedForbiddenTable {
                    assertion_ordinal,
                    reason,
                });
            }
        }
    }

    Ok(FiniteTableSource {
        problem,
        domain,
        domain_positions,
        operation,
        live_terms: scan.live_terms,
        base_assertion_ordinals,
        forbidden_records,
        forbidden_by_table,
        max_term_depth: scan.max_term_depth,
    })
}

fn enforce_global_caps(
    problem: &Problem,
    assertion_count: usize,
) -> Result<(), SourceCompileError> {
    for (resource, limit, actual) in [
        ("source assertions", MAX_SOURCE_ASSERTIONS, assertion_count),
        ("arena terms", MAX_ARENA_TERMS, problem.arena.terms.len()),
        (
            "arena applications",
            MAX_ARENA_APPLICATIONS,
            problem.arena.apps.len(),
        ),
    ] {
        if actual > limit {
            return Err(SourceCompileError::StructuralCap {
                resource,
                limit,
                actual,
                assertion_ordinal: None,
            });
        }
    }
    for (application_index, &term) in problem.arena.apps.iter().enumerate() {
        if term >= problem.arena.terms.len() {
            return Err(SourceCompileError::InvalidArenaApplication {
                application_index,
                term,
            });
        }
    }
    Ok(())
}

fn source_unsupported_reasons(problem: &Problem) -> Vec<String> {
    let complete_bool_ast = problem
        .bool_problem
        .as_ref()
        .is_some_and(|bool_problem| bool_problem.unsupported.is_empty());
    let mut reasons = BTreeSet::new();
    for message in &problem.unsupported {
        if !(complete_bool_ast && is_legacy_route_warning(message)) {
            reasons.insert(message.clone());
        }
    }
    if let Some(bool_problem) = &problem.bool_problem {
        reasons.extend(bool_problem.unsupported.iter().cloned());
    }
    reasons.into_iter().collect()
}

fn is_legacy_route_warning(message: &str) -> bool {
    message.starts_with("positive or needs DPLL(T)")
        || message.starts_with("Boolean connective `")
        || message.starts_with("Boolean atom `")
        || message.starts_with("formula headed by `")
}

fn validate_live_boolean_terms(
    problem: &Problem,
    scan: &AssertionScan,
) -> Result<(), SourceCompileError> {
    let bool_problem = problem
        .bool_problem
        .as_ref()
        .expect("caller requires a Boolean problem");
    for &term_id in &scan.live_terms {
        if problem.arena.terms[term_id].sort != BOOL_SORT {
            continue;
        }
        let assertion_ordinal = scan.first_assertion[&term_id];
        if bool_problem.true_term == bool_problem.false_term && term_id == bool_problem.true_term {
            return Err(SourceCompileError::InvalidAssertion {
                assertion_ordinal,
                reason: AssertionError::BooleanAnchorsAlias(term_id),
            });
        }
        if term_id != bool_problem.true_term && term_id != bool_problem.false_term {
            return Err(SourceCompileError::InvalidAssertion {
                assertion_ordinal,
                reason: AssertionError::UndeterminedBooleanTerm(term_id),
            });
        }
        let term = &problem.arena.terms[term_id];
        let key = TermKey {
            fun: term.fun,
            args: Vec::new(),
        };
        if !term.args.is_empty() || problem.arena.interned.get(&key) != Some(&term_id) {
            return Err(SourceCompileError::InvalidAssertion {
                assertion_ordinal,
                reason: AssertionError::InvalidBooleanAnchor(term_id),
            });
        }
    }
    Ok(())
}

fn validate_domain(
    problem: &Problem,
    scan: &AssertionScan,
    domain: &[TermId],
    mandatory_disequalities: &rustc_hash::FxHashSet<(TermId, TermId)>,
    finite_terms: &rustc_hash::FxHashSet<TermId>,
) -> Result<(BTreeMap<TermId, usize>, SortId), SourceCompileError> {
    if !(MIN_DOMAIN_SIZE..=MAX_DOMAIN_SIZE).contains(&domain.len()) {
        return Err(SourceCompileError::InvalidDomainSize {
            actual: domain.len(),
        });
    }

    let mut positions = BTreeMap::new();
    let mut symbols = BTreeSet::new();
    let mut domain_sort = None;
    for (position, &term_id) in domain.iter().enumerate() {
        let Some(term) = problem.arena.terms.get(term_id) else {
            return Err(SourceCompileError::InvalidDomainTerm {
                term: term_id,
                reason: DomainTermError::Missing,
            });
        };
        if !scan.live_terms.contains(&term_id) {
            return Err(SourceCompileError::InvalidDomainTerm {
                term: term_id,
                reason: DomainTermError::NotLive,
            });
        }
        if term.sort == BOOL_SORT {
            return Err(SourceCompileError::InvalidDomainTerm {
                term: term_id,
                reason: DomainTermError::Boolean,
            });
        }
        if !term.args.is_empty() {
            return Err(SourceCompileError::InvalidDomainTerm {
                term: term_id,
                reason: DomainTermError::NotNullary,
            });
        }
        let Some(declaration) = problem.fun_decls.get(term.fun) else {
            return Err(SourceCompileError::InvalidDomainTerm {
                term: term_id,
                reason: DomainTermError::MissingDeclaration,
            });
        };
        if !declaration.arg_sorts.is_empty() || declaration.result_sort != term.sort {
            return Err(SourceCompileError::InvalidDomainTerm {
                term: term_id,
                reason: DomainTermError::DeclarationMismatch,
            });
        }
        let key = TermKey {
            fun: term.fun,
            args: Vec::new(),
        };
        if problem.arena.interned.get(&key) != Some(&term_id) {
            return Err(SourceCompileError::InvalidDomainTerm {
                term: term_id,
                reason: DomainTermError::NotInternedAsNamedNullary,
            });
        }
        if !symbols.insert(term.fun) {
            return Err(SourceCompileError::InvalidDomainTerm {
                term: term_id,
                reason: DomainTermError::DuplicateSymbol,
            });
        }
        if domain_sort.is_some_and(|sort| sort != term.sort) {
            return Err(SourceCompileError::InvalidDomainTerm {
                term: term_id,
                reason: DomainTermError::SortMismatch,
            });
        }
        if !finite_terms.contains(&term_id) {
            let assertion_ordinal = scan.first_assertion[&term_id];
            return Err(SourceCompileError::InvalidAssertion {
                assertion_ordinal,
                reason: AssertionError::NonFiniteTerm(term_id),
            });
        }
        domain_sort = Some(term.sort);
        positions.insert(term_id, position);
    }

    for (left_position, &left) in domain.iter().enumerate() {
        for &right in &domain[(left_position + 1)..] {
            if !mandatory_disequalities.contains(&normalized_pair(left, right)) {
                return Err(SourceCompileError::DomainTermsNotPairwiseDistinct { left, right });
            }
        }
    }
    Ok((
        positions,
        domain_sort.expect("bounded nonempty domain has a sort"),
    ))
}

fn validate_live_non_boolean_terms(
    problem: &Problem,
    scan: &AssertionScan,
    domain_positions: &BTreeMap<TermId, usize>,
    domain_sort: SortId,
    finite_terms: &rustc_hash::FxHashSet<TermId>,
) -> Result<SymId, SourceCompileError> {
    let mut ordered_terms = scan.live_terms.iter().copied().collect::<Vec<_>>();
    ordered_terms.sort_by_key(|term| (scan.first_assertion[term], *term));
    let mut operation = None;
    for term_id in ordered_terms {
        let term = &problem.arena.terms[term_id];
        if term.sort == BOOL_SORT {
            continue;
        }
        let assertion_ordinal = scan.first_assertion[&term_id];
        if domain_positions.contains_key(&term_id) {
            if !finite_terms.contains(&term_id) {
                return Err(SourceCompileError::InvalidAssertion {
                    assertion_ordinal,
                    reason: AssertionError::NonFiniteTerm(term_id),
                });
            }
            continue;
        }
        if term.args.is_empty() {
            return Err(SourceCompileError::InvalidAssertion {
                assertion_ordinal,
                reason: AssertionError::NonDomainNullaryTerm(term_id),
            });
        }
        let declaration = problem
            .fun_decls
            .get(term.fun)
            .expect("assertion scan checked live declarations");
        if term.sort != domain_sort
            || term.args.len() != 2
            || declaration.arg_sorts.as_slice() != [domain_sort, domain_sort]
            || declaration.result_sort != domain_sort
        {
            return Err(SourceCompileError::InvalidAssertion {
                assertion_ordinal,
                reason: AssertionError::NonHomogeneousBinaryTerm {
                    term: term_id,
                    fun: term.fun,
                },
            });
        }
        if let Some(expected) = operation {
            if expected != term.fun {
                return Err(SourceCompileError::MultipleBinaryOperations {
                    assertion_ordinal,
                    expected,
                    found: term.fun,
                });
            }
        } else {
            operation = Some(term.fun);
        }
        if !finite_terms.contains(&term_id) {
            return Err(SourceCompileError::InvalidAssertion {
                assertion_ordinal,
                reason: AssertionError::NonFiniteTerm(term_id),
            });
        }
    }
    operation.ok_or(SourceCompileError::MissingBinaryOperation)
}

fn extract_forbidden_table(
    problem: &Problem,
    assertion: &BoolExpr,
    domain_positions: &BTreeMap<TermId, usize>,
    operation: SymId,
) -> Result<Option<BinaryTable>, MalformedForbiddenTableError> {
    let BoolExpr::Not(inner) = assertion else {
        return Ok(None);
    };
    if !matches!(inner.as_ref(), BoolExpr::And(_)) {
        return Ok(None);
    }
    let mentions_operation = bool_expr_mentions_operation(problem, inner, operation);
    let mut equalities = Vec::new();
    if !flatten_conjunctive_equalities(inner, &mut equalities) {
        return if mentions_operation {
            Err(MalformedForbiddenTableError::NonEqualityLeaf)
        } else {
            Ok(None)
        };
    }
    if !mentions_operation {
        return Ok(None);
    }

    let degree = domain_positions.len();
    let expected = degree * degree;
    if equalities.len() != expected {
        return Err(MalformedForbiddenTableError::WrongEqualityCount {
            expected,
            actual: equalities.len(),
        });
    }
    let mut entries = vec![None; expected];
    for (equality_index, &(left, right)) in equalities.iter().enumerate() {
        let Some((row, column, value)) =
            table_cell_assignment(problem, domain_positions, operation, left, right).or_else(
                || table_cell_assignment(problem, domain_positions, operation, right, left),
            )
        else {
            return Err(MalformedForbiddenTableError::NonCellEquality { equality_index });
        };
        let slot = row * degree + column;
        if entries[slot].replace(value).is_some() {
            return Err(MalformedForbiddenTableError::DuplicateCell {
                equality_index,
                row,
                column,
            });
        }
    }
    for (slot, entry) in entries.iter().enumerate() {
        if entry.is_none() {
            return Err(MalformedForbiddenTableError::MissingCell {
                row: slot / degree,
                column: slot % degree,
            });
        }
    }
    Ok(Some(
        BinaryTable::new(degree, entries.into_iter().flatten().collect())
            .expect("checked complete table has the right shape and range"),
    ))
}

fn flatten_conjunctive_equalities(
    expression: &BoolExpr,
    output: &mut Vec<(TermId, TermId)>,
) -> bool {
    match expression {
        BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
            output.push((*left, *right));
            true
        }
        BoolExpr::And(children) => children
            .iter()
            .all(|child| flatten_conjunctive_equalities(child, output)),
        _ => false,
    }
}

fn bool_expr_mentions_operation(
    problem: &Problem,
    expression: &BoolExpr,
    operation: SymId,
) -> bool {
    match expression {
        BoolExpr::Const(_) => false,
        BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
            term_mentions_operation(problem, *left, operation)
                || term_mentions_operation(problem, *right, operation)
        }
        BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => {
            term_mentions_operation(problem, *term, operation)
        }
        BoolExpr::Not(child) => bool_expr_mentions_operation(problem, child, operation),
        BoolExpr::And(children) | BoolExpr::Or(children) | BoolExpr::Iff(children) => children
            .iter()
            .any(|child| bool_expr_mentions_operation(problem, child, operation)),
        BoolExpr::Ite(condition, then_expression, else_expression) => {
            bool_expr_mentions_operation(problem, condition, operation)
                || bool_expr_mentions_operation(problem, then_expression, operation)
                || bool_expr_mentions_operation(problem, else_expression, operation)
        }
    }
}

fn term_mentions_operation(problem: &Problem, root: TermId, operation: SymId) -> bool {
    let mut pending = vec![root];
    let mut seen = BTreeSet::new();
    while let Some(term_id) = pending.pop() {
        if !seen.insert(term_id) {
            continue;
        }
        let term = &problem.arena.terms[term_id];
        if term.fun == operation {
            return true;
        }
        pending.extend(term.args.iter().copied());
    }
    false
}

fn table_cell_assignment(
    problem: &Problem,
    domain_positions: &BTreeMap<TermId, usize>,
    operation: SymId,
    application: TermId,
    value: TermId,
) -> Option<(usize, usize, usize)> {
    let value = *domain_positions.get(&value)?;
    let term = problem.arena.terms.get(application)?;
    let [left, right] = term.args.as_slice() else {
        return None;
    };
    if term.fun != operation {
        return None;
    }
    Some((
        *domain_positions.get(left)?,
        *domain_positions.get(right)?,
        value,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TermValue {
    Domain(usize),
    Bool(bool),
}

struct CompleteTableEvaluator<'compiled, 'problem, 'table> {
    compiled: &'compiled FiniteTableSource<'problem>,
    table: &'table BinaryTable,
    memo: Vec<Option<TermValue>>,
    visiting: Vec<bool>,
}

impl<'compiled, 'problem, 'table> CompleteTableEvaluator<'compiled, 'problem, 'table> {
    fn new(compiled: &'compiled FiniteTableSource<'problem>, table: &'table BinaryTable) -> Self {
        Self {
            compiled,
            table,
            memo: vec![None; compiled.problem.arena.terms.len()],
            visiting: vec![false; compiled.problem.arena.terms.len()],
        }
    }

    fn term(&mut self, term_id: TermId) -> Result<TermValue, EvaluationError> {
        if !self.compiled.live_terms.contains(&term_id) {
            return Err(EvaluationError::TermNotLive(term_id));
        }
        if let Some(value) = self
            .memo
            .get(term_id)
            .ok_or(EvaluationError::MissingTerm(term_id))?
        {
            return Ok(*value);
        }
        if self.visiting[term_id] {
            return Err(EvaluationError::CyclicTerm(term_id));
        }
        self.visiting[term_id] = true;
        let bool_problem = self
            .compiled
            .problem
            .bool_problem
            .as_ref()
            .expect("compiled source has a Boolean problem");
        let value = if let Some(&value) = self.compiled.domain_positions.get(&term_id) {
            TermValue::Domain(value)
        } else if term_id == bool_problem.true_term {
            TermValue::Bool(true)
        } else if term_id == bool_problem.false_term {
            TermValue::Bool(false)
        } else {
            let term = self
                .compiled
                .problem
                .arena
                .terms
                .get(term_id)
                .ok_or(EvaluationError::MissingTerm(term_id))?;
            if term.fun != self.compiled.operation {
                return Err(EvaluationError::UnsupportedTerm(term_id));
            }
            let [left_term, right_term] = term.args.as_slice() else {
                return Err(EvaluationError::UnsupportedTerm(term_id));
            };
            let left = match self.term(*left_term)? {
                TermValue::Domain(value) => value,
                TermValue::Bool(_) => {
                    return Err(EvaluationError::ExpectedDomainValue(*left_term));
                }
            };
            let right = match self.term(*right_term)? {
                TermValue::Domain(value) => value,
                TermValue::Bool(_) => {
                    return Err(EvaluationError::ExpectedDomainValue(*right_term));
                }
            };
            TermValue::Domain(self.table.get(left, right).ok_or(
                EvaluationError::MissingTableCell {
                    term: term_id,
                    left,
                    right,
                },
            )?)
        };
        self.visiting[term_id] = false;
        self.memo[term_id] = Some(value);
        Ok(value)
    }

    fn bool_expr(&mut self, expression: &BoolExpr) -> Result<bool, EvaluationError> {
        match expression {
            BoolExpr::Const(value) => Ok(*value),
            BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => {
                Ok(self.term(*left)? == self.term(*right)?)
            }
            BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => match self.term(*term)? {
                TermValue::Bool(value) => Ok(value),
                TermValue::Domain(_) => Err(EvaluationError::ExpectedBooleanValue(*term)),
            },
            BoolExpr::Not(child) => Ok(!self.bool_expr(child)?),
            BoolExpr::And(children) => {
                for child in children {
                    if !self.bool_expr(child)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            BoolExpr::Or(children) => {
                for child in children {
                    if self.bool_expr(child)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            BoolExpr::Iff(children) => {
                let Some((first, rest)) = children.split_first() else {
                    return Ok(true);
                };
                let first = self.bool_expr(first)?;
                for child in rest {
                    if self.bool_expr(child)? != first {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            BoolExpr::Ite(condition, then_expression, else_expression) => {
                if self.bool_expr(condition)? {
                    self.bool_expr(then_expression)
                } else {
                    self.bool_expr(else_expression)
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PartialTermValue {
    Domain(u8),
    Bool(PartialTruth),
}

struct PartialTableEvaluator<'compiled, 'problem, 'table> {
    compiled: &'compiled FiniteTableSource<'problem>,
    cell_domains: &'table [u8],
    memo: Vec<Option<PartialTermValue>>,
    visiting: Vec<bool>,
}

impl<'compiled, 'problem, 'table> PartialTableEvaluator<'compiled, 'problem, 'table> {
    fn new(compiled: &'compiled FiniteTableSource<'problem>, cell_domains: &'table [u8]) -> Self {
        Self {
            compiled,
            cell_domains,
            memo: vec![None; compiled.problem.arena.terms.len()],
            visiting: vec![false; compiled.problem.arena.terms.len()],
        }
    }

    fn term(&mut self, term_id: TermId) -> Result<PartialTermValue, EvaluationError> {
        if !self.compiled.live_terms.contains(&term_id) {
            return Err(EvaluationError::TermNotLive(term_id));
        }
        if let Some(value) = self
            .memo
            .get(term_id)
            .ok_or(EvaluationError::MissingTerm(term_id))?
        {
            return Ok(*value);
        }
        if self.visiting[term_id] {
            return Err(EvaluationError::CyclicTerm(term_id));
        }
        self.visiting[term_id] = true;
        let bool_problem = self
            .compiled
            .problem
            .bool_problem
            .as_ref()
            .expect("compiled source has a Boolean problem");
        let value = if let Some(&position) = self.compiled.domain_positions.get(&term_id) {
            PartialTermValue::Domain(1u8 << position)
        } else if term_id == bool_problem.true_term {
            PartialTermValue::Bool(PartialTruth::True)
        } else if term_id == bool_problem.false_term {
            PartialTermValue::Bool(PartialTruth::False)
        } else {
            let term = self
                .compiled
                .problem
                .arena
                .terms
                .get(term_id)
                .ok_or(EvaluationError::MissingTerm(term_id))?;
            if term.fun != self.compiled.operation {
                return Err(EvaluationError::UnsupportedTerm(term_id));
            }
            let [left_term, right_term] = term.args.as_slice() else {
                return Err(EvaluationError::UnsupportedTerm(term_id));
            };
            let left_mask = match self.term(*left_term)? {
                PartialTermValue::Domain(mask) => mask,
                PartialTermValue::Bool(_) => {
                    return Err(EvaluationError::ExpectedDomainValue(*left_term));
                }
            };
            let right_mask = match self.term(*right_term)? {
                PartialTermValue::Domain(mask) => mask,
                PartialTermValue::Bool(_) => {
                    return Err(EvaluationError::ExpectedDomainValue(*right_term));
                }
            };
            let degree = self.compiled.domain.len();
            let mut result_mask = 0u8;
            for left in 0..degree {
                if left_mask & (1u8 << left) == 0 {
                    continue;
                }
                for right in 0..degree {
                    if right_mask & (1u8 << right) != 0 {
                        result_mask |= self.cell_domains[left * degree + right];
                    }
                }
            }
            debug_assert_ne!(result_mask, 0);
            PartialTermValue::Domain(result_mask)
        };
        self.visiting[term_id] = false;
        self.memo[term_id] = Some(value);
        Ok(value)
    }

    fn equality(&mut self, left: TermId, right: TermId) -> Result<PartialTruth, EvaluationError> {
        if left == right {
            self.term(left)?;
            return Ok(PartialTruth::True);
        }
        match (self.term(left)?, self.term(right)?) {
            (PartialTermValue::Domain(left_mask), PartialTermValue::Domain(right_mask)) => {
                if left_mask & right_mask == 0 {
                    Ok(PartialTruth::False)
                } else if left_mask == right_mask && left_mask.is_power_of_two() {
                    Ok(PartialTruth::True)
                } else {
                    Ok(PartialTruth::Unknown)
                }
            }
            (PartialTermValue::Bool(left), PartialTermValue::Bool(right)) => {
                Ok(kleene_iff([left, right]))
            }
            _ => Err(EvaluationError::UnsupportedTerm(left)),
        }
    }

    fn bool_expr(&mut self, expression: &BoolExpr) -> Result<PartialTruth, EvaluationError> {
        match expression {
            BoolExpr::Const(false) => Ok(PartialTruth::False),
            BoolExpr::Const(true) => Ok(PartialTruth::True),
            BoolExpr::Atom(BoolAtomKey::Eq(left, right)) => self.equality(*left, *right),
            BoolExpr::Atom(BoolAtomKey::BoolTerm(term)) => match self.term(*term)? {
                PartialTermValue::Bool(value) => Ok(value),
                PartialTermValue::Domain(_) => Err(EvaluationError::ExpectedBooleanValue(*term)),
            },
            BoolExpr::Not(child) => Ok(self.bool_expr(child)?.not()),
            BoolExpr::And(children) => {
                let mut result = PartialTruth::True;
                for child in children {
                    match self.bool_expr(child)? {
                        PartialTruth::False => return Ok(PartialTruth::False),
                        PartialTruth::Unknown => result = PartialTruth::Unknown,
                        PartialTruth::True => {}
                    }
                }
                Ok(result)
            }
            BoolExpr::Or(children) => {
                let mut result = PartialTruth::False;
                for child in children {
                    match self.bool_expr(child)? {
                        PartialTruth::False => {}
                        PartialTruth::Unknown => result = PartialTruth::Unknown,
                        PartialTruth::True => return Ok(PartialTruth::True),
                    }
                }
                Ok(result)
            }
            BoolExpr::Iff(children) => {
                let Some((first, rest)) = children.split_first() else {
                    return Ok(PartialTruth::True);
                };
                let first = self.bool_expr(first)?;
                if rest.is_empty() {
                    return Ok(PartialTruth::True);
                }
                let mut values = Vec::with_capacity(children.len());
                values.push(first);
                for child in rest {
                    values.push(self.bool_expr(child)?);
                }
                Ok(kleene_iff(values))
            }
            BoolExpr::Ite(condition, then_expression, else_expression) => {
                match self.bool_expr(condition)? {
                    PartialTruth::True => self.bool_expr(then_expression),
                    PartialTruth::False => self.bool_expr(else_expression),
                    PartialTruth::Unknown => {
                        let then_value = self.bool_expr(then_expression)?;
                        let else_value = self.bool_expr(else_expression)?;
                        if then_value == else_value && then_value != PartialTruth::Unknown {
                            Ok(then_value)
                        } else {
                            Ok(PartialTruth::Unknown)
                        }
                    }
                }
            }
        }
    }
}

fn kleene_iff(values: impl IntoIterator<Item = PartialTruth>) -> PartialTruth {
    let mut saw_false = false;
    let mut saw_unknown = false;
    let mut saw_true = false;
    for value in values {
        match value {
            PartialTruth::False => saw_false = true,
            PartialTruth::Unknown => saw_unknown = true,
            PartialTruth::True => saw_true = true,
        }
    }
    if saw_false && saw_true {
        PartialTruth::False
    } else if saw_unknown {
        PartialTruth::Unknown
    } else {
        PartialTruth::True
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ScopedLetMode, parse_problem_with_scoped_let_mode};
    use std::{env, fs};

    fn parse(source: &str) -> Problem {
        parse_problem_with_scoped_let_mode(source, ScopedLetMode::Off).unwrap()
    }

    fn complete_source(exclusion: &str) -> String {
        format!(
            "(set-logic QF_UF)\n\
             (declare-sort I 0)\n\
             (declare-fun a () I)\n\
             (declare-fun b () I)\n\
             (declare-fun op (I I) I)\n\
             (assert (distinct a b))\n\
             (assert (and\n\
               (or (= (op a a) a) (= (op a a) b))\n\
               (or (= (op a b) a) (= (op a b) b))\n\
               (or (= (op b a) a) (= (op b a) b))\n\
               (or (= (op b b) a) (= (op b b) b))))\n\
             (assert (= (op (op a a) b) (op a b)))\n\
             (assert {exclusion})\n\
             (check-sat)\n"
        )
    }

    fn nested_exclusion() -> &'static str {
        "(not (and\n\
           (= (op a a) a)\n\
           (and (= b (op a b))\n\
                (and (= (op b a) b) (= a (op b b))))))"
    }

    fn operation_term(
        problem: &Problem,
        compiled: &FiniteTableSource<'_>,
        left: TermId,
        right: TermId,
    ) -> TermId {
        problem.arena.interned[&TermKey {
            fun: compiled.operation(),
            args: vec![left, right],
        }]
    }

    fn degree_two_partial_table(mut ordinal: usize) -> Vec<u8> {
        (0..4)
            .map(|_| {
                let mask = [0b01, 0b10, 0b11][ordinal % 3];
                ordinal /= 3;
                mask
            })
            .collect()
    }

    fn degree_two_completions(cell_domains: &[u8]) -> Vec<BinaryTable> {
        (0..16)
            .filter_map(|ordinal| {
                let entries = (0..4).map(|cell| (ordinal >> cell) & 1).collect::<Vec<_>>();
                entries
                    .iter()
                    .enumerate()
                    .all(|(cell, &value)| cell_domains[cell] & (1u8 << value) != 0)
                    .then(|| BinaryTable::new(2, entries).unwrap())
            })
            .collect()
    }

    fn differential_expressions(
        problem: &Problem,
        compiled: &FiniteTableSource<'_>,
    ) -> Vec<BoolExpr> {
        let mut expressions = problem.bool_problem.as_ref().unwrap().assertions.clone();
        let terms = compiled
            .live_terms
            .iter()
            .copied()
            .filter(|term| problem.arena.terms[*term].sort != BOOL_SORT)
            .collect::<Vec<_>>();
        let mut equalities = Vec::new();
        for &left in &terms {
            for &right in &terms {
                equalities.push(BoolExpr::Atom(BoolAtomKey::Eq(left, right)));
            }
        }
        expressions.extend(equalities.iter().cloned());
        let first = equalities[0].clone();
        let middle = equalities[equalities.len() / 2].clone();
        let last = equalities[equalities.len() - 1].clone();
        expressions.extend([
            BoolExpr::Not(Box::new(first.clone())),
            BoolExpr::And(Vec::new()),
            BoolExpr::And(vec![first.clone(), middle.clone(), last.clone()]),
            BoolExpr::Or(Vec::new()),
            BoolExpr::Or(vec![first.clone(), middle.clone(), last.clone()]),
            BoolExpr::Iff(Vec::new()),
            BoolExpr::Iff(vec![middle.clone()]),
            BoolExpr::Iff(vec![first.clone(), middle.clone(), last.clone()]),
            BoolExpr::Ite(
                Box::new(middle.clone()),
                Box::new(first.clone()),
                Box::new(last.clone()),
            ),
            BoolExpr::Ite(
                Box::new(middle.clone()),
                Box::new(BoolExpr::Const(true)),
                Box::new(BoolExpr::Const(true)),
            ),
            BoolExpr::Ite(
                Box::new(middle),
                Box::new(BoolExpr::Const(false)),
                Box::new(BoolExpr::Const(false)),
            ),
        ]);
        expressions
    }

    fn source_with_replacement_base(replacement: &str) -> String {
        complete_source(nested_exclusion())
            .replace("(assert (= (op (op a a) b) (op a b)))", replacement)
    }

    #[test]
    fn structural_relabeling_certificate_proves_a_symmetric_base() {
        let problem = parse(&source_with_replacement_base(
            "(assert (and (= (op a a) a) (= (op b b) b)))",
        ));
        let compiled = compile_finite_table_source(&problem).unwrap();
        let certificate = compiled.certify_structural_base_relabeling().unwrap();
        let telemetry = certificate.telemetry();

        assert_eq!(
            telemetry.evidence_kind,
            RelabelingEvidenceKind::StructuralProof
        );
        assert_eq!(telemetry.degree, 2);
        assert_eq!(telemetry.base_assertions, 3);
        assert_eq!(telemetry.permutations_checked, 2);
        assert_eq!(telemetry.assertion_images_checked, 6);
        assert!(telemetry.normalized_nodes > 0);
        assert_eq!(
            compiled.verify_structural_base_relabeling(&certificate),
            Ok(telemetry)
        );
        assert_eq!(certificate.claim().witnesses().len(), 2);
    }

    #[test]
    fn structural_relabeling_tracks_assertions_that_swap_across_source_boundaries() {
        let problem = parse(&source_with_replacement_base(
            "(assert (= (op a a) a))\n(assert (= (op b b) b))",
        ));
        let compiled = compile_finite_table_source(&problem).unwrap();
        let certificate = compiled.certify_structural_base_relabeling().unwrap();
        let swap = &certificate.claim().witnesses()[1];

        assert_eq!(swap.permutation().images(), &[1, 0]);
        assert_eq!(swap.assertion_images(), &[0, 1, 3, 2]);
        assert_eq!(certificate.telemetry().assertion_images_checked, 8);
    }

    #[test]
    fn structural_relabeling_rejects_a_deliberately_asymmetric_base() {
        let problem = parse(&source_with_replacement_base("(assert (= (op a a) a))"));
        let compiled = compile_finite_table_source(&problem).unwrap();
        let error = compiled.certify_structural_base_relabeling().unwrap_err();
        assert!(matches!(
            error,
            BaseRelabelingError::NotInvariant {
                ref permutation,
                source_base_assertion: 2,
                source_assertion_ordinal: 2,
            } if permutation.images() == [1, 0]
        ));

        let table = BinaryTable::new(2, vec![0, 0, 0, 0]).unwrap();
        let relabeled = table
            .conjugated_by(&CheckedPermutation::new(vec![1, 0]).unwrap())
            .unwrap();
        assert!(compiled.base_assertions_hold(&table).unwrap());
        assert!(!compiled.base_assertions_hold(&relabeled).unwrap());
    }

    #[test]
    fn structural_relabeling_caps_fail_closed_without_a_certificate() {
        let problem = parse(&source_with_replacement_base(
            "(assert (and (= (op a a) a) (= (op b b) b)))",
        ));
        let compiled = compile_finite_table_source(&problem).unwrap();
        let caps = BaseRelabelingCaps::with_limits(
            1,
            MAX_RELABELING_ASSERTION_IMAGES,
            MAX_RELABELING_NORMALIZED_NODES,
            MAX_RELABELING_NODE_VISITS,
        );

        assert_eq!(
            compiled.certify_structural_base_relabeling_with_caps(caps),
            Err(BaseRelabelingError::StructuralCap {
                resource: "permutation count",
                limit: 1,
                actual: 2,
            })
        );
    }

    #[test]
    fn structural_relabeling_replay_rejects_an_incomplete_claim() {
        let problem = parse(&source_with_replacement_base(
            "(assert (and (= (op a a) a) (= (op b b) b)))",
        ));
        let compiled = compile_finite_table_source(&problem).unwrap();
        let certificate = compiled.certify_structural_base_relabeling().unwrap();
        let incomplete = StructuralBaseRelabelingCertificate {
            claim: BaseInvarianceClaim::new(
                certificate.claim().degree(),
                certificate.claim().fingerprint(),
                certificate.claim().assertion_count(),
                Vec::new(),
            ),
            telemetry: certificate.telemetry(),
        };

        assert_eq!(
            compiled.verify_structural_base_relabeling(&incomplete),
            Err(BaseRelabelingError::CertificateMismatch(
                "claim does not contain one witness per permutation"
            ))
        );
    }

    #[test]
    fn partial_masks_and_kleene_gates_are_exact_when_definite() {
        let problem = parse(&complete_source(nested_exclusion()));
        let compiled = compile_finite_table_source(&problem).unwrap();
        let [a, b] = compiled.domain() else {
            panic!("test source must have degree two");
        };
        let aa = operation_term(&problem, &compiled, *a, *a);
        let ab = operation_term(&problem, &compiled, *a, *b);
        let bb = operation_term(&problem, &compiled, *b, *b);
        let cell_domains = [0b11, 0b01, 0b01, 0b10];

        assert_eq!(compiled.partial_term_mask(&cell_domains, *a), Ok(0b01));
        assert_eq!(compiled.partial_term_mask(&cell_domains, *b), Ok(0b10));
        assert_eq!(compiled.partial_term_mask(&cell_domains, aa), Ok(0b11));
        let nested = compiled
            .live_terms
            .iter()
            .copied()
            .find(|term| {
                problem.arena.terms[*term]
                    .args
                    .iter()
                    .any(|argument| !problem.arena.terms[*argument].args.is_empty())
            })
            .unwrap();
        assert_eq!(compiled.partial_term_mask(&cell_domains, nested), Ok(0b11));

        let true_atom = BoolExpr::Atom(BoolAtomKey::Eq(aa, aa));
        let false_atom = BoolExpr::Atom(BoolAtomKey::Eq(ab, bb));
        let unknown_atom = BoolExpr::Atom(BoolAtomKey::Eq(aa, *a));
        assert_eq!(
            compiled.partial_bool_truth(&cell_domains, &true_atom),
            Ok(PartialTruth::True)
        );
        assert_eq!(
            compiled.partial_bool_truth(&cell_domains, &false_atom),
            Ok(PartialTruth::False)
        );
        assert_eq!(
            compiled.partial_bool_truth(&cell_domains, &unknown_atom),
            Ok(PartialTruth::Unknown)
        );
        let cases = [
            (
                BoolExpr::Not(Box::new(unknown_atom.clone())),
                PartialTruth::Unknown,
            ),
            (
                BoolExpr::And(vec![unknown_atom.clone(), false_atom.clone()]),
                PartialTruth::False,
            ),
            (
                BoolExpr::Or(vec![unknown_atom.clone(), true_atom.clone()]),
                PartialTruth::True,
            ),
            (
                BoolExpr::Iff(vec![true_atom.clone(), false_atom.clone()]),
                PartialTruth::False,
            ),
            (
                BoolExpr::Iff(vec![unknown_atom.clone(), true_atom.clone()]),
                PartialTruth::Unknown,
            ),
            (
                BoolExpr::Ite(
                    Box::new(unknown_atom.clone()),
                    Box::new(BoolExpr::Const(true)),
                    Box::new(BoolExpr::Const(true)),
                ),
                PartialTruth::True,
            ),
            (
                BoolExpr::Ite(
                    Box::new(unknown_atom.clone()),
                    Box::new(BoolExpr::Const(false)),
                    Box::new(BoolExpr::Const(false)),
                ),
                PartialTruth::False,
            ),
            (
                BoolExpr::Ite(
                    Box::new(unknown_atom),
                    Box::new(BoolExpr::Const(true)),
                    Box::new(BoolExpr::Const(false)),
                ),
                PartialTruth::Unknown,
            ),
        ];
        for (expression, expected) in cases {
            assert_eq!(
                compiled.partial_bool_truth(&cell_domains, &expression),
                Ok(expected)
            );
        }
    }

    #[test]
    fn rejects_malformed_partial_cell_domains_deterministically() {
        let problem = parse(&complete_source(nested_exclusion()));
        let compiled = compile_finite_table_source(&problem).unwrap();
        assert_eq!(
            compiled.validate_partial_cell_domains(&[1, 2, 3]),
            Err(PartialTableError::WrongCellCount {
                expected: 4,
                actual: 3,
            })
        );
        assert_eq!(
            compiled.validate_partial_cell_domains(&[1, 2, 0, 3]),
            Err(PartialTableError::EmptyCellDomain {
                cell: 2,
                row: 1,
                column: 0,
            })
        );
        assert_eq!(
            compiled.validate_partial_cell_domains(&[1, 2, 4, 3]),
            Err(PartialTableError::CellDomainOutOfRange {
                cell: 2,
                row: 1,
                column: 0,
                mask: 4,
                allowed_mask: 3,
            })
        );
        let multiple_errors = [0, 4, 1, 1];
        for _ in 0..8 {
            assert_eq!(
                compiled.validate_partial_cell_domains(&multiple_errors),
                Err(PartialTableError::EmptyCellDomain {
                    cell: 0,
                    row: 0,
                    column: 0,
                })
            );
        }
    }

    #[test]
    fn partial_first_false_base_assertion_is_source_ordered_and_deterministic() {
        let source = complete_source(nested_exclusion()).replace(
            "(assert (= (op (op a a) b) (op a b)))",
            "(assert (= (op a a) b))",
        );
        let problem = parse(&source);
        let compiled = compile_finite_table_source(&problem).unwrap();
        let all_first_value = [1, 1, 1, 1];
        for _ in 0..8 {
            assert_eq!(
                compiled.first_definitely_false_base_assertion(&all_first_value),
                Ok(Some(2))
            );
            assert_eq!(compiled.base_could_hold(&all_first_value), Ok(false));
        }
        assert_eq!(compiled.base_could_hold(&[3, 3, 3, 3]), Ok(true));
    }

    #[test]
    fn exhaustive_degree_two_partial_truth_agrees_with_every_completion() {
        let problem = parse(&complete_source(nested_exclusion()));
        let compiled = compile_finite_table_source(&problem).unwrap();
        let expressions = differential_expressions(&problem, &compiled);
        let terms = compiled
            .live_terms
            .iter()
            .copied()
            .filter(|term| problem.arena.terms[*term].sort != BOOL_SORT)
            .collect::<Vec<_>>();
        let assertions = &problem.bool_problem.as_ref().unwrap().assertions;

        for partial_ordinal in 0..81 {
            let cell_domains = degree_two_partial_table(partial_ordinal);
            let completions = degree_two_completions(&cell_domains);
            assert!(!completions.is_empty());

            for &term in &terms {
                let mask = compiled.partial_term_mask(&cell_domains, term).unwrap();
                for completion in &completions {
                    let value = compiled.evaluate_term(completion, term).unwrap();
                    assert_ne!(
                        mask & (1u8 << value),
                        0,
                        "partial table {cell_domains:?}, term {term}, completion {completion:?}"
                    );
                }
            }

            for expression in &expressions {
                let partial = compiled
                    .partial_bool_truth(&cell_domains, expression)
                    .unwrap();
                for completion in &completions {
                    let complete = compiled.evaluate_bool_expr(completion, expression).unwrap();
                    match partial {
                        PartialTruth::True => assert!(
                            complete,
                            "partial True disagrees for {cell_domains:?} and {expression:?}"
                        ),
                        PartialTruth::False => assert!(
                            !complete,
                            "partial False disagrees for {cell_domains:?} and {expression:?}"
                        ),
                        PartialTruth::Unknown => {}
                    }
                }
            }

            let first_false = compiled
                .first_definitely_false_base_assertion(&cell_domains)
                .unwrap();
            assert_eq!(
                compiled.base_could_hold(&cell_domains).unwrap(),
                first_false.is_none()
            );
            if let Some(assertion_ordinal) = first_false {
                for completion in &completions {
                    assert!(
                        !compiled
                            .evaluate_bool_expr(completion, &assertions[assertion_ordinal])
                            .unwrap()
                    );
                }
            }
        }
    }

    #[test]
    fn compiles_nested_exclusion_and_evaluates_complete_tables_exactly() {
        let problem = parse(&complete_source(nested_exclusion()));
        let compiled = compile_finite_table_source(&problem).unwrap();
        assert_eq!(compiled.domain().len(), 2);
        assert_eq!(
            compiled.counts(),
            SourceTableCounts {
                total_assertions: 4,
                base_assertions: 3,
                exclusion_assertions: 1,
                unique_forbidden_tables: 1,
                max_term_depth: 2,
            }
        );
        assert_eq!(compiled.base_assertion_ordinals(), &[0, 1, 2]);
        assert_eq!(compiled.forbidden_records()[0].assertion_ordinal, 3);

        let forbidden = BinaryTable::new(2, vec![0, 1, 1, 0]).unwrap();
        assert_eq!(
            compiled.validate_source_table(&forbidden),
            Err(SourceTableValidationError::ForbiddenTable {
                assertion_ordinals: vec![3]
            })
        );

        // This is intentionally not a Latin table; the evaluator imposes no
        // row or column structure beyond authoritative base assertions.
        let accepted = BinaryTable::new(2, vec![0, 0, 0, 0]).unwrap();
        assert_eq!(compiled.validate_source_table(&accepted), Ok(()));
        assert!(compiled.base_assertions_hold(&accepted).unwrap());
        assert_eq!(compiled.base_satisfying_forbidden_table_count().unwrap(), 1);

        let assertions = &problem.bool_problem.as_ref().unwrap().assertions;
        assert!(
            compiled
                .evaluate_bool_expr(&forbidden, &assertions[2])
                .unwrap()
        );
        assert!(
            !compiled
                .evaluate_bool_expr(&forbidden, &assertions[3])
                .unwrap()
        );
        let remaining_gates = BoolExpr::Ite(
            Box::new(BoolExpr::Const(true)),
            Box::new(BoolExpr::Iff(vec![
                BoolExpr::Const(false),
                BoolExpr::Not(Box::new(BoolExpr::Const(true))),
            ])),
            Box::new(BoolExpr::Const(false)),
        );
        assert!(
            compiled
                .evaluate_bool_expr(&accepted, &remaining_gates)
                .unwrap()
        );
    }

    #[test]
    fn retains_every_ordinal_for_duplicate_forbidden_records() {
        let source = complete_source(nested_exclusion()).replace(
            "(check-sat)",
            &format!("(assert {})\n(check-sat)", nested_exclusion()),
        );
        let problem = parse(&source);
        let compiled = compile_finite_table_source(&problem).unwrap();
        assert_eq!(compiled.counts().exclusion_assertions, 2);
        assert_eq!(compiled.counts().unique_forbidden_tables, 1);
        let forbidden = BinaryTable::new(2, vec![0, 1, 1, 0]).unwrap();
        assert_eq!(
            compiled.validate_source_table(&forbidden),
            Err(SourceTableValidationError::ForbiddenTable {
                assertion_ordinals: vec![3, 4]
            })
        );
    }

    #[test]
    fn rejects_a_duplicate_cell_near_match_with_its_assertion_ordinal() {
        let malformed = "(not (and (= (op a a) a) (= (op a b) b) (= (op b a) b) (= (op b a) a)))";
        let problem = parse(&complete_source(malformed));
        assert!(matches!(
            compile_finite_table_source(&problem),
            Err(SourceCompileError::MalformedForbiddenTable {
                assertion_ordinal: 3,
                reason: MalformedForbiddenTableError::DuplicateCell {
                    row: 1,
                    column: 0,
                    ..
                }
            })
        ));
    }

    #[test]
    fn rejects_a_live_nullary_term_outside_the_derived_domain() {
        let source = complete_source(nested_exclusion()).replace(
            "(declare-fun op (I I) I)",
            "(declare-fun op (I I) I)\n(declare-fun extra () I)",
        );
        let source = source.replace(
            "(assert (= (op (op a a) b) (op a b)))",
            "(assert (= extra a))\n(assert (= (op (op a a) b) (op a b)))",
        );
        let problem = parse(&source);
        assert!(matches!(
            compile_finite_table_source(&problem),
            Err(SourceCompileError::InvalidAssertion {
                assertion_ordinal: 2,
                reason: AssertionError::NonDomainNullaryTerm(_),
            })
        ));
    }

    #[test]
    fn rejects_a_well_sorted_operation_term_without_finite_closure() {
        let problem = parse(
            "(set-logic QF_UF)
             (declare-sort I 0)
             (declare-fun a () I)
             (declare-fun b () I)
             (declare-fun op (I I) I)
             (assert (distinct a b))
             (assert (= (op a a) a))
             (check-sat)",
        );
        assert!(matches!(
            compile_finite_table_source(&problem),
            Err(SourceCompileError::InvalidAssertion {
                assertion_ordinal: 1,
                reason: AssertionError::NonFiniteTerm(_),
            })
        ));
    }

    #[test]
    fn rejects_a_second_live_homogeneous_binary_operation() {
        let source = complete_source(nested_exclusion()).replace(
            "(declare-fun op (I I) I)",
            "(declare-fun op (I I) I)\n(declare-fun other (I I) I)",
        );
        let source = source.replace(
            "(assert (= (op (op a a) b) (op a b)))",
            "(assert (= (other a a) a))\n(assert (= (op (op a a) b) (op a b)))",
        );
        let problem = parse(&source);
        assert!(matches!(
            compile_finite_table_source(&problem),
            Err(SourceCompileError::MultipleBinaryOperations {
                assertion_ordinal: 2,
                ..
            })
        ));
    }

    #[test]
    fn ignores_unused_symbols_and_sorts_only_after_the_live_scan() {
        let source = complete_source(nested_exclusion()).replace(
            "(declare-sort I 0)",
            "(declare-sort I 0)\n(declare-sort Unused 0)\n(declare-const spare Unused)",
        );
        let source = source.replace(
            "(declare-fun op (I I) I)",
            "(declare-fun op (I I) I)\n(declare-fun unused_op (Unused Unused) Unused)",
        );
        let problem = parse(&source);
        let compiled = compile_finite_table_source(&problem).unwrap();
        let table = BinaryTable::new(2, vec![0, 0, 0, 0]).unwrap();
        assert_eq!(compiled.validate_source_table(&table), Ok(()));
    }

    #[test]
    fn reports_base_rejection_and_table_degree_without_losing_diagnostics() {
        let source = complete_source(nested_exclusion()).replace(
            "(assert (= (op (op a a) b) (op a b)))",
            "(assert (= (op a a) b))",
        );
        let problem = parse(&source);
        let compiled = compile_finite_table_source(&problem).unwrap();
        let all_a = BinaryTable::new(2, vec![0, 0, 0, 0]).unwrap();
        assert_eq!(
            compiled.validate_source_table(&all_a),
            Err(SourceTableValidationError::BaseAssertionFalse {
                assertion_ordinal: 2
            })
        );
        let wrong_degree = BinaryTable::new(3, vec![0; 9]).unwrap();
        assert_eq!(
            compiled.validate_source_table(&wrong_degree),
            Err(SourceTableValidationError::WrongTableDegree {
                expected: 2,
                actual: 3
            })
        );
    }

    #[test]
    #[ignore = "requires EUF_VIPER_FINITE_TABLE_CASE"]
    fn probe_external_finite_table_case() {
        let source = fs::read_to_string(env::var("EUF_VIPER_FINITE_TABLE_CASE").unwrap()).unwrap();
        let problem = parse_problem_with_scoped_let_mode(&source, ScopedLetMode::Auto).unwrap();
        let compiled = compile_finite_table_source(&problem).unwrap();
        let counts = compiled.counts();
        let base_satisfying_forbidden_tables =
            compiled.base_satisfying_forbidden_table_count().unwrap();
        let relabeling = compiled.certify_structural_base_relabeling().unwrap();
        let relabeling_telemetry = compiled
            .verify_structural_base_relabeling(&relabeling)
            .unwrap();
        println!(
            concat!(
                "{{\"total_assertions\":{},\"base_assertions\":{},",
                "\"exclusion_assertions\":{},\"unique_forbidden_tables\":{},",
                "\"base_satisfying_forbidden_tables\":{},\"max_term_depth\":{},",
                "\"relabeling_evidence\":\"structural_proof\",",
                "\"relabeling_permutations\":{},\"relabeling_assertion_images\":{},",
                "\"relabeling_normalized_nodes\":{}}}"
            ),
            counts.total_assertions,
            counts.base_assertions,
            counts.exclusion_assertions,
            counts.unique_forbidden_tables,
            base_satisfying_forbidden_tables,
            counts.max_term_depth,
            relabeling_telemetry.permutations_checked,
            relabeling_telemetry.assertion_images_checked,
            relabeling_telemetry.normalized_nodes,
        );
    }
}
