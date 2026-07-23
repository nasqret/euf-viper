#![forbid(unsafe_code)]

//! Bounded, representation-neutral solve certificates for Fabric.
//!
//! The envelope uses only projected semantic data and stable [`AtomId`] and
//! [`TermId`] identifiers. SAT evidence contains every source-atom value and a
//! canonical model summary. The checker derives a relation witness from that
//! summary, calls the independent model validator, and requires byte-for-byte
//! equality of the reconstructed canonical data. UNSAT evidence is an existing
//! [`CoverProof`] and is accepted only through [`cover::check_cover`].
//!
//! This is deliberately a correctness substrate, not Fabric's eventual compact
//! scalable proof format. In particular, the current UNSAT cover is exponential
//! in the source-atom count and the SAT payload repeats reconstructible model
//! data. The format constant versions the in-memory contract; it does not yet
//! promise a durable wire encoding.

use super::cover::{
    self, CoverAbstention, CoverCaps, CoverCheck, CoverError, CoverProof, CoverReceipt,
};
use super::model::{
    self, CandidateRelation, CanonicalBooleanValues, CanonicalClass, CanonicalFunction,
    CanonicalModel, InvalidModel, ModelCaps, ModelError, ModelLimit, ModelValidation,
};
use super::native_clause::AtomId;
use super::partition::TermId;
use super::semantic::{SemanticAtom, SemanticExpr, SemanticProblem};
use std::error::Error;
use std::fmt;

pub(crate) const FABRIC_SOLVE_CERTIFICATE_V1: &str = "fabric-solve-certificate-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ProblemFingerprint([u8; 32]);

impl ProblemFingerprint {
    pub(crate) const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for ProblemFingerprint {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(output, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SourceAtomValue {
    pub(crate) atom: AtomId,
    pub(crate) value: bool,
}

/// The semantic portion of [`CanonicalModel`]. Reconstruction counters are
/// intentionally receipts, not witness data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalModelData {
    pub(crate) term_classes: Box<[TermId]>,
    pub(crate) classes: Box<[CanonicalClass]>,
    pub(crate) functions: Box<[CanonicalFunction]>,
    pub(crate) boolean_values: Option<CanonicalBooleanValues>,
}

impl From<CanonicalModel> for CanonicalModelData {
    fn from(model: CanonicalModel) -> Self {
        Self {
            term_classes: model.term_classes,
            classes: model.classes,
            functions: model.functions,
            boolean_values: model.boolean_values,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SatCertificate {
    pub(crate) source_atom_values: Box<[SourceAtomValue]>,
    pub(crate) model: CanonicalModelData,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnsatCertificate {
    pub(crate) cover: CoverProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CertificatePayload {
    Sat(SatCertificate),
    Unsat(UnsatCertificate),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SolveCertificate {
    pub(crate) format: Box<str>,
    pub(crate) problem: ProblemFingerprint,
    pub(crate) payload: CertificatePayload,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CertificateCaps {
    pub(crate) max_format_bytes: usize,
    pub(crate) max_problem_terms: usize,
    pub(crate) max_source_atoms: usize,
    pub(crate) max_term_arguments: usize,
    pub(crate) max_expression_nodes: usize,
    pub(crate) max_root_literals: usize,
    pub(crate) max_model_classes: usize,
    pub(crate) max_model_class_members: usize,
    pub(crate) max_model_functions: usize,
    pub(crate) max_model_function_entries: usize,
    pub(crate) max_model_argument_cells: usize,
    pub(crate) max_cover_nodes: usize,
    pub(crate) max_check_work: usize,
    pub(crate) model: ModelCaps,
    pub(crate) cover: CoverCaps,
}

impl Default for CertificateCaps {
    fn default() -> Self {
        Self {
            max_format_bytes: 64,
            max_problem_terms: 1_000_000,
            max_source_atoms: 1_000_000,
            max_term_arguments: 4_000_000,
            max_expression_nodes: 4_000_000,
            max_root_literals: 2_000_000,
            max_model_classes: 1_000_000,
            max_model_class_members: 1_000_000,
            max_model_functions: 1_000_000,
            max_model_function_entries: 1_000_000,
            max_model_argument_cells: 4_000_000,
            max_cover_nodes: 1_000_000,
            max_check_work: 64_000_000,
            model: ModelCaps::default(),
            cover: CoverCaps::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CertificateResource {
    FormatBytes,
    ProblemTerms,
    SourceAtoms,
    TermArguments,
    ExpressionNodes,
    RootLiterals,
    ModelClasses,
    ModelClassMembers,
    ModelFunctions,
    ModelFunctionEntries,
    ModelArgumentCells,
    CoverNodes,
    CheckWork,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CertificateLimit {
    pub(crate) resource: CertificateResource,
    pub(crate) attempted: usize,
    pub(crate) limit: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CertificateAbstention {
    Envelope(CertificateLimit),
    Model(ModelLimit),
    Cover(CoverAbstention),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CertificateBuild {
    Built(SolveCertificate),
    Abstained(CertificateLimit),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SatReceipt {
    pub(crate) source_atoms_checked: usize,
    pub(crate) terms_checked: usize,
    pub(crate) classes_checked: usize,
    pub(crate) class_members_checked: usize,
    pub(crate) functions_checked: usize,
    pub(crate) function_entries_checked: usize,
    pub(crate) function_argument_cells_checked: usize,
    pub(crate) reconstruction_rounds: usize,
    pub(crate) reconstruction_merges: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CertificateReceiptKind {
    Sat(SatReceipt),
    Unsat(CoverReceipt),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CertificateReceipt {
    pub(crate) format: &'static str,
    pub(crate) problem: ProblemFingerprint,
    /// Deterministic envelope work only. Nested model/cover limits remain
    /// independently enforced by their checkers.
    pub(crate) envelope_work: usize,
    pub(crate) kind: CertificateReceiptKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CertificateCheck {
    Valid(CertificateReceipt),
    Abstained(CertificateAbstention),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ModelObjectError {
    TermClassCount {
        declared: usize,
        expected: usize,
    },
    ClassCountExceedsTerms {
        classes: usize,
        terms: usize,
    },
    EmptyClass {
        class: usize,
    },
    ClassesNotStrictlyOrdered {
        class: usize,
        previous: TermId,
        current: TermId,
    },
    RepresentativeOutOfRange {
        class: usize,
        representative: TermId,
        term_count: usize,
    },
    NonCanonicalRepresentative {
        class: usize,
        representative: TermId,
        first_member: TermId,
    },
    ClassSortMismatch {
        class: usize,
        declared: u32,
        actual: u32,
    },
    MemberOutOfRange {
        class: usize,
        member: TermId,
        term_count: usize,
    },
    MembersNotStrictlyOrdered {
        class: usize,
        previous: TermId,
        current: TermId,
    },
    DuplicateMember {
        term: TermId,
    },
    MemberSortMismatch {
        class: usize,
        member: TermId,
        expected: u32,
        actual: u32,
    },
    TermClassMismatch {
        term: TermId,
        declared: TermId,
        class: TermId,
    },
    MissingClassMember {
        term: TermId,
    },
    TermRepresentativeOutOfRange {
        term: TermId,
        representative: TermId,
        term_count: usize,
    },
    FunctionsNotStrictlyOrdered {
        function: usize,
        previous: u32,
        current: u32,
    },
    FunctionValueOutOfRange {
        function: usize,
        term: TermId,
        term_count: usize,
    },
    NonCanonicalFunctionValue {
        function: usize,
        term: TermId,
        representative: TermId,
    },
    FunctionResultSortMismatch {
        function: usize,
        term: TermId,
        expected: u32,
        actual: u32,
    },
    FunctionEntryArity {
        function: usize,
        entry: usize,
        expected: usize,
        actual: usize,
    },
    FunctionArgumentSortMismatch {
        function: usize,
        entry: usize,
        position: usize,
        expected: u32,
        actual: u32,
    },
    FunctionEntriesNotStrictlyOrdered {
        function: usize,
        entry: usize,
    },
    BooleanValueOutOfRange {
        term: TermId,
        term_count: usize,
    },
    NonCanonicalBooleanValue {
        term: TermId,
        representative: TermId,
    },
    BooleanValuesCollapsed {
        representative: TermId,
    },
}

impl fmt::Display for ModelObjectError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TermClassCount { declared, expected } => write!(
                output,
                "certificate model has {declared} term classes; expected exactly {expected}"
            ),
            Self::ClassCountExceedsTerms { classes, terms } => write!(
                output,
                "certificate model has {classes} classes for only {terms} terms"
            ),
            Self::EmptyClass { class } => {
                write!(output, "certificate model class {class} is empty")
            }
            Self::ClassesNotStrictlyOrdered {
                class,
                previous,
                current,
            } => write!(
                output,
                "certificate model class {class} representative {current} does not follow {previous}"
            ),
            Self::RepresentativeOutOfRange {
                class,
                representative,
                term_count,
            } => write!(
                output,
                "certificate model class {class} representative {representative} is outside 0..{term_count}"
            ),
            Self::NonCanonicalRepresentative {
                class,
                representative,
                first_member,
            } => write!(
                output,
                "certificate model class {class} representative {representative} is not its first member {first_member}"
            ),
            Self::ClassSortMismatch {
                class,
                declared,
                actual,
            } => write!(
                output,
                "certificate model class {class} declares sort {declared}, expected {actual}"
            ),
            Self::MemberOutOfRange {
                class,
                member,
                term_count,
            } => write!(
                output,
                "certificate model class {class} member {member} is outside 0..{term_count}"
            ),
            Self::MembersNotStrictlyOrdered {
                class,
                previous,
                current,
            } => write!(
                output,
                "certificate model class {class} member {current} does not follow {previous}"
            ),
            Self::DuplicateMember { term } => {
                write!(
                    output,
                    "certificate model repeats term {term} in its classes"
                )
            }
            Self::MemberSortMismatch {
                class,
                member,
                expected,
                actual,
            } => write!(
                output,
                "certificate model class {class} member {member} has sort {actual}, expected {expected}"
            ),
            Self::TermClassMismatch {
                term,
                declared,
                class,
            } => write!(
                output,
                "certificate model term {term} declares class {declared}, but appears in class {class}"
            ),
            Self::MissingClassMember { term } => {
                write!(
                    output,
                    "certificate model has no class member for term {term}"
                )
            }
            Self::TermRepresentativeOutOfRange {
                term,
                representative,
                term_count,
            } => write!(
                output,
                "certificate model term {term} representative {representative} is outside 0..{term_count}"
            ),
            Self::FunctionsNotStrictlyOrdered {
                function,
                previous,
                current,
            } => write!(
                output,
                "certificate model function {function} ID {current} does not follow {previous}"
            ),
            Self::FunctionValueOutOfRange {
                function,
                term,
                term_count,
            } => write!(
                output,
                "certificate model function {function} uses term {term} outside 0..{term_count}"
            ),
            Self::NonCanonicalFunctionValue {
                function,
                term,
                representative,
            } => write!(
                output,
                "certificate model function {function} uses noncanonical term {term} with representative {representative}"
            ),
            Self::FunctionResultSortMismatch {
                function,
                term,
                expected,
                actual,
            } => write!(
                output,
                "certificate model function {function} result {term} has sort {actual}, expected {expected}"
            ),
            Self::FunctionEntryArity {
                function,
                entry,
                expected,
                actual,
            } => write!(
                output,
                "certificate model function {function} entry {entry} has arity {actual}, expected {expected}"
            ),
            Self::FunctionArgumentSortMismatch {
                function,
                entry,
                position,
                expected,
                actual,
            } => write!(
                output,
                "certificate model function {function} entry {entry} argument {position} has sort {actual}, expected {expected}"
            ),
            Self::FunctionEntriesNotStrictlyOrdered { function, entry } => write!(
                output,
                "certificate model function {function} entry {entry} is not strictly ordered"
            ),
            Self::BooleanValueOutOfRange { term, term_count } => write!(
                output,
                "certificate model Boolean value {term} is outside 0..{term_count}"
            ),
            Self::NonCanonicalBooleanValue {
                term,
                representative,
            } => write!(
                output,
                "certificate model Boolean value {term} is not canonical; representative is {representative}"
            ),
            Self::BooleanValuesCollapsed { representative } => write!(
                output,
                "certificate model collapses true and false to class {representative}"
            ),
        }
    }
}

impl Error for ModelObjectError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CertificateError {
    WrongFormat,
    WrongProblem {
        declared: ProblemFingerprint,
        actual: ProblemFingerprint,
    },
    SourceAtomCount {
        declared: usize,
        expected: usize,
    },
    NonCanonicalSourceAtom {
        position: usize,
        atom: AtomId,
        expected: AtomId,
    },
    ModelObject(ModelObjectError),
    ModelMismatch,
    SatRejected(InvalidModel),
    StableIdSpaceExhausted {
        context: &'static str,
        count: usize,
    },
    ArithmeticOverflow {
        context: &'static str,
    },
    AllocationFailed {
        context: &'static str,
    },
    Model(ModelError),
    Cover(CoverError),
}

impl fmt::Display for CertificateError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongFormat => write!(output, "unsupported Fabric solve-certificate format"),
            Self::WrongProblem { declared, actual } => write!(
                output,
                "certificate is bound to problem {declared}, not checked problem {actual}"
            ),
            Self::SourceAtomCount { declared, expected } => write!(
                output,
                "certificate has {declared} source-atom values; expected exactly {expected}"
            ),
            Self::NonCanonicalSourceAtom {
                position,
                atom,
                expected,
            } => write!(
                output,
                "certificate source value {position} names atom {}, expected {}",
                atom.index(),
                expected.index()
            ),
            Self::ModelObject(error) => error.fmt(output),
            Self::ModelMismatch => write!(
                output,
                "certificate model differs from independent canonical reconstruction"
            ),
            Self::SatRejected(reason) => {
                write!(output, "certificate SAT witness is invalid: {reason:?}")
            }
            Self::StableIdSpaceExhausted { context, count } => {
                write!(
                    output,
                    "{context} count {count} does not fit a stable identifier"
                )
            }
            Self::ArithmeticOverflow { context } => {
                write!(output, "arithmetic overflow while checking {context}")
            }
            Self::AllocationFailed { context } => {
                write!(output, "allocation failed while checking {context}")
            }
            Self::Model(error) => error.fmt(output),
            Self::Cover(error) => error.fmt(output),
        }
    }
}

impl Error for CertificateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ModelObject(error) => Some(error),
            Self::Model(error) => Some(error),
            Self::Cover(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ModelError> for CertificateError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<CoverError> for CertificateError {
    fn from(error: CoverError) -> Self {
        Self::Cover(error)
    }
}

impl From<ModelObjectError> for CertificateError {
    fn from(error: ModelObjectError) -> Self {
        Self::ModelObject(error)
    }
}

#[derive(Debug)]
enum CheckFailure {
    Limit(CertificateLimit),
    Error(CertificateError),
}

impl From<CertificateError> for CheckFailure {
    fn from(error: CertificateError) -> Self {
        Self::Error(error)
    }
}

impl From<ModelObjectError> for CheckFailure {
    fn from(error: ModelObjectError) -> Self {
        Self::Error(CertificateError::ModelObject(error))
    }
}

#[derive(Debug)]
struct WorkBudget {
    used: usize,
    maximum: usize,
}

impl WorkBudget {
    fn new(maximum: usize) -> Self {
        Self { used: 0, maximum }
    }

    fn charge(&mut self, amount: usize) -> Result<(), CheckFailure> {
        let attempted = self.used.checked_add(amount).unwrap_or(usize::MAX);
        enforce_limit(CertificateResource::CheckWork, attempted, self.maximum)?;
        self.used = attempted;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ModelCounts {
    class_members: usize,
    function_entries: usize,
    function_argument_cells: usize,
}

enum InnerCheck {
    Valid(CertificateReceipt),
    Abstained(CertificateAbstention),
}

pub(crate) fn bind_sat(
    problem: &SemanticProblem,
    source_atom_values: &[bool],
    model: CanonicalModel,
    caps: CertificateCaps,
) -> Result<CertificateBuild, CertificateError> {
    let mut budget = WorkBudget::new(caps.max_check_work);
    let fingerprint = match fingerprint_problem(problem, caps, &mut budget) {
        Ok(fingerprint) => fingerprint,
        Err(CheckFailure::Limit(limit)) => return Ok(CertificateBuild::Abstained(limit)),
        Err(CheckFailure::Error(error)) => return Err(error),
    };
    if source_atom_values.len() != problem.atoms.len() {
        return Err(CertificateError::SourceAtomCount {
            declared: source_atom_values.len(),
            expected: problem.atoms.len(),
        });
    }
    if let Err(failure) = enforce_limit(
        CertificateResource::SourceAtoms,
        source_atom_values.len(),
        caps.max_source_atoms,
    ) {
        return finish_build_failure(failure);
    }

    let model = CanonicalModelData::from(model);
    if let Err(failure) = count_model_payload(&model, caps, &mut budget) {
        return finish_build_failure(failure);
    }

    let mut values = Vec::new();
    values
        .try_reserve_exact(source_atom_values.len())
        .map_err(|_| CertificateError::AllocationFailed {
            context: "certificate source values",
        })?;
    for (index, &value) in source_atom_values.iter().enumerate() {
        values.push(SourceAtomValue {
            atom: checked_atom_id(index)?,
            value,
        });
    }

    Ok(CertificateBuild::Built(SolveCertificate {
        format: FABRIC_SOLVE_CERTIFICATE_V1.into(),
        problem: fingerprint,
        payload: CertificatePayload::Sat(SatCertificate {
            source_atom_values: values.into_boxed_slice(),
            model,
        }),
    }))
}

pub(crate) fn bind_unsat(
    problem: &SemanticProblem,
    cover: CoverProof,
    caps: CertificateCaps,
) -> Result<CertificateBuild, CertificateError> {
    let mut budget = WorkBudget::new(caps.max_check_work);
    let fingerprint = match fingerprint_problem(problem, caps, &mut budget) {
        Ok(fingerprint) => fingerprint,
        Err(CheckFailure::Limit(limit)) => return Ok(CertificateBuild::Abstained(limit)),
        Err(CheckFailure::Error(error)) => return Err(error),
    };
    if let Err(failure) = enforce_limit(
        CertificateResource::CoverNodes,
        cover.nodes.len(),
        caps.max_cover_nodes,
    ) {
        return finish_build_failure(failure);
    }
    Ok(CertificateBuild::Built(SolveCertificate {
        format: FABRIC_SOLVE_CERTIFICATE_V1.into(),
        problem: fingerprint,
        payload: CertificatePayload::Unsat(UnsatCertificate { cover }),
    }))
}

fn finish_build_failure(failure: CheckFailure) -> Result<CertificateBuild, CertificateError> {
    match failure {
        CheckFailure::Limit(limit) => Ok(CertificateBuild::Abstained(limit)),
        CheckFailure::Error(error) => Err(error),
    }
}

pub(crate) fn check_certificate(
    problem: &SemanticProblem,
    certificate: &SolveCertificate,
    caps: CertificateCaps,
) -> Result<CertificateCheck, CertificateError> {
    match check_inner(problem, certificate, caps) {
        Ok(InnerCheck::Valid(receipt)) => Ok(CertificateCheck::Valid(receipt)),
        Ok(InnerCheck::Abstained(reason)) => Ok(CertificateCheck::Abstained(reason)),
        Err(CheckFailure::Limit(limit)) => Ok(CertificateCheck::Abstained(
            CertificateAbstention::Envelope(limit),
        )),
        Err(CheckFailure::Error(error)) => Err(error),
    }
}

fn check_inner(
    problem: &SemanticProblem,
    certificate: &SolveCertificate,
    caps: CertificateCaps,
) -> Result<InnerCheck, CheckFailure> {
    enforce_limit(
        CertificateResource::FormatBytes,
        certificate.format.len(),
        caps.max_format_bytes,
    )?;
    if certificate.format.as_ref() != FABRIC_SOLVE_CERTIFICATE_V1 {
        return Err(CertificateError::WrongFormat.into());
    }

    let mut budget = WorkBudget::new(caps.max_check_work);
    budget.charge(certificate.format.len().saturating_add(1))?;
    let actual_problem = fingerprint_problem(problem, caps, &mut budget)?;
    if certificate.problem != actual_problem {
        return Err(CertificateError::WrongProblem {
            declared: certificate.problem,
            actual: actual_problem,
        }
        .into());
    }

    match &certificate.payload {
        CertificatePayload::Sat(sat) => check_sat(problem, sat, actual_problem, caps, budget),
        CertificatePayload::Unsat(unsat) => {
            check_unsat(problem, unsat, actual_problem, caps, budget)
        }
    }
}

fn check_sat(
    problem: &SemanticProblem,
    certificate: &SatCertificate,
    fingerprint: ProblemFingerprint,
    caps: CertificateCaps,
    mut budget: WorkBudget,
) -> Result<InnerCheck, CheckFailure> {
    enforce_limit(
        CertificateResource::SourceAtoms,
        certificate.source_atom_values.len(),
        caps.max_source_atoms,
    )?;
    if certificate.source_atom_values.len() != problem.atoms.len() {
        return Err(CertificateError::SourceAtomCount {
            declared: certificate.source_atom_values.len(),
            expected: problem.atoms.len(),
        }
        .into());
    }

    let counts = validate_model_object(problem, &certificate.model, caps, &mut budget)?;
    let mut source_values = Vec::new();
    source_values
        .try_reserve_exact(certificate.source_atom_values.len())
        .map_err(|_| CertificateError::AllocationFailed {
            context: "checked source values",
        })?;
    for (position, entry) in certificate.source_atom_values.iter().enumerate() {
        budget.charge(1)?;
        let expected = checked_atom_id(position)?;
        if entry.atom != expected {
            return Err(CertificateError::NonCanonicalSourceAtom {
                position,
                atom: entry.atom,
                expected,
            }
            .into());
        }
        source_values.push(entry.value);
    }

    let mut relations = Vec::new();
    relations
        .try_reserve_exact(certificate.model.term_classes.len())
        .map_err(|_| CertificateError::AllocationFailed {
            context: "certificate model relation witness",
        })?;
    for (index, &representative) in certificate.model.term_classes.iter().enumerate() {
        budget.charge(1)?;
        let term = checked_term_id(index)?;
        if term != representative {
            relations.push(CandidateRelation::equality(term, representative));
        }
    }

    let rebuilt = match model::validate_complete_with_relations(
        problem,
        &source_values,
        &relations,
        caps.model,
    )
    .map_err(CertificateError::Model)?
    {
        ModelValidation::Valid(model) => model,
        ModelValidation::Invalid(reason) => {
            return Err(CertificateError::SatRejected(reason).into());
        }
        ModelValidation::Abstained(limit) => {
            return Ok(InnerCheck::Abstained(CertificateAbstention::Model(limit)));
        }
    };
    let reconstruction_rounds = rebuilt.congruence_rounds;
    let reconstruction_merges = rebuilt.congruence_merges;
    if CanonicalModelData::from(rebuilt) != certificate.model {
        return Err(CertificateError::ModelMismatch.into());
    }

    Ok(InnerCheck::Valid(CertificateReceipt {
        format: FABRIC_SOLVE_CERTIFICATE_V1,
        problem: fingerprint,
        envelope_work: budget.used,
        kind: CertificateReceiptKind::Sat(SatReceipt {
            source_atoms_checked: source_values.len(),
            terms_checked: certificate.model.term_classes.len(),
            classes_checked: certificate.model.classes.len(),
            class_members_checked: counts.class_members,
            functions_checked: certificate.model.functions.len(),
            function_entries_checked: counts.function_entries,
            function_argument_cells_checked: counts.function_argument_cells,
            reconstruction_rounds,
            reconstruction_merges,
        }),
    }))
}

fn check_unsat(
    problem: &SemanticProblem,
    certificate: &UnsatCertificate,
    fingerprint: ProblemFingerprint,
    caps: CertificateCaps,
    mut budget: WorkBudget,
) -> Result<InnerCheck, CheckFailure> {
    enforce_limit(
        CertificateResource::CoverNodes,
        certificate.cover.nodes.len(),
        caps.max_cover_nodes,
    )?;
    budget.charge(1)?;
    match cover::check_cover(problem, &certificate.cover, caps.cover)
        .map_err(CertificateError::Cover)?
    {
        CoverCheck::Valid(receipt) => Ok(InnerCheck::Valid(CertificateReceipt {
            format: FABRIC_SOLVE_CERTIFICATE_V1,
            problem: fingerprint,
            envelope_work: budget.used,
            kind: CertificateReceiptKind::Unsat(receipt),
        })),
        CoverCheck::Abstained(reason) => {
            Ok(InnerCheck::Abstained(CertificateAbstention::Cover(reason)))
        }
    }
}

fn enforce_limit(
    resource: CertificateResource,
    attempted: usize,
    limit: usize,
) -> Result<(), CheckFailure> {
    if attempted <= limit {
        Ok(())
    } else {
        Err(CheckFailure::Limit(CertificateLimit {
            resource,
            attempted,
            limit,
        }))
    }
}

fn checked_atom_id(index: usize) -> Result<AtomId, CertificateError> {
    let raw = u32::try_from(index).map_err(|_| CertificateError::StableIdSpaceExhausted {
        context: "source atom",
        count: index.saturating_add(1),
    })?;
    Ok(AtomId::new(raw))
}

fn checked_term_id(index: usize) -> Result<TermId, CertificateError> {
    TermId::try_from(index).map_err(|_| CertificateError::StableIdSpaceExhausted {
        context: "semantic term",
        count: index.saturating_add(1),
    })
}

fn count_model_payload(
    model: &CanonicalModelData,
    caps: CertificateCaps,
    budget: &mut WorkBudget,
) -> Result<ModelCounts, CheckFailure> {
    enforce_limit(
        CertificateResource::ProblemTerms,
        model.term_classes.len(),
        caps.max_problem_terms,
    )?;
    enforce_limit(
        CertificateResource::ModelClasses,
        model.classes.len(),
        caps.max_model_classes,
    )?;
    enforce_limit(
        CertificateResource::ModelFunctions,
        model.functions.len(),
        caps.max_model_functions,
    )?;

    let mut counts = ModelCounts::default();
    for class in &model.classes {
        counts.class_members = checked_add(
            counts.class_members,
            class.members.len(),
            "certificate model class members",
        )?;
        enforce_limit(
            CertificateResource::ModelClassMembers,
            counts.class_members,
            caps.max_model_class_members,
        )?;
    }
    for function in &model.functions {
        counts.function_entries = checked_add(
            counts.function_entries,
            function.entries.len(),
            "certificate model function entries",
        )?;
        enforce_limit(
            CertificateResource::ModelFunctionEntries,
            counts.function_entries,
            caps.max_model_function_entries,
        )?;
        counts.function_argument_cells = checked_add(
            counts.function_argument_cells,
            function.argument_sorts.len(),
            "certificate model function signatures",
        )?;
        for entry in &function.entries {
            counts.function_argument_cells = checked_add(
                counts.function_argument_cells,
                entry.arguments.len(),
                "certificate model function arguments",
            )?;
        }
        enforce_limit(
            CertificateResource::ModelArgumentCells,
            counts.function_argument_cells,
            caps.max_model_argument_cells,
        )?;
    }

    let work = checked_add(
        checked_add(
            model.term_classes.len(),
            model.classes.len(),
            "certificate model count work",
        )?,
        checked_add(
            counts.class_members,
            checked_add(
                model.functions.len(),
                checked_add(
                    counts.function_entries,
                    counts.function_argument_cells,
                    "certificate model function work",
                )?,
                "certificate model function work",
            )?,
            "certificate model member work",
        )?,
        "certificate model work",
    )?;
    budget.charge(work.saturating_add(1))?;
    Ok(counts)
}

fn validate_model_object(
    problem: &SemanticProblem,
    model: &CanonicalModelData,
    caps: CertificateCaps,
    budget: &mut WorkBudget,
) -> Result<ModelCounts, CheckFailure> {
    let counts = count_model_payload(model, caps, budget)?;
    let term_count = problem.terms.len();
    if model.term_classes.len() != term_count {
        return Err(ModelObjectError::TermClassCount {
            declared: model.term_classes.len(),
            expected: term_count,
        }
        .into());
    }
    if model.classes.len() > term_count {
        return Err(ModelObjectError::ClassCountExceedsTerms {
            classes: model.classes.len(),
            terms: term_count,
        }
        .into());
    }

    for (index, &representative) in model.term_classes.iter().enumerate() {
        if representative.index() >= term_count {
            return Err(ModelObjectError::TermRepresentativeOutOfRange {
                term: checked_term_id(index)?,
                representative,
                term_count,
            }
            .into());
        }
    }

    let mut seen = Vec::new();
    seen.try_reserve_exact(term_count)
        .map_err(|_| CertificateError::AllocationFailed {
            context: "certificate model class coverage",
        })?;
    seen.resize(term_count, false);
    let mut previous_representative = None;
    for (class_index, class) in model.classes.iter().enumerate() {
        let Some(&first_member) = class.members.first() else {
            return Err(ModelObjectError::EmptyClass { class: class_index }.into());
        };
        if let Some(previous) = previous_representative {
            if class.representative <= previous {
                return Err(ModelObjectError::ClassesNotStrictlyOrdered {
                    class: class_index,
                    previous,
                    current: class.representative,
                }
                .into());
            }
        }
        previous_representative = Some(class.representative);
        if class.representative.index() >= term_count {
            return Err(ModelObjectError::RepresentativeOutOfRange {
                class: class_index,
                representative: class.representative,
                term_count,
            }
            .into());
        }
        if class.representative != first_member {
            return Err(ModelObjectError::NonCanonicalRepresentative {
                class: class_index,
                representative: class.representative,
                first_member,
            }
            .into());
        }
        let actual_sort = problem.terms[class.representative.index()].sort;
        if class.sort != actual_sort {
            return Err(ModelObjectError::ClassSortMismatch {
                class: class_index,
                declared: class.sort,
                actual: actual_sort,
            }
            .into());
        }

        let mut previous_member = None;
        for &member in &class.members {
            if member.index() >= term_count {
                return Err(ModelObjectError::MemberOutOfRange {
                    class: class_index,
                    member,
                    term_count,
                }
                .into());
            }
            if let Some(previous) = previous_member {
                if member <= previous {
                    return Err(ModelObjectError::MembersNotStrictlyOrdered {
                        class: class_index,
                        previous,
                        current: member,
                    }
                    .into());
                }
            }
            previous_member = Some(member);
            if seen[member.index()] {
                return Err(ModelObjectError::DuplicateMember { term: member }.into());
            }
            seen[member.index()] = true;
            let member_sort = problem.terms[member.index()].sort;
            if member_sort != class.sort {
                return Err(ModelObjectError::MemberSortMismatch {
                    class: class_index,
                    member,
                    expected: class.sort,
                    actual: member_sort,
                }
                .into());
            }
            let declared = model.term_classes[member.index()];
            if declared != class.representative {
                return Err(ModelObjectError::TermClassMismatch {
                    term: member,
                    declared,
                    class: class.representative,
                }
                .into());
            }
        }
    }
    if let Some(index) = seen.iter().position(|member| !*member) {
        return Err(ModelObjectError::MissingClassMember {
            term: checked_term_id(index)?,
        }
        .into());
    }

    let mut previous_function = None;
    for (function_index, function) in model.functions.iter().enumerate() {
        if let Some(previous) = previous_function {
            if function.function <= previous {
                return Err(ModelObjectError::FunctionsNotStrictlyOrdered {
                    function: function_index,
                    previous,
                    current: function.function,
                }
                .into());
            }
        }
        previous_function = Some(function.function);
        validate_function_value(problem, model, function_index, function.default_result)?;
        let default_sort = problem.terms[function.default_result.index()].sort;
        if default_sort != function.result_sort {
            return Err(ModelObjectError::FunctionResultSortMismatch {
                function: function_index,
                term: function.default_result,
                expected: function.result_sort,
                actual: default_sort,
            }
            .into());
        }
        for (entry_index, entry) in function.entries.iter().enumerate() {
            if entry.arguments.len() != function.argument_sorts.len() {
                return Err(ModelObjectError::FunctionEntryArity {
                    function: function_index,
                    entry: entry_index,
                    expected: function.argument_sorts.len(),
                    actual: entry.arguments.len(),
                }
                .into());
            }
            if entry_index != 0 && function.entries[entry_index - 1].arguments >= entry.arguments {
                return Err(ModelObjectError::FunctionEntriesNotStrictlyOrdered {
                    function: function_index,
                    entry: entry_index,
                }
                .into());
            }
            for (position, (&argument, &expected_sort)) in entry
                .arguments
                .iter()
                .zip(function.argument_sorts.iter())
                .enumerate()
            {
                validate_function_value(problem, model, function_index, argument)?;
                let actual_sort = problem.terms[argument.index()].sort;
                if actual_sort != expected_sort {
                    return Err(ModelObjectError::FunctionArgumentSortMismatch {
                        function: function_index,
                        entry: entry_index,
                        position,
                        expected: expected_sort,
                        actual: actual_sort,
                    }
                    .into());
                }
            }
            validate_function_value(problem, model, function_index, entry.result)?;
            let result_sort = problem.terms[entry.result.index()].sort;
            if result_sort != function.result_sort {
                return Err(ModelObjectError::FunctionResultSortMismatch {
                    function: function_index,
                    term: entry.result,
                    expected: function.result_sort,
                    actual: result_sort,
                }
                .into());
            }
        }
    }

    if let Some(values) = model.boolean_values {
        for term in [values.true_class, values.false_class] {
            if term.index() >= term_count {
                return Err(ModelObjectError::BooleanValueOutOfRange { term, term_count }.into());
            }
            let representative = model.term_classes[term.index()];
            if representative != term {
                return Err(ModelObjectError::NonCanonicalBooleanValue {
                    term,
                    representative,
                }
                .into());
            }
        }
        if values.true_class == values.false_class {
            return Err(ModelObjectError::BooleanValuesCollapsed {
                representative: values.true_class,
            }
            .into());
        }
    }

    Ok(counts)
}

fn validate_function_value(
    problem: &SemanticProblem,
    model: &CanonicalModelData,
    function: usize,
    term: TermId,
) -> Result<(), CheckFailure> {
    if term.index() >= problem.terms.len() {
        return Err(ModelObjectError::FunctionValueOutOfRange {
            function,
            term,
            term_count: problem.terms.len(),
        }
        .into());
    }
    let representative = model.term_classes[term.index()];
    if representative != term {
        return Err(ModelObjectError::NonCanonicalFunctionValue {
            function,
            term,
            representative,
        }
        .into());
    }
    Ok(())
}

fn checked_add(left: usize, right: usize, context: &'static str) -> Result<usize, CheckFailure> {
    left.checked_add(right)
        .ok_or_else(|| CertificateError::ArithmeticOverflow { context }.into())
}

fn fingerprint_problem(
    problem: &SemanticProblem,
    caps: CertificateCaps,
    budget: &mut WorkBudget,
) -> Result<ProblemFingerprint, CheckFailure> {
    enforce_limit(
        CertificateResource::ProblemTerms,
        problem.terms.len(),
        caps.max_problem_terms,
    )?;
    enforce_limit(
        CertificateResource::SourceAtoms,
        problem.atoms.len(),
        caps.max_source_atoms,
    )?;
    enforce_limit(
        CertificateResource::RootLiterals,
        problem.root_literals.len(),
        caps.max_root_literals,
    )?;
    if problem.terms.len() > u32::MAX as usize + 1 {
        return Err(CertificateError::StableIdSpaceExhausted {
            context: "semantic term",
            count: problem.terms.len(),
        }
        .into());
    }
    if problem.atoms.len() > u32::MAX as usize + 1 {
        return Err(CertificateError::StableIdSpaceExhausted {
            context: "source atom",
            count: problem.atoms.len(),
        }
        .into());
    }

    let mut hash = Sha256::new();
    hash.update(b"fabric-semantic-problem-v1\0");
    put_len(&mut hash, problem.terms.len())?;
    let mut term_arguments = 0usize;
    for term in &problem.terms {
        budget.charge(term.arguments.len().saturating_add(1))?;
        term_arguments = checked_add(
            term_arguments,
            term.arguments.len(),
            "semantic term arguments",
        )?;
        enforce_limit(
            CertificateResource::TermArguments,
            term_arguments,
            caps.max_term_arguments,
        )?;
        hash.put_u32(term.function);
        hash.put_u32(term.sort);
        put_len(&mut hash, term.arguments.len())?;
        for argument in &term.arguments {
            hash.put_u32(argument.raw());
        }
    }

    put_len(&mut hash, problem.atoms.len())?;
    budget.charge(problem.atoms.len().saturating_add(1))?;
    for atom in &problem.atoms {
        match atom {
            SemanticAtom::Equality(left, right) => {
                hash.put_u8(0);
                hash.put_u32(left.raw());
                hash.put_u32(right.raw());
            }
            SemanticAtom::BoolTerm(term) => {
                hash.put_u8(1);
                hash.put_u32(term.raw());
            }
        }
    }

    put_len(&mut hash, problem.assertions.len())?;
    let mut expression_nodes = 0usize;
    let mut stack = Vec::<&SemanticExpr>::new();
    stack
        .try_reserve(32)
        .map_err(|_| CertificateError::AllocationFailed {
            context: "problem fingerprint expression stack",
        })?;
    for assertion in &problem.assertions {
        stack.push(assertion);
        while let Some(expression) = stack.pop() {
            expression_nodes = checked_add(expression_nodes, 1, "semantic expression nodes")?;
            enforce_limit(
                CertificateResource::ExpressionNodes,
                expression_nodes,
                caps.max_expression_nodes,
            )?;
            budget.charge(1)?;
            match expression {
                SemanticExpr::Const(value) => {
                    hash.put_u8(0);
                    hash.put_bool(*value);
                }
                SemanticExpr::Atom(atom) => {
                    hash.put_u8(1);
                    hash.put_u32(u32::try_from(atom.index()).map_err(|_| {
                        CertificateError::StableIdSpaceExhausted {
                            context: "expression atom",
                            count: atom.index().saturating_add(1),
                        }
                    })?);
                }
                SemanticExpr::Not(child) => {
                    hash.put_u8(2);
                    push_expression_children(
                        &mut stack,
                        [child.as_ref()],
                        expression_nodes,
                        caps.max_expression_nodes,
                    )?;
                }
                SemanticExpr::And(children) => {
                    hash.put_u8(3);
                    put_len(&mut hash, children.len())?;
                    push_expression_slice(
                        &mut stack,
                        children,
                        expression_nodes,
                        caps.max_expression_nodes,
                    )?;
                }
                SemanticExpr::Or(children) => {
                    hash.put_u8(4);
                    put_len(&mut hash, children.len())?;
                    push_expression_slice(
                        &mut stack,
                        children,
                        expression_nodes,
                        caps.max_expression_nodes,
                    )?;
                }
                SemanticExpr::Iff(children) => {
                    hash.put_u8(5);
                    put_len(&mut hash, children.len())?;
                    push_expression_slice(
                        &mut stack,
                        children,
                        expression_nodes,
                        caps.max_expression_nodes,
                    )?;
                }
                SemanticExpr::Ite(condition, then_expression, else_expression) => {
                    hash.put_u8(6);
                    push_expression_children(
                        &mut stack,
                        [
                            condition.as_ref(),
                            then_expression.as_ref(),
                            else_expression.as_ref(),
                        ],
                        expression_nodes,
                        caps.max_expression_nodes,
                    )?;
                }
            }
        }
    }

    put_len(&mut hash, problem.root_literals.len())?;
    budget.charge(problem.root_literals.len().saturating_add(1))?;
    for literal in &problem.root_literals {
        hash.put_u32(u32::try_from(literal.atom.index()).map_err(|_| {
            CertificateError::StableIdSpaceExhausted {
                context: "root literal atom",
                count: literal.atom.index().saturating_add(1),
            }
        })?);
        hash.put_bool(literal.positive);
    }

    match problem.boolean_values {
        Some((true_term, false_term)) => {
            hash.put_u8(1);
            hash.put_u32(true_term.raw());
            hash.put_u32(false_term.raw());
        }
        None => hash.put_u8(0),
    }

    put_len(&mut hash, problem.atom_components.len())?;
    for component in &problem.atom_components {
        put_len(&mut hash, component.index())?;
    }
    put_len(&mut hash, problem.components.component_count())?;
    put_len(&mut hash, problem.components.max_component_size())?;
    put_len(&mut hash, problem.terms.len())?;
    for index in 0..problem.terms.len() {
        let owner = problem.components.owner(checked_term_id(index)?);
        match owner {
            Some(component) => {
                hash.put_u8(1);
                put_len(&mut hash, component.index())?;
            }
            None => hash.put_u8(0),
        }
    }
    budget.charge(
        problem
            .atom_components
            .len()
            .saturating_add(problem.terms.len())
            .saturating_add(1),
    )?;

    for value in [
        problem.stats.terms,
        problem.stats.applications,
        problem.stats.atoms,
        problem.stats.assertions,
        problem.stats.root_literals,
        problem.stats.components,
        problem.stats.max_component_terms,
        problem.stats.cross_component_boolean_nodes,
        problem.stats.unsupported_fragments,
    ] {
        put_len(&mut hash, value)?;
    }
    hash.put_bool(problem.stats.contradiction);
    budget.charge(10)?;

    Ok(ProblemFingerprint(hash.finalize()))
}

fn push_expression_slice<'a>(
    stack: &mut Vec<&'a SemanticExpr>,
    children: &'a [SemanticExpr],
    visited: usize,
    maximum: usize,
) -> Result<(), CheckFailure> {
    let pending = checked_add(stack.len(), children.len(), "pending expression nodes")?;
    let attempted = checked_add(visited, pending, "semantic expression nodes")?;
    enforce_limit(CertificateResource::ExpressionNodes, attempted, maximum)?;
    stack
        .try_reserve(children.len())
        .map_err(|_| CertificateError::AllocationFailed {
            context: "problem fingerprint expression stack",
        })?;
    stack.extend(children.iter().rev());
    Ok(())
}

fn push_expression_children<'a, const N: usize>(
    stack: &mut Vec<&'a SemanticExpr>,
    children: [&'a SemanticExpr; N],
    visited: usize,
    maximum: usize,
) -> Result<(), CheckFailure> {
    let pending = checked_add(stack.len(), N, "pending expression nodes")?;
    let attempted = checked_add(visited, pending, "semantic expression nodes")?;
    enforce_limit(CertificateResource::ExpressionNodes, attempted, maximum)?;
    stack
        .try_reserve(N)
        .map_err(|_| CertificateError::AllocationFailed {
            context: "problem fingerprint expression stack",
        })?;
    stack.extend(children.into_iter().rev());
    Ok(())
}

fn put_len(hash: &mut Sha256, value: usize) -> Result<(), CheckFailure> {
    let value = u64::try_from(value).map_err(|_| CertificateError::ArithmeticOverflow {
        context: "canonical problem length",
    })?;
    hash.put_u64(value);
    Ok(())
}

#[derive(Clone, Debug)]
struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    length_bytes: u64,
}

impl Sha256 {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    fn new() -> Self {
        Self {
            state: Self::INITIAL,
            buffer: [0; 64],
            buffer_len: 0,
            length_bytes: 0,
        }
    }

    fn put_u8(&mut self, value: u8) {
        self.update(&[value]);
    }

    fn put_bool(&mut self, value: bool) {
        self.put_u8(u8::from(value));
    }

    fn put_u32(&mut self, value: u32) {
        self.update(&value.to_be_bytes());
    }

    fn put_u64(&mut self, value: u64) {
        self.update(&value.to_be_bytes());
    }

    fn update(&mut self, mut input: &[u8]) {
        self.length_bytes = self.length_bytes.wrapping_add(input.len() as u64);
        if self.buffer_len != 0 {
            let copied = (64 - self.buffer_len).min(input.len());
            self.buffer[self.buffer_len..self.buffer_len + copied]
                .copy_from_slice(&input[..copied]);
            self.buffer_len += copied;
            input = &input[copied..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            } else {
                return;
            }
        }
        while input.len() >= 64 {
            let (block, rest) = input.split_at(64);
            self.compress(block.try_into().expect("SHA-256 block has fixed length"));
            input = rest;
        }
        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_len = input.len();
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_length = self.length_bytes.wrapping_mul(8);
        self.update(&[0x80]);
        let zeroes = [0u8; 64];
        if self.buffer_len > 56 {
            self.update(&zeroes[..64 - self.buffer_len]);
        }
        self.update(&zeroes[..56 - self.buffer_len]);
        self.update(&bit_length.to_be_bytes());
        debug_assert_eq!(self.buffer_len, 0);

        let mut digest = [0u8; 32];
        for (chunk, word) in digest.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut words = [0u32; 64];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(chunk.try_into().expect("four-byte SHA word"));
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temporary1 = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
        }

        for (state, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *state = state.wrapping_add(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::parse_problem;
    use super::super::cover::{CoverBuild, CoverNode, build_complete_cover};
    use super::super::semantic::project;
    use super::*;

    fn projected(source: &str) -> SemanticProblem {
        project(&parse_problem(source).unwrap()).unwrap()
    }

    fn equality_problem(assertions: &str) -> SemanticProblem {
        projected(&format!(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-fun a () U)\n\
             (declare-fun b () U)\n\
             {assertions}\n\
             (check-sat)"
        ))
    }

    fn canonical_model(
        problem: &SemanticProblem,
        values: &[bool],
        relations: &[CandidateRelation],
    ) -> CanonicalModel {
        match model::validate_complete_with_relations(
            problem,
            values,
            relations,
            ModelCaps::default(),
        )
        .unwrap()
        {
            ModelValidation::Valid(model) => model,
            outcome => panic!("expected valid canonical model, got {outcome:?}"),
        }
    }

    fn complete_cover(problem: &SemanticProblem) -> CoverProof {
        match build_complete_cover(problem.atoms.len(), CoverCaps::default()) {
            CoverBuild::Built(cover) => cover,
            CoverBuild::Abstained(limit) => panic!("unexpected cover cap: {limit:?}"),
        }
    }

    fn built_sat(
        problem: &SemanticProblem,
        values: &[bool],
        model: CanonicalModel,
    ) -> SolveCertificate {
        match bind_sat(problem, values, model, CertificateCaps::default()).unwrap() {
            CertificateBuild::Built(certificate) => certificate,
            CertificateBuild::Abstained(limit) => {
                panic!("unexpected certificate cap: {limit:?}")
            }
        }
    }

    fn built_unsat(problem: &SemanticProblem, cover: CoverProof) -> SolveCertificate {
        match bind_unsat(problem, cover, CertificateCaps::default()).unwrap() {
            CertificateBuild::Built(certificate) => certificate,
            CertificateBuild::Abstained(limit) => {
                panic!("unexpected certificate cap: {limit:?}")
            }
        }
    }

    fn sat_payload(certificate: &mut SolveCertificate) -> &mut SatCertificate {
        let CertificatePayload::Sat(sat) = &mut certificate.payload else {
            panic!("expected SAT certificate");
        };
        sat
    }

    fn unsat_payload(certificate: &mut SolveCertificate) -> &mut UnsatCertificate {
        let CertificatePayload::Unsat(unsat) = &mut certificate.payload else {
            panic!("expected UNSAT certificate");
        };
        unsat
    }

    #[test]
    fn sha256_matches_standard_vectors() {
        let digest = |input: &[u8]| {
            let mut hash = Sha256::new();
            hash.update(input);
            ProblemFingerprint(hash.finalize()).to_string()
        };
        assert_eq!(
            digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            digest(&vec![b'a'; 1_000]),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }

    #[test]
    fn sat_envelope_reconstructs_canonical_model_and_receipt_deterministically() {
        let problem = equality_problem("(assert (or (= a b) (distinct a b)))");
        let values = [false];
        let certificate = built_sat(&problem, &values, canonical_model(&problem, &values, &[]));

        let first = check_certificate(&problem, &certificate, CertificateCaps::default()).unwrap();
        let second = check_certificate(&problem, &certificate, CertificateCaps::default()).unwrap();
        assert_eq!(first, second);
        let CertificateCheck::Valid(CertificateReceipt {
            kind: CertificateReceiptKind::Sat(receipt),
            ..
        }) = first
        else {
            panic!("expected a valid SAT receipt, got {first:?}");
        };
        assert_eq!(receipt.source_atoms_checked, problem.atoms.len());
        assert_eq!(receipt.terms_checked, problem.terms.len());
        assert_eq!(certificate.problem.bytes().len(), 32);
    }

    #[test]
    fn sat_envelope_preserves_non_source_stable_relations() {
        let problem = projected(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-fun a () U)\n\
             (declare-fun b () U)\n\
             (declare-fun c () U)\n\
             (assert (and (= a a) (= b b) (= c c)))\n\
             (check-sat)",
        );
        let values = vec![true; problem.atoms.len()];
        let boolean_sort = problem
            .boolean_values
            .map(|(true_term, _)| problem.terms[true_term.index()].sort);
        let mut constants = problem
            .terms
            .iter()
            .enumerate()
            .filter(|(_, term)| term.arguments.is_empty() && Some(term.sort) != boolean_sort)
            .map(|(index, _)| TermId::try_from(index).unwrap());
        let relation = CandidateRelation::equality(
            constants.next().expect("first uninterpreted constant"),
            constants.next().expect("second uninterpreted constant"),
        );
        let certificate = built_sat(
            &problem,
            &values,
            canonical_model(&problem, &values, &[relation]),
        );
        assert!(matches!(
            check_certificate(&problem, &certificate, CertificateCaps::default()).unwrap(),
            CertificateCheck::Valid(CertificateReceipt {
                kind: CertificateReceiptKind::Sat(_),
                ..
            })
        ));
    }

    #[test]
    fn sat_checker_rejects_value_id_model_mutation_and_truncation() {
        let problem = equality_problem("(assert (or (= a b) (distinct a b)))");
        let values = [false];
        let certificate = built_sat(&problem, &values, canonical_model(&problem, &values, &[]));

        let mut changed_value = certificate.clone();
        sat_payload(&mut changed_value).source_atom_values[0].value = true;
        assert!(matches!(
            check_certificate(&problem, &changed_value, CertificateCaps::default()),
            Err(CertificateError::ModelMismatch)
        ));

        let mut changed_id = certificate.clone();
        sat_payload(&mut changed_id).source_atom_values[0].atom = AtomId::new(1);
        assert!(matches!(
            check_certificate(&problem, &changed_id, CertificateCaps::default()),
            Err(CertificateError::NonCanonicalSourceAtom { .. })
        ));

        let mut truncated_values = certificate.clone();
        sat_payload(&mut truncated_values).source_atom_values = Box::new([]);
        assert!(matches!(
            check_certificate(&problem, &truncated_values, CertificateCaps::default()),
            Err(CertificateError::SourceAtomCount { .. })
        ));

        let mut truncated_terms = certificate.clone();
        let model = &mut sat_payload(&mut truncated_terms).model;
        model.term_classes = model.term_classes[..model.term_classes.len() - 1].into();
        assert!(matches!(
            check_certificate(&problem, &truncated_terms, CertificateCaps::default()),
            Err(CertificateError::ModelObject(
                ModelObjectError::TermClassCount { .. }
            ))
        ));

        let mut changed_function = certificate;
        let function = sat_payload(&mut changed_function)
            .model
            .functions
            .last_mut()
            .expect("constant function table");
        function.function = u32::MAX;
        assert!(matches!(
            check_certificate(&problem, &changed_function, CertificateCaps::default()),
            Err(CertificateError::ModelMismatch)
        ));
    }

    #[test]
    fn sat_checker_rejects_same_shape_wrong_problem() {
        let equality = equality_problem("(assert (= a b))");
        let disequality = equality_problem("(assert (distinct a b))");
        assert_eq!(equality.terms.len(), disequality.terms.len());
        assert_eq!(equality.atoms.len(), disequality.atoms.len());
        let certificate = built_sat(&equality, &[true], canonical_model(&equality, &[true], &[]));
        assert!(matches!(
            check_certificate(&disequality, &certificate, CertificateCaps::default()),
            Err(CertificateError::WrongProblem { .. })
        ));
    }

    #[test]
    fn unsat_envelope_delegates_to_cover_checker_deterministically() {
        let problem = equality_problem("(assert (= a b)) (assert (distinct a b))");
        let certificate = built_unsat(&problem, complete_cover(&problem));
        let first = check_certificate(&problem, &certificate, CertificateCaps::default()).unwrap();
        let second = check_certificate(&problem, &certificate, CertificateCaps::default()).unwrap();
        assert_eq!(first, second);
        assert!(matches!(
            first,
            CertificateCheck::Valid(CertificateReceipt {
                kind: CertificateReceiptKind::Unsat(CoverReceipt {
                    source_atom_count: 1,
                    ..
                }),
                ..
            })
        ));
    }

    #[test]
    fn unsat_checker_rejects_mutation_truncation_and_wrong_problem() {
        let problem = equality_problem("(assert (= a b)) (assert (distinct a b))");
        let certificate = built_unsat(&problem, complete_cover(&problem));

        let mut mutated = certificate.clone();
        let cover = &mut unsat_payload(&mut mutated).cover;
        let root = cover.root.index();
        let CoverNode::Split { atom, .. } = &mut cover.nodes[root] else {
            panic!("complete one-atom cover must split at its root");
        };
        *atom = AtomId::new(1);
        assert!(matches!(
            check_certificate(&problem, &mutated, CertificateCaps::default()),
            Err(CertificateError::Cover(
                CoverError::NonCanonicalSplit { .. }
            ))
        ));

        let mut truncated = certificate.clone();
        let cover = &mut unsat_payload(&mut truncated).cover;
        cover.nodes = cover.nodes[..cover.nodes.len() - 1].into();
        assert!(matches!(
            check_certificate(&problem, &truncated, CertificateCaps::default()),
            Err(CertificateError::Cover(CoverError::RootOutOfRange { .. }))
        ));

        let wrong_problem = equality_problem("(assert (or (= a b) (distinct a b)))");
        assert_eq!(problem.terms.len(), wrong_problem.terms.len());
        assert_eq!(problem.atoms.len(), wrong_problem.atoms.len());
        assert!(matches!(
            check_certificate(&wrong_problem, &certificate, CertificateCaps::default()),
            Err(CertificateError::WrongProblem { .. })
        ));
    }

    #[test]
    fn hard_caps_abstain_before_nested_validation() {
        let sat_problem = equality_problem("(assert (or (= a b) (distinct a b)))");
        let values = [false];
        let sat = built_sat(
            &sat_problem,
            &values,
            canonical_model(&sat_problem, &values, &[]),
        );

        let mut caps = CertificateCaps::default();
        caps.max_source_atoms = 0;
        assert!(matches!(
            check_certificate(&sat_problem, &sat, caps).unwrap(),
            CertificateCheck::Abstained(CertificateAbstention::Envelope(CertificateLimit {
                resource: CertificateResource::SourceAtoms,
                ..
            }))
        ));

        caps = CertificateCaps::default();
        caps.max_model_classes = 0;
        assert!(matches!(
            check_certificate(&sat_problem, &sat, caps).unwrap(),
            CertificateCheck::Abstained(CertificateAbstention::Envelope(CertificateLimit {
                resource: CertificateResource::ModelClasses,
                ..
            }))
        ));

        caps = CertificateCaps::default();
        caps.model.max_work = 0;
        assert!(matches!(
            check_certificate(&sat_problem, &sat, caps).unwrap(),
            CertificateCheck::Abstained(CertificateAbstention::Model(_))
        ));

        let unsat_problem = equality_problem("(assert (= a b)) (assert (distinct a b))");
        let unsat = built_unsat(&unsat_problem, complete_cover(&unsat_problem));
        caps = CertificateCaps::default();
        caps.max_cover_nodes = 0;
        assert!(matches!(
            check_certificate(&unsat_problem, &unsat, caps).unwrap(),
            CertificateCheck::Abstained(CertificateAbstention::Envelope(CertificateLimit {
                resource: CertificateResource::CoverNodes,
                ..
            }))
        ));

        caps = CertificateCaps::default();
        caps.cover.max_check_work = 0;
        assert!(matches!(
            check_certificate(&unsat_problem, &unsat, caps).unwrap(),
            CertificateCheck::Abstained(CertificateAbstention::Cover(CoverAbstention::Cover(_)))
        ));
    }

    #[test]
    fn malformed_format_and_builder_caps_fail_closed() {
        let problem = equality_problem("(assert (= a b))");
        let mut certificate = built_sat(&problem, &[true], canonical_model(&problem, &[true], &[]));
        certificate.format = "fabric-solve-certificate-v2".into();
        assert!(matches!(
            check_certificate(&problem, &certificate, CertificateCaps::default()),
            Err(CertificateError::WrongFormat)
        ));

        let model = canonical_model(&problem, &[true], &[]);
        let mut caps = CertificateCaps::default();
        caps.max_model_classes = 0;
        assert!(matches!(
            bind_sat(&problem, &[true], model, caps).unwrap(),
            CertificateBuild::Abstained(CertificateLimit {
                resource: CertificateResource::ModelClasses,
                ..
            })
        ));
    }
}
