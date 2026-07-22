#![deny(unsafe_code)]

//! Independent validation of complete Fabric SAT candidates.
//!
//! This module intentionally owns its equality and congruence implementation.
//! It shares only stable semantic identifiers with the solving engines, so a
//! defect in rollback state or incremental congruence cannot validate its own
//! bad candidate.  The reconstructed model uses the minimum observed term in
//! every class as its canonical value and gives every observed function a
//! deterministic default outside its sparse observed table.

use super::native_clause::AtomId;
use super::partition::TermId;
use super::semantic::{SemanticAtom, SemanticExpr, SemanticProblem};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

/// Explicit resource limits for independent model reconstruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ModelCaps {
    pub(crate) max_terms: usize,
    pub(crate) max_atoms: usize,
    pub(crate) max_term_arguments: usize,
    pub(crate) max_root_literals: usize,
    pub(crate) max_expression_nodes: usize,
    pub(crate) max_congruence_rounds: usize,
    pub(crate) max_function_entries: usize,
    pub(crate) max_function_argument_cells: usize,
    pub(crate) max_work: usize,
}

impl Default for ModelCaps {
    fn default() -> Self {
        Self {
            max_terms: 1_000_000,
            max_atoms: 1_000_000,
            max_term_arguments: 4_000_000,
            max_root_literals: 2_000_000,
            max_expression_nodes: 4_000_000,
            max_congruence_rounds: 1_000_001,
            max_function_entries: 1_000_000,
            max_function_argument_cells: 4_000_000,
            max_work: 64_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ModelLimitKind {
    Terms,
    Atoms,
    TermArguments,
    RootLiterals,
    ExpressionNodes,
    CongruenceRounds,
    FunctionEntries,
    FunctionArgumentCells,
    Work,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ModelLimit {
    pub(crate) kind: ModelLimitKind,
    pub(crate) observed: usize,
    pub(crate) maximum: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ModelError {
    AssignmentLength {
        expected: usize,
        actual: usize,
    },
    UnsupportedFragments {
        count: usize,
    },
    TermIdSpaceExhausted {
        count: usize,
    },
    TermArgumentOutOfRange {
        term: TermId,
        argument: TermId,
        term_count: usize,
    },
    InconsistentFunctionSignature {
        function: u32,
        first: TermId,
        second: TermId,
    },
    BooleanValueOutOfRange {
        term: TermId,
        term_count: usize,
    },
    BooleanValueSortMismatch {
        true_term: TermId,
        false_term: TermId,
    },
    MissingBooleanValues {
        atom: AtomId,
    },
    MissingBooleanAtom {
        term: TermId,
    },
    AtomTermOutOfRange {
        atom: AtomId,
        term: TermId,
        term_count: usize,
    },
    IllSortedEquality {
        atom: AtomId,
        left: TermId,
        right: TermId,
    },
    IllSortedBooleanAtom {
        atom: AtomId,
        term: TermId,
    },
    RootAtomOutOfRange {
        literal: usize,
        atom: AtomId,
        atom_count: usize,
    },
    ExpressionAtomOutOfRange {
        assertion: usize,
        atom: AtomId,
        atom_count: usize,
    },
    AllocationFailed {
        context: &'static str,
    },
}

impl fmt::Display for ModelError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AssignmentLength { expected, actual } => write!(
                output,
                "complete model assignment has {actual} values; expected exactly {expected}"
            ),
            Self::UnsupportedFragments { count } => {
                write!(
                    output,
                    "cannot validate a model with {count} unsupported fragments"
                )
            }
            Self::TermIdSpaceExhausted { count } => {
                write!(output, "{count} semantic terms do not fit in TermId")
            }
            Self::TermArgumentOutOfRange {
                term,
                argument,
                term_count,
            } => write!(
                output,
                "term {term} has argument {argument} outside 0..{term_count}"
            ),
            Self::InconsistentFunctionSignature {
                function,
                first,
                second,
            } => write!(
                output,
                "function {function} has inconsistent signatures at terms {first} and {second}"
            ),
            Self::BooleanValueOutOfRange { term, term_count } => write!(
                output,
                "Boolean value term {term} is outside 0..{term_count}"
            ),
            Self::BooleanValueSortMismatch {
                true_term,
                false_term,
            } => write!(
                output,
                "Boolean values {true_term} and {false_term} have different sorts"
            ),
            Self::MissingBooleanValues { atom } => write!(
                output,
                "Boolean atom {} has no distinguished true/false values",
                atom.index()
            ),
            Self::MissingBooleanAtom { term } => write!(
                output,
                "Boolean term {term} has no value in the complete source assignment"
            ),
            Self::AtomTermOutOfRange {
                atom,
                term,
                term_count,
            } => write!(
                output,
                "atom {} contains term {term} outside 0..{term_count}",
                atom.index()
            ),
            Self::IllSortedEquality { atom, left, right } => write!(
                output,
                "equality atom {} relates differently sorted terms {left} and {right}",
                atom.index()
            ),
            Self::IllSortedBooleanAtom { atom, term } => write!(
                output,
                "Boolean atom {} contains non-Boolean term {term}",
                atom.index()
            ),
            Self::RootAtomOutOfRange {
                literal,
                atom,
                atom_count,
            } => write!(
                output,
                "root literal {literal} references atom {} outside 0..{atom_count}",
                atom.index()
            ),
            Self::ExpressionAtomOutOfRange {
                assertion,
                atom,
                atom_count,
            } => write!(
                output,
                "assertion {assertion} references atom {} outside 0..{atom_count}",
                atom.index()
            ),
            Self::AllocationFailed { context } => {
                write!(output, "allocation failed while building {context}")
            }
        }
    }
}

impl Error for ModelError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InvalidModel {
    SourceContradiction,
    TrueEqualsFalse {
        representative: TermId,
    },
    FalseEqualityCollapsed {
        atom: AtomId,
        left: TermId,
        right: TermId,
        representative: TermId,
    },
    AtomValueMismatch {
        atom: AtomId,
        assigned: bool,
        reconstructed: bool,
    },
    RootLiteralUnsatisfied {
        literal: usize,
        atom: AtomId,
        required: bool,
        reconstructed: bool,
    },
    AssertionUnsatisfied {
        assertion: usize,
    },
    FunctionTableConflict {
        function: u32,
        first: TermId,
        second: TermId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalClass {
    pub(crate) representative: TermId,
    pub(crate) sort: u32,
    pub(crate) members: Box<[TermId]>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CanonicalFunctionEntry {
    pub(crate) arguments: Box<[TermId]>,
    pub(crate) result: TermId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalFunction {
    pub(crate) function: u32,
    pub(crate) argument_sorts: Box<[u32]>,
    pub(crate) result_sort: u32,
    /// The value of every well-sorted tuple absent from `entries`.
    pub(crate) default_result: TermId,
    /// All observed tuples, in lexicographic canonical-class order.
    pub(crate) entries: Box<[CanonicalFunctionEntry]>,
}

impl CanonicalFunction {
    pub(crate) fn apply(&self, arguments: &[TermId]) -> Option<TermId> {
        if arguments.len() != self.argument_sorts.len() {
            return None;
        }
        match self
            .entries
            .binary_search_by(|entry| entry.arguments.as_ref().cmp(arguments))
        {
            Ok(index) => Some(self.entries[index].result),
            Err(_) => Some(self.default_result),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalBooleanValues {
    pub(crate) true_class: TermId,
    pub(crate) false_class: TermId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalModel {
    /// Canonical class representative for every semantic term, by term ID.
    pub(crate) term_classes: Box<[TermId]>,
    pub(crate) classes: Box<[CanonicalClass]>,
    pub(crate) functions: Box<[CanonicalFunction]>,
    pub(crate) boolean_values: Option<CanonicalBooleanValues>,
    pub(crate) congruence_rounds: usize,
    pub(crate) congruence_merges: usize,
    pub(crate) observed_function_entries: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ModelValidation {
    Valid(CanonicalModel),
    Invalid(InvalidModel),
    Abstained(ModelLimit),
}

/// Validate one total assignment to exactly the projected source atoms.
pub(crate) fn validate_complete(
    problem: &SemanticProblem,
    source_atom_values: &[bool],
    caps: ModelCaps,
) -> Result<ModelValidation, ModelError> {
    match validate_inner(problem, source_atom_values, caps) {
        Ok(model) => Ok(ModelValidation::Valid(model)),
        Err(CheckFailure::Invalid(reason)) => Ok(ModelValidation::Invalid(reason)),
        Err(CheckFailure::Limit(limit)) => Ok(ModelValidation::Abstained(limit)),
        Err(CheckFailure::Malformed(error)) => Err(error),
    }
}

#[derive(Debug)]
enum CheckFailure {
    Invalid(InvalidModel),
    Limit(ModelLimit),
    Malformed(ModelError),
}

impl From<ModelError> for CheckFailure {
    fn from(error: ModelError) -> Self {
        Self::Malformed(error)
    }
}

type CheckResult<T> = Result<T, CheckFailure>;

#[derive(Clone, Debug)]
struct FunctionSignature {
    first_term: TermId,
    argument_sorts: Box<[u32]>,
    result_sort: u32,
}

fn validate_inner(
    problem: &SemanticProblem,
    source_atom_values: &[bool],
    caps: ModelCaps,
) -> CheckResult<CanonicalModel> {
    if source_atom_values.len() != problem.atoms.len() {
        return Err(ModelError::AssignmentLength {
            expected: problem.atoms.len(),
            actual: source_atom_values.len(),
        }
        .into());
    }
    if problem.stats.unsupported_fragments != 0 {
        return Err(ModelError::UnsupportedFragments {
            count: problem.stats.unsupported_fragments,
        }
        .into());
    }

    enforce_limit(ModelLimitKind::Terms, problem.terms.len(), caps.max_terms)?;
    enforce_limit(ModelLimitKind::Atoms, problem.atoms.len(), caps.max_atoms)?;
    if problem.terms.len() > u32::MAX as usize {
        return Err(ModelError::TermIdSpaceExhausted {
            count: problem.terms.len(),
        }
        .into());
    }

    let mut budget = WorkBudget::new(caps.max_work);
    let signatures = validate_terms(problem, caps, &mut budget)?;
    let boolean_values = validate_boolean_values(problem)?;
    let bool_atoms = validate_atoms(problem, boolean_values, &mut budget)?;
    validate_boolean_coverage(problem, boolean_values, &bool_atoms)?;
    validate_source_shape(problem, caps, &mut budget)?;

    if problem.stats.contradiction {
        return Err(CheckFailure::Invalid(InvalidModel::SourceContradiction));
    }

    let mut equality = Equality::new(problem.terms.len())?;
    let mut negative_equalities = Vec::new();
    negative_equalities
        .try_reserve(problem.atoms.len())
        .map_err(|_| ModelError::AllocationFailed {
            context: "negative equality list",
        })?;

    for (index, (atom, &value)) in problem.atoms.iter().zip(source_atom_values).enumerate() {
        let atom_id = checked_atom_id(index);
        match *atom {
            SemanticAtom::Equality(left, right) if value => {
                equality.merge(left.index(), right.index(), &mut budget)?;
            }
            SemanticAtom::Equality(left, right) => {
                negative_equalities.push((atom_id, left, right));
            }
            SemanticAtom::BoolTerm(term) => {
                let (true_term, false_term) =
                    boolean_values.expect("Boolean atom validation requires distinguished values");
                let target = if value { true_term } else { false_term };
                equality.merge(term.index(), target.index(), &mut budget)?;
            }
        }
    }

    let (congruence_rounds, congruence_merges) =
        saturate_congruence(problem, &mut equality, caps, &mut budget)?;
    let term_classes = canonical_representatives(problem, &mut equality, &mut budget)?;

    let canonical_boole = if let Some((true_term, false_term)) = boolean_values {
        let true_class = term_classes[true_term.index()];
        let false_class = term_classes[false_term.index()];
        if true_class == false_class {
            return Err(CheckFailure::Invalid(InvalidModel::TrueEqualsFalse {
                representative: true_class,
            }));
        }
        Some(CanonicalBooleanValues {
            true_class,
            false_class,
        })
    } else {
        None
    };

    for &(atom, left, right) in &negative_equalities {
        if term_classes[left.index()] == term_classes[right.index()] {
            return Err(CheckFailure::Invalid(
                InvalidModel::FalseEqualityCollapsed {
                    atom,
                    left,
                    right,
                    representative: term_classes[left.index()],
                },
            ));
        }
    }

    let reconstructed = reconstruct_atom_values(problem, &term_classes, canonical_boole)?;
    for (index, (&assigned, &modeled)) in source_atom_values
        .iter()
        .zip(reconstructed.iter())
        .enumerate()
    {
        if assigned != modeled {
            return Err(CheckFailure::Invalid(InvalidModel::AtomValueMismatch {
                atom: checked_atom_id(index),
                assigned,
                reconstructed: modeled,
            }));
        }
    }

    for (index, literal) in problem.root_literals.iter().enumerate() {
        let modeled = reconstructed[literal.atom.index()];
        if modeled != literal.positive {
            return Err(CheckFailure::Invalid(
                InvalidModel::RootLiteralUnsatisfied {
                    literal: index,
                    atom: literal.atom,
                    required: literal.positive,
                    reconstructed: modeled,
                },
            ));
        }
    }
    for (index, assertion) in problem.assertions.iter().enumerate() {
        if !evaluate_expression(assertion, &reconstructed)? {
            return Err(CheckFailure::Invalid(InvalidModel::AssertionUnsatisfied {
                assertion: index,
            }));
        }
    }

    let (classes, domains) = build_classes(problem, &term_classes)?;
    let (functions, observed_function_entries) = build_functions(
        problem,
        &signatures,
        &term_classes,
        &domains,
        caps,
        &mut budget,
    )?;

    Ok(CanonicalModel {
        term_classes: term_classes.into_boxed_slice(),
        classes: classes.into_boxed_slice(),
        functions: functions.into_boxed_slice(),
        boolean_values: canonical_boole,
        congruence_rounds,
        congruence_merges,
        observed_function_entries,
    })
}

fn enforce_limit(kind: ModelLimitKind, observed: usize, maximum: usize) -> CheckResult<()> {
    if observed <= maximum {
        Ok(())
    } else {
        Err(CheckFailure::Limit(ModelLimit {
            kind,
            observed,
            maximum,
        }))
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

    fn charge(&mut self, amount: usize) -> CheckResult<()> {
        let observed = self.used.checked_add(amount).unwrap_or(usize::MAX);
        if observed > self.maximum {
            return Err(CheckFailure::Limit(ModelLimit {
                kind: ModelLimitKind::Work,
                observed,
                maximum: self.maximum,
            }));
        }
        self.used = observed;
        Ok(())
    }
}

fn validate_terms(
    problem: &SemanticProblem,
    caps: ModelCaps,
    budget: &mut WorkBudget,
) -> CheckResult<BTreeMap<u32, FunctionSignature>> {
    let term_count = problem.terms.len();
    let mut argument_count = 0usize;
    let mut signatures = BTreeMap::<u32, FunctionSignature>::new();

    for (index, term) in problem.terms.iter().enumerate() {
        let term_id = checked_term_id(index);
        argument_count = argument_count
            .checked_add(term.arguments.len())
            .unwrap_or(usize::MAX);
        enforce_limit(
            ModelLimitKind::TermArguments,
            argument_count,
            caps.max_term_arguments,
        )?;
        budget.charge(term.arguments.len().saturating_add(1))?;

        for &argument in &term.arguments {
            if argument.index() >= term_count {
                return Err(ModelError::TermArgumentOutOfRange {
                    term: term_id,
                    argument,
                    term_count,
                }
                .into());
            }
        }
        let argument_sorts = term
            .arguments
            .iter()
            .map(|argument| problem.terms[argument.index()].sort)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        if let Some(first) = signatures.get(&term.function) {
            if first.result_sort != term.sort || first.argument_sorts != argument_sorts {
                return Err(ModelError::InconsistentFunctionSignature {
                    function: term.function,
                    first: first.first_term,
                    second: term_id,
                }
                .into());
            }
        } else {
            signatures.insert(
                term.function,
                FunctionSignature {
                    first_term: term_id,
                    argument_sorts,
                    result_sort: term.sort,
                },
            );
        }
    }
    Ok(signatures)
}

fn validate_boolean_values(problem: &SemanticProblem) -> CheckResult<Option<(TermId, TermId)>> {
    let Some((true_term, false_term)) = problem.boolean_values else {
        return Ok(None);
    };
    for term in [true_term, false_term] {
        if term.index() >= problem.terms.len() {
            return Err(ModelError::BooleanValueOutOfRange {
                term,
                term_count: problem.terms.len(),
            }
            .into());
        }
    }
    if problem.terms[true_term.index()].sort != problem.terms[false_term.index()].sort {
        return Err(ModelError::BooleanValueSortMismatch {
            true_term,
            false_term,
        }
        .into());
    }
    Ok(Some((true_term, false_term)))
}

fn validate_atoms(
    problem: &SemanticProblem,
    boolean_values: Option<(TermId, TermId)>,
    budget: &mut WorkBudget,
) -> CheckResult<BTreeSet<TermId>> {
    let term_count = problem.terms.len();
    let mut bool_atoms = BTreeSet::new();
    for (index, atom) in problem.atoms.iter().enumerate() {
        budget.charge(1)?;
        let atom_id = checked_atom_id(index);
        match *atom {
            SemanticAtom::Equality(left, right) => {
                validate_atom_term(atom_id, left, term_count)?;
                validate_atom_term(atom_id, right, term_count)?;
                if problem.terms[left.index()].sort != problem.terms[right.index()].sort {
                    return Err(ModelError::IllSortedEquality {
                        atom: atom_id,
                        left,
                        right,
                    }
                    .into());
                }
            }
            SemanticAtom::BoolTerm(term) => {
                validate_atom_term(atom_id, term, term_count)?;
                let Some((true_term, _)) = boolean_values else {
                    return Err(ModelError::MissingBooleanValues { atom: atom_id }.into());
                };
                if problem.terms[term.index()].sort != problem.terms[true_term.index()].sort {
                    return Err(ModelError::IllSortedBooleanAtom {
                        atom: atom_id,
                        term,
                    }
                    .into());
                }
                bool_atoms.insert(term);
            }
        }
    }
    Ok(bool_atoms)
}

fn validate_atom_term(atom: AtomId, term: TermId, term_count: usize) -> CheckResult<()> {
    if term.index() < term_count {
        Ok(())
    } else {
        Err(ModelError::AtomTermOutOfRange {
            atom,
            term,
            term_count,
        }
        .into())
    }
}

fn validate_boolean_coverage(
    problem: &SemanticProblem,
    boolean_values: Option<(TermId, TermId)>,
    bool_atoms: &BTreeSet<TermId>,
) -> CheckResult<()> {
    let Some((true_term, false_term)) = boolean_values else {
        return Ok(());
    };
    let bool_sort = problem.terms[true_term.index()].sort;
    for (index, term) in problem.terms.iter().enumerate() {
        let term_id = checked_term_id(index);
        if term.sort == bool_sort
            && term_id != true_term
            && term_id != false_term
            && !bool_atoms.contains(&term_id)
        {
            return Err(ModelError::MissingBooleanAtom { term: term_id }.into());
        }
    }
    Ok(())
}

fn validate_source_shape(
    problem: &SemanticProblem,
    caps: ModelCaps,
    budget: &mut WorkBudget,
) -> CheckResult<()> {
    enforce_limit(
        ModelLimitKind::RootLiterals,
        problem.root_literals.len(),
        caps.max_root_literals,
    )?;
    for (index, literal) in problem.root_literals.iter().enumerate() {
        budget.charge(1)?;
        if literal.atom.index() >= problem.atoms.len() {
            return Err(ModelError::RootAtomOutOfRange {
                literal: index,
                atom: literal.atom,
                atom_count: problem.atoms.len(),
            }
            .into());
        }
    }

    let mut nodes = 0usize;
    let mut stack = Vec::new();
    stack
        .try_reserve(problem.assertions.len())
        .map_err(|_| ModelError::AllocationFailed {
            context: "expression validation stack",
        })?;
    for (assertion_index, assertion) in problem.assertions.iter().enumerate() {
        stack.push(assertion);
        while let Some(expression) = stack.pop() {
            nodes = nodes.checked_add(1).unwrap_or(usize::MAX);
            enforce_limit(
                ModelLimitKind::ExpressionNodes,
                nodes,
                caps.max_expression_nodes,
            )?;
            budget.charge(1)?;
            match expression {
                SemanticExpr::Const(_) => {}
                SemanticExpr::Atom(atom) => {
                    if atom.index() >= problem.atoms.len() {
                        return Err(ModelError::ExpressionAtomOutOfRange {
                            assertion: assertion_index,
                            atom: *atom,
                            atom_count: problem.atoms.len(),
                        }
                        .into());
                    }
                }
                SemanticExpr::Not(child) => reserve_and_push(&mut stack, [child.as_ref()])?,
                SemanticExpr::And(children)
                | SemanticExpr::Or(children)
                | SemanticExpr::Iff(children) => {
                    stack.try_reserve(children.len()).map_err(|_| {
                        ModelError::AllocationFailed {
                            context: "expression validation stack",
                        }
                    })?;
                    stack.extend(children.iter().rev());
                }
                SemanticExpr::Ite(condition, then_expression, else_expression) => {
                    reserve_and_push(
                        &mut stack,
                        [
                            else_expression.as_ref(),
                            then_expression.as_ref(),
                            condition.as_ref(),
                        ],
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn reserve_and_push<'a, const N: usize>(
    stack: &mut Vec<&'a SemanticExpr>,
    expressions: [&'a SemanticExpr; N],
) -> CheckResult<()> {
    stack
        .try_reserve(N)
        .map_err(|_| ModelError::AllocationFailed {
            context: "expression validation stack",
        })?;
    stack.extend(expressions);
    Ok(())
}

#[derive(Debug)]
struct Equality {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl Equality {
    fn new(term_count: usize) -> CheckResult<Self> {
        let mut parent = Vec::new();
        parent
            .try_reserve_exact(term_count)
            .map_err(|_| ModelError::AllocationFailed {
                context: "independent equality parents",
            })?;
        parent.extend(0..term_count);
        let mut rank = Vec::new();
        rank.try_reserve_exact(term_count)
            .map_err(|_| ModelError::AllocationFailed {
                context: "independent equality ranks",
            })?;
        rank.resize(term_count, 0);
        Ok(Self { parent, rank })
    }

    fn find(&mut self, term: usize, budget: &mut WorkBudget) -> CheckResult<usize> {
        budget.charge(1)?;
        let mut root = term;
        while self.parent[root] != root {
            budget.charge(1)?;
            root = self.parent[root];
        }
        let mut cursor = term;
        while self.parent[cursor] != cursor {
            budget.charge(1)?;
            let next = self.parent[cursor];
            self.parent[cursor] = root;
            cursor = next;
        }
        Ok(root)
    }

    fn merge(&mut self, left: usize, right: usize, budget: &mut WorkBudget) -> CheckResult<bool> {
        let mut left_root = self.find(left, budget)?;
        let mut right_root = self.find(right, budget)?;
        if left_root == right_root {
            return Ok(false);
        }
        if self.rank[left_root] < self.rank[right_root]
            || (self.rank[left_root] == self.rank[right_root] && left_root > right_root)
        {
            std::mem::swap(&mut left_root, &mut right_root);
        }
        self.parent[right_root] = left_root;
        if self.rank[left_root] == self.rank[right_root] {
            self.rank[left_root] = self.rank[left_root].saturating_add(1);
        }
        Ok(true)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CongruenceSignature {
    function: u32,
    arguments: Box<[usize]>,
}

fn saturate_congruence(
    problem: &SemanticProblem,
    equality: &mut Equality,
    caps: ModelCaps,
    budget: &mut WorkBudget,
) -> CheckResult<(usize, usize)> {
    if problem.terms.is_empty() {
        return Ok((0, 0));
    }
    let mut rounds = 0usize;
    let mut merges = 0usize;
    loop {
        let next_round = rounds.checked_add(1).unwrap_or(usize::MAX);
        enforce_limit(
            ModelLimitKind::CongruenceRounds,
            next_round,
            caps.max_congruence_rounds,
        )?;
        rounds = next_round;

        let mut signatures = BTreeMap::<CongruenceSignature, usize>::new();
        let mut changed = false;
        for (term_index, term) in problem.terms.iter().enumerate() {
            budget.charge(term.arguments.len().saturating_add(1))?;
            let mut arguments = Vec::new();
            arguments
                .try_reserve_exact(term.arguments.len())
                .map_err(|_| ModelError::AllocationFailed {
                    context: "congruence signature",
                })?;
            for argument in &term.arguments {
                arguments.push(equality.find(argument.index(), budget)?);
            }
            let signature = CongruenceSignature {
                function: term.function,
                arguments: arguments.into_boxed_slice(),
            };
            if let Some(&prior) = signatures.get(&signature) {
                if equality.merge(prior, term_index, budget)? {
                    merges = merges.saturating_add(1);
                    changed = true;
                }
            } else {
                signatures.insert(signature, term_index);
            }
        }
        if !changed {
            return Ok((rounds, merges));
        }
    }
}

fn canonical_representatives(
    problem: &SemanticProblem,
    equality: &mut Equality,
    budget: &mut WorkBudget,
) -> CheckResult<Vec<TermId>> {
    let mut roots = Vec::new();
    roots
        .try_reserve_exact(problem.terms.len())
        .map_err(|_| ModelError::AllocationFailed {
            context: "model roots",
        })?;
    let mut minima = vec![usize::MAX; problem.terms.len()];
    for term in 0..problem.terms.len() {
        let root = equality.find(term, budget)?;
        roots.push(root);
        minima[root] = minima[root].min(term);
    }
    let mut representatives = Vec::new();
    representatives
        .try_reserve_exact(problem.terms.len())
        .map_err(|_| ModelError::AllocationFailed {
            context: "canonical term classes",
        })?;
    for root in roots {
        representatives.push(checked_term_id(minima[root]));
    }
    Ok(representatives)
}

fn reconstruct_atom_values(
    problem: &SemanticProblem,
    term_classes: &[TermId],
    boolean_values: Option<CanonicalBooleanValues>,
) -> CheckResult<Vec<bool>> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(problem.atoms.len())
        .map_err(|_| ModelError::AllocationFailed {
            context: "reconstructed atom assignment",
        })?;
    for atom in &problem.atoms {
        values.push(match *atom {
            SemanticAtom::Equality(left, right) => {
                term_classes[left.index()] == term_classes[right.index()]
            }
            SemanticAtom::BoolTerm(term) => {
                let values = boolean_values
                    .expect("Boolean atom validation requires canonical Boolean values");
                term_classes[term.index()] == values.true_class
            }
        });
    }
    Ok(values)
}

enum EvaluationFrame<'a> {
    Visit(&'a SemanticExpr),
    Not,
    And(usize),
    Or(usize),
    Iff(usize),
    Ite,
}

fn evaluate_expression(expression: &SemanticExpr, atom_values: &[bool]) -> CheckResult<bool> {
    let mut frames = Vec::new();
    let mut values = Vec::new();
    frames
        .try_reserve(32)
        .map_err(|_| ModelError::AllocationFailed {
            context: "expression evaluation frames",
        })?;
    values
        .try_reserve(32)
        .map_err(|_| ModelError::AllocationFailed {
            context: "expression evaluation values",
        })?;
    frames.push(EvaluationFrame::Visit(expression));

    while let Some(frame) = frames.pop() {
        match frame {
            EvaluationFrame::Visit(expression) => match expression {
                SemanticExpr::Const(value) => values.push(*value),
                SemanticExpr::Atom(atom) => values.push(atom_values[atom.index()]),
                SemanticExpr::Not(child) => {
                    frames.push(EvaluationFrame::Not);
                    frames.push(EvaluationFrame::Visit(child));
                }
                SemanticExpr::And(children) => {
                    frames.push(EvaluationFrame::And(children.len()));
                    push_children(&mut frames, children)?;
                }
                SemanticExpr::Or(children) => {
                    frames.push(EvaluationFrame::Or(children.len()));
                    push_children(&mut frames, children)?;
                }
                SemanticExpr::Iff(children) => {
                    frames.push(EvaluationFrame::Iff(children.len()));
                    push_children(&mut frames, children)?;
                }
                SemanticExpr::Ite(condition, then_expression, else_expression) => {
                    frames.push(EvaluationFrame::Ite);
                    frames.push(EvaluationFrame::Visit(else_expression));
                    frames.push(EvaluationFrame::Visit(then_expression));
                    frames.push(EvaluationFrame::Visit(condition));
                }
            },
            EvaluationFrame::Not => {
                let value = values
                    .pop()
                    .expect("validated expression produces one value");
                values.push(!value);
            }
            EvaluationFrame::And(count) => {
                let start = values.len() - count;
                let result = values[start..].iter().all(|value| *value);
                values.truncate(start);
                values.push(result);
            }
            EvaluationFrame::Or(count) => {
                let start = values.len() - count;
                let result = values[start..].iter().any(|value| *value);
                values.truncate(start);
                values.push(result);
            }
            EvaluationFrame::Iff(count) => {
                let start = values.len() - count;
                let result = values[start..]
                    .split_first()
                    .is_none_or(|(first, rest)| rest.iter().all(|value| value == first));
                values.truncate(start);
                values.push(result);
            }
            EvaluationFrame::Ite => {
                let otherwise = values.pop().expect("validated ITE has an else value");
                let then_value = values.pop().expect("validated ITE has a then value");
                let condition = values.pop().expect("validated ITE has a condition value");
                values.push(if condition { then_value } else { otherwise });
            }
        }
    }
    debug_assert_eq!(values.len(), 1);
    Ok(values.pop().expect("an expression produces one value"))
}

fn push_children<'a>(
    frames: &mut Vec<EvaluationFrame<'a>>,
    children: &'a [SemanticExpr],
) -> CheckResult<()> {
    frames
        .try_reserve(children.len())
        .map_err(|_| ModelError::AllocationFailed {
            context: "expression evaluation frames",
        })?;
    frames.extend(children.iter().rev().map(EvaluationFrame::Visit));
    Ok(())
}

fn build_classes(
    problem: &SemanticProblem,
    term_classes: &[TermId],
) -> CheckResult<(Vec<CanonicalClass>, BTreeMap<u32, Vec<TermId>>)> {
    let mut members = BTreeMap::<TermId, Vec<TermId>>::new();
    for (index, &representative) in term_classes.iter().enumerate() {
        members
            .entry(representative)
            .or_default()
            .push(checked_term_id(index));
    }

    let mut classes = Vec::new();
    classes
        .try_reserve_exact(members.len())
        .map_err(|_| ModelError::AllocationFailed {
            context: "canonical model classes",
        })?;
    let mut domains = BTreeMap::<u32, Vec<TermId>>::new();
    for (representative, class_members) in members {
        let sort = problem.terms[representative.index()].sort;
        domains.entry(sort).or_default().push(representative);
        classes.push(CanonicalClass {
            representative,
            sort,
            members: class_members.into_boxed_slice(),
        });
    }
    Ok((classes, domains))
}

fn build_functions(
    problem: &SemanticProblem,
    signatures: &BTreeMap<u32, FunctionSignature>,
    term_classes: &[TermId],
    domains: &BTreeMap<u32, Vec<TermId>>,
    caps: ModelCaps,
    budget: &mut WorkBudget,
) -> CheckResult<(Vec<CanonicalFunction>, usize)> {
    let mut observed = BTreeMap::<u32, BTreeMap<Box<[TermId]>, (TermId, TermId)>>::new();
    for (index, term) in problem.terms.iter().enumerate() {
        budget.charge(term.arguments.len().saturating_add(1))?;
        let arguments = term
            .arguments
            .iter()
            .map(|argument| term_classes[argument.index()])
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let result = term_classes[index];
        let table = observed.entry(term.function).or_default();
        if let Some(&(prior_result, prior_term)) = table.get(&arguments) {
            if prior_result != result {
                return Err(CheckFailure::Invalid(InvalidModel::FunctionTableConflict {
                    function: term.function,
                    first: prior_term,
                    second: checked_term_id(index),
                }));
            }
        } else {
            table.insert(arguments, (result, checked_term_id(index)));
        }
    }

    let mut entry_count = 0usize;
    let mut argument_cells = 0usize;
    for table in observed.values() {
        entry_count = entry_count.checked_add(table.len()).unwrap_or(usize::MAX);
        for arguments in table.keys() {
            argument_cells = argument_cells
                .checked_add(arguments.len())
                .unwrap_or(usize::MAX);
        }
    }
    enforce_limit(
        ModelLimitKind::FunctionEntries,
        entry_count,
        caps.max_function_entries,
    )?;
    enforce_limit(
        ModelLimitKind::FunctionArgumentCells,
        argument_cells,
        caps.max_function_argument_cells,
    )?;

    let mut functions = Vec::new();
    functions
        .try_reserve_exact(signatures.len())
        .map_err(|_| ModelError::AllocationFailed {
            context: "canonical function tables",
        })?;
    for (&function, signature) in signatures {
        let default_result = *domains
            .get(&signature.result_sort)
            .and_then(|domain| domain.first())
            .expect("every observed result sort has a canonical class");
        let table = observed
            .remove(&function)
            .expect("every observed function has a table");
        let entries = table
            .into_iter()
            .map(|(arguments, (result, _))| CanonicalFunctionEntry { arguments, result })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        functions.push(CanonicalFunction {
            function,
            argument_sorts: signature.argument_sorts.clone(),
            result_sort: signature.result_sort,
            default_result,
            entries,
        });
    }
    Ok((functions, entry_count))
}

fn checked_term_id(index: usize) -> TermId {
    debug_assert!(index <= u32::MAX as usize);
    TermId::new(index as u32)
}

fn checked_atom_id(index: usize) -> AtomId {
    debug_assert!(index <= u32::MAX as usize);
    AtomId::new(index as u32)
}

#[cfg(test)]
mod tests {
    use super::super::super::parse_problem;
    use super::super::semantic::{RootLiteral, SemanticTerm, project};
    use super::*;

    fn projected(source: &str) -> SemanticProblem {
        project(&parse_problem(source).expect("test source parses")).expect("test source projects")
    }

    fn root_assignment(problem: &SemanticProblem) -> Vec<bool> {
        let mut assignment = vec![false; problem.atoms.len()];
        for literal in &problem.root_literals {
            assignment[literal.atom.index()] = literal.positive;
        }
        assignment
    }

    fn is_valid(outcome: Result<ModelValidation, ModelError>) -> bool {
        matches!(outcome, Ok(ModelValidation::Valid(_)))
    }

    #[test]
    fn exhaustive_four_term_euf_assignments_match_a_tiny_reference() {
        let source = "(set-logic QF_UF)\n\
            (declare-sort U 0)\n\
            (declare-const a U) (declare-const b U)\n\
            (declare-fun f (U) U)\n\
            (assert (or (= a b) (not (= a b))))\n\
            (assert (or (= a (f a)) (not (= a (f a)))))\n\
            (assert (or (= a (f b)) (not (= a (f b)))))\n\
            (assert (or (= b (f a)) (not (= b (f a)))))\n\
            (assert (or (= b (f b)) (not (= b (f b)))))\n\
            (assert (or (= (f a) (f b)) (not (= (f a) (f b)))))\n\
            (check-sat)";
        let problem = projected(source);
        assert_eq!(problem.atoms.len(), 6);
        assert!(
            problem
                .atoms
                .iter()
                .all(|atom| matches!(atom, SemanticAtom::Equality(_, _)))
        );

        let mut accepted = 0usize;
        for bits in 0..(1usize << problem.atoms.len()) {
            let assignment = (0..problem.atoms.len())
                .map(|bit| bits & (1 << bit) != 0)
                .collect::<Vec<_>>();
            let expected = tiny_euf_consistent(&problem, &assignment);
            let actual = is_valid(validate_complete(
                &problem,
                &assignment,
                ModelCaps::default(),
            ));
            assert_eq!(actual, expected, "assignment {bits:06b}");
            accepted += usize::from(actual);
        }
        assert!(accepted > 0);
        assert!(accepted < (1usize << problem.atoms.len()));
    }

    fn tiny_euf_consistent(problem: &SemanticProblem, assignment: &[bool]) -> bool {
        let mut parent = (0..problem.terms.len()).collect::<Vec<_>>();
        fn find(parent: &mut [usize], mut value: usize) -> usize {
            while parent[value] != value {
                value = parent[value];
            }
            value
        }
        fn merge(parent: &mut [usize], left: usize, right: usize) -> bool {
            let left = find(parent, left);
            let right = find(parent, right);
            if left == right {
                false
            } else {
                parent[right] = left;
                true
            }
        }

        for (atom, value) in problem.atoms.iter().zip(assignment) {
            if let SemanticAtom::Equality(left, right) = atom {
                if *value {
                    merge(&mut parent, left.index(), right.index());
                }
            }
        }
        loop {
            let mut changed = false;
            for left in 0..problem.terms.len() {
                for right in 0..left {
                    let left_term = &problem.terms[left];
                    let right_term = &problem.terms[right];
                    if left_term.function == right_term.function
                        && left_term.arguments.len() == right_term.arguments.len()
                        && left_term.arguments.iter().zip(&right_term.arguments).all(
                            |(left_argument, right_argument)| {
                                find(&mut parent, left_argument.index())
                                    == find(&mut parent, right_argument.index())
                            },
                        )
                    {
                        changed |= merge(&mut parent, left, right);
                    }
                }
            }
            if !changed {
                break;
            }
        }
        problem
            .atoms
            .iter()
            .zip(assignment)
            .all(|(atom, value)| match atom {
                SemanticAtom::Equality(left, right) => {
                    (find(&mut parent, left.index()) == find(&mut parent, right.index())) == *value
                }
                SemanticAtom::BoolTerm(_) => unreachable!(),
            })
    }

    #[test]
    fn exhaustive_boolean_candidates_require_exact_two_value_semantics() {
        let problem = projected(
            "(set-logic QF_UF)\n\
             (declare-const p Bool) (declare-const q Bool)\n\
             (assert (xor p q))\n\
             (check-sat)",
        );
        assert_eq!(problem.atoms.len(), 2);
        for bits in 0..4usize {
            let assignment = vec![bits & 1 != 0, bits & 2 != 0];
            assert_eq!(
                is_valid(validate_complete(
                    &problem,
                    &assignment,
                    ModelCaps::default(),
                )),
                assignment[0] != assignment[1],
                "assignment {bits:02b}"
            );
        }
    }

    #[test]
    fn congruence_rejects_a_false_equality_after_argument_merge() {
        let problem = projected(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U) (declare-const b U)\n\
             (declare-fun f (U) U)\n\
             (assert (= a b))\n\
             (assert (not (= (f a) (f b))))\n\
             (check-sat)",
        );
        let assignment = problem
            .atoms
            .iter()
            .map(|atom| match atom {
                SemanticAtom::Equality(left, right) => {
                    problem.terms[left.index()].arguments.is_empty()
                        && problem.terms[right.index()].arguments.is_empty()
                }
                SemanticAtom::BoolTerm(_) => unreachable!(),
            })
            .collect::<Vec<_>>();
        let outcome = validate_complete(&problem, &assignment, ModelCaps::default());
        assert!(
            matches!(
                outcome,
                Ok(ModelValidation::Invalid(
                    InvalidModel::FalseEqualityCollapsed { .. }
                ))
            ),
            "{outcome:?}"
        );
    }

    #[test]
    fn canonical_summary_and_sparse_totalization_are_deterministic() {
        let problem = projected(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U) (declare-const b U)\n\
             (declare-fun f (U) U)\n\
             (assert (distinct a b))\n\
             (assert (= (f a) (f a)))\n\
             (check-sat)",
        );
        let assignment = problem
            .atoms
            .iter()
            .map(|atom| matches!(atom, SemanticAtom::Equality(left, right) if left == right))
            .collect::<Vec<_>>();
        let first = validate_complete(&problem, &assignment, ModelCaps::default()).unwrap();
        let second = validate_complete(&problem, &assignment, ModelCaps::default()).unwrap();
        assert_eq!(first, second);
        let ModelValidation::Valid(model) = &first else {
            panic!("expected a valid model, got {first:?}");
        };
        assert!(
            model
                .classes
                .windows(2)
                .all(|pair| { pair[0].representative < pair[1].representative })
        );
        let function = model
            .functions
            .iter()
            .find(|function| function.argument_sorts.len() == 1)
            .expect("unary function table");
        assert_eq!(function.entries.len(), 1);
        assert_eq!(function.apply(&[]), None);
        assert_eq!(
            function.apply(&[function.entries[0].arguments[0]]),
            Some(function.entries[0].result)
        );
        let unobserved = model
            .classes
            .iter()
            .map(|class| class.representative)
            .find(|class| *class != function.entries[0].arguments[0])
            .unwrap();
        assert_eq!(function.apply(&[unobserved]), Some(function.default_result));
    }

    #[test]
    fn malformed_assignment_and_semantic_references_are_errors() {
        let source = "(set-logic QF_UF)\n\
            (declare-sort U 0) (declare-const a U) (declare-const b U)\n\
            (assert (= a b)) (check-sat)";
        let problem = projected(source);
        assert!(matches!(
            validate_complete(&problem, &[], ModelCaps::default()),
            Err(ModelError::AssignmentLength { .. })
        ));

        let mut bad_argument = projected(
            "(set-logic QF_UF)\n\
             (declare-sort U 0) (declare-const a U)\n\
             (declare-fun f (U) U) (assert (= (f a) a)) (check-sat)",
        );
        let application = bad_argument
            .terms
            .iter()
            .position(|term| !term.arguments.is_empty())
            .unwrap();
        bad_argument.terms[application].arguments =
            vec![TermId::new(bad_argument.terms.len() as u32)].into_boxed_slice();
        let values = root_assignment(&bad_argument);
        assert!(matches!(
            validate_complete(&bad_argument, &values, ModelCaps::default()),
            Err(ModelError::TermArgumentOutOfRange { .. })
        ));

        let mut bad_root = problem.clone();
        let mut root_literals = bad_root.root_literals.into_vec();
        root_literals.push(RootLiteral {
            atom: AtomId::new(bad_root.atoms.len() as u32),
            positive: true,
        });
        bad_root.root_literals = root_literals.into_boxed_slice();
        assert!(matches!(
            validate_complete(&bad_root, &[true], ModelCaps::default()),
            Err(ModelError::RootAtomOutOfRange { .. })
        ));
    }

    #[test]
    fn malformed_function_and_boolean_projection_are_errors() {
        let mut bad_function = projected(
            "(set-logic QF_UF)\n\
             (declare-sort U 0) (declare-const a U)\n\
             (declare-fun f (U) U) (assert (= (f a) a)) (check-sat)",
        );
        let constant = bad_function
            .terms
            .iter()
            .position(|term| term.arguments.is_empty())
            .unwrap();
        let application = bad_function
            .terms
            .iter()
            .position(|term| !term.arguments.is_empty())
            .unwrap();
        bad_function.terms[application].function = bad_function.terms[constant].function;
        let values = root_assignment(&bad_function);
        assert!(matches!(
            validate_complete(&bad_function, &values, ModelCaps::default()),
            Err(ModelError::InconsistentFunctionSignature { .. })
        ));

        let mut missing_values = projected(
            "(set-logic QF_UF)\n\
             (declare-const p Bool) (assert p) (check-sat)",
        );
        missing_values.boolean_values = None;
        assert!(matches!(
            validate_complete(&missing_values, &[true], ModelCaps::default()),
            Err(ModelError::MissingBooleanValues { .. })
        ));

        let mut missing_atom = projected(
            "(set-logic QF_UF)\n\
             (declare-const p Bool) (assert p) (check-sat)",
        );
        let bool_sort = missing_atom.terms[missing_atom.boolean_values.unwrap().0.index()].sort;
        let mut terms = missing_atom.terms.into_vec();
        terms.push(SemanticTerm {
            function: u32::MAX,
            sort: bool_sort,
            arguments: Box::new([]),
        });
        missing_atom.terms = terms.into_boxed_slice();
        assert!(matches!(
            validate_complete(&missing_atom, &[true], ModelCaps::default()),
            Err(ModelError::MissingBooleanAtom { .. })
        ));
    }

    #[test]
    fn only_explicit_caps_abstain() {
        let problem = projected(
            "(set-logic QF_UF)\n\
             (declare-sort U 0) (declare-const a U)\n\
             (assert (= a a)) (check-sat)",
        );
        let assignment = root_assignment(&problem);

        let mut term_caps = ModelCaps::default();
        term_caps.max_terms = problem.terms.len() - 1;
        assert_eq!(
            validate_complete(&problem, &assignment, term_caps).unwrap(),
            ModelValidation::Abstained(ModelLimit {
                kind: ModelLimitKind::Terms,
                observed: problem.terms.len(),
                maximum: problem.terms.len() - 1,
            })
        );

        let mut work_caps = ModelCaps::default();
        work_caps.max_work = 0;
        assert!(matches!(
            validate_complete(&problem, &assignment, work_caps),
            Ok(ModelValidation::Abstained(ModelLimit {
                kind: ModelLimitKind::Work,
                ..
            }))
        ));

        let mut round_caps = ModelCaps::default();
        round_caps.max_congruence_rounds = 0;
        assert!(matches!(
            validate_complete(&problem, &assignment, round_caps),
            Ok(ModelValidation::Abstained(ModelLimit {
                kind: ModelLimitKind::CongruenceRounds,
                ..
            }))
        ));
    }

    #[test]
    fn contradiction_and_false_assertion_are_invalid_not_errors() {
        let mut contradiction = projected("(set-logic QF_UF)\n(assert false)\n(check-sat)");
        contradiction.stats.contradiction = true;
        assert_eq!(
            validate_complete(&contradiction, &[], ModelCaps::default()).unwrap(),
            ModelValidation::Invalid(InvalidModel::SourceContradiction)
        );

        let false_assertion = projected(
            "(set-logic QF_UF)\n\
             (declare-sort U 0) (declare-const a U) (declare-const b U)\n\
             (assert (= a b)) (check-sat)",
        );
        let outcome = validate_complete(&false_assertion, &[false], ModelCaps::default());
        assert!(
            matches!(
                outcome,
                Ok(ModelValidation::Invalid(
                    InvalidModel::AssertionUnsatisfied { .. }
                ))
            ),
            "{outcome:?}"
        );
    }
}
