#![forbid(unsafe_code)]

//! Tiny, independent finite-model oracle for projected Fabric semantics.
//!
//! The oracle enumerates typed equivalence relations directly as restricted-
//! growth strings. It deliberately shares no partition, congruence, search,
//! cover, or model-reconstruction implementation with Fabric. The fixed caps
//! make it suitable as a differential-test oracle, not as a general solver.

use super::semantic::{SemanticAtom, SemanticExpr, SemanticProblem};
use std::error::Error;
use std::fmt;

/// Ordinary source terms, excluding the projection's true/false sentinels.
pub(crate) const MAX_GROUND_TERMS: usize = 4;
pub(crate) const MAX_SEMANTIC_TERMS: usize = MAX_GROUND_TERMS + 2;
pub(crate) const MAX_ATOMS: usize = 64;
pub(crate) const MAX_TERM_ARGUMENTS: usize = 16;
pub(crate) const MAX_ROOT_LITERALS: usize = 64;
pub(crate) const MAX_ASSERTIONS: usize = 64;
pub(crate) const MAX_EXPRESSION_NODES: usize = 512;
pub(crate) const MAX_EXPRESSION_DEPTH: usize = 64;
/// Bell number B6: every untyped partition at the absolute term cap.
pub(crate) const MAX_PARTITIONS: usize = 203;
pub(crate) const MAX_WORK: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OracleResource {
    SemanticTerms,
    GroundTerms,
    Atoms,
    TermArguments,
    RootLiterals,
    Assertions,
    ExpressionNodes,
    ExpressionDepth,
    Partitions,
    Work,
}

impl fmt::Display for OracleResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::SemanticTerms => "semantic terms",
            Self::GroundTerms => "ground terms",
            Self::Atoms => "atoms",
            Self::TermArguments => "term argument cells",
            Self::RootLiterals => "root literals",
            Self::Assertions => "assertions",
            Self::ExpressionNodes => "expression nodes",
            Self::ExpressionDepth => "expression depth",
            Self::Partitions => "typed partitions",
            Self::Work => "semantic work",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OracleAbstention {
    UnsupportedFragments {
        count: usize,
    },
    CapExceeded {
        resource: OracleResource,
        attempted: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        resource: OracleResource,
    },
    AllocationFailed {
        context: &'static str,
    },
}

impl fmt::Display for OracleAbstention {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFragments { count } => write!(
                output,
                "finite oracle cannot decide a projection with {count} unsupported fragments"
            ),
            Self::CapExceeded {
                resource,
                attempted,
                limit,
            } => write!(
                output,
                "finite oracle {resource} cap exceeded: attempted {attempted}, limit {limit}"
            ),
            Self::ArithmeticOverflow { resource } => {
                write!(output, "finite oracle {resource} counter overflowed")
            }
            Self::AllocationFailed { context } => {
                write!(
                    output,
                    "finite oracle allocation failed while building {context}"
                )
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OracleError {
    TermArgumentOutOfRange {
        term: usize,
        argument: usize,
        term_count: usize,
    },
    InconsistentFunctionSignature {
        function: u32,
        first: usize,
        second: usize,
    },
    BooleanValueOutOfRange {
        term: usize,
        term_count: usize,
    },
    BooleanValuesCoincide {
        term: usize,
    },
    BooleanValueSortMismatch {
        true_term: usize,
        false_term: usize,
    },
    MissingBooleanValues {
        atom: usize,
    },
    AtomTermOutOfRange {
        atom: usize,
        term: usize,
        term_count: usize,
    },
    IllSortedEquality {
        atom: usize,
        left: usize,
        right: usize,
    },
    IllSortedBooleanTerm {
        atom: usize,
        term: usize,
    },
    RootAtomOutOfRange {
        literal: usize,
        atom: usize,
        atom_count: usize,
    },
    ExpressionAtomOutOfRange {
        assertion: usize,
        atom: usize,
        atom_count: usize,
    },
}

impl fmt::Display for OracleError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
            Self::BooleanValuesCoincide { term } => {
                write!(output, "Boolean true and false both name term {term}")
            }
            Self::BooleanValueSortMismatch {
                true_term,
                false_term,
            } => write!(
                output,
                "Boolean values {true_term} and {false_term} have different sorts"
            ),
            Self::MissingBooleanValues { atom } => write!(
                output,
                "Boolean atom {atom} has no distinguished true/false values"
            ),
            Self::AtomTermOutOfRange {
                atom,
                term,
                term_count,
            } => write!(
                output,
                "atom {atom} contains term {term} outside 0..{term_count}"
            ),
            Self::IllSortedEquality { atom, left, right } => write!(
                output,
                "equality atom {atom} relates differently sorted terms {left} and {right}"
            ),
            Self::IllSortedBooleanTerm { atom, term } => {
                write!(
                    output,
                    "Boolean atom {atom} contains non-Boolean term {term}"
                )
            }
            Self::RootAtomOutOfRange {
                literal,
                atom,
                atom_count,
            } => write!(
                output,
                "root literal {literal} references atom {atom} outside 0..{atom_count}"
            ),
            Self::ExpressionAtomOutOfRange {
                assertion,
                atom,
                atom_count,
            } => write!(
                output,
                "assertion {assertion} references atom {atom} outside 0..{atom_count}"
            ),
        }
    }
}

impl Error for OracleError {}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct OracleStats {
    pub(crate) partitions_examined: usize,
    pub(crate) boolean_rejections: usize,
    pub(crate) congruence_rejections: usize,
    pub(crate) source_rejections: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OracleModel {
    /// Minimum term index in each term's typed equivalence class.
    pub(crate) term_classes: Box<[usize]>,
    /// Exact semantic value of every source atom, in source-atom order.
    pub(crate) source_atom_values: Box<[bool]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OracleOutcome {
    Sat {
        model: OracleModel,
        stats: OracleStats,
    },
    Unsat {
        stats: OracleStats,
    },
    Abstained {
        reason: OracleAbstention,
        stats: OracleStats,
    },
}

impl OracleOutcome {
    pub(crate) const fn stats(&self) -> OracleStats {
        match self {
            Self::Sat { stats, .. } | Self::Unsat { stats } | Self::Abstained { stats, .. } => {
                *stats
            }
        }
    }
}

/// Decide a projected problem by exhaustive typed ground-term partitions.
///
/// `Sat` and `Unsat` are returned only after all relevant checks complete.
/// Unsupported input, exhausted resources, overflow, and allocation failure
/// are explicit abstentions; malformed semantic records are errors.
pub(crate) fn solve(problem: &SemanticProblem) -> Result<OracleOutcome, OracleError> {
    let mut stats = OracleStats::default();
    let mut budget = WorkBudget::new();

    if let Err(failure) = validate_problem(problem, &mut budget) {
        return finish_failure(failure, stats);
    }
    if problem.stats.contradiction {
        return Ok(OracleOutcome::Unsat { stats });
    }

    let mut classes = [0usize; MAX_SEMANTIC_TERMS];
    match search_partitions(problem, 0, 0, &mut classes, &mut budget, &mut stats) {
        Ok(Some(model)) => Ok(OracleOutcome::Sat { model, stats }),
        Ok(None) => Ok(OracleOutcome::Unsat { stats }),
        Err(failure) => finish_failure(failure, stats),
    }
}

fn finish_failure(
    failure: OracleFailure,
    stats: OracleStats,
) -> Result<OracleOutcome, OracleError> {
    match failure {
        OracleFailure::Abstained(reason) => Ok(OracleOutcome::Abstained { reason, stats }),
        OracleFailure::Malformed(error) => Err(error),
    }
}

#[derive(Debug)]
enum OracleFailure {
    Abstained(OracleAbstention),
    Malformed(OracleError),
}

impl From<OracleError> for OracleFailure {
    fn from(error: OracleError) -> Self {
        Self::Malformed(error)
    }
}

type OracleResult<T> = Result<T, OracleFailure>;

#[derive(Debug)]
struct WorkBudget {
    used: usize,
}

impl WorkBudget {
    const fn new() -> Self {
        Self { used: 0 }
    }

    fn charge(&mut self, amount: usize) -> OracleResult<()> {
        let attempted = self.used.checked_add(amount).ok_or_else(|| {
            OracleFailure::Abstained(OracleAbstention::ArithmeticOverflow {
                resource: OracleResource::Work,
            })
        })?;
        enforce_limit(OracleResource::Work, attempted, MAX_WORK)?;
        self.used = attempted;
        Ok(())
    }
}

fn enforce_limit(resource: OracleResource, attempted: usize, limit: usize) -> OracleResult<()> {
    if attempted <= limit {
        Ok(())
    } else {
        Err(OracleFailure::Abstained(OracleAbstention::CapExceeded {
            resource,
            attempted,
            limit,
        }))
    }
}

fn checked_add(left: usize, right: usize, resource: OracleResource) -> OracleResult<usize> {
    left.checked_add(right)
        .ok_or_else(|| OracleFailure::Abstained(OracleAbstention::ArithmeticOverflow { resource }))
}

fn validate_problem(problem: &SemanticProblem, budget: &mut WorkBudget) -> OracleResult<()> {
    if problem.stats.unsupported_fragments != 0 {
        return Err(OracleFailure::Abstained(
            OracleAbstention::UnsupportedFragments {
                count: problem.stats.unsupported_fragments,
            },
        ));
    }

    enforce_limit(
        OracleResource::SemanticTerms,
        problem.terms.len(),
        MAX_SEMANTIC_TERMS,
    )?;
    enforce_limit(OracleResource::Atoms, problem.atoms.len(), MAX_ATOMS)?;
    enforce_limit(
        OracleResource::RootLiterals,
        problem.root_literals.len(),
        MAX_ROOT_LITERALS,
    )?;
    enforce_limit(
        OracleResource::Assertions,
        problem.assertions.len(),
        MAX_ASSERTIONS,
    )?;

    let term_count = problem.terms.len();
    let mut argument_cells = 0usize;
    for (term_index, term) in problem.terms.iter().enumerate() {
        argument_cells = checked_add(
            argument_cells,
            term.arguments.len(),
            OracleResource::TermArguments,
        )?;
        enforce_limit(
            OracleResource::TermArguments,
            argument_cells,
            MAX_TERM_ARGUMENTS,
        )?;
        for argument in &term.arguments {
            budget.charge(1)?;
            if argument.index() >= term_count {
                return Err(OracleError::TermArgumentOutOfRange {
                    term: term_index,
                    argument: argument.index(),
                    term_count,
                }
                .into());
            }
        }
    }

    validate_function_signatures(problem, budget)?;
    let boolean_sort = validate_boolean_values(problem)?;
    let distinguished_terms = problem.boolean_values.map_or(0, |(true_term, false_term)| {
        1 + usize::from(true_term != false_term)
    });
    let ground_terms = problem.terms.len() - distinguished_terms;
    enforce_limit(OracleResource::GroundTerms, ground_terms, MAX_GROUND_TERMS)?;
    validate_atoms(problem, boolean_sort, budget)?;

    for (literal_index, literal) in problem.root_literals.iter().enumerate() {
        budget.charge(1)?;
        if literal.atom.index() >= problem.atoms.len() {
            return Err(OracleError::RootAtomOutOfRange {
                literal: literal_index,
                atom: literal.atom.index(),
                atom_count: problem.atoms.len(),
            }
            .into());
        }
    }

    let mut expression_nodes = 0usize;
    for (assertion_index, assertion) in problem.assertions.iter().enumerate() {
        validate_expression(
            assertion,
            assertion_index,
            1,
            problem.atoms.len(),
            &mut expression_nodes,
            budget,
        )?;
    }
    Ok(())
}

fn validate_function_signatures(
    problem: &SemanticProblem,
    budget: &mut WorkBudget,
) -> OracleResult<()> {
    for second in 0..problem.terms.len() {
        for first in 0..second {
            budget.charge(1)?;
            let first_term = &problem.terms[first];
            let second_term = &problem.terms[second];
            if first_term.function != second_term.function {
                continue;
            }
            let same_signature = first_term.sort == second_term.sort
                && first_term.arguments.len() == second_term.arguments.len()
                && first_term.arguments.iter().zip(&second_term.arguments).all(
                    |(first_argument, second_argument)| {
                        problem.terms[first_argument.index()].sort
                            == problem.terms[second_argument.index()].sort
                    },
                );
            if !same_signature {
                return Err(OracleError::InconsistentFunctionSignature {
                    function: first_term.function,
                    first,
                    second,
                }
                .into());
            }
        }
    }
    Ok(())
}

fn validate_boolean_values(problem: &SemanticProblem) -> OracleResult<Option<u32>> {
    let Some((true_term, false_term)) = problem.boolean_values else {
        return Ok(None);
    };
    for term in [true_term, false_term] {
        if term.index() >= problem.terms.len() {
            return Err(OracleError::BooleanValueOutOfRange {
                term: term.index(),
                term_count: problem.terms.len(),
            }
            .into());
        }
    }
    if true_term == false_term {
        return Err(OracleError::BooleanValuesCoincide {
            term: true_term.index(),
        }
        .into());
    }
    let true_sort = problem.terms[true_term.index()].sort;
    if true_sort != problem.terms[false_term.index()].sort {
        return Err(OracleError::BooleanValueSortMismatch {
            true_term: true_term.index(),
            false_term: false_term.index(),
        }
        .into());
    }
    Ok(Some(true_sort))
}

fn validate_atoms(
    problem: &SemanticProblem,
    boolean_sort: Option<u32>,
    budget: &mut WorkBudget,
) -> OracleResult<()> {
    for (atom_index, atom) in problem.atoms.iter().enumerate() {
        budget.charge(1)?;
        match *atom {
            SemanticAtom::Equality(left, right) => {
                validate_atom_term(atom_index, left.index(), problem.terms.len())?;
                validate_atom_term(atom_index, right.index(), problem.terms.len())?;
                if problem.terms[left.index()].sort != problem.terms[right.index()].sort {
                    return Err(OracleError::IllSortedEquality {
                        atom: atom_index,
                        left: left.index(),
                        right: right.index(),
                    }
                    .into());
                }
            }
            SemanticAtom::BoolTerm(term) => {
                validate_atom_term(atom_index, term.index(), problem.terms.len())?;
                let Some(boolean_sort) = boolean_sort else {
                    return Err(OracleError::MissingBooleanValues { atom: atom_index }.into());
                };
                if problem.terms[term.index()].sort != boolean_sort {
                    return Err(OracleError::IllSortedBooleanTerm {
                        atom: atom_index,
                        term: term.index(),
                    }
                    .into());
                }
            }
        }
    }
    Ok(())
}

fn validate_atom_term(atom: usize, term: usize, term_count: usize) -> OracleResult<()> {
    if term < term_count {
        Ok(())
    } else {
        Err(OracleError::AtomTermOutOfRange {
            atom,
            term,
            term_count,
        }
        .into())
    }
}

fn validate_expression(
    expression: &SemanticExpr,
    assertion: usize,
    depth: usize,
    atom_count: usize,
    nodes: &mut usize,
    budget: &mut WorkBudget,
) -> OracleResult<()> {
    enforce_limit(OracleResource::ExpressionDepth, depth, MAX_EXPRESSION_DEPTH)?;
    *nodes = checked_add(*nodes, 1, OracleResource::ExpressionNodes)?;
    enforce_limit(
        OracleResource::ExpressionNodes,
        *nodes,
        MAX_EXPRESSION_NODES,
    )?;
    budget.charge(1)?;

    let child_depth = || checked_add(depth, 1, OracleResource::ExpressionDepth);
    match expression {
        SemanticExpr::Const(_) => Ok(()),
        SemanticExpr::Atom(atom) => {
            if atom.index() < atom_count {
                Ok(())
            } else {
                Err(OracleError::ExpressionAtomOutOfRange {
                    assertion,
                    atom: atom.index(),
                    atom_count,
                }
                .into())
            }
        }
        SemanticExpr::Not(child) => {
            validate_expression(child, assertion, child_depth()?, atom_count, nodes, budget)
        }
        SemanticExpr::And(children) | SemanticExpr::Or(children) | SemanticExpr::Iff(children) => {
            for child in children {
                validate_expression(child, assertion, child_depth()?, atom_count, nodes, budget)?;
            }
            Ok(())
        }
        SemanticExpr::Ite(condition, then_expression, else_expression) => {
            let next_depth = child_depth()?;
            for child in [
                condition.as_ref(),
                then_expression.as_ref(),
                else_expression.as_ref(),
            ] {
                validate_expression(child, assertion, next_depth, atom_count, nodes, budget)?;
            }
            Ok(())
        }
    }
}

fn search_partitions(
    problem: &SemanticProblem,
    term_index: usize,
    class_count: usize,
    classes: &mut [usize; MAX_SEMANTIC_TERMS],
    budget: &mut WorkBudget,
    stats: &mut OracleStats,
) -> OracleResult<Option<OracleModel>> {
    budget.charge(1)?;
    if term_index == problem.terms.len() {
        let attempted = checked_add(stats.partitions_examined, 1, OracleResource::Partitions)?;
        enforce_limit(OracleResource::Partitions, attempted, MAX_PARTITIONS)?;
        stats.partitions_examined = attempted;

        if !has_exact_boolean_domain(problem, classes, budget)? {
            stats.boolean_rejections += 1;
            return Ok(None);
        }
        if !is_ground_congruent(problem, classes, budget)? {
            stats.congruence_rejections += 1;
            return Ok(None);
        }
        let atom_values = evaluate_atoms(problem, classes, budget)?;
        if !satisfies_source(problem, &atom_values, budget)? {
            stats.source_rejections += 1;
            return Ok(None);
        }
        return Ok(Some(build_model(
            problem.terms.len(),
            classes,
            atom_values,
        )?));
    }

    let sort = problem.terms[term_index].sort;
    let mut seen = [false; MAX_SEMANTIC_TERMS];
    for previous in 0..term_index {
        if problem.terms[previous].sort != sort {
            continue;
        }
        let class = classes[previous];
        if seen[class] {
            continue;
        }
        seen[class] = true;
        classes[term_index] = class;
        if let Some(model) =
            search_partitions(problem, term_index + 1, class_count, classes, budget, stats)?
        {
            return Ok(Some(model));
        }
    }

    classes[term_index] = class_count;
    search_partitions(
        problem,
        term_index + 1,
        class_count + 1,
        classes,
        budget,
        stats,
    )
}

fn has_exact_boolean_domain(
    problem: &SemanticProblem,
    classes: &[usize; MAX_SEMANTIC_TERMS],
    budget: &mut WorkBudget,
) -> OracleResult<bool> {
    let Some((true_term, false_term)) = problem.boolean_values else {
        return Ok(true);
    };
    let true_class = classes[true_term.index()];
    let false_class = classes[false_term.index()];
    if true_class == false_class {
        return Ok(false);
    }

    let boolean_sort = problem.terms[true_term.index()].sort;
    for (term_index, term) in problem.terms.iter().enumerate() {
        budget.charge(1)?;
        if term.sort == boolean_sort
            && classes[term_index] != true_class
            && classes[term_index] != false_class
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn is_ground_congruent(
    problem: &SemanticProblem,
    classes: &[usize; MAX_SEMANTIC_TERMS],
    budget: &mut WorkBudget,
) -> OracleResult<bool> {
    for second in 0..problem.terms.len() {
        for first in 0..second {
            budget.charge(1)?;
            let first_term = &problem.terms[first];
            let second_term = &problem.terms[second];
            if first_term.function != second_term.function {
                continue;
            }

            let mut equal_arguments = true;
            for (first_argument, second_argument) in
                first_term.arguments.iter().zip(&second_term.arguments)
            {
                budget.charge(1)?;
                if classes[first_argument.index()] != classes[second_argument.index()] {
                    equal_arguments = false;
                    break;
                }
            }
            if equal_arguments && classes[first] != classes[second] {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn evaluate_atoms(
    problem: &SemanticProblem,
    classes: &[usize; MAX_SEMANTIC_TERMS],
    budget: &mut WorkBudget,
) -> OracleResult<Box<[bool]>> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(problem.atoms.len())
        .map_err(|_| allocation_failure("source atom values"))?;
    for (atom_index, atom) in problem.atoms.iter().enumerate() {
        budget.charge(1)?;
        let value = match *atom {
            SemanticAtom::Equality(left, right) => classes[left.index()] == classes[right.index()],
            SemanticAtom::BoolTerm(term) => {
                let Some((true_term, _)) = problem.boolean_values else {
                    return Err(OracleError::MissingBooleanValues { atom: atom_index }.into());
                };
                classes[term.index()] == classes[true_term.index()]
            }
        };
        values.push(value);
    }
    Ok(values.into_boxed_slice())
}

fn satisfies_source(
    problem: &SemanticProblem,
    atom_values: &[bool],
    budget: &mut WorkBudget,
) -> OracleResult<bool> {
    for literal in &problem.root_literals {
        budget.charge(1)?;
        if atom_values[literal.atom.index()] != literal.positive {
            return Ok(false);
        }
    }
    for (assertion_index, assertion) in problem.assertions.iter().enumerate() {
        if !evaluate_expression(assertion, assertion_index, atom_values, budget)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn evaluate_expression(
    expression: &SemanticExpr,
    assertion: usize,
    atom_values: &[bool],
    budget: &mut WorkBudget,
) -> OracleResult<bool> {
    budget.charge(1)?;
    Ok(match expression {
        SemanticExpr::Const(value) => *value,
        SemanticExpr::Atom(atom) => *atom_values.get(atom.index()).ok_or_else(|| {
            OracleFailure::Malformed(OracleError::ExpressionAtomOutOfRange {
                assertion,
                atom: atom.index(),
                atom_count: atom_values.len(),
            })
        })?,
        SemanticExpr::Not(child) => !evaluate_expression(child, assertion, atom_values, budget)?,
        SemanticExpr::And(children) => {
            let mut value = true;
            for child in children {
                if !evaluate_expression(child, assertion, atom_values, budget)? {
                    value = false;
                    break;
                }
            }
            value
        }
        SemanticExpr::Or(children) => {
            let mut value = false;
            for child in children {
                if evaluate_expression(child, assertion, atom_values, budget)? {
                    value = true;
                    break;
                }
            }
            value
        }
        SemanticExpr::Iff(children) => {
            let Some((first, rest)) = children.split_first() else {
                return Ok(true);
            };
            let first_value = evaluate_expression(first, assertion, atom_values, budget)?;
            let mut value = true;
            for child in rest {
                if evaluate_expression(child, assertion, atom_values, budget)? != first_value {
                    value = false;
                    break;
                }
            }
            value
        }
        SemanticExpr::Ite(condition, then_expression, else_expression) => {
            if evaluate_expression(condition, assertion, atom_values, budget)? {
                evaluate_expression(then_expression, assertion, atom_values, budget)?
            } else {
                evaluate_expression(else_expression, assertion, atom_values, budget)?
            }
        }
    })
}

fn build_model(
    term_count: usize,
    classes: &[usize; MAX_SEMANTIC_TERMS],
    source_atom_values: Box<[bool]>,
) -> OracleResult<OracleModel> {
    let mut canonical = Vec::new();
    canonical
        .try_reserve_exact(term_count)
        .map_err(|_| allocation_failure("canonical term classes"))?;
    for term in 0..term_count {
        let mut representative = term;
        for candidate in 0..term {
            if classes[candidate] == classes[term] {
                representative = candidate;
                break;
            }
        }
        canonical.push(representative);
    }
    Ok(OracleModel {
        term_classes: canonical.into_boxed_slice(),
        source_atom_values,
    })
}

fn allocation_failure(context: &'static str) -> OracleFailure {
    OracleFailure::Abstained(OracleAbstention::AllocationFailed { context })
}

#[cfg(test)]
mod tests {
    use super::super::super::parse_problem;
    use super::super::native_clause::AtomId;
    use super::super::semantic::{RootLiteral, SemanticTerm, project};
    use super::*;

    fn projected(source: &str) -> SemanticProblem {
        project(&parse_problem(source).expect("test source parses")).expect("test source projects")
    }

    fn atom(index: u32) -> SemanticExpr {
        SemanticExpr::Atom(AtomId::new(index))
    }

    fn evaluate(expression: &SemanticExpr, values: &[bool]) -> bool {
        evaluate_expression(expression, 0, values, &mut WorkBudget::new()).unwrap()
    }

    #[test]
    fn exhaustive_same_sort_search_visits_all_four_term_partitions() {
        let mut problem = projected(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U) (declare-const b U)\n\
             (declare-const c U) (declare-const d U)\n\
             (assert (or (= a b) (= c d)))\n\
             (assert (not (or (= a b) (= c d))))\n\
             (check-sat)",
        );
        problem.stats.contradiction = false;
        let outcome = solve(&problem).unwrap();

        assert!(matches!(outcome, OracleOutcome::Unsat { .. }));
        assert_eq!(outcome.stats().partitions_examined, 30);
        assert_eq!(outcome.stats().boolean_rejections, 15);
        assert_eq!(outcome.stats().source_rejections, 15);
    }

    #[test]
    fn typed_search_is_the_product_of_per_sort_partitions() {
        let mut problem = projected(
            "(set-logic QF_UF)\n\
             (declare-sort U 0) (declare-sort V 0)\n\
             (declare-const a U) (declare-const b U)\n\
             (declare-const c V) (declare-const d V)\n\
             (assert (or (= a b) (= c d)))\n\
             (assert (not (or (= a b) (= c d))))\n\
             (check-sat)",
        );
        problem.stats.contradiction = false;
        let outcome = solve(&problem).unwrap();

        assert!(matches!(outcome, OracleOutcome::Unsat { .. }));
        assert_eq!(outcome.stats().partitions_examined, 8);
        assert_eq!(outcome.stats().boolean_rejections, 4);
    }

    #[test]
    fn first_satisfying_partition_and_witness_are_deterministic() {
        let problem = projected(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U) (declare-const b U)\n\
             (assert (distinct a b))\n\
             (check-sat)",
        );
        let first = solve(&problem).unwrap();
        let second = solve(&problem).unwrap();

        assert_eq!(first, second);
        let OracleOutcome::Sat { model, stats } = first else {
            panic!("expected SAT")
        };
        assert_eq!(stats.partitions_examined, 4);
        for (index, atom) in problem.atoms.iter().enumerate() {
            let SemanticAtom::Equality(left, right) = atom else {
                panic!("unexpected Boolean atom")
            };
            assert_eq!(
                model.source_atom_values[index],
                model.term_classes[left.index()] == model.term_classes[right.index()]
            );
        }
    }

    #[test]
    fn ground_function_congruence_closes_equal_argument_tuples() {
        let problem = projected(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U) (declare-const b U)\n\
             (declare-fun f (U) U)\n\
             (assert (= a b))\n\
             (assert (distinct (f a) (f b)))\n\
             (check-sat)",
        );
        assert_eq!(problem.terms.len(), 6);
        let outcome = solve(&problem).unwrap();

        assert!(matches!(outcome, OracleOutcome::Unsat { .. }));
        assert!(outcome.stats().congruence_rejections > 0);
    }

    #[test]
    fn exact_boolean_domain_exhausts_the_six_term_partition_cap() {
        let mut problem = projected(
            "(set-logic QF_UF)\n\
             (declare-const p Bool) (declare-const q Bool)\n\
             (declare-const r Bool) (declare-const s Bool)\n\
             (assert p)\n\
             (assert (not p))\n\
             (assert (or q (not q)))\n\
             (assert (or r (not r)))\n\
             (assert (or s (not s)))\n\
             (check-sat)",
        );
        assert_eq!(problem.terms.len(), 6);
        problem.stats.contradiction = false;
        let outcome = solve(&problem).unwrap();

        assert!(matches!(outcome, OracleOutcome::Unsat { .. }));
        assert_eq!(outcome.stats().partitions_examined, 203);
        assert_eq!(outcome.stats().boolean_rejections, 187);
        assert_eq!(outcome.stats().source_rejections, 16);
    }

    #[test]
    fn boolean_sat_witness_assigns_every_boolean_term_true_or_false() {
        let problem = projected(
            "(set-logic QF_UF)\n\
             (declare-const p Bool) (declare-const q Bool)\n\
             (assert (xor p q))\n\
             (check-sat)",
        );
        let OracleOutcome::Sat { model, .. } = solve(&problem).unwrap() else {
            panic!("expected SAT")
        };
        let (true_term, false_term) = problem.boolean_values.unwrap();
        let true_class = model.term_classes[true_term.index()];
        let false_class = model.term_classes[false_term.index()];

        assert_ne!(true_class, false_class);
        let boolean_sort = problem.terms[true_term.index()].sort;
        for (index, term) in problem.terms.iter().enumerate() {
            if term.sort == boolean_sort {
                assert!(
                    model.term_classes[index] == true_class
                        || model.term_classes[index] == false_class
                );
            }
        }
    }

    #[test]
    fn semantic_expression_truth_tables_are_exact() {
        let expressions = [
            SemanticExpr::Const(true),
            SemanticExpr::Const(false),
            SemanticExpr::Not(Box::new(atom(0))),
            SemanticExpr::And(vec![atom(0), atom(1)].into_boxed_slice()),
            SemanticExpr::Or(vec![atom(0), atom(1)].into_boxed_slice()),
            SemanticExpr::Iff(vec![atom(0), atom(1)].into_boxed_slice()),
            SemanticExpr::Ite(Box::new(atom(0)), Box::new(atom(1)), Box::new(atom(2))),
        ];

        for bits in 0..8usize {
            let values = [bits & 1 != 0, bits & 2 != 0, bits & 4 != 0];
            let expected = [
                true,
                false,
                !values[0],
                values[0] && values[1],
                values[0] || values[1],
                values[0] == values[1],
                if values[0] { values[1] } else { values[2] },
            ];
            for (expression, expected) in expressions.iter().zip(expected) {
                assert_eq!(evaluate(expression, &values), expected, "bits {bits:03b}");
            }
        }

        assert!(evaluate(&SemanticExpr::And(Box::new([])), &[]));
        assert!(!evaluate(&SemanticExpr::Or(Box::new([])), &[]));
        assert!(evaluate(&SemanticExpr::Iff(Box::new([])), &[]));
        assert!(evaluate(
            &SemanticExpr::Iff(vec![atom(0)].into_boxed_slice()),
            &[false]
        ));
    }

    #[test]
    fn unsupported_and_every_bounded_shape_fail_closed() {
        let base = projected(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U)\n\
             (assert (= a a))\n\
             (check-sat)",
        );

        let mut unsupported = base.clone();
        unsupported.stats.unsupported_fragments = 1;
        assert!(matches!(
            solve(&unsupported),
            Ok(OracleOutcome::Abstained {
                reason: OracleAbstention::UnsupportedFragments { count: 1 },
                ..
            })
        ));

        let mut too_many_terms = base.clone();
        let template = too_many_terms.terms[0].clone();
        too_many_terms.terms = vec![template; MAX_GROUND_TERMS + 1].into_boxed_slice();
        too_many_terms.atoms = Box::new([]);
        too_many_terms.assertions = Box::new([]);
        too_many_terms.root_literals = Box::new([]);
        too_many_terms.boolean_values = None;
        assert_cap(solve(&too_many_terms), OracleResource::GroundTerms);

        let mut too_many_semantic_terms = too_many_terms.clone();
        let template = too_many_semantic_terms.terms[0].clone();
        too_many_semantic_terms.terms = vec![template; MAX_SEMANTIC_TERMS + 1].into_boxed_slice();
        assert_cap(
            solve(&too_many_semantic_terms),
            OracleResource::SemanticTerms,
        );

        let mut too_many_atoms = base.clone();
        let template = too_many_atoms.atoms[0].clone();
        too_many_atoms.atoms = vec![template; MAX_ATOMS + 1].into_boxed_slice();
        assert_cap(solve(&too_many_atoms), OracleResource::Atoms);

        let mut too_many_arguments = base.clone();
        let argument = match too_many_arguments.atoms[0] {
            SemanticAtom::Equality(left, _) => left,
            SemanticAtom::BoolTerm(term) => term,
        };
        too_many_arguments.terms[0].arguments =
            vec![argument; MAX_TERM_ARGUMENTS + 1].into_boxed_slice();
        assert_cap(solve(&too_many_arguments), OracleResource::TermArguments);

        let mut too_many_roots = base.clone();
        too_many_roots.root_literals = vec![
            RootLiteral {
                atom: AtomId::new(0),
                positive: true,
            };
            MAX_ROOT_LITERALS + 1
        ]
        .into_boxed_slice();
        assert_cap(solve(&too_many_roots), OracleResource::RootLiterals);

        let mut too_many_assertions = base.clone();
        too_many_assertions.assertions =
            vec![SemanticExpr::Const(true); MAX_ASSERTIONS + 1].into_boxed_slice();
        assert_cap(solve(&too_many_assertions), OracleResource::Assertions);

        let mut too_many_nodes = base;
        too_many_nodes.assertions = vec![SemanticExpr::And(
            vec![SemanticExpr::Const(true); MAX_EXPRESSION_NODES + 1].into_boxed_slice(),
        )]
        .into_boxed_slice();
        assert_cap(solve(&too_many_nodes), OracleResource::ExpressionNodes);
    }

    fn assert_cap(outcome: Result<OracleOutcome, OracleError>, resource: OracleResource) {
        assert!(matches!(
            outcome,
            Ok(OracleOutcome::Abstained {
                reason: OracleAbstention::CapExceeded { resource: got, .. },
                ..
            }) if got == resource
        ));
    }

    #[test]
    fn malformed_semantic_records_return_errors_not_solver_answers() {
        let mut bad_argument = projected(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U) (declare-const b U)\n\
             (assert (= a b))\n\
             (check-sat)",
        );
        let (true_term, false_term) = bad_argument.boolean_values.unwrap();
        let invalid_argument = match bad_argument.atoms[0] {
            SemanticAtom::Equality(left, right) => [left, right, true_term, false_term]
                .into_iter()
                .max()
                .expect("fixture has semantic terms"),
            SemanticAtom::BoolTerm(_) => panic!("expected equality"),
        };
        let mut terms = bad_argument.terms.into_vec();
        assert_eq!(invalid_argument.index(), terms.len() - 1);
        terms.pop();
        terms[0].arguments = vec![invalid_argument].into_boxed_slice();
        bad_argument.terms = terms.into_boxed_slice();
        assert!(matches!(
            solve(&bad_argument),
            Err(OracleError::TermArgumentOutOfRange { .. })
        ));

        let mut bad_signature = projected(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U) (declare-const b U)\n\
             (assert (= a b))\n\
             (check-sat)",
        );
        let signature_argument = match bad_signature.atoms[0] {
            SemanticAtom::Equality(left, _) => left,
            SemanticAtom::BoolTerm(term) => term,
        };
        bad_signature.terms[1].function = bad_signature.terms[0].function;
        bad_signature.terms[1].arguments = vec![signature_argument].into_boxed_slice();
        assert!(matches!(
            solve(&bad_signature),
            Err(OracleError::InconsistentFunctionSignature { .. })
        ));

        let mut missing_boolean_values = projected(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U)\n\
             (assert (= a a))\n\
             (check-sat)",
        );
        let boolean_term = missing_boolean_values.boolean_values.unwrap().0;
        missing_boolean_values.atoms =
            vec![SemanticAtom::BoolTerm(boolean_term)].into_boxed_slice();
        missing_boolean_values.assertions = Box::new([]);
        missing_boolean_values.root_literals = Box::new([]);
        missing_boolean_values.boolean_values = None;
        assert!(matches!(
            solve(&missing_boolean_values),
            Err(OracleError::MissingBooleanValues { atom: 0 })
        ));

        let mut coincident_boolean_values =
            projected("(set-logic QF_UF)\n(assert true)\n(check-sat)");
        let true_term = coincident_boolean_values.boolean_values.unwrap().0;
        coincident_boolean_values.boolean_values = Some((true_term, true_term));
        assert_eq!(
            solve(&coincident_boolean_values),
            Err(OracleError::BooleanValuesCoincide {
                term: true_term.index()
            })
        );

        let mut bad_expression = projected("(set-logic QF_UF)\n(assert true)\n(check-sat)");
        bad_expression.assertions = vec![atom(7)].into_boxed_slice();
        assert!(matches!(
            solve(&bad_expression),
            Err(OracleError::ExpressionAtomOutOfRange {
                assertion: 0,
                atom: 7,
                ..
            })
        ));
    }

    #[test]
    fn direct_semantic_fixture_rejects_ill_sorted_equalities() {
        let mut problem = projected(
            "(set-logic QF_UF)\n\
             (declare-sort U 0) (declare-sort V 0)\n\
             (declare-const a U) (declare-const b V)\n\
             (assert (and (= a a) (= b b)))\n\
             (check-sat)",
        );
        assert_eq!(problem.terms.len(), 4);
        let (true_term, false_term) = problem.boolean_values.unwrap();
        let data_terms = (0..problem.terms.len())
            .filter(|&term| term != true_term.index() && term != false_term.index())
            .collect::<Vec<_>>();
        assert_eq!(data_terms.len(), 2);
        let mut data_ids = problem
            .atoms
            .iter()
            .filter_map(|atom| match atom {
                SemanticAtom::Equality(left, right)
                    if left == right && data_terms.contains(&left.index()) =>
                {
                    Some(*left)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        data_ids.sort_unstable();
        data_ids.dedup();
        assert_eq!(data_ids.len(), 2);
        let left = data_ids[0];
        let right = data_ids[1];
        problem.atoms = vec![SemanticAtom::Equality(left, right)].into_boxed_slice();
        problem.assertions = Box::new([]);
        problem.root_literals = Box::new([]);

        assert_eq!(
            solve(&problem),
            Err(OracleError::IllSortedEquality {
                atom: 0,
                left: left.index(),
                right: right.index(),
            })
        );
    }

    #[test]
    fn expression_depth_is_capped_before_recursive_evaluation() {
        let mut problem = projected("(set-logic QF_UF)\n(assert true)\n(check-sat)");
        let mut expression = SemanticExpr::Const(true);
        for _ in 0..MAX_EXPRESSION_DEPTH {
            expression = SemanticExpr::Not(Box::new(expression));
        }
        problem.assertions = vec![expression].into_boxed_slice();

        assert_cap(solve(&problem), OracleResource::ExpressionDepth);
    }

    #[test]
    fn explicit_source_contradiction_is_unsat_only_after_validation() {
        let mut problem = projected("(set-logic QF_UF)\n(assert true)\n(check-sat)");
        problem.stats.contradiction = true;
        let outcome = solve(&problem).unwrap();
        assert_eq!(
            outcome,
            OracleOutcome::Unsat {
                stats: OracleStats::default()
            }
        );

        problem.assertions = vec![atom(1)].into_boxed_slice();
        assert!(matches!(
            solve(&problem),
            Err(OracleError::ExpressionAtomOutOfRange { .. })
        ));
    }

    #[test]
    fn manually_well_formed_zero_arity_problem_is_sat() {
        let mut problem = projected("(set-logic QF_UF)\n(assert true)\n(check-sat)");
        problem.terms = vec![SemanticTerm {
            function: 0,
            sort: 0,
            arguments: Box::new([]),
        }]
        .into_boxed_slice();
        problem.atoms = Box::new([]);
        problem.assertions = Box::new([]);
        problem.root_literals = Box::new([]);
        problem.boolean_values = None;
        problem.stats.contradiction = false;

        let OracleOutcome::Sat { model, stats } = solve(&problem).unwrap() else {
            panic!("expected SAT")
        };
        assert_eq!(model.term_classes.as_ref(), &[0]);
        assert!(model.source_atom_values.is_empty());
        assert_eq!(stats.partitions_examined, 1);
    }
}
