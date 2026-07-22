#![deny(unsafe_code)]

//! Independent replay for the first Fabric-native proof event format.
//!
//! The checker deliberately owns a small equality implementation. It does not
//! share partition state, representatives, signatures, or congruence helpers
//! with a proof producer.

use super::native_clause::AtomId;
use super::partition::TermId;
use super::semantic::{SemanticAtom, SemanticExpr, SemanticProblem};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;

pub const FABRIC_NATIVE_V1: &str = "fabric-native-v1";

// These are checker limits, not representational limits. A proof outside this
// envelope is rejected before replay instead of risking unchecked allocation
// or arithmetic.
pub const MAX_CHECK_TERMS: usize = 1_000_000;
pub const MAX_CHECK_ATOMS: usize = 1_000_000;
pub const MAX_CHECK_EVENTS: usize = 1_000_000;
pub const MAX_TERM_ARGUMENTS: usize = 4_000_000;
pub const MAX_EXPRESSION_NODES: usize = 4_000_000;
pub const MAX_SOURCE_LITERALS: usize = 2_000_000;
pub const MAX_PREMISES_PER_EVENT: usize = 65_536;
pub const MAX_TOTAL_PREMISES: usize = 4_000_000;
pub const MAX_CONGRUENCE_ARITY: usize = 65_536;
pub const MAX_CHECK_WORK: usize = 64_000_000;

/// A stable index into one event stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId(u32);

impl EventId {
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }

    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(output)
    }
}

/// The representation-neutral events accepted by `fabric-native-v1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofEvent {
    AssertEquality {
        atom: AtomId,
    },
    AssertDisequality {
        atom: AtomId,
    },
    CongruenceMerge {
        left: TermId,
        right: TermId,
        premises: Box<[EventId]>,
    },
    NativeUnit {
        atom: AtomId,
        positive: bool,
        premises: Box<[EventId]>,
    },
    NativeConflict {
        premises: Box<[EventId]>,
    },
    UnsatRoot {
        conflict: EventId,
    },
}

pub type FabricEvent = ProofEvent;

/// A versioned event stream. The format comparison is byte-exact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventStream {
    pub format: Box<str>,
    pub events: Box<[ProofEvent]>,
}

impl EventStream {
    pub fn new(events: impl Into<Box<[ProofEvent]>>) -> Self {
        Self {
            format: FABRIC_NATIVE_V1.into(),
            events: events.into(),
        }
    }

    pub fn with_format(format: impl Into<Box<str>>, events: impl Into<Box<[ProofEvent]>>) -> Self {
        Self {
            format: format.into(),
            events: events.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckReceipt {
    pub format: &'static str,
    pub events_checked: usize,
    pub unsat_root: EventId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckError {
    WrongFormat,
    UnsupportedFragments {
        count: usize,
    },
    TooManyTerms {
        count: usize,
        maximum: usize,
    },
    TooManyAtoms {
        count: usize,
        maximum: usize,
    },
    TooManyEvents {
        count: usize,
        maximum: usize,
    },
    TooManyTermArguments {
        count: usize,
        maximum: usize,
    },
    TooManyExpressionNodes {
        count: usize,
        maximum: usize,
    },
    TooManySourceLiterals {
        count: usize,
        maximum: usize,
    },
    TooManyPremises {
        event: EventId,
        count: usize,
        maximum: usize,
    },
    TooManyTotalPremises {
        count: usize,
        maximum: usize,
    },
    CongruenceArityLimit {
        event: EventId,
        arity: usize,
        maximum: usize,
    },
    WorkLimitExceeded {
        event: Option<EventId>,
        maximum: usize,
    },
    AllocationFailed {
        context: &'static str,
    },
    SemanticTermArgumentOutOfRange {
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
    InvalidBooleanValues {
        true_term: TermId,
        false_term: TermId,
    },
    MissingBooleanValues,
    AtomTermOutOfRange {
        atom: AtomId,
        term: TermId,
        term_count: usize,
    },
    IllSortedAtom {
        atom: AtomId,
    },
    SourceAtomOutOfRange {
        atom: AtomId,
        atom_count: usize,
    },
    EventAtomOutOfRange {
        event: EventId,
        atom: AtomId,
        atom_count: usize,
    },
    EventTermOutOfRange {
        event: EventId,
        term: TermId,
        term_count: usize,
    },
    SourceLiteralNotAsserted {
        event: EventId,
        atom: AtomId,
        positive: bool,
    },
    PremiseOutOfRange {
        event: EventId,
        premise: EventId,
        event_count: usize,
    },
    ForwardPremise {
        event: EventId,
        premise: EventId,
    },
    InvalidPremiseKind {
        event: EventId,
        premise: EventId,
    },
    CongruenceFunctionMismatch {
        event: EventId,
        left: TermId,
        right: TermId,
    },
    CongruenceSortMismatch {
        event: EventId,
        left: TermId,
        right: TermId,
    },
    CongruenceArityMismatch {
        event: EventId,
        left: TermId,
        right: TermId,
    },
    CongruenceArgumentNotEqual {
        event: EventId,
        position: usize,
        left: TermId,
        right: TermId,
    },
    CongruencePremisesDoNotProveArgument {
        event: EventId,
        position: usize,
        left: TermId,
        right: TermId,
    },
    NativeUnitNotProved {
        event: EventId,
        atom: AtomId,
        positive: bool,
    },
    NativeConflictNotProved {
        event: EventId,
    },
    UnsatRootDoesNotCiteConflict {
        event: EventId,
        premise: EventId,
    },
    EventAfterUnsatRoot {
        event: EventId,
    },
    MissingUnsatRoot,
}

impl fmt::Display for CheckError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongFormat => write!(output, "expected exact proof format {FABRIC_NATIVE_V1}"),
            Self::UnsupportedFragments { count } => {
                write!(
                    output,
                    "semantic problem contains {count} unsupported fragments"
                )
            }
            Self::TooManyTerms { count, maximum } => {
                write!(
                    output,
                    "checker term limit {maximum} exceeded by {count} terms"
                )
            }
            Self::TooManyAtoms { count, maximum } => {
                write!(
                    output,
                    "checker atom limit {maximum} exceeded by {count} atoms"
                )
            }
            Self::TooManyEvents { count, maximum } => {
                write!(
                    output,
                    "checker event limit {maximum} exceeded by {count} events"
                )
            }
            Self::TooManyTermArguments { count, maximum } => write!(
                output,
                "checker term-argument limit {maximum} exceeded by {count} arguments"
            ),
            Self::TooManyExpressionNodes { count, maximum } => write!(
                output,
                "checker expression-node limit {maximum} exceeded by {count} nodes"
            ),
            Self::TooManySourceLiterals { count, maximum } => write!(
                output,
                "checker source-literal limit {maximum} exceeded by {count} literals"
            ),
            Self::TooManyPremises {
                event,
                count,
                maximum,
            } => write!(
                output,
                "event {event} has {count} premises, exceeding limit {maximum}"
            ),
            Self::TooManyTotalPremises { count, maximum } => write!(
                output,
                "stream has {count} premises, exceeding limit {maximum}"
            ),
            Self::CongruenceArityLimit {
                event,
                arity,
                maximum,
            } => write!(
                output,
                "event {event} congruence arity {arity} exceeds limit {maximum}"
            ),
            Self::WorkLimitExceeded { event, maximum } => match event {
                Some(event) => write!(output, "event {event} exceeds checker work limit {maximum}"),
                None => write!(
                    output,
                    "semantic validation exceeds checker work limit {maximum}"
                ),
            },
            Self::AllocationFailed { context } => {
                write!(output, "checker allocation failed for {context}")
            }
            Self::SemanticTermArgumentOutOfRange {
                term,
                argument,
                term_count,
            } => write!(
                output,
                "semantic term {term} argument {argument} is outside 0..{term_count}"
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
            Self::InvalidBooleanValues {
                true_term,
                false_term,
            } => write!(
                output,
                "Boolean value terms {true_term} and {false_term} are not distinct, same-sort terms"
            ),
            Self::MissingBooleanValues => {
                write!(
                    output,
                    "BoolTerm atoms require explicit semantic Boolean value terms"
                )
            }
            Self::AtomTermOutOfRange {
                atom,
                term,
                term_count,
            } => write!(
                output,
                "semantic atom {} term {term} is outside 0..{term_count}",
                atom.index()
            ),
            Self::IllSortedAtom { atom } => {
                write!(output, "semantic atom {} is ill sorted", atom.index())
            }
            Self::SourceAtomOutOfRange { atom, atom_count } => write!(
                output,
                "source atom {} is outside 0..{atom_count}",
                atom.index()
            ),
            Self::EventAtomOutOfRange {
                event,
                atom,
                atom_count,
            } => write!(
                output,
                "event {event} atom {} is outside 0..{atom_count}",
                atom.index()
            ),
            Self::EventTermOutOfRange {
                event,
                term,
                term_count,
            } => write!(
                output,
                "event {event} term {term} is outside 0..{term_count}"
            ),
            Self::SourceLiteralNotAsserted {
                event,
                atom,
                positive,
            } => write!(
                output,
                "event {event} claims unasserted source literal {}{}",
                if *positive { "" } else { "not " },
                atom.index()
            ),
            Self::PremiseOutOfRange {
                event,
                premise,
                event_count,
            } => write!(
                output,
                "event {event} premise {premise} is outside 0..{event_count}"
            ),
            Self::ForwardPremise { event, premise } => {
                write!(output, "event {event} has non-earlier premise {premise}")
            }
            Self::InvalidPremiseKind { event, premise } => write!(
                output,
                "event {event} cannot use event {premise} as a relation premise"
            ),
            Self::CongruenceFunctionMismatch { event, left, right } => write!(
                output,
                "event {event} merges different functions at terms {left} and {right}"
            ),
            Self::CongruenceSortMismatch { event, left, right } => write!(
                output,
                "event {event} merges different result sorts at terms {left} and {right}"
            ),
            Self::CongruenceArityMismatch { event, left, right } => write!(
                output,
                "event {event} merges different arities at terms {left} and {right}"
            ),
            Self::CongruenceArgumentNotEqual {
                event,
                position,
                left,
                right,
            } => write!(
                output,
                "event {event} argument {position} terms {left} and {right} are not already equal"
            ),
            Self::CongruencePremisesDoNotProveArgument {
                event,
                position,
                left,
                right,
            } => write!(
                output,
                "event {event} premises do not prove argument {position} terms {left} and {right} equal"
            ),
            Self::NativeUnitNotProved {
                event,
                atom,
                positive,
            } => write!(
                output,
                "event {event} premises do not prove native unit {}{}",
                if *positive { "" } else { "not " },
                atom.index()
            ),
            Self::NativeConflictNotProved { event } => {
                write!(output, "event {event} premises do not prove a conflict")
            }
            Self::UnsatRootDoesNotCiteConflict { event, premise } => write!(
                output,
                "UNSAT root event {event} cites non-conflict event {premise}"
            ),
            Self::EventAfterUnsatRoot { event } => {
                write!(output, "event {event} appears after an UNSAT root")
            }
            Self::MissingUnsatRoot => write!(output, "event stream has no UNSAT root"),
        }
    }
}

impl Error for CheckError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Relation {
    Equality(TermId, TermId),
    Disequality(TermId, TermId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CheckedFact {
    Equality(TermId, TermId),
    Disequality(TermId, TermId),
    Conflict,
    UnsatRoot,
}

impl From<Relation> for CheckedFact {
    fn from(relation: Relation) -> Self {
        match relation {
            Relation::Equality(left, right) => Self::Equality(left, right),
            Relation::Disequality(left, right) => Self::Disequality(left, right),
        }
    }
}

struct SemanticView {
    source_literals: HashSet<(usize, bool)>,
    source_conflict: bool,
    boolean_values: Option<(TermId, TermId)>,
}

struct WorkBudget {
    used: usize,
}

impl WorkBudget {
    fn new() -> Self {
        Self { used: 0 }
    }

    fn charge(&mut self, amount: usize, event: Option<EventId>) -> Result<(), CheckError> {
        self.used = self
            .used
            .checked_add(amount)
            .ok_or(CheckError::WorkLimitExceeded {
                event,
                maximum: MAX_CHECK_WORK,
            })?;
        if self.used > MAX_CHECK_WORK {
            return Err(CheckError::WorkLimitExceeded {
                event,
                maximum: MAX_CHECK_WORK,
            });
        }
        Ok(())
    }
}

/// Check a complete `fabric-native-v1` stream and return only after an UNSAT
/// root has cited a previously checked conflict.
pub fn check(problem: &SemanticProblem, stream: &EventStream) -> Result<CheckReceipt, CheckError> {
    check_stream(problem, stream.format.as_ref(), &stream.events)
}

fn check_stream(
    problem: &SemanticProblem,
    format: &str,
    events: &[ProofEvent],
) -> Result<CheckReceipt, CheckError> {
    if format != FABRIC_NATIVE_V1 {
        return Err(CheckError::WrongFormat);
    }
    if events.len() > MAX_CHECK_EVENTS {
        return Err(CheckError::TooManyEvents {
            count: events.len(),
            maximum: MAX_CHECK_EVENTS,
        });
    }

    let mut budget = WorkBudget::new();
    let semantic = validate_semantic_problem(problem, &mut budget)?;
    let mut equality = EqualityState::new(problem.terms.len())?;
    let mut facts = Vec::new();
    facts
        .try_reserve_exact(events.len())
        .map_err(|_| CheckError::AllocationFailed {
            context: "checked events",
        })?;

    let mut total_premises = 0usize;
    let mut unsat_root = None;
    for (index, event) in events.iter().enumerate() {
        let event_id = checked_event_id(index);
        if unsat_root.is_some() {
            return Err(CheckError::EventAfterUnsatRoot { event: event_id });
        }
        budget.charge(1, Some(event_id))?;

        let fact = match event {
            ProofEvent::AssertEquality { atom } => {
                check_source_literal(problem, &semantic, event_id, *atom, true)?
            }
            ProofEvent::AssertDisequality { atom } => {
                check_source_literal(problem, &semantic, event_id, *atom, false)?
            }
            ProofEvent::CongruenceMerge {
                left,
                right,
                premises,
            } => check_congruence(
                problem,
                event_id,
                *left,
                *right,
                premises,
                &facts,
                events.len(),
                &mut total_premises,
                &mut budget,
                &mut equality,
            )?,
            ProofEvent::NativeUnit {
                atom,
                positive,
                premises,
            } => check_native_unit(
                problem,
                &semantic,
                event_id,
                *atom,
                *positive,
                premises,
                &facts,
                events.len(),
                &mut total_premises,
                &mut budget,
            )?,
            ProofEvent::NativeConflict { premises } => check_native_conflict(
                &semantic,
                event_id,
                premises,
                &facts,
                events.len(),
                &mut total_premises,
                &mut budget,
            )?,
            ProofEvent::UnsatRoot { conflict } => {
                check_reference(event_id, *conflict, events.len())?;
                let Some(CheckedFact::Conflict) = facts.get(conflict.index()) else {
                    return Err(CheckError::UnsatRootDoesNotCiteConflict {
                        event: event_id,
                        premise: *conflict,
                    });
                };
                unsat_root = Some(event_id);
                CheckedFact::UnsatRoot
            }
        };

        match fact {
            CheckedFact::Equality(left, right) => equality.merge(left, right)?,
            CheckedFact::Disequality(_, _) | CheckedFact::Conflict | CheckedFact::UnsatRoot => {}
        }
        facts.push(fact);
    }

    let unsat_root = unsat_root.ok_or(CheckError::MissingUnsatRoot)?;
    Ok(CheckReceipt {
        format: FABRIC_NATIVE_V1,
        events_checked: facts.len(),
        unsat_root,
    })
}

/// Convenience entry point for an in-memory v1 event slice.
pub fn check_events(
    problem: &SemanticProblem,
    events: &[ProofEvent],
) -> Result<CheckReceipt, CheckError> {
    check_stream(problem, FABRIC_NATIVE_V1, events)
}

fn validate_semantic_problem(
    problem: &SemanticProblem,
    budget: &mut WorkBudget,
) -> Result<SemanticView, CheckError> {
    if problem.stats.unsupported_fragments != 0 {
        return Err(CheckError::UnsupportedFragments {
            count: problem.stats.unsupported_fragments,
        });
    }
    let term_count = problem.terms.len();
    if term_count > MAX_CHECK_TERMS {
        return Err(CheckError::TooManyTerms {
            count: term_count,
            maximum: MAX_CHECK_TERMS,
        });
    }
    if problem.atoms.len() > MAX_CHECK_ATOMS {
        return Err(CheckError::TooManyAtoms {
            count: problem.atoms.len(),
            maximum: MAX_CHECK_ATOMS,
        });
    }

    let mut argument_count = 0usize;
    let mut first_by_function = HashMap::<u32, usize>::new();
    first_by_function
        .try_reserve(term_count)
        .map_err(|_| CheckError::AllocationFailed {
            context: "semantic function signatures",
        })?;
    for (index, term) in problem.terms.iter().enumerate() {
        let term_id = checked_term_id(index);
        argument_count = argument_count.checked_add(term.arguments.len()).ok_or(
            CheckError::TooManyTermArguments {
                count: usize::MAX,
                maximum: MAX_TERM_ARGUMENTS,
            },
        )?;
        if argument_count > MAX_TERM_ARGUMENTS {
            return Err(CheckError::TooManyTermArguments {
                count: argument_count,
                maximum: MAX_TERM_ARGUMENTS,
            });
        }
        let term_work =
            term.arguments
                .len()
                .checked_add(1)
                .ok_or(CheckError::WorkLimitExceeded {
                    event: None,
                    maximum: MAX_CHECK_WORK,
                })?;
        budget.charge(term_work, None)?;
        for &argument in &term.arguments {
            if argument.index() >= term_count {
                return Err(CheckError::SemanticTermArgumentOutOfRange {
                    term: term_id,
                    argument,
                    term_count,
                });
            }
        }

        if let Some(&first_index) = first_by_function.get(&term.function) {
            let first = &problem.terms[first_index];
            let same_signature = first.sort == term.sort
                && first.arguments.len() == term.arguments.len()
                && first.arguments.iter().zip(term.arguments.iter()).all(
                    |(first_argument, argument)| {
                        problem.terms[first_argument.index()].sort
                            == problem.terms[argument.index()].sort
                    },
                );
            if !same_signature {
                return Err(CheckError::InconsistentFunctionSignature {
                    function: term.function,
                    first: checked_term_id(first_index),
                    second: term_id,
                });
            }
        } else {
            first_by_function.insert(term.function, index);
        }
    }

    let boolean_values = validate_boolean_values(problem)?;
    for (index, atom) in problem.atoms.iter().enumerate() {
        let atom_id = AtomId::new(index as u32);
        match atom {
            SemanticAtom::Equality(left, right) => {
                validate_atom_term(atom_id, *left, problem)?;
                validate_atom_term(atom_id, *right, problem)?;
                if problem.terms[left.index()].sort != problem.terms[right.index()].sort {
                    return Err(CheckError::IllSortedAtom { atom: atom_id });
                }
            }
            SemanticAtom::BoolTerm(term) => {
                validate_atom_term(atom_id, *term, problem)?;
                let Some((true_term, _)) = boolean_values else {
                    return Err(CheckError::MissingBooleanValues);
                };
                if problem.terms[term.index()].sort != problem.terms[true_term.index()].sort {
                    return Err(CheckError::IllSortedAtom { atom: atom_id });
                }
            }
        }
    }

    if problem.root_literals.len() > MAX_SOURCE_LITERALS {
        return Err(CheckError::TooManySourceLiterals {
            count: problem.root_literals.len(),
            maximum: MAX_SOURCE_LITERALS,
        });
    }
    let source_capacity =
        problem
            .atoms
            .len()
            .checked_mul(2)
            .ok_or(CheckError::TooManySourceLiterals {
                count: usize::MAX,
                maximum: MAX_SOURCE_LITERALS,
            })?;
    let mut source_literals = HashSet::new();
    source_literals
        .try_reserve(source_capacity.min(MAX_SOURCE_LITERALS))
        .map_err(|_| CheckError::AllocationFailed {
            context: "source literals",
        })?;
    for literal in &problem.root_literals {
        budget.charge(1, None)?;
        validate_source_atom(literal.atom, problem.atoms.len())?;
        source_literals.insert((literal.atom.index(), literal.positive));
    }
    let mut source_conflict = collect_assertion_literals(
        &problem.assertions,
        problem.atoms.len(),
        &mut source_literals,
        budget,
    )?;
    source_conflict |= source_literals
        .iter()
        .any(|(atom, positive)| source_literals.contains(&(*atom, !*positive)));

    for &(atom_index, positive) in &source_literals {
        let relation = literal_relation(
            problem,
            boolean_values,
            AtomId::new(atom_index as u32),
            positive,
        )?;
        if matches!(relation, Relation::Disequality(left, right) if left == right) {
            source_conflict = true;
        }
    }

    Ok(SemanticView {
        source_literals,
        source_conflict,
        boolean_values,
    })
}

fn validate_boolean_values(
    problem: &SemanticProblem,
) -> Result<Option<(TermId, TermId)>, CheckError> {
    let Some((true_term, false_term)) = problem.boolean_values else {
        return Ok(None);
    };
    for term in [true_term, false_term] {
        if term.index() >= problem.terms.len() {
            return Err(CheckError::BooleanValueOutOfRange {
                term,
                term_count: problem.terms.len(),
            });
        }
    }
    if true_term == false_term
        || problem.terms[true_term.index()].sort != problem.terms[false_term.index()].sort
    {
        return Err(CheckError::InvalidBooleanValues {
            true_term,
            false_term,
        });
    }
    Ok(Some((true_term, false_term)))
}

fn validate_atom_term(
    atom: AtomId,
    term: TermId,
    problem: &SemanticProblem,
) -> Result<(), CheckError> {
    if term.index() >= problem.terms.len() {
        return Err(CheckError::AtomTermOutOfRange {
            atom,
            term,
            term_count: problem.terms.len(),
        });
    }
    Ok(())
}

fn validate_source_atom(atom: AtomId, atom_count: usize) -> Result<(), CheckError> {
    if atom.index() >= atom_count {
        return Err(CheckError::SourceAtomOutOfRange { atom, atom_count });
    }
    Ok(())
}

fn collect_assertion_literals(
    assertions: &[SemanticExpr],
    atom_count: usize,
    source_literals: &mut HashSet<(usize, bool)>,
    budget: &mut WorkBudget,
) -> Result<bool, CheckError> {
    if assertions.len() > MAX_EXPRESSION_NODES {
        return Err(CheckError::TooManyExpressionNodes {
            count: assertions.len(),
            maximum: MAX_EXPRESSION_NODES,
        });
    }
    let mut stack = Vec::new();
    stack
        .try_reserve(assertions.len())
        .map_err(|_| CheckError::AllocationFailed {
            context: "semantic expression traversal",
        })?;
    stack.extend(
        assertions
            .iter()
            .rev()
            .map(|assertion| (assertion, Some(true))),
    );

    let mut nodes = 0usize;
    let mut source_conflict = false;
    while let Some((expression, required)) = stack.pop() {
        nodes = nodes
            .checked_add(1)
            .ok_or(CheckError::TooManyExpressionNodes {
                count: usize::MAX,
                maximum: MAX_EXPRESSION_NODES,
            })?;
        if nodes > MAX_EXPRESSION_NODES {
            return Err(CheckError::TooManyExpressionNodes {
                count: nodes,
                maximum: MAX_EXPRESSION_NODES,
            });
        }
        budget.charge(1, None)?;

        match expression {
            SemanticExpr::Const(value) => {
                if required.is_some_and(|required| required != *value) {
                    source_conflict = true;
                }
            }
            SemanticExpr::Atom(atom) => {
                validate_source_atom(*atom, atom_count)?;
                if let Some(positive) = required {
                    source_literals.insert((atom.index(), positive));
                }
            }
            SemanticExpr::Not(child) => {
                reserve_stack(&mut stack, 1, nodes)?;
                stack.push((child, required.map(|value| !value)));
            }
            SemanticExpr::And(children) => {
                reserve_stack(&mut stack, children.len(), nodes)?;
                let child_required = (required == Some(true)).then_some(true);
                stack.extend(children.iter().rev().map(|child| (child, child_required)));
            }
            SemanticExpr::Or(children) => {
                reserve_stack(&mut stack, children.len(), nodes)?;
                let child_required = (required == Some(false)).then_some(false);
                stack.extend(children.iter().rev().map(|child| (child, child_required)));
            }
            SemanticExpr::Iff(children) => {
                reserve_stack(&mut stack, children.len(), nodes)?;
                stack.extend(children.iter().rev().map(|child| (child, None)));
            }
            SemanticExpr::Ite(condition, then_expression, else_expression) => {
                reserve_stack(&mut stack, 3, nodes)?;
                stack.push((else_expression, None));
                stack.push((then_expression, None));
                stack.push((condition, None));
            }
        }
    }
    Ok(source_conflict)
}

fn reserve_stack<'a>(
    stack: &mut Vec<(&'a SemanticExpr, Option<bool>)>,
    additional: usize,
    visited: usize,
) -> Result<(), CheckError> {
    let discovered = visited
        .checked_add(stack.len())
        .and_then(|count| count.checked_add(additional))
        .ok_or(CheckError::TooManyExpressionNodes {
            count: usize::MAX,
            maximum: MAX_EXPRESSION_NODES,
        })?;
    if discovered > MAX_EXPRESSION_NODES {
        return Err(CheckError::TooManyExpressionNodes {
            count: discovered,
            maximum: MAX_EXPRESSION_NODES,
        });
    }
    stack
        .try_reserve(additional)
        .map_err(|_| CheckError::AllocationFailed {
            context: "semantic expression traversal",
        })
}

fn check_source_literal(
    problem: &SemanticProblem,
    semantic: &SemanticView,
    event: EventId,
    atom: AtomId,
    positive: bool,
) -> Result<CheckedFact, CheckError> {
    validate_event_atom(event, atom, problem.atoms.len())?;
    if !semantic.source_literals.contains(&(atom.index(), positive)) {
        return Err(CheckError::SourceLiteralNotAsserted {
            event,
            atom,
            positive,
        });
    }
    Ok(literal_relation(problem, semantic.boolean_values, atom, positive)?.into())
}

#[allow(clippy::too_many_arguments)]
fn check_congruence(
    problem: &SemanticProblem,
    event: EventId,
    left: TermId,
    right: TermId,
    premises: &[EventId],
    facts: &[CheckedFact],
    event_count: usize,
    total_premises: &mut usize,
    budget: &mut WorkBudget,
    equality: &mut EqualityState,
) -> Result<CheckedFact, CheckError> {
    validate_event_term(event, left, problem.terms.len())?;
    validate_event_term(event, right, problem.terms.len())?;
    validate_premises(event, premises, event_count, total_premises, budget)?;

    let left_term = &problem.terms[left.index()];
    let right_term = &problem.terms[right.index()];
    if left_term.function != right_term.function {
        return Err(CheckError::CongruenceFunctionMismatch { event, left, right });
    }
    if left_term.sort != right_term.sort {
        return Err(CheckError::CongruenceSortMismatch { event, left, right });
    }
    if left_term.arguments.len() != right_term.arguments.len() {
        return Err(CheckError::CongruenceArityMismatch { event, left, right });
    }
    if left_term.arguments.len() > MAX_CONGRUENCE_ARITY {
        return Err(CheckError::CongruenceArityLimit {
            event,
            arity: left_term.arguments.len(),
            maximum: MAX_CONGRUENCE_ARITY,
        });
    }
    budget.charge(left_term.arguments.len(), Some(event))?;

    let local_capacity = local_capacity(premises.len(), left_term.arguments.len())?;
    let mut local = SparseEquality::new(local_capacity)?;
    add_equality_premises(event, premises, facts, &mut local)?;
    for (position, (&left_argument, &right_argument)) in left_term
        .arguments
        .iter()
        .zip(right_term.arguments.iter())
        .enumerate()
    {
        if !equality.equivalent(left_argument, right_argument) {
            return Err(CheckError::CongruenceArgumentNotEqual {
                event,
                position,
                left: left_argument,
                right: right_argument,
            });
        }
        if !local.equivalent(left_argument, right_argument) {
            return Err(CheckError::CongruencePremisesDoNotProveArgument {
                event,
                position,
                left: left_argument,
                right: right_argument,
            });
        }
    }
    Ok(CheckedFact::Equality(left, right))
}

#[allow(clippy::too_many_arguments)]
fn check_native_unit(
    problem: &SemanticProblem,
    semantic: &SemanticView,
    event: EventId,
    atom: AtomId,
    positive: bool,
    premises: &[EventId],
    facts: &[CheckedFact],
    event_count: usize,
    total_premises: &mut usize,
    budget: &mut WorkBudget,
) -> Result<CheckedFact, CheckError> {
    validate_event_atom(event, atom, problem.atoms.len())?;
    validate_premises(event, premises, event_count, total_premises, budget)?;
    let relation = literal_relation(problem, semantic.boolean_values, atom, positive)?;
    if premises.is_empty() {
        if !semantic.source_literals.contains(&(atom.index(), positive)) {
            return Err(CheckError::SourceLiteralNotAsserted {
                event,
                atom,
                positive,
            });
        }
    } else if !relation_proved(event, relation, premises, facts, semantic.boolean_values)? {
        return Err(CheckError::NativeUnitNotProved {
            event,
            atom,
            positive,
        });
    }
    Ok(relation.into())
}

#[allow(clippy::too_many_arguments)]
fn check_native_conflict(
    semantic: &SemanticView,
    event: EventId,
    premises: &[EventId],
    facts: &[CheckedFact],
    event_count: usize,
    total_premises: &mut usize,
    budget: &mut WorkBudget,
) -> Result<CheckedFact, CheckError> {
    validate_premises(event, premises, event_count, total_premises, budget)?;
    if premises.is_empty() {
        if semantic.source_conflict {
            return Ok(CheckedFact::Conflict);
        }
        return Err(CheckError::NativeConflictNotProved { event });
    }

    let mut local = SparseEquality::new(local_capacity(premises.len(), 0)?)?;
    add_equality_premises_allow_disequality(event, premises, facts, &mut local)?;
    let mut conflict = false;
    for &premise in premises {
        if let CheckedFact::Disequality(left, right) = facts[premise.index()] {
            conflict |= local.equivalent(left, right);
        }
    }
    if let Some((true_term, false_term)) = semantic.boolean_values {
        conflict |= local.equivalent(true_term, false_term);
    }
    if !conflict {
        return Err(CheckError::NativeConflictNotProved { event });
    }
    Ok(CheckedFact::Conflict)
}

fn relation_proved(
    event: EventId,
    relation: Relation,
    premises: &[EventId],
    facts: &[CheckedFact],
    boolean_values: Option<(TermId, TermId)>,
) -> Result<bool, CheckError> {
    let mut local = SparseEquality::new(local_capacity(premises.len(), 0)?)?;
    add_equality_premises_allow_disequality(event, premises, facts, &mut local)?;
    Ok(match relation {
        Relation::Equality(left, right) => local.equivalent(left, right),
        Relation::Disequality(left, right) => {
            let mut proved = false;
            for &premise in premises {
                if let CheckedFact::Disequality(witness_left, witness_right) =
                    facts[premise.index()]
                {
                    proved |=
                        relation_aligned(&mut local, left, right, witness_left, witness_right);
                }
            }
            if let Some((true_term, false_term)) = boolean_values {
                proved |= relation_aligned(&mut local, left, right, true_term, false_term);
            }
            proved
        }
    })
}

fn relation_aligned(
    equality: &mut SparseEquality,
    left: TermId,
    right: TermId,
    witness_left: TermId,
    witness_right: TermId,
) -> bool {
    (equality.equivalent(left, witness_left) && equality.equivalent(right, witness_right))
        || (equality.equivalent(left, witness_right) && equality.equivalent(right, witness_left))
}

fn add_equality_premises(
    event: EventId,
    premises: &[EventId],
    facts: &[CheckedFact],
    equality: &mut SparseEquality,
) -> Result<(), CheckError> {
    for &premise in premises {
        match facts[premise.index()] {
            CheckedFact::Equality(left, right) => equality.merge(left, right),
            CheckedFact::Disequality(_, _) | CheckedFact::Conflict | CheckedFact::UnsatRoot => {
                return Err(CheckError::InvalidPremiseKind { event, premise });
            }
        }
    }
    Ok(())
}

fn add_equality_premises_allow_disequality(
    event: EventId,
    premises: &[EventId],
    facts: &[CheckedFact],
    equality: &mut SparseEquality,
) -> Result<(), CheckError> {
    for &premise in premises {
        match facts[premise.index()] {
            CheckedFact::Equality(left, right) => equality.merge(left, right),
            CheckedFact::Disequality(_, _) => {}
            CheckedFact::Conflict | CheckedFact::UnsatRoot => {
                return Err(CheckError::InvalidPremiseKind { event, premise });
            }
        }
    }
    Ok(())
}

fn validate_premises(
    event: EventId,
    premises: &[EventId],
    event_count: usize,
    total_premises: &mut usize,
    budget: &mut WorkBudget,
) -> Result<(), CheckError> {
    if premises.len() > MAX_PREMISES_PER_EVENT {
        return Err(CheckError::TooManyPremises {
            event,
            count: premises.len(),
            maximum: MAX_PREMISES_PER_EVENT,
        });
    }
    *total_premises =
        total_premises
            .checked_add(premises.len())
            .ok_or(CheckError::TooManyTotalPremises {
                count: usize::MAX,
                maximum: MAX_TOTAL_PREMISES,
            })?;
    if *total_premises > MAX_TOTAL_PREMISES {
        return Err(CheckError::TooManyTotalPremises {
            count: *total_premises,
            maximum: MAX_TOTAL_PREMISES,
        });
    }
    budget.charge(premises.len(), Some(event))?;
    for &premise in premises {
        check_reference(event, premise, event_count)?;
    }
    Ok(())
}

fn check_reference(event: EventId, premise: EventId, event_count: usize) -> Result<(), CheckError> {
    if premise.index() >= event_count {
        return Err(CheckError::PremiseOutOfRange {
            event,
            premise,
            event_count,
        });
    }
    if premise.index() >= event.index() {
        return Err(CheckError::ForwardPremise { event, premise });
    }
    Ok(())
}

fn literal_relation(
    problem: &SemanticProblem,
    boolean_values: Option<(TermId, TermId)>,
    atom: AtomId,
    positive: bool,
) -> Result<Relation, CheckError> {
    Ok(match problem.atoms[atom.index()] {
        SemanticAtom::Equality(left, right) => {
            if positive {
                Relation::Equality(left, right)
            } else {
                Relation::Disequality(left, right)
            }
        }
        SemanticAtom::BoolTerm(term) => {
            let (true_term, false_term) = boolean_values.ok_or(CheckError::MissingBooleanValues)?;
            Relation::Equality(term, if positive { true_term } else { false_term })
        }
    })
}

fn validate_event_atom(event: EventId, atom: AtomId, atom_count: usize) -> Result<(), CheckError> {
    if atom.index() >= atom_count {
        return Err(CheckError::EventAtomOutOfRange {
            event,
            atom,
            atom_count,
        });
    }
    Ok(())
}

fn validate_event_term(event: EventId, term: TermId, term_count: usize) -> Result<(), CheckError> {
    if term.index() >= term_count {
        return Err(CheckError::EventTermOutOfRange {
            event,
            term,
            term_count,
        });
    }
    Ok(())
}

fn local_capacity(premises: usize, arity: usize) -> Result<usize, CheckError> {
    premises
        .checked_add(arity)
        .and_then(|count| count.checked_mul(2))
        .and_then(|count| count.checked_add(4))
        .ok_or(CheckError::AllocationFailed {
            context: "premise-local equality state",
        })
}

fn checked_event_id(index: usize) -> EventId {
    debug_assert!(index <= MAX_CHECK_EVENTS && MAX_CHECK_EVENTS <= u32::MAX as usize);
    EventId::new(index as u32)
}

fn checked_term_id(index: usize) -> TermId {
    debug_assert!(index <= MAX_CHECK_TERMS && MAX_CHECK_TERMS <= u32::MAX as usize);
    TermId::new(index as u32)
}

struct EqualityState {
    parent: Vec<u32>,
    size: Vec<u32>,
}

impl EqualityState {
    fn new(term_count: usize) -> Result<Self, CheckError> {
        let mut parent = Vec::new();
        parent
            .try_reserve_exact(term_count)
            .map_err(|_| CheckError::AllocationFailed {
                context: "equality parents",
            })?;
        for index in 0..term_count {
            parent.push(index as u32);
        }
        let mut size = Vec::new();
        size.try_reserve_exact(term_count)
            .map_err(|_| CheckError::AllocationFailed {
                context: "equality class sizes",
            })?;
        size.resize(term_count, 1u32);
        Ok(Self { parent, size })
    }

    fn root(&mut self, term: TermId) -> usize {
        let start = term.index();
        let mut root = start;
        while self.parent[root] as usize != root {
            root = self.parent[root] as usize;
        }
        let mut current = start;
        while self.parent[current] as usize != root {
            let next = self.parent[current] as usize;
            self.parent[current] = root as u32;
            current = next;
        }
        root
    }

    fn equivalent(&mut self, left: TermId, right: TermId) -> bool {
        self.root(left) == self.root(right)
    }

    fn merge(&mut self, left: TermId, right: TermId) -> Result<(), CheckError> {
        let mut left_root = self.root(left);
        let mut right_root = self.root(right);
        if left_root == right_root {
            return Ok(());
        }
        if self.size[left_root] < self.size[right_root] {
            std::mem::swap(&mut left_root, &mut right_root);
        }
        self.parent[right_root] = left_root as u32;
        self.size[left_root] = self.size[left_root]
            .checked_add(self.size[right_root])
            .ok_or(CheckError::WorkLimitExceeded {
                event: None,
                maximum: MAX_CHECK_WORK,
            })?;
        Ok(())
    }
}

struct SparseEquality {
    index: HashMap<TermId, usize>,
    parent: Vec<usize>,
    size: Vec<usize>,
}

impl SparseEquality {
    fn new(capacity: usize) -> Result<Self, CheckError> {
        let mut index = HashMap::new();
        index
            .try_reserve(capacity)
            .map_err(|_| CheckError::AllocationFailed {
                context: "premise-local term map",
            })?;
        let mut parent = Vec::new();
        parent
            .try_reserve(capacity)
            .map_err(|_| CheckError::AllocationFailed {
                context: "premise-local parents",
            })?;
        let mut size = Vec::new();
        size.try_reserve(capacity)
            .map_err(|_| CheckError::AllocationFailed {
                context: "premise-local class sizes",
            })?;
        Ok(Self {
            index,
            parent,
            size,
        })
    }

    fn term_index(&mut self, term: TermId) -> usize {
        if let Some(&index) = self.index.get(&term) {
            return index;
        }
        let index = self.parent.len();
        self.index.insert(term, index);
        self.parent.push(index);
        self.size.push(1);
        index
    }

    fn root_index(&mut self, start: usize) -> usize {
        let mut root = start;
        while self.parent[root] != root {
            root = self.parent[root];
        }
        let mut current = start;
        while self.parent[current] != root {
            let next = self.parent[current];
            self.parent[current] = root;
            current = next;
        }
        root
    }

    fn root(&mut self, term: TermId) -> usize {
        let index = self.term_index(term);
        self.root_index(index)
    }

    fn equivalent(&mut self, left: TermId, right: TermId) -> bool {
        self.root(left) == self.root(right)
    }

    fn merge(&mut self, left: TermId, right: TermId) {
        let mut left_root = self.root(left);
        let mut right_root = self.root(right);
        if left_root == right_root {
            return;
        }
        if self.size[left_root] < self.size[right_root] {
            std::mem::swap(&mut left_root, &mut right_root);
        }
        self.parent[right_root] = left_root;
        self.size[left_root] += self.size[right_root];
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::parse_problem;
    use super::super::semantic::project;
    use super::*;

    fn projection(source: &str) -> SemanticProblem {
        project(&parse_problem(source).unwrap()).unwrap()
    }

    fn event_ids(ids: &[u32]) -> Box<[EventId]> {
        ids.iter()
            .copied()
            .map(EventId::new)
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }

    fn atom_id(problem: &SemanticProblem, predicate: impl Fn(&SemanticAtom) -> bool) -> AtomId {
        let index = problem.atoms.iter().position(predicate).unwrap();
        AtomId::new(index as u32)
    }

    fn congruence_problem() -> SemanticProblem {
        projection(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U) (declare-const b U)\n\
             (declare-fun f (U) U)\n\
             (assert (= a b))\n\
             (assert (not (= (f a) (f b))))\n\
             (check-sat)",
        )
    }

    fn congruence_atoms(problem: &SemanticProblem) -> (AtomId, AtomId, TermId, TermId) {
        let base = atom_id(problem, |atom| match atom {
            SemanticAtom::Equality(left, right) => {
                problem.terms[left.index()].arguments.is_empty()
                    && problem.terms[right.index()].arguments.is_empty()
            }
            SemanticAtom::BoolTerm(_) => false,
        });
        let application = atom_id(problem, |atom| match atom {
            SemanticAtom::Equality(left, right) => {
                !problem.terms[left.index()].arguments.is_empty()
                    && !problem.terms[right.index()].arguments.is_empty()
            }
            SemanticAtom::BoolTerm(_) => false,
        });
        let SemanticAtom::Equality(left, right) = problem.atoms[application.index()] else {
            unreachable!();
        };
        (base, application, left, right)
    }

    fn valid_congruence_events(problem: &SemanticProblem) -> Vec<ProofEvent> {
        let (base, application, left, right) = congruence_atoms(problem);
        vec![
            ProofEvent::AssertEquality { atom: base },
            ProofEvent::AssertDisequality { atom: application },
            ProofEvent::CongruenceMerge {
                left,
                right,
                premises: event_ids(&[0]),
            },
            ProofEvent::NativeUnit {
                atom: application,
                positive: true,
                premises: event_ids(&[2]),
            },
            ProofEvent::NativeConflict {
                premises: event_ids(&[1, 3]),
            },
            ProofEvent::UnsatRoot {
                conflict: EventId::new(4),
            },
        ]
    }

    #[test]
    fn checks_native_unit_congruence_conflict_and_unsat_root() {
        let problem = congruence_problem();
        let events = valid_congruence_events(&problem);

        let receipt = check(&problem, &EventStream::new(events)).unwrap();

        assert_eq!(receipt.format, FABRIC_NATIVE_V1);
        assert_eq!(receipt.events_checked, 6);
        assert_eq!(receipt.unsat_root, EventId::new(5));
    }

    #[test]
    fn bool_term_units_use_explicit_semantic_value_terms() {
        let mut problem = projection(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U)\n\
             (declare-fun p (U) Bool)\n\
             (assert (p a))\n\
             (assert (not (p a)))\n\
             (check-sat)",
        );
        let atom = atom_id(&problem, |atom| matches!(atom, SemanticAtom::BoolTerm(_)));
        let events = vec![
            ProofEvent::NativeUnit {
                atom,
                positive: true,
                premises: event_ids(&[]),
            },
            ProofEvent::NativeUnit {
                atom,
                positive: false,
                premises: event_ids(&[]),
            },
            ProofEvent::NativeConflict {
                premises: event_ids(&[0, 1]),
            },
            ProofEvent::UnsatRoot {
                conflict: EventId::new(2),
            },
        ];
        assert!(check(&problem, &EventStream::new(events.clone())).is_ok());

        problem.boolean_values = None;
        assert_eq!(
            check(&problem, &EventStream::new(events)),
            Err(CheckError::MissingBooleanValues)
        );
    }

    #[test]
    fn rejects_tampered_source_polarity() {
        let problem = congruence_problem();
        let (base, application, _, _) = congruence_atoms(&problem);
        let events = vec![
            ProofEvent::AssertDisequality { atom: base },
            ProofEvent::AssertEquality { atom: application },
        ];

        assert!(matches!(
            check(&problem, &EventStream::new(events)),
            Err(CheckError::SourceLiteralNotAsserted {
                event: EventId(0),
                atom,
                positive: false,
            }) if atom == base
        ));
    }

    #[test]
    fn rejects_congruence_before_arguments_are_equal() {
        let problem = congruence_problem();
        let (_, _, left, right) = congruence_atoms(&problem);
        let events = vec![ProofEvent::CongruenceMerge {
            left,
            right,
            premises: event_ids(&[]),
        }];

        assert!(matches!(
            check(&problem, &EventStream::new(events)),
            Err(CheckError::CongruenceArgumentNotEqual {
                event: EventId(0),
                position: 0,
                ..
            })
        ));
    }

    #[test]
    fn rejects_congruence_with_unrelated_or_missing_premises() {
        let problem = congruence_problem();
        let (base, _, left, right) = congruence_atoms(&problem);
        let events = vec![
            ProofEvent::AssertEquality { atom: base },
            ProofEvent::CongruenceMerge {
                left,
                right,
                premises: event_ids(&[]),
            },
        ];

        assert!(matches!(
            check(&problem, &EventStream::new(events)),
            Err(CheckError::CongruencePremisesDoNotProveArgument {
                event: EventId(1),
                position: 0,
                ..
            })
        ));
    }

    #[test]
    fn rejects_different_function_congruence() {
        let problem = congruence_problem();
        let (_, _, application, _) = congruence_atoms(&problem);
        let base_term = problem
            .atoms
            .iter()
            .find_map(|atom| match atom {
                SemanticAtom::Equality(left, _)
                    if problem.terms[left.index()].arguments.is_empty() =>
                {
                    Some(*left)
                }
                _ => None,
            })
            .unwrap();
        let events = vec![ProofEvent::CongruenceMerge {
            left: application,
            right: base_term,
            premises: event_ids(&[]),
        }];

        assert!(matches!(
            check(&problem, &EventStream::new(events)),
            Err(CheckError::CongruenceFunctionMismatch {
                event: EventId(0),
                ..
            })
        ));
    }

    #[test]
    fn rejects_forward_and_out_of_range_premises() {
        let problem = congruence_problem();
        let (base, _, left, right) = congruence_atoms(&problem);
        let forward = vec![
            ProofEvent::AssertEquality { atom: base },
            ProofEvent::CongruenceMerge {
                left,
                right,
                premises: event_ids(&[2]),
            },
            ProofEvent::NativeConflict {
                premises: event_ids(&[]),
            },
        ];
        assert_eq!(
            check(&problem, &EventStream::new(forward)),
            Err(CheckError::ForwardPremise {
                event: EventId::new(1),
                premise: EventId::new(2),
            })
        );

        let out_of_range = vec![
            ProofEvent::AssertEquality { atom: base },
            ProofEvent::CongruenceMerge {
                left,
                right,
                premises: event_ids(&[99]),
            },
        ];
        assert_eq!(
            check(&problem, &EventStream::new(out_of_range)),
            Err(CheckError::PremiseOutOfRange {
                event: EventId::new(1),
                premise: EventId::new(99),
                event_count: 2,
            })
        );
    }

    #[test]
    fn rejects_unproved_conflict_and_non_conflict_unsat_root() {
        let problem = congruence_problem();
        let (base, application, _, _) = congruence_atoms(&problem);
        let unproved = vec![
            ProofEvent::AssertEquality { atom: base },
            ProofEvent::AssertDisequality { atom: application },
            ProofEvent::NativeConflict {
                premises: event_ids(&[0, 1]),
            },
        ];
        assert_eq!(
            check(&problem, &EventStream::new(unproved)),
            Err(CheckError::NativeConflictNotProved {
                event: EventId::new(2),
            })
        );

        let mut wrong_root = valid_congruence_events(&problem);
        wrong_root[5] = ProofEvent::UnsatRoot {
            conflict: EventId::new(3),
        };
        assert_eq!(
            check(&problem, &EventStream::new(wrong_root)),
            Err(CheckError::UnsatRootDoesNotCiteConflict {
                event: EventId::new(5),
                premise: EventId::new(3),
            })
        );
    }

    #[test]
    fn rejects_format_tampering() {
        let problem = congruence_problem();
        let stream =
            EventStream::with_format("fabric-native-v2", valid_congruence_events(&problem));
        assert_eq!(check(&problem, &stream), Err(CheckError::WrongFormat));
    }
}
