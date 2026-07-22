#![forbid(unsafe_code)]

//! Correctness-first reference search for the E2 Fabric state machine.
//!
//! This module is deliberately not connected to the command-line solver. It
//! establishes the executable result contract against which incremental
//! watches, partition actions, and conflict learning can be compared.

use super::bool_cnf::{self, LoweringCaps, LoweringError, NativeFormula};
use super::congruence::{
    Abstention as CongruenceAbstention, ApplyOutcome, CongruenceError, CongruenceLimits,
    CongruenceSnapshot, RollbackCongruence,
};
use super::cover::{
    self, CoverAbstention, CoverBuild, CoverCaps, CoverCheck, CoverError, CoverProof, CoverReceipt,
};
use super::model::{
    self, CanonicalModel, InvalidModel, ModelCaps, ModelError, ModelLimit, ModelValidation,
};
use super::native_clause::{AtomId, Lit, Truth};
use super::partition::{ReasonId, Relation, TermId};
use super::semantic::{SemanticAtom, SemanticExpr, SemanticProblem};
use super::trail::{EnqueueOutcome, Reason, TheoryReasonId, Trail, TrailError};
use std::error::Error;
use std::fmt;

const ROOT_BOOLEAN_SEPARATION_REASON: ReasonId = ReasonId::MIN;
const DOMAIN_REASON_TAG: u64 = 1_u64 << 63;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EngineCaps {
    pub(crate) lowering: LoweringCaps,
    pub(crate) congruence: CongruenceLimits,
    pub(crate) model: ModelCaps,
    pub(crate) cover: CoverCaps,
    pub(crate) max_search_nodes: usize,
    pub(crate) max_decisions: usize,
    pub(crate) max_propagations: usize,
    pub(crate) max_boolean_domain_updates: usize,
}

impl Default for EngineCaps {
    fn default() -> Self {
        Self {
            lowering: LoweringCaps::new(2_000_000, 5_000_000, 20_000_000),
            congruence: CongruenceLimits::default(),
            model: ModelCaps::default(),
            cover: CoverCaps::default(),
            max_search_nodes: 1_000_000,
            max_decisions: 1_000_000,
            max_propagations: 10_000_000,
            max_boolean_domain_updates: 1_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct EngineStats {
    pub(crate) search_nodes: usize,
    pub(crate) decisions: usize,
    pub(crate) propagations: usize,
    pub(crate) boolean_domain_updates: usize,
    pub(crate) closed_branches: usize,
    pub(crate) maximum_depth: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EngineResource {
    SearchNodes,
    Decisions,
    Propagations,
    BooleanDomainUpdates,
}

impl fmt::Display for EngineResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::SearchNodes => "search nodes",
            Self::Decisions => "decisions",
            Self::Propagations => "propagations",
            Self::BooleanDomainUpdates => "Boolean-domain updates",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EngineAbstention {
    UnsupportedFragments {
        count: usize,
    },
    CapExceeded {
        resource: EngineResource,
        attempted: usize,
        limit: usize,
    },
    Congruence(CongruenceAbstention),
    Model(ModelLimit),
    Cover(CoverAbstention),
}

impl fmt::Display for EngineAbstention {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFragments { count } => {
                write!(
                    output,
                    "semantic projection contains {count} unsupported fragments"
                )
            }
            Self::CapExceeded {
                resource,
                attempted,
                limit,
            } => write!(
                output,
                "Fabric reference {resource} cap exceeded: attempted {attempted}, limit {limit}"
            ),
            Self::Congruence(reason) => reason.fmt(output),
            Self::Model(limit) => write!(
                output,
                "independent model checker {:?} cap exceeded: observed {}, limit {}",
                limit.kind, limit.observed, limit.maximum
            ),
            Self::Cover(reason) => write!(output, "independent UNSAT cover abstained: {reason:?}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReferenceOutcome {
    Sat {
        source_atom_values: Box<[bool]>,
        model: CanonicalModel,
        stats: EngineStats,
    },
    Unsat {
        cover: CoverProof,
        receipt: CoverReceipt,
        stats: EngineStats,
    },
    Abstained {
        reason: EngineAbstention,
        stats: EngineStats,
    },
}

impl ReferenceOutcome {
    pub(crate) const fn stats(&self) -> EngineStats {
        match self {
            Self::Sat { stats, .. } | Self::Unsat { stats, .. } | Self::Abstained { stats, .. } => {
                *stats
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum EngineError {
    Lowering(LoweringError),
    Congruence(CongruenceError),
    Model(ModelError),
    Cover(CoverError),
    Trail(TrailError),
    FormulaAtomOutOfRange { atom: AtomId, atom_count: usize },
    ClauseIndexOverflow { index: usize },
    InvalidBooleanUniverse,
    IncompleteBooleanTerm { atom: AtomId, term: TermId },
    CandidateDoesNotSatisfySource,
    IndependentModelRejected(InvalidModel),
    Invariant(&'static str),
}

impl fmt::Display for EngineError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lowering(error) => error.fmt(output),
            Self::Congruence(error) => error.fmt(output),
            Self::Model(error) => error.fmt(output),
            Self::Cover(error) => error.fmt(output),
            Self::Trail(error) => error.fmt(output),
            Self::FormulaAtomOutOfRange { atom, atom_count } => write!(
                output,
                "formula atom {} is outside 0..{atom_count}",
                atom.index()
            ),
            Self::ClauseIndexOverflow { index } => {
                write!(output, "clause index {index} does not fit a trail reason")
            }
            Self::InvalidBooleanUniverse => {
                output.write_str("semantic Boolean universe is missing or ill-sorted")
            }
            Self::IncompleteBooleanTerm { atom, term } => write!(
                output,
                "Boolean atom {} for term {term} remained incomplete at a SAT leaf",
                atom.index()
            ),
            Self::CandidateDoesNotSatisfySource => {
                output.write_str("completed Fabric candidate does not satisfy the source formula")
            }
            Self::IndependentModelRejected(reason) => write!(
                output,
                "independent model checker rejected a Fabric SAT candidate: {reason:?}"
            ),
            Self::Invariant(message) => output.write_str(message),
        }
    }
}

impl Error for EngineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Lowering(error) => Some(error),
            Self::Congruence(error) => Some(error),
            Self::Model(error) => Some(error),
            Self::Cover(error) => Some(error),
            Self::Trail(error) => Some(error),
            _ => None,
        }
    }
}

impl From<LoweringError> for EngineError {
    fn from(error: LoweringError) -> Self {
        Self::Lowering(error)
    }
}

impl From<CongruenceError> for EngineError {
    fn from(error: CongruenceError) -> Self {
        Self::Congruence(error)
    }
}

impl From<ModelError> for EngineError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<CoverError> for EngineError {
    fn from(error: CoverError) -> Self {
        Self::Cover(error)
    }
}

impl From<TrailError> for EngineError {
    fn from(error: TrailError) -> Self {
        Self::Trail(error)
    }
}

enum SearchOutcome {
    Sat {
        source_atom_values: Box<[bool]>,
        model: CanonicalModel,
    },
    Unsat,
    Abstained(EngineAbstention),
}

enum ApplyLiteralOutcome {
    Unchanged,
    Changed,
    Conflict,
    Abstained(EngineAbstention),
}

enum PropagationOutcome {
    Fixpoint,
    Conflict,
    Abstained(EngineAbstention),
}

enum DomainOutcome {
    Unchanged,
    Changed,
    Conflict,
    Abstained(EngineAbstention),
}

struct SearchState<'problem> {
    problem: &'problem SemanticProblem,
    formula: NativeFormula,
    congruence: RollbackCongruence<'problem>,
    trail: Trail,
    caps: EngineCaps,
    stats: EngineStats,
}

pub(crate) fn solve_reference(
    problem: &SemanticProblem,
    caps: EngineCaps,
) -> Result<ReferenceOutcome, EngineError> {
    if problem.stats.unsupported_fragments != 0 {
        return Ok(ReferenceOutcome::Abstained {
            reason: EngineAbstention::UnsupportedFragments {
                count: problem.stats.unsupported_fragments,
            },
            stats: EngineStats::default(),
        });
    }

    let formula = bool_cnf::lower(problem, caps.lowering)?;
    let congruence = match RollbackCongruence::with_limits(&problem.terms, caps.congruence) {
        Ok(engine) => engine,
        Err(CongruenceError::ConstructionAbstained(reason)) => {
            return Ok(ReferenceOutcome::Abstained {
                reason: EngineAbstention::Congruence(reason),
                stats: EngineStats::default(),
            });
        }
        Err(error) => return Err(error.into()),
    };
    let mut state = SearchState {
        problem,
        trail: Trail::new(formula.atom_count),
        formula,
        congruence,
        caps,
        stats: EngineStats::default(),
    };

    if problem.stats.contradiction {
        state.stats.closed_branches = 1;
        return certify_unsat(problem, caps.cover, state.stats);
    }
    if let Some((true_term, false_term)) = problem.boolean_values {
        match state.congruence.assert_disequality(
            true_term,
            false_term,
            ROOT_BOOLEAN_SEPARATION_REASON,
        )? {
            ApplyOutcome::Applied(_) => {}
            ApplyOutcome::Conflict(_) => {
                state.stats.closed_branches = 1;
                return certify_unsat(problem, caps.cover, state.stats);
            }
            ApplyOutcome::Abstained(reason) => {
                return Ok(ReferenceOutcome::Abstained {
                    reason: EngineAbstention::Congruence(reason),
                    stats: state.stats,
                });
            }
        }
    } else if problem
        .atoms
        .iter()
        .any(|atom| matches!(atom, SemanticAtom::BoolTerm(_)))
    {
        return Err(EngineError::InvalidBooleanUniverse);
    }

    let outcome = state.search()?;
    let stats = state.stats;
    match outcome {
        SearchOutcome::Sat {
            source_atom_values,
            model,
        } => Ok(ReferenceOutcome::Sat {
            source_atom_values,
            model,
            stats,
        }),
        SearchOutcome::Unsat => certify_unsat(problem, caps.cover, stats),
        SearchOutcome::Abstained(reason) => Ok(ReferenceOutcome::Abstained { reason, stats }),
    }
}

fn certify_unsat(
    problem: &SemanticProblem,
    caps: CoverCaps,
    stats: EngineStats,
) -> Result<ReferenceOutcome, EngineError> {
    let proof = match cover::build_complete_cover(problem.atoms.len(), caps) {
        CoverBuild::Built(proof) => proof,
        CoverBuild::Abstained(limit) => {
            return Ok(ReferenceOutcome::Abstained {
                reason: EngineAbstention::Cover(CoverAbstention::Cover(limit)),
                stats,
            });
        }
    };
    match cover::check_cover(problem, &proof, caps)? {
        CoverCheck::Valid(receipt) => Ok(ReferenceOutcome::Unsat {
            cover: proof,
            receipt,
            stats,
        }),
        CoverCheck::Abstained(reason) => Ok(ReferenceOutcome::Abstained {
            reason: EngineAbstention::Cover(reason),
            stats,
        }),
    }
}

impl SearchState<'_> {
    fn search(&mut self) -> Result<SearchOutcome, EngineError> {
        if let Some(reason) = bump(
            EngineResource::SearchNodes,
            &mut self.stats.search_nodes,
            self.caps.max_search_nodes,
        ) {
            return Ok(SearchOutcome::Abstained(reason));
        }
        self.stats.maximum_depth = self.stats.maximum_depth.max(self.trail.current_level());

        match self.propagate()? {
            PropagationOutcome::Conflict => {
                self.stats.closed_branches += 1;
                return Ok(SearchOutcome::Unsat);
            }
            PropagationOutcome::Abstained(reason) => {
                return Ok(SearchOutcome::Abstained(reason));
            }
            PropagationOutcome::Fixpoint => {}
        }

        if let Some(literal) = self.choose_clause_literal()? {
            return self.branch(literal);
        }
        if let Some(literal) = self.choose_incomplete_boolean_term()? {
            return self.branch(literal);
        }

        let source_atom_values = self.complete_source_values()?;
        if !self.source_formula_holds(&source_atom_values)? {
            return Err(EngineError::CandidateDoesNotSatisfySource);
        }
        let model =
            match model::validate_complete(self.problem, &source_atom_values, self.caps.model)? {
                ModelValidation::Valid(model) => model,
                ModelValidation::Invalid(reason) => {
                    return Err(EngineError::IndependentModelRejected(reason));
                }
                ModelValidation::Abstained(limit) => {
                    return Ok(SearchOutcome::Abstained(EngineAbstention::Model(limit)));
                }
            };
        Ok(SearchOutcome::Sat {
            source_atom_values,
            model,
        })
    }

    fn branch(&mut self, positive: Lit) -> Result<SearchOutcome, EngineError> {
        if let Some(reason) = bump(
            EngineResource::Decisions,
            &mut self.stats.decisions,
            self.caps.max_decisions,
        ) {
            return Ok(SearchOutcome::Abstained(reason));
        }

        for literal in [positive, positive.negate()] {
            let snapshot = self.congruence.snapshot();
            let parent_level = self.trail.current_level();
            self.trail.new_decision_level()?;
            let result = match self.apply_literal(literal, Reason::Decision)? {
                ApplyLiteralOutcome::Conflict => {
                    self.stats.closed_branches += 1;
                    SearchOutcome::Unsat
                }
                ApplyLiteralOutcome::Abstained(reason) => SearchOutcome::Abstained(reason),
                ApplyLiteralOutcome::Changed | ApplyLiteralOutcome::Unchanged => self.search()?,
            };
            self.restore(snapshot, parent_level)?;

            match result {
                SearchOutcome::Sat {
                    source_atom_values,
                    model,
                } => {
                    return Ok(SearchOutcome::Sat {
                        source_atom_values,
                        model,
                    });
                }
                SearchOutcome::Abstained(reason) => {
                    return Ok(SearchOutcome::Abstained(reason));
                }
                SearchOutcome::Unsat => {}
            }
        }
        Ok(SearchOutcome::Unsat)
    }

    fn restore(
        &mut self,
        snapshot: CongruenceSnapshot,
        parent_level: u32,
    ) -> Result<(), EngineError> {
        self.congruence.rollback(snapshot)?;
        self.trail.backtrack(parent_level)?;
        Ok(())
    }

    fn propagate(&mut self) -> Result<PropagationOutcome, EngineError> {
        loop {
            match self.propagate_boolean_domain()? {
                DomainOutcome::Conflict => return Ok(PropagationOutcome::Conflict),
                DomainOutcome::Abstained(reason) => {
                    return Ok(PropagationOutcome::Abstained(reason));
                }
                DomainOutcome::Changed => continue,
                DomainOutcome::Unchanged => {}
            }

            let mut unit = None;
            for clause_index in 0..self.formula.clauses.len() {
                let clause = &self.formula.clauses[clause_index];
                let mut unknown = None;
                let mut unknown_count = 0usize;
                let mut satisfied = false;
                for &literal in clause.iter() {
                    match self.literal_truth(literal)? {
                        Truth::True => {
                            satisfied = true;
                            break;
                        }
                        Truth::Unknown => {
                            unknown = Some(literal);
                            unknown_count += 1;
                        }
                        Truth::False => {}
                    }
                }
                if satisfied {
                    continue;
                }
                match (unknown_count, unknown) {
                    (0, _) => return Ok(PropagationOutcome::Conflict),
                    (1, Some(literal)) => {
                        unit = Some((clause_index, literal));
                        break;
                    }
                    _ => {}
                }
            }

            let Some((clause_index, literal)) = unit else {
                return Ok(PropagationOutcome::Fixpoint);
            };
            if let Some(reason) = bump(
                EngineResource::Propagations,
                &mut self.stats.propagations,
                self.caps.max_propagations,
            ) {
                return Ok(PropagationOutcome::Abstained(reason));
            }
            let raw_reason =
                u32::try_from(clause_index).map_err(|_| EngineError::ClauseIndexOverflow {
                    index: clause_index,
                })?;
            match self.apply_literal(literal, Reason::Theory(TheoryReasonId::new(raw_reason)))? {
                ApplyLiteralOutcome::Changed | ApplyLiteralOutcome::Unchanged => {}
                ApplyLiteralOutcome::Conflict => return Ok(PropagationOutcome::Conflict),
                ApplyLiteralOutcome::Abstained(reason) => {
                    return Ok(PropagationOutcome::Abstained(reason));
                }
            }
        }
    }

    fn propagate_boolean_domain(&mut self) -> Result<DomainOutcome, EngineError> {
        let Some((true_term, false_term)) = self.problem.boolean_values else {
            return Ok(DomainOutcome::Unchanged);
        };
        let bool_sort = self
            .problem
            .terms
            .get(true_term.index())
            .ok_or(EngineError::InvalidBooleanUniverse)?
            .sort;
        if self
            .problem
            .terms
            .get(false_term.index())
            .is_none_or(|term| term.sort != bool_sort)
        {
            return Err(EngineError::InvalidBooleanUniverse);
        }

        for (index, term) in self.problem.terms.iter().enumerate() {
            if term.sort != bool_sort {
                continue;
            }
            let term_id = TermId::try_from(index)
                .map_err(|_| EngineError::Invariant("semantic term does not fit TermId"))?;
            let to_true = self.congruence.relation(term_id, true_term)?;
            let to_false = self.congruence.relation(term_id, false_term)?;
            let forced = match (to_true, to_false) {
                (Relation::Disequal, Relation::Disequal) => return Ok(DomainOutcome::Conflict),
                (Relation::Disequal, Relation::Unknown) => Some(false_term),
                (Relation::Unknown, Relation::Disequal) => Some(true_term),
                _ => None,
            };
            let Some(value_term) = forced else {
                continue;
            };
            if let Some(reason) = bump(
                EngineResource::BooleanDomainUpdates,
                &mut self.stats.boolean_domain_updates,
                self.caps.max_boolean_domain_updates,
            ) {
                return Ok(DomainOutcome::Abstained(reason));
            }
            let reason = domain_reason(term_id, value_term == true_term);
            return match self
                .congruence
                .assert_equality(term_id, value_term, reason)?
            {
                ApplyOutcome::Applied(stats) => {
                    if stats.explicit_update || stats.congruence_merges != 0 {
                        Ok(DomainOutcome::Changed)
                    } else {
                        Err(EngineError::Invariant(
                            "forced Boolean-domain equality made no progress",
                        ))
                    }
                }
                ApplyOutcome::Conflict(_) => Ok(DomainOutcome::Conflict),
                ApplyOutcome::Abstained(reason) => Ok(DomainOutcome::Abstained(
                    EngineAbstention::Congruence(reason),
                )),
            };
        }
        Ok(DomainOutcome::Unchanged)
    }

    fn choose_clause_literal(&self) -> Result<Option<Lit>, EngineError> {
        let mut selected = None;
        for clause in self.formula.clauses.iter() {
            let mut satisfied = false;
            for &literal in clause.iter() {
                if self.literal_truth(literal)? == Truth::True {
                    satisfied = true;
                    break;
                }
            }
            if satisfied {
                continue;
            }
            for &literal in clause.iter() {
                if self.literal_truth(literal)? == Truth::Unknown
                    && selected.is_none_or(|current: Lit| literal.atom() < current.atom())
                {
                    selected = Some(Lit::positive(literal.atom()));
                }
            }
        }
        Ok(selected)
    }

    fn choose_incomplete_boolean_term(&self) -> Result<Option<Lit>, EngineError> {
        for (index, atom) in self.problem.atoms.iter().enumerate() {
            if !matches!(atom, SemanticAtom::BoolTerm(_)) {
                continue;
            }
            let atom_id = AtomId::new(index as u32);
            let literal = Lit::positive(atom_id);
            if self.literal_truth(literal)? == Truth::Unknown {
                return Ok(Some(literal));
            }
        }
        Ok(None)
    }

    fn apply_literal(
        &mut self,
        literal: Lit,
        trail_reason: Reason,
    ) -> Result<ApplyLiteralOutcome, EngineError> {
        match self.literal_truth(literal)? {
            Truth::True => return Ok(ApplyLiteralOutcome::Unchanged),
            Truth::False => return Ok(ApplyLiteralOutcome::Conflict),
            Truth::Unknown => {}
        }

        let atom_index = literal.atom().index();
        if atom_index >= self.formula.atom_count {
            return Err(EngineError::FormulaAtomOutOfRange {
                atom: literal.atom(),
                atom_count: self.formula.atom_count,
            });
        }
        if atom_index >= self.formula.source_atom_count {
            return Ok(match self.trail.enqueue(literal, trail_reason)? {
                EnqueueOutcome::Assigned => ApplyLiteralOutcome::Changed,
                EnqueueOutcome::AlreadyAssigned => ApplyLiteralOutcome::Unchanged,
                EnqueueOutcome::Conflict { .. } => ApplyLiteralOutcome::Conflict,
            });
        }

        let reason = literal_reason(literal);
        let decision = match self.problem.atoms.get(atom_index) {
            Some(SemanticAtom::Equality(left, right)) => {
                if literal.is_positive() {
                    (*left, *right, true)
                } else {
                    (*left, *right, false)
                }
            }
            Some(SemanticAtom::BoolTerm(term)) => {
                let (true_term, false_term) = self
                    .problem
                    .boolean_values
                    .ok_or(EngineError::InvalidBooleanUniverse)?;
                (
                    *term,
                    if literal.is_positive() {
                        true_term
                    } else {
                        false_term
                    },
                    true,
                )
            }
            None => {
                return Err(EngineError::FormulaAtomOutOfRange {
                    atom: literal.atom(),
                    atom_count: self.problem.atoms.len(),
                });
            }
        };

        let outcome = if decision.2 {
            self.congruence
                .assert_equality(decision.0, decision.1, reason)?
        } else {
            self.congruence
                .assert_disequality(decision.0, decision.1, reason)?
        };
        Ok(match outcome {
            ApplyOutcome::Applied(stats) => {
                if stats.explicit_update || stats.congruence_merges != 0 {
                    ApplyLiteralOutcome::Changed
                } else {
                    ApplyLiteralOutcome::Unchanged
                }
            }
            ApplyOutcome::Conflict(_) => ApplyLiteralOutcome::Conflict,
            ApplyOutcome::Abstained(reason) => {
                ApplyLiteralOutcome::Abstained(EngineAbstention::Congruence(reason))
            }
        })
    }

    fn literal_truth(&self, literal: Lit) -> Result<Truth, EngineError> {
        let atom_index = literal.atom().index();
        let positive_truth = if atom_index < self.formula.source_atom_count {
            match self.problem.atoms.get(atom_index) {
                Some(SemanticAtom::Equality(left, right)) => {
                    relation_truth(self.congruence.relation(*left, *right)?)
                }
                Some(SemanticAtom::BoolTerm(term)) => self.boolean_term_truth(*term)?,
                None => {
                    return Err(EngineError::FormulaAtomOutOfRange {
                        atom: literal.atom(),
                        atom_count: self.problem.atoms.len(),
                    });
                }
            }
        } else if atom_index < self.formula.atom_count {
            match self.trail.assignment(literal.atom())? {
                Some((assigned, _, _)) if assigned.is_positive() => Truth::True,
                Some(_) => Truth::False,
                None => Truth::Unknown,
            }
        } else {
            return Err(EngineError::FormulaAtomOutOfRange {
                atom: literal.atom(),
                atom_count: self.formula.atom_count,
            });
        };
        Ok(if literal.is_positive() {
            positive_truth
        } else {
            negate_truth(positive_truth)
        })
    }

    fn boolean_term_truth(&self, term: TermId) -> Result<Truth, EngineError> {
        let (true_term, false_term) = self
            .problem
            .boolean_values
            .ok_or(EngineError::InvalidBooleanUniverse)?;
        let to_true = self.congruence.relation(term, true_term)?;
        let to_false = self.congruence.relation(term, false_term)?;
        Ok(match (to_true, to_false) {
            (Relation::Equal, _) | (_, Relation::Disequal) => Truth::True,
            (_, Relation::Equal) | (Relation::Disequal, _) => Truth::False,
            (Relation::Unknown, Relation::Unknown) => Truth::Unknown,
        })
    }

    fn complete_source_values(&self) -> Result<Box<[bool]>, EngineError> {
        self.problem
            .atoms
            .iter()
            .enumerate()
            .map(|(index, atom)| {
                let value = match atom {
                    SemanticAtom::Equality(left, right) => {
                        matches!(self.congruence.relation(*left, *right)?, Relation::Equal)
                    }
                    SemanticAtom::BoolTerm(term) => match self.boolean_term_truth(*term)? {
                        Truth::True => true,
                        Truth::False => false,
                        Truth::Unknown => {
                            return Err(EngineError::IncompleteBooleanTerm {
                                atom: AtomId::new(index as u32),
                                term: *term,
                            });
                        }
                    },
                };
                Ok(value)
            })
            .collect::<Result<Vec<_>, EngineError>>()
            .map(Vec::into_boxed_slice)
    }

    fn source_formula_holds(&self, values: &[bool]) -> Result<bool, EngineError> {
        if values.len() != self.problem.atoms.len() {
            return Ok(false);
        }
        if !self
            .problem
            .root_literals
            .iter()
            .all(|literal| values[literal.atom.index()] == literal.positive)
        {
            return Ok(false);
        }
        for assertion in self.problem.assertions.iter() {
            if !evaluate_expression(assertion, values)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn bump(resource: EngineResource, counter: &mut usize, limit: usize) -> Option<EngineAbstention> {
    let attempted = counter.checked_add(1).unwrap_or(usize::MAX);
    if attempted > limit {
        return Some(EngineAbstention::CapExceeded {
            resource,
            attempted,
            limit,
        });
    }
    *counter = attempted;
    None
}

fn relation_truth(relation: Relation) -> Truth {
    match relation {
        Relation::Equal => Truth::True,
        Relation::Disequal => Truth::False,
        Relation::Unknown => Truth::Unknown,
    }
}

fn negate_truth(value: Truth) -> Truth {
    match value {
        Truth::True => Truth::False,
        Truth::False => Truth::True,
        Truth::Unknown => Truth::Unknown,
    }
}

fn literal_reason(literal: Lit) -> ReasonId {
    let raw = 1 + (literal.atom().index() as u64) * 2 + u64::from(!literal.is_positive());
    ReasonId::new(raw)
}

fn domain_reason(term: TermId, true_value: bool) -> ReasonId {
    let raw = DOMAIN_REASON_TAG | ((term.raw() as u64) << 1) | u64::from(!true_value);
    ReasonId::new(raw)
}

fn evaluate_expression(expression: &SemanticExpr, values: &[bool]) -> Result<bool, EngineError> {
    Ok(match expression {
        SemanticExpr::Const(value) => *value,
        SemanticExpr::Atom(atom) => {
            *values
                .get(atom.index())
                .ok_or(EngineError::FormulaAtomOutOfRange {
                    atom: *atom,
                    atom_count: values.len(),
                })?
        }
        SemanticExpr::Not(child) => !evaluate_expression(child, values)?,
        SemanticExpr::And(children) => {
            let mut value = true;
            for child in children.iter() {
                value &= evaluate_expression(child, values)?;
            }
            value
        }
        SemanticExpr::Or(children) => {
            let mut value = false;
            for child in children.iter() {
                value |= evaluate_expression(child, values)?;
            }
            value
        }
        SemanticExpr::Iff(children) => {
            let Some(first) = children.first() else {
                return Ok(true);
            };
            let expected = evaluate_expression(first, values)?;
            let mut value = true;
            for child in &children[1..] {
                value &= evaluate_expression(child, values)? == expected;
            }
            value
        }
        SemanticExpr::Ite(condition, then_expression, else_expression) => {
            if evaluate_expression(condition, values)? {
                evaluate_expression(then_expression, values)?
            } else {
                evaluate_expression(else_expression, values)?
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::super::super::parse_problem;
    use super::super::semantic::project;
    use super::*;

    fn solve(source: &str) -> ReferenceOutcome {
        let problem = project(&parse_problem(source).unwrap()).unwrap();
        solve_reference(&problem, EngineCaps::default()).unwrap()
    }

    fn is_sat(outcome: &ReferenceOutcome) -> bool {
        matches!(outcome, ReferenceOutcome::Sat { .. })
    }

    #[test]
    fn congruence_conflict_closes_at_root() {
        let outcome = solve(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-fun a () U)\n\
             (declare-fun b () U)\n\
             (declare-fun f (U) U)\n\
             (assert (= a b))\n\
             (assert (distinct (f a) (f b)))\n\
             (check-sat)",
        );
        assert!(matches!(outcome, ReferenceOutcome::Unsat { .. }));
    }

    #[test]
    fn disjunctive_equality_search_returns_a_checked_candidate() {
        let outcome = solve(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-fun a () U)\n\
             (declare-fun b () U)\n\
             (declare-fun c () U)\n\
             (assert (or (= a b) (= a c)))\n\
             (assert (distinct b c))\n\
             (check-sat)",
        );
        assert!(is_sat(&outcome));
        assert!(outcome.stats().decisions >= 1);
    }

    #[test]
    fn exact_boolean_domain_drives_function_congruence() {
        let outcome = solve(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-fun p () Bool)\n\
             (declare-fun g (Bool) U)\n\
             (assert (distinct p true))\n\
             (assert (distinct (g p) (g false)))\n\
             (check-sat)",
        );
        assert!(matches!(outcome, ReferenceOutcome::Unsat { .. }));
        assert!(outcome.stats().propagations >= 1);
    }

    #[test]
    fn all_three_term_literal_cubes_match_equivalence_consistency() {
        let pairs = [("a", "b"), ("a", "c"), ("b", "c")];
        for encoded in 0usize..3usize.pow(3) {
            let mut value = encoded;
            let mut assertions = String::new();
            let mut parent = [0usize, 1, 2];
            let mut negatives = Vec::new();
            for (left, right) in pairs {
                let state = value % 3;
                value /= 3;
                let left_index = match left {
                    "a" => 0,
                    "b" => 1,
                    _ => 2,
                };
                let right_index = match right {
                    "a" => 0,
                    "b" => 1,
                    _ => 2,
                };
                match state {
                    1 => {
                        assertions.push_str(&format!("(assert (= {left} {right}))\n"));
                        let old = parent[right_index];
                        let new = parent[left_index];
                        for entry in &mut parent {
                            if *entry == old {
                                *entry = new;
                            }
                        }
                    }
                    2 => {
                        assertions.push_str(&format!("(assert (distinct {left} {right}))\n"));
                        negatives.push((left_index, right_index));
                    }
                    _ => {}
                }
            }
            let expected_sat = negatives
                .iter()
                .all(|&(left, right)| parent[left] != parent[right]);
            let source = format!(
                "(set-logic QF_UF)\n\
                 (declare-sort U 0)\n\
                 (declare-fun a () U)\n\
                 (declare-fun b () U)\n\
                 (declare-fun c () U)\n\
                 {assertions}(check-sat)"
            );
            let outcome = solve(&source);
            assert_eq!(is_sat(&outcome), expected_sat, "cube {encoded}");
        }
    }

    #[test]
    fn all_two_clause_three_equality_formulas_match_five_partitions() {
        const PARTITIONS: [[bool; 3]; 5] = [
            [false, false, false],
            [true, false, false],
            [false, true, false],
            [false, false, true],
            [true, true, true],
        ];
        let atoms = ["(= a b)", "(= a c)", "(= b c)"];

        let render_clause = |mut encoded: usize| {
            let mut literals = Vec::new();
            for atom in atoms {
                match encoded % 3 {
                    1 => literals.push(atom.to_owned()),
                    2 => literals.push(format!("(not {atom})")),
                    _ => {}
                }
                encoded /= 3;
            }
            format!("(or {})", literals.join(" "))
        };
        let clause_holds = |mut encoded: usize, partition: [bool; 3]| {
            let mut result = false;
            for atom_value in partition {
                match encoded % 3 {
                    1 => result |= atom_value,
                    2 => result |= !atom_value,
                    _ => {}
                }
                encoded /= 3;
            }
            result
        };

        for first in 1usize..27 {
            for second in 1usize..27 {
                let expected_sat = PARTITIONS.iter().copied().any(|partition| {
                    clause_holds(first, partition) && clause_holds(second, partition)
                });
                let source = format!(
                    "(set-logic QF_UF)\n\
                     (declare-sort U 0)\n\
                     (declare-fun a () U)\n\
                     (declare-fun b () U)\n\
                     (declare-fun c () U)\n\
                     (assert {})\n\
                     (assert {})\n\
                     (check-sat)",
                    render_clause(first),
                    render_clause(second),
                );
                let outcome = solve(&source);
                assert_eq!(
                    is_sat(&outcome),
                    expected_sat,
                    "clause pair ({first}, {second})"
                );
            }
        }
    }

    #[test]
    fn semantic_work_caps_abstain_without_promoting_a_result() {
        let problem = project(
            &parse_problem(
                "(set-logic QF_UF)\n\
                 (declare-sort U 0)\n\
                 (declare-fun a () U)\n\
                 (declare-fun b () U)\n\
                 (assert (or (= a b) (distinct a b)))\n\
                 (check-sat)",
            )
            .unwrap(),
        )
        .unwrap();
        let mut caps = EngineCaps::default();
        caps.max_search_nodes = 0;
        let outcome = solve_reference(&problem, caps).unwrap();
        assert!(matches!(
            outcome,
            ReferenceOutcome::Abstained {
                reason: EngineAbstention::CapExceeded {
                    resource: EngineResource::SearchNodes,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn unchecked_large_unsat_abstains_when_reference_cover_is_capped() {
        let mut source = String::from("(set-logic QF_UF)\n(declare-sort U 0)\n");
        for index in 0..20 {
            source.push_str(&format!("(declare-fun a{index} () U)\n"));
        }
        for index in 1..20 {
            source.push_str(&format!("(assert (= a0 a{index}))\n"));
        }
        source.push_str("(assert (distinct a0 a1))\n(check-sat)\n");
        let problem = project(&parse_problem(&source).unwrap()).unwrap();

        let outcome = solve_reference(&problem, EngineCaps::default()).unwrap();

        assert!(matches!(
            outcome,
            ReferenceOutcome::Abstained {
                reason: EngineAbstention::Cover(CoverAbstention::Cover(_)),
                ..
            }
        ));
    }

    #[test]
    fn repeated_runs_are_deterministic_except_for_no_timing_fields() {
        let source = "(set-logic QF_UF)\n\
                      (declare-sort U 0)\n\
                      (declare-fun a () U)\n\
                      (declare-fun b () U)\n\
                      (assert (or (= a b) (distinct a b)))\n\
                      (check-sat)";
        assert_eq!(solve(source), solve(source));
    }
}
