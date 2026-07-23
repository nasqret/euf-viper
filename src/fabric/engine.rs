#![forbid(unsafe_code)]

//! Correctness-first reference search for the E2 Fabric state machine.
//!
//! This module is deliberately not connected to the command-line solver. It
//! establishes the executable result contract against which incremental
//! watches, partition actions, and conflict learning can be compared.

use super::action::{self, ActionCaps, ActionError, ActionLimit, ActionOutcome, PartitionAction};
use super::action_nogood::{
    ActionDomainKey, ActionEufReplay, ActionEufReplayCaps, ActionNogood, ActionNogoodArena,
    ActionNogoodArenaCaps, ActionNogoodBuild, ActionNogoodCaps, ActionNogoodError,
    ActionNogoodInsert, ActionNogoodMatch, ActionValue, CertificateEvidence, FrozenAction,
    RelationCondition,
};
use super::bool_cnf::{self, LoweringCaps, LoweringError, NativeFormula};
use super::congruence::{
    Abstention as CongruenceAbstention, ApplyOutcome, ConflictOrigin, CongruenceConflict,
    CongruenceError, CongruenceLimits, ExplanationOutcome, RollbackCongruence,
};
use super::cover::{
    self, CoverAbstention, CoverBuild, CoverCaps, CoverCheck, CoverError, CoverProof, CoverReceipt,
};
use super::domain_proof::{
    DOMAIN_PROOF_REASON_TAG, DomainProofArena, DomainProofCaps, DomainProofError,
    DomainProofLookupError,
};
use super::impact::{self, ImpactCaps, ImpactError, ImpactLimit, ImpactOutcome};
use super::incremental_congruence::IncrementalCongruence;
use super::learned_clause::{
    LearnedClauseCaps, LearnedClauseDb, LearnedClauseError, LearnedClauseInsert, LearnedScanCaps,
};
use super::learning::{self, AnalysisCaps, AnalysisError, AnalysisOutcome, ReasonProvider};
use super::model::{
    self, CandidateRelation, CanonicalModel, InvalidModel, ModelCaps, ModelError, ModelLimit,
    ModelValidation,
};
use super::native_clause::{AtomId, ClauseId, Lit, Truth};
use super::partition::{Partition, ReasonId, Relation, TermId};
use super::semantic::{SemanticAtom, SemanticExpr, SemanticProblem};
use super::theory_atom_index::{
    TheoryAtomIndex, TheoryAtomIndexCaps, TheoryAtomIndexError, TheoryAtomIndexResource,
};
use super::theory_reason::{
    TheoryReasonArena, TheoryReasonCaps, TheoryReasonError, TheoryReasonInsert,
};
use super::trail::{EnqueueOutcome, Reason, Trail, TrailError};
use super::watch::{
    Capped as WatchCapped, PropagationKind, TruthSource, WatchCaps, WatchError, WatchLimit,
    WatchScheduler,
};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

const ROOT_BOOLEAN_SEPARATION_REASON: ReasonId = ReasonId::MIN;
const FIRST_ACTION_REASON: u64 = 1_u64 << 60;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum BranchingMode {
    #[default]
    EqualityAtoms,
    CanonicalPartitions,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EngineCaps {
    pub(crate) lowering: LoweringCaps,
    pub(crate) congruence: CongruenceLimits,
    pub(crate) model: ModelCaps,
    pub(crate) cover: CoverCaps,
    pub(crate) actions: ActionCaps,
    pub(crate) action_nogoods: ActionNogoodCaps,
    pub(crate) action_nogood_arena: ActionNogoodArenaCaps,
    pub(crate) action_euf_replay: ActionEufReplayCaps,
    pub(crate) watches: WatchCaps,
    pub(crate) impact: ImpactCaps,
    pub(crate) theory_atoms: TheoryAtomIndexCaps,
    pub(crate) theory_reasons: TheoryReasonCaps,
    pub(crate) domain_proofs: DomainProofCaps,
    pub(crate) learned_clauses: LearnedClauseCaps,
    pub(crate) learned_scan: LearnedScanCaps,
    pub(crate) analysis: AnalysisCaps,
    pub(crate) enable_learning: bool,
    pub(crate) enable_compact_unsat_precheck: bool,
    pub(crate) compact_precheck_min_branches: usize,
    pub(crate) enable_action_nogoods: bool,
    pub(crate) max_action_nogood_minimization_checks: usize,
    pub(crate) branching: BranchingMode,
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
            actions: ActionCaps::default(),
            action_nogoods: ActionNogoodCaps::default(),
            action_nogood_arena: ActionNogoodArenaCaps::default(),
            action_euf_replay: ActionEufReplayCaps::default(),
            watches: WatchCaps::default(),
            impact: ImpactCaps::default(),
            theory_atoms: TheoryAtomIndexCaps::default(),
            theory_reasons: TheoryReasonCaps::default(),
            domain_proofs: DomainProofCaps::default(),
            learned_clauses: LearnedClauseCaps::default(),
            learned_scan: LearnedScanCaps::default(),
            analysis: AnalysisCaps::default(),
            enable_learning: false,
            enable_compact_unsat_precheck: false,
            compact_precheck_min_branches: 16,
            enable_action_nogoods: false,
            max_action_nogood_minimization_checks: 256,
            branching: BranchingMode::default(),
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
    pub(crate) partition_action_nodes: usize,
    pub(crate) partition_action_alternatives: usize,
    pub(crate) partition_action_relation_queries: usize,
    pub(crate) conflicts_analyzed: usize,
    pub(crate) learned_clauses: usize,
    pub(crate) learned_general_clauses: usize,
    pub(crate) learned_units: usize,
    pub(crate) backjumps: usize,
    pub(crate) action_nogood_replays: usize,
    pub(crate) action_nogoods: usize,
    pub(crate) action_nogood_minimization_checks: usize,
    pub(crate) action_nogood_prunes: usize,
    pub(crate) action_nogood_match_queries: usize,
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
    Actions(ActionLimit),
    Watches(WatchLimit),
    Impact(ImpactLimit),
    TheoryAtoms {
        resource: TheoryAtomIndexResource,
        attempted: usize,
        limit: usize,
    },
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
            Self::Actions(limit) => write!(
                output,
                "canonical partition action {:?} cap exceeded: attempted {}, limit {}",
                limit.resource, limit.attempted, limit.limit
            ),
            Self::Watches(limit) => {
                write!(output, "incremental watch scheduler abstained: {limit}")
            }
            Self::Impact(limit) => write!(
                output,
                "theory-impact {:?} cap exceeded: attempted {}, limit {}",
                limit.resource, limit.attempted, limit.limit
            ),
            Self::TheoryAtoms {
                resource,
                attempted,
                limit,
            } => write!(
                output,
                "{resource} cap exceeded: attempted {attempted}, limit {limit}"
            ),
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
    Action(ActionError),
    ActionNogood(ActionNogoodError),
    Watch(WatchError),
    Impact(ImpactError),
    TheoryAtoms(TheoryAtomIndexError),
    TheoryReasons(TheoryReasonError),
    LearnedClauses(LearnedClauseError),
    Analysis(AnalysisError),
    DomainProof(DomainProofError),
    DomainProofLookup(DomainProofLookupError),
    Trail(TrailError),
    FormulaAtomOutOfRange { atom: AtomId, atom_count: usize },
    ClauseIndexOverflow { index: usize },
    InvalidBooleanUniverse,
    IncompleteBooleanTerm { atom: AtomId, term: TermId },
    CandidateDoesNotSatisfySource,
    IndependentModelRejected(InvalidModel),
    AllocationFailed(&'static str),
    Invariant(&'static str),
}

impl fmt::Display for EngineError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lowering(error) => error.fmt(output),
            Self::Congruence(error) => error.fmt(output),
            Self::Model(error) => error.fmt(output),
            Self::Cover(error) => error.fmt(output),
            Self::Action(error) => error.fmt(output),
            Self::ActionNogood(error) => error.fmt(output),
            Self::Watch(error) => error.fmt(output),
            Self::Impact(error) => error.fmt(output),
            Self::TheoryAtoms(error) => error.fmt(output),
            Self::TheoryReasons(error) => error.fmt(output),
            Self::LearnedClauses(error) => error.fmt(output),
            Self::Analysis(error) => error.fmt(output),
            Self::DomainProof(error) => error.fmt(output),
            Self::DomainProofLookup(error) => error.fmt(output),
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
            Self::AllocationFailed(context) => {
                write!(output, "Fabric allocation failed while building {context}")
            }
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
            Self::Action(error) => Some(error),
            Self::ActionNogood(error) => Some(error),
            Self::Watch(error) => Some(error),
            Self::Impact(error) => Some(error),
            Self::TheoryAtoms(error) => Some(error),
            Self::TheoryReasons(error) => Some(error),
            Self::LearnedClauses(error) => Some(error),
            Self::Analysis(error) => Some(error),
            Self::DomainProof(error) => Some(error),
            Self::DomainProofLookup(error) => Some(error),
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

impl From<ActionError> for EngineError {
    fn from(error: ActionError) -> Self {
        Self::Action(error)
    }
}

impl From<ActionNogoodError> for EngineError {
    fn from(error: ActionNogoodError) -> Self {
        Self::ActionNogood(error)
    }
}

impl From<WatchError> for EngineError {
    fn from(error: WatchError) -> Self {
        Self::Watch(error)
    }
}

impl From<ImpactError> for EngineError {
    fn from(error: ImpactError) -> Self {
        Self::Impact(error)
    }
}

impl From<TheoryAtomIndexError> for EngineError {
    fn from(error: TheoryAtomIndexError) -> Self {
        Self::TheoryAtoms(error)
    }
}

impl From<TheoryReasonError> for EngineError {
    fn from(error: TheoryReasonError) -> Self {
        Self::TheoryReasons(error)
    }
}

impl From<LearnedClauseError> for EngineError {
    fn from(error: LearnedClauseError) -> Self {
        Self::LearnedClauses(error)
    }
}

impl From<AnalysisError> for EngineError {
    fn from(error: AnalysisError) -> Self {
        Self::Analysis(error)
    }
}

impl From<DomainProofError> for EngineError {
    fn from(error: DomainProofError) -> Self {
        Self::DomainProof(error)
    }
}

impl From<DomainProofLookupError> for EngineError {
    fn from(error: DomainProofLookupError) -> Self {
        Self::DomainProofLookup(error)
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
    Backjump {
        target: u32,
        root_unit: Option<Lit>,
    },
    Abstained(EngineAbstention),
}

enum ApplyLiteralOutcome {
    Unchanged,
    Changed,
    Conflict(Option<Box<[Lit]>>),
    Abstained(EngineAbstention),
}

enum PropagationOutcome {
    Fixpoint,
    Conflict(Option<ConflictSource>),
    Abstained(EngineAbstention),
}

enum ConflictSource {
    Clause(ClauseId),
    Theory(Box<[Lit]>),
}

enum DomainOutcome {
    Unchanged,
    Changed,
    Conflict,
    Abstained(EngineAbstention),
}

enum ConflictLearning {
    Backjump { target: u32, root_unit: Option<Lit> },
    RootConflict,
    Unavailable,
}

enum LearnedPropagation {
    None,
    Unit { clause: ClauseId, literal: Lit },
    Conflict { clause: ClauseId },
}

enum RollbackImpact {
    Disabled,
    Complete(Box<[TermId]>),
    Abstained(EngineAbstention),
}

trait CongruenceBackend {
    type Snapshot: Copy;

    fn partition(&self) -> &Partition;
    fn snapshot(&self) -> Self::Snapshot;
    fn snapshot_depth(snapshot: Self::Snapshot) -> usize;
    fn rollback(&mut self, snapshot: Self::Snapshot) -> Result<(), CongruenceError>;
    fn relation(&self, left: TermId, right: TermId) -> Result<Relation, CongruenceError>;
    fn explain_equal(
        &self,
        left: TermId,
        right: TermId,
    ) -> Result<ExplanationOutcome, CongruenceError>;
    fn assert_equality(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
    ) -> Result<ApplyOutcome, CongruenceError>;
    fn assert_disequality(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
    ) -> Result<ApplyOutcome, CongruenceError>;
}

impl CongruenceBackend for RollbackCongruence<'_> {
    type Snapshot = super::congruence::CongruenceSnapshot;

    fn partition(&self) -> &Partition {
        RollbackCongruence::partition(self)
    }

    fn snapshot(&self) -> Self::Snapshot {
        RollbackCongruence::snapshot(self)
    }

    fn snapshot_depth(snapshot: Self::Snapshot) -> usize {
        snapshot.depth()
    }

    fn rollback(&mut self, snapshot: Self::Snapshot) -> Result<(), CongruenceError> {
        RollbackCongruence::rollback(self, snapshot).map(|_| ())
    }

    fn relation(&self, left: TermId, right: TermId) -> Result<Relation, CongruenceError> {
        RollbackCongruence::relation(self, left, right)
    }

    fn explain_equal(
        &self,
        left: TermId,
        right: TermId,
    ) -> Result<ExplanationOutcome, CongruenceError> {
        RollbackCongruence::explain_equal(self, left, right)
    }

    fn assert_equality(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
    ) -> Result<ApplyOutcome, CongruenceError> {
        RollbackCongruence::assert_equality(self, left, right, reason)
    }

    fn assert_disequality(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
    ) -> Result<ApplyOutcome, CongruenceError> {
        RollbackCongruence::assert_disequality(self, left, right, reason)
    }
}

impl CongruenceBackend for IncrementalCongruence<'_> {
    type Snapshot = super::incremental_congruence::IncrementalCongruenceSnapshot;

    fn partition(&self) -> &Partition {
        IncrementalCongruence::partition(self)
    }

    fn snapshot(&self) -> Self::Snapshot {
        IncrementalCongruence::snapshot(self)
    }

    fn snapshot_depth(snapshot: Self::Snapshot) -> usize {
        snapshot.depth()
    }

    fn rollback(&mut self, snapshot: Self::Snapshot) -> Result<(), CongruenceError> {
        IncrementalCongruence::rollback(self, snapshot).map(|_| ())
    }

    fn relation(&self, left: TermId, right: TermId) -> Result<Relation, CongruenceError> {
        IncrementalCongruence::relation(self, left, right)
    }

    fn explain_equal(
        &self,
        left: TermId,
        right: TermId,
    ) -> Result<ExplanationOutcome, CongruenceError> {
        IncrementalCongruence::explain_equal(self, left, right)
    }

    fn assert_equality(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
    ) -> Result<ApplyOutcome, CongruenceError> {
        IncrementalCongruence::assert_equality(self, left, right, reason)
    }

    fn assert_disequality(
        &mut self,
        left: TermId,
        right: TermId,
        reason: ReasonId,
    ) -> Result<ApplyOutcome, CongruenceError> {
        IncrementalCongruence::assert_disequality(self, left, right, reason)
    }
}

struct SearchState<'problem, Backend> {
    problem: &'problem SemanticProblem,
    formula: NativeFormula,
    congruence: Backend,
    watches: Option<WatchScheduler>,
    theory_atoms: Option<TheoryAtomIndex>,
    theory_reasons: Option<TheoryReasonArena>,
    domain_proofs: DomainProofArena,
    learned: Option<LearnedClauseDb>,
    action_nogoods: Option<ActionNogoodArena>,
    trail: Trail,
    caps: EngineCaps,
    stats: EngineStats,
    active_equality_terms: Box<[TermId]>,
    next_action_reason: u64,
}

struct EngineReasonProvider<'state> {
    formula: &'state NativeFormula,
    theory: &'state TheoryReasonArena,
    learned: &'state LearnedClauseDb,
}

impl ReasonProvider for EngineReasonProvider<'_> {
    fn clause_reason(&self, reason: ClauseId) -> Option<&[Lit]> {
        if reason.index() < self.formula.clauses.len() {
            self.formula.clauses.get(reason.index()).map(AsRef::as_ref)
        } else {
            self.learned.clause(reason)
        }
    }

    fn theory_reason(&self, reason: super::trail::TheoryReasonId) -> Option<&[Lit]> {
        self.theory.get(reason)
    }
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
    solve_with_formula_and_backend(problem, caps, formula, congruence, None)
}

/// Runs the same correctness-first search with the rollback signature-index
/// backend. This is a differential research entry point, not a production
/// solver route.
pub(crate) fn solve_incremental_reference(
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
    let congruence = match IncrementalCongruence::with_limits(&problem.terms, caps.congruence) {
        Ok(engine) => engine,
        Err(CongruenceError::ConstructionAbstained(reason)) => {
            return Ok(ReferenceOutcome::Abstained {
                reason: EngineAbstention::Congruence(reason),
                stats: EngineStats::default(),
            });
        }
        Err(error) => return Err(error.into()),
    };
    solve_with_formula_and_backend(problem, caps, formula, congruence, None)
}

/// Runs the signature-index backend with deterministic incremental native
/// clause scheduling. Forward theory changes are scheduled through stable
/// quotient impact frontiers; initialization and rollback deliberately use a
/// conservative all-source rescan through the reverse incidence index.
pub(crate) fn solve_incremental_watched_reference(
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
    let watches = match WatchScheduler::initialize_unknown(&formula, caps.watches)? {
        WatchCapped::Complete(scheduler) => scheduler,
        WatchCapped::Abstained(reason) => {
            return Ok(ReferenceOutcome::Abstained {
                reason: EngineAbstention::Watches(reason),
                stats: EngineStats::default(),
            });
        }
    };
    let congruence = match IncrementalCongruence::with_limits(&problem.terms, caps.congruence) {
        Ok(engine) => engine,
        Err(CongruenceError::ConstructionAbstained(reason)) => {
            return Ok(ReferenceOutcome::Abstained {
                reason: EngineAbstention::Congruence(reason),
                stats: EngineStats::default(),
            });
        }
        Err(error) => return Err(error.into()),
    };
    solve_with_formula_and_backend(problem, caps, formula, congruence, Some(watches))
}

/// Opt-in first-UIP research arm. Learning is restricted to the binary
/// equality-atom search; canonical quotient actions use their separate stable
/// finite-domain nogood system.
pub(crate) fn solve_incremental_learned_reference(
    problem: &SemanticProblem,
    mut caps: EngineCaps,
) -> Result<ReferenceOutcome, EngineError> {
    caps.enable_learning = true;
    caps.enable_compact_unsat_precheck = true;
    solve_incremental_watched_reference(problem, caps)
}

/// Opt-in canonical finite-domain arm with independently replayed direct
/// action conflicts. Recursive UNSAT results are intentionally not learned.
pub(crate) fn solve_incremental_action_nogood_reference(
    problem: &SemanticProblem,
    mut caps: EngineCaps,
) -> Result<ReferenceOutcome, EngineError> {
    caps.branching = BranchingMode::CanonicalPartitions;
    caps.enable_action_nogoods = true;
    solve_incremental_watched_reference(problem, caps)
}

fn solve_with_formula_and_backend<Backend: CongruenceBackend>(
    problem: &SemanticProblem,
    caps: EngineCaps,
    formula: NativeFormula,
    congruence: Backend,
    watches: Option<WatchScheduler>,
) -> Result<ReferenceOutcome, EngineError> {
    let mut theory_atoms = if watches.is_some() {
        match TheoryAtomIndex::with_caps(problem, caps.theory_atoms) {
            Ok(index) => Some(index),
            Err(TheoryAtomIndexError::CapExceeded {
                resource,
                attempted,
                limit,
            }) => {
                return Ok(ReferenceOutcome::Abstained {
                    reason: EngineAbstention::TheoryAtoms {
                        resource,
                        attempted,
                        limit,
                    },
                    stats: EngineStats::default(),
                });
            }
            Err(error) => return Err(error.into()),
        }
    } else {
        None
    };
    if let Some(index) = theory_atoms.as_mut() {
        match index.mark_all_terms() {
            Ok(_) => {}
            Err(TheoryAtomIndexError::CapExceeded {
                resource,
                attempted,
                limit,
            }) => {
                return Ok(ReferenceOutcome::Abstained {
                    reason: EngineAbstention::TheoryAtoms {
                        resource,
                        attempted,
                        limit,
                    },
                    stats: EngineStats::default(),
                });
            }
            Err(error) => return Err(error.into()),
        }
    }
    let theory_reasons = watches
        .as_ref()
        .map(|_| TheoryReasonArena::new(formula.atom_count, caps.theory_reasons));
    let learned = if caps.enable_learning
        && watches.is_some()
        && caps.branching == BranchingMode::EqualityAtoms
    {
        Some(LearnedClauseDb::with_caps(
            formula.atom_count,
            formula.clauses.len(),
            caps.learned_clauses,
        )?)
    } else {
        None
    };
    let action_nogoods =
        if caps.enable_action_nogoods && caps.branching == BranchingMode::CanonicalPartitions {
            Some(ActionNogoodArena::new(
                problem.terms.len(),
                caps.action_nogood_arena,
            ))
        } else {
            None
        };
    let domain_proofs = DomainProofArena::new(
        problem.terms.len(),
        formula.source_atom_count,
        caps.domain_proofs,
    );
    let mut state = SearchState {
        problem,
        trail: Trail::new(formula.atom_count),
        formula,
        congruence,
        watches,
        theory_atoms,
        theory_reasons,
        domain_proofs,
        learned,
        action_nogoods,
        caps,
        stats: EngineStats::default(),
        active_equality_terms: active_equality_terms(problem)?,
        next_action_reason: FIRST_ACTION_REASON,
    };

    if caps.enable_compact_unsat_precheck {
        if let Some(outcome) = certify_compact_unsat(
            problem,
            caps.cover,
            caps.compact_precheck_min_branches,
            state.stats,
        )? {
            return Ok(outcome);
        }
    }

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
        SearchOutcome::Backjump { .. } => Err(EngineError::Invariant(
            "nonchronological backjump escaped the root search frame",
        )),
        SearchOutcome::Abstained(reason) => Ok(ReferenceOutcome::Abstained { reason, stats }),
    }
}

fn certify_compact_unsat(
    problem: &SemanticProblem,
    caps: CoverCaps,
    min_branches: usize,
    mut stats: EngineStats,
) -> Result<Option<ReferenceOutcome>, EngineError> {
    let Some(proof) =
        cover::build_root_disjunction_conflict_with_min_branches(problem, caps, min_branches)?
    else {
        return Ok(None);
    };
    let CoverCheck::Valid(receipt) = cover::check_cover(problem, &proof, caps)? else {
        return Ok(None);
    };
    stats.closed_branches = stats
        .closed_branches
        .checked_add(1)
        .ok_or(EngineError::Invariant("closed branch counter overflowed"))?;
    return Ok(Some(ReferenceOutcome::Unsat {
        cover: proof,
        receipt,
        stats,
    }));
}

fn certify_unsat(
    problem: &SemanticProblem,
    caps: CoverCaps,
    stats: EngineStats,
) -> Result<ReferenceOutcome, EngineError> {
    if let Some(proof) = cover::build_root_literal_conflict(problem)? {
        return match cover::check_cover(problem, &proof, caps)? {
            CoverCheck::Valid(receipt) => Ok(ReferenceOutcome::Unsat {
                cover: proof,
                receipt,
                stats,
            }),
            CoverCheck::Abstained(reason) => Ok(ReferenceOutcome::Abstained {
                reason: EngineAbstention::Cover(reason),
                stats,
            }),
        };
    }
    if let Some(proof) = cover::build_root_theory_conflict(problem, caps)? {
        return match cover::check_cover(problem, &proof, caps)? {
            CoverCheck::Valid(receipt) => Ok(ReferenceOutcome::Unsat {
                cover: proof,
                receipt,
                stats,
            }),
            CoverCheck::Abstained(reason) => Ok(ReferenceOutcome::Abstained {
                reason: EngineAbstention::Cover(reason),
                stats,
            }),
        };
    }
    if let Some(proof) = cover::build_root_disjunction_conflict(problem, caps)? {
        return match cover::check_cover(problem, &proof, caps)? {
            CoverCheck::Valid(receipt) => Ok(ReferenceOutcome::Unsat {
                cover: proof,
                receipt,
                stats,
            }),
            CoverCheck::Abstained(reason) => Ok(ReferenceOutcome::Abstained {
                reason: EngineAbstention::Cover(reason),
                stats,
            }),
        };
    }
    if let Some(proof) = cover::build_root_propagation_conflict(problem, caps)? {
        return match cover::check_cover(problem, &proof, caps)? {
            CoverCheck::Valid(receipt) => Ok(ReferenceOutcome::Unsat {
                cover: proof,
                receipt,
                stats,
            }),
            CoverCheck::Abstained(reason) => Ok(ReferenceOutcome::Abstained {
                reason: EngineAbstention::Cover(reason),
                stats,
            }),
        };
    }
    if let cover::PrunedCoverBuild::Built(proof) = cover::build_pruned_cover(problem, caps)? {
        if let CoverCheck::Valid(receipt) = cover::check_cover(problem, &proof, caps)? {
            return Ok(ReferenceOutcome::Unsat {
                cover: proof,
                receipt,
                stats,
            });
        }
    }
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

impl<Backend: CongruenceBackend> SearchState<'_, Backend> {
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
            PropagationOutcome::Conflict(source) => {
                self.stats.closed_branches += 1;
                if self.trail.current_level() != 0 {
                    if let Some(source) = source.as_ref() {
                        match self.learn_from_conflict(source)? {
                            ConflictLearning::Backjump { target, root_unit } => {
                                return Ok(SearchOutcome::Backjump { target, root_unit });
                            }
                            ConflictLearning::RootConflict => {
                                return Ok(SearchOutcome::Unsat);
                            }
                            ConflictLearning::Unavailable => {}
                        }
                    }
                }
                return Ok(SearchOutcome::Unsat);
            }
            PropagationOutcome::Abstained(reason) => {
                return Ok(SearchOutcome::Abstained(reason));
            }
            PropagationOutcome::Fixpoint => {}
        }

        if self.caps.branching == BranchingMode::CanonicalPartitions
            && self.has_open_unknown_equality()?
        {
            let remaining_relation_queries = self
                .caps
                .actions
                .max_relation_queries
                .saturating_sub(self.stats.partition_action_relation_queries);
            let mut action_caps = self.caps.actions;
            action_caps.max_relation_queries = remaining_relation_queries;
            match action::next_actions(
                self.congruence.partition(),
                &self.problem.terms,
                &self.active_equality_terms,
                action_caps,
            )? {
                ActionOutcome::Actions(actions) => {
                    self.consume_action_relation_queries(actions.relation_queries)?;
                    return self.branch_partition(&actions.alternatives);
                }
                ActionOutcome::Abstained(limit) => {
                    return Ok(SearchOutcome::Abstained(EngineAbstention::Actions(
                        self.global_action_limit(limit),
                    )));
                }
                ActionOutcome::Complete { relation_queries } => {
                    self.consume_action_relation_queries(relation_queries)?;
                    return Err(EngineError::Invariant(
                        "canonical partition is complete while a source equality is unknown",
                    ));
                }
            }
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
        let candidate_relations = self.candidate_relations()?;
        let model = match model::validate_complete_with_relations(
            self.problem,
            &source_atom_values,
            &candidate_relations,
            self.caps.model,
        )? {
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

    fn learn_from_conflict(
        &mut self,
        conflict_source: &ConflictSource,
    ) -> Result<ConflictLearning, EngineError> {
        let (Some(learned), Some(theory)) = (self.learned.as_ref(), self.theory_reasons.as_ref())
        else {
            return Ok(ConflictLearning::Unavailable);
        };
        let source_literals = match conflict_source {
            ConflictSource::Clause(conflict_id) => {
                if conflict_id.index() < self.formula.clauses.len() {
                    Some(self.formula.clauses[conflict_id.index()].as_ref())
                } else {
                    learned.clause(*conflict_id)
                }
            }
            ConflictSource::Theory(clause) => Some(clause.as_ref()),
        };
        let Some(source_literals) = source_literals else {
            return Ok(ConflictLearning::Unavailable);
        };
        let mut conflict = Vec::new();
        conflict
            .try_reserve_exact(source_literals.len())
            .map_err(|_| EngineError::AllocationFailed("conflict clause copy"))?;
        conflict.extend_from_slice(source_literals);
        for &literal in &conflict {
            let Some((assignment, _, _)) = self.trail.assignment(literal.atom())? else {
                return Ok(ConflictLearning::Unavailable);
            };
            if assignment != literal.negate() {
                return Ok(ConflictLearning::Unavailable);
            }
        }

        let analysis = {
            let provider = EngineReasonProvider {
                formula: &self.formula,
                theory,
                learned,
            };
            match learning::analyze(&self.trail, &provider, &conflict, self.caps.analysis) {
                Ok(outcome) => outcome,
                Err(
                    AnalysisError::UnresolvablePivot { .. } | AnalysisError::MissingReason { .. },
                ) => return Ok(ConflictLearning::Unavailable),
                Err(error) => return Err(error.into()),
            }
        };
        match analysis {
            AnalysisOutcome::Abstained { .. } => Ok(ConflictLearning::Unavailable),
            AnalysisOutcome::RootConflict(_) => {
                self.stats.conflicts_analyzed = self
                    .stats
                    .conflicts_analyzed
                    .checked_add(1)
                    .ok_or(EngineError::Invariant(
                        "analyzed conflict counter overflowed",
                    ))?;
                Ok(ConflictLearning::RootConflict)
            }
            AnalysisOutcome::Learned(clause) => {
                self.stats.conflicts_analyzed = self
                    .stats
                    .conflicts_analyzed
                    .checked_add(1)
                    .ok_or(EngineError::Invariant(
                        "analyzed conflict counter overflowed",
                    ))?;
                let insertion = match self
                    .learned
                    .as_mut()
                    .ok_or(EngineError::Invariant(
                        "learned clause database disappeared",
                    ))?
                    .insert(&clause.literals)
                {
                    Ok(insertion) => insertion,
                    Err(
                        LearnedClauseError::CapExceeded { .. }
                        | LearnedClauseError::CountOverflow { .. }
                        | LearnedClauseError::ClauseIdSpaceExhausted { .. }
                        | LearnedClauseError::AllocationFailed { .. },
                    ) => return Ok(ConflictLearning::Unavailable),
                    Err(error) => return Err(error.into()),
                };
                let root_unit = match insertion {
                    LearnedClauseInsert::Stored(_) => {
                        self.stats.learned_clauses =
                            self.stats.learned_clauses.checked_add(1).ok_or(
                                EngineError::Invariant("learned clause counter overflowed"),
                            )?;
                        self.stats.learned_general_clauses =
                            self.stats.learned_general_clauses.checked_add(1).ok_or(
                                EngineError::Invariant("learned general clause counter overflowed"),
                            )?;
                        None
                    }
                    LearnedClauseInsert::Existing(_) => None,
                    LearnedClauseInsert::Unit(literal) => {
                        self.stats.learned_clauses =
                            self.stats.learned_clauses.checked_add(1).ok_or(
                                EngineError::Invariant("learned clause counter overflowed"),
                            )?;
                        self.stats.learned_units = self
                            .stats
                            .learned_units
                            .checked_add(1)
                            .ok_or(EngineError::Invariant("learned unit counter overflowed"))?;
                        Some(literal)
                    }
                    LearnedClauseInsert::Empty => return Ok(ConflictLearning::RootConflict),
                    LearnedClauseInsert::Tautology => {
                        return Ok(ConflictLearning::Unavailable);
                    }
                };
                if root_unit.is_some() && clause.backjump_level != 0 {
                    return Err(EngineError::Invariant(
                        "a learned unit requested a non-root backjump",
                    ));
                }
                self.stats.backjumps = self
                    .stats
                    .backjumps
                    .checked_add(1)
                    .ok_or(EngineError::Invariant("backjump counter overflowed"))?;
                Ok(ConflictLearning::Backjump {
                    target: clause.backjump_level,
                    root_unit,
                })
            }
        }
    }

    fn scan_learned_clauses(&self) -> Result<LearnedPropagation, EngineError> {
        let Some(learned) = self.learned.as_ref() else {
            return Ok(LearnedPropagation::None);
        };
        let mut work = 0usize;
        for (clause, literals) in learned.iter() {
            if !charge_optional_scan(&mut work, self.caps.learned_scan.max_work) {
                return Ok(LearnedPropagation::None);
            }
            let mut unknown = None;
            let mut unknown_count = 0usize;
            let mut satisfied = false;
            for &literal in literals {
                if !charge_optional_scan(&mut work, self.caps.learned_scan.max_work) {
                    return Ok(LearnedPropagation::None);
                }
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
                (0, _) => return Ok(LearnedPropagation::Conflict { clause }),
                (1, Some(literal)) => {
                    return Ok(LearnedPropagation::Unit { clause, literal });
                }
                _ => {}
            }
        }
        Ok(LearnedPropagation::None)
    }

    fn branch(&mut self, positive: Lit) -> Result<SearchOutcome, EngineError> {
        if let Some(reason) = bump(
            EngineResource::Decisions,
            &mut self.stats.decisions,
            self.caps.max_decisions,
        ) {
            return Ok(SearchOutcome::Abstained(reason));
        }

        let mut first_abstention = None;
        for literal in [positive, positive.negate()] {
            let snapshot = self.congruence.snapshot();
            let parent_level = self.trail.current_level();
            self.trail.new_decision_level()?;
            let attempted = (|| -> Result<SearchOutcome, EngineError> {
                Ok(match self.apply_literal(literal, Reason::Decision)? {
                    ApplyLiteralOutcome::Conflict(theory_clause) => {
                        self.stats.closed_branches += 1;
                        if let Some(clause) = theory_clause {
                            match self.learn_from_conflict(&ConflictSource::Theory(clause))? {
                                ConflictLearning::Backjump { target, root_unit } => {
                                    SearchOutcome::Backjump { target, root_unit }
                                }
                                ConflictLearning::RootConflict => SearchOutcome::Unsat,
                                ConflictLearning::Unavailable => SearchOutcome::Unsat,
                            }
                        } else {
                            SearchOutcome::Unsat
                        }
                    }
                    ApplyLiteralOutcome::Abstained(reason) => SearchOutcome::Abstained(reason),
                    ApplyLiteralOutcome::Changed | ApplyLiteralOutcome::Unchanged => {
                        self.search()?
                    }
                })
            })();
            let restored = self.restore(snapshot, parent_level);
            let result = match (attempted, restored) {
                (Ok(result), Ok(None)) => result,
                (Ok(_), Ok(Some(reason))) => {
                    return Ok(SearchOutcome::Abstained(reason));
                }
                (Err(error), Ok(_)) => return Err(error),
                (_, Err(error)) => return Err(error),
            };

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
                SearchOutcome::Backjump { target, root_unit } => {
                    if target > parent_level {
                        return Err(EngineError::Invariant(
                            "backjump target is below the restored child but above its parent",
                        ));
                    }
                    if target < parent_level {
                        return Ok(SearchOutcome::Backjump { target, root_unit });
                    }
                    if let Some(unit) = root_unit {
                        if target != 0 {
                            return Err(EngineError::Invariant(
                                "root learned unit reached a non-root frame",
                            ));
                        }
                        match self.apply_literal(unit, Reason::Root)? {
                            ApplyLiteralOutcome::Conflict(_) => return Ok(SearchOutcome::Unsat),
                            ApplyLiteralOutcome::Abstained(reason) => {
                                return Ok(SearchOutcome::Abstained(reason));
                            }
                            ApplyLiteralOutcome::Changed | ApplyLiteralOutcome::Unchanged => {}
                        }
                    }
                    return self.search();
                }
                SearchOutcome::Abstained(reason) => {
                    first_abstention.get_or_insert(reason);
                }
                SearchOutcome::Unsat => {}
            }
        }
        Ok(first_abstention.map_or(SearchOutcome::Unsat, SearchOutcome::Abstained))
    }

    fn branch_partition(
        &mut self,
        alternatives: &[PartitionAction],
    ) -> Result<SearchOutcome, EngineError> {
        if let Some(reason) = bump(
            EngineResource::Decisions,
            &mut self.stats.decisions,
            self.caps.max_decisions,
        ) {
            return Ok(SearchOutcome::Abstained(reason));
        }
        self.stats.partition_action_nodes += 1;
        self.stats.partition_action_alternatives = self
            .stats
            .partition_action_alternatives
            .checked_add(alternatives.len())
            .ok_or(EngineError::Invariant(
                "partition action telemetry overflowed",
            ))?;

        let frozen_alternatives = self.freeze_action_alternatives(alternatives)?;

        let mut first_abstention = None;
        for (alternative_index, alternative) in alternatives.iter().enumerate() {
            let frozen = frozen_alternatives
                .as_ref()
                .and_then(|actions| actions.get(alternative_index));
            if let Some(action) = frozen {
                if self.action_nogood_prunes(action)? {
                    self.stats.closed_branches = self
                        .stats
                        .closed_branches
                        .checked_add(1)
                        .ok_or(EngineError::Invariant("closed branch counter overflowed"))?;
                    continue;
                }
            }
            let snapshot = self.congruence.snapshot();
            let parent_level = self.trail.current_level();
            self.trail.new_decision_level()?;
            let attempted = (|| -> Result<SearchOutcome, EngineError> {
                Ok(match self.apply_partition_action(alternative)? {
                    ApplyLiteralOutcome::Conflict(_) => {
                        if let Some(action) = frozen {
                            self.learn_direct_action_conflict(action)?;
                        }
                        self.stats.closed_branches += 1;
                        SearchOutcome::Unsat
                    }
                    ApplyLiteralOutcome::Abstained(reason) => SearchOutcome::Abstained(reason),
                    ApplyLiteralOutcome::Changed | ApplyLiteralOutcome::Unchanged => {
                        self.search()?
                    }
                })
            })();
            let restored = self.restore(snapshot, parent_level);
            let result = match (attempted, restored) {
                (Ok(result), Ok(None)) => result,
                (Ok(_), Ok(Some(reason))) => {
                    return Ok(SearchOutcome::Abstained(reason));
                }
                (Err(error), Ok(_)) => return Err(error),
                (_, Err(error)) => return Err(error),
            };
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
                SearchOutcome::Backjump { target, root_unit } => {
                    if target > parent_level {
                        return Err(EngineError::Invariant(
                            "backjump target is below the restored child but above its parent",
                        ));
                    }
                    if target < parent_level {
                        return Ok(SearchOutcome::Backjump { target, root_unit });
                    }
                    if let Some(unit) = root_unit {
                        if target != 0 {
                            return Err(EngineError::Invariant(
                                "root learned unit reached a non-root frame",
                            ));
                        }
                        match self.apply_literal(unit, Reason::Root)? {
                            ApplyLiteralOutcome::Conflict(_) => return Ok(SearchOutcome::Unsat),
                            ApplyLiteralOutcome::Abstained(reason) => {
                                return Ok(SearchOutcome::Abstained(reason));
                            }
                            ApplyLiteralOutcome::Changed | ApplyLiteralOutcome::Unchanged => {}
                        }
                    }
                    return self.search();
                }
                SearchOutcome::Abstained(reason) => {
                    first_abstention.get_or_insert(reason);
                }
                SearchOutcome::Unsat => {}
            }
        }
        Ok(first_abstention.map_or(SearchOutcome::Unsat, SearchOutcome::Abstained))
    }

    fn freeze_action_alternatives(
        &self,
        alternatives: &[PartitionAction],
    ) -> Result<Option<Box<[FrozenAction]>>, EngineError> {
        if self.action_nogoods.is_none() {
            return Ok(None);
        }
        let Some(first) = alternatives.first() else {
            return Err(EngineError::Invariant(
                "canonical partition branch has no alternatives",
            ));
        };
        let pivot = match first {
            PartitionAction::Merge { pivot, .. } | PartitionAction::Fresh { pivot, .. } => *pivot,
        };
        let mut frontier = Vec::new();
        frontier
            .try_reserve_exact(alternatives.len().saturating_sub(1))
            .map_err(|_| EngineError::AllocationFailed("frozen action frontier"))?;
        let mut saw_fresh = false;
        for alternative in alternatives {
            match alternative {
                PartitionAction::Merge {
                    pivot: action_pivot,
                    target,
                } => {
                    if *action_pivot != pivot || saw_fresh {
                        return Err(EngineError::Invariant(
                            "canonical action set has inconsistent pivot or ordering",
                        ));
                    }
                    frontier.push(*target);
                }
                PartitionAction::Fresh {
                    pivot: action_pivot,
                    separate_from,
                } => {
                    if *action_pivot != pivot || saw_fresh || separate_from.as_ref() != frontier {
                        return Err(EngineError::Invariant(
                            "canonical fresh action does not close its merge frontier",
                        ));
                    }
                    saw_fresh = true;
                }
            }
        }
        if !saw_fresh || alternatives.len() != frontier.len().saturating_add(1) {
            return Err(EngineError::Invariant(
                "canonical action set lacks one terminal fresh alternative",
            ));
        }
        let domain = match ActionDomainKey::new(pivot, &frontier, self.caps.action_nogoods) {
            Ok(domain) => domain,
            Err(error) if optional_action_nogood_error(&error) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut frozen = Vec::new();
        frozen
            .try_reserve_exact(alternatives.len())
            .map_err(|_| EngineError::AllocationFailed("frozen action alternatives"))?;
        for alternative in alternatives {
            let value = match alternative {
                PartitionAction::Merge { target, .. } => ActionValue::Existing(*target),
                PartitionAction::Fresh { .. } => ActionValue::Fresh,
            };
            match FrozenAction::new(domain.clone(), value) {
                Ok(action) => frozen.push(action),
                Err(error) if optional_action_nogood_error(&error) => return Ok(None),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(Some(frozen.into_boxed_slice()))
    }

    fn action_nogood_prunes(&mut self, assumed: &FrozenAction) -> Result<bool, EngineError> {
        let Some(arena) = self.action_nogoods.as_ref() else {
            return Ok(false);
        };
        let mut query_count = 0usize;
        let mut matched = false;
        for (_, nogood) in arena.iter() {
            match nogood.match_partition_assuming(
                self.congruence.partition(),
                assumed,
                self.caps.action_nogoods,
            )? {
                ActionNogoodMatch::Matched { relation_queries } => {
                    query_count =
                        query_count
                            .checked_add(relation_queries)
                            .ok_or(EngineError::Invariant(
                                "action-nogood query counter overflowed",
                            ))?;
                    matched = true;
                    break;
                }
                ActionNogoodMatch::Refuted { relation_queries }
                | ActionNogoodMatch::Undetermined { relation_queries } => {
                    query_count =
                        query_count
                            .checked_add(relation_queries)
                            .ok_or(EngineError::Invariant(
                                "action-nogood query counter overflowed",
                            ))?;
                }
                ActionNogoodMatch::Abstained(_) => break,
            }
        }
        self.stats.action_nogood_match_queries = self
            .stats
            .action_nogood_match_queries
            .checked_add(query_count)
            .ok_or(EngineError::Invariant(
                "action-nogood query telemetry overflowed",
            ))?;
        if matched {
            self.stats.action_nogood_prunes = self
                .stats
                .action_nogood_prunes
                .checked_add(1)
                .ok_or(EngineError::Invariant(
                    "action-nogood prune telemetry overflowed",
                ))?;
        }
        Ok(matched)
    }

    fn learn_direct_action_conflict(&mut self, action: &FrozenAction) -> Result<(), EngineError> {
        if self.action_nogoods.is_none() {
            return Ok(());
        }
        let mut relations = self.partition_relation_conditions()?;
        let Some(mut nogood) = self.build_direct_action_nogood(action, &relations)? else {
            return Ok(());
        };
        if !self.replay_action_nogood(&nogood)? {
            return Ok(());
        }

        let mut index = relations.len();
        while index != 0
            && self.stats.action_nogood_minimization_checks
                < self.caps.max_action_nogood_minimization_checks
        {
            index -= 1;
            self.stats.action_nogood_minimization_checks = self
                .stats
                .action_nogood_minimization_checks
                .checked_add(1)
                .ok_or(EngineError::Invariant(
                    "action-nogood minimization telemetry overflowed",
                ))?;
            let removed = relations.remove(index);
            let candidate = self.build_direct_action_nogood(action, &relations)?;
            let retain_removal = match candidate.as_ref() {
                Some(candidate) => self.replay_action_nogood(candidate)?,
                None => false,
            };
            if retain_removal {
                nogood = candidate.expect("verified candidate exists");
            } else {
                relations.insert(index, removed);
            }
        }

        let insertion = match self
            .action_nogoods
            .as_mut()
            .ok_or(EngineError::Invariant("action-nogood arena disappeared"))?
            .insert(nogood)
        {
            Ok(insertion) => insertion,
            Err(error) if optional_action_nogood_error(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if matches!(insertion, ActionNogoodInsert::Stored(_)) {
            self.stats.action_nogoods =
                self.stats
                    .action_nogoods
                    .checked_add(1)
                    .ok_or(EngineError::Invariant(
                        "action-nogood storage telemetry overflowed",
                    ))?;
        }
        Ok(())
    }

    fn partition_relation_conditions(&self) -> Result<Vec<RelationCondition>, EngineError> {
        let partition = self.congruence.partition();
        let classes = partition.classes().map_err(CongruenceError::from)?;
        let disequalities = partition
            .canonical_disequalities()
            .map_err(CongruenceError::from)?;
        let equality_count = classes.iter().try_fold(0usize, |total, class| {
            total.checked_add(class.members.len().saturating_sub(1))
        });
        let capacity = equality_count
            .and_then(|count| count.checked_add(disequalities.len()))
            .ok_or(EngineError::Invariant(
                "action-nogood relation count overflowed",
            ))?;
        let mut relations = Vec::new();
        relations
            .try_reserve_exact(capacity)
            .map_err(|_| EngineError::AllocationFailed("action-nogood relation facts"))?;
        for class in classes {
            for member in class.members.into_iter().skip(1) {
                relations.push(RelationCondition::equal(class.representative, member));
            }
        }
        relations.extend(
            disequalities
                .into_iter()
                .map(|edge| RelationCondition::disequal(edge.left, edge.right)),
        );
        relations.sort_unstable();
        relations.dedup();
        Ok(relations)
    }

    fn build_direct_action_nogood(
        &self,
        action: &FrozenAction,
        relations: &[RelationCondition],
    ) -> Result<Option<ActionNogood>, EngineError> {
        let action_evidence = match action.value() {
            ActionValue::Existing(_) => 1usize,
            ActionValue::Fresh => action.domain().frontier().len(),
        };
        let capacity =
            action_evidence
                .checked_add(relations.len())
                .ok_or(EngineError::Invariant(
                    "action-nogood evidence count overflowed",
                ))?;
        let mut evidence = Vec::new();
        evidence
            .try_reserve_exact(capacity)
            .map_err(|_| EngineError::AllocationFailed("action-nogood evidence"))?;
        match action.value() {
            ActionValue::Existing(_) => match CertificateEvidence::existing(action.clone()) {
                Ok(item) => evidence.push(item),
                Err(error) => return Err(error.into()),
            },
            ActionValue::Fresh => {
                for &anchor in action.domain().frontier() {
                    match CertificateEvidence::fresh(action.clone(), anchor) {
                        Ok(item) => evidence.push(item),
                        Err(error) => return Err(error.into()),
                    }
                }
            }
        }
        evidence.extend(
            relations
                .iter()
                .copied()
                .map(CertificateEvidence::forbidden_relation),
        );
        let mut copied_relations = Vec::new();
        copied_relations
            .try_reserve_exact(relations.len())
            .map_err(|_| EngineError::AllocationFailed("action-nogood relations"))?;
        copied_relations.extend_from_slice(relations);
        let build = match ActionNogood::build(
            self.problem.terms.len(),
            vec![action.clone()],
            copied_relations,
            evidence,
            self.caps.action_nogoods,
        ) {
            Ok(build) => build,
            Err(error) if optional_action_nogood_error(&error) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Ok(match build {
            ActionNogoodBuild::Built(nogood) => Some(nogood),
            ActionNogoodBuild::ContradictoryConstraint(nogood) => Some(nogood),
            ActionNogoodBuild::TautologicalConstraint { .. } => None,
        })
    }

    fn replay_action_nogood(&mut self, nogood: &ActionNogood) -> Result<bool, EngineError> {
        self.stats.action_nogood_replays =
            self.stats
                .action_nogood_replays
                .checked_add(1)
                .ok_or(EngineError::Invariant(
                    "action-nogood replay telemetry overflowed",
                ))?;
        match nogood.replay_euf_certificate_with(
            &self.problem.terms,
            self.caps.action_euf_replay,
            |_, _| false,
        ) {
            Ok(ActionEufReplay::VerifiedConflict { .. }) => Ok(true),
            Ok(
                ActionEufReplay::NoConflict { .. }
                | ActionEufReplay::ExternalEvidenceRejected { .. }
                | ActionEufReplay::Abstained(_),
            ) => Ok(false),
            Err(error) if optional_action_nogood_error(&error) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn apply_partition_action(
        &mut self,
        action: &PartitionAction,
    ) -> Result<ApplyLiteralOutcome, EngineError> {
        let checkpoint = self.congruence.snapshot();
        let reason_checkpoint = self.next_action_reason;
        let outcome = self.apply_partition_action_inner(action);
        if outcome.is_err() {
            self.congruence.rollback(checkpoint)?;
            self.next_action_reason = reason_checkpoint;
        }
        outcome
    }

    fn apply_partition_action_inner(
        &mut self,
        action: &PartitionAction,
    ) -> Result<ApplyLiteralOutcome, EngineError> {
        let mut changed = false;
        match action {
            PartitionAction::Merge { pivot, target } => {
                let reason = self.allocate_action_reason()?;
                let merge_start = self.congruence.partition().merge_count();
                match self.congruence.assert_equality(*pivot, *target, reason)? {
                    ApplyOutcome::Applied(stats) => {
                        changed |= stats.explicit_update || stats.congruence_merges != 0;
                        let explicit_seed = stats.explicit_update.then_some((*pivot, *target));
                        if let Some(reason) =
                            self.schedule_partition_update(merge_start, explicit_seed)?
                        {
                            return Ok(ApplyLiteralOutcome::Abstained(reason));
                        }
                    }
                    ApplyOutcome::Conflict(_) => {
                        return Ok(ApplyLiteralOutcome::Conflict(None));
                    }
                    ApplyOutcome::Abstained(reason) => {
                        return Ok(ApplyLiteralOutcome::Abstained(
                            EngineAbstention::Congruence(reason),
                        ));
                    }
                }
            }
            PartitionAction::Fresh {
                pivot,
                separate_from,
            } => {
                for &target in separate_from.iter() {
                    let reason = self.allocate_action_reason()?;
                    let merge_start = self.congruence.partition().merge_count();
                    match self.congruence.assert_disequality(*pivot, target, reason)? {
                        ApplyOutcome::Applied(stats) => {
                            changed |= stats.explicit_update;
                            let explicit_seed = stats.explicit_update.then_some((*pivot, target));
                            if let Some(reason) =
                                self.schedule_partition_update(merge_start, explicit_seed)?
                            {
                                return Ok(ApplyLiteralOutcome::Abstained(reason));
                            }
                        }
                        ApplyOutcome::Conflict(_) => {
                            return Ok(ApplyLiteralOutcome::Conflict(None));
                        }
                        ApplyOutcome::Abstained(reason) => {
                            return Ok(ApplyLiteralOutcome::Abstained(
                                EngineAbstention::Congruence(reason),
                            ));
                        }
                    }
                }
            }
        }
        Ok(if changed {
            ApplyLiteralOutcome::Changed
        } else {
            ApplyLiteralOutcome::Unchanged
        })
    }

    fn candidate_relations(&self) -> Result<Box<[CandidateRelation]>, EngineError> {
        let partition = self.congruence.partition();
        let classes = partition.classes().map_err(CongruenceError::from)?;
        let disequalities = partition
            .canonical_disequalities()
            .map_err(CongruenceError::from)?;
        let equality_count = classes.iter().try_fold(0usize, |total, class| {
            total.checked_add(class.members.len().saturating_sub(1))
        });
        let relation_count = equality_count
            .and_then(|count| count.checked_add(disequalities.len()))
            .ok_or(EngineError::Invariant(
                "candidate relation count overflowed",
            ))?;
        let mut relations = Vec::new();
        relations
            .try_reserve_exact(relation_count)
            .map_err(|_| EngineError::AllocationFailed("candidate relations"))?;
        for class in classes {
            for member in class.members.into_iter().skip(1) {
                relations.push(CandidateRelation::equality(class.representative, member));
            }
        }
        for edge in disequalities {
            relations.push(CandidateRelation::disequality(edge.left, edge.right));
        }
        Ok(relations.into_boxed_slice())
    }

    fn consume_action_relation_queries(&mut self, amount: usize) -> Result<(), EngineError> {
        let attempted = self
            .stats
            .partition_action_relation_queries
            .checked_add(amount)
            .ok_or(EngineError::Invariant(
                "canonical action relation-query counter overflowed",
            ))?;
        if attempted > self.caps.actions.max_relation_queries {
            return Err(EngineError::Invariant(
                "canonical action exceeded its solve-wide relation-query budget",
            ));
        }
        self.stats.partition_action_relation_queries = attempted;
        Ok(())
    }

    fn global_action_limit(&self, mut limit: ActionLimit) -> ActionLimit {
        if limit.resource == action::ActionResource::RelationQueries {
            limit.attempted = self
                .stats
                .partition_action_relation_queries
                .checked_add(limit.attempted)
                .unwrap_or(usize::MAX);
            limit.limit = self.caps.actions.max_relation_queries;
        }
        limit
    }

    fn allocate_action_reason(&mut self) -> Result<ReasonId, EngineError> {
        if self.next_action_reason >= DOMAIN_PROOF_REASON_TAG - 1 {
            return Err(EngineError::Invariant(
                "partition action reason space exhausted",
            ));
        }
        let reason = ReasonId::new(self.next_action_reason);
        self.next_action_reason += 1;
        Ok(reason)
    }

    fn restore(
        &mut self,
        snapshot: Backend::Snapshot,
        parent_level: u32,
    ) -> Result<Option<EngineAbstention>, EngineError> {
        let rollback_impact = self.prepare_rollback_impact(snapshot)?;
        self.congruence.rollback(snapshot)?;
        let removed = self.trail.backtrack(parent_level)?;
        let mut first_abstention = match rollback_impact {
            RollbackImpact::Disabled => None,
            RollbackImpact::Abstained(reason) => Some(reason),
            RollbackImpact::Complete(terms) => {
                if terms.is_empty() {
                    None
                } else {
                    let index = self.theory_atoms.as_mut().ok_or(EngineError::Invariant(
                        "rollback impact exists without a theory atom index",
                    ))?;
                    match index.mark_affected_terms(&terms) {
                        Ok(_) => None,
                        Err(error) => Some(classify_theory_atom_error(error)?),
                    }
                }
            }
        };
        for literal in removed {
            if literal.atom().index() < self.formula.source_atom_count {
                continue;
            }
            if let Some(limit) =
                self.enqueue_watch_truth(TruthSource::BooleanTrail, literal.atom(), Truth::Unknown)?
            {
                first_abstention.get_or_insert(EngineAbstention::Watches(limit));
            }
        }
        Ok(first_abstention)
    }

    fn prepare_rollback_impact(
        &self,
        snapshot: Backend::Snapshot,
    ) -> Result<RollbackImpact, EngineError> {
        if self.theory_atoms.is_none() {
            return Ok(RollbackImpact::Disabled);
        }
        let depth = Backend::snapshot_depth(snapshot);
        let current = self.congruence.partition().update_count();
        let update_count = current.checked_sub(depth).ok_or(EngineError::Invariant(
            "rollback snapshot is newer than the active partition",
        ))?;
        if update_count > self.caps.impact.max_seed_relations {
            return Ok(RollbackImpact::Abstained(EngineAbstention::Impact(
                ImpactLimit {
                    resource: impact::ImpactResource::SeedRelations,
                    attempted: update_count,
                    limit: self.caps.impact.max_seed_relations,
                },
            )));
        }
        if update_count == 0 {
            return Ok(RollbackImpact::Complete(Box::new([])));
        }
        let seeds = self
            .congruence
            .partition()
            .update_endpoints_since(depth)
            .map_err(CongruenceError::from)?;
        if seeds.len() != update_count {
            return Err(EngineError::Invariant(
                "rollback update endpoint count changed during inspection",
            ));
        }
        match impact::affected_terms(self.congruence.partition(), &seeds, self.caps.impact)? {
            ImpactOutcome::Complete { terms, .. } => Ok(RollbackImpact::Complete(terms)),
            ImpactOutcome::Abstained { limit, .. } => {
                Ok(RollbackImpact::Abstained(EngineAbstention::Impact(limit)))
            }
        }
    }

    fn mark_all_source_atoms(&mut self) -> Result<Option<EngineAbstention>, EngineError> {
        let Some(index) = self.theory_atoms.as_mut() else {
            return Ok(None);
        };
        match index.mark_all_terms() {
            Ok(_) => Ok(None),
            Err(error) => classify_theory_atom_error(error).map(Some),
        }
    }

    fn schedule_partition_update(
        &mut self,
        merge_start: usize,
        explicit_seed: Option<(TermId, TermId)>,
    ) -> Result<Option<EngineAbstention>, EngineError> {
        if self.theory_atoms.is_none() {
            return Ok(None);
        }
        let records = self.congruence.partition().merge_records();
        let new_records = records.get(merge_start..).ok_or(EngineError::Invariant(
            "partition merge history shrank during a forward update",
        ))?;
        let capacity = new_records
            .len()
            .checked_add(usize::from(explicit_seed.is_some()))
            .ok_or(EngineError::Invariant(
                "theory-impact seed count overflowed",
            ))?;
        let mut seeds = Vec::new();
        seeds
            .try_reserve_exact(capacity)
            .map_err(|_| EngineError::AllocationFailed("theory-impact seeds"))?;
        seeds.extend(new_records.iter().map(|record| (record.left, record.right)));
        if let Some(seed) = explicit_seed {
            seeds.push(seed);
        }
        if seeds.is_empty() {
            return Ok(None);
        }

        let terms =
            match impact::affected_terms(self.congruence.partition(), &seeds, self.caps.impact)? {
                ImpactOutcome::Complete { terms, .. } => terms,
                ImpactOutcome::Abstained { limit, .. } => {
                    return Ok(Some(EngineAbstention::Impact(limit)));
                }
            };
        let index = self.theory_atoms.as_mut().ok_or(EngineError::Invariant(
            "theory atom index disappeared during impact scheduling",
        ))?;
        match index.mark_affected_terms(&terms) {
            Ok(_) => Ok(None),
            Err(error) => classify_theory_atom_error(error).map(Some),
        }
    }

    fn enqueue_watch_truth(
        &mut self,
        source: TruthSource,
        atom: AtomId,
        truth: Truth,
    ) -> Result<Option<WatchLimit>, EngineError> {
        let Some(watches) = self.watches.as_mut() else {
            return Ok(None);
        };
        match watches.enqueue_truth(source, atom, truth)? {
            WatchCapped::Complete(_) => Ok(None),
            WatchCapped::Abstained(limit) => Ok(Some(limit)),
        }
    }

    fn propagate(&mut self) -> Result<PropagationOutcome, EngineError> {
        if self.watches.is_some() {
            self.propagate_watched()
        } else {
            self.propagate_scanning()
        }
    }

    fn propagate_scanning(&mut self) -> Result<PropagationOutcome, EngineError> {
        loop {
            match self.propagate_boolean_domain()? {
                DomainOutcome::Conflict => return Ok(PropagationOutcome::Conflict(None)),
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
                    (0, _) => {
                        let raw = u32::try_from(clause_index).map_err(|_| {
                            EngineError::ClauseIndexOverflow {
                                index: clause_index,
                            }
                        })?;
                        return Ok(PropagationOutcome::Conflict(Some(ConflictSource::Clause(
                            ClauseId::new(raw),
                        ))));
                    }
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
            match self.apply_literal(literal, Reason::Clause(ClauseId::new(raw_reason)))? {
                ApplyLiteralOutcome::Changed | ApplyLiteralOutcome::Unchanged => {}
                ApplyLiteralOutcome::Conflict(theory_clause) => {
                    return Ok(PropagationOutcome::Conflict(Some(
                        theory_clause.map_or_else(
                            || ConflictSource::Clause(ClauseId::new(raw_reason)),
                            ConflictSource::Theory,
                        ),
                    )));
                }
                ApplyLiteralOutcome::Abstained(reason) => {
                    return Ok(PropagationOutcome::Abstained(reason));
                }
            }
        }
    }

    fn propagate_watched(&mut self) -> Result<PropagationOutcome, EngineError> {
        loop {
            match self.propagate_boolean_domain()? {
                DomainOutcome::Conflict => return Ok(PropagationOutcome::Conflict(None)),
                DomainOutcome::Abstained(reason) => {
                    return Ok(PropagationOutcome::Abstained(reason));
                }
                DomainOutcome::Changed => continue,
                DomainOutcome::Unchanged => {}
            }

            if let Some(limit) = self.synchronize_watch_truths()? {
                return Ok(PropagationOutcome::Abstained(EngineAbstention::Watches(
                    limit,
                )));
            }
            match self.scan_learned_clauses()? {
                LearnedPropagation::Conflict { clause } => {
                    return Ok(PropagationOutcome::Conflict(Some(ConflictSource::Clause(
                        clause,
                    ))));
                }
                LearnedPropagation::Unit { clause, literal } => {
                    if let Some(reason) = bump(
                        EngineResource::Propagations,
                        &mut self.stats.propagations,
                        self.caps.max_propagations,
                    ) {
                        return Ok(PropagationOutcome::Abstained(reason));
                    }
                    match self.apply_literal(literal, Reason::Clause(clause))? {
                        ApplyLiteralOutcome::Changed | ApplyLiteralOutcome::Unchanged => continue,
                        ApplyLiteralOutcome::Conflict(theory_clause) => {
                            return Ok(PropagationOutcome::Conflict(Some(
                                theory_clause
                                    .map_or(ConflictSource::Clause(clause), ConflictSource::Theory),
                            )));
                        }
                        ApplyLiteralOutcome::Abstained(reason) => {
                            return Ok(PropagationOutcome::Abstained(reason));
                        }
                    }
                }
                LearnedPropagation::None => {}
            }
            let event = match self
                .watches
                .as_mut()
                .expect("watched propagation requires a scheduler")
                .pop_propagation()?
            {
                WatchCapped::Complete(event) => event,
                WatchCapped::Abstained(limit) => {
                    return Ok(PropagationOutcome::Abstained(EngineAbstention::Watches(
                        limit,
                    )));
                }
            };
            let Some(event) = event else {
                return Ok(PropagationOutcome::Fixpoint);
            };
            match event.kind {
                PropagationKind::Conflict => {
                    return Ok(PropagationOutcome::Conflict(Some(ConflictSource::Clause(
                        event.clause,
                    ))));
                }
                PropagationKind::Unit { literal } => {
                    if let Some(reason) = bump(
                        EngineResource::Propagations,
                        &mut self.stats.propagations,
                        self.caps.max_propagations,
                    ) {
                        return Ok(PropagationOutcome::Abstained(reason));
                    }
                    match self.apply_literal(literal, Reason::Clause(event.clause))? {
                        ApplyLiteralOutcome::Changed | ApplyLiteralOutcome::Unchanged => {}
                        ApplyLiteralOutcome::Conflict(theory_clause) => {
                            return Ok(PropagationOutcome::Conflict(Some(theory_clause.map_or(
                                ConflictSource::Clause(event.clause),
                                ConflictSource::Theory,
                            ))));
                        }
                        ApplyLiteralOutcome::Abstained(reason) => {
                            return Ok(PropagationOutcome::Abstained(reason));
                        }
                    }
                }
            }
        }
    }

    fn synchronize_watch_truths(&mut self) -> Result<Option<WatchLimit>, EngineError> {
        let pending = self
            .theory_atoms
            .as_mut()
            .ok_or(EngineError::Invariant(
                "watch synchronization has no theory atom index",
            ))?
            .take_pending()?;
        let mut derived_assignments = Vec::new();
        derived_assignments
            .try_reserve_exact(pending.len())
            .map_err(|_| EngineError::AllocationFailed("derived theory assignments"))?;
        for atom in pending {
            let atom_index = atom.index();
            if atom_index >= self.formula.source_atom_count {
                return Err(EngineError::Invariant(
                    "theory atom index scheduled an auxiliary Boolean atom",
                ));
            }
            let desired = self.literal_truth(Lit::positive(atom))?;
            let scheduled = self
                .watches
                .as_ref()
                .expect("watch synchronization requires a scheduler")
                .scheduled_truth(atom)?;
            if desired == scheduled {
                if desired != Truth::Unknown && self.trail.assignment(atom)?.is_none() {
                    derived_assignments.push(match desired {
                        Truth::True => Lit::positive(atom),
                        Truth::False => Lit::negative(atom),
                        Truth::Unknown => unreachable!(),
                    });
                }
                continue;
            }
            if desired != Truth::Unknown && self.trail.assignment(atom)?.is_none() {
                derived_assignments.push(match desired {
                    Truth::True => Lit::positive(atom),
                    Truth::False => Lit::negative(atom),
                    Truth::Unknown => unreachable!(),
                });
            }
            match self
                .watches
                .as_mut()
                .expect("watch synchronization requires a scheduler")
                .enqueue_truth(TruthSource::TheoryPartition, atom, desired)?
            {
                WatchCapped::Complete(_) => {}
                WatchCapped::Abstained(limit) => return Ok(Some(limit)),
            }
        }
        self.enqueue_derived_theory_assignments(&derived_assignments)?;
        let drained = match self
            .watches
            .as_mut()
            .expect("watch synchronization requires a scheduler")
            .drain_truth_queue()?
        {
            WatchCapped::Complete(_) => None,
            WatchCapped::Abstained(limit) => Some(limit),
        };
        if drained.is_none() {
            #[cfg(test)]
            self.assert_all_watch_truths_match()?;
        }
        Ok(drained)
    }

    fn enqueue_derived_theory_assignments(
        &mut self,
        candidates: &[Lit],
    ) -> Result<(), EngineError> {
        if self.theory_reasons.is_none() || candidates.is_empty() {
            return Ok(());
        }
        let mut remaining = Vec::new();
        remaining
            .try_reserve_exact(candidates.len())
            .map_err(|_| EngineError::AllocationFailed("pending theory explanations"))?;
        remaining.extend_from_slice(candidates);

        loop {
            let mut next = Vec::new();
            next.try_reserve_exact(remaining.len())
                .map_err(|_| EngineError::AllocationFailed("deferred theory explanations"))?;
            let mut progress = false;
            for assignment in remaining {
                if self.trail.assignment(assignment.atom())?.is_some() {
                    continue;
                }
                let Some((clause, antecedents)) = self.build_theory_reason(assignment)? else {
                    continue;
                };
                let mut ready = true;
                for antecedent in antecedents.iter().copied() {
                    match self.trail.assignment(antecedent.atom())? {
                        Some((actual, _, _)) if actual == antecedent => {}
                        Some(_) => {
                            return Err(EngineError::Invariant(
                                "theory explanation antecedent contradicts the trail",
                            ));
                        }
                        None => {
                            ready = false;
                            break;
                        }
                    }
                }
                if !ready {
                    next.push(assignment);
                    continue;
                }

                let reason = match self
                    .theory_reasons
                    .as_mut()
                    .ok_or(EngineError::Invariant("theory reason arena disappeared"))?
                    .insert(&clause)
                {
                    Ok(
                        TheoryReasonInsert::Stored(reason) | TheoryReasonInsert::Existing(reason),
                    ) => Some(reason),
                    Ok(TheoryReasonInsert::Tautology)
                    | Err(TheoryReasonError::CapExceeded { .. })
                    | Err(TheoryReasonError::CountOverflow { .. })
                    | Err(TheoryReasonError::ReasonIdSpaceExhausted { .. }) => None,
                    Err(error) => return Err(error.into()),
                };
                let Some(reason) = reason else {
                    continue;
                };
                match self.trail.enqueue(assignment, Reason::Theory(reason))? {
                    EnqueueOutcome::Assigned => progress = true,
                    EnqueueOutcome::AlreadyAssigned => {}
                    EnqueueOutcome::Conflict { .. } => {
                        return Err(EngineError::Invariant(
                            "theory explanation assignment contradicts the trail",
                        ));
                    }
                }
            }
            if next.is_empty() || !progress {
                return Ok(());
            }
            remaining = next;
        }
    }

    fn build_theory_reason(
        &self,
        assignment: Lit,
    ) -> Result<Option<(Vec<Lit>, Vec<Lit>)>, EngineError> {
        let atom_index = assignment.atom().index();
        if atom_index >= self.formula.source_atom_count {
            return Err(EngineError::Invariant(
                "requested a theory explanation for an auxiliary atom",
            ));
        }
        let cap = self
            .theory_reasons
            .as_ref()
            .ok_or(EngineError::Invariant("theory explanation has no arena"))?
            .caps()
            .max_clause_literals;
        let mut antecedents = BTreeSet::new();
        let mut expanding = BTreeSet::new();
        let atom =
            self.problem
                .atoms
                .get(atom_index)
                .ok_or(EngineError::FormulaAtomOutOfRange {
                    atom: assignment.atom(),
                    atom_count: self.problem.atoms.len(),
                })?;
        let explained = match atom {
            SemanticAtom::Equality(left, right) if assignment.is_positive() => self
                .collect_equality_antecedents(
                    *left,
                    *right,
                    &mut antecedents,
                    &mut expanding,
                    cap,
                )?,
            SemanticAtom::Equality(left, right) => self.collect_disequality_antecedents(
                *left,
                *right,
                &mut antecedents,
                &mut expanding,
                cap,
            )?,
            SemanticAtom::BoolTerm(term) => self.collect_boolean_antecedents(
                *term,
                assignment.is_positive(),
                &mut antecedents,
                &mut expanding,
                cap,
            )?,
        };
        if !explained || antecedents.contains(&assignment) {
            return Ok(None);
        }
        if antecedents.contains(&assignment.negate()) {
            return Err(EngineError::Invariant(
                "theory explanation contains the negated conclusion as an antecedent",
            ));
        }
        let clause_len = antecedents
            .len()
            .checked_add(1)
            .ok_or(EngineError::Invariant(
                "theory explanation clause length overflowed",
            ))?;
        if clause_len > cap {
            return Ok(None);
        }
        let antecedents = antecedents.into_iter().collect::<Vec<_>>();
        let mut clause = Vec::new();
        clause
            .try_reserve_exact(clause_len)
            .map_err(|_| EngineError::AllocationFailed("theory explanation clause"))?;
        clause.push(assignment);
        clause.extend(antecedents.iter().map(|literal| literal.negate()));
        clause.sort_unstable();
        clause.dedup();
        Ok(Some((clause, antecedents)))
    }

    fn build_explicit_theory_conflict_clause(
        &self,
        conflict: &CongruenceConflict,
    ) -> Result<Option<Box<[Lit]>>, EngineError> {
        if self.learned.is_none() || self.theory_reasons.is_none() {
            return Ok(None);
        }
        let cap = self
            .caps
            .analysis
            .max_clause_literals
            .min(self.caps.theory_reasons.max_clause_literals);
        let mut antecedents = BTreeSet::new();
        let mut expanding = BTreeSet::new();
        let explained = match conflict.origin {
            ConflictOrigin::ExplicitEquality {
                left,
                right,
                reason,
            } => {
                self.collect_disequality_antecedents(
                    left,
                    right,
                    &mut antecedents,
                    &mut expanding,
                    cap,
                )? && self.expand_partition_reason(reason, &mut antecedents, &mut expanding, cap)?
            }
            ConflictOrigin::ExplicitDisequality {
                left,
                right,
                reason,
            } => {
                self.collect_equality_antecedents(
                    left,
                    right,
                    &mut antecedents,
                    &mut expanding,
                    cap,
                )? && self.expand_partition_reason(reason, &mut antecedents, &mut expanding, cap)?
            }
            ConflictOrigin::Congruence {
                left_application,
                right_application,
                ..
            } => {
                let disequality_explained = self.collect_disequality_antecedents(
                    left_application,
                    right_application,
                    &mut antecedents,
                    &mut expanding,
                    cap,
                )?;
                if !disequality_explained {
                    false
                } else {
                    let mut equality_explained = true;
                    for &reason in &conflict.equality_reasons {
                        if !self.expand_partition_reason(
                            reason,
                            &mut antecedents,
                            &mut expanding,
                            cap,
                        )? {
                            equality_explained = false;
                            break;
                        }
                    }
                    equality_explained
                }
            }
        };
        if !explained || antecedents.len() > cap {
            return Ok(None);
        }
        for &antecedent in &antecedents {
            let Some((assignment, _, _)) = self.trail.assignment(antecedent.atom())? else {
                return Ok(None);
            };
            if assignment != antecedent {
                return Err(EngineError::Invariant(
                    "explicit theory conflict antecedent contradicts the trail",
                ));
            }
        }
        let mut clause = Vec::new();
        clause
            .try_reserve_exact(antecedents.len())
            .map_err(|_| EngineError::AllocationFailed("explicit theory conflict clause"))?;
        clause.extend(antecedents.into_iter().map(Lit::negate));
        clause.sort_unstable();
        clause.dedup();
        if clause
            .windows(2)
            .any(|pair| pair[0].atom() == pair[1].atom())
        {
            return Err(EngineError::Invariant(
                "explicit theory conflict clause is tautological",
            ));
        }
        Ok(Some(clause.into_boxed_slice()))
    }

    fn collect_boolean_antecedents(
        &self,
        term: TermId,
        value: bool,
        antecedents: &mut BTreeSet<Lit>,
        expanding: &mut BTreeSet<ReasonId>,
        cap: usize,
    ) -> Result<bool, EngineError> {
        let (true_term, false_term) = self
            .problem
            .boolean_values
            .ok_or(EngineError::InvalidBooleanUniverse)?;
        let to_true = self.congruence.relation(term, true_term)?;
        let to_false = self.congruence.relation(term, false_term)?;
        if to_true == Relation::Disequal && to_false == Relation::Disequal {
            return Err(EngineError::Invariant(
                "Boolean term is disequal from both exact Boolean values",
            ));
        }

        let mut options = Vec::new();
        options
            .try_reserve_exact(2)
            .map_err(|_| EngineError::AllocationFailed("Boolean explanation routes"))?;
        let routes = if value {
            [
                (to_true == Relation::Equal, true, true_term),
                (to_false == Relation::Disequal, false, false_term),
            ]
        } else {
            [
                (to_false == Relation::Equal, true, false_term),
                (to_true == Relation::Disequal, false, true_term),
            ]
        };
        for (available, equality, target) in routes {
            if !available {
                continue;
            }
            let mut candidate = antecedents.clone();
            let mut candidate_expanding = expanding.clone();
            let explained = if equality {
                self.collect_equality_antecedents(
                    term,
                    target,
                    &mut candidate,
                    &mut candidate_expanding,
                    cap,
                )?
            } else {
                self.collect_disequality_antecedents(
                    term,
                    target,
                    &mut candidate,
                    &mut candidate_expanding,
                    cap,
                )?
            };
            if explained {
                options.push((candidate, candidate_expanding));
            }
        }
        let Some((selected, selected_expanding)) = options.into_iter().min_by(|left, right| {
            left.0
                .len()
                .cmp(&right.0.len())
                .then_with(|| left.0.iter().cmp(right.0.iter()))
        }) else {
            return Ok(false);
        };
        *antecedents = selected;
        *expanding = selected_expanding;
        Ok(true)
    }

    fn collect_equality_antecedents(
        &self,
        left: TermId,
        right: TermId,
        antecedents: &mut BTreeSet<Lit>,
        expanding: &mut BTreeSet<ReasonId>,
        cap: usize,
    ) -> Result<bool, EngineError> {
        let reasons = match self.congruence.explain_equal(left, right)? {
            ExplanationOutcome::Explained(reasons) => reasons,
            ExplanationOutcome::NotEqual | ExplanationOutcome::Abstained(_) => return Ok(false),
        };
        let mut candidate = antecedents.clone();
        let mut candidate_expanding = expanding.clone();
        for reason in reasons {
            if reason == ROOT_BOOLEAN_SEPARATION_REASON {
                return Ok(false);
            }
            if !self.expand_partition_reason(
                reason,
                &mut candidate,
                &mut candidate_expanding,
                cap,
            )? {
                return Ok(false);
            }
        }
        *antecedents = candidate;
        *expanding = candidate_expanding;
        Ok(true)
    }

    fn collect_disequality_antecedents(
        &self,
        left: TermId,
        right: TermId,
        antecedents: &mut BTreeSet<Lit>,
        expanding: &mut BTreeSet<ReasonId>,
        cap: usize,
    ) -> Result<bool, EngineError> {
        let Some(mut witnesses) = self
            .congruence
            .partition()
            .separation_witnesses(left, right)
            .map_err(CongruenceError::from)?
        else {
            return Ok(false);
        };
        witnesses.sort_by_key(|record| (record.reason, record.left, record.right));
        for witness in witnesses {
            let direct = self.congruence.relation(left, witness.left)? == Relation::Equal
                && self.congruence.relation(right, witness.right)? == Relation::Equal;
            let swapped = self.congruence.relation(left, witness.right)? == Relation::Equal
                && self.congruence.relation(right, witness.left)? == Relation::Equal;
            let (left_witness, right_witness) = if direct {
                (witness.left, witness.right)
            } else if swapped {
                (witness.right, witness.left)
            } else {
                return Err(EngineError::Invariant(
                    "disequality witness endpoints do not align with queried classes",
                ));
            };

            let mut candidate = antecedents.clone();
            let mut candidate_expanding = expanding.clone();
            let witness_explained = if witness.reason == ROOT_BOOLEAN_SEPARATION_REASON {
                self.is_root_boolean_separation(witness.left, witness.right)?
            } else {
                self.expand_partition_reason(
                    witness.reason,
                    &mut candidate,
                    &mut candidate_expanding,
                    cap,
                )?
            };
            if !witness_explained
                || !self.collect_equality_antecedents(
                    left,
                    left_witness,
                    &mut candidate,
                    &mut candidate_expanding,
                    cap,
                )?
                || !self.collect_equality_antecedents(
                    right,
                    right_witness,
                    &mut candidate,
                    &mut candidate_expanding,
                    cap,
                )?
            {
                continue;
            }
            *antecedents = candidate;
            *expanding = candidate_expanding;
            return Ok(true);
        }
        Ok(false)
    }

    fn expand_partition_reason(
        &self,
        reason: ReasonId,
        antecedents: &mut BTreeSet<Lit>,
        expanding: &mut BTreeSet<ReasonId>,
        cap: usize,
    ) -> Result<bool, EngineError> {
        if reason == ROOT_BOOLEAN_SEPARATION_REASON || reason == ReasonId::MAX {
            return Ok(false);
        }
        if let Some(literal) = literal_from_reason(reason, self.formula.source_atom_count) {
            antecedents.insert(literal);
            return Ok(antecedents
                .len()
                .checked_add(1)
                .is_some_and(|length| length <= cap));
        }
        if reason.raw() & DOMAIN_PROOF_REASON_TAG == 0 {
            return Ok(false);
        }
        let proof = self.domain_proofs.lookup(reason)?;
        for antecedent in proof.antecedents() {
            antecedents.insert(*antecedent);
            if antecedents
                .len()
                .checked_add(1)
                .is_none_or(|length| length > cap)
            {
                return Ok(false);
            }
        }
        let _ = expanding;
        Ok(true)
    }

    fn is_root_boolean_separation(&self, left: TermId, right: TermId) -> Result<bool, EngineError> {
        let Some((true_term, false_term)) = self.problem.boolean_values else {
            return Ok(false);
        };
        Ok(
            (left == true_term && right == false_term)
                || (left == false_term && right == true_term),
        )
    }

    fn freeze_boolean_domain_reason(
        &mut self,
        term: TermId,
        value: bool,
        opposite: TermId,
    ) -> Result<ReasonId, EngineError> {
        let antecedent_cap = self.domain_proofs.caps().max_antecedents_per_proof;
        let clause_cap = antecedent_cap.saturating_add(1);
        let mut antecedents = BTreeSet::new();
        let mut expanding = BTreeSet::new();
        if !self.collect_disequality_antecedents(
            term,
            opposite,
            &mut antecedents,
            &mut expanding,
            clause_cap,
        )? {
            return self.allocate_action_reason();
        }
        let antecedents = antecedents.into_iter().collect::<Vec<_>>();
        match self.domain_proofs.insert(term, value, &antecedents) {
            Ok(stored) => Ok(stored.reason()),
            Err(
                DomainProofError::CapExceeded { .. }
                | DomainProofError::ArithmeticOverflow { .. }
                | DomainProofError::ReasonIdSpaceExhausted { .. }
                | DomainProofError::AllocationFailed { .. },
            ) => self.allocate_action_reason(),
            Err(error) => Err(error.into()),
        }
    }

    #[cfg(test)]
    fn assert_all_watch_truths_match(&self) -> Result<(), EngineError> {
        let watches = self
            .watches
            .as_ref()
            .ok_or(EngineError::Invariant("watch oracle has no scheduler"))?;
        for atom_index in 0..self.formula.atom_count {
            let atom = AtomId::new(
                u32::try_from(atom_index)
                    .map_err(|_| EngineError::Invariant("formula atom does not fit AtomId"))?,
            );
            let expected = self.literal_truth(Lit::positive(atom))?;
            if watches.truth(atom)? != expected || watches.scheduled_truth(atom)? != expected {
                return Err(EngineError::Invariant(
                    "impact scheduler left a watched atom truth stale",
                ));
            }
        }
        Ok(())
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
            let value = value_term == true_term;
            let opposite = if value { false_term } else { true_term };
            let reason = self.freeze_boolean_domain_reason(term_id, value, opposite)?;
            let merge_start = self.congruence.partition().merge_count();
            return match self
                .congruence
                .assert_equality(term_id, value_term, reason)?
            {
                ApplyOutcome::Applied(stats) => {
                    if stats.explicit_update || stats.congruence_merges != 0 {
                        let explicit_seed = stats.explicit_update.then_some((term_id, value_term));
                        if let Some(reason) =
                            self.schedule_partition_update(merge_start, explicit_seed)?
                        {
                            Ok(DomainOutcome::Abstained(reason))
                        } else {
                            Ok(DomainOutcome::Changed)
                        }
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

    fn has_open_unknown_equality(&self) -> Result<bool, EngineError> {
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
                let atom_index = literal.atom().index();
                if atom_index < self.formula.source_atom_count
                    && self.literal_truth(literal)? == Truth::Unknown
                    && matches!(self.problem.atoms[atom_index], SemanticAtom::Equality(_, _))
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
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
        let atom_index = literal.atom().index();
        if atom_index >= self.formula.atom_count {
            return Err(EngineError::FormulaAtomOutOfRange {
                atom: literal.atom(),
                atom_count: self.formula.atom_count,
            });
        }
        match self.literal_truth(literal)? {
            Truth::True => {
                if atom_index < self.formula.source_atom_count {
                    return Ok(match self.trail.enqueue(literal, trail_reason)? {
                        EnqueueOutcome::Assigned => ApplyLiteralOutcome::Changed,
                        EnqueueOutcome::AlreadyAssigned => ApplyLiteralOutcome::Unchanged,
                        EnqueueOutcome::Conflict { .. } => ApplyLiteralOutcome::Conflict(None),
                    });
                }
                return Ok(ApplyLiteralOutcome::Unchanged);
            }
            Truth::False => return Ok(ApplyLiteralOutcome::Conflict(None)),
            Truth::Unknown => {}
        }

        if atom_index >= self.formula.source_atom_count {
            return Ok(match self.trail.enqueue(literal, trail_reason)? {
                EnqueueOutcome::Assigned => {
                    let truth = if literal.is_positive() {
                        Truth::True
                    } else {
                        Truth::False
                    };
                    if let Some(limit) =
                        self.enqueue_watch_truth(TruthSource::BooleanTrail, literal.atom(), truth)?
                    {
                        ApplyLiteralOutcome::Abstained(EngineAbstention::Watches(limit))
                    } else {
                        ApplyLiteralOutcome::Changed
                    }
                }
                EnqueueOutcome::AlreadyAssigned => ApplyLiteralOutcome::Unchanged,
                EnqueueOutcome::Conflict { .. } => ApplyLiteralOutcome::Conflict(None),
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

        let assigned = match self.trail.enqueue(literal, trail_reason)? {
            EnqueueOutcome::Assigned => true,
            EnqueueOutcome::AlreadyAssigned => false,
            EnqueueOutcome::Conflict { .. } => {
                return Ok(ApplyLiteralOutcome::Conflict(None));
            }
        };

        let merge_start = self.congruence.partition().merge_count();
        let outcome = if decision.2 {
            self.congruence
                .assert_equality(decision.0, decision.1, reason)?
        } else {
            self.congruence
                .assert_disequality(decision.0, decision.1, reason)?
        };
        Ok(match outcome {
            ApplyOutcome::Applied(stats) => {
                let explicit_seed = stats.explicit_update.then_some((decision.0, decision.1));
                if let Some(reason) = self.schedule_partition_update(merge_start, explicit_seed)? {
                    return Ok(ApplyLiteralOutcome::Abstained(reason));
                }
                if assigned || stats.explicit_update || stats.congruence_merges != 0 {
                    ApplyLiteralOutcome::Changed
                } else {
                    ApplyLiteralOutcome::Unchanged
                }
            }
            ApplyOutcome::Conflict(conflict) => ApplyLiteralOutcome::Conflict(
                self.build_explicit_theory_conflict_clause(&conflict)?,
            ),
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

fn classify_theory_atom_error(
    error: TheoryAtomIndexError,
) -> Result<EngineAbstention, EngineError> {
    match error {
        TheoryAtomIndexError::CapExceeded {
            resource,
            attempted,
            limit,
        } => Ok(EngineAbstention::TheoryAtoms {
            resource,
            attempted,
            limit,
        }),
        error => Err(error.into()),
    }
}

fn optional_action_nogood_error(error: &ActionNogoodError) -> bool {
    matches!(
        error,
        ActionNogoodError::TooManyTerms { .. }
            | ActionNogoodError::CapExceeded(_)
            | ActionNogoodError::ArithmeticOverflow { .. }
            | ActionNogoodError::NogoodIdSpaceExhausted { .. }
            | ActionNogoodError::AllocationFailed { .. }
    )
}

fn charge_optional_scan(work: &mut usize, limit: usize) -> bool {
    let Some(attempted) = work.checked_add(1) else {
        return false;
    };
    if attempted > limit {
        return false;
    }
    *work = attempted;
    true
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

fn literal_from_reason(reason: ReasonId, source_atom_count: usize) -> Option<Lit> {
    let encoded = reason.raw().checked_sub(1)?;
    let atom_index = usize::try_from(encoded / 2).ok()?;
    if atom_index >= source_atom_count || atom_index > u32::MAX as usize {
        return None;
    }
    let atom = AtomId::new(atom_index as u32);
    Some(if encoded % 2 == 0 {
        Lit::positive(atom)
    } else {
        Lit::negative(atom)
    })
}

fn active_equality_terms(problem: &SemanticProblem) -> Result<Box<[TermId]>, EngineError> {
    let mut active = BTreeSet::new();
    for atom in problem.atoms.iter() {
        if let SemanticAtom::Equality(left, right) = atom {
            if left.index() >= problem.terms.len() || right.index() >= problem.terms.len() {
                return Err(EngineError::Invariant(
                    "semantic equality references an out-of-range term",
                ));
            }
            active.insert(*left);
            active.insert(*right);
        }
    }
    Ok(active.into_iter().collect::<Vec<_>>().into_boxed_slice())
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
    use super::super::finite_oracle::{self, OracleOutcome};
    use super::super::semantic::project;
    use super::*;

    fn solve(source: &str) -> ReferenceOutcome {
        solve_with_branching(source, BranchingMode::EqualityAtoms)
    }

    fn solve_with_branching(source: &str, branching: BranchingMode) -> ReferenceOutcome {
        let problem = project(&parse_problem(source).unwrap()).unwrap();
        let mut caps = EngineCaps::default();
        caps.branching = branching;
        solve_reference(&problem, caps).unwrap()
    }

    fn is_sat(outcome: &ReferenceOutcome) -> bool {
        match outcome {
            ReferenceOutcome::Sat { .. } => true,
            ReferenceOutcome::Unsat { .. } => false,
            ReferenceOutcome::Abstained { reason, .. } => {
                panic!("bounded correctness test unexpectedly abstained: {reason}")
            }
        }
    }

    fn oracle_is_sat(outcome: &OracleOutcome) -> bool {
        match outcome {
            OracleOutcome::Sat { .. } => true,
            OracleOutcome::Unsat { .. } => false,
            OracleOutcome::Abstained { reason, .. } => {
                panic!("finite correctness oracle unexpectedly abstained: {reason}")
            }
        }
    }

    fn watched_state<'problem>(
        problem: &'problem SemanticProblem,
    ) -> SearchState<'problem, IncrementalCongruence<'problem>> {
        let caps = EngineCaps::default();
        let formula = bool_cnf::lower(problem, caps.lowering).unwrap();
        let watches = match WatchScheduler::initialize_unknown(&formula, caps.watches).unwrap() {
            WatchCapped::Complete(watches) => watches,
            WatchCapped::Abstained(limit) => panic!("unexpected watch abstention: {limit}"),
        };
        let mut theory_atoms = TheoryAtomIndex::with_caps(problem, caps.theory_atoms).unwrap();
        theory_atoms.mark_all_terms().unwrap();
        let mut state = SearchState {
            problem,
            trail: Trail::new(formula.atom_count),
            theory_reasons: Some(TheoryReasonArena::new(
                formula.atom_count,
                caps.theory_reasons,
            )),
            formula,
            congruence: IncrementalCongruence::new(&problem.terms).unwrap(),
            watches: Some(watches),
            theory_atoms: Some(theory_atoms),
            domain_proofs: DomainProofArena::new(
                problem.terms.len(),
                problem.atoms.len(),
                caps.domain_proofs,
            ),
            learned: None,
            action_nogoods: None,
            caps,
            stats: EngineStats::default(),
            active_equality_terms: active_equality_terms(problem).unwrap(),
            next_action_reason: FIRST_ACTION_REASON,
        };
        if let Some((true_term, false_term)) = problem.boolean_values {
            assert!(matches!(
                state
                    .congruence
                    .assert_disequality(true_term, false_term, ROOT_BOOLEAN_SEPARATION_REASON)
                    .unwrap(),
                ApplyOutcome::Applied(_)
            ));
        }
        state
    }

    fn theory_clause(state: &SearchState<'_, IncrementalCongruence<'_>>, atom: AtomId) -> Vec<Lit> {
        let (_, _, Reason::Theory(reason)) = state
            .trail
            .assignment(atom)
            .unwrap()
            .expect("derived source atom must be assigned")
        else {
            panic!("derived source atom has no theory reason")
        };
        state
            .theory_reasons
            .as_ref()
            .unwrap()
            .get(reason)
            .unwrap()
            .to_vec()
    }

    fn assert_backends_equal(
        problem: &SemanticProblem,
        caps: EngineCaps,
        context: &str,
    ) -> ReferenceOutcome {
        let scan = solve_reference(problem, caps).unwrap();
        let incremental = solve_incremental_reference(problem, caps).unwrap();
        assert_eq!(
            incremental, scan,
            "congruence backends disagree for {context}"
        );
        let watched = solve_incremental_watched_reference(problem, caps).unwrap();
        assert_eq!(
            watched, scan,
            "watched incremental backend disagrees for {context}"
        );
        let learned = solve_incremental_learned_reference(problem, caps).unwrap();
        assert_eq!(
            is_sat(&learned),
            is_sat(&scan),
            "opt-in learned backend disagrees for {context}"
        );
        if caps.branching == BranchingMode::CanonicalPartitions {
            let action_learned = solve_incremental_action_nogood_reference(problem, caps).unwrap();
            assert_eq!(
                is_sat(&action_learned),
                is_sat(&scan),
                "opt-in action-nogood backend disagrees for {context}"
            );
        }
        scan
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
        let source = "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-fun a () U)\n\
             (declare-fun b () U)\n\
             (declare-fun c () U)\n\
             (assert (or (= a b) (= a c)))\n\
             (assert (distinct b c))\n\
             (check-sat)";
        let atom_outcome = solve(source);
        assert!(is_sat(&atom_outcome));
        assert!(atom_outcome.stats().decisions >= 1);

        let partition_outcome = solve_with_branching(source, BranchingMode::CanonicalPartitions);
        assert!(is_sat(&partition_outcome));
        assert!(partition_outcome.stats().partition_action_nodes >= 1);
        assert!(partition_outcome.stats().partition_action_alternatives >= 2);
    }

    #[test]
    fn later_sat_sibling_survives_an_earlier_branch_local_abstention() {
        let problem = project(
            &parse_problem(
                "(set-logic QF_UF)\n\
                 (declare-sort U 0)\n\
                 (declare-fun a () U)\n\
                 (declare-fun b () U)\n\
                 (declare-fun f (U) U)\n\
                 (assert (or (distinct a b) (distinct (f a) (f b))))\n\
                 (check-sat)",
            )
            .unwrap(),
        )
        .unwrap();

        for branching in [
            BranchingMode::EqualityAtoms,
            BranchingMode::CanonicalPartitions,
        ] {
            let mut caps = EngineCaps::default();
            caps.branching = branching;
            caps.congruence.max_congruence_merges = 0;
            let outcome = solve_reference(&problem, caps).unwrap();
            assert!(
                matches!(outcome, ReferenceOutcome::Sat { .. }),
                "{branching:?} returned {outcome:?}"
            );
        }
    }

    #[test]
    fn failed_multi_relation_action_restores_partition_and_reason_state() {
        let problem = project(
            &parse_problem(
                "(set-logic QF_UF)\n\
                 (declare-sort U 0)\n\
                 (declare-fun a () U)\n\
                 (declare-fun b () U)\n\
                 (declare-fun c () U)\n\
                 (assert (or (= a b) (= a c)))\n\
                 (check-sat)",
            )
            .unwrap(),
        )
        .unwrap();
        let formula = bool_cnf::lower(&problem, LoweringCaps::default()).unwrap();
        let atom_count = formula.atom_count;
        let active_equality_terms = active_equality_terms(&problem).unwrap();
        assert_eq!(active_equality_terms.len(), 3);
        let mut state = SearchState {
            problem: &problem,
            formula,
            congruence: RollbackCongruence::new(&problem.terms).unwrap(),
            watches: None,
            theory_atoms: None,
            theory_reasons: None,
            domain_proofs: DomainProofArena::new(
                problem.terms.len(),
                problem.atoms.len(),
                DomainProofCaps::default(),
            ),
            learned: None,
            action_nogoods: None,
            trail: Trail::new(atom_count),
            caps: EngineCaps::default(),
            stats: EngineStats::default(),
            active_equality_terms: active_equality_terms.clone(),
            next_action_reason: DOMAIN_PROOF_REASON_TAG - 2,
        };
        let before = state.congruence.snapshot();
        let reason_before = state.next_action_reason;
        let action = PartitionAction::Fresh {
            pivot: active_equality_terms[2],
            separate_from: active_equality_terms[..2].to_vec().into_boxed_slice(),
        };

        assert!(matches!(
            state.apply_partition_action(&action),
            Err(EngineError::Invariant(
                "partition action reason space exhausted"
            ))
        ));
        assert_eq!(state.congruence.snapshot(), before);
        assert_eq!(state.next_action_reason, reason_before);
        for target in &active_equality_terms[..2] {
            assert_eq!(
                state
                    .congruence
                    .relation(active_equality_terms[2], *target)
                    .unwrap(),
                Relation::Unknown
            );
        }
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
        let mut atom_search_nodes = 0usize;
        let mut partition_search_nodes = 0usize;

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
                let problem = project(&parse_problem(&source).unwrap()).unwrap();
                let oracle = finite_oracle::solve(&problem).unwrap();
                let atom_outcome = assert_backends_equal(
                    &problem,
                    EngineCaps::default(),
                    &format!("atom branching, clause pair ({first}, {second})"),
                );
                let mut partition_caps = EngineCaps::default();
                partition_caps.branching = BranchingMode::CanonicalPartitions;
                let partition_outcome = assert_backends_equal(
                    &problem,
                    partition_caps,
                    &format!("partition branching, clause pair ({first}, {second})"),
                );
                atom_search_nodes = atom_search_nodes
                    .checked_add(atom_outcome.stats().search_nodes)
                    .unwrap();
                partition_search_nodes = partition_search_nodes
                    .checked_add(partition_outcome.stats().search_nodes)
                    .unwrap();
                assert_eq!(
                    oracle_is_sat(&oracle),
                    expected_sat,
                    "finite oracle, clause pair ({first}, {second})"
                );
                assert_eq!(
                    is_sat(&atom_outcome),
                    expected_sat,
                    "atom branching, clause pair ({first}, {second})"
                );
                assert_eq!(
                    is_sat(&partition_outcome),
                    expected_sat,
                    "partition branching, clause pair ({first}, {second})"
                );
                assert_eq!(
                    is_sat(&partition_outcome),
                    is_sat(&atom_outcome),
                    "branching modes disagree for clause pair ({first}, {second})"
                );
            }
        }
        assert!(
            partition_search_nodes <= atom_search_nodes,
            "canonical partition branching explored {partition_search_nodes} nodes, \
             binary equality branching explored {atom_search_nodes}"
        );
        assert_eq!(atom_search_nodes, 1_422);
        assert_eq!(partition_search_nodes, 1_422);
    }

    #[test]
    fn canonical_mode_matches_the_finite_oracle_with_functions_and_booleans() {
        let cases = [
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-fun a () U)\n\
             (declare-fun b () U)\n\
             (declare-fun f (U) U)\n\
             (assert (= a b))\n\
             (assert (distinct (f a) (f b)))\n\
             (check-sat)",
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-fun p () Bool)\n\
             (declare-fun g (Bool) U)\n\
             (assert (distinct p true))\n\
             (assert (distinct (g p) (g false)))\n\
             (check-sat)",
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-fun a () U)\n\
             (declare-fun b () U)\n\
             (declare-fun f (U) Bool)\n\
             (assert (or (f a) (not (f b))))\n\
             (assert (= a b))\n\
             (check-sat)",
        ];
        for source in cases {
            let problem = project(&parse_problem(source).unwrap()).unwrap();
            let oracle = finite_oracle::solve(&problem).unwrap();
            let mut caps = EngineCaps::default();
            caps.branching = BranchingMode::CanonicalPartitions;
            let canonical = assert_backends_equal(&problem, caps, source);
            assert_eq!(is_sat(&canonical), oracle_is_sat(&oracle), "{source}");
        }
    }

    #[test]
    fn full_partition_blocker_bounds_reference_action_overhead() {
        let source = "(set-logic QF_UF)\n\
                      (declare-sort U 0)\n\
                      (declare-fun a () U)\n\
                      (declare-fun b () U)\n\
                      (declare-fun c () U)\n\
                      (assert (or (= a b) (= a c) (= b c)))\n\
                      (assert (or (distinct a b) (= a c) (= b c)))\n\
                      (assert (or (= a b) (distinct a c) (= b c)))\n\
                      (assert (or (= a b) (= a c) (distinct b c)))\n\
                      (assert (or (distinct a b) (distinct a c) (distinct b c)))\n\
                      (check-sat)";
        let atom = solve(source);
        let canonical = solve_with_branching(source, BranchingMode::CanonicalPartitions);
        assert!(matches!(atom, ReferenceOutcome::Unsat { .. }));
        assert!(matches!(canonical, ReferenceOutcome::Unsat { .. }));
        assert_eq!(atom.stats().search_nodes, 7);
        assert_eq!(canonical.stats().search_nodes, 8);
        assert_eq!(canonical.stats().partition_action_nodes, 3);
        assert_eq!(canonical.stats().partition_action_alternatives, 7);
    }

    #[test]
    fn canonical_action_caps_abstain_without_falling_back_to_atom_branching() {
        let problem = project(
            &parse_problem(
                "(set-logic QF_UF)\n\
                 (declare-sort U 0)\n\
                 (declare-fun a () U)\n\
                 (declare-fun b () U)\n\
                 (declare-fun c () U)\n\
                 (assert (or (= a b) (= a c)))\n\
                 (check-sat)",
            )
            .unwrap(),
        )
        .unwrap();
        let mut caps = EngineCaps::default();
        caps.branching = BranchingMode::CanonicalPartitions;
        caps.actions.max_alternatives = 1;

        let outcome = solve_reference(&problem, caps).unwrap();

        assert!(matches!(
            outcome,
            ReferenceOutcome::Abstained {
                reason: EngineAbstention::Actions(ActionLimit {
                    resource: action::ActionResource::Alternatives,
                    attempted: 2,
                    limit: 1,
                }),
                ..
            }
        ));
    }

    #[test]
    fn canonical_relation_query_budget_is_solve_wide() {
        let problem = project(
            &parse_problem(
                "(set-logic QF_UF)\n\
                 (declare-sort U 0)\n\
                 (declare-fun a () U)\n\
                 (declare-fun b () U)\n\
                 (declare-fun c () U)\n\
                 (assert (or (= a b) (= a c) (= b c)))\n\
                 (assert (or (distinct a b) (= a c) (= b c)))\n\
                 (assert (or (= a b) (distinct a c) (= b c)))\n\
                 (assert (or (= a b) (= a c) (distinct b c)))\n\
                 (assert (or (distinct a b) (distinct a c) (distinct b c)))\n\
                 (check-sat)",
            )
            .unwrap(),
        )
        .unwrap();
        let mut caps = EngineCaps::default();
        caps.branching = BranchingMode::CanonicalPartitions;
        caps.actions.max_relation_queries = 1;

        let outcome = solve_reference(&problem, caps).unwrap();

        assert!(matches!(
            outcome,
            ReferenceOutcome::Abstained {
                reason: EngineAbstention::Actions(ActionLimit {
                    resource: action::ActionResource::RelationQueries,
                    attempted: 2,
                    limit: 1,
                }),
                stats: EngineStats {
                    partition_action_relation_queries: 1,
                    ..
                },
            }
        ));
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
    fn impacted_watch_path_reschedules_imported_disequality_neighbors() {
        let problem = project(
            &parse_problem(
                "(set-logic QF_UF)\n\
                 (declare-sort U 0)\n\
                 (declare-fun a () U)\n\
                 (declare-fun b () U)\n\
                 (declare-fun c () U)\n\
                 (declare-fun d () U)\n\
                 (declare-fun e () U)\n\
                 (assert (distinct a c))\n\
                 (assert (= a b))\n\
                 (assert (or (= b c) (= d e)))\n\
                 (assert (distinct d e))\n\
                 (check-sat)",
            )
            .unwrap(),
        )
        .unwrap();

        let outcome = assert_backends_equal(
            &problem,
            EngineCaps::default(),
            "imported disequality neighbor",
        );
        assert!(matches!(outcome, ReferenceOutcome::Unsat { .. }));
    }

    #[test]
    fn derived_theory_reasons_replay_over_stable_source_literals() {
        let congruence_problem = project(
            &parse_problem(
                "(set-logic QF_UF)\n\
                 (declare-sort U 0)\n\
                 (declare-fun a () U)\n\
                 (declare-fun b () U)\n\
                 (declare-fun f (U) U)\n\
                 (assert (or (= a b) (= (f a) (f b))))\n\
                 (check-sat)",
            )
            .unwrap(),
        )
        .unwrap();
        let mut base = None;
        let mut derived = None;
        for (index, atom) in congruence_problem.atoms.iter().enumerate() {
            let SemanticAtom::Equality(left, right) = atom else {
                continue;
            };
            let id = AtomId::new(index as u32);
            if congruence_problem.terms[left.index()].arguments.is_empty()
                && congruence_problem.terms[right.index()].arguments.is_empty()
            {
                base = Some(id);
            } else {
                derived = Some(id);
            }
        }
        let base = base.unwrap();
        let derived = derived.unwrap();
        let mut state = watched_state(&congruence_problem);
        state.trail.new_decision_level().unwrap();
        assert!(matches!(
            state
                .apply_literal(Lit::positive(base), Reason::Decision)
                .unwrap(),
            ApplyLiteralOutcome::Changed
        ));
        assert_eq!(state.synchronize_watch_truths().unwrap(), None);
        let mut expected = vec![Lit::negative(base), Lit::positive(derived)];
        expected.sort_unstable();
        assert_eq!(theory_clause(&state, derived), expected);

        let disequality_problem = project(
            &parse_problem(
                "(set-logic QF_UF)\n\
                 (declare-sort U 0)\n\
                 (declare-fun a () U)\n\
                 (declare-fun b () U)\n\
                 (declare-fun c () U)\n\
                 (assert (or (= a b) (= a c) (= b c)))\n\
                 (check-sat)",
            )
            .unwrap(),
        )
        .unwrap();
        let equalities = disequality_problem
            .atoms
            .iter()
            .enumerate()
            .map(|(index, atom)| match atom {
                SemanticAtom::Equality(left, right) => (AtomId::new(index as u32), *left, *right),
                SemanticAtom::BoolTerm(_) => panic!("unexpected Boolean atom"),
            })
            .collect::<Vec<_>>();
        assert_eq!(equalities.len(), 3);
        let separated = equalities[0];
        let merged = equalities
            .iter()
            .copied()
            .find(|candidate| {
                candidate.0 != separated.0
                    && [candidate.1, candidate.2]
                        .iter()
                        .any(|term| *term == separated.1 || *term == separated.2)
            })
            .unwrap();
        let transported = equalities
            .iter()
            .copied()
            .find(|candidate| candidate.0 != separated.0 && candidate.0 != merged.0)
            .unwrap();
        let mut state = watched_state(&disequality_problem);
        state.trail.new_decision_level().unwrap();
        state
            .apply_literal(Lit::negative(separated.0), Reason::Decision)
            .unwrap();
        state.synchronize_watch_truths().unwrap();
        state
            .apply_literal(Lit::positive(merged.0), Reason::Decision)
            .unwrap();
        state.synchronize_watch_truths().unwrap();
        let clause = theory_clause(&state, transported.0);
        assert!(clause.contains(&Lit::negative(transported.0)));
        assert!(clause.contains(&Lit::positive(separated.0)));
        assert!(clause.contains(&Lit::negative(merged.0)));
        assert_eq!(clause.len(), 3);

        let mut boolean_problem = project(
            &parse_problem(
                "(set-logic QF_UF)\n\
                 (declare-fun p () Bool)\n\
                 (assert p)\n\
                 (check-sat)",
            )
            .unwrap(),
        )
        .unwrap();
        let bool_atom = boolean_problem
            .atoms
            .iter()
            .position(|atom| matches!(atom, SemanticAtom::BoolTerm(_)))
            .map(|index| AtomId::new(index as u32))
            .unwrap();
        let SemanticAtom::BoolTerm(bool_term) = boolean_problem.atoms[bool_atom.index()] else {
            unreachable!()
        };
        let (_, false_term) = boolean_problem.boolean_values.unwrap();
        let mut atoms = boolean_problem.atoms.to_vec();
        let equality_atom = AtomId::new(atoms.len() as u32);
        atoms.push(SemanticAtom::Equality(bool_term, false_term));
        boolean_problem.atoms = atoms.into_boxed_slice();
        let mut atom_components = boolean_problem.atom_components.to_vec();
        atom_components.push(boolean_problem.atom_components[bool_atom.index()]);
        boolean_problem.atom_components = atom_components.into_boxed_slice();
        boolean_problem.stats.atoms += 1;
        let mut state = watched_state(&boolean_problem);
        state.trail.new_decision_level().unwrap();
        state
            .apply_literal(Lit::negative(equality_atom), Reason::Decision)
            .unwrap();
        assert!(matches!(
            state.propagate_boolean_domain().unwrap(),
            DomainOutcome::Changed
        ));
        state.synchronize_watch_truths().unwrap();
        let mut expected = vec![Lit::positive(equality_atom), Lit::positive(bool_atom)];
        expected.sort_unstable();
        assert_eq!(theory_clause(&state, bool_atom), expected);
    }

    #[test]
    fn impacted_watch_caps_abstain_without_fallback_or_result_promotion() {
        let problem = project(
            &parse_problem(
                "(set-logic QF_UF)\n\
                 (declare-sort U 0)\n\
                 (declare-fun a () U)\n\
                 (declare-fun b () U)\n\
                 (declare-fun c () U)\n\
                 (assert (or (= a b) (= a c)))\n\
                 (check-sat)",
            )
            .unwrap(),
        )
        .unwrap();

        let mut index_caps = EngineCaps::default();
        index_caps.theory_atoms.max_term_marks = 0;
        assert!(matches!(
            solve_incremental_watched_reference(&problem, index_caps).unwrap(),
            ReferenceOutcome::Abstained {
                reason: EngineAbstention::TheoryAtoms {
                    resource: TheoryAtomIndexResource::TermMarks,
                    ..
                },
                ..
            }
        ));

        let mut impact_caps = EngineCaps::default();
        impact_caps.impact.max_seed_relations = 0;
        assert!(matches!(
            solve_incremental_watched_reference(&problem, impact_caps).unwrap(),
            ReferenceOutcome::Abstained {
                reason: EngineAbstention::Impact(ImpactLimit {
                    resource: impact::ImpactResource::SeedRelations,
                    ..
                }),
                ..
            }
        ));
    }

    #[test]
    fn opt_in_first_uip_learns_root_unit_and_backjumps() {
        let problem = project(
            &parse_problem(
                "(set-logic QF_UF)\n\
                 (declare-sort U 0)\n\
                 (declare-fun a () U)\n\
                 (declare-fun b () U)\n\
                 (declare-fun c () U)\n\
                 (declare-fun d () U)\n\
                 (assert (or (= a b) (= a c)))\n\
                 (assert (or (distinct a b) (= a d)))\n\
                 (assert (or (distinct a c) (= a d)))\n\
                 (assert (or (distinct a d) (= b c)))\n\
                 (assert (or (distinct a d) (distinct b c)))\n\
                 (check-sat)",
            )
            .unwrap(),
        )
        .unwrap();
        let oracle = finite_oracle::solve(&problem).unwrap();
        assert!(!oracle_is_sat(&oracle));

        let mut learned_caps = EngineCaps::default();
        learned_caps.enable_learning = true;
        let outcome = solve_incremental_watched_reference(&problem, learned_caps).unwrap();
        assert!(matches!(outcome, ReferenceOutcome::Unsat { .. }));
        assert!(outcome.stats().conflicts_analyzed >= 1);
        assert!(outcome.stats().learned_clauses >= 1);
        assert!(outcome.stats().backjumps >= 1);
    }

    #[test]
    fn opt_in_first_uip_persists_general_clause_and_propagates_after_backjump() {
        let problem = project(
            &parse_problem(
                "(set-logic QF_UF)\n\
                 (declare-sort U 0)\n\
                 (declare-fun a () U)\n\
                 (declare-fun b () U)\n\
                 (declare-fun c () U)\n\
                 (declare-fun d () U)\n\
                 (assert (or (distinct a b) (distinct a c) (= a d)))\n\
                 (assert (or (distinct a c) (= b c)))\n\
                 (assert (or (distinct a d) (distinct b c)))\n\
                 (check-sat)",
            )
            .unwrap(),
        )
        .unwrap();
        let oracle = finite_oracle::solve(&problem).unwrap();
        assert!(oracle_is_sat(&oracle));

        let mut learned_caps = EngineCaps::default();
        learned_caps.enable_learning = true;
        let outcome = solve_incremental_watched_reference(&problem, learned_caps).unwrap();
        assert!(matches!(outcome, ReferenceOutcome::Sat { .. }));
        assert!(outcome.stats().conflicts_analyzed >= 1);
        assert!(outcome.stats().learned_general_clauses >= 1);
        assert!(outcome.stats().backjumps >= 1);
    }

    #[test]
    fn congruence_conflict_learns_root_unit_and_backjumps() {
        let problem = project(
            &parse_problem(
                "(set-logic QF_UF)\n\
                 (declare-sort U 0)\n\
                 (declare-fun a () U)\n\
                 (declare-fun b () U)\n\
                 (declare-fun c () U)\n\
                 (declare-fun d () U)\n\
                 (declare-fun f (U) U)\n\
                 (assert (distinct (f a) (f b)))\n\
                 (assert (distinct (f c) (f d)))\n\
                 (assert (or (= a b) (= c d)))\n\
                 (check-sat)",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!is_sat(
            &solve_incremental_watched_reference(&problem, EngineCaps::default()).unwrap()
        ));

        let mut learned_caps = EngineCaps::default();
        learned_caps.enable_learning = true;
        let outcome = solve_incremental_watched_reference(&problem, learned_caps).unwrap();
        assert!(matches!(outcome, ReferenceOutcome::Unsat { .. }));
        assert_eq!(
            outcome.stats().conflicts_analyzed,
            1,
            "unexpected learned-run telemetry: {:?}",
            outcome.stats()
        );
        assert_eq!(outcome.stats().learned_general_clauses, 1);
        assert_eq!(outcome.stats().backjumps, 1);
    }

    #[test]
    fn congruence_conflict_clause_replays_transported_disequality_endpoints() {
        let problem = project(
            &parse_problem(
                "(set-logic QF_UF)\n\
                 (declare-sort U 0)\n\
                 (declare-fun a () U)\n\
                 (declare-fun b () U)\n\
                 (declare-fun c () U)\n\
                 (declare-fun d () U)\n\
                 (declare-fun x () U)\n\
                 (declare-fun y () U)\n\
                 (declare-fun u () U)\n\
                 (declare-fun v () U)\n\
                 (declare-fun f (U) U)\n\
                 (assert (distinct x y))\n\
                 (assert (= x (f a)))\n\
                 (assert (= y (f b)))\n\
                 (assert (distinct u v))\n\
                 (assert (= u (f c)))\n\
                 (assert (= v (f d)))\n\
                 (assert (or (= a b) (= c d)))\n\
                 (check-sat)",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!is_sat(
            &solve_incremental_watched_reference(&problem, EngineCaps::default()).unwrap()
        ));

        let mut learned_caps = EngineCaps::default();
        learned_caps.enable_learning = true;
        let outcome = solve_incremental_watched_reference(&problem, learned_caps).unwrap();
        assert!(matches!(outcome, ReferenceOutcome::Unsat { .. }));
        assert_eq!(
            outcome.stats().conflicts_analyzed,
            1,
            "unexpected learned-run telemetry: {:?}",
            outcome.stats()
        );
        assert_eq!(outcome.stats().learned_general_clauses, 1);
        assert_eq!(outcome.stats().backjumps, 1);
    }

    #[test]
    fn canonical_direct_conflict_is_replayed_minimized_and_stored() {
        let problem = project(
            &parse_problem(
                "(set-logic QF_UF)\n\
                 (declare-sort U 0)\n\
                 (declare-fun a () U)\n\
                 (declare-fun b () U)\n\
                 (declare-fun c () U)\n\
                 (declare-fun d () U)\n\
                 (declare-fun f (U) U)\n\
                 (assert (distinct (f a) (f b)))\n\
                 (assert (or (= a b) (= c d)))\n\
                 (check-sat)",
            )
            .unwrap(),
        )
        .unwrap();

        let outcome =
            solve_incremental_action_nogood_reference(&problem, EngineCaps::default()).unwrap();
        assert!(matches!(outcome, ReferenceOutcome::Sat { .. }));
        assert!(outcome.stats().action_nogood_replays >= 1);
        assert_eq!(outcome.stats().action_nogoods, 1);
        assert!(outcome.stats().action_nogood_minimization_checks >= 1);
    }

    #[test]
    fn large_opposite_root_literals_use_compact_checked_unsat_proof() {
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

        let ReferenceOutcome::Unsat { cover, receipt, .. } = outcome else {
            panic!("opposite root literals did not produce certified UNSAT");
        };
        assert_eq!(cover.nodes.len(), 1);
        assert_eq!(receipt.nodes_checked, 1);
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

    #[test]
    #[ignore = "manual release-mode microbenchmark"]
    fn microbench_scan_vs_incremental_congruence_backend() {
        use std::hint::black_box;
        use std::time::Instant;

        let width = 96usize;
        let repetitions = 5usize;
        let mut source =
            String::from("(set-logic QF_UF)\n(declare-sort U 0)\n(declare-fun f (U) U)\n");
        for index in 0..width {
            source.push_str(&format!("(declare-fun a{index} () U)\n"));
            source.push_str(&format!("(declare-fun b{index} () U)\n"));
        }
        source.push_str("(assert (and\n");
        for index in 0..width {
            source.push_str(&format!("  (= a{index} b{index})\n"));
            source.push_str(&format!(
                "  (or (= (f a{index}) (f b{index})) (distinct (f a{index}) (f b{index})))\n"
            ));
        }
        source.push_str("))\n(check-sat)\n");
        let problem = project(&parse_problem(&source).unwrap()).unwrap();

        fn exercise<Backend: CongruenceBackend>(
            problem: &SemanticProblem,
            mut backend: Backend,
        ) -> usize {
            for (atom_index, atom) in problem.atoms.iter().enumerate() {
                let SemanticAtom::Equality(left, right) = atom else {
                    continue;
                };
                if !problem.terms[left.index()].arguments.is_empty()
                    || !problem.terms[right.index()].arguments.is_empty()
                {
                    continue;
                }
                let literal = Lit::positive(AtomId::new(atom_index as u32));
                let outcome = backend
                    .assert_equality(*left, *right, literal_reason(literal))
                    .unwrap();
                assert!(matches!(outcome, ApplyOutcome::Applied(_)));
            }
            black_box(backend.partition().classes().unwrap().len())
        }

        let mut scan_ns = Vec::new();
        let mut incremental_ns = Vec::new();
        let mut expected_classes = None;
        for _ in 0..repetitions {
            let started = Instant::now();
            let classes = exercise(&problem, RollbackCongruence::new(&problem.terms).unwrap());
            scan_ns.push(started.elapsed().as_nanos());
            expected_classes.get_or_insert(classes);
            assert_eq!(Some(classes), expected_classes);

            let started = Instant::now();
            let classes = exercise(
                &problem,
                IncrementalCongruence::new(&problem.terms).unwrap(),
            );
            incremental_ns.push(started.elapsed().as_nanos());
            assert_eq!(Some(classes), expected_classes);
        }
        scan_ns.sort_unstable();
        incremental_ns.sort_unstable();
        let scan_median = scan_ns[scan_ns.len() / 2];
        let incremental_median = incremental_ns[incremental_ns.len() / 2];
        println!(
            "fabric_backend_microbench width={width} terms={} base_equalities={width} repetitions={repetitions} scan_median_ns={scan_median} incremental_median_ns={incremental_median} speedup={:.3}",
            problem.terms.len(),
            scan_median as f64 / incremental_median as f64,
        );
    }
}
