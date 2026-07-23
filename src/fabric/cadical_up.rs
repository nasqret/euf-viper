#![forbid(unsafe_code)]

//! Default-isolated CaDiCaL IPASIR-UP research adapter for Fabric.
//!
//! Only stable source atoms are observed by the external propagator. Native
//! Boolean auxiliaries remain entirely inside CaDiCaL. Every source assignment
//! has a deterministic [`ReasonId`], while [`ROOT_BOOLEAN_SEPARATION_REASON`]
//! is reserved for the built-in `true != false` axiom and is the only reason
//! omitted from an emitted theory clause.

use super::bool_cnf::NativeFormula;
use super::congruence::{
    Abstention as CongruenceAbstention, ApplyOutcome, CONGRUENCE_PARTITION_REASON,
    CongruenceConflict, CongruenceError, CongruenceLimits, ExplanationOutcome,
};
use super::impact::{self, ImpactCaps, ImpactError, ImpactLimit, ImpactOutcome, ImpactStats};
use super::incremental_congruence::{IncrementalCongruenceSnapshot, RollbackIncrementalCongruence};
use super::model::{self, CanonicalModel, ModelCaps, ModelLimit, ModelValidation};
use super::native_clause::{AtomId, Lit};
use super::partition::{
    ProspectiveMergeIncidenceOutcome, ProspectiveMergeIncidenceResource, ReasonId, Relation,
    SeparationRecord, TermId,
};
use super::semantic::{SemanticAtom, SemanticProblem};
use super::signature::SignatureTelemetry;
use super::theory_atom_index::{
    TheoryAtomIndex, TheoryAtomIndexCaps, TheoryAtomIndexError, TheoryAtomIndexResource,
    TheoryAtomIndexTelemetry,
};
use rustsat::solvers::{GetInternalStats, LimitConflicts, LimitDecisions, Solve, SolverResult};
use rustsat::types::{Clause as SatClause, Lit as SatLit, Var};
use rustsat_cadical::{CaDiCaL, Config, ExternalClause, ExternalPropagation, ExternalPropagator};
use std::collections::{BTreeSet, VecDeque};
use std::time::Instant;

const ROOT_BOOLEAN_SEPARATION_REASON: ReasonId = ReasonId::MIN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CadicalUpCaps {
    pub(crate) lazy_propagation_reasons: bool,
    pub(crate) indexed_class_members: bool,
    pub(crate) pair_filtered_impact_atoms: bool,
    pub(crate) demand_driven_propagation_flush: bool,
    pub(crate) narrow_explicit_merge_frontier: bool,
    pub(crate) sparse_root_initialization: bool,
    pub(crate) post_construction_congruence_validation: bool,
    pub(crate) profile_callback_timings: bool,
    pub(crate) allocation_free_assignment_decode: bool,
    pub(crate) propagate_implied_atoms: bool,
    pub(crate) propagate_explicit_equalities: bool,
    pub(crate) propagate_explicit_disequalities: bool,
    pub(crate) propagation_batch_updates: usize,
    pub(crate) max_source_atoms: usize,
    pub(crate) max_native_atoms: usize,
    pub(crate) max_native_clauses: usize,
    pub(crate) max_native_literals: usize,
    pub(crate) max_assignment_notifications: usize,
    pub(crate) max_decision_levels: usize,
    pub(crate) max_backtracks: usize,
    pub(crate) max_atom_evaluations: usize,
    pub(crate) max_narrow_neighbor_classes: usize,
    pub(crate) max_deferred_narrow_terms: usize,
    pub(crate) max_pending_propagations: usize,
    pub(crate) max_pending_external_clauses: usize,
    pub(crate) max_theory_propagations: usize,
    pub(crate) max_theory_clauses: usize,
    pub(crate) max_theory_clause_literals: usize,
    pub(crate) max_logged_literals: usize,
    pub(crate) max_reason_antecedents: usize,
    pub(crate) max_model_checks: usize,
    pub(crate) max_model_blocks: usize,
    pub(crate) max_solver_conflicts: u32,
    pub(crate) max_solver_decisions: u32,
    pub(crate) congruence: CongruenceLimits,
    pub(crate) impact: ImpactCaps,
    pub(crate) theory_atoms: TheoryAtomIndexCaps,
    pub(crate) model: ModelCaps,
}

impl Default for CadicalUpCaps {
    fn default() -> Self {
        Self {
            lazy_propagation_reasons: false,
            indexed_class_members: true,
            pair_filtered_impact_atoms: false,
            demand_driven_propagation_flush: false,
            narrow_explicit_merge_frontier: false,
            sparse_root_initialization: false,
            post_construction_congruence_validation: true,
            profile_callback_timings: false,
            allocation_free_assignment_decode: false,
            propagate_implied_atoms: true,
            propagate_explicit_equalities: true,
            propagate_explicit_disequalities: true,
            propagation_batch_updates: 1,
            max_source_atoms: 250_000,
            max_native_atoms: 500_000,
            max_native_clauses: 1_000_000,
            max_native_literals: 8_000_000,
            max_assignment_notifications: 5_000_000,
            max_decision_levels: 250_000,
            max_backtracks: 1_000_000,
            max_atom_evaluations: 20_000_000,
            max_narrow_neighbor_classes: 1_000_000,
            max_deferred_narrow_terms: 10_000_000,
            max_pending_propagations: 250_000,
            max_pending_external_clauses: 16_384,
            max_theory_propagations: 2_000_000,
            max_theory_clauses: 2_000_000,
            max_theory_clause_literals: 250_000,
            max_logged_literals: 32_000_000,
            max_reason_antecedents: 16_384,
            max_model_checks: 250_000,
            max_model_blocks: 250_000,
            max_solver_conflicts: 5_000_000,
            max_solver_decisions: 5_000_000,
            congruence: CongruenceLimits::default(),
            impact: ImpactCaps::default(),
            theory_atoms: TheoryAtomIndexCaps::default(),
            model: ModelCaps::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CadicalUpResource {
    SourceAtoms,
    NativeAtoms,
    NativeClauses,
    NativeLiterals,
    AssignmentNotifications,
    DecisionLevels,
    Backtracks,
    AtomEvaluations,
    NarrowNeighborClasses,
    DeferredNarrowTerms,
    PendingPropagations,
    PendingExternalClauses,
    TheoryPropagations,
    TheoryClauses,
    TheoryClauseLiterals,
    LoggedLiterals,
    ReasonAntecedents,
    ModelChecks,
    ModelBlocks,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CadicalUpAbstention {
    UnsupportedFragments {
        count: usize,
    },
    CapExceeded {
        resource: CadicalUpResource,
        attempted: usize,
        limit: usize,
    },
    Congruence(CongruenceAbstention),
    Impact(ImpactLimit),
    TheoryAtoms {
        resource: TheoryAtomIndexResource,
        attempted: usize,
        limit: usize,
    },
    Model(ModelLimit),
    Malformed(&'static str),
    Internal(&'static str),
    SolverInterrupted,
    SolverFailure,
    UnsatAfterDroppedPendingClauses {
        count: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TheoryClauseKind {
    Propagation { literal: Lit },
    Conflict,
    ModelBlock,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TheoryClauseLog {
    pub(crate) sequence: usize,
    pub(crate) kind: TheoryClauseKind,
    pub(crate) clause: Box<[Lit]>,
    pub(crate) antecedent_reasons: Box<[ReasonId]>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CadicalUpStats {
    pub(crate) input_validation_ns: u128,
    pub(crate) propagator_construction_ns: u128,
    pub(crate) congruence_construction_ns: u128,
    pub(crate) congruence_universe_validation_ns: u128,
    pub(crate) congruence_partition_construction_ns: u128,
    pub(crate) congruence_signature_index_construction_ns: u128,
    pub(crate) congruence_initial_saturation_ns: u128,
    pub(crate) congruence_post_construction_validation_ns: u128,
    pub(crate) theory_atom_index_construction_ns: u128,
    pub(crate) adapter_state_allocation_ns: u128,
    pub(crate) root_scheduling_ns: u128,
    pub(crate) solver_setup_ns: u128,
    pub(crate) clause_loading_ns: u128,
    pub(crate) observed_variable_setup_ns: u128,
    pub(crate) solver_search_ns: u128,
    pub(crate) callback_assignment_ns: u128,
    pub(crate) callback_decision_level_ns: u128,
    pub(crate) callback_backtrack_ns: u128,
    pub(crate) callback_propagation_ns: u128,
    pub(crate) callback_reason_ns: u128,
    pub(crate) callback_external_clause_ns: u128,
    pub(crate) callback_model_ns: u128,
    pub(crate) assignment_frontier_ns: u128,
    pub(crate) assignment_congruence_ns: u128,
    pub(crate) assignment_equality_congruence_ns: u128,
    pub(crate) assignment_disequality_congruence_ns: u128,
    pub(crate) assignment_post_update_ns: u128,
    pub(crate) source_atoms: usize,
    pub(crate) native_atoms: usize,
    pub(crate) native_clauses: usize,
    pub(crate) native_literals: usize,
    pub(crate) observed_variables: usize,
    pub(crate) assignment_batches: usize,
    pub(crate) assignment_notifications: usize,
    pub(crate) decision_levels: usize,
    pub(crate) peak_decision_level: usize,
    pub(crate) backtracks: usize,
    pub(crate) source_assignments_applied: usize,
    pub(crate) source_equality_assignments: usize,
    pub(crate) source_disequality_assignments: usize,
    pub(crate) explicit_partition_updates: usize,
    pub(crate) congruence_merges: usize,
    pub(crate) impact_calls: usize,
    pub(crate) impact_seed_relations: usize,
    pub(crate) impact_neighbor_edges: usize,
    pub(crate) impact_class_member_visits: usize,
    pub(crate) impact_affected_terms: usize,
    pub(crate) narrow_merge_frontiers: usize,
    pub(crate) narrow_frontier_terms: usize,
    pub(crate) sparse_root_terms: usize,
    pub(crate) atom_evaluations: usize,
    pub(crate) propagation_candidates: usize,
    pub(crate) theory_propagations: usize,
    pub(crate) lazy_reason_requests: usize,
    pub(crate) theory_conflicts: usize,
    pub(crate) model_checks: usize,
    pub(crate) valid_models: usize,
    pub(crate) invalid_models: usize,
    pub(crate) model_blocks: usize,
    pub(crate) coalesced_theory_conflicts: usize,
    pub(crate) unadvertised_theory_clauses_dropped: usize,
    pub(crate) theory_clauses: usize,
    pub(crate) theory_clause_literals: usize,
    pub(crate) fail_closed_clauses: usize,
    pub(crate) solver_propagations: usize,
    pub(crate) solver_decisions: usize,
    pub(crate) solver_conflicts: usize,
    pub(crate) theory_index: TheoryAtomIndexTelemetry,
    pub(crate) signature_index: SignatureTelemetry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CadicalUpOutcome {
    Sat {
        source_atom_values: Box<[bool]>,
        model: CanonicalModel,
    },
    Unsat,
    Abstain {
        reason: CadicalUpAbstention,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CadicalUpReport {
    pub(crate) outcome: CadicalUpOutcome,
    pub(crate) stats: CadicalUpStats,
    pub(crate) theory_log: Box<[TheoryClauseLog]>,
}

/// Solve one already-lowered Fabric problem through the isolated IPASIR-UP
/// adapter. This function is intentionally not routed from production code.
pub(crate) fn solve(
    problem: &SemanticProblem,
    formula: &NativeFormula,
    caps: CadicalUpCaps,
) -> CadicalUpReport {
    let mut stats = CadicalUpStats::default();
    let phase_start = Instant::now();
    let validation = validate_input(problem, formula, caps, &mut stats);
    stats.input_validation_ns = phase_start.elapsed().as_nanos();
    if let Err(reason) = validation {
        return empty_report(reason, stats);
    }
    if problem.stats.unsupported_fragments != 0 {
        return empty_report(
            CadicalUpAbstention::UnsupportedFragments {
                count: problem.stats.unsupported_fragments,
            },
            stats,
        );
    }

    let phase_start = Instant::now();
    let mut propagator =
        match TheoryPropagator::new(problem, formula.source_atom_count, caps, stats) {
            Ok(mut propagator) => {
                propagator.stats.propagator_construction_ns = phase_start.elapsed().as_nanos();
                propagator
            }
            Err((reason, mut stats)) => {
                stats.propagator_construction_ns = phase_start.elapsed().as_nanos();
                return empty_report(reason, stats);
            }
        };

    let phase_start = Instant::now();
    let mut solver = CaDiCaL::default();
    let solver_setup = solver.set_configuration(Config::Plain).and_then(|_| {
        solver
            .limit_conflicts(Some(caps.max_solver_conflicts))
            .and_then(|_| solver.limit_decisions(Some(caps.max_solver_decisions)))
    });
    propagator.stats.solver_setup_ns = phase_start.elapsed().as_nanos();
    if solver_setup.is_err() {
        return propagator.finish(CadicalUpOutcome::Abstain {
            reason: CadicalUpAbstention::SolverFailure,
        });
    }

    let phase_start = Instant::now();
    for native in formula.clauses.iter() {
        let mut clause = SatClause::new();
        if clause.try_reserve_exact(native.len()).is_err() {
            propagator.stats.clause_loading_ns = phase_start.elapsed().as_nanos();
            return propagator.finish(CadicalUpOutcome::Abstain {
                reason: CadicalUpAbstention::Internal("allocating a CaDiCaL input clause"),
            });
        }
        for &literal in native.iter() {
            clause.add(to_sat_lit(literal));
        }
        if solver.add_clause(clause).is_err() {
            propagator.stats.clause_loading_ns = phase_start.elapsed().as_nanos();
            return propagator.finish(CadicalUpOutcome::Abstain {
                reason: CadicalUpAbstention::SolverFailure,
            });
        }
    }
    propagator.stats.clause_loading_ns = phase_start.elapsed().as_nanos();

    let phase_start = Instant::now();
    let mut observed = Vec::new();
    if observed
        .try_reserve_exact(formula.source_atom_count)
        .is_err()
    {
        propagator.stats.observed_variable_setup_ns = phase_start.elapsed().as_nanos();
        return propagator.finish(CadicalUpOutcome::Abstain {
            reason: CadicalUpAbstention::Internal("allocating observed source variables"),
        });
    }
    for index in 0..formula.source_atom_count {
        observed.push(Var::new(index as u32));
    }
    propagator.stats.observed_variables = observed.len();
    propagator.stats.observed_variable_setup_ns = phase_start.elapsed().as_nanos();

    let phase_start = Instant::now();
    let solve_result = solver.solve_with_external_propagator(&mut propagator, &observed);
    propagator.stats.solver_search_ns = phase_start.elapsed().as_nanos();
    propagator.stats.solver_propagations = solver.propagations();
    propagator.stats.solver_decisions = solver.decisions();
    propagator.stats.solver_conflicts = solver.conflicts();

    let outcome = if let Some(reason) = propagator.failure.take() {
        CadicalUpOutcome::Abstain { reason }
    } else {
        match solve_result {
            Err(_) => CadicalUpOutcome::Abstain {
                reason: CadicalUpAbstention::SolverFailure,
            },
            Ok(SolverResult::Interrupted) => CadicalUpOutcome::Abstain {
                reason: CadicalUpAbstention::SolverInterrupted,
            },
            Ok(SolverResult::Unsat)
                if propagator.stats.unadvertised_theory_clauses_dropped != 0 =>
            {
                CadicalUpOutcome::Abstain {
                    reason: CadicalUpAbstention::UnsatAfterDroppedPendingClauses {
                        count: propagator.stats.unadvertised_theory_clauses_dropped,
                    },
                }
            }
            Ok(SolverResult::Unsat) => CadicalUpOutcome::Unsat,
            Ok(SolverResult::Sat) => match propagator.accepted_model.take() {
                Some((source_atom_values, model)) => CadicalUpOutcome::Sat {
                    source_atom_values,
                    model,
                },
                None => CadicalUpOutcome::Abstain {
                    reason: CadicalUpAbstention::Internal(
                        "CaDiCaL returned SAT without an accepted validated model",
                    ),
                },
            },
        }
    };
    propagator.finish(outcome)
}

fn empty_report(reason: CadicalUpAbstention, stats: CadicalUpStats) -> CadicalUpReport {
    CadicalUpReport {
        outcome: CadicalUpOutcome::Abstain { reason },
        stats,
        theory_log: Box::new([]),
    }
}

fn validate_input(
    problem: &SemanticProblem,
    formula: &NativeFormula,
    caps: CadicalUpCaps,
    stats: &mut CadicalUpStats,
) -> Result<(), CadicalUpAbstention> {
    if caps.propagation_batch_updates == 0 {
        return Err(CadicalUpAbstention::Malformed(
            "propagation batch size must be positive",
        ));
    }
    check_cap(
        CadicalUpResource::SourceAtoms,
        formula.source_atom_count,
        caps.max_source_atoms,
    )?;
    check_cap(
        CadicalUpResource::NativeAtoms,
        formula.atom_count,
        caps.max_native_atoms,
    )?;
    check_cap(
        CadicalUpResource::NativeClauses,
        formula.clauses.len(),
        caps.max_native_clauses,
    )?;
    if formula.source_atom_count != problem.atoms.len() {
        return Err(CadicalUpAbstention::Malformed(
            "native source-atom count differs from the semantic problem",
        ));
    }
    if formula.source_atom_count > formula.atom_count {
        return Err(CadicalUpAbstention::Malformed(
            "native source-atom count exceeds the total atom count",
        ));
    }
    let expected_auxiliary = formula
        .atom_count
        .checked_sub(formula.source_atom_count)
        .ok_or(CadicalUpAbstention::Malformed(
            "native auxiliary-atom count underflowed",
        ))?;
    if formula.auxiliary_atom_count != expected_auxiliary {
        return Err(CadicalUpAbstention::Malformed(
            "native auxiliary-atom count is inconsistent",
        ));
    }
    if formula.atom_count > i32::MAX as usize {
        return Err(CadicalUpAbstention::Malformed(
            "native atom identifiers do not fit IPASIR",
        ));
    }

    let mut literal_count = 0usize;
    for clause in formula.clauses.iter() {
        for literal in clause.iter() {
            if literal.atom().index() >= formula.atom_count {
                return Err(CadicalUpAbstention::Malformed(
                    "native clause contains an out-of-range atom",
                ));
            }
        }
        literal_count =
            literal_count
                .checked_add(clause.len())
                .ok_or(CadicalUpAbstention::Internal(
                    "native literal count overflowed",
                ))?;
        check_cap(
            CadicalUpResource::NativeLiterals,
            literal_count,
            caps.max_native_literals,
        )?;
    }
    stats.source_atoms = formula.source_atom_count;
    stats.native_atoms = formula.atom_count;
    stats.native_clauses = formula.clauses.len();
    stats.native_literals = literal_count;
    Ok(())
}

#[derive(Clone, Debug)]
struct PendingPropagation {
    literal: Lit,
    eager_reason: Option<(Box<[Lit]>, Box<[ReasonId]>)>,
}

#[derive(Clone, Copy, Debug)]
enum HistoricalReasonWitness {
    Equality {
        left: TermId,
        right: TermId,
    },
    Disequality {
        left: TermId,
        right: TermId,
        left_witness: TermId,
        right_witness: TermId,
        separation: SeparationRecord,
    },
}

#[derive(Clone, Copy, Debug)]
struct PropagationReasonToken {
    literal: Lit,
    snapshot: IncrementalCongruenceSnapshot,
    witness: HistoricalReasonWitness,
}

#[derive(Clone, Debug)]
struct PendingClause {
    kind: TheoryClauseKind,
    clause: Box<[Lit]>,
    antecedent_reasons: Box<[ReasonId]>,
}

struct TheoryPropagator<'problem> {
    problem: &'problem SemanticProblem,
    source_atom_count: usize,
    caps: CadicalUpCaps,
    congruence: RollbackIncrementalCongruence<'problem>,
    theory_atoms: TheoryAtomIndex,
    assignments: Box<[Option<bool>]>,
    trail: Vec<Lit>,
    level_starts: Vec<usize>,
    level_snapshots: Vec<IncrementalCongruenceSnapshot>,
    queued_polarities: Box<[Option<bool>]>,
    reason_tokens: Box<[Option<PropagationReasonToken>]>,
    affected_term_generations: Box<[u32]>,
    affected_generation: u32,
    pending_propagations: VecDeque<PendingPropagation>,
    pending_clauses: VecDeque<PendingClause>,
    deferred_merge_start: Option<usize>,
    deferred_disequality_seeds: Vec<(TermId, TermId)>,
    deferred_narrow_terms: Vec<TermId>,
    deferred_partition_updates: usize,
    failure: Option<CadicalUpAbstention>,
    fail_closed_emitted: bool,
    accepted_model: Option<(Box<[bool]>, CanonicalModel)>,
    stats: CadicalUpStats,
    theory_log: Vec<TheoryClauseLog>,
}

impl<'problem> TheoryPropagator<'problem> {
    fn new(
        problem: &'problem SemanticProblem,
        source_atom_count: usize,
        caps: CadicalUpCaps,
        mut stats: CadicalUpStats,
    ) -> Result<Self, (CadicalUpAbstention, CadicalUpStats)> {
        if let Err(reason) = validate_boolean_universe(problem) {
            return Err((reason, stats));
        }
        let phase_start = Instant::now();
        let mut congruence = match RollbackIncrementalCongruence::with_limits_and_post_validation(
            &problem.terms,
            caps.congruence,
            caps.post_construction_congruence_validation,
        ) {
            Ok(congruence) => congruence,
            Err(CongruenceError::ConstructionAbstained(reason)) => {
                return Err((CadicalUpAbstention::Congruence(reason), stats));
            }
            Err(_) => {
                return Err((
                    CadicalUpAbstention::Internal("constructing incremental congruence"),
                    stats,
                ));
            }
        };
        stats.congruence_construction_ns = phase_start.elapsed().as_nanos();
        let construction_timings = congruence.construction_timings();
        stats.congruence_universe_validation_ns = construction_timings.universe_validation_ns;
        stats.congruence_partition_construction_ns = construction_timings.partition_construction_ns;
        stats.congruence_signature_index_construction_ns =
            construction_timings.signature_index_construction_ns;
        stats.congruence_initial_saturation_ns = construction_timings.initial_saturation_ns;
        stats.congruence_post_construction_validation_ns =
            construction_timings.post_construction_validation_ns;

        if let Some((true_term, false_term)) = problem.boolean_values {
            match congruence.assert_disequality(
                true_term,
                false_term,
                ROOT_BOOLEAN_SEPARATION_REASON,
            ) {
                Ok(ApplyOutcome::Applied(applied)) => {
                    stats.explicit_partition_updates += usize::from(applied.explicit_update);
                    stats.congruence_merges += applied.congruence_merges;
                }
                Ok(ApplyOutcome::Abstained(reason)) => {
                    return Err((CadicalUpAbstention::Congruence(reason), stats));
                }
                Ok(ApplyOutcome::Conflict(_)) => {
                    return Err((
                        CadicalUpAbstention::Malformed(
                            "the distinguished Boolean values cannot be separated",
                        ),
                        stats,
                    ));
                }
                Err(_) => {
                    return Err((
                        CadicalUpAbstention::Internal("asserting Boolean value separation"),
                        stats,
                    ));
                }
            }
        }

        let phase_start = Instant::now();
        let mut theory_atoms = match TheoryAtomIndex::with_caps(problem, caps.theory_atoms) {
            Ok(index) => index,
            Err(error) => return Err((classify_theory_atom_error(error), stats)),
        };
        if caps.propagate_implied_atoms {
            let mark_result = if caps.sparse_root_initialization {
                let reflexive_count = theory_atoms.telemetry().reflexive_equalities;
                let boolean_count = usize::from(problem.boolean_values.is_some()) * 2;
                let capacity = match reflexive_count.checked_add(boolean_count) {
                    Some(capacity) => capacity,
                    None => {
                        return Err((
                            CadicalUpAbstention::Internal("sparse root-frontier size overflowed"),
                            stats,
                        ));
                    }
                };
                let mut root_terms = match try_vec(capacity, "collecting sparse root terms") {
                    Ok(terms) => terms,
                    Err(reason) => return Err((reason, stats)),
                };
                if let Some((true_term, false_term)) = problem.boolean_values {
                    root_terms.push(true_term);
                    root_terms.push(false_term);
                }
                root_terms.extend(problem.atoms.iter().filter_map(|atom| match atom {
                    SemanticAtom::Equality(left, right) if left == right => Some(*left),
                    _ => None,
                }));
                stats.sparse_root_terms = root_terms.len();
                theory_atoms.mark_affected_terms(&root_terms)
            } else {
                theory_atoms.mark_all_terms()
            };
            if let Err(error) = mark_result {
                return Err((classify_theory_atom_error(error), stats));
            }
        }
        stats.theory_atom_index_construction_ns = phase_start.elapsed().as_nanos();

        let phase_start = Instant::now();
        let assignments = match try_filled_box(source_atom_count, None) {
            Ok(values) => values,
            Err(reason) => return Err((reason, stats)),
        };
        let queued_polarities = match try_filled_box(source_atom_count, None) {
            Ok(values) => values,
            Err(reason) => return Err((reason, stats)),
        };
        let reason_tokens = match try_filled_box(source_atom_count, None) {
            Ok(values) => values,
            Err(reason) => return Err((reason, stats)),
        };
        let affected_term_generations = match try_filled_box(problem.terms.len(), 0u32) {
            Ok(values) => values,
            Err(reason) => return Err((reason, stats)),
        };
        stats.adapter_state_allocation_ns = phase_start.elapsed().as_nanos();
        let mut propagator = Self {
            problem,
            source_atom_count,
            caps,
            congruence,
            theory_atoms,
            assignments,
            trail: Vec::new(),
            level_starts: Vec::new(),
            level_snapshots: Vec::new(),
            queued_polarities,
            reason_tokens,
            affected_term_generations,
            affected_generation: 0,
            pending_propagations: VecDeque::new(),
            pending_clauses: VecDeque::new(),
            deferred_merge_start: None,
            deferred_disequality_seeds: Vec::new(),
            deferred_narrow_terms: Vec::new(),
            deferred_partition_updates: 0,
            failure: None,
            fail_closed_emitted: false,
            accepted_model: None,
            stats,
            theory_log: Vec::new(),
        };
        if propagator.caps.propagate_implied_atoms {
            let phase_start = Instant::now();
            if let Err(reason) = propagator.schedule_marked_atoms() {
                let stats = propagator.stats;
                return Err((reason, stats));
            }
            propagator.stats.root_scheduling_ns = phase_start.elapsed().as_nanos();
        }
        Ok(propagator)
    }

    fn finish(mut self, outcome: CadicalUpOutcome) -> CadicalUpReport {
        self.stats.theory_index = self.theory_atoms.telemetry();
        self.stats.signature_index = self.congruence.signature_telemetry();
        CadicalUpReport {
            outcome,
            stats: self.stats,
            theory_log: self.theory_log.into_boxed_slice(),
        }
    }

    fn fail(&mut self, reason: CadicalUpAbstention) {
        if self.failure.is_some() {
            return;
        }
        while let Some(pending) = self.pending_propagations.pop_front() {
            self.queued_polarities[pending.literal.atom().index()] = None;
        }
        self.pending_clauses.clear();
        self.deferred_merge_start = None;
        self.deferred_disequality_seeds.clear();
        self.deferred_narrow_terms.clear();
        self.deferred_partition_updates = 0;
        self.failure = Some(reason);
    }

    fn notify_assignment_inner(&mut self, literals: &[SatLit]) -> Result<(), CadicalUpAbstention> {
        if literals.is_empty() {
            return Ok(());
        }
        let attempted = checked_add(
            self.stats.assignment_notifications,
            literals.len(),
            "assignment notification count overflowed",
        )?;
        check_cap(
            CadicalUpResource::AssignmentNotifications,
            attempted,
            self.caps.max_assignment_notifications,
        )?;
        let mut decoded = if self.caps.allocation_free_assignment_decode {
            None
        } else {
            Some(try_vec(literals.len(), "decoding source assignments")?)
        };
        for &literal in literals {
            let decoded_literal = self.decode_source_literal(literal)?;
            if self.assignments[decoded_literal.atom().index()].is_some() {
                return Err(CadicalUpAbstention::Internal(
                    "CaDiCaL repeated a source assignment without backtracking",
                ));
            }
            if let Some(decoded) = decoded.as_mut() {
                decoded.push(decoded_literal);
            }
        }
        self.trail
            .try_reserve(literals.len())
            .map_err(|_| CadicalUpAbstention::Internal("growing the source trail"))?;

        if let Some(decoded) = decoded.as_ref() {
            for &literal in decoded {
                self.assignments[literal.atom().index()] = Some(literal.is_positive());
                self.trail.push(literal);
            }
        } else {
            for &literal in literals {
                let literal = self.decode_source_literal(literal)?;
                self.assignments[literal.atom().index()] = Some(literal.is_positive());
                self.trail.push(literal);
            }
        }
        self.stats.assignment_batches = checked_add(
            self.stats.assignment_batches,
            1,
            "assignment batch count overflowed",
        )?;
        self.stats.assignment_notifications = attempted;

        if let Some(decoded) = decoded {
            for literal in decoded {
                match self.apply_source_literal(literal)? {
                    SourceApply::Applied => {}
                    SourceApply::Conflict(conflict) => {
                        self.queue_congruence_conflict(&conflict)?;
                        break;
                    }
                }
            }
        } else {
            for &literal in literals {
                let literal = self.decode_source_literal(literal)?;
                match self.apply_source_literal(literal)? {
                    SourceApply::Applied => {}
                    SourceApply::Conflict(conflict) => {
                        self.queue_congruence_conflict(&conflict)?;
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn notify_new_decision_level_inner(&mut self) -> Result<(), CadicalUpAbstention> {
        self.flush_deferred_partition_updates()?;
        let attempted = checked_add(
            self.level_snapshots.len(),
            1,
            "decision level count overflowed",
        )?;
        check_cap(
            CadicalUpResource::DecisionLevels,
            attempted,
            self.caps.max_decision_levels,
        )?;
        self.level_starts
            .try_reserve(1)
            .map_err(|_| CadicalUpAbstention::Internal("growing decision-level trail starts"))?;
        self.level_snapshots
            .try_reserve(1)
            .map_err(|_| CadicalUpAbstention::Internal("growing congruence snapshots"))?;
        self.level_starts.push(self.trail.len());
        self.level_snapshots.push(self.congruence.snapshot());
        self.stats.decision_levels = checked_add(
            self.stats.decision_levels,
            1,
            "decision-level telemetry overflowed",
        )?;
        self.stats.peak_decision_level = self.stats.peak_decision_level.max(attempted);
        Ok(())
    }

    fn notify_backtrack_inner(&mut self, new_level: usize) -> Result<(), CadicalUpAbstention> {
        if new_level >= self.level_snapshots.len()
            || self.level_snapshots.len() != self.level_starts.len()
        {
            return Err(CadicalUpAbstention::Internal(
                "CaDiCaL reported an invalid decision-level backtrack",
            ));
        }
        if !self.pending_clauses.is_empty() {
            self.stats.unadvertised_theory_clauses_dropped = checked_add(
                self.stats.unadvertised_theory_clauses_dropped,
                self.pending_clauses.len(),
                "unadvertised theory clause drop count overflowed",
            )?;
            self.pending_clauses.clear();
        }
        let attempted = checked_add(self.stats.backtracks, 1, "backtrack count overflowed")?;
        check_cap(
            CadicalUpResource::Backtracks,
            attempted,
            self.caps.max_backtracks,
        )?;
        self.clear_pending_propagations();
        self.deferred_merge_start = None;
        self.deferred_disequality_seeds.clear();
        self.deferred_narrow_terms.clear();
        self.deferred_partition_updates = 0;

        let snapshot = self.level_snapshots[new_level];
        let affected = if self.caps.propagate_implied_atoms {
            self.rollback_affected_terms(snapshot)?
        } else {
            Box::new([])
        };
        self.congruence
            .rollback(snapshot)
            .map_err(|_| CadicalUpAbstention::Internal("rolling back incremental congruence"))?;

        let keep = self.level_starts[new_level];
        for literal in self.trail.drain(keep..) {
            self.assignments[literal.atom().index()] = None;
            self.reason_tokens[literal.atom().index()] = None;
        }
        self.level_starts.truncate(new_level);
        self.level_snapshots.truncate(new_level);
        self.stats.backtracks = attempted;

        if !affected.is_empty() {
            self.mark_affected_atoms(&affected)?;
            self.schedule_marked_atoms()?;
        }
        Ok(())
    }

    fn rollback_affected_terms(
        &mut self,
        snapshot: IncrementalCongruenceSnapshot,
    ) -> Result<Box<[TermId]>, CadicalUpAbstention> {
        let depth = snapshot.depth();
        let current = self.congruence.partition().update_count();
        let update_count = current
            .checked_sub(depth)
            .ok_or(CadicalUpAbstention::Internal(
                "rollback snapshot is newer than theory state",
            ))?;
        if update_count == 0 {
            return Ok(Box::new([]));
        }
        let seeds = self
            .congruence
            .partition()
            .update_endpoints_since(depth)
            .map_err(|_| CadicalUpAbstention::Internal("reading rollback impact seeds"))?;
        if seeds.len() != update_count {
            return Err(CadicalUpAbstention::Internal(
                "rollback impact seed count changed",
            ));
        }
        self.compute_impact(&seeds)
    }

    fn apply_source_literal(&mut self, literal: Lit) -> Result<SourceApply, CadicalUpAbstention> {
        let atom = self.problem.atoms.get(literal.atom().index()).ok_or(
            CadicalUpAbstention::Malformed("source assignment references a missing semantic atom"),
        )?;
        let reason = literal_reason(literal)?;
        let (left, right, equal) = match atom {
            SemanticAtom::Equality(left, right) => (*left, *right, literal.is_positive()),
            SemanticAtom::BoolTerm(term) => {
                let (true_term, false_term) =
                    self.problem
                        .boolean_values
                        .ok_or(CadicalUpAbstention::Malformed(
                            "Boolean-term atom has no distinguished Boolean values",
                        ))?;
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
        };
        let merge_start = self.congruence.partition().merge_count();
        let phase_start = self.caps.profile_callback_timings.then(Instant::now);
        let prospective_narrow_terms = if self.caps.narrow_explicit_merge_frontier
            && self.caps.propagate_implied_atoms
            && self.caps.propagate_explicit_equalities
            && equal
        {
            Some(self.prospective_narrow_merge_terms(left, right)?)
        } else {
            None
        };
        if let Some(phase_start) = phase_start {
            self.stats.assignment_frontier_ns = self
                .stats
                .assignment_frontier_ns
                .saturating_add(phase_start.elapsed().as_nanos());
        }
        let phase_start = self.caps.profile_callback_timings.then(Instant::now);
        let outcome = if equal {
            self.congruence.assert_equality(left, right, reason)
        } else {
            self.congruence.assert_disequality(left, right, reason)
        }
        .map_err(|_| CadicalUpAbstention::Internal("applying a source theory literal"))?;
        if let Some(phase_start) = phase_start {
            let elapsed = phase_start.elapsed().as_nanos();
            self.stats.assignment_congruence_ns =
                self.stats.assignment_congruence_ns.saturating_add(elapsed);
            if equal {
                self.stats.assignment_equality_congruence_ns = self
                    .stats
                    .assignment_equality_congruence_ns
                    .saturating_add(elapsed);
            } else {
                self.stats.assignment_disequality_congruence_ns = self
                    .stats
                    .assignment_disequality_congruence_ns
                    .saturating_add(elapsed);
            }
        }
        self.stats.source_assignments_applied = checked_add(
            self.stats.source_assignments_applied,
            1,
            "applied source assignment count overflowed",
        )?;
        if equal {
            self.stats.source_equality_assignments = checked_add(
                self.stats.source_equality_assignments,
                1,
                "source equality assignment count overflowed",
            )?;
        } else {
            self.stats.source_disequality_assignments = checked_add(
                self.stats.source_disequality_assignments,
                1,
                "source disequality assignment count overflowed",
            )?;
        }

        let phase_start = self.caps.profile_callback_timings.then(Instant::now);
        let result = match outcome {
            ApplyOutcome::Abstained(reason) => Err(CadicalUpAbstention::Congruence(reason)),
            ApplyOutcome::Conflict(conflict) => Ok(SourceApply::Conflict(conflict)),
            ApplyOutcome::Applied(applied) => {
                self.stats.explicit_partition_updates = checked_add(
                    self.stats.explicit_partition_updates,
                    usize::from(applied.explicit_update),
                    "explicit partition update count overflowed",
                )?;
                self.stats.congruence_merges = checked_add(
                    self.stats.congruence_merges,
                    applied.congruence_merges,
                    "congruence merge count overflowed",
                )?;
                if self.caps.propagate_implied_atoms {
                    let relevant_explicit = applied.explicit_update
                        && if equal {
                            self.caps.propagate_explicit_equalities
                        } else {
                            self.caps.propagate_explicit_disequalities
                        };
                    let relevant_updates = checked_add(
                        usize::from(relevant_explicit),
                        applied.congruence_merges,
                        "deferred partition update count overflowed",
                    )?;
                    if relevant_updates != 0 {
                        if relevant_explicit
                            && equal
                            && applied.congruence_merges == 0
                            && self.caps.narrow_explicit_merge_frontier
                        {
                            self.defer_narrow_partition_update(prospective_narrow_terms.ok_or(
                                CadicalUpAbstention::Internal(
                                    "missing a prospective explicit-merge frontier",
                                ),
                            )?)?;
                        } else {
                            let disequality_seed = relevant_explicit
                                .then_some((left, right))
                                .filter(|_| !equal);
                            self.defer_partition_update(
                                merge_start,
                                disequality_seed,
                                relevant_updates,
                            )?;
                        }
                    }
                }
                Ok(SourceApply::Applied)
            }
        };
        if let Some(phase_start) = phase_start {
            self.stats.assignment_post_update_ns = self
                .stats
                .assignment_post_update_ns
                .saturating_add(phase_start.elapsed().as_nanos());
        }
        result
    }

    fn prospective_narrow_merge_terms(
        &self,
        left: TermId,
        right: TermId,
    ) -> Result<Vec<TermId>, CadicalUpAbstention> {
        let partition = self.congruence.partition();
        let (kept, mut terms) = match partition
            .prospective_merge_incidence_terms(
                left,
                right,
                self.caps.max_narrow_neighbor_classes,
                self.caps.max_deferred_narrow_terms,
            )
            .map_err(|_| {
                CadicalUpAbstention::Internal("computing a prospective explicit-merge frontier")
            })? {
            ProspectiveMergeIncidenceOutcome::Complete { kept, terms } => (kept, terms),
            ProspectiveMergeIncidenceOutcome::LimitExceeded {
                resource,
                attempted,
                limit,
            } => {
                let resource = match resource {
                    ProspectiveMergeIncidenceResource::NeighborClasses => {
                        CadicalUpResource::NarrowNeighborClasses
                    }
                    ProspectiveMergeIncidenceResource::Terms => {
                        CadicalUpResource::DeferredNarrowTerms
                    }
                };
                return Err(CadicalUpAbstention::CapExceeded {
                    resource,
                    attempted,
                    limit,
                });
            }
        };

        if self.theory_atoms.telemetry().boolean_term_atoms != 0 {
            if let Some((true_term, false_term)) = self.problem.boolean_values {
                let touches_boolean_value = terms.binary_search(&true_term).is_ok()
                    || terms.binary_search(&false_term).is_ok();
                if touches_boolean_value {
                    let kept_size = partition.class_size(kept).map_err(|_| {
                        CadicalUpAbstention::Internal("reading the kept Boolean merge class size")
                    })?;
                    let attempted = checked_add(
                        terms.len(),
                        kept_size,
                        "Boolean-observable merge frontier size overflowed",
                    )?;
                    check_cap(
                        CadicalUpResource::DeferredNarrowTerms,
                        attempted,
                        self.caps.max_deferred_narrow_terms,
                    )?;
                    let mut kept_members = partition.class_members(kept).map_err(|_| {
                        CadicalUpAbstention::Internal("collecting the kept Boolean merge class")
                    })?;
                    terms.try_reserve(kept_members.len()).map_err(|_| {
                        CadicalUpAbstention::Internal("growing a Boolean-observable merge frontier")
                    })?;
                    terms.append(&mut kept_members);
                    terms.sort_unstable();
                    terms.dedup();
                }
            }
        }
        Ok(terms)
    }

    fn defer_partition_update(
        &mut self,
        merge_start: usize,
        disequality_seed: Option<(TermId, TermId)>,
        update_count: usize,
    ) -> Result<(), CadicalUpAbstention> {
        if self.deferred_merge_start.is_none() {
            self.deferred_merge_start = Some(merge_start);
        }
        if let Some(seed) = disequality_seed {
            self.deferred_disequality_seeds
                .try_reserve(1)
                .map_err(|_| CadicalUpAbstention::Internal("growing deferred theory seeds"))?;
            self.deferred_disequality_seeds.push(seed);
        }
        self.deferred_partition_updates = checked_add(
            self.deferred_partition_updates,
            update_count,
            "deferred partition update count overflowed",
        )?;
        if !self.caps.demand_driven_propagation_flush
            && self.deferred_partition_updates >= self.caps.propagation_batch_updates
        {
            self.flush_deferred_partition_updates()?;
        }
        Ok(())
    }

    fn defer_narrow_partition_update(
        &mut self,
        mut terms: Vec<TermId>,
    ) -> Result<(), CadicalUpAbstention> {
        let term_count = terms.len();
        let attempted = checked_add(
            self.deferred_narrow_terms.len(),
            term_count,
            "deferred narrow-frontier term count overflowed",
        )?;
        check_cap(
            CadicalUpResource::DeferredNarrowTerms,
            attempted,
            self.caps.max_deferred_narrow_terms,
        )?;
        self.deferred_narrow_terms
            .try_reserve(terms.len())
            .map_err(|_| CadicalUpAbstention::Internal("growing narrow merge frontiers"))?;
        self.deferred_narrow_terms.append(&mut terms);
        self.deferred_partition_updates = checked_add(
            self.deferred_partition_updates,
            1,
            "deferred partition update count overflowed",
        )?;
        self.stats.narrow_merge_frontiers = checked_add(
            self.stats.narrow_merge_frontiers,
            1,
            "narrow merge-frontier count overflowed",
        )?;
        self.stats.narrow_frontier_terms = checked_add(
            self.stats.narrow_frontier_terms,
            term_count,
            "narrow merge-frontier term telemetry overflowed",
        )?;
        if !self.caps.demand_driven_propagation_flush
            && self.deferred_partition_updates >= self.caps.propagation_batch_updates
        {
            self.flush_deferred_partition_updates()?;
        }
        Ok(())
    }

    fn flush_deferred_partition_updates(&mut self) -> Result<(), CadicalUpAbstention> {
        let merge_start = self.deferred_merge_start.take();
        if merge_start.is_none() && self.deferred_narrow_terms.is_empty() {
            return Ok(());
        }
        let mut disequality_seeds = std::mem::take(&mut self.deferred_disequality_seeds);
        let mut narrow_terms = std::mem::take(&mut self.deferred_narrow_terms);
        self.deferred_partition_updates = 0;
        let result = (|| {
            if let Some(merge_start) = merge_start {
                self.mark_partition_update(merge_start, &disequality_seeds)?;
            } else if !disequality_seeds.is_empty() {
                return Err(CadicalUpAbstention::Internal(
                    "deferred disequality seeds have no merge-history start",
                ));
            }
            if !narrow_terms.is_empty() {
                self.mark_incident_atoms(&narrow_terms, false)?;
            }
            self.schedule_marked_atoms()
        })();
        disequality_seeds.clear();
        narrow_terms.clear();
        self.deferred_disequality_seeds = disequality_seeds;
        self.deferred_narrow_terms = narrow_terms;
        result
    }

    fn mark_partition_update(
        &mut self,
        merge_start: usize,
        explicit_seeds: &[(TermId, TermId)],
    ) -> Result<(), CadicalUpAbstention> {
        let records = self.congruence.partition().merge_records();
        let new_records = records
            .get(merge_start..)
            .ok_or(CadicalUpAbstention::Internal(
                "partition merge history shrank during scheduling",
            ))?;
        let capacity = new_records.len().checked_add(explicit_seeds.len()).ok_or(
            CadicalUpAbstention::Internal("theory impact seed count overflowed"),
        )?;
        if capacity == 0 {
            return Ok(());
        }
        let mut seeds = try_vec(capacity, "collecting theory impact seeds")?;
        seeds.extend(
            new_records
                .iter()
                .filter(|record| {
                    self.caps.propagate_explicit_equalities
                        || record.reason == CONGRUENCE_PARTITION_REASON
                })
                .map(|record| (record.left, record.right)),
        );
        seeds.extend_from_slice(explicit_seeds);
        if seeds.is_empty() {
            return Ok(());
        }
        let affected = self.compute_impact(&seeds)?;
        self.mark_affected_atoms(&affected)
    }

    fn mark_affected_atoms(&mut self, affected: &[TermId]) -> Result<(), CadicalUpAbstention> {
        self.mark_incident_atoms(affected, self.caps.pair_filtered_impact_atoms)
    }

    fn mark_incident_atoms(
        &mut self,
        affected: &[TermId],
        pair_filtered: bool,
    ) -> Result<(), CadicalUpAbstention> {
        if pair_filtered {
            self.affected_generation = match self.affected_generation.checked_add(1) {
                Some(generation) => generation,
                None => {
                    self.affected_term_generations.fill(0);
                    1
                }
            };
            for &term in affected {
                let slot = self.affected_term_generations.get_mut(term.index()).ok_or(
                    CadicalUpAbstention::Internal("impact frontier contains an out-of-range term"),
                )?;
                *slot = self.affected_generation;
            }
        }
        let assignments = &self.assignments;
        let problem = self.problem;
        let generations = &self.affected_term_generations;
        let generation = self.affected_generation;
        self.theory_atoms
            .mark_affected_terms_where(affected, |atom| {
                assignments[atom.index()].is_none()
                    && (!pair_filtered
                        || atom_relation_may_change(problem, atom, generations, generation))
            })
            .map_err(classify_theory_atom_error)?;
        Ok(())
    }

    fn compute_impact(
        &mut self,
        seeds: &[(TermId, TermId)],
    ) -> Result<Box<[TermId]>, CadicalUpAbstention> {
        match impact::affected_terms_with_member_index(
            self.congruence.partition(),
            seeds,
            self.caps.impact,
            self.caps.indexed_class_members,
        )
        .map_err(classify_impact_error)?
        {
            ImpactOutcome::Abstained { limit, stats } => {
                self.accumulate_impact(stats)?;
                Err(CadicalUpAbstention::Impact(limit))
            }
            ImpactOutcome::Complete { terms, stats } => {
                self.accumulate_impact(stats)?;
                Ok(terms)
            }
        }
    }

    fn accumulate_impact(&mut self, impact: ImpactStats) -> Result<(), CadicalUpAbstention> {
        self.stats.impact_calls =
            checked_add(self.stats.impact_calls, 1, "impact call count overflowed")?;
        self.stats.impact_seed_relations = checked_add(
            self.stats.impact_seed_relations,
            impact.seed_relations,
            "impact seed telemetry overflowed",
        )?;
        self.stats.impact_neighbor_edges = checked_add(
            self.stats.impact_neighbor_edges,
            impact.neighbor_edges,
            "impact neighbor telemetry overflowed",
        )?;
        self.stats.impact_class_member_visits = checked_add(
            self.stats.impact_class_member_visits,
            impact.class_member_visits,
            "impact member telemetry overflowed",
        )?;
        self.stats.impact_affected_terms = checked_add(
            self.stats.impact_affected_terms,
            impact.affected_terms,
            "impact affected-term telemetry overflowed",
        )?;
        Ok(())
    }

    fn schedule_marked_atoms(&mut self) -> Result<(), CadicalUpAbstention> {
        let pending = self
            .theory_atoms
            .take_pending()
            .map_err(classify_theory_atom_error)?;
        if !self.caps.propagate_implied_atoms {
            return Ok(());
        }
        let attempted = checked_add(
            self.stats.atom_evaluations,
            pending.len(),
            "theory atom evaluation count overflowed",
        )?;
        check_cap(
            CadicalUpResource::AtomEvaluations,
            attempted,
            self.caps.max_atom_evaluations,
        )?;
        self.stats.atom_evaluations = attempted;

        for atom in pending {
            if atom.index() >= self.source_atom_count {
                return Err(CadicalUpAbstention::Internal(
                    "theory atom index scheduled a native auxiliary",
                ));
            }
            if self.assignments[atom.index()].is_some() {
                continue;
            }
            let Some(literal) = self.implied_source_literal(atom)? else {
                continue;
            };
            if let Some(queued) = self.queued_polarities[atom.index()] {
                if queued != literal.is_positive() {
                    return Err(CadicalUpAbstention::Internal(
                        "opposite theory propagations were queued for one atom",
                    ));
                }
                continue;
            }
            let eager_reason = if self.caps.lazy_propagation_reasons {
                None
            } else {
                Some(self.build_propagation_reason(literal)?)
            };
            let queue_size = checked_add(
                self.pending_propagations.len(),
                1,
                "pending propagation count overflowed",
            )?;
            check_cap(
                CadicalUpResource::PendingPropagations,
                queue_size,
                self.caps.max_pending_propagations,
            )?;
            self.pending_propagations
                .try_reserve(1)
                .map_err(|_| CadicalUpAbstention::Internal("growing pending propagations"))?;
            self.pending_propagations.push_back(PendingPropagation {
                literal,
                eager_reason,
            });
            self.queued_polarities[atom.index()] = Some(literal.is_positive());
            self.stats.propagation_candidates = checked_add(
                self.stats.propagation_candidates,
                1,
                "propagation candidate count overflowed",
            )?;
        }
        Ok(())
    }

    fn implied_source_literal(&self, atom: AtomId) -> Result<Option<Lit>, CadicalUpAbstention> {
        let semantic =
            self.problem
                .atoms
                .get(atom.index())
                .ok_or(CadicalUpAbstention::Malformed(
                    "theory atom index references a missing atom",
                ))?;
        let positive = match semantic {
            SemanticAtom::Equality(left, right) => match self
                .congruence
                .relation(*left, *right)
                .map_err(|_| CadicalUpAbstention::Internal("querying an equality atom"))?
            {
                Relation::Equal => Some(true),
                Relation::Disequal => Some(false),
                Relation::Unknown => None,
            },
            SemanticAtom::BoolTerm(term) => self.implied_boolean_value(*term)?,
        };
        Ok(positive.map(|value| {
            if value {
                Lit::positive(atom)
            } else {
                Lit::negative(atom)
            }
        }))
    }

    fn implied_boolean_value(&self, term: TermId) -> Result<Option<bool>, CadicalUpAbstention> {
        let (true_term, false_term) =
            self.problem
                .boolean_values
                .ok_or(CadicalUpAbstention::Malformed(
                    "Boolean-term atom has no distinguished Boolean values",
                ))?;
        let to_true = self
            .congruence
            .relation(term, true_term)
            .map_err(|_| CadicalUpAbstention::Internal("querying Boolean true relation"))?;
        let to_false = self
            .congruence
            .relation(term, false_term)
            .map_err(|_| CadicalUpAbstention::Internal("querying Boolean false relation"))?;
        Ok(
            if to_true == Relation::Equal || to_false == Relation::Disequal {
                Some(true)
            } else if to_false == Relation::Equal || to_true == Relation::Disequal {
                Some(false)
            } else {
                None
            },
        )
    }

    fn build_propagation_reason(
        &self,
        literal: Lit,
    ) -> Result<(Box<[Lit]>, Box<[ReasonId]>), CadicalUpAbstention> {
        let semantic = self.problem.atoms.get(literal.atom().index()).ok_or(
            CadicalUpAbstention::Malformed("propagation references a missing semantic atom"),
        )?;
        let reasons = match semantic {
            SemanticAtom::Equality(left, right) if literal.is_positive() => self
                .equality_reasons(*left, *right)?
                .ok_or(CadicalUpAbstention::Internal(
                    "an implied equality has no explanation",
                ))?,
            SemanticAtom::Equality(left, right) => {
                self.disequality_reasons(*left, *right)?
                    .ok_or(CadicalUpAbstention::Internal(
                        "an implied disequality has no explanation",
                    ))?
            }
            SemanticAtom::BoolTerm(term) => {
                self.boolean_reasons(*term, literal.is_positive())?.ok_or(
                    CadicalUpAbstention::Internal("an implied Boolean term has no explanation"),
                )?
            }
        };
        self.propagation_clause_from_reasons(literal, reasons)
    }

    fn build_reason_token(
        &self,
        literal: Lit,
    ) -> Result<PropagationReasonToken, CadicalUpAbstention> {
        let semantic = self.problem.atoms.get(literal.atom().index()).ok_or(
            CadicalUpAbstention::Malformed("propagation references a missing semantic atom"),
        )?;
        let witness = match semantic {
            SemanticAtom::Equality(left, right) if literal.is_positive() => {
                HistoricalReasonWitness::Equality {
                    left: *left,
                    right: *right,
                }
            }
            SemanticAtom::Equality(left, right) => {
                self.select_disequality_witness(*left, *right)?
            }
            SemanticAtom::BoolTerm(term) => {
                self.select_boolean_witness(*term, literal.is_positive())?
            }
        };
        Ok(PropagationReasonToken {
            literal,
            snapshot: self.congruence.snapshot(),
            witness,
        })
    }

    fn select_boolean_witness(
        &self,
        term: TermId,
        value: bool,
    ) -> Result<HistoricalReasonWitness, CadicalUpAbstention> {
        let (true_term, false_term) =
            self.problem
                .boolean_values
                .ok_or(CadicalUpAbstention::Malformed(
                    "Boolean-term atom has no distinguished Boolean values",
                ))?;
        let to_true = self
            .congruence
            .relation(term, true_term)
            .map_err(|_| CadicalUpAbstention::Internal("querying Boolean true relation"))?;
        let to_false = self
            .congruence
            .relation(term, false_term)
            .map_err(|_| CadicalUpAbstention::Internal("querying Boolean false relation"))?;
        let witness = if value {
            if to_true == Relation::Equal {
                Some(HistoricalReasonWitness::Equality {
                    left: term,
                    right: true_term,
                })
            } else if to_false == Relation::Disequal {
                Some(self.select_disequality_witness(term, false_term)?)
            } else {
                None
            }
        } else if to_false == Relation::Equal {
            Some(HistoricalReasonWitness::Equality {
                left: term,
                right: false_term,
            })
        } else if to_true == Relation::Disequal {
            Some(self.select_disequality_witness(term, true_term)?)
        } else {
            None
        };
        witness.ok_or(CadicalUpAbstention::Internal(
            "an implied Boolean term has no historical witness",
        ))
    }

    fn select_disequality_witness(
        &self,
        left: TermId,
        right: TermId,
    ) -> Result<HistoricalReasonWitness, CadicalUpAbstention> {
        let Some(mut witnesses) = self
            .congruence
            .partition()
            .separation_witnesses(left, right)
            .map_err(|_| CadicalUpAbstention::Internal("reading disequality witnesses"))?
        else {
            return Err(CadicalUpAbstention::Internal(
                "an implied disequality has no explicit witness",
            ));
        };
        witnesses.sort_by_key(|witness| (witness.reason, witness.left, witness.right));
        for separation in witnesses {
            let direct = self.relation_is_equal(left, separation.left)?
                && self.relation_is_equal(right, separation.right)?;
            let swapped = self.relation_is_equal(left, separation.right)?
                && self.relation_is_equal(right, separation.left)?;
            let (left_witness, right_witness) = if direct {
                (separation.left, separation.right)
            } else if swapped {
                (separation.right, separation.left)
            } else {
                continue;
            };
            return Ok(HistoricalReasonWitness::Disequality {
                left,
                right,
                left_witness,
                right_witness,
                separation,
            });
        }
        Err(CadicalUpAbstention::Internal(
            "no disequality witness aligns with the queried classes",
        ))
    }

    fn expand_reason_token(
        &self,
        token: PropagationReasonToken,
    ) -> Result<(Box<[Lit]>, Box<[ReasonId]>), CadicalUpAbstention> {
        let reasons = match token.witness {
            HistoricalReasonWitness::Equality { left, right } => self
                .equality_reasons_at(left, right, token.snapshot)?
                .ok_or(CadicalUpAbstention::Internal(
                    "historically implied equality has no bounded explanation",
                ))?,
            HistoricalReasonWitness::Disequality {
                left,
                right,
                left_witness,
                right_witness,
                separation,
            } => {
                if separation.reason == ROOT_BOOLEAN_SEPARATION_REASON
                    && !self.is_boolean_separation(separation.left, separation.right)
                {
                    return Err(CadicalUpAbstention::Internal(
                        "the reserved Boolean reason labels another separation",
                    ));
                }
                let mut reasons = Vec::new();
                if separation.reason != ROOT_BOOLEAN_SEPARATION_REASON {
                    reasons.push(separation.reason);
                }
                let left_reasons = self
                    .equality_reasons_at(left, left_witness, token.snapshot)?
                    .ok_or(CadicalUpAbstention::Internal(
                        "historical disequality witness lost its left equality",
                    ))?;
                let right_reasons = self
                    .equality_reasons_at(right, right_witness, token.snapshot)?
                    .ok_or(CadicalUpAbstention::Internal(
                        "historical disequality witness lost its right equality",
                    ))?;
                reasons.extend(left_reasons);
                reasons.extend(right_reasons);
                self.canonical_explicit_reasons(reasons)?
            }
        };
        self.propagation_clause_from_reasons(token.literal, reasons)
    }

    fn propagation_clause_from_reasons(
        &self,
        literal: Lit,
        reasons: Vec<ReasonId>,
    ) -> Result<(Box<[Lit]>, Box<[ReasonId]>), CadicalUpAbstention> {
        let antecedents = self.active_literals_for_reasons(&reasons)?;
        if antecedents.contains(&literal) {
            return Err(CadicalUpAbstention::Internal(
                "a theory propagation depends on its own conclusion",
            ));
        }
        if antecedents.contains(&literal.negate()) {
            return Err(CadicalUpAbstention::Internal(
                "a theory propagation contradicts an active antecedent",
            ));
        }
        let clause_len = antecedents
            .len()
            .checked_add(1)
            .ok_or(CadicalUpAbstention::Internal(
                "theory propagation clause length overflowed",
            ))?;
        check_cap(
            CadicalUpResource::TheoryClauseLiterals,
            clause_len,
            self.caps.max_theory_clause_literals,
        )?;
        let mut clause = try_vec(clause_len, "building a theory propagation clause")?;
        clause.push(literal);
        clause.extend(antecedents.into_iter().map(Lit::negate));
        let clause = canonical_clause(clause)?;
        Ok((clause, reasons.into_boxed_slice()))
    }

    fn equality_reasons_at(
        &self,
        left: TermId,
        right: TermId,
        snapshot: IncrementalCongruenceSnapshot,
    ) -> Result<Option<Vec<ReasonId>>, CadicalUpAbstention> {
        match self
            .congruence
            .explain_equal_at(left, right, snapshot)
            .map_err(|_| CadicalUpAbstention::Internal("explaining a historical equality"))?
        {
            ExplanationOutcome::NotEqual => Ok(None),
            ExplanationOutcome::Abstained(reason) => Err(CadicalUpAbstention::Congruence(reason)),
            ExplanationOutcome::Explained(reasons) => {
                let reasons = self.canonical_explicit_reasons(reasons)?;
                Ok(Some(reasons))
            }
        }
    }

    fn equality_reasons(
        &self,
        left: TermId,
        right: TermId,
    ) -> Result<Option<Vec<ReasonId>>, CadicalUpAbstention> {
        match self
            .congruence
            .explain_equal(left, right)
            .map_err(|_| CadicalUpAbstention::Internal("explaining a congruence equality"))?
        {
            ExplanationOutcome::NotEqual => Ok(None),
            ExplanationOutcome::Abstained(reason) => Err(CadicalUpAbstention::Congruence(reason)),
            ExplanationOutcome::Explained(reasons) => {
                let reasons = self.canonical_explicit_reasons(reasons)?;
                Ok(Some(reasons))
            }
        }
    }

    fn disequality_reasons(
        &self,
        left: TermId,
        right: TermId,
    ) -> Result<Option<Vec<ReasonId>>, CadicalUpAbstention> {
        let Some(mut witnesses) = self
            .congruence
            .partition()
            .separation_witnesses(left, right)
            .map_err(|_| CadicalUpAbstention::Internal("reading disequality witnesses"))?
        else {
            return Ok(None);
        };
        witnesses.sort_by_key(|witness| (witness.reason, witness.left, witness.right));
        let mut best: Option<Vec<ReasonId>> = None;
        for witness in witnesses {
            let direct = self.relation_is_equal(left, witness.left)?
                && self.relation_is_equal(right, witness.right)?;
            let swapped = self.relation_is_equal(left, witness.right)?
                && self.relation_is_equal(right, witness.left)?;
            let (left_witness, right_witness) = if direct {
                (witness.left, witness.right)
            } else if swapped {
                (witness.right, witness.left)
            } else {
                return Err(CadicalUpAbstention::Internal(
                    "disequality witness does not align with queried classes",
                ));
            };

            let mut reasons = Vec::new();
            if witness.reason == ROOT_BOOLEAN_SEPARATION_REASON {
                if !self.is_boolean_separation(witness.left, witness.right) {
                    return Err(CadicalUpAbstention::Internal(
                        "the reserved Boolean reason labels another separation",
                    ));
                }
            } else {
                reasons.push(witness.reason);
            }
            let Some(left_reasons) = self.equality_reasons(left, left_witness)? else {
                return Err(CadicalUpAbstention::Internal(
                    "disequality witness lacks its left equality explanation",
                ));
            };
            let Some(right_reasons) = self.equality_reasons(right, right_witness)? else {
                return Err(CadicalUpAbstention::Internal(
                    "disequality witness lacks its right equality explanation",
                ));
            };
            reasons.extend(left_reasons);
            reasons.extend(right_reasons);
            let candidate = self.canonical_explicit_reasons(reasons)?;
            if best.as_ref().is_none_or(|current| {
                candidate.len() < current.len()
                    || (candidate.len() == current.len() && candidate < *current)
            }) {
                best = Some(candidate);
            }
        }
        Ok(best)
    }

    fn boolean_reasons(
        &self,
        term: TermId,
        value: bool,
    ) -> Result<Option<Vec<ReasonId>>, CadicalUpAbstention> {
        let (true_term, false_term) =
            self.problem
                .boolean_values
                .ok_or(CadicalUpAbstention::Malformed(
                    "Boolean-term atom has no distinguished Boolean values",
                ))?;
        let to_true = self
            .congruence
            .relation(term, true_term)
            .map_err(|_| CadicalUpAbstention::Internal("querying Boolean true relation"))?;
        let to_false = self
            .congruence
            .relation(term, false_term)
            .map_err(|_| CadicalUpAbstention::Internal("querying Boolean false relation"))?;
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
        let mut best: Option<Vec<ReasonId>> = None;
        for (available, equality, target) in routes {
            if !available {
                continue;
            }
            let Some(candidate) = (if equality {
                self.equality_reasons(term, target)?
            } else {
                self.disequality_reasons(term, target)?
            }) else {
                continue;
            };
            if best.as_ref().is_none_or(|current| {
                candidate.len() < current.len()
                    || (candidate.len() == current.len() && candidate < *current)
            }) {
                best = Some(candidate);
            }
        }
        Ok(best)
    }

    fn canonical_explicit_reasons(
        &self,
        reasons: Vec<ReasonId>,
    ) -> Result<Vec<ReasonId>, CadicalUpAbstention> {
        let mut canonical = BTreeSet::new();
        for reason in reasons {
            if reason == ROOT_BOOLEAN_SEPARATION_REASON {
                return Err(CadicalUpAbstention::Internal(
                    "the Boolean separation reason appeared in an equality proof",
                ));
            }
            if reason == ReasonId::MAX {
                return Err(CadicalUpAbstention::Internal(
                    "a derived partition marker escaped into an explanation",
                ));
            }
            canonical.insert(reason);
            check_cap(
                CadicalUpResource::ReasonAntecedents,
                canonical.len(),
                self.caps.max_reason_antecedents,
            )?;
        }
        let mut output = try_vec(canonical.len(), "canonicalizing explicit reasons")?;
        output.extend(canonical);
        Ok(output)
    }

    fn active_literals_for_reasons(
        &self,
        reasons: &[ReasonId],
    ) -> Result<BTreeSet<Lit>, CadicalUpAbstention> {
        let mut literals = BTreeSet::new();
        for &reason in reasons {
            let literal = literal_from_reason(reason, self.source_atom_count).ok_or(
                CadicalUpAbstention::Internal("theory explanation contains an unknown reason"),
            )?;
            if self.assignments[literal.atom().index()] != Some(literal.is_positive()) {
                return Err(CadicalUpAbstention::Internal(
                    "theory explanation contains an inactive source reason",
                ));
            }
            if literals.contains(&literal.negate()) {
                return Err(CadicalUpAbstention::Internal(
                    "theory explanation antecedents are contradictory",
                ));
            }
            literals.insert(literal);
        }
        Ok(literals)
    }

    fn queue_congruence_conflict(
        &mut self,
        conflict: &CongruenceConflict,
    ) -> Result<(), CadicalUpAbstention> {
        let mut reasons = BTreeSet::new();
        for &reason in conflict
            .equality_reasons
            .iter()
            .chain(conflict.disequality_reasons.iter())
        {
            if reason == ROOT_BOOLEAN_SEPARATION_REASON {
                continue;
            }
            if reason == ReasonId::MAX
                || literal_from_reason(reason, self.source_atom_count).is_none()
            {
                return Err(CadicalUpAbstention::Internal(
                    "congruence conflict contains a non-source explicit reason",
                ));
            }
            reasons.insert(reason);
            check_cap(
                CadicalUpResource::ReasonAntecedents,
                reasons.len(),
                self.caps.max_reason_antecedents,
            )?;
        }
        let mut reason_list = try_vec(reasons.len(), "canonicalizing conflict reasons")?;
        reason_list.extend(reasons);
        let antecedents = self.active_literals_for_reasons(&reason_list)?;
        let mut clause = try_vec(antecedents.len(), "building a theory conflict clause")?;
        clause.extend(antecedents.into_iter().map(Lit::negate));
        let clause = canonical_clause(clause)?;
        self.queue_external_clause(
            TheoryClauseKind::Conflict,
            clause,
            reason_list.into_boxed_slice(),
        )
    }

    fn queue_external_clause(
        &mut self,
        kind: TheoryClauseKind,
        clause: Box<[Lit]>,
        antecedent_reasons: Box<[ReasonId]>,
    ) -> Result<(), CadicalUpAbstention> {
        check_cap(
            CadicalUpResource::TheoryClauseLiterals,
            clause.len(),
            self.caps.max_theory_clause_literals,
        )?;
        self.validate_false_clause(&clause)?;
        if !self.pending_clauses.is_empty() {
            if kind != TheoryClauseKind::Conflict {
                return Err(CadicalUpAbstention::Internal(
                    "a non-conflict clause was queued behind an unresolved theory conflict",
                ));
            }
            self.stats.coalesced_theory_conflicts = checked_add(
                self.stats.coalesced_theory_conflicts,
                1,
                "coalesced theory conflict count overflowed",
            )?;
            return Ok(());
        }
        let attempted = checked_add(
            self.pending_clauses.len(),
            1,
            "pending external clause count overflowed",
        )?;
        check_cap(
            CadicalUpResource::PendingExternalClauses,
            attempted,
            self.caps.max_pending_external_clauses,
        )?;
        self.pending_clauses
            .try_reserve(1)
            .map_err(|_| CadicalUpAbstention::Internal("growing pending external clauses"))?;
        self.pending_clauses.push_back(PendingClause {
            kind,
            clause,
            antecedent_reasons,
        });
        Ok(())
    }

    fn validate_false_clause(&self, clause: &[Lit]) -> Result<(), CadicalUpAbstention> {
        for &literal in clause {
            if self.assignments[literal.atom().index()] != Some(!literal.is_positive()) {
                return Err(CadicalUpAbstention::Internal(
                    "an external theory clause is not false on the active trail",
                ));
            }
        }
        Ok(())
    }

    fn emit_propagation(&mut self) -> Result<Option<ExternalPropagation>, CadicalUpAbstention> {
        if !self.pending_clauses.is_empty() {
            return Ok(None);
        }
        self.flush_deferred_partition_updates()?;
        while let Some(pending) = self.pending_propagations.pop_front() {
            self.queued_polarities[pending.literal.atom().index()] = None;
            if self.assignments[pending.literal.atom().index()].is_some() {
                continue;
            }
            if self.implied_source_literal(pending.literal.atom())? != Some(pending.literal) {
                return Err(CadicalUpAbstention::Internal(
                    "a queued theory propagation became stale without backtracking",
                ));
            }
            let attempted = checked_add(
                self.stats.theory_propagations,
                1,
                "theory propagation count overflowed",
            )?;
            check_cap(
                CadicalUpResource::TheoryPropagations,
                attempted,
                self.caps.max_theory_propagations,
            )?;
            self.stats.theory_propagations = attempted;
            if let Some((clause, antecedent_reasons)) = pending.eager_reason {
                self.validate_propagation_clause(pending.literal, &clause)?;
                let sat_clause = sat_literals(&clause)?;
                self.record_theory_clause(
                    TheoryClauseKind::Propagation {
                        literal: pending.literal,
                    },
                    &clause,
                    &antecedent_reasons,
                )?;
                return Ok(Some(ExternalPropagation::new(
                    to_sat_lit(pending.literal),
                    sat_clause,
                )));
            }

            let token = self.build_reason_token(pending.literal)?;
            self.reason_tokens[pending.literal.atom().index()] = Some(token);
            return Ok(Some(ExternalPropagation::lazy(to_sat_lit(pending.literal))));
        }
        Ok(None)
    }

    fn provide_lazy_reason_inner(
        &mut self,
        propagated: SatLit,
    ) -> Result<Vec<SatLit>, CadicalUpAbstention> {
        let literal = self.decode_source_literal(propagated)?;
        if self.assignments[literal.atom().index()] == Some(!literal.is_positive()) {
            return Err(CadicalUpAbstention::Internal(
                "CaDiCaL requested a lazy reason for an oppositely assigned propagation",
            ));
        }
        let token = self.reason_tokens[literal.atom().index()].ok_or(
            CadicalUpAbstention::Internal("CaDiCaL requested an unknown lazy propagation reason"),
        )?;
        if token.literal != literal {
            return Err(CadicalUpAbstention::Internal(
                "CaDiCaL requested a lazy reason with the wrong polarity",
            ));
        }
        let (clause, antecedent_reasons) = self.expand_reason_token(token)?;
        self.validate_propagation_clause(literal, &clause)?;
        let sat_clause = sat_literals(&clause)?;
        self.record_theory_clause(
            TheoryClauseKind::Propagation { literal },
            &clause,
            &antecedent_reasons,
        )?;
        self.stats.lazy_reason_requests = checked_add(
            self.stats.lazy_reason_requests,
            1,
            "lazy reason request count overflowed",
        )?;
        Ok(sat_clause)
    }

    fn validate_propagation_clause(
        &self,
        conclusion: Lit,
        clause: &[Lit],
    ) -> Result<(), CadicalUpAbstention> {
        let mut found = false;
        for &literal in clause {
            if literal == conclusion {
                found = true;
            } else if self.assignments[literal.atom().index()] != Some(!literal.is_positive()) {
                return Err(CadicalUpAbstention::Internal(
                    "a propagation reason is not unit on the active trail",
                ));
            }
        }
        if !found {
            return Err(CadicalUpAbstention::Internal(
                "a propagation reason omits its conclusion",
            ));
        }
        Ok(())
    }

    fn emit_external_clause(&mut self) -> Result<Option<ExternalClause>, CadicalUpAbstention> {
        let Some(pending) = self.pending_clauses.pop_front() else {
            return Ok(None);
        };
        self.validate_false_clause(&pending.clause)?;
        let sat_clause = sat_literals(&pending.clause)?;
        self.record_theory_clause(pending.kind, &pending.clause, &pending.antecedent_reasons)?;
        match pending.kind {
            TheoryClauseKind::Conflict => {
                self.stats.theory_conflicts = checked_add(
                    self.stats.theory_conflicts,
                    1,
                    "theory conflict count overflowed",
                )?;
            }
            TheoryClauseKind::ModelBlock => {
                self.stats.model_blocks =
                    checked_add(self.stats.model_blocks, 1, "model block count overflowed")?;
            }
            TheoryClauseKind::Propagation { .. } => {
                return Err(CadicalUpAbstention::Internal(
                    "a propagation was queued as an external clause",
                ));
            }
        }
        Ok(Some(ExternalClause::new(sat_clause, false)))
    }

    fn record_theory_clause(
        &mut self,
        kind: TheoryClauseKind,
        clause: &[Lit],
        antecedent_reasons: &[ReasonId],
    ) -> Result<(), CadicalUpAbstention> {
        let clause_count = checked_add(
            self.stats.theory_clauses,
            1,
            "theory clause count overflowed",
        )?;
        check_cap(
            CadicalUpResource::TheoryClauses,
            clause_count,
            self.caps.max_theory_clauses,
        )?;
        let literal_count = checked_add(
            self.stats.theory_clause_literals,
            clause.len(),
            "logged theory literal count overflowed",
        )?;
        check_cap(
            CadicalUpResource::LoggedLiterals,
            literal_count,
            self.caps.max_logged_literals,
        )?;
        let clause_copy = try_boxed_copy(clause, "copying a theory clause into the replay log")?;
        let reason_copy = try_boxed_copy(
            antecedent_reasons,
            "copying theory reasons into the replay log",
        )?;
        self.theory_log
            .try_reserve(1)
            .map_err(|_| CadicalUpAbstention::Internal("growing the theory replay log"))?;
        self.theory_log.push(TheoryClauseLog {
            sequence: self.theory_log.len(),
            kind,
            clause: clause_copy,
            antecedent_reasons: reason_copy,
        });
        self.stats.theory_clauses = clause_count;
        self.stats.theory_clause_literals = literal_count;
        Ok(())
    }

    fn check_found_model_inner(&mut self, model: &[SatLit]) -> Result<bool, CadicalUpAbstention> {
        let attempted = checked_add(self.stats.model_checks, 1, "model check count overflowed")?;
        check_cap(
            CadicalUpResource::ModelChecks,
            attempted,
            self.caps.max_model_checks,
        )?;
        self.stats.model_checks = attempted;

        let mut values = try_filled_vec(self.source_atom_count, None)?;
        for &literal in model {
            let source = self.decode_source_literal(literal)?;
            let slot = &mut values[source.atom().index()];
            if slot.replace(source.is_positive()).is_some() {
                return Err(CadicalUpAbstention::Internal(
                    "a complete model assigns a source atom twice",
                ));
            }
        }
        if values.iter().any(Option::is_none) {
            return Err(CadicalUpAbstention::Internal(
                "a complete model omits an observed source atom",
            ));
        }
        let mut complete = try_vec(values.len(), "materializing a complete source model")?;
        for (index, value) in values.into_iter().enumerate() {
            let value = value.ok_or(CadicalUpAbstention::Internal(
                "validated complete model contains an unknown value",
            ))?;
            if self.assignments[index] != Some(value) {
                return Err(CadicalUpAbstention::Internal(
                    "model callback disagrees with the reported source trail",
                ));
            }
            complete.push(value);
        }

        match model::validate_complete(self.problem, &complete, self.caps.model) {
            Err(_) => Err(CadicalUpAbstention::Internal(
                "independent complete-model validation failed",
            )),
            Ok(ModelValidation::Abstained(limit)) => Err(CadicalUpAbstention::Model(limit)),
            Ok(ModelValidation::Valid(model)) => {
                self.stats.valid_models =
                    checked_add(self.stats.valid_models, 1, "valid model count overflowed")?;
                self.accepted_model = Some((complete.into_boxed_slice(), model));
                Ok(true)
            }
            Ok(ModelValidation::Invalid(_)) => {
                self.stats.invalid_models = checked_add(
                    self.stats.invalid_models,
                    1,
                    "invalid model count overflowed",
                )?;
                let blocks = checked_add(self.stats.model_blocks, 1, "model block cap overflowed")?;
                check_cap(
                    CadicalUpResource::ModelBlocks,
                    blocks,
                    self.caps.max_model_blocks,
                )?;
                let mut clause = try_vec(complete.len(), "building a complete model block")?;
                let mut reasons = try_vec(complete.len(), "building model-block reasons")?;
                for (index, value) in complete.into_iter().enumerate() {
                    let atom = AtomId::new(index as u32);
                    let assignment = if value {
                        Lit::positive(atom)
                    } else {
                        Lit::negative(atom)
                    };
                    clause.push(assignment.negate());
                    reasons.push(literal_reason(assignment)?);
                }
                self.queue_external_clause(
                    TheoryClauseKind::ModelBlock,
                    canonical_clause(clause)?,
                    reasons.into_boxed_slice(),
                )?;
                Ok(false)
            }
        }
    }

    fn relation_is_equal(&self, left: TermId, right: TermId) -> Result<bool, CadicalUpAbstention> {
        self.congruence
            .are_equal(left, right)
            .map_err(|_| CadicalUpAbstention::Internal("aligning a disequality witness"))
    }

    fn is_boolean_separation(&self, left: TermId, right: TermId) -> bool {
        self.problem
            .boolean_values
            .is_some_and(|(true_term, false_term)| {
                (left == true_term && right == false_term)
                    || (left == false_term && right == true_term)
            })
    }

    fn decode_source_literal(&self, literal: SatLit) -> Result<Lit, CadicalUpAbstention> {
        let index = literal.vidx32() as usize;
        if index >= self.source_atom_count {
            return Err(CadicalUpAbstention::Internal(
                "IPASIR-UP callback mentioned an unobserved native auxiliary",
            ));
        }
        let atom = AtomId::new(index as u32);
        Ok(if literal.is_pos() {
            Lit::positive(atom)
        } else {
            Lit::negative(atom)
        })
    }

    fn clear_pending_propagations(&mut self) {
        while let Some(pending) = self.pending_propagations.pop_front() {
            self.queued_polarities[pending.literal.atom().index()] = None;
        }
    }
}

impl ExternalPropagator for TheoryPropagator<'_> {
    fn notify_assignment(&mut self, literals: &[SatLit]) {
        if self.failure.is_some() {
            return;
        }
        let phase_start = self.caps.profile_callback_timings.then(Instant::now);
        let result = self.notify_assignment_inner(literals);
        if let Some(phase_start) = phase_start {
            self.stats.callback_assignment_ns = self
                .stats
                .callback_assignment_ns
                .saturating_add(phase_start.elapsed().as_nanos());
        }
        if let Err(reason) = result {
            self.fail(reason);
        }
    }

    fn notify_new_decision_level(&mut self) {
        if self.failure.is_some() {
            return;
        }
        let phase_start = self.caps.profile_callback_timings.then(Instant::now);
        let result = self.notify_new_decision_level_inner();
        if let Some(phase_start) = phase_start {
            self.stats.callback_decision_level_ns = self
                .stats
                .callback_decision_level_ns
                .saturating_add(phase_start.elapsed().as_nanos());
        }
        if let Err(reason) = result {
            self.fail(reason);
        }
    }

    fn notify_backtrack(&mut self, new_level: usize) {
        if self.failure.is_some() {
            return;
        }
        let phase_start = self.caps.profile_callback_timings.then(Instant::now);
        let result = self.notify_backtrack_inner(new_level);
        if let Some(phase_start) = phase_start {
            self.stats.callback_backtrack_ns = self
                .stats
                .callback_backtrack_ns
                .saturating_add(phase_start.elapsed().as_nanos());
        }
        if let Err(reason) = result {
            self.fail(reason);
        }
    }

    fn propagate(&mut self) -> Option<ExternalPropagation> {
        if self.failure.is_some() {
            return None;
        }
        let phase_start = self.caps.profile_callback_timings.then(Instant::now);
        let result = self.emit_propagation();
        if let Some(phase_start) = phase_start {
            self.stats.callback_propagation_ns = self
                .stats
                .callback_propagation_ns
                .saturating_add(phase_start.elapsed().as_nanos());
        }
        match result {
            Ok(propagation) => propagation,
            Err(reason) => {
                self.fail(reason);
                None
            }
        }
    }

    fn reason(&mut self, propagated: SatLit) -> Option<Vec<SatLit>> {
        if self.failure.is_some() {
            return None;
        }
        let phase_start = self.caps.profile_callback_timings.then(Instant::now);
        let result = self.provide_lazy_reason_inner(propagated);
        if let Some(phase_start) = phase_start {
            self.stats.callback_reason_ns = self
                .stats
                .callback_reason_ns
                .saturating_add(phase_start.elapsed().as_nanos());
        }
        match result {
            Ok(reason) => Some(reason),
            Err(failure) => {
                self.fail(failure);
                None
            }
        }
    }

    fn external_clause(&mut self) -> Option<ExternalClause> {
        if self.failure.is_some() {
            if self.fail_closed_emitted {
                return None;
            }
            self.fail_closed_emitted = true;
            self.stats.fail_closed_clauses = self.stats.fail_closed_clauses.saturating_add(1);
            return Some(ExternalClause::conflict());
        }
        let phase_start = self.caps.profile_callback_timings.then(Instant::now);
        let result = self.emit_external_clause();
        if let Some(phase_start) = phase_start {
            self.stats.callback_external_clause_ns = self
                .stats
                .callback_external_clause_ns
                .saturating_add(phase_start.elapsed().as_nanos());
        }
        match result {
            Ok(clause) => clause,
            Err(reason) => {
                self.fail(reason);
                self.fail_closed_emitted = true;
                self.stats.fail_closed_clauses = self.stats.fail_closed_clauses.saturating_add(1);
                Some(ExternalClause::conflict())
            }
        }
    }

    fn check_found_model(&mut self, model: &[SatLit]) -> bool {
        if self.failure.is_some() {
            return false;
        }
        let phase_start = self.caps.profile_callback_timings.then(Instant::now);
        let result = self.check_found_model_inner(model);
        if let Some(phase_start) = phase_start {
            self.stats.callback_model_ns = self
                .stats
                .callback_model_ns
                .saturating_add(phase_start.elapsed().as_nanos());
        }
        match result {
            Ok(accepted) => accepted,
            Err(reason) => {
                self.fail(reason);
                false
            }
        }
    }
}

enum SourceApply {
    Applied,
    Conflict(CongruenceConflict),
}

fn validate_boolean_universe(problem: &SemanticProblem) -> Result<(), CadicalUpAbstention> {
    let has_boolean_atoms = problem
        .atoms
        .iter()
        .any(|atom| matches!(atom, SemanticAtom::BoolTerm(_)));
    let Some((true_term, false_term)) = problem.boolean_values else {
        return if has_boolean_atoms {
            Err(CadicalUpAbstention::Malformed(
                "Boolean-term atoms lack distinguished Boolean values",
            ))
        } else {
            Ok(())
        };
    };
    if true_term == false_term {
        return Err(CadicalUpAbstention::Malformed(
            "the distinguished Boolean values are the same term",
        ));
    }
    let Some(true_semantic) = problem.terms.get(true_term.index()) else {
        return Err(CadicalUpAbstention::Malformed(
            "the distinguished true term is out of range",
        ));
    };
    let Some(false_semantic) = problem.terms.get(false_term.index()) else {
        return Err(CadicalUpAbstention::Malformed(
            "the distinguished false term is out of range",
        ));
    };
    if true_semantic.sort != false_semantic.sort {
        return Err(CadicalUpAbstention::Malformed(
            "the distinguished Boolean values have different sorts",
        ));
    }
    Ok(())
}

fn atom_relation_may_change(
    problem: &SemanticProblem,
    atom: AtomId,
    affected_generations: &[u32],
    generation: u32,
) -> bool {
    let contains =
        |term: TermId| affected_generations.get(term.index()).copied() == Some(generation);
    match problem.atoms.get(atom.index()) {
        Some(SemanticAtom::Equality(left, right)) => contains(*left) && contains(*right),
        Some(SemanticAtom::BoolTerm(term)) => {
            contains(*term)
                && problem
                    .boolean_values
                    .is_some_and(|(true_term, false_term)| {
                        contains(true_term) || contains(false_term)
                    })
        }
        None => false,
    }
}

fn literal_reason(literal: Lit) -> Result<ReasonId, CadicalUpAbstention> {
    let doubled =
        (literal.atom().index() as u64)
            .checked_mul(2)
            .ok_or(CadicalUpAbstention::Internal(
                "source reason encoding overflowed",
            ))?;
    let raw = doubled
        .checked_add(1 + u64::from(!literal.is_positive()))
        .ok_or(CadicalUpAbstention::Internal(
            "source reason encoding overflowed",
        ))?;
    if raw == ROOT_BOOLEAN_SEPARATION_REASON.raw() || raw == ReasonId::MAX.raw() {
        return Err(CadicalUpAbstention::Internal(
            "source reason encoding entered a reserved range",
        ));
    }
    Ok(ReasonId::new(raw))
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

fn canonical_clause(mut clause: Vec<Lit>) -> Result<Box<[Lit]>, CadicalUpAbstention> {
    clause.sort_unstable();
    clause.dedup();
    if clause.windows(2).any(|pair| {
        pair[0].atom() == pair[1].atom() && pair[0].is_positive() != pair[1].is_positive()
    }) {
        return Err(CadicalUpAbstention::Internal(
            "a theory clause is tautological",
        ));
    }
    Ok(clause.into_boxed_slice())
}

fn to_sat_lit(literal: Lit) -> SatLit {
    if literal.is_positive() {
        SatLit::positive(literal.atom().index() as u32)
    } else {
        SatLit::negative(literal.atom().index() as u32)
    }
}

fn sat_literals(literals: &[Lit]) -> Result<Vec<SatLit>, CadicalUpAbstention> {
    let mut converted = try_vec(literals.len(), "converting a theory clause to IPASIR")?;
    converted.extend(literals.iter().copied().map(to_sat_lit));
    Ok(converted)
}

fn classify_theory_atom_error(error: TheoryAtomIndexError) -> CadicalUpAbstention {
    match error {
        TheoryAtomIndexError::CapExceeded {
            resource,
            attempted,
            limit,
        } => CadicalUpAbstention::TheoryAtoms {
            resource,
            attempted,
            limit,
        },
        _ => CadicalUpAbstention::Internal("updating the stable theory atom index"),
    }
}

fn classify_impact_error(_error: ImpactError) -> CadicalUpAbstention {
    CadicalUpAbstention::Internal("computing the stable theory impact frontier")
}

fn check_cap(
    resource: CadicalUpResource,
    attempted: usize,
    limit: usize,
) -> Result<(), CadicalUpAbstention> {
    if attempted > limit {
        return Err(CadicalUpAbstention::CapExceeded {
            resource,
            attempted,
            limit,
        });
    }
    Ok(())
}

fn checked_add(
    left: usize,
    right: usize,
    message: &'static str,
) -> Result<usize, CadicalUpAbstention> {
    left.checked_add(right)
        .ok_or(CadicalUpAbstention::Internal(message))
}

fn try_vec<T>(capacity: usize, context: &'static str) -> Result<Vec<T>, CadicalUpAbstention> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| CadicalUpAbstention::Internal(context))?;
    Ok(values)
}

fn try_filled_vec<T: Clone>(count: usize, value: T) -> Result<Vec<T>, CadicalUpAbstention> {
    let mut values = try_vec(count, "allocating capped adapter state")?;
    values.resize(count, value);
    Ok(values)
}

fn try_filled_box<T: Clone>(count: usize, value: T) -> Result<Box<[T]>, CadicalUpAbstention> {
    try_filled_vec(count, value).map(Vec::into_boxed_slice)
}

fn try_boxed_copy<T: Copy>(
    values: &[T],
    context: &'static str,
) -> Result<Box<[T]>, CadicalUpAbstention> {
    let mut copy = try_vec(values.len(), context)?;
    copy.extend_from_slice(values);
    Ok(copy.into_boxed_slice())
}

#[cfg(test)]
mod tests {
    use super::super::bool_cnf::{self, LoweringCaps};
    use super::super::engine::{EngineCaps, ReferenceOutcome, solve_incremental_reference};
    use super::super::model::{
        LiteralConjunctionValidation, ModelValidation, validate_complete,
        validate_literal_conjunction,
    };
    use super::super::semantic::{self, RootLiteral};
    use super::*;
    use crate::parse_problem;

    fn project(source: &str) -> (SemanticProblem, NativeFormula) {
        let parsed = parse_problem(source).expect("test source must parse");
        let problem = semantic::project(&parsed).expect("test source must project");
        let formula =
            bool_cnf::lower(&problem, LoweringCaps::unlimited()).expect("test source must lower");
        (problem, formula)
    }

    fn run(source: &str) -> (SemanticProblem, NativeFormula, CadicalUpReport) {
        let (problem, formula) = project(source);
        let report = solve(&problem, &formula, CadicalUpCaps::default());
        (problem, formula, report)
    }

    fn assert_sat(report: &CadicalUpReport) {
        assert!(
            matches!(report.outcome, CadicalUpOutcome::Sat { .. }),
            "expected SAT, got {report:#?}"
        );
    }

    fn assert_unsat(report: &CadicalUpReport) {
        assert!(
            matches!(report.outcome, CadicalUpOutcome::Unsat),
            "expected UNSAT, got {report:#?}"
        );
    }

    #[test]
    fn tiny_sat_and_unsat() {
        let (_, _, sat) = run("(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U) (declare-const b U)\n\
             (assert (or (= a b) (not (= a b))))\n\
             (check-sat)");
        assert_sat(&sat);

        let (_, _, unsat) = run("(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U) (declare-const b U)\n\
             (declare-fun f (U) U)\n\
             (assert (= a b))\n\
             (assert (not (= (f a) (f b))))\n\
             (check-sat)");
        assert_unsat(&unsat);
        assert!(unsat.stats.theory_conflicts > 0);
    }

    #[test]
    fn congruence_implication_is_propagated_with_a_replayable_reason() {
        let (problem, formula, report) = run("(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U) (declare-const b U)\n\
             (declare-const c U) (declare-const d U)\n\
             (declare-fun f (U) U)\n\
             (assert (= a b))\n\
             (assert (or (= (f a) (f b)) (= c d)))\n\
             (check-sat)");
        assert_sat(&report);
        assert!(formula.auxiliary_atom_count > 0);
        assert_eq!(report.stats.observed_variables, problem.atoms.len());
        assert!(report.stats.observed_variables < formula.atom_count);
        assert!(report.theory_log.iter().any(|entry| {
            matches!(entry.kind, TheoryClauseKind::Propagation { .. })
                && !entry.antecedent_reasons.is_empty()
        }));
        validate_emitted_lemmas(&problem, &report);
    }

    #[test]
    fn explicit_theory_conflict_contains_only_negated_source_antecedents() {
        let (problem, _, report) = run("(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U) (declare-const b U)\n\
             (declare-fun f (U) U)\n\
             (assert (= a b))\n\
             (assert (not (= (f a) (f b))))\n\
             (check-sat)");
        assert_unsat(&report);
        let conflicts = report
            .theory_log
            .iter()
            .filter(|entry| entry.kind == TheoryClauseKind::Conflict)
            .collect::<Vec<_>>();
        assert!(!conflicts.is_empty());
        for conflict in conflicts {
            assert!(
                !conflict
                    .antecedent_reasons
                    .contains(&ROOT_BOOLEAN_SEPARATION_REASON)
            );
            for (&literal, &reason) in conflict
                .clause
                .iter()
                .zip(conflict.antecedent_reasons.iter())
            {
                assert_eq!(
                    literal_from_reason(reason, problem.atoms.len()),
                    Some(literal.negate())
                );
            }
        }
        validate_emitted_lemmas(&problem, &report);
    }

    #[test]
    fn boolean_term_implication_crosses_theory_boundary() {
        let (problem, _, report) = run("(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U) (declare-const b U)\n\
             (declare-const c U) (declare-const d U)\n\
             (declare-fun p (U) Bool)\n\
             (assert (= a b))\n\
             (assert (p b))\n\
             (assert (or (p a) (= c d)))\n\
             (check-sat)");
        assert_sat(&report);
        assert!(report.theory_log.iter().any(|entry| {
            let TheoryClauseKind::Propagation { literal } = entry.kind else {
                return false;
            };
            matches!(
                problem.atoms[literal.atom().index()],
                SemanticAtom::BoolTerm(_)
            )
        }));
        validate_emitted_lemmas(&problem, &report);
    }

    #[test]
    fn narrow_merge_frontier_propagates_boolean_class_members_and_flushes_tails() {
        let (problem, formula) = project(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U) (declare-const b U)\n\
             (declare-fun p (U) Bool)\n\
             (assert (or (= a b) (p a) (p b)))\n\
             (check-sat)",
        );
        let (equality_atom, equality_terms) = problem
            .atoms
            .iter()
            .enumerate()
            .find_map(|(index, atom)| match atom {
                SemanticAtom::Equality(left, right) => Some((index, (*left, *right))),
                _ => None,
            })
            .unwrap();
        let boolean_atoms = problem
            .atoms
            .iter()
            .enumerate()
            .filter_map(|(index, atom)| matches!(atom, SemanticAtom::BoolTerm(_)).then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(boolean_atoms.len(), 2);

        for demand_driven in [false, true] {
            let mut caps = CadicalUpCaps::default();
            caps.narrow_explicit_merge_frontier = true;
            caps.sparse_root_initialization = true;
            caps.demand_driven_propagation_flush = demand_driven;
            caps.propagation_batch_updates = 4;
            let mut propagator = TheoryPropagator::new(
                &problem,
                formula.source_atom_count,
                caps,
                CadicalUpStats::default(),
            )
            .unwrap();

            propagator
                .notify_assignment_inner(&[SatLit::positive(equality_atom as u32)])
                .unwrap();
            assert!(
                propagator.deferred_partition_updates > 0
                    && propagator.deferred_partition_updates < caps.propagation_batch_updates
            );
            propagator.notify_new_decision_level_inner().unwrap();
            assert_eq!(propagator.deferred_partition_updates, 0);

            let assigned_boolean = boolean_atoms[0];
            let target_boolean = boolean_atoms[1];
            propagator
                .notify_assignment_inner(&[SatLit::positive(assigned_boolean as u32)])
                .unwrap();
            assert_eq!(propagator.deferred_partition_updates, 1);
            let propagation = propagator.emit_propagation().unwrap().unwrap();
            assert_eq!(
                propagation.literal(),
                SatLit::positive(target_boolean as u32)
            );
            assert_eq!(propagator.deferred_partition_updates, 0);

            propagator.notify_backtrack_inner(0).unwrap();
            assert_eq!(
                propagator
                    .congruence
                    .relation(equality_terms.0, equality_terms.1)
                    .unwrap(),
                Relation::Equal
            );
            assert_eq!(propagator.assignments[equality_atom], Some(true));
            assert_eq!(propagator.assignments[assigned_boolean], None);
        }
    }

    #[test]
    fn decision_level_backtrack_restores_congruence_and_source_trail() {
        let (problem, formula) = project(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U) (declare-const b U)\n\
             (declare-const c U) (declare-const d U)\n\
             (assert (or (= a b) (= c d)))\n\
             (check-sat)",
        );
        let atom_index = problem
            .atoms
            .iter()
            .position(|atom| matches!(atom, SemanticAtom::Equality(_, _)))
            .unwrap();
        let SemanticAtom::Equality(left, right) = problem.atoms[atom_index] else {
            unreachable!();
        };
        let mut propagator = TheoryPropagator::new(
            &problem,
            formula.source_atom_count,
            CadicalUpCaps::default(),
            CadicalUpStats::default(),
        )
        .unwrap();

        propagator.notify_new_decision_level_inner().unwrap();
        propagator
            .notify_assignment_inner(&[SatLit::positive(atom_index as u32)])
            .unwrap();
        assert_eq!(
            propagator.congruence.relation(left, right).unwrap(),
            Relation::Equal
        );
        assert_eq!(propagator.assignments[atom_index], Some(true));

        propagator.notify_backtrack_inner(0).unwrap();
        assert_eq!(
            propagator.congruence.relation(left, right).unwrap(),
            Relation::Unknown
        );
        assert_eq!(propagator.assignments[atom_index], None);
        assert!(propagator.trail.is_empty());
        assert!(propagator.level_snapshots.is_empty());
        assert_eq!(propagator.stats.backtracks, 1);
    }

    #[test]
    fn lazy_reason_uses_the_pre_propagation_snapshot() {
        let (problem, formula) = project(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U) (declare-const b U)\n\
             (declare-fun f (U) U)\n\
             (assert (= a b))\n\
             (assert (or (= (f a) (f b)) (not (= a b))))\n\
             (check-sat)",
        );
        let mut base_atom = None;
        let mut consequence_atom = None;
        for (index, atom) in problem.atoms.iter().enumerate() {
            let SemanticAtom::Equality(left, right) = atom else {
                continue;
            };
            let left_arity = problem.terms[left.index()].arguments.len();
            let right_arity = problem.terms[right.index()].arguments.len();
            match (left_arity, right_arity) {
                (0, 0) => base_atom = Some(index),
                (1, 1) => consequence_atom = Some(index),
                _ => {}
            }
        }
        let base_atom = base_atom.unwrap();
        let consequence_atom = consequence_atom.unwrap();
        let mut caps = CadicalUpCaps::default();
        caps.lazy_propagation_reasons = true;
        let mut propagator = TheoryPropagator::new(
            &problem,
            formula.source_atom_count,
            caps,
            CadicalUpStats::default(),
        )
        .unwrap();

        propagator
            .notify_assignment_inner(&[SatLit::positive(base_atom as u32)])
            .unwrap();
        let propagation = propagator.emit_propagation().unwrap().unwrap();
        assert_eq!(propagation.literal().vidx32() as usize, consequence_atom);
        let propagated = propagation.literal();

        // CaDiCaL reports the propagated literal before asking for its reason.
        // The delayed proof must still exclude this conclusion assignment.
        propagator.notify_assignment_inner(&[propagated]).unwrap();
        let reason = propagator.provide_lazy_reason_inner(propagated).unwrap();
        assert!(reason.contains(&propagated));
        assert!(reason.contains(&SatLit::negative(base_atom as u32)));
        assert!(!reason.contains(&!propagated));
        let log = propagator.theory_log.last().unwrap();
        assert_eq!(
            log.antecedent_reasons.as_ref(),
            &[literal_reason(Lit::positive(AtomId::new(base_atom as u32))).unwrap()]
        );
        assert!(!log.antecedent_reasons.contains(
            &literal_reason(Lit::positive(AtomId::new(consequence_atom as u32))).unwrap()
        ));
    }

    #[test]
    fn malformed_input_and_callback_cap_abstain() {
        let (problem, formula) = project(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-const a U) (declare-const b U)\n\
             (assert (= a b))\n\
             (check-sat)",
        );
        let mut malformed = formula.clone();
        malformed.source_atom_count += 1;
        let malformed_report = solve(&problem, &malformed, CadicalUpCaps::default());
        assert!(matches!(
            malformed_report.outcome,
            CadicalUpOutcome::Abstain {
                reason: CadicalUpAbstention::Malformed(_)
            }
        ));

        let mut caps = CadicalUpCaps::default();
        caps.max_assignment_notifications = 0;
        let capped = solve(&problem, &formula, caps);
        assert!(matches!(
            capped.outcome,
            CadicalUpOutcome::Abstain {
                reason: CadicalUpAbstention::CapExceeded {
                    resource: CadicalUpResource::AssignmentNotifications,
                    ..
                }
            }
        ));
        assert_eq!(capped.stats.fail_closed_clauses, 1);
        assert!(!matches!(capped.outcome, CadicalUpOutcome::Unsat));
    }

    #[test]
    fn stable_literal_reason_mapping_round_trips() {
        let mut seen = BTreeSet::new();
        for atom_index in 0..128u32 {
            for literal in [
                Lit::positive(AtomId::new(atom_index)),
                Lit::negative(AtomId::new(atom_index)),
            ] {
                let reason = literal_reason(literal).unwrap();
                assert!(seen.insert(reason));
                assert_eq!(literal_from_reason(reason, 128), Some(literal));
            }
        }
        assert!(!seen.contains(&ROOT_BOOLEAN_SEPARATION_REASON));
        assert!(!seen.contains(&ReasonId::MAX));
    }

    #[test]
    fn repeated_solves_have_identical_outcome_telemetry_and_log() {
        let source = "(set-logic QF_UF)\n\
            (declare-sort U 0)\n\
            (declare-const a U) (declare-const b U)\n\
            (declare-const c U) (declare-const d U)\n\
            (declare-fun f (U) U)\n\
            (assert (= a b))\n\
            (assert (or (= (f a) (f b)) (= c d)))\n\
            (check-sat)";
        let (problem, formula) = project(source);
        let first = solve(&problem, &formula, CadicalUpCaps::default());
        let second = solve(&problem, &formula, CadicalUpCaps::default());
        assert_eq!(first.outcome, second.outcome);
        assert_eq!(first.theory_log, second.theory_log);
        let mut first_stats = first.stats;
        let mut second_stats = second.stats;
        clear_wall_clock_timings(&mut first_stats);
        clear_wall_clock_timings(&mut second_stats);
        assert_eq!(first_stats, second_stats);
    }

    fn clear_wall_clock_timings(stats: &mut CadicalUpStats) {
        stats.input_validation_ns = 0;
        stats.propagator_construction_ns = 0;
        stats.congruence_construction_ns = 0;
        stats.congruence_universe_validation_ns = 0;
        stats.congruence_partition_construction_ns = 0;
        stats.congruence_signature_index_construction_ns = 0;
        stats.congruence_initial_saturation_ns = 0;
        stats.congruence_post_construction_validation_ns = 0;
        stats.theory_atom_index_construction_ns = 0;
        stats.adapter_state_allocation_ns = 0;
        stats.root_scheduling_ns = 0;
        stats.solver_setup_ns = 0;
        stats.clause_loading_ns = 0;
        stats.observed_variable_setup_ns = 0;
        stats.solver_search_ns = 0;
        stats.callback_assignment_ns = 0;
        stats.callback_decision_level_ns = 0;
        stats.callback_backtrack_ns = 0;
        stats.callback_propagation_ns = 0;
        stats.callback_reason_ns = 0;
        stats.callback_external_clause_ns = 0;
        stats.callback_model_ns = 0;
        stats.assignment_frontier_ns = 0;
        stats.assignment_congruence_ns = 0;
        stats.assignment_equality_congruence_ns = 0;
        stats.assignment_disequality_congruence_ns = 0;
        stats.assignment_post_update_ns = 0;
    }

    #[test]
    fn exhaustive_three_constant_conjunctions_match_fabric_reference() {
        let pairs = [("a", "b"), ("a", "c"), ("b", "c")];
        for encoded in 0usize..27 {
            let mut source = String::from(
                "(set-logic QF_UF)\n\
                 (declare-sort U 0)\n\
                 (declare-const a U) (declare-const b U) (declare-const c U)\n",
            );
            let mut value = encoded;
            for (left, right) in pairs {
                match value % 3 {
                    0 => {}
                    1 => source.push_str(&format!("(assert (= {left} {right}))\n")),
                    2 => source.push_str(&format!("(assert (not (= {left} {right})))\n")),
                    _ => unreachable!(),
                }
                value /= 3;
            }
            source.push_str("(check-sat)\n");
            let (problem, formula) = project(&source);
            let actual = solve(&problem, &formula, CadicalUpCaps::default());
            let reference = solve_incremental_reference(&problem, EngineCaps::default()).unwrap();
            let actual_sat = match actual.outcome {
                CadicalUpOutcome::Sat { .. } => true,
                CadicalUpOutcome::Unsat => false,
                CadicalUpOutcome::Abstain { ref reason } => {
                    panic!("adapter abstained for generated case {encoded}: {reason:?}")
                }
            };
            let reference_sat = match reference {
                ReferenceOutcome::Sat { .. } => true,
                ReferenceOutcome::Unsat { .. } => false,
                ReferenceOutcome::Abstained { reason, .. } => {
                    panic!("reference abstained for generated case {encoded}: {reason:?}")
                }
            };
            assert_eq!(actual_sat, reference_sat, "generated case {encoded}");
        }
    }

    #[test]
    fn lazy_and_eager_reasons_match_on_three_constant_conjunctions() {
        let pairs = [("a", "b"), ("a", "c"), ("b", "c")];
        for encoded in 0usize..27 {
            let mut source = String::from(
                "(set-logic QF_UF)\n\
                 (declare-sort U 0)\n\
                 (declare-const a U) (declare-const b U) (declare-const c U)\n",
            );
            let mut value = encoded;
            for (left, right) in pairs {
                match value % 3 {
                    0 => {}
                    1 => source.push_str(&format!("(assert (= {left} {right}))\n")),
                    2 => source.push_str(&format!("(assert (not (= {left} {right})))\n")),
                    _ => unreachable!(),
                }
                value /= 3;
            }
            source.push_str("(check-sat)\n");
            let (problem, formula) = project(&source);
            let eager = solve(&problem, &formula, CadicalUpCaps::default());
            let mut lazy_caps = CadicalUpCaps::default();
            lazy_caps.lazy_propagation_reasons = true;
            let lazy = solve(&problem, &formula, lazy_caps);
            let mut filtered_caps = lazy_caps;
            filtered_caps.pair_filtered_impact_atoms = true;
            let filtered = solve(&problem, &formula, filtered_caps);
            let mut demand_caps = filtered_caps;
            demand_caps.demand_driven_propagation_flush = true;
            let demand = solve(&problem, &formula, demand_caps);
            let mut narrow_caps = demand_caps;
            narrow_caps.narrow_explicit_merge_frontier = true;
            let narrow = solve(&problem, &formula, narrow_caps);
            let mut sparse_caps = narrow_caps;
            sparse_caps.sparse_root_initialization = true;
            let sparse = solve(&problem, &formula, sparse_caps);
            let mut fast_constructor_caps = narrow_caps;
            fast_constructor_caps.post_construction_congruence_validation = false;
            let fast_constructor = solve(&problem, &formula, fast_constructor_caps);
            let mut compact_callback_caps = fast_constructor_caps;
            compact_callback_caps.allocation_free_assignment_decode = true;
            let compact_callback = solve(&problem, &formula, compact_callback_caps);
            assert_eq!(
                std::mem::discriminant(&lazy.outcome),
                std::mem::discriminant(&eager.outcome),
                "lazy/eager outcome mismatch for generated case {encoded}: eager={:?}, lazy={:?}",
                eager.outcome,
                lazy.outcome
            );
            assert!(
                !matches!(lazy.outcome, CadicalUpOutcome::Abstain { .. }),
                "lazy adapter abstained for generated case {encoded}: {:?}",
                lazy.outcome
            );
            assert_eq!(
                std::mem::discriminant(&filtered.outcome),
                std::mem::discriminant(&eager.outcome),
                "filtered/eager outcome mismatch for generated case {encoded}: eager={:?}, filtered={:?}",
                eager.outcome,
                filtered.outcome
            );
            assert!(
                !matches!(filtered.outcome, CadicalUpOutcome::Abstain { .. }),
                "filtered adapter abstained for generated case {encoded}: {:?}",
                filtered.outcome
            );
            assert_eq!(
                std::mem::discriminant(&demand.outcome),
                std::mem::discriminant(&eager.outcome),
                "demand/eager outcome mismatch for generated case {encoded}: eager={:?}, demand={:?}",
                eager.outcome,
                demand.outcome
            );
            assert!(
                !matches!(demand.outcome, CadicalUpOutcome::Abstain { .. }),
                "demand adapter abstained for generated case {encoded}: {:?}",
                demand.outcome
            );
            assert_eq!(
                std::mem::discriminant(&narrow.outcome),
                std::mem::discriminant(&eager.outcome),
                "narrow/eager outcome mismatch for generated case {encoded}: eager={:?}, narrow={:?}",
                eager.outcome,
                narrow.outcome
            );
            assert!(
                !matches!(narrow.outcome, CadicalUpOutcome::Abstain { .. }),
                "narrow adapter abstained for generated case {encoded}: {:?}",
                narrow.outcome
            );
            assert_eq!(
                std::mem::discriminant(&sparse.outcome),
                std::mem::discriminant(&eager.outcome),
                "sparse/eager outcome mismatch for generated case {encoded}: eager={:?}, sparse={:?}",
                eager.outcome,
                sparse.outcome
            );
            assert!(
                !matches!(sparse.outcome, CadicalUpOutcome::Abstain { .. }),
                "sparse adapter abstained for generated case {encoded}: {:?}",
                sparse.outcome
            );
            assert_eq!(
                std::mem::discriminant(&fast_constructor.outcome),
                std::mem::discriminant(&eager.outcome),
                "fast-constructor/eager outcome mismatch for generated case {encoded}: eager={:?}, fast={:?}",
                eager.outcome,
                fast_constructor.outcome
            );
            assert!(
                !matches!(fast_constructor.outcome, CadicalUpOutcome::Abstain { .. }),
                "fast constructor abstained for generated case {encoded}: {:?}",
                fast_constructor.outcome
            );
            assert_eq!(
                std::mem::discriminant(&compact_callback.outcome),
                std::mem::discriminant(&eager.outcome),
                "compact-callback/eager outcome mismatch for generated case {encoded}: eager={:?}, compact={:?}",
                eager.outcome,
                compact_callback.outcome
            );
            assert!(
                !matches!(compact_callback.outcome, CadicalUpOutcome::Abstain { .. }),
                "compact callback abstained for generated case {encoded}: {:?}",
                compact_callback.outcome
            );
            validate_emitted_lemmas(&problem, &lazy);
            validate_emitted_lemmas(&problem, &filtered);
            validate_emitted_lemmas(&problem, &demand);
            validate_emitted_lemmas(&problem, &narrow);
            validate_emitted_lemmas(&problem, &sparse);
            validate_emitted_lemmas(&problem, &fast_constructor);
            validate_emitted_lemmas(&problem, &compact_callback);
        }
    }

    fn validate_emitted_lemmas(problem: &SemanticProblem, report: &CadicalUpReport) {
        for entry in report.theory_log.iter() {
            match entry.kind {
                TheoryClauseKind::Propagation { .. } | TheoryClauseKind::Conflict => {
                    let literals = entry
                        .clause
                        .iter()
                        .map(|literal| RootLiteral {
                            atom: literal.atom(),
                            positive: !literal.is_positive(),
                        })
                        .collect::<Vec<_>>();
                    assert!(
                        matches!(
                            validate_literal_conjunction(problem, &literals, ModelCaps::default())
                                .unwrap(),
                            LiteralConjunctionValidation::Conflict { .. }
                        ),
                        "emitted lemma {} is not independently valid: {entry:?}",
                        entry.sequence
                    );
                }
                TheoryClauseKind::ModelBlock => {
                    assert_eq!(entry.clause.len(), problem.atoms.len());
                    let mut values = vec![None; problem.atoms.len()];
                    for literal in entry.clause.iter() {
                        values[literal.atom().index()] = Some(!literal.is_positive());
                    }
                    let values = values.into_iter().map(Option::unwrap).collect::<Vec<_>>();
                    assert!(matches!(
                        validate_complete(problem, &values, ModelCaps::default()).unwrap(),
                        ModelValidation::Invalid(_)
                    ));
                }
            }
        }
    }
}
