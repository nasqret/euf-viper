//! Conflict-only CaDiCaL adapter for the rollback EUF core.

use rustc_hash::FxHashSet as HashSet;
use rustsat::types::{Lit, Var};
use rustsat_cadical::{ExternalClause, ExternalPropagator, PropagatorAbort, PropagatorResult};
use std::time::Instant;

use super::{
    BoolAtomKey, CnfProblem, TermArena, TermId, UnionFind, congruence_closure,
    rollback_euf::{EufConflict, RollbackEuf, RollbackEufError, RollbackEufLimits},
    t7_explanation::{
        T7ExperimentConfig, T7RunSummary, T7Selector, T7Telemetry, TranscriptReceipt,
    },
};

const DEFAULT_MAX_CONFLICTS: usize = 10_000;
const DEFAULT_MAX_OBSERVED_VARIABLES: usize = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TheoryAtom {
    Equality(TermId, TermId),
    BoolTerm(TermId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RollbackPropagatorBuildError {
    VariableIndexExceeded { variable: usize, maximum: u32 },
    ObservedVariableLimitExceeded { variables: usize, limit: usize },
    Core(RollbackEufError),
    InitialTheoryConflict,
    T7Telemetry(String),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RollbackPropagatorStats {
    pub(crate) t7_enabled: bool,
    pub(crate) assignments: usize,
    pub(crate) decision_levels: usize,
    pub(crate) backtracks: usize,
    pub(crate) conflicts: usize,
    pub(crate) repeated_assignment_conflicts: usize,
    pub(crate) model_checks: usize,
    pub(crate) model_check_time_ns: u128,
    pub(crate) theory_conflicts: usize,
    pub(crate) candidate_duplicates: usize,
    pub(crate) disagreements: usize,
    pub(crate) candidate_replays: usize,
    pub(crate) replay_failures: usize,
    pub(crate) candidate_build_time_ns: u128,
    pub(crate) candidate_score_time_ns: u128,
    pub(crate) candidate_replay_time_ns: u128,
}

struct T7State {
    selector: T7Selector,
    telemetry: T7Telemetry,
}

pub(crate) struct RollbackEufPropagator<'arena> {
    engine: RollbackEuf<'arena>,
    atoms: Vec<Option<TheoryAtom>>,
    observed: Vec<Var>,
    true_term: TermId,
    false_term: TermId,
    pending_clause: Option<(Vec<i32>, ExternalClause, Option<usize>)>,
    emitted_clauses: HashSet<Vec<i32>>,
    max_conflicts: usize,
    stats: RollbackPropagatorStats,
    t7: Option<T7State>,
}

impl<'arena> RollbackEufPropagator<'arena> {
    pub(crate) fn from_cnf(
        arena: &'arena TermArena,
        cnf: &CnfProblem,
        true_term: TermId,
        false_term: TermId,
        limits: RollbackEufLimits,
    ) -> Result<Self, RollbackPropagatorBuildError> {
        Self::from_cnf_internal(arena, cnf, true_term, false_term, limits, None)
    }

    pub(crate) fn from_cnf_with_t7(
        arena: &'arena TermArena,
        cnf: &CnfProblem,
        true_term: TermId,
        false_term: TermId,
        limits: RollbackEufLimits,
        config: T7ExperimentConfig,
    ) -> Result<Self, RollbackPropagatorBuildError> {
        Self::from_cnf_internal(arena, cnf, true_term, false_term, limits, Some(config))
    }

    fn from_cnf_internal(
        arena: &'arena TermArena,
        cnf: &CnfProblem,
        true_term: TermId,
        false_term: TermId,
        limits: RollbackEufLimits,
        t7_config: Option<T7ExperimentConfig>,
    ) -> Result<Self, RollbackPropagatorBuildError> {
        let observed_count = cnf.var_atoms.iter().flatten().count();
        if observed_count > DEFAULT_MAX_OBSERVED_VARIABLES {
            return Err(
                RollbackPropagatorBuildError::ObservedVariableLimitExceeded {
                    variables: observed_count,
                    limit: DEFAULT_MAX_OBSERVED_VARIABLES,
                },
            );
        }
        let mut atoms = vec![None; cnf.var_count()];
        let mut observed = Vec::with_capacity(observed_count);
        for (dimacs_variable, atom) in cnf.var_atoms.iter().enumerate().skip(1) {
            let Some(atom) = atom else {
                continue;
            };
            let variable_index = dimacs_variable - 1;
            let variable = Var::new_with_error(u32::try_from(variable_index).map_err(|_| {
                RollbackPropagatorBuildError::VariableIndexExceeded {
                    variable: variable_index,
                    maximum: Var::MAX_IDX,
                }
            })?)
            .map_err(|_| RollbackPropagatorBuildError::VariableIndexExceeded {
                variable: variable_index,
                maximum: Var::MAX_IDX,
            })?;
            atoms[variable_index] = Some(match atom {
                BoolAtomKey::Eq(left, right) => TheoryAtom::Equality(*left, *right),
                BoolAtomKey::BoolTerm(term) => TheoryAtom::BoolTerm(*term),
            });
            observed.push(variable);
        }

        let mut engine =
            RollbackEuf::new(arena, limits).map_err(RollbackPropagatorBuildError::Core)?;
        if engine
            .assume_distinct_axiom(true_term, false_term)
            .map_err(RollbackPropagatorBuildError::Core)?
            .is_some()
        {
            return Err(RollbackPropagatorBuildError::InitialTheoryConflict);
        }
        let t7 = if let Some(config) = t7_config {
            let clauses: Vec<Vec<i32>> = cnf.clauses.iter().map(<[i32]>::to_vec).collect();
            Some(T7State {
                selector: T7Selector::new(config.mode),
                telemetry: T7Telemetry::new(&config, cnf.var_count(), &clauses)
                    .map_err(RollbackPropagatorBuildError::T7Telemetry)?,
            })
        } else {
            None
        };
        let stats = RollbackPropagatorStats {
            t7_enabled: t7.is_some(),
            ..RollbackPropagatorStats::default()
        };
        Ok(Self {
            engine,
            atoms,
            observed,
            true_term,
            false_term,
            pending_clause: None,
            emitted_clauses: HashSet::default(),
            max_conflicts: DEFAULT_MAX_CONFLICTS,
            stats,
            t7,
        })
    }

    pub(crate) fn observed_variables(&self) -> &[Var] {
        &self.observed
    }

    pub(crate) fn stats(&self) -> RollbackPropagatorStats {
        self.stats
    }

    pub(crate) fn finish_t7(
        &self,
        summary: &T7RunSummary,
    ) -> Result<Option<TranscriptReceipt>, String> {
        match &self.t7 {
            Some(t7) => t7.telemetry.finish(summary),
            None => Ok(None),
        }
    }

    fn atom(&self, literal: Lit) -> PropagatorResult<TheoryAtom> {
        self.atoms
            .get(literal.var().idx())
            .and_then(|atom| *atom)
            .ok_or_else(|| {
                PropagatorAbort::new(format!(
                    "assignment for unregistered theory variable {}",
                    literal.var().to_ipasir()
                ))
            })
    }

    fn record_conflict(
        &mut self,
        conflict: EufConflict,
        assignment_callback: bool,
    ) -> PropagatorResult<()> {
        if self.t7.is_none() && self.pending_clause.is_some() {
            return Ok(());
        }
        if self.t7.is_some() {
            self.stats.theory_conflicts = self.stats.theory_conflicts.saturating_add(1);
        }
        let (conflict, event) = self.select_conflict(conflict)?;
        let clause = conflict.clause().to_vec();
        if self.pending_clause.is_some() {
            self.set_t7_disposition(event, "pending-occupied")?;
            return Ok(());
        }
        if self.emitted_clauses.contains(&clause) {
            self.set_t7_disposition(event, "persistent-duplicate")?;
            if assignment_callback {
                if self.stats.repeated_assignment_conflicts >= self.max_conflicts {
                    return Err(PropagatorAbort::new(format!(
                        "rollback EUF repeated-assignment conflict cap {} exhausted",
                        self.max_conflicts
                    )));
                }
                // CaDiCaL can notify the retained lower-level trail before its
                // newly persistent external clause is processed by ordinary
                // propagation. The clause is already in CaDiCaL, so emitting it
                // again adds no information. A complete model that violates it
                // remains a fail-closed error below.
                self.stats.repeated_assignment_conflicts =
                    self.stats.repeated_assignment_conflicts.saturating_add(1);
                return Ok(());
            }
            return Err(PropagatorAbort::new(
                "rollback EUF reached a complete model blocked by an emitted conflict",
            ));
        }
        if self.stats.conflicts >= self.max_conflicts {
            return Err(PropagatorAbort::new(format!(
                "rollback EUF conflict cap {} exhausted",
                self.max_conflicts
            )));
        }
        let literals: Result<Vec<Lit>, _> =
            clause.iter().map(|raw| Lit::from_ipasir(*raw)).collect();
        let literals = literals.map_err(|_| {
            PropagatorAbort::new("rollback EUF replay produced an invalid DIMACS literal")
        })?;
        self.set_t7_disposition(event, "queued")?;
        self.pending_clause = Some((clause, ExternalClause::new(literals), event));
        Ok(())
    }

    fn select_conflict(
        &mut self,
        conflict: EufConflict,
    ) -> PropagatorResult<(EufConflict, Option<usize>)> {
        if self.t7.is_none() {
            if !self.engine.replay_conflict(&conflict) {
                return Err(PropagatorAbort::new(
                    "rollback EUF conflict failed independent replay",
                ));
            }
            return Ok((conflict, None));
        }

        let build_started = Instant::now();
        let pool = self
            .engine
            .explanation_candidates(&conflict)
            .map_err(core_abort)?;
        let build_ns = build_started.elapsed().as_nanos();
        let replay_started = Instant::now();
        let replay_valid: Vec<bool> = pool
            .candidates
            .iter()
            .map(|candidate| self.engine.replay_conflict(candidate.conflict()))
            .collect();
        let replay_ns = replay_started.elapsed().as_nanos();
        let replay_failures = replay_valid.iter().filter(|&&valid| !valid).count();
        self.stats.replay_failures = self.stats.replay_failures.saturating_add(replay_failures);
        if replay_failures != 0 {
            return Err(PropagatorAbort::new(format!(
                "T7 reconstructed {replay_failures} explanation candidates that failed replay"
            )));
        }

        let score_started = Instant::now();
        let current_level = self.engine.level();
        let selection = self
            .t7
            .as_mut()
            .expect("T7 state was checked")
            .selector
            .select(
                &pool.candidates,
                |literal| self.engine.literal_decision_level(literal),
                current_level,
            )
            .map_err(PropagatorAbort::new)?;
        let score_ns = score_started.elapsed().as_nanos();
        let facts = self.engine.active_fact_records();
        let selected = pool.candidates[selection.selected_index].conflict().clone();
        let event = self
            .t7
            .as_mut()
            .expect("T7 state was checked")
            .telemetry
            .record_conflict(
                &facts,
                current_level,
                &pool.candidates,
                &replay_valid,
                &selection,
                pool.duplicates,
                build_ns,
                score_ns,
                replay_ns,
            )
            .map_err(PropagatorAbort::new)?;
        self.stats.candidate_duplicates = self
            .stats
            .candidate_duplicates
            .saturating_add(pool.duplicates);
        self.stats.disagreements = self
            .stats
            .disagreements
            .saturating_add(usize::from(selection.disagreement));
        self.stats.candidate_replays = self
            .stats
            .candidate_replays
            .saturating_add(pool.candidates.len());
        self.stats.candidate_build_time_ns =
            self.stats.candidate_build_time_ns.saturating_add(build_ns);
        self.stats.candidate_score_time_ns =
            self.stats.candidate_score_time_ns.saturating_add(score_ns);
        self.stats.candidate_replay_time_ns = self
            .stats
            .candidate_replay_time_ns
            .saturating_add(replay_ns);
        Ok((selected, Some(event)))
    }

    fn set_t7_disposition(
        &mut self,
        event: Option<usize>,
        disposition: &'static str,
    ) -> PropagatorResult<()> {
        let (Some(t7), Some(event)) = (&mut self.t7, event) else {
            return Ok(());
        };
        t7.telemetry
            .set_disposition(event, disposition)
            .map_err(PropagatorAbort::new)
    }

    fn apply_literal(&mut self, literal: Lit) -> PropagatorResult<()> {
        let raw = literal.to_ipasir();
        let conflict = match (self.atom(literal)?, literal.is_pos()) {
            (TheoryAtom::Equality(left, right), true) => self
                .engine
                .assert_equality(left, right, raw)
                .map_err(core_abort)?,
            (TheoryAtom::Equality(left, right), false) => self
                .engine
                .assert_disequality(left, right, raw)
                .map_err(core_abort)?,
            (TheoryAtom::BoolTerm(term), true) => self
                .engine
                .assert_equality(term, self.true_term, raw)
                .map_err(core_abort)?,
            (TheoryAtom::BoolTerm(term), false) => self
                .engine
                .assert_equality(term, self.false_term, raw)
                .map_err(core_abort)?,
        };
        if let Some(conflict) = conflict {
            self.record_conflict(conflict, true)?;
        }
        self.stats.assignments = self.stats.assignments.saturating_add(1);
        Ok(())
    }

    fn fresh_model_is_consistent(&self, model: &[Lit]) -> PropagatorResult<bool> {
        let mut closure = UnionFind::new(self.engine.term_count());
        let mut disequalities = Vec::new();
        for &literal in model {
            match (self.atom(literal)?, literal.is_pos()) {
                (TheoryAtom::Equality(left, right), true) => {
                    closure.union(left, right);
                }
                (TheoryAtom::Equality(left, right), false) => {
                    disequalities.push((left, right));
                }
                (TheoryAtom::BoolTerm(term), true) => {
                    closure.union(term, self.true_term);
                }
                (TheoryAtom::BoolTerm(term), false) => {
                    closure.union(term, self.false_term);
                }
            }
        }
        congruence_closure(self.engine.arena(), &mut closure);
        if closure.find(self.true_term) == closure.find(self.false_term) {
            return Ok(false);
        }
        Ok(disequalities
            .into_iter()
            .all(|(left, right)| closure.find(left) != closure.find(right)))
    }
}

impl ExternalPropagator for RollbackEufPropagator<'_> {
    fn notify_assignment(&mut self, literals: &[Lit]) -> PropagatorResult<()> {
        // Process the complete batch even after finding a conflict. The native
        // bridge records every notified assignment before invoking this method;
        // retained assignments will not be notified again after a partial
        // backtrack.
        for &literal in literals {
            self.apply_literal(literal)?;
        }
        Ok(())
    }

    fn notify_new_decision_level(&mut self) -> PropagatorResult<()> {
        self.engine.push_level();
        self.stats.decision_levels = self.stats.decision_levels.saturating_add(1);
        Ok(())
    }

    fn notify_backtrack(&mut self, new_level: usize) -> PropagatorResult<()> {
        self.engine.rollback_to(new_level).map_err(core_abort)?;
        if let Some((_, _, event)) = self.pending_clause.take() {
            self.set_t7_disposition(event, "preempted")?;
        }
        self.stats.backtracks = self.stats.backtracks.saturating_add(1);
        Ok(())
    }

    fn check_found_model(&mut self, model: &[Lit]) -> PropagatorResult<bool> {
        let started = Instant::now();
        self.stats.model_checks = self.stats.model_checks.saturating_add(1);
        let fresh_consistent = self.fresh_model_is_consistent(model)?;
        self.stats.model_check_time_ns = self
            .stats
            .model_check_time_ns
            .saturating_add(started.elapsed().as_nanos());
        let rollback_conflict = self.engine.current_conflict().map_err(core_abort)?;
        match (fresh_consistent, rollback_conflict) {
            (true, None) => Ok(true),
            (false, Some(conflict)) => {
                self.record_conflict(conflict, false)?;
                Ok(false)
            }
            (fresh_consistent, rollback_conflict) => Err(PropagatorAbort::new(format!(
                "fresh model validation disagreed with rollback EUF: fresh_consistent={fresh_consistent} rollback_conflict={}",
                rollback_conflict.is_some()
            ))),
        }
    }

    fn external_clause(&mut self) -> PropagatorResult<Option<ExternalClause>> {
        let Some((key, clause, event)) = self.pending_clause.take() else {
            return Ok(None);
        };
        if !self.emitted_clauses.insert(key) {
            self.set_t7_disposition(event, "handoff-duplicate")?;
            return Err(PropagatorAbort::new(
                "rollback EUF emitted a duplicate no-progress conflict",
            ));
        }
        self.set_t7_disposition(event, "emitted")?;
        self.stats.conflicts = self.stats.conflicts.saturating_add(1);
        Ok(Some(clause))
    }
}

fn core_abort(error: RollbackEufError) -> PropagatorAbort {
    PropagatorAbort::new(format!("rollback EUF core failed: {error:?}"))
}

#[cfg(test)]
mod tests {
    use rustsat::solvers::{PhaseLit, Solve, SolverResult};
    use rustsat_cadical::{CaDiCaL, Config};

    use super::*;
    use crate::SortId;

    struct RootNoop;

    impl ExternalPropagator for RootNoop {}

    struct Fixture {
        arena: TermArena,
        cnf: CnfProblem,
        true_term: TermId,
        false_term: TermId,
        equality: i32,
        congruent_equality: i32,
    }

    fn fixture() -> Fixture {
        let mut arena = TermArena::default();
        let sort = SortId(1);
        let a = arena.intern_typed(1, vec![], sort);
        let b = arena.intern_typed(2, vec![], sort);
        let fa = arena.intern_typed(10, vec![a], sort);
        let fb = arena.intern_typed(10, vec![b], sort);
        let true_term = arena.intern_typed(20, vec![], crate::BOOL_SORT);
        let false_term = arena.intern_typed(21, vec![], crate::BOOL_SORT);
        let mut cnf = CnfProblem::new();
        let equality = cnf.new_var(Some(BoolAtomKey::Eq(a, b)));
        let congruent_equality = cnf.new_var(Some(BoolAtomKey::Eq(fa, fb)));
        Fixture {
            arena,
            cnf,
            true_term,
            false_term,
            equality,
            congruent_equality,
        }
    }

    fn run_fixture(fixture: &Fixture, units: &[i32]) -> (SolverResult, RollbackPropagatorStats) {
        let mut solver = CaDiCaL::default();
        // The macOS test binary also links rustsat-kissat, whose embedded
        // legacy Kitten has global symbols that collide with CaDiCaL's newer
        // Kitten. Production configuration already uses Plain; preserve that
        // exact boundary here so CaDiCaL never enters the colliding sweeper.
        solver.set_configuration(Config::Plain).unwrap();
        for &unit in units {
            solver
                .add_unit(Lit::from_ipasir(unit).expect("fixture literal"))
                .unwrap();
        }
        let mut propagator = RollbackEufPropagator::from_cnf(
            &fixture.arena,
            &fixture.cnf,
            fixture.true_term,
            fixture.false_term,
            RollbackEufLimits::default(),
        )
        .unwrap();
        let observed = propagator.observed_variables().to_vec();
        let result = solver
            .with_external_propagator(&mut propagator, observed, |session| {
                session.solve().unwrap()
            })
            .unwrap();
        (result, propagator.stats())
    }

    #[test]
    fn real_cadical_session_rejects_a_congruence_inconsistent_model() {
        let fixture = fixture();
        let (result, stats) =
            run_fixture(&fixture, &[fixture.equality, -fixture.congruent_equality]);

        assert_eq!(result, SolverResult::Unsat);
        assert_eq!(stats.conflicts, 1);
        assert!(stats.assignments >= 2);
    }

    #[test]
    fn combined_backend_plain_configuration_is_safe() {
        let fixture = fixture();
        let mut solver = CaDiCaL::default();
        solver.set_configuration(Config::Plain).unwrap();
        solver
            .add_unit(Lit::from_ipasir(fixture.equality).unwrap())
            .unwrap();
        solver
            .add_unit(Lit::from_ipasir(fixture.congruent_equality).unwrap())
            .unwrap();
        let mut propagator = RootNoop;
        let observed = [Var::new(0), Var::new(1)];

        let result = solver
            .with_external_propagator(&mut propagator, observed, |session| {
                session.solve().unwrap()
            })
            .unwrap();

        assert_eq!(result, SolverResult::Sat);
    }

    #[test]
    fn real_cadical_session_accepts_a_theory_consistent_model() {
        let fixture = fixture();
        let (result, stats) =
            run_fixture(&fixture, &[fixture.equality, fixture.congruent_equality]);

        assert_eq!(result, SolverResult::Sat);
        assert_eq!(stats.conflicts, 0);
        assert!(stats.model_checks >= 1);
    }

    #[test]
    fn non_root_conflict_learns_backtracks_and_recovers_sat() {
        let fixture = fixture();
        let mut solver = CaDiCaL::default();
        solver.set_configuration(Config::Plain).unwrap();
        let equality = Lit::from_ipasir(fixture.equality).unwrap();
        let congruent = Lit::from_ipasir(fixture.congruent_equality).unwrap();
        solver.add_binary(equality, congruent).unwrap();
        solver.add_binary(!equality, !congruent).unwrap();
        solver.phase_lit(equality).unwrap();
        solver.phase_lit(!congruent).unwrap();
        let mut propagator = RollbackEufPropagator::from_cnf(
            &fixture.arena,
            &fixture.cnf,
            fixture.true_term,
            fixture.false_term,
            RollbackEufLimits::default(),
        )
        .unwrap();
        let observed = propagator.observed_variables().to_vec();

        let result = solver
            .with_external_propagator(&mut propagator, observed, |session| {
                session.solve().unwrap()
            })
            .unwrap();

        assert_eq!(result, SolverResult::Sat);
        assert!(propagator.stats().conflicts >= 1);
        assert!(propagator.stats().backtracks >= 1);
    }

    #[test]
    fn boolean_as_data_conflict_is_reported() {
        let mut arena = TermArena::default();
        let true_term = arena.intern_typed(20, vec![], crate::BOOL_SORT);
        let false_term = arena.intern_typed(21, vec![], crate::BOOL_SORT);
        let predicate = arena.intern_typed(22, vec![], crate::BOOL_SORT);
        let mut cnf = CnfProblem::new();
        let predicate_true = cnf.new_var(Some(BoolAtomKey::BoolTerm(predicate)));
        let predicate_false = cnf.new_var(Some(BoolAtomKey::Eq(predicate, false_term)));
        let mut solver = CaDiCaL::default();
        solver.set_configuration(Config::Plain).unwrap();
        solver
            .add_unit(Lit::from_ipasir(predicate_true).unwrap())
            .unwrap();
        solver
            .add_unit(Lit::from_ipasir(predicate_false).unwrap())
            .unwrap();
        let mut propagator = RollbackEufPropagator::from_cnf(
            &arena,
            &cnf,
            true_term,
            false_term,
            RollbackEufLimits::default(),
        )
        .unwrap();
        let observed = propagator.observed_variables().to_vec();

        let result = solver
            .with_external_propagator(&mut propagator, observed, |session| {
                session.solve().unwrap()
            })
            .unwrap();

        assert_eq!(result, SolverResult::Unsat);
        assert_eq!(propagator.stats().conflicts, 1);
    }

    #[test]
    fn unobserved_assignment_and_duplicate_conflict_fail_closed() {
        let fixture = fixture();
        let mut propagator = RollbackEufPropagator::from_cnf(
            &fixture.arena,
            &fixture.cnf,
            fixture.true_term,
            fixture.false_term,
            RollbackEufLimits::default(),
        )
        .unwrap();
        assert!(propagator.notify_assignment(&[Lit::positive(99)]).is_err());

        propagator
            .notify_assignment(&[
                Lit::from_ipasir(fixture.equality).unwrap(),
                Lit::from_ipasir(-fixture.congruent_equality).unwrap(),
            ])
            .unwrap();
        assert!(propagator.external_clause().unwrap().is_some());
        assert!(
            propagator
                .check_found_model(&[
                    Lit::from_ipasir(fixture.equality).unwrap(),
                    Lit::from_ipasir(-fixture.congruent_equality).unwrap(),
                ])
                .is_err()
        );

        let mut mismatched = RollbackEufPropagator::from_cnf(
            &fixture.arena,
            &fixture.cnf,
            fixture.true_term,
            fixture.false_term,
            RollbackEufLimits::default(),
        )
        .unwrap();
        assert!(
            mismatched
                .check_found_model(&[
                    Lit::from_ipasir(fixture.equality).unwrap(),
                    Lit::from_ipasir(-fixture.congruent_equality).unwrap(),
                ])
                .is_err()
        );
    }

    #[test]
    fn conflict_preempted_before_handoff_can_be_queued_again() {
        let fixture = fixture();
        let mut propagator = RollbackEufPropagator::from_cnf(
            &fixture.arena,
            &fixture.cnf,
            fixture.true_term,
            fixture.false_term,
            RollbackEufLimits::default(),
        )
        .unwrap();
        let conflict = [
            Lit::from_ipasir(fixture.equality).unwrap(),
            Lit::from_ipasir(-fixture.congruent_equality).unwrap(),
        ];

        propagator.notify_new_decision_level().unwrap();
        propagator.notify_assignment(&conflict).unwrap();
        assert_eq!(propagator.stats().conflicts, 0);

        // An internal SAT conflict may backtrack before CaDiCaL asks for the
        // queued theory clause. That clause was never emitted and may recur.
        propagator.notify_backtrack(0).unwrap();
        propagator.notify_new_decision_level().unwrap();
        propagator.notify_assignment(&conflict).unwrap();
        assert!(propagator.external_clause().unwrap().is_some());
        assert_eq!(propagator.stats().conflicts, 1);

        propagator.notify_backtrack(0).unwrap();
        propagator.notify_new_decision_level().unwrap();
        propagator.notify_assignment(&conflict).unwrap();
        assert!(propagator.external_clause().unwrap().is_none());
        assert_eq!(propagator.stats().repeated_assignment_conflicts, 1);
        assert!(propagator.check_found_model(&conflict).is_err());
    }
}
