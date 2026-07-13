use rustsat::{
    solvers::{Solve, SolverResult},
    types::{Lit, Var},
};
use rustsat_cadical::{
    CaDiCaL, ExternalClause, ExternalPropagator, ExternalPropagatorError,
    ExternalPropagatorFailure, PropagatorAbort, PropagatorResult,
};

struct UnitConflict {
    variable: Var,
    pending: bool,
}

impl ExternalPropagator for UnitConflict {
    fn notify_assignment(&mut self, literals: &[Lit]) -> PropagatorResult<()> {
        self.pending |= literals
            .iter()
            .any(|literal| literal.var() == self.variable && literal.is_pos());
        Ok(())
    }

    fn external_clause(&mut self) -> PropagatorResult<Option<ExternalClause>> {
        if !self.pending {
            return Ok(None);
        }
        self.pending = false;
        Ok(Some(ExternalClause::new([Lit::new(
            self.variable.idx32(),
            true,
        )])))
    }
}

#[test]
fn callback_conflict_refutes_otherwise_sat_instance() {
    let x = Lit::positive(0);
    let mut solver = CaDiCaL::default();
    solver.add_unit(x).unwrap();
    let mut propagator = UnitConflict {
        variable: x.var(),
        pending: false,
    };

    let result = solver
        .with_external_propagator(&mut propagator, [x.var()], |session| {
            assert_eq!(session.failure(), None);
            session.solve().unwrap()
        })
        .unwrap();

    assert_eq!(result, SolverResult::Unsat);
}

#[test]
fn cached_sat_result_is_revalidated_after_connection() {
    let x = Lit::positive(0);
    let mut solver = CaDiCaL::default();
    solver.add_unit(x).unwrap();
    assert_eq!(solver.solve().unwrap(), SolverResult::Sat);
    let mut propagator = UnitConflict {
        variable: x.var(),
        pending: false,
    };

    let result = solver
        .with_external_propagator(&mut propagator, [x.var()], |session| {
            session.solve().unwrap()
        })
        .unwrap();

    assert_eq!(result, SolverResult::Unsat);
}

#[derive(Debug, Clone, Copy)]
enum TrailEvent {
    NewLevel,
    Backtrack(usize),
}

#[derive(Default)]
struct RejectFirstModel {
    pending: Option<ExternalClause>,
    model_checks: usize,
    events: Vec<TrailEvent>,
}

impl ExternalPropagator for RejectFirstModel {
    fn notify_new_decision_level(&mut self) -> PropagatorResult<()> {
        self.events.push(TrailEvent::NewLevel);
        Ok(())
    }

    fn notify_backtrack(&mut self, new_level: usize) -> PropagatorResult<()> {
        self.events.push(TrailEvent::Backtrack(new_level));
        Ok(())
    }

    fn check_found_model(&mut self, model: &[Lit]) -> PropagatorResult<bool> {
        self.model_checks += 1;
        if self.model_checks == 1 {
            self.pending = Some(ExternalClause::new(model.iter().map(|literal| !*literal)));
            Ok(false)
        } else {
            Ok(true)
        }
    }

    fn external_clause(&mut self) -> PropagatorResult<Option<ExternalClause>> {
        Ok(self.pending.take())
    }
}

#[test]
fn model_rejection_continues_search_and_backtracks_in_order() {
    let x = Lit::positive(0);
    let y = Lit::positive(1);
    let mut solver = CaDiCaL::default();
    solver.add_binary(x, y).unwrap();
    solver.add_binary(!x, !y).unwrap();
    let mut propagator = RejectFirstModel::default();

    let result = solver
        .with_external_propagator(&mut propagator, [x.var(), y.var()], |session| {
            let result = session.solve().unwrap();
            assert_eq!(session.failure(), None);
            result
        })
        .unwrap();

    assert_eq!(result, SolverResult::Sat);
    assert!(propagator.model_checks >= 2);
    assert!(propagator
        .events
        .iter()
        .any(|event| matches!(event, TrailEvent::Backtrack(_))));

    let mut level = 0;
    for event in &propagator.events {
        match event {
            TrailEvent::NewLevel => level += 1,
            TrailEvent::Backtrack(new_level) => {
                assert!(*new_level < level);
                level = *new_level;
            }
        }
    }

    let model_checks = propagator.model_checks;
    assert_eq!(solver.solve().unwrap(), SolverResult::Sat);
    assert_eq!(propagator.model_checks, model_checks);
}

struct PanickingPropagator;

impl ExternalPropagator for PanickingPropagator {
    fn notify_assignment(&mut self, _literals: &[Lit]) -> PropagatorResult<()> {
        panic!("intentional callback panic");
    }
}

struct AbortOnAssignment;

impl ExternalPropagator for AbortOnAssignment {
    fn notify_assignment(&mut self, _literals: &[Lit]) -> PropagatorResult<()> {
        Err(PropagatorAbort::new("reject fixed assignment"))
    }
}

#[test]
fn registration_callback_failure_prevents_operation() {
    let x = Lit::positive(0);
    let mut solver = CaDiCaL::default();
    solver.add_unit(x).unwrap();
    assert_eq!(solver.solve().unwrap(), SolverResult::Sat);
    let mut propagator = AbortOnAssignment;
    let operation_called = std::cell::Cell::new(false);

    let failure = solver
        .with_external_propagator(&mut propagator, [x.var()], |_session| {
            operation_called.set(true);
        })
        .unwrap_err();

    assert!(!operation_called.get());
    assert!(matches!(
        failure,
        ExternalPropagatorError::Callback(ExternalPropagatorFailure::CallbackAborted {
            callback: "notify_assignment",
            ..
        })
    ));
}

#[test]
fn callback_panic_terminates_without_unwinding_through_ffi() {
    let x = Lit::positive(0);
    let mut solver = CaDiCaL::default();
    solver.add_unit(x).unwrap();
    let mut propagator = PanickingPropagator;

    let failure = solver
        .with_external_propagator(&mut propagator, [x.var()], |session| {
            session.solve().unwrap()
        })
        .unwrap_err();

    assert!(matches!(
        failure,
        ExternalPropagatorError::Callback(ExternalPropagatorFailure::CallbackPanicked {
            callback: "notify_assignment"
        })
    ));
}

struct UnobservedConflict {
    pending: bool,
    unobserved: Lit,
}

impl ExternalPropagator for UnobservedConflict {
    fn notify_assignment(&mut self, _literals: &[Lit]) -> PropagatorResult<()> {
        self.pending = true;
        Ok(())
    }

    fn external_clause(&mut self) -> PropagatorResult<Option<ExternalClause>> {
        if !self.pending {
            return Ok(None);
        }
        self.pending = false;
        Ok(Some(ExternalClause::new([self.unobserved])))
    }
}

#[test]
fn malformed_clause_output_terminates_before_reaching_cadical() {
    let x = Lit::positive(0);
    let y = Lit::positive(1);
    let mut solver = CaDiCaL::default();
    solver.add_unit(x).unwrap();
    let mut propagator = UnobservedConflict {
        pending: false,
        unobserved: !y,
    };

    let failure = solver
        .with_external_propagator(&mut propagator, [x.var()], |session| {
            session.solve().unwrap()
        })
        .unwrap_err();

    assert!(matches!(
        failure,
        ExternalPropagatorError::Callback(ExternalPropagatorFailure::MalformedClause {
            callback: "has_external_clause",
            ..
        })
    ));
}

#[test]
fn explicit_abort_fails_the_scope() {
    let x = Lit::positive(0);
    let mut solver = CaDiCaL::default();
    solver.add_unit(x).unwrap();
    let mut propagator = RejectFirstModel::default();

    let failure = solver
        .with_external_propagator(&mut propagator, [x.var()], |session| {
            session.abort("test requested stop");
        })
        .unwrap_err();

    assert!(matches!(
        failure,
        ExternalPropagatorError::Callback(ExternalPropagatorFailure::ExplicitAbort {
            message
        }) if message == "test requested stop"
    ));
}

#[test]
fn operation_panic_disconnects_before_unwinding() {
    let x = Lit::positive(0);
    let mut solver = CaDiCaL::default();
    solver.add_unit(x).unwrap();
    let mut propagator = RejectFirstModel::default();

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = solver.with_external_propagator(&mut propagator, [x.var()], |_session| {
            panic!("intentional operation panic");
        });
    }));

    assert!(panic.is_err());
    assert_eq!(solver.solve().unwrap(), SolverResult::Sat);
}

struct AbortOnBacktrack;

impl ExternalPropagator for AbortOnBacktrack {
    fn notify_backtrack(&mut self, _new_level: usize) -> PropagatorResult<()> {
        Err(PropagatorAbort::new("reject teardown backtrack"))
    }
}

#[test]
fn disconnect_callback_failure_is_not_lost() {
    let x = Lit::positive(0);
    let y = Lit::positive(1);
    let mut solver = CaDiCaL::default();
    solver.add_binary(x, y).unwrap();
    let mut propagator = AbortOnBacktrack;

    let failure = solver
        .with_external_propagator(&mut propagator, [x.var(), y.var()], |session| {
            assert_eq!(session.solve().unwrap(), SolverResult::Sat);
        })
        .unwrap_err();

    assert!(matches!(
        failure,
        ExternalPropagatorError::Callback(ExternalPropagatorFailure::CallbackAborted {
            callback: "notify_backtrack",
            ..
        })
    ));
}

struct RejectWithoutClause;

impl ExternalPropagator for RejectWithoutClause {
    fn check_found_model(&mut self, _model: &[Lit]) -> PropagatorResult<bool> {
        Ok(false)
    }
}

#[test]
fn rejected_model_without_clause_fails_callback_order() {
    let x = Lit::positive(0);
    let mut solver = CaDiCaL::default();
    solver.add_unit(x).unwrap();
    let mut propagator = RejectWithoutClause;

    let failure = solver
        .with_external_propagator(&mut propagator, [x.var()], |session| {
            session.solve().unwrap()
        })
        .unwrap_err();

    assert!(matches!(
        failure,
        ExternalPropagatorError::Callback(ExternalPropagatorFailure::CallbackOrder {
            callback: "has_external_clause",
            ..
        })
    ));
}

#[test]
fn ordinary_solver_behavior_is_unchanged_without_connection() {
    let x = Lit::positive(0);
    let y = Lit::positive(1);
    let mut solver = CaDiCaL::default();
    solver.add_binary(x, y).unwrap();
    solver.add_unit(!x).unwrap();

    assert_eq!(solver.solve().unwrap(), SolverResult::Sat);
    assert!(solver.lit_val(y).unwrap().to_bool_with_def(false));

    solver.add_unit(!y).unwrap();
    assert_eq!(solver.solve().unwrap(), SolverResult::Unsat);
}

#[test]
fn accepted_model_is_readable_before_disconnect() {
    struct AcceptAll;
    impl ExternalPropagator for AcceptAll {}

    let x = Lit::positive(0);
    let mut solver = CaDiCaL::default();
    solver.add_unit(x).unwrap();
    let mut propagator = AcceptAll;

    let value = solver
        .with_external_propagator(&mut propagator, [x.var()], |session| {
            assert_eq!(session.solve().unwrap(), SolverResult::Sat);
            session.lit_val(x).unwrap()
        })
        .unwrap();

    assert!(value.to_bool_with_def(false));
}
