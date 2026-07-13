//! Safe, conflict-only access to CaDiCaL's IPASIR-UP propagator callbacks.

use std::{
    cell::{Cell, RefCell, UnsafeCell},
    collections::{BTreeMap, BTreeSet},
    ffi::{c_int, c_void},
    marker::PhantomData,
    panic::{catch_unwind, AssertUnwindSafe},
    pin::Pin,
    ptr::NonNull,
    rc::Rc,
    slice,
};

use rustsat::{
    solvers::{Solve, SolverResult},
    types::{Lit, TernaryVal, Var},
};
use thiserror::Error;

use crate::{ffi, CaDiCaL, InternalSolverState};

/// A controlled abort requested by an external propagator callback.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{message}")]
pub struct PropagatorAbort {
    message: String,
}

impl PropagatorAbort {
    /// Creates a callback abort with a diagnostic message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the abort diagnostic.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Result returned by external propagator callbacks.
pub type PropagatorResult<T> = Result<T, PropagatorAbort>;

/// A clause supplied during CaDiCaL search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalClause {
    literals: Vec<Lit>,
    forgettable: bool,
}

impl ExternalClause {
    /// Creates a persistent external clause.
    pub fn new(literals: impl IntoIterator<Item = Lit>) -> Self {
        Self {
            literals: literals.into_iter().collect(),
            forgettable: false,
        }
    }

    /// Marks whether CaDiCaL may remove this clause during database reduction.
    #[must_use]
    pub fn forgettable(mut self, forgettable: bool) -> Self {
        self.forgettable = forgettable;
        self
    }

    /// Returns the clause literals.
    #[must_use]
    pub fn literals(&self) -> &[Lit] {
        &self.literals
    }

    /// Returns whether the clause may be forgotten.
    #[must_use]
    pub fn is_forgettable(&self) -> bool {
        self.forgettable
    }
}

/// Conflict-only subset of CaDiCaL's external propagator interface.
///
/// Decision and propagation callbacks are intentionally unavailable. CaDiCaL
/// always receives zero from both callbacks. Every external clause is checked
/// to contain only observed variables and to be falsified by the current
/// notified assignment before it crosses the FFI boundary.
pub trait ExternalPropagator {
    /// Observes newly assigned literals at the current decision level.
    fn notify_assignment(&mut self, _literals: &[Lit]) -> PropagatorResult<()> {
        Ok(())
    }

    /// Observes creation of a decision level.
    fn notify_new_decision_level(&mut self) -> PropagatorResult<()> {
        Ok(())
    }

    /// Observes rollback to `new_level`.
    fn notify_backtrack(&mut self, _new_level: usize) -> PropagatorResult<()> {
        Ok(())
    }

    /// Checks a complete assignment. Returning `false` requires the next
    /// [`Self::external_clause`] call to return a blocking clause.
    fn check_found_model(&mut self, _model: &[Lit]) -> PropagatorResult<bool> {
        Ok(true)
    }

    /// Returns a conflict clause for the current assignment, if one exists.
    fn external_clause(&mut self) -> PropagatorResult<Option<ExternalClause>> {
        Ok(None)
    }

    /// Returns the reason for an externally propagated literal.
    ///
    /// Propagation is disabled in this research API, so CaDiCaL must not call
    /// this method. It is retained to keep the adapter's reason callback
    /// fail-closed and to define the future extension point.
    fn reason_clause(&mut self, _propagated: Lit) -> PropagatorResult<ExternalClause> {
        Err(PropagatorAbort::new(
            "reason requested while external propagation is disabled",
        ))
    }
}

/// Why an external propagator connection aborted.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ExternalPropagatorFailure {
    /// A callback returned a controlled abort.
    #[error("external propagator callback `{callback}` aborted: {message}")]
    CallbackAborted {
        /// Callback name.
        callback: &'static str,
        /// Callback diagnostic.
        message: String,
    },
    /// A callback panicked. The panic was caught before crossing the FFI boundary.
    #[error("external propagator callback `{callback}` panicked")]
    CallbackPanicked {
        /// Callback name.
        callback: &'static str,
    },
    /// CaDiCaL attempted a nested callback while another callback was active.
    #[error("reentrant external propagator callback `{callback}`")]
    ReentrantCallback {
        /// Callback name.
        callback: &'static str,
    },
    /// A literal received from CaDiCaL was not a valid IPASIR literal.
    #[error("callback `{callback}` received malformed literal {literal}")]
    MalformedLiteral {
        /// Callback name.
        callback: &'static str,
        /// Raw IPASIR literal.
        literal: c_int,
    },
    /// A callback supplied a clause that violates the conflict-only contract.
    #[error("callback `{callback}` supplied a malformed clause: {message}")]
    MalformedClause {
        /// Callback name.
        callback: &'static str,
        /// Validation diagnostic.
        message: String,
    },
    /// CaDiCaL invoked callbacks in an invalid order.
    #[error("callback order violation in `{callback}`: {message}")]
    CallbackOrder {
        /// Callback name.
        callback: &'static str,
        /// Ordering diagnostic.
        message: String,
    },
    /// Callback input could not be buffered without exceeding available memory.
    #[error("callback `{callback}` could not allocate space for {elements} literals")]
    AllocationFailure {
        /// Callback name.
        callback: &'static str,
        /// Requested number of literals.
        elements: usize,
    },
    /// The caller explicitly aborted the connection.
    #[error("external propagator explicitly aborted: {message}")]
    ExplicitAbort {
        /// Abort diagnostic.
        message: String,
    },
}

/// Error while establishing an external propagator connection.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ExternalPropagatorConnectError {
    /// The native adapter could not be allocated or connected.
    #[error("CaDiCaL rejected the external propagator connection")]
    NativeConnectionFailed,
    /// CaDiCaL rejected an observed variable.
    #[error("CaDiCaL rejected observed variable {variable}")]
    ObserveVariableFailed {
        /// One-based DIMACS variable index.
        variable: c_int,
    },
}

/// Error returned by a scoped external propagator run.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ExternalPropagatorError {
    /// The native connection could not be established.
    #[error(transparent)]
    Connection(#[from] ExternalPropagatorConnectError),
    /// A callback failed after the native connection was established.
    #[error(transparent)]
    Callback(ExternalPropagatorFailure),
}

enum ClauseStream {
    Idle,
    External {
        literals: Vec<c_int>,
        next: usize,
    },
    Reason {
        propagated: c_int,
        literals: Vec<c_int>,
        next: usize,
    },
}

struct CallbackInner<'prop> {
    propagator: &'prop mut dyn ExternalPropagator,
    observed: BTreeSet<c_int>,
    assignments: BTreeMap<c_int, c_int>,
    trail: Vec<(c_int, c_int)>,
    level_starts: Vec<usize>,
    stream: ClauseStream,
    rejected_model: bool,
}

struct CallbackState<'prop> {
    in_callback: Cell<bool>,
    failure: RefCell<Option<ExternalPropagatorFailure>>,
    inner: UnsafeCell<CallbackInner<'prop>>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl CallbackState<'_> {
    fn record_failure(&self, failure: ExternalPropagatorFailure) {
        let mut current = self.failure.borrow_mut();
        if current.is_none() {
            *current = Some(failure);
        }
    }

    fn run<T>(
        &self,
        callback: &'static str,
        operation: impl FnOnce(&mut CallbackInner<'_>) -> Result<T, ExternalPropagatorFailure>,
    ) -> Option<T> {
        if self.failure.borrow().is_some() {
            return None;
        }
        if self.in_callback.replace(true) {
            self.record_failure(ExternalPropagatorFailure::ReentrantCallback { callback });
            return None;
        }

        let result = catch_unwind(AssertUnwindSafe(|| {
            // The entry flag prevents a nested callback from creating another
            // mutable reference to the callback payload.
            let inner = unsafe { &mut *self.inner.get() };
            operation(inner)
        }));
        self.in_callback.set(false);

        match result {
            Ok(Ok(value)) if self.failure.borrow().is_none() => Some(value),
            Ok(Ok(_)) => None,
            Ok(Err(failure)) => {
                self.record_failure(failure);
                None
            }
            Err(_) => {
                self.record_failure(ExternalPropagatorFailure::CallbackPanicked { callback });
                None
            }
        }
    }
}

fn callback_abort(callback: &'static str, abort: PropagatorAbort) -> ExternalPropagatorFailure {
    ExternalPropagatorFailure::CallbackAborted {
        callback,
        message: abort.message,
    }
}

fn parse_literals(
    inner: &CallbackInner<'_>,
    callback: &'static str,
    raw: *const c_int,
    len: usize,
) -> Result<Vec<Lit>, ExternalPropagatorFailure> {
    if len > 0 && raw.is_null() {
        return Err(ExternalPropagatorFailure::CallbackOrder {
            callback,
            message: "non-empty literal array had a null pointer".to_owned(),
        });
    }
    let raw_literals = if len == 0 {
        &[]
    } else {
        // CaDiCaL owns this immutable array for the duration of the callback.
        unsafe { slice::from_raw_parts(raw, len) }
    };
    let mut literals = Vec::new();
    literals
        .try_reserve_exact(len)
        .map_err(|_| ExternalPropagatorFailure::AllocationFailure {
            callback,
            elements: len,
        })?;
    for &raw_lit in raw_literals {
        let literal =
            Lit::from_ipasir(raw_lit).map_err(|_| ExternalPropagatorFailure::MalformedLiteral {
                callback,
                literal: raw_lit,
            })?;
        let variable = literal.var().to_ipasir();
        if !inner.observed.contains(&variable) {
            return Err(ExternalPropagatorFailure::MalformedClause {
                callback,
                message: format!("literal {raw_lit} uses unobserved variable {variable}"),
            });
        }
        literals.push(literal);
    }
    Ok(literals)
}

fn require_idle(
    inner: &CallbackInner<'_>,
    callback: &'static str,
) -> Result<(), ExternalPropagatorFailure> {
    if matches!(inner.stream, ClauseStream::Idle) {
        Ok(())
    } else {
        Err(ExternalPropagatorFailure::CallbackOrder {
            callback,
            message: "a previous clause callback was not terminated".to_owned(),
        })
    }
}

fn validate_conflict_clause(
    inner: &CallbackInner<'_>,
    callback: &'static str,
    clause: ExternalClause,
) -> Result<(Vec<c_int>, bool), ExternalPropagatorFailure> {
    let mut variables = BTreeSet::new();
    let mut raw = Vec::new();
    raw.try_reserve_exact(clause.literals.len()).map_err(|_| {
        ExternalPropagatorFailure::AllocationFailure {
            callback,
            elements: clause.literals.len(),
        }
    })?;
    for literal in clause.literals {
        let raw_lit = literal.to_ipasir();
        let variable = literal.var().to_ipasir();
        if !inner.observed.contains(&variable) {
            return Err(ExternalPropagatorFailure::MalformedClause {
                callback,
                message: format!("literal {raw_lit} uses unobserved variable {variable}"),
            });
        }
        if !variables.insert(variable) {
            return Err(ExternalPropagatorFailure::MalformedClause {
                callback,
                message: format!("variable {variable} occurs more than once"),
            });
        }
        let Some(&assigned) = inner.assignments.get(&variable) else {
            return Err(ExternalPropagatorFailure::MalformedClause {
                callback,
                message: format!("variable {variable} is not currently assigned"),
            });
        };
        if assigned == raw_lit {
            return Err(ExternalPropagatorFailure::MalformedClause {
                callback,
                message: format!("literal {raw_lit} is true in the current assignment"),
            });
        }
        raw.push(raw_lit);
    }
    Ok((raw, clause.forgettable))
}

fn validate_reason_clause(
    inner: &CallbackInner<'_>,
    callback: &'static str,
    propagated: Lit,
    clause: ExternalClause,
) -> Result<Vec<c_int>, ExternalPropagatorFailure> {
    let propagated_raw = propagated.to_ipasir();
    let mut raw = Vec::new();
    raw.try_reserve_exact(clause.literals.len()).map_err(|_| {
        ExternalPropagatorFailure::AllocationFailure {
            callback,
            elements: clause.literals.len(),
        }
    })?;
    let mut variables = BTreeSet::new();
    let mut seen_propagated = false;
    for literal in clause.literals {
        let raw_lit = literal.to_ipasir();
        let variable = literal.var().to_ipasir();
        if !inner.observed.contains(&variable) {
            return Err(ExternalPropagatorFailure::MalformedClause {
                callback,
                message: format!("literal {raw_lit} uses unobserved variable {variable}"),
            });
        }
        if !variables.insert(variable) {
            return Err(ExternalPropagatorFailure::MalformedClause {
                callback,
                message: format!("variable {variable} occurs more than once"),
            });
        }
        if raw_lit == propagated_raw {
            seen_propagated = true;
        } else if inner.assignments.get(&variable) != Some(&-raw_lit) {
            return Err(ExternalPropagatorFailure::MalformedClause {
                callback,
                message: format!("reason literal {raw_lit} is not currently false"),
            });
        }
        raw.push(raw_lit);
    }
    if !seen_propagated {
        return Err(ExternalPropagatorFailure::MalformedClause {
            callback,
            message: format!("reason does not contain propagated literal {propagated_raw}"),
        });
    }
    Ok(raw)
}

unsafe fn state_from_ptr<'a>(state: *mut c_void) -> Option<&'a CallbackState<'a>> {
    state.cast::<CallbackState<'a>>().as_ref()
}

unsafe extern "C" fn notify_assignment(state: *mut c_void, raw: *const c_int, len: usize) -> c_int {
    let Some(state) = (unsafe { state_from_ptr(state) }) else {
        return 0;
    };
    state
        .run("notify_assignment", |inner| {
            require_idle(inner, "notify_assignment")?;
            let literals = parse_literals(inner, "notify_assignment", raw, len)?;
            let mut newly_assigned = Vec::new();
            newly_assigned.try_reserve_exact(literals.len()).map_err(|_| {
                ExternalPropagatorFailure::AllocationFailure {
                    callback: "notify_assignment",
                    elements: literals.len(),
                }
            })?;
            for literal in literals {
                let variable = literal.var().to_ipasir();
                let raw_lit = literal.to_ipasir();
                if let Some(&assigned) = inner.assignments.get(&variable) {
                    if assigned == raw_lit {
                        continue;
                    }
                    return Err(ExternalPropagatorFailure::CallbackOrder {
                        callback: "notify_assignment",
                        message: format!(
                            "variable {variable} changed from {assigned} to {raw_lit} without rollback"
                        ),
                    });
                }
                inner.assignments.insert(variable, raw_lit);
                inner.trail.push((variable, raw_lit));
                newly_assigned.push(literal);
            }
            if newly_assigned.is_empty() {
                Ok(())
            } else {
                inner
                    .propagator
                    .notify_assignment(&newly_assigned)
                    .map_err(|abort| callback_abort("notify_assignment", abort))
            }
        })
        .map_or(0, |()| 1)
}

unsafe extern "C" fn notify_new_decision_level(state: *mut c_void) -> c_int {
    let Some(state) = (unsafe { state_from_ptr(state) }) else {
        return 0;
    };
    state
        .run("notify_new_decision_level", |inner| {
            require_idle(inner, "notify_new_decision_level")?;
            inner.level_starts.push(inner.trail.len());
            inner
                .propagator
                .notify_new_decision_level()
                .map_err(|abort| callback_abort("notify_new_decision_level", abort))
        })
        .map_or(0, |()| 1)
}

unsafe extern "C" fn notify_backtrack(state: *mut c_void, new_level: usize) -> c_int {
    let Some(state) = (unsafe { state_from_ptr(state) }) else {
        return 0;
    };
    state
        .run("notify_backtrack", |inner| {
            require_idle(inner, "notify_backtrack")?;
            let current_level = inner.level_starts.len() - 1;
            if new_level >= current_level {
                return Err(ExternalPropagatorFailure::CallbackOrder {
                    callback: "notify_backtrack",
                    message: format!("cannot backtrack from level {current_level} to {new_level}"),
                });
            }
            let keep = inner.level_starts[new_level + 1];
            while inner.trail.len() > keep {
                let (variable, _) = inner.trail.pop().expect("trail length checked");
                inner.assignments.remove(&variable);
            }
            inner.level_starts.truncate(new_level + 1);
            inner.rejected_model = false;
            inner
                .propagator
                .notify_backtrack(new_level)
                .map_err(|abort| callback_abort("notify_backtrack", abort))
        })
        .map_or(0, |()| 1)
}

unsafe extern "C" fn check_found_model(
    state: *mut c_void,
    raw: *const c_int,
    len: usize,
    accepted: *mut c_int,
) -> c_int {
    let Some(state) = (unsafe { state_from_ptr(state) }) else {
        return 0;
    };
    if accepted.is_null() {
        state.record_failure(ExternalPropagatorFailure::CallbackOrder {
            callback: "check_found_model",
            message: "null result pointer".to_owned(),
        });
        return 0;
    }
    let Some(is_accepted) = state.run("check_found_model", |inner| {
        require_idle(inner, "check_found_model")?;
        let model = parse_literals(inner, "check_found_model", raw, len)?;
        if model.len() != inner.observed.len() {
            return Err(ExternalPropagatorFailure::CallbackOrder {
                callback: "check_found_model",
                message: format!(
                    "model has {} literals for {} observed variables",
                    model.len(),
                    inner.observed.len()
                ),
            });
        }
        let mut model_variables = BTreeSet::new();
        for literal in &model {
            let variable = literal.var().to_ipasir();
            if !model_variables.insert(variable) {
                return Err(ExternalPropagatorFailure::CallbackOrder {
                    callback: "check_found_model",
                    message: format!("model assigns variable {variable} more than once"),
                });
            }
            if inner.assignments.get(&variable) != Some(&literal.to_ipasir()) {
                return Err(ExternalPropagatorFailure::CallbackOrder {
                    callback: "check_found_model",
                    message: format!("model disagrees with notified assignment for {variable}"),
                });
            }
        }
        let accepted = inner
            .propagator
            .check_found_model(&model)
            .map_err(|abort| callback_abort("check_found_model", abort))?;
        inner.rejected_model = !accepted;
        Ok(accepted)
    }) else {
        return 0;
    };
    unsafe { accepted.write(c_int::from(is_accepted)) };
    1
}

unsafe extern "C" fn has_external_clause(
    state: *mut c_void,
    has_clause: *mut c_int,
    forgettable: *mut c_int,
) -> c_int {
    let Some(state) = (unsafe { state_from_ptr(state) }) else {
        return 0;
    };
    if has_clause.is_null() || forgettable.is_null() {
        state.record_failure(ExternalPropagatorFailure::CallbackOrder {
            callback: "has_external_clause",
            message: "null result pointer".to_owned(),
        });
        return 0;
    }
    let Some(clause) = state.run("has_external_clause", |inner| {
        require_idle(inner, "has_external_clause")?;
        let clause = inner
            .propagator
            .external_clause()
            .map_err(|abort| callback_abort("has_external_clause", abort))?;
        if inner.rejected_model && clause.is_none() {
            return Err(ExternalPropagatorFailure::CallbackOrder {
                callback: "has_external_clause",
                message: "a rejected model was not followed by a blocking clause".to_owned(),
            });
        }
        let Some(clause) = clause else {
            return Ok(None);
        };
        let (literals, forgettable) =
            validate_conflict_clause(inner, "has_external_clause", clause)?;
        inner.stream = ClauseStream::External { literals, next: 0 };
        Ok(Some(forgettable))
    }) else {
        return 0;
    };
    unsafe {
        has_clause.write(c_int::from(clause.is_some()));
        forgettable.write(c_int::from(clause.unwrap_or(false)));
    }
    1
}

unsafe extern "C" fn add_external_clause_lit(state: *mut c_void, literal: *mut c_int) -> c_int {
    let Some(state) = (unsafe { state_from_ptr(state) }) else {
        return 0;
    };
    if literal.is_null() {
        state.record_failure(ExternalPropagatorFailure::CallbackOrder {
            callback: "add_external_clause_lit",
            message: "null result pointer".to_owned(),
        });
        return 0;
    }
    let Some(next_literal) = state.run("add_external_clause_lit", |inner| {
        let ClauseStream::External { literals, next } = &mut inner.stream else {
            return Err(ExternalPropagatorFailure::CallbackOrder {
                callback: "add_external_clause_lit",
                message: "no external clause is pending".to_owned(),
            });
        };
        if *next < literals.len() {
            let literal = literals[*next];
            *next += 1;
            Ok(literal)
        } else {
            inner.stream = ClauseStream::Idle;
            inner.rejected_model = false;
            Ok(0)
        }
    }) else {
        return 0;
    };
    unsafe { literal.write(next_literal) };
    1
}

unsafe extern "C" fn add_reason_clause_lit(
    state: *mut c_void,
    propagated_raw: c_int,
    literal: *mut c_int,
) -> c_int {
    let Some(state) = (unsafe { state_from_ptr(state) }) else {
        return 0;
    };
    if literal.is_null() {
        state.record_failure(ExternalPropagatorFailure::CallbackOrder {
            callback: "add_reason_clause_lit",
            message: "null result pointer".to_owned(),
        });
        return 0;
    }
    let Some(next_literal) = state.run("add_reason_clause_lit", |inner| {
        let propagated = Lit::from_ipasir(propagated_raw).map_err(|_| {
            ExternalPropagatorFailure::MalformedLiteral {
                callback: "add_reason_clause_lit",
                literal: propagated_raw,
            }
        })?;
        if !inner.observed.contains(&propagated.var().to_ipasir()) {
            return Err(ExternalPropagatorFailure::MalformedClause {
                callback: "add_reason_clause_lit",
                message: format!("propagated literal {propagated_raw} is not observed"),
            });
        }
        if matches!(inner.stream, ClauseStream::Idle) {
            let clause = inner
                .propagator
                .reason_clause(propagated)
                .map_err(|abort| callback_abort("add_reason_clause_lit", abort))?;
            let literals =
                validate_reason_clause(inner, "add_reason_clause_lit", propagated, clause)?;
            inner.stream = ClauseStream::Reason {
                propagated: propagated_raw,
                literals,
                next: 0,
            };
        }
        let ClauseStream::Reason {
            propagated,
            literals,
            next,
        } = &mut inner.stream
        else {
            return Err(ExternalPropagatorFailure::CallbackOrder {
                callback: "add_reason_clause_lit",
                message: "an external conflict clause is pending".to_owned(),
            });
        };
        if *propagated != propagated_raw {
            return Err(ExternalPropagatorFailure::CallbackOrder {
                callback: "add_reason_clause_lit",
                message: "reason literal changed while streaming a clause".to_owned(),
            });
        }
        if *next < literals.len() {
            let literal = literals[*next];
            *next += 1;
            Ok(literal)
        } else {
            inner.stream = ClauseStream::Idle;
            Ok(0)
        }
    }) else {
        return 0;
    };
    unsafe { literal.write(next_literal) };
    1
}

const CALLBACKS: ffi::CCaDiCaLExternalPropagatorCallbacks =
    ffi::CCaDiCaLExternalPropagatorCallbacks {
        notify_assignment: Some(notify_assignment),
        notify_new_decision_level: Some(notify_new_decision_level),
        notify_backtrack: Some(notify_backtrack),
        check_found_model: Some(check_found_model),
        has_external_clause: Some(has_external_clause),
        add_external_clause_lit: Some(add_external_clause_lit),
        add_reason_clause_lit: Some(add_reason_clause_lit),
    };

struct DisconnectGuard {
    native: NonNull<ffi::CCaDiCaLExternalPropagator>,
}

impl Drop for DisconnectGuard {
    fn drop(&mut self) {
        unsafe { ffi::ccadical_disconnect_external_propagator(self.native.as_ptr()) };
    }
}

/// Restricted solver and status handle valid only inside a connected scope.
///
/// This type deliberately does not expose `&mut CaDiCaL`: replacing or
/// reconnecting the solver while the native adapter holds pointers into the
/// callback state would invalidate those pointers.
pub struct ExternalPropagatorSession<'scope, 'prop, 'term, 'learn> {
    solver: &'scope mut CaDiCaL<'term, 'learn>,
    native: NonNull<ffi::CCaDiCaLExternalPropagator>,
    state: &'scope CallbackState<'prop>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl std::fmt::Debug for ExternalPropagatorSession<'_, '_, '_, '_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExternalPropagatorSession")
            .field("failure", &self.failure())
            .finish_non_exhaustive()
    }
}

impl ExternalPropagatorSession<'_, '_, '_, '_> {
    /// Solves with the external propagator connected.
    pub fn solve(&mut self) -> anyhow::Result<SolverResult> {
        self.solver.solve()
    }

    /// Reads a literal from the accepted model before native disconnect can
    /// backtrack while unobserving variables.
    pub fn lit_val(&self, literal: Lit) -> anyhow::Result<TernaryVal> {
        self.solver.lit_val(literal)
    }

    /// Requests termination and records an explicit failure.
    pub fn abort(&self, message: impl Into<String>) {
        self.state
            .record_failure(ExternalPropagatorFailure::ExplicitAbort {
                message: message.into(),
            });
        unsafe { ffi::ccadical_external_propagator_abort(self.native.as_ptr()) };
    }

    /// Returns the first fail-closed condition observed by the adapter.
    #[must_use]
    pub fn failure(&self) -> Option<ExternalPropagatorFailure> {
        self.state.failure.borrow().clone()
    }

    /// Returns whether the adapter has entered its fail-closed state.
    #[must_use]
    pub fn is_aborted(&self) -> bool {
        self.state.failure.borrow().is_some()
    }
}

impl<'term, 'learn> CaDiCaL<'term, 'learn> {
    /// Connects an external propagator for exactly the duration of `operation`.
    ///
    /// The callback payload is pinned before native connection, the closure
    /// cannot outlive either borrowed object, and a guard disconnects the C++
    /// adapter before the callback payload is dropped, including during panic
    /// unwinding.
    ///
    /// A callback failure takes precedence over `operation`'s return value.
    /// Callers must wait for this method to return before acting on a solver
    /// result produced inside the closure.
    pub fn with_external_propagator<'prop, I, F, R>(
        &mut self,
        propagator: &'prop mut dyn ExternalPropagator,
        observed: I,
        operation: F,
    ) -> Result<R, ExternalPropagatorError>
    where
        I: IntoIterator<Item = Var>,
        F: FnOnce(&mut ExternalPropagatorSession<'_, 'prop, 'term, 'learn>) -> R,
    {
        let observed: BTreeSet<c_int> = observed.into_iter().map(Var::to_ipasir).collect();
        let state = CallbackState {
            in_callback: Cell::new(false),
            failure: RefCell::new(None),
            inner: UnsafeCell::new(CallbackInner {
                propagator,
                observed: observed.clone(),
                assignments: BTreeMap::new(),
                trail: Vec::new(),
                level_starts: vec![0],
                stream: ClauseStream::Idle,
                rejected_model: false,
            }),
            _not_send_or_sync: PhantomData,
        };
        let state: Pin<Box<CallbackState<'_>>> = Box::pin(state);
        let state_ptr = std::ptr::from_ref(state.as_ref().get_ref())
            .cast_mut()
            .cast::<c_void>();
        let native = NonNull::new(unsafe {
            ffi::ccadical_connect_external_propagator(self.handle, state_ptr, CALLBACKS)
        })
        .ok_or(ExternalPropagatorConnectError::NativeConnectionFailed)?;
        let guard = DisconnectGuard { native };
        if self.state != InternalSolverState::Configuring {
            // Connecting can backtrack the native solver. More importantly,
            // a cached SAT result must never bypass the propagator callbacks.
            self.state = InternalSolverState::Input;
        }
        for variable in observed {
            let accepted = unsafe {
                ffi::ccadical_external_propagator_add_observed_var(native.as_ptr(), variable)
            };
            if accepted != 1 {
                drop(guard);
                self.state = InternalSolverState::Input;
                return Err(
                    ExternalPropagatorConnectError::ObserveVariableFailed { variable }.into(),
                );
            }
            if let Some(failure) = state.failure.borrow().clone() {
                drop(guard);
                self.state = InternalSolverState::Input;
                return Err(ExternalPropagatorError::Callback(failure));
            }
        }
        let mut session = ExternalPropagatorSession {
            solver: self,
            native,
            state: state.as_ref().get_ref(),
            _not_send_or_sync: PhantomData,
        };
        let result = operation(&mut session);
        drop(session);
        drop(guard);
        let failure = state.failure.borrow().clone();
        if let Some(failure) = failure {
            self.state = InternalSolverState::Input;
            Err(ExternalPropagatorError::Callback(failure))
        } else {
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopPropagator;

    impl ExternalPropagator for NoopPropagator {}

    fn callback_state(propagator: &mut dyn ExternalPropagator) -> CallbackState<'_> {
        CallbackState {
            in_callback: Cell::new(false),
            failure: RefCell::new(None),
            inner: UnsafeCell::new(CallbackInner {
                propagator,
                observed: BTreeSet::from([1]),
                assignments: BTreeMap::new(),
                trail: Vec::new(),
                level_starts: vec![0],
                stream: ClauseStream::Idle,
                rejected_model: false,
            }),
            _not_send_or_sync: PhantomData,
        }
    }

    #[test]
    fn reentrant_callback_never_borrows_payload_twice() {
        let mut propagator = NoopPropagator;
        let state = callback_state(&mut propagator);

        let result = state.run("outer", |_inner| {
            assert!(state.run("inner", |_inner| Ok(())).is_none());
            Ok(())
        });

        assert!(result.is_none());
        assert!(matches!(
            state.failure.borrow().as_ref(),
            Some(ExternalPropagatorFailure::ReentrantCallback { callback: "inner" })
        ));
    }

    #[test]
    fn malformed_raw_literal_fails_inside_ffi_trampoline() {
        let mut propagator = NoopPropagator;
        let state = callback_state(&mut propagator);
        let raw = [0];

        let status = unsafe {
            notify_assignment(
                std::ptr::from_ref(&state).cast_mut().cast(),
                raw.as_ptr(),
                raw.len(),
            )
        };

        assert_eq!(status, 0);
        assert!(matches!(
            state.failure.borrow().as_ref(),
            Some(ExternalPropagatorFailure::MalformedLiteral {
                callback: "notify_assignment",
                literal: 0
            })
        ));
    }
}
