//! Safe scoped bindings for CaDiCaL's IPASIR-UP external propagator API.

use std::{
    any::Any,
    collections::{HashMap, HashSet},
    ffi::{c_int, c_void},
    marker::PhantomData,
    mem,
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
};

use anyhow::Context;
use rustsat::{
    solvers::{Solve, SolverResult},
    types::{Lit, Var},
};
use thiserror::Error;

use crate::{ffi, CaDiCaL, InternalSolverState, InvalidApiReturn};

/// A literal to propagate together with an eager or on-demand reason clause.
///
/// The reason must contain `literal`, and every other reason literal must be
/// false under the assignment reported to the propagator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalPropagation {
    literal: Lit,
    reason: ExternalPropagationReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExternalPropagationReason {
    Eager(Vec<Lit>),
    Lazy,
}

impl ExternalPropagation {
    /// Creates an external propagation and its reason clause.
    pub fn new<I>(literal: Lit, reason: I) -> Self
    where
        I: IntoIterator<Item = Lit>,
    {
        Self {
            literal,
            reason: ExternalPropagationReason::Eager(reason.into_iter().collect()),
        }
    }

    /// Creates an external propagation whose reason is constructed on demand.
    ///
    /// If CaDiCaL requests the reason, the bridge calls
    /// [`ExternalPropagator::reason`] with `literal`.
    #[must_use]
    pub fn lazy(literal: Lit) -> Self {
        Self {
            literal,
            reason: ExternalPropagationReason::Lazy,
        }
    }

    /// Returns the propagated literal.
    #[must_use]
    pub fn literal(&self) -> Lit {
        self.literal
    }

    /// Returns the eager reason clause.
    ///
    /// Lazy propagations return an empty slice. Use
    /// [`ExternalPropagation::is_lazy`] to distinguish them from eager
    /// propagations.
    #[must_use]
    pub fn reason(&self) -> &[Lit] {
        match &self.reason {
            ExternalPropagationReason::Eager(reason) => reason,
            ExternalPropagationReason::Lazy => &[],
        }
    }

    /// Returns whether the reason will be constructed on demand.
    #[must_use]
    pub fn is_lazy(&self) -> bool {
        matches!(&self.reason, ExternalPropagationReason::Lazy)
    }
}

/// A clause supplied by an external propagator during search.
///
/// An empty clause is an external conflict and makes the solve
/// unsatisfiable. Forgettable clauses may be removed by CaDiCaL during clause
/// database reduction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalClause {
    literals: Vec<Lit>,
    forgettable: bool,
}

impl ExternalClause {
    /// Creates an external lemma.
    pub fn new<I>(literals: I, forgettable: bool) -> Self
    where
        I: IntoIterator<Item = Lit>,
    {
        Self {
            literals: literals.into_iter().collect(),
            forgettable,
        }
    }

    /// Creates an empty external conflict clause.
    #[must_use]
    pub fn conflict() -> Self {
        Self {
            literals: Vec::new(),
            forgettable: false,
        }
    }

    /// Returns the clause literals.
    #[must_use]
    pub fn literals(&self) -> &[Lit] {
        &self.literals
    }

    /// Returns whether CaDiCaL may forget the clause.
    #[must_use]
    pub fn is_forgettable(&self) -> bool {
        self.forgettable
    }
}

/// Receives CaDiCaL IPASIR-UP notifications and supplies external search
/// decisions, propagations, and clauses.
///
/// Implementations may borrow non-`'static` state. They are called
/// synchronously by [`CaDiCaL::solve_with_external_propagator`] and are
/// disconnected before that method returns.
///
/// The bridge validates the IPASIR representation and structural callback
/// protocol. The implementation remains responsible for the logical validity
/// of every propagation reason and external clause it supplies.
pub trait ExternalPropagator {
    /// Reports a batch of newly assigned observed literals in trail order.
    fn notify_assignment(&mut self, _literals: &[Lit]) {}

    /// Reports that CaDiCaL opened a new decision level.
    fn notify_new_decision_level(&mut self) {}

    /// Reports a backtrack that keeps decision levels below `new_level`.
    fn notify_backtrack(&mut self, _new_level: usize) {}

    /// Checks a complete assignment of all observed variables.
    ///
    /// Returning `false` requires [`ExternalPropagator::external_clause`] to
    /// return a clause on the immediately following request. Every literal in
    /// that clause must be false under this exact model. An empty clause is
    /// structurally accepted, but the implementation remains responsible for
    /// the clause's logical validity.
    fn check_found_model(&mut self, _model: &[Lit]) -> bool {
        true
    }

    /// Optionally chooses the next decision literal.
    fn decide(&mut self) -> Option<Lit> {
        None
    }

    /// Optionally supplies a propagation with a reason clause.
    fn propagate(&mut self) -> Option<ExternalPropagation> {
        None
    }

    /// Supplies an on-demand reason for a lazy propagation.
    ///
    /// This callback is invoked only after [`ExternalPropagator::propagate`]
    /// returned [`ExternalPropagation::lazy`] and CaDiCaL requests that
    /// propagation's reason. The clause must contain `propagated`; every
    /// other literal must be false under the currently reported assignment.
    /// Returning `None` for a requested lazy reason is a protocol error.
    fn reason(&mut self, _propagated: Lit) -> Option<Vec<Lit>> {
        None
    }

    /// Optionally supplies an external conflict or lemma clause.
    fn external_clause(&mut self) -> Option<ExternalClause> {
        None
    }
}

/// An error raised by the scoped external propagator bridge.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExternalPropagatorError {
    /// A callback panicked. The panic was caught before returning to C++.
    #[error("external propagator callback `{callback}` panicked: {message}")]
    CallbackPanicked {
        /// The callback in which the panic occurred.
        callback: &'static str,
        /// The panic payload, when it was a string.
        message: String,
    },
    /// A callback violated the IPASIR-UP protocol.
    #[error("external propagator protocol error in `{callback}`: {message}")]
    Protocol {
        /// The callback in which the violation was detected.
        callback: &'static str,
        /// A description of the violation.
        message: String,
    },
    /// The C++ adapter failed to connect, observe, or disconnect.
    #[error("CaDiCaL external propagator adapter `{operation}` failed with code {code}")]
    Adapter {
        /// The adapter operation that failed.
        operation: &'static str,
        /// The integer status returned by the adapter.
        code: c_int,
    },
}

#[derive(Debug)]
enum CachedReasonState {
    Lazy,
    Materialized(Vec<c_int>),
}

#[derive(Debug)]
struct CachedReason {
    generation: u64,
    active: bool,
    state: CachedReasonState,
}

#[derive(Debug)]
struct ReasonReplay {
    propagated: c_int,
    generation: u64,
    literals: Vec<c_int>,
    next: usize,
}

#[derive(Debug)]
struct ClauseReplay {
    literals: Vec<c_int>,
    next: usize,
}

struct PropagatorBridge<'a, P: ExternalPropagator + ?Sized> {
    propagator: &'a mut P,
    observed: HashSet<u32>,
    trail: Vec<Lit>,
    assigned: HashMap<u32, Lit>,
    level_starts: Vec<usize>,
    reasons: HashMap<c_int, CachedReason>,
    next_reason_generation: u64,
    reason_replay: Option<ReasonReplay>,
    emergency_reason: Option<(c_int, bool)>,
    clause_replay: Option<ClauseReplay>,
    rejected_model: Option<HashMap<u32, Lit>>,
    failure: Option<ExternalPropagatorError>,
}

impl<'a, P: ExternalPropagator + ?Sized> PropagatorBridge<'a, P> {
    fn new(propagator: &'a mut P, observed: HashSet<u32>) -> Self {
        Self {
            propagator,
            observed,
            trail: Vec::new(),
            assigned: HashMap::new(),
            level_starts: Vec::new(),
            reasons: HashMap::new(),
            next_reason_generation: 0,
            reason_replay: None,
            emergency_reason: None,
            clause_replay: None,
            rejected_model: None,
            failure: None,
        }
    }

    fn callback<R, F>(&mut self, name: &'static str, fallback: R, callback: F) -> R
    where
        F: FnOnce(&mut Self) -> Result<R, String>,
    {
        if self.failure.is_some() {
            return fallback;
        }
        match catch_unwind(AssertUnwindSafe(|| callback(self))) {
            Ok(Ok(value)) => value,
            Ok(Err(message)) => {
                self.fail(ExternalPropagatorError::Protocol {
                    callback: name,
                    message,
                });
                fallback
            }
            Err(payload) => {
                let message = panic_message(payload.as_ref());
                // A user-provided panic payload can have a panicking Drop
                // implementation. It must not be dropped in an FFI callback.
                mem::forget(payload);
                self.fail(ExternalPropagatorError::CallbackPanicked {
                    callback: name,
                    message,
                });
                fallback
            }
        }
    }

    fn fail(&mut self, failure: ExternalPropagatorError) {
        if self.failure.is_none() {
            self.failure = Some(failure);
        }
    }

    fn decode_lits(&self, raw: *const c_int, len: usize) -> Result<Vec<Lit>, String> {
        if len != 0 && raw.is_null() {
            return Err("received a null literal array with non-zero length".to_owned());
        }
        let raw_lits = if len == 0 {
            &[]
        } else {
            // SAFETY: CaDiCaL owns this array and promises it is readable for
            // the duration of the synchronous callback.
            unsafe { slice::from_raw_parts(raw, len) }
        };
        raw_lits
            .iter()
            .map(|&raw_lit| self.decode_lit(raw_lit))
            .collect()
    }

    fn decode_lit(&self, raw: c_int) -> Result<Lit, String> {
        let lit = Lit::from_ipasir(raw)
            .map_err(|err| format!("received invalid IPASIR literal {raw}: {err}"))?;
        let roundtrip = lit
            .to_ipasir_with_error()
            .map_err(|err| format!("received out-of-range IPASIR literal {raw}: {err}"))?;
        if roundtrip != raw {
            return Err(format!("IPASIR literal {raw} did not round-trip"));
        }
        self.validate_observed(lit)?;
        Ok(lit)
    }

    fn encode_lit(&self, lit: Lit) -> Result<c_int, String> {
        self.validate_observed(lit)?;
        lit.to_ipasir_with_error()
            .map_err(|err| format!("literal {lit:?} does not fit the CaDiCaL API: {err}"))
    }

    fn validate_observed(&self, lit: Lit) -> Result<(), String> {
        if self.observed.contains(&lit.vidx32()) {
            Ok(())
        } else {
            Err(format!(
                "literal {lit:?} uses unobserved variable {}",
                lit.vidx32()
            ))
        }
    }

    fn rebuild_assignments(&mut self) {
        self.assigned.clear();
        self.assigned
            .extend(self.trail.iter().map(|&lit| (lit.vidx32(), lit)));
    }

    fn prepare_propagation(&mut self, propagation: ExternalPropagation) -> Result<c_int, String> {
        let ExternalPropagation { literal, reason } = propagation;
        let propagated = self.encode_lit(literal)?;
        if let Some(assigned) = self.assigned.get(&literal.vidx32()) {
            return Err(format!(
                "propagation literal {propagated} uses variable {} already assigned as {assigned:?}",
                literal.vidx32()
            ));
        }
        if let Some(replay) = &self.reason_replay {
            return Err(format!(
                "new propagation {propagated} was supplied before reason replay for {} completed",
                replay.propagated
            ));
        }

        let state = match reason {
            ExternalPropagationReason::Eager(reason) => CachedReasonState::Materialized(
                self.validate_reason_clause(literal, propagated, reason)?,
            ),
            ExternalPropagationReason::Lazy => CachedReasonState::Lazy,
        };
        let generation = self.next_reason_generation;
        let next_generation = generation
            .checked_add(1)
            .ok_or_else(|| "external propagation generation counter overflowed".to_owned())?;
        let reason = CachedReason {
            generation,
            active: true,
            state,
        };

        // The complete replacement is built and validated before the old
        // generation is removed from the signed-literal cache.
        self.reasons.insert(propagated, reason);
        self.next_reason_generation = next_generation;
        Ok(propagated)
    }

    fn validate_reason_clause(
        &self,
        propagated_lit: Lit,
        propagated: c_int,
        reason: Vec<Lit>,
    ) -> Result<Vec<c_int>, String> {
        let mut encoded = Vec::with_capacity(reason.len());
        let mut seen = HashSet::with_capacity(reason.len());
        let mut contains_propagated = false;

        for lit in reason {
            let raw = self.encode_lit(lit)?;
            if seen.contains(&-raw) {
                return Err(format!(
                    "reason for {propagated} is tautological at literal {raw}"
                ));
            }
            if !seen.insert(raw) {
                return Err(format!("reason for {propagated} repeats literal {raw}"));
            }
            if raw == propagated {
                contains_propagated = true;
            } else if self.assigned.get(&lit.vidx32()).copied() != Some(!lit) {
                return Err(format!(
                    "reason literal {raw} is not false under the reported assignment"
                ));
            }
            encoded.push(raw);
        }

        if !contains_propagated {
            return Err(format!(
                "reason clause does not contain propagated literal {propagated}"
            ));
        }
        if let Some(&assigned) = self.assigned.get(&propagated_lit.vidx32()) {
            if assigned != propagated_lit {
                return Err(format!(
                    "propagated literal {propagated} is reported assigned with the opposite polarity {assigned:?}"
                ));
            }
        }
        Ok(encoded)
    }

    fn materialize_lazy_reason(
        &mut self,
        propagated_lit: Lit,
        propagated: c_int,
    ) -> Result<Vec<c_int>, String> {
        if let Some(&assigned) = self.assigned.get(&propagated_lit.vidx32()) {
            if assigned != propagated_lit {
                return Err(format!(
                    "lazy reason requested for propagated literal {propagated}, but its variable is reported assigned as {assigned:?}"
                ));
            }
        }
        let reason = self.propagator.reason(propagated_lit).ok_or_else(|| {
            format!("no on-demand reason supplied for lazy propagation {propagated}")
        })?;
        self.validate_reason_clause(propagated_lit, propagated, reason)
    }

    fn materialize_cached_reason(&mut self, propagated: c_int) -> Result<u64, String> {
        let (generation, is_lazy) = match self.reasons.get(&propagated) {
            Some(reason) => (
                reason.generation,
                matches!(&reason.state, CachedReasonState::Lazy),
            ),
            None => {
                return Err(format!(
                    "no cached reason for propagated literal {propagated}"
                ));
            }
        };
        if !is_lazy {
            return Ok(generation);
        }

        let propagated_lit = self.decode_lit(propagated)?;
        let literals = self.materialize_lazy_reason(propagated_lit, propagated)?;
        let cached = self.reasons.get_mut(&propagated).ok_or_else(|| {
            format!("cached reason for propagated literal {propagated} disappeared")
        })?;
        if cached.generation != generation {
            return Err(format!(
                "reason generation for propagated literal {propagated} changed from {generation} to {} during materialization",
                cached.generation
            ));
        }
        if !matches!(&cached.state, CachedReasonState::Lazy) {
            return Err(format!(
                "lazy reason generation {generation} for propagated literal {propagated} was replaced during materialization"
            ));
        }
        cached.state = CachedReasonState::Materialized(literals);
        Ok(generation)
    }

    fn materialize_active_lazy_reasons(&mut self) -> Result<(), String> {
        let mut pending = self
            .reasons
            .iter()
            .filter_map(|(&propagated, reason)| {
                (reason.active && matches!(&reason.state, CachedReasonState::Lazy))
                    .then_some((reason.generation, propagated))
            })
            .collect::<Vec<_>>();
        pending.sort_unstable();

        for (generation, propagated) in pending {
            let materialized_generation = self.materialize_cached_reason(propagated)?;
            if materialized_generation != generation {
                return Err(format!(
                    "active reason generation for propagated literal {propagated} changed from {generation} to {materialized_generation}"
                ));
            }
        }
        Ok(())
    }

    fn deactivate_removed_reason_generations(&mut self) -> Result<(), String> {
        let active = self
            .reasons
            .iter()
            .filter_map(|(&propagated, reason)| {
                reason.active.then_some((propagated, reason.generation))
            })
            .collect::<Vec<_>>();

        for (propagated, generation) in active {
            let propagated_lit = self.decode_lit(propagated)?;
            if self.assigned.get(&propagated_lit.vidx32()).copied() == Some(propagated_lit) {
                continue;
            }
            let cached = self.reasons.get_mut(&propagated).ok_or_else(|| {
                format!("cached reason for propagated literal {propagated} disappeared")
            })?;
            if cached.generation != generation {
                return Err(format!(
                    "reason generation for propagated literal {propagated} changed from {generation} to {} during backtrack",
                    cached.generation
                ));
            }
            cached.active = false;
        }
        Ok(())
    }

    fn next_reason_lit(&mut self, propagated: c_int) -> Result<c_int, String> {
        self.decode_lit(propagated)?;
        if let Some(replay) = &mut self.reason_replay {
            if replay.propagated != propagated {
                return Err(format!(
                    "reason replay for {} was interrupted by request for {propagated}",
                    replay.propagated
                ));
            }
            let current_generation = self
                .reasons
                .get(&propagated)
                .map(|reason| reason.generation);
            if current_generation != Some(replay.generation) {
                return Err(format!(
                    "reason replay generation {} for propagated literal {propagated} no longer matches cache generation {current_generation:?}",
                    replay.generation
                ));
            }
            if replay.next == replay.literals.len() {
                self.reason_replay = None;
                return Ok(0);
            }
            let lit = replay.literals[replay.next];
            replay.next += 1;
            return Ok(lit);
        }

        let generation = self.materialize_cached_reason(propagated)?;
        let literals = match self.reasons.get(&propagated) {
            Some(CachedReason {
                generation: cached_generation,
                state: CachedReasonState::Materialized(literals),
                ..
            }) if *cached_generation == generation => literals.clone(),
            Some(CachedReason {
                state: CachedReasonState::Lazy,
                ..
            }) => {
                return Err(format!(
                    "lazy reason for propagated literal {propagated} was not materialized"
                ));
            }
            Some(reason) => {
                return Err(format!(
                    "cached reason generation {} for propagated literal {propagated} does not match materialized generation {generation}",
                    reason.generation
                ));
            }
            None => {
                return Err(format!(
                    "cached reason for propagated literal {propagated} disappeared"
                ));
            }
        };
        let first = literals[0];
        self.reason_replay = Some(ReasonReplay {
            propagated,
            generation,
            literals,
            next: 1,
        });
        Ok(first)
    }

    fn emergency_reason_lit(&mut self, propagated: c_int) -> c_int {
        match self.emergency_reason {
            Some((active, false)) if active == propagated => {
                self.emergency_reason = Some((propagated, true));
                propagated
            }
            Some((active, true)) if active == propagated => {
                self.emergency_reason = None;
                0
            }
            _ => {
                self.emergency_reason = Some((propagated, true));
                propagated
            }
        }
    }

    fn reason_callback(&mut self, propagated: c_int) -> c_int {
        if self.failure.is_some() {
            return self.emergency_reason_lit(propagated);
        }
        match catch_unwind(AssertUnwindSafe(|| self.next_reason_lit(propagated))) {
            Ok(Ok(lit)) => lit,
            Ok(Err(message)) => {
                self.fail(ExternalPropagatorError::Protocol {
                    callback: "add_reason_clause_lit",
                    message,
                });
                self.emergency_reason_lit(propagated)
            }
            Err(payload) => {
                let message = panic_message(payload.as_ref());
                // See `callback`: dropping an arbitrary panic payload here
                // could otherwise start a second unwind across the C ABI.
                mem::forget(payload);
                self.fail(ExternalPropagatorError::CallbackPanicked {
                    callback: "add_reason_clause_lit",
                    message,
                });
                self.emergency_reason_lit(propagated)
            }
        }
    }

    fn prepare_external_clause(&mut self, clause: ExternalClause) -> Result<bool, String> {
        if self.clause_replay.is_some() {
            return Err("CaDiCaL requested a new clause before consuming the prior one".to_owned());
        }
        let mut literals = Vec::with_capacity(clause.literals.len());
        for lit in clause.literals {
            let raw = self.encode_lit(lit)?;
            if let Some(model) = &self.rejected_model {
                let model_value = model.get(&lit.vidx32()).ok_or_else(|| {
                    format!(
                        "rejected model has no assignment for clause variable {}",
                        lit.vidx32()
                    )
                })?;
                if *model_value != !lit {
                    return Err(format!(
                        "external clause literal {raw} is not false under rejected model assignment {model_value:?}"
                    ));
                }
            }
            literals.push(raw);
        }
        let forgettable = clause.forgettable;
        self.clause_replay = Some(ClauseReplay { literals, next: 0 });
        self.rejected_model = None;
        Ok(forgettable)
    }

    fn prepare_fail_closed_clause(&mut self) {
        self.clause_replay = Some(ClauseReplay {
            literals: Vec::new(),
            next: 0,
        });
        self.rejected_model = None;
    }

    fn next_external_clause_lit(&mut self) -> Result<c_int, String> {
        let Some(replay) = &mut self.clause_replay else {
            return Err("CaDiCaL requested clause data without a pending clause".to_owned());
        };
        if replay.next == replay.literals.len() {
            self.clause_replay = None;
            return Ok(0);
        }
        let lit = replay.literals[replay.next];
        replay.next += 1;
        Ok(lit)
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

unsafe fn bridge_mut<'callback, P: ExternalPropagator + ?Sized>(
    state: *mut c_void,
) -> Option<&'callback mut PropagatorBridge<'callback, P>> {
    if state.is_null() {
        None
    } else {
        // SAFETY: The scoped connection keeps the bridge alive and uniquely
        // borrowed until the C++ adapter has been deactivated and disconnected.
        Some(unsafe { &mut *state.cast::<PropagatorBridge<'callback, P>>() })
    }
}

unsafe extern "C" fn notify_assignment<P: ExternalPropagator + ?Sized>(
    state: *mut c_void,
    literals: *const c_int,
    len: usize,
) {
    let Some(bridge) = (unsafe { bridge_mut::<P>(state) }) else {
        return;
    };
    bridge.callback("notify_assignment", (), |bridge| {
        let decoded = bridge.decode_lits(literals, len)?;
        let mut fresh = Vec::with_capacity(decoded.len());
        for &lit in &decoded {
            if let Some(&previous) = bridge.assigned.get(&lit.vidx32()) {
                if previous == lit {
                    continue;
                }
                return Err(format!(
                    "variable {} changed assignment from {previous:?} to {lit:?} without a backtrack",
                    lit.vidx32()
                ));
            }
            bridge.assigned.insert(lit.vidx32(), lit);
            bridge.trail.push(lit);
            fresh.push(lit);
        }
        if !fresh.is_empty() {
            bridge.propagator.notify_assignment(&fresh);
        }
        Ok(())
    });
}

unsafe extern "C" fn notify_new_decision_level<P: ExternalPropagator + ?Sized>(state: *mut c_void) {
    let Some(bridge) = (unsafe { bridge_mut::<P>(state) }) else {
        return;
    };
    bridge.callback("notify_new_decision_level", (), |bridge| {
        bridge.level_starts.push(bridge.trail.len());
        bridge.propagator.notify_new_decision_level();
        Ok(())
    });
}

unsafe extern "C" fn notify_backtrack<P: ExternalPropagator + ?Sized>(
    state: *mut c_void,
    new_level: usize,
) {
    let Some(bridge) = (unsafe { bridge_mut::<P>(state) }) else {
        return;
    };
    bridge.callback("notify_backtrack", (), |bridge| {
        if new_level >= bridge.level_starts.len() {
            return Err(format!(
                "backtrack target {new_level} is not below current level {}",
                bridge.level_starts.len()
            ));
        }
        // CaDiCaL can issue a virtual backtrack followed by a full trail
        // re-notification. Freeze every active deferred reason before either
        // side discards the old trail or provider-owned reason tokens.
        bridge.materialize_active_lazy_reasons()?;
        let keep = bridge.level_starts[new_level];
        bridge.trail.truncate(keep);
        bridge.level_starts.truncate(new_level);
        bridge.rebuild_assignments();
        bridge.deactivate_removed_reason_generations()?;
        bridge.reason_replay = None;
        bridge.propagator.notify_backtrack(new_level);
        Ok(())
    });
}

unsafe extern "C" fn check_found_model<P: ExternalPropagator + ?Sized>(
    state: *mut c_void,
    model: *const c_int,
    len: usize,
) -> c_int {
    let Some(bridge) = (unsafe { bridge_mut::<P>(state) }) else {
        return 0;
    };
    let checked = bridge.callback("check_found_model", None, |bridge| {
        let decoded = bridge.decode_lits(model, len)?;
        let mut assignments = HashMap::with_capacity(decoded.len());
        for &lit in &decoded {
            if assignments.insert(lit.vidx32(), lit).is_some() {
                return Err(format!(
                    "model assigns observed variable {} more than once",
                    lit.vidx32()
                ));
            }
        }
        if assignments.len() != bridge.observed.len() {
            return Err(format!(
                "model covers {} of {} observed variables",
                assignments.len(),
                bridge.observed.len()
            ));
        }
        let accepted = bridge.propagator.check_found_model(&decoded);
        Ok(Some((accepted, assignments)))
    });
    let accepted = checked.is_some_and(|(accepted, assignments)| {
        bridge.rejected_model = (!accepted).then_some(assignments);
        accepted
    });
    c_int::from(accepted)
}

unsafe extern "C" fn decide<P: ExternalPropagator + ?Sized>(state: *mut c_void) -> c_int {
    let Some(bridge) = (unsafe { bridge_mut::<P>(state) }) else {
        return 0;
    };
    bridge.callback("decide", 0, |bridge| {
        let Some(lit) = bridge.propagator.decide() else {
            return Ok(0);
        };
        let raw = bridge.encode_lit(lit)?;
        if bridge.assigned.contains_key(&lit.vidx32()) {
            return Err(format!("decision literal {raw} is already assigned"));
        }
        Ok(raw)
    })
}

unsafe extern "C" fn propagate<P: ExternalPropagator + ?Sized>(state: *mut c_void) -> c_int {
    let Some(bridge) = (unsafe { bridge_mut::<P>(state) }) else {
        return 0;
    };
    bridge.callback("propagate", 0, |bridge| {
        let Some(propagation) = bridge.propagator.propagate() else {
            return Ok(0);
        };
        bridge.prepare_propagation(propagation)
    })
}

unsafe extern "C" fn add_reason_clause_lit<P: ExternalPropagator + ?Sized>(
    state: *mut c_void,
    propagated: c_int,
) -> c_int {
    let Some(bridge) = (unsafe { bridge_mut::<P>(state) }) else {
        return 0;
    };
    bridge.reason_callback(propagated)
}

unsafe extern "C" fn has_external_clause<P: ExternalPropagator + ?Sized>(
    state: *mut c_void,
    is_forgettable: *mut c_int,
) -> c_int {
    let Some(bridge) = (unsafe { bridge_mut::<P>(state) }) else {
        if !is_forgettable.is_null() {
            // SAFETY: The C++ adapter supplied this out pointer.
            unsafe { *is_forgettable = 0 };
        }
        return 1;
    };
    if is_forgettable.is_null() {
        bridge.fail(ExternalPropagatorError::Protocol {
            callback: "has_external_clause",
            message: "received a null forgettable out pointer".to_owned(),
        });
    }

    if bridge.failure.is_some() {
        bridge.prepare_fail_closed_clause();
        if !is_forgettable.is_null() {
            // SAFETY: Null was checked above.
            unsafe { *is_forgettable = 0 };
        }
        return 1;
    }

    let clause = bridge.callback("has_external_clause", None, |bridge| {
        Ok(bridge.propagator.external_clause())
    });
    if bridge.failure.is_some() {
        bridge.prepare_fail_closed_clause();
        if !is_forgettable.is_null() {
            // SAFETY: Null was checked above.
            unsafe { *is_forgettable = 0 };
        }
        return 1;
    }

    let Some(clause) = clause else {
        if bridge.rejected_model.is_some() {
            bridge.fail(ExternalPropagatorError::Protocol {
                callback: "has_external_clause",
                message: "a rejected model was not followed by an external clause".to_owned(),
            });
            bridge.prepare_fail_closed_clause();
            if !is_forgettable.is_null() {
                // SAFETY: Null was checked above.
                unsafe { *is_forgettable = 0 };
            }
            return 1;
        }
        return 0;
    };

    match bridge.prepare_external_clause(clause) {
        Ok(forgettable) => {
            if !is_forgettable.is_null() {
                // SAFETY: Null was checked above.
                unsafe { *is_forgettable = c_int::from(forgettable) };
            }
            1
        }
        Err(message) => {
            bridge.fail(ExternalPropagatorError::Protocol {
                callback: "has_external_clause",
                message,
            });
            bridge.prepare_fail_closed_clause();
            if !is_forgettable.is_null() {
                // SAFETY: Null was checked above.
                unsafe { *is_forgettable = 0 };
            }
            1
        }
    }
}

unsafe extern "C" fn add_external_clause_lit<P: ExternalPropagator + ?Sized>(
    state: *mut c_void,
) -> c_int {
    let Some(bridge) = (unsafe { bridge_mut::<P>(state) }) else {
        return 0;
    };
    bridge.callback("add_external_clause_lit", 0, |bridge| {
        bridge.next_external_clause_lit()
    })
}

fn callbacks<P: ExternalPropagator + ?Sized>() -> ffi::CCaDiCaLExternalPropagatorCallbacks {
    ffi::CCaDiCaLExternalPropagatorCallbacks {
        notify_assignment: Some(notify_assignment::<P>),
        notify_new_decision_level: Some(notify_new_decision_level::<P>),
        notify_backtrack: Some(notify_backtrack::<P>),
        check_found_model: Some(check_found_model::<P>),
        decide: Some(decide::<P>),
        propagate: Some(propagate::<P>),
        add_reason_clause_lit: Some(add_reason_clause_lit::<P>),
        has_external_clause: Some(has_external_clause::<P>),
        add_external_clause_lit: Some(add_external_clause_lit::<P>),
    }
}

struct ExternalConnection<'bridge> {
    solver: *mut ffi::CCaDiCaL,
    adapter: *mut ffi::CCaDiCaLExternalPropagator,
    _bridge: PhantomData<&'bridge mut c_void>,
}

impl<'bridge> ExternalConnection<'bridge> {
    fn connect<P: ExternalPropagator + ?Sized>(
        solver: *mut ffi::CCaDiCaL,
        bridge: &'bridge mut PropagatorBridge<'_, P>,
    ) -> anyhow::Result<Self> {
        let mut adapter = ptr::null_mut();
        let callbacks = callbacks::<P>();
        let status = unsafe {
            ffi::ccadical_connect_external_propagator_mem(
                solver,
                ptr::from_mut(bridge).cast::<c_void>(),
                &callbacks,
                0,
                0,
                &mut adapter,
            )
        };
        adapter_status(status, "connect")?;
        if adapter.is_null() {
            return Err(ExternalPropagatorError::Adapter {
                operation: "connect",
                code: status,
            }
            .into());
        }
        Ok(Self {
            solver,
            adapter,
            _bridge: PhantomData,
        })
    }

    fn add_observed_var(&mut self, var: c_int) -> anyhow::Result<()> {
        let status = unsafe { ffi::ccadical_add_observed_var_mem(self.solver, var) };
        adapter_status(status, "add_observed_var")
    }

    fn disconnect(mut self) -> anyhow::Result<()> {
        let adapter = self.adapter;
        self.adapter = ptr::null_mut();
        let status = unsafe { ffi::ccadical_disconnect_external_propagator(self.solver, adapter) };
        adapter_status(status, "disconnect")
    }
}

impl Drop for ExternalConnection<'_> {
    fn drop(&mut self) {
        if self.adapter.is_null() {
            return;
        }
        unsafe {
            ffi::ccadical_disconnect_external_propagator(self.solver, self.adapter);
        }
        self.adapter = ptr::null_mut();
    }
}

fn adapter_status(status: c_int, operation: &'static str) -> anyhow::Result<()> {
    if status == 0 {
        Ok(())
    } else if status == ffi::OUT_OF_MEM {
        Err(rustsat::OutOfMemory::ExternalApi)
            .with_context(|| format!("cadical external propagator `{operation}` ran out of memory"))
    } else if status == ffi::EXTERNAL_PROPAGATOR_ERROR {
        Err(ExternalPropagatorError::Adapter {
            operation,
            code: status,
        }
        .into())
    } else {
        Err(InvalidApiReturn {
            api_call: operation,
            value: status,
        }
        .into())
    }
}

fn validate_observed_vars(observed: &[Var]) -> anyhow::Result<(Vec<c_int>, HashSet<u32>)> {
    let mut raw_vars = Vec::with_capacity(observed.len());
    let mut variables = HashSet::with_capacity(observed.len());
    for &var in observed {
        let raw = var
            .to_ipasir_with_error()
            .map_err(|err| ExternalPropagatorError::Protocol {
                callback: "registration",
                message: format!("observed variable {var:?} is invalid for CaDiCaL: {err}"),
            })?;
        if variables.insert(var.idx32()) {
            raw_vars.push(raw);
        }
    }
    Ok((raw_vars, variables))
}

impl CaDiCaL<'_, '_> {
    /// Solves once with a scoped borrowed IPASIR-UP external propagator.
    ///
    /// `observed` lists every variable that callbacks may mention. The
    /// propagator is connected only for this call and is disconnected before
    /// the method returns, including while unwinding. This lets the caller
    /// inspect borrowed telemetry immediately after solving.
    ///
    /// Callback panics are caught at the FFI boundary. Invalid callback data
    /// records an [`ExternalPropagatorError`], supplies an empty external
    /// conflict to fail closed, and makes this method return the error instead
    /// of a solver result. Because CaDiCaL learns that empty clause, discard the
    /// solver after a callback or protocol error.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustsat::{
    ///     solvers::{Solve, SolverResult},
    ///     types::{Lit, Var},
    /// };
    /// use rustsat_cadical::{CaDiCaL, ExternalPropagator};
    ///
    /// struct Telemetry<'a>(&'a mut usize);
    ///
    /// impl ExternalPropagator for Telemetry<'_> {
    ///     fn notify_assignment(&mut self, literals: &[Lit]) {
    ///         *self.0 += literals.len();
    ///     }
    /// }
    ///
    /// let mut assignments = 0;
    /// let mut solver = CaDiCaL::default();
    /// solver.add_unit(Lit::positive(0)).unwrap();
    /// let result = {
    ///     let mut telemetry = Telemetry(&mut assignments);
    ///     solver
    ///         .solve_with_external_propagator(&mut telemetry, &[Var::new(0)])
    ///         .unwrap()
    /// };
    /// assert_eq!(result, SolverResult::Sat);
    /// assert!(assignments > 0);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid observed variable, a callback panic or
    /// protocol violation, a C++ adapter failure, or a normal CaDiCaL solve
    /// error.
    pub fn solve_with_external_propagator<P>(
        &mut self,
        propagator: &mut P,
        observed: &[Var],
    ) -> anyhow::Result<SolverResult>
    where
        P: ExternalPropagator + ?Sized,
    {
        let (raw_vars, observed) = validate_observed_vars(observed)?;
        let mut bridge = PropagatorBridge::new(propagator, observed);
        let mut connection = ExternalConnection::connect(self.handle, &mut bridge)?;

        let solve_result = (|| {
            for var in raw_vars {
                connection.add_observed_var(var)?;
            }
            // A previously cached SAT result must be checked again under the
            // newly connected external constraints.
            self.state = InternalSolverState::Input;
            <Self as Solve>::solve(self)
        })();
        let disconnect_result = connection.disconnect();

        if let Some(failure) = bridge.failure.take() {
            return Err(failure.into());
        }
        disconnect_result?;
        solve_result
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use rustsat::{
        solvers::{Solve, SolverResult},
        types::{Lit, TernaryVal, Var},
    };

    use super::{
        CaDiCaL, ExternalClause, ExternalPropagation, ExternalPropagator, ExternalPropagatorError,
    };
    use crate::Config;

    #[derive(Default)]
    struct BatchRecorder {
        batches: Vec<Vec<Lit>>,
        decision: Option<Lit>,
    }

    impl ExternalPropagator for BatchRecorder {
        fn notify_assignment(&mut self, literals: &[Lit]) {
            self.batches.push(literals.to_vec());
        }

        fn decide(&mut self) -> Option<Lit> {
            self.decision.take()
        }
    }

    #[test]
    fn assignment_notifications_are_batched() {
        let x = Lit::positive(0);
        let y = Lit::positive(1);
        let z = Lit::positive(2);
        let mut solver = CaDiCaL::default();
        solver.set_configuration(Config::Plain).unwrap();
        solver.add_binary(!x, y).unwrap();
        solver.add_binary(!y, z).unwrap();
        let mut propagator = BatchRecorder {
            batches: Vec::new(),
            decision: Some(x),
        };

        assert_eq!(
            solver
                .solve_with_external_propagator(
                    &mut propagator,
                    &[Var::new(0), Var::new(1), Var::new(2)],
                )
                .unwrap(),
            SolverResult::Sat
        );
        assert!(propagator.batches.iter().any(|batch| {
            batch.len() >= 3 && batch.contains(&x) && batch.contains(&y) && batch.contains(&z)
        }));
    }

    struct BacktrackRecorder {
        decision: Lit,
        decision_sent: bool,
        clause_sent: bool,
        new_levels: usize,
        backtracks: Vec<usize>,
    }

    impl ExternalPropagator for BacktrackRecorder {
        fn notify_new_decision_level(&mut self) {
            self.new_levels += 1;
        }

        fn notify_backtrack(&mut self, new_level: usize) {
            self.backtracks.push(new_level);
        }

        fn decide(&mut self) -> Option<Lit> {
            if self.decision_sent {
                None
            } else {
                self.decision_sent = true;
                Some(self.decision)
            }
        }

        fn external_clause(&mut self) -> Option<ExternalClause> {
            if self.decision_sent && !self.clause_sent {
                self.clause_sent = true;
                Some(ExternalClause::new([!self.decision], false))
            } else {
                None
            }
        }
    }

    #[test]
    fn decision_levels_and_backtracks_are_reported() {
        let x = Lit::positive(0);
        let y = Lit::positive(1);
        let mut solver = CaDiCaL::default();
        solver.add_binary(x, y).unwrap();
        let mut propagator = BacktrackRecorder {
            decision: x,
            decision_sent: false,
            clause_sent: false,
            new_levels: 0,
            backtracks: Vec::new(),
        };

        assert_eq!(
            solver
                .solve_with_external_propagator(&mut propagator, &[Var::new(0), Var::new(1)],)
                .unwrap(),
            SolverResult::Sat
        );
        assert!(propagator.new_levels > 0);
        assert!(propagator.backtracks.contains(&0));
        assert!(propagator.clause_sent);
    }

    struct ImplicationPropagator {
        trigger: Lit,
        consequence: Lit,
        assigned: HashSet<Lit>,
        propagated: bool,
    }

    impl ExternalPropagator for ImplicationPropagator {
        fn notify_assignment(&mut self, literals: &[Lit]) {
            self.assigned.extend(literals.iter().copied());
        }

        fn propagate(&mut self) -> Option<ExternalPropagation> {
            if self.assigned.contains(&self.trigger) && !self.propagated {
                self.propagated = true;
                Some(ExternalPropagation::new(
                    self.consequence,
                    [!self.trigger, self.consequence],
                ))
            } else {
                None
            }
        }
    }

    #[test]
    fn propagation_with_reason_assigns_unassigned_consequence() {
        let x = Lit::positive(0);
        let y = Lit::positive(1);
        let mut solver = CaDiCaL::default();
        solver.add_unit(x).unwrap();
        let mut propagator = ImplicationPropagator {
            trigger: x,
            consequence: y,
            assigned: HashSet::new(),
            propagated: false,
        };

        assert_eq!(
            solver
                .solve_with_external_propagator(&mut propagator, &[Var::new(0), Var::new(1)],)
                .unwrap(),
            SolverResult::Sat
        );
        assert!(propagator.propagated);
        assert_eq!(solver.lit_val(y).unwrap(), TernaryVal::True);
    }

    fn assigned_consequence_error(assigned: Lit) -> anyhow::Error {
        let x = Lit::positive(0);
        let y = Lit::positive(1);
        let mut solver = CaDiCaL::default();
        solver.add_unit(x).unwrap();
        solver.add_unit(assigned).unwrap();
        let mut propagator = ImplicationPropagator {
            trigger: x,
            consequence: y,
            assigned: HashSet::new(),
            propagated: false,
        };

        solver
            .solve_with_external_propagator(&mut propagator, &[Var::new(0), Var::new(1)])
            .expect_err("an assigned consequence must return a bridge error, not a solve result")
    }

    fn assert_assigned_consequence_error(error: &anyhow::Error) {
        match error.downcast_ref::<ExternalPropagatorError>() {
            Some(ExternalPropagatorError::Protocol { callback, message }) => {
                assert_eq!(*callback, "propagate");
                assert!(message.contains("already assigned"));
            }
            other => panic!("expected propagation protocol error, got {other:?}"),
        }
    }

    #[test]
    fn already_true_propagation_consequence_is_rejected() {
        let error = assigned_consequence_error(Lit::positive(1));
        assert_assigned_consequence_error(&error);
    }

    #[test]
    fn already_false_propagation_consequence_is_rejected() {
        let error = assigned_consequence_error(Lit::negative(1));
        assert_assigned_consequence_error(&error);
    }

    struct NoopPropagator;

    impl ExternalPropagator for NoopPropagator {}

    #[test]
    fn propagation_reason_can_be_replayed_more_than_once() {
        let x = Lit::positive(0);
        let y = Lit::positive(1);
        let mut propagator = NoopPropagator;
        let mut bridge =
            super::PropagatorBridge::new(&mut propagator, HashSet::from([x.vidx32(), y.vidx32()]));
        bridge.trail.push(x);
        bridge.assigned.insert(x.vidx32(), x);
        let propagated = bridge
            .prepare_propagation(ExternalPropagation::new(y, [!x, y]))
            .unwrap();
        let expected = [!x, y].map(Lit::to_ipasir);

        for _ in 0..2 {
            assert_eq!(bridge.reason_callback(propagated), expected[0]);
            assert_eq!(bridge.reason_callback(propagated), expected[1]);
            assert_eq!(bridge.reason_callback(propagated), 0);
        }
    }

    struct LazyReasonRecorder {
        propagated: Lit,
        reason: Vec<Lit>,
        calls: usize,
    }

    impl ExternalPropagator for LazyReasonRecorder {
        fn reason(&mut self, propagated: Lit) -> Option<Vec<Lit>> {
            assert_eq!(propagated, self.propagated);
            self.calls += 1;
            Some(self.reason.clone())
        }
    }

    #[test]
    fn lazy_propagation_does_not_construct_its_reason() {
        let x = Lit::positive(0);
        let y = Lit::positive(1);
        let propagation = ExternalPropagation::lazy(y);
        assert_eq!(propagation.literal(), y);
        assert!(propagation.is_lazy());
        assert!(propagation.reason().is_empty());

        let mut propagator = LazyReasonRecorder {
            propagated: y,
            reason: vec![!x, y],
            calls: 0,
        };
        {
            let mut bridge = super::PropagatorBridge::new(
                &mut propagator,
                HashSet::from([x.vidx32(), y.vidx32()]),
            );
            bridge.trail.push(x);
            bridge.assigned.insert(x.vidx32(), x);
            bridge.prepare_propagation(propagation).unwrap();
        }

        assert_eq!(propagator.calls, 0);
    }

    #[test]
    fn lazy_reason_is_generated_once_and_replayed_from_cache() {
        let x = Lit::positive(0);
        let y = Lit::positive(1);
        let mut propagator = LazyReasonRecorder {
            propagated: y,
            reason: vec![!x, y],
            calls: 0,
        };
        let mut bridge =
            super::PropagatorBridge::new(&mut propagator, HashSet::from([x.vidx32(), y.vidx32()]));
        bridge.trail.push(x);
        bridge.assigned.insert(x.vidx32(), x);
        let propagated = bridge
            .prepare_propagation(ExternalPropagation::lazy(y))
            .unwrap();
        assert_eq!(bridge.propagator.calls, 0);

        let expected = [!x, y].map(Lit::to_ipasir);
        // A reason request before the propagated conclusion is reported is
        // permitted and materializes the reason once.
        assert_eq!(bridge.reason_callback(propagated), expected[0]);
        assert_eq!(bridge.reason_callback(propagated), expected[1]);
        assert_eq!(bridge.reason_callback(propagated), 0);
        assert_eq!(bridge.propagator.calls, 1);

        // Once the conclusion is reported with its propagated polarity, a
        // repeated replay comes entirely from the bridge cache.
        bridge.trail.push(y);
        bridge.assigned.insert(y.vidx32(), y);
        assert_eq!(bridge.reason_callback(propagated), expected[0]);
        assert_eq!(bridge.reason_callback(propagated), expected[1]);
        assert_eq!(bridge.reason_callback(propagated), 0);
        assert_eq!(bridge.propagator.calls, 1);
    }

    #[test]
    fn invalid_lazy_reasons_fail_when_requested() {
        let x = Lit::positive(0);
        let y = Lit::positive(1);
        let invalid_reasons = [
            (vec![!x], "does not contain propagated literal"),
            (vec![!x, y, y], "repeats literal"),
            (vec![!x, x, y], "is tautological"),
            (vec![x, y], "is not false"),
        ];

        for (reason, expected_message) in invalid_reasons {
            let mut propagator = LazyReasonRecorder {
                propagated: y,
                reason,
                calls: 0,
            };
            let mut bridge = super::PropagatorBridge::new(
                &mut propagator,
                HashSet::from([x.vidx32(), y.vidx32()]),
            );
            bridge.trail.push(x);
            bridge.assigned.insert(x.vidx32(), x);
            let propagated = bridge
                .prepare_propagation(ExternalPropagation::lazy(y))
                .unwrap();
            bridge.trail.push(y);
            bridge.assigned.insert(y.vidx32(), y);

            assert_eq!(bridge.reason_callback(propagated), propagated);
            match bridge.failure.as_ref() {
                Some(ExternalPropagatorError::Protocol { callback, message }) => {
                    assert_eq!(*callback, "add_reason_clause_lit");
                    assert!(message.contains(expected_message), "{message}");
                }
                other => panic!("expected lazy-reason protocol error, got {other:?}"),
            }
            assert_eq!(bridge.propagator.calls, 1);
            assert_eq!(bridge.reason_callback(propagated), 0);
        }
    }

    #[test]
    fn lazy_reason_rejects_opposite_conclusion_assignment_without_callback() {
        let x = Lit::positive(0);
        let y = Lit::positive(1);
        let mut propagator = LazyReasonRecorder {
            propagated: y,
            reason: vec![!x, y],
            calls: 0,
        };
        let mut bridge =
            super::PropagatorBridge::new(&mut propagator, HashSet::from([x.vidx32(), y.vidx32()]));
        bridge.trail.push(x);
        bridge.assigned.insert(x.vidx32(), x);
        let propagated = bridge
            .prepare_propagation(ExternalPropagation::lazy(y))
            .unwrap();
        bridge.trail.push(!y);
        bridge.assigned.insert(y.vidx32(), !y);

        assert_eq!(bridge.reason_callback(propagated), propagated);
        match bridge.failure.as_ref() {
            Some(ExternalPropagatorError::Protocol { callback, message }) => {
                assert_eq!(*callback, "add_reason_clause_lit");
                assert!(message.contains("reported assigned"));
            }
            other => panic!("expected lazy-reason protocol error, got {other:?}"),
        }
        assert_eq!(bridge.propagator.calls, 0);
        assert_eq!(bridge.reason_callback(propagated), 0);
    }

    #[test]
    fn missing_lazy_reason_fails_closed_across_ffi() {
        let x = Lit::positive(0);
        let y = Lit::positive(1);
        let mut propagator = NoopPropagator;
        let mut bridge =
            super::PropagatorBridge::new(&mut propagator, HashSet::from([x.vidx32(), y.vidx32()]));
        bridge.trail.push(x);
        bridge.assigned.insert(x.vidx32(), x);
        let propagated = bridge
            .prepare_propagation(ExternalPropagation::lazy(y))
            .unwrap();
        bridge.trail.push(y);
        bridge.assigned.insert(y.vidx32(), y);
        let state = std::ptr::from_mut(&mut bridge).cast();

        assert_eq!(
            unsafe { super::add_reason_clause_lit::<NoopPropagator>(state, propagated) },
            propagated
        );
        assert_eq!(
            unsafe { super::add_reason_clause_lit::<NoopPropagator>(state, propagated) },
            0
        );
        match bridge.failure.as_ref() {
            Some(ExternalPropagatorError::Protocol { callback, message }) => {
                assert_eq!(*callback, "add_reason_clause_lit");
                assert!(message.contains("no on-demand reason supplied"));
            }
            other => panic!("expected missing lazy-reason error, got {other:?}"),
        }

        let mut forgettable = 1;
        assert_eq!(
            unsafe { super::has_external_clause::<NoopPropagator>(state, &mut forgettable) },
            1
        );
        assert_eq!(forgettable, 0);
        assert_eq!(
            unsafe { super::add_external_clause_lit::<NoopPropagator>(state) },
            0
        );
    }

    struct PanickingLazyReason;

    impl ExternalPropagator for PanickingLazyReason {
        fn reason(&mut self, _propagated: Lit) -> Option<Vec<Lit>> {
            panic!("lazy reason panic is contained");
        }
    }

    #[test]
    fn panicking_lazy_reason_fails_closed_across_ffi() {
        let y = Lit::positive(0);
        let mut propagator = PanickingLazyReason;
        let mut bridge = super::PropagatorBridge::new(&mut propagator, HashSet::from([y.vidx32()]));
        let propagated = bridge
            .prepare_propagation(ExternalPropagation::lazy(y))
            .unwrap();
        bridge.trail.push(y);
        bridge.assigned.insert(y.vidx32(), y);
        let state = std::ptr::from_mut(&mut bridge).cast();

        assert_eq!(
            unsafe { super::add_reason_clause_lit::<PanickingLazyReason>(state, propagated) },
            propagated
        );
        assert_eq!(
            unsafe { super::add_reason_clause_lit::<PanickingLazyReason>(state, propagated) },
            0
        );
        assert!(matches!(
            bridge.failure.as_ref(),
            Some(ExternalPropagatorError::CallbackPanicked {
                callback: "add_reason_clause_lit",
                ..
            })
        ));

        let mut forgettable = 1;
        assert_eq!(
            unsafe { super::has_external_clause::<PanickingLazyReason>(state, &mut forgettable) },
            1
        );
        assert_eq!(forgettable, 0);
        assert_eq!(
            unsafe { super::add_external_clause_lit::<PanickingLazyReason>(state) },
            0
        );
    }

    struct ExpectedReason {
        backtracks: usize,
        propagated: Lit,
        literals: Option<Vec<Lit>>,
    }

    struct BacktrackSensitiveReasons {
        expected: Vec<ExpectedReason>,
        next: usize,
        reason_calls: usize,
        backtracks: usize,
    }

    impl ExternalPropagator for BacktrackSensitiveReasons {
        fn notify_backtrack(&mut self, _new_level: usize) {
            self.backtracks += 1;
        }

        fn reason(&mut self, propagated: Lit) -> Option<Vec<Lit>> {
            let expected = self
                .expected
                .get(self.next)
                .unwrap_or_else(|| panic!("unexpected reason request for {propagated:?}"));
            assert_eq!(self.backtracks, expected.backtracks);
            assert_eq!(propagated, expected.propagated);
            let literals = expected.literals.clone();
            self.next += 1;
            self.reason_calls += 1;
            literals
        }
    }

    fn replay_reason<P>(
        bridge: &mut super::PropagatorBridge<'_, P>,
        propagated: std::ffi::c_int,
    ) -> Vec<std::ffi::c_int>
    where
        P: ExternalPropagator + ?Sized,
    {
        let mut literals = Vec::new();
        loop {
            let literal = bridge.reason_callback(propagated);
            if literal == 0 {
                return literals;
            }
            literals.push(literal);
        }
    }

    #[test]
    fn unresolved_lazy_reasons_survive_virtual_full_renotify() {
        let root = Lit::positive(0);
        let antecedent = Lit::positive(1);
        let first = Lit::positive(2);
        let second = Lit::positive(3);
        let first_reason = vec![!antecedent, first];
        let second_reason = vec![!antecedent, second];
        let mut propagator = BacktrackSensitiveReasons {
            expected: vec![
                ExpectedReason {
                    backtracks: 0,
                    propagated: first,
                    literals: Some(first_reason.clone()),
                },
                ExpectedReason {
                    backtracks: 0,
                    propagated: second,
                    literals: Some(second_reason.clone()),
                },
            ],
            next: 0,
            reason_calls: 0,
            backtracks: 0,
        };
        let mut bridge = super::PropagatorBridge::new(
            &mut propagator,
            HashSet::from([
                root.vidx32(),
                antecedent.vidx32(),
                first.vidx32(),
                second.vidx32(),
            ]),
        );
        bridge.trail.push(root);
        bridge.assigned.insert(root.vidx32(), root);
        bridge.level_starts.push(bridge.trail.len());
        bridge.trail.push(antecedent);
        bridge.assigned.insert(antecedent.vidx32(), antecedent);
        let first_raw = bridge
            .prepare_propagation(ExternalPropagation::lazy(first))
            .unwrap();
        bridge.trail.push(first);
        bridge.assigned.insert(first.vidx32(), first);
        let second_raw = bridge
            .prepare_propagation(ExternalPropagation::lazy(second))
            .unwrap();
        bridge.trail.push(second);
        bridge.assigned.insert(second.vidx32(), second);
        assert_eq!(bridge.propagator.reason_calls, 0);
        let state = std::ptr::from_mut(&mut bridge).cast();

        // CaDiCaL uses this virtual rollback before re-notifying the same
        // non-root trail. Both reasons must be frozen before provider tokens
        // are invalidated by its backtrack callback.
        unsafe { super::notify_backtrack::<BacktrackSensitiveReasons>(state, 0) };
        assert!(bridge.failure.is_none());
        assert_eq!(bridge.propagator.reason_calls, 2);
        assert_eq!(bridge.propagator.backtracks, 1);
        assert_eq!(bridge.trail, [root]);
        for propagated in [first_raw, second_raw] {
            let reason = bridge.reasons.get(&propagated).unwrap();
            assert!(!reason.active);
            assert!(matches!(
                &reason.state,
                super::CachedReasonState::Materialized(_)
            ));
        }

        let root_replay = [root.to_ipasir()];
        unsafe {
            super::notify_assignment::<BacktrackSensitiveReasons>(
                state,
                root_replay.as_ptr(),
                root_replay.len(),
            );
            super::notify_new_decision_level::<BacktrackSensitiveReasons>(state);
        }
        let level_replay = [
            antecedent.to_ipasir(),
            first.to_ipasir(),
            second.to_ipasir(),
        ];
        unsafe {
            super::notify_assignment::<BacktrackSensitiveReasons>(
                state,
                level_replay.as_ptr(),
                level_replay.len(),
            )
        };
        assert!(bridge.failure.is_none());

        let expected_first = first_reason
            .iter()
            .copied()
            .map(Lit::to_ipasir)
            .collect::<Vec<_>>();
        let expected_second = second_reason
            .iter()
            .copied()
            .map(Lit::to_ipasir)
            .collect::<Vec<_>>();
        let first_replay = replay_reason(&mut bridge, first_raw);
        let second_replay = replay_reason(&mut bridge, second_raw);
        assert_eq!(first_replay, expected_first);
        assert_eq!(second_replay, expected_second);
        assert_eq!(replay_reason(&mut bridge, first_raw), first_replay);
        assert_eq!(replay_reason(&mut bridge, second_raw), second_replay);
        assert_eq!(bridge.propagator.reason_calls, 2);
        assert!(bridge.failure.is_none());
    }

    #[test]
    fn same_signed_literal_gets_a_new_reason_generation_after_backtrack() {
        let first_antecedent = Lit::positive(0);
        let second_antecedent = Lit::positive(1);
        let propagated_lit = Lit::positive(2);
        let first_reason = vec![!first_antecedent, propagated_lit];
        let second_reason = vec![!second_antecedent, propagated_lit];
        let mut propagator = BacktrackSensitiveReasons {
            expected: vec![
                ExpectedReason {
                    backtracks: 0,
                    propagated: propagated_lit,
                    literals: Some(first_reason.clone()),
                },
                ExpectedReason {
                    backtracks: 1,
                    propagated: propagated_lit,
                    literals: Some(second_reason.clone()),
                },
            ],
            next: 0,
            reason_calls: 0,
            backtracks: 0,
        };
        let mut bridge = super::PropagatorBridge::new(
            &mut propagator,
            HashSet::from([
                first_antecedent.vidx32(),
                second_antecedent.vidx32(),
                propagated_lit.vidx32(),
            ]),
        );
        bridge.level_starts.push(0);
        bridge.trail.push(first_antecedent);
        bridge
            .assigned
            .insert(first_antecedent.vidx32(), first_antecedent);
        let propagated = bridge
            .prepare_propagation(ExternalPropagation::lazy(propagated_lit))
            .unwrap();
        let first_generation = bridge.reasons[&propagated].generation;
        bridge.trail.push(propagated_lit);
        bridge
            .assigned
            .insert(propagated_lit.vidx32(), propagated_lit);
        let state = std::ptr::from_mut(&mut bridge).cast();

        unsafe { super::notify_backtrack::<BacktrackSensitiveReasons>(state, 0) };
        assert!(bridge.failure.is_none());
        assert_eq!(bridge.propagator.reason_calls, 1);
        assert_eq!(bridge.propagator.backtracks, 1);

        bridge.level_starts.push(0);
        bridge.trail.push(second_antecedent);
        bridge
            .assigned
            .insert(second_antecedent.vidx32(), second_antecedent);
        assert_eq!(
            bridge
                .prepare_propagation(ExternalPropagation::lazy(propagated_lit))
                .unwrap(),
            propagated
        );
        let replacement = bridge.reasons.get(&propagated).unwrap();
        assert!(replacement.generation > first_generation);
        assert!(replacement.active);
        assert!(matches!(&replacement.state, super::CachedReasonState::Lazy));
        bridge.trail.push(propagated_lit);
        bridge
            .assigned
            .insert(propagated_lit.vidx32(), propagated_lit);

        let replay = replay_reason(&mut bridge, propagated);
        let expected = second_reason
            .iter()
            .copied()
            .map(Lit::to_ipasir)
            .collect::<Vec<_>>();
        assert_eq!(replay, expected);
        assert_ne!(
            replay,
            first_reason
                .iter()
                .copied()
                .map(Lit::to_ipasir)
                .collect::<Vec<_>>()
        );
        assert_eq!(bridge.propagator.reason_calls, 2);
        assert!(bridge.failure.is_none());
    }

    #[test]
    fn opposite_polarities_keep_distinct_reason_generations() {
        let first_antecedent = Lit::positive(0);
        let second_antecedent = Lit::positive(1);
        let positive = Lit::positive(2);
        let negative = !positive;
        let positive_reason = vec![!first_antecedent, positive];
        let negative_reason = vec![!second_antecedent, negative];
        let mut propagator = BacktrackSensitiveReasons {
            expected: vec![
                ExpectedReason {
                    backtracks: 0,
                    propagated: positive,
                    literals: Some(positive_reason),
                },
                ExpectedReason {
                    backtracks: 1,
                    propagated: negative,
                    literals: Some(negative_reason.clone()),
                },
            ],
            next: 0,
            reason_calls: 0,
            backtracks: 0,
        };
        let mut bridge = super::PropagatorBridge::new(
            &mut propagator,
            HashSet::from([
                first_antecedent.vidx32(),
                second_antecedent.vidx32(),
                positive.vidx32(),
            ]),
        );
        bridge.level_starts.push(0);
        bridge.trail.push(first_antecedent);
        bridge
            .assigned
            .insert(first_antecedent.vidx32(), first_antecedent);
        let positive_raw = bridge
            .prepare_propagation(ExternalPropagation::lazy(positive))
            .unwrap();
        bridge.trail.push(positive);
        bridge.assigned.insert(positive.vidx32(), positive);
        let state = std::ptr::from_mut(&mut bridge).cast();
        unsafe { super::notify_backtrack::<BacktrackSensitiveReasons>(state, 0) };
        assert!(bridge.failure.is_none());

        bridge.level_starts.push(0);
        bridge.trail.push(second_antecedent);
        bridge
            .assigned
            .insert(second_antecedent.vidx32(), second_antecedent);
        let negative_raw = bridge
            .prepare_propagation(ExternalPropagation::lazy(negative))
            .unwrap();
        bridge.trail.push(negative);
        bridge.assigned.insert(negative.vidx32(), negative);
        assert_ne!(positive_raw, negative_raw);
        assert!(bridge.reasons.contains_key(&positive_raw));
        assert!(bridge.reasons.contains_key(&negative_raw));

        let replay = replay_reason(&mut bridge, negative_raw);
        assert_eq!(
            replay,
            negative_reason
                .iter()
                .copied()
                .map(Lit::to_ipasir)
                .collect::<Vec<_>>()
        );
        assert_eq!(bridge.propagator.reason_calls, 2);
        assert!(bridge.failure.is_none());
    }

    #[test]
    fn invalid_reason_during_backtrack_pre_materialization_fails_closed() {
        let antecedent = Lit::positive(0);
        let propagated_lit = Lit::positive(1);
        let mut propagator = BacktrackSensitiveReasons {
            expected: vec![ExpectedReason {
                backtracks: 0,
                propagated: propagated_lit,
                literals: Some(vec![!antecedent]),
            }],
            next: 0,
            reason_calls: 0,
            backtracks: 0,
        };
        let mut bridge = super::PropagatorBridge::new(
            &mut propagator,
            HashSet::from([antecedent.vidx32(), propagated_lit.vidx32()]),
        );
        bridge.level_starts.push(0);
        bridge.trail.push(antecedent);
        bridge.assigned.insert(antecedent.vidx32(), antecedent);
        let propagated = bridge
            .prepare_propagation(ExternalPropagation::lazy(propagated_lit))
            .unwrap();
        bridge.trail.push(propagated_lit);
        bridge
            .assigned
            .insert(propagated_lit.vidx32(), propagated_lit);
        let old_trail = bridge.trail.clone();
        let old_levels = bridge.level_starts.clone();
        let state = std::ptr::from_mut(&mut bridge).cast();

        unsafe { super::notify_backtrack::<BacktrackSensitiveReasons>(state, 0) };
        match bridge.failure.as_ref() {
            Some(ExternalPropagatorError::Protocol { callback, message }) => {
                assert_eq!(*callback, "notify_backtrack");
                assert!(message.contains("does not contain propagated literal"));
            }
            other => panic!("expected pre-materialization protocol error, got {other:?}"),
        }
        assert_eq!(bridge.propagator.reason_calls, 1);
        assert_eq!(bridge.propagator.backtracks, 0);
        assert_eq!(bridge.trail, old_trail);
        assert_eq!(bridge.level_starts, old_levels);
        assert!(matches!(
            &bridge.reasons[&propagated].state,
            super::CachedReasonState::Lazy
        ));

        let mut forgettable = 1;
        assert_eq!(
            unsafe {
                super::has_external_clause::<BacktrackSensitiveReasons>(state, &mut forgettable)
            },
            1
        );
        assert_eq!(forgettable, 0);
        assert_eq!(
            unsafe { super::add_external_clause_lit::<BacktrackSensitiveReasons>(state) },
            0
        );
    }

    #[derive(Default)]
    struct ConflictPropagator {
        emitted: bool,
    }

    impl ExternalPropagator for ConflictPropagator {
        fn external_clause(&mut self) -> Option<ExternalClause> {
            if self.emitted {
                None
            } else {
                self.emitted = true;
                Some(ExternalClause::conflict())
            }
        }
    }

    #[test]
    fn empty_external_clause_is_a_conflict() {
        let x = Lit::positive(0);
        let mut solver = CaDiCaL::default();
        solver.add_unit(x).unwrap();
        let mut propagator = ConflictPropagator::default();

        assert_eq!(
            solver
                .solve_with_external_propagator(&mut propagator, &[Var::new(0)])
                .unwrap(),
            SolverResult::Unsat
        );
        assert!(propagator.emitted);
    }

    struct RejectFirstModel {
        variable: Var,
        first_value: Option<Lit>,
        pending: Option<ExternalClause>,
        checks: usize,
    }

    impl ExternalPropagator for RejectFirstModel {
        fn check_found_model(&mut self, model: &[Lit]) -> bool {
            self.checks += 1;
            if self.first_value.is_some() {
                return true;
            }
            let Some(&value) = model.iter().find(|lit| lit.var() == self.variable) else {
                return false;
            };
            self.first_value = Some(value);
            self.pending = Some(ExternalClause::new([!value], false));
            false
        }

        fn external_clause(&mut self) -> Option<ExternalClause> {
            self.pending.take()
        }
    }

    #[test]
    fn rejected_model_is_followed_by_clause_and_rechecked() {
        let x = Lit::positive(0);
        let y = Lit::positive(1);
        let mut solver = CaDiCaL::default();
        solver.add_binary(x, y).unwrap();
        let mut propagator = RejectFirstModel {
            variable: Var::new(0),
            first_value: None,
            pending: None,
            checks: 0,
        };

        assert_eq!(
            solver
                .solve_with_external_propagator(&mut propagator, &[Var::new(0), Var::new(1)],)
                .unwrap(),
            SolverResult::Sat
        );
        assert!(propagator.checks >= 2);
        assert!(propagator.pending.is_none());
        assert_eq!(
            solver.lit_val(propagator.first_value.unwrap()).unwrap(),
            TernaryVal::False
        );
    }

    struct RejectWithNonblockingClause {
        variable: Var,
        pending: Option<ExternalClause>,
    }

    impl ExternalPropagator for RejectWithNonblockingClause {
        fn check_found_model(&mut self, model: &[Lit]) -> bool {
            let value = *model
                .iter()
                .find(|lit| lit.var() == self.variable)
                .expect("complete model must contain the observed variable");
            self.pending = Some(ExternalClause::new([value], false));
            false
        }

        fn external_clause(&mut self) -> Option<ExternalClause> {
            self.pending.take()
        }
    }

    #[test]
    fn nonblocking_clause_after_rejected_model_is_rejected() {
        let x = Lit::positive(0);
        let y = Lit::positive(1);
        let mut solver = CaDiCaL::default();
        solver.add_binary(x, y).unwrap();
        let mut propagator = RejectWithNonblockingClause {
            variable: Var::new(0),
            pending: None,
        };

        let error = solver
            .solve_with_external_propagator(&mut propagator, &[Var::new(0), Var::new(1)])
            .expect_err("a nonblocking rejection clause must not produce a solve result");
        match error.downcast_ref::<ExternalPropagatorError>() {
            Some(ExternalPropagatorError::Protocol { callback, message }) => {
                assert_eq!(*callback, "has_external_clause");
                assert!(message.contains("not false under rejected model"));
            }
            other => panic!("expected rejected-model protocol error, got {other:?}"),
        }
    }

    #[test]
    fn rejected_model_snapshot_is_used_when_trail_is_insufficient() {
        let x = Lit::positive(0);
        let mut propagator = NoopPropagator;
        let mut bridge = super::PropagatorBridge::new(&mut propagator, HashSet::from([x.vidx32()]));
        assert!(bridge.assigned.is_empty());
        bridge.rejected_model = Some(HashMap::from([(x.vidx32(), x)]));

        assert!(!bridge
            .prepare_external_clause(ExternalClause::new([!x], false))
            .unwrap());
        assert_eq!(bridge.next_external_clause_lit().unwrap(), (!x).to_ipasir());
        assert_eq!(bridge.next_external_clause_lit().unwrap(), 0);

        bridge.rejected_model = Some(HashMap::from([(x.vidx32(), x)]));
        assert!(!bridge
            .prepare_external_clause(ExternalClause::conflict())
            .unwrap());
    }

    struct BorrowedCounter<'a> {
        calls: &'a mut usize,
    }

    impl ExternalPropagator for BorrowedCounter<'_> {
        fn notify_assignment(&mut self, _literals: &[Lit]) {
            *self.calls += 1;
        }

        fn check_found_model(&mut self, _model: &[Lit]) -> bool {
            *self.calls += 1;
            true
        }
    }

    #[test]
    fn borrowed_propagator_is_disconnected_before_it_dies() {
        let x = Lit::positive(0);
        let mut solver = CaDiCaL::default();
        solver.add_unit(x).unwrap();
        let mut calls = 0;
        {
            let mut propagator = BorrowedCounter { calls: &mut calls };
            assert_eq!(
                solver
                    .solve_with_external_propagator(&mut propagator, &[Var::new(0)])
                    .unwrap(),
                SolverResult::Sat
            );
        }
        let calls_after_scoped_solve = calls;
        assert!(calls_after_scoped_solve > 0);

        solver.add_binary(x, !x).unwrap();
        assert_eq!(solver.solve().unwrap(), SolverResult::Sat);
        solver.add_binary(x, !x).unwrap();
        assert_eq!(solver.solve().unwrap(), SolverResult::Sat);
        assert_eq!(calls, calls_after_scoped_solve);
    }

    struct PanickingPropagator;

    impl ExternalPropagator for PanickingPropagator {
        fn notify_assignment(&mut self, _literals: &[Lit]) {
            panic!("callback panic is contained");
        }
    }

    #[test]
    fn callback_panic_is_caught_and_reported() {
        let x = Lit::positive(0);
        let mut solver = CaDiCaL::default();
        solver.add_unit(x).unwrap();
        let error = solver
            .solve_with_external_propagator(&mut PanickingPropagator, &[Var::new(0)])
            .unwrap_err();

        assert!(matches!(
            error.downcast_ref::<ExternalPropagatorError>(),
            Some(ExternalPropagatorError::CallbackPanicked {
                callback: "notify_assignment",
                ..
            })
        ));
    }

    struct InvalidReason {
        trigger: Lit,
        consequence: Lit,
        assigned: bool,
    }

    impl ExternalPropagator for InvalidReason {
        fn notify_assignment(&mut self, literals: &[Lit]) {
            self.assigned |= literals.contains(&self.trigger);
        }

        fn propagate(&mut self) -> Option<ExternalPropagation> {
            self.assigned
                .then(|| ExternalPropagation::new(self.consequence, [!self.trigger]))
        }
    }

    #[test]
    fn invalid_reason_fails_closed_without_crossing_ffi() {
        let x = Lit::positive(0);
        let y = Lit::positive(1);
        let mut solver = CaDiCaL::default();
        solver.add_unit(x).unwrap();
        let mut propagator = InvalidReason {
            trigger: x,
            consequence: y,
            assigned: false,
        };
        let error = solver
            .solve_with_external_propagator(&mut propagator, &[Var::new(0), Var::new(1)])
            .unwrap_err();

        assert!(matches!(
            error.downcast_ref::<ExternalPropagatorError>(),
            Some(ExternalPropagatorError::Protocol {
                callback: "propagate",
                ..
            })
        ));
    }
}
