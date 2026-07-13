// CaDiCaL C API Extension (Christoph Jabs)
// To be included at the bottom of `ccadical.cpp`

#ifdef V220
class RustSatExternalPropagator final : public CaDiCaL::ExternalPropagator {
  CaDiCaL::Solver *solver;
  void *state;
  CCaDiCaLExternalPropagatorCallbacks callbacks;
  bool aborted = false;
  bool connected = false;

  bool callback_succeeded(int status) {
    if (status == 1)
      return true;
    abort();
    return false;
  }

public:
  RustSatExternalPropagator(
      CaDiCaL::Solver *solver, void *state,
      CCaDiCaLExternalPropagatorCallbacks callbacks)
      : solver(solver), state(state), callbacks(callbacks) {}

  void mark_connected() { connected = true; }

  void disconnect() {
    if (!connected)
      return;
    solver->disconnect_external_propagator();
    connected = false;
  }

  void abort() {
    if (aborted)
      return;
    aborted = true;
    solver->terminate();
  }

  void add_observed_var(int var) { solver->add_observed_var(var); }

  void notify_assignment(const std::vector<int> &lits) override {
    if (aborted)
      return;
    callback_succeeded(
        callbacks.notify_assignment(state, lits.data(), lits.size()));
  }

  void notify_new_decision_level() override {
    if (aborted)
      return;
    callback_succeeded(callbacks.notify_new_decision_level(state));
  }

  void notify_backtrack(size_t new_level) override {
    if (aborted)
      return;
    callback_succeeded(callbacks.notify_backtrack(state, new_level));
  }

  bool cb_check_found_model(const std::vector<int> &model) override {
    if (aborted)
      return false;
    int accepted = 0;
    if (!callback_succeeded(callbacks.check_found_model(
            state, model.data(), model.size(), &accepted)))
      return false;
    if (accepted != 0 && accepted != 1) {
      abort();
      return false;
    }
    return accepted == 1;
  }

  int cb_decide() override { return 0; }

  int cb_propagate() override { return 0; }

  int cb_add_reason_clause_lit(int propagated_lit) override {
    if (aborted)
      return 0;
    int lit = 0;
    if (!callback_succeeded(
            callbacks.add_reason_clause_lit(state, propagated_lit, &lit)))
      return 0;
    return lit;
  }

  bool cb_has_external_clause(bool &is_forgettable) override {
    if (aborted)
      return false;
    int has_clause = 0;
    int forgettable = 0;
    if (!callback_succeeded(callbacks.has_external_clause(
            state, &has_clause, &forgettable)))
      return false;
    if ((has_clause != 0 && has_clause != 1) ||
        (forgettable != 0 && forgettable != 1)) {
      abort();
      return false;
    }
    is_forgettable = forgettable == 1;
    return has_clause == 1;
  }

  int cb_add_external_clause_lit() override {
    if (aborted)
      return 0;
    int lit = 0;
    if (!callback_succeeded(callbacks.add_external_clause_lit(state, &lit)))
      return 0;
    return lit;
  }
};

struct CCaDiCaLExternalPropagator {
  RustSatExternalPropagator implementation;

  CCaDiCaLExternalPropagator(
      CaDiCaL::Solver *solver, void *state,
      CCaDiCaLExternalPropagatorCallbacks callbacks)
      : implementation(solver, state, callbacks) {}
};
#endif

extern "C" {

int ccadical_add_mem(CCaDiCaL *wrapper, int lit) {
  try {
    ((Wrapper *)wrapper)->solver->add(lit);
    return 0;
  } catch (std::bad_alloc &) {
    return OUT_OF_MEM;
  }
}

int ccadical_assume_mem(CCaDiCaL *wrapper, int lit) {
  try {
    ((Wrapper *)wrapper)->solver->assume(lit);
    return 0;
  } catch (std::bad_alloc &) {
    return OUT_OF_MEM;
  }
}

int ccadical_constrain_mem(CCaDiCaL *wrapper, int lit) {
  try {
    ((Wrapper *)wrapper)->solver->constrain(lit);
    return 0;
  } catch (std::bad_alloc &) {
    return OUT_OF_MEM;
  }
}

int ccadical_solve_mem(CCaDiCaL *wrapper) {
  try {
    return ((Wrapper *)wrapper)->solver->solve();
  } catch (std::bad_alloc &) {
    return OUT_OF_MEM;
  }
}

int ccadical_configure(CCaDiCaL *ptr, const char *name) {
  return ((Wrapper *)ptr)->solver->configure(name);
}

#ifndef V220
void ccadical_phase(CCaDiCaL *ptr, int lit) {
  ((Wrapper *)ptr)->solver->phase(lit);
}

void ccadical_unphase(CCaDiCaL *ptr, int lit) {
  ((Wrapper *)ptr)->solver->unphase(lit);
}

int ccadical_vars(CCaDiCaL *ptr) { return ((Wrapper *)ptr)->solver->vars(); }
#endif

int ccadical_set_option_ret(CCaDiCaL *wrapper, const char *name, int val) {
  return ((Wrapper *)wrapper)->solver->set(name, val);
}

int ccadical_limit_ret(CCaDiCaL *wrapper, const char *name, int val) {
  return ((Wrapper *)wrapper)->solver->limit(name, val);
}

int64_t ccadical_redundant(CCaDiCaL *wrapper) {
  return ((Wrapper *)wrapper)->solver->redundant();
}

int ccadical_simplify_rounds(CCaDiCaL *wrapper, int rounds) {
  return ((Wrapper *)wrapper)->solver->simplify(rounds);
}

int ccadical_resize(CCaDiCaL *wrapper, int min_max_var) {
  try {
#ifdef V220
    ((Wrapper *)wrapper)->solver->resize(min_max_var);
#else
    ((Wrapper *)wrapper)->solver->reserve(min_max_var);
#endif
    return 0;
  } catch (std::bad_alloc &) {
    return OUT_OF_MEM;
  }
}

#ifndef V220
int64_t ccadical_propagations(CCaDiCaL *wrapper) {
  return ((Wrapper *)wrapper)->solver->propagations();
}

int64_t ccadical_decisions(CCaDiCaL *wrapper) {
  return ((Wrapper *)wrapper)->solver->decisions();
}

int64_t ccadical_conflicts(CCaDiCaL *wrapper) {
  return ((Wrapper *)wrapper)->solver->conflicts();
}
#endif

#ifdef V154
int ccadical_flip(CCaDiCaL *wrapper, int lit) {
  return ((Wrapper *)wrapper)->solver->flip(lit);
}

int ccadical_flippable(CCaDiCaL *wrapper, int lit) {
  return ((Wrapper *)wrapper)->solver->flippable(lit);
}
#endif

#ifndef V213
int ccadical_propcheck(CCaDiCaL *wrapper, const int *assumps,
                       size_t assumps_len, int psaving,
                       void (*prop_cb)(void *, int), void *cb_data) {
  try {
    if (((Wrapper *)wrapper)
            ->solver->prop_check(assumps, assumps_len, psaving, prop_cb,
                                 cb_data)) {
      return 10;
    }
    return 20;
  } catch (std::bad_alloc &) {
    return OUT_OF_MEM;
  }
}
#else
int ccadical_propagate(CCaDiCaL *wrapper) {
  try {
    return ((Wrapper *)wrapper)->solver->propagate();
  } catch (std::bad_alloc &) {
    return OUT_OF_MEM;
  }
}

void ccadical_implied(CCaDiCaL *wrapper, void (*implied_cb)(void *, int),
                      void *cb_data) {
  std::vector<int> implied{};
#ifdef V220
  ((Wrapper *)wrapper)->solver->implied(implied);
#else
  ((Wrapper *)wrapper)->solver->get_entrailed_literals(implied);
#endif
  for (int lit : implied) {
    implied_cb(cb_data, lit);
  }
}
#endif

#ifndef NTRACING
int ccadical_trace_api_calls(CCaDiCaL *wrapper, const char *const path) {
  FILE *trace_file = fopen(path, "w");
  if (!trace_file)
    return 1;
  ((Wrapper *)wrapper)->solver->trace_api_calls(trace_file);
  return 0;
}
#endif

int ccadical_trace_proof_path(CCaDiCaL *wrapper, const char *const path) {
  return ((Wrapper *)wrapper)->solver->trace_proof(path);
}
}

#ifdef V220
int64_t ccadical_get_statistic_value(const CCaDiCaL *wrapper,
                                     const char *const opt) {
  return ((Wrapper *)wrapper)->solver->get_statistic_value(opt);
}

CCaDiCaLExternalPropagator *ccadical_connect_external_propagator(
    CCaDiCaL *wrapper, void *state,
    CCaDiCaLExternalPropagatorCallbacks callbacks) {
  if (!wrapper || !state || !callbacks.notify_assignment ||
      !callbacks.notify_new_decision_level || !callbacks.notify_backtrack ||
      !callbacks.check_found_model || !callbacks.has_external_clause ||
      !callbacks.add_external_clause_lit ||
      !callbacks.add_reason_clause_lit)
    return nullptr;
  CCaDiCaLExternalPropagator *propagator = nullptr;
  try {
    Wrapper *rustsat_wrapper = (Wrapper *)wrapper;
    propagator = new CCaDiCaLExternalPropagator(rustsat_wrapper->solver, state,
                                                callbacks);
    rustsat_wrapper->solver->connect_external_propagator(
        &propagator->implementation);
    propagator->implementation.mark_connected();
    return propagator;
  } catch (...) {
    delete propagator;
    return nullptr;
  }
}

int ccadical_external_propagator_add_observed_var(
    CCaDiCaLExternalPropagator *propagator, int var) {
  if (!propagator || var <= 0)
    return 0;
  try {
    propagator->implementation.add_observed_var(var);
    return 1;
  } catch (...) {
    propagator->implementation.abort();
    return 0;
  }
}

void ccadical_external_propagator_abort(
    CCaDiCaLExternalPropagator *propagator) {
  if (propagator)
    propagator->implementation.abort();
}

void ccadical_disconnect_external_propagator(
    CCaDiCaLExternalPropagator *propagator) {
  if (!propagator)
    return;
  propagator->implementation.disconnect();
  delete propagator;
}
#endif

#ifdef V200
#include "ctracer.cpp"
#endif
