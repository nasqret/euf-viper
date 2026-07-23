// CaDiCaL C API Extension (Christoph Jabs)
// To be included at the bottom of `ccadical.cpp`

#include <memory>

#ifdef V220
struct CCaDiCaLExternalPropagator final : CaDiCaL::ExternalPropagator {
  void *state;
  CCaDiCaLExternalPropagatorCallbacks callbacks;
  bool active;

  CCaDiCaLExternalPropagator(
      void *state_, const CCaDiCaLExternalPropagatorCallbacks &callbacks_,
      bool is_lazy_, bool reasons_forgettable_)
      : state(state_), callbacks(callbacks_), active(true) {
    is_lazy = is_lazy_;
    are_reasons_forgettable = reasons_forgettable_;
  }

  void deactivate() {
    active = false;
    state = 0;
  }

  void notify_assignment(const std::vector<int> &lits) override {
    if (active)
      callbacks.notify_assignment(state, lits.data(), lits.size());
  }

  void notify_new_decision_level() override {
    if (active)
      callbacks.notify_new_decision_level(state);
  }

  void notify_backtrack(size_t new_level) override {
    if (active)
      callbacks.notify_backtrack(state, new_level);
  }

  bool cb_check_found_model(const std::vector<int> &model) override {
    if (!active)
      return false;
    return callbacks.check_found_model(state, model.data(), model.size()) != 0;
  }

  int cb_decide() override {
    if (!active)
      return 0;
    return callbacks.decide(state);
  }

  int cb_propagate() override {
    if (!active)
      return 0;
    return callbacks.propagate(state);
  }

  int cb_add_reason_clause_lit(int propagated_lit) override {
    if (!active)
      return 0;
    return callbacks.add_reason_clause_lit(state, propagated_lit);
  }

  bool cb_has_external_clause(bool &is_forgettable) override {
    if (!active) {
      is_forgettable = false;
      return true;
    }
    int forgettable = 0;
    const int has_clause =
        callbacks.has_external_clause(state, &forgettable);
    is_forgettable = forgettable != 0;
    return has_clause != 0;
  }

  int cb_add_external_clause_lit() override {
    if (!active)
      return 0;
    return callbacks.add_external_clause_lit(state);
  }
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

#ifdef V220
int ccadical_connect_external_propagator_mem(
    CCaDiCaL *wrapper, void *state,
    const CCaDiCaLExternalPropagatorCallbacks *callbacks, int is_lazy,
    int reasons_forgettable, CCaDiCaLExternalPropagator **propagator) {
  if (!wrapper || !state || !callbacks || !propagator ||
      !callbacks->notify_assignment ||
      !callbacks->notify_new_decision_level || !callbacks->notify_backtrack ||
      !callbacks->check_found_model || !callbacks->decide ||
      !callbacks->propagate || !callbacks->add_reason_clause_lit ||
      !callbacks->has_external_clause ||
      !callbacks->add_external_clause_lit)
    return EXTERNAL_PROPAGATOR_ERROR;

  *propagator = 0;
  std::unique_ptr<CCaDiCaLExternalPropagator> adapter;
  try {
    adapter.reset(new CCaDiCaLExternalPropagator(
        state, *callbacks, is_lazy != 0, reasons_forgettable != 0));
    ((Wrapper *)wrapper)->solver->connect_external_propagator(adapter.get());
    *propagator = adapter.release();
    return 0;
  } catch (std::bad_alloc &) {
    if (adapter)
      adapter->deactivate();
    return OUT_OF_MEM;
  } catch (...) {
    if (adapter)
      adapter->deactivate();
    return EXTERNAL_PROPAGATOR_ERROR;
  }
}

int ccadical_add_observed_var_mem(CCaDiCaL *wrapper, int var) {
  if (!wrapper || var <= 0)
    return EXTERNAL_PROPAGATOR_ERROR;
  try {
    ((Wrapper *)wrapper)->solver->add_observed_var(var);
    return 0;
  } catch (std::bad_alloc &) {
    return OUT_OF_MEM;
  } catch (...) {
    return EXTERNAL_PROPAGATOR_ERROR;
  }
}

int ccadical_disconnect_external_propagator(
    CCaDiCaL *wrapper, CCaDiCaLExternalPropagator *propagator) {
  if (!wrapper || !propagator)
    return EXTERNAL_PROPAGATOR_ERROR;

  // Sever the borrowed Rust state first. Even if CaDiCaL rejects the
  // disconnect, subsequent callbacks cannot access that state.
  propagator->deactivate();
  try {
    ((Wrapper *)wrapper)->solver->disconnect_external_propagator();
    delete propagator;
    return 0;
  } catch (std::bad_alloc &) {
    return OUT_OF_MEM;
  } catch (...) {
    return EXTERNAL_PROPAGATOR_ERROR;
  }
}
#endif

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
#endif

#ifdef V200
#include "ctracer.cpp"
#endif
