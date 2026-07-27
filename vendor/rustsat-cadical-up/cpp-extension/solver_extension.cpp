namespace CaDiCaL {

#ifndef V220
int64_t Solver::propagations() const {
  TRACE("propagations");
  REQUIRE_VALID_STATE();
  int64_t res = internal->stats.propagations.search;
  LOG_API_CALL_RETURNS("propagations", res);
  return res;
}

int64_t Solver::decisions() const {
  TRACE("decisions");
  REQUIRE_VALID_STATE();
  int64_t res = internal->stats.decisions;
  LOG_API_CALL_RETURNS("decisions", res);
  return res;
}

int64_t Solver::conflicts() const {
  TRACE("conflicts");
  REQUIRE_VALID_STATE();
  int64_t res = internal->stats.conflicts;
  LOG_API_CALL_RETURNS("conflicts", res);
  return res;
}
#endif

bool Solver::configure_decision_probe(int64_t conflict_delta,
                                      int64_t min_decisions,
                                      int64_t max_decisions) {
  REQUIRE_VALID_STATE();
  if (conflict_delta < 0 || min_decisions < 0 ||
      min_decisions > max_decisions ||
      conflict_delta > INT64_MAX - internal->stats.conflicts ||
      (internal->inc.conflicts >= 0 &&
       internal->inc.conflicts < conflict_delta) ||
      (internal->inc.conflicts >= 0 &&
       internal->inc.conflicts > INT64_MAX - internal->stats.conflicts))
    return false;
  Limit &probe_limit = internal->lim;
  probe_limit.decision_probe.state = 1;
  probe_limit.decision_probe.conflict_limit =
      internal->stats.conflicts + conflict_delta;
  probe_limit.decision_probe.base_conflicts = internal->stats.conflicts;
  probe_limit.decision_probe.base_decisions = internal->stats.decisions;
  probe_limit.decision_probe.min_decisions = min_decisions;
  probe_limit.decision_probe.max_decisions = max_decisions;
  probe_limit.decision_probe.observed_conflicts = -1;
  probe_limit.decision_probe.observed_decisions = -1;
  probe_limit.decision_probe.resume_conflict_delta = internal->inc.conflicts;
  probe_limit.decision_probe.resume_conflict_limit =
      internal->inc.conflicts < 0
          ? -1
          : internal->stats.conflicts + internal->inc.conflicts;
  internal->inc.conflicts = conflict_delta;
  return true;
}

void Solver::clear_decision_probe() {
  REQUIRE_VALID_STATE();
  if (internal->lim.decision_probe.state == 1 &&
      internal->inc.conflicts ==
          internal->lim.decision_probe.conflict_limit -
              internal->lim.decision_probe.base_conflicts)
    internal->inc.conflicts =
        internal->lim.decision_probe.resume_conflict_delta;
  internal->lim.decision_probe.state = 0;
  internal->lim.decision_probe.observed_conflicts = -1;
  internal->lim.decision_probe.observed_decisions = -1;
}

int Solver::decision_probe_state() const {
  REQUIRE_INITIALIZED();
  return internal->lim.decision_probe.state;
}

int64_t Solver::decision_probe_conflicts() const {
  REQUIRE_INITIALIZED();
  return internal->lim.decision_probe.observed_conflicts;
}

int64_t Solver::decision_probe_decisions() const {
  REQUIRE_INITIALIZED();
  return internal->lim.decision_probe.observed_decisions;
}

#ifndef V213
// Propagate and check
// This is based on the implementation in PySat
// https://github.com/pysathq/pysat/blob/master/solvers/patches/cadical195.patch
bool Solver::prop_check(const int *assumps, size_t assumps_len, bool psaving,
                        void (*prop_cb)(void *, int), void *cb_data) {
  if (internal->unsat || internal->unsat_constraint) {
    return false;
  }

  // saving default options
#ifdef V190
  int old_ilb = internal->opts.ilb;
#ifndef V194
  int old_reimply = internal->opts.reimply;
#endif
#endif
  int old_psave = internal->opts.rephase;
  int old_lucky = internal->opts.lucky;
  int old_resall = internal->opts.restoreall;

  // resetting the above options
#ifdef V190
  internal->opts.ilb = 0;
#ifndef V194
  internal->opts.reimply = 0;
#endif
#endif
  internal->opts.lucky = psaving;
  internal->opts.rephase = psaving;
  internal->opts.restoreall = 2;

  int tmp = internal->already_solved();
  if (!tmp)
    tmp = internal->restore_clauses();
  if (tmp) {
    // restoring default option values
#ifdef V190
    internal->opts.ilb = old_ilb;
#ifndef V194
    internal->opts.reimply = old_reimply;
#endif
#endif
    internal->opts.lucky = old_lucky;
    internal->opts.rephase = old_psave;
    internal->opts.restoreall = old_resall;
    internal->reset_solving();
    internal->report_solving(tmp);
    return false;
  }
  internal->opts.restoreall = old_resall;

  bool unsat = false;
  int level = internal->level;
  bool noconfl = true;
  Clause *old_conflict = internal->conflict;

  // propagate each assumption at a new decision level
  for (size_t i = 0; !unsat && noconfl && i < assumps_len; ++i) {
    int p = assumps[i];

    // deciding
    const signed char tmp = internal->val(p);
    if (tmp < 0) // if assumption is already set to false
      unsat = true;
    else {
#ifdef V160
      if (tmp > 0) {
        // add pseudo decision level
#ifdef V190
        internal->new_trail_level(0);
#else
        internal->level++;
        internal->control.push_back(Level(0, internal->trail.size()));
#endif
        internal->notify_decision();
      } else
        internal->search_assume_decision(p);

      noconfl = internal->propagate();
      if (noconfl)
        noconfl = internal->external_propagate();
#else
      if (tmp == 0) {
        internal->search_assume_decision(p);
        noconfl = internal->propagate();
      }
#endif
    }
  }

  // copy results
  if (internal->level > level) {
    for (size_t i = internal->control[level + 1].trail;
         i < internal->trail.size(); ++i) {
      prop_cb(cb_data, internal->trail[i]);
    }
    // if there is a conflict, push the conflicting literal as well
    if (!noconfl) {
      literal_iterator conflict_ptr = internal->conflict->begin();
      int conflict_val = *conflict_ptr;
      prop_cb(cb_data, conflict_val);
    }
    // backtrack
    internal->backtrack(level);
  }

#ifdef V190
  internal->opts.ilb = old_ilb;
#ifndef V194
  internal->opts.reimply = old_reimply;
#endif
#endif

  // restore phase saving
  internal->opts.rephase = old_psave;
  internal->opts.lucky = old_lucky;
  // reset conflict
  internal->conflict = old_conflict;
  internal->reset_solving();
  internal->report_solving(tmp);

  return !unsat && noconfl;
}
#endif

} // namespace CaDiCaL
