// CaDiCaL Solver API Extension (Christoph Jabs)
// To be included in the public interface of `Solver` in `cadical.hpp`

#ifndef V220
int64_t propagations() const;
int64_t decisions() const;
int64_t conflicts() const;
#endif

#ifndef V213
bool prop_check(const int *assumps, size_t assumps_len, bool psaving,
                void (*prop_cb)(void *, int), void *cb_data);
#endif

bool configure_decision_probe(int64_t conflict_delta, int64_t min_decisions,
                              int64_t max_decisions);
void clear_decision_probe();
int decision_probe_state() const;
int64_t decision_probe_conflicts() const;
int64_t decision_probe_decisions() const;
