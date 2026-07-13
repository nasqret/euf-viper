# Production evidence

## Contract

`solve --evidence-out PATH FILE` makes the result and its same-run evidence one
fail-closed operation. The solver writes a canonical
UTF-8 `euf-viper.production-evidence.v1` JSON document beside `PATH`, flushes it,
publishes it with a no-replace hard link, syncs the directory, and only then
prints a decisive result. An existing target is never replaced.

For SAT, the sidecar binds:

- source bytes and SHA-256;
- compile-time Git revision and dirty state;
- selected backend and every `EUF_VIPER_*` runtime setting;
- resolved root-CNF options and a canonical configuration hash;
- the exact completed SAT assignment when a CNF backend was used;
- every production theory atom and its assignment value;
- the induced typed ground-term partition.

`check_production_evidence.py` uses the independent SMT-LIB parser. It checks
the assignment-to-atom relation, typed classes, Boolean values, ground function
consistency, and every reconstructed source assertion. It does not rerun the
solver or substitute a canonical encoding for the production path.

```bash
target/release/euf-viper solve input.smt2 \
  --evidence-out results/input.production-evidence.json
python3 scripts/cert/check_production_evidence.py \
  results/input.production-evidence.json --source input.smt2 --status sat
```

## Locked campaigns

New solver configurations opt in with an exact evidence schema, CLI flag, and
accepted decisive statuses. The locked runner derives a unique path from the
run sequence and binds the path, artifact hash, source hash, solver revision,
locked solver-configuration hash, runtime-configuration hash, status, and
schema into the hash-chained run record.

A decisive row without evidence stops the runner. The strict analyzer resolves
and rehashes every bound artifact. The shadow campaign independently validates
each production SAT model before starting its separate canonical certificate
rerun. The canonical rerun remains additional source-level evidence; it is not
reported as certification of the timed production execution.

The sidecar and journal are each atomically published, but they are separate
files. A machine failure after sidecar publication and before journal append
leaves an orphan artifact and deliberately blocks automatic reuse of that run
path. A fresh campaign output directory is required for recovery because the
timing record cannot be reconstructed safely.

## Current limitations

Only SAT is accepted as a decisive production-evidence status. Every production
UNSAT route currently fails closed:

- the vendored Kissat interface does not emit a proof on the production call;
- CaDiCaL proof tracing is not yet bound to the exact direct-root CNF and all
  dynamically added EUF lemmas;
- Varisat proof output is not enabled on the production refinement loop;
- the internal DPLL(T), parser-contradiction, and direct congruence-closure
  routes do not emit replayable explanation traces.

The existing `certify` command builds a fresh canonical CNF and proof. It is
valuable independent source-level evidence, but it does not certify the
literal timed backend call, its transformed CNF, or its inprocessing history.

Locked-campaign process wall and CPU timing includes model extraction,
serialization, sync, and publication overhead. The solver's diagnostic
`elapsed_ns` ends after the solve and therefore excludes serialization and
publication. A timeout or process crash may have no complete sidecar; such a
run is nondecisive. The SAT model is a total model for the ground query, not a
general-purpose SMT-LIB `get-model` response for terms absent from the query.
Portfolio fallback execution is outside this standalone evidence contract and
retains the fallback solver's trust boundary.
