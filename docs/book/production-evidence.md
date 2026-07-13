# Production evidence

## Contract

`solve --evidence-out PATH FILE` makes the result and its same-run evidence one
fail-closed operation. The solver writes a canonical
UTF-8 `euf-viper.production-evidence.v2` JSON document beside `PATH`, flushes it,
publishes it with a no-replace hard link, syncs the directory, and only then
prints a decisive result. An existing target is never replaced.

Canonical JSON is the compact, key-sorted, non-ASCII-preserving UTF-8 encoding
with a single trailing newline. NaN and infinity are forbidden. The source is
opened once with no-follow semantics; the exact bytes read from that descriptor
are both parsed and hashed, with descriptor and path identity checked before and
after the read. Checkers apply the same rule to source and sidecar bytes.

For SAT, the sidecar binds:

- source bytes and SHA-256;
- compile-time Git revision and dirty state;
- the trusted executable SHA-256 and a build hash over the feature set, target,
  profile, Rust and Cargo toolchains, and source manifest;
- a caller-generated 256-bit run nonce;
- selected backend and every result-affecting `EUF_VIPER_*` runtime setting;
- resolved root-CNF options and a canonical configuration hash;
- the exact clause stream loaded into the backend, its variable and clause
  counts, and the canonical clause hash when a CNF backend was used;
- the exact completed SAT assignment and a complete map for every atom and
  auxiliary CNF variable;
- every production theory atom and its assignment value;
- the induced typed ground-term partition.

`check_production_evidence.py` uses the independent SMT-LIB parser. It checks
the assignment-to-atom relation and exact atom coverage, every literal of every
backend clause against the completed assignment, typed classes, Boolean values,
ground function consistency, and every reconstructed source assertion. It also
enforces the exact status/backend-status pairs `sat/sat`,
`unsupported/unsupported`, and `unsupported/unsat`. It does not rerun the solver
or substitute a canonical encoding for the production path.

Decisive evidence is rejected by default when the build is dirty. A decisive
check also requires an independently trusted executable SHA-256; the value
recorded by the sidecar is not self-authenticating. The emitter requires both
control variables below and verifies the running executable before publishing
evidence or a result:

```bash
export EUF_VIPER_RUN_NONCE="$(openssl rand -hex 32)"
export EUF_VIPER_TRUSTED_EXECUTABLE_SHA256="$(shasum -a 256 \
  target/release/euf-viper | awk '{print $1}')"
target/release/euf-viper solve input.smt2 \
  --evidence-out results/input.production-evidence.json
python3 scripts/cert/check_production_evidence.py \
  results/input.production-evidence.json --source input.smt2 --status sat \
  --executable-sha256 "$EUF_VIPER_TRUSTED_EXECUTABLE_SHA256"
```

## Locked campaigns

New solver configurations opt in with an exact evidence schema, CLI flag, and
accepted decisive statuses. The locked runner derives a unique path from the
run sequence and binds the path, artifact hash, source hash, solver revision,
locked executable and build hashes, run nonce, locked solver-configuration hash,
runtime-configuration hash, status, and schema into the hash-chained run record.
Runtime configuration is compared structurally with the configuration derived
from the lock, not merely with a sidecar-provided hash.

A decisive row without evidence stops the runner. The strict analyzer resolves
and rehashes every bound artifact. The shadow campaign independently validates
each production SAT model and rechecks the journal-bound sidecar hash before
starting its separate canonical certificate rerun. All completed sidecars are
reopened and rehashed on resume and immediately before finalization in the
runner and shadow campaign. The canonical rerun remains additional source-level
evidence; it is not reported as certification of the timed production execution.

The sidecar and journal are each atomically published, but they are separate
files. A machine failure after sidecar publication and before journal append
leaves an orphan artifact and deliberately blocks automatic reuse of that run
path. A fresh campaign output directory is required for recovery because the
timing record cannot be reconstructed safely. Journal rows are canonical JSON
hash frames linked by `previous_record_sha256`; creation and recovery sync the
journal parent directory. Recovery may truncate only a non-newline-terminated
tail after validating the complete authenticated prefix. A malformed complete
frame, a broken hash link, or a missing completed sidecar is fatal.

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
Schema v2 binds and replays the exact pre-inprocessing clause stream presented
through the backend API; it still cannot attest to undocumented clauses or
transformations created internally by a third-party backend after loading.

Locked-campaign process wall and CPU timing includes model extraction,
serialization, sync, and publication overhead. The solver's diagnostic
`elapsed_ns` ends after the solve and therefore excludes serialization and
publication. A timeout or process crash may have no complete sidecar; such a
run is nondecisive. The SAT model is a total model for the ground query, not a
general-purpose SMT-LIB `get-model` response for terms absent from the query.
Portfolio fallback execution is outside this standalone evidence contract and
retains the fallback solver's trust boundary.
