# Production evidence

## Scope

Production evidence v3 is a **restricted SAT-only certifying mode**. It is
available only through the explicit `production-evidence` Cargo feature and is
not enabled by the default Cargo features or by the existing `certificates`
feature. With `--evidence-out` absent, the ordinary parser, solver configuration,
routes, result, and output contract remain unchanged.

Evidence mode forces deterministic canonical routes for the supported Boolean
CNF path. It disables result-affecting finite-domain, full-Ackermann,
equality-abstraction, chordal-transitivity, and adaptive-refinement choices and
binds the resulting configuration. Congruence-closure SAT and UNSAT are emitted
as nondecisive `unsupported` evidence because that route has no complete replay
contract. The same fail-closed rule applies to every unsupported path and every
UNSAT route without a same-run proof.

This feature does not establish a coverage result, certify the normal-default
solver, or support a solver-superiority claim. It is an integration candidate;
no corpus campaign is admissible until a fresh independent review accepts this
reconstruction.

## Contract

`solve --evidence-out PATH FILE` makes the result and its same-run evidence one
fail-closed operation. The solver writes a canonical
UTF-8 `euf-viper.production-evidence.v3` JSON document at `PATH`, flushes it,
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
- resolved root-CNF and evidence-mode options plus a canonical configuration
  hash;
- the independently reconstructible initial production CNF, exact variable
  count and namespace, and complete atom/auxiliary variable map;
- the ordered final clause stream supplied through the backend API, with exact
  initial/final counts and canonical hashes;
- a deterministic solve, assignment, validation, and clause-addition event
  transcript with an exact count and canonical hash;
- the exact completed SAT assignment and a complete map for every atom and
  auxiliary CNF variable;
- every production theory atom and its assignment value;
- the induced typed ground-term partition.

`check_production_evidence.py` uses the independent SMT-LIB parser. It checks
the exact direct-root production encoding, variable namespace and identity map,
static transitivity and congruence clauses, and each dynamically added theory
clause. It independently replays every assignment and EUF validation event,
requires the replayed stream to equal the sidecar byte-for-byte under canonical
JSON encoding, and checks every final clause against the completed assignment.
It also verifies typed classes, Boolean values, ground function consistency,
every source assertion, and the exact status/backend-status pairs `sat/sat`,
`unsupported/sat`, `unsupported/unsupported`, and `unsupported/unsat`.

Decisive evidence is rejected by default when the build is dirty. A decisive
check also requires an independently trusted executable SHA-256; the value
recorded by the sidecar is not self-authenticating. The emitter requires both
control variables below and verifies the running executable before publishing
evidence or a result:

```bash
cargo build --release --features production-evidence
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

The locked WMI preparation builds one campaign binary with
`--features certificates,production-evidence`. It queries that executable's
compile-time feature report immediately after the build and fails before solver
installation or campaign freezing if either feature is absent. The
solver-configuration recorder repeats the production-evidence check against the
real executable before it can exercise `--evidence-out` or publish a lock.

New solver configurations opt in with an exact evidence schema, CLI flag, and
accepted decisive statuses. The locked runner derives a unique path from the
run sequence and binds the path, artifact hash, source hash, solver revision,
locked executable and build hashes, run nonce, locked solver-configuration hash,
runtime-configuration hash, status, and schema into the hash-chained run record.
Runtime configuration is compared structurally with the configuration derived
from the lock, not merely with a sidecar-provided hash.

A decisive row without evidence stops the runner. The strict analyzer resolves
and rehashes every bound artifact and runs the independent production checker
before classifying any candidate SAT row. A forged or unknown origin and any
checker failure remain nondecisive. The shadow campaign consumes only those
checked bindings and rechecks each journal-bound sidecar before starting its
separate canonical certificate rerun. All completed sidecars are reopened and
rehashed on resume. A final rehash runs inside the atomic summary publication
step, before `status: complete` can replace the in-progress summary. The
canonical rerun remains additional source-level evidence; it is not reported as
certification of the timed production execution.

The sidecar and journal are each atomically published, but they are separate
files. Every parent path component is traversed through no-follow directory
descriptors; a symlinked output or `production-evidence` directory is rejected.
A machine failure after sidecar publication and before journal append
leaves an orphan artifact and deliberately blocks automatic reuse of that run
path. A fresh campaign output directory is required for recovery because the
timing record cannot be reconstructed safely. Journal rows are canonical JSON
hash frames linked by `previous_record_sha256`; creation and append sync the
journal and its parent directory. Ordinary resume rejects an incomplete trailing
frame without truncating or changing the journal. Any offline salvage must be a
separate, explicitly non-promotional copy; it cannot create a promotable complete
summary. A malformed frame, broken hash link, or missing completed sidecar is
fatal.

`scripts/cert/recover_hash_journal.py SOURCE OUTPUT` performs that separate
forensic recovery. It verifies every complete canonical hash frame and appends a
`non_promotional_recovery` marker binding the discarded tail. Runner and shadow
journal schemas reject the marked output, so it cannot be resumed or finalized.

## Current limitations

Only SAT is accepted as a decisive production-evidence status. Every production
UNSAT route currently fails closed:

- the vendored Kissat interface does not emit a proof on the production call;
- CaDiCaL proof tracing is not yet bound to the exact direct-root CNF and all
  dynamically added EUF lemmas;
- Varisat proof output is not enabled on the production refinement loop;
- the parser-contradiction and direct congruence-closure routes do not emit
  replayable explanation traces.

Congruence-closure SAT and UNSAT are always recorded as `unsupported/sat` and
`unsupported/unsat`, respectively. This includes empty-CNF SAT. Evidence mode
is derived from the hash-bound backend and resolved configuration, never from
model metadata.

The existing `certify` command builds a fresh canonical CNF and proof. It is
valuable independent source-level evidence, but it does not certify the
literal timed backend call, its transformed CNF, or its inprocessing history.
Schema v3 binds and replays the exact pre-inprocessing clause stream presented
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

With evidence capture off, backend assignments still exist long enough for the
ordinary EUF model check, but no evidence transcript vector, duplicate backend
clause stream, retained DPLL model, evidence-only assignment copy, or canonical
evidence sort is constructed. Unit instrumentation covers Kissat, CaDiCaL,
CaDiCaL refinement, Varisat, and DPLL and checks exact ordinary result parity.
