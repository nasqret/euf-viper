# Production evidence

## Scope

Production evidence v4 is a **restricted SAT-only certifying mode**. It is
available only through the explicit `production-evidence` Cargo feature and is
not enabled by the default Cargo features or by the existing `certificates`
feature. With `--evidence-out` absent, the ordinary parser, solver configuration,
routes, result, and output contract remain unchanged. This is checked by
independently checking out and building `f8d9205` with the pinned toolchain,
then comparing byte-exact stdout, stderr, and exit status for no arguments,
help, unknown and
extra legacy arguments, file and stdin parsing, successful solves, parse errors,
and missing files. Strict evidence argument parsing is activated only when the
exact `--evidence-out` flag occurs; ordinary help remains baseline-compatible.

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
UTF-8 `euf-viper.production-evidence.v4` JSON document at `PATH`, flushes it,
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
  profile, Rust and Cargo toolchains, selected source manifest, sealed full
  source snapshot manifest, and build execution closure;
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

Decisive evidence is rejected unless it came from the sealed Linux builder. An
ordinary Cargo build, including a Linux build with the feature enabled, can run
off-mode and fail-closed tests but cannot emit evidence. A decisive
check also requires an independently trusted executable SHA-256; the value
recorded by the sidecar is not self-authenticating. The emitter requires both
control variables below and verifies the running executable before publishing
evidence or a result:

```bash
TOOLCHAIN=1.96.0
ATTEMPT="/tmp/euf-viper-sealed-$UID"
install -d -m 0700 "$ATTEMPT" "$ATTEMPT/home"
python3 -B scripts/wmi/sealed_linux_build.py build \
  --repository . --revision "$(git rev-parse HEAD)" \
  --artifact-dir target/sealed-release \
  --staging-root "$ATTEMPT/sealed-staging" \
  --cargo-home "$HOME/.cargo" --rustup-home "$HOME/.rustup" \
  --home "$ATTEMPT/home" \
  --git "$(command -v git)" \
  --cargo "$(rustup which --toolchain "$TOOLCHAIN" cargo)" \
  --rustc "$(rustup which --toolchain "$TOOLCHAIN" rustc)" \
  --unshare "$(command -v unshare)" --ldd "$(command -v ldd)" \
  --cc "$(command -v cc)" --cxx "$(command -v c++)" \
  --ar "$(command -v ar)" --ranlib "$(command -v ranlib)"
export EUF_VIPER_RUN_NONCE="$(openssl rand -hex 32)"
export EUF_VIPER_TRUSTED_EXECUTABLE_SHA256="$(sha256sum \
  target/sealed-release/euf-viper | awk '{print $1}')"
target/sealed-release/euf-viper solve input.smt2 \
  --evidence-out results/input.production-evidence.json
python3 scripts/cert/check_production_evidence.py \
  results/input.production-evidence.json --source input.smt2 --status sat \
  --executable-sha256 "$EUF_VIPER_TRUSTED_EXECUTABLE_SHA256"
```

The builder requires Linux `/proc/self/fd`, sealed `memfd_create`, a working
unprivileged user and mount namespace, private mount propagation, tmpfs, and a
read-only recursive bind remount. It disables same-UID process inspection,
extracts the exact Git archive plus the `cargo vendor --locked` registry into
an attempt-private tmpfs, copies and inventories the pinned Rust sysroot,
verifies every source byte and mode, and remounts all inputs read-only before
Cargo or a native compiler runs. Rust/Cargo, compiler/linker/archive tools,
dynamic loaders, shared libraries, and the full vendored registry are hashed.
External native tool paths whose file or parent directory is writable by the
build UID are rejected. Failure of any namespace, seal, mount, read-only, or
path-stability primitive aborts the build; there is no pathname-only fallback.

## Locked campaigns

The locked WMI preparation builds one campaign binary from the sealed snapshot
with `--features certificates,production-evidence`. The same sealed build emits the
opt-in `euf-viper-build-features` companion executable. Preparation queries that
report immediately and fails before solver installation or campaign freezing if
either feature is absent; the real solver must then pass an evidence-emitting
smoke. The
solver-configuration recorder repeats the production-evidence check against the
compiled companion report, then exercises the real solver with `--evidence-out`,
before it can publish a lock.

Submission is split into two invocations. The first creates the attempt and
submits **only** preparation:

```bash
scripts/wmi/submit_locked_p0.sh
```

It writes a local canonical `locked-p0-prepare-*.json` receipt containing the
prepare job and exact remote `prepare.json` path. An external orchestrator must
wait for successful preparation, read that final remote file, capture its
SHA-256 outside the dependency graph, and explicitly supply both values:

```bash
scripts/wmi/submit_locked_p0_dependents.sh \
  results/locked-p0-prepare-ATTEMPT.json \
  EXTERNALLY_CAPTURED_PREPARE_JSON_SHA256
```

The second invocation rehashes the remote receipt under that supplied digest
and runs the full provenance verifier before submitting either array. Both
arrays and the audit receive the exact digest and independently reject any
different receipt. The audit depends only on the two accepted arrays. No array
or audit submission exists in the preparation submitter.

Every preparation creates a private, attempt-specific mode-0700 remote root and
a fresh no-hardlink detached checkout. The revision is never used as a reusable
checkout or results directory. Preparation binds the attempt identity and
canonical paths, every tracked source blob and mode, Git tree, exact execution
environment, runtime realpaths and hashes, solver binaries, feature report,
corpus manifests, and generated lock artifacts into immutable receipts. Any
tracked mutation, skip-worktree or assume-unchanged index flag, untracked file,
or ignored file in the execution checkout aborts the chain.

SLURM stages receive only an explicit receipt-bound `EUF_VIPER_*` allowlist,
never `--export=ALL`, and execute tools through a clean environment. Ambient
Rust/Cargo wrappers and flags, Cargo configuration overrides, Python path/home
and startup hooks, shell startup files, build helpers, Git object/config
overrides, and unlisted solver controls are rejected before source execution.
Python runs with `-B -I -S`; build, cache, home, temporary, solver, corpus, log,
and result paths created by the attempt live outside the checkout but inside its
private root. A pre-existing shared corpus may remain outside that root; its
canonical manifest paths and hashes are receipt-bound before shard execution.

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

On Linux, the timed solver, SMT source, certificate solver, Python interpreter,
checker source, independent parser, generated certificate manifest, and
generated DIMACS/proof pair, and optional `drat-trim` executable are opened and
hash-checked once, then executed or read through inherited `/proc/self/fd`
descriptors. The checker preserves the bound DIMACS, proof, and `drat-trim`
descriptors when spawning `drat-trim`. Production execution fails closed on
platforms without this primitive. Preparation separately inventories and
rehashes every runtime executable, its loader and shared-library closure, the
checker sources, the sealed build manifest, and Z3's exact `libz3`; sealed
artifact hashes must match the prepared solver and feature-report bindings.

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
Schema v4 binds and replays the exact pre-inprocessing clause stream presented
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
evidence sort is constructed. Test-only instrumentation, absent from production
code generation, also covers symbol retention, source capture, hashing,
serialization, payload construction, and immutable publication. It checks SAT
and UNSAT for every backend, parser contradiction, congruence-closure SAT/UNSAT,
invalid-model refinement cuts, unsupported and unavailable backends,
interruption, limits, errors, and early returns, while asserting exact ordinary
result parity.
