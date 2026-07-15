# Production-evidence v4 validation

Date: 2026-07-15 (Europe/Warsaw)

## Candidate identity

- Isolated clone: `/private/tmp/euf-viper-production-evidence-v4`
- Branch: `production-evidence-v4`
- Published research base: `b9da60ba50164fd14d9db2177c245cb4ac1cf681`
- Validated implementation commit: `3a292f3bbc29b514440268b30703d14927d4c343`
- Source clone mode: no hardlinks; push URL set to `DISABLED`
- Original checkout: `/Users/airbartek/codex/z3`, not modified
- WMI submission: not invoked
- Git push: not invoked

## Contract implemented

1. Preparation submits alone. A second external-orchestrator command requires an
   externally supplied SHA-256 of the completed remote preparation receipt,
   rehashes that exact receipt remotely, and exports the digest to both arrays
   and the dependent audit. Every shard and audit rejects a different digest.
2. Production binaries are built only by the Linux sealed builder from an exact
   Git archive plus `cargo vendor --locked`. The sealed memfd snapshot and copied
   Rust sysroot are verified, inventoried, recursively remounted read-only in a
   private user/mount namespace, and bound to embedded manifest hashes. Missing
   Linux enforcement fails closed.
3. Timed solvers, source files, the certificate solver, Python, checker source,
   independent parser, generated manifest/CNF/proof, and optional `drat-trim`
   are hash-checked and consumed through inherited Linux procfd descriptors.
4. Build and runtime closure manifests bind executables, native compiler tools
   and subtools, the Rust sysroot, vendored Cargo registry, dynamic loader and
   shared libraries, checker artifacts, sealed build manifest, and Z3 `libz3`.
5. Python and Rust immutable publication now use full inode/metadata identity,
   recheck the final lexical path and reopened parent after directory sync, and
   refresh identity after each cleanup unlink. Tests cover final replacement,
   parent rename, injected fsync and post-link failures, concurrency, and Linux
   executable/source substitution.
6. Ordinary CLI compatibility is measured against an independently cloned,
   detached, `cargo --locked` build of published baseline `f8d9205`; no expected
   stdout, stderr, or exit constants remain in the candidate-controlled check.
7. Rust is pinned by `rust-toolchain.toml` to `1.96.0`; production and CI Cargo
   build/test/vendor commands use `--locked`.

Production evidence remains opt-in. The independently built ordinary CLI
differential and off-mode instrumentation verify that an ordinary invocation
does not perform evidence-only source capture, hashing, transcript retention,
serialization, or publication.

## Validation environment

- Host: `Darwin 25.0.0 arm64` (macOS, not Linux)
- Python: `3.14.6`
- Rust: `rustc 1.96.0 (ac68faa20 2026-05-25)`
- Cargo: `cargo 1.96.0 (30a34c682 2026-05-25)`
- Jupyter Book: `1.0.4.post1`

## Final local results

### Python

Command:

```text
python3 -B -m unittest discover -s tests -p 'test_*.py'
```

Result: PASS, 414 tests run, 0 failures, 43 platform/tool-dependent skips.
Linux-only procfd, namespace, and execution-closure process tests were skipped
because the host kernel is Darwin; they were not simulated.

Python compilation checks passed for every changed production-evidence,
provenance, closure, baseline, runner, analyzer, shadow, and checker module.
`bash -n` passed for every changed shell and SLURM entry point.

### Rust feature matrix

Every command used `cargo test --locked` with the pinned `1.96.0` toolchain.

| Features | Unit result | Integration result |
|---|---:|---:|
| default | 242 passed, 3 ignored | 4 passed |
| `--no-default-features` | 236 passed, 3 ignored | 4 passed |
| no default + `certificates` | 242 passed, 4 ignored | 4 passed |
| no default + `production-evidence` | 245 passed, 3 ignored | 5 passed |
| no default + both evidence features | 251 passed, 4 ignored | 5 passed |
| `--all-features` | 257 passed, 4 ignored | 5 passed |

`cargo fmt --all -- --check`: PASS.

### Independent ordinary CLI baseline

- Baseline revision: `f8d9205e8a18e3496d236fb9b94ed181add93e80`
- Baseline tree: `c568afb1760f7f8a74fb6aceae58de6749683e5c`
- Baseline `Cargo.lock` SHA-256:
  `66c19c2bdd228d51c2c2d6f31822125b3ce1d8cb1f8f34e03bdec65a5bbfa52f`
- Baseline executable SHA-256:
  `d193c3e254dabdf1e05b3528c4706971352d84b8049cf2bd72e7cd8e5b4aed24`
- Baseline checkout/output:
  `/private/tmp/euf-viper-cli-baseline-production-evidence-v4`

The candidate release was rebuilt with
`cargo build --locked --release --features certificates,production-evidence`.
The differential compared exit status, stdout, and stderr for no arguments,
help aliases, an unknown command, missing solve input, ordinary solve, legacy
extra arguments, parse error, missing file, and file/stdin parse-check cases.

Result: PASS, byte-for-byte match with the independently built baseline.

### Documentation and Git

- `./docs/book/scripts/validate-book.sh`: PASS with `-W -n --all`; 11 source
  pages built successfully.
- `git diff --cached --check`: PASS before the implementation commit.
- `git fsck --full`: exit 0, no corrupt or missing objects. The no-hardlink
  local clone inherited unreachable objects, which Git reported as dangling;
  they are not repository integrity errors and were not pruned.

## Linux prerequisite not executed locally

The full sealed build, runtime execution-closure inventory, Linux descriptor
substitution process tests, and real release evidence smoke were not run on this
Darwin host. The local probe failed closed with exit 2 and this precise reason:

```text
sealed build rejected: production evidence requires Linux user/mount namespaces, sealed memfd, and read-only bind mounts
```

A remaining acceptance run therefore requires a real Linux host with mounted
`/proc/self/fd`, `memfd_create` sealing, working unprivileged user and mount
namespaces, private mount propagation, tmpfs, recursive read-only bind remounts,
and the pinned Rust/Cargo and native toolchain. The GitHub Linux workflow runs
the full sealed build and release smoke and is intentionally fail-closed if any
primitive is unavailable. No weaker local result is substituted for that gate.
