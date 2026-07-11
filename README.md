# euf-viper

`euf-viper` is a Rust-first SMT solver for quantifier-free equality with
uninterpreted functions. It parses ground SMT-LIB Boolean structure, builds a
Tseitin CNF, runs an eager finite-domain/EUF encoding through SAT backends, and
validates candidate SAT models with congruence closure before accepting them.

The long-term research target is to outperform both Z3 and Yices2 on QF_UF.
This repository is structured so that claim can only be made after reproducible
SMT-LIB and SMT-COMP runs.

> **Soundness and claim status, 2026-07-11:** the historically measured
> `58efe9d` binary is not generally sound for Boolean values used only as UF
> data. It also predates repairs for quoted reserved symbols and single-query
> command ordering. The current local candidate repairs all three known
> failures and passes 165 all-feature Rust tests plus 86 benchmark-tool tests,
> but it is not promoted until the hash-pinned WMI differential, full paired,
> and four-solver gates complete. No current result establishes superiority
> over Z3 or Yices2.

## Quick Start

```bash
cargo test
cargo run --release -- gen chain 1000 > /tmp/chain.smt2
cargo run --release -- solve --stats /tmp/chain.smt2
cargo run --release -- portfolio \
  --yices third_party/solvers/bin/yices-smt2 /tmp/chain.smt2
cargo run --release -- bench --cases 10 --size 5000
target/release/euf-viper bench-or --cases 4 --branches 256 --depth 4
python3 benches/compare_z3.py generated/synthetic --viper target/release/euf-viper
scripts/bench/install_solvers.sh
scripts/bench/fetch_smtlib_qf_uf.sh
python3 scripts/bench/compare_solvers.py \
  benchmarks/smtlib-2025/qf_uf_manifest.jsonl --timeout 2 --jobs 8
cargo build --release --features certificates
target/release/euf-viper certify tests/fixtures/basic_unsat.smt2 \
  --out-prefix results/cert-basic
scripts/cert/check_certificate.py results/cert-basic.euf.json
scripts/cert/run_official_smoke.sh
```

Expected solver output is one of:

- `sat`
- `unsat`
- `unsupported`

`unsupported` is reserved for syntax or resource boundaries that are not
implemented soundly; it is distinct from a timeout.

## Historical Benchmark Checkpoints

The results below remain useful as exact-corpus opportunity evidence. They are
not general soundness evidence because the measured binaries predate the
Boolean-data repair.

On 2026-07-08, with Z3 4.16.0 installed via Homebrew, `euf-viper` beat Z3 on
three generated conjunction-heavy canaries after warm-up.  It also proved an
equational-diamond `or` fixture unsat via common branch consequences.  The raw
interpretation is recorded in
`research-vault/06-results/2026-07-08-local-canary.md`.  This is not a global
SMT-LIB claim.

The next milestone improved the positive-`or` preprocessor.  On generated
OR-stress canaries, median local speedups over Z3 4.16.0 were 18.8x and 64.4x
on diamond instances, and 1.7x on a pruned-branch instance.  See
`research-vault/06-results/2026-07-08-or-preprocessor.md`.

The final four-solver WMI campaign `139381` ran all 7,503 SMT-LIB 2025 QF_UF
instances at two seconds. `euf-viper` solved 6,471 at a 0.0886s median, Z3
solved 6,911 at 0.1705s, cvc5 solved 6,505 at 0.2956s, and Yices2 solved 7,394
at 0.0450s. All decisive answers matched the manifest. The data supports a
faster-than-Z3 head on common solved instances, but Yices2 decisively leads the
current implementation. See the corresponding notes under
`research-vault/06-results/`.

The 60-second sharded campaign `139420`/`139421`/`139422` also completed every
solver-instance row without a wrong answer, disagreement, or execution error:

| Solver | Correct | Coverage | Median | Total time |
|---|---:|---:|---:|---:|
| euf-viper | 7,434 | 99.08% | 0.0666s | 10,082.63s |
| Z3 4.16.0 | 7,486 | 99.77% | 0.1426s | 5,024.91s |
| cvc5 1.3.4 | 7,471 | 99.57% | 0.2293s | 9,694.51s |
| Yices 2.7.0 | 7,500 | 99.96% | 0.0278s | 1,640.91s |

`euf-viper` wins 5,581/7,433 common cases against Z3 with a 1.585x geometric
speedup, but loses on tail-inclusive total time. All four solvers time out on
the same three PEQ instances. A 1,200-second continuation from a new
`euf-viper` revision retains 22,457 unchanged comparator rows, reruns all 7,503
`euf-viper` rows and 52 comparator timeouts, and writes a new immutable run.

The revision-aware 1,200-second continuation `139688`/`139689`/`139690`
completed with zero wrong answers, disagreements, or execution errors:

| Solver | Correct | Coverage | Median | Total time |
|---|---:|---:|---:|---:|
| euf-viper | 7,478 | 99.67% | 0.0910s | 50,674.22s |
| Z3 4.16.0 | 7,500 | 99.96% | 0.1426s | 11,435.55s |
| cvc5 1.3.4 | 7,491 | 99.84% | 0.2293s | 27,875.21s |
| Yices 2.7.0 | 7,503 | 100.00% | 0.0278s | 2,652.64s |

On 7,478 common `euf-viper`/Z3 solves, `euf-viper` has a 1.069x geometric
speedup but loses common aggregate time 20,668.55s to 5,365.05s. Yices covers
all 25 `euf-viper` gaps and is fastest on 6,821/7,503 instances. The comparator
totals combine retained successful 60-second rows with rerun timeout rows; all
`euf-viper` rows were newly measured at revision `1f68ff1`.

### Opt-In Structural Portfolio

`portfolio` uses a frozen depth-3 lexical router, runs `euf-viper` internally
for 65 structurally selected corpus cases, and execs a supplied Yices binary
otherwise. It does not inspect benchmark paths or `:status` metadata. Full
exact-source paired WMI gate `140030`/`140035` at 1,200 seconds produced:

| Metric | Direct Yices | Portfolio |
|---|---:|---:|
| Correct | 7,503 | 7,503 |
| Median | 0.0290s | 0.0334s |
| Total time | 1,241.01s | 1,186.49s |
| Pairwise wins | 6,327 | 1,176 |

The portfolio is 1.046x faster by aggregate time but 0.8788x by geometric
speed, so it is an aggregate-tail optimization rather than a per-instance
win. It depends on Yices, was trained and measured on the same corpus, and is
not an independent fastest-solver claim. `solve` remains standalone and
unchanged. Training and all rejected follow-ups are recorded in
`research-vault/06-results/2026-07-08-structural-yices-portfolio.md`.

The first controlled post-campaign optimization replaces Varisat with CaDiCaL
refinement only after Kissat returns a SAT assignment that fails EUF model
validation. Full-corpus paired job `139497` improved two-second coverage from
6,873 to 6,886 and timeout-inclusive total time by 0.34%, with zero wrong
answers or execution errors. Linux x86_64 now uses this route by default;
`EUF_VIPER_INVALID_MODEL_FALLBACK=varisat` restores the prior behavior.

The 2026-07-09 accepted iteration adds a colder, structurally gated route for
large non-finite formulas whose first Kissat model fails EUF validation. It
rebuilds root assertions directly, adds full Ackermann function and predicate
axioms, completes the equality graph with bounded sparse chordal fill, and
runs one fresh Kissat solve before the existing CaDiCaL fallback. Full-corpus
paired WMI array `141911` plus strict merge `141916` improved two-second
coverage from 6,993 to 7,002, timeout-inclusive total time by 1.0169x,
common-correct aggregate time by 1.0336x, and geometric speed by 1.0961x. All
15,006 observations completed with no wrong answer or execution error. This is
an exact A/B result against the previous binary, not a new Z3 or Yices
comparison and not yet a replacement for the 1,200-second campaign.

Five controlled hard-tail alternatives were rejected or left unimplemented:
raising the finite-domain cap solved 0/4 selected PEQ gaps, disabling finite
routing reduced 69-case tail coverage from 12 to 8, sequential at-most-one
clauses solved 0/4 selected gaps for both encodings, direct CaDiCaL solved 0/4
just as the automatic Kissat route did, and a root-level pigeonhole clique
detector found no target clique while adding measurable preprocessing. The
negative results and immutable WMI job identifiers are retained under
`research-vault/06-results/`.

## Repository Map

- `src/main.rs`: SMT-LIB parser, Boolean CNF encoder, SAT portfolio,
  congruence-closure validator, CLI, and unit tests.
- `src/model_scout.rs`, `src/quotient_csp.rs`, `src/orbit_canon.rs`,
  `src/orbit_cover.rs`, `src/forbidden_table_mdd.rs`, and
  `src/hall_certificate.rs`: test-only semantic and certificate references;
  none can alter production answers.
- `benches/`: local comparator harnesses.
- `scripts/wmi/`: WMI SLURM preflight, sync, and benchmark campaign scripts.
- `scripts/cert/`: pinned DRAT checker setup and independent certificate replay.
- `scripts/lts/`: LTS/CAS preflights and artifact checks.
- `artifacts/`: SageMath, Magma, Singular, Oscar, and Rust-adjacent
  mathematical sanity artifacts.
- `research-vault/`: Obsidian-compatible notes.
- `docs/book/`: Jupyter Book source.
- `MEMORY.md`, `JOURNAL.md`, `PLAN.md`: durable project state.

## Research Sources

- SMT-LIB QF_UF logic: https://smt-lib.org/logics-all.shtml#QF_UF
- SMT-LIB benchmark releases: https://smt-lib.org/benchmarks.shtml
- SMT-COMP tooling and benchmark selection workflow:
  https://github.com/SMT-COMP/smt-comp.github.io
- LLM2SMT QF_UF case study: https://arxiv.org/abs/2603.06931
- Congruence closure in proof-producing settings:
  https://arxiv.org/abs/1701.04391
- Small proofs from congruence closure: https://arxiv.org/abs/2209.03398
- Chordal completion for sparse transitivity constraints:
  https://arxiv.org/abs/cs/0008001
- Yices 2 architecture and performance: https://yices.csl.sri.com/papers/cav2014.pdf
- DRAT-trim proof checker: https://github.com/marijnheule/drat-trim

## Current Boundary

The evidence supports a fast-head QF_UF tier and several serious research
mechanisms, not a global superiority claim. In the latest historical
1,200-second opportunity run, the old binary solved 7,502/7,503, versus 7,500
for Z3 and 7,503 for Yices2, but Yices2 was about 4.27 times faster by full
total. That old binary has the known Boolean-data defect.

The current acceptance chain is:

- full exact repair A/B array `143700` and merge `143701`;
- sound candidate build `143747` at source
  `b39706e7243c97d3950fceef636ea56a1f8b04c6`;
- real four-solver parser metamorphics `143765` and 10,000-case optimized-path
  differential `143776`;
- same-binary direct-negated-root target A/B `143751` and profile `143758`;
- fixed full four-solver 2-second array `143752` and merge `143753`.

The leading differentiated opportunity is a verified quotient of 5,040
forbidden degree-seven operation tables that form one exact `S_7` conjugacy
orbit. Orbit, MDD, quotient-CSP, and Hall mechanisms remain test-only until
their source-level preconditions and certificates are independently replayed.
