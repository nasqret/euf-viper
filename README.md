# euf-viper

`euf-viper` is a Rust-first SMT solver for quantifier-free equality with
uninterpreted functions. It parses ground SMT-LIB Boolean structure, builds a
Tseitin CNF, runs an eager finite-domain/EUF encoding through SAT backends, and
validates candidate SAT models with congruence closure before accepting them.

The long-term research target is to outperform Z3 on QF_UF benchmark families.
This repository is structured so that claim can only be made after reproducible
SMT-LIB and SMT-COMP runs.

## Quick Start

```bash
cargo test
cargo run --release -- gen chain 1000 > /tmp/chain.smt2
cargo run --release -- solve --stats /tmp/chain.smt2
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
```

Expected solver output is one of:

- `sat`
- `unsat`
- `unsupported`

`unsupported` is reserved for syntax or resource boundaries that are not
implemented soundly; it is distinct from a timeout.

## Local Canary

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

The first controlled post-campaign optimization replaces Varisat with CaDiCaL
refinement only after Kissat returns a SAT assignment that fails EUF model
validation. Full-corpus paired job `139497` improved two-second coverage from
6,873 to 6,886 and timeout-inclusive total time by 0.34%, with zero wrong
answers or execution errors. Linux x86_64 now uses this route by default;
`EUF_VIPER_INVALID_MODEL_FALLBACK=varisat` restores the prior behavior.

## Repository Map

- `src/main.rs`: SMT-LIB parser, Boolean CNF encoder, SAT portfolio,
  congruence-closure validator, CLI, and unit tests.
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
- DRAT-trim proof checker: https://github.com/marijnheule/drat-trim

## Current Boundary

The evidence supports a fast-head QF_UF tier, not a global superiority claim.
The hard tail is concentrated in finite-model and pigeonhole-shaped families.
Yices 2.7.0 is in the comparator, the 60-second campaign is complete, and
certificate v1 checks the exact SAT refutation plus all EUF clauses. The
competition-budget continuation remains pending, and certificate v1 still
trusts the SMT-to-base-CNF translation.
