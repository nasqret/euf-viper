# euf-viper

`euf-viper` is a Rust-first SMT verifier for the equality theory of
uninterpreted functions (EUF).  The current milestone is a deliberately strict
QF_UF ground-conjunction checker: it accepts equalities, disequalities,
`and`, `not` around atoms, `distinct`, and `let`, then runs congruence closure.
It rejects Boolean search problems as `unsupported` until the DPLL(T) layer is
implemented.

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
```

Expected solver output is one of:

- `sat`
- `unsat`
- `unsupported`

`unsupported` is an intentional correctness boundary, not a timeout.

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

The fixed WMI corpus campaign ingested the official SMT-LIB 2025 QF_UF slice
and ran a 40-instance deterministic sample against `euf-viper`, Z3, and cvc5.
Z3 and cvc5 agreed on all non-timeout results.  `euf-viper` solved one official
`eq_diamond` instance and returned `unsupported` on the other 39 sample
instances.  See
`research-vault/06-results/2026-07-08-qf-uf-corpus-wmi-139149.md`.

## Repository Map

- `src/main.rs`: SMT-LIB subset parser, term arena, congruence closure engine,
  CLI, and unit tests.
- `benches/`: local comparator harnesses.
- `scripts/wmi/`: WMI SLURM preflight, sync, and benchmark campaign scripts.
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

## Current Boundary

This is not yet a full SMT solver.  It is a fast EUF verifier for conjunctions
of ground literals.  The next performance jump is a DPLL(T) layer with cheap
preprocessing for disjunctive benchmark families such as equational diamonds.
