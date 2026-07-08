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

The full WMI campaign `139158` ran all 7,503 SMT-LIB 2025 QF_UF instances at a
two-second per-solver budget. `euf-viper` solved 6,276 with zero wrong answers,
versus 6,910 for Z3 and 6,513 for cvc5. Its median latency was lowest at
0.1126s, but its coverage and aggregate time did not beat Z3. The accepted
post-parser smoke `139229` reached 37/40, matching Z3 on that sample with a
0.0739s median. See the corresponding notes under `research-vault/06-results/`.

## Repository Map

- `src/main.rs`: SMT-LIB parser, Boolean CNF encoder, SAT portfolio,
  congruence-closure validator, CLI, and unit tests.
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

The evidence supports a fast-head QF_UF tier, not a global superiority claim.
The hard tail is concentrated in finite-model and pigeonhole-shaped families.
The next mandatory experiments add Yices 2.7.0, increase the full-corpus time
budgets, and emit independently checked UNSAT certificates.
