# Project Memory

## 2026-07-08 Bootstrap

- Workspace started empty at `/Users/airbartek/codex/z3`; it was not a Z3
  checkout.
- WMI preflight succeeded through `wmicluster`; VPN route used `utun21`,
  SLURM controllers were up, and CPU/GPU nodes were visible.
- Two unrelated WMI jobs were already running: `139140` and `139142`, both named
  `sg-c-lean-targets`.
- Local Rust toolchain exists: `rustc 1.96.0`, `cargo 1.96.0`.
- Local `z3` binary was not found.
- Default WMI login shell did not expose `z3`, `cargo`, or `rustc`.
- Default LTS login shell exposed `/usr/bin/julia` but not Magma, Sage,
  Singular, Z3, Cargo, or Rust through `command -v`.
- GitHub CLI auth was valid for account `nasqret` with repo scope.
- Installed local Z3 4.16.0 via Homebrew to enable comparator checks.

## Design Decisions

- First solver milestone is a strict EUF ground-conjunction verifier, not a
  full Boolean SMT solver.
- Unsupported Boolean structures are reported as `unsupported` instead of being
  approximated.
- The first Rust implementation has no external crate dependencies so it can
  build in restricted cluster environments once Rust is available.
- Z3 superiority claims are blocked until a reproducible benchmark campaign is
  completed.

## Local Canary Results

- Warm rerun synthetic canaries:
  - `generated/synthetic/chain1000_sat.smt2`: `euf-viper` 0.0029s, Z3
    0.0064s.
  - `generated/synthetic/chain1000_unsat.smt2`: `euf-viper` 0.0030s, Z3
    0.0062s.
  - `generated/synthetic/grid1000x8_unsat.smt2`: `euf-viper` 0.0033s, Z3
    0.0057s.
- `tests/fixtures/eq_diamond_unsat.smt2` proves the safe common-branch
  consequence preprocessor can return `unsat` on a positive `or` case.
- These are narrow canaries, not global SMT-LIB evidence.

## OR Preprocessor Improvement

- Branch-aware positive `or` preprocessing now tracks both equalities and
  disequalities per branch.
- Same-level `and` processing delays positive `or` analysis until surrounding
  non-`or` literals have been collected.
- New generators:
  - `euf-viper gen diamond BRANCHES DEPTH`
  - `euf-viper gen pruned-or BRANCHES`
  - `euf-viper bench-or --cases N --branches N --depth N`
- Local median comparison against Z3 4.16.0:
  - `diamond_b128_d8_unsat.smt2`: 18.8x faster.
  - `diamond_b512_d4_unsat.smt2`: 64.4x faster.
  - `pruned_or_b512_unsat.smt2`: 1.7x faster.
- A larger local single point, `diamond 2048 4`, solved in about 0.01s by
  `euf-viper` and about 5.10s by Z3.

## WMI Runs

- Job `139145` completed on WMI `cpu_idle` node `c3n1` in 10s with MaxRSS
  `479492K`; 40 synthetic cases, 600380 total terms, benchmark wall time
  2.895389861s. The submit script initially failed to forward local
  `EUF_VIPER_CASES` and `EUF_VIPER_SIZE`; fixed after the run.
- Job `139146` completed on WMI `cpu_idle` node `c3n1` in 14s; OR bench used
  8 cases, branches 1024, depth 4, total terms 24584, wall time 217220141ns.
- Job `139149` completed the fixed QF_UF corpus campaign on WMI in 1:56 with
  MaxRSS `2338356K`; official SMT-LIB 2025 QF_UF corpus ingested as 7503 files,
  deterministic 40-instance sample run with `euf-viper`, Z3Py 4.16.0, and cvc5
  1.3.4. No Z3/cvc5 mismatches; `euf-viper` solved 1 eq-diamond instance and
  returned `unsupported` on 39 Boolean-heavy instances.

## Benchmark Corpus

- Official source: SMT-LIB release 2025 non-incremental benchmark record
  `10.5281/zenodo.16740866`.
- QF_UF archive: `QF_UF.tar.zst`, size `54182823`, MD5
  `e185bc80a80116bcfea116df190f87d2`.
- Local and WMI ingestion found 7503 `QF_UF` SMT2 files: 4361 `unsat`, 3142
  `sat`.
- Downloaded corpora and manifests are ignored under `benchmarks/smtlib-2025/`
  because manifests contain machine-local absolute paths.

## Solvers

- Local cvc5 Homebrew formula was unavailable; installed official cvc5 1.3.4
  macOS arm64 static release under ignored `third_party/solvers`.
- WMI cvc5 uses official cvc5 1.3.4 Linux x86_64 static release.
- WMI Z3 uses Python `z3-solver 4.16.0.0` wrapper because WMI glibc is 2.35
  and official Z3 4.16.0 Linux CLI binary requires glibc 2.39.

## LTS/Magma

- LTS has Magma at `/opt/magma/V2.28-3/magma`; use `magma -n` to bypass the
  user startup file because home-directory logging hit quota.
- `scripts/lts/run_magma_remote.sh` ran `artifacts/magma/euf_quotient.m`
  successfully from `/tmp/$USER/euf-viper-cas`.

## Literature Pointers

- SMT-LIB QF_UF permits closed quantifier-free formulas over Core with free
  sort and function symbols.
- LLM2SMT reports that a QF_UF solver using Nieuwenhuis-Oliveras congruence
  closure plus preprocessing was competitive but still behind Z3 on solved
  instances in their 2026 experiment.
- The equational diamond family is a key DPLL(T) stressor; common-branch EUF
  consequences are a high-priority preprocessor target.
