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

- The current solver supports arbitrary ground Boolean QF_UF structure through
  Tseitin CNF plus SAT backends. Unsupported syntax is still reported rather
  than approximated.
- UNSAT from a sound eager encoding is accepted; SAT assignments are checked
  with full EUF congruence closure, and invalid assignments trigger lazy
  theory-lemma refinement. This is the core soundness boundary.
- Linux uses a namespaced Kissat 0.1 backend because Kissat 4 was slower on the
  measured WMI hard tail. CaDiCaL and Varisat remain available as alternate
  routes.
- On Linux x86_64, an eager Kissat SAT assignment that fails full EUF model
  validation now falls back to incremental CaDiCaL refinement. Full-corpus A/B
  job `139497` improved coverage by 13 and timeout-inclusive total time by
  0.34%. `EUF_VIPER_INVALID_MODEL_FALLBACK=varisat` is the rollback control.
- Finite predicate-table channeling is retained behind environment flags but is
  not enabled by default because WMI jobs `139240` and `139242` showed no hard
  tail gain.
- Z3 superiority claims are blocked until a reproducible benchmark campaign is
  completed.
- Long-timeout campaigns use a prepare job, bounded-concurrency SLURM array,
  and dependent merge job. The prepare job creates
  `qf_uf_campaign_<run-id>.jsonl`; every shard and the merge read that exact
  manifest. The merge must see one row per manifest-path and solver pair.
- Certificate format `euf-viper-euf-cnf-v1` links source, DIMACS, and ASCII DRAT
  files by SHA-256. The Python checker invokes independent `drat-trim` and
  validates each non-base clause by an EUF congruence replay. Format v1 does
  not include finite-domain axioms and still trusts the SMT-to-base-CNF encoder.
- Certificate code is behind the non-default `certificates` Cargo feature. The
  default release text section is byte-identical to pre-certificate commit
  `0bb34c2`, preserving the measured solver executable path.
- Official-corpus certificate smoke passed on Rodin
  `smt3166111930664231918` and TypeSafe `z3.1184163`; the latter required one
  replayed EUF clause. Both exact DIMACS files and DRAT traces were accepted by
  the independent checker.

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
- Job `139158` completed all 7,503 official instances at two seconds per solver.
  `euf-viper` solved 6,276 (83.65%), Z3 solved 6,910 (92.10%), and cvc5 solved
  6,513 (86.81%); all three had zero wrong answers. `euf-viper` median latency
  was 0.1126s versus Z3's 0.1676s and cvc5's 0.2939s.
- Job `139229` is the accepted post-parser finite-domain smoke checkpoint:
  37/40 correct, matching Z3 coverage on that sample, with 1.0848x aggregate
  speedup over `139211` on common correct instances.
- Job `139375` confirms the accepted platform split still builds and solves on
  Linux after rejecting the Kissat 4 experiment.
- Job `139381` is the first full four-solver, two-second campaign after adding
  pinned Yices 2.7.0. Final coverage: `euf-viper` 6,471, Z3 6,911, cvc5 6,505,
  Yices2 7,394; medians were 0.0886s, 0.1705s, 0.2956s, and 0.0450s
  respectively. There were no wrong answers or solver disagreements.
- Jobs `139382` through `139384` validate the sharded prepare-array-merge chain
  on eight sampled instances with four solvers and strict completeness checks.
- Jobs `139420` through `139422` completed the full 7,503-instance corpus at 60
  seconds with 64 shards and four active allocations. Coverage was 7,434 for
  `euf-viper`, 7,486 for Z3, 7,471 for cvc5, and 7,500 for Yices2, with no wrong
  answers, disagreements, or execution errors. The complete prepare-to-merge
  wall interval was 26m35s and peak shard MaxRSS was 5,413,416 KiB.
- Jobs `139433`, `139477`, and `139497`/`139498` form the accepted invalid-model
  fallback gate. The affected profile improved 2.36x, the 40-case control kept
  39/40 coverage, and the full paired corpus improved 6,873 to 6,886 correct
  with 1.0034x timeout-inclusive aggregate speed and no wrong answers.

## Research Position

- Current evidence supports a fast-head portfolio tier, not a general claim of
  being a better SMT solver than Z3.
- Yices2 decisively dominates the current implementation at two seconds: it
  wins 6,166 of 6,463 jointly correct instances and has 98.55% coverage. The
  research target is now a specialized certifying front tier or a structural
  portfolio contribution, not an overall fastest-QF_UF claim.
- The unresolved tail is concentrated in finite-model, pigeonhole-shaped
  families where one-hot CNF encounters hard resolution proofs.
- The 60-second run leaves 69 `euf-viper`, 17 Z3, 32 cvc5, and 3 Yices2
  timeouts. The all-solver oracle covers 7,500/7,503; `PEQ014_size10`,
  `PEQ014_size11`, and `PEQ018_size7` are the shared UNSAT gaps.
- The next mandatory experiment is the 1,200-second continuation. If the
  `euf-viper` revision changes, it must retain only 22,457 unchanged comparator
  rows, rerun all 7,503 `euf-viper` rows plus 52 comparator timeouts, and write
  new outputs. Reusing old solver timings across revisions is forbidden.
- Certificate work should pair SAT proof traces for the exact emitted CNF with
  a replayable manifest of EUF-derived clauses and finite-domain axioms.

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
- WMI Yices uses official Yices 2.7.0 Linux x86_64 static-GMP release, SHA-256
  `49566b6f817692820538df78fe406878400d79810631c9372b2495bc81d3e00a`.
  Four-solver smoke job `139380` passed. The official Apple arm64 asset links
  to `/usr/local/lib/libcudd-3.0.0.0.dylib`; local setup omits Yices with a
  warning when that dylib is unavailable.

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
