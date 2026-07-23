# Representative Triad Top-Four Local Report

Date: 2026-07-22

Status: complete local diagnostic; not corpus evidence.

## Bound evidence

- Summary: `2026-07-22-representative-triad-top4-local.json`, SHA-256
  `7614b84657f8fb38cf5d8b6bfafb26a0703a8783d693fec014e1d4dd20f75ec0`.
- Raw CSV: `2026-07-22-representative-triad-top4-local.csv`, SHA-256
  `245fd1586fed016977be1cc6431d79e0fd963fc018b183c4abfbdb2e1b3da167`.
- Three-case manifest: `2026-07-22-representative-triad.local.jsonl`, SHA-256
  `c618918689a1bcd257662f27f8f2163768d994739b854c1a1a5ca74c29795a50`.
- Explicit-selection report:
  `2026-07-22-representative-triad.local.selection.json`, SHA-256
  `3c778bcab7bb7da96eb4fde598ef7bb53507041cafa29f05cbdf649b053969a9`.

The run used parser-inclusive subprocess wall time on one Darwin 25 arm64
MacBook Air, a five-second per-run timeout, and four balanced Williams
first-order carryover repeats. Four arms over three paths produced 48 measured
runs. CPU affinity was not fixed.

`viper-structural` used conflict limit `1000000`, CaDiCaL mode `unsat-safe`,
search mode `balanced`, direct-negated-root auto mode, and finite-rook symmetry.
Z3, Yices2, and cvc5 had no recorded environment overrides.

## Per-path result

Times are medians of four complete repeats. Every displayed answer occurred in
all four repeats; `timeout` also means four of four repeats.

| Explicitly selected case | Expected | viper-structural | Z3 4.16.0 | Yices2 2.7.0 | cvc5 1.3.4 |
| --- | --- | ---: | ---: | ---: | ---: |
| Goel `QF_UF_frogs.2.prop1_ab_br_max.smt2` | SAT | timeout | 0.061785s | 0.016496s | 0.433974s |
| PEQ `PEQ012_size6.smt2` | UNSAT | 0.475877s | 3.049892s | 0.931155s | timeout |
| QG7 `iso_icl_nogen001.smt2` | UNSAT | 3.670762s | 0.565416s | 0.152545s | 1.340887s |

Coverage on this explicit triad was viper-structural `2/3`, Z3 `3/3`, Yices2
`3/3`, and cvc5 `2/3`. There were eight timeout runs: four viper runs on Goel
and four cvc5 runs on PEQ. There were zero wrong answers, unexpected results,
or execution errors.

The input SHA-256 values were:

- Goel: `6db2ccdeecb6e2ef248596dc6b85a3bba3da39aa5dcdde859d5c1e05916417cc`.
- PEQ: `b3ef5c792f5df9f55bddc92062262b75b3f53aeae51609cde0b301c8f973b139`.
- QG7: `6e9ea0786a672c467f853bf8964283bbdc53c2b51c41e0b0e6fc1fbd8ba34be0`.

The measured executable SHA-256 values were viper
`ab641974196a077e07503ee8b6abee0a75477ccd0c9240367e777410de6dda59`,
Z3 `537a502af2f4013a8e887beebe525a0dae84918a61ff545991e36dfda07ed6d7`,
Yices2 `783047ce14bfe44cfa237d217afb76ed8cd2bb22c58f37b83fec62919d7d88a0`,
and cvc5 `76677e62998e673622edc8ad2df168cb2445177ab7a336c5a25ce149bad836e1`.
External comparator provenance is detailed in
`2026-07-22-comparator-pin-local.md`.

## Interpretation boundary

Within these three cases, viper-structural was fastest on the PEQ case but
timed out on Goel. Yices2 was fastest on Goel and QG7 and solved all three; Z3
also solved all three. cvc5 solved Goel and QG7 but timed out on PEQ.

No corpus superiority follows. The triad was explicitly chosen from a
7,503-input manifest rather than sampled to estimate population performance.
Only QG7 was common-correct across all four arms, so the summary's common-set
speedups reduce to that single path. The run is local, parser-inclusive, small,
and without fixed affinity or a recorded Git revision. The viper executable
hash pins its bytes, but `host.git_revision` is `null` and therefore does not
bind those bytes to a source commit.

OpenSMT and LLM2SMT were not arms in this top-four JSON. Their version and byte
pins belong to the companion comparator note; separate LLM2SMT triad evidence
must not be merged into this run's accounting.
