# qg6 Dense-Six CaDiCaL Route

Date: 2026-07-26

Decision: local A0-A2 pass; Helios A3/A4 pending

## Mechanism

The candidate changes only SAT-backend search policy after the existing finite
analysis proves all of the following semantic signature:

- finite carrier size exactly 6;
- no Boolean-valued applications;
- at least 200 explicit disequality-graph edges; and
- no guarded disequality clauses.

The route selects CaDiCaL's `Unsat` configuration while preserving Viper's
existing `sweep=0` and `inprobing=0` safety restrictions. It does not inspect a
benchmark path, family name, source ID, or expected status. The environment
switch `EUF_VIPER_FINITE_DENSE6_CADICAL=0` restores the previous route.

## Opportunity And Controls

The complete qg6 census covers 244/244 sources with no analysis failures. All
244 have carrier size 6, zero Boolean applications, zero guarded disequality
clauses, and 201-232 disequality edges. The complete `loops6` control has the
same carrier size and Boolean/guarded counts but exactly 195 disequality edges,
so all 448 controls remain outside the route. The 47-source PEQ control also
remains outside because its edge counts are 4-66; 40 rows additionally contain
guarded disequalities.

The checked portable qg6 manifest contains 244 canonical sources: 122 SAT and
122 UNSAT. It revalidates each source's size, SHA-256, logic, and declared
status before publication.

## Same-Binary ABBA

The local arm64 discovery run used one release binary with SHA-256
`372b69ea75d64578753748202b739bad5a9465092a66f3b77f0259cf062582fc`.
The only arm difference was:

- baseline: `EUF_VIPER_FINITE_DENSE6_CADICAL=0`;
- candidate: `EUF_VIPER_FINITE_DENSE6_CADICAL=1`.

At a 2 s timeout, one cold repetition, and zero warmups:

| Metric | Route off | Route on | Delta/factor |
| --- | ---: | ---: | ---: |
| Correct coverage | 192/244 | 244/244 | +52 |
| Wrong answers | 0 | 0 | 0 |
| Execution errors | 0 | 0 | 0 |
| Common-total speed | - | - | `1.89734x` |
| Common-geometric speed | - | - | `1.20616x` |
| SAT common-total speed | - | - | `1.19440x` |
| SAT common-geometric speed | - | - | `1.03637x` |
| UNSAT common-total speed | - | - | `2.26530x` |
| UNSAT common-geometric speed | - | - | `1.57125x` |

A separate backend-isolation profile compared the previous finite Kissat arm
with CaDiCaL `Unsat`: coverage changed from 221/244 to 244/244, common-total
speed was `3.69060x`, and common-geometric speed was `3.35360x`. This supports
the backend hypothesis but is not the promotion experiment; the same-binary
off/on run above is the behavioral evidence.

## Broad-Score Boundary

The current audited Helios baseline, before this change, solves 223/244 qg6
sources and 7,436/7,503 sources overall at 2 s. Yices2 solves 244/244 qg6 and
7,490/7,503 overall; Z3 default solves 7,446 and Z3 `sat.euf=true` solves
7,459. If, and only if, the new route converts all 21 Helios qg6 timeouts
without regressions, Viper would project to 7,457 solves: 11 ahead of Z3
default, 2 behind Z3 `sat.euf=true`, and 33 behind Yices2. This projection is
not dashboard evidence and must not be reported as achieved coverage.

Promotion requires the exact all-solver Helios campaign, complete validity
accounting, family/status panels, and broad PAR-2/common-time deltas. The local
run has one repetition on a different CPU architecture and therefore cannot
establish robustness or a broad lead.

## Artifacts

| Artifact | SHA-256 |
| --- | --- |
| `benchmarks/novelty-tail/qg6-full.jsonl` | `508cc1f8ccd298843559df18fe3e64c8971026f9d080802431b75c566b6f0132` |
| `benchmarks/novelty-tail/qg6-full.selection.json` | `fe0db746073828daa0e063fc1a2a48da08c187de5550707ac0a4529b1b2bf533` |
| `2026-07-26-qg6-dense6-cadical-abba-local.csv` | `ae1d2d46f29812b84dc558332356ea1d92d6d3425423c2dcd7959695ef886cf9` |
| `2026-07-26-qg6-dense6-cadical-abba-local.json` | `14a075cd544006cc5ebd2b8738335a3e5b3f8fe543bfe9770b23914af15c67fa` |
| `2026-07-26-qg6-kissat-vs-cadical-unsat-local.csv` | `83b93c6751dbee48e0ed5ba5fa322afbdde600c1021059d43fc02dabc0454f05` |
| `2026-07-26-qg6-kissat-vs-cadical-unsat-local.json` | `1d55fae0932dc05b86cd99d706cacc86a4cf25f55a8161278e4ff3f86b954b47` |
| `2026-07-26-qg6-finite-structure-census.json` | `8d2b39cdfa78e3b918a38d4d85436af260908ed27d0b962ce4de3dad04090e90` |
| `2026-07-26-loops6-finite-structure-census.json` | `760b75e25560e8d8e990139f8362d9622e4e15c25827def8912acc029ef77515` |
| `2026-07-26-peq-finite-structure-census.json` | `f0776bafee5f5a41d56620063c195eb5239bc009fca71f1a645b5557a8849241` |
