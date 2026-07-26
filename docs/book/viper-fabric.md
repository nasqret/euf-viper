# Viper Fabric

Viper Fabric is the default-off research architecture for replacing one global
QF_UF proof system with a proof-reconfigurable semantic solver. Stable typed
components may use sparse eager SAT, rollback congruence closure, native
canonical partition CDCL, or canonical quotient-frontier search. Components
exchange only independently replayable bridge clauses.

The complete design and stop rules are in the
[`Viper Fabric execution contract`](https://github.com/nasqret/euf-viper/blob/main/research-vault/02-design/2026-07-22-viper-fabric-execution-contract.md).
The exact E2 assignment, propagation, learning, and answer invariants are in
the [`E2 state-machine contract`](https://github.com/nasqret/euf-viper/blob/main/research-vault/02-design/2026-07-22-e2-state-machine.md).
The machine-readable contract is
[`viper-fabric-2026-07.json`](../../campaigns/viper-fabric-2026-07.json).
The bounded closest-prior-art audit and mechanism-specific falsifiers are in
the [`novelty-boundary ledger`](https://github.com/nasqret/euf-viper/blob/main/research-vault/01-literature/2026-07-22-viper-fabric-novelty-boundaries.md).
The Dsat prior-art boundary and the gated dynamic-domain experiment are in
[`the Dsat boundary`](https://github.com/nasqret/euf-viper/blob/main/research-vault/01-literature/2026-07-22-dsat-partition-boundary.md)
and [`the E2 domain-watch contract`](https://github.com/nasqret/euf-viper/blob/main/research-vault/02-design/2026-07-22-e2-domain-watch-experiment.md).

## Current Checkpoint

The implemented default-off substrate contains stable term, atom, and
component IDs; deterministic semantic projection and native definitional CNF;
native watched clauses; a reasoned implication trail; rollback equality and
disequality state; and a correctness-first rollback congruence engine. The
reference E2 search reads source equalities from the live partition, applies
the exact two-value Boolean domain, and exhaustively closes both alternatives
of every unresolved action under explicit work caps.

Every internal SAT leaf is reconstructed by a second implementation which
shares no partition or congruence operations with the search engine. It checks
typed classes, observed function tables, Boolean values, root literals, and
the source formula. Reference UNSAT is accepted only after a separate checker
enumerates a canonical binary cover of every source-atom assignment and the
model checker rejects every complete leaf. The default reference cover is
intentionally capped at 18 atoms; larger conflicts abstain until compact proof
production is connected. A separate `fabric-native-v1` event checker
independently replays equality, congruence, native-unit, conflict, and
UNSAT-root events. Neither reference result path is connected to the public
solve command.

The continuation branch adds canonical existing-class-or-fresh actions and a
rollback application-signature index. Binary and canonical branching agree
with all 676 formulas in the three-term five-partition oracle. They each visit
1,422 search nodes on that easy panel; on the complete five-partition UNSAT
blocker the canonical reference visits eight nodes versus seven for binary
branching. Canonical enumeration alone therefore has no performance credit.
The signature backend and watched propagation now have an impact-driven
integration arm: a stable CSR index maps changed quotient terms to source
atoms, while an all-atom test oracle checks every synchronized state. Stable
theory reason clauses cover congruence equalities and endpoint-aligned
disequalities. First-UIP and partition-level learning still must earn their own
gates; a pre-merge frozen domain-proof repair is active before either can be
enabled.

The only feature-gated command is `fabric-shadow`. It emits structural and
timing telemetry but cannot emit `sat` or `unsat`. The strict corpus runner
binds every manifest, input, and solver hash; rejects malformed output and
timeouts; resumes only an exact prefix; and publishes one atomic summary. The
WMI wrapper additionally requires a clean public revision, pinned Rust/Python
executables, one allocated CPU, read-only corpus access, and `/work`-resident
build and result paths.

The F0 campaign is frozen in
[`viper-fabric-f0-shadow-v1.json`](../../campaigns/viper-fabric-f0-shadow-v1.json).
Its full corpus is exactly 7,503 rows with manifest SHA-256
`9c509b0f...50a08db`. A frozen two-row smoke manifest precedes it. The exact
reference revision
`51fc7d31a0e499fc9ffc4c30bf9227e6b8c0fdcc` is published on
`perf-viper-fabric` and passed hosted run `29881100724`. Direct access
through the VPN gateway IP confirmed that all SLURM controllers are up, the
read-only corpus is present under `/home`, and campaign storage is present
under `/work`. The two-row smoke WMI job `169653` completed `0:0` on
2026-07-24. Its fetched six-file bundle and original submission receipt passed
the independent offline audit: two complete rows, no errors or duplicates,
exact revision/tool/input bindings, and zero solver-result claims. The full
7,503-row non-attesting shadow is now authorized but remains unsubmitted.

## Source-Structural Quotient-JIT Tier

The continuation branch now exposes a default-off `quotient-portfolio` arm
which selects finite mechanisms from the parsed formula, never from benchmark
identity. A formula enters the general finite tier only after the analyzer has
proved a complete finite closure and bounded the eager encoding. The current
limits are domain size at most 11 and at most 200,000 estimated one-hot
clauses. Formulas with Boolean-valued applications additionally require at
most 16,384 such applications and at most 100,000 application-value channel
pairs.

The key recovered technique is dual support for a verified injection. Suppose
terms $x_1,\ldots,x_n$ each range over the same finite domain
$D=\{d_1,\ldots,d_n\}$ and are pairwise distinct. The ordinary one-hot rows
state

$$
\bigvee_{j=1}^n (x_i=d_j)
\quad\text{and}\quad
\neg(x_i=d_j)\lor\neg(x_i=d_k) \quad (j\ne k).
$$

Injectivity and $|\{x_i\}|=|D|$ imply surjectivity, so the solver may also add
the checked column clauses

$$
\bigvee_{i=1}^n (x_i=d_j), \qquad j=1,\ldots,n.
$$

These clauses do not remove models; they expose Hall-style reasoning to the
SAT backend. On `SEQ009_size10`, five paired runs moved from about 2.41 seconds
without the clauses to 0.013 seconds with focused support, approximately
`184x`, and closed the final SEQ timeout.

The two-second local family scorecards are:

| Family | Viper | Yices2 | Z3 | cvc5 |
| --- | ---: | ---: | ---: | ---: |
| PEQ | 44/47 | 40/47 | 34/47 | 28/47 |
| SEQ | 56/56 | 56/56 | 51/56 | 46/56 |
| NEQ | 48/48 | 44/48 | 41/48 | 39/48 |

Viper is faster on common NEQ solves by `2.948x` aggregate over Yices2,
`3.753x` over Z3, and `6.388x` over cvc5. It still loses common-case aggregate
timing to Yices2 on PEQ and SEQ, and its frozen Goel canary is only `0.286x`
as fast as Yices2. Therefore this is a finite-family tier result, not evidence
that Viper is the overall QF_UF leader. The exact ledgers and causal controls
are indexed in
[`the finite-family campaign note`](https://github.com/nasqret/euf-viper/blob/main/research-vault/06-results/2026-07-26-quotient-jit-finite-family-campaign.md).

## Family-Disjoint PGO Experiment

Profile-guided optimization is isolated as a build experiment. It does not
alter the solver algorithm and cannot establish novelty by itself. The test is
whether a profile learned without any Goel source improves an untouched Goel
holdout while preserving exact answers and coverage.

The deterministic splitter selects 101 official sources from seven non-Goel
families, with at most 16 per family and a 2 MB source cap. All 302 official
Goel sources are held out. The builder verifies source bytes and hashes, uses
separate profile-generation and profile-use targets, pins the matching LLVM
profile merger, and records every resulting artifact. Training `unknown` is
permitted only by an explicit option and must be replayed exactly by the
optimized binary; it never receives solve credit.

The WMI design compares standard Viper, PGO Viper, Z3, Yices2, and cvc5 in one
complete cold-process Williams block on one CPU. The two Viper arms use the
same explicitly recorded ten-setting Fabric configuration. A completion
receipt is emitted only after checking the split, clean revision, tool and
binary hashes, environment maps, row completeness, wrong answers, and process
errors. The full protocol and promotion boundary are in the
[`family-disjoint PGO campaign`](https://github.com/nasqret/euf-viper/blob/main/research-vault/02-design/2026-07-23-family-disjoint-pgo-campaign.md).
The machine-readable contract is
[`viper-pgo-goel-holdout-v1.json`](../../campaigns/viper-pgo-goel-holdout-v1.json).

The campaign also runs a frozen adjudicator before publishing its completion
receipt. It requires no coverage or timeout regression, aggregate and geometric
point wins, 99% paired instance-bootstrap lower bounds above one, and a p95
slowdown no greater than `1.05x`. The decision is recorded as `promote` or
`reject`; thresholds are not chosen after observing the holdout.

A local plumbing smoke successfully profiled and replayed an `unknown` result,
but it was built from a dirty worktree and used an incompatible Apple LLVM 17
fallback with Rust LLVM 21.1.8. The builder now rejects such a mismatch before
compilation. The F0 prerequisite is complete, but no WMI PGO holdout result
exists yet. This experiment therefore does not change the current comparison
with Yices2 or Z3.

## Implementation Surface

The isolated `fabric` Cargo feature currently owns:

- semantic component decomposition and stable IDs;
- rollback equality partitions and explicit disequalities;
- rollback congruence with explicit causal antecedents;
- deterministic native CNF, watched clauses, and an implication trail;
- exhaustive binary and canonical-action E2 search with hard-cap abstention;
- deterministic rollback application signatures with reverse argument uses
  and exact collision deltas;
- impact-driven source-atom scheduling with a full-state differential oracle;
- canonical append-only theory reasons over stable source literals;
- an isolated finite-domain quotient-action nogood and certificate checker;
- independent SAT-model reconstruction, exhaustive UNSAT covers, and native
  UNSAT event replay;
- non-attesting corpus telemetry and WMI campaign machinery.

Integration of signature buckets into congruence, first-UIP native learning,
dynamic quotient-domain watches, quotient-state/frontier memoization, theory
extension definitions, repeated semantic symmetry, bridge replay, and one-way
migration remain staged work.
They are not implied by the presence of their architecture contracts.

Ordinary builds do not include the module. Tests compile it so each primitive
can mature without changing the measured production route.

E3 is the strongest open algorithmic bet and X1 is the cheapest opportunity
census. E2 remains experimental until every learned object is invariant under
class relabeling. X2 must be compared directly with SORB. X3 migration remains
forbidden because the measured fixed-arm oracle headroom is 3.74%, below the
10% prerequisite.

## Promotion Boundary

Every mechanism moves through exhaustive tests, generated differential tests,
target ABBA, anti-target controls, hot-400, full 7,503-instance runs on two CPU
classes, the official 3,521-instance selection, and a sealed holdout. No
mechanism is composed or enabled by default without an isolated decision packet
and user approval.

The final release must solve at least 7,446/7,501/7,503 full-corpus instances at
2/60/1,200 seconds and 3,491/3,519/3,521 official instances, while beating every
comparator by at least 1.05x on common geometric, common aggregate, and
timeout-charged time. Every SAT model and UNSAT proof must pass an independent
checker.

This checkpoint is not evidence that Viper Fabric beats Yices2, Z3, cvc5, or
OpenSMT. The current audited production solver still trails Yices2 in coverage
and common timing. A competitive claim starts only after a fixed E2/E3 binary
passes independent answer checking and the registered paired campaigns.
