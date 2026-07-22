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
`9c509b0f...50a08db`. A frozen two-row smoke manifest precedes it. Direct
access through the VPN gateway IP confirmed that all SLURM controllers are up,
the read-only corpus is present under `/home`, and campaign storage is present
under `/work`. At the latest preflight all 308 CPU cores were allocated;
submission waits for a frozen published Fabric revision and will therefore
enter the ordinary queue rather than displacing existing work.

## Implementation Surface

The isolated `fabric` Cargo feature currently owns:

- semantic component decomposition and stable IDs;
- rollback equality partitions and explicit disequalities;
- rollback congruence with explicit causal antecedents;
- deterministic native CNF, watched clauses, and an implication trail;
- exhaustive reference E2 search with hard-cap abstention;
- independent SAT-model reconstruction, exhaustive UNSAT covers, and native
  UNSAT event replay;
- non-attesting corpus telemetry and WMI campaign machinery.

Incremental signature buckets, first-UIP native learning,
quotient-state/frontier memoization, theory extension definitions, repeated
semantic symmetry, bridge replay, and one-way migration remain staged work.
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
