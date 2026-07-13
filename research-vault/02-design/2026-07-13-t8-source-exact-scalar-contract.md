# T8 Source-Exact Scalar Frontier Contract

Date: 2026-07-13

Status: preregistered design; implementation blocked on prerequisites

Machine-readable contract: `campaigns/t8-scalar-frontier-census-v1.json`

## Decision

The historical right-translation exact-cover search is not the T8 UNSAT
engine. It separates one table-pattern abstraction from the rest of the source,
checks residual predicates only after an abstract witness, has no source
residual in its state, and cannot emit a complete UNSAT cover. On the frozen 12
qg7 deficits, only `001` and `003` entered that search and both rejected their
first residual source predicate; the other ten were ineligible. Its
source-exact UNSAT coverage is therefore `0/12`.

T8 M0 is instead a deterministic, scalar, no-forget typed partial-algebra
transducer. Right translations, forbidden-table MVDD nodes, and verified source
automorphisms may be checked accelerators, but none defines the semantics.

No implementation starts until:

- T1's exact typed-parser parity passes independent review;
- command-level source and auxiliary assertion lineage exists;
- corrected T4 census `146071` supplies exact checked finite ranges; and
- the frozen source populations and independent tiny oracle are hash bound.

T4 has now completed with 7,503 rows and zero parse errors. It found zero
non-uniform value-cell savings and is rejected as a Hall/PB implementation.
More importantly for T8, all 12 P12 rows report
`no_proven_non_bool_range`, empty domains, and zero range facts. T4 therefore
does not discharge T8's finite-domain prerequisite. T8 must prove the exact
domain-seven semantics in its source ledger with a separate checked certificate
or stop. T1 review, assertion lineage, and this P12 certificate all block
implementation.

The freeze is executable. `scripts/bench/validate_t8_scalar_contract.py` binds
the exact contract, strict JSON types and keys, T4 record identity, the raw P12
summary SHA-256, all 12 source paths, and every zero-range field in hosted CI.
Its successful result reports `implementation_authorized=false` and
`simd_authorized=false`; passing this freeze check cannot satisfy a prerequisite.

## Source Ledger

Each source `(assert A_i)` receives a command-level identity containing its
source ordinal, exact byte span, and raw-AST SHA-256. The ledger binds the raw
source SHA-256, declarations and definitions, parser revision/mode, checked
finite-range certificate, and the active `check-sat` command.

Every parser-generated assertion is recorded as
`Auxiliary { origin_assertion, kind, local_index }`. This is required because
term ITE elimination and materialized Boolean processing can create assertions
that are not represented by a source assertion ordinal.

Every source assertion remains an authoritative Boolean root. A specialized
transition carries an equivalence certificate and complete source-lineage set.
Operationally deduplicated exclusions retain all original ledger entries. A
case is source-complete only if every source assertion, generated auxiliary,
and live symbol is represented. Projected unused declarations receive checked
arbitrary defaults during model totalization.

The `_sk` targets contain live unary and nullary Skolem symbols. A table-only
state cannot evaluate them and must abstain.

## Authoritative State

Use a deterministic min-fill schedule over source terms, applications, atoms,
and Boolean gates. The canonical key is:

\[
(\text{layer},\ \text{live typed partition},\ \text{ghost tokens},
\ \text{function memos},\ \text{live atom/gate values},
\ \text{derived specialized summaries}).
\]

Specialized summaries may include Latin row/column masks and an exact
forbidden-suffix MVDD node, but they must be reconstructed from the
authoritative state.

- Anonymous values are renamed by typed restricted-growth order.
- M0 forgets a term ID only after its final incidence. It retains all value
  tokens and function memo entries. Optimized forgetting is forbidden until a
  separate extension lemma passes exhaustive checking.
- A permutation of named carrier constants is allowed only when a checker
  proves it is an automorphism of the complete source assertion multiset and
  current schedule prefix. Otherwise the subgroup is the identity.
- State interning hashes `(layer, serialized canonical key)` and compares full
  keys after hash matches.

## Transitions

The primitive events are:

1. `introduce-term`;
2. `introduce-application`;
3. `evaluate-source-atom`;
4. `evaluate-Boolean-gate`;
5. `forget-term` after final incidence.

For qg7, a right-translation edge may assign one complete column permutation
only as a checked macro for seven primitive table-cell transitions. Its
candidate set must partition every assignment allowed by source-derived Latin
constraints. Nested applications, Skolem values, residual disjunctions, and
all other source gates remain in the same state.

A transition prunes only with a replayable source-linked contradiction. Every
terminal state evaluates every source assertion to true. The opportunity census
constructs the complete reachable graph even for SAT cases; it does not stop at
the first witness.

## Independent Oracle And Evidence

The tiny oracle has a separate parser and evaluator and shares no lowering,
canonicalization, propagation, or state code with the producer. It enumerates
every total interpretation for domain sizes one through three under a hard
one-million-interpretation cap. The comparison is the exact hash of the set of
satisfying total interpretations, not only SAT/UNSAT.

Generated cases cover arbitrary event orders, up to eight terms, two symbols
of arity at most two, duplicate and reordered assertions, nested applications,
term ITE, Boolean-valued terms, Skolem symbols, and carrier renamings. Mutations
must expose every transition, memo, canonicalization, and forgetting defect.

SAT output contains a total interpretation for every declared symbol, an
accepting path, source/ledger/schedule hashes, and per-assertion results. UNSAT
output is a decision DAG forming a disjoint cube cover. Every split proves a
complete value or permutation partition, every leaf carries a source-linked
contradiction, and every merge carries a checked canonicalization witness. The
checker reparses the source and reconstructs transitions, branch coverage,
merge witnesses, and leaves. A capped or partial graph cannot prove UNSAT.

## State Cap And Metrics

The `1,000,000` cap counts cumulative unique reachable canonical states,
including root and accepting states but excluding immediately rejected
transitions. Attempting state `1,000,001` emits `ABSTAIN_STATE_CAP`, records the
cap layer and attempted-key hash, and discards every partial result.

Each source row records:

- source, parser, typed-IR, range, ledger, schedule, model/proof, and row hashes;
- per-layer attempted, rejected, legal, unique, accepting, and dead states and
  transitions;
- `reuse_hits = legal_successor_insertions - unique_successor_insertions`,
  reuse rate, suffix-sharing hits, and canonicalization time;
- peak and summed typed-term, Boolean, memo, table-cell, token, and serialized
  separator widths;
- attempted/legal transition cost, propagation work, gate visits, MVDD work,
  bytes per state, and peak RSS;
- parse, ledger, range check, schedule, specialization, graph build, decode,
  validation, proof build, and proof check times.

`build_ns` starts at source read and ends only after complete reachable-graph
construction. Build cost is `build_ns` divided by the pinned Yices2 end-to-end
median wall time on the same source and host.

## Frozen Populations

### P12 Deficit

The twelve exact qg7 deficits are `iso_icl_nogen` and
`iso_icl_nogen_sk` at indices `001,002,003,004,005,007`. The sorted relative
path stream SHA-256 is
`1fd24c2c5fa8eafd07a39f28c96d828e0e0aa1072fd032db413c60f34270b6fa`.
The sorted `<path><TAB><raw-source-sha256><LF>` stream SHA-256 is
`78e09b9437525c77f61014f865a5e91242a713c54d1550550903500c970753c3`.
Paths and expected statuses are evidence-only and forbidden runtime routing
features.

### Broader Structure

- `DOMAIN7_ONE_TABLE`: 261 sources, selector-manifest SHA-256
  `feaee694c894b899938494ca70b9c1641e032452e217c21233bd12e4c688fbe5`.
- `DOMAIN7_TABLE`: 431 sources, selector-manifest SHA-256
  `3c40aa2d1a6a7a2751a73af3a1b20a589f23b601644dbcc3321c85fdf723f758`.
- 12 historical SAT shadow-witness controls, source-bound TSV SHA-256
  `8a4ca8e5464abd2964788b3e151603b0e37d7c2497655a9d01de0dca0886e6be`.
- 19 historical residual-predicate abstentions, source-bound TSV SHA-256
  `1f98164da78bb7783a8dcfe1e8a1f094b0841f24b315968100d935e102c6c3f7`.

The old control outcomes are construction diagnostics only. They cannot label
new SAT/UNSAT results or authorize path-based selection.

## Gates

T8 M0 passes only if:

- all tiny-oracle satisfying-model-set hashes match and every mutation is
  rejected;
- every source and auxiliary ledger entry has complete lineage;
- at least 200 of 261 `DOMAIN7_ONE_TABLE` sources are source-complete;
- at least 10 of 12 P12 cases complete below the one-million-state cap;
- complete graph construction costs at most 10% of pinned Yices2 time on at
  least 7 of 12 P12 cases and more than half of every broader qualifying
  population;
- every SAT witness and UNSAT cube-cover DAG passes the independent checker;
- there are zero parse, hash, cap-as-UNSAT, source-lineage, model, proof,
  checker, or missing-row errors.

Only then may an isolated solver implementation run a direct end-to-end Yices2
comparison. It must reach at least `1.10x` including setup, model/proof
construction, and checking. SIMD work remains forbidden until the scalar route
passes and measured useful lane occupancy reaches 70%.

## Reuse And Rejection Boundary

Potentially reusable after review: typed `Problem`/`BoolExpr`/`TermArena`,
`quotient_csp` model totalization, `quotient_state_search` fail-closed
certificate patterns, checked `orbit_canon` permutations, `orbit_cover`
witnesses, small-degree `stabilizer_order`, and MVDD suffix hash-consing.

New code is required for the assertion ledger, source-exact bounded compiler,
complete residual state, prefix automorphism checker, state interning, decision
DAG and checker, independent tiny interpreter, and scalar census schema.

`eq_abstraction`, forbidden-orbit probes, and the old right-translation search
may donate memoization or checked accelerators only. None is an equivalent
source-state semantics or an UNSAT certificate.

Related: [[2026-07-11-sat-native-quotient-search]],
[[2026-07-11-orbit-forbidden-table-automaton]],
[[2026-07-11-tail-opportunity-atlas]], and
[[2026-07-13-unresolved-track-refresh]].
