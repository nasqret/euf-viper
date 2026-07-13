# Current Campaign

Date: 2026-07-13

This chapter is the current evidence checkpoint. Older chapters preserve exact
historical campaigns and may describe earlier binaries. The authoritative
machine-readable experiment contract is
[`campaigns/best-overall-qf-uf-2026-07.json`](../../campaigns/best-overall-qf-uf-2026-07.json),
and the ordered execution state is maintained in
[`PLAN.md`](https://github.com/nasqret/euf-viper/blob/main/PLAN.md).

```{admonition} Result
:class: warning
Euf-viper is not yet better overall than Z3 or Yices2. It has a strong
common-instance fast head against Z3, but lower coverage and expensive tail
instances dominate aggregate time. Every completed full/official promotion
audit at two and 60 seconds rejects.
```

## Frozen Baseline

The authoritative baseline uses solver revision
`30828a4f0c1e7e478a9c6f406ccb245eeefc4961` and WMI jobs
`144990`/`144991`/`144992`/`144993`. Parent locks bind the full 7,503-source
SMT-LIB 2025 QF_UF library and exact 3,521-source SMT-COMP selection, all source
hashes, six solver configurations, CPU/resource controls, and every child row.

| Solver configuration | Full 2s / 7,503 | Official 2s / 3,521 | Full 60s / 7,503 | Official 60s / 3,521 |
| --- | ---: | ---: | ---: | ---: |
| euf-viper | 7,269 | 3,400 | 7,480 | 3,508 |
| cvc5 | 7,222 | 3,384 | 7,479 | 3,510 |
| OpenSMT | 6,916 | 3,215 | 7,448 | 3,497 |
| Yices2 | 7,445 | 3,490 | 7,500 | 3,518 |
| Z3 default | 7,412 | 3,474 | 7,489 | 3,514 |
| Z3 `sat.euf=true` | 7,395 | 3,469 | 7,484 | 3,511 |

Correctness and coverage are lexicographically prior to timing. On the set
$C$ solved correctly by a baseline $b$ and candidate $c$, paired geometric
speed is

$$
G(b,c)=\exp\left(\frac{1}{|C|}\sum_{i\in C}
\log\frac{t_{b,i}}{t_{c,i}}\right).
$$

At 60 seconds, $G(\mathrm{Z3},\mathrm{viper})$ is `1.5685` on the full corpus
and `1.5214` on the official set. Those numbers describe the typical common
instance. The corresponding ratios of summed common wall time are only
`0.5873` and `0.6146`, so Z3 remains better on aggregate. Against Yices2, the
geometric ratios are `0.4910` and `0.4710`; Yices2 is both faster and more
complete. A ratio above one favors euf-viper.

The full 60-second pairwise boundary is exact. Z3 default and Yices2 both solve
22 instances that euf-viper misses: nine Goel cases, `PEQ012_size6`, and twelve
`qg7` isomorphism cases. Euf-viper has 13 Z3-only solves but only two
Yices-only solves. With no regression it needs ten new solves to lead Z3 and
21 to lead Yices. On the Yices common set, parity also requires approximately
`2.04x` broad geometric and `4.89x` aggregate improvement. The post-fix full
60-second audit SHA-256 is
`2458b01872a290c89f715a277dfd41e2c28091fc649925c9acbfefeb6e72686a`.

## Evidence Boundary

The independent Python checker reconstructs typed source terms, theory atoms,
canonical base Tseitin CNF, EUF lemmas, SAT assignments, and DRAT validation.
The hardened two-second shadow campaigns are:

| Scope | Prepare | Array | Audit | Dependency |
| --- | ---: | ---: | ---: | --- |
| Full | `146076` | `146077` | `146078` | corrected source census `146071` |
| Official | `146079` | `146080` | `146081` | corrected source census `146071` |

The first source dependency `145883` wrote all 7,503 rows but terminated
nonzero because 17 deeply nested NEQ `let` chains exceeded the independent
Python parser's expression recursion limit. Its certificate dependents were
cancelled. Commits `6b51b39` and `8f78543` replace recursive `let` expansion
with an iterative, simultaneous-scope-preserving machine and pin a four-hour
wall limit. Corrected census `146071` runs at exact revision `8f78543`; no T4
decision or certificate evidence follows until its zero-error aggregate
returns.

These replacement campaigns can establish that each reported source result has
an independently checked canonical witness or refutation. They do **not** yet
prove
that the literal timed production invocation emitted that same model, proof, or
CNF trace. Production promotion therefore also requires an atomic sidecar that
binds source hash, solver revision/configuration, returned status, actual model
or proof bytes, and evidence hash to the timed row. A later rerun is not a
substitute for this binding.

Research schema v1 at `6095e29` failed adversarial review. The independent
checker accepted assignments whose auxiliary values falsified the production
CNF, an empty atom map, dirty standalone builds, and incoherent statuses. The
source and sidecar paths also had hash/parse TOCTOU windows, and resume could
declare completion after a sidecar was deleted. Schema v2 repair must bind the
exact clause stream, complete variable map, trusted executable hash, same-byte
parsing, and resume-time evidence rechecks before integration.

## Causal Controls

### Modern Kissat

The valid 64-case SC2021-versus-Kissat-4 sample is job `145905`. Both backends
solve 53 cases with zero wrong answers or execution errors. Kissat 4 wins 16
paired instances and loses 37. With SC2021/Kissat-4 orientation, geometric
speed is `0.928694`, common-total speed is `0.963416`, median speed is
`0.973994`, and sign-flip $p=0.999500$. Broad job `145906` and merge `145907`
were dependency-cancelled. Wholesale Kissat 4 replacement is rejected; an
individual inprocessing pass requires a new one-factor control.

### Rollback EUF

The explicit `cadical-rollback` backend is an engineering control, not a
novelty claim. It loads only base Boolean CNF, receives no external decisions or
propagations, emits independently replayed typed conflict clauses, validates
the final model, and fails closed as `unsupported`.

The first path-correct WMI run exposed a callback-boundary bug: a pending clause
was marked emitted before CaDiCaL requested it. Commit `01be0a9` moves
deduplication and telemetry to actual `external_clause` handoff. Commit
`2dc4bf7` adds an exact four-observation anti-target ABBA canary before array
release. Commit `835d134` pins an absolute Python interpreter after the first
guarded prepare found that nested `srun` did not resolve bare `python3`.

Prepare `145923` reached the exact canary but rejected with two correct baseline
observations and two candidate coverage misses. The remaining recurrence was an
already persistent lemma reported during `notify_assignment`, before ordinary
propagation consumed it on the retained trail. Commit `8e26569` suppresses and
counts only that bounded assignment-time repeat. An emitted lemma reaching a
complete model, a duplicate callback handoff, or cap exhaustion still aborts.

Exact branch head `6e402f0` passed hosted run `29277510106`. Fresh prepare
`145927` completed in `00:06:06`; its immutable ABBA canary returned baseline
`correct:2`, candidate `correct:2`, and four bounded repeated-assignment
conflicts. Its locked binary SHA-256 is `0cff30a189d46423...`, the preflight
journal SHA-256 is `e223befc265ee95e...`, and the preflight-summary file SHA-256
is `2809e913e30b5bb7...`. Array `145928` released automatically and final audit
`145929` remains dependency-held. Six array shards are complete and two are
active at this checkpoint. Only that immutable final audit may decide
whether validation-count, target-speed, anti-target-overhead, and conflict-
evidence gates pass. Partial state is not timing evidence.

## Long-Timeout Graph

Full and official 1,200-second timeout-only arrays are `145785` and `145787`.
Audits `145786`/`145788` and finalizer `145789` depend on their completion. Each
task requests one CPU and 10 GiB in `cpu_idle`; the current wait is scheduler
availability/priority, not an impossible resource shape. The graph is preserved
without cancellation or resubmission so physical-origin evidence remains
intact. Two full shards are complete and a third is active at this checkpoint;
the remaining full shards and official array are scheduler-bound.

## Opportunity Gates

No representation enters the solver merely because it is unusual.

1. T1 must match the authoritative typed tree parser on every one of 7,503
   sources with all sorts, signatures, term types, applications, assertions,
   Boolean-data terms, and unsupported diagnostics preserved.
2. T4 replacement job `146071` must return exactly 7,503 source-only rows and
   zero parser errors. The failed predecessor projected zero savings on its
   successfully parsed population, so Hall/PB implementation is unlikely but
   cannot be rejected before all 17 omitted sources are included. It still
   needs the preregistered 30% value-cell reduction on a broad population.
3. T5 must project exact class-code, restricted-growth, sorting-network,
   clause, literal, two-watch, and decoder costs. Both QG and Goel must show at
   least 25% broad reduction without weighted or p95 variable growth above
   `1.25`.
4. T6 must separate tree encoding, generic Boolean DAG sharing, root-equality
   union plus DAG, and full typed EUF quotient plus DAG. The full route must
   reduce projected CNF by at least 25% on 8/10 frozen hard cases and beat both
   generic controls by at least five percentage points.

T1 typed-parser parity is isolated on `research-typed-stream-parity`; its first
prepare failed before testing because WMI did not resolve bare `cargo`. Final
revision `8952dcb` raises a tested fail-closed nesting cap above the measured
corpus maximum and pins Cargo plus parser semantics. WMI chain
`146214`/`146215`/`146216` completed with all 7,503 snapshots matching and zero
fallback, mismatch, or error. This is under independent adversarial review and
permits only the next timing gate.

T5's hardened source-only census at `b51c75e` failed its second review: the WMI
receipt trusted aggregate booleans, contradictory oracle counters could pass,
and semantically impossible rehashed count rows were accepted. A strict bundle
verifier repair is active; no WMI census was submitted. T6 exact revision
`9833ec3` is queued as job `146075`, with promotion disabled until its current
12-source manifest is derived mechanically from the frozen P0 audit.

The next broad route after these gates is T3 M0 component-pressure telemetry,
not migration code. It stops if fewer than two fixed representations survive or
their oracle headroom is below 10%. The qg7-specific backup is a scalar,
source-exact frontier quotient census; SIMD remains conditional on at least 70%
useful lane occupancy.

Every opportunity artifact is source-only, deterministic, hash chained, and
forbidden from reporting SAT or UNSAT. Passing a structural gate permits an
isolated implementation; it does not establish speed.

## Victory Conditions

The project closes only when one frozen standalone release:

1. has zero wrong answers, invalid models/proofs, missing rows, hash failures,
   or unrecorded fallback;
2. matches the best coverage at two, 60, and 1,200 seconds on both corpora;
3. improves timeout/PAR-2 aggregate and paired geometric time against every
   comparator;
4. reproduces on a second CPU class and sealed family-held-out data; and
5. supports any novelty claim with closest-prior-art and ingredient ablations.

Until all five hold, the accurate description is a fast-head QF_UF research
solver with several independently checked experimental representations, not the
best solver overall.
