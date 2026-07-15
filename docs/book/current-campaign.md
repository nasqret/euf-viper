# Current Campaign

Date: 2026-07-15

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
wall limit. Corrected census `146071` completed at exact revision `8f78543`
with all 7,503 rows and zero parser errors. Certificate prepares
`146076`/`146079` completed, but arrays `146077`/`146080` failed after `/home`
returned `EDQUOT`; audits `146078`/`146081` were cancelled. This is an
infrastructure failure and establishes no certificate result. Recovery requires
fresh exact-revision roots under `/work`, complete arrays, and new terminal
audits. Replacement chains are full `147315`/`147316`/`147317` and official
`147318`/`147319`/`147320`. No partial certificate output is interpreted.

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

Schema v2 revision `e3add515` is also rejected. Its sidecar-controlled
congruence-closure origin bypassed CNF/assignment checks; self-consistent CNF,
variable, and atom-map omissions passed; and the primary analyzer could count
unchecked SAT before shadow verification. Final summary publication also
preceded rehash, parent symlinks escaped containment, incomplete journal tails
were truncated, and preparation JSON accepted ambiguity. Schema v3 must
independently reconstruct source/config CNF and namespace, replay dynamic API
clauses, require exact maps, and run the checker before SAT classification.

Schema v3 revision `578deb8` closes those semantic gaps and passes the local
checker boundaries, but it predates current main, puts evidence into the
default feature set, and certifies only a restricted SAT configuration. Its
current-main opt-in reconstruction at `d47e1c6` is also review NO-GO: the WMI
prepare builds `certificates` without the separately required evidence feature,
ordinary solves still allocate transcripts and duplicate clause streams while
evidence is disabled, and the ordinary solve CLI changed. A real combined-
feature smoke, instrumented zero-work off mode, and legacy CLI parity are
required before branch publication. No production-evidence corpus run exists.

Repair revision `939bc60` requests both features, probes the compiled feature
report, and removes the reviewed SAT-happy-path allocations, but a second
independent review is still NO-GO. The submitter reuses a revision checkout and
exports ambient/untracked build influence; ordinary usage output is not
byte-identical to `f8d9205`; zero-work tests omit exceptional solver paths; and
the exact combined release does not traverse the complete miniature evidence
pipeline. A private attempt checkout, environment allowlist, exhaustive CLI
differential, path-complete telemetry, and combined-release Linux smoke are
required before publication or WMI.

Research successor `e838c1f` earned a narrow independent GO for branch
publication and hosted Linux matrices only. Review still found a mutable
self-certified prepare receipt, hash-check/build and hash-check/exec gaps,
replaceable final publication, incomplete loader/library/toolchain closure, and
a candidate-owned CLI oracle. It is therefore WMI and merge NO-GO. The first
hosted run `29384179332` found a negative-smoke exit expectation bug. Commit
`b9da60b` bound that check to exit 1 plus the exact status-mismatch diagnostic,
and exact-head run `29384633378` passed every feature matrix plus the real
combined-release recorder/checker/runner/analyzer smoke in `5m43s`. That green
run changes no promotion decision. A phase-separated immutable-snapshot repair
produced diagnostic commit `cd62e3c`. Exact-head run `29389748725` failed its
414-test Python gate with three failures and four errors before any Rust or
release step: hash validation was undefined, plan metadata was incomplete,
bound source bytes were replaceable, and resume reconstructed the wrong
arguments. Independent review also rejects forgeable embedded build metadata,
an unenforced compiler baseline, incomplete execution closure, and
nontransactional publication. The conditional one-input WMI preflight was not
submitted; no production-evidence corpus run exists.

Repair `afa2a844` passed all local feature matrices and received independent
approval only for non-attesting branch publication and hosted Linux diagnosis.
Review still found that source bytes can change during a second unverified
descriptor read, the sealed-build receipt is candidate-authored, build tracing
does not bind every input channel or publish trace bytes, runtime closure is
incomplete and path-executed, final analysis publication is mutable, baseline
compiler/oracle trust is shared, and hosted revision equality is not asserted.
Exact-head run `29395085728` then failed its 424-test Python step with 12
failures and five errors. Checker-command arity, Python loader resolution,
missing parser metadata, newly runner-owned receipt fixtures, and receipt checks
that mask intended negative cases stopped the workflow before Rust, release,
`strace`, namespaces, sealed memfd, procfs, or locked smoke. No WMI preflight or
corpus run followed; another isolated repair is active.

## Causal Controls

### Modern Kissat

The valid 64-case SC2021-versus-Kissat-4 sample is job `145905`. Both backends
solve 53 cases with zero wrong answers or execution errors. Kissat 4 wins 16
paired instances and loses 37. With SC2021/Kissat-4 orientation, geometric
speed is `0.928694`, common-total speed is `0.963416`, median speed is
`0.973994`, and sign-flip $p=0.999500$. Broad job `145906` and merge `145907`
were dependency-cancelled. Wholesale Kissat 4 replacement is rejected; an
individual inprocessing pass requires a new one-factor control.

### DDFW And Phase Search

The 2026 CaDiCaL study by Pollitt, Fleury, Schidler, Biere, et al. makes DDFW,
target phases, and rephasing a stronger ordinary SAT control. It does not open
a production track for this corpus. Only six of the frozen 22 common misses are
SAT, whereas ten conversions are needed to lead Z3 and 21 to lead Yices2.
Against Yices2 at 60 seconds, the common-time deficit is `739.461s` on SAT and
`2,624.977s` on UNSAT. A semantic local-search implementation therefore fails
the opportunity ceiling before coding.

The only retained reopen test is a charged three-arm oracle: no imported phase,
deterministically shuffled source-atom phases, and phases projected from a
complete independently validated EUF model. It must convert at least one of the
six SAT Goel timeouts, beat both controls by `2x` on median, lose no solve, and
stay below `1%` p95 phase-import overhead. Ordinary DDFW remains a factorial
control. No implementation or WMI run is authorized.

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
is `2809e913e30b5bb7...`. Array `145928` completed all 12 shards. Final audit
`145929` returned a valid scientific rejection with zero wrong answers or
execution errors, no baseline-only solve, and coverage improving from 15 to 23
in every comparison. Target geometric speedups were `7.6029x` against current,
`9.0741x` against dynamic Ackermann, and `7.3178x` against model cuts.

The corresponding anti-target p95 overheads were `11.1689x`, `32.7545x`, and
`23.3462x`, all far above the preregistered `1.10x` cap. Whole-instance rollback
is therefore rejected as a default. Its sharp target/anti-target separation may
feed T3 M0 telemetry, but it does not authorize migration or integration. The
final audit file SHA-256 is `fffb152c...e3831ff`.

### SAT-Impact Explanation Falsifier

Current eager and model-cut conflict generation runs only after a complete SAT
assignment. It has no SAT decision levels and retains one causal explanation,
so adding an activity score there would not test SAT-aware selection. The
minimal T7 experiment is therefore isolated on frozen rollback head `6e402f0`,
where callback levels, active facts, causal edges, replay, and final model
validation already exist. The frozen implementation retains only a conflict
count from the first eager failure, not the assignment and clauses previously
claimed in the plan, so offline selector replay is not evidence.

Both experimental arms build and independently replay the same pool of at most
four deterministic explanation forests. Both restrict selection to the common
minimum-width clauses. The control chooses lexically; the candidate minimizes
LBD, current-level literal count, second-highest level, negative historical
reuse, and then lexical order. This prevents a shorter proof from masquerading
as a SAT-impact result.

The first stop is opportunity-only: at least two of three frozen multi-round
controls must expose two distinct replay-valid minimum-width clauses and a
policy disagreement. A survivor receives a 32-observation, four-source ABBA
canary; only a passing canary receives the 24-source, 192-observation panel.
Required gates are `1.10x` target geometric speed, at least 20% fewer
validations or propagations, under 5% selector work, A12 p95 overhead at most
`1.10`, and zero wrong, missing, replay, certificate, fallback, or off-only
outcomes. No vivification, integration, or WMI run is bundled with this test.

Exact initial implementation `6269084` rebuilt and source-verified the frozen
24-source manifest at SHA-256 `bea69013...a657`, matching an independent
reconstruction. The permitted local M3 diagnostic timed out on the first
`peg_solitaire.2` source at 60 seconds before producing a transcript. It
therefore fails the opportunity gate and authorizes no ABBA canary or WMI run.
Review also requires corrected median aggregation, fail-closed nonempty
opportunity evidence, complete selector-cost accounting, timing separation, a
lexically sound reference parser, and independent forest reconstruction before
the track can be reopened.

Repair `fa01e99` corrected lexical macro scope, median arithmetic, terminal
four-forest reconstruction, and wall/CPU/RSS collection, and its retained local
artifacts internally report three qualifying M3 sources. Independent review
still rejects the result. Historical reuse records omit the prior candidate
pools needed to reconstruct each selection; synthetic canary rows can pass on
embedded certificate fields with nonexistent transcripts; repeat medians do not
bind complete source identity; and a 9.17% off-arm materialization cost can
create the entire `1.10x` speed gate while the combined two-arm overhead stays
below 5%. Two successes plus one timeout also authorize `ready`, and the cited
artifacts are ephemeral rather than repository-bound. The exact commit is not
publishable and authorizes no hosted qualification, canary, full timing, or WMI
action. A further isolated repair is active.

## Long-Timeout Graph

Full and official 1,200-second timeout-only arrays were `145785` and `145787`.
They eventually ran, but late shards could not create locked output under the
`/home` campaign root. Three shards first exited nonzero, later tasks failed in
three to nine seconds with signal 53, and exact stderr records
`OSError: [Errno 122] Disk quota exceeded`. Audits `145786`/`145788` and
finalizer `145789` were cancelled. The graph is preserved as failed provenance,
but its completed partial rows are not benchmark evidence.

At the 2026-07-15 refresh, `/home` used 174.49 GiB of 200 GiB and 1,838,881 of
2,000,000 files; `/work` used 561.09 GiB of 1 TiB and 3,687,608 of 10,000,000
files. Recovery therefore stages a fresh exact `30828a4` checkout and verified
P0 base under `/work`, submits an entirely new continuation chain, and requires
both global audits plus finalization. No old shard is imported into that result.
Recovery barrier `147305` completed and dispatcher `147306` validated the copied
base. It submitted fresh 60-second full/official arrays `147307`/`147309`,
audits `147308`/`147310`, and successor dispatcher `147311`, which releases the
1,200-second stage only after both audits. The first full shard completed from
the `/work` command and output paths. Official array `147309` later completed
all 64 tasks with zero task, batch, or extern exits. Full audit `147308` was
scheduler-preempted after `02:09:26`; Slurm requeued the immutable job with one
restart, and the first attempt left no final or temporary analysis artifact.
The restarted full audit must run from scratch and pass duplicate-aware terminal
accounting. No continuation row is interpreted before both audits finish.

## Opportunity Gates

No representation enters the solver merely because it is unusual.

1. T1 must match the authoritative typed tree parser on every one of 7,503
   sources with all sorts, signatures, term types, applications, assertions,
   Boolean-data terms, and unsupported diagnostics preserved.
2. T4 replacement job `146071` returned exactly 7,503 source-only rows and zero
   parser errors. Its complete aggregate has 124,698 uniform and 124,698
   non-uniform value cells, exactly zero savings, 157 certified domains, 24
   checked Hall subsets, zero Hall conflicts, and zero eligible sources. This
   definitively rejects Hall/PB implementation against the preregistered 30%
   value-cell reduction gate.
3. T5 must project exact class-code, restricted-growth, sorting-network,
   clause, literal, two-watch, and decoder costs. Both QG and Goel must show at
   least 25% broad reduction without weighted or p95 variable growth above
   `1.25`.
4. T6 must separate tree encoding, generic Boolean DAG sharing, root-equality
   union plus DAG, and full typed EUF quotient plus DAG. The full route must
   reduce projected CNF by at least 25% on 8/10 frozen hard cases and beat both
   generic controls by at least five percentage points.

T1 typed-parser parity is complete. Final revision `e77846d` executes the
no-follow-opened parser binary through its inherited descriptor, pins canonical
Python identity, and strictly rejects ambiguous or non-finite JSON. WMI chain
`146510`/`146511`/`146512` plus independent reconstruction `146652` covered all
7,503 sources with zero fallback, mismatch, error, or other status. A separate
review reconstructed every row and artifact hash and approved parity-only
integration. Evidence machinery landed at `84b4c8e`, and the exact reviewed
parser source plus fixtures are source-complete on main at `00c11a5`. This does
not authorize timing or parser
completeness: 98 matching rows contain 4,851 unsupported diagnostics, and the
production tree-parser solve path is unchanged.

Initial T1 timing revision `a99d9bf` was rejected before publication or WMI.
Its empty miss set passed as zero overhead; timeout censoring could select a
favorable common population; ambient contract/manifest overrides were not
bound to the submitter's hashes; metrics preceded semantic parity; a
telemetry-only symbol clone polluted the timed path; and untracked remote
inputs escaped the provenance guard. The repair must require all 7,503 common
sources, zero timeouts/errors, exact per-source result and semantic parity, a
nonempty full-population p95 overhead metric, production-equivalent timed code,
and a fresh hash-bound execution root.

Revision `20be404` repaired those formulas and timed paths but failed the second
review. Parsed timing and semantic payloads were not rebound to their captured
stdout, so changing every candidate time to one nanosecond produced a forged
all-7,503 pass. The submitter also adopted the current remote manifest hash as
expected, `repetitions=128` incorrectly duplicated the 128-shard dimension,
Cargo had a transient source-mutation window, machine/toolchain identity was
too weak for a sub-1% threshold, and CI did not execute the exact release path.
The next revision must seal raw command bytes and shard receipts, require the
accepted corpus digest, separate shard and ABBA-round constants, monitor the
build snapshot, lock a homogeneous timing lane, and run the real release on
Linux before WMI.

Revision `26156e3` closed the raw-output and shard-set attacks, bound the
accepted 7,503-source corpus, split 128 shards from five measured ABBA rounds,
and used locked offline compilation. Independent review nevertheless approved
only exact-SHA publication for Linux diagnostics. WMI remains forbidden because
ambient values still choose submit and job roots, public stop sentinels can end
mutation monitors before compilation, final ELF/loader/library/toolchain
closure is incomplete, and the lane does not enforce the placement needed for
a sub-1% conclusion. Hosted run `29386186960` then failed before creating any
job: the workflow used `runner.temp` in job-level `env`, where the
[GitHub context table](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#context-availability)
does not provide `runner`. A fourth evidence repair is isolated; no timing row
or WMI submission exists. That repair, `7a278b7`, passed local matrices and was
published only after review allowed a hosted diagnostic. Exact run
`29389308332` failed both real Linux mutate-and-restore tests because the
monitor returned success rather than the fail-closed semantic exit. Review also
found that scripts were reopened by pathname after monitoring, a manual ELF
walk did not establish the dynamic loader's actual closure, and 128 exclusive
array elements pinned to sole node `c1n1` could not realize the declared 32-way
schedule. The run failure cancels the conditional one-shard infrastructure
canary. A fifth repair must bind actual executed bytes, obtain monitor-owned
readiness evidence, and replace the placement claim with an enforceable
schedule before another hosted review. No T1 timing WMI job exists.

Repair `ea28651` received branch/hosted-diagnostic approval only. Review found
that caller-selected canary shard IDs can assemble all 128 shards under a
nonpromotable label, helper scripts are checked and then reopened by pathname,
monitor readiness does not bind the exact watch set, and scheduler evidence plus
cancellation ownership remain incomplete. Exact-head run `29392563168` then
failed at guarded release compilation: global `+crt-static` target features
reached the host `partial_ref_derive` proc-macro build. No release artifact,
canary, or timing row was produced. The next repair must close all four evidence
boundaries and scope static flags to the final target executable.

Successor `d53b32b6` is published only as a diagnostic reproducer. Independent
review confirmed the exact canary/full population split, complete-population
parity gates, and analyzer arithmetic. It rejected cluster execution because
the receipt copies requested placement instead of observing the complete Slurm
state; arbitrary task IDs and one-of-64-CPU whole-node claims pass; inotify can
watch a root different from the scanned inode; Rust 1.96 and final-link-only
flags are not fully pinned; build tools can be replaced and restored around
pathname execution; and interrupted publication cannot resume or publish a
terminal release/cancel receipt. Exact hosted run `29398685115` completed the
release build but failed the guarded ELF check because `DT_NEEDED` entries were
still present. No T1 timing job exists.

T5's hardened source-only census at `b51c75e` failed its second review: the WMI
receipt trusted aggregate booleans, contradictory oracle counters could pass,
and semantically impossible rehashed count rows were accepted. A strict bundle
verifier repair is active; no WMI census was submitted. Revision `e930abf`
closed those direct cases but failed the next review: coordinated record,
target, gate, and decoder mutations could still reach `completed`, publication
had a final digest race, failed reruns retained stale completion metadata, and
untracked Python modules escaped revision integrity. The next repair must
semantically verify captured bytes and atomically publish an immutable bundle.
Revision `ea8dee5` closed the semantic replay and Python-identity defects but
also failed independent review: skip-worktree hid modified tracked imports, the
final digest still preceded pathname publication, and a failed same-job rerun
left an older completed bundle visible. Exact Git-blob checks, publication of
the checked inode, and attempt-scoped current markers were repaired at
`64770d8`, but its destination became visible before it was complete and cleanup
could remove a racing publisher's artifact. Revision `2080b26` added Linux
same-inode/no-replace publication; review still rejected a non-Linux fallback,
check-then-unlink cleanup, and a source-swap test that preferred relinking to a
fail-closed stop. Revision `55c0101` removed that fallback but still trusted a
stage pathname after checking descriptor identity, could unlink a replacement
`.current`, and reused revision-keyed remote work/results across concurrent
submissions. Revision `cf1aa3e` added private roots and descriptor-selected
publication, but review demonstrated that the retained staging hard link could
mutate the completed archive after `.current`. The symlink marker was also
swappable, Git/lock checks remained environment-sensitive, nonce/final digests
were not bound into a completed receipt, lower-level cleanup races survived,
Linux tests emulated pathname linking, and the verifier reused the candidate
projection implementation. An unnamed one-link archive, content-bearing
completion receipt, hermetic exact-blob guard, real Linux race tests, and an
independent projection checker are required before WMI.
Recovered valid commit `0ad8431` implemented that shape locally but failed the
next independent review. Its WMI script selects the tracked 3,521-row official
manifest while the analyzer requires 7,503 rows, so execution aborts before the
census. Its empty-path link policy is capability-dependent despite an
unprivileged requirement; scheduler evidence drops the cluster component and
does not bind `SLUID`, submit time, user, job name, or work directory; and the
second projection remains structurally close to the first. Exact SHA was
published only for diagnostic hosted execution. Run `29385400195` failed two
Linux consumer-test contracts after 88 tests. The one-link test passed on that
runner, but effective capabilities were not recorded, so it proves no
capability-free path. T5 remains WMI NO-GO and under repair.

Repair `446b424` selected the external 7,503-row manifest, rejected the tracked
3,521-row official manifest, implemented procfs `O_TMPFILE` one-link
publication, bound full Slurm allocation identity, expanded runtime inventory,
and added a structurally separate projection checker. Exact-head hosted run
`29388947138` passed its Linux publication diagnostics. Independent review
still rejected research evidence: both SMT-LIB parsers leak caller-local names
into `define-fun` bodies, the submitter releases the held census before local
receipt persistence is complete, and the hosted 7,503-source integration test
is skipped unless externally provisioned and uses synthetic scheduler evidence
when enabled. Linux mechanism smoke is therefore green while T5 and WMI remain
NO-GO. The scope/release/CI repair is active.

That repair, `48f3cec`, passed exact hosted run `29392694401` for mandatory
ordinary-Linux publication/procfs diagnostics and the root test matrices. The
provisioned 7,503-source job truthfully skipped because the corpus was absent.
Independent review still rejects corpus and WMI execution: transitive
free-global dependencies can escape through intermediate macros; release and
cancellation do not revalidate complete scheduler ownership; remote namespace
relationships, unique physical source coverage, unsupported top-level forms,
canary revision identity, hosted `GITHUB_SHA`, and all action pins are not fully
closed. Thus the green run is mechanism smoke only, not a scanner, census, or
performance result.

Successor `891c34e7` is also diagnostic-only. Independent review reproduced the
transitive quoted-macro scanner, 7,503-record ledger, scheduler receipt,
namespace closure, canary split, and local matrices. It found one remaining
execution boundary: the environment canary imports project code before checkout
validation, so ignored unchecked-hash Python bytecode can supply absent source.
Exact hosted run `29398119605` then failed during workflow compilation and
created zero jobs. Actionlint v1.7.12 identifies `${{ runner.temp }}` in
job-level `env`; only step execution exposes the `runner` context. No hosted
test, corpus scan, canary, census, or timing evidence was produced.

T6 exact revision `9833ec3` is queued as job `146075`, with promotion disabled
until its current 12-source manifest is derived mechanically from the frozen P0
audit. Diagnostic commit `b71a491` reproduced exactly 90,036 observation keys
and the 12 current qg7 UNSAT deficits, with byte-identical regeneration and
independently matching source records. Review still rejects it: inputs are
hashed then reopened, observation-matrix semantics and provenance are
underchecked, complete physical `DOMAIN7_HUGE` membership is not proved, alias
paths pass, and the 10-of-12 gate is not derived from population size. The
checkpoint is branch-only. A repair must derive the gate as `ceil(4N/5)` and
close every input/structure boundary; old job `146075` remains untouched.
Exact-head hosted contract run `29390630178` passed and changes no decision.

Repair `b587847` generated the hardened 12-source artifact
`1b3f4e52...05c21`. Independent review reproduced all 90,036 observations,
frozen provenance, physical hashes, domain-7 table structure, zero guarded
clauses, byte-identical output, and the derived `ceil(8N/10) = 10` gate. Those
exact population bytes are accepted. The branch and census remain no-go because
the CLI permits caller-selected digest contracts, JSON accepts non-finite
constants, corpus-manifest regeneration embeds checkout paths, and the exact
Rust/Slurm consumer still requires manifest v1, 10 sources, and an 8-source
gate. A separate reviewed v2 consumer revision is required before WMI.

Successor `58aee6e9` generates portable artifact `33a9f001...07c78` and an
independent review proved that it represents the same exact 12 sources as the
accepted predecessor. Overrides and non-finite JSON are closed, manifest v2 is
consumed, and the threshold is mechanically 10-of-12. The commit is published
only as a diagnostic. Exact-head run `29397378080` is green but supplemental:
the workflow omits the new T6 Python modules and explicit locked Rust 1.96.
WMI currently has Rust 1.93 and its attempted 1.96 rustup fetch fails quota;
toolchain/environment identity, runtime no-follow source opening, and complete
independent report recomputation also remain open. No projection has run and no
WMI or promotion decision is authorized.

The next broad route after these gates is T3 M0 component-pressure telemetry,
not migration code. It stops if fewer than two fixed representations survive or
their oracle headroom is below 10%. The qg7-specific backup is a scalar,
source-exact frontier quotient census; SIMD remains conditional on at least 70%
useful lane occupancy.

The M0 contract is now frozen in
`campaigns/t3-m0-component-pressure-v1.json`. The existing 24-source rollback
panel is not admissible training evidence because every target is Goel and every
control is QG. Under coverage-aware PAR-2 its best fixed arm totals `223.453`
seconds and its per-source oracle totals `215.403` seconds, only `3.74%`
headroom. M0 therefore remains stopped. If later fixed arms create at least 10%
cluster-bootstrap lower-bound headroom, S0 will expose only static typed and
base-CNF semantics and S1 only a common bounded eager prefix. Paths, families,
lineages, names, hashes, expected/final results, final runtimes, winners, and
post-checkpoint events are forbidden selector inputs. The fixed classifier is a
depth-four tree; sealed balanced-accuracy LCB must reach `0.80`, telemetry p95
ratio UCB must stay below `1.01`, and off/on semantic traces must be byte
identical.

The conditional qg7 route is also frozen as
`campaigns/t8-scalar-frontier-census-v1.json`. The prior right-translation
search has no source-exact UNSAT coverage on the frozen 12 deficits: it omits
the residual source from its state and can only abstain after an abstract
witness. T8 therefore starts, if prerequisites pass, as a scalar no-forget
typed partial-algebra transducer with command-level assertion lineage, complete
residual Boolean state, an independent domain-1--3 total-model-set oracle, and
checked SAT interpretations or UNSAT cube-cover DAGs. It must make at least
200/261 one-table cases source-complete, finish at least 10/12 deficits below
one million states, and keep complete graph-build cost below 10% of Yices2 on
at least 7/12. T1 review, the missing assertion-lineage ledger, and corrected
T4 range evidence were the initial gates. T4 is now complete but rejects
Hall/PB with zero savings. Every one of the 12 frozen qg7 rows has an empty
domain list and zero range facts, so T4 also fails to supply T8's finite-domain
certificate. Hosted CI strictly validates the machine contract, raw P12
negative-evidence artifact, and exact T4 rejection receipt; both evidence paths
are mandatory. Successful validation explicitly authorizes neither
implementation nor SIMD. T1 review, the missing assertion-lineage ledger, and a
separate checked domain-seven proof still block T8. Independent review is GO
only for retaining this denial-only control, with hosted run `29290493620`
green.

The first assertion-lineage implementation, `203158c3`, is preserved on
`research-t8-assertion-lineage` only as a failed-review reproducer. Its producer
handles the tested byte spans, lexical scopes, repeated roots, transitive macro
ownership, and typed materialization objects, and feature-off CLI behavior
matches its parent. It does not yet establish complete lineage: ordinary
verification skips full semantic reconstruction; the 7,503-record audit does
not compare rows with the frozen manifest and discards the per-source ledgers;
build and Slurm identity are self-reported; `push`/`pop` does not maintain the
active assertion stack; final pathname replacement can escape the last identity
check; and default builds still scan ambient Git state. Exact hosted run
`29398694222` passed its generic campaign and Rust steps, but it performs no
admissible lineage census and changes none of those findings. The scalar
frontier and SIMD remain unauthorized.

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
