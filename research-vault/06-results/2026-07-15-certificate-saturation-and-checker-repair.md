# Certificate Saturation And Checker Repair

Date: 2026-07-15

## Decision

The replacement certificate arrays are not evidence of corpus coverage. Full
array `147316` failed on tasks 0--5 and official array `147319` failed on tasks
0--44; the remaining tasks are held. Audits `147317` and `147320` remain
dependency-held. No partial row is interpreted and the old arrays must not be
released.

The failures expose two separate, reproducible bottlenecks:

- certificate generation can remain inside dynamic EUF saturation until the
  shard timeout; and
- the independent checker used to revalidate the complete reconstructed
  problem once for every theory lemma.

Both are implementation defects in the certificate path, not evidence about
the timed production solver.

## Failure Classification

The first 45 official shards produced exactly 15 `certify_timeout` and 30
`checker_timeout` records. The first six full shards produced three of each.
Artifacts classified as `certify_timeout` contain no DIMACS, DRAT, or manifest,
which localizes the timeout before proof emission, inside
`discover_certificate_theory_conflicts`.

The 15 official generation timeouts are one Goel rush-hour source, fourteen
NEQ/PEQ sources, and include `NEQ048_size9`. The checker-timeout population
spans loops6, NEQ, PEQ, qg5, and Goel. The arrays stay held while bounded probes
replace speculation with phase measurements.

## Checker Probe

WMI diagnostic root:
`/work/bnaskrecki/euf-viper-diagnostics/certificate-phase-20260715`.

Baseline job `147498` completed in `3m45s`. Without DRAT time,
`gensys_icl019` reconstruction took `47.511s` and `iso_icl068` took `176.956s`;
their DRAT checks took only `0.128s` and `0.135s`.

The hoisted-validation prototype job `147503` completed in `17s`:

| Source | Baseline reconstruction | Prototype reconstruction |
| --- | ---: | ---: |
| `gensys_icl019` | `47.511s` | `4.931s` |
| `iso_icl068` | `176.956s` | `11.046s` |

Integrated jobs `147514` and `147515` then independently verified the same
sources in six and twelve seconds of job wall time, with empty stderr. The
candidate checker validates the reconstructed problem once, uses a detached
canonical snapshot, and validates all suffix lemmas against that snapshot. A
direct equality contradiction now returns before congruence closure. The exact
21,006-lemma `NEQ048_size9` suffix validates locally in `2.1508s`.

Candidate commit `e3c1309bd4bb1dc19ad0fc5b73e02c585121f6cd` remains isolated
after independent review found no parsed-file soundness differential. The
review measured a `36.56x` local diagnostic speedup on the 21,006-lemma
artifact, but found two public-API defects: a hostile integer subclass could
escape the checker exception contract through formatting, and non-parser
zero/one-arity `iff` nodes survived assertion snapshots. Exact-head hosted run
`29403602171` passed.

Fresh post-CI WMI jobs `147522` and `147523` used exact checker SHA-256
`3d0c6cf0...90eec97`, exact driver SHA-256 `0c48e390...6949b2`, and drat-trim
SHA-256 `58a121de...443e5`. They verified copied, hash-bound `gensys_icl019` and
`iso_icl068` artifacts in `3.88s` and `5.98s` wall time with approximately
65 MB peak RSS. The job output SHA-256 values are `f97342c8...ded784` and
`34847a94...bf6ff`; both exit codes are zero. The root
`/work/bnaskrecki/euf-viper-diagnostics/checker-post-ci-e3c1309-20260715` was
made read-only after terminal inspection.

Repair chain `940c556`/`75347bd`/`11fe184` closes those two API findings,
requires exact integer manifest counts, regenerates the exact static seed
prefix, and bounds Python candidate work to the Rust limits. The 355-test Python
suite passes and the checker regenerates the 28,972-clause artifact exactly.
Independent paired review nevertheless remains NO-GO: the CLI accepts duplicate
JSON keys and non-finite constants, permits float SAT variable counts, and
reports missing required fields through an uncaught traceback. The Rust peer
`d570062` also maps some impossible second-pass budget divergences to ordinary
fallback instead of aborting. Both repairs are active; no exact-head push,
hosted gate, WMI control, merge, or campaign is authorized.

## Generation Probe

WMI root
`/work/bnaskrecki/euf-viper-diagnostics/certify-saturation-neq048-20260715`
records job `147517`. Production solved `NEQ048_size9` in `0.791s`; its default
eager dump had 452,786 clauses and solved in `0.558s`; current certification
timed out after 300 seconds without an artifact.

Job `147518` disabled finite-domain axioms and materialized only replayable EUF
seeds. Construction took about `1.036s`; the resulting CNF had 7,966 base,
19,260 transitivity, and 1,746 congruence clauses, 28,972 total. Exact local
reconstruction later produced byte-identical Rust and probe files with SHA-256
`387fd1e5cd8a5fb8b75c4d6dff38143e9a1163d5bcaeaeb981931ec24a3ae00e`.
A fresh direct solve returned SAT in `0.123458ms`. The earlier WMI timing line
was misinterpreted and is not an UNSAT result.

This rejects static eager seeds as the solution to `NEQ048_size9`. They remain
useful, independently replayable accelerators on other instances, but they do
not replace dynamic saturation or the finite route on this wall.

Exact eager-seed commit
`3f6421cfef52cec86f7bb76cb3a16f4ac3c49a9f` passed hosted run
`29402707176`. Hosted green establishes branch health only. Before a bounded
canary, the independent checker must also require exact clause-accounting
metadata, `finite_domain_axioms == 0`, and category-consistent transitivity and
congruence segments.

## Finite-Orbit Prototype

A deterministic no-symmetry domain-9 probe emitted 194,093 finite clauses but
did not solve within 26 seconds and was stopped. The production finite route
verified adjacent source swaps, emitted 233,158 finite clauses, and solved UNSAT
in `0.164s`. The decisive mechanism is orbit canonicalization, not one-hot
finite-domain encoding alone.

Experimental branch `research-certificate-finite-domain` has head
`8af25b610848fd173b7c9523506eaef9509602cb`. Its explicit
`certify --finite-orbit` mode preserves default v2 behavior, rejects all ambient
finite and axiom-order controls, records a separate finite prefix, emits v3 only
for finite UNSAT, and fails closed if that path reaches SAT. It is a prototype,
not an accepted certificate format.

On `NEQ048_size9` the route emitted 24,264 variables and 452,786 clauses:

| Category | Clauses |
| --- | ---: |
| canonical base | 7,966 |
| finite-domain plus verified symmetry | 233,158 |
| transitivity | 209,916 |
| congruence | 1,746 |
| dynamic conflicts | 0 |

Generation plus DRAT emission took `0.78s`. Direct `drat-trim -I` verified the
propositional proof in `0.364s`; two runs produced identical CNF, DRAT, and
manifest hashes. Rust release tests passed 256/260 with four explicit ignores
under all features, 234/237 with three ignores by default, and 228/231 with
three ignores without default features.

The missing trust step is explicit: the v2 checker correctly rejects v3. An
independent v3 checker must reconstruct or validate the finite range premise,
prove the source is invariant under each adjacent domain swap, reconstruct the
exact lex-leader auxiliary clauses, validate all added equality atoms, replay
the remaining EUF lemmas, and only then invoke DRAT. Until that exists and
passes adversarial review, the result establishes a fast certifying route
candidate, not a sound certificate or coverage claim.

## Strict Kernel And Integrated Checker

Strict guarded kernel commit `51d0d4ddd6669627c0aadb6d23e977e5a3046812`
removes the redundant full finite/transitivity suffix. On the exact source
SHA-256 `06cb8e01...b42ab64`, it emits 24,264 variables and 262,908 clauses:

| Category | Clauses |
| --- | ---: |
| canonical base | 7,966 |
| guarded rows | 63,153 |
| finite coverage | 1,754 |
| equality channels | 20,223 |
| predicate channels | 1,674 |
| adjacent-orbit lex | 39,024 |
| guarded channels | 129,114 |

This is 189,878 clauses fewer than the 452,786-clause prototype, a `41.9%`
reduction. Nontrivial predicate-congruence tests confirm that the base CNF does
not contain an empty clause and that the contradiction requires both equality
and predicate channels.

Independent checker commit `39acd097bf67ea44b3a63f967da3eb21696d78bd`
parses the source itself and reconstructs the domain clique, top-level finite
coverage, closed functions, closure, adjacent-swap automorphisms, atom IDs,
all seven clause categories, lex auxiliaries, and exact DIMACS bytes before
running `drat-trim`. It does not trust Rust's finite-analysis witness. Separate
adversarial review accepted this v3 contract for the sealed WMI setting;
concurrent hostile artifact mutation and unbounded external proof-checker time
remain explicit operational risks.

The paired seed/checker findings are repaired as well. Rust aborts on
planning/materialization divergence, uses bounded exact commitments over seed
family, order, and normalized literals, and owns CNF/DRAT/manifest publication
through one cleanup transaction. The CLI starts that transaction after parsing
the output prefix but before parsing later options, so malformed limits cannot
leave stale artifacts. The strict JSON/checker boundary rejects duplicate keys,
non-finite values, and non-integer counts. These repairs were independently
accepted on their isolated exact heads before integration.

Combined head `ee2de94de86f34d00dcc83cf9b79767b42d9911d` passes 57 focused
Python checker tests, 376 full Python tests, and the Rust matrices: 264 passed
with four ignored under all features, 234/3 by default, 228/3 without default
features, and 256/4 with certificates only. A release build from that exact
head regenerated `NEQ048_size9` in `0.65s` with CNF SHA-256
`fed1870786e338b2fb4af09ccf49d23a5df9e1158905aeb28fd5b9a386f14df9`
and DRAT SHA-256
`38913e75653ab9239226085ae41578248d2796b0ac9da1536029acccf426a61e`.
The independent checker returned `verified` in `0.84s`, reconstructing 254,942
kernel clauses beyond the 7,966-clause base; direct `drat-trim -I` verified in
`0.23s`.

Fresh combined review returned NO-GO on `ee2de94` for three release defects:

1. source, DIMACS, and proof paths were hashed and then reopened, so the hashes
   were not bound to the bytes later parsed or checked;
2. an input named as `<prefix>.cnf` could be deleted by output cleanup before
   the alias was rejected; and
3. certify CLI parsing accepted unknown options and could consume a flag as an
   output-prefix value.

Repair commit `4851361b9ac81dec33dab150428e97d967e19854`, tree
`b99b4ec5c17010686c5618cbeb951cc8bb707b7f`, snapshots each checker input
through one source open into a private read-only temporary file while hashing,
then parses and checks only those snapshots. Rust normalizes lexical paths,
checks existing Unix device/inode identity for source/output and output/output
aliases before constructing the cleanup transaction, and uses a strict
two-stage certify grammar. Regressions cover path replacement, lexical aliases,
symlinks, hardlinks, duplicate prefixes, unknown options, missing values, and
the hosted checker-test list.

The repaired head passes all 378 Python tests and 268 all-feature Rust tests
with four ignored. Exact CNF and DRAT hashes remain unchanged; snapshot-bound
checking takes `1.69s` locally. Its replacement independent review is active.
It is not published and has no hosted or WMI result yet. WMI access has
recovered, but no bounded control is authorized before review and exact-head
hosted CI pass.

## Ordered Gate

1. Completed on isolated heads: every Rust materialization-pass divergence
   aborts, and the Python artifact boundary rejects duplicate/non-finite JSON
   and non-integer SAT counts.
2. Completed locally: the independent v3 checker reconstructs the finite-orbit
   contract without importing Rust finite-analysis output.
3. Finish replacement review of repair head `4851361`, then run exact-head
   hosted CI. A green result is branch health, not corpus proof.
4. Run one bounded `NEQ048_size9` generation-and-v3-checker control from the
   reviewed exact head.
5. Run the frozen 15 generation failures, representative checker failures, and
   one SAT v2 control.
6. Only if all rows are correct and resource-bounded, create fresh full and
   official certificate campaigns under new immutable roots.

No timing or superiority claim follows from this certificate work.

Related: [[2026-07-15-wmi-full-audit-preemption]],
[[2026-07-11-tail-opportunity-atlas]], and
[[2026-07-12-best-overall-qf-uf-campaign]].
