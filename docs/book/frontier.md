# Research Frontier

## Active Correctness Blocker

The accepted binary incorrectly reports SAT for a formula requiring three
distinct Boolean arguments. Boolean-valued terms used only as UF arguments are
not guaranteed to receive `BoolTerm` atoms, and backend `DontCare` assignments
can also be skipped by validation. The immediate research order is therefore:

1. restore the accepted source lineage;
2. atomize all Boolean data terms and require total theory assignments;
3. pass differential and WMI correctness gates;
4. only then resume performance promotion.

The exact corpus campaigns remain useful paired timing evidence, but they do
not establish general soundness. See the dedicated soundness chapter for the
counterexample and repair contract.

This chapter records the 2026-07-10 program for testing whether `euf-viper`
can eventually outperform the established QF_UF solvers. It is a research
contract, not a superiority claim.

```{admonition} Status: no superiority claim
:class: warning
The current evidence supports a fast common-solve result against Z3 and cvc5
at a two-second timeout. It also shows a coverage deficit against Z3 and a
large speed and coverage deficit against Yices2. The focused finite
permutation rule has not passed the complete-corpus promotion gate described
here. None of these results establishes standalone or certifying superiority.
```

The labels below keep different kinds of statements separate:

- **[M] Measured result:** a dated, archived repository experiment.
- **[R] Repository fact:** an implementation or artifact visible in this
  checkout, but not itself a performance result.
- **[S] Source fact:** a statement from a linked primary paper, artifact,
  release, or official solver source. It does not predict local performance.
- **[H] Hypothesis:** a proposed mechanism, policy, or expected effect that
  still requires the stated experiment.

## Latest 60-Second Baseline

**[M]** Exact accepted-binary campaign `143248`/`143249`/`143254` ran all
7,503 SMT-LIB 2025 QF_UF instances at 60 seconds per solver. It used source
`58efe9d`, binary SHA-256
`4d5431135c95a2c528d287efd2803eaf895a5ec526c9642a570797b02fd47eb7`,
and a manifest with SHA-256
`2ab1041d877d65befb41d5c7ae0c942a970bc4266aa37167dc8a77ec91bd2acf`.
All 30,012 observations completed with zero wrong answers, disagreements,
execution errors, or failed shards.

| Solver | Correct | Timeouts | Median | Timeout-charged total |
| --- | ---: | ---: | ---: | ---: |
| euf-viper | 7,478 | 25 | 0.0471s | 5,930.09s |
| Z3 4.16.0 | 7,490 | 13 | 0.1285s | 3,998.14s |
| cvc5 1.3.4 | 7,473 | 30 | 0.1888s | 7,752.73s |
| Yices 2.7.0 | 7,500 | 3 | 0.0243s | 1,307.54s |

On the 7,466 common euf-viper/Z3 solves, euf-viper wins 5,811 instances and
has a `1.8883x` geometric speed ratio. Its common-total ratio is only
`0.7233x`: a small hard tail outweighs the large fast-head win. Against Yices,
euf-viper has only three unique solves while Yices has 25, and Yices wins
7,013/7,475 common cases. The four-solver oracle covers all 7,503 instances.

**[M]** The exact 1,200-second timeout-only continuation is running as prep
`143382`, array `143383`, and merge `143384`. It inherits solved observations
from `143248` and reruns only its 71 timeout cells. No final competition-budget
claim is made before the dependent merge completes.

**[M]** Global PGO was separately rejected after losing four solves and
aggregate time on a disjoint 512-case holdout. A structural PGO rule passed
five-fold validation and a disjoint 40-case control, but improved all-time by
only `1.00010x` on the control before routing overhead. It is not promoted.
The detailed evidence is in
`research-vault/06-results/2026-07-10-pgo-and-long-timeout.md`.

**[M]** A separate same-binary gate re-tested focused permutation support only
on the complete population selected by the promoted `>=512` lexical-let
threshold. Job `143412` preserved 17/17 coverage and improved all-total,
common-total, and geometric speed by `1.6475x`, `1.6475x`, and `1.8109x`.
`NEQ027_size11.smt2` improved from 56.39s to 1.16s median. This justifies an
automatic-route implementation, not global activation or promotion; sample,
hot, and full gates remain mandatory.

At the two-second boundary, five-repeat job `143438` improved this population's
coverage from 9 to 12 and passed all/common/geometric speed at
`1.2357x`/`1.1934x`/`1.1670x`. The three gains were stable in every repeat and
there was no baseline-only case. This is still selected-population evidence.

## Current Comparator

**[M]** Campaign `142480` used revision
`d9fe1edd8b36d50af9c07bc248e453f598974d2d` and `euf-viper` binary SHA-256
`e262a27d93e63c9073ba721fb6097344ee645fc98ad1134b3dd166f18bc610ab`.
It ran all 7,503 SMT-LIB 2025 QF_UF instances at two seconds per
solver-instance. The strict merge contained all `30,012/30,012` observations,
with zero wrong answers, execution errors, decisive disagreements, failed
shards, or binary-hash mismatches.

| Solver | Correct | Coverage | Timeouts | Median | Timeout-charged total |
| --- | ---: | ---: | ---: | ---: | ---: |
| euf-viper | 6,874 | 91.62% | 629 | 0.0532s | 2,562.49s |
| Z3 4.16.0 | 7,123 | 94.94% | 380 | 0.1353s | 2,485.35s |
| cvc5 1.3.4 | 6,831 | 91.04% | 672 | 0.2106s | 3,508.39s |
| Yices 2.7.0 | 7,420 | 98.89% | 83 | 0.0265s | 831.23s |

For common correct instances, define the displayed speed ratio as

$$
\rho(A,B)=\frac{\text{time of comparator }B}
                 {\text{time of euf-viper }A},
$$

so a value above one favors `euf-viper`.

| Comparator | Common correct | euf-viper only | Comparator only | Common-total $\rho$ | Geometric $\rho$ |
| --- | ---: | ---: | ---: | ---: | ---: |
| Z3 | 6,833 | 41 | 290 | 1.1110x | 2.0353x |
| cvc5 | 6,684 | 190 | 147 | 1.7274x | 2.9364x |
| Yices2 | 6,865 | 9 | 555 | 0.2790x | 0.4155x |

**[M]** The honest interpretation is narrow:

- `euf-viper` is faster than Z3 and cvc5 on their common solved instances at
  this timeout, and it beats cvc5 on coverage and timeout-charged total.
- Z3's 249-solve coverage lead is enough to give Z3 the better
  timeout-charged total despite `euf-viper`'s common-solve advantage.
- Yices2 leads both the easy head and hard tail. Nine `euf-viper`-only solves
  show complementarity, not overall superiority.
- The finite-permutation candidate discussed below uses a later experimental
  binary and is not represented in this comparator table.

The complete report is the
[four-solver campaign note](https://github.com/nasqret/euf-viper/blob/main/research-vault/06-results/2026-07-10-qf-uf-four-solver-wmi-142480.md).

## Victory Contract

The word *victory* is reserved for the following reproducible levels. A result
at one level must not be reported as a stronger level.

| Level | Exact criterion |
| --- | --- |
| **V0: valid candidate** | Zero wrong answers and execution errors; no coverage loss against its immediate baseline; timeout-charged total, common-solve total, and geometric speed ratios all at least `1.00`; exact binary SHA and raw rows archived. |
| **V1: fast-head leader** | Best median and geometric mean against Z3, cvc5, and Yices2 at two seconds; no material non-QG regression; coverage deficit, if any, stated explicitly. |
| **V2: coverage parity** | At least `7,500/7,503` at 1,200 seconds to match Z3 and `7,503/7,503` to match Yices2; no comparator fallback. |
| **V3: standalone superiority** | Coverage at least equal to Z3 and Yices2 at every declared timeout; at least `1.05x` lower timeout-charged aggregate time in two complete runs; geometric speed ratio at least `1.02x` in both runs; same direction on held-out data; no proof- or model-validator discrepancy. |
| **V4: certifying superiority** | V3 plus independent reconstruction of the base Tseitin CNF; a checked proof for every UNSAT answer, including finite-domain, symmetry, counting, and theory lemmas; proof generation and checking measured separately and end to end. |

**[R]** An opt-in Yices-dependent portfolio is operationally useful but cannot
satisfy V2--V4 as a standalone solver. Content hashes and benchmark names are
forbidden routing features.

## Eager, Lazy, And Online EUF

For applications of one uninterpreted function, every Ackermann implication

$$
\left(\bigwedge_{i=1}^{k} a_i=b_i\right)
\Longrightarrow
f(a_1,\ldots,a_k)=f(b_1,\ldots,b_k)
$$

is an EUF theorem. For Boolean-valued applications, the consequent is the
equivalence of the two result literals.

**[R]** The current architecture is already hybrid:

1. The eager side emits the Boolean encoding, selected equality transitivity,
   selected congruence/Ackermann clauses, and proved finite-domain clauses
   before the first SAT call.
2. The lazy side checks a complete SAT assignment by congruence closure. An
   invalid model yields violated congruence or explanation clauses and another
   SAT call.
3. A complete congruence-closure validator remains the final authority for SAT.
   A bounded optimization may abstain; it may not validate a model.

**[S]** The
[partial Ackermannization study](https://doi.org/10.1007/11916277_38)
reports no universal eager-versus-lazy winner in its workloads. The pinned
[Yices policy](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/api/yices_api.c#L9456-L9470)
uses bounded dynamic Ackermann lemmas, while
[Z3's EUF Ackermann implementation](https://github.com/Z3Prover/z3/blob/z3-4.16.0/src/sat/smt/euf_ackerman.cpp)
uses search-activity controls. These are mechanism facts, not local speed
predictions.

**[H]** The next architecture should choose at function or connected-component
granularity:

| Mode | Trigger | Intended role | Mandatory backstop |
| --- | --- | --- | --- |
| Lazy | Default for cold or sparse symbols | Avoid unused equality atoms and clauses | Complete-model validation |
| Eager | Low estimated completion cost or a proved structural route | Remove predictable repeated theory conflicts | Differential clause and model tests |
| Online promotion | Repeated violated congruences from one symbol/component | Pay completion cost only after observed activity | Logged quotas and complete-model validation |
| Trail propagator | Partial assignment already entails conflict or an existing atom | Avoid waiting for another complete invalid model | Replayable delayed reason |

The experiment must record per symbol: application count, candidate-pair count,
new equality atoms, generated clauses, violated congruences, SAT calls, invalid
models, reason width, and end-to-end time. A smaller eager CNF or fewer SAT
calls is not sufficient if total time or coverage regresses.

## Finite Injection Implies Permutation

Let

$$
D=\{d_1,\ldots,d_n\},\qquad
C=\{t_1,\ldots,t_n\},\qquad
x_{ij}\;\Longleftrightarrow\;(t_i=d_j).
$$

Assume all four preconditions are proved:

1. every $t_i$ has the exhaustive range $D$;
2. the values $d_1,\ldots,d_n$ are pairwise distinct;
3. the terms $t_1,\ldots,t_n$ are pairwise disequal;
4. $|C|=|D|=n$.

The row constraints include

$$
\bigvee_{j=1}^{n}x_{ij}
\quad\text{and}\quad
\neg x_{ij}\lor\neg x_{ik}\quad(j\ne k).
$$

Pairwise disequality gives column at-most-one clauses

$$
\neg x_{ij}\lor\neg x_{\ell j}\quad(i\ne\ell).
$$

```{admonition} Injection-to-permutation theorem
:class: theorem
Under the four preconditions, for every $d_j\in D$,

$$
\bigvee_{i=1}^{n}x_{ij}
\;=\;
\bigvee_{t\in C}(t=d_j)
$$

is a logical consequence. Together with column at-most-one, every value occurs
exactly once.
```

**Proof sketch.** Any satisfying assignment defines
$g:C\rightarrow D$ by $g(t_i)=d_j$ when $x_{ij}$ holds. Exhaustive range makes
$g$ total. Pairwise disequality makes it injective. An injection between two
finite sets of the same cardinality is surjective, so every $d_j$ has a
preimage. This proves the column-support clause. The argument is invalid if
the range is not exhaustive, the values are not proved distinct, or the clique
and domain sizes differ.

**[M]** The default-off `focused` policy adds these support clauses only when
the formula has one closed table or exactly one domain-sized guarded
injection. This is a structural formula metric, not a benchmark name or hash.
Same-binary controlled gates reported zero wrong answers and execution errors:

| Gate | Instances | Timeout/repeats | Coverage | All-total | Common-total | Geometric |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Uniform target `142564` | 6 | 120s / 3 | 6 -> 6 | 2.180x | 2.180x | 2.046x |
| Uniform finite `142567` | 151 | 2s / 3 | 126 -> 127 | 1.034x | 1.044x | 1.071x |
| Uniform boundary `142572` | 4 | 3s / 7 | 3 -> 4 | 1.445x | 1.074x | 1.007x |
| Focused boundary `142578` | 4 | 3s / 7 | 3 -> 4 | 1.821x | 1.449x | 1.334x |
| Focused finite `142581` | 151 | 2s / 3 | 126 -> 128 | 1.043x | 1.047x | 1.070x |

**[M]** The uniform policy is rejected. It lost `PEQ013_size7.smt2` at the
two-second boundary and regressed the excluded 109-instance population
(`0.989x` all-total, `0.995x` common-total, `0.999x` geometric). The focused
151-instance gate retained both new solves and removed all baseline-only cases.
That is finite-family evidence only. At the dated checkpoint, hot-400 and full
7,503-instance gates were still required before default promotion. See the
[finite-permutation result note](https://github.com/nasqret/euf-viper/blob/main/research-vault/06-results/2026-07-10-finite-permutation-support.md).

## Why Hall Propagation Is Next

The permutation theorem handles one special tight case: $n$ variables, the
same $n$ values, and a complete disequality clique. Hall reasoning handles
unequal and partially pruned candidate sets.

For finite-domain variables $X$ with exhaustive candidate sets $D(x)$, define

$$
N(S)=\bigcup_{x\in S}D(x),\qquad S\subseteq X.
$$

**[S]** Matching-based `AllDifferent` filtering uses the following facts:

$$
|N(S)|<|S| \quad\Longrightarrow\quad \text{conflict},
$$

and, for a Hall-tight set,

$$
|N(S)|=|S|
\quad\Longrightarrow\quad
D(y)\leftarrow D(y)\setminus N(S)
\quad\text{for every }y\in X\setminus S.
$$

The primary algorithmic source is
[Regin's matching-based `AllDifferent` paper](https://cdn.aaai.org/AAAI/1994/AAAI94-055.pdf).

**[H]** This is the next generalization because it reasons across the row
exact-one and cross-term disequality constraints instead of merely changing
the CNF spelling of each row. The full injection above is one Hall-tight set;
native matching can also detect deficits and reserve values before all rows
form a full permutation.

Promotion requires a checkable provenance object for every native constraint:
the finite sort, distinct domain values, each exhaustive candidate list, and
the relevant disequality group. A conflict explanation must carry a witness
$S$ with $|N(S)|<|S|$; a propagation explanation must identify the tight set
that forbids the removed edge. Reasons must be translated to existing value
literals and independently replayed as clauses or checked pseudo-Boolean
steps. Complete congruence-closure model validation remains active.

## Yices Equality Abstraction

**[S]** The pinned Yices source maps equalities implied by a formula to a
partition of terms. Let $E(P)\subseteq T\times T$ be the equivalence relation
represented by partition $P$, and let $P(t)$ be the class containing $t$.
Yices names the two operations as follows:

$$
E(P\mathbin{\sqcap_Y}Q)
=\operatorname{EqCl}\bigl(E(P)\cup E(Q)\bigr),
$$

$$
E(P\mathbin{\sqcup_Y}Q)
=E(P)\cap E(Q),
$$

where $\operatorname{EqCl}$ is equivalence closure. Equivalently, the join
keeps only equalities common to both branches:

$$
P\mathbin{\sqcup_Y}Q
=\{P(t)\cap Q(t)\mid t\in T\},
$$

with duplicate classes removed and singleton classes omitted by Yices's
compact representation. These `meet` and `join` names follow Yices's
abstract-domain order; reversing the partition order reverses conventional
lattice terminology. The exact contracts are in the pinned
[partition interface](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/eq_abstraction.h#L159-L200).

If $\alpha(F)$ is the partition of equalities implied by $F$, then

$$
\alpha(F\land G)=\alpha(F)\mathbin{\sqcap_Y}\alpha(G),
\qquad
\alpha(F\lor G)=\alpha(F)\mathbin{\sqcup_Y}\alpha(G).
$$

For Boolean $u_1,u_2$, the source computes

$$
\alpha(u_1\leftrightarrow u_2)
=\bigl(\alpha(\neg u_1)\mathbin{\sqcup_Y}\alpha(u_2)\bigr)
 \mathbin{\sqcap_Y}
 \bigl(\alpha(\neg u_2)\mathbin{\sqcup_Y}\alpha(u_1)\bigr),
$$

and

$$
\alpha(\operatorname{ite}(c,u_1,u_2))
=\bigl(\alpha(\neg c)\mathbin{\sqcup_Y}\alpha(u_1)\bigr)
 \mathbin{\sqcap_Y}
 \bigl(\alpha(c)\mathbin{\sqcup_Y}\alpha(u_2)\bigr).
$$

The polarity-aware recurrences are visible in the pinned
[Yices equality learner](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/eq_learner.c#L158-L307).

**[H]** A local implementation should begin in shadow mode: compute the
partition without changing clauses or substitutions and compare it with a
complete branch oracle. A facts-only mode may then register proved equalities.
Substitution, clause deletion, or recursive colored reasoning must wait until
fact provenance, proof replay, and full-corpus gates pass. This is a possible
generalization of the current positive-`or` branch intersection, not evidence
of a speedup.

## Rollback E-Graph And IPASIR-UP

**[R]** The current lazy loop waits for a complete inconsistent Boolean model,
runs closure, adds clauses, and calls SAT again. It is not a partial-trail
theory propagator.

**[S]**
[IPASIR-UP](https://doi.org/10.1613/jair.1.16163) provides assignment,
decision-level, and backtrack notifications; complete-model checks; external
conflicts and propagations; delayed reasons; and optional theory decisions.
Observed variables have special inprocessing restrictions, and decision
override can damage SAT performance.

**[H]** The proposed state is one rollback-capable congruence engine with:

- union by size and an explicit undo log, without destructive path compression;
- per-class application use-lists and a canonical signature table;
- typed proof-forest edges for asserted and congruence merges;
- stable SAT atom identifiers, so explanations never invent unregistered
  equalities;
- generation-stamped scratch storage and counters for merges, rehashes,
  callbacks, explanations, and reason width.

The integration must be staged:

| Stage | Behavior | Acceptance discriminator |
| --- | --- | --- |
| **M0** | Move the current final-model check behind the model callback; return the same conflicts. | Same results and accepted/rejected model sequence as the current loop. |
| **M1** | Observe only equality/disequality atoms; maintain rollback closure; report a conflict as soon as a partial trail makes disequal endpoints congruent. | Fewer complete inconsistent models, replayable conflicts, no easy-head regression. |
| **M2** | Propagate only an existing equality/disequality atom entailed by closure; build its reason only when requested. | Fewer SAT rounds with acceptable callback and reason cost. |
| **M3** | Experiment with theory-directed decisions or phases in a separate default-off build. | M1/M2 traces predict the decision; fixed-seed A/B passes independently. |

The full-corpus gate is attempted only after the multi-round target records
fewer complete SAT rounds and at least `1.10x` end-to-end improvement. The
complete-model validator remains permanently enabled. M1 or M2 is rejected if
reason replay fails, callback overhead regresses the easy head, or complete
inconsistent models do not decrease.

## Parser And Memory Roadmap

All items in this section are **[H]** until differential semantics and
end-to-end gates pass.

| Step | Change | Semantic guard | Measurements |
| --- | --- | --- | --- |
| Direct-root CNF | Encode top-level assertions directly instead of assigning every root another Tseitin variable. | Exhaustive nested `and`, `or`, `not`, `iff`, and `ite` differential tests against the old encoder. | Variables, clauses, watches, FFI calls, allocations, total time. |
| Streaming commands | Replace `tokenize -> full S-expression tree -> traversal` with a borrowed byte scanner that consumes one top-level command at a time. | Preserve quoted symbols, comments, annotations, scopes, and unsupported-syntax diagnostics; compare every corpus semantic IR. | Parse time, copied bytes, allocations, peak RSS, total time. |
| Compact terms | Use `u32` term IDs, one stored argument slice, fingerprint buckets, and exact collision checks. | Fingerprints are never equality proofs; compare term counts and serialized semantic IR. | Arena bytes, duplicate slices, hash probes, peak RSS. |
| Boolean DAG sharing | Hash-cons immutable Boolean nodes before Tseitin encoding while preserving sorts and ordered ITE branches. | SAT/UNSAT differential tests and certificate reconstruction. | Source nodes, shared nodes, Tseitin variables/clauses. |
| Packed CNF | Replace nested clause vectors and backend copies with flat literals plus offsets; reserve variables once and load clauses directly. | DIMACS-equivalent clause multiset modulo legal order; unchanged model projection. | Bytes copied, FFI calls, load time, peak RSS. |
| Layout last | Train PGO on family-grouped data disjoint from evaluation; keep portable `x86-64-v3`; isolate cold certificate/error paths. | Exact binary digest and architecture canaries. | End-to-end time, not instruction count alone. |

The roadmap deliberately separates semantic representation from storage. A
parser speedup that increases solver time, a compact arena that changes term
identity, or a smaller CNF that loses proof reconstruction is rejected.

## Proof And Certificate Obligations

**[R]** Certificate format v1 emits a propositional proof and an EUF manifest,
but finite-domain shortcuts are excluded and independent reconstruction of all
base Tseitin clauses remains incomplete. That is a trust boundary, not merely
missing documentation.

The required checking order is:

1. Parse SMT-LIB independently and reconstruct the atom map and base CNF.
2. Compare the reconstructed clause multiset and stable variable/provenance map
   with the solver manifest.
3. Validate every added rule according to its actual kind.
4. Check the final SAT proof only after all base and derived clauses are
   accepted.
5. For SAT, independently validate the complete model by congruence closure.
6. Bind input, binary, options, CNF, manifest, model, and proof by digest.

| Clause/result kind | Required independent obligation |
| --- | --- |
| Tseitin/base clause | Checker-side reconstruction from parsed SMT-LIB; never trust a second solver-emitted copy. |
| EUF transitivity/congruence | Negate antecedents and replay a proof-producing closure to the claimed equality or conflict. |
| Injection/permutation support | Verify exhaustive ranges, distinct values, full clique, equal cardinalities, and then the finite bijection theorem above. |
| Hall or PB reason | Check the explicit neighborhood/matching witness or a checked pseudo-Boolean derivation; do not label it a generic EUF lemma. |
| Symmetry clause | Verify a whole-formula automorphism witness and the stated canonical-order rule; symmetry is satisfiability-preserving, not an EUF consequence. |
| IPASIR-UP external clause | Preserve incremental proof semantics and delayed-reason provenance over observed variables. |
| SAT answer | Complete congruence-closure model validation, including all applications and predicate atoms. |
| UNSAT answer | Checked DRAT/LRAT/FRAT-style propositional derivation after every theory/native addition is accepted. |

Every active route needs one checked SAT model and one checked UNSAT
certificate. Mutation tests must independently corrupt an atom map, Tseitin
clause, theory antecedent, proof-forest edge, finite witness, model entry, and
final SAT proof; each corruption must fail at its intended layer. Proof solve,
write, elaborate, and check time are reported separately from ordinary solve
time. Relevant primary sources include
[proof-producing congruence closure](https://www.cs.upc.edu/~roberto/papers/rta05.pdf),
[small congruence proofs](https://arxiv.org/abs/2209.03398),
[FRAT](https://arxiv.org/abs/2109.09665), and
[LRAT](https://arxiv.org/abs/1612.02353).

## Experiment Ladder

Every candidate follows the same order:

1. Compile and hash exact control and candidate binaries.
2. Run unit, property, parser-differential, and SAT/UNSAT canaries.
3. Run the structural target with at least five or seven repeats.
4. Repeat the target gate on AMD and Intel WMI nodes.
5. Run the stable hot-400 gate with three repeats.
6. Run finite hard-tail and non-finite Goel manifests.
7. Run the full paired 7,503-instance corpus with strict merge.
8. Run a fresh four-solver two-second comparison.
9. Rerun `euf-viper` at 60 and 1,200 seconds while preserving comparator rows.
10. Run an independent repeat and a source-family-held-out or newly released
    evaluation.

Promotion requires zero wrong answers, zero execution errors, no coverage
loss, and all three full-corpus ratios at least `1.00`. V3 imposes the stronger
`1.05x` aggregate and `1.02x` geometric thresholds in two runs plus held-out
confirmation.

### Rejection Rules

| Observation | Decision |
| --- | --- |
| Wrong answer, decisive discrepancy, invalid model, failed proof replay, or incomplete strict merge | Reject immediately; no timing interpretation. |
| Parser/IR mismatch, fingerprint-only equality, rollback mismatch, or corrupted reason accepted | Reject the implementation as unsound. |
| Coverage loss or any full-corpus speed ratio below `1.00` | Do not promote the candidate default. Preserve only as a more narrowly justified experiment. |
| Large synthetic or selected-family gain but failed hot, tail, or full gate | Not promotion evidence and not a superiority claim. A structural route may remain default-off if independently justified. |
| Smaller CNF, fewer clauses/SAT calls, lower instruction count, or newer backend version without end-to-end gain | Insufficient evidence. |
| Whole-backend regression | Reject that configuration, not an isolated mechanism that was never ablated. |
| Hall propagation does not reduce scaling conflict search, or a witness fails replay | Reject native Hall promotion. |
| IPASIR-UP M1/M2 does not reduce complete inconsistent models or regresses the easy head | Reject that stage before a full gate. |
| A new native rule lacks independent reconstruction or mutation rejection | Block promotion regardless of speed. |
| Uniform finite support helps selected structures but regresses the excluded population | Reject the uniform policy; retain only the prospectively tested focused guard. |

Local timing remains a smoke test. Benchmark-name routing, content-hash answer
caches, comparator fallback, and acceptance of SAT without full model
validation are explicit non-goals.

## Sources And Artifacts

The four dated repository sources for this chapter are:

- [superiority research program](https://github.com/nasqret/euf-viper/blob/main/research-vault/02-design/2026-07-10-superiority-program.md);
- [expert implementation ledger](https://github.com/nasqret/euf-viper/blob/main/research-vault/01-literature/2026-07-10-expert-implementation-ledger.md);
- [four-solver campaign 142480](https://github.com/nasqret/euf-viper/blob/main/research-vault/06-results/2026-07-10-qf-uf-four-solver-wmi-142480.md);
- [finite injection/permutation result](https://github.com/nasqret/euf-viper/blob/main/research-vault/06-results/2026-07-10-finite-permutation-support.md).

Direct repository artifacts:

- [`src/main.rs`](https://github.com/nasqret/euf-viper/blob/main/src/main.rs),
  the current solver and certificate implementation;
- [`analyze_ab_opportunities.py`](https://github.com/nasqret/euf-viper/blob/main/scripts/bench/analyze_ab_opportunities.py),
  the paired-result opportunity analyzer;
- [`analyze_finite_structures.py`](https://github.com/nasqret/euf-viper/blob/main/scripts/bench/analyze_finite_structures.py),
  the read-only finite-structure recognizer;
- [`sync_and_submit_sharded_corpus.sh`](https://github.com/nasqret/euf-viper/blob/main/scripts/wmi/sync_and_submit_sharded_corpus.sh),
  the strict sharded campaign entry point;
- [`check_certificate.py`](https://github.com/nasqret/euf-viper/blob/main/scripts/cert/check_certificate.py),
  the current independent certificate checker.

Primary papers and official sources used by the ledger include:

- [Fast Congruence Closure and Extensions](https://www.cs.upc.edu/~roberto/papers/IC06.pdf);
- [Clausal Congruence Closure](https://doi.org/10.4230/LIPIcs.SAT.2024.6);
- [Yices 2.2 architecture](https://yices.csl.sri.com/papers/cav2014.pdf);
- [IPASIR-UP user propagators](https://doi.org/10.1613/jair.1.16163);
- [matching-based `AllDifferent`](https://cdn.aaai.org/AAAI/1994/AAAI94-055.pdf);
- [partial Ackermannization](https://doi.org/10.1007/11916277_38);
- [complete finite-model symmetry breaking](https://doi.org/10.1609/aaai.v39i11.33217);
- [symmetry-aware finite-model cube and conquer](https://doi.org/10.4230/LIPIcs.CP.2023.8).
