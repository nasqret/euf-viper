# Shadow Probes Before New Proof Systems

Date: 2026-07-10

Status: implementation contracts for telemetry-only experiments. Neither probe
may alter a result, CNF, SAT call, backend route, or accepted solver binary.

## EUF-Consistent Lucky Models

### Hypothesis

Kissat's cheap lucky assignments suggest trying four typed EUF models before
CDCL: one singleton quotient per non-Boolean sort and a free-term quotient,
each with source Boolean-returning UF applications uniformly false or true.
This is an EUF analogue, not a literal port of Kissat's propositional probes.

### Required Semantics

- `Bool` always contains distinct `false` and `true`; it is never collapsed.
- The singleton model has one value per non-Boolean sort, not one global value.
- The free model begins with distinct non-Boolean ground terms and closes under
  typed congruence.
- Source Boolean UFs, including zero-arity Boolean constants, take the selected
  phase. Derived Boolean expressions are evaluated, not phase-assigned.
- Formula ITEs select the evaluated branch. Lowered term ITEs also select their
  branch; the current guarded-equality lowering is insufficient provenance by
  itself.
- Every sort remains nonempty and every function interpretation is total.

`Problem` therefore needs a creation-ordered, profile-only provenance side
table such as `InternalTermDef::Ite` and `InternalTermDef::BoolExpr`. Raw
`TermId` identity is not a sound free model when Boolean values are UF
arguments.

### Reuse And Hook

- Reuse `BoolExpr`, `BoolAtomKey`, `UnionFind`, and `congruence_closure`.
- Promote the exact test evaluator in `eq_abstraction.rs` to a production-safe
  read-only helper rather than inventing a second Boolean semantics.
- Independently project every candidate to atom values and require the existing
  `theory_conflict_clauses` validator to return no conflict.
- Add `BoolTerm` atoms for every Boolean-sorted arena term before validation so
  Boolean terms used only as UF arguments are not invisible.
- Run only under `EUF_VIPER_PROFILE`; never return early from the solver.

### Telemetry

Use mask bits `1=singleton_false`, `2=singleton_true`, `4=free_false`, and
`8=free_true`. Emit total time, validation time/calls, exact hit mask,
applicability reason, validator failures, sort counts, Boolean UF/argument
counts, term ITEs, derived Boolean definitions, and Boolean branch nodes.

Aggregate distinct paths by exact mask. Expected-UNSAT hits and validator
failures are hard errors. Empty-assertion hits are recorded but excluded from
actionable totals.

### Tests And Gate

Tests cover an exclusive hit for every bit, two uninterpreted sorts, Boolean
arguments, term ITEs, materialized Boolean expressions, typed congruence, and
profile-off/on result parity. A small typed-DAG property loop must prove that
congruent arguments receive equal results.

The WMI campaign uses the same binary on both sides of the existing 64-shard
full-corpus harness, adding only `EUF_VIPER_PROFILE=1` to the candidate. It
hard-fails on answer differences, malformed or missing records, UNSAT hits, or
validator failures. Implementation of an early-return path is allowed only if
the shadow union finds nontrivial branchy hits not already covered by current
fast paths.

Primary inspiration: [Kissat 4.0.4 lucky.c](https://github.com/arminbiere/kissat/blob/rel-4.0.4/src/lucky.c#L307-L390).

## Post-Assignment FCC Clique Probe

### Qualification

The current finite `k` is not a global `card(S,k)` assertion. It is a
scope-local palette for terms proved eligible for the finite encoding. The
probe may conclude only about recognized finite terms with complete membership
rows over that palette.

### Scope Capture

Under strict default-off `EUF_VIPER_FCC_SHADOW=1`, capture a
`FiniteModelScope` where finite axioms are built. It contains:

- root mandatory disequalities and the selected domain;
- covered, closed, and recognized finite terms;
- original equality atoms before generated membership atoms;
- exact membership literals and one-hot rows;
- the verified symmetry bound and palette size `k`.

`finite_added > 0` is the eligibility boundary. The scope is observational and
must not affect finite encoding.

### Verified Model Graph

- Build pre-colour EUF classes from original equality atoms assigned explicitly
  true, then close congruence.
- Add an edge only for an original equality atom assigned explicitly false;
  `DontCare` is never a disequality.
- Mark a model-guarded edge only for the existing exact binary guard shape when
  both guard and consequence values are explicit in the assignment.
- Exclude generated membership atoms from the pre-colour graph.
- Require every clique class to contain a recognized finite term with a
  complete `k`-literal row.
- Independently quotient by membership choices and require the existing full
  validator to confirm the resulting collapse/self-conflict.

A witness is new only when an exact `(k+1)` class clique exists after the model
assignment, no such root mandatory clique exists, and telemetry-only root BCP
also finds none. This separates the probe from the rejected static root-clique
experiment.

### Telemetry And Witnesses

Count finite models, complete relevant models, models with don't-cares, root
and BCP edges, model direct/guarded edges, class self-conflicts, `(k+1)` hits,
new post-assignment hits, search nodes/caps, witness count, and elapsed time.

Each canonical `fcc_shadow_v1` JSON witness records stage/round, `k`, domain
IDs, class representatives, source edge atoms, DIMACS edge/guard literals,
equality explanation literals, colliding membership literals, root-hit flags,
and search completeness. The collector attaches path and source/binary hashes.

### Tests And Gate

Tests cover dynamic `k=3` discovery, root-static exclusion, unknown guards,
generated-membership exclusion, class merging and reasons, deterministic
serialization, corrupted-witness rejection, duplicate root-BCP literals, and
shadow-off/on answer/CNF/SAT-call parity.

The first WMI gate is the frozen 151-row finite manifest with plain CaDiCaL,
model cuts, ten seconds, and identical binary/configuration except shadow off
versus on. It requires 151/151 records, exact parity, replay of every witness,
and explicit unknown status for capped searches. Zero verified new witnesses
rejects regionalization; at least one witness must reproduce three times before
behavior-changing implementation begins.

Primary basis: [Finite Model Finding in SMT, CAV 2013](https://cvc4.cs.stanford.edu/papers/CAV-2013/fmf_smt_reynolds_cav2013.pdf).
