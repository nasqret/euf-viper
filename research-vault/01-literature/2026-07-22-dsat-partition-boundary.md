# Dsat Boundary for Partition-Native EUF Search

Date: 2026-07-22

Status: primary-source design boundary. This note narrows the E2 novelty claim;
it does not authorize a benchmark route.

## Primary Source

Yaofang Zhang, Ken Zhou, and Adnan Darwiche, [Dsat: A Native SAT Solver for
Discrete Logic](https://doi.org/10.4230/LIPIcs.SAT.2026.31), SAT 2026.
The paper and its [reference implementation](https://github.com/uclareasoning/dsat)
are the closest current source for native finite-domain watching, set-valued
decisions, and first-UIP learning.

Related controls:

- Pollitt et al., [Factoring Learned
  Clauses](https://doi.org/10.4230/LIPIcs.SAT.2026.28), for generic extended
  resolution and learned XOR/ITE factoring.
- Anders, Codel, and Heule, [Simplify, Order, Break,
  Repeat](https://doi.org/10.4230/LIPIcs.SAT.2026.4), for repeated
  connectivity-aware symmetry simplification using unit and binary clauses.
- Biere et al., [Clausal Congruence
  Closure](https://doi.org/10.4230/LIPIcs.SAT.2024.6), for extracting gates
  from CNF and applying congruence closure during SAT inprocessing.

## Occupied Territory

Dsat already establishes the following ideas for fixed finite-domain
variables:

1. native clauses whose literals denote sets of values;
2. two clause watches plus one watched state for each currently watched
   finite-domain literal;
3. rollback state pruning with a reason and time on each pruned state;
4. first-UIP learning by resolving implicit state sets rather than eagerly
   constructing every intermediate literal;
5. non-simple decisions that prune a scored subset of active states;
6. activity normalized by the number of active states;
7. learned-clause minimization, restarts, LBD, and deletion in a native
   finite-domain solver.

Fabric must not claim any of those ingredients independently.

## Fabric Delta

E2 does not have fixed variables with fixed values. A pivot term has a dynamic
quotient domain:

```text
current same-sort canonical classes + one unique fresh-class action
```

Merges collapse several domain values, congruence can merge result terms
without a direct pivot decision, disequalities remove values, and rollback
restores both the quotient and application-signature collisions. The plausible
contribution is therefore narrower:

- native set-valued literals over a changing canonical quotient domain;
- two-level watches whose state identities are stable source terms rather than
  transient union-find roots or class numbers;
- first-UIP reasons that survive class relabeling and independently replay as
  source equalities, disequalities, and congruence antecedents;
- one search state shared by Boolean definitions, quotient-domain pruning, and
  observed uninterpreted-function rows.

This delta is only a hypothesis until the relabeling oracle, Dsat-style
ablation, and fixed-engine timing gates pass.

## Direct Engineering Consequences

1. Keep `existing-class-or-fresh` as the simple-decision control.
2. Add a domain literal `Allowed(pivot, stable_targets, fresh_allowed)` whose
   complement is represented as pruned alternatives, not pairwise SAT atoms.
3. A clause watches two native literals. A watched domain literal watches one
   still-active stable target or the fresh token.
4. Store the decision level, monotone time, and replayable reason for every
   pruned alternative.
5. Build first-UIP over sets only after chronological nogoods and every
   relabeling test pass.
6. Compare fixed-value, equality/separation, and scored subset decisions under
   identical propagation and restart policies.
7. Treat Dsat's reported subset heuristic as a control, not a default. Sweep a
   frozen small set of thresholds and select none unless a development corpus
   gate survives family-held-out confirmation.

## Cheapest Falsifiers

- Exhaust every restricted-growth partition through four terms and every
  sequence of domain pruning, merge, and rollback.
- Permute all non-stable class labels after every step; watched results,
  reasons, learned clauses, and outcomes must be byte-identical.
- Require fewer visited native states or fewer watched entries than simple
  class choice on a frozen exhaustive blocker suite.
- Charge every canonicalization, target collapse, watched-state move, and
  reason-set operation.
- Stop the domain-watch arm if its p95 anti-target overhead exceeds 1%, if it
  reduces to ordinary equality-variable clauses, or if Dsat's fixed-domain
  control explains the full gain.

## Current Observation

The first correctness-only canonical action engine is not yet faster
structurally. Across 676 two-clause formulas over three equality atoms, binary
and canonical modes each visit 1,422 search nodes. On a formula excluding all
five three-term partitions, the canonical reference visits eight nodes versus
seven for binary branching. This justifies domain pruning and learning as
separate experiments; class enumeration alone receives no performance credit.
