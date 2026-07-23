# E2 Dynamic Quotient-Domain Watch Experiment

Date: 2026-07-22

Status: preregistered design; implementation begins only after canonical action
and incremental congruence differential gates pass.

## Question

Can E2 reduce proof states and watched-clause work by pruning sets of canonical
class alternatives instead of immediately assigning one equality or one final
class?

The experiment adapts native discrete CDCL to a quotient domain that changes
under EUF congruence. Dsat is the mandatory fixed-domain prior-art control.

## Stable Domain

For a pivot term `p`, the live alternatives are:

```text
Existing(r) for each earlier same-sort canonical representative r
Fresh(p)
```

`Existing(r)` is stored by stable minimum `TermId`, never by union-find root
or dense class number. After a merge, targets are canonicalized and duplicate
alternatives collapse. `Fresh(p)` is the unique choice that separates `p`
from every earlier live same-sort representative.

The active frontier contains only terms that can affect a source equality,
Boolean value, application collision, explicit disequality, or total-model
obligation.

## Domain Literals

A domain literal is a nonempty proper subset of a pivot's live alternatives:

```text
Allowed(p, existing_target_set, fresh_allowed)
```

Asserting the literal prunes every omitted alternative. A singleton forces its
remaining action. An empty domain is a conflict. A full domain is a tautology
and is never stored.

Canonical serialization sorts stable targets and writes the fresh bit last.
Serialization re-canonicalizes after every merge and rejects a target from the
wrong sort, a future term, or a duplicated representative.

## Two-Level Watches

1. Every native clause watches two literals.
2. Every watched domain literal watches one active alternative.
3. Pruning an alternative visits only domain literals watching it.
4. Falsifying a domain literal visits only clauses watching it.
5. A surviving alternative moves the inner watch; a surviving literal moves
   the clause watch.

Watch positions need not roll back. Domain activity, pruning reasons, and
pruning times do roll back. Every move and examined entry is charged.

## Reasons and Learning

Each pruned alternative records:

- decision level and level-local monotone time;
- source clause or learned clause ID;
- stable equality/disequality antecedents;
- congruence event IDs when an application collision removed the alternative.

The chronological reference learns a blocking domain nogood for a completely
checked failed branch. First-UIP then resolves implicit target sets until one
domain literal remains falsified at the current level. No learned object may
mention a union-find root, transient class label, or unregistered synthetic
equality.

The independent checker reconstructs each live domain from source terms and
replays every target removal. It rejects a learned clause unless it is false at
the conflict, unit after the declared backjump, and invariant under every
bounded class relabeling.

## Decision Arms

- `A0`: binary equality/separation control.
- `A1`: simple existing-class-or-fresh choice.
- `A2`: fail-first singleton choice.
- `A3`: scored subset pruning using a fixed Dsat-style threshold.
- `A4`: score-mass subset pruning with threshold selected only on the
  development split.

All arms share parsing, watches, congruence, restarts, learning, caps, and proof
checking. No arm may inspect path, family, expected status, hash, or prior
runtime.

## Gates

### G0: State Correctness

- all typed partitions through four terms;
- all valid pruning subsets;
- merge, separation, congruence, and rollback interleavings;
- every class relabeling;
- zero mismatch against direct finite-model enumeration.

### G1: Structural Opportunity

On a frozen generated blocker suite, require one of `A2`-`A4` to reduce both
visited domain states and watched entries by at least 20% against `A1`, with
canonicalization below 10% of charged work.

### G2: Causal Timing

Parser-inclusive ABBA on frozen target and anti-target panels:

- zero wrong, abstaining, or unchecked results;
- common geometric and aggregate speedup at least 1.10x on targets;
- p95 anti-target overhead at most 1.01x;
- proof checking included in end-to-end time.

### G3: Broad Fixed Engine

Run the fixed E2 arm over all 7,503 sources. Require no coverage loss at each
budget, lower PAR-2, and positive family-macro timing before any composition.

## Kill Conditions

Stop this arm if:

- one relabeling changes a reason, learned clause, or outcome;
- dynamic domain maintenance costs more work than it avoids;
- the winning arm reduces to ordinary pair-equality decisions;
- the same gain is reproduced by fixed-domain Dsat or generic SAT factoring;
- any incomplete domain cover is accepted as UNSAT.
