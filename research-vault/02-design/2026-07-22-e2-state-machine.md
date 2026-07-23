# E2 Canonical Partition CDCL State Machine

Date: 2026-07-22

Status: implementation contract for the fixed E2 engine. This document does
not authorize routing, composition, or default behavior.

## Non-Collapse Requirement

E2 is not a SAT assignment with a congruence-closure callback. The live typed
partition is part of the assignment. A partition action may determine many
source equality atoms simultaneously, and watched clauses read equality truth
directly from the partition.

The experiment fails its novelty objective if all useful decisions and learned
objects reduce to independent source equality variables without reducing
states, clauses, or explanation work against the E1 DPLL(T) control.

## Stable Namespaces

- `TermId`: parser traversal order, shared by terms, components, partition,
  model reconstruction, and proof events.
- `AtomId[0..source_atom_count)`: sorted semantic source atoms.
- `AtomId[source_atom_count..atom_count)`: deterministic Boolean definition
  atoms allocated by postorder lowering.
- `ComponentId`: connected theory regions ordered by minimum `TermId`.
- `ReasonId`: append-only engine reason index; never a pointer or class label.

No proof event may expose union-find roots. Canonical representatives are
minimum stable terms and may be recomputed by the checker.

## Assignment Layers

The combined three-valued interpretation is ordered as follows:

1. A source equality atom reads `Equal`, `Disequal`, or `Unknown` from the
   rollback partition.
2. A source Boolean-term atom reads equality with the explicit stable `true`
   and `false` terms.
3. A Boolean definition atom reads its implication-trail assignment.
4. A contradiction between layers is a checked conflict, never last-writer
   wins.

The parser-provided true and false terms are separated at root level. Positive
and negative Boolean-term literals merge their term with true or false,
respectively. Function congruence may therefore determine Boolean atoms.

## Decision Frames

Each frame stores:

- partition and congruence snapshot;
- implication-trail level start;
- proof-event start;
- propagation queue start;
- selected canonical action and remaining alternatives;
- semantic-work counters used by hard caps.

Rollback restores all five mutable layers or returns an internal error. A
snapshot from another state lineage is rejected.

### Partition actions

For the smallest eligible term of a sort, enumerate current classes in
canonical minimum-term order followed by exactly one fresh-class action.
Choosing an existing class merges with its canonical representative. Choosing
fresh separates the term from every earlier live representative required by
the bounded cover. Pairwise equality/separation is the reference encoding of
that action, not the public decision language.

The simple action is the fixed correctness control. The separately
preregistered
`research-vault/02-design/2026-07-22-e2-domain-watch-experiment.md` tests
set-valued pruning over the same dynamic quotient domain. Dsat is explicit
prior art for fixed-domain set decisions, watched states, and native first-UIP;
only the changing congruence quotient and stable replay boundary are candidate
Fabric contributions.

Unbounded irrelevant terms need no decision. Only terms that can change a live
source atom, function collision, disequality, or model obligation enter the
frontier.

### Boolean actions

An unassigned definition atom may be decided only after clause propagation and
all currently forced partition actions reach a fixpoint. Source equality atoms
are never assigned independently when their truth is already determined by the
partition.

## Propagation Fixpoint

One propagation round performs:

1. consume every newly false watched literal;
2. apply native unit literals transactionally;
3. update application signatures affected by changed argument classes;
4. merge equal-function applications with equal argument-class tuples;
5. detect disequality or Boolean-value conflicts;
6. publish newly determined source atoms to the watch queues;
7. repeat until all queues are empty.

The correctness reference may scan every clause and application. The timing
engine uses literal watch lists, rollback signature buckets, a stable
term-to-source-atom CSR index, and a quotient impact frontier. Forward updates
visit the endpoint classes and their post-update disequality neighbors;
initialization and rollback conservatively mark all source terms. Tests compare
all watched truths with a full semantic scan after every synchronization.

Every implication reason is a clause over stable source or definition atoms.
A congruence reason recursively expands to explicit equality antecedents. An
unknown relation is never used as a negative antecedent.

Boolean-domain causes are frozen before mutation. Every inference allocates a
fresh monotonic proof ID containing already-flattened source antecedents;
reconstructing the cause from the post-merge partition is forbidden because it
can cycle through its own equality and can alias replacement-branch proofs.
Opaque canonical-action provenance disables first-UIP transitively for that
branch. It is never encoded as a fake Boolean literal.

## Conflict Analysis

The initial reference may learn the chronological blocking nogood for a fully
checked failed branch. First-UIP is mandatory before timing promotion.

First-UIP resolves a falsified conflict clause against clause or theory reason
clauses until exactly one literal remains at the current level. The learned
clause must satisfy all of these checks before insertion:

- every atom is registered;
- every pivot appears with opposite polarity in both parents;
- no class label or union-find root occurs;
- the checker replays each theory reason;
- the learned clause is false at conflict time;
- the asserted literal is unit after backjump;
- a relabeling oracle accepts the native object.

Tautologies are discarded. Empty learned clauses authorize UNSAT only when the
complete root proof replays.

Quotient-action learning is a separate finite-domain system. Its learned object
is a forbidden tuple over frozen `ActionDomainKey` and `ActionValue` values,
plus stable relation conditions and independently replayed evidence. The first
eligible implementation learns only from a direct congruence conflict caused
by the current action. Recursive UNSAT, Boolean conflict analysis, model
failure, and abstention cannot create an action nogood.

## SAT Completion

A Boolean fixpoint is not a model. SAT completion must:

1. choose values for remaining Boolean definition atoms;
2. complete all live source atoms consistently with the partition;
3. saturate congruence;
4. preserve true/false separation and every disequality;
5. build one typed value per canonical class;
6. totalize every observed function table consistently;
7. evaluate all source assertions and root facts independently.

Failure returns a refinement conflict or `abstain`; it cannot be interpreted as
UNSAT.

## UNSAT Completion

UNSAT requires one of:

- an independently replayed empty learned clause whose ancestry reaches only
  source clauses and checked theory reasons; or
- a checked cover DAG whose outgoing canonical actions exhaust every allowed
  class choice at every node.

A node cap, reason cap, proof cap, allocation failure, or incomplete cover
returns `abstain`.

## Initial Caps

The fixed reference exposes explicit limits for terms, atoms, clauses, literal
occurrences, decision frames, propagations, congruence merges, reason literals,
learned clauses, proof events, and model-validation work. Caps are semantic
work counters and do not inspect paths, families, expected results, or prior
runtimes.

## Promotion Sequence

1. Exact truth tables for semantic projection and native CNF.
2. Exhaustive partition and disequality states through four terms.
3. Exhaustive E2 result parity with direct finite-model enumeration.
4. Every class relabeling replays every reason and learned nogood.
5. One million generated differential cases against two independent solvers.
6. Target and anti-target fixed-engine ABBA timing.
7. Full-corpus correctness shadow with no routing.
8. Only then consider a fixed `fabric-solve --engine e2` benchmark arm.
