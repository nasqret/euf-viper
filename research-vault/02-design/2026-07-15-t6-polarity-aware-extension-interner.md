# T6 Polarity-Aware Extension Interner

Date: 2026-07-15
Status: syntactic arm rejected; diagnostic retained pending review

## Decision

The next eligible performance experiment is a default-off source Boolean-DAG
interner that shares extension literals by typed operator, polarity, canonical
children, and an optional independently replayable EUF guard. It must preserve
the existing atom IDs, eager theory clauses, SAT backend, and feature-off CNF
bytes.

Ordinary Boolean
hash-consing, polarity-aware Tseitin encodings, and clausal congruence are known
controls. The only potentially distinct ingredient is guarded source-level
reuse modulo independently proved EUF congruence, and that boundary still needs
a pinned prior-art audit.

Commit `c8c336d2450a0cc6e497777c8f7cb5b862fb2be2` implements only the
default-off syntactic projection diagnostic. It cannot route or invoke solving.
Independent code review is pending, so the commit is implementation evidence,
not a trusted semantic or novelty result.

## Motivation

The exact full 60-second deficit contains nine Goel, one `PEQ012_size6`, and
twelve qg7 instances. The 2-second deficit is dominated by QG and then Goel.
Existing source telemetry shows substantial repeated Boolean structure on qg7,
but direct-root CNF and atom memoization already remove some obvious
duplication. Source-node counts therefore cannot authorize implementation; only
actual emitted-CNF projection can.

## Arms

1. `off`: byte-identical current encoder.
2. `syntactic`: canonical source-DAG interning with no theory quotient.
3. `guarded-euf`: the same interner plus reuse only under a replayable guard
   proving the required argument equalities.
4. `post-cnf-control`: generic clausal factoring or congruence after ordinary
   emission.

For associative `and` and `or`, children are deterministically canonicalized.
`ite` order is preserved. One-sided definitions are emitted for single-polarity
use; full equivalence is emitted only when both polarities require it. Missing
guards, unsupported syntax, cap exhaustion, or unverifiable provenance fall
back to the unchanged encoder.

## Frozen Structural Envelope

- qg7: domain size 7, at least one closed table function, at least 49 binary
  table applications, no guarded disequality clauses, and at least 80,000
  parentheses.
- Goel: no closed or binary tables, at least 2,500 graph vertices, 5,000 edges,
  and 3,000 distinct constants.
- PEQ: a finite domain and guarded disequality clique lower bound at least the
  domain size.
- Broad 2-second projection: the frozen `TABLE_CORE OR GRAPH_32` envelope.

Paths, family labels, expected status, observed result, and timing are forbidden
router inputs.

## Projection Gate

Measure emitted variables, clauses, literal occurrences, watch slots, encoder
time, and provenance bytes on the frozen twelve qg7, nine Goel, and one PEQ
targets. Require at least 25% fewer emitted literals on 10/12 qg7, 8/9 Goel,
and 1/1 PEQ. The guarded-EUF arm must beat the syntactic and post-CNF controls.
Kill the experiment before corpus timing if any population threshold fails.

## Frozen Result

The syntactic arm emitted actual candidate DIMACS and measured the frozen
projection panel. Encoder nanoseconds are diagnostic measurements, not a timing
campaign.

| Population | Cases passing 25% literal reduction | Baseline literals | Candidate literals | Aggregate change |
| --- | ---: | ---: | ---: | ---: |
| qg7 | 12/12 | 20,460,088 | 1,313,046 | -93.582% |
| Goel | 4/9 | 1,194,032 | 860,102 | -27.967% |
| `PEQ012_size6` | 0/1 | 1,579 | 1,765 | +11.780% |

The arm fails the preregistered 8/9 Goel and 1/1 PEQ population gates. It is
therefore killed before solver timing and cannot enter the solve path. Candidate
encoding was also slower on all three aggregates, so qg7 compression alone is
not sufficient evidence for promotion.

The only remaining T6 hypothesis is an independently replayable guarded-EUF
arm with the frozen interface
`GuardProvider::prove(TypedCanonicalKey, TypedCanonicalKey,
RequiredPolarity)`. It must beat this syntactic control and still pass every
population threshold; otherwise T6 is closed entirely.

## Soundness Gate

- Feature-off DIMACS must remain byte-identical.
- An independent checker reconstructs every node key, extension definition,
  guard, EUF witness, and source-to-CNF provenance edge.
- Exhaustively compare formulas through six theory atoms.
- Fuzz at least one million typed formulas, including Boolean-valued UF
  arguments.
- Validate SAT against the original source model.
- Accept UNSAT only with a replayable candidate-CNF proof and independent
  source-to-CNF equisatisfiability validation.

## Timing Gate

Only after projection and soundness pass, run same-binary alternating WMI
controls on the exact 22 targets, three 60-second repeats, and a second CPU
class. Require zero wrong answers and baseline-only solves, every target-class
timing ratio above `1.05`, the guarded arm beating both controls, and at least
one conversion in each structural class. Then run `sample-40`, `hot-400`, and
the frozen broad structural envelopes at two seconds with anti-target p95 below
1% and bootstrap lower bounds above one.

Related: [[2026-07-11-tail-opportunity-atlas]],
[[2026-07-11-novelty-exclusion-map]], and
[[2026-07-12-best-overall-qf-uf-campaign]].
