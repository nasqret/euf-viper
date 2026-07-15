# PoS 2026 DDFW Boundary

Date: 2026-07-15

Primary source: Florian Pollitt, Mathias Fleury, Andre Schidler, Armin Biere,
Johannes Grober, Jakob Peterson, Rico Andris, and Lea Hohl,
[*Improving Local Search and adding DDFW to CaDiCaL*](https://cca.informatik.uni-freiburg.de/papers/PollittFleurySchidlerBiereGroeberPetersonAndrisHohl-POS26.pdf),
PoS 2026.

## What The Paper Changes

The paper ports modern DDFW/TaSSAT local search into CaDiCaL, uses deterministic
tick budgets, describes flip caching already present in Kissat, and reports a
broad gain from DDFW plus rephasing. The mechanism is incomplete SAT search and
exchanges heuristic assignments with CDCL. It neither proves UNSAT nor searches
typed EUF interpretations.

This strengthens the project's required control. DDFW, target phases,
rephasing, assignment import, and generic local-search/CDCL exchange are not a
novel contribution for euf-viper.

## Opportunity Check

The frozen common deficit contains six SAT Goel sources and sixteen UNSAT
sources. Direct SAT discovery can therefore recover at most six, below the ten
conversions needed to lead Z3 and the 21 needed to lead Yices2. At 60 seconds,
euf-viper's common-time deficit against Yices2 is `739.461s` on SAT and
`2,624.977s` on UNSAT. The dominant problem remains UNSAT proof search.

The six SAT misses are non-table `GRAPH_2500` Goel formulas, while the available
checked finite-search machinery is bounded and does not cover that population.
The twelve qg7 misses are UNSAT and have no checked non-Boolean range from T4.
Building a semantic DDFW engine now therefore fails the opportunity gate before
implementation.

## Reopen Falsifier

Retain one oracle upper-bound experiment only:

1. forced CaDiCaL with no imported phases;
2. the same binary and options with deterministically shuffled source phases;
3. phases projected from a complete, independently source-validated EUF model,
   with projection and import time charged.

Use the six SAT common misses for efficacy, all 39 frozen `GRAPH_2500` sources
for matched controls, and PEQ012 plus twelve qg7 sources as UNSAT anti-targets.
Reopen implementation only if the perfect-model arm beats both controls,
converts at least one 60-second SAT timeout, reaches `2x` median speed, causes
zero baseline-only loss, and stays below `1%` p95 phase overhead.

Only phases may cross into CDCL. Failed semantic states cannot become clauses,
conflicts, pruning, or UNSAT evidence. Any direct SAT answer still requires a
complete typed interpretation checked against every source assertion.

## Decision

No DDFW implementation, production route, or WMI campaign. Keep the oracle as a
conditional falsifier, not an active plan item.
