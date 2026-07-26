# Hot EUF And SAT Research Map

Date: 2026-07-26

Status: primary-source map for experiments, not a comprehensive priority audit

## Purpose

This map converts current public work into falsifiable Viper experiments. A
paper being recent or successful is not evidence that its mechanism helps
QF_UF. Every item starts as a control or opportunity census.

| Source | Established result | Viper experiment | Candidate delta | First gate |
| --- | --- | --- | --- | --- |
| [Dsat: A Native SAT Solver for Discrete Logic](https://doi.org/10.4230/LIPIcs.SAT.2026.31) | CDCL-style propagation and learning can operate directly over discrete variables rather than Boolean binarization | Native finite-domain decisions and nogoods on source-proved finite EUF components | Congruence-aware class/value reasons with checked EUF model reconstruction | Beat one-hot on unseen finite scaling before corpus timing |
| [Simplify, Order, Break, Repeat](https://doi.org/10.4230/LIPIcs.SAT.2026.4) | Unit/binary symmetry cuts can simplify a formula and expose further symmetries; reported SAT Competition PAR-2 gains are substantial | Generic SORB control followed by EUF rewriting and a second typed symmetry round | Automorphisms exposed by dynamic equality classes and application rows | Produce a replay-valid second-round cut absent from SORB and one-shot controls |
| [Factoring Learned Clauses](https://doi.org/10.4230/LIPIcs.SAT.2026.28) | Modern extended-resolution factoring can help hard combinatorial families without broad SAT Competition degradation | Generic factoring, XOR/ITE factoring, and exact EUF motif census | Define only recurring concrete congruence paths or application rows generic factoring misses | At least 25% conflict-weighted motif coverage and 20% projected literal reduction |
| [CaDiCaL 3.0](https://doi.org/10.4230/LIPIcs.SAT.2026.40) | Kissat techniques, clausal congruence, equivalence sweeping, BVA, proof logging, and deterministic ticks scheduling coexist in an incremental solver | Identical-CNF backend and scheduling factorial | Theory-aware tick charges and route-local schedules | End-to-end gain with proof/model checks on two CPU classes |
| [Clausal Congruence Closure](https://doi.org/10.4230/LIPIcs.SAT.2024.6) | Gate extraction plus congruence closure removes redundant isomorphic CNF structure, including structure exposed during solving | Run as a generic structural control on Viper-emitted CNF | Cross the Boolean/EUF boundary using source-stable typed identities | EUF-aware arm must beat ordinary clausal congruence on exact same CNF population |
| [Small Proofs from Congruence Closure](https://arxiv.org/abs/2209.03398) | A practical greedy method can shrink congruence proofs without asymptotic overhead | Greedy short-proof control for every theory reason | Select reasons by measured SAT impact while preserving short certificates | Nonzero replay-valid choice, lower downstream work, and inclusive timing gain |
| [Simplified and Verified proof-producing union-find](https://arxiv.org/abs/2504.10246) | A proof-producing union-find explain operation has a machine-checked soundness/completeness development | Audit Viper's representation-neutral proof events against the verified conceptual boundary | Compact replay-oriented source-term proof arena | Differential proof replay through all bounded partition states |
| [IPASIR-UP and satisfiability modulo user propagators](https://doi.org/10.1613/JAIR.1.16163) | CDCL can host external propagators with reasons through a disciplined interface | Lazy-first and propagation controls against eager encoding | Source-stable EUF reasons that survive Viper's quotient representations | Zero unreplayable reasons and target speedup without easy-head loss |
| [SMT-COMP 2025 processed results](https://smt-comp.github.io/2025/results/) | Official selections and processed data define the external comparison surface | Keep exact official QF_UF selection and refresh new entries | None; this is measurement infrastructure | Hash-bound ingestion and complete comparator accounting |

## Prior-Art Boundaries

The following are not novelty claims by themselves:

- eager Ackermann or finite encodings;
- rollback congruence closure and DPLL(T);
- one-hot, cardinality, Hall, or pseudo-Boolean reasoning;
- symmetry breaking, SORB, or lex leaders;
- extended resolution, BVA, vivification, and clausal congruence closure;
- proof-producing union-find or greedy short explanations;
- PGO, arena allocation, compact IDs, SIMD, or hardware-aware scheduling; and
- portfolios or representation migration in general.

The defensible candidate contributions are narrower compositions:

1. source-complete canonical quotient residual memoization across different
   Boolean histories;
2. orbit-invariant native CDCL learning over typed EUF partitions with only
   stable source-level reasons;
3. proof-carrying compilation of bounded equality resolution whose internal
   equalities need not exist in the source atom map;
4. repeated semantic symmetry after EUF rewriting, with checked redundancy
   witnesses; and
5. eventually, proof-carrying component-local representation migration, but
   only if fixed-arm oracle headroom becomes large enough.

## Research Watch

At the start of each broad step, check:

1. the latest SMT-COMP QF_Equality/QF_UF result and solver submissions;
2. SAT/SMT/CADE/CAV/FMCAD proceedings for equality reasoning, proof logging,
   discrete CDCL, symmetry, clause factoring, and solver scheduling;
3. current CaDiCaL, Kissat, Yices2, Z3, cvc5, and OpenSMT release notes;
4. proof formats and checker changes relevant to DRAT, LRAT, Alethe, or CPC;
5. whether a claimed Viper delta has appeared in a paper, dissertation,
   artifact, issue, or source branch since the previous audit.

Only primary papers, official documentation, solver source, and competition
artifacts can promote or invalidate a novelty statement. Search snippets and
secondary summaries can identify leads but are not claim evidence.
