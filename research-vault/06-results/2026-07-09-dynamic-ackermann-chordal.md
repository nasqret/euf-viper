# Dynamic Ackermann and Chordal Completion

Date: 2026-07-09

## Question

Can a modern eager SAT route recover the non-finite Goel tail without
regressing the dominant QG fast path?

## Construction

After a first Kissat assignment fails full EUF validation, selected formulas
are rebuilt with direct root clauses. For applications of the same function,
the candidate emits the Ackermann implication

$$
\bigwedge_i a_i=b_i \Longrightarrow f(\bar a)=f(\bar b),
$$

using equivalence for Boolean-valued applications. It then applies bounded
minimum-degree chordal fill to the equality graph and emits triangle
transitivity clauses. SAT results are still checked by full congruence closure;
UNSAT uses only base clauses and sound EUF consequences.

The automatic route requires no finite-domain axioms, at least 100,000 base
clauses, and at most 256 applications. `EUF_VIPER_FULL_ACKERMANN=on|off` and
`EUF_VIPER_CHORDAL_MAX_FILL` are explicit experiment controls.

Literature anchor: Bryant and Velev, *Boolean Satisfiability with Transitivity
Constraints*, https://arxiv.org/abs/cs/0008001.

## Controlled Iterations

| Gate | Candidate | Coverage result | Decision |
|---|---|---:|---|
| `140140`/`140144` | forced completion, five Goel gaps | 0 to 5 | route signal only |
| `140191`/`140196` | unconditional completion, hard 35 | 11 to 17 | reject speed regression |
| `140413`/`140418` | dynamic completion, hard 35 | 12 to 19 | retain |
| `140673`/`140693` | dynamic completion, Goel 773 | 735 to 741 | retain |
| `140803`/`140808` | pre-Fx full 7,503 | 7,045 to 7,039 | reject |
| `141883`/`141888` | Fx candidate, stable hot 400 | 396 to 397 | pass |
| `141902`/`141907` | Fx candidate, hard 35 | 12 to 17 | pass targeted gate |
| `141911`/`141916` | exact candidate, full 7,503 | 6,993 to 7,002 | accept |

Cold-code-only and thin-LTO-only candidates were also rejected after
`141116`/`141121`, `141708`/`141713`, and `141872`/`141877` failed at least one
coverage or speed criterion.

## Accepted Full Gate

- Corpus: SMT-LIB 2025 QF_UF, 7,503 instances.
- Timeout: 2 seconds per binary, one repeat, no warm-up.
- Observations: 15,006, all present.
- Baseline correct: 6,993.
- Candidate correct: 7,002, delta +9.
- All-instance totals: 2,309.1185s to 2,270.6504s, 1.0169x.
- Common-correct totals: 1,243.0053s to 1,202.5552s, 1.0336x.
- Geometric speedup: 1.0961x.
- Pairwise wins: candidate 5,356, baseline 1,610.
- Wrong answers: 0.
- Execution errors: 0.
- Candidate binary SHA-256:
  `f45b51ec65c36ca3df63397ba22a078c0e8490041c5e504f68ff9c2982a77a2d`.
- Local ignored evidence:
  `results/wmi/dynamic-ack-fx-full-141911/`.

## Interpretation

This accepts the iteration relative to the preceding standalone binary: it
raises coverage and passes timeout-inclusive, common-aggregate, and geometric
speed gates simultaneously. It does not establish a fresh comparison with Z3,
cvc5, or Yices and does not supersede the older 1,200-second boundary. The next
required campaign is a longer-timeout rerun, followed by a separate attack on
the remaining finite-model tail.
