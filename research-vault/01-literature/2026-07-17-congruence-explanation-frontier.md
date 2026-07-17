# Congruence Explanation Frontier For T11

Date: 2026-07-17

## Primary sources

- Tveretina and Zantema, *A Proof System and a Decision Procedure for Equality
  Logic*: <https://pure.tue.nl/ws/files/2252462/200302.pdf>
- Nieuwenhuis and Oliveras, *Proof-Producing Congruence Closure*:
  <https://www.cs.upc.edu/~oliveras/rta05.pdf>
- Nieuwenhuis and Oliveras, *Fast Congruence Closure and Extensions*:
  <https://www.cs.upc.edu/~oliveras/IC.pdf>
- Bryant, German, and Velev, *Exploiting Positive Equality in a Logic of
  Equality with Uninterpreted Functions*:
  <https://www.cs.cmu.edu/~bryant/pubdir/cav99a.pdf>
- Bryant and Velev, *Boolean Satisfiability with Transitivity Constraints*:
  <https://www.cs.cmu.edu/~bryant/pubdir/tocl-trans01.pdf>
- Rodeh and Strichman, *Building Small Equality Graphs for Deciding Equality
  Logic with Uninterpreted Functions* / Minimal-E encoding:
  <https://www.cs.bgu.ac.il/~mcodish/jsatornot/IC05.pdf>
- Rozanov and Strichman, *Efficient Generation of Reduced Transitivity
  Constraints*:
  <https://ofers.dds.technion.ac.il/publications/smt07.pdf>
- Fellner, Fontaine, and Woltzenlogel Paleo, *NP-completeness of Small Conflict
  Set Generation for Congruence Closure*:
  <https://link.springer.com/article/10.1007/s10703-017-0283-x>
- Flatt, Coward, Willsey, Tatlock, and Panchekha, *Small Proofs from Congruence
  Closure*: <https://arxiv.org/abs/2209.03398>
- Andreotti and Barbosa, *Producing Shorter Congruence Closure Proofs in a
  State-of-the-Art SMT Solver*:
  <https://www.hanielbarbosa.com/papers/2026vmcai.pdf>

## Consequences for T11

Equality resolution is already a sound and complete clause-level proof system
for equality CNF. T11 can use that rule, but not claim it. A proof node must
carry the side literals of the exact clause containing its positive equality;
otherwise the compiler silently assumes a conditional equality.

Proof-producing congruence closure can recover a (k)-step explanation in
quasi-linear time without changing the classical (O(n\log n)) closure bound.
This supports a replayable trace design, but it also means that proof production
itself is not novel.

Deciding whether a congruence explanation of size at most (k) exists is
NP-complete, so computing a smallest explanation is NP-hard. The T11 search may
retain bounded support antichains and deterministic greedy priorities, but it
must not promise minimal explanations. Exhaustive or optimal proof search is
incompatible with the final 8ms compiler budget.

Flatt et al. provide an (O(n^5)) optimal tree-size algorithm and a practical
(O(n\log n)) greedy alternative. Andreotti and Barbosa adapt the greedy idea
to cvc5, including redundant congruence edges and fuel-bounded recursive
explanations. Their evaluation is an important negative control: explanation
sizes improve, but aggregate runtime rises about 45.59% overall and 29.85% in
their non-array/non-string grouping. They also report isolated families with
large speedups. T11 therefore routes only the frozen structural tail and caps
every queue, support set, and proof arena.

The cvc5 work identifies implicit dependencies created by SAT propagation and
uses edge levels to prevent circular explanations. T11's clause-level trace
must instead preserve exact parent clause IDs and topological proof order. An
equality derived from a T11 output clause cannot justify itself or an ancestor.

Positive equality, sparse transitivity, Minimal-E, and RTC are separate prior
techniques. T11 v1 does not add a positive-equality arm, BCC/Minimal-E pruning,
or a triangle fallback. Their inclusion would create unregistered degrees of
freedom and obscure whether clause-level equality resolution is responsible
for any result.

## Novelty discipline

The only plausible novelty is architectural: a source-structural router plus a
bounded static equality-resolution compiler whose missing equalities remain
proof-internal, whose exported clauses use only baseline variables, and whose
UNSAT result is accepted only after independent theory-trace checking and,
whenever a SAT backend is called, independent SAT-proof checking. A checked
theory-empty trace is terminal without a fictitious SAT proof. This remains a
hypothesis until closest-code inspection, held-out tests, and component
ablations show that the complete combination is absent from existing solvers
and materially improves results.
