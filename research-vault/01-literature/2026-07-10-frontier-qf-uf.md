# Frontier QF_UF And SAT Engineering Watchlist

Date: 2026-07-10

Purpose: map primary papers and current solver source to falsifiable euf-viper
experiments. A citation is not evidence that an experiment will help this
corpus.

## Direct Source Audit

### Yices2

Official source snapshot:
`b11db7c43ef72f9bd77d66a9c588d3eae80eaf93`

Repository: https://github.com/SRI-CSL/yices2

Observed QF_UF mechanisms:

- dedicated e-graph architecture;
- dynamic Ackermann and Boolean Ackermann lemmas enabled by default;
- top-level equality learning through partition meet/join abstraction;
- range-constraint symmetry detection;
- explicit invariance checks using a transposition and a cycle generating the
  full permutation group;
- value/range symmetry clauses;
- theory-clause caching.

Consequence: plain congruence closure, dynamic Ackermannization, and ordinary
range/LNH symmetry are not omissions. A standalone win needs stronger finite
reasoning, lower frontend/CNF overhead, or earlier theory interaction.

Architecture paper: https://yices.csl.sri.com/papers/cav2014.pdf

### Kissat

Official source snapshot:
`8af8e56f174b778aef3aa45af9f739b2a5f492c2` (`rel-4.0.4`)

Repository: https://github.com/arminbiere/kissat

Observed mechanisms:

- clausal congruence closure over extracted AND, XOR, and ITE gates;
- repeated preprocessing/inprocessing, not just an initial pass;
- equivalent-literal substitution and proof-producing binary clauses;
- probing, vivification, elimination, sweeping, target phases, and local
  search machinery.

The project previously rejected a generic Kissat 4 backend swap. Reconsider
specific mechanisms or configurations, not an undifferentiated version bump.

## Highest-Priority Papers

### Clausal Congruence Closure

Armin Biere, Katalin Fazekas, Mathias Fleury, Nils Froleyks, SAT 2024.

- Paper: https://doi.org/10.4230/LIPIcs.SAT.2024.6
- Source artifact: https://doi.org/10.5281/zenodo.11652423
- Key point: recover gate structure from CNF, hash congruent gates, and run the
  process to completion in pre- and inprocessing.
- euf-viper experiment: simplify and structurally hash the original Boolean
  DAG before Tseitin encoding, retain gate metadata, then test CaDiCaL
  congruence/sweep options on generated CNF.
- Avoided dead ends: unrestricted HBR, tree look-ahead, simple probing, and
  blocked-clause decomposition without a new structural restriction.

### IPASIR-UP User Propagators

Katalin Fazekas et al., JAIR 2024.

- Paper:
  https://cca.informatik.uni-freiburg.de/papers/FazekasNiemetzPreinerKirchwegerSzeiderBiere-JAIR24.pdf
- Artifact: https://zenodo.org/records/13710465
- Key point: trail notifications, backtracking, delayed explanations, external
  conflicts/propagations, model checks, and theory-directed decisions.
- euf-viper experiment: a staged CaDiCaL bridge with a rollback e-graph,
  beginning with model checking and partial-trail conflicts.
- Risk: observed variables are frozen; reasons and reconstruction must remain
  proof-correct.

### CaDiCaL 2.0 And Modern Inprocessing

- CAV 2024 paper:
  https://cca.informatik.uni-freiburg.de/papers/BiereFallerFazekasFleuryFroleyksPollitt-CAV24.pdf
- SAT preprocessing survey:
  https://fmv.jku.at/papers/BiereJarvisaloKiesl-SAT-Handbook-2021-Preprocessing-Chapter-Manuscript.pdf
- euf-viper experiment: controlled `plain` versus individual simplification
  passes on invalid-model, finite-tail, hot, and full manifests.
- Required measurement: end-to-end time after preprocessing cost, not only CNF
  shrinkage.

### Detecting Cardinality Constraints In CNF

Armin Biere, Daniel Le Berre, Emmanuel Lonca, Norbert Manthey, SAT 2014.

- Paper: https://fmv.jku.at/papers/BiereLeBerreLoncaManthey-SAT14.pdf
- Key point: fast syntactic detection of at-most-one/two constraints and more
  expensive semantic detection of general at-most-k constraints.
- euf-viper experiment: do not redetect structure that the finite encoder
  already knows. Preserve it explicitly and compare native Hall/PB propagation
  with pairwise CNF.

### Exploiting Symmetry In SMT Problems

David Deharbe, Pascal Fontaine, Stephan Merz, Bruno Woltzenlogel Paleo,
CADE 2011.

- Paper: https://doi.org/10.1007/978-3-642-22438-6_18
- Key point: detect constant-permutation invariance and add range/value
  symmetry constraints.
- Current status: variants are implemented in Yices2 and euf-viper. The next
  research step is complete multi-table canonization and stabilizers.

## Finite-Model And Counting Front

### Paradox / MACE-Style Finite Model Finding

- Paper: https://fitelson.org/paradox.pdf
- euf-viper experiment: recognize fully ranged terms and closed function
  tables as a finite CSP rather than treating all constraints as anonymous CNF.

### Matching-Based AllDifferent Propagation

Jean-Charles Regin, AAAI 1994.

- Paper: https://m.aaai.org/Library/AAAI/1994/aaai94-055.php
- euf-viper experiment: Hall-set conflicts and propagation with independently
  replayable explanations.
- Soundness condition: domain exhaustiveness and distinct values must be
  proved before a matching conflict is accepted.

### Complete Symmetry Breaking For Finite Models

- AAAI 2025: https://ojs.aaai.org/index.php/AAAI/article/view/33217
- euf-viper experiment: compact canonizing permutation sets, diagonal-first
  ordering, and dynamic stabilizers for multiple function tables.
- Research gap: generalization from one operation to several functions,
  predicates, and distinguished constants.

### Symmetry-Aware Cube And Conquer

- CP 2023: https://doi.org/10.4230/LIPIcs.CP.2023.8
- euf-viper experiment: canonical table-cell cubes with explicit isomorphism
  witnesses for discarded cubes and aggregate UNSAT proofs.

### Checked Pseudo-Boolean Proofs

- CP 2025: https://doi.org/10.4230/LIPIcs.CP.2025.21
- euf-viper experiment: native PB range/AllDifferent constraints only after a
  complete proof-generation and checking path exists.

## General EUF Front

### Partial Ackermannization

- Paper: https://disi.unitn.it/rseba/papers/lpar06_ack.pdf
- Key point: no universal eager/lazy winner; select at function/component
  granularity.
- euf-viper experiment: application-interference graph, low-fill/high-reuse
  component completion, and model-directed violated cuts.

### Colored E-Graphs

- Paper: https://arxiv.org/abs/2305.19203
- euf-viper experiment: conditional congruence layers for nested branch
  intersections and guarded theory consequences.

### Small Proofs From Congruence Closure

- Paper: https://arxiv.org/abs/2209.03398
- euf-viper experiment: proof-forest explanation minimization before learning
  theory clauses; independently replay minimized explanations and fall back on
  failure.

## Experiment Priority Derived From Literature

1. Direct-root CNF and frontend/layout removal.
2. CaDiCaL pre/inprocessing ablation, especially congruence and vivification.
3. Read-only finite recognizer.
4. Native Hall/`AllDifferent` reasoning.
5. Complete multi-table canonization.
6. Model-directed component Ackermann cuts.
7. Worklist proof-forest congruence closure.
8. IPASIR-UP rollback e-graph.
9. Symmetry-aware cube and conquer for the competition-budget tail.

The literature supports these as plausible mechanisms. Only controlled WMI
gates can promote them.
