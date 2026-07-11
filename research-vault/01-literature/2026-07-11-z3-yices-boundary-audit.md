# Z3 and Yices2 QF_UF Boundary Audit

**Date:** 2026-07-11

**Purpose:** establish the implementation boundary that euf-viper must exceed, not merely reproduce.

**Scope:** public, current Z3 and Yices2 source and first-party documentation for quantifier-free equality with uninterpreted functions (QF_UF). The audit covers parsing and rewriting, e-graphs, partial-trail propagation, equality learning, Ackermann lemmas, symmetry, model construction, SAT integration, proof support, and one-shot optimizations.

## Source snapshot and evidence policy

The source audit is pinned so that line-level claims remain reproducible:

- **Z3:** commit [`efe5e946f16ec223a91d15101cefc49fb197534d`](https://github.com/Z3Prover/z3/commit/efe5e946f16ec223a91d15101cefc49fb197534d), committed 2026-07-10.
- **Yices2:** commit [`b11db7c43ef72f9bd77d66a9c588d3eae80eaf93`](https://github.com/SRI-CSL/yices2/commit/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93), committed 2026-07-08.

Evidence labels used throughout:

- **[C] Confirmed implementation:** directly visible in the pinned source.
- **[D] Confirmed documentation:** stated by a first-party manual, architecture paper, or official design note.
- **[I] Inference:** a conclusion from control flow or composition, not an explicit upstream claim.
- **[N] Negative audit result:** no corresponding mechanism was found in the named route and searched source. This is not proof of global absence.

Current source controls implementation claims. Older first-party papers are used only to explain intent or provenance. In particular, Z3's classic SMT core and its newer SAT-owned EUF core are audited separately because the latter is not the default QF_UF route.

## Executive boundary

| Area | Z3 current public implementation | Yices2 current public implementation | Boundary for euf-viper |
|---|---|---|---|
| Parsing and rewriting | Generic SMT-LIB parser builds shared ASTs; hash-consing, canonical constructors, cached rewriting, then a QF_UF tactic pipeline. | SMT-LIB term stack calls simplifying constructors backed by a global hash-consed term table, then context preprocessing. | A DAG parser plus local simplification is baseline infrastructure, not novelty. |
| E-graph | Classic SMT context owns rollback congruence closure; optional `sat.smt` path owns a separate EUF e-graph. | Dedicated rollback e-graph attached to a custom SMT/CDCL core. | Rollback congruence closure, parent reindexing, and causal explanations are excluded mechanisms. |
| Partial-trail propagation | Boolean propagation, equality propagation, congruence propagation, and theory propagation alternate to a fixed point during search. | SAT assignments are asserted into the e-graph; Boolean and theory propagation alternate to a fixed point at each trail prefix. | "EUF on the partial SAT trail" is already central to both solvers. |
| Equality learning | `solve-eqs`, value propagation, local-context simplification, and in-search congruence propagation. No Yices-style partition abstraction was found in the audited QF_UF path. | Pre-search abstract interpretation over equality partitions computes equalities common to Boolean branches and feeds them back as auxiliary equalities. | Yices-style meet/join equality abstraction is expressly excluded as a novelty claim. |
| Ackermann lemmas | Conflict/use-count selected dynamic congruence and optional equality-transitivity lemmas in both classic and optional EUF cores. | Collision/conflict-hit selected Boolean and non-Boolean Ackermann clauses, with per-kind limits and an auxiliary-equality quota. | Dynamic Ackermannization, including separate predicate clauses, thresholds, caches, and quotas, is excluded. |
| Symmetry | Formula-invariance checked permutations of similarly colored uninterpreted constants; emits membership constraints. Disabled with proofs or unsat cores in the QF_UF tactic. | Detects finite range constraints, verifies invariance under generators, and emits cost-selected range/membership constraints in one-check mode. | Constant/value permutation symmetry and membership constraints are excluded. |
| Model construction | Assigns values to relevant e-classes; observed applications become finite function entries; partial functions receive an `else` value. Optional EUF core has a dependency-sorted version. | Assigns every root class; builds observed function maps and an arbitrary QF_UF default; creates fresh anonymous values where needed. | E-class-to-finite-model construction with observed maps and arbitrary defaults is excluded. |
| SAT integration | Default classic CDCL(T) context; optional SAT-owned EUF core internalizes Boolean terms and exchanges explanations/lemmas directly with SAT. | Custom CDCL core exposes callbacks for trail levels, atom assertion, propagation, explanations, final checks, and clause insertion. | Tight custom SAT/EUF integration is not novel by itself. |
| Proofs | Classic proof objects; optional RUP/DRAT-style trace support and EUF proof hints checked by a union-find plugin, with documented fallback caveats. | SMT-LIB accepts the command syntax but current frontend explicitly reports `get-proof` unsupported. | A low-overhead, independently checkable end-to-end certificate remains differentiated, but "Z3 has no EUF proof machinery" would be false. |
| One-shot specialization | QF_UF-specific tactic preamble, symmetry, and search parameters. | One-check-only symmetry, variable elimination, equality abstraction, staged internalization, dynamic Ackermann defaults, and short theory-clause caching. | Static preprocessing portfolios and one-shot special cases are excluded unless a new interface materially changes them. |

## Z3 boundary

### 1. Default route is the classic SMT core

- **[C]** The strategic solver maps logic `QF_UF` to `mk_qfuf_tactic` in [`smt_strategic_solver.cpp:mk_tactic_for_logic`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/tactic/portfolio/smt_strategic_solver.cpp#L67-L70).
- **[C]** [`qfuf_tactic.cpp:mk_qfuf_tactic`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/tactic/smtlogics/qfuf_tactic.cpp#L27-L37) runs, in order: general simplification, value propagation, equation solving, another simplification with cheap ITE pulling and a large local-context limit, symmetry reduction when proofs and cores are disabled, then `mk_smt_tactic`.
- **[C]** [`smt_params.cpp:smt_params::setup_QF_UF`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/params/smt_params.cpp#L198-L204) selects QF_UF-specific relevance, CNF, restart, phase, and initial-activity settings.
- **[C]** The newer SAT-based incremental SMT core is opt-in: [`sat_params.pyg`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/params/sat_params.pyg#L49-L55) declares `sat.smt` with default `false`.

**Boundary conclusion:** the default comparison target is a preprocessed classic CDCL(T) solver. Results obtained against default Z3 must not be explained as beating the optional SAT-owned EUF implementation unless `sat.smt=true` is benchmarked separately.

### 2. Parsing, DAG construction, and rewriting

- **[C]** [`smt2parser.cpp:parse_expr`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/parsers/smt2/smt2parser.cpp#L2213-L2270) is an iterative frame-based SMT-LIB expression parser. Applications are constructed through the command context in [`pop_app_frame`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/parsers/smt2/smt2parser.cpp#L1987-L2043); `let` bindings are scoped to already-built ASTs rather than retained as solver nodes ([`smt2parser.cpp`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/parsers/smt2/smt2parser.cpp#L2048-L2084)).
- **[C]** [`ast_manager::register_node_core`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/ast/ast.cpp#L1663-L1689) hashes a node and inserts it only if absent. [`ast_manager::mk_app_core`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/ast/ast.cpp#L2115-L2165) routes applications through this table, while [`ast_manager::mk_app`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/ast/ast.cpp#L2186-L2238) normalizes chainable and associative declaration shapes before construction.
- **[C]** The generic rewriter caches completed subterm rewrites and invokes family-specific `reduce_app` callbacks; see [`rewriter_def.h`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/ast/rewriter/rewriter_def.h#L133-L229) and its application reduction loop ([`rewriter_def.h`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/ast/rewriter/rewriter_def.h#L267-L327)).

**Boundary conclusion:** structural sharing, constructor normalization, constant folding, and memoized bottom-up rewriting are mature Z3 mechanisms. A claimed advance must be more specific than "parse once into a DAG" or "simplify before SAT." A genuinely different path would have to avoid or exploit a boundary that the generic AST-plus-tactic architecture cannot, and demonstrate that advantage in parser-inclusive timing.

### 3. Classic e-graph and partial-trail propagation

- **[C]** EUF congruence closure is integrated into `smt::context`, not exposed as a separate classic `theory_uf` module. [`context::add_eq`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/smt/smt_context.cpp#L481-L595) merges roots, prefers the larger class except for interpreted/value-root constraints, trails mutations, removes stale parent signatures, relabels the smaller class, reinserts parents, and propagates Boolean consequences.
- **[C]** [`context::reinsert_parents_into_cg_table`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/smt/smt_context.cpp#L661-L728) detects newly congruent parent applications, queues equality propagation, and can notify dynamic Ackermannization when a congruence is the root of a conflict.
- **[C]** Boolean terms participate in equivalence classes. [`context::propagate_bool_enode_assignment`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/smt/smt_context.cpp#L912-L970) propagates an assigned Boolean value across a merge and records a congruence justification.
- **[C]** [`context::propagate`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/smt/smt_context.cpp#L1815-L1855) interleaves Boolean constraint propagation, atom propagation, equality propagation, theory equality/disequality propagation, and theory propagators. The search loop repeats propagation and conflict resolution before choosing another decision ([`smt_context.cpp`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/smt/smt_context.cpp#L4113-L4187)).
- **[D]** The official [Z3 Internals draft](https://z3prover.github.io/papers/z3internals.html#equality-and-uninterpreted-functions) documents unique DAG nodes, union-find plus an e-table, lesser-half merging, undo trails, justification forests, and Boolean propagation through congruence closure. The public implementation above confirms those mechanisms in the pinned tree.

**Boundary conclusion:** a rollback e-graph attached to the current SAT trail, including Boolean-as-data propagation and causal explanations, is a direct reproduction of Z3's core design.

### 4. Equality learning and one-shot equation elimination

- **[C]** The QF_UF preamble already performs `propagate-values`, `solve-eqs`, and local-context simplification before search ([`qfuf_tactic.cpp`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/tactic/smtlogics/qfuf_tactic.cpp#L27-L37)). [`solve_eqs_tactic.h:mk_solve_eqs_tactic`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/tactic/core/solve_eqs_tactic.h#L73-L82) wraps the shared `euf::solve_eqs` simplifier.
- **[N]** A targeted search of the QF_UF tactic, classic SMT core, and core tactics found no `epartition`, equality-partition abstract domain, or Yices-style branch meet/join equality learner.
- **[I]** Z3 therefore has substantial equality preprocessing and in-search equality propagation, but the audited default route does not expose the same pre-search global branch-intersection abstraction used by Yices. This is a narrow route-level distinction, not a claim that no semantically equivalent transformation exists anywhere in Z3.

**Boundary conclusion:** plain substitution, solved-form elimination, and local-context rewriting are excluded. A new equality-learning claim must specify what information it derives beyond these operations and beyond Yices's partition abstraction below.

### 5. Dynamic Ackermann learning

- **[C]** Z3's default classic SMT configuration enables dynamic Ackermannization mode 1: instantiate the congruence/Leibniz clause when a congruence is the root of a conflict. The current defaults and thresholds are explicit in [`smt_params_helper.pyg`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/params/smt_params_helper.pyg#L128-L136).
- **[C]** [`dyn_ack`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/smt/dyn_ack.h#L91-L124) receives congruence-use, congruence-conflict, equality-use, and propagation events. Candidate pairs accumulate occurrences ([`dyn_ack.cpp`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/smt/dyn_ack.cpp#L197-L230)); propagation is budgeted relative to conflict count ([`dyn_ack.cpp`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/smt/dyn_ack.cpp#L375-L396)).
- **[C]** [`dyn_ack_manager::instantiate`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/smt/dyn_ack.cpp#L407-L444) adds the standard congruence clause from argument equalities to result equality, with proof justification. An optional path also learns equality-transitivity clauses ([`dyn_ack.cpp`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/smt/dyn_ack.cpp#L463-L503)).

**Boundary conclusion:** conflict-triggered or occurrence-threshold Ackermann clauses are not an abandoned idea absent from Z3. Novelty would require a materially different selection signal, representation, or SAT/e-graph feedback loop, and must beat this default rather than an Ackermann-disabled baseline.

### 6. Symmetry breaking

- **[C]** The default QF_UF tactic invokes symmetry reduction only when neither proofs nor unsat cores are requested ([`qfuf_tactic.cpp`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/tactic/smtlogics/qfuf_tactic.cpp#L32-L37)).
- **[C]** The implementation identifies itself as a literal adaptation of the veriT algorithms ([`symmetry_reduce_tactic.cpp`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/tactic/core/symmetry_reduce_tactic.cpp#L1-L20)). It normalizes associative/commutative terms, colors candidates by sort, occurrence, and depth, requires repeated constants, verifies formula invariance under candidate permutations, selects terms, and adds membership predicates ([`symmetry_reduce_tactic.cpp:imp::operator()`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/tactic/core/symmetry_reduce_tactic.cpp#L120-L159), [`find_candidate_permutations`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/tactic/core/symmetry_reduce_tactic.cpp#L171-L196)).
- **[C]** The tactic itself rejects proof, core, and quantified goals ([`symmetry_reduce_tactic.cpp`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/tactic/core/symmetry_reduce_tactic.cpp#L608-L617)).

**Boundary conclusion:** detecting interchangeable uninterpreted constants and adding verified membership constraints is already upstream. Orbit quotienting, proof-carrying canonicalization, or SAT-variable identification would be different interfaces; a renamed membership scheme would not be.

### 7. Model construction

- **[D]** [Programming Z3, EUF Models](https://z3prover.github.io/papers/programmingz3.html#euf-models) describes one distinct value per required equivalence class, finite tables for observed function applications, and an `else` value for all unobserved arguments.
- **[C]** The classic model generator assigns Boolean values, existing model values, theory-produced values, or fresh values to relevant e-class roots in [`model_generator::mk_value_procs`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/smt/smt_model_generator.cpp#L89-L147). It dependency-sorts value producers before materialization ([`smt_model_generator.cpp`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/smt/smt_model_generator.cpp#L267-L341)).
- **[C]** [`model_generator::mk_func_interps`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/smt/smt_model_generator.cpp#L420-L469) inserts entries for relevant congruence-root applications. [`proto_model::complete_partial_func`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/smt/proto_model/proto_model.cpp#L341-L370) completes a partial function using a fresh value, the most frequent result, or another value of the range sort.
- **[C]** The optional SAT-owned EUF model path similarly dependency-sorts e-nodes, assigns fresh user-sort values, and inserts observed function entries; see [`euf_model.cpp:solver::update_model`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/sat/smt/euf_model.cpp#L79-L101), [`dependencies2values`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/sat/smt/euf_model.cpp#L152-L214), and [`values2model`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/sat/smt/euf_model.cpp#L216-L263).

**Boundary conclusion:** SAT-result validation by constructing a finite EUF model is necessary engineering, not a novel solver mechanism. A differentiated model path must change search, certification, incremental reuse, or asymptotic cost rather than merely emit the standard finite interpretation.

### 8. Optional SAT-owned EUF core

- **[C]** With `sat.smt=true`, [`euf::solver::solver`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/sat/smt/euf_solver.cpp#L43-L82) owns an e-graph and installs propagation and merge callbacks.
- **[C]** Internalization recursively creates e-nodes, attaches SAT literals to Boolean nodes, and marks SAT variables as external; see [`euf_internalize.cpp`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/sat/smt/euf_internalize.cpp#L37-L201). [`solver::mk_enode`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/sat/smt/euf_internalize.cpp#L485-L525) explicitly enables true/false merging for Boolean arguments used as data by non-Boolean functions.
- **[C]** [`solver::asserted`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/sat/smt/euf_solver.cpp#L446-L494) maps a SAT assignment to an e-graph value, merges Boolean terms with true/false, and processes equality atoms as merges or disequalities. [`unit_propagate`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/sat/smt/euf_solver.cpp#L508-L536) reports e-graph conflicts and propagates consequences. [`get_antecedents`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/sat/smt/euf_solver.cpp#L279-L328) expands EUF and theory explanations for SAT.
- **[C]** The optional core also has frequency-selected Ackermann clauses in [`euf_ackerman.cpp`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/sat/smt/euf_ackerman.cpp#L170-L225).

**Boundary conclusion:** moving an e-graph "inside" a modern SAT solver, exposing SAT literals on Boolean e-nodes, and asking the e-graph for antecedents are all present in current Z3 source. An euf-viper SAT integration claim must identify a stronger interface than ownership and callback placement.

### 9. Proof support

- **[D]** [Programming Z3, Proofs](https://z3prover.github.io/papers/programmingz3.html#proofs) states that the Solver interface can return natural-deduction-style proof objects when proof production is enabled.
- **[C]** The QF_UF tactic preserves the proof-capable classic SMT path but skips symmetry reduction when proofs are enabled ([`qfuf_tactic.cpp`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/tactic/smtlogics/qfuf_tactic.cpp#L32-L37)).
- **[C]** The SAT parameters expose DRAT output, internal unsat checking, SAT-model checking, and on-the-fly SMT proof checking ([`sat_params.pyg`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/params/sat_params.pyg#L49-L55)).
- **[C]** [`euf_proof_checker.cpp:eq_theory_checker`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/sat/smt/euf_proof_checker.cpp#L35-L63) specifies timestamp-ordered congruence claims and checks equality consequences with a small union-find checker; the implementation checks equalities, disequalities, congruence premises, and distinct values in [`eq_theory_checker::check`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/sat/smt/euf_proof_checker.cpp#L151-L219).
- **[C]** The proof-command framework checks RUP steps and custom proof hints, but its own header comment says unsupported or failed custom checks may fall back to asking SMT whether a conclusion follows, which is weaker self-validation ([`proof_cmds.cpp`](https://github.com/Z3Prover/z3/blob/efe5e946f16ec223a91d15101cefc49fb197534d/src/cmd_context/extra_cmds/proof_cmds.cpp#L18-L36)).
- **[I]** Z3 therefore has real EUF proof machinery, but the audited optional path should not be described as an independently verified, standardized external certificate pipeline without separately establishing the exact output mode and checker trust base used in an experiment.

**Boundary conclusion:** "emit a DRAT trace" or "check congruence with union-find" alone is not novel. A credible differentiator is an end-to-end, independently replayable certificate that also covers preprocessing and symmetry without solver fallback, with measured low overhead.

## Yices2 boundary

### 1. QF_UF defaults and one-check configuration

- **[C]** The API's logic table maps `QF_UF` to the pure e-graph architecture `CTX_ARCH_EG` ([`context_config.c:logic2arch`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/api/context_config.c#L140-L201)).
- **[C]** [`context_set_default_options`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/api/yices_api.c#L8837-L8906) enables variable elimination and equality abstraction for contexts. For the e-graph architecture it enables disequality/OR flattening and, in `CTX_MODE_ONECHECK`, symmetry breaking.
- **[C]** [`yices_set_default_params`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/api/yices_api.c#L9456-L9470) enables Boolean dynamic Ackermannization, non-Boolean dynamic Ackermannization, and theory-clause caching up to size 12 for `CTX_ARCH_EG`.
- **[D]** The first-party [Yices 2.2 architecture paper](https://yices.csl.sri.com/papers/cav2014.pdf) describes a CDCL SAT solver with theory-created literals, theory clauses, theory propagation, an explanation-producing UF e-graph, Boolean terms in the e-graph, dynamic Ackermannization, and QF_UF symmetry preprocessing. The pinned source confirms that these mechanisms remain active.

**Boundary conclusion:** benchmark Yices2 with its normal QF_UF defaults. Disabling equality abstraction, symmetry, dynamic Ackermannization, or theory-clause caching creates an ablation target, not the competitor.

### 2. Parsing, constructor simplification, and global term sharing

- **[D]** The Yices architecture paper states that Yices maintains a global term/type database, uses compact structures, and hash-conses terms to maximize subterm sharing ([paper, architecture section](https://yices.csl.sri.com/papers/cav2014.pdf)).
- **[C]** The SMT-LIB term stack rewrites chainable equality syntax before construction ([`smt2_term_stack.c`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/frontend/smt2/smt2_term_stack.c#L428-L464)) and maps generic symbol application to `MK_APPLY` ([`smt2_term_stack.c`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/frontend/smt2/smt2_term_stack.c#L2045-L2073)).
- **[C]** [`mk_eq`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/terms/term_manager.c#L3846-L3887) performs type-specific equality construction, reflexivity/distinctness simplification, and canonical operand ordering. [`mk_application`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/terms/term_manager.c#L4015-L4067) simplifies function updates before calling the raw constructor.
- **[C]** [`app_term`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/terms/terms.c#L2124-L2146) builds applications through the term hash table, and the term table explicitly owns a hash-consing table ([`terms.h`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/terms/terms.h#L470-L508)).

**Boundary conclusion:** constructor-level simplification and maximal term sharing are not missing Yices optimizations. A stream-native euf-viper frontend is interesting only if it proves a measurable advantage over this global term-table path or enables a representation unavailable after generic construction.

### 3. One-shot preprocessing order

- **[C]** [`context_process_assertions`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/context.c#L6840-L6973) first flattens assertions. For `CTX_ARCH_EG`, it then runs UF symmetry breaking, equality abstraction, auxiliary-equality processing, and candidate substitution before building sharing data.
- **[C]** Internalization is staged: pre-internalized terms, top-level equalities, other atoms, then non-atomic formulas, with base-level propagation after each group ([`context.c`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/context.c#L6974-L7057)).

**Boundary conclusion:** "preprocess all asserted formulas once, internalize equalities first, and propagate between stages" is already a concrete Yices one-shot optimization. Euf-viper must either improve its cost/benefit control or establish a different representation boundary.

### 4. Global equality learning by abstract interpretation

- **[C]** [`eq_learner.c`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/eq_learner.c#L19-L22) explicitly analyzes a UF formula to learn global equalities implied by it and represents the result as an equality partition.
- **[C]** For a positive OR, [`eq_abstract_or`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/eq_learner.c#L152-L197) takes the join of branch abstractions, retaining equalities common to every disjunct. For a negated OR, it takes the meet of the conjunct abstractions. The partition API defines meet as the closure of equalities from either input and join as equalities common to both ([`eq_abstraction.h`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/eq_abstraction.h#L158-L206)).
- **[C]** Boolean equality and ITE are abstracted compositionally using meet and join in [`eq_abstract_eq`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/eq_learner.c#L218-L271) and [`eq_abstract_ite`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/eq_learner.c#L274-L313).
- **[C]** `analyze_uf` invokes the learner over top-level formulas and converts learned classes into auxiliary equalities before substitution and internalization ([`context_simplifier.c`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/context_simplifier.c#L2744-L2794)).

**Boundary conclusion:** learning branch-invariant equalities with a partition lattice is a current Yices default, not a fresh "abandoned" technique. A successor must go beyond the same meet/join domain, for example by learning conditional equalities, disequality structure, cardinality, or proof-cost information without losing its near-linear behavior.

### 5. Rollback e-graph and partial-trail SAT integration

- **[D]** The architecture paper states that the UF solver uses congruence closure with explanations, stores Boolean terms, and can propagate disequalities through congruence ([Yices 2.2, solver architecture](https://yices.csl.sri.com/papers/cav2014.pdf)).
- **[C]** The context initializes an SMT core with e-graph control and SMT callback interfaces ([`context.c`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/context.c#L6350-L6377)). Those interfaces include start, propagation, final check, level, backtrack, push/pop, atom assertion, explanation expansion, and polarity selection ([`smt_core.h`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/solvers/cdcl/smt_core.h#L600-L657)).
- **[C]** [`theory_propagation`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/solvers/cdcl/smt_core.c#L2753-L2805) sends newly assigned theory atoms to the e-graph and invokes its propagation routine. [`smt_propagation`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/solvers/cdcl/smt_core.c#L2810-L2837) alternates Boolean and theory propagation to a fixed point.
- **[C]** Theory-implied literals carry generic antecedents via [`propagate_literal`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/solvers/cdcl/smt_core.c#L2138-L2166); [`explain_antecedent`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/solvers/cdcl/smt_core.c#L3191-L3207) requires causal explanation literals that precede the propagated literal.
- **[C]** The e-graph tracks decision levels and push state ([`egraph_start_search`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/solvers/egraph/egraph.c#L4513-L4632)). [`egraph_local_backtrack`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/solvers/egraph/egraph.c#L4908-L4987) undoes merges, distinct constraints, simplifications, congruence-root state, propagation-stack entries, and arena allocations.
- **[C]** [`egraph_assert_atom`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/solvers/egraph/egraph.c#L6496-L6533) receives SAT assignments. [`egraph_expand_explanation`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/solvers/egraph/egraph.c#L6752-L6798) reconstructs the literal explanation delivered to CDCL.
- **[C]** The core can cache short theory conflicts and implications as permanent clauses, and QF_UF defaults set the size bound to 12 ([`smt_core.c`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/solvers/cdcl/smt_core.c#L3017-L3183), [`yices_api.c`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/api/yices_api.c#L9460-L9470)).

**Boundary conclusion:** Yices already has fine-grained, causal, partial-trail theory propagation and selective permanence for short theory clauses. A lazy e-graph fallback that implements only these callbacks is a compatibility baseline, not an innovation.

### 6. Dynamic Boolean and non-Boolean Ackermannization

- **[D]** The official [heuristic-parameter documentation](https://yices.csl.sri.com/doc/parameters.html#theory-lemmas) describes generic theory-clause caching, non-Boolean Ackermann lemmas, two-clause predicate Ackermann lemmas, hit thresholds, per-kind limits, and auxiliary-equality quotas.
- **[C]** [`egraph_make_aux_eq`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/solvers/egraph/egraph.c#L3376-L3434) hash-conses newly required equality atoms but stops when the auxiliary-equality quota is exhausted.
- **[C]** [`create_ackermann_lemma`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/solvers/egraph/egraph.c#L3490-L3621) maintains a cache/hit counter per application pair. Boolean results generate two implication clauses after the Boolean threshold; non-Boolean results generate the standard congruence clause after their threshold.
- **[C]** A pending conflict application pair is converted into an Ackermann lemma before rollback in [`egraph_local_backtrack`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/solvers/egraph/egraph.c#L4896-L4934).

**Boundary conclusion:** collision-triggered, cached, quota-limited dynamic Ackermannization is a signature Yices mechanism. Reimplementing it faithfully may improve euf-viper coverage, but it cannot carry the novelty claim.

### 7. Symmetry breaking

- **[C]** Yices recognizes range constraints equivalent to `(or (= t c1) ... (= t cn))` over distinct uninterpreted constants ([`symmetry_breaking.h`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/symmetry_breaking.h#L38-L81)).
- **[C]** It verifies invariance under a transposition and a cycle, which generate the symmetric group ([`symmetry_breaking.h`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/symmetry_breaking.h#L101-L135)). The implementation then tracks available/used constants and scores candidate terms by how many constants a clause consumes ([`symmetry_breaking.h`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/symmetry_breaking.h#L141-L209)).
- **[C]** [`break_uf_symmetries`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/context_simplifier.c#L3678-L3740) collects records, verifies assertion invariance, combines compatible records, and invokes the breaker. Default activation is restricted to one-check e-graph contexts ([`yices_api.c`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/api/yices_api.c#L8865-L8870)).
- **[D]** The source identifies this as based on Deharbe, Fontaine, Merz, and Woltzenlogel Paleo, "Exploiting Symmetry in SMT Problems," CADE 2011 ([`context_types.h`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/context/context_types.h#L97-L118)); the first-party Yices paper reports that the preprocessing materially improved QF_UF performance ([Yices 2.2](https://yices.csl.sri.com/papers/cav2014.pdf)).

**Boundary conclusion:** finite-range detection, generator-based invariance checking, and costed membership clauses are all upstream. A stronger approach must alter the search representation, certificate, or automorphism exploitation, not only recognize more syntactic variants of the same range constraint.

### 8. Model construction and theory-guided branching

- **[C]** [`egraph_make_fun_value`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/solvers/egraph/egraph.c#L7861-L7917) gathers values for observed applications from an e-class's parent vector and extends the finite map with an arbitrary default. The source explicitly justifies arbitrary completion for QF_UF.
- **[C]** [`egraph_value_of_uninterpreted_class`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/solvers/egraph/egraph.c#L7957-L7993) reuses a constant already in the class or creates a fresh anonymous uninterpreted value. Boolean classes are expected to have been assigned and merged into the Boolean constant class ([`egraph.c`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/solvers/egraph/egraph.c#L8016-L8024)).
- **[C]** [`egraph_build_model`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/solvers/egraph/egraph.c#L8172-L8217) assigns values to all root classes in type-rank order.
- **[D]** Yices also supports branching modes that delegate atom polarity to a theory solver, including the e-graph, which evaluates the atom in its current local model ([Yices heuristic parameters](https://yices.csl.sri.com/doc/parameters.html#decision-heuristic)).
- **[C]** The base search parameters select `BRANCHING_DEFAULT` ([`search_parameters.c`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/api/search_parameters.c#L82-L85)), and the `CTX_ARCH_EG` case in `yices_set_default_params` does not override branching ([`yices_api.c`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/api/yices_api.c#L9460-L9470)). Thus theory branching is a supported ablation, not the current QF_UF default.

**Boundary conclusion:** finite-model completion and simple theory-evaluated polarity are excluded. A model-guided innovation must use richer information, such as predicted e-class split/merge cost, countermodel distance, or proof-complexity impact, and must be compared with Yices's supported theory-branching mode as an ablation.

### 9. Proof support

- **[C]** Current SMT-LIB state marks `produce_proofs` unsupported in [`smt2_commands.h`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/frontend/smt2/smt2_commands.h#L384-L393).
- **[C]** [`smt2_get_proof`](https://github.com/SRI-CSL/yices2/blob/b11db7c43ef72f9bd77d66a9c588d3eae80eaf93/src/frontend/smt2/smt2_commands.c#L5054-L5061) unconditionally reports `get-proof is not supported` after the normal logic check.
- **[I]** Yices's internal explanations are sufficient for CDCL conflict analysis, but the audited public source does not expose them as an end-to-end externally checkable UNSAT proof.

**Boundary conclusion:** proof production is a real differentiation opportunity against Yices2, provided certificate generation does not sacrifice the performance claim and the checker is independent of the solver.

## Cross-solver conclusions

### Mechanisms already jointly occupied

The following design space is occupied by both implementations, even when the exact data structures differ:

1. Hash-consed term DAGs with constructor simplification.
2. Specialized QF_UF preprocessing before CDCL search.
3. Rollback congruence closure synchronized with SAT decision levels.
4. Boolean terms represented in or synchronized with the equality engine.
5. Theory propagation from the current partial Boolean trail.
6. Causal EUF explanations returned to conflict analysis.
7. Conflict- or collision-selected Ackermann lemmas.
8. Permanent caching of selected theory consequences.
9. Symmetry breaking over interchangeable uninterpreted constants.
10. Finite e-class models with observed function entries and arbitrary defaults.
11. A custom, direct SAT/theory callback layer rather than a batch final-model check only.

These are all reasonable baseline components for a competitive solver. They are not eligible as the central novelty of euf-viper.

### Important asymmetries

- **[C]** Yices has a current default partition-domain equality learner.
- **[N]** No corresponding stage was found in Z3's audited default QF_UF route.
- **[C]** Z3 has public proof objects and an optional SAT/EUF proof-hint checker; Yices's current SMT-LIB frontend explicitly does not support proofs.
- **[C]** Z3's general constant-permutation symmetry tactic and Yices's finite-range-oriented breaker overlap but are not identical. Claiming novelty requires beating both semantic envelopes.
- **[C]** Z3 exposes two EUF/SAT integration architectures, while Yices's QF_UF path is a mature custom e-graph/CDCL composition.
- **[I]** The most defensible euf-viper opportunity is therefore not a third conventional lazy e-graph. It is an adaptive representation and certification layer whose decisions are informed by proof complexity and whose fallback can still match the mature partial-trail baseline.

## Experimental consequences

Any mechanism promoted from the underexplored list should pass the following boundary tests:

1. Compare against current default Z3 and default Yices2, not feature-disabled variants.
2. Add explicit ablations against Z3 `sat.smt=true`, Z3 dynamic Ackermann settings, Yices equality abstraction, Yices symmetry breaking, Yices dynamic Ackermannization, Yices theory-clause caching, and Yices theory branching when relevant.
3. Measure parser-inclusive one-shot wall time, peak RSS, solved count, SAT/UNSAT split, and tail survival at more than one timeout.
4. Validate every SAT result with an independent model checker and every UNSAT result with the intended certificate checker or a trusted differential oracle until certificate coverage is complete.
5. Stratify by structural family so gains on the easy mass cannot hide regressions on finite-domain, pigeonhole, deep-congruence, Boolean-as-data, or parser-heavy instances.
6. Preserve rejected variants and per-instance paired results. A mechanism is "novel and useful" only when its incremental effect survives paired corpus gates against both competitors and its closest upstream analogue.

## Exclusion checklist

Before calling an euf-viper mechanism novel, verify every relevant item below. A checked item means "treated as prior/upstream mechanism," not "forbidden to implement."

- [ ] Do not claim novelty for SMT-LIB parsing into a maximally shared DAG.
- [ ] Do not claim novelty for constructor simplification, cached rewriting, Boolean flattening, or canonical equality ordering.
- [ ] Do not claim novelty for top-level value propagation, solved-equality substitution, variable elimination, or staged base propagation.
- [ ] Do not claim novelty for rollback union-find/e-graph congruence closure with parent signature tables.
- [ ] Do not claim novelty for mirroring SAT trail levels in the e-graph and undoing merges on backtrack.
- [ ] Do not claim novelty for Boolean terms or predicates participating in congruence closure.
- [ ] Do not claim novelty for partial-trail EUF propagation, theory conflicts, or causal equality explanations.
- [ ] Do not claim novelty for Yices-style meet/join equality-partition abstraction over OR, equality, and ITE.
- [ ] Do not claim novelty for conflict/use/hit-triggered dynamic Ackermannization.
- [ ] Do not claim novelty for separate Boolean/predicate and non-Boolean Ackermann clauses.
- [ ] Do not claim novelty for Ackermann pair caches, thresholds, per-conflict budgets, garbage collection, or auxiliary-equality quotas.
- [ ] Do not claim novelty for short theory-clause caching.
- [ ] Do not claim novelty for detecting interchangeable constants, checking formula invariance, or adding range/membership symmetry breakers.
- [ ] Do not claim novelty for assigning fresh values to e-classes and building finite maps from observed UF applications.
- [ ] Do not claim novelty for arbitrary/default function completion in QF_UF.
- [ ] Do not claim novelty for simple theory-evaluated branch polarity.
- [ ] Do not claim novelty for putting an e-graph under direct SAT callbacks or making SAT variables external theory atoms.
- [ ] Do not claim novelty for DRAT/RUP logging, EUF congruence proof hints, or a union-find lemma checker in isolation.
- [ ] Do not claim novelty for a fixed one-shot QF_UF tactic/configuration profile.
- [ ] Do not claim novelty for full eager Ackermann reduction itself; novelty, if any, must lie in representation, selection, compression, adaptation, or certification and must be isolated experimentally.

## Underexplored interfaces

These are **research hypotheses**, not claims that no prior solver or paper has ever explored them. They are the interfaces not visibly realized by the audited current QF_UF paths and should be checked against broader literature before publication.

### 1. Proof-complexity-driven representation switching

Both solvers use structural preprocessing and conflict-local feedback, but neither audited default path visibly predicts whether a prospective eager encoding will induce cardinality/pigeonhole resolution hardness. A candidate interface is:

1. Estimate finite-domain width, orbit structure, equality-density, and expected clause-width before encoding.
2. Choose eager SAT, native cardinality/PB, lazy e-graph, or a mixed component-level representation.
3. Monitor learned-clause LBD/width, conflict growth, and congruence-collision rates online.
4. Abandon or refine a representation under a replayable budget, preserving learned facts that have route-independent proofs.

The novelty candidate is the **reversible, evidence-driven boundary**, not any individual backend.

### 2. Component-level heterogeneous solving

The audited routes select a solver/tactic for the formula or context. A less occupied interface is to decompose the ground term/application graph and assign different components to eager finite-domain encoding, lazy congruence closure, or direct simplification while retaining one Boolean skeleton. The hard questions are cross-component equalities, explanation composition, and whether decomposition overhead is repaid. This needs adversarial tests because naive component splitting can destroy useful global propagation.

### 3. Automorphism quotienting instead of added symmetry clauses

Z3 and Yices verify symmetries and add constraints. A stronger interface would quotient applications, equality atoms, or SAT states by certified automorphism orbits, then lift models/proofs back to the original problem. This is materially different only if it reduces variables/states rather than emitting another family of membership clauses. The certificate must cover orbit computation and lifting.

### 4. Proof-carrying one-shot preprocessing

Z3 skips its QF_UF symmetry tactic under proof production; Yices exposes no proof. This leaves a concrete interface for independently checkable certificates for:

- solved-equality elimination,
- branch-invariant equality learning,
- finite-range/symmetry reduction,
- eager or hybrid EUF encoding, and
- SAT refutation plus EUF lemma replay.

A small checker should reject unsupported steps rather than invoke the solver as a semantic fallback. Performance must be reported with certificate emission and independent checking enabled.

### 5. Bidirectional SAT-to-e-graph resource control

Current dynamic Ackermannization feeds congruence conflict/use events into lemma generation. A broader interface could feed SAT-side LBD, variable activity, clause survival, restart phase, and propagation gain back into:

- which parent signatures receive aggressive indexing,
- which congruence paths are retained for short explanations,
- which equalities become explicit SAT atoms,
- which Ackermann candidates are materialized, and
- when a finite-domain/cardinality view replaces pairwise equality reasoning.

To be distinct from upstream dynamic Ackermannization, the policy must use more than a per-pair hit counter and demonstrate that SAT feedback changes e-graph representation or explanation quality.

### 6. Conditional equality abstraction beyond partitions

Yices learns unconditional equalities common to Boolean branches. A richer but cost-sensitive abstract domain could retain compact guarded equalities, disequality cliques, bounded-domain facts, or "at least one merge" constraints, then compile each fact into the cheapest available backend. The research problem is to cap the domain so preprocessing remains cheaper than search. Every learned object should carry a local proof and an estimated propagation benefit.

### 7. Model-delta branching and countermodel fingerprints

Yices already supports theory-evaluated polarity, so evaluating an atom in the current e-graph model is excluded. A different interface would score a branch by predicted e-class merges/splits, finite-domain pressure, model repair cost, and expected certificate size. Repeated failed partial models could be summarized as compact fingerprints that guide branching or route selection without adding unsound semantic assumptions.

### 8. Parser-to-solver structural streaming

Both competitors first construct generic shared terms, then preprocess/internalize them. A specialized one-shot QF_UF frontend could stream declarations and assertions into a compact structural IR, incrementally compute occurrence colors, domain candidates, connected components, and prospective encoding costs, and discard generic syntax earlier. This is only worthwhile if parser-inclusive wall time and memory improve on the hash-consed generic frontends; it must not compromise full SMT-LIB correctness or model-name reconstruction.

### 9. Representation-neutral learned-fact exchange

A reversible eager/lazy portfolio needs a small fact language that can cross backend boundaries: equalities, disequalities, guarded congruences, domain bounds, and symmetry/orbit facts, each with a checker-replayable proof. Neither audited path visibly exposes such a representation-neutral exchange because each owns one primary search representation. This interface could make adaptation useful rather than a restart from zero.

### 10. Certificate-aware performance objectives

Competitor heuristics optimize solve time, while Z3's proof-compatible route drops at least the QF_UF symmetry pass and Yices has no public proof. Euf-viper can optimize a joint objective:

\[
T_{\mathrm{solve}} + \lambda T_{\mathrm{check}} + \mu S_{\mathrm{certificate}},
\]

with route selection trained or tuned on held-out families and evaluated without benchmark leakage. This makes "fast and certifying" an architectural objective rather than a post-hoc logging mode.

The practical target is not "another optimized e-graph." It is a solver whose representation boundary, proof-complexity feedback, and certificate path let it select or construct a cheaper proof than the mature Z3 and Yices2 mechanisms catalogued above.
