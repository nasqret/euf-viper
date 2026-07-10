# Implementation

The current pipeline keeps each soundness boundary explicit.

1. Parse SMT-LIB S-expressions.
2. Hash-cons data and Boolean application terms.
3. Encode top-level assertions directly, introducing Tseitin variables only
   for internal Boolean values that must be named.
4. Detect small explicit finite domains and add sound one-hot and function
   channeling clauses where applicable.
5. Add selected equality-transitivity and congruence axioms.
6. Solve with Kissat, CaDiCaL, or Varisat according to structural routing.
7. Trust UNSAT from the sound clause set; validate SAT models with full EUF
   congruence closure.
8. If validation finds a theory conflict on a selected large sparse shape,
   rebuild the direct-root CNF with bounded propositional completion and retry.
9. Otherwise add explanation clauses and refine incrementally.

On Linux x86_64, step 9 uses incremental CaDiCaL refinement by default after
the eager routes are exhausted. This is deliberately post-validation: eager
UNSAT and EUF-valid SAT paths are unchanged. Set
`EUF_VIPER_INVALID_MODEL_FALLBACK=varisat` to restore the previous fallback.
The default was promoted only after a targeted repeated profile, a repeated
40-instance control, and a 7,503-instance paired WMI gate.

The parser also retains a narrowly gated branch-intersection preprocessor for
single-assertion equational diamonds. Finite predicate-table channeling exists
as an experimental flag, but remains disabled after failing its WMI hard-tail
gate.

## Direct-root Boolean encoding

The default encoder applies the truth requirement directly to each assertion.
For example, a positive conjunction emits its children as required clauses and
a positive disjunction emits one clause over child literals, rather than
allocating a fresh root variable and a unit clause. Internal subformulas still
use Tseitin definitions whenever their value is shared or must appear as a
literal. Exhaustive assignment tests compare both encoders across nested
`and`, `or`, `not`, `iff`, and `ite` formulas.

The complete paired gate improved coverage from 6,825 to 6,843 and passed all
three speed criteria. `EUF_VIPER_DIRECT_ROOT_CNF=0` retains the old root-unit
encoding as an exact rollback.

## Parser routing

Nested SMT-LIB `let` expressions can use in-place scoped restoration instead
of cloning the complete binding map at every level. This reduced two
parser-dominated NEQ cases by 5.63x in a repeated gate, but unconditional use
lost one net solve and regressed geometric speed on the complete corpus.
`EUF_VIPER_SCOPED_LET=off|auto|on` therefore keeps both implementations. The
promoted `auto` policy selects scoped restoration only when a bounded lexical
scan reaches 512 `let` forms. Its complete paired gate added 30 solves and
improved all-total, common-total, and geometric speed; the coverage gains then
reproduced on both WMI CPU classes. `off` remains the exact rollback.

## Equality abstraction

The default-off `EUF_VIPER_EQ_ABSTRACTION=shadow|facts` experiment computes
equalities common to Boolean branches using partition meet and join. Fact mode
adds only already-materialized equality atoms by default, suppresses duplicate
positive units, and rolls back transactionally at explicit quotas. Creating
fresh equality atoms requires the separate
`EUF_VIPER_EQ_ABSTRACTION_FRESH=1` opt-in. Shadow telemetry covered all 7,503
inputs, but no fact route is promoted until same-binary sample, hard-hit, and
complete-corpus gates pass.

## Dynamic Ackermann completion

For two applications of the same uninterpreted function, the completion emits

$$
\left(\bigwedge_i a_i = b_i\right) \Longrightarrow
f(a_1,\ldots,a_n)=f(b_1,\ldots,b_n).
$$

For Boolean-valued functions, the consequent is propositional equivalence.
These are sound EUF consequences. Equality atoms form an undirected graph; a
minimum-degree elimination adds bounded fill edges, after which triangle
clauses encode transitivity over the chordal completion. This follows the
sparse-transitivity approach of Bryant and Velev:
https://arxiv.org/abs/cs/0008001.

The route is deliberately cold. In automatic mode it is considered only after
Kissat produced an EUF-invalid model, no finite-domain axioms were added, the
base CNF has at least 100,000 clauses, and the term arena has at most 256
applications. Root-level conjunction, equivalence, and conditional assertions
are encoded directly in the rebuilt CNF. `EUF_VIPER_FULL_ACKERMANN=on` forces
completion, `off` disables the dynamic route, and
`EUF_VIPER_CHORDAL_MAX_FILL` bounds fill edges. If completion is capped or a
SAT assignment remains invalid, the solver abstains from that result and
continues to the validated fallback.

Internal maps and sets use deterministic Fx hashing. Release builds use one
codegen unit and thin LTO. These choices were accepted only as part of the
exact full-corpus candidate; isolated cold-code and LTO variants failed earlier
gates.

## Structural portfolio

The explicit `portfolio` command is separate from standalone `solve`. A frozen
depth-3 tree counts parentheses, `not`, and `declare-fun` forms without using
the benchmark path or expected-status metadata. Selected inputs run through
`euf-viper` in-process; all other inputs replace the current Unix process with
a user-supplied Yices executable.

The tree is trained by `scripts/bench/train_structural_router.py`, which uses
source-hash folds and rejects configurations that send an unresolved holdout
case to `euf-viper`. The accepted full-corpus gate preserves complete Yices
coverage and improves aggregate time, but not geometric speed. This mode
inherits Yices's trust boundary and is not covered by certificate format v1.

## UNSAT certificates

The opt-in `certificates` Cargo feature keeps proof dependencies and code out of
the benchmarked default binary. With that feature enabled, `certify` uses a
deliberately separate path. It emits the base Tseitin clauses,
equality-transitivity clauses, congruence clauses, and any EUF explanation
clauses needed to reach Boolean UNSAT. Finite-domain shortcuts are omitted in
certificate format v1. A fresh CaDiCaL instance then emits an ASCII DRAT proof
for that exact DIMACS file.

The manifest records every term, every SAT-variable interpretation, category
counts, and SHA-256 digests for the source, DIMACS, and proof. The checker first
runs `drat-trim`. For each non-base clause $C$, it then assumes $\neg C$, closes
the resulting equalities under congruence, and requires a disequality conflict.
This independently validates the SAT refutation and EUF axioms. The remaining
v1 trust boundary is reconstruction of the base Tseitin clauses from SMT-LIB.
