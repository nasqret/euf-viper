# Finite-Structure Canonization Campaign

Date: 2026-07-11

Status: design only. No mechanism in this note is implemented or accepted.

Scope: three mutually distinct, sound mechanisms for the finite QF_UF tail.
The goal is not ordinary value precedence, adjacent-swap lex leaders, or a
renamed Yices range-symmetry pass. The three experiments attack different
objects:

1. complete canonical representatives of the finite assignment under the
   verified formula automorphism group;
2. an isotopy/paratopy gauge change for closed Latin tables;
3. canonical quotient caching and orbit transport of EUF conflicts.

The word "novel" below always means a falsifiable novelty hypothesis. It is not
a publication claim until the source and literature audit described at the end
finds no earlier implementation.

## Executive Decision

Implement **Mechanism 1, verified stabilizer-chain canonical search**, first.
It has the best ratio of measured opportunity to proof risk: the exact first
scope contains 261 formulas, five current 60-second timeouts, and 421.535
seconds of excess time over Z3 on the 256 common solves. It can reuse the
existing finite tensor and formula-invariance machinery while replacing the
incomplete "lex against adjacent generators" policy with an exact orbit
representative test.

Mechanism 2 has the largest possible reduction per recognized formula, but its
recognizer may prove that few hard formulas preserve a useful isotopy subgroup.
It therefore starts as telemetry. Mechanism 3 is the most generally composable
and potentially the most novel SMT mechanism, but it needs the incremental
theory boundary and total-model repair, so it is third.

No performance work in this note can be promoted until the Boolean-as-data and
`DontCare` soundness defects are repaired. A symmetry optimization is not a
valid reason to weaken total model validation.

## Measured Opportunity

The counts below join:

- `results/wmi/finite-structures-full-c958-142731/finite-structures-full-c958.json`;
- `results/wmi/four-solver-60s-143248/qf-uf-corpus-143248.csv`.

They are structural counts, not benchmark-name routes.

| Population | Structural selector | Cases | euf-viper timeouts | Solved at least 5s | Common excess vs Z3 | Common excess vs Yices2 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Domain-7 closed tables | `n=7`, `closed>=1`, `binary_apps>=49`, `guarded=0` | 431 | 10 | 52 | 834.122s / 420 common | 1008.484s / 420 common |
| Exact one-table scope | preceding selector and `closed=1` | 261 | 5 | 28 | 421.535s / 256 common | 518.751s / 256 common |
| Multi-table scope | preceding selector and `closed>=2` | 170 | 5 | 24 | 412.587s / 164 common | 489.732s / 164 common |

All 431 cases have `all_different_clique_lb=7`. The ten euf-viper timeouts
contain only 147 to 196 binary applications in the hard formulas identified by
the 60-second audit; the current `apps>=1000` symmetry threshold therefore
misses the population entirely.

The immediate objective is not a marginal median win. A surviving mechanism
must convert tail instances while preserving the existing fast head.

## Common Formal Setting

Let the recognized finite carrier be

\[
D=\{d_0,\ldots,d_{n-1}\},
\]

where pairwise distinctness and exhaustiveness have been proved by the finite
recognizer. For each closed function `f` of arity `r`, define the exact finite
table atom

\[
x^f_{i_1,\ldots,i_r,k}
\quad\Longleftrightarrow\quad
f(d_{i_1},\ldots,d_{i_r})=d_k.
\]

The one-hot finite encoding gives every table cell exactly one output. Let
`X` be the ordered vector of all finite membership atoms and let `Y` contain
the residual Boolean/EUF atoms. The normalized finite problem is
`P_F(X,Y)`.

An action is admissible only if all of the following are checked:

1. it is a bijection on the affected term, atom, and table-cell IDs;
2. it preserves sorts, function arities, argument positions unless an explicit
   parastrophic role action is being checked, and Boolean polarity;
3. it maps the normalized assertion multiset to itself;
4. it maps every generated finite axiom family to itself;
5. it maps every residual atom or leaves it fixed;
6. its inverse passes the same check.

No family name, expected result, filename, or measured runtime may participate
in an admissibility decision. A failed check disables the mechanism.

## Mechanism 1: Verified Stabilizer-Chain Canonical Search

### Idea

Compute the actual automorphism group of the finite QF_UF formula, represent it
by a base and strong generating set, and admit exactly the lexicographically
least finite assignment in every group orbit. Unlike the current code, this is
not lexicographic comparison against adjacent generators. A generator-only
lex test is generally incomplete because a non-generator product can map an
assignment below all generator images.

The implementation is a small canonicality propagator over the finite tensor.
It uses a stabilizer chain to find a minimal image of the currently assigned
prefix. A branch is rejected only after producing a concrete group element
that maps its fixed prefix to a smaller compatible prefix.

### Mathematical invariant

Build a colored incidence hypergraph `H_F` whose vertices encode:

- domain constants;
- function symbols, colored by sort signature and arity;
- table cells and their argument-position incidence;
- normalized Boolean DAG nodes;
- equality/disequality atoms and polarity;
- distinguished constants, predicates, and residual terms.

Let

\[
G=\operatorname{Aut}(H_F)\restriction_X.
\]

Every `g in G` has a separately checked lift to all normalized formula atoms.
The required invariant is

\[
P_F(X,Y)=P_F(gX,gY) \qquad\text{for every }g\in G.
\]

Choose a deterministic cell/value order and define

\[
\operatorname{can}_G(X)
  \quad\Longleftrightarrow\quad
  X=\min_{g\in G} gX.
\]

Every orbit of the projected finite `X`-vector has exactly one minimum vector,
even when several group elements reach it because the assignment has a
nontrivial stabilizer.

### Equisatisfiability argument

The forward direction is immediate because the canonical problem adds a
restriction. For the reverse direction, let `(X,Y)` satisfy `P_F` and choose
`g*` minimizing `gX` over `G`. Set `(X*,Y*)=g*(X,Y)`. Formula invariance gives
`P_F(X*,Y*)`, and by construction `can_G(X*)`. Therefore

\[
P_F \text{ is SAT}
\quad\Longleftrightarrow\quad
P_F\land\operatorname{can}_G \text{ is SAT}.
\]

The propagator may prune a partial assignment `p` only when it returns a
specific `g` and an index `j` such that, for every `i<j`, both `X_i` and the
source bit mapped to `X_i` by `g` are assigned and equal, while both bits at
`j` are assigned and the image bit is smaller. These values are independent of
every unassigned suffix bit, so every completion of `p` is noncanonical under
the same witness.

### Exact data structures

```text
ColoredFormulaGraph
  colors: Vec<u32>
  offsets: Vec<u32>          # CSR hyperedge incidence
  neighbors: Vec<u32>
  edge_role: Vec<u8>         # arg-0, arg-1, output, polarity, DAG edge

Permutation
  domain_image: SmallVec<[u8; 16]>
  term_image: Vec<TermId>
  atom_image: Vec<LitId>

BSGS
  base: SmallVec<[CellId; 16]>
  strong_generators: Vec<PermutationId>
  level_orbits: Vec<BitSet>
  transversal_parent: Vec<Vec<PermutationId>>

CanonicalPrefixState
  level: u8
  fixed_prefix: Packed2BitVector
  active_cosets: SmallVec<[CosetId; 32]>
  partition_fingerprint: u128
```

For `n<=11`, domain permutations fit in fixed arrays. Table membership bits are
laid out cell-major and value-minor so the canonical test scans contiguous
memory. The partition fingerprint is only a cache key; equality of packed
states is checked after every hash hit.

Group discovery is two-stage:

1. color refinement and individualization produce candidate generators;
2. the existing normalized-AST mapper verifies every generator and inverse.

The BSGS is constructed from only verified generators. Canonical prefix states
are rollback objects indexed by SAT decision level. The first implementation
may run only on complete assignments, but the performance experiment of
interest is partial-prefix pruning.

### Complexity and failure risks

- Canonical image is graph-isomorphism hard in general. Highly regular Latin
  tensors can make individualization-refinement expensive.
- Full lex-leader CNF can be exponential even for tame groups. This design
  avoids eager expansion, but callback overhead can still dominate.
- A bad base order can create wide coset frontiers. Base cells must be selected
  by smallest refined orbit, then highest finite-clause activity.
- Table symmetries and Boolean-DAG symmetries can interact. Projecting a graph
  automorphism to `X` without a checked lift to `Y` is unsound.
- A partial prefix that is smaller under a permutation only conditionally is
  not prunable. The witness rule above must be applied literally.

Hard resource limits are fail-open for performance and fail-closed for proof:
if graph search or a canonicality check exceeds its budget, the solver keeps
the branch and records an abstention.

### Certificate and witness format

`finite-action-v1.json`:

```json
{
  "formula_hash": "sha256:...",
  "normalized_graph_hash": "sha256:...",
  "cell_order_hash": "sha256:...",
  "generators": [
    {
      "domain_permutation": [0, 2, 1],
      "term_map_hash": "sha256:...",
      "assertion_before_hash": "sha256:...",
      "assertion_after_hash": "sha256:..."
    }
  ],
  "base": [0, 7, 14],
  "group_order": "5040"
}
```

Each prune emits `canonical-prune-v1` containing the decision-level prefix,
the first differing cell, and a word in verified generators for the witness
permutation. An independent checker reconstructs the permutation, verifies
formula invariance, and checks the strict prefix comparison.

For SAT, emit the finite table and its canonical label. For UNSAT, combine the
SAT proof with substitution-redundancy records for every canonical prune; do
not pretend that a symmetry-breaking clause is an EUF theorem.

### Target selector

First scope:

```text
domain_size == 7
closed_table_functions == 1
binary_table_apps >= domain_size * domain_size
all_different_clique_lb >= domain_size
guarded_disequality_clauses == 0
```

Current population: 261 formulas, five euf-viper 60-second timeouts, 28
additional solves taking at least five seconds, and 16 taking at least ten
seconds. This population is the first gate even if graph discovery identifies
a larger safe scope.

### Staged gate

1. **Action oracle.** Exhaustively enumerate all `3^9=19,683` binary tables on
   three values. Compare the propagator's orbit partition and canonical member
   with brute-force enumeration of all six value permutations. Require exactly
   one representative per orbit.
2. **Adversarial oracle.** Generate colored formulas with one fixed constant,
   asymmetric predicates, repeated terms, and automorphism groups of orders
   `1, 2, 3, 4, 6, 8, 12, 24`. Compare group order, orbits, and minimal images
   with exhaustive permutation enumeration for `n<=6`.
3. **Shadow corpus pass.** Run the recognizer and canonical checker without
   pruning on all 261 cases. Record group order, refined cells, canonical
   checks, search nodes, witness lengths, and estimated rejected models. Any
   unverified generator is a hard failure.
4. **Complete-model gate.** Same binary, `off` versus `complete-only`, all 261,
   three alternating repeats at 60 seconds. Require zero wrong answers,
   errors, or baseline-only solves; at least one timeout conversion; and
   all-total, common-total, and geometric ratios all above `1.05`.
5. **Partial-prefix gate.** Compare `complete-only` with `prefix`, not merely
   `off` with `prefix`. Require fewer SAT decisions and conflicts on every
   converted timeout, with the same timing requirements.
6. **Architecture gate.** Repeat on both WMI CPU classes. A result that appears
   on only one class is not promotable.
7. **Blast-radius gate.** Run finite-151, hot-400, hard-tail, and full 7,503 at
   two seconds, then full corpus at 60 seconds. Coverage cannot decrease; all
   three ratios must exceed one. Run a 2x2 factorial test with the existing
   focused permutation support before combining them.

### Prior art and novelty boundary

Known prior art includes lex leaders; stabilizer-chain symmetry breaking;
nauty/Traces individualization-refinement; structure-aware SAT symmetry
breaking; SAT modulo symmetries; and Danco et al.'s complete symmetry break for
a single binary operation. The current euf-viper adjacent-swap verifier and
table lex leaders are also prior local work.

The potentially new contribution is the combination of:

- the exact automorphism group of the *ground QF_UF formula plus finite
  reduction*, rather than a generic CNF graph or unconstrained magma;
- a rollback BSGS canonical-prefix propagator over typed multi-object table
  tensors;
- checked lifts through residual EUF/Boolean atoms; and
- proof-carrying canonical-prune witnesses composable with the SAT proof.

If the literature audit finds this exact combination, the mechanism remains a
performance experiment but loses its novelty claim.

## Mechanism 2: Isotopy And Paratopy Gauge Elimination

### Idea

Ordinary finite-model isomorphism applies one permutation to every occurrence
of a domain value. A closed Latin table has a larger natural coordinate action:
rows, columns, and output symbols can be permuted independently. For a binary
table this isotopy group is

\[
\Gamma_{\mathrm{iso}}=S_n^{\mathrm{row}}
  \times S_n^{\mathrm{column}}
  \times S_n^{\mathrm{output}}.
\]

When argument/output roles may also be exchanged, the paratopy action extends
this by a subgroup of `S_3`. With several same-signature tables it may extend
further by verified table permutations.

This mechanism does not add generic range-symmetry clauses. It proves that the
*finite propositionalized formula* is invariant under a subgroup of the
coordinate action, then changes gauge. In the full-isotopy case it eliminates
the first row and column by restricting the table to reduced Latin form:

\[
f(d_0,d_j)=d_j,\qquad f(d_i,d_0)=d_i.
\]

That fixes `2n-1` cells. At `n=7`, 13 of 49 cells and their 91 one-hot literals
can be propagated away before CNF reaches the SAT solver. A full implementation
rebuilds the tensor around the `(n-1)^2` free core instead of merely appending
unit clauses.

### Mathematical invariant

Write a table as a ternary relation

\[
R_f=\{(i,j,k): f(d_i,d_j)=d_k\}.
\]

An isotopy `g=(alpha,beta,gamma)` acts by

\[
gR_f=\{(\alpha i,\beta j,\gamma k):(i,j,k)\in R_f\}.
\]

Let `Gamma_F` be the subgroup of the product action for which exact atom-level
normalization proves

\[
P_F(X,Y)=P_F(gX,gY).
\]

The recognizer must prove both that `R_f` is a total Latin table and that the
required row, column, and output actions lie in `Gamma_F`. A benchmark label
such as `QG` is not evidence of either fact.

For paratopy, a role permutation maps relation coordinates before the three
value permutations. It is admitted only if the transformed atom map preserves
the whole formula. Nested applications, distinguished constants, and
cross-role equalities usually destroy this symmetry and must cause rejection.

### Equisatisfiability argument

Every Latin square is isotopic to a reduced Latin square. Choose an anchor cell
`(r,c)` and an output permutation `gamma` with
`gamma(f(r,c))=0`. Define

\[
\alpha(i)=\gamma(f(i,c)),\qquad
\beta(j)=\gamma(f(r,j)).
\]

The Latin property makes `alpha` and `beta` permutations, with
`alpha(r)=beta(c)=0`. Under the corresponding coordinate action, the new first
row and column are both the identity order. If full isotopy is contained in
`Gamma_F`, formula invariance maps the original model to this reduced model.
Hence the fixed gauge is equisatisfiable.

For a proper subgroup, no fixed cell is emitted merely because it is reachable
from the current model. The implementation computes a transversal of the
subgroup action and emits only a normalization slice for which it has a total
transporter construction. If totality cannot be proved, it abstains.

Paratopy orientation uses the same argument: among the finitely many verified
role images, choose the least reduced tensor. It is a second stage, never part
of the initial isotopy proof.

### Exact data structures

```text
TableTensor
  function: SymId
  arity: u8
  shape: [u8; MAX_ARITY_PLUS_OUTPUT]
  literals: Vec<LitId>       # contiguous row/column/output order

RoleAction
  function_image: SymId
  role_permutation: SmallVec<[u8; 4]>
  coordinate_permutations: SmallVec<[SmallPerm; 4]>
  residual_atom_map: Vec<LitId>

IsotopyGroup
  role_colors: Vec<u32>
  generators: Vec<RoleAction>
  bsgs_by_role: ProductBSGS

GaugeRecipe
  anchor_cell: CellId
  fixed_cells: Vec<(CellId, ValueId)>
  eliminated_literals: BitSet
  transporter_program: Vec<GaugeOp>
```

The formula is encoded as a colored 3-uniform incidence hypergraph over row,
column, output, function, and assertion vertices. Product-group refinement is
performed before any generic graph canonizer: row signatures, column
signatures, output occurrence signatures, and function-use signatures are
refined independently. Candidate actions are still verified by exact
normalized-form equality.

The `transporter_program` is a straight-line construction from the anchor row
and column permutations. It is used only by the checker and SAT-model
reconstruction; the hot solve path sees the reduced tensor.

### Complexity and failure risks

- Most algebraic identities are not isotopy invariant. A broad syntactic guess
  would be unsound and is forbidden.
- Formula-level isotopy discovery can be more expensive than solving easy
  cases. It needs a strict structural router and a telemetry-first gate.
- Fixing 13 cells may expose a harder residual SAT variable order. Cell order
  and phase initialization must be measured independently from clause count.
- Multiple tables can share coordinate roles in incompatible ways. The first
  implementation handles exactly one closed binary table.
- A parastrophy can exchange the output coordinate with an input coordinate
  only for a proved Latin relation and only if the entire encoded formula is
  invariant under that role map.
- A reduced-table theorem does not imply a unique representative of an isotopy
  class. This mechanism claims gauge reduction, not complete canonization.

### Certificate and witness format

`finite-isotopy-v1.json` contains:

- formula and normalized finite-encoding hashes;
- the verified product-group generators;
- row/column/output atom maps and inverse checks;
- the Latin-totality witness: exact-one cells plus row/column permutation
  support;
- the gauge recipe and its symbolic transporter proof;
- optional paratopy role maps, separately tagged.

The independent checker validates the constructive theorem: for an arbitrary
total Latin tensor, executing the recipe yields a reduced tensor; every recipe
operation belongs to the verified group; and the transformed normalized
formula is identical. SAT models are expanded back to ordinary function
tables. UNSAT certification uses a dedicated `latin-isotopy-reduce` redundancy
rule or an elaborated substitution-redundancy proof, never an EUF-lemma tag.

### Target selector

Telemetry scope:

```text
5 <= domain_size <= 7
closed_table_functions == 1
binary_table_apps >= domain_size * domain_size
all_different_clique_lb >= domain_size
guarded_disequality_clauses == 0
```

Current population: 6,167 formulas (`5: 5,290`, `6: 616`, `7: 261`).

Performance scope: the 261-case domain-7 one-table selector from Mechanism 1.
The recognizer result is an additional gate: if no hard formula has a useful
coordinate subgroup, the experiment stops without weakening the invariant.

### Staged gate

1. **Latin theorem oracle.** Enumerate every order-3 Latin square and every
   element of `S_3^3`. Verify that reduction preserves Latin totality and that
   every isotopy class has at least one reduced member. Randomly test orders
   four through seven against a separate SageMath/Magma implementation.
2. **Negative recognizer suite.** Add identities, fixed constants, nested table
   applications, cross-role equalities, asymmetric predicates, and partial
   rows. Every unsupported coordinate action must be rejected.
3. **Shadow scan.** Run product-group discovery on all 6,167 telemetry cases.
   Record group order by role, full-isotopy count, number of safely fixed cells,
   recognizer time, and membership-literal reduction. Continue only if at least
   three of the five domain-7 timeout formulas admit a nontrivial gauge and the
   predicted finite CNF shrinks by at least 20 percent on those recognized
   targets.
4. **Unit-gauge gate.** Same binary `off` versus `gauge-units`, all recognized
   domain-7 cases, three alternating 60-second repeats. Require no losses or
   wrong answers, at least one timeout conversion, and all three timing ratios
   above `1.05`.
5. **Eliminated-core gate.** Compare `gauge-units` with construction of the
   reduced tensor core. Require lower variables, clauses, propagation work, and
   wall time; clause reduction without wall-time gain is rejection.
6. **Paratopy gate.** Test role orientation separately and only on formulas
   whose exact action checker admits it. Require a strict gain over isotopy-only.
7. **Combination gate.** Run a 2x2 factorial experiment with Mechanism 1.
   Promote the combination only if its gain is not explained by either arm
   alone and it passes the two-CPU, hot-400, hard-tail, and full-corpus gates.

### Prior art and novelty boundary

Reduced Latin squares, isotopisms, paratopisms, autotopism groups, and
canonical labeling of Latin squares are established mathematics. Recent work
gives average-case canonical labeling algorithms for Latin squares. Finite
model finders also exploit isomorphism and least-number heuristics.

The potentially new contribution is automatic, proof-producing discovery of
role-separated isotopy/paratopy actions in a ground QF_UF formula, followed by
compile-time elimination of a gauge-fixed table tensor and residual-stabilizer
canonization. This differs from Yices-style value/range symmetry because the
row, column, and output permutations are independent and are verified against
the exact finite encoding.

The novelty claim fails if an SMT or finite-model implementation already
performs exact formula-level coordinate-action discovery and uses it to
reparameterize the table core. Classical reduced Latin-square enumeration by
itself does not establish that prior implementation.

## Mechanism 3: Canonical Quotient Conflict Transducer

### Idea

Do not restrict the SAT search to canonical models. Instead, canonicalize each
invalid finite EUF candidate *after* it reaches theory validation, cache its
quotient structure up to the verified formula group, and transport the minimal
EUF conflict across the quotient orbit.

This attacks repeated theory work, not propositional model symmetry. One
invalid assignment can yield a family of checked theory clauses that blocks
all group-equivalent congruence failures. The cache also identifies repeated
invalid quotient structures reached through different Boolean assignments.

### Mathematical invariant

A total assignment `A` to all theory-relevant atoms induces a finite candidate
prestructure

\[
Q_A=(T/{\sim_A},\widehat f_A,\widehat P_A),
\]

where `T` is the ground-term set and `sim_A` is the equality partition before
the final congruence check. `Q_A` may fail to be a valid EUF quotient because
equal argument tuples receive unequal results, a disequality collapses, or a
Boolean-domain condition fails.

Let `G` be the verified formula action group from Mechanism 1. It acts on
ground terms, literals, and candidate quotients. Define a canonical key

\[
K(A)=\min_{g\in G}\operatorname{encode}(gQ_A).
\]

The canonicalizer must return both `K(A)` and a transporter `h_A in G`.
Hash equality alone is never a proof of orbit equivalence.

Suppose validation derives the EUF-valid conflict clause

\[
C_A=\neg \ell_1\lor\cdots\lor\neg\ell_m\lor r.
\]

For every verified `g in G`, `gC_A` is also a valid, typed EUF clause. Store
`h_A C_A` in canonical coordinates. On an orbit-equivalent cache hit `B`, use
the checked transporter to emit

\[
h_B^{-1}h_A C_A.
\]

Optionally enumerate a bounded orbit of distinct transformed clauses under the
current stabilizer. This is theory-lemma orbit saturation, not a symmetry
breaking predicate.

### Equisatisfiability argument

Every emitted clause is independently replayed as an EUF consequence. Adding
valid theory lemmas cannot remove a theory model and cannot create a model.
Cache canonicalization affects only which already-valid lemma is selected.
Therefore the procedure is equisatisfiable even if the cache has no hits.

If canonical labeling finds an isomorphism outside `G`, the corresponding
entry may be used for statistics but not for clause transport. A valid
transporter word in verified generators is mandatory.

### Exact data structures

```text
CandidateQuotient
  class_of_term: Vec<ClassId>
  class_color: Vec<u32>
  app_edges: Vec<(SymId, SmallVec<[ClassId; 3]>, ClassId)>
  predicate_bits: PackedBitVector
  disequality_edges: Vec<(ClassId, ClassId)>

CanonicalQuotientKey
  digest: u128
  packed_form: Arc<[u32]>     # collision check
  transporter: PermutationWord

ConflictTemplate
  canonical_antecedents: SmallVec<[LitId; 16]>
  canonical_consequent: Option<LitId>
  explanation_dag: ExplanationId
  support_classes: SmallVec<[ClassId; 16]>

QuotientCache
  buckets: RobinHoodMap<u128, SmallVec<[Entry; 2]>>
  byte_budget: usize
  generation: u32

OrbitEmitter
  stabilizer: BSGSView
  seen_clause_hashes: HashSet<u128>
  clause_budget: u16
```

The quotient incidence graph is colored by sort, function symbol, argument
position, predicate polarity, and distinguished term status. Canonicalization
uses partition refinement first; only unresolved cells invoke
individualization. Cache entries are immutable and generation-scoped so a
restart can discard them cheaply.

Explanation minimization runs before canonicalization. The cache stores
canonical literal IDs, never mutable union-find representatives. A full packed
form resolves digest collisions.

### Complexity and failure risks

- A highly symmetric invalid quotient can be expensive to canonicalize.
  Observe-only telemetry must establish repeated work before enabling it.
- Clause orbits can contain thousands of clauses. Start with one transported
  cache lemma, then a strict budget such as 8 or 32 shortest distinct images.
- Long orbit clauses can flood the SAT database and damage locality. Measure
  LBD, propagation count, and survival after reduction.
- Two quotients can be graph-isomorphic but not related by a formula
  automorphism. Only a transporter in the verified group permits reuse.
- An incomplete SAT model invalidates `Q_A`. Every relevant atom must have a
  total truth value; `DontCare` causes abstention or safe completion before the
  cache is consulted.
- Boolean-as-data terms must be atomized before quotient construction.

### Certificate and witness format

Each emitted `orbit-euf-lemma-v1` record contains:

- source quotient canonical key and full packed-form hash;
- source EUF explanation DAG;
- source-to-canonical and canonical-to-current transporter words;
- the transformed literal list;
- generator/action certificate hash.

The checker replays the original congruence explanation, composes and verifies
the transporter, transforms the clause, and compares it byte-for-byte with the
SAT lemma. The SAT proof then treats the checked theory lemma as an input
lemma. Cache misses and evictions need no proof records.

### Target selector

First scope:

```text
domain_size == 7
closed_table_functions >= 2
binary_table_apps >= domain_size * domain_size
all_different_clique_lb >= domain_size
guarded_disequality_clauses == 0
```

Current population: 170 formulas, five euf-viper 60-second timeouts, 24
additional solves taking at least five seconds, and 17 taking at least ten
seconds. On 164 common Z3 solves this subset accounts for 412.587 seconds of
euf-viper excess time; against Yices2 the common excess is 489.732 seconds.

The multi-table scope is intentional: it is where a static single-table
canonizer is least complete and repeated isomorphic quotient failures should
have the largest reusable support.

### Staged gate

1. **Explanation transport oracle.** Generate small typed EUF problems over
   domains two through four. Enumerate every verified group element and check
   every transformed conflict independently with brute-force finite models and
   a separate congruence-closure checker.
2. **Observe-only replay.** Preserve the exact complete-model sequence of the
   current solver on all 170 targets. Compute quotient keys and predicted cache
   hits without adding clauses. Continue only if at least three of the five
   timeout formulas show either a 20-percent duplicate-quotient rate or an
   orbit containing at least eight distinct minimal conflicts.
3. **Single-transport gate.** Enable one transported lemma per cache hit, with
   orbit saturation disabled. Require exactly the baseline answers and fewer
   repeated invalid quotients on every target that performs multiple theory
   rounds.
4. **Orbit-budget sweep.** Compare budgets `0, 1, 2, 4, 8, 16, 32` on the 170
   cases. Predeclare the winner on a training half and evaluate it once on the
   held-out half. Do not choose a budget from full-corpus timing.
5. **Target performance gate.** Same binary off/on, three alternating repeats
   at 60 seconds on both CPU classes. Require no baseline-only solve, at least
   one timeout conversion, at least `1.10x` on the 170-case all-total metric,
   and common/geometric ratios above `1.05`.
6. **Ablation gate.** Compare ordinary model cut, minimized cut, canonical
   cache only, orbit emission only, and cache plus orbit. The claimed gain must
   be attributable to the new mechanism.
7. **Portfolio gate.** Only after the standalone result, combine with
   Mechanisms 1 and 2 and the later rollback e-graph. Run finite, hot, hard-tail,
   full-2s, and full-60s gates with no coverage loss or wrong answer.

### Prior art and novelty boundary

Symmetric explanation learning already studies orbits of SAT conflict clauses.
SAT modulo symmetries prunes noncanonical partial combinatorial objects.
Finite-model cube methods discard isomorphic cubes. Canonical labeling and
memoization of finite structures are established techniques. Standard SMT
solvers cache theory clauses.

The potentially new contribution is canonicalization of *invalid EUF quotient
prestructures* followed by proof-carrying transport of minimized congruence
explanations across a verified finite formula group. It acts at the boundary
between SAT assignments and EUF validation; it neither enumerates models nor
merely learns the propositional orbit of a CDCL conflict.

This novelty claim must be withdrawn if prior work transports theory lemmas by
canonical quotient keys in DPLL(T), even if it was evaluated in a theory other
than EUF.

## Ranking

| Rank | Mechanism | Expected upside | Soundness risk | Engineering risk | First decision |
| ---: | --- | --- | --- | --- | --- |
| 1 | Stabilizer-chain canonical search | Converts one-table domain-7 tail and generalizes to simultaneous tables | Low to medium: explicit orbit witness | Medium | Implement complete-model oracle, then prefix propagator |
| 2 | Isotopy/paratopy gauge elimination | Removes 26.5% of a domain-7 table before SAT in full-isotopy scope | Medium: subgroup recognition is delicate | Medium | Telemetry recognizer before solver changes |
| 3 | Canonical quotient conflict transducer | Reuses one EUF conflict across many symmetric invalid candidates | Low per emitted lemma, but requires total models | High | Observe-only replay after soundness repair |

Mechanism 1 is first because its target is known, its witness is local, and its
first scope is exact. Mechanism 2 is not ranked first despite its larger group:
the hard formulas may intentionally break isotopy while retaining ordinary
isomorphism. Mechanism 3 waits for an incremental SAT/theory interface and
complete assignments.

## Campaign Discipline

### Quality invariants

Every stage must report:

- parser result and expected status;
- Z3, Yices2, and cvc5 differential result;
- total relevant-atom assignment coverage;
- group order, generator count, and action-verification status;
- abstention reason when a guard fails;
- SAT variables, clauses, decisions, propagations, conflicts, and restarts;
- theory calls, invalid models, learned theory clauses, and proof-check time;
- wall time, CPU time, peak RSS, binary hash, source revision, CPU model, and
  all environment toggles.

Any wrong answer, malformed proof, action mismatch, or unexplained baseline-only
solve rejects the candidate. A timeout is not a wrong answer, but a promoted
default may not reduce coverage at any required gate.

### Controlled experiment order

1. repair global soundness and freeze a new accepted baseline;
2. implement shared action/certificate types without pruning;
3. run Mechanism 1 oracle, shadow, and standalone gates;
4. run Mechanism 2 telemetry independently from Mechanism 1;
5. implement only the isotopy subgroup justified by telemetry;
6. add quotient telemetry after total model extraction is proved;
7. test every mechanism alone before any pair;
8. run all three pairwise 2x2 factorial experiments;
9. test the three-way combination only if at least two pairwise interactions
   are nonnegative;
10. compare the final survivor directly with Z3 and Yices2 at 2s, 60s, and the
    competition budget on both CPU classes.

For a claim of overall improvement on this corpus, require two independent
full runs with:

- zero wrong answers and execution errors;
- no lower coverage than either comparator at the stated timeout;
- at least `1.05x` timeout-charged total-time improvement against both Z3 and
  Yices2;
- at least `1.02x` geometric improvement on common solves against both;
- independently checked SAT/UNSAT certificates for the claimed configuration.

### Novelty audit before paper language

Search and record, at minimum:

1. Yices2, Z3, cvc5, Vampire, Mace4, Paradox, Kodkod, BreakID, satsuma, and SAT
   modulo symmetries source for finite-table action code;
2. `isotopy`, `paratopy`, `autotopism`, `reduced Latin square`, `canonical
   augmentation`, `minimal image`, `stabilizer chain`, `theory lemma orbit`,
   `symmetric explanation`, and `quotient cache` across DBLP, arXiv, ACM,
   Springer, and SMT-COMP artifacts;
3. proof systems for symmetry and substitution redundancy;
4. patents only after the academic/source search, to avoid a false novelty
   statement based on publication vocabulary.

Maintain a claim matrix with columns: exact mechanism, closest source, same
mathematical object, same integration layer, proof production, implementation
available, and surviving difference. Use "new" only when the surviving
difference is algorithmically material, not merely a Rust implementation.

## Closest Literature

- Deharbe, Fontaine, Merz, and Woltzenlogel Paleo, *Exploiting Symmetry in SMT
  Problems* (CADE 2011):
  https://doi.org/10.1007/978-3-642-22438-6_18
- McKay and Piperno, *Practical Graph Isomorphism, II* (JSC 2014):
  https://arxiv.org/abs/1301.1493
- Araujo, Chow, and Janota, *Symmetries for Cube-And-Conquer in Finite Model
  Finding* (CP 2023):
  https://doi.org/10.4230/LIPIcs.CP.2023.8
- Anders, Brenner, and Rattan, *satsuma: Structure-based Symmetry Breaking in
  SAT* (2024):
  https://arxiv.org/abs/2406.13557
- Gill, Mammoliti, and Wanless, *Canonical Labelling of Latin Squares in
  Average-Case Polynomial Time* (2024/2025):
  https://arxiv.org/abs/2402.06205
- Danco, Janota, Codish, and Araujo, *Complete Symmetry Breaking for Finite
  Models* (AAAI 2025):
  https://doi.org/10.1609/aaai.v39i11.33217
- Devriendt et al., *Symmetric Explanation Learning: Effective Dynamic
  Symmetry Handling for SAT*:
  https://jodevriendt.com/wp-content/uploads/2021/09/sat-sel.pdf

These sources establish that symmetry breaking, canonical labeling, isotopy,
and conflict orbits are not individually novel. The campaign is specifically
testing whether their proof-carrying placement at the finite QF_UF/SAT boundary
creates a new and materially faster solver architecture.
