# Measured novelty gates, round 2

Date: 2026-07-11

Status: active; no solver-superiority claim

## Fixed reference

- Exact sound source: `ebf8e27`.
- Exact WMI binary SHA-256:
  `38421e03b51fae69c354258614f25d507409a689e7fb70981b51328f23e4412a`.
- Corpus: SMT-LIB 2025 QF_UF, 7,503 instances.
- Every timing comparison uses paired arm order and explicit environment
  settings. SAT and UNSAT outputs must match the manifest; a speed result
  cannot override a semantic failure.

## Correctness evidence

- Exact Boolean-data differential `143810` executed 10,041 formulas with no
  euf-viper discrepancy and no reference failure. The job wrapper failed only
  because the earlier Python harness did not persist the files expected by the
  shell script; commit `7929e87` repairs deterministic manifest/results
  persistence and hashes.
- Leaf-quotient soundness `143829` passed. Boolean-data differential `143832`
  executed 2,041 formulas: 726 SAT, 1,315 UNSAT, and zero discrepancies against
  both Z3 and cvc5.
- Leaf parser differential `143866` gave the candidate zero failed cases and
  zero failed groups across 1,620 cases and 550 groups. The 21 comparator
  anomalies are retained as reference behavior, not attributed to euf-viper.

## Novelty census

Full test-only census `143814` parsed all 7,503 formulas.

- The complete-model scouts validated only 4 SAT models among 3,142 SAT
  instances. This is below the 5% opportunity gate, so the current two fixed
  scout assignments are rejected.
- 4,692 formulas contain unconditional positive equality facts.
- 4,058 formulas have a nonzero quotient reduction.
- The quotient applies 430,194 effective unions and removes 668,507 canonical
  Boolean nodes.
- Global unique-node reduction is 3.8935%; among affected formulas it is
  7.4559%.
- 1,200 formulas have at least 10% unique-node reduction.

The qg7 pattern census `143840`, commit `21ff258`, persisted 418/418 records
with SHA-256
`903c9b50c24db31c1a98b3aee1ffd8f864484a5b1009d0ac4e236ef9efcfadd5`.

- 296 formulas have checked patterns; 122 have no exact pattern.
- 174 are exact first-orbit covers: 120 width-6, 52 width-49, and 2 width-5.
- The exact set contains 146 SAT and 28 UNSAT benchmarks.
- Another 122 width-49 formulas are partial/non-cover and remain ineligible.

## Low-level candidates

### Small clause storage

Candidate `0a37b0f` replaces `Vec<i32>` per CNF clause by
`SmallVec<[i32; 4]>` while preserving clause order and the indexed one-hot
builder.

- Soundness `143820`: passed; binary SHA-256 starts `980581a9`.
- Hot-80 `143825`: 80/80 correct; 1.0248x total, 1.0362x geometric,
  1.0269x median. All 95% lower bounds exceed 1.0; paired p-value is
  `0.00009999`.
- Independent hot-320 holdout `143826`: 320/320 correct, 244 wins and 76
  losses; 1.0160x total, 1.0376x geometric, 1.0326x median. Lower bounds are
  1.0059x, 1.0302x, and 1.0250x respectively; paired p-value is
  `0.00009999`.
- Resource gate `143861`: 320/320 correct over 1,920 observations. Summed
  paired median RSS is 0.9847 candidate/baseline, geometric RSS is 0.9917,
  and median RSS ratio is 0.9992. Their 95% bootstrap intervals remain below
  1.0. Maximum RSS is effectively unchanged, 37,112 versus 37,096 KiB.
- Full 7,503-instance array `143842` and merge/gate `143843` are running.

Decision: promoted through target and holdout gates; do not merge before the
complete-corpus result.

### Rejected isolated mechanisms

- Direct Kissat short-clause loading `d4992e2`: sound, but target-31 total is
  0.9947x and all-time is 0.9986x. Reject as an isolated FFI change.
- Borrowed parser atoms `3d308f6`: parse phase improves 1.26--1.36x on the
  profiled large cases, but end-to-end target timing is only 1.001x geometric
  and statistically indistinguishable. Retain scanner machinery; reject the
  partial ownership change.
- `x86-64-v3` build `143824`: 80/80 correct, 1.0004x total, confidence
  intervals cross a loss. Reject compiler ISA as the explanation for prior
  compound gains.

## Structural candidates

### Deep-let focused permutations

Automatic candidate `3426e63` enables focused finite permutation support only
after the existing scoped-let selector reaches 512 lexical lets.

- Soundness `143827`: passed.
- Two-second gate `143828`: candidate coverage 13/17 versus 9/17. On nine
  common solves it is 1.3146x total and 1.2726x geometric. The generic gate
  rejects asymmetric timeout sets and a median lower bound below 1.0.
- Sixty-second gate `143851`: all 17 solve in both arms; 1.6357x total,
  1.8593x geometric, 1.0437x median, p=`0.0019998`. Total and geometric lower
  bounds pass; median lower bound is 0.9984, so the pre-registered gate still
  rejects promotion.

The near-neutral losses concentrate in small verified domains. Candidate
`88bcede` pre-registers a semantics-based refinement: automatic focused
support requires verified domain size at least six; explicit `focused` and
`all` remain unchanged. Soundness `143876`, exact comparison `143877`, and
causal comparison against `3426e63` in `143878` are running.

Decision: retain as a narrow high-value route; no global promotion until a
pre-registered refinement passes without weakening statistics.

### Unconditional leaf quotient

Candidate `414b109` extracts only positive equality facts at assertion roots
or under root conjunctions. It preserves supporting equality atoms and
projects only Boolean leaves; theory and finite-domain structures remain raw.

- Soundness and both differential gates pass.
- Target-90 `143830`: candidate gains two solved Goel peg-solitaire instances
  and improves common-total time by 1.1476x, but loses the median at 0.9854x,
  has geometric lower bound 0.9390, and paired p=`0.3657`.
- The candidate is slower on 38 of 64 common solves. Reduction percentage by
  itself does not predict timing reliably.
- Exploratory 60-second Goel-20 job `143865` is running only to determine
  whether the two-second coverage gain extends into the tail.

Decision: reject as a general route. Preserve the sound projection primitive
for a future Boolean e-graph or a separately pre-registered Goel-tail rule.

### Right-translation exact cover

Commit `a1749dc` adds a test-only degree-7 Algorithm-X shadow search over
right translations.

- Each selected column is a permutation; row/value masks impose the remaining
  Latin exact-cover condition.
- Flat multiword bitsets track forbidden-pattern compatibility.
- Search uses deterministic minimum-remaining-values column choice.
- SAT witnesses are independently replayed against row, column, range, and
  every forbidden pattern.
- Every structural, preparation, and search cap returns ABSTAIN. UNSAT is
  emitted only after exhaustive abstract search.
- Outcomes concern only the `latin_pattern_avoidance` abstraction and cannot
  answer the source SMT formula.

The next gate runs only the 174 exact qg7 orbit-cover cases. Production use
would additionally require a checked reduction proving that the source formula
forces the Latin abstraction and a replayable lift back to the original terms.

## Literature connections

- Biere, Fazekas, Fleury, and Froleyks recover gate structure from CNF and
  propagate normalized gate equivalences with occurrence lists and union-find.
  Our differentiated variant can act before CNF on the retained Boolean DAG,
  where no gate recovery is needed:
  <https://doi.org/10.4230/LIPIcs.SAT.2024.6>.
- Bryant and Velev make sparse equality graphs chordal so triangle constraints
  suffice instead of cubic dense transitivity. This motivates a direct
  triangle-native clause builder rather than another generic theory solver:
  <https://www.cs.cmu.edu/~bryant/pubdir/tocl-trans01.pdf>.
- Bryant, German, and Velev exploit positive equality through maximally diverse
  interpretations. The failed two-model scout is only a tiny special case, not
  a refutation of the broader polarity technique:
  <https://arxiv.org/abs/cs/9910014>.
- Yices2 uses a lazy E-graph-style congruence closure and remains the principal
  comparison target; reproducing that architecture is not the novelty goal:
  <https://yices.csl.sri.com/papers/cav2014.pdf>.

## Next measured order

1. Finish SmallVec full-corpus gate `143842`/`143843`; merge only on semantic,
   coverage, timing, and RSS passage.
2. Gate the domain-six deep-let refinement `143876`--`143878`.
3. Run the reviewed RTXC shadow census on the exact 174 qg7 cases.
4. Complete the one-pass semantic parser in `tree|shadow|stream` mode and run
   full-corpus shadow parity before timing.
5. If SmallVec survives, compare a flat literal slab directly against
   SmallVec, not against the older `Vec<Vec<i32>>` baseline.
6. Measure dense finite-membership storage, reusable symmetry verification,
   triangle-native transitivity, application-pair congruence joins, and bulk
   SAT model readback one mechanism at a time.
