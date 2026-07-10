# Deep-Let Permutation Route

Date: 2026-07-10

Status: same-binary structural-population gate passed; automatic source route
not yet implemented or promoted.

## Hypothesis

Focused finite permutation support was previously rejected as a global default
after small regressions outside its strongest targets. The promoted scoped-let
selector identifies exactly 17 corpus files with at least 512 lexical `(let`
forms. All 17 are finite NEQ instances, and historical data suggested that
scoped parsing and permutation support are strongly complementary.

The proposed route is the conjunction:

$$
\text{scoped-let-selected}
\;\land\;
\text{focused-permutation-applicable}.
$$

Path, family, expected status, source hash, and prior result are not routing
features.

## Fixed Experiment

- WMI job: `143412` on `c3n1`.
- Source: accepted `58efe9d`.
- Binary SHA-256:
  `4d5431135c95a2c528d287efd2803eaf895a5ec526c9642a570797b02fd47eb7`.
- Manifest: all 17 official corpus files with lexical-let count at least 512.
- Manifest SHA-256:
  `8681a05a28df440ff87db3942d515e43eef70d0b4da7479659b957abccd98c24`.
- Three alternating repeats, no warmup, 60-second cap.
- Both sides used the exact production environment. The only difference was
  `EUF_VIPER_FINITE_PERMUTATION_SUPPORT=0` versus `focused`.

## Result

| Instances | Coverage | All-total | Common-total | Geometric | Candidate wins |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 17 | 17 -> 17 | 1.6475x | 1.6475x | 1.8109x | 13 |

There were no one-sided solves, wrong answers, or execution errors. Baseline
median total was 184.0071 seconds; candidate median total was 111.6853 seconds.

Largest changes:

| Instance | Baseline median | Candidate median | Speedup |
| --- | ---: | ---: | ---: |
| `NEQ027_size11.smt2` | 56.3857s | 1.1553s | 48.81x |
| `NEQ031_size10.smt2` | 11.1007s | 0.7995s | 13.88x |
| `NEQ027_size10.smt2` | 5.7461s | 0.8365s | 6.87x |
| `NEQ031_size9.smt2` | 1.2288s | 0.6219s | 1.98x |

Four cases favored baseline, all narrowly. The largest candidate regression
was `NEQ027_size8.smt2`, from 0.4251 to 0.4345 seconds. The aggregate gain is
not driven by timeout substitution.

## Interpretation

The route combines two previously separate observations:

1. Scoped let restoration removes parser-state copying on deeply nested NEQ
   formulas.
2. Dual column-support clauses expose the finite injection/permutation
   structure to CDCL.

Neither mechanism alone produced this measured population result. The
conjunction is predeclared and structural, and the population is small enough
to gate exhaustively.

## Required Next Gates

1. Revert the rejected typed-parser experiment so the route is implemented on
   the accepted source lineage.
2. Add an automatic mode that enables focused support only when the existing
   scoped-let selector is active. Preserve explicit `off`, `focused`, and
   `all` controls.
3. Unit-test the exact 511/512 lexical-let boundary and explicit overrides.
4. Repeat the 17-case gate with the automatic mode.
5. Run sample 40, hot 400, and complete 7,503-instance A/B gates. Promotion
   requires unchanged or improved coverage and all three speed ratios above
   one at every gate.

## Artifacts

- `results/wmi/deep-let-focused-143412/deep-let17.jsonl`.
- `results/wmi/deep-let-focused-143412/wmi-ab-corpus-143412.csv`.
- Raw CSV SHA-256:
  `72be29e448d8e2de09dea04c902fc7fff731e90c2a10f27119f3cd10e580fdea`.
- Summary SHA-256:
  `9722e94da69d4961c7b9d7e85403b41fa2f5990b89dd5cf9ecaae5864778d881`.

## Decision

Proceed to the automatic route after restoring the accepted source baseline.
Do not globally enable focused permutation support and do not claim a
full-corpus improvement from this selected-population gate.
