# Exact Forbidden-Table Orbit Probe

Date: 2026-07-11

Status: measured typed-structure result; no solver timing or novelty claim

## Result

The production parser plus the test-only typed extractor analyzed
`QF_UF/QG-classification/qg7/iso_icl_nogen001.smt2`, source SHA-256
`6e9ea0786a672c467f853bf8964283bbdc53c2b51c41e0b0e6fc1fbd8ba34be0`.

It extracted 5,040 well-typed complete binary tables over a seven-element
domain. All records are unique. Exhaustive conjugation of the first table by
all 5,040 elements of `S_7` produced an orbit of size 5,040, and the extracted
set equals that orbit exactly:

| Metric | Value |
| --- | ---: |
| Complete exclusion records | 5,040 |
| Unique exclusions | 5,040 |
| Duplicate exclusions | 0 |
| Permutations enumerated | 5,040 |
| First-table orbit size | 5,040 |
| Extracted exclusions in that orbit | 5,040 |
| Missing orbit members | 0 |
| Out-of-orbit exclusions | 0 |
| Malformed candidates | 0 |

The optimized test body completed in 0.14 seconds after compilation. The test
binary SHA-256 is
`088cc9eba11d689b470f4c34555df13d51987b5eab4fdf6aaeccc061ccf02ef5`.

## Interpretation

The formula repeats one full `S_7` orbit as 5,040 separate negated complete
table assignments. This validates the extraction and anti-model quotient
premise of the orbit-forbidden-table design on the representative instance.
It does not yet establish that the base constraints are invariant, that the
canonical search is exhaustive, or that the resulting solver is faster.

## Reproduction

```bash
EUF_VIPER_ORBIT_PROBE_CASE=/tmp/iso_icl_nogen001.smt2 \
  cargo test --release --all-features \
  forbidden_orbit_probe::tests::probe_external_formula -- \
  --ignored --exact --nocapture
```

The machine-readable record is
`2026-07-11-forbidden-orbit-probe.json` in this directory.

