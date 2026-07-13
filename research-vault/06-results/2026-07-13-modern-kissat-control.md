# Modern Kissat Backend Control

Date: 2026-07-13

Status: implementation and validation complete; timing not started; no
performance promotion

## Question

Production Linux euf-viper used the SAT Competition 2021 Kissat source while
non-Linux builds used Kissat 4.0.4 through RustSAT. Before attributing a broad
performance change to novel SMT machinery, the campaign needs a controlled
Linux comparison on identical SMT parsing, CNF construction, finite axioms,
EUF clauses, model validation, and fallback policy.

## Implementation

Public branch `research-modern-kissat`, validation commit `d7c14da`, adds:

- an unmodified vendored Kissat 4.0.4 source snapshot at upstream commit
  `8af8e56f174b778aef3aa45af9f739b2a5f492c2`;
- feature-selected `kissat-sc2021` and `kissat-4` Linux builds;
- complete Kitten C-symbol namespacing against CaDiCaL;
- `EUF_VIPER_KISSAT_MODE` and `EUF_VIPER_KISSAT_OPTIONS`;
- fail-closed rejection of unknown, malformed, or out-of-range options;
- explicit `unknown` instead of silent Varisat fallback on configuration
  failure;
- backend identity in `euf-viper --version`; and
- a durable WMI job preserving and hashing both release binaries.

Default builds retain SC2021. Enabling `kissat-4` selects 4.0.4; Linux
`--all-features` intentionally exercises 4.0.4.

## Validation

Hosted GitHub Actions run `29214335958` passed on `d7c14da`. WMI job `144945`
completed with exit `0` and preserved these binaries:

| Backend | SHA-256 |
| --- | --- |
| Kissat SC2021 | `d7321602b8cc86683ccb41e90bea7b843a5059caad62d1eba347bb3e69c70362` |
| Kissat 4.0.4 | `ecbcfebb1f39c725c1d0266442c7dcc80083b8347e3b77d90bfb5646bd4ea6b6` |

The default suite passed 222 tests with three environment-only probes ignored.
The modern all-feature suite passed 228 tests with four ignored. Both release
binaries agreed on the chain SAT/UNSAT, transitivity, predicate-congruence, and
Boolean-as-data fixtures. The modern artifact passed the independent SAT plus
five-UNSAT certificate smoke with pinned `drat-trim` SHA-256
`58a121dec7dc8e192f38dc2626c4a993946d487cc0238679fef11f5de63443e5`.

## Cheap Falsification

A separate same-binary CaDiCaL control tested clausal congruence on
`QG-classification/loops6/iso_icl053.smt2`. It reduced conflicts from 62 to 51
and decisions from 69 to 59, but a 20-pair local ABBA regressed median
end-to-end time from 8.055 ms to 9.737 ms, a 1.209x slowdown. This rejects
unconditional CaDiCaL congruence as a broad route and demonstrates why SAT
internal counts are not promotion evidence.

## Next Gate

Do not time the modern binaries until P0 global audit `144826` passes. Then:

1. compare the two exact WMI binaries on the frozen sample and anti-targets;
2. require identical answers and no fallback/configuration failures;
3. advance only on positive total and geometric timing with no coverage loss;
4. ablate congruence, sweeping, factor/BVA, vivification, and phase mechanisms
   one at a time inside the 4.0.4 binary; and
5. require independent model/certificate checks before any full promotion.

This is an engineering control, not the novelty claim. The original candidate
architecture remains proof-pressure-triggered representation migration and
source-certified finite Hall/PB recovery.
