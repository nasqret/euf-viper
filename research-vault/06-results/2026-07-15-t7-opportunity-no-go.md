# T7 SAT-Impact Opportunity Gate: No-Go

Date: 2026-07-15

## Decision

The initial T7 implementation at exact commit
`6269084326b99c500911a7c735e502da74858e97` fails its preregistered local M3
opportunity gate. No ABBA canary, WMI job, timing claim, integration, or
vivification experiment is authorized from this revision.

## Reproduction

The diagnostic used a clean detached checkout and explicit Rust `1.96.0` after
the local `stable` alias was found to lack its standard-library payload.

- Release binary SHA-256:
  `fca2fe64d2fd30924a693cd5267bff8da68655ac9e5fcf08e78c38f7d0ae21d4`.
- Full source manifest SHA-256:
  `9c509b0ffd35a371738dbb31865f975b43350fca5f54393f7bb5014d450a08db`.
- Fresh 24-source T7 manifest SHA-256:
  `bea690135735d5e2d5a5c13d9329c71a3f833ed1b071a2ea41a65173d8d1a657`.
- Population: M3=3, T9=9, A12=12; all 24 source hashes verified against the
  local 7,503-source corpus.

The rebuilt manifest digest exactly matches the independent reviewer's
reconstruction. The permitted one-pass command used the exact release, exact
manifest, corpus root, and a 60-second per-source timeout.

## Result

The first frozen source,
`QF_UF/2018-Goel-hwbench/QF_UF_peg_solitaire.2.prop1_ab_br_max.smt2`, timed out
after 60 seconds. The gate exited 2 immediately and emitted no T7 transcript or
opportunity summary. Therefore it established neither a qualifying conflict nor
an `off`/`on` disagreement on any source.

Independent review also found that the broader campaign analyzer aggregates
per-repeat ratios instead of ratios of per-source medians, the report can
self-hash an empty opportunity result, selector-overhead accounting omits major
work, validation is interleaved with timing, the SMT-LIB reference parser has a
lexical `define-fun` scope defect, and forest identity is self-attested. Those
defects independently prohibit canary timing even if M3 later becomes solvable.

The repair must make the exact M3 opportunity pass bounded and independently
auditable, correct every aggregation and accounting rule, and obtain another
review before any timing stage.
