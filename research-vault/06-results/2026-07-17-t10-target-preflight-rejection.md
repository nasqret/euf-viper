# T10 Target Preflight Rejection

Date: 2026-07-17

Decision: terminal rejection before the full Stage 0 census

## Exact objects

- Design commit: `05de7841ac005e2a251d71e1a2394f8980cbdd17`
- Core commit: `898df6d916c313baefd3baae6e820db85e678cce`
- Core tree: `95443fbaf3911c0f55ec0b37ab5271e98407842a`
- Core parent: `37aeefef7ad8fdcc82752c4dc71e5bce0e906223`
- Unused census harness commit: `50ed9155700012354a8db6d97472dd3fec70f3f5`
- Target SHA-256:
  `cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112`
- Local projector binary SHA-256:
  `10e4a9b9554347a6f6abe877bb6584a9ed239f3d7cac5c266dac819cd2f3ec7d`
- Independent rebuild binary SHA-256:
  `b41bbcda93752d2ca9f664a6fcda5250a990d992001c78150f9dbae662eddedc`
- Projection record SHA-256:
  `1458b9036c2879a5f5e04f646182737a76effc59a4167ce0ced890e552f468ce`

## Result

The immutable projector selected the sole frozen T9 source, enumerated 3,686
full typed Ackermann clauses, and retained zero clauses whose complete atom set
already existed in the baseline CNF. It reported 7,958 full literal slots,
maximum width three, zero added variables, zero new atoms, zero fill edges,
zero transitivity clauses, and zero SAT calls. Before/after CNF, atom-map, and
combined-problem hashes are equal.

The preregistered selected-row bound was `1..4096` closed clauses. Zero is a
necessary-gate failure, so no SAT-enabled candidate or WMI timing is permitted.
Because the selected row alone is decisive, the 7,503-source census harness was
preserved but not integrated or executed. This result must not be described as
a completed Stage 0 corpus audit.

## Independent audit

A separate Z3 4.16 AST walk reproduced 138 unique applications in six
same-function groups. Their pair counts were 210, 3,321, 6, 28, 55, and 66,
for a total of 3,686. It independently reproduced 4,272 differing argument
positions, 7,958 literal slots, and maximum width three. Of all pairs, 203 had
every required argument-equality atom and zero had the required result-equality
atom. Therefore the independently computed closed total is also zero.

The exact core passed 19 focused T10 tests. Independent all-feature testing
passed 296 tests with four ignored, parent/current behavior matched on 11 SMT
fixtures, and `project-t9` remained byte-identical. Two repeated target
projections were byte-identical.

## Stop rule

Do not run T10 Stage 1, WMI timing, streaming-parser integration, sample-40,
hot-400, broad-corpus timing, merge, or promotion. The next experiment requires
a separate preregistration for a proof-producing equality-resolution compiler.
