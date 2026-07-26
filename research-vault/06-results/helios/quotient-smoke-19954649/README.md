# Helios quotient-portfolio smoke 19954649

This directory is the fetched, immutable evidence bundle for the first
complete Helios execution of solver revision
`8368d21de96eec77f3bb5f6820c11d1363d3041b` through the exact command:

```text
euf-viper fabric-solve --engine quotient-portfolio {instance}
```

The orchestration revision is
`19293e2ba64fa2e055f4e2280892aedfde7185fa`. Job `19954649` completed
`0:0` on one AMD EPYC 9654 core. The bound campaign contains three instances,
six solver configurations, one two-second repetition, and exactly 18 raw
records. The raw SHA-256 is
`6af290f207c8d206e7b0bef7f43aa8f2eda1973f1a0c442f499087144edbcbaf`.

Viper and Yices2 solve all three rows; both Z3 configurations solve two;
cvc5 and OpenSMT solve one. Against Yices2, Viper has a `1.462x` PAR-2 and
common-total factor but only a `0.651x` common-geometric factor. The paired
analyzer therefore rejects promotion. This tiny selected smoke qualifies the
runner and does not support a corpus-level performance or superiority claim.

`remote-run/` excludes the run-local Cargo target. The candidate binary hash
is nevertheless bound in `remote-run/receipt.tsv` and every campaign lock.
`all-comparator-analysis.json` is the repository-owned analyzer output for all
five comparator configurations. Its SHA-256 is
`c75beb10498368172254e5110af28e1fccd445ab9bee33f3455eb9606770092e`.
