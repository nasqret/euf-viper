# OR-Stress Canaries

Generated on 2026-07-08 with:

```bash
target/release/euf-viper gen diamond 128 8 > generated/or-stress/diamond_b128_d8_unsat.smt2
target/release/euf-viper gen diamond 512 4 > generated/or-stress/diamond_b512_d4_unsat.smt2
target/release/euf-viper gen pruned-or 512 > generated/or-stress/pruned_or_b512_unsat.smt2
```

These files exercise branch-common equality extraction and all-branch pruning
for positive `or` formulas.  They are targeted stress canaries, not SMT-COMP
coverage.
