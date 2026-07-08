# Synthetic Canaries

Generated on 2026-07-08 with:

```bash
target/release/euf-viper gen chain 1000 > generated/synthetic/chain1000_unsat.smt2
target/release/euf-viper gen chain 1000 --sat > generated/synthetic/chain1000_sat.smt2
target/release/euf-viper gen grid 1000 8 > generated/synthetic/grid1000x8_unsat.smt2
```

These are narrow conjunction-heavy canaries.  They are not a substitute for the
SMT-LIB QF_UF benchmark campaign.
