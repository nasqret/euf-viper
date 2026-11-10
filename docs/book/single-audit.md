# When one witness is checked twice

For each root pair, Viper's mixed adjacency iterator combines physical separation records with implicit witnesses from a compact group. On one immutable traversal, a physical record can be validated at lookup and then again in the enclosing audit. Counting a duplicate requires both checks to finish successfully for the **same ID on the same directed pair**. Merely observing the same term elsewhere in a search is not enough.

The original Sokoban3 input returned SAT. At fixed-root setup only 4 second-pass visits were physical; after setup, 195,207 of 537,159 visits repeated a physical check. Overall that is 195,211 of 537,163 visits (36.34%). The UNSAT mechanism control had 0 duplicates out of 126 visits. These are one-process observations on each input, not distinct global witness counts or samples of elapsed time.

```{image} ../../results/local/single-audit-2026-11-10/host-counts.svg
:alt: Fraction of witness visits already physically validated: 36.34% on 724; 0% on 990001.
```

A one-pass implementation could reuse an already validated record within the same borrow. It still has to validate virtual witnesses and preserve the identity, order and polarity of each reason. The real question is whether the change reduces end-to-end solve time while preserving those guarantees. That requires a separate release race; no ranking follows from the present counts.

See the {download}`experiment and replay instructions <../../results/local/single-audit-2026-11-10/README.md>` and {download}`machine-readable result <../../status/euf-single-audit-host-2026-11-10.json>`.
