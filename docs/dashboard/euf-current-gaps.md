# Current EUF Gap Map

Candidate: `euf-viper` at `d2b45f5ea1263476405ca4da7fdeaf92328f1e8f`.
Corpus: `smtlib-2025-full`; 7503 instances; timeout 2s.

A factor above `1.0x` means the comparator took longer than Viper on the common solved set.

## Overall

| Comparator | Viper solved | Comparator solved | Viper only | Comparator only | Common total | Common geometric |
|---|---:|---:|---:|---:|---:|---:|
| yices2 | 7449 | 7490 | 7 | 48 | 0.3164x | 0.3895x |

## Family Matrix

### yices2

| Family | Instances | Viper | Comparator | Viper only | Comparator only | Total factor | Geometric factor |
|---|---:|---:|---:|---:|---:|---:|---:|
| QF_UF/20170829-Rodin | 34 | 34 | 34 | 0 | 0 | 0.9968x | 0.9968x |
| QF_UF/2018-Goel-hwbench | 773 | 772 | 773 | 0 | 1 | 0.4291x | 0.6314x |
| QF_UF/20190906-CLEARSY | 46 | 46 | 46 | 0 | 0 | 0.8996x | 0.9184x |
| QF_UF/NEQ | 48 | 48 | 43 | 5 | 0 | 2.1655x | 1.3666x |
| QF_UF/PEQ | 47 | 40 | 39 | 2 | 1 | 0.7535x | 0.5872x |
| QF_UF/QG-classification | 6396 | 6351 | 6396 | 0 | 45 | 0.2883x | 0.3524x |
| QF_UF/SEQ | 56 | 55 | 56 | 0 | 1 | 0.5380x | 0.6187x |
| QF_UF/TypeSafe | 3 | 3 | 3 | 0 | 0 | 0.9835x | 0.9835x |
| QF_UF/eq_diamond | 100 | 100 | 100 | 0 | 0 | 0.9870x | 0.9874x |
