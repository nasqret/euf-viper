# Current EUF Gap Map

Candidate: `euf-viper` at `8368d21de96eec77f3bb5f6820c11d1363d3041b`.
Corpus: `smtlib-2025-full`; 7503 instances; timeout 2s.

A factor above `1.0x` means the comparator took longer than Viper on the common solved set.

## Overall

| Comparator | Viper solved | Comparator solved | Viper only | Comparator only | Common total | Common geometric |
|---|---:|---:|---:|---:|---:|---:|
| yices2 | 7436 | 7490 | 7 | 61 | 0.2889x | 0.3934x |
| z3-default | 7436 | 7446 | 37 | 47 | 0.7238x | 0.8858x |
| z3-sat-euf | 7436 | 7459 | 27 | 50 | 0.8170x | 0.9544x |
| cvc5 | 7436 | 7364 | 97 | 25 | 1.0257x | 1.2257x |
| opensmt | 7436 | 7289 | 158 | 11 | 1.5824x | 0.9680x |

## Family Matrix

### yices2

| Family | Instances | Viper | Comparator | Viper only | Comparator only | Total factor | Geometric factor |
|---|---:|---:|---:|---:|---:|---:|---:|
| QF_UF/20170829-Rodin | 34 | 34 | 34 | 0 | 0 | 0.9988x | 0.9988x |
| QF_UF/2018-Goel-hwbench | 773 | 772 | 773 | 0 | 1 | 0.4313x | 0.6367x |
| QF_UF/20190906-CLEARSY | 46 | 46 | 46 | 0 | 0 | 0.9110x | 0.9304x |
| QF_UF/NEQ | 48 | 48 | 43 | 5 | 0 | 2.2431x | 1.3429x |
| QF_UF/PEQ | 47 | 39 | 39 | 2 | 2 | 0.7827x | 0.5887x |
| QF_UF/QG-classification | 6396 | 6339 | 6396 | 0 | 57 | 0.2599x | 0.3561x |
| QF_UF/SEQ | 56 | 55 | 56 | 0 | 1 | 0.5183x | 0.6304x |
| QF_UF/TypeSafe | 3 | 3 | 3 | 0 | 0 | 0.9874x | 0.9873x |
| QF_UF/eq_diamond | 100 | 100 | 100 | 0 | 0 | 0.9874x | 0.9873x |

### z3-default

| Family | Instances | Viper | Comparator | Viper only | Comparator only | Total factor | Geometric factor |
|---|---:|---:|---:|---:|---:|---:|---:|
| QF_UF/20170829-Rodin | 34 | 34 | 34 | 0 | 0 | 1.9111x | 1.8571x |
| QF_UF/2018-Goel-hwbench | 773 | 772 | 772 | 1 | 1 | 1.6114x | 1.5954x |
| QF_UF/20190906-CLEARSY | 46 | 46 | 46 | 0 | 0 | 1.3611x | 1.3139x |
| QF_UF/NEQ | 48 | 48 | 40 | 8 | 0 | 2.9617x | 2.3241x |
| QF_UF/PEQ | 47 | 39 | 33 | 7 | 1 | 1.6572x | 1.7782x |
| QF_UF/QG-classification | 6396 | 6339 | 6367 | 17 | 45 | 0.6588x | 0.8042x |
| QF_UF/SEQ | 56 | 55 | 51 | 4 | 0 | 0.9484x | 1.2773x |
| QF_UF/TypeSafe | 3 | 3 | 3 | 0 | 0 | 0.9844x | 0.9844x |
| QF_UF/eq_diamond | 100 | 100 | 100 | 0 | 0 | 1.3132x | 1.2519x |

### z3-sat-euf

| Family | Instances | Viper | Comparator | Viper only | Comparator only | Total factor | Geometric factor |
|---|---:|---:|---:|---:|---:|---:|---:|
| QF_UF/20170829-Rodin | 34 | 34 | 34 | 0 | 0 | 1.5134x | 1.4512x |
| QF_UF/2018-Goel-hwbench | 773 | 772 | 773 | 0 | 1 | 1.6343x | 1.6423x |
| QF_UF/20190906-CLEARSY | 46 | 46 | 46 | 0 | 0 | 1.5696x | 1.5380x |
| QF_UF/NEQ | 48 | 48 | 40 | 8 | 0 | 2.9148x | 2.4422x |
| QF_UF/PEQ | 47 | 39 | 32 | 7 | 0 | 2.1957x | 2.2607x |
| QF_UF/QG-classification | 6396 | 6339 | 6381 | 7 | 49 | 0.7445x | 0.8664x |
| QF_UF/SEQ | 56 | 55 | 50 | 5 | 0 | 1.8643x | 1.8726x |
| QF_UF/TypeSafe | 3 | 3 | 3 | 0 | 0 | 0.9890x | 0.9890x |
| QF_UF/eq_diamond | 100 | 100 | 100 | 0 | 0 | 1.7331x | 1.7051x |

### cvc5

| Family | Instances | Viper | Comparator | Viper only | Comparator only | Total factor | Geometric factor |
|---|---:|---:|---:|---:|---:|---:|---:|
| QF_UF/20170829-Rodin | 34 | 34 | 34 | 0 | 0 | 1.4019x | 1.3393x |
| QF_UF/2018-Goel-hwbench | 773 | 772 | 756 | 17 | 1 | 2.8460x | 1.9589x |
| QF_UF/20190906-CLEARSY | 46 | 46 | 46 | 0 | 0 | 1.2663x | 1.1679x |
| QF_UF/NEQ | 48 | 48 | 32 | 16 | 0 | 6.6714x | 5.4589x |
| QF_UF/PEQ | 47 | 39 | 24 | 15 | 0 | 5.0324x | 5.2425x |
| QF_UF/QG-classification | 6396 | 6339 | 6325 | 38 | 24 | 0.9031x | 1.1315x |
| QF_UF/SEQ | 56 | 55 | 44 | 11 | 0 | 4.0642x | 3.3859x |
| QF_UF/TypeSafe | 3 | 3 | 3 | 0 | 0 | 0.9785x | 0.9785x |
| QF_UF/eq_diamond | 100 | 100 | 100 | 0 | 0 | 1.6168x | 1.5250x |

### opensmt

| Family | Instances | Viper | Comparator | Viper only | Comparator only | Total factor | Geometric factor |
|---|---:|---:|---:|---:|---:|---:|---:|
| QF_UF/20170829-Rodin | 34 | 34 | 34 | 0 | 0 | 0.9940x | 0.9941x |
| QF_UF/2018-Goel-hwbench | 773 | 772 | 763 | 10 | 1 | 2.0847x | 1.4524x |
| QF_UF/20190906-CLEARSY | 46 | 46 | 46 | 0 | 0 | 0.9598x | 0.9666x |
| QF_UF/NEQ | 48 | 48 | 27 | 21 | 0 | 4.2688x | 4.5433x |
| QF_UF/PEQ | 47 | 39 | 22 | 17 | 0 | 3.3446x | 3.9413x |
| QF_UF/QG-classification | 6396 | 6339 | 6245 | 104 | 10 | 1.5404x | 0.9068x |
| QF_UF/SEQ | 56 | 55 | 49 | 6 | 0 | 1.4559x | 1.5195x |
| QF_UF/TypeSafe | 3 | 3 | 3 | 0 | 0 | 0.9796x | 0.9796x |
| QF_UF/eq_diamond | 100 | 100 | 100 | 0 | 0 | 0.9938x | 0.9937x |
