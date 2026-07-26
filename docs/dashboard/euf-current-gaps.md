# Current EUF Gap Map

Candidate: `euf-viper` at `b5f78fb6cfef648178089a680bf365ff4367b075`.
Corpus: `smtlib-2025-full`; 7503 instances; timeout 2s.

A factor above `1.0x` means the comparator took longer than Viper on the common solved set.

## Overall

| Comparator | Viper solved | Comparator solved | Viper only | Comparator only | Common total | Common geometric |
|---|---:|---:|---:|---:|---:|---:|
| yices2 | 7458 | 7490 | 7 | 39 | 0.3139x | 0.3928x |
| z3-default | 7458 | 7447 | 46 | 35 | 0.7454x | 0.8826x |
| z3-sat-euf | 7458 | 7458 | 35 | 35 | 0.8394x | 0.9510x |
| cvc5 | 7458 | 7362 | 113 | 17 | 1.0502x | 1.2220x |
| opensmt | 7458 | 7283 | 182 | 7 | 1.5675x | 0.9632x |

## Family Matrix

### yices2

| Family | Instances | Viper | Comparator | Viper only | Comparator only | Total factor | Geometric factor |
|---|---:|---:|---:|---:|---:|---:|---:|
| QF_UF/20170829-Rodin | 34 | 34 | 34 | 0 | 0 | 1.0206x | 1.0181x |
| QF_UF/2018-Goel-hwbench | 773 | 773 | 773 | 0 | 0 | 0.4083x | 0.6355x |
| QF_UF/20190906-CLEARSY | 46 | 46 | 46 | 0 | 0 | 0.9177x | 0.9339x |
| QF_UF/NEQ | 48 | 48 | 43 | 5 | 0 | 2.2684x | 1.3674x |
| QF_UF/PEQ | 47 | 39 | 39 | 2 | 2 | 0.8706x | 0.6242x |
| QF_UF/QG-classification | 6396 | 6360 | 6396 | 0 | 36 | 0.2866x | 0.3555x |
| QF_UF/SEQ | 56 | 55 | 56 | 0 | 1 | 0.5130x | 0.6227x |
| QF_UF/TypeSafe | 3 | 3 | 3 | 0 | 0 | 0.9685x | 0.9686x |
| QF_UF/eq_diamond | 100 | 100 | 100 | 0 | 0 | 0.9934x | 0.9931x |

### z3-default

| Family | Instances | Viper | Comparator | Viper only | Comparator only | Total factor | Geometric factor |
|---|---:|---:|---:|---:|---:|---:|---:|
| QF_UF/20170829-Rodin | 34 | 34 | 34 | 0 | 0 | 1.6702x | 1.6232x |
| QF_UF/2018-Goel-hwbench | 773 | 773 | 773 | 0 | 0 | 1.5309x | 1.5695x |
| QF_UF/20190906-CLEARSY | 46 | 46 | 46 | 0 | 0 | 1.3078x | 1.2459x |
| QF_UF/NEQ | 48 | 48 | 40 | 8 | 0 | 2.9961x | 2.3637x |
| QF_UF/PEQ | 47 | 39 | 33 | 7 | 1 | 1.6289x | 1.8259x |
| QF_UF/QG-classification | 6396 | 6360 | 6367 | 27 | 34 | 0.6823x | 0.8023x |
| QF_UF/SEQ | 56 | 55 | 51 | 4 | 0 | 0.9289x | 1.2612x |
| QF_UF/TypeSafe | 3 | 3 | 3 | 0 | 0 | 0.9743x | 0.9743x |
| QF_UF/eq_diamond | 100 | 100 | 100 | 0 | 0 | 1.4203x | 1.3345x |

### z3-sat-euf

| Family | Instances | Viper | Comparator | Viper only | Comparator only | Total factor | Geometric factor |
|---|---:|---:|---:|---:|---:|---:|---:|
| QF_UF/20170829-Rodin | 34 | 34 | 34 | 0 | 0 | 1.5505x | 1.4908x |
| QF_UF/2018-Goel-hwbench | 773 | 773 | 773 | 0 | 0 | 1.5141x | 1.6205x |
| QF_UF/20190906-CLEARSY | 46 | 46 | 46 | 0 | 0 | 1.5714x | 1.5269x |
| QF_UF/NEQ | 48 | 48 | 40 | 8 | 0 | 2.8579x | 2.4231x |
| QF_UF/PEQ | 47 | 39 | 32 | 7 | 0 | 2.1079x | 2.2919x |
| QF_UF/QG-classification | 6396 | 6360 | 6380 | 15 | 35 | 0.7719x | 0.8645x |
| QF_UF/SEQ | 56 | 55 | 50 | 5 | 0 | 1.8274x | 1.8502x |
| QF_UF/TypeSafe | 3 | 3 | 3 | 0 | 0 | 0.9746x | 0.9746x |
| QF_UF/eq_diamond | 100 | 100 | 100 | 0 | 0 | 1.7249x | 1.6826x |

### cvc5

| Family | Instances | Viper | Comparator | Viper only | Comparator only | Total factor | Geometric factor |
|---|---:|---:|---:|---:|---:|---:|---:|
| QF_UF/20170829-Rodin | 34 | 34 | 34 | 0 | 0 | 1.0280x | 1.0267x |
| QF_UF/2018-Goel-hwbench | 773 | 773 | 756 | 17 | 0 | 2.6732x | 1.9426x |
| QF_UF/20190906-CLEARSY | 46 | 46 | 46 | 0 | 0 | 1.2990x | 1.1915x |
| QF_UF/NEQ | 48 | 48 | 31 | 17 | 0 | 6.2241x | 5.2380x |
| QF_UF/PEQ | 47 | 39 | 24 | 15 | 0 | 5.0856x | 5.4170x |
| QF_UF/QG-classification | 6396 | 6360 | 6324 | 53 | 17 | 0.9321x | 1.1311x |
| QF_UF/SEQ | 56 | 55 | 44 | 11 | 0 | 3.8728x | 3.2720x |
| QF_UF/TypeSafe | 3 | 3 | 3 | 0 | 0 | 0.9735x | 0.9735x |
| QF_UF/eq_diamond | 100 | 100 | 100 | 0 | 0 | 1.5906x | 1.5063x |

### opensmt

| Family | Instances | Viper | Comparator | Viper only | Comparator only | Total factor | Geometric factor |
|---|---:|---:|---:|---:|---:|---:|---:|
| QF_UF/20170829-Rodin | 34 | 34 | 34 | 0 | 0 | 0.9969x | 0.9968x |
| QF_UF/2018-Goel-hwbench | 773 | 773 | 764 | 9 | 0 | 1.9910x | 1.4599x |
| QF_UF/20190906-CLEARSY | 46 | 46 | 46 | 0 | 0 | 0.9678x | 0.9717x |
| QF_UF/NEQ | 48 | 48 | 27 | 21 | 0 | 4.2319x | 4.5788x |
| QF_UF/PEQ | 47 | 39 | 22 | 17 | 0 | 3.8515x | 4.1901x |
| QF_UF/QG-classification | 6396 | 6360 | 6238 | 129 | 7 | 1.5270x | 0.9007x |
| QF_UF/SEQ | 56 | 55 | 49 | 6 | 0 | 1.4176x | 1.5006x |
| QF_UF/TypeSafe | 3 | 3 | 3 | 0 | 0 | 0.9750x | 0.9750x |
| QF_UF/eq_diamond | 100 | 100 | 100 | 0 | 0 | 0.9907x | 0.9912x |
