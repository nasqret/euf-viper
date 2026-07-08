# UNSAT Certificate Milestone

Date: 2026-07-08

## Artifact contract

`euf-viper certify INPUT --out-prefix PREFIX` produces:

- `PREFIX.cnf`: exact DIMACS consumed by the proof-producing SAT run;
- `PREFIX.drat`: ASCII DRAT emitted by a fresh CaDiCaL instance;
- `PREFIX.euf.json`: source, term, atom, clause-category, and SHA-256 metadata.

Certificate mode omits finite-domain shortcuts. It starts with Tseitin,
transitivity, and congruence clauses, then learns EUF explanation clauses until
the Boolean CNF is UNSAT. `check_certificate.py` validates the three hashes,
checks the DRAT proof with `drat-trim`, and independently replays every non-base
clause as an EUF tautology.

## Local canaries

The reproducible smoke script passed:

| Instance | Variables | Clauses | Replayed theory clauses | Learned conflicts |
|---|---:|---:|---:|---:|
| basic function congruence | 2 | 3 | 1 | 0 |
| equational diamond | 9 | 19 | 6 | 0 |
| predicate congruence | 3 | 5 | 2 | 0 |
| equality transitivity | 3 | 6 | 3 | 0 |
| 1,000-edge chain | 1,002 | 1,004 | 1 | 1 |

The SAT chain was rejected with `input is satisfiable; no UNSAT certificate
exists`.

## Official corpus smoke

Two SMT-LIB 2025 QF_UF instances also passed the independent checker:

| Instance | Variables | Clauses | Replayed theory clauses | Source SHA-256 |
|---|---:|---:|---:|---|
| `20170829-Rodin/smt3166111930664231918.smt2` | 5 | 8 | 0 | `1abb91b15a44b6be0202349f3f747f3dfb892aefbca9fe65f84c132c269c4e89` |
| `TypeSafe/z3.1184163.smt2` | 4 | 5 | 1 | `b9f7f1d6254ef94dd6472cfd24690e0652e30d2c734c219b69e4ee508fccf578` |

The first certificate had DIMACS hash
`d2aa935dfde5e4d452516ce09dc2fda256e89692d2ed79bb9a343535e65c7a01`;
the second had
`0dda8634051cd8ce3482ddbbf9f34ebcf5189ea1a5876f4d2c3841d1ba1d5a56`.
Pinned `drat-trim` accepted both proof traces and the Python checker replayed
the TypeSafe theory clause.

## Trust boundary

Format `euf-viper-euf-cnf-v1` independently checks that the emitted CNF is
UNSAT and that all appended theory clauses are valid in EUF. It does not yet
independently reconstruct the base Tseitin CNF from the SMT-LIB source. Global
certification claims remain blocked on that final translation check.
