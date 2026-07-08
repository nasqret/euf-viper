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

## Trust boundary

Format `euf-viper-euf-cnf-v1` independently checks that the emitted CNF is
UNSAT and that all appended theory clauses are valid in EUF. It does not yet
independently reconstruct the base Tseitin CNF from the SMT-LIB source. Global
certification claims remain blocked on that final translation check.
