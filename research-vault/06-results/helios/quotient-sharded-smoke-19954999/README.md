# Helios build-once sharded smoke 19954999

This directory preserves the first complete live execution of the build-once
Helios runner. Preparation job `19954911` built solver revision
`8368d21de96eec77f3bb5f6820c11d1363d3041b` once under orchestration revision
`683b05672484b3269b521140b511b68fdb7ca7bf`. Array `19954999` ran two
single-core shards and finalizer `19955000` completed `0:0` after both shards.

The frozen campaign contains three instances, six solver configurations, and
exactly 18 hash-bound raw records. Coverage and two-second timing factors are:

| Comparator | Viper solved | Comparator solved | PAR-2 factor | Common geometric | Common total |
| --- | ---: | ---: | ---: | ---: | ---: |
| Yices2 | 3/3 | 3/3 | 1.484x | 0.657x | 1.484x |
| Z3 default | 3/3 | 2/3 | 4.376x | 1.570x | 2.258x |
| Z3 `sat.euf` | 3/3 | 2/3 | 4.218x | 1.405x | 1.853x |
| cvc5 | 3/3 | 1/3 | 7.656x | 6.771x | 6.771x |
| OpenSMT | 3/3 | 1/3 | 7.155x | 1.709x | 1.709x |

The all-comparator analyzer rejects promotion because Viper's common-solved
geometric factor against Yices2 is below one. This selected smoke qualifies
execution mechanics only and is not corpus-level competitive evidence.

The live v1 audit is valid and has SHA-256
`cd508a1c0a5c42deaee06acb738590bbe01efadfae30fd7d4774b8c6140c535d`, but
it records absolute Helios paths. Fetch replay exposed that portability defect.
`local-replay-audit-v2.json` verifies the same candidate, locks, 18 rows, task
receipts, resource captures, and analysis after replacing those location-bound
fields with evidence-relative paths. A second live v2 smoke is required before
the full-corpus launch.

The 4.5 MB candidate binary is included so the fetched bundle can be audited
without trusting a detached hash. Its SHA-256 is
`c146a7be8b2146e9d405feffc68d821608908c08d06632e738ef9ab53e9772e0`.
