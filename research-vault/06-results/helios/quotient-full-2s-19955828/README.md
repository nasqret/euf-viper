# Helios Current-Route Full Campaign 19955828

This is the first complete, promotion-eligible, build-once sharded campaign for
solver revision `8368d21de96eec77f3bb5f6820c11d1363d3041b` under orchestration
revision `da57b301a57211dcf87cfbb8863add8526b13e2f`.

Preparation job `19955431` built the candidate once and froze the 7,503-source
taxonomy, lock, solver configuration, and 64 balanced shard locks. Array job
`19955828` produced 45,018/45,018 rows for six solver configurations.
Dependency-gated finalizer `19955833` completed the audit and analysis. The run
identity is `20260726T203358Z-da57b301a572-8368d21`.

At 2 s, Viper solves 7,436 sources, Yices2 7,490, Z3 default 7,446, Z3
`sat.euf=true` 7,459, cvc5 7,364, and OpenSMT 7,289. Against Yices2 on 7,429
common solves, Viper's comparator/candidate factors are `0.300581x` PAR-2,
`0.288925x` common total, and `0.393365x` common geometric. Viper is therefore
not the broad leader.

The 61 Yices-only solves comprise 57 QG-classification sources, one Goel
source, two PEQ sources, and one SEQ source; 52 are UNSAT. The archive is the
source for dashboard panel `panel-cce4ebc63bc3a66e` and the exact cohort report
in `docs/dashboard/euf-current-gaps.md`.

The portable replay reproduced the live audit and analysis byte-for-byte. Key
SHA-256 identities are:

- campaign audit: `1db9cfd281df1a6b13533740ab30f1999d4578df9087c2263123c62166ed04f1`;
- campaign analysis: `a5ef77ee4e235bc31b31d58ce64d987dd906794d722d70716ff08ecdd9c58ba`;
- candidate binary: `c146a7be8b2146e9d405feffc68d821608908c08d06632e738ef9ab53e9772e0`.
