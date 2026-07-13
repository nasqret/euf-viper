# T8 Contract Control Review

Date: 2026-07-13

Scope: preregistration and negative-evidence control only

Decision: GO to retain the frozen control; no scalar or SIMD implementation is
authorized.

## First Review

The first independent review found two low-severity interface gaps at
`eb80ab6`:

- hosted CI consumed the contract and P12 summary but not the T4 rejection
  receipt;
- the CLI required the P12 summary, while the Python helper could validate the
  contract without it.

Neither gap enabled implementation, but both were repaired rather than waived.

## Closure

At `14754f8`, the contract binds the raw T4 receipt SHA-256, the validator
checks the receipt's exact bytes and semantics, and hosted CI supplies both the
P12 summary and receipt. The Python API now requires both paths.

The focused re-review confirmed that:

- receipt status and nested summary-hash mutations fail;
- omitted-summary, omitted-receipt, and omitted-both API calls raise
  `TypeError`;
- valid output remains `implementation_authorized=false` and
  `simd_authorized=false`;
- hosted run `29290493620` passes at exact commit `14754f8`.

The final small coverage note, separate tests for each omitted argument, was
added to the checkpoint. The T8 design remains blocked on independent T1
acceptance, complete assertion/auxiliary lineage, and a checked P12 finite-domain
certificate.
