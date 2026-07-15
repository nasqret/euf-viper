# T6 b587847 Review: Population Accepted, Census No-Go

Date: 2026-07-15

## Decision

The exact committed 12-source population artifact at repair commit
`b587847ad6a5cda1bfa5f76271a1255da1191e36` is accepted with SHA-256
`1b3f4e52c8c856e09205baf88b4cff8604f6d864e93373a980ba8d974e205c21`.
This accepts only the frozen population bytes. The branch itself is not
publishable, and its consumer, submission path, WMI census, and promotion
claims remain no-go.

## Independently Reproduced Facts

- The audit contains exactly 90,036 unique observations: 7,503 sources by two
  budgets by six exact solvers.
- The frozen provenance, carry-forward rules, origin budget, result, and source
  records were reproduced.
- All 12 physical sources were opened and checked. Python structural metrics
  match exact-commit Rust `stats`, including domain 7, closed tables, binary
  applications, zero guarded clauses, raw parentheses, bytes, and hashes.
- Regeneration was byte-identical. The threshold is mechanically
  `ceil(8N/10)`, yielding 10 for 12 sources.
- Focused tests passed 17/17 and the reviewed worktree remained clean.

## Blocking Findings

1. The CLI accepts caller-supplied expected digest overrides. A caller can
   replace projection-template arms or source metadata and validate against a
   matching replacement digest, defeating the frozen-input contract.
2. The Rust consumer still requires manifest v1, 10 sources, and an 8-source
   gate. The Slurm and submission scripts also select the historical hard-10
   population. Exact commit `b587847` cannot run the accepted v2 12-source
   artifact.
3. Clean-checkout corpus-manifest regeneration embeds absolute checkout paths,
   making the digest location-dependent and encouraging the unsafe override
   interface.
4. Corpus JSON parsing rejects duplicate keys but accepts non-finite constants
   such as `NaN` in otherwise unused fields.

## Consequences

Old job `146075` remains historical administrative/developmental hard-10
provenance only. It cannot confirm the accepted population or establish current
implementation eligibility. A separate reviewed commit must remove digest
overrides, reject non-finite JSON, make manifest generation path-independent,
and update the Rust/Slurm consumer to v2, 12 sources, and the derived 10-of-12
gate before any new source-only census can be considered.
