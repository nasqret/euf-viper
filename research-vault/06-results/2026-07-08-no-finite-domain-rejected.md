# Disabling Finite-Domain Routing Rejected

Date: 2026-07-08

A/B array: `139710`; merge: `139711`

## Hypothesis

The eager one-hot finite-domain encoding can create difficult resolution
proofs. Test whether bypassing that route improves the 69-instance hard tail
left by the 60-second campaign.

## Protocol

Both configurations used the accepted CaDiCaL invalid-model fallback and the
same binary. The baseline used automatic backend selection. The candidate
forced Kissat, bypassing finite-domain routing. Each of the 69 prior
`euf-viper` timeouts ran once per configuration with a 60-second timeout.

## Result

| Metric | Automatic finite route | Finite route disabled |
|---|---:|---:|
| Correct | 12/69 | 8/69 |
| Configuration-only solves | 5 | 1 |
| Timeout-inclusive total | 3,824.18s | 3,782.85s |

There were no wrong answers or execution errors. The candidate was 1.6174x
faster on the seven cases both configurations solved and showed a 1.7624x
geometric speedup, but those metrics exclude five baseline-only solves. The
1.0109x timeout-inclusive total gain is therefore bought with a four-instance
coverage regression.

## Decision

Reject. Keep automatic finite-domain routing. Common-solved speed alone is not
an acceptable optimization gate when the candidate loses coverage.
