---
title: Authoritative staged Yices opportunity atlas
date: 2026-08-03
status: diagnostic-complete
campaign_revision: 30828a4f0c1e7e478a9c6f406ccb245eeefc4961
chain_id: 147306
promotion_eligible: false
---

# Authoritative staged Yices opportunity atlas

This diagnostic reconstructs the effective observations of the post-parser-fix
full QF_UF campaign directly from its immutable 2/60/1200-second staged
evidence. It replaces opportunity estimates taken from the obsolete flat
`143248` CSV, but it does not itself promote a solver revision.

## Evidence

- Corpus: 7,503 instances, six recorded solvers, 45,018 effective observations
  per budget. The repaired analyzer takes its required comparator matrix from
  the staged `candidate_id`, `baseline_ids`, and `solver_binary_sha256`
  declarations rather than inferring it from surviving rows.
- Source revision: `30828a4f0c1e7e478a9c6f406ccb245eeefc4961`.
- Continuation chain: base preparation `144990`, chain `147306`.
- Reconstruction job `218741` produced the hash-bound staged report; its first
  atlas pass then failed closed on a family-name convention.
- Final atlas job `218746` completed on `c3n1` in 46 seconds with 401,360 KiB
  MaxRSS.
- Local artifact index:
  `results/wmi/yices-opportunity-30828a4-chain147306/index.json`.

## Bounded audit repairs

Atlas schema v2 retains unquantized wall times and deficits for comparisons and
cohort selection, but serializes geometric factors to 12 significant decimal
digits. This removes the observed one-ULP Linux/macOS `math.exp` difference from
canonical JSON without changing any ranking, solve count, or deficit.

Each regenerated atlas also contains a self-hashed prospective cohort manifest
bound to the selected dataset hash. Its targets are the first 100
common-correct instances ordered by descending positive
`Viper time - Yices time`, with `relative_path` ascending as the tie-breaker.
For every `(source family, expected SAT/UNSAT status)` target stratum, controls
are selected without replacement from common-correct non-target instances in
the same stratum. Their order is the ascending SHA-256 of a fixed domain,
family, status, and path tuple, with path as the digest tie-breaker. Control
entries contain paths only: their selection makes no baseline timing or deficit
claim.

## Direct comparison

The geometric factor is `Yices time / Viper time` on positive-time instances
solved correctly by both solvers. A value below one favors Yices.

| Budget | Viper solved | Yices solved | Common | Viper wins | Yices wins | Geometric factor | Net Viper deficit | Positive deficit |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 60 s | 7,480 | 7,500 | 7,478 | 1,492 | 5,986 | 0.490090 | 2,605.34 s | 2,670.93 s |
| 1,200 s | 7,502 | 7,503 | 7,502 | 1,495 | 6,007 | 0.483825 | 4,911.11 s | 5,437.86 s |

At 60 seconds, geometric parity requires about a 2.04x Viper speedup on the
common-correct set. At 1,200 seconds it requires about 2.07x. Longer time
nearly closes coverage but exposes more expensive Viper solves, so the timing
gap grows rather than disappearing.

## Sixty-second deficit map

| Family | Instances | Common | Viper wins | Yices wins | Geometric factor | Positive deficit |
|---|---:|---:|---:|---:|---:|---:|
| QG-classification | 6,396 | 6,384 | 1,358 | 5,026 | 0.500342 | 1,915.29 s |
| 2018-Goel-hwbench | 773 | 764 | 83 | 681 | 0.426186 | 474.03 s |
| PEQ | 47 | 43 | 3 | 40 | 0.223246 | 118.44 s |
| SEQ | 56 | 56 | 2 | 54 | 0.336991 | 86.86 s |
| NEQ | 48 | 48 | 12 | 36 | 0.466074 | 75.26 s |

The worst 10, 50, 100, and 500 common-correct losses contain respectively
16.1%, 42.9%, 56.1%, and 78.8% of all positive deficit. This supports two
parallel optimization lanes:

1. A prospective tail lane over the frozen worst 100 instances plus the
   hash-selected matched controls can falsify targeted mechanisms quickly.
2. A broad QG/Goel lane is mandatory because isolated tail repair cannot close
   a roughly 2x geometric gap across thousands of instances.

## Promotion rule

A development experiment remains non-promotable until an ABBA same-node run
shows at least a 1.05x improvement in both geometric and aggregate time on its
predeclared cohort, captures meaningful positive-deficit mass, and introduces
no coverage or correctness regression. Surviving mechanisms then advance to a
fresh full staged comparison against the pinned Yices binary.

## Consequence for T11

The atlas supports testing proof-internal equality resolution as a T11
hypothesis on the PEQ/SEQ-style tail; it does not establish that the mechanism
causes or repairs those deficits. Likewise, QG is a mandatory broad target, but
finite-table proof complexity and broad per-instance overhead are competing
causal hypotheses that require profiles and controlled ablations. No T11-only
result can establish overall Yices parity from this atlas.
