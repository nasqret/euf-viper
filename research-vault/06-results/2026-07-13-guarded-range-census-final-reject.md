# Corrected Guarded-Range Census: Final Rejection

Date: 2026-07-13

Revision: `8f785437830e9ae25ba3d0eb96e2f4c9ef66daa3`

WMI job: `146071`

Decision: stop T4 before Hall/PB solver implementation

## Integrity

The corrected source-only census completed in `01:53:20` with Slurm state
`COMPLETED`, exit `0:0`, and empty stderr. It observed exactly 7,503/7,503
sources with zero structured-parser errors. This includes the 17 deep-`let`
sources omitted by failed predecessor `145883`.

Hashes:

- aggregate: `b37b95509c36b29c1f6ab5f55d5754ce1aab0b4ec2efe447488ecfacc8cc4e42`;
- records: `4cfb2d1da7f2691485978d33b5a7a39b586246ade226d455b9516e8c74ff961c`;
- metadata: `f4efbe5a08f85c59d7aa44150064a835233a66f1853b2b1a5c642cc505df474e`;
- manifest: `32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4`;
- analyzer: `f776cea8204ba5e588b0f2c5a21379f6b9232ffe3b8164f09ad44720d5e69c00`;
- independent parser: `7438ee209f090fbc35eb15e58720ec2a54403548ec1c823641eaae28eea4811b`.

The compact evidence packet is under
`results/wmi/guarded-range-census-146071/`; the 34 MiB records file remains on
WMI and is bound by its hash.

## Opportunity Result

| Metric | Result |
| --- | ---: |
| Certified uniform domains | 157 |
| Effective candidate ranges | 25,760 |
| Proven range facts | 24,365 |
| Uniform value cells | 124,698 |
| Non-uniform value cells | 124,698 |
| Value-cell savings | 0 |
| Hall subsets checked | 24 |
| Hall conflicts | 0 |
| Eligible sources | 0 / 7,503 |

The preregistered implementation gate required at least 30% fewer value cells
on a broad source population. The measured reduction is exactly 0%; every
source is ineligible. T4 is therefore scientifically rejected before encoding,
native PB, reversible matching, or timing work. The finite-range facts remain
valid source telemetry but do not authorize a Hall/PB solver path. A direct
read of the 12 frozen qg7 rows found zero domains and zero range facts in every
case, each with `no_proven_non_bool_range`. T4 therefore cannot supply T8's
domain-seven certificate; T8 must prove that boundary separately or stop.

Successful completion released certificate prepare jobs `146076` and `146079`.
Those chains certify canonical source reruns only and remain separate from this
opportunity rejection.

Related: [[2026-07-13-corrected-opportunity-gates]],
[[2026-07-13-t8-source-exact-scalar-contract]], and
[[2026-07-13-unresolved-track-refresh]].
