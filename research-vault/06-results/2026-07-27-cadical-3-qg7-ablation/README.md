# CaDiCaL 3.0.1 QG7 Compatibility Ablation

This local arm64 experiment asks whether the current CaDiCaL 3 release is a
drop-in improvement for Viper's dense-seven route. It is a compatibility and
configuration ablation, not broad performance evidence.

## Frozen inputs

- CaDiCaL 3.0.1 source revision:
  `c60730422e758ef1cebe7aeddf2dda31c996bf04`
- RustSAT master inspected at:
  `c6c9a5be...` (its vendored CaDiCaL remained 2.2.1)
- Viper solver revision: `d2b45f5ea1263476405ca4da7fdeaf92328f1e8f`
- CaDiCaL 2.2.1 Viper binary SHA-256:
  `421ed78b2677da6f04879e0c92f191303691292e03a31e9ae638655e3dd9a941`
- CaDiCaL 3.0.1 Viper binary SHA-256:
  `b5261fcfae11a5b7262a8fcb051519488f225b95d2631569b3b6c8e916e5b9a4`

The existing RustSAT patch applied cleanly to 3.0.1. The release build and the
full all-feature suite pass: 643 tests passed and ten intentional tests were
ignored.

## Exact production-command result

The complete 36-row frozen qg7 residual was run once with the production
argument vector.

| CaDiCaL 3.0.1 setting | Correct solves | Common total | Common geometric |
| --- | ---: | ---: | ---: |
| release defaults | 8/36 | `0.8858x` | `0.9041x` |
| `preprocesslight=1` | 17/36 | `1.0001x` | `1.0004x` |
| `preprocesslight=1,factor=1` | 14/36 | `0.8957x` | `0.9090x` |

The reference CaDiCaL 2.2.1 binary solves 17/36. CaDiCaL 3.0.1 changed
`preprocesslight` to default-off; restoring it recovers parity but no measured
gain. Enabling `factor` regresses coverage and timing. Therefore Viper does not
upgrade its embedded CaDiCaL and does not enable `factor`.

## Artifact hashes

| Artifact | SHA-256 |
| --- | --- |
| `euf-viper-qg7-gap-cadical221-vs-301-exact.csv` | `4e62e744e3f72b5a71f416702144675dc5512084f505c034753f0f93ec742d45` |
| `euf-viper-qg7-gap-cadical221-vs-301-exact.json` | `3d1182b0cc8f7a4c31870a7e2a4cd1570f8313d8d5640c132e2e93305637f858` |
| `euf-viper-qg7-gap-cadical221-vs-301-preprocesslight.csv` | `c3be2f1f3578f11ed2607ac706ac6eeabe1e74671c25e1cf2822f36df0fd2346` |
| `euf-viper-qg7-gap-cadical221-vs-301-preprocesslight.json` | `5365c500cd70153f5555661c1b2c1a36ee6befde97803249580a0a25656abd7b` |
| `euf-viper-qg7-gap-cadical221-vs-301-factor.csv` | `3669f01e11bd1e09a1e6a792971b78cfc23a4e988ff89ee22f1ae2c6aff0fbb7` |
| `euf-viper-qg7-gap-cadical221-vs-301-factor.json` | `cbb215f3864bd9840b12bbf1a248f683ebf4fefd11cde470700cdca684a0569f` |

An earlier invocation used the legacy `solve` command rather than the current
production argument vector. It was quarantined and is deliberately absent
from this evidence directory.
