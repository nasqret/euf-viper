# Local Comparator Pin

Date: 2026-07-22

Scope: the arm64 macOS comparator bytes available in this worktree. This note
separates upstream source/release identity, downloaded upstream archive bytes,
and the exact local executable bytes. SHA-256 values below were recomputed from
local files unless explicitly marked as ledger-only.

## Evidence anchors

- Release ledger: `campaigns/solver-releases-2026-07.json`, SHA-256
  `afbc1aa43127a467540167ef5e4e6d201f1b0a3840d99cec78dd761607d66cfd`.
- Installer: `scripts/bench/install_solvers.sh`, SHA-256
  `020718c0ed501213650458978d0295c772683120e7ea935eded18fb51be3e886`.
- Host executables are Mach-O arm64. Their version commands returned Z3
  `4.16.0`, cvc5 `1.3.4`, Yices `2.7.0`, OpenSMT `v2.9.2`, and LLM2SMT
  `0.2.4` (`Release`, CaDiCaL backend).

## Exact pins

| Comparator | Source identity | Upstream or distribution archive bytes present locally | Runnable executable SHA-256 |
| --- | --- | --- | --- |
| Z3 4.16.0 | tag `z3-4.16.0`; ledger commit `ddb49568d3520e99799e364fb22f35fc67d887b1` | No Z3-upstream Darwin arm64 release asset is pinned. The installed Homebrew arm64 Tahoe bottle, which is a Homebrew distribution artifact, is `ee99aab378c77dfd90c002bcceb28164c1c78d9705df789151e781dfa26f0177`. | `/opt/homebrew/Cellar/z3/4.16.0/bin/z3`: `537a502af2f4013a8e887beebe525a0dae84918a61ff545991e36dfda07ed6d7` |
| cvc5 1.3.4 | tag `cvc5-1.3.4`; ledger commit `f3b21c4483d3b88dc63cb7cd3e5eb092eee5e341`; binary reports `f3b21c4` | Official `cvc5-macOS-arm64-static.zip`: `3840aa53f6ee6fc357415dcfe291d7f5ffec6cfb1ccca6fef64120a0d2be4cb6` | `third_party/solvers/pinned/bin/cvc5`: `76677e62998e673622edc8ad2df168cb2445177ab7a336c5a25ce149bad836e1` |
| Yices2 2.7.0 | tag `yices-2.7.0`; revision reported by binary and ledger commit `85cf17e44eac76b5d14b297c09fc9bfecf47ef65` | Official `yices-2.7.0-arm-apple-darwin24.5.0-static-gmp.tar.gz`: `5682fedf13add7818e8d05796b9133e67844fce2bb72fd1ecc75dcb73167c7ac` | Locally patched `third_party/solvers/pinned/bin/yices-smt2`: `783047ce14bfe44cfa237d217afb76ed8cd2bb22c58f37b83fec62919d7d88a0` |
| OpenSMT 2.9.2 | tag `v2.9.2`; ledger commit `34bc1b8870784a12d8e5812e1c99aacad96211c4` | Official `opensmt-arm-osx.tar.bz2`: `6c8605db38e0f62ea040cffc670e65bd5f47e4fb65ecd65c6aaf4170cd19c51c` | `third_party/solvers/pinned/bin/opensmt`: `3ae478c700539d0ea3e9c57a704596c32715b2d187bf87fdca7bb396cff4d6b6` |
| LLM2SMT 0.2.4 | local clean tracked checkout at tag `v0.2.4`, commit `b7c805c184529313d4436051eed9cda4a20e1151`, tree `2be0d5ef4e3cc8f4b0cb20db926a125bdaf3b0e7` | No upstream binary/archive bytes are present. A locally generated `git archive` tar of `v0.2.4` has SHA-256 `2a2f7a06f88375e1574aa09936aa99937ffe2f8a0be8f42c3cadb0d8c2d01507`; this is a derived source snapshot, not an upstream release asset. | Local Release build `third_party/solvers/llm2smt/build/bin/llm2smt`: `5520d1ddab12f9b3d96bbcea9318e9e6bfa2badbb02c11d3b57b79a472f9012d` |

For cvc5 and OpenSMT, the runnable executable hash equals the corresponding
freshly extracted executable hash. Archive hashes and executable hashes identify
different byte objects and are not expected to match.

## Yices dylib patch

The official archive is unchanged. Its extracted `yices-smt2` has SHA-256
`cd9ccbb41c238f510896bf3c17ea63036b059b175c85691aae952ef5569c7d00`
and loads `/usr/local/lib/libcudd-3.0.0.0.dylib`. The runnable copy rewrites that
Mach-O load command to
`@loader_path/../cudd-install/lib/libcudd-3.0.0.0.dylib`, producing the distinct
`783047...d88a0` executable hash above. The locally built CUDD dylib loaded at
that path has SHA-256
`b167acfdc4d0fa95a8f5ab1943b5e25403351c3195354f88edf25615c3bed324`.

This is a patch to the Yices executable's dylib reference, not to the archived
`libyices.2.dylib`. The latter remains in the extraction with SHA-256
`4caecf89f6ac1402413015da770c17ca11d564a05c6973294b5e6f97431bf1ab`;
`otool -L` shows that the static-GMP `yices-smt2` executable does not load it.

## Modern comparator boundary

LLM2SMT is included as a modern QF_UF comparator from the locally available
[v0.2.4 source](https://github.com/MikolasJanota/llm2smt/tree/v0.2.4) and the
already recorded [LLM2SMT case-study preprint](https://arxiv.org/abs/2603.06931).
The separate local artifact
`research-vault/06-results/2026-07-22-representative-triad-multiarm-local.json`
records one solved SAT case and two five-second UNSAT timeouts for this exact
LLM2SMT binary, with no wrong answers or execution errors. That three-case
observation is diagnostic only and establishes no corpus ranking.

## Caveats

- The first four source commits come from the existing release ledger. Only
  Yices reports the full commit at runtime; cvc5 reports its short prefix.
  Their source trees were not locally checked out and rehashed in this pass.
- Homebrew's installed Z3 was poured from a bottle. Its executable and bottle
  hashes are local byte pins, not hashes of an official Z3 Darwin arm64 asset.
- LLM2SMT is a local build from a verified Git checkout, not an upstream binary
  release. Rebuilding can change executable bytes even at the same source tree.
