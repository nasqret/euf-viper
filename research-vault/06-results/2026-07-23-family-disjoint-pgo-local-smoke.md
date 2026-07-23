# Family-Disjoint PGO Local Smoke

Date: 2026-07-23

Decision: control-flow pass, PGO artifact rejected

## Contract Exercised

- Training source: `QF_UF/eq_diamond/eq_diamond24.smt2`
- Manifest expected status: `unsat`
- Explicit mode: `--allow-unknown-training`
- Training repeats: 1
- Solver timeout: 30 seconds
- Accepted ten-setting Fabric environment: recorded exactly
- Repository head: `51fc7d31a0e499fc9ffc4c30bf9227e6b8c0fdcc`
- Worktree dirty: yes
- Report promotable: no
- Rust LLVM: 21.1.8
- `llvm-profdata`: Apple LLVM 17.0.0
- Toolchain compatibility: fail

## Result

- Generation outcome: `unknown`
- Nonempty raw profiles: 1
- Profile merge: complete
- Optimized replay outcome: `unknown`
- Optimized binary bytes: 3,654,640
- Optimized binary SHA-256:
  `719a421db0cfdb4ba94e4256a8f8c10a7f03317e37319458437b3687055639f0`
- Local report:
  `/tmp/euf-viper-pgo-unknown-smoke-20260723b/artifacts/report.json`

The outcome proves only that explicit `unknown` training is profiled and
replayed consistently. It gives no solve credit and no speed, coverage,
promotion, or competitor claim. The builder now rejects the observed LLVM
version mismatch before compilation. A clean WMI build with the matching
Rust-sysroot profile tool is required for evidence.
