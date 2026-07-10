# Typed Parser Performance

Date: 2026-07-10

Status: soundness foundation implemented, performance promotion pending. The
accepted standalone binary remains source `58efe9d`.

## Purpose

Definitional substitution and future multi-sort model construction require
every term to carry a sort and every function declaration to retain its full
argument/result signature. The parser must reject cross-sort equality,
ill-sorted `ite`, arity errors, and ill-sorted applications without imposing a
net corpus slowdown.

## Implemented Soundness

Commit `94c86c0` introduced compact `SortId`, full function signatures, and
typed terms. Commit `991d700` moved the duplicate whole-assertion validation
pass to parse-error diagnostics, so valid inputs are not traversed twice.
All-feature release tests cover cross-sort equality and branches, typed Boolean
arguments, arity mismatches, and full zero-arity signatures.

The first WMI sample `142943` from `94c86c0` kept 37/37 coverage but measured
only 0.9820x all-total, 0.9649x common-total, and 0.9474x geometric speed. The
deferred-diagnostic revision had SHA-256
`0fa572d17534e52974bf5aced437e659d200b40bc201ac00743d220ecdb4f9a8`;
its within-typed sample `143080` recovered aggregate speed but remained below
the geometric gate.

## Dense Declaration Index

Symbol IDs are dense `u32` values. Commit `1820fef` replaces
`HashMap<SymId, FunDecl>` with `Vec<Option<FunDecl>>`, preserving undeclared
slots and every diagnostic. Its frozen WMI binary SHA-256 is
`375f0a2d99d45d2fbb83d0983c45de5e20da6ea28b87128684ddc356c36b7e92`.
All 97 all-feature release tests pass.

Five-repeat isolated gate `143178` compared the same typed implementation
before and after dense lookup, with equality abstraction explicitly off:

| Coverage | All-total | Common-total | Geometric | Baseline wins | Candidate wins |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 37 -> 37 | 1.0102x | 1.0203x | 1.0129x | 11 | 26 |

There were no one-sided solves, wrong answers, or execution errors. Dense
lookup is a measured improvement within the typed branch.

## Accepted-Baseline Comparison

Gate `143188` then compared the dense typed binary directly with accepted
pre-typed source `58efe9d`, binary SHA-256
`4d5431135c95a2c528d287efd2803eaf895a5ec526c9642a570797b02fd47eb7`:

| Coverage | All-total | Common-total | Geometric | Baseline wins | Candidate wins |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 37 -> 37 | 0.9962x | 0.9923x | 0.9835x | 26 | 11 |

The branch therefore remains unpromoted. The next candidate must preserve
strict first-seen signature checking while avoiding redundant checks when the
exact `(function, argument TermIds)` application was already validated and
interned.

## Rejected Exact-Term Reuse

Commit `f7b52fb` replaced the composite interning map with a dense per-function
index so exact argument slices could be queried without allocation. It skipped
signature checks only for an already validated `(function, argument TermIds)`
hit; first-seen malformed applications remained rejected, and 99 all-feature
release tests passed. Its WMI binary SHA-256 was
`009462d5d6982e943f08b23669101ce7aa836c9ac455fcf77593df3beaad7872`.

Five-repeat isolated sample `143202` kept 37/37 coverage. Geometric speed was
effectively flat at 1.00003x, while all-total and common-total failed the strict
gate at 0.99995x and 0.99987x. The change was reverted in `d69792a` without a
production-baseline, hot-400, or full-corpus run.

## Rejected Guarded-Context Removal

Phase profile `143209` showed typed+dense parse medians were faster on all four
completed QG controls, by 1.006x to 1.063x. This weakened the hypothesis that
sort parsing itself explains the remaining end-to-end loss. Commit `93e2d90`
therefore removed the rejected guarded-facts implementation and its shared
finite-analysis context while preserving typed+dense code.

Five-repeat isolated gate `143220` again kept 37/37. Geometric speed improved
to 1.0036x, but all-total and common-total failed at 0.9992x and 0.9985x. The
strict gate rejected the removal, and `92a7a8f` restored the default-off
implementation. The remaining production gap is not attributable to that
context refactor alone.

## Artifacts

- Initial typed sample: `results/wmi/typed-sorts-sample40-142943/`.
- Deferred-diagnostic sample: `results/wmi/typed-sorts-fast-sample40-143080/`.
- Dense lookup isolation: `results/wmi/dense-fun-decls-sample40-143178/`.
- Dense typed versus accepted pre-typed:
  `results/wmi/typed-dense-vs-pretyped-sample40-143188/`.
- Rejected exact-term reuse:
  `results/wmi/exact-term-reuse-sample40-143202/`.
- QG phase profile: `results/wmi/typed-dense-profile-qg5-143209/`.
- Rejected guarded-context removal:
  `results/wmi/remove-guarded-context-sample40-143220/`.

## Decision

Keep dense declaration indexing in the research branch because it is a clean
measured improvement, but do not call the typed branch accepted and do not
start substitution. Promotion still requires a direct win over `58efe9d`,
then hot-400 and complete-corpus gates with no coverage loss or error.
