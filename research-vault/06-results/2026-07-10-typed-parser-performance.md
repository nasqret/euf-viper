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

## Artifacts

- Initial typed sample: `results/wmi/typed-sorts-sample40-142943/`.
- Deferred-diagnostic sample: `results/wmi/typed-sorts-fast-sample40-143080/`.
- Dense lookup isolation: `results/wmi/dense-fun-decls-sample40-143178/`.
- Dense typed versus accepted pre-typed:
  `results/wmi/typed-dense-vs-pretyped-sample40-143188/`.

## Decision

Keep dense declaration indexing in the research branch because it is a clean
measured improvement, but do not call the typed branch accepted and do not
start substitution. Promotion still requires a direct win over `58efe9d`,
then hot-400 and complete-corpus gates with no coverage loss or error.
