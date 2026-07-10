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

Seven-repeat cross-architecture confirmation `143228` on `c2n1` kept 39/39 but
again failed all three speed boundaries: all-total 0.9997x, common-total
0.9995x, and geometric 0.9876x. This rules out treating the original `c3n1`
failure as a single-node fluctuation.

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

## Rejected Entry API Fast Path

Worst-loss profile `143224` localized the current typed+dense deficit to parse
time (0.9860x geometric, 0.9773x aggregate) plus smaller CNF, load, and SAT
shifts. Commit `d5a0e14` preserved the global interner but used
`HashMap::entry` so occupied terms skipped signature checks.

The entry path made worst-10 parse time slower by another 1.3% and failed
seven-repeat isolated sample `143232`: coverage stayed 37/37, geometric speed
was 1.0032x, but all-total/common-total regressed to 0.9935x/0.9873x. Commit
`aaffae3` reverted it. The follow-up candidate retains the original
`get`/`insert` sequence and only moves validation after the existing miss.

## Rejected Global-Get Fast Path

Commit `4a0ff44` kept the original map layout and `get`/`insert` sequence,
moving signature validation only behind the existing lookup miss. Worst-10
profile `143241` improved parse by 1.0337x and end-to-end geometric speed by
1.0167x over typed+dense.

The authoritative seven-repeat sample `143239` stayed 37/37 and improved
all-total/common-total to 1.0011x/1.0021x, but geometric speed failed at
0.9955x. Commit `6973ed4` reverted the candidate. The next experiment changes
the operation count more substantially: validate argument sorts once over
unique interned applications after parsing, not once per syntax occurrence.

## Rejected Unique-Term Validation

Commit `5f67b6f` moved argument-sort checking from every syntax occurrence to a
single post-parse pass over unique interned applications. Immediate undeclared
function and arity errors remained unchanged; malformed argument sorts were
rejected before solving with their original diagnostics. All 98 all-feature
release tests passed. Its WMI binary SHA-256 was
`43e702ba413ad9f57d408a6575db26b4b3381111fd45423e45446b7140b81ba7`.

Worst-10 profile `143246` improved parse by 1.0127x and end-to-end geometric
speed by 1.0159x. Seven-repeat sample `143244` stayed 37/37 and improved
geometric speed to 1.0017x, but heavy QG regressions pulled all-total and
common-total down to 0.9931x and 0.9865x. The strict gate rejects the candidate;
no production-baseline, hot-400, or full-corpus run is justified.

## Artifacts

- Initial typed sample: `results/wmi/typed-sorts-sample40-142943/`.
- Deferred-diagnostic sample: `results/wmi/typed-sorts-fast-sample40-143080/`.
- Dense lookup isolation: `results/wmi/dense-fun-decls-sample40-143178/`.
- Dense typed versus accepted pre-typed:
  `results/wmi/typed-dense-vs-pretyped-sample40-143188/`.
- Dense typed versus accepted pre-typed on `c2n1`:
  `results/wmi/typed-dense-vs-pretyped-c2-sample40-143228/`.
- Rejected exact-term reuse:
  `results/wmi/exact-term-reuse-sample40-143202/`.
- QG phase profile: `results/wmi/typed-dense-profile-qg5-143209/`.
- Rejected guarded-context removal:
  `results/wmi/remove-guarded-context-sample40-143220/`.
- Worst-10 typed profile:
  `results/wmi/typed-dense-profile-worst10-143224/`.
- Rejected entry fast path:
  `results/wmi/entry-fast-profile-worst10-143236/` and
  `results/wmi/entry-fast-sample40-143232/`.
- Rejected global-get fast path:
  `results/wmi/get-fast-profile-worst10-143241/` and
  `results/wmi/get-fast-sample40-143239/`.
- Rejected unique-term validation:
  `results/wmi/unique-sort-profile-worst10-143246/` and
  `results/wmi/unique-sort-sample40-143244/`.

## Decision

Keep dense declaration indexing in the research branch because it is a clean
measured improvement, but do not call the typed branch accepted and do not
start substitution. Promotion still requires a direct win over `58efe9d`,
then hot-400 and complete-corpus gates with no coverage loss or error.
