# Production Evidence V4: Hosted Gate No-Go

Date: 2026-07-15

## Decision

Exact research commit `cd62e3c9f4bbdb9644cb06db400d91971883b6e6` is
diagnostic-only. GitHub Actions run `29389748725` failed before the Rust matrix,
so no WMI preflight, corpus run, merge, or production-certificate claim is
authorized.

## Hosted Result

- Branch: `research-production-evidence-v4`.
- Exact head: `cd62e3c9f4bbdb9644cb06db400d91971883b6e6`.
- Run: `29389748725`.
- Python result: 414 tests in 203.359 seconds, with three failures, four errors,
  and four skips.
- The workflow stopped in `Test campaign validator`; every Rust, exact-release,
  comparator, CLI, and locked-smoke step was skipped.

The failures are substantive rather than runner noise:

1. `_validate_process_record` calls undefined `_require_hash`, breaking three
   global-audit cases and the shadow resume path.
2. `build_summary` assumes `plan["python"]`, causing a `KeyError` in a final
   sidecar-mutation test.
3. Executable/source pathname substitution allowed the attacker source bytes to
   reach the process instead of the bound original source bytes.
4. Locked-campaign resume passed timeout values (`"7"`) where the test required
   the source schedule, breaking suffix reconstruction.

## Independent Review Boundary

Even a green diagnostic would not make this revision mergeable. Review found
that build metadata can be forged from inside `build.rs`; the independently
reported Rust compiler is not forced through Cargo; native, Python, loader, and
runtime closure remains incomplete; multi-artifact publication is not
transactional; and hosted identities are diagnostic rather than immutable
campaign evidence.

The next revision must first clear the complete local and hosted matrices, then
receive a new independent review. A one-input WMI environment/release preflight
may be reconsidered only after both gates are green. No WMI action used this
revision.
