# T5 Evidence Review: No-Go

Date: 2026-07-13

Reviewed revision: `e930abf2a7fe0e89efbb6a4d73540ef2fe266175`

Decision: reject WMI submission pending another evidence-wrapper repair

## What Passed

- The full verifier reconstructs the 7,503-source contract, parser/source
  commitments, row invariants, terminal chain, decoder oracle, targets,
  aggregate, and gates.
- Missing/extra row keys, Boolean-as-integer values, terminal-chain rebinding,
  extra aggregate/target keys, zero receipt hashes, and ordinary aggregate
  mutation are rejected.
- The path remains source-only and has no SAT/UNSAT solver invocation.
- Remote Python realpath, version, and executable SHA-256 are checked before
  analyzer, verifier, and metadata phases.
- Focused suite passed 57 tests; hosted CI on the exact public revision passed.

## Blocking Findings

1. The finalizer does not itself replay the full semantic verifier. Coordinated
   changes to a source ID plus record chain, a schema-invalid target,
   `implementation_allowed`, or decoder counters/digest can still produce
   `status: completed` when the mutable verifier receipt is changed
   consistently.
2. A check-to-publish race remains. An aggregate change after the final digest
   check and immediately before metadata publication yields completed metadata
   whose recorded aggregate digest no longer matches the file.
3. A failed rerun can leave an older completed receipt. The verifier can also
   write `verified=true, validity_pass=false` before `--require-validity` exits
   nonzero.
4. The dedicated remote checkout ignores untracked files. An untracked Python
   module under `scripts/bench` can affect imports despite the claimed exact
   revision.

## Required Repair

- Completion must run full semantic verification over captured bytes and
  publish a new immutable bundle built from those exact bytes.
- Publication must be atomic into a previously nonexistent destination and
  remain correct under a deterministic mutation immediately before publish.
- Every failure path must remove or invalidate completion metadata; rejected
  verifier output must never carry a successful status.
- The remote checkout must be clean including untracked files, with sanitized
  Python import state.
- Coherent mutation and stale-receipt regressions must pass before a third
  review.

No WMI job was submitted. This is an evidence-integrity rejection, not a
decision about T5's structural opportunity.

Related: [[2026-07-13-unresolved-track-refresh]] and
[[2026-07-13-t3-m0-telemetry-contract]].
