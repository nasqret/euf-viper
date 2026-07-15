# T5 48f3cec Review: Hosted Diagnostic Green, WMI No-Go

Date: 2026-07-15

## Decision

Exact commit `48f3cec3b09b42fc6e5dc407f7207cf86434cc20` is acceptable as a
diagnostic research branch only. Hosted run `29392694401` passed its mandatory
ordinary-Linux publication/procfs job and root Rust/Python checks, but the
provisioned 7,503-source semantic job truthfully skipped because no corpus was
present. Independent review rejects corpus scanning, any WMI canary, the full
census, merge, and promotion.

## Verified Repairs

- The direct `define-fun` caller-scope regression was repaired independently in
  the candidate and audit parsers.
- Held-job release now occurs after local receipt validation and persistence in
  the tested direct path.
- Mandatory Linux mechanism diagnostics are separate from the provisioned
  semantic integration job, and the hosted labels no longer imply a corpus run.

## Blocking Findings

1. The scanner does not follow transitive caller-scope dependencies through
   intermediate macros, including quoted identifiers. Hidden free globals can
   therefore escape the lexical-scope census.
2. Release and cancellation do not revalidate scheduler ownership immediately
   before mutation. Zero matching `squeue` rows can be treated as successful
   cancellation, permitting an orphaned held job or action against a recycled
   identifier.
3. The pre-release `remote_namespace` contract admits extra fields and does not
   recompute all relationships among the bound values.
4. The source scan does not prove unique physical coverage, recompute the
   source-set digest, or retain a per-source ledger. Unsupported top-level forms
   such as `define-fun-rec` can be silently ignored.
5. The proposed tiny WMI canary does not bind a clean immutable checkout or the
   complete scheduler identity, and submitted hashes are not all cross-checked.
6. Hosted identity does not require `GITHUB_SHA` to equal `HEAD`; the
   provisioned job omits the scanner and deletes results; action-pin tests do
   not cover every action use.

## Hosted Diagnostic

Run `29392694401` completed successfully. This proves the tested Linux
publication and procfs behavior on that runner and the non-corpus unit matrix.
It does not provide a 7,503-source scanner row, live Slurm accounting evidence,
or a T5 projection result.

## Required Repair

Compute transitive lexical dependencies, reject every unsupported top-level
form, bind a unique physical source ledger and digest, revalidate complete
scheduler ownership before release/cancel, close the namespace schema, and bind
hosted plus WMI execution to exact immutable revisions. Repeat independent
review before any corpus or cluster run.
