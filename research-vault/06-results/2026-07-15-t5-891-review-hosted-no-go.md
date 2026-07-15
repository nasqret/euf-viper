# T5 891c34e Review: Bytecode And Workflow No-Go

Date: 2026-07-15

## Decision

Exact commit `891c34e7eb3425e3580cf71961e15f41aa3e189f` is published on
`research-t5-component-quotient-census-recovered` only as a diagnostic.
Independent review allows source-only evaluation from a freshly cleaned,
provisioned checkout, but not the WMI canary or full census. Exact hosted run
`29398119605` failed before creating any job. No corpus source was scanned.

## Confirmed

- The scanner follows transitive free globals through quoted and shadowed
  macros and rejects unsupported top-level forms.
- The physical ledger requires 7,503 unique sources and binds source identity,
  namespace, scheduler receipt, canary mode, and final artifact structure.
- Relevant local Rust, Python, shell, and adversarial contract matrices passed
  at the reviewed commit.

## Review Finding

The environment canary imports `t5_linux_publication` before validating the
checkout. Ordinary `git clean` ignores ignored files, so unchecked-hash Python
bytecode can execute when the corresponding source is absent. Diagnostic branch
publication and a freshly cleaned source-only scan were allowed; even the tiny
WMI canary was rejected until import isolation is fail-closed.

## Hosted Failure

Run `29398119605` has conclusion `failure` and zero jobs. The workflow is valid
YAML, but GitHub rejects this job-level assignment:

```yaml
EUF_VIPER_T5_E2E_ARTIFACT_DIR: ${{ runner.temp }}/t5-semantic-artifacts
```

Actionlint v1.7.12 reproduces the exact error at line 131: context `runner` is
not available at job-level `env`; only `github`, `inputs`, `matrix`, `needs`,
`secrets`, `strategy`, and `vars` are available there. The separate custom
`t5-corpus` runner-label diagnostic is linter configuration, not the workflow
rejection.

## Required Repair

Move temporary-path derivation into a step context, make every pre-validation
import immune to source-less bytecode, and rerun the exact-head hosted workflow.
Repeat independent review before any corpus scan or WMI submission.
