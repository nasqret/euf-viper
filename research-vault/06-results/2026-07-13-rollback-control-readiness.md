# Rollback Control Campaign Readiness

Date: 2026-07-13

Status: published and locally verified; WMI execution not started; no timing
or promotion claim

## Question

Does the explicit rollback EUF backend reduce complete-model validation enough
to beat each existing invalid-model route on the frozen Goel pressure set,
without losing coverage or imposing material overhead on unrelated formulas?

This is an engineering control. A pass permits work on state-preserving,
component-local migration. It does not establish novelty, full-corpus
superiority, or an overall win over Yices2 or Z3.

## Immutable Implementation

- branch: `research-rollback-propagator`;
- standalone backend and telemetry: `4b60113`;
- complete campaign harness: `e8fb05c`;
- hosted campaign-contract run: `29272420042` passed;
- backend selector: `EUF_VIPER_BACKEND=cadical-rollback`;
- measured artifact: one release binary copied read-only into the reserved run
  root and rebound by SHA-256 before every stage.

The harness tests deterministic selection, source and binary tampering,
environment isolation, complete ABBA blocks, modulo sharding, CPU affinity,
hash-chain integrity, missing and duplicate records, timeout and unsupported
outcomes, telemetry accumulation, and passing and rejecting audit boundaries.

## Frozen Workset

The target stratum is the 12 exact `GRAPH_2500` Goel formulas listed in the
tail opportunity atlas. The anti-target stratum contains six SAT and six UNSAT
non-Goel formulas no larger than 262,144 bytes. Anti-targets are ranked by a
canonical hash of seed, relative path, source SHA-256, and status. Selection
therefore cannot depend on measured timing.

Preparation requires the complete 7,503-row QF_UF manifest, verifies every
selected source against its recorded byte count and SHA-256, and records a
canonical source-set digest. Missing targets, status drift, duplicate paths,
or insufficient balanced anti-targets fail before compilation or timing.

## Same-Binary Controls

Each comparison differs only in the sanitized `EUF_VIPER_*` environment:

| Comparison | Baseline | Candidate |
| --- | --- | --- |
| `current` | CaDiCaL refinement, current explanations | rollback backend |
| `model-cuts` | CaDiCaL refinement, model cuts | rollback backend |
| `dynamic` | automatic eager path with dynamic completion | rollback backend |

Four repeats produce two complete ABBA blocks per instance. A manifest ordinal
modulo four assigns each instance and all of its paired observations to one
array task. Three comparisons times four shards gives exactly 12 one-core WMI
tasks. The physical timeout is 60 seconds per solver invocation.

## Promotion Gate

For comparison (c), let (T_c) be target formulas solved correctly by both
labels. The end-to-end target gate is

\[
  \exp\left(\frac{1}{|T_c|}
  \sum_{i\in T_c}\log\frac{t_{i,\mathrm{baseline}}}
                             {t_{i,\mathrm{rollback}}}\right)
  \geq 1.10.
\]

The nearest-rank p95 of rollback-to-baseline time on common anti-targets must
be at most 1.10. Each comparison must also have at least two completed targets
whose baseline median uses more than one complete validation. On every such
target, rollback must use strictly fewer complete validations and every
candidate repeat must report at least one independently checked rollback
conflict.

The audit additionally requires zero wrong answers and execution errors, no
baseline-only solve, candidate coverage at least baseline coverage, an exact
comparison-by-shard cross-product, one shared binary hash, singleton CPU
affinity, exact ABBA multiplicities, intact record chains, and all source and
environment bindings. Empty timing or multi-round populations reject.

## WMI Command

Run only from clean published commit `e8fb05c` after restoring WMI access:

```bash
EUF_VIPER_WMI_HOST=wmicluster \
EUF_VIPER_ROLLBACK_REVISION=e8fb05c6e1a22bca83edbe687f93a6e0a3774c50 \
EUF_VIPER_ROLLBACK_CORPUS_ROOT=/home/bnaskrecki/euf-viper/benchmarks/smtlib-2025/QF_UF \
EUF_VIPER_ROLLBACK_CORPUS_MANIFEST=/home/bnaskrecki/euf-viper/benchmarks/smtlib-2025/qf_uf_manifest.jsonl \
./scripts/wmi/submit_rollback_control.sh
```

Manifest paths already include the leading `QF_UF/` component. The extracted
archive is nested as `smtlib-2025/QF_UF/QF_UF/...`, so this root and the sibling
manifest path are intentionally different.

The submitter itself must be the public research-branch head. It verifies that
the explicit campaign revision is a published ancestor, writes
`submission_intent` locally before the first `sbatch`, reserves the remote run
root with `mkdir`, and registers prepare, array, and audit jobs through
`afterok`. Invalid job IDs cancel the accepted prefix.
After SSH response loss, the interrupted receipt and reserved run root must be
reconciled with `sacct`; the run ID is never recycled.

## Blocker And Next Decision

At the last live check, SSH to `access.cluster.wmi.amu.edu.pl:22` timed out
before authentication. No rollback campaign job ID has been accepted or
claimed. Once access returns:

1. inventory `sacct`, existing run roots, and interrupted receipts first;
2. submit this exact published revision and retain the returned receipt;
3. fetch and review `final-audit.json` even when the audit job exits rejected;
4. proceed to eager-state migration only if all three comparison gates pass.
