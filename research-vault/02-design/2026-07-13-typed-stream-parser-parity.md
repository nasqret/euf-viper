# T1 Typed Streaming Parser Parity

## Scope

T1 is isolated from production solving. `solve`, `stats`, certification, and
portfolio execution continue to use the existing tree parser. The streaming
front end is reachable only through:

```text
euf-viper parse-check FILE
```

The old checkpoint `58f015b` is not merged. Its event-scanner idea is reused,
but its untyped `arity/result_is_bool` reducer, parser routing environment, and
tree fallback are discarded.

## Typed Contract

The streaming scanner constructs one top-level S-expression at a time and
feeds the current typed `ParseCtx`. The tree parser and stream parser each
produce a `Problem`. A deterministic `TypedSemanticSnapshot` compares:

- interned symbol spellings and declared sort bindings;
- every function argument/result signature;
- every term's function, arguments, and result sort;
- application order and the complete term-interning map;
- equalities, disequalities, Boolean assertions, and Boolean-as-data terms;
- ordinary and Boolean unsupported diagnostics; and
- the contradiction flag.

Before comparison, both results must satisfy the same well-sorted invariant.
The invariant checks declaration sort IDs, term signatures, interning and
application indexes, equality endpoint sorts, Boolean term sorts, and every
Boolean expression recursively.

There is no fallback route. A tree error, stream error, ill-sorted result, or
snapshot difference makes `parse-check` fail. A match emits one ASCII JSON line
with `fallback=false` and a deterministic snapshot fingerprint. This is parity
telemetry, not a speed result.

The scanner rejects nesting above 8,192 levels. This bound is deliberately
above the frozen corpus maximum of 4,244 while remaining finite and directly
tested. The earlier 512-level bound rejected 17 tree-accepted NEQ sources and
was therefore not a valid parity boundary.

## Full-Corpus Gate

`scripts/bench/typed_parser_parity.py` implements three fail-closed phases:

1. `prepare` validates the exact 7,503-row source manifest, source bytes and
   SHA-256 hashes, exact Git revision, executable hash, tool hash, and a frozen
   contiguous workset. It also records the fixed parser environment:
   `EUF_VIPER_SCOPED_LET=auto`,
   `EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT=1024`, and an unset
   `EUF_VIPER_PROFILE`.
2. `run-shard` rechecks every source hash and invokes only `parse-check`.
   Tree rejection, mismatch, fallback, malformed output, timeout, and generic
   errors remain separate record statuses. Every row records the same parser
   environment, and execution fails before parsing if the ambient values drift.
3. `audit` requires exactly 7,503 contiguous source-bound records and the count
   `{match: 7503, fallback: 0, mismatch: 0, error: 0}`. It writes merged records
   and hashes every shard and aggregate input. Ambient or row-level parser
   environment drift is a hard audit error.

The WMI prepare, array, and audit jobs form an `afterok` chain. Preparation
builds the exact detached revision and runs a typed Bool-as-data preflight.
All three jobs override inherited scoped-let and term-limit values and unset
the profile before invoking the campaign tool; the submitter also pins these
values explicitly despite retaining `--export=ALL` for unrelated job state.
The submitter accepts only a clean revision published at
`origin/research-typed-stream-parity`.

Passing this gate permits a separate parser-inclusive ABBA timing experiment.
It does not promote the stream parser into `solve` and does not establish a
speed claim.
