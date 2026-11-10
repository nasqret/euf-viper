# Native single-audit regression fixture

This standalone Cargo package runs the four original single-audit tests from
revision `967d4d0bce9cb55a9b889e2cda5e8619ff512810`. It exercises the
measured partition, virtual adjacency, impact traversal, counters and JSON
serializer. It does **not** build a solver, parse an SMT input, reproduce a
solver execution or measure performance.

## Run

From this directory with Rust **1.93.0** and the locked crates cached:

```sh
cargo +1.93.0 test --locked --offline -j 1 --lib single_audit_ -- --test-threads=1
```

Expected: **4 passed, 0 failed, 0 ignored**. Other tests in the measured
modules are compiled but filtered out. Keep the default `fabric` feature on:
it enables the original sidecar serializer and the assertions that read its
output. The tests create their own temporary file; no audit environment
variables, solver binary or input dataset are needed.

| Original test suffix (after `single_audit_`) | What it checks |
|---|---|
| `completed_ordered_ids_only_and_scope_exclusions` | Counts physical and virtual IDs in the targeted walk, excludes direct and whole-partition reads, and verifies the JSON receipt. |
| `partial_first_pass_cannot_be_promoted_to_duplicate` | A live ID on the wrong edge fails; a partial first pass earns no duplicate credit. |
| `impact_deduplicates_across_roles_not_across_calls` | Seed and neighbor roles share a seen set only within one immutable impact call. |
| `checked_batch_hits_are_not_root_traversals` | A cached batch hit does not count as an actual validation traversal. |

## Provenance and boundary

[BLOBS.json](BLOBS.json) maps every file under `src/fabric/` to its original
Git blob ID. All eleven files are byte-for-byte extracts. The inherited
test modules are included because the unchanged partition names them under
`cfg(test)`. The command below checks the complete extracted file set using
Git's blob framing; it needs neither the original repository nor a network
connection.

```sh
python3 verify_blobs.py
```

When the original Git object database is available locally, the optional
`--git-dir PATH` check (Python 3.11+) also compares each file directly with
the commit and verifies every fixture registry version and checksum against
the measured source lock. The fixture uses real `rustc-hash` 2.1.3 and
`serde_json` 1.0.150; neither is shimmed. [Cargo.lock](Cargo.lock) omits the
unrelated solver dependencies and contains no local dependency paths.

[src/lib.rs](src/lib.rs) is the only Rust harness file. Its test-only
`policy_ablation_review::forced()` returns `None`: no override from the
omitted CLI experiment. The original tests select their representation
explicitly. The hook does not implement, replace, or bypass any validation,
counter, impact traversal, or serialization logic.
