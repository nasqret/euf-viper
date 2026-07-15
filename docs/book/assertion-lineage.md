# Assertion Lineage

The T8 assertion-lineage layer is an opt-in, source-only prerequisite. It ends
at the typed `Problem`/`BoolProblem` boundary and never invokes a SAT backend,
frontier search, or SIMD code. It does not establish solver coverage,
correctness, or performance.

## Byte Binding

The `lineage` feature adds one CLI command without changing the default solve
path:

```bash
cargo +1.96.0 build --release --locked --features lineage
target/release/euf-viper lineage SOURCE.smt2 \
  --source-sha256 EXPECTED_SHA256 \
  --source-bytes EXPECTED_BYTES \
  --out SOURCE.lineage.json
```

The command opens the final source component with `O_NOFOLLOW`, requires a
regular file, reads one descriptor into one byte buffer, checks the expected
SHA-256 and size, and rechecks descriptor bytes and path identity before and
after publication. Mutation, replacement, truncation, symlink substitution,
malformed UTF-8, or a stale manifest identity fails closed.

Every top-level command receives a zero-based, half-open byte span. Every
source assertion records its command ordinal, source ordinal, exact span,
SHA-256 of the exact command slice, and SHA-256 of a lossless raw token tree.
The latter removes comments and layout between tokens while preserving token
kind and exact quoted-symbol spelling. Repeated identical assertions therefore
have the same raw-AST identity but distinct command IDs and spans.

## Typed Objects

The feature-gated recorder uses the authoritative typed tree parser. It records
all stored source Boolean roots and every parser-created object at that
boundary:

- term-ITE result terms and the two defining Boolean assertions;
- materialized Bool-as-data terms and defining equivalences;
- shared internal true/false terms;
- EUF equalities and disequalities extracted by the current parser;
- parser contradiction events; and
- every current problem or Boolean unsupported diagnostic.

Each object carries a closed transformation kind, deterministic local index,
typed-object hash, and a sorted, duplicate-free list of complete source
assertion identities. Macro-owned auxiliaries accumulate every unshadowed
source use transitively. Lexical `let` bindings take precedence over macro
names, including quoted names. An auxiliary with no source assertion origin,
an unknown transformation, an ambiguous assertion mapping, or a mismatch
between recorder counts and the typed `Problem` is rejected.

Ordinary parsing initializes no recorder. In a feature-off build the recorder
field is absent entirely; in a feature-on ordinary solve it remains `None` and
allocates nothing.

## Independent Check

`scripts/cert/verify_assertion_lineage.py` is a separate Python
verifier/reconstructor. It has its own no-follow source reader, lossless
SMT-LIB command parser, raw-AST encoding, strict JSON loader, and supported
fixture lowering. It reconstructs command and assertion spans directly from
source bytes, checks every origin against those records, rejects duplicate
keys and non-finite numbers, requires canonical JSON, and recomputes the
ledger commitment.

The adversarial fixture independently reconstructs quoted macro shadowing,
nested simultaneous `let`, repeated identical roots, shared macro-generated
Bool-as-data auxiliaries, and term-ITE auxiliaries. Generic census verification
uses the independent source/span and structural checks; the fixture subset also
reconstructs the expected auxiliary multiset without calling Rust code.

## Frozen Census

`campaigns/t8-assertion-lineage-census-v1.json` preregisters a 64-shard WMI
census over exactly 7,503 physical SMT-LIB 2025 QF_UF sources. The audit gate
requires:

- exactly 7,503 records, relative paths, and unique `(device,inode)` pairs;
- one exact clean Git revision, parser-source revision, and build-source
  revision;
- zero parse, source-hash, lineage, verifier, unsupported-accounting, missing
  row, or solver-invocation errors; and
- no SAT/UNSAT result field or solver invocation.

Accounted parser unsupported diagnostics are retained with exact messages and
command identities; they are not silently reclassified as lineage errors.
`scripts/wmi/euf_viper_t8_lineage_census.sbatch` only dispatches the source
census. There is intentionally no submit helper, and this campaign has not
been submitted.
