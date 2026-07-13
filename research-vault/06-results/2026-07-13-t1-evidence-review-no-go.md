# T1 Evidence Review: No-Go

Date: 2026-07-13

Reviewed revision: `7214d6396905466b459ca7d614bc2e1c6c85ec93`

Reviewed WMI chain: `146374` / `146375` / `146376`

Decision: reject integration and regenerate full parity evidence after repair

## Valid Mechanical Result

The fresh campaign completed 7,503 exact rows with
`match=7503, fallback=0, mismatch=0, error=0`. It bound the same captured source
bytes to source hashing and `parse-check -`, and independently reconstructed all
128 shard hashes. Key hashes were:

- audit: `fea1b2ec59df0187e62d38bd7a996f3fa30c9cbdecee6520dca485364c59d355`;
- records: `ea41a7b31de5da39d0eb7ccaaf864ad1a1093dcff5b30a62cfcc070c8a5b6ebb`;
- prepare: `cfa226b1e2beb3f243f41cdd49d2dbb461595784206580664af48f050ec5cc5c`;
- workset: `6ed706949a02840cab5f65bf5d8b08d26ee73eb72753eb98f6bb6c648c76fa29`.

This remains useful reproduction evidence, but it does not clear the integrity
gate below.

## Blocking Findings

1. The parser executable is hashed during prepared-state validation and later
   reopened by pathname. A same-size replacement restored before audit emitted
   a forged matching fingerprint and passed the audit.
2. WMI Python is recorded and invoked through the configured absolute alias,
   not its canonical realpath. A symlink alias was accepted unchanged; the
   evidence therefore does not bind the actual interpreter target as claimed.
3. Artifact JSON is permissive outside the parser payload. A shard record with
   `exit_code: NaN` passed audit and propagated `NaN` into merged records.

## Confirmed Fixed

- Each source is captured once and the same bytes are hashed and supplied to
  `parse-check -`.
- Prepare, workset, shard, merged-record, and audit parsing/hashing use captured
  or generated buffers rather than hash/parse double opens.
- Parser stdout has one LF-framed object, exact keys, strict booleans and
  nonnegative counts, and a 16-lowercase-hex fingerprint.
- Fallback, mismatch, depth failure, and generic errors remain distinct.
- Production solving still uses the authoritative tree parser; no speed claim
  exists.

## Required Repair

- Execute the exact no-follow-opened and hashed binary object, for example via
  a stable inherited descriptor on Linux, so pathname replacement is irrelevant.
- Canonicalize and bind the interpreter realpath before every hash, invocation,
  and receipt.
- Reject duplicate keys and non-finite constants in every artifact and require
  exact row schemas and strict field types.
- Add deterministic replacement, alias, duplicate-key, and `NaN` regressions,
  then rerun all 7,503 sources under a fresh WMI chain.

T1 remains parser-parity research only. Timing is still unmeasured.

Related: [[2026-07-13-typed-stream-parser-parity]] and
[[2026-07-13-t8-source-exact-scalar-contract]].
