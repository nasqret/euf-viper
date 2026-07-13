# T1 Typed-Parser Parity Review: GO

Date: 2026-07-13

Research revision: `e77846df010ff777a3dd50d510d0a89cff10f1e6`

Evidence integration commit: `84b4c8e`

Source-complete integration commit: `00c11a5a69a53d24f3f09aed516f483a17de1e86`

Decision: GO for typed-parser parity integration only.

## Evidence Chain

- prepare `146510`: completed `0:0`;
- 128-task array `146511`: every task completed `0:0`;
- audit `146512`: completed `0:0`;
- independent stdin-only reconstruction `146652`: completed `0:0`.

Both reconstructions report 7,503 source, workset, record, and shard rows with
7,503 matches and zero fallback, mismatch, error, or other status. Total source
bytes are 988,035,549.

## Repaired Boundary

The executable is opened with no-follow semantics, hashed and fingerprinted on
that descriptor, executed through `/proc/self/fd/N`, and checked again after
execution. Python is bound by canonical realpath, version, and executable hash.
Duplicate keys, `NaN`, and infinities fail at every prepare, workset, shard,
record, and audit boundary.

The independent reviewer reproduced all rows without invoking the campaign
checker and confirmed local, public, remote, and artifact revision equality.

## Frozen Hashes

- binary: `001df316c18d86efce4f81b20a640daa334177dbd0effcf944734999e32e46e2`;
- records: `9b40c47167bc7f6adc45004469d76fc06ca25c7e56b5f592c74b5b4dfa4d720d`;
- audit: `7724a375a4f62d0862aa38230ed008ee877118298dd1ceaecfda76eb58af7b92`;
- independent reconstruction:
  `61d3a50d57683b126cfe20bc581f1e57b033b6f9bdd9b0bd943cfce2f3295596`;
- submission receipt:
  `e395b077eafebf5b54254e55f2c97d264fc11f2ae248c1d43949f5e77576533f`.

## Limits

The remote checkout has one untracked corpus symlink. It is non-authoritative:
the manifest and every source byte are independently hash-bound. Also, 98
matching records contain 4,851 unsupported diagnostics. The evidence proves
semantic-snapshot parity under the frozen contract, not parser completeness,
solver correctness, or speed. The production tree-parser solve path is unchanged.
