# T6 58aee6e Review: Population Accepted, WMI No-Go

Date: 2026-07-15

## Decision

Exact commit `58aee6e9cb010f60d844385e4bc820316516ea1b` is published on
`research-t6-theory-dag` only as a population/consumer diagnostic. Independent
review accepts artifact SHA-256
`33a9f0016570dc07dc4c9aed2f575633eb5a2ee10d21177c97a4e86b65507c78`
as the portable successor to `1b3f4e52...05c21`, representing the same exact
12 physical sources. No projection was executed, promotion remains false, and
hosted contract evidence, WMI census, implementation, merge, and performance
claims remain no-go.

## Independent Reconstruction

- Two independent 7,503-row corpus descriptors generated under different
  absolute roots were byte-identical at `597f8ee5...eac0a`.
- Two relocated physical-corpus derivations reproduced the committed artifact
  byte-for-byte.
- Old and new artifacts differ only by explicit `population_status`, explicit
  `projection_status`, and replacement of the absolute-path corpus digest with
  the portable descriptor digest.
- All 7,503 source rows otherwise match. The 12-source arrays, IDs, bytes, and
  structural fields are equal; total bytes are `72,154,706`.
- Canonical path digest remains `1fd24c2c...b6fa`; source-record digest remains
  `f274424d...f5b0b`; identity/bytes/structure digest remains
  `748ff7b4...cfd`.
- Removed overrides, changed inputs with matching replacement digests,
  duplicate keys, non-finite numbers, path/inode aliases, v1 hard-10 inputs,
  wrong population/threshold, and changed source rows are rejected.

Focused Python passed 26/26; full Python passed 307/307; Rust default passed
232 with three external tests ignored; all-features passed 247 with five
external tests ignored; release T6 passed nine with the external census ignored.
No projection or census ran.

## Blocking Findings

1. WMI currently exposes Rust 1.93.0. The required `cargo +1.96.0` preflight
   attempts a rustup install and fails with `Disk quota exceeded`. Global Rustup
   must not be modified by this campaign.
2. The submitter exports the ambient environment, preserves inherited target
   directories, and hashes a rustup proxy rather than the selected Cargo and
   rustc binaries. Compiler version/hash, Cargo configuration, wrappers,
   linkers, and build-affecting environment are not completely bound.
3. Hosted workflow does not run the two new T6 Python modules and uses unpinned
   Cargo without `+1.96.0 --locked`.
4. Derivation opens physical sources component-wise with no-follow stable
   snapshots and inode checks; the Rust census later uses joined pathname
   `File::open`, weakening physical provenance.
5. Slurm report validation does not independently recompute all per-row
   reductions, qualifying count, and aggregate decision from the 12 records.

## Hosted Diagnostic

Exact-head run `29397378080` completed successfully in 1m40s. This is
supplemental branch health only. Because of finding 3, it is not the exact T6
contract gate and does not authorize WMI.

## Old Job

Job `146075` remains pending at historical commit `9833ec3`, runtime zero, with
the hard-10 development contract. It cannot confirm this artifact or count
toward current projection, implementation, or promotion evidence.

## Required Repair

Require externally provisioned direct Cargo/rustc 1.96 binaries and a sanitized
explicit environment; bind complete compiler/configuration identity; run exact
T6 tests in hosted CI; use descriptor-relative no-follow stable source opening
in Rust; and independently recompute the full report. Repeat review before any
source-only WMI census.
