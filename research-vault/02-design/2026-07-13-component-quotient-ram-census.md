# T5 Component-Quotient RAM Census Contract

Date: 2026-07-14

Status: source-only opportunity census repaired after the sixth independent
review. The code now has an independent source-to-decision verifier, Linux-only
unnamed-inode publication, a content-bearing marker, and a post-job consumer.
Bounded macOS tests pass, but Linux CI has not yet established GO. No WMI
decision run was submitted. This is not a production solver route, a timing
experiment, or evidence that T5 should be implemented.

## Recovery Provenance

The old clone's `6249393` is invalid: its object database is missing objects
referenced by that identifier. It is neither a reviewable revision nor evidence
and must never be repaired, fetched from, or cited. The physical source snapshot
was recovered into a fresh clone on branch
`research-t5-component-quotient-census-recovered`, rooted at valid origin
revision `e930abf2a7fe0e89efbb6a4d73540ef2fe266175`; that clone passed
`git fsck --full` before the snapshot was reviewed. Provenance begins with the
new commit made from the recovered files, not with `6249393`.

## Purpose

The T5 census asks one deliberately narrow question before behavioral work:
does a component-local quotient representation with sorted function records
have a broad structural construction advantage over eager EUF completion?

The analyzer parses source only through
`scripts.cert.independent_qfuf.parse_and_encode`. It does not invoke
euf-viper, a SAT solver, Z3, Yices2, or cvc5, and it never emits `sat` or
`unsat`. All reported quantities are exact integer counts for the declared
CNF templates. No count is converted into a fabricated time or memory result.

## Compared Encodings

The eager control reproduces these structural operations:

1. full typed Ackermann clauses over each non-nullary function symbol;
2. every equality variable introduced by argument and non-Boolean result
   pairs;
3. deterministic minimum-active-degree chordal fill with term-ID tie breaks;
4. one unit for each reflexive equality atom and three ternary transitivity
   clauses for every triangle in the completed equality graph.

The CQRAM projection uses:

1. typed interference components formed by source equality endpoints, all
   results of one non-Boolean symbol, and all terms in one non-Boolean argument
   position of one symbol;
2. `max(1, ceil(log2(n)))` class codes and restricted-growth canonicalization
   independently in each component;
3. exact links from every source equality atom to class-code identity;
4. one-bit Boolean values, including explicit true/false units when those
   values are materialized as data;
5. one padded bitonic record memory per symbol and guarded adjacent-record
   consistency after sorting.

The bitonic network is deterministic but is not claimed to be stable. Stable
tie ordering is unnecessary: every equal-key block is contiguous after any
correct sort, and adjacent consistency therefore enforces one result for the
whole block. Omitting origin tags is part of the preregistered projection and
avoids counting a property that the soundness argument does not use.

## Typed Decoder Invariant

Every non-Boolean decoded value is

```text
(sort_id, component_id, class_code)
```

Values from disconnected components are deliberately distinct. This is
complete because no equality atom or function-record position relates those
components. Terms occupying one record position are unioned before widths are
chosen, so every key and result position has exactly one namespace. Boolean
positions use their existing one-bit atom channel.

After a satisfying projected assignment, the decoder checks source equality
atoms and all observed function records, installs one result for each observed
typed key, and gives every unobserved tuple an arbitrary typed default. Every
sort receives a default, including a declared sort with no observed term.

The decoder is executable. Given component class codes and Boolean carrier
bits, it sorts padded function records, rejects conflicting repeated keys,
constructs typed function tables, fills unobserved tuples with typed arbitrary
defaults, reevaluates every observed term, and checks every semantic equality
or Boolean-term atom against the projected assignment.

Before any source can be projected, a bounded exhaustive oracle runs two fixed
typed fixtures. It exhausts 316 restricted-growth/Boolean assignments: 179
reconstruct satisfying EUF interpretations and 137 are rejected for conflicting
repeated keys. The passing receipt covers Boolean carriers, multiple typed
components and sorts, four disconnected components of one sort, three-to-four
record padding, repeated keys, empty-sort defaults, 1,608 exhaustive
non-nullary arbitrary-default probes, and 2,998 reconstructed term/atom
satisfaction checks. It also fixes 1,608 total arbitrary-default probes, 170
padded assignments, and 55 repeated-key assignments. The exact canonical
receipt SHA-256 is
`7562fb7e9953604bd61a68689466e617013bb798bc2657d0c8522e488262af89`.
That digest and all eight counters are frozen in the campaign lock and bound
into every source record and the aggregate. A missing, failed, drifted,
feature/counter-contradictory, or merely self-consistent but non-frozen receipt
aborts the census before outputs are written.

The exhaustive bound is four terms per component and two free Boolean terms.
This is an executable regression oracle for the general decoder algorithm, not
a claim that finite testing proves the unbounded construction. Per-source typed
partition, namespace, Boolean-channel, cap, and reconstruction preconditions
remain fail-closed structural checks. Decoder operation counts remain
structural telemetry only, not a performance estimate.

## Fail-Closed Evidence

The campaign lock fixes:

- exactly 7,503 source records;
- the portable source-set SHA-256
  `d8997c621fbd58034e55bef1e6636ea0f0a28bc63bb6391be39e9195c6f44653`,
  independently reproduced from the local and WMI manifests;
- QG population 6,396 and Goel population 773;
- parser, analyzer, taxonomy builder, lock, manifest, portable source-set,
  record-stream, terminal-record, and target-manifest hashes;
- a canonical JSONL hash chain in strict relative-path order;
- semantic validation of every nested `Counts` object, category sum,
  unit/non-unit literal layout, two-watch relation, component/symbol model,
  selector, decoder, and status/cap relation;
- explicit caps, with every cap event causing the validity gate to fail;
- `max_symbols` counts every parser function entry, including internal,
  nullary, unused, and macro declarations, rather than only symbols with
  observed non-nullary applications;
- the exact frozen bounded exhaustive decoder-oracle receipt for every source;
- a separate decision verifier that does not import or call the analyzer. It
  reparses every captured source, rebuilds typed components and equality
  completion with separate data structures, independently counts both
  projections, reconstructs every component, symbol, decoder, ratio, record,
  canonical chain, target, aggregate, provenance hash, family population,
  percentile, median, control, validity, and authorization field, and requires
  the complete stored bytes to equal that recomputation;
- exhaustive differential tests over all 75 equality graphs through four
  vertices, generated Boolean/multisort/padding cases, tampered/rechained
  records, and a synthetic 7,503-record population with the exact QG and Goel
  cardinalities. The independent bounded decoder oracle examines 255 record
  assignments and has frozen receipt SHA-256
  `d869fe2de073014dcef83160535318c976897d1da946590e19f0912bc658d4f5`.

The portable source-set digest hashes only relative path, byte count, and
source SHA-256. Host-specific absolute manifest paths therefore do not make
the local and WMI source identities appear different.

The run consumes the tracked 7,503-row manifest
`benchmarks/smtcomp-2025/qf_uf_manifest.jsonl`, fixed at SHA-256
`ed00b0e2105ec9579b02448d161e7f04ceceaf816919535b48734c6525a2aaa6`.
Only the SMT-LIB payload directory is supplied by the shared corpus mount; every
payload is reopened without following its final path component and checked
against the tracked byte count and SHA-256 before it enters the archive.

The independent verifier emits
`euf-viper.component-quotient-independent-decision.v1`. It is decisive only
after exact full-artifact reconstruction and binds all source, manifest,
record, target, aggregate, provenance, gate, and oracle hashes. Any cap,
unsupported construct, field mismatch, missing captured source, or incomplete
recomputation yields a nondecisive result and cannot authorize T5.

### Immutable publication protocol

Every submission first creates a private attempt directory with remote `mktemp`
under the configured campaign root, then clones the published revision into
that empty directory. The exact directory and random attempt ID are bound into
the local submission receipt. Repeated or concurrent submissions of one
revision therefore have disjoint checkouts and results namespaces; no wrapper
resets, cleans, reuses, or removes another attempt path.

All campaign Python processes run under `env -i` with `-I -B -S`. Submission
uses an explicit `sbatch --export` allowlist and never `--export=ALL`. Entry
guards reject ambient `GIT_*`, `BASH_ENV`, Python, Cargo, Rust, and dynamic
loader controls before preflight. Environment-sanitized Git uses explicit
git-dir/work-tree paths to compare the campaign lock, manifest-producing code,
every executable/imported campaign file, and every config directly with exact
revision blobs and modes. The read-only guard never clears index flags.

Every submission receives a private remote `mktemp` namespace, 256-bit nonce,
and inode identities for the namespace and result directory. Its canonical
submission receipt is explicitly `submitted_pending_nondecisive`, with
`decisive=false` and `authoritative=false`. Repeated submissions of one revision
cannot share or clean a checkout. Neither wrapper, finalizer, analyzer, nor
consumer removes a stage, archive, marker, receipt, or bundle by pathname.
Partial attempt files and immutable orphans may leak and remain non-authoritative.

On Linux, the finalizer creates the archive with `O_TMPFILE` in the opened result
directory. The inode has link count zero while it is written, file-fsynced,
chmoded `0444`, file-fsynced again, hashed, and descriptor-checked. One
`linkat(fd, "", dirfd, final, AT_EMPTY_PATH)` atomically gives that exact inode
its only name. The final inode must have link count one. There is no named
staging alias, `/proc/self/fd` fallback, immediately-unlinked pathname fallback,
replacement inode, or pathname publication fallback. Unsupported kernels or
filesystems fail closed. Immediately after linking, the finalizer opens and
proves a same-inode read-only descriptor, closes the writable `O_TMPFILE`
descriptor, and only then exposes the linked boundary to subsequent checks.

Linux requires `CAP_DAC_READ_SEARCH` to use `linkat(AT_EMPTY_PATH)`. The
[Linux `open(2)` documentation](https://man7.org/linux/man-pages/man2/open.2.html)
recommends `/proc/self/fd` plus `AT_SYMLINK_FOLLOW` when that capability is
absent, but this preregistered contract deliberately forbids that pathname
fallback. Therefore capability-free hosted CI is expected to fail with `EPERM`
unless the publication policy is explicitly revised. Such a failure is a
source-gate result, not permission to claim Linux GO or submit WMI.

The archive contains the exact source bytes used by the decision verifier, not
only their manifest hashes. The finalizer fsyncs the result directory, reopens
the archive with `O_NOFOLLOW`, proves descriptor/name identity, link count,
mode, length, and a fresh SHA-256, and repeatedly proves that the named namespace
and result path still resolve to the pinned directory descriptors.

The final operation publishes `.current` as another `O_TMPFILE` inode, never a
symlink. Its canonical bytes bind final name, archive SHA-256/size/inode/mode/link
count, revision, job, submission attempt, nonce, remote namespace and directory
identities, lock/manifest/portable-source/runtime hashes, independent receipt,
and bundle metadata. Marker publication is no-replace, descriptor-bound,
file/directory-fsynced, and freshly reverified. An fsync or race failure may
leave a visible immutable orphan; no code attempts unsafe rollback.

A marker is never completion by itself. The post-job consumer first requires a
unique root `sacct` row with `COMPLETED` and `0:0`, then reopens the bound result
directory, marker, and archive with no-follow semantics, repeats all inode,
link, mode, content, nonce, namespace, revision, exact-blob, member, and digest
checks, rebuilds the independent decision from archived source bytes, and emits
a no-replace final receipt containing both the fresh archive and marker digests.
That receipt remains explicitly non-authoritative without successful consumer
exit, so an fsync-failure orphan cannot self-certify.

## Preregistered Decision

The prospective target selector uses only:

```text
applications >= 64
maximum applications for one symbol >= 32
```

QG and Goel must each cover at least 5 percent of their population and eight
generator lineages. Within each family, either clauses or two-watch entries
must show all three of:

- at least 25 percent weighted reduction;
- at least 25 percent median reduction;
- at least half of files individually reducing by at least 25 percent.

That primary reduction is necessary but no longer sufficient. Both clauses and
literal slots must also show no regression in the weighted aggregate and at the
nearest-rank 95th percentile. Therefore a watch-only reduction cannot promote a
candidate whose unit-clause mix hides larger clause storage or long clauses. An
adversarial regression fixture with a passing 50 percent watch reduction, a
1.5x clause increase, and a 333x literal-slot increase is required to fail.

Candidate variables must be at most 1.25 times eager variables both in the
weighted aggregate and at the nearest-rank 95th percentile. T5 remains
rejected unless validity and every family gate pass. A valid negative result
is a successful census and must not be relabeled as an infrastructure error.
