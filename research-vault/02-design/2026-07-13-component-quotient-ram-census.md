# T5 Component-Quotient RAM Census Contract

Date: 2026-07-13

Status: implemented source-only opportunity census, repaired after a second
independent review, and awaiting re-review. No WMI decision run has been
submitted. This is not a production solver route, a timing experiment, or
evidence that T5 should be implemented.

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
- a separate strict bundle-verifier process that rereads the lock, manifest,
  source files, records, targets, and aggregate; checks all parser, taxonomy,
  analyzer, portable-source, artifact, oracle, and chain-endpoint hashes;
  reconstructs every record from source; and recomputes the complete aggregate
  and all gates without trusting stored `pass` booleans.

The portable source-set digest hashes only relative path, byte count, and
source SHA-256. Host-specific absolute manifest paths therefore do not make
the local and WMI source identities appear different.

The verifier emits schema
`euf-viper.component-quotient-ram-bundle-verification.v1` only after exact
reconstruction. Its receipt binds source and target cardinalities, the frozen
oracle digest, validity and implementation decisions, every aggregate artifact
hash, the aggregate JSON hash, and a separately recomputed gates hash. WMI
metadata may acquire status `completed` only from this receipt with
`verified=true` and recomputed `validity_pass=true`; it does not read aggregate
validity booleans directly.

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
