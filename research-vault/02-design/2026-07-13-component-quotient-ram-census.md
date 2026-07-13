# T5 Component-Quotient RAM Census Contract

Date: 2026-07-13

Status: implemented source-only opportunity census. This is not a production
solver route, a timing experiment, or evidence that T5 should be implemented.

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

The census records operation counts for this reconstruction. They are
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
- explicit caps, with every cap event causing the validity gate to fail.

The portable source-set digest hashes only relative path, byte count, and
source SHA-256. Host-specific absolute manifest paths therefore do not make
the local and WMI source identities appear different.

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

Candidate variables must be at most 1.25 times eager variables both in the
weighted aggregate and at the nearest-rank 95th percentile. T5 remains
rejected unless validity and every family gate pass. A valid negative result
is a successful census and must not be relabeled as an infrastructure error.
