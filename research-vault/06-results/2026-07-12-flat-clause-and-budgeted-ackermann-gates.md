# Flat Clause And Budgeted Ackermann Gates

Date: 2026-07-12

## Promoted Flat Clause Store

Commit `2274c75` replaces persistent `Vec<Vec<Lit>>` clause ownership with a
flat literal arena and offset metadata. WMI soundness `144006`, hot-320
`144062`, resource `144063`, and full paired array `144072` passed.

The full campaign contains 7,503 instances, three repeats per arm, and 45,018
observations. It reports:

| Metric | Baseline | Candidate or ratio |
| --- | ---: | ---: |
| Correct instances | 7,418 | 7,419 |
| All timeout-charged total | 742.017s | 737.928s (`1.0055x`) |
| Common-correct total | - | `1.0071x` |
| Geometric speed | - | `1.0309x` |
| Median speed | - | `1.0314x` |
| Candidate-only instances | 0 | 1 |
| Reverse timeout improvements | 0 | 0 |

Common-total, geometric, and median 95% lower bounds are `1.0065x`, `1.0303x`,
and `1.0304x`; paired p=`0.00009999`. There are zero wrong answers or execution
errors. The candidate-only input is
`QF_UF/QG-classification/qg7/iso_icl_repgen002.smt2`.

The mechanism is promoted on main as `3c178dc`. Exact current-main soundness
jobs `144213` and `144214` pass. Current-lineage array/merge `144224`/`144225`
reports:

| Metric | Baseline | Candidate or ratio |
| --- | ---: | ---: |
| Correct instances | 7,418 | 7,421 |
| Common-total speed | - | 1.0094x |
| All-total speed | - | 1.0073x |
| Geometric speed | - | 1.0320x |
| Median speed | - | 1.0323x |

Every timing check and confidence bound passes, and there is no baseline-only
correct instance. The strict sample policy mechanically rejects one candidate
timeout with a baseline-correct repeat on `PEQ014_size9`; another repeat in the
same full run goes in the opposite direction. Pinned same-node job `144309`
runs 31 repeats and solves 31/31 in both arms, with candidate median/total
`1.0225x` faster. The repeated boundary gate does not reproduce a regression,
so promotion is retained while the original strict reject remains archived.

## Automatic Quotient Route

Commit `1cd9ec4` activates leaf quotienting only when canonical unique Boolean
node reduction is at least 1,000. Soundness and the frozen 32-case gate pass,
but full array/merge `144056`/`144061` rejects default activation:

| Metric | Baseline | Candidate or ratio |
| --- | ---: | ---: |
| Correct instances | 7,271 | 7,272 |
| Common-total speed | - | 0.9970x |
| All-total speed | - | 0.9995x |
| Geometric speed | - | 0.9940x |
| Median speed | - | 0.9974x |
| Baseline-only instances | 2 | - |
| Candidate-only instances | - | 3 |

Ten reverse timeout samples occur across nine instances. Every speed bootstrap
lower bound is below parity. The selected 32-case route remains useful
mechanism evidence but is not a production selector.

Successor `550853b` counts the 696 required root equalities before allocating a
quotient plan. Direct-parent hot-320 job `144222` preserves 320/320 coverage but
measures `0.9998x` total and `1.0004x` geometric speed. This is neutral evidence,
so no full successor gate is justified yet.

## Budgeted Full Ackermann

Forced leaf quotient plus full Ackermann completion improves six selected Goel
profiles by `19.27x` geometrically relative to lazy quotienting. The mechanism
is unsafe without an allocation-independent guard: mixed gate `143957` loses
`NEQ033_size6` to OOM, and profile `144074` records 8,137 applications,
10,136,258 Ackermann clauses, and 341,413 fill edges before termination.

A production candidate must reject before cloning unless all caps pass:

1. base terms, variables, clauses, and literal slots;
2. function applications, maximum arity, and total argument slots;
3. candidate-pair examinations and projected Ackermann literal slots;
4. fill-edge and fill-pair work;
5. the actual selected SAT backend.

The transaction must preserve existing CNF and finite-domain axioms. It may be
timed only after soundness, backend-route tests, and independent review pass.

## Class-Label Successor

Polarity-aware component-local class labels project 2.57--6.79x fewer
completion watches than equality-triangle completion on the six Goel profiles,
at a 4.2--5.1x variable increase. Even deleting all triangle construction and
load time leaves this slice about 3.07x slower than Yices2. Exact function
argument and result sorts are currently not retained, so implementation begins
with typed metadata and exhaustive reference equivalence, not production SAT.

## Claim Boundary

Flat clause storage is the first broad mechanism in this round to satisfy the
project promotion contract. It does not establish superiority over Z3 or
Yices2. The latest four-solver reference still shows a substantial Yices2
coverage and total-time lead, and every successor remains separately gated.
