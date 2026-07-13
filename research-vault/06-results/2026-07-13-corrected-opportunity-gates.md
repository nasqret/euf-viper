# Corrected Opportunity Gates

Date: 2026-07-13

Status: active checkpoint, not a promotion result

## T4 Guarded Ranges

WMI census `145883` wrote 7,503 records but failed its zero-error contract.
Seventeen deeply nested NEQ sources exceeded the independent Python parser's
expression recursion limit. The successfully parsed population projected:

- 91,895 uniform value cells;
- 91,895 non-uniform value cells;
- zero value-cell savings;
- 151 certified uniform domains;
- 14,311 effective ranges;
- 24 checked Hall subsets; and
- zero Hall conflicts.

The zero saving is strong negative evidence, but it is not a valid final T4
decision because the 17 omitted sources could change the aggregate and the
preregistered gate requires zero parser errors.

Commits `6b51b39` and `8f78543` implement iterative, simultaneous-scope `let`
parsing and pin a four-hour census wall limit. Corrected exact census `146071`
runs at revision `8f78543`. Its replacement certificate chains are full
`146076`-`146078` and official `146079`-`146081`.

## Other Active Gates

- T1 typed-stream parity: branch `research-typed-stream-parity`, checkpoint
  `47d7b0a`; first prepare `145940` failed before testing on bare `cargo`; final
  semantic-snapshot repair is in progress.
- T2 rollback control: array `145928`, audit `145929`; six shards complete and
  two active at this checkpoint. Only the final audit can decide promotion.
- T5 component quotient RAM: checkpoint `b51c75e`; second independent review
  pending before integration or WMI submission.
- T6 theory-conditioned Boolean DAG: checkpoint `9833ec3`, WMI job `146075`
  priority-pending; historical hard-10 results cannot promote.
- Production evidence: checkpoint `6095e29`; independent review must establish
  clause-level replay of the exact production assignment and clean-build
  identity before integration.
- Long timeout: full array `145785` has two completed and one active shard;
  official `145787` remains scheduler-bound. Preserve graph `145785`-`145789`.

## Decision Rule

No partial row, queued job, structural reduction, source-valid rerun, or
historical target set is promotion evidence. Follow the frozen gates in
[[2026-07-12-best-overall-qf-uf-campaign]] and the prior-art exclusions in
[[2026-07-11-novelty-exclusion-map]].
