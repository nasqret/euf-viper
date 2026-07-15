# T7 SAT-Impact Explanation Falsifier

Date: 2026-07-15

Status: preregistered before opportunity or timing results

## Boundary

Small congruence proofs, proof forests, rollback DPLL(T), user propagators, and
fixed explanation portfolios are known. This experiment tests one narrower
hypothesis: among equally short, independently valid EUF conflict clauses, does
a SAT-level/reuse objective reduce later CDCL work enough to improve end-to-end
time?

Current main's eager/model-cut path is not a valid test bed. It runs after a
complete assignment, records one causal forest, and has no decision-level, LBD,
backjump, or alternative-reason data. Use the isolated rollback sidecar based
on exact `6e402f0`, where callback levels and independently replayed causal
conflicts already exist. Any positive result must later be ported and repeated
on current main.

## Identical Work Contract

One binary exposes strict `EUF_VIPER_T7_EXPLANATION=off|on`; unknown values fail
closed. Both arms:

- reconstruct at most four forests by trail, reverse-trail, increasing-level,
  and decreasing-level fact order;
- canonicalize, deduplicate, and replay every candidate without changing the
  online closure;
- buffer equivalent chain-hashed candidate and timing telemetry;
- restrict selection to the identical minimum-width candidate pool.

`off` chooses the lexically first minimum-width clause. `on` minimizes the tuple

\[
(\mathrm{LBD},\ n_{\mathrm{current}},\ \ell_{\mathrm{second}},\
-\mathrm{reuse},\ \mathrm{lexical\ clause}).
\]

The candidate can never win merely by selecting a shorter explanation.

## Frozen Populations

- M3 opportunity controls: `peg_solitaire.2`, `peg_solitaire.4`, and
  `sokoban.3.prop1_ab_reg_max`.
- T9 targets: the two `firewire_tree.5` regularity properties,
  `frogs.{2,3,5}`, `h_TicTacToe`, `hanoi.3`, and `sokoban.{2,3}`.
- A12 anti-targets: `loops6/iso_icl007` and the eleven frozen qg5 sources from
  the rollback control.

The old 24-row manifest bytes are absent locally. Freeze a new T7 manifest from
the exact tracked source rows and publish its new digest; never claim
byte-identical T2 reuse.

## Stages

1. Shadow opportunity pass on M3. Reject unless at least two sources contain a
   conflict with two distinct replay-valid minimum-width candidates and an
   `off`/`on` disagreement.
2. If stage 1 passes, run four sources, two arms, four cold-process balanced
   ABBA repeats: 32 observations on one core at 60 seconds.
3. If stage 2 passes, run the frozen 24 sources, two arms, four repeats: 192
   observations. Do not compose vivification or a certificate-aware selector.

## Evidence

Each candidate transcript binds the active trail, decision levels, all clauses
and scores, selected index, replay result, construction/scoring/replay time,
and cumulative decisions, propagations, backtracks, SAT conflicts, theory
conflicts, model checks, final validations, duplicate clauses, CPU, wall, and
RSS. An independent source-level checker must verify every clause is falsified
by its logged trail and passes `validate_euf_lemma`. Every timed SAT assignment
is checked directly. Requested UNSAT evidence consists of the exact base CNF,
selected EUF suffix, and a checked DRAT proof; a separate saturation rerun does
not certify the timed selector transcript.

## Gates

For target median capped wall times `m[arm, source]`, require

\[
\exp\left(\frac{1}{9}\sum_{s\in T9}
\log\frac{m[off,s]}{m[on,s]}\right) \ge 1.10.
\]

Also require:

- at least 20% fewer summed median validations or propagations over M3 plus
  paired-correct T9;
- total candidate construction, scoring, and replay below 5% of wall time;
- every selected width equal to the common minimum and nonzero disagreements;
- zero wrong answers, errors, missing rows, replay failures, certificate
  failures, fallbacks, and off-only solves;
- A12 p95 `on/off` overhead at most `1.10`, with no anti-target solve loss.

A pass authorizes only a current-main port and the later
shortest/SAT-impact/certificate-aware comparison. It does not authorize
vivification, migration, integration, or solver promotion.
