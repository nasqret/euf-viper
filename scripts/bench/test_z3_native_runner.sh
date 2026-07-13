#!/usr/bin/env bash
set -euo pipefail

RUNNER="${1:?usage: test_z3_native_runner.sh RUNNER}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/z3-native-runner.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat >"$TMP/sat.smt2" <<'EOF'
(set-logic QF_UF)
(declare-sort U 0)
(declare-const x U)
(declare-fun f (U) U)
(assert (= (f x) (f x)))
(check-sat)
EOF

cat >"$TMP/unsat.smt2" <<'EOF'
(set-logic QF_UF)
(declare-sort U 0)
(declare-const x U)
(assert (distinct x x))
(check-sat)
EOF

test "$("$RUNNER" "$TMP/sat.smt2")" = sat
test "$("$RUNNER" sat.euf=true "$TMP/sat.smt2")" = sat
test "$("$RUNNER" sat.euf=false "$TMP/unsat.smt2")" = unsat

set +e
"$RUNNER" smt.random_seed=1 "$TMP/sat.smt2" >"$TMP/invalid.stdout" 2>"$TMP/invalid.stderr"
STATUS=$?
set -e
test "$STATUS" -eq 64
grep -Fq 'unsupported Z3 parameter: smt.random_seed=1' "$TMP/invalid.stderr"

printf 'z3 native runner smoke: ok\n'
