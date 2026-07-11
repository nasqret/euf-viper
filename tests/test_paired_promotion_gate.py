from __future__ import annotations

import csv
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "paired_promotion_gate.py"
SPEC = importlib.util.spec_from_file_location("paired_promotion_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def campaign_rows(
    timings: list[tuple[float, float]], repeats: int = 3
) -> list[dict[str, object]]:
    rows = []
    repeat_factors = [1.0 + 0.02 * (repeat - repeats // 2) for repeat in range(repeats)]
    for index, (baseline_time, candidate_time) in enumerate(timings):
        relative_path = f"QF_UF/case-{index:03d}.smt2"
        expected_status = "sat" if index % 2 else "unsat"
        for repeat, factor in enumerate(repeat_factors):
            labels = (
                ("baseline", "candidate")
                if (index + repeat) % 2 == 0
                else ("candidate", "baseline")
            )
            for label in labels:
                time_s = baseline_time if label == "baseline" else candidate_time
                rows.append(
                    {
                        "relative_path": relative_path,
                        "expected_status": expected_status,
                        "label": label,
                        "repeat": repeat,
                        "result": expected_status,
                        "time_s": time_s * factor,
                        "exit_code": 0,
                        "stderr": "",
                    }
                )
    return rows


def mark_timeouts(
    rows: list[dict[str, object]],
    *,
    instance: int = 0,
    labels: tuple[str, ...] = ("baseline", "candidate"),
    repeats: tuple[int, ...] | None = None,
    time_s: float = 2.0,
) -> None:
    relative_path = f"QF_UF/case-{instance:03d}.smt2"
    for row in rows:
        if row["relative_path"] != relative_path or row["label"] not in labels:
            continue
        if repeats is not None and row["repeat"] not in repeats:
            continue
        row.update({"result": "timeout", "time_s": time_s, "exit_code": 124})


def write_rows(
    path: Path,
    rows: list[dict[str, object]],
    fieldnames: list[str] | None = None,
) -> None:
    selected_fields = GATE.FIELDNAMES if fieldnames is None else fieldnames
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=selected_fields,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)


def evaluate(path: Path, **overrides: object) -> dict:
    parameters = {
        "bootstrap_iterations": 256,
        "permutation_iterations": 256,
        "confidence_level": 0.9,
    }
    parameters.update(overrides)
    return GATE.evaluate_csv(path, **parameters)


class PromotionGateTests(unittest.TestCase):
    def test_clear_paired_wins_pass_every_check(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "wins.csv"
            write_rows(
                csv_path,
                campaign_rows(
                    [(2.0 + index, 1.0 + index / 2) for index in range(6)]
                ),
            )

            result = evaluate(csv_path)

            self.assertTrue(result["promoted"])
            self.assertEqual(result["status"], "promoted")
            self.assertTrue(all(check["passed"] for check in result["checks"].values()))
            self.assertEqual(result["ratio_direction"], "baseline_over_candidate")
            self.assertEqual(result["pairing"]["paired_instance_medians"], 6)
            self.assertEqual(result["pairing"]["paired_timing_samples"], 18)
            self.assertEqual(result["timing"]["wins"], 6)
            self.assertEqual(result["timing"]["losses"], 0)
            self.assertEqual(result["timing"]["ties"], 0)
            self.assertAlmostEqual(result["timing"]["median_speedup"], 2.0)
            self.assertAlmostEqual(result["timing"]["total_speedup"], 2.0)
            self.assertAlmostEqual(result["timing"]["geometric_speedup"], 2.0)
            for interval in result["bootstrap"]["metrics"].values():
                self.assertAlmostEqual(interval["estimate"], 2.0)
                self.assertAlmostEqual(interval["ci_lower"], 2.0)
                self.assertAlmostEqual(interval["ci_upper"], 2.0)
            test = result["permutation_test"]
            self.assertEqual(test["method"], "exact_paired_sign_flip")
            self.assertEqual(test["evaluated_permutations"], 64)
            self.assertAlmostEqual(test["p_value"], 1 / 64)

    def test_timing_regression_reports_losses_and_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "regression.csv"
            write_rows(
                csv_path,
                campaign_rows(
                    [(1.0 + index, 2.0 + 2 * index) for index in range(6)]
                ),
            )

            result = evaluate(csv_path)

            self.assertFalse(result["promoted"])
            self.assertEqual(result["timing"]["wins"], 0)
            self.assertEqual(result["timing"]["losses"], 6)
            self.assertAlmostEqual(result["timing"]["median_speedup"], 0.5)
            self.assertFalse(result["checks"]["median_speedup"]["passed"])
            self.assertFalse(result["checks"]["total_speedup"]["passed"])
            self.assertFalse(result["checks"]["geometric_speedup"]["passed"])
            self.assertFalse(result["checks"]["permutation_p_value"]["passed"])

    def test_candidate_wrong_answer_is_a_coverage_regression(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "wrong.csv"
            rows = campaign_rows([(2.0, 1.0)] * 6)
            target = next(
                row
                for row in rows
                if row["relative_path"] == "QF_UF/case-000.smt2"
                and row["label"] == "candidate"
                and row["repeat"] == 1
            )
            target["result"] = "sat"
            write_rows(csv_path, rows)

            result = evaluate(csv_path)

            self.assertFalse(result["promoted"])
            self.assertEqual(result["quality"]["candidate"]["wrong_answer_samples"], 1)
            self.assertEqual(result["quality"]["sample_coverage_delta"], -1)
            self.assertEqual(result["quality"]["instance_coverage_delta"], -1)
            self.assertEqual(
                result["quality"]["baseline_only_correct_instances"]["count"], 1
            )
            self.assertFalse(
                result["checks"]["candidate_has_no_wrong_answers"]["passed"]
            )
            self.assertFalse(result["checks"]["no_wrong_answers"]["passed"])
            self.assertFalse(
                result["checks"]["no_instance_coverage_regressions"]["passed"]
            )

    def test_equal_aggregate_coverage_cannot_hide_a_paired_sample_loss(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "coverage-swap.csv"
            rows = campaign_rows([(2.0, 1.0)] * 6)
            baseline_loss = next(
                row
                for row in rows
                if row["relative_path"] == "QF_UF/case-000.smt2"
                and row["label"] == "baseline"
                and row["repeat"] == 0
            )
            candidate_loss = next(
                row
                for row in rows
                if row["relative_path"] == "QF_UF/case-000.smt2"
                and row["label"] == "candidate"
                and row["repeat"] == 1
            )
            baseline_loss["result"] = "unknown"
            candidate_loss["result"] = "unknown"
            write_rows(csv_path, rows)

            result = evaluate(csv_path, allow_common_timeouts=True)

            self.assertEqual(result["quality"]["sample_coverage_delta"], 0)
            self.assertEqual(result["quality"]["instance_coverage_delta"], 0)
            self.assertEqual(
                result["quality"]["baseline_only_correct_samples"]["count"], 1
            )
            self.assertEqual(
                result["quality"]["candidate_only_correct_samples"]["count"], 1
            )
            self.assertTrue(
                result["checks"]["sample_coverage_non_regression"]["passed"]
            )
            self.assertFalse(
                result["checks"]["no_sample_coverage_regressions"]["passed"]
            )
            self.assertTrue(
                result["checks"]["timeouts_satisfy_policy"]["passed"]
            )
            self.assertFalse(result["promoted"])

    def test_strict_default_rejects_matched_common_timeouts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "common-timeouts.csv"
            rows = campaign_rows([(2.0, 1.0)] * 7)
            mark_timeouts(rows)
            write_rows(csv_path, rows)

            result = evaluate(csv_path)

            self.assertFalse(result["promoted"])
            self.assertEqual(result["issues"]["timeouts"]["count"], 6)
            self.assertEqual(result["pairing"]["paired_instance_medians"], 6)
            self.assertEqual(result["pairing"]["paired_timing_samples"], 18)
            self.assertAlmostEqual(result["timing"]["total_speedup"], 2.0)
            self.assertFalse(
                result["checks"]["timeouts_satisfy_policy"]["passed"]
            )
            policy = result["timeout_policy"]
            self.assertEqual(policy["name"], "strict_no_timeouts")
            self.assertEqual(policy["common_timeout_samples"], 3)
            self.assertEqual(policy["matched_common_timeout_instances"], 1)
            self.assertEqual(policy["tolerated_common_timeout_samples"], 0)
            self.assertEqual(policy["tolerated_common_timeout_instances"], 0)

    def test_opt_in_accepts_matched_timeouts_for_quality_checks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "common-timeouts.csv"
            rows = campaign_rows([(2.0, 1.0)] * 7)
            mark_timeouts(rows)
            write_rows(csv_path, rows)

            result = evaluate(csv_path, allow_common_timeouts=True)

            self.assertTrue(result["promoted"])
            self.assertTrue(
                result["checks"]["timeouts_satisfy_policy"]["passed"]
            )
            self.assertTrue(
                result["checks"]["no_sample_coverage_regressions"]["passed"]
            )
            self.assertTrue(result["checks"]["no_wrong_answers"]["passed"])
            self.assertTrue(result["checks"]["no_execution_errors"]["passed"])
            self.assertEqual(result["pairing"]["paired_instance_medians"], 6)
            policy = result["timeout_policy"]
            self.assertEqual(policy["name"], "allow_common_timeouts")
            self.assertEqual(policy["timeout_observations"], 6)
            self.assertEqual(policy["tolerated_common_timeout_samples"], 3)
            self.assertEqual(policy["tolerated_common_timeout_instances"], 1)
            self.assertEqual(policy["unmatched_timeout_samples"], 0)
            self.assertEqual(
                result["parameters"]["timeout_policy"], "allow_common_timeouts"
            )

    def test_opt_in_rejects_candidate_only_timeout_as_coverage_loss(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "candidate-timeout.csv"
            rows = campaign_rows([(2.0, 1.0)] * 6)
            mark_timeouts(rows, labels=("candidate",), repeats=(2,))
            write_rows(csv_path, rows)

            result = evaluate(csv_path, allow_common_timeouts=True)

            self.assertFalse(result["promoted"])
            self.assertFalse(
                result["checks"]["timeouts_satisfy_policy"]["passed"]
            )
            self.assertFalse(
                result["checks"]["no_sample_coverage_regressions"]["passed"]
            )
            self.assertEqual(
                result["quality"]["baseline_only_correct_samples"]["count"], 1
            )
            policy = result["timeout_policy"]
            self.assertEqual(policy["unmatched_timeout_samples"], 1)
            self.assertEqual(policy["unmatched_timeout_instances"], 1)
            self.assertEqual(policy["tolerated_common_timeout_samples"], 0)

    def test_opt_in_does_not_override_timing_thresholds(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "threshold-with-timeout.csv"
            rows = campaign_rows([(2.0, 1.0)] * 7)
            mark_timeouts(rows)
            write_rows(csv_path, rows)

            result = evaluate(
                csv_path,
                allow_common_timeouts=True,
                min_total_speedup=2.01,
            )

            self.assertFalse(result["promoted"])
            self.assertTrue(
                result["checks"]["timeouts_satisfy_policy"]["passed"]
            )
            self.assertFalse(result["checks"]["total_speedup"]["passed"])
            self.assertFalse(
                result["checks"]["total_bootstrap_lower_bound"]["passed"]
            )

    def test_opt_in_never_tolerates_wrong_answers_or_execution_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for kind in ("wrong-answer", "execution-error"):
                with self.subTest(kind=kind):
                    csv_path = root / f"{kind}.csv"
                    rows = campaign_rows([(2.0, 1.0)] * 7)
                    mark_timeouts(rows)
                    target = next(
                        row
                        for row in rows
                        if row["relative_path"] == "QF_UF/case-001.smt2"
                        and row["label"] == "baseline"
                        and row["repeat"] == 0
                    )
                    if kind == "wrong-answer":
                        target["result"] = (
                            "sat" if target["expected_status"] == "unsat" else "unsat"
                        )
                    else:
                        target.update({"result": "exit-7", "exit_code": 7})
                    write_rows(csv_path, rows)

                    result = evaluate(csv_path, allow_common_timeouts=True)

                    self.assertTrue(
                        result["checks"]["timeouts_satisfy_policy"]["passed"]
                    )
                    self.assertFalse(result["promoted"])
                    check = (
                        "no_wrong_answers"
                        if kind == "wrong-answer"
                        else "no_execution_errors"
                    )
                    self.assertFalse(result["checks"][check]["passed"])

    def test_reports_win_loss_and_tie_counts_with_tolerance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "mixed.csv"
            write_rows(csv_path, campaign_rows([(2.0, 1.0), (1.0, 2.0), (1.0, 1.0005)]))

            result = evaluate(
                csv_path,
                max_p_value=1.0,
                min_median_speedup=0.1,
                min_total_speedup=0.1,
                min_geometric_speedup=0.1,
                tie_relative_tolerance=0.001,
            )

            self.assertEqual(result["timing"]["wins"], 1)
            self.assertEqual(result["timing"]["losses"], 1)
            self.assertEqual(result["timing"]["ties"], 1)

    def test_seeded_statistics_and_row_order_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "varied.csv"
            timings = [
                (1.0 + index / 5, (1.0 + index / 5) / (1.02 + index / 100))
                for index in range(25)
            ]
            rows = campaign_rows(timings)
            write_rows(csv_path, rows)

            first = evaluate(
                csv_path,
                seed=1729,
                bootstrap_iterations=257,
                permutation_iterations=127,
            )
            write_rows(csv_path, list(reversed(rows)))
            second = evaluate(
                csv_path,
                seed=1729,
                bootstrap_iterations=257,
                permutation_iterations=127,
            )

            self.assertEqual(first, second)
            self.assertEqual(
                first["permutation_test"]["method"],
                "monte_carlo_paired_sign_flip",
            )
            self.assertEqual(first["permutation_test"]["evaluated_permutations"], 127)
            self.assertEqual(
                json.dumps(first, allow_nan=False, indent=2, sort_keys=True),
                json.dumps(second, allow_nan=False, indent=2, sort_keys=True),
            )

    def test_thresholds_are_independent_and_configurable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "threshold.csv"
            write_rows(csv_path, campaign_rows([(2.0, 1.0)] * 6))

            result = evaluate(csv_path, min_total_speedup=2.01)

            self.assertFalse(result["promoted"])
            self.assertFalse(result["checks"]["total_speedup"]["passed"])
            self.assertFalse(
                result["checks"]["total_bootstrap_lower_bound"]["passed"]
            )
            self.assertTrue(result["checks"]["median_speedup"]["passed"])
            self.assertEqual(
                result["parameters"]["thresholds"]["min_total_speedup"], 2.01
            )


class InputValidationTests(unittest.TestCase):
    def assert_invalid(self, csv_path: Path, text: str) -> None:
        with self.assertRaises(GATE.GateInputError) as raised:
            evaluate(csv_path)
        self.assertIn(text, "\n".join(raised.exception.errors))

    def test_missing_pair_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "missing.csv"
            rows = campaign_rows([(2.0, 1.0)] * 2)
            rows.remove(
                next(
                    row
                    for row in rows
                    if row["relative_path"] == "QF_UF/case-001.smt2"
                    and row["label"] == "candidate"
                    and row["repeat"] == 2
                )
            )
            write_rows(csv_path, rows)

            self.assert_invalid(csv_path, "incomplete paired campaign")
            self.assert_invalid(csv_path, "case-001.smt2")

    def test_malformed_rows_and_campaign_shapes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base_rows = campaign_rows([(2.0, 1.0)] * 2)
            cases: list[tuple[str, list[dict[str, object]], list[str], str]] = []

            bad_time = [dict(row) for row in base_rows]
            bad_time[0]["time_s"] = "nan"
            cases.append(("bad-time", bad_time, GATE.FIELDNAMES, "finite and positive"))

            duplicate = [dict(row) for row in base_rows]
            duplicate.append(dict(duplicate[0]))
            cases.append(("duplicate", duplicate, GATE.FIELDNAMES, "duplicate observation"))

            inconsistent = [dict(row) for row in base_rows]
            target = next(
                row
                for row in inconsistent
                if row["relative_path"] == "QF_UF/case-000.smt2"
                and row["repeat"] == 1
            )
            target["expected_status"] = "sat"
            target["result"] = "sat"
            cases.append(
                ("inconsistent", inconsistent, GATE.FIELDNAMES, "inconsistent expected_status")
            )

            noncontiguous = [
                dict(row) for row in base_rows if row["repeat"] != 1
            ]
            cases.append(
                ("noncontiguous", noncontiguous, GATE.FIELDNAMES, "contiguous from zero")
            )

            bad_timeout = [dict(row) for row in base_rows]
            bad_timeout[0]["result"] = "timeout"
            cases.append(("bad-timeout", bad_timeout, GATE.FIELDNAMES, "timeout rows"))

            missing_header = GATE.FIELDNAMES[:-1]
            cases.append(
                (
                    "header",
                    [dict(row) for row in base_rows],
                    missing_header,
                    "incompatible CSV header",
                )
            )

            for name, rows, fields, expected_error in cases:
                with self.subTest(name=name):
                    csv_path = root / f"{name}.csv"
                    write_rows(csv_path, rows, fields)
                    self.assert_invalid(csv_path, expected_error)

    def test_finite_timings_with_nonfinite_derived_ratio_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "overflow.csv"
            write_rows(csv_path, campaign_rows([(2.0, 5e-324)]))

            self.assert_invalid(csv_path, "invalid timing ratio")

    def test_surplus_row_columns_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "extra-column.csv"
            write_rows(csv_path, campaign_rows([(2.0, 1.0)]))
            lines = csv_path.read_text(encoding="utf-8").splitlines()
            lines[1] += ",unexpected"
            csv_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            self.assert_invalid(csv_path, "unexpected extra fields")


class CliTests(unittest.TestCase):
    def run_gate(self, csv_path: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(csv_path),
                "--bootstrap-iterations",
                "128",
                "--permutation-iterations",
                "128",
                *arguments,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_cli_exit_codes_for_promotion_rejection_and_invalid_input(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            winner = root / "winner.csv"
            regression = root / "regression.csv"
            missing = root / "missing.csv"
            write_rows(winner, campaign_rows([(2.0, 1.0)] * 6))
            write_rows(regression, campaign_rows([(1.0, 2.0)] * 6))
            missing_rows = campaign_rows([(2.0, 1.0)] * 6)
            missing_rows.pop()
            write_rows(missing, missing_rows)

            promoted = self.run_gate(winner)
            rejected = self.run_gate(regression)
            invalid = self.run_gate(missing)

            self.assertEqual(promoted.returncode, 0, promoted.stderr)
            self.assertEqual(rejected.returncode, 1, rejected.stderr)
            self.assertEqual(invalid.returncode, 2, invalid.stderr)
            self.assertEqual(promoted.stderr, "")
            self.assertEqual(rejected.stderr, "")
            self.assertEqual(invalid.stderr, "")
            self.assertTrue(promoted.stdout.endswith("\n"))
            self.assertEqual(json.loads(promoted.stdout)["status"], "promoted")
            self.assertEqual(json.loads(rejected.stdout)["status"], "rejected")
            invalid_payload = json.loads(invalid.stdout)
            self.assertEqual(invalid_payload["status"], "invalid_input")
            self.assertFalse(invalid_payload["promoted"])
            self.assertIn("incomplete paired campaign", invalid_payload["errors"][0])

    def test_cli_output_file_is_stable_and_thresholds_control_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            csv_path = root / "winner.csv"
            output_path = root / "nested" / "gate.json"
            write_rows(csv_path, campaign_rows([(2.0, 1.0)] * 6))

            first = self.run_gate(
                csv_path,
                "--seed",
                "42",
                "--out",
                str(output_path),
            )
            first_bytes = output_path.read_bytes()
            second = self.run_gate(
                csv_path,
                "--seed",
                "42",
                "--out",
                str(output_path),
            )
            second_bytes = output_path.read_bytes()
            threshold_rejection = self.run_gate(
                csv_path,
                "--min-total-speedup",
                "2.01",
            )

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(first.stdout, "")
            self.assertEqual(second.stdout, "")
            self.assertEqual(first_bytes, second_bytes)
            self.assertTrue(first_bytes.endswith(b"\n"))
            self.assertEqual(threshold_rejection.returncode, 1)
            payload = json.loads(threshold_rejection.stdout)
            self.assertFalse(payload["checks"]["total_speedup"]["passed"])

    def test_cli_allow_common_timeouts_is_explicit_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "common-timeouts.csv"
            rows = campaign_rows([(2.0, 1.0)] * 7)
            mark_timeouts(rows)
            write_rows(csv_path, rows)

            strict = self.run_gate(csv_path)
            allowed = self.run_gate(csv_path, "--allow-common-timeouts")

            self.assertEqual(strict.returncode, 1, strict.stderr)
            self.assertEqual(allowed.returncode, 0, allowed.stderr)
            strict_payload = json.loads(strict.stdout)
            allowed_payload = json.loads(allowed.stdout)
            self.assertEqual(
                strict_payload["timeout_policy"]["name"], "strict_no_timeouts"
            )
            self.assertEqual(
                allowed_payload["timeout_policy"]["name"],
                "allow_common_timeouts",
            )
            self.assertEqual(
                allowed_payload["timeout_policy"][
                    "tolerated_common_timeout_instances"
                ],
                1,
            )


if __name__ == "__main__":
    unittest.main()
