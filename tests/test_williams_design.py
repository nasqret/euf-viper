from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "williams_design.py"
MODULE_SPEC = importlib.util.spec_from_file_location("williams_design", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
WILLIAMS = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(WILLIAMS)


def arm_ids(count: int) -> list[str]:
    return [f"arm-{index:02d}" for index in range(count)]


def independent_counts(
    arms: list[str], rows: list[list[str]]
) -> tuple[Counter[tuple[str, int]], Counter[tuple[str, str]]]:
    positions: Counter[tuple[str, int]] = Counter()
    predecessors: Counter[tuple[str, str]] = Counter()
    for row in rows:
        for position, arm in enumerate(row):
            positions[(arm, position)] += 1
        predecessors.update(zip(row, row[1:]))
    return positions, predecessors


class WilliamsDesignPropertyTests(unittest.TestCase):
    def test_complete_design_properties_for_every_arm_count_two_to_ten(self) -> None:
        for count in range(2, 11):
            arms = arm_ids(count)
            block_rows = count if count % 2 == 0 else 2 * count
            for blocks in (1, 2, 3):
                with self.subTest(arm_count=count, blocks=blocks):
                    repeats = block_rows * blocks
                    payload = WILLIAMS.build_design(arms, repeats)
                    rows = [record["order"] for record in payload["rows"]]
                    positions, predecessors = independent_counts(arms, rows)
                    expected_count = repeats // count

                    self.assertEqual(len(rows), repeats)
                    self.assertTrue(payload["complete_design"])
                    self.assertTrue(payload["declared_balance_preserved"])
                    self.assertEqual(payload["status"], "balanced")
                    self.assertTrue(payload["balance"]["balanced"])
                    for row in rows:
                        self.assertEqual(len(row), count)
                        self.assertEqual(set(row), set(arms))
                        self.assertEqual(len(set(row)), count)
                    for arm in arms:
                        for position in range(count):
                            self.assertEqual(
                                positions[(arm, position)], expected_count
                            )
                        for successor in arms:
                            if successor != arm:
                                self.assertEqual(
                                    predecessors[(arm, successor)], expected_count
                                )
                            else:
                                self.assertEqual(predecessors[(arm, successor)], 0)

                    position_report = {
                        record["arm"]: record["by_position"]
                        for record in payload["balance"]["position"]["counts"]
                    }
                    predecessor_report = {
                        (record["predecessor"], record["successor"]): record[
                            "count"
                        ]
                        for record in payload["balance"][
                            "directed_predecessor"
                        ]["counts"]
                    }
                    self.assertEqual(
                        position_report,
                        {
                            arm: [
                                positions[(arm, position)]
                                for position in range(count)
                            ]
                            for arm in arms
                        },
                    )
                    self.assertEqual(
                        predecessor_report,
                        {
                            (arm, successor): predecessors[(arm, successor)]
                            for arm in arms
                            for successor in arms
                            if arm != successor
                        },
                    )

    def test_minimum_block_has_no_duplicate_rows_for_two_to_ten_arms(self) -> None:
        for count in range(2, 11):
            with self.subTest(arm_count=count):
                rows = WILLIAMS.williams_block(arm_ids(count))
                self.assertEqual(len(rows), WILLIAMS.complete_block_rows(count))
                self.assertEqual(len({tuple(row) for row in rows}), len(rows))

    def test_known_small_designs_fix_the_deterministic_convention(self) -> None:
        self.assertEqual(
            WILLIAMS.williams_block(["off", "candidate"]),
            [["off", "candidate"], ["candidate", "off"]],
        )
        self.assertEqual(
            WILLIAMS.williams_block(["off", "candidate", "yices"]),
            [
                ["off", "candidate", "yices"],
                ["candidate", "yices", "off"],
                ["yices", "off", "candidate"],
                ["yices", "candidate", "off"],
                ["candidate", "off", "yices"],
                ["off", "yices", "candidate"],
            ],
        )
        self.assertEqual(
            WILLIAMS.williams_block(["a", "b", "c", "d"]),
            [
                ["a", "b", "d", "c"],
                ["b", "c", "a", "d"],
                ["c", "d", "b", "a"],
                ["d", "a", "c", "b"],
            ],
        )

    def test_generation_is_deterministic_for_two_to_ten_arms(self) -> None:
        for count in range(2, 11):
            with self.subTest(arm_count=count):
                arms = arm_ids(count)
                repeats = WILLIAMS.complete_block_rows(count) * 2
                first = WILLIAMS.build_design(arms, repeats)
                second = WILLIAMS.build_design(tuple(arms), repeats)
                self.assertEqual(first, second)
                self.assertEqual(
                    json.dumps(first, ensure_ascii=True, sort_keys=True),
                    json.dumps(second, ensure_ascii=True, sort_keys=True),
                )

    def test_remaining_supported_arm_counts_are_balanced(self) -> None:
        for count in range(11, 17):
            with self.subTest(arm_count=count):
                repeats = WILLIAMS.complete_block_rows(count)
                payload = WILLIAMS.build_design(arm_ids(count), repeats)
                expected_count = 1 if count % 2 == 0 else 2
                self.assertTrue(payload["balance"]["balanced"])
                self.assertEqual(
                    payload["balance"]["position"][
                        "expected_count_per_arm_position"
                    ],
                    expected_count,
                )
                self.assertEqual(
                    payload["balance"]["directed_predecessor"][
                        "expected_count_per_pair"
                    ],
                    expected_count,
                )


class PrefixAndValidationTests(unittest.TestCase):
    def test_incomplete_repeats_fail_closed_with_exact_boundaries(self) -> None:
        cases = [
            (2, 1, None, 2),
            (3, 3, None, 6),
            (4, 6, 4, 8),
            (5, 11, 10, 20),
        ]
        for count, repeats, previous, next_valid in cases:
            with self.subTest(arm_count=count, repeats=repeats):
                with self.assertRaises(WILLIAMS.DesignError) as caught:
                    WILLIAMS.generate_schedule(arm_ids(count), repeats)
                error = caught.exception
                self.assertEqual(error.code, "incomplete_balance_block")
                self.assertEqual(
                    error.details["required_multiple"],
                    WILLIAMS.complete_block_rows(count),
                )
                self.assertEqual(error.details["previous_valid_repeats"], previous)
                self.assertEqual(error.details["next_valid_repeats"], next_valid)

    def test_odd_half_block_reports_position_but_not_predecessor_balance(self) -> None:
        arms = ["a", "b", "c"]
        payload = WILLIAMS.build_design(arms, 3, allow_prefix=True)

        self.assertEqual(payload["status"], "prefix_only")
        self.assertFalse(payload["complete_design"])
        self.assertFalse(payload["declared_balance_preserved"])
        self.assertEqual(payload["complete_blocks"], 0)
        self.assertEqual(payload["prefix_rows"], 3)
        self.assertTrue(payload["balance"]["position"]["balanced"])
        self.assertFalse(
            payload["balance"]["directed_predecessor"]["balanced"]
        )
        pair_counts = {
            (record["predecessor"], record["successor"]): record["count"]
            for record in payload["balance"]["directed_predecessor"]["counts"]
        }
        self.assertEqual(
            pair_counts,
            {
                ("a", "b"): 2,
                ("a", "c"): 0,
                ("b", "a"): 0,
                ("b", "c"): 2,
                ("c", "a"): 2,
                ("c", "b"): 0,
            },
        )

    def test_nonintegral_prefix_report_exposes_exact_fraction_and_counts(self) -> None:
        arms = ["a", "b", "c", "d"]
        payload = WILLIAMS.build_design(arms, 3, allow_prefix=True)
        report = payload["balance"]

        self.assertEqual(
            report["position"]["target"],
            {"denominator": 4, "integer": False, "numerator": 3},
        )
        self.assertIsNone(report["position"]["expected_count_per_arm_position"])
        self.assertIsNone(
            report["directed_predecessor"]["expected_count_per_pair"]
        )
        self.assertFalse(report["balanced"])
        self.assertEqual(report["rows"]["count"], 3)
        self.assertEqual(report["rows"]["expected_length"], 4)

    def test_malformed_arm_collections_are_rejected(self) -> None:
        invalid = [
            [],
            ["only"],
            arm_ids(17),
            ["a", "a"],
            ["a", ""],
            ["a", "   "],
            ["a", 7],
            "ab",
            {"a": 1, "b": 2},
            None,
        ]
        for arms in invalid:
            with self.subTest(arms=arms):
                with self.assertRaises(WILLIAMS.DesignError):
                    WILLIAMS.validate_arms(arms)

    def test_invalid_repeat_values_are_rejected(self) -> None:
        for repeats in (0, -1, True, 2.0, "2", None):
            with self.subTest(repeats=repeats):
                with self.assertRaises(WILLIAMS.DesignError) as caught:
                    WILLIAMS.generate_schedule(["a", "b"], repeats)
                self.assertEqual(caught.exception.code, "invalid_repeats")

    def test_malformed_rows_fail_before_balance_is_declared(self) -> None:
        malformed = [
            ([], "invalid_schedule"),
            (["ab"], "invalid_schedule_row"),
            ([[]], "invalid_row_length"),
            ([["a"]], "invalid_row_length"),
            ([["a", "a"]], "invalid_row_permutation"),
            ([["a", "unknown"]], "invalid_row_permutation"),
            ([["a", 2]], "invalid_schedule_arm_id"),
        ]
        for rows, code in malformed:
            with self.subTest(rows=rows):
                with self.assertRaises(WILLIAMS.DesignError) as caught:
                    WILLIAMS.balance_report(["a", "b"], rows)
                self.assertEqual(caught.exception.code, code)

    def test_structurally_valid_unbalanced_rows_are_rejected_by_default(self) -> None:
        rows = [["a", "b"], ["a", "b"]]
        report = WILLIAMS.validate_schedule(
            ["a", "b"], rows, require_balance=False
        )
        self.assertFalse(report["position"]["balanced"])
        self.assertFalse(report["directed_predecessor"]["balanced"])
        with self.assertRaises(WILLIAMS.DesignError) as caught:
            WILLIAMS.validate_schedule(["a", "b"], rows)
        self.assertEqual(caught.exception.code, "unbalanced_schedule")


class WilliamsDesignCliTests(unittest.TestCase):
    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *arguments],
            cwd=ROOT,
            check=False,
            capture_output=True,
        )

    def test_cli_output_is_deterministic_ascii_json(self) -> None:
        arguments = ("--arms", "off", "candidate", "yices", "--repeats", "6")
        first = self.run_cli(*arguments)
        second = self.run_cli(*arguments)

        self.assertEqual(first.returncode, 0)
        self.assertEqual(first.stderr, b"")
        self.assertEqual(first.stdout, second.stdout)
        first.stdout.decode("ascii")
        payload = json.loads(first.stdout)
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["design"], "williams_first_order_carryover")
        self.assertEqual(
            [record["repeat"] for record in payload["rows"]], list(range(6))
        )

    def test_cli_supports_repeated_arm_options(self) -> None:
        completed = self.run_cli(
            "--arm",
            "baseline",
            "--arm",
            "candidate",
            "--repeats",
            "2",
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(
            json.loads(completed.stdout)["arms"], ["baseline", "candidate"]
        )

    def test_cli_failure_is_machine_readable_and_closed(self) -> None:
        completed = self.run_cli("--arms", "a", "b", "c", "--repeats", "3")

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, b"")
        error = json.loads(completed.stderr)
        self.assertEqual(error["status"], "error")
        self.assertEqual(error["error"]["code"], "incomplete_balance_block")
        self.assertEqual(error["error"]["details"]["required_multiple"], 6)

    def test_cli_allow_prefix_emits_a_precise_nonbalanced_report(self) -> None:
        completed = self.run_cli(
            "--arms",
            "a",
            "b",
            "c",
            "--repeats",
            "3",
            "--allow-prefix",
        )

        self.assertEqual(completed.returncode, 0)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "prefix_only")
        self.assertTrue(payload["balance"]["position"]["balanced"])
        self.assertFalse(
            payload["balance"]["directed_predecessor"]["balanced"]
        )

    def test_owned_files_are_ascii_only(self) -> None:
        for path in (SCRIPT, Path(__file__)):
            with self.subTest(path=path):
                path.read_bytes().decode("ascii")


if __name__ == "__main__":
    unittest.main()
