from __future__ import annotations

import csv
import importlib.util
import json
import math
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "analyze_yices_opportunity.py"
SPEC = importlib.util.spec_from_file_location("analyze_yices_opportunity", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ATLAS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ATLAS
SPEC.loader.exec_module(ATLAS)


FIELDNAMES = [
    "id",
    "relative_path",
    "expected_status",
    "solver",
    "result",
    "time_s",
    "exit_code",
    "stderr",
]
SOLVERS = ("euf-viper", "z3", "cvc5", "yices2")


def row(
    identifier: str,
    path: str,
    expected: str,
    solver: str,
    result: str,
    time_s: str,
) -> dict[str, str]:
    return {
        "id": identifier,
        "relative_path": path,
        "expected_status": expected,
        "solver": solver,
        "result": result,
        "time_s": time_s,
        "exit_code": "124" if result == "timeout" else "0",
        "stderr": "timed out" if result == "timeout" else "",
    }


def fixture_rows() -> list[dict[str, str]]:
    cases = [
        (
            "0",
            "QF_UF/QG-classification/qg7/a.smt2",
            "unsat",
            {"euf-viper": ("unsat", "4"), "yices2": ("unsat", "1")},
        ),
        (
            "1",
            "QF_UF/QG-classification/loops7/b.smt2",
            "sat",
            {"euf-viper": ("sat", "1"), "yices2": ("sat", "2")},
        ),
        (
            "2",
            "QF_UF/2018-Goel-hwbench/c.smt2",
            "sat",
            {"euf-viper": ("timeout", "60"), "yices2": ("sat", "0.5")},
        ),
        (
            "3",
            "QF_UF/NEQ/d.smt2",
            "unsat",
            {"euf-viper": ("unsat", "0.25"), "yices2": ("timeout", "60")},
        ),
    ]
    rows = []
    for identifier, path, expected, special in cases:
        for solver in SOLVERS:
            result, time_s = special.get(solver, (expected, "0.75"))
            rows.append(row(identifier, path, expected, solver, result, time_s))
    return rows


class OpportunityAtlasTests(unittest.TestCase):
    def write_csv(self, path: Path, rows: list[dict[str, str]]) -> None:
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
            writer.writeheader()
            writer.writerows(rows)

    def run_cli(
        self, source: Path, output: Path, *extra: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(source), "--out", str(output), *extra],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_metrics_groups_coverage_and_timeout_exclusion(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yices atlas ") as temp:
            root = Path(temp)
            source = root / "four.csv"
            output = root / "atlas.json"
            self.write_csv(source, fixture_rows())

            completed = self.run_cli(source, output, "--top-n", "1,2,10")

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(output.read_text(encoding="ascii"))
            overall = payload["overall"]
            self.assertEqual(overall["instances"], 4)
            self.assertEqual(overall["common_correct"], 2)
            self.assertEqual(overall["net_time_deficit_s"], 2.0)
            self.assertEqual(overall["positive_time_deficit_s"], 3.0)
            self.assertEqual(overall["yices2_only_correct"], 1)
            self.assertEqual(overall["viper_only_correct"], 1)
            self.assertAlmostEqual(
                overall["geometric_yices_over_viper_factor"], math.sqrt(0.5)
            )

            self.assertEqual(
                payload["by_expected_status"]["unsat"]["positive_time_deficit_s"],
                3.0,
            )
            self.assertEqual(
                payload["by_expected_status"]["sat"]["net_time_deficit_s"], -1.0
            )
            self.assertEqual(payload["by_family"]["QG-classification"]["instances"], 2)
            self.assertEqual(payload["by_qg_degree"]["7"]["common_correct"], 2)
            self.assertEqual(
                payload["coverage_only_gaps"]["yices2_only_correct"],
                [
                    {
                        "euf_viper_result": "timeout",
                        "expected_status": "sat",
                        "relative_path": "QF_UF/2018-Goel-hwbench/c.smt2",
                    }
                ],
            )
            self.assertEqual(
                payload["cumulative_top_n_positive_deficit"],
                [
                    {
                        "actual_count": 1,
                        "fraction_of_total_positive_deficit": 1.0,
                        "positive_time_deficit_s": 3.0,
                        "requested_top_n": 1,
                    },
                    {
                        "actual_count": 1,
                        "fraction_of_total_positive_deficit": 1.0,
                        "positive_time_deficit_s": 3.0,
                        "requested_top_n": 2,
                    },
                    {
                        "actual_count": 1,
                        "fraction_of_total_positive_deficit": 1.0,
                        "positive_time_deficit_s": 3.0,
                        "requested_top_n": 10,
                    },
                ],
            )
            cohorts = {
                (item["dimension"], item["cohort"])
                for item in payload["qualifying_path_independent_cohorts"]
            }
            self.assertIn(("expected_status", "unsat"), cohorts)
            self.assertIn(("source_family", "QG-classification"), cohorts)
            self.assertIn(("qg_degree", "7"), cohorts)
            self.assertNotIn(("expected_status", "sat"), cohorts)

    def test_output_is_canonical_and_independent_of_csv_row_order(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yices atlas deterministic ") as temp:
            root = Path(temp)
            first_csv = root / "first.csv"
            second_csv = root / "second.csv"
            first_json = root / "first.json"
            second_json = root / "second.json"
            rows = fixture_rows()
            self.write_csv(first_csv, rows)
            self.write_csv(second_csv, list(reversed(rows)))

            first = self.run_cli(first_csv, first_json)
            second = self.run_cli(second_csv, second_json)

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(first_json.read_bytes(), second_json.read_bytes())
            self.assertEqual(
                first_json.read_bytes(),
                ATLAS.canonical_json_bytes(json.loads(first_json.read_bytes())),
            )

    def test_duplicate_pair_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yices atlas duplicate ") as temp:
            root = Path(temp)
            source = root / "duplicate.csv"
            output = root / "atlas.json"
            rows = fixture_rows()
            rows.append(dict(rows[0]))
            self.write_csv(source, rows)

            completed = self.run_cli(source, output)

            self.assertEqual(completed.returncode, 2)
            self.assertIn("duplicate row", completed.stderr)
            self.assertFalse(output.exists())

    def test_malformed_or_incomplete_data_fails_closed(self) -> None:
        mutations = {
            "nonfinite": lambda rows: rows[0].update(time_s="nan"),
            "infinite": lambda rows: rows[0].update(time_s="inf"),
            "negative": lambda rows: rows[0].update(time_s="-0.1"),
            "bad-status": lambda rows: rows[0].update(expected_status="unknown"),
            "blank-result": lambda rows: rows[0].update(result=""),
            "bad-exit": lambda rows: rows[0].update(exit_code="1.5"),
            "missing-pair": lambda rows: rows.pop(0),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                prefix=f"yices atlas {name} "
            ) as temp:
                root = Path(temp)
                source = root / "bad.csv"
                output = root / "atlas.json"
                rows = fixture_rows()
                mutate(rows)
                self.write_csv(source, rows)

                completed = self.run_cli(source, output)

                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertFalse(output.exists())

    def test_zero_time_is_not_negative_but_is_excluded_from_geometric_factor(self) -> None:
        rows = fixture_rows()
        for record in rows:
            if (
                record["relative_path"].endswith("a.smt2")
                and record["solver"] == "euf-viper"
            ):
                record["time_s"] = "0"
        with tempfile.TemporaryDirectory(prefix="yices atlas zero ") as temp:
            root = Path(temp)
            source = root / "zero.csv"
            output = root / "atlas.json"
            self.write_csv(source, rows)

            completed = self.run_cli(source, output)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            overall = json.loads(output.read_text())["overall"]
            self.assertEqual(overall["common_correct"], 2)
            self.assertEqual(overall["geometric_pair_count"], 1)
            self.assertEqual(overall["zero_time_pairs_excluded_from_geometric"], 1)
            self.assertEqual(overall["geometric_yices_over_viper_factor"], 2.0)

    def test_output_must_not_alias_input(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yices atlas alias ") as temp:
            root = Path(temp)
            source = root / "four.csv"
            self.write_csv(source, fixture_rows())
            original = source.read_bytes()

            same_path = self.run_cli(source, source)

            self.assertEqual(same_path.returncode, 2)
            self.assertIn("must be different files", same_path.stderr)
            self.assertEqual(source.read_bytes(), original)

            hard_link = root / "hard-link.json"
            hard_link.hardlink_to(source)
            hard_link_result = self.run_cli(source, hard_link)

            self.assertEqual(hard_link_result.returncode, 2)
            self.assertIn("must be different files", hard_link_result.stderr)
            self.assertEqual(source.read_bytes(), original)

    def test_publication_uses_unique_staging_and_preserves_existing_output_on_error(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yices atlas publication ") as temp:
            root = Path(temp)
            source = root / "four.csv"
            output = root / "atlas.json"
            predictable_staging = root / ".atlas.json.tmp"
            self.write_csv(source, fixture_rows())
            predictable_staging.write_text("unrelated", encoding="ascii")

            completed = self.run_cli(source, output)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(predictable_staging.read_text(encoding="ascii"), "unrelated")
            published = output.read_bytes()
            self.assertFalse(any(root.glob(".atlas.json.*.tmp")))

            rows = fixture_rows()
            rows.append(dict(rows[0]))
            self.write_csv(source, rows)
            rejected = self.run_cli(source, output)

            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(output.read_bytes(), published)

    def test_extreme_finite_times_do_not_overflow_ratio_construction(self) -> None:
        rows = fixture_rows()
        for record in rows:
            if record["relative_path"].endswith("a.smt2"):
                if record["solver"] == "euf-viper":
                    record["time_s"] = "1e-300"
                elif record["solver"] == "yices2":
                    record["time_s"] = "1e300"
            elif record["relative_path"].endswith("d.smt2"):
                record["relative_path"] = "QF_UF/QG-classification/qg7/d.smt2"
                if record["solver"] == "euf-viper":
                    record["time_s"] = "1e300"
                elif record["solver"] == "yices2":
                    record["result"] = "unsat"
                    record["time_s"] = "1e-300"
        with tempfile.TemporaryDirectory(prefix="yices atlas extreme ") as temp:
            root = Path(temp)
            source = root / "extreme.csv"
            output = root / "atlas.json"
            self.write_csv(source, rows)

            completed = self.run_cli(source, output)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            factor = json.loads(output.read_text())["overall"][
                "geometric_yices_over_viper_factor"
            ]
            self.assertTrue(math.isfinite(factor))


if __name__ == "__main__":
    unittest.main()
