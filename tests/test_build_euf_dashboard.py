from __future__ import annotations

import copy
import gzip
import importlib.util
import json
import math
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "build_euf_dashboard.py"
MODULE_SPEC = importlib.util.spec_from_file_location("build_euf_dashboard", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
DASHBOARD = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(DASHBOARD)


REVISION_A = "1" * 40
REVISION_B = "2" * 40
SOURCE_HASH = "a" * 64


def result(solver_id: str, status: str, time_s: float | None) -> dict:
    return {"solver_id": solver_id, "status": status, "time_s": time_s}


def instance(
    identifier: str,
    viper_time: float | None,
    competitor_time: float | None,
    *,
    viper_status: str = "solved",
    competitor_status: str = "solved",
) -> dict:
    return {
        "id": identifier,
        "results": [
            result("viper", viper_status, viper_time),
            result("competitor", competitor_status, competitor_time),
        ],
    }


def evidence(
    identifier: str,
    instances: list[dict],
    *,
    revision: str = REVISION_A,
    host_id: str = "host-a",
    host_label: str = "Host A",
    evidence_class: str = "official-campaign",
    evidence_status: str = "verified",
    scope: str = "broad",
) -> dict:
    return {
        "id": identifier,
        "scope": scope,
        "evidence_class": evidence_class,
        "evidence_status": evidence_status,
        "revision": revision,
        "solver_ids": ["viper", "competitor"],
        "host": {"id": host_id, "label": host_label},
        "corpus": {"id": "fixture-corpus", "label": "Fixture corpus"},
        "timeout_s": 10.0,
        "family": {"id": "all", "label": "All families"},
        "expected_status": "all",
        "source": {"path": f"fixtures/{identifier}.json", "sha256": SOURCE_HASH},
        "instances": instances,
    }


def fixture_registry(*items: dict) -> dict:
    if not items:
        items = (
            evidence(
                "broad-a",
                [
                    instance("case-a", 2.0, 4.0),
                    instance("case-b", 4.0, 8.0),
                ],
            ),
        )
    return {
        "schema_version": DASHBOARD.REGISTRY_SCHEMA_VERSION,
        "registry_id": "self-contained-fixture",
        "title": "EUF fixture dashboard",
        "updated_at": "2026-07-26T12:00:00Z",
        "viper_solver_id": "viper",
        "solvers": [
            {"id": "competitor", "label": "Competitor"},
            {"id": "viper", "label": "Viper"},
        ],
        "evidence": list(items),
    }


def assert_no_nonfinite(test: unittest.TestCase, value: object) -> None:
    if isinstance(value, float):
        test.assertTrue(math.isfinite(value))
    elif type(value) is dict:
        for child in value.values():
            assert_no_nonfinite(test, child)
    elif type(value) is list:
        for child in value:
            assert_no_nonfinite(test, child)


class MetricTests(unittest.TestCase):
    def test_ratios_signed_index_and_required_improvement(self) -> None:
        model = DASHBOARD.build_dashboard(fixture_registry())
        panel = model["panels"][0]
        summaries = {item["solver_id"]: item for item in panel["solvers"]}

        self.assertEqual(panel["instances"], 2)
        self.assertEqual(panel["leader_solver_ids"], ["competitor", "viper"])
        self.assertEqual(summaries["viper"]["coverage"]["value"], 1.0)
        self.assertEqual(
            summaries["viper"]["leader_relative_coverage"]["value"], 1.0
        )
        self.assertEqual(summaries["viper"]["par2_s"]["value"], 3.0)
        self.assertEqual(summaries["competitor"]["par2_s"]["value"], 6.0)
        self.assertEqual(summaries["viper"]["median_s"]["value"], 3.0)
        self.assertAlmostEqual(summaries["viper"]["p95_s"]["value"], 3.9)

        comparison = panel["comparisons"][0]
        self.assertEqual(comparison["common_solved"], 2)
        for metric_name in (
            "par2",
            "common_geometric",
            "common_total",
            "median",
            "p95",
        ):
            metric = comparison["metrics"][metric_name]
            with self.subTest(metric=metric_name):
                self.assertEqual(metric["status"], "available")
                self.assertAlmostEqual(metric["ratio"], 2.0)
                self.assertAlmostEqual(metric["signed_performance_index"], 1.0)
                self.assertEqual(metric["required_viper_time_reduction"], 0.0)
                self.assertEqual(metric["required_viper_speedup"], 0.0)
        self.assertEqual(comparison["performance_index"]["basis"], "common_geometric")

        slower = fixture_registry(
            evidence(
                "slower-viper",
                [
                    instance("case-a", 4.0, 2.0),
                    instance("case-b", 8.0, 4.0),
                ],
            )
        )
        metric = DASHBOARD.build_dashboard(slower)["panels"][0]["comparisons"][0][
            "performance_index"
        ]
        self.assertAlmostEqual(metric["ratio"], 0.5)
        self.assertAlmostEqual(metric["signed_performance_index"], -0.5)
        self.assertAlmostEqual(metric["required_viper_time_reduction"], 0.5)
        self.assertAlmostEqual(metric["required_viper_speedup"], 1.0)

    def test_par2_and_leader_relative_coverage_charge_non_solves(self) -> None:
        registry = fixture_registry(
            evidence(
                "coverage",
                [
                    instance("a", 1.0, 2.0),
                    instance(
                        "b",
                        None,
                        3.0,
                        viper_status="timeout",
                    ),
                ],
            )
        )
        panel = DASHBOARD.build_dashboard(registry)["panels"][0]
        summaries = {item["solver_id"]: item for item in panel["solvers"]}
        self.assertEqual(panel["leader_solver_ids"], ["competitor"])
        self.assertEqual(summaries["viper"]["coverage"]["value"], 0.5)
        self.assertEqual(
            summaries["viper"]["leader_relative_coverage"]["value"], 0.5
        )
        self.assertEqual(summaries["viper"]["par2_s"]["value"], 10.5)
        self.assertEqual(summaries["competitor"]["par2_s"]["value"], 2.5)

    def test_missing_data_is_unavailable_not_zero_or_timeout(self) -> None:
        registry = fixture_registry(
            evidence(
                "missing",
                [
                    instance("a", 1.0, 2.0),
                    instance(
                        "b",
                        2.0,
                        None,
                        competitor_status="unavailable",
                    ),
                ],
                evidence_status="incomplete",
            )
        )
        model = DASHBOARD.build_dashboard(registry)
        panel = model["panels"][0]
        summaries = {item["solver_id"]: item for item in panel["solvers"]}
        competitor = summaries["competitor"]
        self.assertFalse(panel["complete"])
        self.assertIsNone(panel["leader_solved"])
        self.assertEqual(competitor["coverage"]["status"], "unavailable")
        self.assertIsNone(competitor["coverage"]["value"])
        self.assertEqual(competitor["par2_s"]["status"], "unavailable")
        self.assertEqual(
            summaries["viper"]["leader_relative_coverage"]["status"],
            "unavailable",
        )
        comparison = panel["comparisons"][0]
        self.assertEqual(comparison["metrics"]["par2"]["status"], "unavailable")
        for name in ("common_geometric", "common_total", "median", "p95"):
            self.assertEqual(comparison["metrics"][name]["status"], "unavailable")
            self.assertIsNone(comparison["metrics"][name]["ratio"])
        rendered = DASHBOARD.render_html(model)
        self.assertIn("Unavailable", rendered)
        assert_no_nonfinite(self, model)
        json.dumps(model, allow_nan=False)


class ProvenanceIsolationTests(unittest.TestCase):
    def test_expected_status_is_part_of_the_claim_boundary(self) -> None:
        all_record = evidence("all", [instance("a", 1.0, 2.0)])
        sat_record = evidence("sat", [instance("b", 1.0, 2.0)])
        sat_record["expected_status"] = "sat"
        panels = DASHBOARD.build_dashboard(
            fixture_registry(all_record, sat_record)
        )["panels"]
        self.assertEqual(len(panels), 2)
        self.assertEqual(
            {panel["claim_boundary"]["expected_status"] for panel in panels},
            {"all", "sat"},
        )

    def test_solver_subsets_form_distinct_complete_panels(self) -> None:
        registry = fixture_registry(
            evidence("pair-a", [instance("a", 1.0, 2.0)]),
            {
                **evidence("pair-b", [instance("b", 1.0, 3.0)]),
                "solver_ids": ["viper", "second"],
                "instances": [
                    {
                        "id": "b",
                        "results": [
                            result("viper", "solved", 1.0),
                            result("second", "solved", 3.0),
                        ],
                    }
                ],
            },
        )
        registry["solvers"].append({"id": "second", "label": "Second"})
        panels = DASHBOARD.build_dashboard(registry)["panels"]
        self.assertEqual(len(panels), 2)
        self.assertTrue(all(panel["complete"] for panel in panels))
        self.assertEqual(
            {tuple(panel["claim_boundary"]["solver_ids"]) for panel in panels},
            {("competitor", "viper"), ("second", "viper")},
        )
        self.assertEqual(
            {comparison["competitor_id"] for panel in panels for comparison in panel["comparisons"]},
            {"competitor", "second"},
        )

    def test_revision_host_and_evidence_class_never_share_a_panel(self) -> None:
        records = [
            evidence("base", [instance("same", 1.0, 2.0)]),
            evidence(
                "revision-b",
                [instance("same", 1.0, 2.0)],
                revision=REVISION_B,
            ),
            evidence(
                "host-b",
                [instance("same", 1.0, 2.0)],
                host_id="host-b",
                host_label="Host B",
            ),
            evidence(
                "canary",
                [instance("same", 1.0, 2.0)],
                evidence_class="local-canary",
            ),
        ]
        panels = DASHBOARD.build_dashboard(fixture_registry(*records))["panels"]
        self.assertEqual(len(panels), 4)
        boundaries = [panel["claim_boundary"] for panel in panels]
        triples = {
            (
                boundary["revision"],
                boundary["host"]["id"],
                boundary["evidence_class"],
            )
            for boundary in boundaries
        }
        self.assertEqual(len(triples), 4)
        self.assertTrue(all(len(panel["evidence_ids"]) == 1 for panel in panels))

    def test_compatible_shards_merge_but_duplicate_instances_fail_closed(self) -> None:
        first = evidence("shard-a", [instance("a", 1.0, 2.0)])
        second = evidence("shard-b", [instance("b", 2.0, 4.0)])
        model = DASHBOARD.build_dashboard(fixture_registry(first, second))
        self.assertEqual(len(model["panels"]), 1)
        self.assertEqual(model["panels"][0]["instances"], 2)
        self.assertEqual(model["panels"][0]["evidence_ids"], ["shard-a", "shard-b"])

        second["instances"][0]["id"] = "a"
        with self.assertRaisesRegex(
            DASHBOARD.DashboardInputError, "duplicate instance"
        ):
            DASHBOARD.build_dashboard(fixture_registry(first, second))


class SchemaValidationTests(unittest.TestCase):
    def test_gzip_registry_loads_with_the_same_strict_validation(self) -> None:
        registry = fixture_registry()
        payload = json.dumps(registry, allow_nan=False, sort_keys=True).encode()
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "registry.json.gz"
            path.write_bytes(gzip.compress(payload, mtime=0))
            self.assertEqual(
                DASHBOARD.load_registry(path), DASHBOARD.validate_registry(registry)
            )

    def test_decisive_wall_time_may_include_timeout_grace_overhead(self) -> None:
        registry = fixture_registry()
        registry["evidence"][0]["instances"][0]["results"][0]["time_s"] = 10.25
        model = DASHBOARD.build_dashboard(registry)
        competitor = next(
            item
            for item in model["panels"][0]["solvers"]
            if item["solver_id"] == "competitor"
        )
        self.assertEqual(competitor["solved"], 2)

    def test_bad_schema_and_result_shapes_are_rejected(self) -> None:
        cases: list[tuple[str, dict, str]] = []
        wrong_version = fixture_registry()
        wrong_version["schema_version"] = "future"
        cases.append(("version", wrong_version, "schema_version"))

        extra_key = fixture_registry()
        extra_key["extra"] = True
        cases.append(("extra", extra_key, "unexpected keys"))

        missing_solver = fixture_registry()
        missing_solver["evidence"][0]["instances"][0]["results"].pop()
        cases.append(("solver", missing_solver, "every declared solver"))

        invalid_time = fixture_registry()
        invalid_time["evidence"][0]["instances"][0]["results"][0]["time_s"] = None
        cases.append(("time", invalid_time, "must be a number"))

        timeout_time = fixture_registry()
        timeout_time["evidence"][0]["instances"][0]["results"][0] = result(
            "viper", "timeout", 10.0
        )
        cases.append(("timeout-time", timeout_time, "must be null"))

        for name, registry, message in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(DASHBOARD.DashboardInputError, message):
                    DASHBOARD.build_dashboard(registry)

    def test_utc_offset_timestamp_and_non_string_keys_are_handled_strictly(self) -> None:
        registry = fixture_registry()
        registry["updated_at"] = "2026-07-26T12:00:00+00:00"
        model = DASHBOARD.build_dashboard(registry)
        self.assertEqual(
            model["registry"]["updated_at"], "2026-07-26T12:00:00+00:00"
        )

        invalid = fixture_registry()
        invalid[1] = "not a JSON object key"
        with self.assertRaisesRegex(
            DASHBOARD.DashboardInputError, "object keys must be strings"
        ):
            DASHBOARD.build_dashboard(invalid)

    def test_strict_json_rejects_nan_infinity_and_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "registry.json"
            for name, raw, message in (
                ("nan", "{\"value\": NaN}", "non-finite"),
                ("infinity", "{\"value\": Infinity}", "non-finite"),
                ("duplicate", "{\"value\": 1, \"value\": 2}", "duplicate JSON key"),
            ):
                with self.subTest(name=name):
                    path.write_text(raw, encoding="utf-8")
                    with self.assertRaisesRegex(DASHBOARD.DashboardInputError, message):
                        DASHBOARD.load_registry(path)


class OutputTests(unittest.TestCase):
    def test_model_html_and_cli_outputs_are_deterministic_and_atomic(self) -> None:
        registry = fixture_registry(
            evidence(
                "targeted-z",
                [instance("z", 3.0, 6.0)],
                scope="targeted",
                evidence_class="targeted-abba",
                evidence_status="provisional",
            ),
            evidence("broad-a", [instance("a", 1.0, 2.0)]),
        )
        first_model = DASHBOARD.build_dashboard(copy.deepcopy(registry))
        reordered = copy.deepcopy(registry)
        reordered["solvers"].reverse()
        reordered["evidence"].reverse()
        for item in reordered["evidence"]:
            item["instances"].reverse()
            for observed_instance in item["instances"]:
                observed_instance["results"].reverse()
        second_model = DASHBOARD.build_dashboard(reordered)
        self.assertEqual(
            DASHBOARD.pretty_json_bytes(first_model),
            DASHBOARD.pretty_json_bytes(second_model),
        )
        first_html = DASHBOARD.render_html(first_model).encode("utf-8")
        second_html = DASHBOARD.render_html(second_model).encode("utf-8")
        self.assertEqual(first_html, second_html)
        self.assertIn(b'data-scope="broad"', first_html)
        self.assertIn(b'data-scope="targeted"', first_html)
        self.assertIn(b'id="corpus-filter"', first_html)
        self.assertIn(b'id="timeout-filter"', first_html)
        self.assertIn(b'id="family-filter"', first_html)
        self.assertIn(b'id="expected-filter"', first_html)
        self.assertIn(b'id="status-filter"', first_html)

        with tempfile.TemporaryDirectory(prefix="euf dashboard ") as temp_dir:
            root = Path(temp_dir)
            registry_path = root / "registry.json"
            html_path = root / "dashboard.html"
            json_path = root / "dashboard.json"
            registry_path.write_text(
                json.dumps(registry, allow_nan=False, sort_keys=True),
                encoding="utf-8",
            )
            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = DASHBOARD.main(
                    [
                        str(registry_path),
                        "--html-out",
                        str(html_path),
                        "--json-out",
                        str(json_path),
                    ]
                )
            self.assertEqual(exit_code, 0)
            receipt = json.loads(stdout.getvalue())
            self.assertEqual(receipt["panels"], 2)
            initial_html = html_path.read_bytes()
            initial_json = json_path.read_bytes()

            with redirect_stdout(StringIO()):
                self.assertEqual(
                    DASHBOARD.main(
                        [
                            str(registry_path),
                            "--html-out",
                            str(html_path),
                            "--json-out",
                            str(json_path),
                        ]
                    ),
                    0,
                )
            self.assertEqual(html_path.read_bytes(), initial_html)
            self.assertEqual(json_path.read_bytes(), initial_json)
            self.assertFalse(list(root.glob(".*.tmp")))
            json.loads(initial_json, parse_constant=lambda token: self.fail(token))

    def test_invalid_cli_input_preserves_existing_outputs(self) -> None:
        bad = fixture_registry()
        bad["evidence"][0]["timeout_s"] = float("nan")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            registry_path = root / "bad.json"
            html_path = root / "dashboard.html"
            json_path = root / "dashboard.json"
            registry_path.write_text(
                json.dumps(bad, allow_nan=True), encoding="utf-8"
            )
            html_path.write_text("old html", encoding="utf-8")
            json_path.write_text("old json", encoding="utf-8")
            stderr = StringIO()
            with redirect_stderr(stderr):
                exit_code = DASHBOARD.main(
                    [
                        str(registry_path),
                        "--html-out",
                        str(html_path),
                        "--json-out",
                        str(json_path),
                    ]
                )
            self.assertEqual(exit_code, 2)
            self.assertIn("non-finite", stderr.getvalue())
            self.assertEqual(html_path.read_text(encoding="utf-8"), "old html")
            self.assertEqual(json_path.read_text(encoding="utf-8"), "old json")
            self.assertFalse(list(root.glob(".*.tmp")))


if __name__ == "__main__":
    unittest.main()
