from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import statistics
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "import_fast_cycle_dashboard.py"
DASHBOARD_SCRIPT = ROOT / "scripts" / "bench" / "build_euf_dashboard.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


IMPORTER = load_module("import_fast_cycle_dashboard", SCRIPT)
DASHBOARD = load_module("build_euf_dashboard_for_import", DASHBOARD_SCRIPT)

REVISION = "9a0763538a496898bace0325a456d0a86771a3c5"
CANDIDATE_HASH = "a" * 64
BASELINE_HASHES = {"yices2": "b" * 64, "z3": "c" * 64, "cvc5": "d" * 64}
BASELINE_COMMANDS = {
    "yices2": ["bin/yices-smt2", "{input}"],
    "z3": ["bin/z3", "-smt2", "{input}"],
    "cvc5": ["bin/cvc5", "{input}"],
}
CANDIDATE_COMMAND = [
    "target/release/euf-viper",
    "fabric-solve",
    "--engine",
    "quotient-portfolio",
    "{input}",
]


def sample(
    result: str,
    time_s: float,
    *,
    timed_out: bool = False,
    error_kind: str = "",
    exit_code: int = 0,
    process_returncode: int | None = None,
) -> dict:
    return {
        "result": result,
        "time_s": time_s,
        "timed_out": timed_out,
        "error_kind": error_kind,
        "exit_code": exit_code,
        "process_returncode": (
            exit_code if process_returncode is None else process_returncode
        ),
    }


def correct(result: str, time_s: float) -> dict:
    return sample(result, time_s)


def fixture_options(**overrides) -> argparse.Namespace:
    values = {
        "registry_id": "fixture-fast-cycle",
        "title": "Fixture fast-cycle evidence",
        "updated_at": None,
        "viper_solver_id": "euf-viper",
        "viper_label": "EUF Viper",
        "corpus_id": "fixture-qf-uf",
        "corpus_label": "Fixture QF_UF",
        "evidence_class": "local-one-repeat-discovery",
        "evidence_status": "provisional",
        "include_status_panels": False,
        "combined_family_id": None,
        "combined_family_label": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class FastCycleFixture:
    def __init__(
        self,
        directory: Path,
        *,
        comparator: str = "yices2",
        stage: str = "Q2PF",
        instances: list[dict] | None = None,
        repeats: int = 1,
        finished_at: str = "2026-07-26T14:45:06+00:00",
        baseline_command: list[str] | None = None,
    ) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True)
        self.comparator = comparator
        self.stage = stage
        self.repeats = repeats
        self.finished_at = finished_at
        self.candidate_command = list(CANDIDATE_COMMAND)
        self.baseline_command = list(
            baseline_command or BASELINE_COMMANDS[comparator]
        )
        self.instances = instances or [
            {
                "path": "QF_UF/PEQ/example-a.smt2",
                "expected": "sat",
                "candidate": [correct("sat", 0.1)] * repeats,
                "baseline": [correct("sat", 0.2)] * repeats,
            }
        ]
        self.csv_path = directory / f"{stage.lower()}-{comparator}.csv"
        self.summary_path = directory / f"{stage.lower()}-{comparator}.json"
        self.ledger_path = directory / "ledger.json"
        self.rows = self._make_rows()
        self._write_csv()
        self._write_summary()
        self._write_ledger()

    @staticmethod
    def _expanded(command: list[str], input_path: str) -> list[str]:
        return [input_path if token == "{input}" else token for token in command]

    @staticmethod
    def _covered(samples: list[dict], expected: str) -> bool:
        return all(
            item["result"] == expected
            and item["result"] in {"sat", "unsat"}
            and not item["timed_out"]
            and not item["error_kind"]
            and item["exit_code"] == 0
            for item in samples
        )

    def _make_rows(self) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        sequence = 0
        for row_index, instance in enumerate(self.instances):
            self.assert_fixture_repeats(instance)
            for repeat in range(self.repeats):
                order = (
                    ("baseline", "candidate")
                    if (row_index + repeat) % 2 == 0
                    else ("candidate", "baseline")
                )
                for order_in_repeat, label in enumerate(order):
                    observation = instance[label][repeat]
                    command = (
                        self.candidate_command
                        if label == "candidate"
                        else self.baseline_command
                    )
                    input_path = f"/corpus/{instance['path']}"
                    rows.append(
                        {
                            "sequence": str(sequence),
                            "row_index": str(row_index),
                            "id": str(100 + row_index),
                            "relative_path": instance["path"],
                            "expected_status": instance["expected"],
                            "label": label,
                            "repeat": str(repeat),
                            "order_in_repeat": str(order_in_repeat),
                            "result": observation["result"],
                            "time_s": f"{observation['time_s']:.9f}",
                            "exit_code": str(observation["exit_code"]),
                            "process_returncode": str(
                                observation["process_returncode"]
                            ),
                            "timed_out": "1" if observation["timed_out"] else "0",
                            "error_kind": observation["error_kind"],
                            "stdout": "",
                            "stderr": "",
                            "argv_json": json.dumps(
                                self._expanded(command, input_path),
                                separators=(",", ":"),
                            ),
                        }
                    )
                    sequence += 1
        return rows

    def assert_fixture_repeats(self, instance: dict) -> None:
        if len(instance["candidate"]) != self.repeats:
            raise AssertionError("candidate fixture repeat mismatch")
        if len(instance["baseline"]) != self.repeats:
            raise AssertionError("baseline fixture repeat mismatch")

    def _write_csv(self) -> None:
        with self.csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=IMPORTER.CSV_FIELDS)
            writer.writeheader()
            writer.writerows(self.rows)

    def _summary_arm(self, samples: list[dict], expected: str) -> dict:
        covered = self._covered(samples, expected)
        return {
            "covered": covered,
            "correct": covered,
            "median_time_s": statistics.median(
                float(f"{item['time_s']:.9f}") for item in samples
            ),
        }

    def _write_summary(self) -> None:
        csv_payload = self.csv_path.read_bytes()
        paths = []
        for row_index, instance in enumerate(self.instances):
            paths.append(
                {
                    "row_index": row_index,
                    "id": 100 + row_index,
                    "relative_path": instance["path"],
                    "expected_status": instance["expected"],
                    "candidate": self._summary_arm(
                        instance["candidate"], instance["expected"]
                    ),
                    "baseline": self._summary_arm(
                        instance["baseline"], instance["expected"]
                    ),
                }
            )
        summary = {
            "schema_version": 1,
            "status": "complete",
            "timeout_s": 2.0,
            "repeats": self.repeats,
            "warmups": 0,
            "instances": len(self.instances),
            "measured_runs": len(self.rows),
            "candidate": self.candidate_command,
            "baseline": self.baseline_command,
            "candidate_sha256": CANDIDATE_HASH,
            "baseline_sha256": BASELINE_HASHES[self.comparator],
            "candidate_correct": sum(
                self._covered(item["candidate"], item["expected"])
                for item in self.instances
            ),
            "baseline_correct": sum(
                self._covered(item["baseline"], item["expected"])
                for item in self.instances
            ),
            "host": {
                "hostname": "fixture-host.local",
                "system": "Darwin",
                "machine": "arm64",
            },
            "paths": paths,
            "artifacts": {
                "results_csv": {
                    "path": str(self.csv_path),
                    "resolved_path": str(self.csv_path.resolve()),
                    "sha256": hashlib.sha256(csv_payload).hexdigest(),
                    "size_bytes": len(csv_payload),
                    "fieldnames": list(IMPORTER.CSV_FIELDS),
                }
            },
        }
        self.summary_path.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def _write_ledger(self) -> None:
        run = {
            "blocking_performance": False,
            "command_returncode": 0,
            "common_aggregate_speedup": 1.0,
            "common_geometric_speedup": 1.0,
            "comparator": self.comparator,
            "coverage_delta": 0,
            "coverage_dominance": False,
            "csv": str(self.csv_path),
            "failures": [],
            "kind": "competitor",
            "passed": True,
            "performance_target_failures": [],
            "performance_target_met": True,
            "stage": self.stage,
            "stderr_tail": "",
            "stdout_tail": "",
            "summary": str(self.summary_path),
        }
        ledger = {
            "campaign_id": "fixture-fast-cycle",
            "finished_at": self.finished_at,
            "preflight": [],
            "reference_binary": None,
            "repository": {"clean": False, "revision": REVISION},
            "runs": [run],
            "schema_version": 2,
            "selected_comparators": {self.stage: [self.comparator]},
            "selected_stages": [self.stage],
            "spec": {"path": "campaigns/fixture.json", "sha256": "e" * 64},
            "started_at": "2026-07-26T14:44:00+00:00",
            "status": "passed",
        }
        self.ledger_path.write_text(
            json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def refresh_summary_csv_receipt(self) -> None:
        summary = json.loads(self.summary_path.read_text(encoding="utf-8"))
        payload = self.csv_path.read_bytes()
        summary["artifacts"]["results_csv"]["sha256"] = hashlib.sha256(
            payload
        ).hexdigest()
        summary["artifacts"]["results_csv"]["size_bytes"] = len(payload)
        summary["measured_runs"] = len(
            list(csv.DictReader(StringIO(payload.decode("utf-8"))))
        )
        self.summary_path.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


class ImportTests(unittest.TestCase):
    def test_optional_expected_status_panels_are_exact_subsets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = FastCycleFixture(
                Path(temporary) / "run",
                instances=[
                    {
                        "path": "QF_UF/PEQ/sat.smt2",
                        "expected": "sat",
                        "candidate": [correct("sat", 0.1)],
                        "baseline": [correct("sat", 0.2)],
                    },
                    {
                        "path": "QF_UF/PEQ/unsat.smt2",
                        "expected": "unsat",
                        "candidate": [correct("unsat", 0.2)],
                        "baseline": [correct("unsat", 0.3)],
                    },
                ],
            )
            registry = IMPORTER.build_registry(
                [fixture.ledger_path],
                fixture_options(include_status_panels=True),
            )
            self.assertEqual(len(registry["evidence"]), 3)
            counts = {
                item["expected_status"]: len(item["instances"])
                for item in registry["evidence"]
            }
            self.assertEqual(counts, {"all": 2, "sat": 1, "unsat": 1})
            self.assertEqual(len(DASHBOARD.build_dashboard(registry)["panels"]), 3)

    def test_optional_combined_family_panel_preserves_source_shards(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            peq = FastCycleFixture(root / "peq")
            seq = FastCycleFixture(
                root / "seq",
                stage="Q2SF",
                finished_at="2026-07-26T14:46:00+00:00",
                instances=[
                    {
                        "path": "QF_UF/SEQ/example-b.smt2",
                        "expected": "unsat",
                        "candidate": [correct("unsat", 0.12)],
                        "baseline": [correct("unsat", 0.25)],
                    }
                ],
            )
            registry = IMPORTER.build_registry(
                [peq.ledger_path, seq.ledger_path],
                fixture_options(
                    combined_family_id="structural-combined",
                    combined_family_label="PEQ + SEQ",
                ),
            )
            self.assertEqual(len(registry["evidence"]), 4)
            combined = [
                item
                for item in registry["evidence"]
                if item["family"]["id"] == "structural-combined"
            ]
            self.assertEqual(len(combined), 2)
            self.assertEqual(len({item["source"]["sha256"] for item in combined}), 2)
            model = DASHBOARD.build_dashboard(registry)
            combined_panel = next(
                panel
                for panel in model["panels"]
                if panel["claim_boundary"]["family"]["id"]
                == "structural-combined"
            )
            self.assertEqual(combined_panel["instances"], 2)
            self.assertEqual(len(combined_panel["evidence_ids"]), 2)

    def test_pairwise_solver_subsets_and_provenance_validate_in_dashboard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            yices = FastCycleFixture(root / "yices")
            z3 = FastCycleFixture(
                root / "z3",
                comparator="z3",
                finished_at="2026-07-26T14:46:00+00:00",
            )
            registry = IMPORTER.build_registry(
                [z3.ledger_path, yices.ledger_path], fixture_options()
            )

            self.assertEqual(
                registry["updated_at"], "2026-07-26T14:46:00Z"
            )
            self.assertEqual(
                [solver["id"] for solver in registry["solvers"]],
                ["euf-viper", "yices2", "z3"],
            )
            self.assertEqual(
                {tuple(item["solver_ids"]) for item in registry["evidence"]},
                {("euf-viper", "yices2"), ("euf-viper", "z3")},
            )
            for item in registry["evidence"]:
                self.assertEqual(item["family"], {"id": "peq", "label": "PEQ"})
                source = Path(item["source"]["path"])
                if not source.is_absolute():
                    source = ROOT / source
                expected_hash = hashlib.sha256(source.read_bytes()).hexdigest()
                self.assertEqual(item["source"]["sha256"], expected_hash)
            validated = DASHBOARD.validate_registry(registry)
            self.assertEqual(len(validated["evidence"]), 2)

    def test_maps_non_solves_conservatively(self) -> None:
        instances = [
            {
                "path": "QF_UF/PEQ/solved-timeout.smt2",
                "expected": "sat",
                "candidate": [correct("sat", 2.01)],
                "baseline": [
                    sample(
                        "timeout",
                        2.01,
                        timed_out=True,
                        error_kind="timeout",
                        exit_code=124,
                        process_returncode=-9,
                    )
                ],
            },
            {
                "path": "QF_UF/PEQ/unknown-wrong.smt2",
                "expected": "unsat",
                "candidate": [correct("unknown", 0.2)],
                "baseline": [correct("sat", 0.3)],
            },
            {
                "path": "QF_UF/PEQ/error-solved.smt2",
                "expected": "sat",
                "candidate": [
                    sample(
                        "invalid-output",
                        0.4,
                        error_kind="nonzero_exit+invalid_stdout",
                        exit_code=1,
                    )
                ],
                "baseline": [correct("sat", 0.5)],
            },
            {
                "path": "QF_UF/PEQ/unresolved-ground-truth.smt2",
                "expected": "unknown",
                "candidate": [correct("sat", 0.6)],
                "baseline": [correct("unknown", 0.7)],
            },
        ]
        with tempfile.TemporaryDirectory() as temporary:
            fixture = FastCycleFixture(Path(temporary) / "run", instances=instances)
            registry = IMPORTER.build_registry(
                [fixture.ledger_path], fixture_options()
            )
            observations = {
                item["id"]: {
                    result["solver_id"]: result
                    for result in item["results"]
                }
                for item in registry["evidence"][0]["instances"]
            }
            self.assertEqual(
                observations[instances[0]["path"]]["euf-viper"],
                {
                    "solver_id": "euf-viper",
                    "status": "solved",
                    "time_s": 2.01,
                },
            )
            self.assertEqual(
                observations[instances[0]["path"]]["yices2"]["status"], "timeout"
            )
            self.assertIsNone(
                observations[instances[0]["path"]]["yices2"]["time_s"]
            )
            self.assertEqual(
                observations[instances[1]["path"]]["euf-viper"]["status"], "unknown"
            )
            self.assertEqual(
                observations[instances[1]["path"]]["yices2"]["status"],
                "wrong-answer",
            )
            self.assertEqual(
                observations[instances[2]["path"]]["euf-viper"]["status"], "error"
            )
            self.assertEqual(
                observations[instances[3]["path"]]["euf-viper"]["status"], "unknown"
            )
            DASHBOARD.validate_registry(registry)

    def test_repeats_are_aggregated_by_median(self) -> None:
        instances = [
            {
                "path": "QF_UF/PEQ/repeated.smt2",
                "expected": "unsat",
                "candidate": [
                    correct("unsat", 0.1),
                    correct("unsat", 0.3),
                    correct("unsat", 0.2),
                ],
                "baseline": [
                    correct("unsat", 0.4),
                    correct("unsat", 0.6),
                    correct("unsat", 0.5),
                ],
            }
        ]
        with tempfile.TemporaryDirectory() as temporary:
            fixture = FastCycleFixture(
                Path(temporary) / "run", instances=instances, repeats=3
            )
            registry = IMPORTER.build_registry(
                [fixture.ledger_path], fixture_options()
            )
            results = {
                item["solver_id"]: item
                for item in registry["evidence"][0]["instances"][0]["results"]
            }
            self.assertEqual(results["euf-viper"]["time_s"], 0.2)
            self.assertEqual(results["yices2"]["time_s"], 0.5)

    def test_mismatched_candidate_and_baseline_instances_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = FastCycleFixture(Path(temporary) / "run")
            fixture.rows.pop()
            fixture._write_csv()
            fixture.refresh_summary_csv_receipt()
            with self.assertRaisesRegex(
                IMPORTER.FastCycleImportError,
                "candidate/baseline instances do not match",
            ):
                IMPORTER.build_registry([fixture.ledger_path], fixture_options())

    def test_candidate_and_comparator_identity_mismatches_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bad_baseline = FastCycleFixture(
                root / "baseline",
                comparator="yices2",
                baseline_command=["bin/z3", "-smt2", "{input}"],
            )
            with self.assertRaisesRegex(
                IMPORTER.FastCycleImportError, "does not match baseline executable"
            ):
                IMPORTER.build_registry(
                    [bad_baseline.ledger_path], fixture_options()
                )

            bad_candidate = FastCycleFixture(root / "candidate")
            summary = json.loads(
                bad_candidate.summary_path.read_text(encoding="utf-8")
            )
            summary["candidate"][0] = "bin/not-viper"
            bad_candidate.summary_path.write_text(
                json.dumps(summary, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                IMPORTER.FastCycleImportError,
                "candidate executable must identify euf-viper",
            ):
                IMPORTER.build_registry(
                    [bad_candidate.ledger_path], fixture_options()
                )

    def test_csv_receipt_tampering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = FastCycleFixture(Path(temporary) / "run")
            fixture.csv_path.write_text(
                fixture.csv_path.read_text(encoding="utf-8") + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                IMPORTER.FastCycleImportError, "CSV SHA-256 mismatch"
            ):
                IMPORTER.build_registry([fixture.ledger_path], fixture_options())

    def test_duplicate_and_overlapping_evidence_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = FastCycleFixture(root / "first")
            with self.assertRaisesRegex(
                IMPORTER.FastCycleImportError, "duplicate evidence ledger"
            ):
                IMPORTER.build_registry(
                    [first.ledger_path, first.ledger_path], fixture_options()
                )

            second = FastCycleFixture(
                root / "second", finished_at="2026-07-26T14:47:00+00:00"
            )
            with self.assertRaisesRegex(
                IMPORTER.FastCycleImportError,
                "duplicate evidence observations",
            ):
                IMPORTER.build_registry(
                    [first.ledger_path, second.ledger_path], fixture_options()
                )

    def test_cli_output_is_atomic_deterministic_and_metadata_is_configurable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = FastCycleFixture(root / "run")
            first = root / "first.json"
            second = root / "nested" / "second.json"
            common = [
                str(fixture.ledger_path),
                "--registry-id",
                "custom-registry",
                "--title",
                "Custom evidence title",
                "--updated-at",
                "2026-07-26T15:00:00Z",
                "--corpus-id",
                "custom-corpus",
                "--corpus-label",
                "Custom corpus",
                "--evidence-class",
                "custom-discovery",
                "--evidence-status",
                "provisional",
            ]
            for output in (first, second):
                stdout = StringIO()
                stderr = StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    returncode = IMPORTER.main([*common, "--output", str(output)])
                self.assertEqual(returncode, 0, stderr.getvalue())
                self.assertEqual(stdout.getvalue().strip(), str(output))
            self.assertEqual(first.read_bytes(), second.read_bytes())
            registry = json.loads(first.read_text(encoding="ascii"))
            self.assertEqual(registry["registry_id"], "custom-registry")
            self.assertEqual(registry["title"], "Custom evidence title")
            self.assertEqual(registry["updated_at"], "2026-07-26T15:00:00Z")
            self.assertEqual(
                registry["evidence"][0]["corpus"],
                {"id": "custom-corpus", "label": "Custom corpus"},
            )
            self.assertEqual(
                registry["evidence"][0]["evidence_class"], "custom-discovery"
            )
            DASHBOARD.validate_registry(registry)


if __name__ == "__main__":
    unittest.main()
