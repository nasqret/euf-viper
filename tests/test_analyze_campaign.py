from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "analyze_campaign.py"
SPEC = importlib.util.spec_from_file_location("analyze_campaign", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ANALYZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZER)

BASELINE_SHA256 = "a" * 64
CANDIDATE_SHA256 = "b" * 64


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def case(
    family: str,
    expected: str,
    baseline_wall: float,
    candidate_wall: float,
    *,
    baseline_result: str | None = None,
    candidate_result: str | None = None,
) -> dict[str, object]:
    return {
        "family": family,
        "expected": expected,
        "baseline_wall": baseline_wall,
        "candidate_wall": candidate_wall,
        "baseline_result": baseline_result or expected,
        "candidate_result": candidate_result or expected,
    }


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ANALYZER.FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def write_fixture(
    directory: Path,
    cases: list[dict[str, object]],
    *,
    budgets: tuple[float, ...] = (10.0,),
) -> tuple[Path, Path, list[dict[str, object]]]:
    manifest_path = directory / "manifest.jsonl"
    manifest_rows = []
    identities = []
    for index, data in enumerate(cases):
        family = str(data["family"])
        relative_path = f"QF_UF/{family}/case-{index:03d}.smt2"
        instance_sha256 = digest(f"instance-{index}-{family}")
        identities.append((relative_path, instance_sha256))
        manifest_rows.append(
            {
                "family": family,
                "relative_path": relative_path,
                "sha256": instance_sha256,
                "status": data["expected"],
            }
        )
    manifest_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in manifest_rows),
        encoding="utf-8",
    )
    manifest_sha256 = ANALYZER.sha256_file(manifest_path)

    rows: list[dict[str, object]] = []
    for data, (relative_path, instance_sha256) in zip(cases, identities):
        for budget in budgets:
            for label in ANALYZER.LABELS:
                wall = float(data[f"{label}_wall"])
                result = str(data[f"{label}_result"])
                rows.append(
                    {
                        "relative_path": relative_path,
                        "family": data["family"],
                        "expected_status": data["expected"],
                        "budget_s": budget,
                        "label": label,
                        "manifest_sha256": manifest_sha256,
                        "instance_sha256": instance_sha256,
                        "binary_sha256": (
                            BASELINE_SHA256
                            if label == "baseline"
                            else CANDIDATE_SHA256
                        ),
                        "result": result,
                        "cpu_time_s": wall * 0.8,
                        "wall_time_s": wall,
                    }
                )
    csv_path = directory / "campaign.csv"
    write_csv(csv_path, rows)
    return csv_path, manifest_path, rows


def write_locked_fixture(
    directory: Path,
) -> tuple[Path, Path, list[dict[str, object]]]:
    instances = []
    for index, (family, status) in enumerate(
        (("alpha", "sat"), ("beta", "unsat"))
    ):
        instances.append(
            {
                "id": str(index),
                "relative_path": f"QF_UF/{family}/case-{index}.smt2",
                "path": str(directory / f"case-{index}.smt2"),
                "sha256": digest(f"locked-instance-{index}"),
                "bytes": 100 + index,
                "status": status,
                "family": family,
                "lineage": f"{family}/generator",
                "normalized_sha256": digest(f"normalized-{index}"),
                "split": "development",
            }
        )
    solvers = []
    for solver_id in ("euf-viper", "z3"):
        solvers.append(
            {
                "id": solver_id,
                "comparator_id": solver_id,
                "configuration": "default",
                "version": "test-1",
                "binary": str(directory / solver_id),
                "sha256": digest(f"binary-{solver_id}"),
                "argv_template": [
                    "{binary}",
                    "{instance}",
                    "--timeout={budget_s}",
                ],
                "version_output": None,
                "version_output_sha256": None,
                "environment": {},
            }
        )
    lock: dict[str, object] = {
        "schema_version": 1,
        "campaign_id": "locked-test",
        "lock_sha256": "",
        "created_from_commit_time": "2026-07-12T00:00:00+00:00",
        "promotion_eligible": True,
        "spec": {"path": str(directory / "spec.json"), "sha256": "1" * 64},
        "repository": {},
        "host": {},
        "corpus": {
            "id": "test-corpus",
            "manifest_path": str(directory / "manifest.jsonl"),
            "manifest_sha256": "2" * 64,
            "taxonomy_path": str(directory / "taxonomy.jsonl"),
            "taxonomy_sha256": "3" * 64,
            "root": str(directory),
            "instances": instances,
        },
        "solver_config": {
            "path": str(directory / "solvers.json"),
            "sha256": "4" * 64,
        },
        "solver_release_lock": {
            "path": str(directory / "solver-releases.json"),
            "sha256": "5" * 64,
        },
        "solvers": solvers,
        "budgets_s": [10],
        "execution": {
            "resource_model": "single_core_cold_process",
            "cpu_ids": [0],
            "memory_bytes": 1024**3,
            "order": "abba",
            "environment": {"PATH": "/usr/bin"},
            "timeout_grace_s": 0.25,
        },
        "output": {
            "directory": str(directory),
            "journal": "journal.jsonl",
            "raw": "raw.jsonl",
            "summary": "summary.json",
        },
    }
    unsigned = dict(lock)
    unsigned["lock_sha256"] = ""
    lock["lock_sha256"] = hashlib.sha256(
        ANALYZER._canonical_json_bytes(unsigned)
    ).hexdigest()
    lock_path = directory / "lock.json"
    lock_path.write_bytes(ANALYZER._canonical_json_bytes(lock))

    records: list[dict[str, object]] = []
    previous_sha256 = digest("invocation-record")
    for item in ANALYZER._locked_schedule(lock):
        expected = item["instance"]["status"]
        solver_id = item["solver"]["id"]
        wall = 1.0 if solver_id == "euf-viper" else 2.0
        record: dict[str, object] = {
            "record_type": "run",
            "schema_version": 1,
            "lock_sha256": lock["lock_sha256"],
            "invocation": 0,
            "sequence": item["sequence"],
            "key": item["key"],
            "instance_id": item["instance"]["id"],
            "relative_path": item["instance"]["relative_path"],
            "instance_sha256": item["instance"]["sha256"],
            "expected_status": expected,
            "family": item["instance"]["family"],
            "solver_id": solver_id,
            "solver_sha256": item["solver"]["sha256"],
            "solver_version": item["solver"]["version"],
            "budget_s": item["budget_s"],
            "repetition": item["repetition"],
            "cpu_id": item["cpu_id"],
            "argv": item["argv"],
            "descriptor_binding": {
                "mechanism": "platform_pathname",
                "solver_sha256": item["solver"]["sha256"],
                "source_sha256": item["instance"]["sha256"],
            },
            "environment_sha256": item["environment_sha256"],
            "pid": 1000 + item["sequence"],
            "started_at": "2026-07-12T00:00:00+00:00",
            "finished_at": "2026-07-12T00:00:01+00:00",
            "wall_time_s": wall,
            "child_user_time_s": wall * 0.7,
            "child_system_time_s": wall * 0.1,
            "child_cpu_time_s": wall * 0.8,
            "max_rss_bytes": 1024,
            "exit_code": 0,
            "termination_cause": "exit",
            "termination_signal": None,
            "timed_out": False,
            "spawn_error": None,
            "stdout_sha256": digest(f"stdout-{item['sequence']}"),
            "stdout_bytes": len(expected),
            "stderr_sha256": digest(""),
            "stderr_bytes": 0,
            "result_token": expected,
            "result_token_status": "valid",
            "previous_record_sha256": previous_sha256,
            "record_sha256": "",
        }
        record["record_sha256"] = ANALYZER._record_digest(record)
        previous_sha256 = str(record["record_sha256"])
        records.append(record)
    raw_path = directory / "raw.jsonl"
    raw_path.write_bytes(
        b"".join(ANALYZER._canonical_json_bytes(record) for record in records)
    )
    return lock_path, raw_path, records


def write_raw_for_lock(lock: dict[str, object], raw_path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    previous_sha256 = digest("invocation-record")
    for item in ANALYZER._locked_schedule(lock):
        expected = item["instance"]["status"]
        solver_id = item["solver"]["id"]
        wall = 1.0 if solver_id == "euf-viper" else 2.0
        record: dict[str, object] = {
            "record_type": "run",
            "schema_version": 1,
            "lock_sha256": lock["lock_sha256"],
            "invocation": 0,
            "sequence": item["sequence"],
            "key": item["key"],
            "instance_id": item["instance"]["id"],
            "relative_path": item["instance"]["relative_path"],
            "instance_sha256": item["instance"]["sha256"],
            "expected_status": expected,
            "family": item["instance"]["family"],
            "solver_id": solver_id,
            "solver_sha256": item["solver"]["sha256"],
            "solver_version": item["solver"]["version"],
            "budget_s": item["budget_s"],
            "repetition": item["repetition"],
            "cpu_id": item["cpu_id"],
            "argv": item["argv"],
            "descriptor_binding": {
                "mechanism": "platform_pathname",
                "solver_sha256": item["solver"]["sha256"],
                "source_sha256": item["instance"]["sha256"],
            },
            "environment_sha256": item["environment_sha256"],
            "pid": 2000 + item["sequence"],
            "started_at": "2026-07-12T00:00:00+00:00",
            "finished_at": "2026-07-12T00:00:01+00:00",
            "wall_time_s": wall,
            "child_user_time_s": wall * 0.7,
            "child_system_time_s": wall * 0.1,
            "child_cpu_time_s": wall * 0.8,
            "max_rss_bytes": 1024,
            "exit_code": 0,
            "termination_cause": "exit",
            "termination_signal": None,
            "timed_out": False,
            "spawn_error": None,
            "stdout_sha256": digest(f"shard-stdout-{item['sequence']}"),
            "stdout_bytes": len(expected),
            "stderr_sha256": digest(""),
            "stderr_bytes": 0,
            "result_token": expected,
            "result_token_status": "valid",
            "previous_record_sha256": previous_sha256,
            "record_sha256": "",
        }
        record["record_sha256"] = ANALYZER._record_digest(record)
        previous_sha256 = str(record["record_sha256"])
        records.append(record)
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_bytes(
        b"".join(ANALYZER._canonical_json_bytes(record) for record in records)
    )
    return records


def write_sharded_fixture(
    directory: Path,
) -> tuple[Path, list[tuple[Path, Path]]]:
    parent_path, _, _ = write_locked_fixture(directory)
    parent = json.loads(parent_path.read_text(encoding="utf-8"))
    lock_directory = directory / "locks"
    results_directory = directory / "results"
    pairs: list[tuple[Path, Path]] = []
    for index in range(2):
        prepared = ANALYZER._expected_prepared_shard(parent, index, 2)
        cpu_id = index + 4
        bound = {
            **prepared,
            "lock_sha256": "",
            "execution": {**prepared["execution"], "cpu_ids": [cpu_id]},
            "runtime_binding": {
                "parent_lock_sha256": prepared["lock_sha256"],
                "mechanism": "first_allowed_slurm_cpu",
                "cpu_ids": [cpu_id],
            },
        }
        bound["lock_sha256"] = ANALYZER._lock_sha256(bound)
        lock_path = lock_directory / f"bound-{index:04d}.json"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_bytes(ANALYZER._canonical_json_bytes(bound))
        raw_path = results_directory / f"shard-{index:04d}" / "raw.jsonl"
        write_raw_for_lock(bound, raw_path)
        pairs.append((lock_path, raw_path))
    return parent_path, pairs


def write_sparse_sharded_fixture(
    directory: Path,
) -> tuple[Path, list[tuple[Path, Path]]]:
    parent_path, _, _ = write_locked_fixture(directory)
    parent = json.loads(parent_path.read_text(encoding="utf-8"))
    selection = [
        {"instance_id": "0", "solver_id": "euf-viper"},
        {"instance_id": "1", "solver_id": "z3"},
    ]
    parent["budgets_s"] = [60]
    parent["schema_version"] = 2
    parent["execution"]["order"] = "balanced_latin_square"
    for solver in parent["solvers"]:
        solver["argv_template"] = ["{binary}", "{instance}"]
    parent["continuation"] = {
        "mode": "timeout_only",
        "root_lock_sha256": "7" * 64,
        "parent_lock_path": str((directory / "source-parent.json").resolve()),
        "parent_lock_file_sha256": "6" * 64,
        "parent_lock_sha256": "7" * 64,
        "shard_bundle_sha256": "8" * 64,
        "source_evidence_sha256": "8" * 64,
        "shard_lock_directory": str((directory / "source-locks").resolve()),
        "shard_results_root": str((directory / "source-results").resolve()),
        "source_budget_s": 2,
        "target_budget_s": 60,
        "selection_sha256": hashlib.sha256(
            ANALYZER._canonical_json_bytes(selection)
        ).hexdigest(),
        "selected_instances": 2,
        "selected_runs": 2,
        "runner_path": str(
            (ROOT / "scripts" / "bench" / "run_locked_campaign.py").resolve()
        ),
        "runner_sha256": hashlib.sha256(
            (ROOT / "scripts" / "bench" / "run_locked_campaign.py").read_bytes()
        ).hexdigest(),
    }
    parent["run_selection"] = selection
    parent["lock_sha256"] = ANALYZER._lock_sha256(parent)
    parent_path.write_bytes(ANALYZER._canonical_json_bytes(parent))

    pairs: list[tuple[Path, Path]] = []
    for index in range(2):
        prepared = ANALYZER._expected_prepared_shard(parent, index, 2)
        cpu_id = index + 6
        bound = {
            **prepared,
            "lock_sha256": "",
            "execution": {**prepared["execution"], "cpu_ids": [cpu_id]},
            "runtime_binding": {
                "parent_lock_sha256": prepared["lock_sha256"],
                "mechanism": "first_allowed_slurm_cpu",
                "cpu_ids": [cpu_id],
            },
        }
        bound["lock_sha256"] = ANALYZER._lock_sha256(bound)
        lock_path = directory / "sparse-locks" / f"bound-{index:04d}.json"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_bytes(ANALYZER._canonical_json_bytes(bound))
        raw_path = directory / "sparse-results" / f"shard-{index:04d}" / "raw.jsonl"
        write_raw_for_lock(bound, raw_path)
        pairs.append((lock_path, raw_path))
    return parent_path, pairs


def analyze(csv_path: Path, manifest_path: Path, **overrides: object) -> dict:
    parameters = {
        "seed": 17,
        "bootstrap_replicates": 256,
        "confidence_level": 0.9,
    }
    parameters.update(overrides)
    return ANALYZER.analyze_campaign(csv_path, manifest_path, **parameters)


class ExactStatisticsTests(unittest.TestCase):
    def test_exact_two_sided_mcnemar(self) -> None:
        one_sided_discordance = ANALYZER.exact_mcnemar(0, 6)
        self.assertEqual(one_sided_discordance["exact_fraction"], "1/32")
        self.assertEqual(one_sided_discordance["p_value"], 0.03125)

        mixed_discordance = ANALYZER.exact_mcnemar(1, 3)
        self.assertEqual(mixed_discordance["exact_fraction"], "5/8")
        self.assertEqual(mixed_discordance["p_value"], 0.625)

        no_discordance = ANALYZER.exact_mcnemar(0, 0)
        self.assertEqual(no_discordance["exact_fraction"], "1/1")
        self.assertEqual(no_discordance["p_value"], 1.0)

    def test_scores_cpu_wall_and_common_ratios(self) -> None:
        cases = [
            case("alpha", "sat", 2.0, 1.0),
            case(
                "beta",
                "unsat",
                10.0,
                4.0,
                baseline_result="timeout",
            ),
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path, manifest_path, _ = write_fixture(Path(temp_dir), cases)
            campaign = ANALYZER.load_campaign(csv_path, manifest_path)
            summary = ANALYZER.summarize_pairs(campaign["pairs"])

        self.assertEqual(summary["arms"]["baseline"]["solved"], 1)
        self.assertEqual(summary["arms"]["candidate"]["solved"], 2)
        self.assertAlmostEqual(
            summary["arms"]["baseline"]["timeout_charged_wall_s"], 12.0
        )
        self.assertAlmostEqual(
            summary["arms"]["candidate"]["timeout_charged_wall_s"], 5.0
        )
        self.assertAlmostEqual(summary["arms"]["baseline"]["par2_wall_s"], 22.0)
        self.assertAlmostEqual(summary["arms"]["candidate"]["par2_wall_s"], 5.0)
        self.assertAlmostEqual(summary["speedups"]["common_wall_total"], 2.0)
        self.assertAlmostEqual(summary["speedups"]["common_wall_geometric"], 2.0)
        self.assertAlmostEqual(summary["speedups"]["common_cpu_total"], 2.0)
        self.assertEqual(summary["coverage"]["candidate_only"], 1)
        self.assertEqual(summary["coverage"]["mcnemar"]["p_value"], 1.0)

        campaign["pairs"][0]["candidate"]["cpu_time_s"] = 0.0
        rounded_cpu = ANALYZER.summarize_pairs(campaign["pairs"])
        self.assertIsNone(rounded_cpu["speedups"]["common_cpu_total"])
        self.assertIsNone(rounded_cpu["speedups"]["common_cpu_geometric"])
        self.assertAlmostEqual(rounded_cpu["speedups"]["common_wall_total"], 2.0)


class StrictIngestionTests(unittest.TestCase):
    def _assert_invalid(
        self,
        mutation,
        expected_fragment: str,
        *,
        case_count: int = 2,
    ) -> None:
        cases = [case("family", "sat", 2.0, 1.0) for _ in range(case_count)]
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path, manifest_path, rows = write_fixture(Path(temp_dir), cases)
            mutation(rows)
            write_csv(csv_path, rows)
            with self.assertRaises(ANALYZER.CampaignInputError) as caught:
                ANALYZER.load_campaign(csv_path, manifest_path)
        self.assertTrue(
            any(expected_fragment in error for error in caught.exception.errors),
            caught.exception.errors,
        )

    def test_rejects_duplicate_and_missing_keys(self) -> None:
        self._assert_invalid(
            lambda rows: rows.append(dict(rows[0])), "duplicate observation key"
        )
        self._assert_invalid(lambda rows: rows.pop(), "incomplete paired campaign")

    def test_rejects_hash_mismatches(self) -> None:
        self._assert_invalid(
            lambda rows: rows[1].update({"instance_sha256": "f" * 64}),
            "instance SHA-256 mismatch",
        )
        self._assert_invalid(
            lambda rows: rows[-1].update({"binary_sha256": "c" * 64}),
            "must declare exactly one binary SHA-256",
        )

    def test_rejects_wrong_answers_and_invalid_statuses(self) -> None:
        self._assert_invalid(
            lambda rows: rows[1].update({"result": "unsat"}), "wrong answer"
        )
        self._assert_invalid(
            lambda rows: rows[1].update({"result": "crashed"}),
            "invalid result status",
        )

    def test_rejects_incomparable_budgets(self) -> None:
        self._assert_invalid(
            lambda rows: rows[1].update({"budget_s": 20.0}),
            "incomparable budgets",
        )

    def test_manifest_enforces_whole_campaign_coverage(self) -> None:
        cases = [
            case("alpha", "sat", 2.0, 1.0),
            case("beta", "unsat", 2.0, 1.0),
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path, manifest_path, rows = write_fixture(Path(temp_dir), cases)
            rows[:] = [row for row in rows if "case-001" not in row["relative_path"]]
            write_csv(csv_path, rows)
            with self.assertRaises(ANALYZER.CampaignInputError) as caught:
                ANALYZER.load_campaign(csv_path, manifest_path)
        self.assertTrue(
            any("missing manifest instances" in error for error in caught.exception.errors)
        )


class LockedArtifactTests(unittest.TestCase):
    def test_native_locked_jsonl_is_verified_and_analyzed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_path, raw_path, _ = write_locked_fixture(Path(temp_dir))
            expected_raw_sha256 = ANALYZER.sha256_file(raw_path)
            report = ANALYZER.analyze_locked_campaign(
                lock_path,
                raw_path,
                candidate_id="euf-viper",
                baseline_ids=["z3"],
                seed=31,
                bootstrap_replicates=64,
                confidence_level=0.9,
            )

        self.assertTrue(report["promoted"])
        self.assertEqual(report["inputs"]["raw_records"], 8)
        self.assertEqual(report["input_hashes"]["raw_sha256"], expected_raw_sha256)
        comparison = report["comparisons"]["z3"]
        aggregate = comparison["budgets"]["10"]["aggregate"]
        self.assertAlmostEqual(
            aggregate["speedups"]["common_wall_geometric"], 2.0
        )
        self.assertAlmostEqual(
            aggregate["speedups"]["common_cpu_geometric"], 2.0
        )
        self.assertEqual(
            report["assumptions"]["repetition_aggregation"],
            "per_instance_median_after_status_consistency_check",
        )

    def test_locked_jsonl_rejects_digest_drift_and_missing_schedule_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_path, raw_path, records = write_locked_fixture(Path(temp_dir))
            records[0]["wall_time_s"] = 1.25
            raw_path.write_bytes(
                b"".join(
                    ANALYZER._canonical_json_bytes(record) for record in records
                )
            )
            with self.assertRaises(ANALYZER.CampaignInputError) as digest_error:
                ANALYZER.load_locked_campaign(lock_path, raw_path)
            self.assertTrue(
                any(
                    "record SHA-256 mismatch" in error
                    for error in digest_error.exception.errors
                )
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            lock_path, raw_path, records = write_locked_fixture(Path(temp_dir))
            raw_path.write_bytes(
                b"".join(
                    ANALYZER._canonical_json_bytes(record) for record in records[:-1]
                )
            )
            with self.assertRaises(ANALYZER.CampaignInputError) as missing_error:
                ANALYZER.load_locked_campaign(lock_path, raw_path)
            self.assertTrue(
                any(
                    "incomplete locked campaign" in error
                    for error in missing_error.exception.errors
                )
            )

    def test_locked_jsonl_rejects_wrong_answer_after_valid_rehash(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_path, raw_path, records = write_locked_fixture(Path(temp_dir))
            first = records[0]
            first["result_token"] = (
                "unsat" if first["expected_status"] == "sat" else "sat"
            )
            first["record_sha256"] = ANALYZER._record_digest(first)
            raw_path.write_bytes(
                b"".join(
                    ANALYZER._canonical_json_bytes(record) for record in records
                )
            )
            with self.assertRaises(ANALYZER.CampaignInputError) as caught:
                ANALYZER.load_locked_campaign(lock_path, raw_path)
        self.assertTrue(
            any("wrong answer" in error for error in caught.exception.errors),
            caught.exception.errors,
        )

    def test_sharded_campaign_is_globally_verified_and_analyzed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            parent_path, pairs = write_sharded_fixture(root)
            discovered = ANALYZER.discover_shard_pairs(
                root / "locks", root / "results"
            )
            self.assertEqual(discovered, pairs)
            report = ANALYZER.analyze_sharded_locked_campaign(
                parent_path,
                pairs,
                candidate_id="euf-viper",
                baseline_ids=["z3"],
                seed=31,
                bootstrap_replicates=64,
                confidence_level=0.9,
            )

        self.assertTrue(report["promoted"])
        self.assertEqual(report["inputs"]["instances"], 2)
        self.assertEqual(report["inputs"]["raw_records"], 8)
        self.assertEqual(len(report["inputs"]["shards"]), 2)
        self.assertEqual(
            sorted(report["input_hashes"]["shard_raw_sha256"]), ["0", "1"]
        )

    def test_sharded_campaign_rejects_missing_or_parent_drifted_shards(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            parent_path, pairs = write_sharded_fixture(Path(temp_dir))
            with self.assertRaisesRegex(
                ANALYZER.CampaignInputError, "partition is incomplete"
            ):
                ANALYZER.load_sharded_locked_campaign(parent_path, pairs[:1])

        with tempfile.TemporaryDirectory() as temp_dir:
            parent_path, pairs = write_sharded_fixture(Path(temp_dir))
            lock_path, raw_path = pairs[0]
            bound = json.loads(lock_path.read_text(encoding="utf-8"))
            bound["promotion_eligible"] = False
            prepared = dict(bound)
            prepared.pop("runtime_binding")
            prepared["execution"] = {**prepared["execution"], "cpu_ids": [0]}
            prepared["lock_sha256"] = ANALYZER._lock_sha256(prepared)
            bound["runtime_binding"]["parent_lock_sha256"] = prepared[
                "lock_sha256"
            ]
            bound["lock_sha256"] = ANALYZER._lock_sha256(bound)
            lock_path.write_bytes(ANALYZER._canonical_json_bytes(bound))
            write_raw_for_lock(bound, raw_path)
            with self.assertRaises(ANALYZER.CampaignInputError) as caught:
                ANALYZER.load_sharded_locked_campaign(parent_path, pairs)
        self.assertTrue(
            any("exact derivation" in error for error in caught.exception.errors),
            caught.exception.errors,
        )

    def test_sparse_continuation_shards_validate_without_fabricating_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            parent_path, pairs = write_sparse_sharded_fixture(Path(temp_dir))
            campaign = ANALYZER.load_sharded_locked_campaign(parent_path, pairs)

            self.assertEqual(campaign["raw_records"], 2)
            self.assertEqual(len(campaign["observations"]), 2)
            self.assertEqual(
                sorted(
                    (path, solver_id)
                    for path, _, solver_id in campaign["observations"]
                ),
                [
                    ("QF_UF/alpha/case-0.smt2", "euf-viper"),
                    ("QF_UF/beta/case-1.smt2", "z3"),
                ],
            )
            with self.assertRaisesRegex(
                ANALYZER.CampaignInputError, "must be assembled with its parent"
            ):
                ANALYZER.analyze_sharded_locked_campaign(
                    parent_path,
                    pairs,
                    bootstrap_replicates=8,
                )

    def test_sparse_continuation_rejects_budget_dependent_argv(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            parent_path, _ = write_sparse_sharded_fixture(Path(temp_dir))
            parent = json.loads(parent_path.read_text(encoding="utf-8"))
            parent["solvers"][0]["argv_template"].append("{budget_s}")
            parent["lock_sha256"] = ANALYZER._lock_sha256(parent)
            parent_path.write_bytes(ANALYZER._canonical_json_bytes(parent))

            with self.assertRaisesRegex(
                ANALYZER.CampaignInputError, "budget-dependent"
            ):
                ANALYZER._load_lock(parent_path)


class ProductionRecordContractTests(unittest.TestCase):
    def production_record(
        self, directory: Path
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object], str]:
        lock_path, _, _ = write_locked_fixture(directory)
        lock = json.loads(lock_path.read_text(encoding="ascii"))
        receipt_sha256 = "c" * 64
        lock["repository"] = {"commit": "d" * 40}
        candidate = next(
            solver for solver in lock["solvers"] if solver["id"] == "euf-viper"
        )
        candidate["evidence"] = {
            "schema": "euf-viper.production-evidence.v4",
            "argv_flag": "--evidence-out",
            "accepted_decisive_statuses": ["sat"],
        }
        candidate["environment"] = {
            "EUF_VIPER_SEALED_BUILD_RECEIPT_SHA256": receipt_sha256
        }
        lock["lock_sha256"] = ANALYZER._lock_sha256(lock)
        item = next(
            scheduled
            for scheduled in ANALYZER._locked_schedule(lock)
            if scheduled["solver"]["id"] == "euf-viper"
            and scheduled["instance"]["status"] == "sat"
        )
        runtime_config_sha256 = "e" * 64
        evidence_sha256 = "f" * 64
        evidence = {
            "path": item["evidence_path"].relative_to(directory).as_posix(),
            "sha256": evidence_sha256,
            "bytes": 4096,
            "schema": "euf-viper.production-evidence.v4",
            "source_sha256": item["instance"]["sha256"],
            "solver_revision": lock["repository"]["commit"],
            "solver_executable_sha256": candidate["sha256"],
            "solver_configuration": candidate["configuration"],
            "solver_config_sha256": hashlib.sha256(
                ANALYZER._canonical_json_bytes(candidate)
            ).hexdigest(),
            "solver_runtime_config_sha256": runtime_config_sha256,
            "solver_build_sha256": "1" * 64,
            "sealed_build_receipt_sha256": receipt_sha256,
            "run_nonce": "2" * 64,
            "status": "sat",
            "backend_status": "sat",
        }
        record: dict[str, object] = {
            "record_type": "run",
            "schema_version": 1,
            "lock_sha256": lock["lock_sha256"],
            "invocation": 0,
            "sequence": item["sequence"],
            "key": item["key"],
            "instance_id": item["instance"]["id"],
            "relative_path": item["instance"]["relative_path"],
            "instance_sha256": item["instance"]["sha256"],
            "expected_status": "sat",
            "family": item["instance"]["family"],
            "solver_id": "euf-viper",
            "solver_sha256": candidate["sha256"],
            "solver_version": candidate["version"],
            "budget_s": item["budget_s"],
            "repetition": item["repetition"],
            "cpu_id": item["cpu_id"],
            "argv": item["argv"],
            "descriptor_binding": {
                "mechanism": "linux_procfd",
                "solver_sha256": candidate["sha256"],
                "source_sha256": item["instance"]["sha256"],
                "sealed_build_receipt_sha256": receipt_sha256,
            },
            "environment_sha256": item["environment_sha256"],
            "pid": 1234,
            "started_at": "2026-07-15T00:00:00+00:00",
            "finished_at": "2026-07-15T00:00:01+00:00",
            "wall_time_s": 0.5,
            "child_user_time_s": 0.3,
            "child_system_time_s": 0.1,
            "child_cpu_time_s": 0.4,
            "max_rss_bytes": 4096,
            "exit_code": 0,
            "termination_cause": "exit",
            "termination_signal": None,
            "timed_out": False,
            "spawn_error": None,
            "stdout_sha256": digest("sat\n"),
            "stdout_bytes": 4,
            "stderr_sha256": digest(""),
            "stderr_bytes": 0,
            "result_token": "sat",
            "result_token_status": "valid",
            "production_evidence": evidence,
            "previous_record_sha256": "3" * 64,
            "record_sha256": "",
        }
        record["record_sha256"] = ANALYZER._record_digest(record)
        checked = {
            "schema": evidence["schema"],
            "status": evidence["status"],
            "backend_status": evidence["backend_status"],
            "run_nonce": evidence["run_nonce"],
            "evidence_sha256": evidence_sha256,
            "evidence_bytes": evidence["bytes"],
            "source_sha256": evidence["source_sha256"],
            "solver_revision": evidence["solver_revision"],
            "solver_executable_sha256": evidence["solver_executable_sha256"],
            "solver_config_sha256": runtime_config_sha256,
            "solver_build_sha256": evidence["solver_build_sha256"],
            "sealed_build_receipt_sha256": receipt_sha256,
        }
        return record, item, checked, receipt_sha256

    def test_real_evidence_row_receipt_binding_is_accepted_and_cross_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, expected, checked, receipt_sha256 = self.production_record(
                Path(temporary)
            )
            with mock.patch.object(
                ANALYZER, "validate_production_evidence", return_value=checked
            ) as checker:
                result = ANALYZER._validate_locked_record(
                    record,
                    expected,
                    record["lock_sha256"],
                    "fixture row",
                )
        self.assertEqual(result, "sat")
        self.assertEqual(
            checker.call_args.kwargs["expected_sealed_build_receipt_sha256"],
            receipt_sha256,
        )

    def test_descriptor_receipt_drift_is_rejected_before_checker_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, expected, checked, _ = self.production_record(Path(temporary))
            record["descriptor_binding"]["sealed_build_receipt_sha256"] = "9" * 64
            record["record_sha256"] = ANALYZER._record_digest(record)
            with mock.patch.object(
                ANALYZER, "validate_production_evidence", return_value=checked
            ) as checker, self.assertRaisesRegex(
                ANALYZER.CampaignInputError, "sealed build receipt hash mismatch"
            ):
                ANALYZER._validate_locked_record(
                    record,
                    expected,
                    record["lock_sha256"],
                    "fixture row",
                )
        checker.assert_not_called()


class AnalyzerExitContractTests(unittest.TestCase):
    def run_analyzer(
        self, csv_path: Path, manifest_path: Path, output: Path
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-B",
                str(SCRIPT),
                str(csv_path),
                "--manifest",
                str(manifest_path),
                "--bootstrap-replicates",
                "16",
                "--out",
                str(output),
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_rejection_input_failure_and_publication_failure_have_distinct_exits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            csv_path, manifest_path, rows = write_fixture(
                root,
                [case("alpha", "sat", 1.0, 2.0)],
            )
            rejected_output = root / "rejected.json"
            rejected = self.run_analyzer(csv_path, manifest_path, rejected_output)
            self.assertEqual(rejected.returncode, ANALYZER.EXIT_STATISTICALLY_REJECTED)
            self.assertEqual(
                json.loads(rejected_output.read_text(encoding="ascii"))["status"],
                "rejected",
            )

            rows[1]["result"] = "unsat"
            write_csv(csv_path, rows)
            invalid_output = root / "invalid.json"
            invalid = self.run_analyzer(csv_path, manifest_path, invalid_output)
            self.assertEqual(invalid.returncode, ANALYZER.EXIT_INVALID_INPUT)
            self.assertEqual(
                json.loads(invalid_output.read_text(encoding="ascii"))["status"],
                "invalid_input",
            )

            publication_output = root / "existing.json"
            publication_output.write_text("do not replace\n", encoding="ascii")
            publication_output.chmod(0o400)
            publication = self.run_analyzer(
                csv_path, manifest_path, publication_output
            )
            self.assertEqual(
                publication.returncode, ANALYZER.EXIT_PUBLICATION_FAILED
            )
            self.assertIn("publication failed", publication.stderr)
            self.assertEqual(
                publication_output.read_text(encoding="ascii"), "do not replace\n"
            )


class ResamplingAndMultiplicityTests(unittest.TestCase):
    def test_bootstrap_resamples_whole_family_clusters(self) -> None:
        cases = [
            case("large", "sat", 1.0, 0.25),
            case("large", "unsat", 1.0, 0.25),
            case("large", "sat", 1.0, 0.25),
            case("small", "unsat", 1.0, 4.0),
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path, manifest_path, _ = write_fixture(Path(temp_dir), cases)
            report = analyze(
                csv_path,
                manifest_path,
                seed=7,
                bootstrap_replicates=512,
                confidence_level=0.9,
            )
        bootstrap = report["budgets"]["10"]["bootstrap"]
        self.assertEqual(bootstrap["resampling_unit"], "declared_family")
        self.assertEqual(bootstrap["cluster_count"], 2)
        self.assertEqual(bootstrap["cluster_sizes"], {"large": 3, "small": 1})
        interval = bootstrap["metrics"]["common_wall_geometric"]
        self.assertAlmostEqual(interval["ci_lower"], 0.25)
        self.assertAlmostEqual(interval["ci_upper"], 4.0)

    def test_holm_correction_is_named_and_step_down(self) -> None:
        corrected = ANALYZER.holm_correction(
            {"third": 0.04, "first": 0.01, "second": 0.03}, alpha=0.05
        )
        self.assertEqual(corrected["order"], ["first", "second", "third"])
        self.assertAlmostEqual(
            corrected["results"]["first"]["adjusted_p_value"], 0.03
        )
        self.assertAlmostEqual(
            corrected["results"]["second"]["adjusted_p_value"], 0.06
        )
        self.assertAlmostEqual(
            corrected["results"]["third"]["adjusted_p_value"], 0.06
        )
        self.assertTrue(corrected["results"]["first"]["rejected"])
        self.assertFalse(corrected["results"]["second"]["rejected"])
        self.assertFalse(corrected["results"]["third"]["rejected"])

    def test_cli_json_is_deterministic_and_records_hashes_and_assumptions(self) -> None:
        cases = [
            case(f"family-{index % 2}", "sat" if index % 2 else "unsat", 2.0, 1.0)
            for index in range(8)
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path, manifest_path, _ = write_fixture(Path(temp_dir), cases)
            expected_csv_sha256 = ANALYZER.sha256_file(csv_path)
            command = [
                sys.executable,
                "-B",
                str(SCRIPT),
                str(csv_path),
                "--manifest",
                str(manifest_path),
                "--seed",
                "23",
                "--bootstrap-replicates",
                "64",
                "--confidence-level",
                "0.9",
            ]
            first = subprocess.run(command, text=True, capture_output=True, check=False)
            second = subprocess.run(command, text=True, capture_output=True, check=False)

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.stdout, second.stdout)
        payload = json.loads(first.stdout)
        self.assertEqual(payload["configuration"]["seed"], 23)
        self.assertEqual(
            payload["input_hashes"]["campaign_csv_sha256"],
            expected_csv_sha256,
        )
        self.assertEqual(payload["assumptions"]["par2_penalty"], 2.0)
        self.assertEqual(
            payload["assumptions"]["ratio_direction"], "baseline_over_candidate"
        )


class PromotionTests(unittest.TestCase):
    def test_clear_win_promotes_with_status_and_family_breakdowns(self) -> None:
        cases = [
            case(
                f"family-{index % 4}",
                "sat" if index % 2 else "unsat",
                2.0,
                1.0,
            )
            for index in range(12)
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path, manifest_path, _ = write_fixture(Path(temp_dir), cases)
            report = analyze(csv_path, manifest_path)

        self.assertTrue(report["promoted"])
        budget = report["budgets"]["10"]
        self.assertEqual(set(budget["statuses"]), {"sat", "unsat"})
        self.assertEqual(len(budget["families"]), 4)
        self.assertAlmostEqual(
            budget["family_macro"]["speedups"]["par2_wall"], 2.0
        )
        self.assertTrue(
            all(check["passed"] for check in budget["promotion"]["checks"].values())
        )

    def test_invalid_error_and_coverage_loss_block_promotion(self) -> None:
        scenarios = (
            ("error", "zero_execution_errors"),
            ("invalid", "zero_invalid_results"),
            ("timeout", "zero_coverage_loss"),
        )
        for result, failed_check in scenarios:
            with self.subTest(result=result), tempfile.TemporaryDirectory() as temp_dir:
                cases = [
                    case("alpha", "sat", 2.0, 1.0, candidate_result=result),
                    case("beta", "unsat", 2.0, 1.0),
                ]
                csv_path, manifest_path, _ = write_fixture(Path(temp_dir), cases)
                report = analyze(csv_path, manifest_path)
                checks = report["budgets"]["10"]["promotion"]["checks"]
                self.assertFalse(report["promoted"])
                self.assertFalse(checks[failed_check]["passed"])

    def test_aggregate_win_cannot_hide_one_family_regression(self) -> None:
        cases = [
            case(
                f"family-{index:02d}",
                "sat" if index % 2 else "unsat",
                1.0,
                1.05 if index == 0 else 0.5,
            )
            for index in range(30)
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path, manifest_path, _ = write_fixture(Path(temp_dir), cases)
            report = analyze(
                csv_path,
                manifest_path,
                bootstrap_replicates=512,
            )

        budget = report["budgets"]["10"]
        self.assertGreater(
            budget["bootstrap"]["metrics"]["common_wall_geometric"]["ci_lower"],
            1.0,
        )
        family_check = budget["promotion"]["checks"]["family_non_regression"]
        self.assertFalse(report["promoted"])
        self.assertFalse(family_check["passed"])
        self.assertTrue(
            any(
                failure["group"] == "family-00"
                and failure["metric"] == "common_wall_total"
                for failure in family_check["details"]
            )
        )

    def test_aggregate_and_families_cannot_hide_status_regression(self) -> None:
        cases = []
        for index in range(10):
            family = f"family-{index:02d}"
            cases.append(case(family, "sat", 1.0, 0.5))
            cases.append(case(family, "unsat", 1.0, 1.05))
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path, manifest_path, _ = write_fixture(Path(temp_dir), cases)
            report = analyze(csv_path, manifest_path)

        checks = report["budgets"]["10"]["promotion"]["checks"]
        self.assertTrue(checks["family_non_regression"]["passed"])
        self.assertFalse(checks["status_non_regression"]["passed"])
        self.assertTrue(
            any(
                failure["group"] == "unsat"
                and failure["metric"] == "common_wall_geometric"
                for failure in checks["status_non_regression"]["details"]
            )
        )
        self.assertFalse(report["promoted"])

    def test_configured_lower_confidence_threshold_is_enforced(self) -> None:
        cases = [
            case(f"family-{index}", "sat", 1.5, 1.0) for index in range(6)
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path, manifest_path, _ = write_fixture(Path(temp_dir), cases)
            report = analyze(csv_path, manifest_path, minimum_speedup=1.6)

        checks = report["budgets"]["10"]["promotion"]["checks"]
        self.assertFalse(report["promoted"])
        self.assertFalse(
            checks["common_wall_geometric_bootstrap_lower_bound"]["passed"]
        )
        self.assertEqual(
            checks["common_wall_geometric_bootstrap_lower_bound"]["threshold"],
            1.6,
        )


if __name__ == "__main__":
    unittest.main()
