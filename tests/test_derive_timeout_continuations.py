from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "derive_timeout_continuations.py"
MODULE_SPEC = importlib.util.spec_from_file_location(
    "derive_timeout_continuations", SCRIPT
)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
DERIVER = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(DERIVER)
ANALYZER = DERIVER.campaign_analyzer


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _instance(directory: Path, index: int) -> dict[str, Any]:
    family = ("alpha", "beta", "gamma")[index]
    status = "sat" if index != 1 else "unsat"
    return {
        "id": f"instance-{index}",
        "relative_path": f"QF_UF/{family}/case-{index}.smt2",
        "path": str(directory / f"case-{index}.smt2"),
        "sha256": digest(f"instance-{index}"),
        "bytes": 100 + index,
        "status": status,
        "family": family,
        "lineage": f"{family}/generator",
        "normalized_sha256": digest(f"normalized-{index}"),
        "split": "development",
    }


def _solver(directory: Path, solver_id: str) -> dict[str, Any]:
    return {
        "id": solver_id,
        "comparator_id": solver_id,
        "configuration": "default",
        "version": "test-1",
        "binary": str(directory / solver_id),
        "sha256": digest(f"binary-{solver_id}"),
        "argv_template": ["{binary}", "{instance}"],
        "version_output": None,
        "version_output_sha256": None,
        "environment": {},
    }


def _parent_lock(directory: Path, budgets: list[int] | None = None) -> dict[str, Any]:
    spec_path = directory / "spec.json"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text('{"budgets_s":[2,60,1200]}\n', encoding="utf-8")
    lock: dict[str, Any] = {
        "schema_version": 1,
        "campaign_id": "continuation-test",
        "lock_sha256": "",
        "created_from_commit_time": "2026-07-12T00:00:00+00:00",
        "promotion_eligible": True,
        "spec": {
            "path": str(spec_path),
            "sha256": ANALYZER.sha256_file(spec_path),
        },
        "repository": {},
        "host": {},
        "corpus": {
            "id": "test-corpus",
            "manifest_path": str(directory / "manifest.jsonl"),
            "manifest_sha256": "2" * 64,
            "taxonomy_path": str(directory / "taxonomy.jsonl"),
            "taxonomy_sha256": "3" * 64,
            "root": str(directory),
            "instances": [_instance(directory, index) for index in range(3)],
        },
        "solver_config": {
            "path": str(directory / "solvers.json"),
            "sha256": "4" * 64,
        },
        "solver_release_lock": {
            "path": str(directory / "solver-releases.json"),
            "sha256": "5" * 64,
        },
        "solvers": [
            _solver(directory, solver_id)
            for solver_id in ("cvc5", "euf-viper", "z3")
        ],
        "budgets_s": budgets or [2],
        "execution": {
            "resource_model": "single_core_cold_process",
            "cpu_ids": [0],
            "memory_bytes": 1024**3,
            "order": "balanced_latin_square",
            "environment": {"PATH": "/usr/bin"},
            "timeout_grace_s": 0.25,
        },
        "output": {
            "directory": str(directory / "source-results"),
            "journal": "journal.jsonl",
            "raw": "raw.jsonl",
            "summary": "summary.json",
        },
    }
    lock["lock_sha256"] = ANALYZER._lock_sha256(lock)
    return lock


def _run_record(
    scheduled: Mapping[str, Any],
    classification: str,
    previous_sha256: str,
) -> dict[str, Any]:
    instance = scheduled["instance"]
    solver = scheduled["solver"]
    expected = instance["status"]
    timed_out = classification == "timeout"
    wrong = classification == "wrong"
    unknown = classification == "unknown"
    invalid = classification == "invalid"
    error = classification == "error"
    if timed_out or invalid or error:
        result_token = None
        result_token_status = "missing"
    elif unknown:
        result_token = "unknown"
        result_token_status = "valid"
    else:
        result_token = (
            "unsat" if expected == "sat" else "sat"
        ) if wrong else expected
        result_token_status = "valid"
    record: dict[str, Any] = {
        "record_type": "run",
        "schema_version": 1,
        "lock_sha256": scheduled["lock_sha256"],
        "invocation": 0,
        "sequence": scheduled["sequence"],
        "key": scheduled["key"],
        "instance_id": instance["id"],
        "relative_path": instance["relative_path"],
        "instance_sha256": instance["sha256"],
        "expected_status": expected,
        "family": instance["family"],
        "solver_id": solver["id"],
        "solver_sha256": solver["sha256"],
        "solver_version": solver["version"],
        "budget_s": scheduled["budget_s"],
        "repetition": scheduled["repetition"],
        "cpu_id": scheduled["cpu_id"],
        "argv": scheduled["argv"],
        "environment_sha256": scheduled["environment_sha256"],
        "pid": 1000 + scheduled["sequence"],
        "started_at": "2026-07-12T00:00:00+00:00",
        "finished_at": "2026-07-12T00:00:02+00:00",
        "wall_time_s": 2.0,
        "child_user_time_s": 1.5,
        "child_system_time_s": 0.2,
        "child_cpu_time_s": 1.7,
        "max_rss_bytes": 4096,
        "exit_code": 1 if error else (-15 if timed_out else 0),
        "termination_cause": "timeout" if timed_out else "exit",
        "termination_signal": 15 if timed_out else None,
        "timed_out": timed_out,
        "spawn_error": None,
        "stdout_sha256": digest(
            "" if result_token is None else str(result_token)
        ),
        "stdout_bytes": 0 if result_token is None else len(str(result_token)),
        "stderr_sha256": digest(""),
        "stderr_bytes": 0,
        "result_token": result_token,
        "result_token_status": result_token_status,
        "previous_record_sha256": previous_sha256,
        "record_sha256": "",
    }
    record["record_sha256"] = ANALYZER._record_digest(record)
    return record


def _write_raw(
    lock: dict[str, Any],
    raw_path: Path,
    classifications: Mapping[tuple[str, str], str],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    previous_sha256 = digest("invocation")
    for scheduled_value in ANALYZER._locked_schedule(lock):
        scheduled = dict(scheduled_value)
        scheduled["lock_sha256"] = lock["lock_sha256"]
        key = (scheduled["instance"]["id"], scheduled["solver"]["id"])
        record = _run_record(
            scheduled, classifications.get(key, "success"), previous_sha256
        )
        records.append(record)
        previous_sha256 = record["record_sha256"]
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_bytes(
        b"".join(ANALYZER._canonical_json_bytes(record) for record in records)
    )
    return records


def write_sharded_campaign(
    directory: Path,
    classifications: Mapping[tuple[str, str], str] | None = None,
    *,
    budgets: list[int] | None = None,
) -> tuple[Path, Path, Path]:
    classifications = classifications or {}
    parent = _parent_lock(directory, budgets)
    parent_path = directory / "parent.json"
    parent_path.write_bytes(ANALYZER._canonical_json_bytes(parent))
    lock_directory = directory / "bound-locks"
    results_root = directory / "shard-results"
    for index in range(2):
        prepared = ANALYZER._expected_prepared_shard(parent, index, 2)
        cpu_id = 8 + index
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
        bound_path = lock_directory / f"bound-{index:04d}.json"
        bound_path.parent.mkdir(parents=True, exist_ok=True)
        bound_path.write_bytes(ANALYZER._canonical_json_bytes(bound))
        _write_raw(
            bound,
            results_root / f"shard-{index:04d}" / "raw.jsonl",
            classifications,
        )
    return parent_path, lock_directory, results_root


def derive(
    directory: Path,
    classifications: Mapping[tuple[str, str], str] | None = None,
    *,
    budgets: list[int] | None = None,
    target_budget: int = 60,
) -> tuple[dict[str, Any], Path, Path, Path, Path]:
    parent, locks, results = write_sharded_campaign(
        directory, classifications, budgets=budgets
    )
    output = directory / "continuation"
    index = DERIVER.derive_continuation(
        parent, locks, results, target_budget, output
    )
    return index, parent, locks, results, output


class TimeoutContinuationTests(unittest.TestCase):
    def test_exact_union_and_run_selection_exclude_successes(self) -> None:
        classifications = {
            ("instance-0", "z3"): "timeout",
            ("instance-0", "cvc5"): "timeout",
            ("instance-2", "euf-viper"): "timeout",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            index, parent_path, locks, results, output = derive(
                root, classifications
            )
            parent = json.loads(parent_path.read_text(encoding="utf-8"))
            lock_path = output / DERIVER.LOCK_FILENAME
            lock = json.loads(lock_path.read_text(encoding="utf-8"))

            expected_selection = [
                {"instance_id": "instance-0", "solver_id": "cvc5"},
                {"instance_id": "instance-0", "solver_id": "z3"},
                {"instance_id": "instance-2", "solver_id": "euf-viper"},
            ]
            self.assertEqual(lock["run_selection"], expected_selection)
            self.assertTrue(
                all(set(item) == DERIVER.RUN_SELECTION_KEYS for item in expected_selection)
            )
            self.assertEqual(
                [item["id"] for item in lock["corpus"]["instances"]],
                ["instance-0", "instance-2"],
            )
            self.assertEqual(lock["solvers"], parent["solvers"])
            self.assertEqual(lock["budgets_s"], [60])
            self.assertEqual(
                lock["execution"]["order"], "balanced_latin_square"
            )
            self.assertEqual(lock["output"]["directory"], str(output.resolve()))
            self.assertEqual(lock["lock_sha256"], DERIVER.lock_hash(lock))
            self.assertEqual(lock["schema_version"], 2)
            self.assertFalse(lock["promotion_eligible"])
            self.assertEqual(ANALYZER._load_lock(lock_path), lock)

            provenance = lock["continuation"]
            self.assertEqual(set(provenance), DERIVER.CONTINUATION_KEYS)
            self.assertEqual(provenance["parent_lock_path"], str(parent_path.resolve()))
            self.assertEqual(
                provenance["parent_lock_file_sha256"],
                ANALYZER.sha256_file(parent_path),
            )
            self.assertEqual(provenance["parent_lock_sha256"], parent["lock_sha256"])
            self.assertEqual(provenance["root_lock_sha256"], parent["lock_sha256"])
            self.assertEqual(provenance["mode"], "timeout_only")
            self.assertEqual(
                provenance["source_evidence_sha256"],
                provenance["shard_bundle_sha256"],
            )
            self.assertEqual(provenance["shard_lock_directory"], str(locks.resolve()))
            self.assertEqual(provenance["shard_results_root"], str(results.resolve()))
            self.assertEqual(provenance["source_budget_s"], 2)
            self.assertEqual(provenance["target_budget_s"], 60)
            self.assertEqual(provenance["selected_instances"], 2)
            self.assertEqual(provenance["selected_runs"], 3)
            self.assertEqual(
                provenance["selection_sha256"],
                DERIVER.selection_hash(expected_selection),
            )

            self.assertEqual(index["status"], "ready")
            self.assertEqual(set(index), DERIVER.INDEX_KEYS)
            self.assertEqual(set(index["source"]), DERIVER.INDEX_SOURCE_KEYS)
            self.assertEqual(index["source"]["parent_lock"], str(parent_path.resolve()))
            self.assertEqual(index["source"]["budget_s"], 2)
            self.assertEqual(index["target_budget_s"], 60)
            self.assertEqual(index["selected_instances"], 2)
            self.assertEqual(index["selected_runs"], 3)
            self.assertEqual(
                index["selection_sha256"], DERIVER.selection_hash(expected_selection)
            )
            self.assertEqual(index["output_directory"], str(output.resolve()))
            self.assertEqual(
                set(index["continuation_lock"]), DERIVER.INDEX_LOCK_KEYS
            )
            self.assertEqual(
                index["continuation_lock"]["file_sha256"],
                hashlib.sha256(lock_path.read_bytes()).hexdigest(),
            )

    def test_zero_timeout_campaign_writes_index_without_runnable_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            index, _, _, _, output = derive(Path(temporary))

            self.assertEqual(index["status"], "no_timeouts")
            self.assertEqual(set(index), DERIVER.INDEX_KEYS)
            self.assertEqual(set(index["source"]), DERIVER.INDEX_SOURCE_KEYS)
            self.assertIsNone(index["continuation_lock"])
            self.assertEqual(index["selected_instances"], 0)
            self.assertEqual(index["selected_runs"], 0)
            self.assertEqual(
                index["selection_sha256"],
                DERIVER.selection_hash([]),
            )
            self.assertTrue((output / DERIVER.INDEX_FILENAME).is_file())
            self.assertFalse((output / DERIVER.LOCK_FILENAME).exists())
            self.assertEqual(
                (output / DERIVER.INDEX_FILENAME).read_bytes(),
                DERIVER.canonical_bytes(index),
            )

    def test_source_tampering_and_wrong_answers_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent, locks, results = write_sharded_campaign(root)
            raw_path = results / "shard-0000" / "raw.jsonl"
            records = [
                json.loads(line)
                for line in raw_path.read_text(encoding="utf-8").splitlines()
            ]
            records[0]["stdout_bytes"] += 1
            raw_path.write_bytes(
                b"".join(
                    ANALYZER._canonical_json_bytes(record) for record in records
                )
            )
            with self.assertRaisesRegex(DERIVER.ContinuationError, "record SHA-256"):
                DERIVER.derive_continuation(
                    parent, locks, results, 60, root / "continuation"
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent, locks, results = write_sharded_campaign(
                root, {("instance-1", "z3"): "wrong"}
            )
            with self.assertRaisesRegex(DERIVER.ContinuationError, "wrong answer"):
                DERIVER.derive_continuation(
                    parent, locks, results, 60, root / "continuation"
                )

    def test_non_timeout_nonsuccess_and_budget_misuse_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent, locks, results = write_sharded_campaign(
                root, {("instance-0", "z3"): "unknown"}
            )
            with self.assertRaisesRegex(
                DERIVER.ContinuationError, "non-runnable classification"
            ):
                DERIVER.derive_continuation(
                    parent, locks, results, 60, root / "continuation"
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent, locks, results = write_sharded_campaign(root, budgets=[2, 10])
            with self.assertRaisesRegex(DERIVER.ContinuationError, "exactly one budget"):
                DERIVER.derive_continuation(
                    parent, locks, results, 60, root / "continuation"
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent, locks, results = write_sharded_campaign(root)
            with self.assertRaisesRegex(
                DERIVER.ContinuationError, "strictly greater"
            ):
                DERIVER.derive_continuation(
                    parent, locks, results, 2, root / "continuation"
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent, locks, results = write_sharded_campaign(root)
            campaign = DERIVER._validated_source_campaign(parent, locks, results)
            campaign["lock"]["solvers"][0]["argv_template"].append("{budget_s}")
            with self.assertRaisesRegex(
                DERIVER.ContinuationError, "budget-dependent argv"
            ):
                DERIVER.make_continuation_lock(
                    campaign,
                    parent_lock_path=parent.resolve(),
                    shard_lock_directory=locks.resolve(),
                    shard_results_root=results.resolve(),
                    target_budget_s=60,
                    output_directory=(root / "continuation").resolve(),
                )

    def test_repeated_derivation_is_byte_deterministic_and_rejects_drift(self) -> None:
        classifications = {("instance-0", "z3"): "timeout"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent, locks, results = write_sharded_campaign(root, classifications)
            output = root / "continuation"
            first = DERIVER.derive_continuation(parent, locks, results, 60, output)
            lock_path = output / DERIVER.LOCK_FILENAME
            index_path = output / DERIVER.INDEX_FILENAME
            first_lock_bytes = lock_path.read_bytes()
            first_index_bytes = index_path.read_bytes()

            second = DERIVER.derive_continuation(parent, locks, results, 60, output)
            self.assertEqual(second, first)
            self.assertEqual(lock_path.read_bytes(), first_lock_bytes)
            self.assertEqual(index_path.read_bytes(), first_index_bytes)

            lock_path.write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(DERIVER.ContinuationError, "output drift"):
                DERIVER.derive_continuation(parent, locks, results, 60, output)

    def test_zero_timeout_derivation_rejects_a_stale_runnable_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent, locks, results = write_sharded_campaign(root)
            output = root / "continuation"
            output.mkdir()
            (output / DERIVER.LOCK_FILENAME).write_text("stale\n", encoding="utf-8")

            with self.assertRaisesRegex(
                DERIVER.ContinuationError, "zero-timeout derivation"
            ):
                DERIVER.derive_continuation(parent, locks, results, 60, output)


if __name__ == "__main__":
    unittest.main()
