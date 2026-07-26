from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "import_staged_dashboard.py"
SPEC = importlib.util.spec_from_file_location("import_staged_dashboard", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
IMPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMPORTER)


LOCK_HASH = "a" * 64
REVISION = "1" * 40


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )


def make_record(
    path: str,
    solver_id: str,
    budget: float,
    expected: str,
    result: str,
    wall: float,
) -> dict:
    timed_out = result == "timeout"
    record = {
        "budget_s": budget,
        "child_cpu_time_s": None if timed_out else wall * 0.9,
        "exit_code": None if timed_out else 0,
        "expected_status": expected,
        "lock_sha256": LOCK_HASH,
        "relative_path": path,
        "result_token": None if timed_out else result,
        "result_token_status": "missing" if timed_out else "valid",
        "solver_id": solver_id,
        "spawn_error": None,
        "termination_cause": "timeout" if timed_out else "exit",
        "timed_out": timed_out,
        "wall_time_s": wall,
    }
    record["record_sha256"] = IMPORTER._record_digest(record)
    return record


def make_fixture(root: Path) -> tuple[Path, Path, dict]:
    parent_path = root / "parent.json"
    parent = {
        "repository": {"commit": REVISION},
        "corpus": {
            "id": "fixture-qf-uf",
            "instances": [
                {
                    "relative_path": "QF_UF/alpha/a.smt2",
                    "family": "QF_UF/alpha",
                    "status": "sat",
                },
                {
                    "relative_path": "QF_UF/beta/b.smt2",
                    "family": "QF_UF/beta",
                    "status": "unsat",
                },
            ],
        },
    }
    write_json(parent_path, parent)
    parent_hash = IMPORTER.sha256_file(parent_path)

    records = [
        make_record("QF_UF/alpha/a.smt2", "euf-viper", 1, "sat", "sat", 0.1),
        make_record("QF_UF/alpha/a.smt2", "yices2", 1, "sat", "sat", 0.2),
        make_record(
            "QF_UF/beta/b.smt2", "euf-viper", 1, "unsat", "timeout", 1.0
        ),
        make_record("QF_UF/beta/b.smt2", "yices2", 1, "unsat", "unsat", 0.3),
        make_record("QF_UF/beta/b.smt2", "euf-viper", 5, "unsat", "unsat", 2.0),
    ]
    raw_path = root / "raw.jsonl"
    raw_path.write_text(
        "".join(
            json.dumps(record, allow_nan=False, separators=(",", ":"), sort_keys=True)
            + "\n"
            for record in records
        ),
        encoding="ascii",
    )
    raw_hash = IMPORTER.sha256_file(raw_path)
    by_key = {
        (record["relative_path"], record["solver_id"], float(record["budget_s"])): record
        for record in records
    }

    provenance = []
    source_budget = {
        ("QF_UF/alpha/a.smt2", "euf-viper", 1.0): 1.0,
        ("QF_UF/alpha/a.smt2", "yices2", 1.0): 1.0,
        ("QF_UF/beta/b.smt2", "euf-viper", 1.0): 1.0,
        ("QF_UF/beta/b.smt2", "yices2", 1.0): 1.0,
        ("QF_UF/alpha/a.smt2", "euf-viper", 5.0): 1.0,
        ("QF_UF/alpha/a.smt2", "yices2", 5.0): 1.0,
        ("QF_UF/beta/b.smt2", "euf-viper", 5.0): 5.0,
        ("QF_UF/beta/b.smt2", "yices2", 5.0): 1.0,
    }
    for (relative_path, solver_id, budget), origin_budget in sorted(source_budget.items()):
        record = by_key[(relative_path, solver_id, origin_budget)]
        if record["timed_out"]:
            result = "timeout"
        else:
            result = record["result_token"]
        provenance.append(
            {
                "budget_s": budget,
                "carried_forward": budget != origin_budget,
                "origin_budget_s": origin_budget,
                "relative_path": relative_path,
                "result": result,
                "solver_id": solver_id,
                "source_lock_sha256": LOCK_HASH,
                "source_raw_sha256": raw_hash,
                "source_record_sha256s": [record["record_sha256"]],
            }
        )
    analysis = {
        "status": "rejected",
        "promoted": False,
        "input_hashes": {"base_lock_file_sha256": parent_hash},
        "inputs": {
            "base": {"parent_lock": str(parent_path)},
            "base_shards": [{"raw": str(raw_path), "raw_sha256": raw_hash}],
            "stages": [],
            "candidate_id": "euf-viper",
            "baseline_ids": ["yices2"],
            "budgets_s": [1, 5],
            "instances": 2,
            "observation_provenance": provenance,
        },
    }
    analysis_path = root / "analysis.json"
    write_json(analysis_path, analysis)
    return analysis_path, raw_path, analysis


def import_fixture(analysis_path: Path) -> dict:
    return IMPORTER.import_staged_campaign(
        analysis_path,
        registry_id="fixture-registry",
        title="Fixture staged evidence",
        updated_at="2026-07-26T00:00:00Z",
        evidence_prefix="fixture",
        corpus_id_override="fixture-qf-uf-subset",
        corpus_label="Fixture QF_UF",
        host_id="fixture-host",
        host_label="Fixture host",
    )


class ImportTests(unittest.TestCase):
    def test_reconstructs_whole_corpus_and_family_panels(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            analysis_path, _, _ = make_fixture(Path(temporary))
            registry = import_fixture(analysis_path)
            self.assertEqual(registry["viper_solver_id"], "euf-viper")
            self.assertTrue(
                all(
                    item["corpus"]["id"] == "fixture-qf-uf-subset"
                    for item in registry["evidence"]
                )
            )
            self.assertEqual(len(registry["evidence"]), 14)
            self.assertTrue(
                all(
                    item["solver_ids"] == ["euf-viper", "yices2"]
                    for item in registry["evidence"]
                )
            )
            self.assertEqual(
                {item["expected_status"] for item in registry["evidence"]},
                {"all", "sat", "unsat"},
            )
            model = IMPORTER.dashboard.build_dashboard(registry)
            all_panels = [
                panel
                for panel in model["panels"]
                if panel["claim_boundary"]["family"]["id"] == "all"
                and panel["claim_boundary"]["expected_status"] == "all"
            ]
            self.assertEqual(len(all_panels), 2)
            at_one = next(
                panel
                for panel in all_panels
                if panel["claim_boundary"]["timeout_s"] == 1.0
            )
            summaries = {item["solver_id"]: item for item in at_one["solvers"]}
            self.assertEqual(summaries["euf-viper"]["solved"], 1)
            self.assertEqual(summaries["yices2"]["solved"], 2)

    def test_tampered_raw_shard_fails_hash_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            analysis_path, raw_path, _ = make_fixture(Path(temporary))
            raw_path.write_text(raw_path.read_text() + "\n", encoding="ascii")
            with self.assertRaisesRegex(
                IMPORTER.StagedDashboardImportError, "raw shard SHA-256 mismatch"
            ):
                import_fixture(analysis_path)

    def test_provenance_result_disagreement_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analysis_path, _, analysis = make_fixture(root)
            changed = copy.deepcopy(analysis)
            changed["inputs"]["observation_provenance"][0]["result"] = "unknown"
            write_json(analysis_path, changed)
            with self.assertRaisesRegex(
                IMPORTER.StagedDashboardImportError, "disagrees with reconstructed"
            ):
                import_fixture(analysis_path)

    def test_cli_failure_preserves_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analysis_path, raw_path, _ = make_fixture(root)
            output = root / "registry.json"
            output.write_text("old output", encoding="ascii")
            raw_path.write_text("tampered\n", encoding="ascii")
            stderr = StringIO()
            with redirect_stderr(stderr), redirect_stdout(StringIO()):
                exit_code = IMPORTER.main(
                    [
                        str(analysis_path),
                        "--output",
                        str(output),
                        "--registry-id",
                        "fixture-registry",
                        "--title",
                        "Fixture",
                        "--updated-at",
                        "2026-07-26T00:00:00Z",
                        "--evidence-prefix",
                        "fixture",
                        "--corpus-id",
                        "fixture-qf-uf-subset",
                        "--corpus-label",
                        "Fixture corpus",
                        "--host-id",
                        "fixture-host",
                        "--host-label",
                        "Fixture host",
                    ]
                )
            self.assertEqual(exit_code, 2)
            self.assertIn("SHA-256 mismatch", stderr.getvalue())
            self.assertEqual(output.read_text(encoding="ascii"), "old output")


if __name__ == "__main__":
    unittest.main()
