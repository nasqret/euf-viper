from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    path = ROOT / "scripts" / "bench" / f"{name}.py"
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


IMPORTER = load_script("import_sharded_dashboard")
GAPS = load_script("analyze_solver_gap_cohorts")


def observation(result: str, wall_time_s: float) -> dict[str, object]:
    return {"result": result, "wall_time_s": wall_time_s}


def fixture() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    instances = [
        {
            "id": "0",
            "relative_path": "QF_UF/QG/qg7/iso_icl007.smt2",
            "family": "QF_UF/QG",
            "status": "unsat",
            "bytes": 8192,
            "split": "dev",
            "lineage": "QF_UF/QG/iso_icl007",
            "sha256": "1" * 64,
        },
        {
            "id": "1",
            "relative_path": "QF_UF/NEQ/NEQ003_size5.smt2",
            "family": "QF_UF/NEQ",
            "status": "sat",
            "bytes": 65536,
            "split": "holdout",
            "lineage": "QF_UF/NEQ/NEQ003_size5",
            "sha256": "2" * 64,
        },
    ]
    campaign = {
        "lock": {
            "lock_sha256": "3" * 64,
            "budgets_s": [2.0],
            "solvers": [{"id": "euf-viper"}, {"id": "yices2"}],
            "corpus": {"id": "test-corpus", "instances": instances},
        },
        "observations": {
            (instances[0]["relative_path"], 2.0, "euf-viper"): observation(
                "timeout", 2.01
            ),
            (instances[0]["relative_path"], 2.0, "yices2"): observation(
                "unsat", 0.2
            ),
            (instances[1]["relative_path"], 2.0, "euf-viper"): observation(
                "sat", 0.1
            ),
            (instances[1]["relative_path"], 2.0, "yices2"): observation(
                "timeout", 2.01
            ),
        },
    }
    audit = {"solver_revision": "4" * 40}
    analysis = {
        "status": "rejected",
        "inputs": {"candidate_id": "euf-viper", "baseline_ids": ["yices2"]},
    }
    return campaign, audit, analysis


class ShardedDashboardAndGapTests(unittest.TestCase):
    def test_dashboard_registry_preserves_solver_revision_and_gaps(self) -> None:
        campaign, audit, analysis = fixture()
        registry = IMPORTER.build_registry(
            campaign,
            audit,
            analysis,
            registry_id="test-registry",
            title="Test registry",
            updated_at="2026-07-26T00:00:00Z",
            evidence_prefix="test",
            corpus_id_override=None,
            corpus_label="Test corpus",
            host_id="test-host",
            host_label="Test host",
            evidence_class="test-audited",
            evidence_status="verified",
            source_path="audit-index.json",
            source_sha256="5" * 64,
        )
        self.assertEqual(registry["viper_solver_id"], "euf-viper")
        self.assertTrue(registry["evidence"])
        self.assertTrue(
            all(item["revision"] == "4" * 40 for item in registry["evidence"])
        )
        whole = next(
            item
            for item in registry["evidence"]
            if item["family"]["id"] == "all" and item["expected_status"] == "all"
        )
        by_path = {item["id"]: item for item in whole["instances"]}
        qg = by_path["QF_UF/QG/qg7/iso_icl007.smt2"]
        statuses = {item["solver_id"]: item["status"] for item in qg["results"]}
        self.assertEqual(statuses, {"euf-viper": "timeout", "yices2": "solved"})

    def test_gap_report_has_exact_direction_and_structural_cohorts(self) -> None:
        campaign, audit, analysis = fixture()
        report = GAPS.build_report(
            campaign,
            audit,
            analysis,
            candidate_id="euf-viper",
            baseline_ids=["yices2"],
            budget_s=2.0,
            audit_path="audit-index.json",
            audit_sha256="5" * 64,
        )
        comparison = report["comparisons"][0]
        self.assertEqual(comparison["overall"]["candidate_only"], 1)
        self.assertEqual(comparison["overall"]["baseline_only"], 1)
        self.assertEqual(
            comparison["gaps"]["baseline_only"][0]["generator_class"],
            "qg7/iso_icl#",
        )
        self.assertEqual(
            comparison["gaps"]["candidate_only"][0]["size_bucket"],
            "64-256-kib",
        )

    def test_gap_report_rejects_candidate_as_baseline(self) -> None:
        campaign, audit, analysis = fixture()
        with self.assertRaisesRegex(GAPS.GapAnalysisError, "candidate"):
            GAPS.build_report(
                campaign,
                audit,
                analysis,
                candidate_id="euf-viper",
                baseline_ids=["euf-viper"],
                budget_s=2.0,
                audit_path="audit-index.json",
                audit_sha256="5" * 64,
            )


if __name__ == "__main__":
    unittest.main()
