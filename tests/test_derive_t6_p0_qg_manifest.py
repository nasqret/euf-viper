from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "derive_t6_p0_qg_manifest.py"
COMMITTED = ROOT / "campaigns" / "t6-theory-dag-p0-qg12-v1.json"
SPEC = importlib.util.spec_from_file_location("derive_t6_p0_qg_manifest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
T6 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(T6)


def source(source_id: int, relative_path: str, status: str = "unsat") -> dict:
    return {
        "bytes": 6_000_000 + source_id,
        "id": source_id,
        "logic": "QF_UF",
        "relative_path": relative_path,
        "sha256": f"{source_id + 1:064x}",
        "status": status,
    }


def observation(budget: float, solver: str, path: str, result: str) -> dict:
    return {
        "budget_s": budget,
        "carried_forward": budget == 60.0 and solver in {"yices2", "z3-default"},
        "origin_budget_s": 2.0 if budget == 60.0 and solver in {"yices2", "z3-default"} else budget,
        "relative_path": path,
        "result": result,
        "solver_id": solver,
        "source_lock_sha256": "a" * 64,
        "source_raw_sha256": "b" * 64,
        "source_record_sha256s": ["c" * 64],
    }


def fixture() -> tuple[dict, list[dict]]:
    rows = [
        source(0, "QF_UF/QG-classification/qg7/iso_icl_nogen001.smt2"),
        source(1, "QF_UF/QG-classification/qg7/iso_icl_nogen_sk001.smt2"),
        source(2, "QF_UF/PEQ/PEQ001_size1.smt2"),
    ]
    solvers = ["euf-viper", "cvc5", "opensmt", "yices2", "z3-default", "z3-sat-euf"]
    observations = []
    for budget in (2.0, 60.0):
        for row in rows:
            for solver in solvers:
                result = row["status"]
                if budget == 60.0 and solver == "euf-viper":
                    result = "timeout"
                observations.append(observation(budget, solver, row["relative_path"], result))
    audit = {
        "input_hashes": {
            "manifest_sha256": T6.P0_AUDIT_MANIFEST_SHA256,
            "solver_binary_sha256": {"euf-viper": T6.P0_BINARY_SHA256},
        },
        "inputs": {
            "baseline_ids": ["cvc5", "opensmt", "yices2", "z3-default", "z3-sat-euf"],
            "budgets_s": [2.0, 60.0],
            "campaign_id": "best-overall-qf-uf-2026-07",
            "candidate_id": "euf-viper",
            "instances": 3,
            "observation_provenance": observations,
        },
        "schema_version": 1,
        "status": "rejected",
    }
    return audit, rows


class T6P0ManifestTests(unittest.TestCase):
    def derive(self, audit: dict, rows: list[dict]) -> dict:
        return T6.derive_manifest(
            audit,
            rows,
            {"arms": {"A": "a", "B": "b", "C": "c", "D": "d"}},
            audit_sha256="d" * 64,
            local_manifest_sha256="e" * 64,
            projection_template_sha256="f" * 64,
            expected_sources=3,
            expected_selected=2,
        )

    def test_derivation_is_structural_deterministic_and_hash_bound(self) -> None:
        audit, rows = fixture()
        first = self.derive(audit, rows)
        second = self.derive(copy.deepcopy(audit), copy.deepcopy(rows))
        self.assertEqual(first, second)
        self.assertEqual(first["selection"]["candidate_count"], 2)
        self.assertFalse(first["implementation_or_promotion_eligible"])
        self.assertEqual(first["gate"]["minimum_qualifying_sources"], 10)
        self.assertEqual(
            [row["relative_path"] for row in first["sources"]],
            sorted(row["relative_path"] for row in rows[:2]),
        )
        self.assertTrue(
            all("DOMAIN7_HUGE" in row["selection_tags"] for row in first["sources"])
        )
        self.assertEqual(first["sources"][0]["p0_results"]["euf-viper"], "timeout")

    def test_committed_manifest_is_closed_and_self_consistent(self) -> None:
        manifest = json.loads(COMMITTED.read_text(encoding="ascii"))
        self.assertEqual(manifest["schema"], T6.SCHEMA)
        self.assertFalse(manifest["implementation_or_promotion_eligible"])
        self.assertEqual(len(manifest["sources"]), T6.EXPECTED_SELECTED_SOURCES)
        self.assertEqual(manifest["gate"]["minimum_qualifying_sources"], 10)
        paths = [row["relative_path"] for row in manifest["sources"]]
        self.assertEqual(paths, sorted(paths, key=lambda value: value.encode("utf-8")))
        self.assertEqual(
            T6.canonical_path_digest(paths),
            manifest["selection"]["canonical_path_list_sha256"],
        )
        self.assertEqual(
            T6.canonical_source_digest(manifest["sources"]),
            manifest["selection"]["source_records_sha256"],
        )
        self.assertTrue(all(row["source_status"] == "unsat" for row in manifest["sources"]))

    def test_comparator_loss_or_candidate_solve_removes_source(self) -> None:
        for solver, result in (("z3-default", "timeout"), ("euf-viper", "unsat")):
            audit, rows = fixture()
            target = "QF_UF/QG-classification/qg7/iso_icl_nogen001.smt2"
            for observation_row in audit["inputs"]["observation_provenance"]:
                if (
                    observation_row["budget_s"] == 60.0
                    and observation_row["solver_id"] == solver
                    and observation_row["relative_path"] == target
                ):
                    observation_row["result"] = result
            with self.assertRaisesRegex(T6.DerivationError, "shared-deficit count"):
                self.derive(audit, rows)

    def test_duplicate_missing_and_malformed_observations_fail(self) -> None:
        audit, rows = fixture()
        audit["inputs"]["observation_provenance"].append(
            copy.deepcopy(audit["inputs"]["observation_provenance"][0])
        )
        with self.assertRaisesRegex(T6.DerivationError, "observation count"):
            self.derive(audit, rows)

        audit, rows = fixture()
        audit["inputs"]["observation_provenance"][0]["source_raw_sha256"] = "bad"
        with self.assertRaisesRegex(T6.DerivationError, "raw SHA-256"):
            self.derive(audit, rows)

    def test_source_status_size_and_identity_are_checked(self) -> None:
        audit, rows = fixture()
        rows[0]["bytes"] = T6.MINIMUM_SOURCE_BYTES - 1
        with self.assertRaisesRegex(T6.DerivationError, "outside DOMAIN7_HUGE"):
            self.derive(audit, rows)

        audit, rows = fixture()
        rows[0]["status"] = "sat"
        with self.assertRaisesRegex(T6.DerivationError, "comparator/source status"):
            self.derive(audit, rows)

    def test_atomic_output_is_canonical_and_replaces_existing_file(self) -> None:
        audit, rows = fixture()
        payload = self.derive(audit, rows)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text("stale", encoding="ascii")
            T6.atomic_write_json(path, payload)
            first = path.read_bytes()
            T6.atomic_write_json(path, payload)
            self.assertEqual(path.read_bytes(), first)
            self.assertEqual(json.loads(first), payload)
            self.assertTrue(first.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
