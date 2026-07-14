from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "cert" / "audit_staged_shadow_campaign.py"
SPEC = importlib.util.spec_from_file_location("audit_staged_shadow_campaign", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


class StagedShadowAuditTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, list[Path]]:
        provenance = []
        cases = (
            ("a.smt2", "sat", 2.0),
            ("b.smt2", "unsat", 60.0),
            ("c.smt2", "sat", 1200.0),
            ("d.smt2", "timeout", 1200.0),
        )
        for budget in (2.0, 60.0, 1200.0):
            for path, result, origin in cases:
                current = result if budget == 1200.0 else "timeout"
                provenance.append(
                    {
                        "relative_path": path,
                        "budget_s": budget,
                        "solver_id": "euf-viper",
                        "result": current,
                        "origin_budget_s": origin if current in {"sat", "unsat"} else budget,
                    }
                )
        analysis = {
            "schema_version": 1,
            "status": "rejected",
            "assumptions": {"complete_declared_budget_ladder": True},
            "inputs": {
                "budgets_s": [2.0, 60.0, 1200.0],
                "observation_provenance": provenance,
            },
            "input_hashes": {
                "staged_evidence_sha256": "1" * 64,
                "observation_provenance_sha256": hashlib.sha256(
                    canonical(provenance)
                ).hexdigest(),
            },
        }
        analysis_path = root / "analysis.json"
        analysis_path.write_text(json.dumps(analysis, indent=2) + "\n")
        audits = []
        for budget, rows in (
            (2.0, [("a.smt2", "sat")]),
            (60.0, [("b.smt2", "unsat")]),
            (1200.0, [("c.smt2", "sat")]),
        ):
            verified = [
                {
                    "relative_path": path,
                    "result": result,
                    "work_sha256": hashlib.sha256(path.encode()).hexdigest(),
                }
                for path, result in rows
            ]
            payload = {
                "schema_version": 1,
                "status": "complete",
                "budget_s": budget,
                "source_shard_bundle_sha256": str(int(budget))[-1] * 64,
                "selection_sha256": hashlib.sha256(canonical(verified)).hexdigest(),
                "verified_instances": len(verified),
                "verified": verified,
            }
            path = root / f"audit-{budget:g}.json"
            path.write_bytes(canonical(payload))
            audits.append(path)
        return analysis_path, audits

    def test_matches_every_final_solve_to_its_physical_origin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            analysis, audits = self.fixture(Path(temporary))
            report = AUDIT.audit_staged_shadow_campaign(analysis, audits)

        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["verified_instances"], 3)
        self.assertEqual(
            report["verified_by_origin_budget"], {"2": 1, "60": 1, "1200": 1}
        )

    def test_rejects_missing_and_wrong_origin_certificates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            analysis, audits = self.fixture(Path(temporary))
            with self.assertRaisesRegex(
                AUDIT.StagedShadowAuditError, "audit set mismatch"
            ):
                AUDIT.audit_staged_shadow_campaign(analysis, audits[:2])

            payload = json.loads(audits[1].read_text(encoding="ascii"))
            payload["verified"][0]["relative_path"] = "c.smt2"
            audits[1].write_bytes(canonical(payload))
            with self.assertRaisesRegex(
                AUDIT.StagedShadowAuditError, "selection SHA-256 mismatch"
            ):
                AUDIT.audit_staged_shadow_campaign(analysis, audits)

            payload["selection_sha256"] = hashlib.sha256(
                canonical(payload["verified"])
            ).hexdigest()
            audits[1].write_bytes(canonical(payload))
            with self.assertRaisesRegex(
                AUDIT.StagedShadowAuditError, "origin budget 60 mismatch"
            ):
                AUDIT.audit_staged_shadow_campaign(analysis, audits)

    def test_rejects_staged_observation_provenance_hash_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            analysis, audits = self.fixture(Path(temporary))
            payload = json.loads(analysis.read_text(encoding="utf-8"))
            payload["inputs"]["observation_provenance"][-1]["result"] = "sat"
            analysis.write_text(json.dumps(payload, indent=2) + "\n")

            with self.assertRaisesRegex(
                AUDIT.StagedShadowAuditError, "provenance SHA-256 mismatch"
            ):
                AUDIT.audit_staged_shadow_campaign(analysis, audits)


if __name__ == "__main__":
    unittest.main()
