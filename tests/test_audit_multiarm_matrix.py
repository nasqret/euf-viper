from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "audit_multiarm_matrix.py"
SPEC = importlib.util.spec_from_file_location("audit_multiarm_matrix", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class MultiarmMatrixAuditTests(unittest.TestCase):
    def test_aggregate_reports_coverage_exchange_and_common_speed(self) -> None:
        paths = [
            {
                "relative_path": "common.smt2",
                "expected_status": "sat",
                "arms": {
                    "baseline": {"covered": True, "median_time_s": 2.0},
                    "candidate": {"covered": True, "median_time_s": 1.0},
                },
            },
            {
                "relative_path": "gain.smt2",
                "expected_status": "unsat",
                "arms": {
                    "baseline": {"covered": False, "median_time_s": None},
                    "candidate": {"covered": True, "median_time_s": 0.5},
                },
            },
            {
                "relative_path": "loss.smt2",
                "expected_status": "sat",
                "arms": {
                    "baseline": {"covered": True, "median_time_s": 1.0},
                    "candidate": {"covered": False, "median_time_s": None},
                },
            },
        ]

        report = AUDIT.aggregate_paths(paths, ["baseline", "candidate"])

        self.assertEqual(report["common_correct_paths"], ["common.smt2"])
        candidate = report["arms"]["candidate"]
        self.assertEqual(candidate["covered_paths"], 2)
        self.assertEqual(candidate["coverage_delta_vs_reference"], 0)
        self.assertEqual(candidate["gains_vs_reference"], ["gain.smt2"])
        self.assertEqual(candidate["losses_vs_reference"], ["loss.smt2"])
        self.assertEqual(candidate["common_aggregate_speedup_vs_reference"], 2.0)
        self.assertEqual(candidate["common_geometric_speedup_vs_reference"], 2.0)
        self.assertEqual(candidate["wins_vs_reference"], 1)

    def test_manifest_pair_and_file_hash_fail_closed(self) -> None:
        digest = "a" * 64
        selection = [{"relative_path": "case.smt2", "status": "sat", "sha256": digest}]
        manifest = [
            {
                "path": "/corpus/case.smt2",
                "relative_path": "case.smt2",
                "status": "unsat",
                "sha256": digest,
            }
        ]
        with self.assertRaisesRegex(AUDIT.AuditError, "manifest row 0 differ"):
            AUDIT.verify_manifest_pair(selection, manifest)

        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact"
            artifact.write_bytes(b"original")
            expected = AUDIT.sha256_file(artifact)
            artifact.write_bytes(b"tampered")
            with self.assertRaisesRegex(AUDIT.AuditError, "hash mismatch"):
                AUDIT.verify_hash(artifact, expected, "test artifact")

    def test_archived_helios_matrices_replay_byte_exactly(self) -> None:
        archives = (
            (
                "2026-07-27-staged-qg7-threshold-19968141",
                6,
                "3d2248b066a8e70db9a8816f77305431ef6f8b6ee832186a95d8295255e09983",
            ),
            (
                "2026-07-27-stage10-qg7-full-19968275",
                64,
                "58a586225621c55d85041b655dbefc72af25bbd4bc81ffff669c0ea6509f6c85",
            ),
        )
        for name, shards, expected_hash in archives:
            with self.subTest(name=name):
                archive = ROOT / "research-vault" / "06-results" / name
                expected = json.loads((archive / "audit.json").read_text(encoding="ascii"))
                replayed = AUDIT.audit(archive / "experiment", shards)
                self.assertEqual(replayed, expected)
                self.assertEqual(replayed["audit_sha256"], expected_hash)


if __name__ == "__main__":
    unittest.main()
