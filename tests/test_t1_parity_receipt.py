from __future__ import annotations

import hashlib
import json
import math
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "results" / "wmi" / "typed-parser-parity-146510"


def reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON constant {value!r}")


def finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"non-finite JSON number {value!r}")
    return result


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_strict(path: Path) -> Any:
    return json.loads(
        path.read_bytes().decode("ascii"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
        parse_float=finite_float,
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class T1ParityReceiptTests(unittest.TestCase):
    def test_compact_evidence_packet_is_bound_and_parity_only(self) -> None:
        receipt = load_strict(EVIDENCE / "receipt.json")
        audit = load_strict(EVIDENCE / "audit.json")
        independent_path = (
            EVIDENCE
            / "typed-parser-parity-20260713T221314Z-66099-independent.json"
        )
        independent = load_strict(independent_path)

        self.assertEqual(
            receipt["schema"], "euf-viper.typed-parser-parity-decision.v1"
        )
        self.assertEqual(receipt["status"], "accepted_for_parser_parity_only")
        self.assertEqual(
            receipt["research_revision"],
            "e77846df010ff777a3dd50d510d0a89cff10f1e6",
        )
        self.assertEqual(receipt["evidence_integration_commit"], "84b4c8e")
        self.assertEqual(
            receipt["source_integration_commit"],
            "00c11a5a69a53d24f3f09aed516f483a17de1e86",
        )
        self.assertEqual(
            receipt["jobs"],
            {
                "prepare": 146510,
                "array": 146511,
                "audit": 146512,
                "independent_reconstruction": 146652,
            },
        )

        expected_counts = {"match": 7503, "fallback": 0, "mismatch": 0, "error": 0}
        self.assertEqual(audit["counts"], expected_counts)
        self.assertEqual(independent["counts"], expected_counts)
        self.assertEqual(independent["source_count"], 7503)
        self.assertEqual(independent["shard_count"], 128)
        self.assertEqual(independent["source_total_bytes"], 988035549)
        self.assertEqual(independent["status"], "verified")
        self.assertTrue(audit["gate"]["passed"])

        artifact_files = {
            "audit_json_sha256": "audit.json",
            "prepare_json_sha256": "prepare.json",
            "preflight_json_sha256": "preflight.json",
            "independent_json_sha256": independent_path.name,
            "submission_json_sha256": "submission.json",
        }
        for field, name in artifact_files.items():
            with self.subTest(field=field):
                self.assertEqual(
                    sha256(EVIDENCE / name), receipt["local_artifacts"][field]
                )

        self.assertEqual(
            receipt["remote_artifacts"]["audit_sha256"], sha256(EVIDENCE / "audit.json")
        )
        self.assertEqual(
            receipt["remote_artifacts"]["independent_sha256"],
            sha256(independent_path),
        )
        self.assertEqual(
            sha256(EVIDENCE / "typed-parser-independent-146652.out"),
            sha256(independent_path),
        )
        self.assertEqual(
            (EVIDENCE / "typed-parser-audit-146512.err").read_bytes(), b""
        )
        self.assertEqual(
            (EVIDENCE / "typed-parser-independent-146652.err").read_bytes(), b""
        )

        self.assertEqual(receipt["scope"]["unsupported_diagnostic_rows"], 98)
        self.assertEqual(receipt["scope"]["unsupported_diagnostics"], 4851)
        self.assertFalse(receipt["scope"]["parser_completeness_claim"])
        self.assertFalse(receipt["scope"]["solver_result_claim"])
        self.assertFalse(receipt["scope"]["performance_claim"])
        self.assertFalse(receipt["scope"]["production_tree_parser_changed"])
        self.assertEqual(receipt["independent_review"], "go_for_parity_only")


if __name__ == "__main__":
    unittest.main()
