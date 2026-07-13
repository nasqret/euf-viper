from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
COMPARE_SCRIPT = ROOT / "scripts" / "bench" / "compare_rollback_control.py"
AUDIT_SCRIPT = ROOT / "scripts" / "bench" / "audit_rollback_control.py"


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


COMPARE = load_module("compare_rollback_control_for_audit", COMPARE_SCRIPT)
AUDIT = load_module("audit_rollback_control", AUDIT_SCRIPT)


FAKE_SOLVER = r"""
#!/usr/bin/env python3
import json
import os
import sys
import time
from pathlib import Path

if len(sys.argv) != 4 or sys.argv[1:3] != ["solve", "--stats"]:
    raise SystemExit(64)
case = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
candidate = os.environ.get("EUF_VIPER_BACKEND") == "cadical-rollback"
if case["control_class"] == "target":
    time.sleep(0.002 if candidate else 0.12)
else:
    time.sleep(0.002 if candidate else 0.05)
print(case["status"])
if candidate:
    print("profile_cadical_rollback_complete_validations_ns=100 count=1", file=sys.stderr)
    print("profile_cadical_rollback_conflicts_ns=0 count=2", file=sys.stderr)
    print("profile_cadical_rollback_propagator_model_checks_ns=80 count=1", file=sys.stderr)
else:
    print("profile_kissat_validation_ns=200 count=1", file=sys.stderr)
    print("profile_cadical_refine_validation_ns=300 count=1", file=sys.stderr)
print("sat_calls=2", file=sys.stderr)
print("theory_lemmas=2", file=sys.stderr)
"""


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def write_executable(path: Path, source: str) -> None:
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    path.chmod(0o755)


def write_case(root: Path, name: str, status: str, control_class: str) -> dict:
    source = root / name
    source.write_text(
        json.dumps(
            {"control_class": control_class, "status": status}, sort_keys=True
        )
        + "\n",
        encoding="utf-8",
    )
    payload = source.read_bytes()
    return {
        "bytes": len(payload),
        "control_class": control_class,
        "path": str(source),
        "relative_path": f"QF_UF/tests/{name}",
        "sha256": digest(payload),
        "status": status,
    }


def rewrite_records(path: Path, records: list[dict]) -> None:
    previous = None
    payload = bytearray()
    for record in records:
        record["previous_record_sha256"] = previous
        record["record_hash"] = AUDIT.record_hash(record)
        previous = record["record_hash"]
        payload.extend(AUDIT.canonical_bytes(record))
    path.write_bytes(bytes(payload))


class RollbackControlAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="rollback audit ")
        self.root = Path(self.temp_dir.name)
        self.solver = self.root / "fake-solver"
        write_executable(self.solver, FAKE_SOLVER)
        self.rows = [
            write_case(self.root, "target.smt2", "unsat", "target"),
            write_case(self.root, "anti.smt2", "sat", "anti-target"),
        ]
        self.manifest = self.root / "manifest.jsonl"
        self.manifest.write_bytes(
            b"".join(COMPARE.canonical_bytes(row) for row in self.rows)
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def generate_evidence(self) -> list[Path]:
        journals: list[Path] = []
        for comparison in COMPARE.COMPARISONS:
            journal = self.root / f"{comparison}.jsonl"
            summary = self.root / f"{comparison}.summary.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(COMPARE_SCRIPT),
                    str(self.manifest),
                    "--binary",
                    str(self.solver),
                    "--comparison",
                    comparison,
                    "--timeout",
                    "1",
                    "--repeats",
                    "2",
                    "--out",
                    str(journal),
                    "--summary",
                    str(summary),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            journals.append(journal)
        return journals

    def run_audit(
        self, journals: list[Path], output: Path
    ) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable,
            str(AUDIT_SCRIPT),
            str(self.manifest),
            "--repeats",
            "2",
            "--min-multi-round-targets",
            "1",
            "--target-speedup",
            "1.10",
            "--anti-target-overhead",
            "1.10",
            "--out",
            str(output),
        ]
        for journal in journals:
            command.extend(("--journal", str(journal)))
        return subprocess.run(
            command, text=True, capture_output=True, check=False
        )

    def test_complete_cross_product_passes_non_vacuous_gate(self) -> None:
        journals = self.generate_evidence()
        output = self.root / "audit.json"
        completed = self.run_audit(journals, output)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(output.read_text())
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["counts"]["observations"], 24)
        self.assertTrue(all(check["passed"] for check in payload["checks"]))
        for comparison in COMPARE.COMPARISONS:
            metrics = payload["comparisons"][comparison]
            self.assertEqual(metrics["multi_round_target_count"], 1)
            self.assertGreater(metrics["target_geometric_speedup"], 1.10)
            self.assertLess(metrics["anti_target_p95_overhead"], 1.10)
            target = metrics["paths"][self.rows[0]["relative_path"]]
            self.assertEqual(
                target["labels"]["baseline"]["complete_validations_median"], 2
            )
            self.assertEqual(
                target["labels"]["candidate"]["complete_validations_median"], 1
            )
            self.assertEqual(target["candidate_replay_conflicts_median"], 2)
            self.assertEqual(target["candidate_model_checks_median"], 1)

    def test_tampering_missing_and_duplicate_rows_are_invalid(self) -> None:
        journals = self.generate_evidence()
        for mode in ("tampered", "missing", "duplicate"):
            with self.subTest(mode=mode):
                copies: list[Path] = []
                for source in journals:
                    copied = self.root / f"{mode}-{source.name}"
                    copied.write_bytes(source.read_bytes())
                    copies.append(copied)
                records = [json.loads(line) for line in copies[0].read_text().splitlines()]
                if mode == "tampered":
                    records[1]["wall_time_ns"] += 1
                    copies[0].write_bytes(
                        b"".join(AUDIT.canonical_bytes(record) for record in records)
                    )
                elif mode == "missing":
                    copies[0].write_bytes(
                        b"".join(AUDIT.canonical_bytes(record) for record in records[:-1])
                    )
                else:
                    duplicate = dict(records[-1])
                    duplicate["previous_record_sha256"] = records[-1]["record_hash"]
                    duplicate["record_hash"] = AUDIT.record_hash(duplicate)
                    copies[0].write_bytes(
                        copies[0].read_bytes() + AUDIT.canonical_bytes(duplicate)
                    )
                output = self.root / f"{mode}-audit.json"
                completed = self.run_audit(copies, output)
                self.assertEqual(completed.returncode, 2, completed.stderr)
                payload = json.loads(output.read_text())
                self.assertEqual(payload["status"], "invalid")

    def test_valid_complete_evidence_can_be_rejected_by_performance_gate(self) -> None:
        journals = self.generate_evidence()
        records = [json.loads(line) for line in journals[0].read_text().splitlines()]
        for record in records[1:]:
            if record["label"] == "candidate" and record["control_class"] == "target":
                record["profile"]["cadical_rollback_complete_validations"]["count"] = 2
                record["profile"]["cadical_rollback_conflicts"]["count"] = 0
        rewrite_records(journals[0], records)

        output = self.root / "reject.json"
        completed = self.run_audit(journals, output)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        payload = json.loads(output.read_text())
        self.assertEqual(payload["status"], "reject")
        failed = {check["check"] for check in payload["checks"] if not check["passed"]}
        self.assertIn(
            "current:fewer_validations_on_every_multi_round_target", failed
        )
        self.assertIn("current:replay_conflicts_on_every_multi_round_target", failed)

    def test_binary_binding_drift_is_invalid(self) -> None:
        journals = self.generate_evidence()
        with self.solver.open("ab") as handle:
            handle.write(b"\n# post-campaign mutation\n")
        output = self.root / "binary-drift.json"
        completed = self.run_audit(journals, output)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        payload = json.loads(output.read_text())
        self.assertEqual(payload["status"], "invalid")
        self.assertIn("binary size drift", payload["errors"][0])


if __name__ == "__main__":
    unittest.main()
