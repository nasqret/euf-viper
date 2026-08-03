from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/bench/execute_t11_stage0a_authorization_request.py"
SPEC = importlib.util.spec_from_file_location(
    "execute_t11_stage0a_authorization_request", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
EXECUTOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EXECUTOR
SPEC.loader.exec_module(EXECUTOR)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def controller_python() -> Path:
    system_python = Path("/usr/bin/python3")
    if sys.platform.startswith("linux") and system_python.is_file():
        return Path(os.path.realpath(system_python))
    return Path(sys.executable).resolve()


class T11Stage0AAuthorizationRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.python = controller_python()
        self.authorizer = self.root / "authorizer.py"
        self.finalizer = self.root / "finalizer.py"
        self.sacct = self.root / "sacct"
        self.submission = self.root / "submission.json"
        self.candidate = self.root / "scheduler-candidate.json"
        self.decision = self.root / "decision.json"
        self.request = self.root / "authorization-request.json"
        self.authorizer.write_text("raise SystemExit(91)\n", encoding="ascii")
        self.finalizer.write_text("# finalizer fixture\n", encoding="ascii")
        self.sacct.write_text("#!/bin/sh\nexit 92\n", encoding="ascii")
        self.submission.write_text("{}\n", encoding="ascii")
        self.authorizer.chmod(0o500)
        self.finalizer.chmod(0o400)
        self.sacct.chmod(0o500)

    def write_submission(self, values: dict[str, str]) -> None:
        control = {field: "a" * 64 for field in EXECUTOR.SUBMISSION_CONTROL_FIELDS}
        control.update(
            {
                "authorizer_sha256": values["authorizer_sha256"],
                "controller_python_sha256": values["controller_python_sha256"],
                "finalizer_sha256": values["finalizer_module_sha256"],
                "sacct_sha256": values["sacct_sha256"],
            }
        )
        payload = {
            "candidate_root": os.fspath(self.root),
            "control": control,
            "final_decision_path": values["decision"],
            "launch_manifest_sha256": "b" * 64,
            "revision": "c" * 40,
            "run_nonce": values["run_nonce"],
            "scheduler_candidate_path": values["scheduler_candidate"],
            "schema": EXECUTOR.SUBMISSION_SCHEMA,
            "slurm": {
                "cluster": "test-cluster",
                "compute_job_id": 4101,
                "finalizer_job_id": 4102,
                "owner_uid": os.getuid(),
            },
        }
        if self.submission.exists():
            self.submission.chmod(0o600)
        self.submission.write_bytes(EXECUTOR.canonical_json_bytes(payload))
        self.submission.chmod(0o400)

    def tearDown(self) -> None:
        for path in self.root.iterdir():
            if path.is_file() and not path.is_symlink():
                path.chmod(0o600)
        self.temporary.cleanup()

    def create(self, **overrides: str):
        values = {
            "controller_python": os.fspath(self.python),
            "controller_python_sha256": sha256(self.python),
            "authorizer": os.fspath(self.authorizer),
            "authorizer_sha256": sha256(self.authorizer),
            "submission": os.fspath(self.submission),
            "submission_sha256": "",
            "scheduler_candidate": os.fspath(self.candidate),
            "decision": os.fspath(self.decision),
            "finalizer_module": os.fspath(self.finalizer),
            "finalizer_module_sha256": sha256(self.finalizer),
            "sacct": os.fspath(self.sacct),
            "sacct_sha256": sha256(self.sacct),
            "run_nonce": "0123456789abcdef0123456789abcdef",
            "poll_attempts": "37",
            "poll_interval_seconds": "0.25",
        }
        values.update(overrides)
        self.write_submission(values)
        if "submission_sha256" not in overrides:
            values["submission_sha256"] = sha256(self.submission)
        return EXECUTOR.create_request(self.request, **values)

    def test_create_publishes_canonical_strict_request_and_exact_argv(self) -> None:
        request, encoded = self.create()
        self.assertEqual(self.request.read_bytes(), encoded)
        self.assertEqual(request["schema"], EXECUTOR.REQUEST_SCHEMA)
        self.assertEqual(
            request["poll"], {"attempts": "37", "interval_seconds": "0.25"}
        )
        self.assertEqual(request["argv"], EXECUTOR._expected_argv(request))
        self.assertEqual(request["argv"][4], "-c")
        compile(request["argv"][5], "authorization-bootstrap", "exec")
        self.assertIn("sealed authorizer", request["argv"][5])

    def test_request_digest_tamper_rejects_before_execution(self) -> None:
        self.create()
        with self.assertRaisesRegex(EXECUTOR.RequestError, "caller binding"):
            EXECUTOR.execute_request(self.request, "0" * 64)
        self.assertFalse(self.decision.exists())

    def test_rehashed_argv_tamper_rejects_exact_contract(self) -> None:
        request, _ = self.create()
        request["argv"].append("--unexpected")
        tampered = EXECUTOR.canonical_json_bytes(request)
        self.request.chmod(0o600)
        self.request.write_bytes(tampered)
        self.request.chmod(0o400)
        with self.assertRaisesRegex(EXECUTOR.RequestError, "argv differs"):
            EXECUTOR.execute_request(
                self.request, hashlib.sha256(tampered).hexdigest()
            )
        self.assertFalse(self.decision.exists())

    def test_unknown_schema_field_rejects(self) -> None:
        request, _ = self.create()
        request["extra"] = False
        with self.assertRaisesRegex(EXECUTOR.RequestError, "strict schema"):
            EXECUTOR.validate_request(request)

    @unittest.skipUnless(
        sys.platform.startswith("linux") and hasattr(os, "memfd_create"),
        "sealed request execution requires Linux memfd support",
    )
    def test_linux_executes_sealed_authorizer_and_matches_decision(self) -> None:
        candidate_payload = {
            "attempt_id": "d" * 64,
            "classification": "scientific_candidate",
            "policy": {"sat_calls": 0},
        }
        self.candidate.write_bytes(EXECUTOR.canonical_json_bytes(candidate_payload))
        self.candidate.chmod(0o400)
        self.authorizer.chmod(0o600)
        self.authorizer.write_text(
            """import argparse
import hashlib
import json
import os

parser = argparse.ArgumentParser()
parser.add_argument("--submission", required=True)
parser.add_argument("--scheduler-candidate", required=True)
parser.add_argument("--output", required=True)
arguments, _ = parser.parse_known_args()
with open(arguments.submission, "rb") as handle:
    submission_bytes = handle.read()
submission = json.loads(submission_bytes)
with open(arguments.scheduler_candidate, "rb") as handle:
    candidate_bytes = handle.read()
candidate = json.loads(candidate_bytes)
submission_stat = os.stat(arguments.submission, follow_symlinks=False)
candidate_stat = os.stat(arguments.scheduler_candidate, follow_symlinks=False)
root_stat = os.stat(submission["candidate_root"], follow_symlinks=False)
raw_sha256 = {"allocation": "e" * 64, "batch": "f" * 64}
root_binding = {
    "device": root_stat.st_dev,
    "inode": root_stat.st_ino,
    "inventory_sha256": "1" * 64,
    "mode": f"{root_stat.st_mode & 0o7777:04o}",
    "path": submission["candidate_root"],
}
candidate_sha256 = hashlib.sha256(candidate_bytes).hexdigest()
submission_sha256 = hashlib.sha256(submission_bytes).hexdigest()
identity = {
    "candidate_root": submission["candidate_root"],
    "candidate_root_binding": root_binding,
    "cluster": submission["slurm"]["cluster"],
    "finalizer_job_id": submission["slurm"]["finalizer_job_id"],
    "finalizer_scheduler_raw_sha256": raw_sha256,
    "launch_manifest_sha256": submission["launch_manifest_sha256"],
    "revision": submission["revision"],
    "run_nonce": submission["run_nonce"],
    "scheduler_candidate_sha256": candidate_sha256,
    "submission_sha256": submission_sha256,
}
identity_bytes = (json.dumps(identity, sort_keys=True, separators=(",", ":")) + "\\n").encode("ascii")
payload = {
    "authorization_id": hashlib.sha256(identity_bytes).hexdigest(),
    "candidate_root": submission["candidate_root"],
    "candidate_root_binding": root_binding,
    "classification": candidate["classification"],
    "control": submission["control"],
    "decision": "authorize_stage0b",
    "finalizer_scheduler": {
        "allocation": {
            "Cluster": submission["slurm"]["cluster"],
            "JobIDRaw": str(submission["slurm"]["finalizer_job_id"]),
        },
        "batch": {},
        "commands": {},
        "raw_sha256": raw_sha256,
    },
    "launch_manifest_sha256": submission["launch_manifest_sha256"],
    "policy": candidate["policy"],
    "revision": submission["revision"],
    "run_nonce": submission["run_nonce"],
    "scheduler_candidate": {
        "attempt_id": candidate["attempt_id"],
        "bytes": len(candidate_bytes),
        "mode": f"{candidate_stat.st_mode & 0o7777:04o}",
        "path": arguments.scheduler_candidate,
        "sha256": candidate_sha256,
    },
    "schema": "euf-viper.t11-stage0a-authorization.v1",
    "stage0b_authority": True,
    "status": "stage0b_authorized",
    "submission": {
        "bytes": len(submission_bytes),
        "mode": f"{submission_stat.st_mode & 0o7777:04o}",
        "path": arguments.submission,
        "sha256": submission_sha256,
    },
    "submission_evidence": {
        "compute_held_record": {},
        "compute_sbatch_argv": [],
        "finalizer_held_record": {},
        "finalizer_sbatch_argv": [],
        "owner_uid": submission["slurm"]["owner_uid"],
    },
}
encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\\n").encode("ascii")
descriptor = os.open(arguments.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
try:
    os.write(descriptor, encoded)
    os.fchmod(descriptor, 0o400)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
os.write(1, encoded)
""",
            encoding="ascii",
        )
        self.authorizer.chmod(0o500)
        _, request_bytes = self.create()
        authorization, encoded = EXECUTOR.execute_request(
            self.request, hashlib.sha256(request_bytes).hexdigest()
        )
        self.assertEqual(authorization["status"], "stage0b_authorized")
        self.assertEqual(self.decision.read_bytes(), encoded)


if __name__ == "__main__":
    unittest.main()
