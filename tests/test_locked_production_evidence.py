from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from tests.test_run_locked_campaign import (
    CampaignFixture,
    RUNNER,
    canonical_bytes,
    sha256_bytes,
    sha256_file,
)
from tests.sealed_build_fixture import independent_attestation


ROOT = Path(__file__).resolve().parents[1]
ANALYZER_PATH = ROOT / "scripts" / "bench" / "analyze_campaign.py"
SPEC = importlib.util.spec_from_file_location("analyze_campaign_evidence_test", ANALYZER_PATH)
assert SPEC is not None and SPEC.loader is not None
ANALYZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZER)
SHADOW_PATH = ROOT / "scripts" / "cert" / "shadow_campaign.py"
SHADOW_SPEC = importlib.util.spec_from_file_location(
    "shadow_campaign_evidence_test", SHADOW_PATH
)
assert SHADOW_SPEC is not None and SHADOW_SPEC.loader is not None
SHADOW = importlib.util.module_from_spec(SHADOW_SPEC)
SHADOW_SPEC.loader.exec_module(SHADOW)


EVIDENCE_SOLVER = textwrap.dedent(
    f"""\
    #!{sys.executable}
    import hashlib
    import json
    import os
    import sys
    from pathlib import Path

    source = Path(sys.argv[1])
    output = Path(sys.argv[sys.argv.index("--evidence-out") + 1])
    controls = {{
        "EUF_VIPER_RUN_NONCE",
        "EUF_VIPER_TRUSTED_EXECUTABLE_SHA256",
        "EUF_VIPER_SEALED_BUILD_RECEIPT",
    }}
    config = {{
        key: value
        for key, value in os.environ.items()
        if key.startswith("EUF_VIPER_") and key not in controls
    }}
    config["resolved.direct_root_cnf"] = os.environ.get("EUF_VIPER_DIRECT_ROOT_CNF", "1")
    config["resolved.direct_negated_root"] = os.environ.get(
        "EUF_VIPER_DIRECT_NEGATED_ROOT", "0"
    )
    config.update({{
        "resolved.production_evidence_contract": "deterministic-cnf-transcript-v1",
        "resolved.production_evidence_mode": "cnf-assignment-transcript",
        "resolved.eq_abstraction": "off",
        "resolved.finite_domain": "off",
        "resolved.full_ackermann": "off",
        "resolved.chordal_transitivity": "off",
        "resolved.refinement_mode": "model-cuts",
    }})
    canonical = lambda value: (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\\n"
    ).encode("utf-8")
    build = {{
        "features": ["production-evidence"],
        "target": "x86_64-unknown-linux-gnu",
        "profile": "release",
        "rustc": "rustc test",
        "cargo": "cargo test",
        "source_manifest_sha256": "0" * 64,
        "sealed_source_manifest_sha256": "1" * 64,
        "execution_closure_sha256": "2" * 64,
    }}
    payload = {{
        "schema": "euf-viper.production-evidence.v4",
        "run_nonce": os.environ["EUF_VIPER_RUN_NONCE"],
        "status": "sat",
        "backend_status": "sat",
        "source": {{
            "path": str(source),
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "bytes": source.stat().st_size,
        }},
        "solver": {{
            "package_version": "test",
            "revision": os.environ["REPOSITORY_REVISION"],
            "dirty": False,
            "executable_sha256": os.environ["EUF_VIPER_TRUSTED_EXECUTABLE_SHA256"],
            "backend": "kissat",
            "config": config,
            "config_sha256": hashlib.sha256(canonical(config)).hexdigest(),
            "build": build,
            "build_sha256": hashlib.sha256(canonical(build)).hexdigest(),
            "sealed_build": {{
                "receipt": json.loads(
                    Path(os.environ["EUF_VIPER_SEALED_BUILD_RECEIPT"]).read_bytes()
                ),
                "receipt_sha256": os.environ[
                    "EUF_VIPER_SEALED_BUILD_RECEIPT_SHA256"
                ],
            }},
        }},
        "backend_cnf": {{
            "format": "dimacs-literal-arrays",
            "claim": "clauses-supplied-through-backend-api",
            "var_count": 0,
            "variables": [],
            "initial_clause_count": 0,
            "initial_clauses_sha256": hashlib.sha256(canonical([])).hexdigest(),
            "initial_clauses": [],
            "final_clause_count": 0,
            "final_clauses_sha256": hashlib.sha256(canonical([])).hexdigest(),
            "final_clauses": [],
            "transcript_event_count": 3,
            "transcript_sha256": "",
            "transcript": [
                {{"kind": "solve", "call": 1}},
                {{"kind": "assignment", "call": 1, "assignment": []}},
                {{"kind": "validation", "call": 1, "conflicts": []}},
            ],
        }},
        "model": {{
            "assignment": [],
            "assignment_sha256": hashlib.sha256(canonical([])).hexdigest(),
            "terms": [
                {{"id": 0, "function": "@fake_true", "args": [], "sort": "Bool", "class": 0, "internal": True, "internal_kind": "true"}},
                {{"id": 1, "function": "@fake_false", "args": [], "sort": "Bool", "class": 1, "internal": True, "internal_kind": "false"}},
            ],
            "atoms": [],
            "true_term": 0,
            "false_term": 1,
        }},
        "limitations": [],
    }}
    payload["backend_cnf"]["transcript_sha256"] = hashlib.sha256(
        canonical(payload["backend_cnf"]["transcript"])
    ).hexdigest()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical(payload))
    print("sat")
    """
)


@unittest.skipUnless(
    sys.platform.startswith("linux") and Path("/proc/self/fd").is_dir(),
    "production solver and checker execution requires Linux /proc/self/fd",
)
class LockedProductionEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def fixture(
        self,
        solver_source: str = EVIDENCE_SOLVER,
        *,
        candidate_environment: dict[str, str] | None = None,
    ) -> CampaignFixture:
        fixture = CampaignFixture(self.root)
        fixture.add_instance(
            "QF_UF/family/sat.smt2",
            status="sat",
            content=b"(set-logic QF_UF)\n(assert true)\n(check-sat)\n",
        )
        fixture.add_solver("euf-viper", solver_source)
        fixture.add_solver("z3")
        payload = fixture.finalize(budgets=[1])
        taxonomy = fixture.artifacts / "taxonomy.jsonl"
        for instance in payload["corpus"]["instances"]:
            instance.update(
                {
                    "family": "family",
                    "lineage": "synthetic/test",
                    "normalized_sha256": sha256_bytes(
                        instance["relative_path"].encode("utf-8")
                    ),
                    "split": "development",
                }
            )
        taxonomy.write_bytes(
            b"".join(canonical_bytes(instance) for instance in payload["corpus"]["instances"])
        )
        payload["corpus"]["taxonomy_path"] = str(taxonomy.resolve())
        payload["corpus"]["taxonomy_sha256"] = sha256_file(taxonomy)
        payload["promotion_eligible"] = True
        candidate = next(
            solver for solver in payload["solvers"] if solver["id"] == "euf-viper"
        )
        candidate["evidence"] = {
            "schema": "euf-viper.production-evidence.v4",
            "argv_flag": "--evidence-out",
            "accepted_decisive_statuses": ["sat"],
        }
        candidate["environment"].update(candidate_environment or {})
        candidate["environment"]["REPOSITORY_REVISION"] = payload["repository"]["commit"]
        receipt = {
            "artifacts": {
                "euf-viper": {
                    "bytes": Path(candidate["binary"]).stat().st_size,
                    "mode": "0500",
                    "sha256": candidate["sha256"],
                },
                "euf-viper-build-features": {
                    "bytes": Path(candidate["binary"]).stat().st_size,
                    "mode": "0500",
                    "sha256": candidate["sha256"],
                },
            },
            "build": {
                "execution_closure_sha256": "2" * 64,
                "features": ["production-evidence"],
                "profile": "release",
                "target": "x86_64-unknown-linux-gnu",
                "toolchain": {"cargo": "cargo test", "rustc": "rustc test"},
            },
            "schema": "euf-viper.sealed-build-receipt.v3",
            "sealed_build_manifest_sha256": "3" * 64,
            "source": {
                "dirty": False,
                "revision": payload["repository"]["commit"],
                "snapshot_manifest_sha256": "1" * 64,
                "tree": "4" * 40,
            },
            "status": "accepted",
        }
        receipt["independent_attestation"] = independent_attestation(
            artifacts=receipt["artifacts"],
            features=receipt["build"]["features"],
            toolchain=receipt["build"]["toolchain"],
            revision=receipt["source"]["revision"],
            tree=receipt["source"]["tree"],
            source_manifest_sha256=receipt["source"]["snapshot_manifest_sha256"],
            closure_sha256=receipt["build"]["execution_closure_sha256"],
            build_manifest_sha256=receipt["sealed_build_manifest_sha256"],
        )
        receipt_path = self.root / "sealed-build-receipt.json"
        receipt_path.write_bytes(canonical_bytes(receipt))
        candidate["environment"]["EUF_VIPER_SEALED_BUILD_RECEIPT_SHA256"] = (
            sha256_file(receipt_path)
        )
        fixture.sealed_build_receipt = receipt_path
        fixture.solver_config.write_bytes(
            canonical_bytes({"schema_version": 1, "solvers": payload["solvers"]})
        )
        payload["solver_config"]["sha256"] = sha256_file(fixture.solver_config)
        payload["lock_sha256"] = ""
        payload["lock_sha256"] = sha256_bytes(canonical_bytes(payload))
        fixture.lock_path.write_bytes(canonical_bytes(payload))
        return fixture

    def run_campaign(self, fixture: CampaignFixture) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(RUNNER), str(fixture.lock_path)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            env={
                **os.environ,
                "EUF_VIPER_SEALED_BUILD_RECEIPT": str(
                    fixture.sealed_build_receipt.resolve()
                ),
            },
        )

    def test_locked_record_binds_artifact_and_audit_rejects_tampering(self) -> None:
        fixture = self.fixture()
        completed = self.run_campaign(fixture)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        raw = fixture.output / "raw.jsonl"
        campaign = ANALYZER.load_locked_campaign(fixture.lock_path, raw)
        observation = campaign["observations"][("QF_UF/family/sat.smt2", 1.0, "euf-viper")]
        binding = observation["production_evidence"][0]
        self.assertEqual(binding["status"], "sat")
        self.assertEqual(binding["solver_revision"], campaign["lock"]["repository"]["commit"])

        artifact = fixture.output / binding["path"]
        original = artifact.read_bytes()
        artifact.write_bytes(artifact.read_bytes() + b" ")
        with self.assertRaisesRegex(ANALYZER.CampaignInputError, "SHA-256 mismatch"):
            ANALYZER.load_locked_campaign(fixture.lock_path, raw)

        artifact.write_bytes(original)
        artifact.unlink()
        with self.assertRaisesRegex(
            ANALYZER.CampaignInputError, "cannot open .*production-evidence"
        ):
            ANALYZER.load_locked_campaign(fixture.lock_path, raw)

    def test_shadow_workset_validates_production_model_before_rerun(self) -> None:
        fixture = self.fixture()
        completed = self.run_campaign(fixture)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        raw = fixture.output / "raw.jsonl"
        campaign = SHADOW.load_validated_campaign(fixture.lock_path, raw)
        works = SHADOW.derive_work_records(campaign, fixture.lock_path)
        self.assertEqual(len(works), 1)
        self.assertEqual(works[0]["production_evidence"][0]["validation"]["status"], "sat")
        SHADOW.validate_work_record(works[0])

        forged = json.loads(json.dumps(works[0]))
        forged["production_evidence"][0]["validation"]["status"] = "unsupported"
        forged["work_sha256"] = SHADOW._work_digest(forged)
        with self.assertRaisesRegex(SHADOW.ShadowError, "validation status mismatch"):
            SHADOW.validate_work_record(forged)

    def test_analyzer_runs_checker_and_rejects_forged_origin(self) -> None:
        fixture = self.fixture()
        completed = self.run_campaign(fixture)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        raw = fixture.output / "raw.jsonl"
        records = [json.loads(line) for line in raw.read_text(encoding="utf-8").splitlines()]
        candidate = next(record for record in records if record.get("production_evidence"))
        binding = candidate["production_evidence"]
        artifact_path = fixture.output / binding["path"]
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        artifact["model"]["origin"] = "forged"
        artifact_path.write_bytes(canonical_bytes(artifact))
        binding["sha256"] = sha256_file(artifact_path)
        binding["bytes"] = artifact_path.stat().st_size
        previous = records[0]["previous_record_sha256"]
        for record in records:
            record["previous_record_sha256"] = previous
            record["record_sha256"] = ANALYZER._record_digest(record)
            previous = record["record_sha256"]
        raw.write_bytes(b"".join(canonical_bytes(record) for record in records))
        with self.assertRaisesRegex(
            ANALYZER.CampaignInputError,
            "independent production-evidence check failed",
        ):
            ANALYZER.load_locked_campaign(fixture.lock_path, raw)

    def test_decisive_result_without_sidecar_stops_the_runner(self) -> None:
        fixture = self.fixture(
            EVIDENCE_SOLVER.replace("output.write_bytes(canonical(payload))", "pass")
        )
        completed = self.run_campaign(fixture)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("omitted production evidence", completed.stderr)
        self.assertFalse((fixture.output / "raw.jsonl").exists())

    def test_resume_rehashes_and_rejects_a_missing_completed_sidecar(self) -> None:
        fixture = self.fixture()
        completed = self.run_campaign(fixture)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        record = fixture.raw_records()[0]
        binding = record["production_evidence"]
        (fixture.output / binding["path"]).unlink()

        resumed = self.run_campaign(fixture)

        self.assertEqual(resumed.returncode, 2)
        self.assertIn("completed production evidence cannot be rehashed", resumed.stderr)

    def test_runner_rejects_a_symlinked_production_evidence_directory(self) -> None:
        fixture = self.fixture()
        fixture.output.mkdir(parents=True)
        escaped = self.root / "escaped-evidence"
        escaped.mkdir()
        (fixture.output / "production-evidence").symlink_to(
            escaped, target_is_directory=True
        )

        completed = self.run_campaign(fixture)

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("without symlinks", completed.stderr)
        self.assertEqual(list(escaped.iterdir()), [])

    def test_unicode_locked_runtime_config_uses_canonical_utf8(self) -> None:
        fixture = self.fixture(
            candidate_environment={"EUF_VIPER_TEST_UNICODE": "zażółć-α"}
        )
        completed = self.run_campaign(fixture)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        record = fixture.raw_records()[0]
        binding = record["production_evidence"]
        artifact = json.loads(
            (fixture.output / binding["path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(
            artifact["solver"]["config"]["EUF_VIPER_TEST_UNICODE"],
            "zażółć-α",
        )


if __name__ == "__main__":
    unittest.main()
