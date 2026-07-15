from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "wmi" / "finalize_locked_audit.py"
AUDIT_BATCH = ROOT / "scripts" / "wmi" / "euf_viper_locked_audit.sbatch"
FIXTURE = ROOT / "tests" / "fixtures" / "locked_audit" / "global-rejected.json"
ANALYZER_FIXTURE_PATH = ROOT / "tests" / "test_analyze_campaign.py"
SPEC = importlib.util.spec_from_file_location("finalize_locked_audit_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
FINALIZER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = FINALIZER
SPEC.loader.exec_module(FINALIZER)
ANALYZER_FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "finalize_analyzer_fixture", ANALYZER_FIXTURE_PATH
)
assert (
    ANALYZER_FIXTURE_SPEC is not None
    and ANALYZER_FIXTURE_SPEC.loader is not None
)
ANALYZER_FIXTURE = importlib.util.module_from_spec(ANALYZER_FIXTURE_SPEC)
ANALYZER_FIXTURE_SPEC.loader.exec_module(ANALYZER_FIXTURE)


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


COMMON_ENVIRONMENT_NAMES = (
    "EUF_VIPER_ATTEMPT_ID",
    "EUF_VIPER_ATTEMPT_ROOT",
    "EUF_VIPER_CHECKOUT",
    "EUF_VIPER_EXPECTED_REVISION",
    "EUF_VIPER_PYTHON",
    "EUF_VIPER_PYTHON_SHA256",
    "EUF_VIPER_PROVENANCE_HELPER_SHA256",
    "EUF_VIPER_SHA256SUM",
    "EUF_VIPER_SUBMISSION_MANIFEST",
    "EUF_VIPER_SUBMISSION_MANIFEST_SHA256",
)


def production_provenance(
    root: Path, *, shards: int, receipt_sha256: str
) -> dict[str, object]:
    revision = "2" * 40
    manifest_sha256 = "1" * 64
    common_environment = {
        "EUF_VIPER_ATTEMPT_ID": "a" * 32,
        "EUF_VIPER_ATTEMPT_ROOT": str(root),
        "EUF_VIPER_CHECKOUT": str(root),
        "EUF_VIPER_EXPECTED_REVISION": revision,
        "EUF_VIPER_PYTHON": sys.executable,
        "EUF_VIPER_PYTHON_SHA256": "b" * 64,
        "EUF_VIPER_PROVENANCE_HELPER_SHA256": "c" * 64,
        "EUF_VIPER_SHA256SUM": "/usr/bin/sha256sum",
        "EUF_VIPER_SUBMISSION_MANIFEST": str(root / "submission-manifest.json"),
        "EUF_VIPER_SUBMISSION_MANIFEST_SHA256": manifest_sha256,
    }
    return {
        "attempt": {
            "checkout": str(root),
            "id": "a" * 32,
            "root": str(root),
        },
        "environment": {
            **common_environment,
            "EUF_VIPER_LOCKED_SHARDS": str(shards),
            "EUF_VIPER_PREPARE_JOB_ID": "10",
            "EUF_VIPER_PREPARE_RECEIPT_SHA256": receipt_sha256,
        },
        "execution_environment": {"scheduler": "test"},
        "manifest": str(root / "submission-manifest.json"),
        "manifest_sha256": manifest_sha256,
        "parameters": {
            "shared_corpus": str(root / "corpus"),
            "shards": str(shards),
        },
        "revision": revision,
        "runtime_tools": {"python": "test"},
        "source_blob_count": 3,
        "source_blobs_sha256": "4" * 64,
        "source_tree": "5" * 40,
        "stage": "audit",
    }


def preparation_environment(
    provenance: dict[str, object], shards: int
) -> dict[str, str]:
    current = provenance["environment"]
    parameters = provenance["parameters"]
    assert isinstance(current, dict) and isinstance(parameters, dict)
    return {
        **{name: str(current[name]) for name in COMMON_ENVIRONMENT_NAMES},
        "EUF_VIPER_LOCKED_SHARDS": str(shards),
        "EUF_VIPER_SHARED_CORPUS": str(parameters["shared_corpus"]),
    }


def bind_preparation_receipt(
    provenance: dict[str, object], receipt_sha256: str
) -> dict[str, object]:
    result = json.loads(json.dumps(provenance))
    result["environment"]["EUF_VIPER_PREPARE_RECEIPT_SHA256"] = receipt_sha256
    return result


def lock_bytes(**fields: object) -> tuple[bytes, str]:
    value = {**fields, "lock_sha256": ""}
    value["lock_sha256"] = sha256(FINALIZER._canonical_analysis_bytes(value))
    return FINALIZER._canonical_analysis_bytes(value), value["lock_sha256"]


def render_analysis(root: Path, kind: str) -> dict[str, object]:
    parent_path = root / "locks" / f"{kind}-parent.json"
    shard_lock_path = root / "locks" / kind / "bound-0000.json"
    shard_raw_path = root / f"{kind}-2s" / "shard-0000" / "raw.jsonl"
    manifest_path = root / "manifests" / f"{kind}.jsonl"
    taxonomy_path = root / "taxonomy" / f"{kind}.jsonl"
    taxonomy_split_path = root / "taxonomy" / f"{kind}-split.json"
    solver_config_path = root / "solver-config.json"
    parent_path.parent.mkdir(parents=True, exist_ok=True)
    shard_lock_path.parent.mkdir(parents=True, exist_ok=True)
    shard_raw_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    taxonomy_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps({"corpus": kind, "instance": "fixture"}, sort_keys=True) + "\n",
        encoding="ascii",
    )
    taxonomy_path.write_text(
        json.dumps({"corpus": kind, "family": "fixture-family"}, sort_keys=True)
        + "\n",
        encoding="ascii",
    )
    taxonomy_split_path.write_text(
        json.dumps({"corpus": kind, "split": "development"}, sort_keys=True)
        + "\n",
        encoding="ascii",
    )
    solver_config_path.write_text(
        json.dumps({"candidate": "euf-viper", "baseline": "z3"}, sort_keys=True)
        + "\n",
        encoding="ascii",
    )

    instances = [
        {
            "id": str(index),
            "relative_path": f"QF_UF/family/case-{index}.smt2",
            "path": str(root / "corpus" / f"case-{index}.smt2"),
            "sha256": f"{index + 5}" * 64,
            "bytes": 100 + index,
            "status": status,
            "family": "fixture-family",
            "lineage": "fixture/generated",
            "normalized_sha256": f"{index + 7}" * 64,
            "split": "development",
        }
        for index, status in enumerate(("sat", "unsat"))
    ]
    solvers = [
        {
            "id": solver_id,
            "comparator_id": solver_id,
            "configuration": "default",
            "version": "fixture-1",
            "binary": str(root / "bin" / solver_id),
            "sha256": digest,
            "argv_template": ["{binary}", "{instance}"],
            "version_output": None,
            "version_output_sha256": None,
            "environment": {},
        }
        for solver_id, digest in (("euf-viper", "2" * 64), ("z3", "3" * 64))
    ]
    parent_raw, parent_lock_sha256 = lock_bytes(
        schema_version=1,
        campaign_id=f"production-p0-{kind}",
        created_from_commit_time="2026-07-15T00:00:00+00:00",
        promotion_eligible=True,
        spec={"path": str(root / "campaign.json"), "sha256": "9" * 64},
        repository={
            "root": str(root),
            "commit": "2" * 40,
            "commit_time": "2026-07-15T00:00:00+00:00",
            "clean": True,
            "promotion_eligible": True,
        },
        host={},
        corpus={
            "id": f"fixture-{kind}",
            "manifest_path": str(manifest_path),
            "manifest_sha256": sha256(manifest_path.read_bytes()),
            "taxonomy_path": str(taxonomy_path),
            "taxonomy_sha256": sha256(taxonomy_path.read_bytes()),
            "root": str(root / "corpus"),
            "instances": instances,
        },
        solver_config={
            "path": str(solver_config_path),
            "sha256": sha256(solver_config_path.read_bytes()),
        },
        solver_release_lock={
            "path": str(root / "solver-releases.json"),
            "sha256": "c" * 64,
        },
        solvers=solvers,
        budgets_s=[2.0],
        execution={},
        output={},
    )
    shard_lock_raw, shard_lock_sha256 = lock_bytes(
        campaign_id=f"production-p0-{kind}",
        schema_version=1,
        shard={"count": 1, "index": 0, "parent_lock_sha256": parent_lock_sha256},
    )
    raw = (
        b'{"record_type":"run","result_token":"sat","schema_version":1}\n'
        b'{"record_type":"run","result_token":"unsupported","schema_version":1}\n'
    )
    parent_path.write_bytes(parent_raw)
    shard_lock_path.write_bytes(shard_lock_raw)
    shard_raw_path.write_bytes(raw)

    bundle = {
        "parent_lock_sha256": parent_lock_sha256,
        "shards": [
            {
                "cpu_ids": [7],
                "index": 0,
                "lock_file_sha256": sha256(shard_lock_raw),
                "lock_sha256": shard_lock_sha256,
                "raw_records": 2,
                "raw_sha256": sha256(raw),
            }
        ],
    }
    substitutions = {
        "@PARENT_LOCK@": str(parent_path),
        "@PARENT_LOCK_FILE_SHA256@": sha256(parent_raw),
        "@PARENT_LOCK_SHA256@": parent_lock_sha256,
        "@SHARD_BUNDLE_SHA256@": sha256(
            FINALIZER._canonical_analysis_bytes(bundle)
        ),
        "@SHARD_LOCK@": str(shard_lock_path),
        "@SHARD_LOCK_FILE_SHA256@": sha256(shard_lock_raw),
        "@SHARD_LOCK_SHA256@": shard_lock_sha256,
        "@SHARD_RAW@": str(shard_raw_path),
        "@SHARD_RAW_SHA256@": sha256(raw),
    }
    rendered = FIXTURE.read_text(encoding="ascii")
    for placeholder, value in substitutions.items():
        rendered = rendered.replace(placeholder, value)
    analysis = json.loads(rendered)
    analysis["inputs"]["campaign_id"] = f"production-p0-{kind}"
    analysis["input_hashes"]["manifest_sha256"] = sha256(
        manifest_path.read_bytes()
    )
    analysis["input_hashes"]["taxonomy_sha256"] = sha256(
        taxonomy_path.read_bytes()
    )
    analysis_path = root / "audit" / kind / "global.json"
    analysis_path.parent.mkdir(parents=True, exist_ok=True)
    if analysis_path.exists():
        analysis_path.chmod(0o600)
    analysis_path.write_text(
        json.dumps(analysis, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    analysis_path.chmod(0o400)
    return analysis


def render_generated_sharded_analysis(
    root: Path, kind: str
) -> dict[str, object]:
    source_root = root / "generated" / kind
    source_root.mkdir(parents=True, exist_ok=True)
    source_parent, _, _ = ANALYZER_FIXTURE.write_locked_fixture(source_root)
    parent_value = json.loads(source_parent.read_text(encoding="utf-8"))
    manifest_path = root / "manifests" / f"{kind}.jsonl"
    taxonomy_path = root / "taxonomy" / f"{kind}.jsonl"
    taxonomy_split_path = root / "taxonomy" / f"{kind}-split.json"
    solver_config_path = root / "solver-config.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    taxonomy_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps({"corpus": kind, "source": "generated"}, sort_keys=True) + "\n",
        encoding="ascii",
    )
    taxonomy_path.write_text(
        json.dumps({"corpus": kind, "families": ["alpha", "beta"]}, sort_keys=True)
        + "\n",
        encoding="ascii",
    )
    taxonomy_split_path.write_text(
        json.dumps({"corpus": kind, "split": "development"}, sort_keys=True)
        + "\n",
        encoding="ascii",
    )
    solver_config_path.write_text(
        json.dumps({"candidate": "euf-viper", "baseline": "z3"}, sort_keys=True)
        + "\n",
        encoding="ascii",
    )
    parent_value["repository"].update(
        {"root": str(root), "commit": "2" * 40}
    )
    parent_value["corpus"].update(
        {
            "manifest_path": str(manifest_path),
            "manifest_sha256": sha256(manifest_path.read_bytes()),
            "taxonomy_path": str(taxonomy_path),
            "taxonomy_sha256": sha256(taxonomy_path.read_bytes()),
        }
    )
    parent_value["solver_config"] = {
        "path": str(solver_config_path),
        "sha256": sha256(solver_config_path.read_bytes()),
    }
    parent_value["output"]["directory"] = str(root / f"{kind}-2s")
    parent_value["lock_sha256"] = ""
    parent_value["lock_sha256"] = ANALYZER_FIXTURE.ANALYZER._lock_sha256(
        parent_value
    )
    parent = root / "locks" / f"{kind}-parent.json"
    parent.parent.mkdir(parents=True, exist_ok=True)
    parent.write_bytes(ANALYZER_FIXTURE.ANALYZER._canonical_json_bytes(parent_value))

    pairs: list[tuple[Path, Path]] = []
    for index in range(2):
        prepared = ANALYZER_FIXTURE.ANALYZER._expected_prepared_shard(
            parent_value, index, 2
        )
        cpu_id = index + 4
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
        bound["lock_sha256"] = ANALYZER_FIXTURE.ANALYZER._lock_sha256(bound)
        lock = root / "locks" / kind / f"bound-{index:04d}.json"
        raw = root / f"{kind}-2s" / f"shard-{index:04d}" / "raw.jsonl"
        lock.parent.mkdir(parents=True, exist_ok=True)
        lock.write_bytes(ANALYZER_FIXTURE.ANALYZER._canonical_json_bytes(bound))
        ANALYZER_FIXTURE.write_raw_for_lock(bound, raw)
        pairs.append((lock, raw))

    report = ANALYZER_FIXTURE.ANALYZER.analyze_sharded_locked_campaign(
        parent,
        pairs,
        candidate_id="euf-viper",
        baseline_ids=["z3"],
        seed=31,
        bootstrap_replicates=16,
        confidence_level=0.9,
    )
    analysis_path = root / "audit" / kind / "global.json"
    analysis_path.parent.mkdir(parents=True, exist_ok=True)
    analysis_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    analysis_path.chmod(0o400)
    return report


def render_preparation_receipt(
    root: Path,
    provenance: dict[str, object],
    *,
    prepare_job: int,
    shards: int,
) -> Path:
    artifact_names = sorted(FINALIZER.PREPARATION_ARTIFACT_NAMES)
    artifacts = {
        name: {
            "path": str((root / name).resolve()),
            "sha256": sha256((root / name).read_bytes()),
        }
        for name in artifact_names
    }
    corpus = {
        "root": str((root / "corpus").resolve()),
        "full_manifest": {
            "path": str((root / "manifests" / "full.jsonl").resolve()),
            "sha256": sha256((root / "manifests" / "full.jsonl").read_bytes()),
        },
        "official_manifest": {
            "path": str((root / "manifests" / "official.jsonl").resolve()),
            "sha256": sha256(
                (root / "manifests" / "official.jsonl").read_bytes()
            ),
        },
    }
    receipt = {
        "schema": "euf-viper.locked-p0-preparation.v3",
        "status": "prepared",
        "attempt": provenance["attempt"],
        "artifacts": artifacts,
        "build_features": [
            "certificates",
            "default",
            "finite-symmetry",
            "production-evidence",
        ],
        "corpus": corpus,
        "environment": preparation_environment(provenance, shards),
        "execution_environment": provenance["execution_environment"],
        "feature_report": {},
        "hostname": "fixture-host",
        "job": {"id": prepare_job, "submit_directory": str(root)},
        "paths": {
            "checkout": str(root),
            "run_root": str(root),
            "submission_manifest": provenance["manifest"],
        },
        "revision": provenance["revision"],
        "runtime_tools": provenance["runtime_tools"],
        "shards": shards,
        "solver_executables": {},
        "sealed_build": {},
        "execution_closure": {},
        "source": {
            "blob_count": provenance["source_blob_count"],
            "blobs_sha256": provenance["source_blobs_sha256"],
            "tree": provenance["source_tree"],
            "snapshot_manifest_sha256": "6" * 64,
            "build_execution_closure_sha256": "7" * 64,
        },
        "submission_manifest_sha256": provenance["manifest_sha256"],
        "viper": {},
    }
    path = root / "prepare.json"
    path.write_bytes(FINALIZER.canonical_json_bytes(receipt))
    path.chmod(0o400)
    return path


def validated_analyses(
    root: Path, analyses: dict[str, dict[str, object]]
) -> dict[str, dict[str, object]]:
    return {
        kind: {
            "sha256": sha256((root / "audit" / kind / "global.json").read_bytes()),
            "process_exit": 0 if value["promoted"] else 1,
        }
        for kind, value in analyses.items()
    }


class FinalizeLockedAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.provenance = production_provenance(
            self.root, shards=1, receipt_sha256="0" * 64
        )
        self.analyses = {
            kind: render_analysis(self.root, kind) for kind in ("full", "official")
        }
        self.output = self.root / "audit" / "index.json"
        self.preparation_receipt = render_preparation_receipt(
            self.root, self.provenance, prepare_job=10, shards=1
        )
        self.provenance = bind_preparation_receipt(
            self.provenance, sha256(self.preparation_receipt.read_bytes())
        )
        self.scheduler_receipt = self.root / "audit" / "scheduler.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def current_bindings(self) -> dict[str, dict[str, object]]:
        analyses = {
            kind: json.loads(
                (self.root / "audit" / kind / "global.json").read_text(
                    encoding="ascii"
                )
            )
            for kind in ("full", "official")
        }
        return validated_analyses(self.root, analyses)

    def write_scheduler(
        self,
        bindings: dict[str, dict[str, object]],
        *,
        preparation_sha256: str | None = None,
    ) -> str:
        receipt_sha256 = preparation_sha256 or sha256(
            self.preparation_receipt.read_bytes()
        )
        self.provenance = bind_preparation_receipt(
            self.provenance, receipt_sha256
        )
        FINALIZER.create_scheduler_receipt(
            self.scheduler_receipt,
            self.provenance,
            self.root,
            10,
            1,
            11,
            self.preparation_receipt,
            receipt_sha256,
            bindings,
        )
        return sha256(self.scheduler_receipt.read_bytes())

    def finalize(self, **kwargs: object) -> dict[str, object]:
        bindings = kwargs.pop(
            "validated_analyses",
            self.current_bindings(),
        )
        write_scheduler = kwargs.pop("write_scheduler", True)
        preparation_sha256 = kwargs.pop(
            "preparation_receipt_sha256",
            sha256(self.preparation_receipt.read_bytes()),
        )
        self.provenance = bind_preparation_receipt(
            self.provenance, preparation_sha256
        )
        scheduler_sha256 = kwargs.pop("scheduler_receipt_sha256", None)
        if write_scheduler:
            scheduler_sha256 = self.write_scheduler(
                bindings, preparation_sha256=preparation_sha256
            )
        assert scheduler_sha256 is not None
        return FINALIZER.finalize(
            self.output,
            self.provenance,
            self.root,
            10,
            1,
            11,
            self.preparation_receipt,
            preparation_sha256,
            self.scheduler_receipt,
            scheduler_sha256,
            bindings,
            **kwargs,
        )

    def rewrite_analysis(self, kind: str, value: dict[str, object]) -> None:
        target = self.root / "audit" / kind / "global.json"
        target.chmod(0o600)
        target.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii"
        )
        target.chmod(0o400)

    def test_schema_accepts_analyzer_generated_sharded_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent, pairs = ANALYZER_FIXTURE.write_sharded_fixture(Path(temporary))
            report = ANALYZER_FIXTURE.ANALYZER.analyze_sharded_locked_campaign(
                parent,
                pairs,
                candidate_id="euf-viper",
                baseline_ids=["z3"],
                seed=31,
                bootstrap_replicates=16,
                confidence_level=0.9,
            )
        FINALIZER._validate_analysis_schema(report, "generated", 2)

    def test_batch_continues_only_for_success_or_statistical_rejection(self) -> None:
        text = AUDIT_BATCH.read_text(encoding="ascii")
        self.assertIn('case "$ANALYSIS_STATUS" in', text)
        self.assertIn('[ -e "$ANALYSIS_OUTPUT" ] || [ -L "$ANALYSIS_OUTPUT" ]', text)
        self.assertIn("analysis completed with statistical rejection", text)
        self.assertIn("analysis rejected its lock/raw input", text)
        self.assertIn("analysis could not publish its output", text)
        self.assertIn("analysis failed internally", text)
        self.assertIn("--validate-analysis", text)
        self.assertIn("--expected-analysis-exit", text)
        self.assertIn("exit 2", text)
        self.assertIn("exit 3", text)
        self.assertIn("exit 4", text)

    def test_live_parent_identity_fields_cannot_be_forged_in_report(self) -> None:
        cases = (
            ("campaign", "campaign identity"),
            ("solver", "solver hashes"),
            ("budget", "budget identity"),
            ("manifest", "manifest identity"),
            ("taxonomy", "taxonomy identity"),
            ("eligibility", "promotion eligibility"),
        )
        for field, diagnostic in cases:
            with self.subTest(field=field):
                value = render_analysis(self.root, "full")
                if field == "campaign":
                    value["inputs"]["campaign_id"] = "forged-campaign"
                elif field == "solver":
                    value["input_hashes"]["solver_binary_sha256"][
                        "euf-viper"
                    ] = "d" * 64
                elif field == "budget":
                    value["inputs"]["budgets_s"] = [3.0]
                    budget = value["comparisons"]["z3"]["budgets"].pop("2")
                    budget["budget_s"] = 3.0
                    value["comparisons"]["z3"]["budgets"]["3"] = budget
                    value["comparisons"]["z3"]["promotion"][
                        "failed_budgets"
                    ] = ["3"]
                elif field == "manifest":
                    value["input_hashes"]["manifest_sha256"] = "d" * 64
                elif field == "taxonomy":
                    value["input_hashes"]["taxonomy_sha256"] = "d" * 64
                else:
                    value["promotion"]["lock_promotion_eligible"] = False
                self.rewrite_analysis("full", value)
                with self.assertRaisesRegex(
                    FINALIZER.AuditFinalizeError, diagnostic
                ):
                    self.finalize()
                self.assertFalse(self.output.exists())

    def test_aggregate_promotion_cannot_contradict_individual_checks(self) -> None:
        value = self.analyses["full"]
        budget = value["comparisons"]["z3"]["budgets"]["2"]
        self.assertFalse(
            budget["promotion"]["checks"]["zero_coverage_loss"]["passed"]
        )
        budget["promotion"].update({"passed": True, "status": "promoted"})
        value["comparisons"]["z3"]["promotion"] = {
            "failed_budgets": [],
            "passed": True,
            "status": "promoted",
        }
        value.update({"promoted": True, "status": "promoted"})
        value["promotion"] = {
            "failed_comparisons": [],
            "lock_promotion_eligible": True,
            "passed": True,
            "status": "promoted",
        }
        self.rewrite_analysis("full", value)
        with self.assertRaisesRegex(
            FINALIZER.AuditFinalizeError, "contradicts individual checks"
        ):
            self.finalize()
        self.assertFalse(self.output.exists())

    def test_every_named_promotion_check_is_semantically_recomputed(self) -> None:
        check_names = sorted(FINALIZER.BUDGET_PROMOTION_CHECK_KEYS)
        for check_name in check_names:
            for field in ("actual", "operator", "threshold", "passed"):
                with self.subTest(check=check_name, field=field):
                    value = render_analysis(self.root, "full")
                    check = value["comparisons"]["z3"]["budgets"]["2"][
                        "promotion"
                    ]["checks"][check_name]
                    check[field] = (
                        not check[field] if field == "passed" else "forged"
                    )
                    self.rewrite_analysis("full", value)
                    with self.assertRaisesRegex(
                        FINALIZER.AuditFinalizeError,
                        f"promotion check '{check_name}'.*contradicts source data",
                    ):
                        self.finalize()
                    self.assertFalse(self.output.exists())

    def test_zero_coverage_loss_source_mutation_is_rejected(self) -> None:
        value = self.analyses["full"]
        budget = value["comparisons"]["z3"]["budgets"]["2"]
        budget["aggregate"]["coverage"]["baseline_only"] = 0
        self.rewrite_analysis("full", value)
        with self.assertRaisesRegex(
            FINALIZER.AuditFinalizeError,
            "promotion check 'zero_coverage_loss' contradicts source data",
        ):
            self.finalize()
        self.assertFalse(self.output.exists())

    def test_failed_promotion_check_cannot_be_omitted(self) -> None:
        value = self.analyses["full"]
        budget = value["comparisons"]["z3"]["budgets"]["2"]
        budget["promotion"]["checks"].pop("zero_coverage_loss")
        budget["promotion"].update({"passed": True, "status": "promoted"})
        value["comparisons"]["z3"]["promotion"] = {
            "failed_budgets": [],
            "passed": True,
            "status": "promoted",
        }
        value.update({"promoted": True, "status": "promoted"})
        value["promotion"] = {
            "failed_comparisons": [],
            "lock_promotion_eligible": True,
            "passed": True,
            "status": "promoted",
        }
        self.rewrite_analysis("full", value)
        with self.assertRaisesRegex(
            FINALIZER.AuditFinalizeError, "missing keys.*zero_coverage_loss"
        ):
            self.finalize()
        self.assertFalse(self.output.exists())

    def test_parent_promotion_eligibility_is_independently_derived(self) -> None:
        parent_path = self.root / "locks" / "full-parent.json"
        parent = json.loads(parent_path.read_text(encoding="ascii"))
        parent["repository"].update(
            {"clean": False, "promotion_eligible": False}
        )
        parent["lock_sha256"] = ""
        parent["lock_sha256"] = sha256(
            FINALIZER._canonical_analysis_bytes(parent)
        )
        parent_path.write_bytes(FINALIZER._canonical_analysis_bytes(parent))

        analysis = self.analyses["full"]
        analysis["input_hashes"]["lock_file_sha256"] = sha256(
            parent_path.read_bytes()
        )
        analysis["input_hashes"]["lock_sha256"] = parent["lock_sha256"]
        self.rewrite_analysis("full", analysis)
        with self.assertRaisesRegex(
            FINALIZER.AuditFinalizeError,
            "promotion eligibility contradicts repository and taxonomy",
        ):
            self.finalize()
        self.assertFalse(self.output.exists())

    def test_analysis_exit_is_accepted_only_after_hash_bound_validation(self) -> None:
        validation = FINALIZER.validate_analysis_output(self.root, "full", 1, 1)
        self.assertFalse(validation["promoted"])
        self.assertEqual(
            validation["analysis_sha256"],
            sha256((self.root / "audit" / "full" / "global.json").read_bytes()),
        )
        with self.assertRaisesRegex(
            FINALIZER.AuditFinalizeError, "contradicts process exit"
        ):
            FINALIZER.validate_analysis_output(self.root, "full", 1, 0)

        raw = self.root / "full-2s" / "shard-0000" / "raw.jsonl"
        raw.write_bytes(raw.read_bytes() + b'{"stale":true}\n')
        with self.assertRaisesRegex(FINALIZER.AuditFinalizeError, "raw hash is stale"):
            FINALIZER.validate_analysis_output(self.root, "full", 1, 1)

    def test_validated_analysis_replacement_before_finalization_is_rejected(self) -> None:
        bindings: dict[str, dict[str, object]] = {}
        for kind in ("full", "official"):
            validation = FINALIZER.validate_analysis_output(self.root, kind, 1, 1)
            bindings[kind] = {
                "sha256": validation["analysis_sha256"],
                "process_exit": validation["expected_analysis_exit"],
            }
        scheduler_sha256 = self.write_scheduler(bindings)

        replacement = json.loads(
            (self.root / "audit" / "full" / "global.json").read_text(
                encoding="ascii"
            )
        )
        replacement["configuration"]["seed"] += 1
        self.rewrite_analysis("full", replacement)
        with self.assertRaisesRegex(
            FINALIZER.AuditFinalizeError,
            "analysis bytes differ from validated analysis receipt",
        ):
            self.finalize(
                validated_analyses=bindings,
                write_scheduler=False,
                scheduler_receipt_sha256=scheduler_sha256,
            )
        self.assertFalse(self.output.exists())

    def test_batch_validation_cli_uses_the_same_hash_bound_contract(self) -> None:
        arguments = [
            sys.executable,
            "-B",
            str(MODULE_PATH),
            "--run-root",
            str(self.root),
            "--shards",
            "1",
            "--validate-analysis",
            "full",
            "--expected-analysis-exit",
            "1",
        ]
        accepted = subprocess.run(
            arguments, text=True, capture_output=True, check=False
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(
            json.loads(accepted.stdout)["analysis_sha256"],
            sha256((self.root / "audit" / "full" / "global.json").read_bytes()),
        )
        rejected = subprocess.run(
            [*arguments[:-1], "0"], text=True, capture_output=True, check=False
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("contradicts process exit", rejected.stderr)

    def test_scheduler_and_final_publication_cli_consume_validation_receipts(self) -> None:
        validations: dict[str, dict[str, object]] = {}
        for kind in ("full", "official"):
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(MODULE_PATH),
                    "--run-root",
                    str(self.root),
                    "--shards",
                    "1",
                    "--validate-analysis",
                    kind,
                    "--expected-analysis-exit",
                    "1",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            validations[kind] = json.loads(completed.stdout)

        provenance = json.dumps(
            self.provenance, sort_keys=True, separators=(",", ":")
        )
        preparation_sha256 = sha256(self.preparation_receipt.read_bytes())
        analysis_arguments: list[str] = []
        for kind in ("full", "official"):
            analysis_arguments.extend(
                [
                    f"--{kind}-analysis-sha256",
                    str(validations[kind]["analysis_sha256"]),
                    f"--{kind}-analysis-exit",
                    str(validations[kind]["expected_analysis_exit"]),
                ]
            )
        common_arguments = [
            "--provenance",
            provenance,
            "--run-root",
            str(self.root),
            "--prepare-job",
            "10",
            "--shards",
            "1",
            "--audit-job",
            "11",
            "--preparation-receipt",
            str(self.preparation_receipt),
            "--preparation-receipt-sha256",
            preparation_sha256,
            *analysis_arguments,
        ]
        scheduler = subprocess.run(
            [
                sys.executable,
                "-B",
                str(MODULE_PATH),
                "--write-scheduler-receipt",
                "--out",
                str(self.scheduler_receipt),
                *common_arguments,
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(scheduler.returncode, 0, scheduler.stderr)
        scheduler_payload = json.loads(scheduler.stdout)
        self.assertEqual(scheduler_payload["jobs"], {"prepare": 10, "audit": 11})

        published = subprocess.run(
            [
                sys.executable,
                "-B",
                str(MODULE_PATH),
                "--out",
                str(self.output),
                "--scheduler-receipt",
                str(self.scheduler_receipt),
                "--scheduler-receipt-sha256",
                sha256(self.scheduler_receipt.read_bytes()),
                *common_arguments,
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(published.returncode, 0, published.stderr)
        payload = json.loads(published.stdout)
        self.assertEqual(payload["scheduler_receipt"]["job_id"], 11)
        for kind in ("full", "official"):
            self.assertEqual(payload["analyses"][kind]["validated_process_exit"], 1)

    def test_non_ascii_two_shard_analyzer_to_finalizer_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_root = (Path(temporary) / "zażółć").resolve()
            run_root.mkdir()
            provenance = production_provenance(
                run_root, shards=2, receipt_sha256="0" * 64
            )
            reports = {
                kind: render_generated_sharded_analysis(run_root, kind)
                for kind in ("full", "official")
            }
            bindings: dict[str, dict[str, object]] = {}
            for kind, report in reports.items():
                expected_exit = 0 if report["promoted"] else 1
                validated = FINALIZER.validate_analysis_output(
                    run_root, kind, 2, expected_exit
                )
                self.assertEqual(validated["promoted"], report["promoted"])
                self.assertEqual(
                    len(validated["input_artifacts"]["shards"]), 2
                )
                bindings[kind] = {
                    "sha256": validated["analysis_sha256"],
                    "process_exit": expected_exit,
                }
            preparation_receipt = render_preparation_receipt(
                run_root, provenance, prepare_job=10, shards=2
            )
            preparation_sha256 = sha256(preparation_receipt.read_bytes())
            provenance = bind_preparation_receipt(
                provenance, preparation_sha256
            )
            scheduler_receipt = run_root / "audit" / "scheduler.json"
            FINALIZER.create_scheduler_receipt(
                scheduler_receipt,
                provenance,
                run_root,
                10,
                2,
                11,
                preparation_receipt,
                preparation_sha256,
                bindings,
            )
            output = run_root / "audit" / "index.json"
            payload = FINALIZER.finalize(
                output,
                provenance,
                run_root,
                10,
                2,
                11,
                preparation_receipt,
                preparation_sha256,
                scheduler_receipt,
                sha256(scheduler_receipt.read_bytes()),
                bindings,
            )
            self.assertIn("zażółć".encode(), scheduler_receipt.read_bytes())
            self.assertEqual(payload["shards"], 2)
            for kind in ("full", "official"):
                identity = payload["analyses"][kind]["input_artifacts"][
                    "parent_lock"
                ]["identity"]
                self.assertEqual(identity["campaign_id"], "locked-test")
                self.assertEqual(
                    identity["solver_binary_sha256"],
                    reports[kind]["input_hashes"]["solver_binary_sha256"],
                )

    def test_preparation_receipt_job_and_lock_hash_are_reopened(self) -> None:
        bindings = self.current_bindings()
        scheduler_sha256 = self.write_scheduler(bindings)
        original = json.loads(
            self.preparation_receipt.read_text(encoding="ascii")
        )
        mutations = (
            (
                "prepare-job",
                lambda value: value["job"].update({"id": 99}),
                "preparation receipt prepare job disagrees",
            ),
            (
                "parent-lock-hash",
                lambda value: value["artifacts"][
                    "locks/full-parent.json"
                ].update({"sha256": "d" * 64}),
                "preparation artifact locks/full-parent.json path or SHA-256 disagrees",
            ),
        )
        for name, mutate, diagnostic in mutations:
            with self.subTest(mutation=name):
                value = json.loads(json.dumps(original))
                mutate(value)
                self.preparation_receipt.chmod(0o600)
                self.preparation_receipt.write_bytes(
                    FINALIZER.canonical_json_bytes(value)
                )
                self.preparation_receipt.chmod(0o400)
                preparation_sha256 = sha256(
                    self.preparation_receipt.read_bytes()
                )
                provenance = bind_preparation_receipt(
                    self.provenance, preparation_sha256
                )
                with self.assertRaisesRegex(
                    FINALIZER.AuditFinalizeError, diagnostic
                ):
                    FINALIZER.finalize(
                        self.output,
                        provenance,
                        self.root,
                        10,
                        1,
                        11,
                        self.preparation_receipt,
                        preparation_sha256,
                        self.scheduler_receipt,
                        scheduler_sha256,
                        bindings,
                    )
                self.assertFalse(self.output.exists())

    def test_parent_repository_commit_must_match_preparation_revision(self) -> None:
        bindings = self.current_bindings()
        scheduler_sha256 = self.write_scheduler(bindings)
        receipt = json.loads(self.preparation_receipt.read_text(encoding="ascii"))
        receipt["revision"] = "d" * 40
        receipt["environment"]["EUF_VIPER_EXPECTED_REVISION"] = "d" * 40
        self.preparation_receipt.chmod(0o600)
        self.preparation_receipt.write_bytes(FINALIZER.canonical_json_bytes(receipt))
        self.preparation_receipt.chmod(0o400)
        provenance = json.loads(json.dumps(self.provenance))
        provenance["revision"] = "d" * 40
        provenance["environment"]["EUF_VIPER_EXPECTED_REVISION"] = "d" * 40
        preparation_sha256 = sha256(self.preparation_receipt.read_bytes())
        provenance = bind_preparation_receipt(provenance, preparation_sha256)
        with self.assertRaisesRegex(
            FINALIZER.AuditFinalizeError,
            "parent repository commit disagrees with provenance revision",
        ):
            FINALIZER.finalize(
                self.output,
                provenance,
                self.root,
                10,
                1,
                11,
                self.preparation_receipt,
                preparation_sha256,
                self.scheduler_receipt,
                scheduler_sha256,
                bindings,
            )
        self.assertFalse(self.output.exists())

    def test_scheduler_receipt_jobs_and_locks_must_match_current_audit(self) -> None:
        bindings = self.current_bindings()
        self.write_scheduler(bindings)
        original = json.loads(self.scheduler_receipt.read_text(encoding="ascii"))
        mutations = (
            (
                "audit-job",
                lambda value: value["jobs"].update({"audit": 12}),
            ),
            (
                "parent-lock",
                lambda value: value["parent_locks"]["official"].update(
                    {"file_sha256": "e" * 64}
                ),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(mutation=name):
                value = json.loads(json.dumps(original))
                mutate(value)
                self.scheduler_receipt.chmod(0o600)
                self.scheduler_receipt.write_bytes(
                    FINALIZER.canonical_json_bytes(value)
                )
                self.scheduler_receipt.chmod(0o400)
                with self.assertRaisesRegex(
                    FINALIZER.AuditFinalizeError,
                    "scheduler receipt disagrees with current jobs, locks, or analyses",
                ):
                    self.finalize(
                        validated_analyses=bindings,
                        write_scheduler=False,
                        scheduler_receipt_sha256=sha256(
                            self.scheduler_receipt.read_bytes()
                        ),
                    )
                self.assertFalse(self.output.exists())

    def test_realistic_rejected_analysis_binds_live_inputs_without_broadening_claims(self) -> None:
        payload = self.finalize()
        self.assertEqual(payload["schema"], FINALIZER.SCHEMA)
        self.assertEqual(payload["status"], "complete")
        stored = json.loads(self.output.read_text(encoding="ascii"))
        for kind in ("full", "official"):
            analysis_path = self.root / "audit" / kind / "global.json"
            binding = stored["analyses"][kind]
            metadata = analysis_path.stat()
            self.assertEqual(binding["inode"], metadata.st_ino)
            self.assertEqual(binding["device"], metadata.st_dev)
            self.assertEqual(binding["bytes"], metadata.st_size)
            self.assertFalse(binding["promoted"])
            self.assertEqual(binding["status"], "rejected")
            raw_binding = binding["input_artifacts"]["shards"][0]["raw"]
            raw_path = self.root / f"{kind}-2s" / "shard-0000" / "raw.jsonl"
            self.assertEqual(raw_binding["sha256"], sha256(raw_path.read_bytes()))
            limitation = self.analyses[kind]["comparisons"]["z3"]["budgets"]["2"][
                "statuses"
            ]["unsat"]
            self.assertEqual(limitation["candidate_result"], "unsupported")
            self.assertFalse(limitation["production_evidence_decisive"])
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o400)
        self.assertEqual(
            stored["preparation_receipt"]["sha256"],
            sha256(self.preparation_receipt.read_bytes()),
        )
        self.assertEqual(
            stored["scheduler_receipt"]["sha256"],
            sha256(self.scheduler_receipt.read_bytes()),
        )
        self.assertEqual(self.finalize(), payload)

    def test_analysis_schema_and_outcome_are_validated(self) -> None:
        target = self.root / "audit" / "full" / "global.json"
        value = json.loads(target.read_text(encoding="ascii"))
        value["schema_version"] = 2
        target.chmod(0o600)
        target.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="ascii")
        target.chmod(0o400)
        with self.assertRaisesRegex(FINALIZER.AuditFinalizeError, "schema version"):
            self.finalize()
        self.assertFalse(self.output.exists())

    def test_stale_analysis_cannot_bind_changed_raw_or_lock_bytes(self) -> None:
        raw_path = self.root / "full-2s" / "shard-0000" / "raw.jsonl"
        raw_path.write_bytes(raw_path.read_bytes() + b'{"retry":"new"}\n')
        with self.assertRaisesRegex(FINALIZER.AuditFinalizeError, "raw hash is stale"):
            self.finalize()
        self.assertFalse(self.output.exists())

        render_analysis(self.root, "full")
        parent = self.root / "locks" / "official-parent.json"
        parent.write_bytes(parent.read_bytes() + b" \n")
        with self.assertRaisesRegex(
            FINALIZER.AuditFinalizeError, "parent-lock file hash is stale"
        ):
            self.finalize()
        self.assertFalse(self.output.exists())

    def test_path_replacement_before_publish_is_rejected(self) -> None:
        target = self.root / "audit" / "full" / "global.json"

        def replace() -> None:
            raw = target.read_bytes()
            target.unlink()
            target.write_bytes(raw)
            target.chmod(0o400)

        with self.assertRaisesRegex(
            FINALIZER.AuditFinalizeError, "no longer names descriptor"
        ):
            self.finalize(pre_publish_hook=replace)
        self.assertFalse(self.output.exists())

    def test_path_replacement_at_link_boundary_rolls_back_index(self) -> None:
        bindings = self.current_bindings()
        scheduler_sha256 = self.write_scheduler(bindings)
        target = self.root / "audit" / "full" / "global.json"
        strict_os = FINALIZER.atomic_write_nofollow.__globals__["os"]
        real_link = strict_os.link
        replaced = False

        def replace_then_link(*args: object, **kwargs: object) -> None:
            nonlocal replaced
            if not replaced:
                replaced = True
                target.unlink()
                target.write_bytes(b'{"replaced":true}\n')
                target.chmod(0o400)
            real_link(*args, **kwargs)

        with mock.patch.object(strict_os, "link", side_effect=replace_then_link):
            with self.assertRaisesRegex(
                FINALIZER.AuditFinalizeError, "no longer names descriptor"
            ):
                self.finalize(
                    validated_analyses=bindings,
                    write_scheduler=False,
                    scheduler_receipt_sha256=scheduler_sha256,
                )
        self.assertTrue(replaced)
        self.assertFalse(self.output.exists())
        self.assertEqual(target.read_bytes(), b'{"replaced":true}\n')

    def test_in_place_analysis_mutation_before_publish_is_rejected(self) -> None:
        target = self.root / "audit" / "official" / "global.json"

        def mutate() -> None:
            target.chmod(0o600)
            target.write_bytes(target.read_bytes() + b" \n")

        with self.assertRaisesRegex(
            FINALIZER.AuditFinalizeError, "changed before index publication"
        ):
            self.finalize(pre_publish_hook=mutate)
        self.assertFalse(self.output.exists())

    def test_in_place_raw_mutation_before_publish_is_rejected(self) -> None:
        target = self.root / "official-2s" / "shard-0000" / "raw.jsonl"

        def mutate() -> None:
            target.write_bytes(target.read_bytes() + b'{"retry":"raced"}\n')

        with self.assertRaisesRegex(
            FINALIZER.AuditFinalizeError, "changed before index publication"
        ):
            self.finalize(pre_publish_hook=mutate)
        self.assertFalse(self.output.exists())

    def test_concurrent_no_replace_publication_never_mixes_indices(self) -> None:
        outcomes: list[str] = []

        def worker() -> None:
            try:
                self.finalize()
            except FINALIZER.AuditFinalizeError:
                outcomes.append("rejected")
            else:
                outcomes.append("published")

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertIn("published", outcomes)
        self.assertEqual(len(outcomes), 2)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o400)


if __name__ == "__main__":
    unittest.main()
