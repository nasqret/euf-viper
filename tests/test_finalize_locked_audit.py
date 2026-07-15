from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path


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


def lock_bytes(**fields: object) -> tuple[bytes, str]:
    value = {**fields, "lock_sha256": ""}
    value["lock_sha256"] = sha256(FINALIZER._canonical_analysis_bytes(value))
    return FINALIZER._canonical_analysis_bytes(value), value["lock_sha256"]


def render_analysis(root: Path, kind: str) -> dict[str, object]:
    parent_path = root / "locks" / f"{kind}-parent.json"
    shard_lock_path = root / "locks" / kind / "bound-0000.json"
    shard_raw_path = root / f"{kind}-2s" / "shard-0000" / "raw.jsonl"
    parent_path.parent.mkdir(parents=True, exist_ok=True)
    shard_lock_path.parent.mkdir(parents=True, exist_ok=True)
    shard_raw_path.parent.mkdir(parents=True, exist_ok=True)

    parent_raw, parent_lock_sha256 = lock_bytes(
        campaign_id=f"production-p0-{kind}", schema_version=1
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
    analysis_path = root / "audit" / kind / "global.json"
    analysis_path.parent.mkdir(parents=True, exist_ok=True)
    if analysis_path.exists():
        analysis_path.chmod(0o600)
    analysis_path.write_text(
        json.dumps(analysis, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    analysis_path.chmod(0o400)
    return analysis


class FinalizeLockedAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.analyses = {
            kind: render_analysis(self.root, kind) for kind in ("full", "official")
        }
        self.output = self.root / "audit" / "index.json"
        self.provenance = {
            "attempt": "attempt-1",
            "environment": {"kind": "test"},
            "manifest_sha256": "1" * 64,
            "revision": "2" * 40,
            "source_blob_count": 3,
            "source_blobs_sha256": "4" * 64,
            "source_tree": "5" * 40,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def finalize(self, **kwargs: object) -> dict[str, object]:
        return FINALIZER.finalize(
            self.output,
            self.provenance,
            self.root,
            10,
            1,
            11,
            {"status": "accepted"},
            **kwargs,
        )

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
        self.assertIn("analysis completed with statistical rejection", text)
        self.assertIn("analysis rejected its lock/raw input", text)
        self.assertIn("analysis could not publish its output", text)
        self.assertIn("exit 2", text)
        self.assertIn("exit 3", text)

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
