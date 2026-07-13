from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "typed_parser_parity.py"
SPEC = importlib.util.spec_from_file_location("typed_parser_parity", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PARITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PARITY)


FAKE_BINARY = """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

if os.environ.get("EUF_VIPER_SCOPED_LET") != "auto":
    raise SystemExit("scoped-let parser environment drift")
if os.environ.get("EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT") != "1024":
    raise SystemExit("preprocess-limit parser environment drift")
if "EUF_VIPER_PROFILE" in os.environ:
    raise SystemExit("profile parser environment drift")
source = Path(sys.argv[-1]).read_text(encoding="utf-8")
if "MISMATCH" in source:
    print("typed parser semantic mismatch", file=sys.stderr)
    raise SystemExit(2)
payload = {
    "schema": "euf-viper.typed-parser-parity.v1",
    "status": "match",
    "tree_well_sorted": True,
    "stream_well_sorted": True,
    "fallback": "FALLBACK" in source,
}
print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
"""


class TypedParserParityFixture:
    def __init__(self, temporary: str, sources: list[str]) -> None:
        self.root = Path(temporary)
        self.repository = self.root / "repository"
        self.corpus = self.repository / "corpus" / "family"
        self.corpus.mkdir(parents=True)
        self.binary = self.root / "fake-euf-viper"
        self.binary.write_text(FAKE_BINARY, encoding="utf-8")
        self.binary.chmod(0o755)
        self.manifest = self.repository / "manifest.jsonl"
        rows = []
        for index, source in enumerate(sources):
            path = self.corpus / f"case-{index}.smt2"
            path.write_text(source, encoding="utf-8")
            raw = path.read_bytes()
            rows.append(
                {
                    "id": index,
                    "path": str(path.relative_to(self.repository)),
                    "relative_path": f"corpus/family/case-{index}.smt2",
                    "bytes": len(raw),
                    "sha256": PARITY.sha256_bytes(raw),
                }
            )
        self.manifest.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        self.revision = "a" * 40
        self.output = self.root / "campaign"

    def prepare(self, *, output: Path | None = None) -> Path:
        output = output or self.output
        PARITY.prepare_campaign(
            Namespace(
                revision=self.revision,
                repository_root=self.repository,
                manifest=self.manifest,
                binary=self.binary,
                expected_sources=len(list(self.corpus.glob("*.smt2"))),
                shards=2,
                timeout_seconds=5,
                output_root=output,
            )
        )
        return output

    def run_all_shards(self, root: Path | None = None) -> None:
        root = root or self.output
        for shard in range(2):
            PARITY.run_shard(
                Namespace(root=root, revision=self.revision, shard=shard)
            )


class TypedParserParityTests(unittest.TestCase):
    def setUp(self) -> None:
        environment = patch.dict(
            os.environ,
            {
                "EUF_VIPER_SCOPED_LET": "auto",
                "EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT": "1024",
            },
            clear=False,
        )
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop("EUF_VIPER_PROFILE", None)

    def test_complete_campaign_passes_and_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary,
                [
                    "(set-logic QF_UF) (assert true) (check-sat)\n",
                    "(set-logic QF_UF) (assert false) (check-sat)\n",
                    "(set-logic QF_UF) (declare-fun p () Bool) (assert p)\n",
                ],
            )
            first = fixture.prepare()
            second = fixture.prepare(output=fixture.root / "campaign-copy")
            self.assertEqual(
                (first / "workset.jsonl").read_bytes(),
                (second / "workset.jsonl").read_bytes(),
            )
            fixture.run_all_shards()
            self.assertTrue(
                PARITY.audit_campaign(
                    Namespace(
                        root=first,
                        revision=fixture.revision,
                        expected_sources=3,
                    )
                )
            )
            audit = json.loads((first / "audit.json").read_text(encoding="ascii"))
            prepare = json.loads(
                (first / "prepare.json").read_text(encoding="ascii")
            )
            records = [
                json.loads(line)
                for line in (first / "records.jsonl")
                .read_text(encoding="ascii")
                .splitlines()
            ]
            self.assertEqual(prepare["parser_environment"], PARITY.PARSER_ENVIRONMENT)
            self.assertEqual(audit["parser_environment"], PARITY.PARSER_ENVIRONMENT)
            self.assertTrue(
                all(
                    record["parser_environment"] == PARITY.PARSER_ENVIRONMENT
                    for record in records
                )
            )
            self.assertEqual(
                audit["counts"],
                {"match": 3, "fallback": 0, "mismatch": 0, "error": 0},
            )
            self.assertTrue(audit["gate"]["passed"])

    def test_prepare_rejects_ambient_parser_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary, ["(set-logic QF_UF) (assert true)\n"]
            )
            cases = (
                ({"EUF_VIPER_SCOPED_LET": "legacy"}, "SCOPED_LET"),
                (
                    {"EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT": "4096"},
                    "PREPROCESS_TERM_LIMIT",
                ),
                ({"EUF_VIPER_PROFILE": ""}, "PROFILE"),
            )
            for index, (override, diagnostic) in enumerate(cases):
                with self.subTest(override=override), patch.dict(
                    os.environ, override, clear=False
                ):
                    with self.assertRaisesRegex(
                        PARITY.CampaignError, diagnostic
                    ):
                        fixture.prepare(output=fixture.root / f"rejected-{index}")

    def test_shard_and_audit_reject_ambient_parser_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary, ["(set-logic QF_UF) (assert true)\n"]
            )
            fixture.prepare()
            with patch.dict(
                os.environ, {"EUF_VIPER_SCOPED_LET": "legacy"}, clear=False
            ), self.assertRaisesRegex(PARITY.CampaignError, "SCOPED_LET"):
                PARITY.run_shard(
                    Namespace(root=fixture.output, revision=fixture.revision, shard=0)
                )

            fixture.run_all_shards()
            with patch.dict(
                os.environ,
                {"EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT": "4096"},
                clear=False,
            ), self.assertRaisesRegex(PARITY.CampaignError, "PREPROCESS_TERM_LIMIT"):
                PARITY.audit_campaign(
                    Namespace(
                        root=fixture.output,
                        revision=fixture.revision,
                        expected_sources=1,
                    )
                )

    def test_prepared_parser_environment_tampering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary, ["(set-logic QF_UF) (assert true)\n"]
            )
            fixture.prepare()
            path = fixture.output / "prepare.json"
            payload = json.loads(path.read_text(encoding="ascii"))
            payload["parser_environment"]["EUF_VIPER_SCOPED_LET"] = "legacy"
            path.write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                PARITY.CampaignError, "environment contract mismatch"
            ):
                PARITY.run_shard(
                    Namespace(root=fixture.output, revision=fixture.revision, shard=0)
                )

    def test_shard_parser_environment_tampering_fails_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary, ["(set-logic QF_UF) (assert true)\n"]
            )
            fixture.prepare()
            fixture.run_all_shards()
            path = fixture.output / "shards" / "shard-00000.jsonl"
            record = json.loads(path.read_text(encoding="ascii"))
            record["parser_environment"]["EUF_VIPER_PROFILE"] = "ambient"
            path.write_text(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                PARITY.CampaignError, "parser environment drift"
            ):
                PARITY.audit_campaign(
                    Namespace(
                        root=fixture.output,
                        revision=fixture.revision,
                        expected_sources=1,
                    )
                )

    def test_fallback_is_recorded_and_rejects_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary,
                ["(set-logic QF_UF) ; FALLBACK\n(assert true)\n"],
            )
            fixture.prepare()
            fixture.run_all_shards()
            self.assertFalse(
                PARITY.audit_campaign(
                    Namespace(
                        root=fixture.output,
                        revision=fixture.revision,
                        expected_sources=1,
                    )
                )
            )
            audit = json.loads(
                (fixture.output / "audit.json").read_text(encoding="ascii")
            )
            self.assertEqual(audit["counts"]["fallback"], 1)
            self.assertEqual(audit["status"], "rejected")

    def test_semantic_mismatch_is_separate_from_generic_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary,
                ["(set-logic QF_UF) ; MISMATCH\n(assert true)\n"],
            )
            fixture.prepare()
            fixture.run_all_shards()
            self.assertFalse(
                PARITY.audit_campaign(
                    Namespace(
                        root=fixture.output,
                        revision=fixture.revision,
                        expected_sources=1,
                    )
                )
            )
            audit = json.loads(
                (fixture.output / "audit.json").read_text(encoding="ascii")
            )
            self.assertEqual(audit["counts"]["mismatch"], 1)
            shard_rows = [
                line
                for path in sorted((fixture.output / "shards").glob("*.jsonl"))
                for line in path.read_text(encoding="ascii").splitlines()
            ]
            record = json.loads(shard_rows[0])
            self.assertIn("semantic mismatch", record["stderr_excerpt"])

    def test_source_mutation_after_prepare_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary, ["(set-logic QF_UF) (assert true)\n"]
            )
            fixture.prepare()
            source = next(fixture.corpus.glob("*.smt2"))
            source.write_text("(assert false)\n", encoding="utf-8")
            fixture.run_all_shards()
            records = []
            for shard in range(2):
                path = fixture.output / "shards" / f"shard-{shard:05d}.jsonl"
                records.extend(
                    json.loads(line)
                    for line in path.read_text(encoding="ascii").splitlines()
                )
            self.assertEqual(records[0]["status"], "error")
            self.assertEqual(records[0]["reason"], "source hash changed after prepare")

    def test_manifest_hash_and_path_traversal_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary, ["(set-logic QF_UF) (assert true)\n"]
            )
            row = json.loads(fixture.manifest.read_text(encoding="utf-8"))
            row["sha256"] = "0" * 64
            fixture.manifest.write_text(json.dumps(row) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(PARITY.CampaignError, "source hash mismatch"):
                fixture.prepare()

            row["sha256"] = PARITY.sha256_file(next(fixture.corpus.glob("*.smt2")))
            row["relative_path"] = "../escape.smt2"
            fixture.manifest.write_text(json.dumps(row) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(PARITY.CampaignError, "unsafe relative_path"):
                fixture.prepare()

    def test_missing_shard_and_revision_drift_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary, ["(set-logic QF_UF) (assert true)\n"]
            )
            fixture.prepare()
            with self.assertRaisesRegex(PARITY.CampaignError, "revision"):
                PARITY.run_shard(
                    Namespace(root=fixture.output, revision="b" * 40, shard=0)
                )
            PARITY.run_shard(
                Namespace(root=fixture.output, revision=fixture.revision, shard=0)
            )
            with self.assertRaisesRegex(PARITY.CampaignError, "cannot read"):
                PARITY.audit_campaign(
                    Namespace(
                        root=fixture.output,
                        revision=fixture.revision,
                        expected_sources=1,
                    )
                )


if __name__ == "__main__":
    unittest.main()
