from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import platform
import subprocess
import sys
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
TEST_PYTHON = Path(sys.executable).resolve(strict=True)
TEST_PYTHON_SHA256 = PARITY.sha256_file(TEST_PYTHON)
TEST_PYTHON_VERSION = f"Python {platform.python_version()}"


FAKE_BINARY = """#!/usr/bin/env python3
import hashlib
import json
import os
import sys

if os.environ.get("EUF_VIPER_SCOPED_LET") != "auto":
    raise SystemExit("scoped-let parser environment drift")
if os.environ.get("EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT") != "1024":
    raise SystemExit("preprocess-limit parser environment drift")
if "EUF_VIPER_PROFILE" in os.environ:
    raise SystemExit("profile parser environment drift")
if sys.argv[1:] != ["parse-check", "-"]:
    raise SystemExit(f"unexpected parser invocation: {sys.argv[1:]!r}")
source_bytes = sys.stdin.buffer.read()
source = source_bytes.decode("utf-8")
if "MISMATCH" in source:
    print("typed parser semantic mismatch", file=sys.stderr)
    raise SystemExit(2)
if "DEPTH" in source:
    print(
        "stream parser rejected tree-accepted input: "
        "SMT-LIB nesting exceeds parser safety limit",
        file=sys.stderr,
    )
    raise SystemExit(2)
payload = {
    "schema": "euf-viper.typed-parser-parity.v1",
    "status": "match",
    "tree_well_sorted": True,
    "stream_well_sorted": True,
    "fallback": "FALLBACK" in source,
    "snapshot_fnv1a64": hashlib.sha256(source_bytes).hexdigest()[:16],
    "symbols": 0,
    "sorts": 0,
    "functions": 0,
    "terms": 0,
    "applications": 0,
    "assertions": 0,
    "bool_data_terms": 0,
    "unsupported_diagnostics": 0,
}
print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
"""


def valid_parser_payload(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": PARITY.PARSER_SCHEMA,
        "status": "match",
        "tree_well_sorted": True,
        "stream_well_sorted": True,
        "fallback": False,
        "snapshot_fnv1a64": "0123456789abcdef",
        "symbols": 0,
        "sorts": 0,
        "functions": 0,
        "terms": 0,
        "applications": 0,
        "assertions": 0,
        "bool_data_terms": 0,
        "unsupported_diagnostics": 0,
    }
    payload.update(updates)
    return payload


def parser_stdout(payload: object) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


def replace_json_field(
    content: bytes, key: str, value: object, replacement: bytes
) -> bytes:
    encoded = json.dumps(
        value, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    token = json.dumps(key).encode("ascii") + b":" + encoded
    if content.count(token) != 1:
        raise AssertionError(f"expected one {key!r} token, found {content.count(token)}")
    return content.replace(token, replacement, 1)


def duplicate_json_field(content: bytes, key: str, value: object) -> bytes:
    encoded = json.dumps(
        value, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    token = json.dumps(key).encode("ascii") + b":" + encoded
    return replace_json_field(content, key, value, token + b"," + token)


def nonfinite_json_field(content: bytes, key: str, value: object) -> bytes:
    return replace_json_field(
        content, key, value, json.dumps(key).encode("ascii") + b":NaN"
    )


class TypedParserParityFixture:
    def __init__(self, temporary: str, sources: list[str]) -> None:
        self.root = Path(temporary)
        self.repository = self.root / "repository"
        self.corpus = self.repository / "corpus" / "family"
        self.corpus.mkdir(parents=True)
        self.binary = self.root / "fake-euf-viper"
        self.binary.write_text(FAKE_BINARY, encoding="utf-8")
        self.binary.chmod(0o755)
        self.preflight = self.repository / "preflight.smt2"
        self.preflight.write_text(
            "(set-logic QF_UF) (assert true) (check-sat)\n", encoding="utf-8"
        )
        self.manifest = self.repository / "manifest.jsonl"
        rows = []
        for index, source in enumerate(sources):
            path = self.corpus / f"case-{index}.smt2"
            path.write_text(source, encoding="utf-8")
            raw = path.read_bytes()
            rows.append(
                {
                    "archive_md5": "0" * 32,
                    "bytes": len(raw),
                    "id": index,
                    "logic": "QF_UF",
                    "path": str(path.relative_to(self.repository)),
                    "relative_path": f"corpus/family/case-{index}.smt2",
                    "sha256": PARITY.sha256_bytes(raw),
                    "source_doi": "10.0000/test",
                    "source_url": "https://example.invalid/qf-uf",
                    "status": "sat",
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
                preflight_source=self.preflight,
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
                "EUF_VIPER_PYTHON": str(TEST_PYTHON),
                "EUF_VIPER_PYTHON_SHA256": TEST_PYTHON_SHA256,
                "EUF_VIPER_PYTHON_VERSION": TEST_PYTHON_VERSION,
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
            self.assertEqual(prepare["python"], audit["python"])
            self.assertEqual(
                prepare["python"],
                {
                    "path": str(TEST_PYTHON),
                    "sha256": TEST_PYTHON_SHA256,
                    "version": TEST_PYTHON_VERSION,
                },
            )
            self.assertTrue(
                all(
                    record["parser_environment"] == PARITY.PARSER_ENVIRONMENT
                    and record["python"] == prepare["python"]
                    for record in records
                )
            )
            self.assertEqual(
                audit["counts"],
                {"match": 3, "fallback": 0, "mismatch": 0, "error": 0},
            )
            self.assertTrue(audit["gate"]["passed"])
            self.assertEqual(audit["byte_binding"], PARITY.BYTE_BINDING)
            audit_bytes = (first / "audit.json").read_bytes()
            self.assertEqual(
                (first / "audit-sha256.txt").read_text(encoding="ascii"),
                f"{PARITY.sha256_bytes(audit_bytes)}  audit.json\n",
            )

    def test_source_hash_and_parser_stdin_share_one_captured_buffer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary, ["(set-logic QF_UF) (assert true)\n"]
            )
            fixture.prepare()
            source = next(fixture.corpus.glob("*.smt2")).resolve()
            original = source.read_bytes()
            replacement = b"(set-logic QF_UF) (assert false)\n"
            source_reads = 0
            parser_input: bytes | None = None
            original_read_bytes = Path.read_bytes

            def counted_read_bytes(path: Path) -> bytes:
                nonlocal source_reads
                content = original_read_bytes(path)
                if path == source:
                    source_reads += 1
                return content

            def racing_parser(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                nonlocal parser_input
                self.assertEqual(command[-2:], ["parse-check", "-"])
                parser_input = kwargs["input"]  # type: ignore[assignment]
                self.assertIsInstance(parser_input, bytes)
                source.write_bytes(replacement)
                payload = valid_parser_payload(
                    snapshot_fnv1a64=hashlib.sha256(parser_input).hexdigest()[:16]
                )
                return subprocess.CompletedProcess(
                    command, 0, stdout=parser_stdout(payload), stderr=b""
                )

            with patch.object(Path, "read_bytes", counted_read_bytes), patch.object(
                PARITY.subprocess, "run", racing_parser
            ):
                PARITY.run_shard(
                    Namespace(root=fixture.output, revision=fixture.revision, shard=0)
                )

            self.assertEqual(source_reads, 1)
            self.assertEqual(parser_input, original)
            self.assertEqual(source.read_bytes(), replacement)
            record = json.loads(
                (fixture.output / "shards" / "shard-00000.jsonl").read_text(
                    encoding="ascii"
                )
            )
            self.assertEqual(record["status"], "match")
            self.assertEqual(record["opened_source_sha256"], PARITY.sha256_bytes(original))
            self.assertEqual(record["opened_source_bytes"], len(original))

    def test_bound_artifacts_are_parsed_and_hashed_from_one_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary, ["(set-logic QF_UF) (assert true)\n"]
            )
            fixture.prepare()
            path = fixture.output / "prepare.json"
            original = path.read_bytes()
            replacement_value = json.loads(original)
            replacement_value["timeout_seconds"] += 1
            replacement = PARITY.canonical_bytes(replacement_value)
            reads = 0
            original_read_bytes = Path.read_bytes

            def racing_read_bytes(candidate: Path) -> bytes:
                nonlocal reads
                content = original_read_bytes(candidate)
                if candidate == path:
                    reads += 1
                    candidate.write_bytes(replacement)
                return content

            with patch.object(Path, "read_bytes", racing_read_bytes):
                value, artifact = PARITY.load_object(
                    path, schema=PARITY.PREPARE_SCHEMA
                )

            self.assertEqual(reads, 1)
            self.assertEqual(value["timeout_seconds"], 5)
            self.assertEqual(artifact.content, original)
            self.assertEqual(artifact.sha256, PARITY.sha256_bytes(original))
            self.assertEqual(path.read_bytes(), replacement)

    def test_same_size_parser_path_replacement_cannot_forge_a_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary, ["(set-logic QF_UF) (assert true)\n"]
            )
            fixture.prepare()
            original = fixture.binary.read_bytes()
            original_sha256 = PARITY.sha256_bytes(original)
            replacement_prefix = (
                b"#!/usr/bin/env python3\n"
                b"import sys\n"
                b"print('replacement executable ran', file=sys.stderr)\n"
                b"raise SystemExit(91)\n#"
            )
            self.assertLess(len(replacement_prefix), len(original))
            replacement = replacement_prefix + b"x" * (
                len(original) - len(replacement_prefix)
            )
            replacement_path = fixture.root / "replacement-parser"
            replacement_path.write_bytes(replacement)
            replacement_path.chmod(0o755)
            original_execute = PARITY.execute_parser
            replaced = False

            def replace_then_execute(
                executable: PARITY.OpenedExecutable,
                source: bytes,
                timeout_seconds: int,
            ) -> PARITY.ParserExecution:
                nonlocal replaced
                if not replaced:
                    os.replace(replacement_path, fixture.binary)
                    replaced = True
                return original_execute(executable, source, timeout_seconds)

            with patch.object(PARITY, "execute_parser", replace_then_execute):
                PARITY.run_shard(
                    Namespace(
                        root=fixture.output, revision=fixture.revision, shard=0
                    )
                )

            self.assertTrue(replaced)
            self.assertEqual(len(fixture.binary.read_bytes()), len(original))
            self.assertNotEqual(PARITY.sha256_file(fixture.binary), original_sha256)
            record = json.loads(
                (fixture.output / "shards" / "shard-00000.jsonl").read_text(
                    encoding="ascii"
                )
            )
            self.assertEqual(record["status"], "match")
            self.assertEqual(record["binary"]["sha256"], original_sha256)

    def test_prepare_hashes_generated_workset_without_reopening_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary, ["(set-logic QF_UF) (assert true)\n"]
            )
            original_sha256_file = PARITY.sha256_file

            def reject_workset_reopen(path: Path) -> str:
                if path.name == "workset.jsonl":
                    self.fail("prepare reopened its generated workset")
                return original_sha256_file(path)

            with patch.object(PARITY, "sha256_file", reject_workset_reopen):
                fixture.prepare()

            prepare = json.loads(
                (fixture.output / "prepare.json").read_text(encoding="ascii")
            )
            workset = (fixture.output / "workset.jsonl").read_bytes()
            self.assertEqual(prepare["workset"]["sha256"], PARITY.sha256_bytes(workset))

    def test_audit_reads_each_bound_input_artifact_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary,
                [
                    "(set-logic QF_UF) (assert true)\n",
                    "(set-logic QF_UF) (assert false)\n",
                ],
            )
            fixture.prepare()
            fixture.run_all_shards()
            watched = {
                (fixture.output / "prepare.json").resolve(),
                (fixture.output / "workset.jsonl").resolve(),
                (fixture.output / "shards" / "shard-00000.jsonl").resolve(),
                (fixture.output / "shards" / "shard-00001.jsonl").resolve(),
            }
            reads = {path: 0 for path in watched}
            original_read_bytes = Path.read_bytes
            original_sha256_file = PARITY.sha256_file

            def counted_read_bytes(path: Path) -> bytes:
                if path in reads:
                    reads[path] += 1
                return original_read_bytes(path)

            def reject_bound_artifact_reopen(path: Path) -> str:
                if path in watched or path.name == "records.jsonl":
                    self.fail(f"audit reopened a bound artifact: {path}")
                return original_sha256_file(path)

            with patch.object(Path, "read_bytes", counted_read_bytes), patch.object(
                PARITY, "sha256_file", reject_bound_artifact_reopen
            ):
                self.assertTrue(
                    PARITY.audit_campaign(
                        Namespace(
                            root=fixture.output,
                            revision=fixture.revision,
                            expected_sources=2,
                        )
                    )
                )

            self.assertEqual(set(reads.values()), {1})

    def test_parser_payload_requires_exact_keys_and_types(self) -> None:
        payload, error = PARITY.parser_payload(parser_stdout(valid_parser_payload()))
        self.assertIsNotNone(payload)
        self.assertIsNone(error)

        missing = valid_parser_payload()
        missing.pop("terms")
        cases: list[tuple[str, bytes]] = [
            ("malformed", b"{not-json}\n"),
            ("missing line feed", parser_stdout(valid_parser_payload()).rstrip(b"\n")),
            ("extra blank line", b"\n" + parser_stdout(valid_parser_payload())),
            ("carriage return", parser_stdout(valid_parser_payload()).replace(b"\n", b"\r\n")),
            ("partial", parser_stdout(missing)),
            ("extra", parser_stdout(valid_parser_payload(extra=0))),
            (
                "uppercase fingerprint",
                parser_stdout(valid_parser_payload(snapshot_fnv1a64="0123456789ABCDEf")),
            ),
            (
                "short fingerprint",
                parser_stdout(valid_parser_payload(snapshot_fnv1a64="0123")),
            ),
            ("boolean count", parser_stdout(valid_parser_payload(terms=True))),
            ("negative count", parser_stdout(valid_parser_payload(terms=-1))),
            ("float count", parser_stdout(valid_parser_payload(terms=1.0))),
            (
                "integer boolean",
                parser_stdout(valid_parser_payload(tree_well_sorted=1)),
            ),
            (
                "duplicate key",
                duplicate_json_field(
                    parser_stdout(valid_parser_payload()), "terms", 0
                ),
            ),
            (
                "non-finite count",
                nonfinite_json_field(
                    parser_stdout(valid_parser_payload()), "terms", 0
                ),
            ),
        ]
        for label, stdout in cases:
            with self.subTest(label=label):
                parsed, diagnostic = PARITY.parser_payload(stdout)
                self.assertIsNone(parsed)
                self.assertIsNotNone(diagnostic)

    def test_campaign_artifact_boundaries_reject_duplicates_and_nonfinite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary, ["(set-logic QF_UF) (assert true)\n"]
            )
            fixture.prepare()
            fixture.run_all_shards()
            self.assertTrue(
                PARITY.audit_campaign(
                    Namespace(
                        root=fixture.output,
                        revision=fixture.revision,
                        expected_sources=1,
                    )
                )
            )

            boundaries = (
                (
                    "prepare",
                    fixture.output / "prepare.json",
                    PARITY.PREPARE_SCHEMA,
                    PARITY.load_object,
                    "timeout_seconds",
                ),
                (
                    "workset",
                    fixture.output / "workset.jsonl",
                    PARITY.WORK_SCHEMA,
                    PARITY.load_jsonl,
                    "manifest_line",
                ),
                (
                    "shard",
                    fixture.output / "shards" / "shard-00000.jsonl",
                    PARITY.RECORD_SCHEMA,
                    PARITY.load_jsonl,
                    "exit_code",
                ),
                (
                    "records",
                    fixture.output / "records.jsonl",
                    PARITY.RECORD_SCHEMA,
                    PARITY.load_jsonl,
                    "elapsed_seconds",
                ),
                (
                    "audit",
                    fixture.output / "audit.json",
                    PARITY.AUDIT_SCHEMA,
                    PARITY.load_object,
                    "source_count",
                ),
            )
            for label, path, schema, loader, field in boundaries:
                original = path.read_bytes()
                value = json.loads(original.splitlines()[0])[field]
                mutations = (
                    ("duplicate", duplicate_json_field(original, field, value)),
                    ("nonfinite", nonfinite_json_field(original, field, value)),
                )
                for mutation, content in mutations:
                    with self.subTest(boundary=label, mutation=mutation):
                        path.write_bytes(content)
                        with self.assertRaisesRegex(
                            PARITY.CampaignError,
                            "duplicate JSON key|non-finite JSON number",
                        ):
                            loader(path, schema=schema)
                        path.write_bytes(original)

    def test_strict_serialization_rejects_nonfinite_values(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaisesRegex(
                PARITY.CampaignError, "strict JSON"
            ):
                PARITY.canonical_bytes({"value": value})

        for token in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(token=token), self.assertRaisesRegex(
                PARITY.CampaignError, "non-finite JSON number"
            ):
                PARITY.strict_json(f'{{"value":{token}}}', where="test")

    def test_every_record_status_has_strict_exit_and_timing_types(self) -> None:
        cases = (
            ("match", "(set-logic QF_UF) (assert true)\n"),
            ("fallback", "(set-logic QF_UF) ; FALLBACK\n(assert true)\n"),
            ("mismatch", "(set-logic QF_UF) ; MISMATCH\n(assert true)\n"),
            ("error", "(set-logic QF_UF) ; DEPTH\n(assert true)\n"),
        )
        for expected_status, source in cases:
            with self.subTest(status=expected_status), tempfile.TemporaryDirectory() as temporary:
                fixture = TypedParserParityFixture(temporary, [source])
                fixture.prepare()
                PARITY.run_shard(
                    Namespace(
                        root=fixture.output,
                        revision=fixture.revision,
                        shard=0,
                    )
                )
                record = json.loads(
                    (fixture.output / "shards" / "shard-00000.jsonl").read_text(
                        encoding="ascii"
                    )
                )
                self.assertEqual(record["status"], expected_status)
                PARITY.validate_record_row(record, where="valid status row")
                for field, invalid in (
                    ("exit_code", True),
                    ("elapsed_seconds", 0),
                ):
                    malformed = dict(record)
                    malformed[field] = invalid
                    with self.assertRaises(PARITY.CampaignError):
                        PARITY.validate_record_row(
                            malformed, where=f"invalid {expected_status} row"
                        )
                extra = dict(record)
                extra["unexpected"] = None
                with self.assertRaisesRegex(PARITY.CampaignError, "fields differ"):
                    PARITY.validate_record_row(extra, where="extra record field")

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

    def test_prepare_rejects_unpinned_or_drifting_python(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary, ["(set-logic QF_UF) (assert true)\n"]
            )
            cases = (
                ({"EUF_VIPER_PYTHON": "python3"}, "absolute path"),
                ({"EUF_VIPER_PYTHON_SHA256": "0" * 63}, "lowercase SHA-256"),
                ({"EUF_VIPER_PYTHON_SHA256": "0" * 64}, "hash mismatch"),
                ({"EUF_VIPER_PYTHON_VERSION": "3.0"}, "malformed"),
                ({"EUF_VIPER_PYTHON_VERSION": "Python 0.0.0"}, "version mismatch"),
            )
            for index, (override, diagnostic) in enumerate(cases):
                with self.subTest(override=override), patch.dict(
                    os.environ, override, clear=False
                ), self.assertRaisesRegex(PARITY.CampaignError, diagnostic):
                    fixture.prepare(output=fixture.root / f"python-rejected-{index}")

    def test_python_symlink_alias_and_target_hash_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            alias = Path(temporary) / "python-alias"
            alias.symlink_to(TEST_PYTHON)
            with patch.dict(
                os.environ, {"EUF_VIPER_PYTHON": str(alias)}, clear=False
            ), self.assertRaisesRegex(PARITY.CampaignError, "canonical realpath"):
                PARITY.validate_python_identity()

            original_sha256_file = PARITY.sha256_file

            def target_drift(path: Path) -> str:
                if path.resolve(strict=True) == TEST_PYTHON:
                    return "f" * 64
                return original_sha256_file(path)

            with patch.object(PARITY, "sha256_file", target_drift), self.assertRaisesRegex(
                PARITY.CampaignError, "hash mismatch"
            ):
                PARITY.validate_python_identity()

    def test_shard_and_audit_reject_python_identity_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary, ["(set-logic QF_UF) (assert true)\n"]
            )
            fixture.prepare()
            with patch.dict(
                os.environ, {"EUF_VIPER_PYTHON_SHA256": "0" * 64}, clear=False
            ), self.assertRaisesRegex(PARITY.CampaignError, "hash mismatch"):
                PARITY.run_shard(
                    Namespace(root=fixture.output, revision=fixture.revision, shard=0)
                )

            fixture.run_all_shards()
            with patch.dict(
                os.environ,
                {"EUF_VIPER_PYTHON_VERSION": "Python 0.0.0"},
                clear=False,
            ), self.assertRaisesRegex(PARITY.CampaignError, "version mismatch"):
                PARITY.audit_campaign(
                    Namespace(
                        root=fixture.output,
                        revision=fixture.revision,
                        expected_sources=1,
                    )
                )

    def test_prepared_python_identity_tampering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary, ["(set-logic QF_UF) (assert true)\n"]
            )
            fixture.prepare()
            path = fixture.output / "prepare.json"
            payload = json.loads(path.read_text(encoding="ascii"))
            payload["python"]["version"] = "Python 0.0.0"
            path.write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                PARITY.CampaignError, "python identity contract mismatch"
            ):
                PARITY.run_shard(
                    Namespace(root=fixture.output, revision=fixture.revision, shard=0)
                )

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
                PARITY.CampaignError, "invalid parser setting"
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
                PARITY.CampaignError, "invalid parser setting"
            ):
                PARITY.audit_campaign(
                    Namespace(
                        root=fixture.output,
                        revision=fixture.revision,
                        expected_sources=1,
                    )
                )

    def test_shard_python_identity_tampering_fails_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary, ["(set-logic QF_UF) (assert true)\n"]
            )
            fixture.prepare()
            fixture.run_all_shards()
            path = fixture.output / "shards" / "shard-00000.jsonl"
            record = json.loads(path.read_text(encoding="ascii"))
            record["python"]["sha256"] = "0" * 64
            path.write_text(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(PARITY.CampaignError, "python identity drift"):
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

    def test_depth_rejection_remains_a_fail_closed_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = TypedParserParityFixture(
                temporary,
                ["(set-logic QF_UF) ; DEPTH\n(assert true)\n"],
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
            self.assertEqual(audit["counts"]["error"], 1)
            self.assertEqual(audit["counts"]["fallback"], 0)
            self.assertEqual(audit["counts"]["mismatch"], 0)

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
