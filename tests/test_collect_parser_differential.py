from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "collect_parser_differential.py"
WMI_SCRIPT = ROOT / "scripts" / "wmi" / "euf_viper_parser_differential.sbatch"
SPEC = importlib.util.spec_from_file_location("collect_parser_differential", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
COLLECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COLLECTOR)


FAKE_PARSER = r"""#!/usr/bin/env python3
import json
import os
import sys
import time
from pathlib import Path

if len(sys.argv) != 3 or sys.argv[1] != "parse-check":
    print("expected parse-check FILE", file=sys.stderr)
    raise SystemExit(64)
payload = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
mode = os.environ.get("EUF_VIPER_PARSER_MODE")
if mode != payload["expected_mode"]:
    print(f"unexpected mode {mode!r}", file=sys.stderr)
    raise SystemExit(65)
if os.environ.get("EUF_VIPER_PARSER") is not None:
    print("legacy parser environment leaked into candidate", file=sys.stderr)
    raise SystemExit(66)
if log_path := os.environ.get("PARSER_INVOCATION_LOG"):
    with Path(log_path).open("a", encoding="utf-8") as handle:
        handle.write(str(Path(sys.argv[2])) + "\n")
if payload.get("sleep"):
    time.sleep(payload["sleep"])
if payload.get("error"):
    print(payload["error"], file=sys.stderr)
    raise SystemExit(payload.get("exit_code", 2))
if payload.get("malformed"):
    print("not a diagnostic")
    raise SystemExit(0)

direct_routes = {"tree": "tree", "shadow": "shadow-match", "stream": "stream"}
route = payload.get("route", direct_routes[mode])
fallback = payload.get("fallback_reason", "none")
status = payload.get("parse_status", "fallback" if fallback != "none" else "ok")
print(
    f"parse_status={status} parser_mode={mode} "
    f"parser_route={route} fallback_reason={fallback}"
)
"""


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def write_case(
    corpus: Path,
    relative_path: str,
    payload: dict,
    *,
    identifier: int = 1,
) -> dict:
    path = corpus.joinpath(*Path(relative_path).parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
    path.write_bytes(encoded)
    return {
        "id": identifier,
        "path": f"/stale/make-manifest-host/{relative_path}",
        "relative_path": relative_path,
        "status": "sat",
        "bytes": len(encoded),
        "sha256": digest_bytes(encoded),
    }


def write_manifest(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


class DiagnosticTests(unittest.TestCase):
    def test_accepts_only_exact_direct_and_tree_fallback_routes(self) -> None:
        for mode, route in (
            ("tree", "tree"),
            ("shadow", "shadow-match"),
            ("stream", "stream"),
        ):
            with self.subTest(mode=mode):
                parsed = COLLECTOR.parse_diagnostic(
                    f"parse_status=ok parser_mode={mode} "
                    f"parser_route={route} fallback_reason=none\n"
                )
                self.assertEqual(parsed["parser_route"], route)

        parsed = COLLECTOR.parse_diagnostic(
            "parse_status=fallback parser_mode=shadow "
            "parser_route=tree-fallback fallback_reason=unsupported_command\n"
        )
        self.assertEqual(parsed["parse_status"], "fallback")

    def test_rejects_status_route_and_reason_inconsistencies(self) -> None:
        malformed = [
            "",
            "parse_status=ok parser_mode=stream parser_route=stream",
            (
                "parse_status=ok parse_status=ok parser_mode=stream "
                "parser_route=stream fallback_reason=none"
            ),
            (
                "parse_status=ok parser_mode=shadow "
                "parser_route=tree-fallback fallback_reason=none"
            ),
            (
                "parse_status=ok parser_mode=stream "
                "parser_route=tree-fallback fallback_reason=unsupported_command"
            ),
            (
                "parse_status=fallback parser_mode=shadow "
                "parser_route=shadow-match fallback_reason=unsupported_command"
            ),
            (
                "parse_status=fallback parser_mode=tree "
                "parser_route=tree-fallback fallback_reason=unsupported_command"
            ),
            (
                "parse_status=fallback parser_mode=stream "
                "parser_route=tree-fallback fallback_reason=none"
            ),
            (
                "parse_status=ok parser_mode=tree "
                "parser_route=stream fallback_reason=none"
            ),
        ]
        for diagnostic in malformed:
            with self.subTest(diagnostic=diagnostic):
                with self.assertRaises(COLLECTOR.HarnessError):
                    COLLECTOR.parse_diagnostic(diagnostic)


class ManifestTests(unittest.TestCase):
    def test_requires_make_manifest_identity_fields_and_preserves_order(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corpus = root / "QF_UF"
            rows = [
                write_case(corpus, "z/case.smt2", {"expected_mode": "tree"}, identifier=1),
                write_case(corpus, "a/case.smt2", {"expected_mode": "tree"}, identifier=2),
            ]
            manifest = root / "manifest.jsonl"
            write_manifest(manifest, rows)

            entries = COLLECTOR.read_manifest(manifest)

            self.assertEqual(
                [entry["relative_path"] for entry in entries],
                ["z/case.smt2", "a/case.smt2"],
            )
            self.assertEqual(entries[0]["manifest_line"], 1)
            self.assertEqual(
                COLLECTOR.resolve_input_path(entries[0], corpus),
                (corpus / "z" / "case.smt2").resolve(),
            )

    def test_rejects_missing_or_malformed_identity_and_paths(self) -> None:
        good = {
            "relative_path": "case.smt2",
            "bytes": 1,
            "sha256": "a" * 64,
        }
        rows = [
            {key: value for key, value in good.items() if key != "bytes"},
            {**good, "bytes": True},
            {key: value for key, value in good.items() if key != "sha256"},
            {**good, "sha256": "A" * 64},
            {**good, "relative_path": "../escape.smt2"},
            {**good, "relative_path": "nested//case.smt2"},
        ]
        for row in rows:
            with self.subTest(row=row):
                with tempfile.TemporaryDirectory() as temp_dir:
                    manifest = Path(temp_dir) / "manifest.jsonl"
                    write_manifest(manifest, [row])
                    with self.assertRaises(COLLECTOR.HarnessError):
                        COLLECTOR.read_manifest(manifest)

    def test_rejects_duplicate_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = Path(temp_dir) / "manifest.jsonl"
            row = {
                "relative_path": "same.smt2",
                "bytes": 0,
                "sha256": digest_bytes(b""),
            }
            write_manifest(manifest, [row, row])
            with self.assertRaisesRegex(COLLECTOR.HarnessError, "duplicate"):
                COLLECTOR.read_manifest(manifest)


class CollectionTests(unittest.TestCase):
    def test_collects_in_manifest_order_and_separates_direct_from_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corpus = root / "QF_UF"
            binary = root / "fake-viper"
            manifest = root / "manifest.jsonl"
            write_executable(binary, FAKE_PARSER)
            rows = [
                write_case(
                    corpus,
                    "direct.smt2",
                    {"expected_mode": "shadow", "route": "shadow-match"},
                    identifier=1,
                ),
                write_case(
                    corpus,
                    "fallback.smt2",
                    {
                        "expected_mode": "shadow",
                        "route": "tree-fallback",
                        "fallback_reason": "term_valued_ite_or_let",
                    },
                    identifier=2,
                ),
            ]
            write_manifest(manifest, rows)

            records, summary = COLLECTOR.collect_manifest(
                manifest,
                binary,
                "shadow",
                timeout_s=1.0,
                jobs=2,
                benchmark_root=corpus,
            )

            self.assertEqual(
                [record["relative_path"] for record in records],
                ["direct.smt2", "fallback.smt2"],
            )
            self.assertTrue(all(record["corpus_verified"] for record in records))
            self.assertEqual(summary["direct_shadow_matches"], 1)
            self.assertEqual(summary["tree_fallbacks"], 1)
            self.assertEqual(
                summary["routes"], {"shadow-match": 1, "tree-fallback": 1}
            )
            self.assertFalse(summary["gate_passed"])

    def test_verifies_both_bytes_and_hash_before_spawning(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corpus = root / "QF_UF"
            binary = root / "fake-viper"
            manifest = root / "manifest.jsonl"
            invocation_log = root / "invocations.log"
            write_executable(binary, FAKE_PARSER)
            row = write_case(
                corpus, "tampered.smt2", {"expected_mode": "stream"}
            )
            write_manifest(manifest, [row])
            (corpus / "tampered.smt2").write_text("changed", encoding="utf-8")

            with mock.patch.dict(
                os.environ, {"PARSER_INVOCATION_LOG": str(invocation_log)}
            ):
                records, summary = COLLECTOR.collect_manifest(
                    manifest,
                    binary,
                    "stream",
                    timeout_s=1.0,
                    jobs=1,
                    benchmark_root=corpus,
                )

            record = records[0]
            self.assertEqual(record["failure_kind"], "source_identity_mismatch")
            self.assertFalse(record["corpus_verified"])
            self.assertNotEqual(
                record["source_expected_sha256"], record["source_actual_sha256"]
            )
            self.assertFalse(invocation_log.exists())
            self.assertEqual(summary["corpus_verification"]["failed"], 1)

    def test_catches_spawn_oserror_as_a_durable_verified_row(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corpus = root / "QF_UF"
            manifest = root / "manifest.jsonl"
            row = write_case(corpus, "case.smt2", {"expected_mode": "stream"})
            write_manifest(manifest, [row])

            records, summary = COLLECTOR.collect_manifest(
                manifest,
                root / "missing-viper",
                "stream",
                timeout_s=1.0,
                jobs=1,
                benchmark_root=corpus,
            )

            self.assertEqual(records[0]["failure_kind"], "spawn_error")
            self.assertIsNone(records[0]["exit_code"])
            self.assertTrue(records[0]["corpus_verified"])
            self.assertGreaterEqual(records[0]["wall_time_ns"], 0)
            self.assertEqual(summary["errors"], 1)

    def test_classifies_timeout_and_diagnostic_errors_per_row(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corpus = root / "QF_UF"
            binary = root / "fake-viper"
            manifest = root / "manifest.jsonl"
            write_executable(binary, FAKE_PARSER)
            rows = [
                write_case(
                    corpus,
                    "timeout.smt2",
                    {"expected_mode": "stream", "sleep": 0.5},
                    identifier=1,
                ),
                write_case(
                    corpus,
                    "malformed.smt2",
                    {"expected_mode": "stream", "malformed": True},
                    identifier=2,
                ),
            ]
            write_manifest(manifest, rows)

            records, summary = COLLECTOR.collect_manifest(
                manifest,
                binary,
                "stream",
                timeout_s=0.2,
                jobs=2,
                benchmark_root=corpus,
            )

            self.assertEqual(
                [record["failure_kind"] for record in records],
                ["timeout", "diagnostic_error"],
            )
            self.assertEqual(summary["timeouts"], 1)
            self.assertEqual(summary["errors"], 1)

    def test_periodic_checkpoint_receives_atomic_prefix_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corpus = root / "QF_UF"
            binary = root / "fake-viper"
            manifest = root / "manifest.jsonl"
            checkpoint_path = root / "checkpoint.jsonl"
            write_executable(binary, FAKE_PARSER)
            rows = [
                write_case(
                    corpus,
                    f"case-{index}.smt2",
                    {"expected_mode": "tree"},
                    identifier=index,
                )
                for index in range(5)
            ]
            write_manifest(manifest, rows)
            checkpoints: list[tuple[int, int, int]] = []

            def checkpoint(records: list[dict], completed: int, expected: int) -> None:
                COLLECTOR.atomic_write_jsonl(checkpoint_path, records)
                checkpoints.append((len(records), completed, expected))

            records, _ = COLLECTOR.collect_manifest(
                manifest,
                binary,
                "tree",
                timeout_s=1.0,
                jobs=2,
                benchmark_root=corpus,
                checkpoint=checkpoint,
                checkpoint_every=2,
            )

            self.assertEqual(checkpoints, [(2, 2, 5), (4, 4, 5), (5, 5, 5)])
            checkpoint_rows = checkpoint_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(checkpoint_rows), len(records))
            self.assertFalse(list(root.glob(".*.tmp-*")))

    def test_exact_completion_rejects_missing_duplicate_and_reordered_rows(self) -> None:
        entries = [
            {"relative_path": "a.smt2"},
            {"relative_path": "b.smt2"},
        ]
        valid = [
            {"relative_path": "a.smt2"},
            {"relative_path": "b.smt2"},
        ]
        COLLECTOR.validate_complete_records(entries, valid)
        for records in (
            valid[:1],
            [valid[0], valid[0]],
            list(reversed(valid)),
        ):
            with self.subTest(records=records):
                with self.assertRaises(COLLECTOR.HarnessError):
                    COLLECTOR.validate_complete_records(entries, records)

    def test_all_fallback_summary_cannot_pass_even_with_an_unbounded_limit(self) -> None:
        records = [
            {
                "status": "ok",
                "relative_path": "only.smt2",
                "parser_route": "tree-fallback",
                "parse_status": "fallback",
                "fallback_reason": "unsupported",
                "corpus_verified": True,
            }
        ]
        summary = COLLECTOR.summarize(
            records,
            "shadow",
            expected_instances=1,
            max_fallbacks=100,
            fallback_limit_explicit=True,
        )
        self.assertFalse(summary["fallback_gate"]["direct_route_observed"])
        self.assertFalse(summary["gate_passed"])


class CliContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.corpus = self.root / "QF_UF"
        self.binary = self.root / "fake-viper"
        self.manifest = self.root / "manifest.jsonl"
        write_executable(self.binary, FAKE_PARSER)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_cli(
        self,
        output_name: str,
        *,
        mode: str,
        expected_binary_sha256: str | None = None,
        expected_instances: int | None = None,
        max_fallbacks: int | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        output = self.root / output_name
        output.mkdir()
        rows = COLLECTOR.read_manifest(self.manifest)
        command = [
            sys.executable,
            str(SCRIPT),
            str(self.manifest),
            "--binary",
            str(self.binary),
            "--expected-binary-sha256",
            expected_binary_sha256 or digest_file(self.binary),
            "--expected-instances",
            str(expected_instances if expected_instances is not None else len(rows)),
            "--candidate-parser-mode",
            mode,
            "--benchmark-root",
            str(self.corpus),
            "--timeout",
            "1",
            "--jobs",
            "2",
            "--checkpoint-every",
            "1",
            "--out",
            str(output / "rows.jsonl"),
            "--summary",
            str(output / "summary.json"),
            "--progress",
            str(output / "progress.json"),
        ]
        if max_fallbacks is not None:
            command.extend(["--max-fallbacks", str(max_fallbacks)])
        return (
            subprocess.run(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
            ),
            output,
        )

    def test_records_exact_binary_manifest_and_corpus_provenance(self) -> None:
        rows = [
            write_case(
                self.corpus,
                "nested/direct.smt2",
                {"expected_mode": "shadow", "route": "shadow-match"},
            )
        ]
        write_manifest(self.manifest, rows)

        completed, output = self.run_cli("success", mode="shadow")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
        progress = json.loads((output / "progress.json").read_text(encoding="utf-8"))
        evidence = [
            json.loads(line)
            for line in (output / "rows.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(summary["binary_sha256"], digest_file(self.binary))
        self.assertEqual(
            summary["expected_binary_sha256"], digest_file(self.binary)
        )
        self.assertEqual(summary["manifest_sha256"], digest_file(self.manifest))
        self.assertTrue(summary["provenance"]["binary"]["sha256_verified"])
        self.assertEqual(summary["corpus_verification"]["verified"], 1)
        self.assertEqual(summary["corpus_verification"]["failed"], 0)
        self.assertTrue(summary["evidence_integrity"]["row_count_verified"])
        self.assertTrue(summary["evidence_integrity"]["unique_paths_verified"])
        self.assertTrue(summary["gate_passed"])
        self.assertEqual(progress["campaign_status"], "complete")
        self.assertEqual(progress["completed_instances"], 1)
        self.assertEqual(len(evidence), 1)
        self.assertTrue(evidence[0]["corpus_verified"])

    def test_rejects_binary_hash_and_instance_count_mismatches_before_running(self) -> None:
        row = write_case(
            self.corpus, "direct.smt2", {"expected_mode": "shadow"}
        )
        write_manifest(self.manifest, [row])

        bad_hash, hash_output = self.run_cli(
            "bad-hash", mode="shadow", expected_binary_sha256="0" * 64
        )
        self.assertEqual(bad_hash.returncode, 2)
        self.assertIn("binary SHA256 mismatch", bad_hash.stderr)
        self.assertEqual(list(hash_output.iterdir()), [])

        bad_count, count_output = self.run_cli(
            "bad-count", mode="shadow", expected_instances=2
        )
        self.assertEqual(bad_count.returncode, 2)
        self.assertIn("manifest instance count mismatch", bad_count.stderr)
        self.assertEqual(list(count_output.iterdir()), [])

    def test_default_zero_fallback_gate_and_explicit_bounded_allowance(self) -> None:
        rows = [
            write_case(
                self.corpus,
                "direct.smt2",
                {"expected_mode": "shadow", "route": "shadow-match"},
                identifier=1,
            ),
            write_case(
                self.corpus,
                "fallback.smt2",
                {
                    "expected_mode": "shadow",
                    "route": "tree-fallback",
                    "fallback_reason": "unsupported_command",
                },
                identifier=2,
            ),
        ]
        write_manifest(self.manifest, rows)

        default, default_output = self.run_cli("default", mode="shadow")
        self.assertEqual(default.returncode, 2, default.stderr)
        default_summary = json.loads(
            (default_output / "summary.json").read_text(encoding="utf-8")
        )
        self.assertEqual(default_summary["fallback_gate"]["max_fallbacks"], 0)
        self.assertFalse(default_summary["fallback_gate"]["explicit_limit"])
        self.assertFalse(default_summary["gate_passed"])

        bounded, bounded_output = self.run_cli(
            "bounded", mode="shadow", max_fallbacks=1
        )
        self.assertEqual(bounded.returncode, 0, bounded.stderr)
        bounded_summary = json.loads(
            (bounded_output / "summary.json").read_text(encoding="utf-8")
        )
        self.assertTrue(bounded_summary["fallback_gate"]["explicit_limit"])
        self.assertTrue(bounded_summary["gate_passed"])

    def test_rejects_a_limit_that_could_admit_all_fallbacks(self) -> None:
        rows = [
            write_case(
                self.corpus,
                "fallback.smt2",
                {
                    "expected_mode": "shadow",
                    "route": "tree-fallback",
                    "fallback_reason": "unsupported_command",
                },
            )
        ]
        write_manifest(self.manifest, rows)

        completed, output = self.run_cli(
            "all-fallback-limit", mode="shadow", max_fallbacks=1
        )

        self.assertEqual(completed.returncode, 2)
        self.assertIn("all-fallback campaign cannot pass", completed.stderr)
        self.assertEqual(list(output.iterdir()), [])


class WmiHarnessTests(unittest.TestCase):
    def run_wrapper(
        self,
        mode: str,
        *,
        remove_environment: str | None = None,
        max_fallbacks: str | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        with tempfile.TemporaryDirectory() as temp_dir:
            work = Path(temp_dir)
            capture = work / "arguments.json"
            recorder = r"""#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

Path(os.environ["PARSER_ARGUMENT_CAPTURE"]).write_text(
    json.dumps(sys.argv[1:]), encoding="utf-8"
)
"""
            write_executable(
                work / "scripts" / "bench" / "collect_parser_differential.py",
                recorder,
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "SLURM_SUBMIT_DIR": str(work),
                    "SLURM_JOB_ID": "123",
                    "SLURM_CPUS_PER_TASK": "4",
                    "EUF_VIPER_PARSER_MODE": mode,
                    "EUF_VIPER_PARSER_MANIFEST": "/corpus/full.jsonl",
                    "EUF_VIPER_PARSER_BENCHMARK_ROOT": "/corpus/QF_UF",
                    "EUF_VIPER_PARSER_BINARY": "/opt/euf-viper",
                    "EUF_VIPER_PARSER_EXPECTED_BINARY_SHA256": "a" * 64,
                    "EUF_VIPER_PARSER_EXPECTED_INSTANCES": "7503",
                    "PARSER_ARGUMENT_CAPTURE": str(capture),
                }
            )
            if max_fallbacks is not None:
                environment["EUF_VIPER_PARSER_MAX_FALLBACKS"] = max_fallbacks
            if remove_environment is not None:
                environment.pop(remove_environment, None)
            completed = subprocess.run(
                ["bash", str(WMI_SCRIPT)],
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )
            arguments = (
                json.loads(capture.read_text(encoding="utf-8"))
                if capture.exists()
                else []
            )
            return completed, arguments

    def test_forwards_exact_provenance_checkpoint_and_mode_contracts(self) -> None:
        completed, arguments = self.run_wrapper("shadow", max_fallbacks="3")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        expected_pairs = {
            "--candidate-parser-mode": "shadow",
            "--benchmark-root": "/corpus/QF_UF",
            "--expected-binary-sha256": "a" * 64,
            "--expected-instances": "7503",
            "--checkpoint-every": "25",
            "--max-fallbacks": "3",
        }
        for option, value in expected_pairs.items():
            with self.subTest(option=option):
                index = arguments.index(option)
                self.assertEqual(arguments[index + 1], value)
        self.assertIn("--progress", arguments)
        self.assertEqual(arguments[0], "/corpus/full.jsonl")

    def test_default_wrapper_does_not_relax_zero_fallback_gate(self) -> None:
        completed, arguments = self.run_wrapper("shadow")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("--max-fallbacks", arguments)

    def test_requires_binary_hash_count_and_explicit_benchmark_root(self) -> None:
        for variable in (
            "EUF_VIPER_PARSER_EXPECTED_BINARY_SHA256",
            "EUF_VIPER_PARSER_EXPECTED_INSTANCES",
            "EUF_VIPER_PARSER_BENCHMARK_ROOT",
        ):
            with self.subTest(variable=variable):
                completed, arguments = self.run_wrapper(
                    "shadow", remove_environment=variable
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(arguments, [])
                self.assertIn(variable, completed.stderr)

    def test_rejects_invalid_parser_mode_before_collection(self) -> None:
        completed, arguments = self.run_wrapper("facts")
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(arguments, [])
        self.assertIn("must be tree, shadow, or stream", completed.stderr)

    def test_wrapper_has_worst_case_walltime_and_valid_bash(self) -> None:
        self.assertTrue(os.access(SCRIPT, os.X_OK))
        completed = subprocess.run(
            ["bash", "-n", str(WMI_SCRIPT)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        script = WMI_SCRIPT.read_text(encoding="utf-8")
        match = re.search(r"^#SBATCH --time=(\d+):(\d+):(\d+)$", script, re.MULTILINE)
        self.assertIsNotNone(match)
        assert match is not None
        hours, minutes, seconds = (int(value) for value in match.groups())
        self.assertGreaterEqual(hours * 3600 + minutes * 60 + seconds, 4 * 3600)


if __name__ == "__main__":
    unittest.main()
