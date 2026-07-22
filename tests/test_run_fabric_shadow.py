from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "run_fabric_shadow.py"
SPEC = importlib.util.spec_from_file_location("run_fabric_shadow", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


FAKE_SOLVER = r"""#!/usr/bin/env python3
import json
import os
import sys
import time
from pathlib import Path

if len(sys.argv) != 3 or sys.argv[1] != "fabric-shadow":
    print("expected: fabric-shadow FILE", file=sys.stderr)
    raise SystemExit(64)

source_path = Path(sys.argv[2])
source = source_path.read_bytes()
payload = json.loads(source.decode("utf-8"))
log_path = os.environ.get("FABRIC_FAKE_LOG")
if log_path:
    with Path(log_path).open("a", encoding="utf-8") as handle:
        handle.write(str(source_path) + "\n")

mode = payload.get("mode", "valid")
if mode == "timeout":
    pid_path = os.environ.get("FABRIC_FAKE_PID")
    if pid_path:
        Path(pid_path).write_text(str(os.getpid()), encoding="ascii")
    time.sleep(payload.get("sleep", 10))

receipt = {
    "schema_version": 1,
    "mode": "fabric_shadow",
    "solver_result_emitted": False,
    "source_bytes": len(source),
    "parse_ns": payload.get("parse_ns", 10),
    "projection_ns": payload.get("projection_ns", 5),
    "terms": payload.get("terms", 1),
    "applications": payload.get("applications", 2),
    "atoms": payload.get("atoms", 3),
    "assertions": payload.get("assertions", 4),
    "root_literals": payload.get("root_literals", 5),
    "components": payload.get("components", 1),
    "max_component_terms": payload.get("max_component_terms", 1),
    "cross_component_boolean_nodes": payload.get("cross_nodes", 0),
    "unsupported_fragments": payload.get("unsupported", 0),
    "contradiction": payload.get("contradiction", False),
}

if mode == "nonzero":
    raise SystemExit(7)
if mode == "stderr":
    print("unexpected diagnostic", file=sys.stderr)
if mode == "solver_result":
    receipt["solver_result_emitted"] = True
if mode == "negative":
    receipt["parse_ns"] = -1
if mode == "boolean_integer":
    receipt["terms"] = True
if mode == "extra_field":
    receipt["result"] = "sat"
if mode == "wrong_bytes":
    receipt["source_bytes"] += 1
if mode == "bad_json":
    print("{")
    raise SystemExit(0)
if mode == "sat_token":
    print("sat")
    raise SystemExit(0)

encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
if mode == "two_lines":
    print(encoded)
    print(encoded)
elif mode == "crlf":
    sys.stdout.buffer.write(encoded.encode("ascii") + b"\r\n")
else:
    print(encoded)
"""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


class FabricShadowCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.work = Path(self.temporary.name)
        self.solver = self.work / "fake-solver"
        self.log = self.work / "invocations.log"
        self.pid_file = self.work / "solver.pid"
        self.manifest = self.work / "manifest.jsonl"
        self.output = self.work / "shadow.jsonl"
        self.summary = self.work / "summary.json"
        write_executable(self.solver, FAKE_SOLVER)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_case(self, name: str, **payload: object) -> Path:
        path = self.work / "corpus" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        return path

    def manifest_row(
        self,
        identifier: str | int,
        source: Path,
        relative_path: str,
        *,
        status: str = "sat",
        declared_path: object = ...,
        declared_sha256: str | None = None,
    ) -> dict:
        row = {
            "id": identifier,
            "relative_path": relative_path,
            "status": status,
            "sha256": declared_sha256 or sha256(source),
            "bytes": source.stat().st_size,
        }
        if declared_path is ...:
            row["path"] = str(source)
        elif declared_path is not None:
            row["path"] = declared_path
        return row

    def write_manifest(self, rows: list[dict]) -> None:
        self.manifest.write_text(
            "".join(
                json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n"
                for row in rows
            ),
            encoding="ascii",
        )

    def run_cli(
        self, *extra: str, output: Path | None = None, summary: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["FABRIC_FAKE_LOG"] = str(self.log)
        environment["FABRIC_FAKE_PID"] = str(self.pid_file)
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(self.manifest),
                "--solver",
                str(self.solver),
                "--out-jsonl",
                str(output or self.output),
                "--summary",
                str(summary or self.summary),
                *extra,
            ],
            text=True,
            capture_output=True,
            env=environment,
            check=False,
            cwd=ROOT,
        )

    def output_rows(self) -> list[dict]:
        return [
            json.loads(line)
            for line in self.output.read_text(encoding="ascii").splitlines()
        ]

    def test_full_run_is_ordered_ascii_and_never_emits_a_solver_result(self) -> None:
        sources = [
            self.make_case(
                "zeta.smt2",
                parse_ns=30,
                projection_ns=15,
                terms=3,
                components=3,
                max_component_terms=5,
            ),
            self.make_case(
                "alpha.smt2",
                parse_ns=10,
                projection_ns=5,
                terms=1,
                components=1,
                max_component_terms=2,
            ),
            self.make_case(
                "middle.smt2",
                parse_ns=20,
                projection_ns=10,
                terms=2,
                components=2,
                max_component_terms=4,
                contradiction=True,
            ),
        ]
        rows = [
            self.manifest_row("z", sources[0], "family/zeta.smt2", status="sat"),
            self.manifest_row("a", sources[1], "family/alpha.smt2", status="unsat"),
            self.manifest_row("m", sources[2], "family/middle.smt2", status="unknown"),
        ]
        self.write_manifest(rows)

        completed = self.run_cli("--jobs", "2")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        raw_output = self.output.read_bytes()
        self.assertTrue(raw_output.endswith(b"\n"))
        self.assertTrue(all(byte < 128 for byte in raw_output))
        output_rows = self.output_rows()
        self.assertEqual([row["id"] for row in output_rows], ["z", "a", "m"])
        self.assertEqual(
            [row["relative_path"] for row in output_rows],
            [row["relative_path"] for row in rows],
        )
        self.assertEqual(
            [row["expected_status"] for row in output_rows],
            ["sat", "unsat", "unknown"],
        )
        for manifest_row, output_row in zip(rows, output_rows):
            self.assertEqual(output_row["path"], manifest_row["path"])
            self.assertEqual(output_row["input_sha256"], manifest_row["sha256"])
            self.assertIs(output_row["solver_result_emitted"], False)
            self.assertNotIn("result", output_row)
            self.assertNotIn("solver_result", output_row)

        invocations = self.log.read_text(encoding="utf-8").splitlines()
        self.assertCountEqual(invocations, [str(source.resolve()) for source in sources])
        self.assertEqual(len(invocations), len(set(invocations)))

        summary = json.loads(self.summary.read_text(encoding="ascii"))
        self.assertEqual(summary["status"], "complete")
        self.assertIsNone(summary["error"])
        self.assertEqual(summary["counts"]["manifest_rows"], 3)
        self.assertEqual(summary["counts"]["completed_rows"], 3)
        self.assertEqual(summary["counts"]["remaining_rows"], 0)
        self.assertEqual(summary["aggregate_component_metrics"]["terms"], 6)
        self.assertEqual(summary["aggregate_component_metrics"]["components"], 6)
        self.assertEqual(
            summary["aggregate_component_metrics"]["max_component_terms"], 5
        )
        self.assertEqual(
            summary["aggregate_component_metrics"]["contradiction_instances"], 1
        )
        self.assertEqual(summary["timing_quantiles_ns"]["parse_ns"]["p50"], 20)
        self.assertEqual(summary["timing_quantiles_ns"]["parse_ns"]["p95"], 30)
        self.assertEqual(summary["out_jsonl_sha256"], sha256(self.output))
        self.assertEqual(summary["parameters"]["timeout_s"], 60.0)
        self.assertTrue(all(row["timeout_s"] == 60.0 for row in output_rows))
        self.assertEqual(
            summary["resolution"]["rule"],
            "declared_path_only_absolute_or_invocation_cwd_relative",
        )

    def test_resume_accepts_only_a_bound_prefix_and_runs_each_missing_row_once(self) -> None:
        sources = [self.make_case(f"case-{index}.smt2") for index in range(3)]
        self.write_manifest(
            [
                self.manifest_row(index, source, f"family/case-{index}.smt2")
                for index, source in enumerate(sources)
            ]
        )
        first = self.run_cli()
        self.assertEqual(first.returncode, 0, first.stderr)
        first_line = self.output.read_bytes().splitlines(keepends=True)[0]
        self.output.write_bytes(first_line)
        self.summary.unlink()
        self.log.write_text("", encoding="utf-8")

        resumed = self.run_cli("--resume", "--jobs", "2")

        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual([row["id"] for row in self.output_rows()], [0, 1, 2])
        self.assertCountEqual(
            self.log.read_text(encoding="utf-8").splitlines(),
            [str(source.resolve()) for source in sources[1:]],
        )
        summary = json.loads(self.summary.read_text(encoding="ascii"))
        self.assertEqual(summary["counts"]["preexisting_rows"], 1)
        self.assertEqual(summary["counts"]["selected_rows"], 2)
        self.assertEqual(summary["counts"]["attempted_rows"], 2)

        self.log.write_text("", encoding="utf-8")
        already_complete = self.run_cli("--resume")
        self.assertEqual(already_complete.returncode, 0, already_complete.stderr)
        self.assertEqual(self.log.read_text(encoding="utf-8"), "")
        final_summary = json.loads(self.summary.read_text(encoding="ascii"))
        self.assertEqual(final_summary["counts"]["selected_rows"], 0)
        self.assertEqual(final_summary["counts"]["attempted_rows"], 0)

        incompatible_timeout = self.run_cli(
            "--resume", "--timeout-s", "30"
        )
        self.assertNotEqual(incompatible_timeout.returncode, 0)
        self.assertIn("timeout_s", incompatible_timeout.stderr)

    def test_resume_rejects_solver_hash_and_manifest_drift_before_invocation(self) -> None:
        source = self.make_case("case.smt2")
        self.write_manifest([self.manifest_row(1, source, "family/case.smt2")])
        first = self.run_cli()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.log.write_text("", encoding="utf-8")
        self.solver.write_text(FAKE_SOLVER + "\n# hash drift\n", encoding="utf-8")
        self.solver.chmod(0o755)

        drifted_solver = self.run_cli("--resume")

        self.assertNotEqual(drifted_solver.returncode, 0)
        self.assertIn("solver_sha256", drifted_solver.stderr)
        self.assertEqual(self.log.read_text(encoding="utf-8"), "")

        write_executable(self.solver, FAKE_SOLVER)
        manifest_row = self.manifest_row(
            1, source, "family/case.smt2", status="unsat"
        )
        self.write_manifest([manifest_row])
        drifted_manifest = self.run_cli("--resume")
        self.assertNotEqual(drifted_manifest.returncode, 0)
        self.assertIn("manifest_sha256", drifted_manifest.stderr)

    def test_malformed_receipts_fail_closed_with_an_atomic_error_summary(self) -> None:
        modes = (
            "nonzero",
            "stderr",
            "solver_result",
            "negative",
            "boolean_integer",
            "extra_field",
            "wrong_bytes",
            "bad_json",
            "sat_token",
            "two_lines",
            "crlf",
        )
        for mode in modes:
            with self.subTest(mode=mode):
                source = self.make_case(f"{mode}.smt2", mode=mode)
                self.write_manifest(
                    [self.manifest_row(mode, source, f"family/{mode}.smt2")]
                )
                output = self.work / f"{mode}.jsonl"
                summary_path = self.work / f"{mode}-summary.json"

                completed = self.run_cli(output=output, summary=summary_path)

                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(output.read_bytes(), b"")
                summary = json.loads(summary_path.read_text(encoding="ascii"))
                self.assertEqual(summary["status"], "error")
                self.assertEqual(summary["error"]["kind"], "receipt_error")
                self.assertEqual(summary["counts"]["completed_rows"], 0)
                self.assertEqual(summary["counts"]["error_rows"], 1)
                self.assertEqual(summary["counts"]["remaining_rows"], 1)
                self.assertEqual(
                    list(self.work.glob(f".{summary_path.name}.*.tmp")), []
                )

    def test_timeout_is_an_execution_error_and_the_child_is_reaped(self) -> None:
        source = self.make_case("timeout.smt2", mode="timeout", sleep=10)
        self.write_manifest(
            [self.manifest_row("timeout", source, "family/timeout.smt2")]
        )
        started = time.monotonic()

        completed = self.run_cli("--timeout-s", "0.5")

        self.assertNotEqual(completed.returncode, 0)
        self.assertLess(time.monotonic() - started, 5.0)
        self.assertEqual(self.output.read_bytes(), b"")
        summary = json.loads(self.summary.read_text(encoding="ascii"))
        self.assertEqual(summary["status"], "error")
        self.assertEqual(summary["error"]["kind"], "execution_error")
        self.assertEqual(summary["parameters"]["timeout_s"], 0.5)
        self.assertEqual(summary["counts"]["completed_rows"], 0)
        self.assertEqual(summary["counts"]["error_rows"], 1)
        pid = int(self.pid_file.read_text(encoding="ascii"))
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_manifest_duplicates_missing_inputs_and_hash_drift_never_invoke_solver(self) -> None:
        first = self.make_case("first.smt2")
        second = self.make_case("second.smt2")
        self.write_manifest(
            [
                self.manifest_row(1, first, "family/first.smt2"),
                self.manifest_row(1, second, "family/second.smt2"),
            ]
        )
        duplicate = self.run_cli()
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn("duplicate id", duplicate.stderr)
        self.assertFalse(self.log.exists())

        self.write_manifest(
            [
                self.manifest_row(
                    2,
                    first,
                    "family/missing.smt2",
                    declared_path=str(self.work / "missing.smt2"),
                )
            ]
        )
        missing = self.run_cli()
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("cannot resolve declared input path", missing.stderr)
        self.assertFalse(self.log.exists())

        self.write_manifest(
            [
                self.manifest_row(
                    3,
                    first,
                    "family/first.smt2",
                    declared_sha256="0" * 64,
                )
            ]
        )
        drift = self.run_cli()
        self.assertNotEqual(drift.returncode, 0)
        self.assertIn("input SHA-256 drift", drift.stderr)
        self.assertFalse(self.log.exists())

    def test_corpus_root_ignores_host_path_and_records_exact_resolution_rule(self) -> None:
        portable_root = self.work / "portable-corpus"
        source = portable_root / "family" / "portable.smt2"
        source.parent.mkdir(parents=True)
        source.write_text('{"terms":7}', encoding="utf-8")
        original_path = "/Users/original/benchmarks/QF_UF/family/portable.smt2"
        self.write_manifest(
            [
                self.manifest_row(
                    "portable",
                    source,
                    "family/portable.smt2",
                    declared_path=original_path,
                )
            ]
        )

        completed = self.run_cli("--corpus-root", str(portable_root))

        self.assertEqual(completed.returncode, 0, completed.stderr)
        record = self.output_rows()[0]
        self.assertEqual(record["path"], original_path)
        self.assertEqual(record["resolved_path"], str(source.resolve()))
        self.assertEqual(record["resolution_rule"], "corpus_root_relative_path")
        summary = json.loads(self.summary.read_text(encoding="ascii"))
        resolution = summary["resolution"]
        self.assertEqual(
            resolution["rule"],
            "corpus_root_plus_relative_path_and_repository_layout_when_repo_root",
        )
        self.assertEqual(resolution["corpus_root"], str(portable_root.resolve()))
        self.assertEqual(resolution["declared_paths"], "preserved_but_ignored")
        self.assertEqual(
            resolution["resolved_by_rule"], {"corpus_root_relative_path": 1}
        )

    def test_pathless_rows_require_root_and_root_resolution_rejects_traversal(self) -> None:
        corpus_root = self.work / "root"
        source = corpus_root / "family" / "case.smt2"
        source.parent.mkdir(parents=True)
        source.write_text("{}", encoding="utf-8")
        self.write_manifest(
            [
                self.manifest_row(
                    1,
                    source,
                    "family/case.smt2",
                    declared_path=None,
                )
            ]
        )

        without_root = self.run_cli()
        self.assertNotEqual(without_root.returncode, 0)
        self.assertIn("--corpus-root is required", without_root.stderr)

        with_root = self.run_cli("--corpus-root", str(corpus_root))
        self.assertEqual(with_root.returncode, 0, with_root.stderr)
        self.assertIsNone(self.output_rows()[0]["path"])

        traversal_manifest = self.work / "traversal.jsonl"
        traversal_manifest.write_text(
            json.dumps(
                {
                    "id": 2,
                    "relative_path": "../escape.smt2",
                    "status": "sat",
                    "sha256": sha256(source),
                }
            )
            + "\n",
            encoding="utf-8",
        )
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(traversal_manifest),
                "--solver",
                str(self.solver),
                "--out-jsonl",
                str(self.work / "traversal-output.jsonl"),
                "--summary",
                str(self.work / "traversal-summary.json"),
                "--corpus-root",
                str(corpus_root),
            ],
            text=True,
            capture_output=True,
            check=False,
            cwd=ROOT,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("cannot traverse", completed.stderr)


class CorpusResolutionUnitTests(unittest.TestCase):
    def make_row(self, source: Path, relative_path: str) -> object:
        return RUNNER.ManifestRow(
            ordinal=0,
            line_number=1,
            identifier=1,
            declared_path=None,
            relative_path=relative_path,
            expected_status="sat",
            declared_sha256=sha256(source),
            declared_bytes=source.stat().st_size,
        )

    def test_repository_root_uses_documented_layout_and_rejects_ambiguity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = Path(temp_dir)
            relative_path = "family/case.smt2"
            documented = (
                repository
                / RUNNER.DOCUMENTED_CORPUS_LAYOUT
                / "family"
                / "case.smt2"
            )
            documented.parent.mkdir(parents=True)
            documented.write_text("documented", encoding="utf-8")
            row = self.make_row(documented, relative_path)

            resolved, rule = RUNNER.resolve_input_path(
                row, repository, repository_root=repository
            )

            self.assertEqual(resolved, documented.resolve())
            self.assertEqual(rule, "repository_corpus_layout_relative_path")

            direct = repository / "family" / "case.smt2"
            direct.parent.mkdir(parents=True)
            direct.write_text("direct", encoding="utf-8")
            with self.assertRaisesRegex(RUNNER.InputError, "ambiguous"):
                RUNNER.resolve_input_path(
                    row, repository, repository_root=repository
                )


if __name__ == "__main__":
    unittest.main()
