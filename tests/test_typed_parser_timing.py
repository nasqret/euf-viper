from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "typed_parser_timing.py"
CONTRACT_PATH = ROOT / "campaigns" / "t1-typed-parser-timing-v1.json"
SPEC = importlib.util.spec_from_file_location("typed_parser_timing", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
TIMING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TIMING)
CONTRACT, _ = TIMING.load_contract(CONTRACT_PATH)
ZERO_SHA256 = "0" * 64


FAKE_BINARY = r'''#!/usr/bin/env python3
import hashlib
import json
import os
import sys

if os.environ.get("EUF_VIPER_SCOPED_LET") != "auto":
    raise SystemExit("scoped-let drift")
if os.environ.get("EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT") != "1024":
    raise SystemExit("preprocess-limit drift")
if "EUF_VIPER_PROFILE" in os.environ:
    raise SystemExit("profile drift")
args = sys.argv[1:]
if len(args) != 6 or args[0] != "research-parser-timing" or args[1] != "--parser" or args[3] != "--phase" or args[5] != "-":
    raise SystemExit(f"unexpected timing invocation: {args!r}")
parser = args[2]
phase_arg = args[4]
phase = "end_to_end" if phase_arg == "end-to-end" else phase_arg
source = sys.stdin.buffer.read()
if b"FLOOD" in source:
    sys.stdout.write("x" * 1048577)
    raise SystemExit(0)
if b"BAD_JSON" in source:
    print('{"schema":"x","schema":"y"}')
    raise SystemExit(0)
elapsed = {
    ("tree", "parse"): 100,
    ("stream", "parse"): 80,
    ("tree", "end_to_end"): 1000,
    ("stream", "end_to_end"): 900,
}[(parser, phase)]
semantic = hashlib.sha256(source).hexdigest()[:16] if phase == "parse" else None
result = "parsed" if phase == "parse" else ("unsat" if b"UNSAT" in source else "sat")
result_fingerprint = None if phase == "parse" else hashlib.sha256(result.encode()).hexdigest()[:16]
payload = {
    "elapsed_ns": elapsed,
    "parser": parser,
    "phase": phase,
    "result": result,
    "result_fnv1a64": result_fingerprint,
    "schema": "euf-viper.typed-parser-timing-observation.v1",
    "semantic_fnv1a64": semantic,
    "source_bytes": len(source),
}
print(json.dumps(payload, allow_nan=False, separators=(",", ":"), sort_keys=True))
'''


def valid_payload(parser: str, phase: str, *, source_bytes: int = 5) -> dict[str, object]:
    return {
        "schema": TIMING.BINARY_OBSERVATION_SCHEMA,
        "parser": parser,
        "phase": phase,
        "elapsed_ns": 100 if parser == "tree" else 90,
        "source_bytes": source_bytes,
        "result": "parsed" if phase == "parse" else "sat",
        "semantic_fnv1a64": "0123456789abcdef" if phase == "parse" else None,
        "result_fnv1a64": None if phase == "parse" else "fedcba9876543210",
    }


def valid_observation(schedule: dict[str, object], *, source_bytes: int = 5) -> dict[str, object]:
    return {
        **schedule,
        "outcome": "ok",
        "exit_code": 0,
        "external_elapsed_ns": 1000,
        "max_rss_kb": 4096,
        "stdout_sha256": ZERO_SHA256,
        "stderr_sha256": ZERO_SHA256,
        "diagnostic": None,
        "payload": valid_payload(
            str(schedule["parser"]), str(schedule["phase"]), source_bytes=source_bytes
        ),
    }


def valid_record(*, result_mismatch: bool = False, parse_mismatch: bool = False) -> dict[str, object]:
    observations = [valid_observation(item) for item in TIMING.expected_schedule(CONTRACT)]
    if result_mismatch:
        target = next(
            item
            for item in observations
            if item["stage"] == "measure"
            and item["phase"] == "end_to_end"
            and item["parser"] == "stream"
        )
        target["payload"]["result_fnv1a64"] = "1111111111111111"
    if parse_mismatch:
        target = next(
            item
            for item in observations
            if item["stage"] == "measure"
            and item["phase"] == "parse"
            and item["parser"] == "stream"
        )
        target["payload"]["semantic_fnv1a64"] = "2222222222222222"
    return {
        "schema": TIMING.RECORD_SCHEMA,
        "byte_binding": TIMING.BYTE_BINDING,
        "process_isolation": TIMING.PROCESS_ISOLATION,
        "sequence": 0,
        "shard": 0,
        "revision": "a" * 40,
        "prepare_sha256": ZERO_SHA256,
        "contract_sha256": ZERO_SHA256,
        "python": {
            "path": "/usr/bin/python3",
            "sha256": ZERO_SHA256,
            "version": "Python 3.10.0",
        },
        "binary": {
            "path": "/tmp/euf-viper",
            "sha256": ZERO_SHA256,
            "bytes": 1,
            "execution": TIMING.EXECUTABLE_BINDING,
        },
        "runtime_environment": TIMING.RUNTIME_ENVIRONMENT,
        "worker": {
            "hostname": "test",
            "platform": "Linux",
            "machine": "x86_64",
            "cpu_id": 0,
            "affinity": "sched_setaffinity-singleton.v1",
        },
        "relative_path": "QF_UF/family/example.smt2",
        "family": "family",
        "expected_status": "sat",
        "source_sha256": ZERO_SHA256,
        "opened_source_sha256": ZERO_SHA256,
        "opened_source_bytes": 5,
        "observations": observations,
    }


def analyzed_row(
    baseline: float,
    candidate: float,
    *,
    family: str = "family",
    status: str = "sat",
    solved_tree: bool = True,
    solved_stream: bool = True,
) -> dict[str, object]:
    phase = {
        "baseline_median_ns": baseline,
        "candidate_median_ns": candidate,
        "baseline_median_rss_kb": 100.0,
        "candidate_median_rss_kb": 90.0,
        "paired_ratios": [candidate / baseline] * 10,
    }
    return {
        "relative_path": f"QF_UF/{family}/example.smt2",
        "family": family,
        "expected_status": status,
        "parse_parity": True,
        "result_parity": True,
        "incorrect_results": 0,
        "solved": {"tree": solved_tree, "stream": solved_stream},
        "outcomes": {"ok": 48, "timeout": 0, "error": 0},
        "phase_metrics": {"parse": copy.deepcopy(phase), "end_to_end": phase},
    }


class StrictJsonTests(unittest.TestCase):
    def test_rejects_duplicate_nonfinite_and_overflow_numbers(self) -> None:
        for text in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '{"x":1e999}'):
            with self.subTest(text=text), self.assertRaises(TIMING.CampaignError):
                TIMING.strict_json(text, where="test")

    def test_binary_payload_rejects_missing_and_noncanonical_output(self) -> None:
        payload = valid_payload("tree", "parse")
        del payload["elapsed_ns"]
        with self.assertRaises(TIMING.CampaignError):
            TIMING.parse_binary_stdout(
                (json.dumps(payload) + "\n").encode(),
                parser="tree",
                phase="parse",
                source_bytes=5,
            )
        valid = valid_payload("tree", "parse")
        with self.assertRaisesRegex(TIMING.CampaignError, "canonical"):
            TIMING.parse_binary_stdout(
                (json.dumps(valid, separators=(",", ":")) + "\n").encode(),
                parser="tree",
                phase="parse",
                source_bytes=5,
            )


class ScheduleTests(unittest.TestCase):
    def test_schedule_is_immutable_abba_for_both_phases(self) -> None:
        schedule = TIMING.expected_schedule(CONTRACT)
        self.assertEqual(len(schedule), (1 + 5) * 2 * 4)
        first = [item["parser"] for item in schedule[:4]]
        second = [item["parser"] for item in schedule[4:8]]
        self.assertEqual(first, list(TIMING.ABBA_ORDER))
        self.assertEqual(second, list(TIMING.ABBA_ORDER))
        self.assertEqual(schedule[0]["phase"], "parse")
        self.assertEqual(schedule[4]["phase"], "end_to_end")

    def test_duplicate_missing_and_reordered_observations_fail(self) -> None:
        observations = [valid_observation(item) for item in TIMING.expected_schedule(CONTRACT)]
        for malformed in (
            observations[:-1],
            observations + [copy.deepcopy(observations[-1])],
            [observations[1], observations[0], *observations[2:]],
        ):
            with self.assertRaises(TIMING.CampaignError):
                TIMING.validate_schedule(
                    malformed,
                    contract=CONTRACT,
                    source_bytes=5,
                    where="test schedule",
                )


class ParityAndGateTests(unittest.TestCase):
    def test_result_and_parse_mismatches_are_detected(self) -> None:
        result = TIMING.analyze_source(valid_record(result_mismatch=True), CONTRACT)
        self.assertFalse(result["result_parity"])
        parse = TIMING.analyze_source(valid_record(parse_mismatch=True), CONTRACT)
        self.assertFalse(parse["parse_parity"])

    def test_all_preregistered_thresholds_must_pass(self) -> None:
        rows = [analyzed_row(100.0, 90.0), analyzed_row(200.0, 180.0, status="unsat")]
        contract = copy.deepcopy(CONTRACT)
        contract["campaign"]["expected_sources"] = len(rows)
        metrics = {phase: TIMING.summarize_phase(rows, phase) for phase in TIMING.PHASES}
        gates = TIMING.evaluate_gates(rows, metrics, contract)
        self.assertTrue(gates["passed"])

        tail_rows = [analyzed_row(100.0, 80.0) for _ in range(19)]
        tail_rows.append(analyzed_row(100.0, 102.0))
        contract["campaign"]["expected_sources"] = len(tail_rows)
        tail_metrics = {
            phase: TIMING.summarize_phase(tail_rows, phase) for phase in TIMING.PHASES
        }
        tail_gates = TIMING.evaluate_gates(tail_rows, tail_metrics, contract)
        self.assertFalse(tail_gates["parse_p95_miss_overhead_below_one_percent"])
        self.assertFalse(tail_gates["passed"])

    def test_solved_count_regression_is_independently_rejected(self) -> None:
        rows = [analyzed_row(100.0, 90.0, solved_stream=False)]
        contract = copy.deepcopy(CONTRACT)
        contract["campaign"]["expected_sources"] = 1
        metrics = {phase: TIMING.summarize_phase(rows, phase) for phase in TIMING.PHASES}
        gates = TIMING.evaluate_gates(rows, metrics, contract)
        self.assertFalse(gates["no_solved_count_regression"])
        self.assertFalse(gates["passed"])


class IdentityAndExecutionTests(unittest.TestCase):
    def test_python_and_binary_hash_drift_fail_closed(self) -> None:
        python_path = Path(sys.executable).resolve(strict=True)
        identity = TIMING.open_regular_artifact(python_path, executable=True)
        environment = {
            TIMING.PYTHON_PATH_ENV: str(python_path),
            TIMING.PYTHON_SHA256_ENV: "f" * 64,
            TIMING.PYTHON_VERSION_ENV: f"Python {platform.python_version()}",
        }
        with patch.dict(os.environ, environment, clear=False):
            with self.assertRaisesRegex(TIMING.CampaignError, "hash mismatch"):
                TIMING.validate_python_identity()

        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fake"
            binary.write_text(FAKE_BINARY, encoding="utf-8")
            binary.chmod(0o500)
            expected = {
                "path": str(binary.resolve()),
                "sha256": identity.sha256,
                "bytes": binary.stat().st_size,
                "execution": TIMING.executable_binding_contract(),
            }
            with self.assertRaisesRegex(TIMING.CampaignError, "identity mismatch"):
                with TIMING.open_verified_executable(binary, expected=expected):
                    pass

    def test_source_hash_drift_fails_before_any_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.smt2"
            source.write_text("(check-sat)\n", encoding="utf-8")
            artifact = TIMING.open_regular_artifact(source)
            prepared = TIMING.PreparedCampaign(
                metadata={"revision": "a" * 40, "contract": {"sha256": ZERO_SHA256}},
                prepare_artifact=artifact,
                contract=CONTRACT,
                workset=[],
                workset_artifact=artifact,
            )
            work = {
                "sequence": 0,
                "source_path": str(source),
                "source_sha256": "f" * 64,
                "source_bytes": len(artifact.content),
                "relative_path": "QF_UF/family/source.smt2",
            }
            with self.assertRaisesRegex(TIMING.CampaignError, "changed after prepare"):
                TIMING.run_work_item(
                    work,
                    shard=0,
                    prepared=prepared,
                    executable=None,
                    worker={
                        "hostname": "test",
                        "platform": "test",
                        "machine": "test",
                        "cpu_id": None,
                        "affinity": "unavailable-nonlinux",
                    },
                )

    def test_descriptor_execution_preserves_cli_and_source_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fake-timing"
            binary.write_text(FAKE_BINARY, encoding="utf-8")
            binary.chmod(0o500)
            source = b"SAT\x00BYTES"
            with TIMING.open_verified_executable(binary) as executable:
                schedule = TIMING.expected_schedule(
                    CONTRACT, measured_rounds=1, warmup_rounds=0
                )
                observations = [
                    TIMING.execute_scheduled_observation(
                        executable,
                        source,
                        item,
                        timeout_seconds=2,
                    )
                    for item in schedule
                ]
            TIMING.validate_schedule(
                observations,
                contract=CONTRACT,
                source_bytes=len(source),
                where="descriptor execution",
                measured_rounds=1,
                warmup_rounds=0,
            )
            TIMING.assert_exact_observation_parity(
                observations, expected_status="sat", where="descriptor execution"
            )
            self.assertTrue(all(item["max_rss_kb"] >= 0 for item in observations))

    def test_oversized_output_is_an_error_not_a_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fake-timing"
            binary.write_text(FAKE_BINARY, encoding="utf-8")
            binary.chmod(0o500)
            schedule = TIMING.expected_schedule(
                CONTRACT, measured_rounds=1, warmup_rounds=0
            )[0]
            with TIMING.open_verified_executable(binary) as executable:
                observation = TIMING.execute_scheduled_observation(
                    executable,
                    b"FLOOD",
                    schedule,
                    timeout_seconds=2,
                )
            self.assertEqual(observation["outcome"], "error")
            self.assertNotEqual(observation["outcome"], "timeout")

    def test_publication_never_replaces_existing_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            TIMING.publish_new(path, b"first\n")
            with self.assertRaisesRegex(TIMING.CampaignError, "refusing to replace"):
                TIMING.publish_new(path, b"second\n")
            self.assertEqual(path.read_bytes(), b"first\n")


class MiniCampaignTests(unittest.TestCase):
    def test_prepare_shards_and_audit_form_a_complete_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            repository = directory / "repository"
            family = repository / "QF_UF" / "mini"
            family.mkdir(parents=True)
            sources = {
                "QF_UF/mini/a.smt2": b"SAT\n",
                "QF_UF/mini/b.smt2": b"UNSAT\n",
            }
            manifest_rows = []
            for index, (relative, content) in enumerate(sources.items()):
                path = repository / relative
                path.write_bytes(content)
                manifest_rows.append(
                    {
                        "archive_md5": None,
                        "bytes": len(content),
                        "id": index,
                        "logic": "QF_UF",
                        "path": str(path),
                        "relative_path": relative,
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "source_doi": None,
                        "source_url": None,
                        "status": "unsat" if b"UNSAT" in content else "sat",
                    }
                )
            manifest = repository / "manifest.jsonl"
            manifest.write_text(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in manifest_rows),
                encoding="utf-8",
            )
            contract = copy.deepcopy(CONTRACT)
            contract["campaign"] = {
                "expected_sources": 2,
                "shards": 2,
                "max_parallel": 2,
            }
            contract_path = repository / "contract.json"
            contract_path.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n")
            binary = repository / "fake-timing"
            binary.write_text(FAKE_BINARY, encoding="utf-8")
            binary.chmod(0o500)
            output_root = repository / "campaign"
            python_path = Path(sys.executable).resolve(strict=True)
            python_hash = TIMING.open_regular_artifact(
                python_path, executable=True
            ).sha256
            environment = {
                TIMING.PYTHON_PATH_ENV: str(python_path),
                TIMING.PYTHON_SHA256_ENV: python_hash,
                TIMING.PYTHON_VERSION_ENV: f"Python {platform.python_version()}",
            }
            for name, (path_env, sha_env, version_env) in TIMING.BUILD_TOOL_ENVIRONMENT.items():
                tool_name = "cargo" if name == "cargo" else "rustc"
                rustup = shutil.which("rustup")
                if rustup:
                    selected = subprocess.run(
                        [rustup, "which", tool_name],
                        check=True,
                        stdout=subprocess.PIPE,
                        text=True,
                    ).stdout.strip()
                else:
                    selected = shutil.which(tool_name) or ""
                tool_path = Path(selected).resolve(strict=True)
                environment[path_env] = str(tool_path)
                environment[sha_env] = TIMING.open_regular_artifact(
                    tool_path, executable=True
                ).sha256
                environment[version_env] = subprocess.run(
                    [tool_path, "--version"],
                    check=True,
                    stdout=subprocess.PIPE,
                    text=True,
                ).stdout.strip()
            revision = "a" * 40
            with patch.dict(os.environ, environment, clear=False):
                TIMING.prepare_campaign(
                    Namespace(
                        manifest=manifest,
                        repository_root=repository,
                        binary=binary,
                        preflight_source=family / "a.smt2",
                        contract=contract_path,
                        revision=revision,
                        output_root=output_root,
                    )
                )
                for shard in range(2):
                    TIMING.run_shard(
                        Namespace(
                            root=output_root,
                            revision=revision,
                            shard=shard,
                            require_linux_affinity=False,
                        )
                    )
                self.assertTrue(
                    TIMING.audit_campaign(
                        Namespace(root=output_root, revision=revision)
                    )
                )
            audit, _ = TIMING.load_object(output_root / "audit.json")
            TIMING.validate_audit(audit, where="mini audit")
            self.assertEqual(audit["status"], "accepted")
            self.assertEqual(audit["counts"]["solved_tree"], 2)
            self.assertEqual(audit["counts"]["solved_stream"], 2)
            self.assertLess(audit["metrics"]["parse"]["aggregate_ratio"], 1.0)
            self.assertLess(audit["metrics"]["end_to_end"]["aggregate_ratio"], 1.0)
            self.assertEqual(audit["strata"]["expected_status"]["sat"]["source_count"], 1)
            self.assertEqual(audit["strata"]["expected_status"]["unsat"]["source_count"], 1)


if __name__ == "__main__":
    unittest.main()
