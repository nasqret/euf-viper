from __future__ import annotations

import copy
import importlib.util
import json
import os
import platform
import subprocess
import sys
import tempfile
import unittest
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
source = sys.stdin.buffer.read()
if len(args) == 4 and args[0] == "research-parser-semantics" and args[1] == "--parser" and args[3] == "-":
    parser = args[2]
    payload = {
        "applications": 1, "assertions": 1, "bool_data_terms": 0,
        "canonical_sha256": hashlib.sha256(source).hexdigest(),
        "contradiction": False, "disequalities": 0, "equalities": 1,
        "functions": 1, "interned_terms": 1, "parser": parser,
        "schema": "euf-viper.typed-parser-semantics.v1", "sort_bindings": 1,
        "sorts": 2, "source_bytes": len(source), "symbols": 2, "terms": 1,
        "unsupported_diagnostics": 0,
    }
    print(json.dumps(payload, allow_nan=False, separators=(",", ":"), sort_keys=True))
    raise SystemExit(0)
if len(args) != 6 or args[0] != "research-parser-timing" or args[1] != "--parser" or args[3] != "--phase" or args[5] != "-":
    raise SystemExit(f"unexpected timing invocation: {args!r}")
parser = args[2]
phase_arg = args[4]
phase = "end_to_end" if phase_arg == "end-to-end" else phase_arg
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
result = "parsed" if phase == "parse" else ("unsat" if b"UNSAT" in source else "sat")
result_digest = None if phase == "parse" else hashlib.sha256(result.encode()).hexdigest()
payload = {
    "elapsed_ns": elapsed,
    "parser": parser,
    "phase": phase,
    "result": result,
    "result_sha256": result_digest,
    "schema": "euf-viper.typed-parser-timing-observation.v1",
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
        "result_sha256": None if phase == "parse" else "f" * 64,
    }


def valid_semantic(parser: str, *, source_bytes: int = 5) -> dict[str, object]:
    return {
        "schema": TIMING.SEMANTIC_ATTESTATION_SCHEMA,
        "parser": parser,
        "source_bytes": source_bytes,
        "canonical_sha256": "1" * 64,
        "symbols": 2,
        "sorts": 2,
        "sort_bindings": 1,
        "functions": 1,
        "terms": 1,
        "applications": 0,
        "interned_terms": 1,
        "equalities": 0,
        "disequalities": 0,
        "assertions": 1,
        "bool_data_terms": 0,
        "unsupported_diagnostics": 0,
        "contradiction": False,
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
        target["payload"]["result_sha256"] = "2" * 64
    if parse_mismatch:
        pass
    semantic_attestations = {
        parser: valid_semantic(parser) for parser in ("tree", "stream")
    }
    if parse_mismatch:
        semantic_attestations["stream"]["canonical_sha256"] = "2" * 64
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
        "semantic_attestations": semantic_attestations,
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
        "baseline_only_solve": solved_tree and not solved_stream,
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
    def test_contract_dimensions_and_order_are_immutable(self) -> None:
        mutations = [
            ("campaign", "source_count", 7502),
            ("campaign", "expected_sources", 7502),
            ("campaign", "repetitions", 127),
            ("campaign", "shards", 127),
            ("execution", "warmup_rounds", 0),
            ("execution", "measured_rounds", 4),
            ("execution", "per_observation_timeout_seconds", 3),
            ("execution", "order", ["stream", "tree", "tree", "stream"]),
            ("execution", "semantic_digest", "fnv64"),
            ("gates", "common_sources_required_per_phase", 7502),
            ("gates", "zero_timeout_observations", False),
            ("gates", "no_baseline_only_solve", False),
        ]
        for section, key, value in mutations:
            altered = copy.deepcopy(CONTRACT)
            altered[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(
                TIMING.CampaignError
            ):
                TIMING.validate_contract(altered)
        renamed = copy.deepcopy(CONTRACT)
        renamed["name"] = "mutable"
        with self.assertRaises(TIMING.CampaignError):
            TIMING.validate_contract(renamed)

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
        counter_mismatch = valid_record()
        counter_mismatch["semantic_attestations"]["stream"]["terms"] += 1
        with self.assertRaisesRegex(TIMING.CampaignError, "attestations differ"):
            TIMING.validate_semantic_pair(
                counter_mismatch["semantic_attestations"],
                source_bytes=5,
                where="counter mismatch",
            )

    def test_all_preregistered_thresholds_must_pass(self) -> None:
        rows = [analyzed_row(100.0, 90.0) for _ in range(TIMING.LOCKED_SOURCE_COUNT)]
        metrics = {phase: TIMING.summarize_phase(rows, phase) for phase in TIMING.PHASES}
        gates = TIMING.evaluate_gates(rows, metrics, CONTRACT)
        self.assertTrue(gates["passed"])

        tail_rows = [analyzed_row(100.0, 80.0) for _ in range(7126)]
        tail_rows.extend(analyzed_row(100.0, 102.0) for _ in range(377))
        tail_metrics = {
            phase: TIMING.summarize_phase(tail_rows, phase) for phase in TIMING.PHASES
        }
        tail_gates = TIMING.evaluate_gates(tail_rows, tail_metrics, CONTRACT)
        self.assertFalse(
            tail_gates["parse_p95_all_source_overhead_below_one_percent"]
        )
        self.assertFalse(tail_gates["passed"])

    def test_no_miss_empty_and_small_populations_fail_closed(self) -> None:
        rows = [analyzed_row(100.0, 90.0) for _ in range(TIMING.LOCKED_SOURCE_COUNT)]
        metrics = TIMING.summarize_phase(rows, "parse")
        self.assertEqual(metrics["overhead_population_sources"], 7503)
        self.assertEqual(metrics["p95_all_source_overhead"], 0.0)
        empty = TIMING.summarize_phase([], "parse")
        self.assertIsNone(empty["p95_all_source_overhead"])
        with self.assertRaises(TIMING.CampaignError):
            TIMING.nearest_rank_p95([])
        small = [analyzed_row(100.0, 90.0)]
        small_metrics = {phase: TIMING.summarize_phase(small, phase) for phase in TIMING.PHASES}
        self.assertFalse(TIMING.evaluate_gates(small, small_metrics, CONTRACT)["passed"])

    def test_timeout_semantic_mismatch_and_baseline_only_solve_are_rejected(self) -> None:
        timeout_record = valid_record()
        timed = next(
            item
            for item in timeout_record["observations"]
            if item["stage"] == "measure" and item["phase"] == "parse"
        )
        timed.update(outcome="timeout", exit_code=None, diagnostic="timeout", payload=None)
        timeout_row = TIMING.analyze_source(timeout_record, CONTRACT)
        self.assertIsNone(timeout_row["phase_metrics"]["parse"])
        rows = [timeout_row] * TIMING.LOCKED_SOURCE_COUNT
        metrics = {phase: TIMING.summarize_phase(rows, phase) for phase in TIMING.PHASES}
        gates = TIMING.evaluate_gates(rows, metrics, CONTRACT)
        self.assertFalse(gates["zero_observation_timeouts"])
        self.assertFalse(gates["parse_full_common_population"])

        mismatch = TIMING.analyze_source(valid_record(parse_mismatch=True), CONTRACT)
        self.assertFalse(mismatch["parse_parity"])
        self.assertIsNone(mismatch["phase_metrics"]["parse"])

        rows = [analyzed_row(100.0, 90.0) for _ in range(TIMING.LOCKED_SOURCE_COUNT)]
        rows[0] = analyzed_row(100.0, 90.0, solved_stream=False)
        metrics = {phase: TIMING.summarize_phase(rows, phase) for phase in TIMING.PHASES}
        gates = TIMING.evaluate_gates(rows, metrics, CONTRACT)
        self.assertFalse(gates["no_solved_count_regression"])
        self.assertFalse(gates["no_baseline_only_solve"])
        self.assertFalse(gates["passed"])


class IdentityAndExecutionTests(unittest.TestCase):
    def test_child_environment_is_an_exact_allowlist(self) -> None:
        with patch.dict(
            os.environ,
            {
                "LD_PRELOAD": "/tmp/inject.so",
                "PYTHONPATH": "/tmp/shadow",
                "EUF_VIPER_T1_TIMING_CONTRACT": "/tmp/contract",
            },
            clear=False,
        ):
            child = TIMING.child_environment()
        self.assertEqual(
            child,
            {key: value for key, value in TIMING.RUNTIME_ENVIRONMENT.items() if value is not None},
        )
        self.assertNotIn("LD_PRELOAD", child)

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
                semantics = TIMING.collect_semantic_attestations(
                    executable, source, timeout_seconds=2
                )
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
            TIMING.validate_semantic_pair(
                semantics, source_bytes=len(source), where="descriptor semantics"
            )
            self.assertTrue(all(item["max_rss_kb"] >= 0 for item in observations))

    def test_one_source_runs_the_full_locked_record_schedule(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            source_path = directory / "source.smt2"
            source_path.write_bytes(b"SAT\n")
            source = TIMING.open_regular_artifact(source_path)
            binary = directory / "fake-timing"
            binary.write_text(FAKE_BINARY, encoding="utf-8")
            binary.chmod(0o500)
            python_path = Path(sys.executable).resolve(strict=True)
            python_artifact = TIMING.open_regular_artifact(
                python_path, executable=True
            )
            prepared = TIMING.PreparedCampaign(
                metadata={
                    "revision": "a" * 40,
                    "contract": {"sha256": ZERO_SHA256},
                    "python": {
                        "path": str(python_path),
                        "sha256": python_artifact.sha256,
                        "version": f"Python {platform.python_version()}",
                    },
                },
                prepare_artifact=source,
                contract=CONTRACT,
                workset=[],
                workset_artifact=source,
            )
            work = {
                "sequence": 0,
                "source_path": str(source.path),
                "source_sha256": source.sha256,
                "source_bytes": len(source.content),
                "relative_path": "QF_UF/fixture/source.smt2",
                "family": "fixture",
                "expected_status": "sat",
            }
            worker = {
                "hostname": "test",
                "platform": "test",
                "machine": "test",
                "cpu_id": None,
                "affinity": "unavailable-nonlinux",
            }
            with TIMING.open_verified_executable(binary) as executable:
                record = TIMING.run_work_item(
                    work,
                    shard=0,
                    prepared=prepared,
                    executable=executable,
                    worker=worker,
                )
            TIMING.validate_record(record, contract=CONTRACT, where="locked record")
            self.assertEqual(
                len(record["observations"]),
                (TIMING.LOCKED_WARMUP_ROUNDS + TIMING.LOCKED_MEASURED_ROUNDS)
                * len(TIMING.PHASES)
                * len(TIMING.ABBA_ORDER),
            )
            analyzed = TIMING.analyze_source(record, CONTRACT)
            self.assertTrue(analyzed["parse_parity"])
            self.assertTrue(analyzed["result_parity"])
            self.assertIsNotNone(analyzed["phase_metrics"]["parse"])
            self.assertIsNotNone(analyzed["phase_metrics"]["end_to_end"])

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


class CleanCheckoutAndWrapperTests(unittest.TestCase):
    def _receipt_repository(self, root: Path) -> tuple[Path, str]:
        repository = root / "repo"
        repository.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repository, check=True)
        receipt_script = ROOT / "scripts" / "wmi" / "t1_timing_checkout_receipt.py"
        runtime_paths = (
            "Cargo.lock",
            "Cargo.toml",
            "campaigns/t1-typed-parser-timing-v1.json",
            "scripts/bench/typed_parser_timing.py",
            "scripts/wmi/t1_timing_checkout_receipt.py",
            "scripts/wmi/t1_timing_common.sh",
            "scripts/wmi/euf_viper_t1_timing_prepare.sbatch",
            "scripts/wmi/euf_viper_t1_timing_array.sbatch",
            "scripts/wmi/euf_viper_t1_timing_audit.sbatch",
            "scripts/wmi/submit_t1_timing.sh",
            "src/main.rs",
            "src/smt2_stream.rs",
        )
        for relative in runtime_paths:
            path = repository / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"{relative}\n", encoding="ascii")
        (repository / ".gitignore").write_text("ignored-state\n", encoding="ascii")
        subprocess.run(["git", "add", "."], cwd=repository, check=True)
        subprocess.run(
            ["git", "-c", "user.name=T1", "-c", "user.email=t1@example.invalid", "commit", "-qm", "fixture"],
            cwd=repository,
            check=True,
        )
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repository, check=True, text=True, stdout=subprocess.PIPE
        ).stdout.strip()
        self.assertTrue(receipt_script.is_file())
        return repository, revision

    def _run_receipt(
        self, root: Path, repository: Path, revision: str
    ) -> subprocess.CompletedProcess[str]:
        environment = {**os.environ, "HOME": str(root / "home")}
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(ROOT / "scripts/wmi/t1_timing_checkout_receipt.py"),
                "--repository",
                str(repository),
                "--revision",
                revision,
                "--published-ref",
                "main",
                "--output",
                str(root / "receipt.json"),
            ],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_clean_checkout_receipt_binds_tree_and_runtime_blobs(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            repository, revision = self._receipt_repository(root)
            completed = self._run_receipt(root, repository, revision)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            receipt = json.loads((root / "receipt.json").read_text(encoding="ascii"))
            self.assertEqual(receipt["revision"], revision)
            self.assertEqual(receipt["published_ref"], "main")
            self.assertEqual(len(receipt["runtime_blobs"]), 12)
            self.assertEqual(receipt["cargo_configs"], [])
            TIMING.validate_checkout_receipt(
                TIMING.open_regular_artifact(root / "receipt.json"),
                repository_root=repository.resolve(),
                revision=revision,
                where="test receipt",
            )
            receipt["status_sha256"] = "f" * 64
            (root / "altered-receipt.json").write_bytes(TIMING.canonical_bytes(receipt))
            with self.assertRaisesRegex(TIMING.CampaignError, "mutable state"):
                TIMING.validate_checkout_receipt(
                    TIMING.open_regular_artifact(root / "altered-receipt.json"),
                    repository_root=repository.resolve(),
                    revision=revision,
                    where="altered receipt",
                )

    def test_ignored_and_untracked_influence_are_rejected_by_receipt(self) -> None:
        for filename, diagnostic in (
            ("untracked-state", "tracked or untracked influence"),
            ("ignored-state", "ignored influence"),
        ):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory_name:
                root = Path(directory_name)
                repository, revision = self._receipt_repository(root)
                (repository / filename).write_text("ambient\n", encoding="ascii")
                completed = self._run_receipt(root, repository, revision)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(diagnostic, completed.stderr)

    def test_wrappers_override_paths_and_forward_all_expected_hashes(self) -> None:
        text = "\n".join(
            (ROOT / relative).read_text(encoding="utf-8")
            for relative in (
                "scripts/wmi/euf_viper_t1_timing_prepare.sbatch",
                "scripts/wmi/euf_viper_t1_timing_array.sbatch",
                "scripts/wmi/euf_viper_t1_timing_audit.sbatch",
            )
        )
        for variable in (
            "EUF_VIPER_T1_TIMING_CONTRACT",
            "EUF_VIPER_T1_TIMING_MANIFEST",
            "EUF_VIPER_T1_TIMING_ROOT",
            "EUF_VIPER_SHARED_CORPUS",
        ):
            self.assertIn(f"unset {variable}", (ROOT / "scripts/wmi/t1_timing_common.sh").read_text())
        for option in (
            "--expected-contract-sha256",
            "--expected-manifest-sha256",
            "--expected-checkout-receipt-sha256",
        ):
            self.assertEqual(text.count(option), 3)

        environment = {
            **os.environ,
            "EUF_VIPER_T1_TIMING_CONTRACT": "/tmp/evil-contract",
            "EUF_VIPER_T1_TIMING_MANIFEST": "/tmp/evil-manifest",
            "EUF_VIPER_T1_TIMING_ROOT": "/tmp/evil-root",
            "EUF_VIPER_SHARED_CORPUS": "/tmp/evil-corpus",
            "PYTHONPATH": "/tmp/shadow",
            "RUSTFLAGS": "--cfg hidden_flag",
            "CARGO_PROFILE_RELEASE_LTO": "false",
            "CC": "/tmp/compiler-wrapper",
            "LD_PRELOAD": "/tmp/inject.so",
        }
        command = (
            "source scripts/wmi/t1_timing_common.sh; t1_reject_ambient_influence; "
            "test -z \"${EUF_VIPER_T1_TIMING_CONTRACT-}\"; "
            "test -z \"${EUF_VIPER_T1_TIMING_MANIFEST-}\"; "
            "test -z \"${EUF_VIPER_T1_TIMING_ROOT-}\"; "
            "test -z \"${EUF_VIPER_SHARED_CORPUS-}\"; "
            "test -z \"${PYTHONPATH-}\"; test -z \"${RUSTFLAGS-}\"; "
            "test -z \"${CARGO_PROFILE_RELEASE_LTO-}\"; test -z \"${CC-}\"; "
            "test -z \"${LD_PRELOAD-}\""
        )
        subprocess.run(["bash", "-c", command], cwd=ROOT, env=environment, check=True)

        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "contract"
            path.write_text("changed\n", encoding="ascii")
            completed = subprocess.run(
                [
                    "bash",
                    "-c",
                    "source scripts/wmi/t1_timing_common.sh; "
                    f"t1_verify_bound_file '{path}' '{'0' * 64}' contract",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("hash mismatch", completed.stderr)

    def test_timed_rust_path_has_no_symbol_clone_telemetry(self) -> None:
        source = (ROOT / "src/main.rs").read_text(encoding="utf-8")
        body = source.split("fn parse_for_timing(", 1)[1].split("fn parse_for_semantics(", 1)[0]
        self.assertNotIn("finish_with_symbol_names", body)
        self.assertIn("timed_parser_path_never_clones_symbol_telemetry", source)


if __name__ == "__main__":
    unittest.main()
