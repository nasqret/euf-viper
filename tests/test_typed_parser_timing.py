from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
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
GUARD_SCRIPT = ROOT / "scripts" / "wmi" / "t1_timing_build_guard.py"
GUARD_SPEC = importlib.util.spec_from_file_location("t1_timing_build_guard", GUARD_SCRIPT)
assert GUARD_SPEC is not None and GUARD_SPEC.loader is not None
BUILD_GUARD = importlib.util.module_from_spec(GUARD_SPEC)
GUARD_SPEC.loader.exec_module(BUILD_GUARD)
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
if os.environ.get("EUF_VIPER_BACKEND") != "auto":
    raise SystemExit("backend drift")
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


def captured_payload(payload: dict[str, object]) -> dict[str, object]:
    stdout = TIMING.canonical_bytes(payload)
    stderr = b""
    return {
        "exit_code": 0,
        "external_elapsed_ns": 1000,
        "max_rss_kb": 4096,
        "stdout_base64": TIMING.encode_raw(stdout),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_base64": TIMING.encode_raw(stderr),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "payload": payload,
    }


def valid_semantic_capture(parser: str, *, source_bytes: int = 5) -> dict[str, object]:
    return captured_payload(valid_semantic(parser, source_bytes=source_bytes))


def valid_worker() -> dict[str, object]:
    return {
        "hostname": "c1n1.cluster.wmi.amu.edu.pl",
        "platform": "Linux",
        "machine": "x86_64",
        "cpu_id": 0,
        "affinity": "sched_setaffinity-singleton.v1",
        "cpu_model": "fixture CPU",
        "microcode": "0x1",
        "physical_package_id": 0,
        "core_id": 0,
        "thread_siblings_list": "0",
        "numa_node": 0,
        "scaling_governor": "performance",
        "scaling_driver": "fixture",
        "scaling_min_khz": 1000,
        "scaling_max_khz": 1000,
        "scaling_current_khz": 1000,
        "turbo_state": "1",
        "slurm_partition": "cpu_idle",
        "slurm_nodelist": "c1n1",
        "slurm_cpus_per_task": 1,
        "slurm_cpu_bind": "cores",
        "slurm_mem_bind": "local",
        "slurm_threads_per_core": 1,
        "slurm_job_cpus_per_node": 64,
        "slurm_job_num_nodes": 1,
        "slurm_cpu_freq_req": "high:UserSpace",
        "physical_cores_on_node": 64,
        "submission_mode": "full",
        "placement_contract": "slurm-exclusive-core-local-high-userspace.v1",
        "governor_control": True,
        "exclusive_control": False,
        "libc": {
            "path": "/usr/lib/libc.so.6",
            "sha256": "3" * 64,
            "bytes": 1,
            "name": "glibc",
            "version": "2.35",
        },
        "allocator": "system-libc",
        "backend": "auto",
    }


def valid_observation(schedule: dict[str, object], *, source_bytes: int = 5) -> dict[str, object]:
    payload = valid_payload(
        str(schedule["parser"]), str(schedule["phase"]), source_bytes=source_bytes
    )
    return {
        **schedule,
        "outcome": "ok",
        **captured_payload(payload),
        "diagnostic": None,
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
        parser: valid_semantic_capture(parser) for parser in ("tree", "stream")
    }
    if parse_mismatch:
        semantic_attestations["stream"]["payload"]["canonical_sha256"] = "2" * 64
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
        "worker": valid_worker(),
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


class RawEvidenceBindingTests(unittest.TestCase):
    def test_timing_payload_cannot_change_independently_of_stdout(self) -> None:
        schedule = next(
            item
            for item in TIMING.expected_schedule(
                CONTRACT, measured_rounds=1, warmup_rounds=0
            )
            if item["parser"] == "stream" and item["phase"] == "parse"
        )
        observation = valid_observation(schedule)
        observation["payload"]["elapsed_ns"] = 1
        with self.assertRaisesRegex(TIMING.CampaignError, "stored payload differs"):
            TIMING.validate_observation(
                observation, schedule=schedule, source_bytes=5, where="elapsed attack"
            )
        observation = valid_observation(schedule)
        observation["stdout_sha256"] = ZERO_SHA256
        observation["stderr_sha256"] = ZERO_SHA256
        with self.assertRaisesRegex(TIMING.CampaignError, "stdout SHA-256"):
            TIMING.validate_observation(
                observation, schedule=schedule, source_bytes=5, where="zero hash attack"
            )

    def test_semantic_counters_and_digest_must_equal_captured_stdout(self) -> None:
        pair = {parser: valid_semantic_capture(parser) for parser in ("tree", "stream")}
        pair["stream"]["payload"]["terms"] = 999
        pair["stream"]["payload"]["canonical_sha256"] = "f" * 64
        with self.assertRaisesRegex(TIMING.CampaignError, "stored semantic payload"):
            TIMING.validate_semantic_pair(pair, source_bytes=5, where="semantic attack")

    def test_malformed_raw_capture_and_malformed_jsonl_fail_closed(self) -> None:
        schedule = TIMING.expected_schedule(
            CONTRACT, measured_rounds=1, warmup_rounds=0
        )[0]
        observation = valid_observation(schedule)
        observation["stdout_base64"] = "***"
        with self.assertRaisesRegex(TIMING.CampaignError, "malformed base64"):
            TIMING.validate_observation(
                observation, schedule=schedule, source_bytes=5, where="base64 attack"
            )
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name).resolve()
            for name, content in (
                ("truncated.jsonl", b'{"sequence":0}'),
                ("nonfinite.jsonl", b'{"sequence":NaN}\n'),
                ("duplicate-key.jsonl", b'{"sequence":0,"sequence":1}\n'),
            ):
                path = root / name
                path.write_bytes(content)
                with self.subTest(name=name), self.assertRaises(TIMING.CampaignError):
                    TIMING.load_jsonl(path)

    def test_duplicate_and_missing_record_sequences_fail(self) -> None:
        with self.assertRaises(TIMING.CampaignError):
            TIMING.assert_complete_record_sequences([{"sequence": 0}, {"sequence": 0}], 2)
        with self.assertRaises(TIMING.CampaignError):
            TIMING.assert_complete_record_sequences([{"sequence": 0}], 2)

    def test_sealed_shard_receipt_precedes_audit_and_detects_post_close_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            (root / "shards").mkdir()
            dummy = root / "prepare.json"
            dummy.write_bytes(b"prepare\n")
            artifact = TIMING.open_regular_artifact(dummy)
            prepared = TIMING.PreparedCampaign(
                metadata={
                    "revision": "a" * 40,
                    "contract": {"sha256": "b" * 64},
                    "shard_count": 1,
                },
                prepare_artifact=artifact,
                contract=CONTRACT,
                workset=[],
                workset_artifact=artifact,
            )
            records_artifact, receipt_artifact = TIMING.publish_sealed_shard(
                root=root,
                shard=0,
                records=[valid_record()],
                prepared=prepared,
                worker=valid_worker(),
            )
            self.assertTrue(receipt_artifact.path.is_file())
            TIMING.load_sealed_shard(root=root, shard=0, prepared=prepared)
            records_artifact.path.chmod(0o600)
            records_artifact.path.write_bytes(records_artifact.content + b"{}\n")
            with self.assertRaisesRegex(
                TIMING.CampaignError, "sealed artifact mode mismatch|file identity mismatch"
            ):
                TIMING.load_sealed_shard(root=root, shard=0, prepared=prepared)

    def test_shard_set_close_rejects_self_consistent_elapsed_and_semantic_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            (root / "shards").mkdir()
            dummy = root / "prepare.json"
            dummy.write_bytes(b"prepare\n")
            artifact = TIMING.open_regular_artifact(dummy)
            prepared = TIMING.PreparedCampaign(
                metadata={
                    "revision": "a" * 40,
                    "contract": {"sha256": "b" * 64},
                    "shard_count": 1,
                },
                prepare_artifact=artifact,
                contract=CONTRACT,
                workset=[],
                workset_artifact=artifact,
            )
            records_artifact, receipt_artifact = TIMING.publish_sealed_shard(
                root=root,
                shard=0,
                records=[valid_record()],
                prepared=prepared,
                worker=valid_worker(),
            )
            _, _, _, receipt = TIMING.load_sealed_shard(
                root=root, shard=0, prepared=prepared
            )
            closed, closed_artifact = TIMING.publish_shard_set_receipt(
                root=root,
                prepared=prepared,
                shards={
                    "00000": TIMING.shard_set_entry(
                        records_artifact, receipt_artifact, receipt
                    )
                },
            )

            rewritten = valid_record()
            for observation in rewritten["observations"]:
                observation["payload"]["elapsed_ns"] = 1
                raw = TIMING.canonical_bytes(observation["payload"])
                observation["stdout_base64"] = TIMING.encode_raw(raw)
                observation["stdout_sha256"] = hashlib.sha256(raw).hexdigest()
            for semantic in rewritten["semantic_attestations"].values():
                semantic["payload"]["terms"] = 999
                raw = TIMING.canonical_bytes(semantic["payload"])
                semantic["stdout_base64"] = TIMING.encode_raw(raw)
                semantic["stdout_sha256"] = hashlib.sha256(raw).hexdigest()
            TIMING.validate_record(rewritten, contract=CONTRACT, where="rewritten record")

            shard = root / "shards" / "shard-00000"
            shard.chmod(0o700)
            records_path = shard / "records.jsonl"
            receipt_path = shard / "receipt.json"
            records_path.chmod(0o600)
            receipt_path.chmod(0o600)
            rewritten_bytes = TIMING.canonical_bytes(rewritten)
            records_path.write_bytes(rewritten_bytes)
            records_path.chmod(0o400)
            rebound = TIMING.open_regular_artifact(records_path)
            receipt["records"] = TIMING.file_binding(rebound)
            receipt["records_chain"] = TIMING.record_hash_chain(rebound.content)
            receipt_path.write_bytes(TIMING.canonical_bytes(receipt))
            receipt_path.chmod(0o400)
            shard.chmod(0o500)

            with self.assertRaisesRegex(TIMING.CampaignError, "changed after close"):
                TIMING.revalidate_shard_set(
                    root=root,
                    prepared=prepared,
                    expected=closed,
                    expected_artifact=closed_artifact,
                    where="post-check attack",
                )


class ScheduleTests(unittest.TestCase):
    def test_contract_dimensions_and_order_are_immutable(self) -> None:
        mutations = [
            ("campaign", "source_count", 7502),
            ("campaign", "expected_sources", 7502),
            ("campaign", "shards", 127),
            ("execution", "warmup_rounds", 0),
            ("execution", "measured_rounds", 4),
            ("execution", "per_observation_timeout_seconds", 3),
            ("execution", "order", ["stream", "tree", "tree", "stream"]),
            ("execution", "semantic_digest", "fnv64"),
            ("corpus", "accepted_manifest_sha256", "0" * 64),
            ("corpus", "accepted_parity_receipt_sha256", "0" * 64),
            ("timing_environment", "partition", "ambient"),
            ("timing_environment", "slurm_nodelist", "ambient"),
            ("timing_environment", "memory_binding", "ambient"),
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
        for section, alias in (
            ("campaign", "repetitions"),
            ("campaign", "timing_repetitions"),
            ("execution", "rounds"),
        ):
            altered = copy.deepcopy(CONTRACT)
            altered[section][alias] = 128
            with self.subTest(alias=alias), self.assertRaises(TIMING.CampaignError):
                TIMING.validate_contract(altered)
        missing = copy.deepcopy(CONTRACT)
        del missing["campaign"]["shards"]
        with self.assertRaises(TIMING.CampaignError):
            TIMING.validate_contract(missing)

    def test_frozen_parity_receipt_binds_the_accepted_manifest(self) -> None:
        path = ROOT / CONTRACT["corpus"]["accepted_parity_receipt_path"]
        artifact = TIMING.load_accepted_parity_receipt(
            path, contract=CONTRACT, where="frozen parity receipt"
        )
        self.assertEqual(artifact.sha256, TIMING.ACCEPTED_PARITY_RECEIPT_SHA256)
        with tempfile.TemporaryDirectory() as directory_name:
            frozen = Path(directory_name)
            for filename in ("receipt.json", *TIMING.ACCEPTED_PARITY_LOCAL_ARTIFACTS.values()):
                (frozen / filename).write_bytes((path.parent / filename).read_bytes())
            TIMING.load_accepted_parity_receipt(
                frozen / "receipt.json", contract=CONTRACT, where="copied frozen bundle"
            )
            prepare = frozen / "prepare.json"
            prepare.write_bytes(prepare.read_bytes() + b"\n")
            with self.assertRaisesRegex(TIMING.CampaignError, "frozen local artifact hash mismatch"):
                TIMING.load_accepted_parity_receipt(
                    frozen / "receipt.json", contract=CONTRACT, where="modified frozen bundle"
                )
            altered = frozen / "altered-receipt.json"
            value = json.loads(path.read_text(encoding="ascii"))
            value["remote_artifacts"]["manifest_sha256"] = "f" * 64
            altered.write_bytes(TIMING.canonical_bytes(value))
            with self.assertRaisesRegex(TIMING.CampaignError, "receipt hash mismatch"):
                TIMING.load_accepted_parity_receipt(
                    altered, contract=CONTRACT, where="altered parity receipt"
                )

    def test_worker_identity_rejects_missing_state_but_allows_unenforced_control(self) -> None:
        worker = valid_worker()
        worker["governor_control"] = False
        worker["exclusive_control"] = False
        TIMING.validate_worker(worker, where="research-only worker")
        for key, value in (
            ("scaling_governor", "unavailable"),
            ("turbo_state", "unavailable"),
            ("scaling_current_khz", 0),
        ):
            altered = copy.deepcopy(worker)
            altered[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(
                TIMING.CampaignError, "identity is unavailable"
            ):
                TIMING.validate_worker(altered, where="missing worker identity")

    def test_worker_homogeneity_rejects_mixed_identity(self) -> None:
        first = valid_worker()
        second = copy.deepcopy(first)
        second["cpu_id"] = 2
        second["core_id"] = 2
        second["thread_siblings_list"] = "2"
        second["scaling_current_khz"] = 999
        TIMING.require_homogeneous_workers([first, second])
        second["microcode"] = "0x2"
        with self.assertRaisesRegex(TIMING.CampaignError, "mixed hardware"):
            TIMING.require_homogeneous_workers([first, second])
        with self.assertRaisesRegex(TIMING.CampaignError, "mixed hardware"):
            TIMING.require_homogeneous_workers([])

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
        counter_mismatch["semantic_attestations"]["stream"]["payload"]["terms"] += 1
        with self.assertRaisesRegex(TIMING.CampaignError, "stored semantic payload"):
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
        TIMING.validate_record(timeout_record, contract=CONTRACT, where="one timeout")
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

    def test_full_placement_accepts_coded_slurm_frequency_after_kernel_proof(self) -> None:
        environment = {
            "SLURM_JOB_CPUS_PER_NODE": "8",
            "SLURM_JOB_NUM_NODES": "1",
            "SLURM_CPU_FREQ_REQ": "4294967294",
            "SLURM_CPUS_PER_TASK": "1",
            "SLURM_THREADS_PER_CORE": "1",
            "SLURM_CPU_BIND_TYPE": "cores",
            "SLURM_MEM_BIND_TYPE": "local",
        }

        def one_line(path: Path, *, unavailable: str = "unavailable") -> str:
            values = {
                "scaling_governor": "userspace",
                "scaling_driver": "fixture-driver",
                "thread_siblings_list": "0",
                "no_turbo": "1",
            }
            return values.get(path.name, "fixture")

        def integer(path: Path) -> int:
            return 2_400_000 if path.name.startswith("scaling_") else 0

        with (
            patch.dict(os.environ, environment, clear=True),
            patch.object(TIMING.sys, "platform", "linux"),
            patch.object(TIMING.os, "sched_getaffinity", return_value={0}, create=True),
            patch.object(TIMING.os, "sched_setaffinity", create=True),
            patch.object(TIMING, "_read_one_line", side_effect=one_line),
            patch.object(TIMING, "_read_integer", side_effect=integer),
            patch.object(
                TIMING,
                "_cpuinfo_fields",
                return_value={"model name": "fixture CPU", "microcode": "0x1"},
            ),
            patch.object(TIMING, "_physical_core_count", return_value=8),
            patch.object(TIMING.platform, "node", return_value="fixture-node"),
            patch.object(TIMING.platform, "system", return_value="Linux"),
            patch.object(TIMING.platform, "machine", return_value="x86_64"),
            patch.object(
                TIMING, "loaded_libc_identity", return_value=valid_worker()["libc"]
            ),
        ):
            worker = TIMING.bind_worker(
                contract=CONTRACT,
                require_linux_affinity=False,
                submission_mode="full",
                require_placement_controls=True,
            )

        self.assertEqual(worker["slurm_cpu_freq_req"], "4294967294")
        self.assertTrue(worker["governor_control"])
        self.assertTrue(worker["exclusive_control"])

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

    def test_path_replacement_cannot_change_opened_executable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fake-timing"
            binary.write_text(FAKE_BINARY, encoding="utf-8")
            binary.chmod(0o500)
            replacement = Path(directory) / "replacement"
            replacement.write_text(
                "#!/bin/sh\nprintf 'unknown\\n'\n", encoding="ascii"
            )
            replacement.chmod(0o500)

            with TIMING.open_verified_executable(binary) as executable:
                replacement.replace(binary)
                execution = TIMING.execute_binary(
                    executable,
                    b"SAT\n",
                    arguments=[
                        "research-parser-timing",
                        "--parser",
                        "tree",
                        "--phase",
                        "end-to-end",
                        "-",
                    ],
                    timeout_seconds=2,
                )

            self.assertEqual(execution.exit_code, 0)
            self.assertEqual(json.loads(execution.stdout)["result"], "sat")

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
            worker = valid_worker()
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

    def test_oversized_output_is_rejected_instead_of_retained_truncated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fake-timing"
            binary.write_text(FAKE_BINARY, encoding="utf-8")
            binary.chmod(0o500)
            schedule = TIMING.expected_schedule(
                CONTRACT, measured_rounds=1, warmup_rounds=0
            )[0]
            with TIMING.open_verified_executable(binary) as executable:
                with self.assertRaisesRegex(TIMING.CampaignError, "exact-capture limit"):
                    TIMING.execute_scheduled_observation(
                        executable,
                        b"FLOOD",
                        schedule,
                        timeout_seconds=2,
                    )

    def test_publication_never_replaces_existing_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            TIMING.publish_new(path, b"first\n")
            with self.assertRaisesRegex(TIMING.CampaignError, "refusing to replace"):
                TIMING.publish_new(path, b"second\n")
            self.assertEqual(path.read_bytes(), b"first\n")


class BuildReceiptValidationTests(unittest.TestCase):
    def test_guarded_build_receipt_binds_inventory_monitor_tools_libc_and_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name).resolve()
            snapshot = root / "source"
            snapshot.mkdir()
            revision = "a" * 40
            inventory = {
                "schema": "euf-viper.t1-source-snapshot-inventory.v1",
                "repository": str(root),
                "revision": revision,
                "snapshot": str(snapshot),
                "tree": "b" * 40,
                "files": 1,
                "source_bytes": 1,
                "entries_sha256": "c" * 64,
            }
            pre = TIMING.publish_json(root / "pre.json", inventory)
            post = TIMING.publish_json(root / "post.json", inventory)
            events = TIMING.publish_new(root / "events.jsonl", b"")
            monitor_payload = {
                "schema": "euf-viper.t1-mutation-monitor-receipt.v2",
                "control": "parent-owned-pipe-eof.v1",
                "monitor_pid": 101,
                "parent_pid": 100,
                "poll_cycles": 2,
                "snapshot": str(snapshot),
                "watched_directories": 1,
                "watch_mask": 1,
                "event_count": 0,
                "events": TIMING.file_binding(events),
                "status": "clean",
            }
            monitor = TIMING.publish_json(root / "monitor.json", monitor_payload)
            dependency_root = root / "dependencies"
            vendor_dir = dependency_root / "vendor"
            vendor_dir.mkdir(parents=True)
            (vendor_dir / "crate").write_bytes(b"x")
            dependency_events = TIMING.publish_new(
                root / "dependency-events.jsonl", b""
            )
            dependency_monitor_payload = {
                "schema": "euf-viper.t1-mutation-monitor-receipt.v2",
                "control": "parent-owned-pipe-eof.v1",
                "monitor_pid": 102,
                "parent_pid": 100,
                "poll_cycles": 2,
                "snapshot": str(dependency_root),
                "watched_directories": 2,
                "watch_mask": 1,
                "event_count": 0,
                "events": TIMING.file_binding(dependency_events),
                "status": "clean",
            }
            dependency_monitor = TIMING.publish_json(
                root / "dependency-monitor.json", dependency_monitor_payload
            )
            dependency_inventory = {
                "schema": "euf-viper.t1-external-dependency-inventory.v1",
                "root": str(dependency_root),
                "directories": 2,
                "files": 1,
                "bytes": 1,
                "entries_sha256": "f" * 64,
            }
            dependency_pre = TIMING.publish_json(
                root / "dependency-pre.json", dependency_inventory
            )
            dependency_post = TIMING.publish_json(
                root / "dependency-post.json", dependency_inventory
            )
            binary_path = root / "euf-viper"
            binary_path.write_bytes(b"binary")
            binary_path.chmod(0o500)
            binary = {
                "path": str(binary_path),
                "sha256": hashlib.sha256(b"binary").hexdigest(),
                "bytes": 6,
                "execution": TIMING.executable_binding_contract(),
            }
            python_identity = {
                "path": "/usr/bin/python3",
                "sha256": "d" * 64,
                "version": "Python 3.12.0",
            }
            tools = {
                name: {
                    "path": f"/usr/bin/{name}",
                    "sha256": str(index) * 64,
                    "bytes": 1,
                    "version": f"{name} 1.0",
                }
                for index, name in enumerate(sorted(TIMING.BUILD_TOOL_ENVIRONMENT), 1)
            }
            elf_template = {
                "abi_version": 0,
                "class": "ELF64",
                "endianness": "little",
                "interpreter": None,
                "machine": "x86_64",
                "needed": [],
                "osabi": 0,
                "rpath": [],
                "runpath": [],
                "soname": None,
                "type": "shared-or-pie",
            }
            interpreter_path = "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
            libc_path = "/usr/lib/x86_64-linux-gnu/libc.so.6"
            objects = [
                {
                    "bytes": binary["bytes"],
                    "elf": {
                        **elf_template,
                        "interpreter": "/lib64/ld-linux-x86-64.so.2",
                        "needed": ["libc.so.6"],
                    },
                    "path": binary["path"],
                    "role": "binary",
                    "sha256": binary["sha256"],
                },
                {
                    "bytes": 1,
                    "elf": {**elf_template, "soname": "ld-linux-x86-64.so.2"},
                    "path": interpreter_path,
                    "role": "interpreter",
                    "sha256": "9" * 64,
                },
                {
                    "bytes": 1,
                    "elf": {**elf_template, "soname": "libc.so.6"},
                    "path": libc_path,
                    "role": "dependency",
                    "sha256": "e" * 64,
                },
            ]
            edges = [
                {
                    "needed": "libc.so.6",
                    "resolved": libc_path,
                    "source": binary["path"],
                }
            ]
            linux_elf = {
                "schema": "euf-viper.t1-linux-elf-provenance.v1",
                "binary_sha256": binary["sha256"],
                "closure_sha256": hashlib.sha256(
                    TIMING.canonical_bytes({"edges": edges, "objects": objects})
                ).hexdigest(),
                "default_search": ["/usr/lib/x86_64-linux-gnu"],
                "edges": edges,
                "interpreter": {
                    "bytes": 1,
                    "path": interpreter_path,
                    "requested": "/lib64/ld-linux-x86-64.so.2",
                    "sha256": "9" * 64,
                },
                "objects": objects,
            }
            (root / "cargo-home").mkdir()
            (root / "fetch-cargo-home").mkdir()
            (root / "target").mkdir()
            receipt = {
                "schema": TIMING.BUILD_RECEIPT_SCHEMA,
                "status": "clean",
                "revision": revision,
                "source_snapshot": str(snapshot),
                "pre_inventory": {
                    "path": str(pre.path),
                    "sha256": pre.sha256,
                    "payload": inventory,
                },
                "post_inventory": {
                    "path": str(post.path),
                    "sha256": post.sha256,
                    "payload": inventory,
                },
                "mutation_monitor": {
                    "path": str(monitor.path),
                    "sha256": monitor.sha256,
                    "payload": monitor_payload,
                },
                "dependency_pre_inventory": {
                    "path": str(dependency_pre.path),
                    "sha256": dependency_pre.sha256,
                    "payload": dependency_inventory,
                },
                "dependency_post_inventory": {
                    "path": str(dependency_post.path),
                    "sha256": dependency_post.sha256,
                    "payload": dependency_inventory,
                },
                "dependency_mutation_monitor": {
                    "path": str(dependency_monitor.path),
                    "sha256": dependency_monitor.sha256,
                    "payload": dependency_monitor_payload,
                },
                "binary": {
                    **{key: binary[key] for key in ("path", "sha256", "bytes")},
                    "attestation": "inherited-open-descriptor.v1",
                },
                "linux_elf": linux_elf,
                "linker_selection": {
                    "driver_path": tools["cc"]["path"],
                    "driver_sha256": tools["cc"]["sha256"],
                    "request": "-fuse-ld=bfd",
                    "resolved_path": tools["ld"]["path"],
                    "resolved_sha256": tools["ld"]["sha256"],
                },
                "python": {**python_identity, "bytes": 1},
                "tools": tools,
                "libc": {
                    "path": libc_path,
                    "sha256": "e" * 64,
                    "bytes": 1,
                    "name": "glibc",
                    "version": "2.35",
                },
                "build": {
                    "allocator": "system-libc",
                    "backend": "auto",
                    "cargo_home": str(root / "cargo-home"),
                    "cargo_profile": "release",
                    "dependency_mode": "locked-vendor-offline-v1",
                    "features": ["finite-symmetry"],
                    "fetch_cargo_home": str(root / "fetch-cargo-home"),
                    "locked": True,
                    "offline": True,
                    "rustflags": f"-C linker={tools['cc']['path']} -C link-arg=-fuse-ld=bfd",
                    "target_dir": str(root / "target"),
                    "vendor_dir": str(vendor_dir),
                },
            }
            artifact = TIMING.publish_json(root / "build-receipt.json", receipt)
            TIMING.validate_build_receipt(
                artifact,
                revision=revision,
                binary=binary,
                python_identity=python_identity,
                build_tools=tools,
                where="build receipt fixture",
            )
            (snapshot / "target").mkdir()
            inside = copy.deepcopy(receipt)
            inside["build"]["target_dir"] = str(snapshot / "target")
            inside_artifact = TIMING.publish_json(root / "inside-build-receipt.json", inside)
            with self.assertRaisesRegex(TIMING.CampaignError, "inside the watched source"):
                TIMING.validate_build_receipt(
                    inside_artifact,
                    revision=revision,
                    binary=binary,
                    python_identity=python_identity,
                    build_tools=tools,
                    where="inside build receipt fixture",
                )
            altered_dependency = copy.deepcopy(dependency_inventory)
            altered_dependency["entries_sha256"] = "0" * 64
            altered_dependency_artifact = TIMING.publish_json(
                root / "altered-dependency-post.json", altered_dependency
            )
            dependency_drift = copy.deepcopy(receipt)
            dependency_drift["dependency_post_inventory"] = {
                "path": str(altered_dependency_artifact.path),
                "sha256": altered_dependency_artifact.sha256,
                "payload": altered_dependency,
            }
            dependency_drift_artifact = TIMING.publish_json(
                root / "dependency-drift-build-receipt.json", dependency_drift
            )
            with self.assertRaisesRegex(TIMING.CampaignError, "dependency inventory changed"):
                TIMING.validate_build_receipt(
                    dependency_drift_artifact,
                    revision=revision,
                    binary=binary,
                    python_identity=python_identity,
                    build_tools=tools,
                    where="dependency drift build receipt fixture",
                )
            online = copy.deepcopy(receipt)
            online["build"]["offline"] = False
            online_artifact = TIMING.publish_json(root / "online-build-receipt.json", online)
            with self.assertRaisesRegex(TIMING.CampaignError, "configuration drifted"):
                TIMING.validate_build_receipt(
                    online_artifact,
                    revision=revision,
                    binary=binary,
                    python_identity=python_identity,
                    build_tools=tools,
                    where="online build receipt fixture",
                )
            dependency_events.path.chmod(0o600)
            dependency_events.path.write_bytes(b"transient dependency mutation\n")
            dependency_events.path.chmod(0o400)
            with self.assertRaisesRegex(TIMING.CampaignError, "event log"):
                TIMING.validate_build_receipt(
                    artifact,
                    revision=revision,
                    binary=binary,
                    python_identity=python_identity,
                    build_tools=tools,
                    where="modified dependency monitor fixture",
                )
            dependency_events.path.chmod(0o600)
            dependency_events.path.write_bytes(b"")
            dependency_events.path.chmod(0o400)
            events.path.chmod(0o600)
            events.path.write_bytes(b"post-check mutation\n")
            events.path.chmod(0o400)
            with self.assertRaisesRegex(TIMING.CampaignError, "event log"):
                TIMING.validate_build_receipt(
                    artifact,
                    revision=revision,
                    binary=binary,
                    python_identity=python_identity,
                    build_tools=tools,
                    where="modified build receipt fixture",
                )


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
            "results/wmi/typed-parser-parity-146510/audit.json",
            "results/wmi/typed-parser-parity-146510/prepare.json",
            "results/wmi/typed-parser-parity-146510/preflight.json",
            "results/wmi/typed-parser-parity-146510/receipt.json",
            "results/wmi/typed-parser-parity-146510/submission.json",
            "results/wmi/typed-parser-parity-146510/typed-parser-parity-20260713T221314Z-66099-independent.json",
            "scripts/bench/typed_parser_timing.py",
            "scripts/wmi/t1_timing_build_guard.py",
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
            self.assertEqual(
                set(receipt["runtime_blobs"]),
                {
                    "Cargo.lock",
                    "Cargo.toml",
                    "campaigns/t1-typed-parser-timing-v1.json",
                    "results/wmi/typed-parser-parity-146510/audit.json",
                    "results/wmi/typed-parser-parity-146510/prepare.json",
                    "results/wmi/typed-parser-parity-146510/preflight.json",
                    "results/wmi/typed-parser-parity-146510/receipt.json",
                    "results/wmi/typed-parser-parity-146510/submission.json",
                    "results/wmi/typed-parser-parity-146510/typed-parser-parity-20260713T221314Z-66099-independent.json",
                    "scripts/bench/typed_parser_timing.py",
                    "scripts/wmi/euf_viper_t1_timing_array.sbatch",
                    "scripts/wmi/euf_viper_t1_timing_audit.sbatch",
                    "scripts/wmi/euf_viper_t1_timing_prepare.sbatch",
                    "scripts/wmi/submit_t1_timing.sh",
                    "scripts/wmi/t1_timing_build_guard.py",
                    "scripts/wmi/t1_timing_checkout_receipt.py",
                    "scripts/wmi/t1_timing_common.sh",
                    "src/main.rs",
                    "src/smt2_stream.rs",
                },
            )
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

    def test_exact_snapshot_inventory_rejects_untracked_build_influence(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            repository, revision = self._receipt_repository(root)
            archive = root / "source.tar"
            snapshot = root / "snapshot"
            snapshot.mkdir()
            subprocess.run(
                ["git", "archive", "--format=tar", f"--output={archive}", revision],
                cwd=repository,
                check=True,
            )
            subprocess.run(["tar", "-xf", archive, "-C", snapshot], check=True)
            guard = ROOT / "scripts/wmi/t1_timing_build_guard.py"
            output = root / "inventory.json"
            command = [
                sys.executable,
                "-I",
                "-B",
                str(guard),
                "inventory",
                "--repository",
                str(repository),
                "--revision",
                revision,
                "--snapshot",
                str(snapshot),
                "--output",
                str(output),
            ]
            subprocess.run(command, check=True)
            payload = json.loads(output.read_text(encoding="ascii"))
            self.assertEqual(payload["revision"], revision)
            (snapshot / "build.py").write_text("hidden influence\n", encoding="ascii")
            rejected = subprocess.run(
                [*command[:-1], str(root / "rejected-inventory.json")],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("snapshot path inventory mismatch", rejected.stderr)
            (snapshot / "build.py").unlink()
            (snapshot / "empty-build-input").mkdir()
            rejected = subprocess.run(
                [*command[:-1], str(root / "rejected-directory-inventory.json")],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("snapshot path inventory mismatch", rejected.stderr)

    def test_external_dependency_inventory_binds_bytes_and_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            dependencies = root / "dependencies"
            vendor = dependencies / "vendor" / "crate-1.0.0"
            vendor.mkdir(parents=True)
            source = vendor / "lib.rs"
            source.write_text("pub fn one() {}\n", encoding="ascii")
            guard = ROOT / "scripts/wmi/t1_timing_build_guard.py"

            def inventory(name: str) -> dict[str, object]:
                output = root / name
                subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-B",
                        str(guard),
                        "inventory-tree",
                        "--root",
                        str(dependencies),
                        "--output",
                        str(output),
                    ],
                    check=True,
                )
                return json.loads(output.read_text(encoding="ascii"))

            before = inventory("before.json")
            source.write_text("pub fn two() {}\n", encoding="ascii")
            after = inventory("after.json")
            self.assertNotEqual(before["entries_sha256"], after["entries_sha256"])
            (vendor / "link").symlink_to(source)
            rejected = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(guard),
                    "inventory-tree",
                    "--root",
                    str(dependencies),
                    "--output",
                    str(root / "rejected.json"),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("not regular", rejected.stderr)

    def test_wrappers_reject_ambient_paths_and_forward_all_expected_hashes(self) -> None:
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
            "EUF_VIPER_T1_TIMING_ACCEPTED_PARITY_RECEIPT",
            "EUF_VIPER_T1_TIMING_BUILD_RECEIPT",
            "EUF_VIPER_SHARED_CORPUS",
        ):
            self.assertIn(variable, (ROOT / "scripts/wmi/t1_timing_common.sh").read_text())
        for option in (
            "--expected-contract-sha256",
            "--expected-manifest-sha256",
            "--expected-checkout-receipt-sha256",
        ):
            self.assertEqual(text.count(option), 3)

        forbidden_overrides = {
            "EUF_VIPER_WMI_HOST": "attacker.example",
            "EUF_VIPER_T1_PUBLISHED_REF": "refs/heads/attacker",
            "EUF_VIPER_T1_REMOTE_PARENT": "/tmp/attacker-root",
            "EUF_VIPER_T1_CAMPAIGN_TAG": "attacker-tag",
            "EUF_VIPER_T1_DEPENDENCY": "999999",
            "EUF_VIPER_T1_TIMING_CONTRACT": "/tmp/evil-contract",
            "EUF_VIPER_T1_TIMING_MANIFEST": "/tmp/evil-manifest",
            "EUF_VIPER_T1_TIMING_ROOT": "/tmp/evil-root",
            "EUF_VIPER_SHARED_CORPUS": "/tmp/evil-corpus",
            "EUF_VIPER_T1_PARTITION": "evil",
            "EUF_VIPER_T1_NODELIST": "evil",
        }
        base_environment = {
            key: value
            for key, value in os.environ.items()
            if key not in forbidden_overrides
        }
        for name, value in forbidden_overrides.items():
            with self.subTest(forbidden=name):
                rejected = subprocess.run(
                    [
                        "bash",
                        "-c",
                        "source scripts/wmi/t1_timing_common.sh; "
                        "t1_reject_ambient_influence",
                    ],
                    cwd=ROOT,
                    env={**base_environment, name: value},
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(f"ambient override is forbidden: {name}", rejected.stderr)

        sanitized_environment = {
            **base_environment,
            "PYTHONPATH": "/tmp/shadow",
            "RUSTFLAGS": "--cfg hidden_flag",
            "CARGO_PROFILE_RELEASE_LTO": "false",
            "CC": "/tmp/compiler-wrapper",
            "LD_PRELOAD": "/tmp/inject.so",
            "GIT_WORK_TREE": "/tmp/alternate-tree",
            "GIT_CONFIG_GLOBAL": "/tmp/alternate-git-config",
            "BASH_ENV": "",
            "ENV": "/tmp/alternate-shell-env",
        }
        command = (
            "source scripts/wmi/t1_timing_common.sh; t1_reject_ambient_influence; "
            "test -z \"${PYTHONPATH-}\"; test -z \"${RUSTFLAGS-}\"; "
            "test -z \"${CARGO_PROFILE_RELEASE_LTO-}\"; test -z \"${CC-}\"; "
            "test -z \"${LD_PRELOAD-}\"; test -z \"${GIT_WORK_TREE-}\"; "
            "test -z \"${GIT_CONFIG_GLOBAL-}\"; test -z \"${BASH_ENV-}\"; "
            "test -z \"${ENV-}\""
        )
        subprocess.run(
            ["bash", "-c", command], cwd=ROOT, env=sanitized_environment, check=True
        )

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


class LinuxElfProvenanceTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "ELF closure is Linux-only")
    def test_elf_interpreter_and_recursive_needed_closure_are_bound(self) -> None:
        binary_path = Path("/bin/true").resolve(strict=True)
        descriptor = os.open(binary_path, os.O_RDONLY)
        try:
            content = BUILD_GUARD.descriptor_bytes(
                descriptor, executable=True, label="ELF fixture"
            )
        finally:
            os.close(descriptor)
        binding = {
            "path": str(binary_path),
            "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content),
            "attestation": "inherited-open-descriptor.v1",
        }
        provenance = BUILD_GUARD.attest_linux_elf(binary_path, content, binding)
        TIMING.validate_linux_elf_provenance(
            provenance,
            binary=binding,
            where="/bin/true provenance",
            verify_runtime_paths=True,
        )
        self.assertEqual(provenance["binary_sha256"], binding["sha256"])
        self.assertTrue(provenance["interpreter"]["requested"].startswith("/"))
        self.assertGreaterEqual(len(provenance["objects"]), 3)
        self.assertTrue(provenance["edges"])
        self.assertTrue(
            any(
                (item["elf"]["soname"] or Path(item["path"]).name).startswith("libc.so")
                for item in provenance["objects"]
            )
        )

    @unittest.skipUnless(sys.platform.startswith("linux"), "ELF closure is Linux-only")
    def test_missing_recursive_needed_edge_fails_closed(self) -> None:
        binary_path = Path("/bin/true").resolve(strict=True)
        content = binary_path.read_bytes()
        binding = {
            "path": str(binary_path),
            "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content),
            "attestation": "inherited-open-descriptor.v1",
        }
        provenance = BUILD_GUARD.attest_linux_elf(binary_path, content, binding)
        broken = copy.deepcopy(provenance)
        broken["edges"] = broken["edges"][1:]
        broken["closure_sha256"] = hashlib.sha256(
            TIMING.canonical_bytes(
                {"edges": broken["edges"], "objects": broken["objects"]}
            )
        ).hexdigest()
        with self.assertRaisesRegex(TIMING.CampaignError, "closure is incomplete"):
            TIMING.validate_linux_elf_provenance(
                broken,
                binary=binding,
                where="incomplete provenance",
                verify_runtime_paths=False,
            )


class LinuxMutationMonitorTests(unittest.TestCase):
    def _start_monitor(
        self, root: Path, snapshot: Path
    ) -> tuple[subprocess.Popen[str], Path, Path, Path, tuple[int, int, int]]:
        ready = root / "ready.json"
        events = root / "events.jsonl"
        receipt = root / "receipt.json"
        ready_fd = os.open(ready, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        events_fd = os.open(events, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        receipt_fd = os.open(receipt, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        evidence_fds = (ready_fd, events_fd, receipt_fd)
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-B",
                str(ROOT / "scripts/wmi/t1_timing_build_guard.py"),
                "monitor",
                "--snapshot",
                str(snapshot),
                "--ready",
                str(ready),
                "--ready-fd",
                str(ready_fd),
                "--control-fd",
                "0",
                "--events",
                str(events),
                "--events-fd",
                str(events_fd),
                "--receipt",
                str(receipt),
                "--receipt-fd",
                str(receipt_fd),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            pass_fds=evidence_fds,
        )
        for _ in range(200):
            if ready.is_file() or process.poll() is not None:
                break
            time.sleep(0.01)
        self.assertTrue(ready.is_file())
        self.assertIsNone(process.poll())
        return process, ready, events, receipt, evidence_fds

    def _close_monitor(
        self, process: subprocess.Popen[str], evidence_fds: tuple[int, int, int]
    ) -> tuple[str, str]:
        assert process.stdin is not None
        process.stdin.close()
        process.stdin = None
        output = process.communicate(timeout=10)
        for descriptor in evidence_fds:
            os.close(descriptor)
        return output

    @unittest.skipUnless(sys.platform.startswith("linux"), "inotify attack runs in Linux CI")
    def test_forgeable_stop_path_cannot_end_monitor(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            snapshot = root / "source"
            snapshot.mkdir()
            (snapshot / "Cargo.toml").write_text("[package]\n", encoding="ascii")
            process, _, _, receipt, evidence_fds = self._start_monitor(root, snapshot)
            (root / "mutation-monitor.stop").touch()
            time.sleep(0.15)
            self.assertIsNone(process.poll(), "a pathname ended a descriptor-owned monitor")
            stdout, stderr = self._close_monitor(process, evidence_fds)
            self.assertEqual(stdout, "")
            self.assertEqual(process.returncode, 0, stderr)
            payload = json.loads(receipt.read_text(encoding="ascii"))
            self.assertEqual(payload["control"], "parent-owned-pipe-eof.v1")
            self.assertEqual(payload["status"], "clean")

    @unittest.skipUnless(sys.platform.startswith("linux"), "inotify attack runs in Linux CI")
    def test_source_and_vendor_mutate_then_restore_are_rejected(self) -> None:
        for tree_name, relative in (
            ("source", Path("Cargo.toml")),
            ("dependencies", Path("vendor/crate-1.0.0/src/lib.rs")),
        ):
            with self.subTest(tree=tree_name), tempfile.TemporaryDirectory() as directory_name:
                root = Path(directory_name)
                snapshot = root / tree_name
                target = snapshot / relative
                target.parent.mkdir(parents=True)
                original = b"pub fn original() {}\n"
                target.write_bytes(original)
                process, _, events, receipt, evidence_fds = self._start_monitor(
                    root, snapshot
                )
                target.write_bytes(b"pub fn injected() {}\n")
                target.write_bytes(original)
                stdout, stderr = self._close_monitor(process, evidence_fds)
                self.assertEqual(stdout, "")
                self.assertEqual(process.returncode, 3, stderr)
                payload = json.loads(receipt.read_text(encoding="ascii"))
                self.assertEqual(payload["status"], "mutated")
                self.assertGreater(payload["event_count"], 0)
                self.assertEqual(payload["events"]["path"], str(events))
                self.assertIn("WRITE", events.read_text(encoding="ascii"))


class RealReleaseIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("EUF_VIPER_T1_REAL_BINARY"),
        "hosted Linux CI supplies the exact locked release ELF",
    )
    def test_real_release_binary_uses_descriptor_harness_for_both_commands(self) -> None:
        binary = Path(os.environ["EUF_VIPER_T1_REAL_BINARY"]).resolve(strict=True)
        inherited_descriptor = int(os.environ["EUF_VIPER_T1_REAL_BINARY_FD"])
        self.assertEqual(binary.read_bytes()[:4], b"\x7fELF")
        source = (ROOT / "tests/fixtures/basic_sat.smt2").read_bytes()
        with TIMING.open_verified_executable(
            binary,
            inherited_descriptor=inherited_descriptor,
            require_linux_elf=True,
        ) as executable:
            semantics = TIMING.collect_semantic_attestations(
                executable, source, timeout_seconds=2
            )
            observations = [
                TIMING.execute_scheduled_observation(
                    executable, source, schedule, timeout_seconds=2
                )
                for schedule in TIMING.expected_schedule(
                    CONTRACT, measured_rounds=1, warmup_rounds=0
                )
            ]
        TIMING.validate_semantic_pair(
            semantics, source_bytes=len(source), where="real release semantics"
        )
        TIMING.validate_schedule(
            observations,
            contract=CONTRACT,
            source_bytes=len(source),
            where="real release timing",
            measured_rounds=1,
            warmup_rounds=0,
        )
        TIMING.assert_exact_observation_parity(
            observations, expected_status="sat", where="real release parity"
        )


if __name__ == "__main__":
    unittest.main()
