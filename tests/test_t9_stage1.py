from __future__ import annotations

import base64
import errno
import hashlib
import json
import platform
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from scripts.bench import audit_t9_stage1 as audit
from scripts.bench import run_t9_stage1 as runner


ANTI_PATH = "QF_UF/QG-classification/qg5/anti.smt2"
ROOT = Path(__file__).resolve().parents[1]
SBATCH = ROOT / "scripts" / "wmi" / "euf_viper_t9_stage1.sbatch"
LINUX_X86_64 = sys.platform == "linux" and platform.machine() == "x86_64"


def observation(
    ordinal: int,
    *,
    path: str,
    expected: str,
    control_class: str,
    selected: bool,
    arm: str,
    phase: str,
    result: str,
    elapsed_ns: int,
    comparison: str | None = None,
    repeat: int | None = None,
    position: int | None = None,
    profile_kind: str | None = None,
    profile: dict[str, str] | None = None,
    stdout: bytes | None = None,
    stderr: bytes | None = None,
    exit_code: int | None = None,
    timed_out: bool | None = None,
    timeout_kill_sent: bool | None = None,
    kill_attempt_ns: int | None = None,
    output_limit_hit: bool = False,
) -> dict[str, object]:
    started_ns = 10_000_000_000 + ordinal * 10_000_000_000
    deadline_ns = started_ns + runner.TIMEOUT_NS
    completed_ns = started_ns + elapsed_ns
    if timed_out is None:
        timed_out = result == "timeout"
    if timeout_kill_sent is None:
        timeout_kill_sent = timed_out
    if timeout_kill_sent and kill_attempt_ns is None:
        kill_attempt_ns = deadline_ns
    if exit_code is None:
        exit_code = -signal.SIGKILL if timed_out else 0
    process_pid = 10_000 + ordinal
    if exit_code >= 0:
        waitid_code = runner.os.CLD_EXITED
        waitid_status = exit_code
    else:
        waitid_code = runner.os.CLD_KILLED
        waitid_status = -exit_code
    if stdout is None:
        stdout = f"{result}\n".encode("ascii") if result in {"sat", "unsat", "unknown"} else b""
    if stderr is None:
        if profile is None:
            stderr = b""
        else:
            fields = " ".join(f"{key}={value}" for key, value in sorted(profile.items()))
            stderr = f"profile_t9_ackermann {fields}\n".encode("ascii")
    return {
        "schema": runner.RAW_SCHEMA,
        "ordinal": ordinal,
        "phase": phase,
        "comparison": comparison,
        "repeat": repeat,
        "position": position,
        "relative_path": path,
        "expected_status": expected,
        "control_class": control_class,
        "selected": selected,
        "arm": arm,
        "profile_kind": profile_kind,
        "profile": profile,
        "result": result,
        "started_ns": started_ns,
        "deadline_ns": deadline_ns,
        "completed_ns": completed_ns,
        "elapsed_ns": elapsed_ns,
        "process_pid": process_pid,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "timeout_kill_sent": timeout_kill_sent,
        "kill_attempt_ns": kill_attempt_ns,
        "kill_errno": 0 if timeout_kill_sent else None,
        "waitid_pid": process_pid,
        "waitid_code": waitid_code,
        "waitid_status": waitid_status,
        "output_limit_hit": output_limit_hit,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "stdout_b64": base64.b64encode(stdout).decode("ascii"),
        "stderr_b64": base64.b64encode(stderr).decode("ascii"),
    }


def fixture() -> tuple[list[runner.Source], list[dict[str, object]]]:
    sources = [
        runner.Source(
            relative_path=runner.TARGET_PATH,
            path=Path("/target"),
            sha256="2" * 64,
            bytes=1,
            status="unsat",
            control_class="target",
            projection={
                "selected": True,
                "reason": "selected",
                "baseline_before_sha256": "a" * 64,
                "baseline_after_sha256": "a" * 64,
                "sat_calls": 0,
            },
        ),
        runner.Source(
            relative_path=ANTI_PATH,
            path=Path("/anti"),
            sha256="3" * 64,
            bytes=1,
            status="sat",
            control_class="anti-target",
            projection={
                "selected": False,
                "reason": "all_different_clique_below_minimum",
                "baseline_before_sha256": "b" * 64,
                "baseline_after_sha256": "b" * 64,
                "sat_calls": 0,
            },
        ),
    ]
    sources.sort(key=lambda source: source.relative_path)
    rows: list[dict[str, object]] = []
    ordinal = 0
    for source in sources:
        selected = source.relative_path == runner.TARGET_PATH
        for arm in ("off", "candidate", "yices"):
            result = "timeout" if selected and arm == "off" else source.status
            rows.append(
                observation(
                    ordinal,
                    path=source.relative_path,
                    expected=source.status,
                    control_class=source.control_class,
                    selected=selected,
                    arm=arm,
                    phase="preflight",
                    result=result,
                    elapsed_ns=2_000_000_000 if result == "timeout" else 100_000_000,
                    profile_kind=(
                        "selected_materialization"
                        if selected and arm == "candidate"
                        else "unchanged_rejection"
                        if arm == "candidate"
                        else None
                    ),
                    profile=(
                        runner.projection_strings(source.projection)
                        if arm == "candidate"
                        else None
                    ),
                )
            )
            ordinal += 1
    comparisons = (
        ("off_candidate", "off", "candidate"),
        ("yices_candidate", "yices", "candidate"),
    )
    for source_index, source in enumerate(sources):
        selected = source.relative_path == runner.TARGET_PATH
        for comparison_index, (comparison, first, second) in enumerate(comparisons):
            for repeat in range(runner.REPEATS):
                arms = (
                    (first, second)
                    if (source_index + comparison_index + repeat) % 2 == 0
                    else (second, first)
                )
                for position, arm in enumerate(arms):
                    result = "timeout" if selected and arm == "off" else source.status
                    if result == "timeout":
                        elapsed = 2_000_000_000
                    elif selected and comparison == "off_candidate" and arm == "candidate":
                        elapsed = 500_000_000
                    elif selected and comparison == "yices_candidate" and arm == "candidate":
                        elapsed = 500_000_000
                    elif selected and arm == "yices":
                        elapsed = 600_000_000
                    elif comparison == "off_candidate" and arm == "candidate":
                        elapsed = 100_500_000
                    else:
                        elapsed = 100_000_000
                    rows.append(
                        observation(
                            ordinal,
                            path=source.relative_path,
                            expected=source.status,
                            control_class=source.control_class,
                            selected=selected,
                            arm=arm,
                            phase="timing",
                            result=result,
                            elapsed_ns=elapsed,
                            comparison=comparison,
                            repeat=repeat,
                            position=position,
                        )
                    )
                    ordinal += 1
    return sources, rows


class EvaluationTests(unittest.TestCase):
    def test_runner_and_auditor_recompute_the_same_passing_gate(self) -> None:
        sources, rows = fixture()
        contract = {
            source.relative_path: {
                "status": source.status,
                "control_class": source.control_class,
                "selected": source.relative_path == runner.TARGET_PATH,
                "projection": source.projection,
            }
            for source in sources
        }
        audit.validate_observations(rows, contract)
        expected = runner.evaluate(sources, rows, {runner.TARGET_PATH})
        self.assertEqual(audit.recompute(rows, contract), expected)
        self.assertEqual(expected["decision"], "pass")
        self.assertAlmostEqual(expected["anti_target_p95_overhead"], 1.005)
        self.assertAlmostEqual(expected["selected_yices_median_speedup"], 1.2)

    def test_yices_and_anti_target_gates_fail_independently(self) -> None:
        sources, rows = fixture()
        for row in rows:
            if (
                row["phase"] == "timing"
                and row["relative_path"] == runner.TARGET_PATH
                and row["comparison"] == "yices_candidate"
                and row["arm"] == "yices"
            ):
                row["elapsed_ns"] = 100_000_000
            if (
                row["phase"] == "timing"
                and row["relative_path"] == ANTI_PATH
                and row["comparison"] == "off_candidate"
                and row["arm"] == "candidate"
            ):
                row["elapsed_ns"] = 102_000_000
        result = runner.evaluate(sources, rows, {runner.TARGET_PATH})
        self.assertEqual(result["decision"], "fail")
        self.assertFalse(result["checks"]["anti_target_p95_overhead"]["passed"])
        self.assertFalse(result["checks"]["selected_yices_median_speedup"]["passed"])

    def test_required_nonselected_yices_result_cannot_timeout(self) -> None:
        sources, rows = fixture()
        for row in rows:
            if row["relative_path"] == ANTI_PATH and row["arm"] == "yices":
                row["result"] = "timeout"
                row["exit_code"] = 124
        result = runner.evaluate(sources, rows, {runner.TARGET_PATH})
        self.assertFalse(result["checks"]["required_arms_correct"]["passed"])

    def test_partial_baseline_timeout_is_not_a_conversion(self) -> None:
        sources, rows = fixture()
        baseline = next(
            row
            for row in rows
            if row["phase"] == "timing"
            and row["relative_path"] == runner.TARGET_PATH
            and row["arm"] == "off"
        )
        baseline["result"] = "unsat"
        baseline["exit_code"] = 0
        baseline["timed_out"] = False
        result = runner.evaluate(sources, rows, {runner.TARGET_PATH})
        self.assertEqual(result["decision"], "fail")
        self.assertFalse(
            result["checks"]["selected_baseline_all_timeout"]["passed"]
        )
        self.assertNotIn(runner.TARGET_PATH, result["candidate_only_paths"])

    def test_schedule_tampering_is_rejected(self) -> None:
        sources, rows = fixture()
        contract = {
            source.relative_path: {
                "status": source.status,
                "control_class": source.control_class,
                "selected": source.relative_path == runner.TARGET_PATH,
                "projection": source.projection,
            }
            for source in sources
        }
        timing = next(row for row in rows if row["phase"] == "timing")
        timing["position"] = 1 - timing["position"]
        with self.assertRaisesRegex(audit.AuditError, "frozen global schedule"):
            audit.validate_observations(rows, contract)

    def test_phase_interleaving_is_rejected_by_the_global_schedule(self) -> None:
        sources, rows = fixture()
        contract = {
            source.relative_path: {
                "status": source.status,
                "control_class": source.control_class,
                "selected": source.relative_path == runner.TARGET_PATH,
                "projection": source.projection,
            }
            for source in sources
        }
        first_timing = next(
            index for index, row in enumerate(rows) if row["phase"] == "timing"
        )
        rows.insert(1, rows.pop(first_timing))
        for ordinal, row in enumerate(rows):
            row["ordinal"] = ordinal
        with self.assertRaisesRegex(audit.AuditError, "frozen global schedule"):
            audit.validate_observations(rows, contract)

    def test_overlapping_observation_intervals_are_rejected(self) -> None:
        sources, rows = fixture()
        contract = {
            source.relative_path: {
                "status": source.status,
                "control_class": source.control_class,
                "selected": source.relative_path == runner.TARGET_PATH,
                "projection": source.projection,
            }
            for source in sources
        }
        rows[1]["started_ns"] = rows[0]["completed_ns"] - 1
        rows[1]["deadline_ns"] = rows[1]["started_ns"] + runner.TIMEOUT_NS
        rows[1]["completed_ns"] = rows[1]["started_ns"] + rows[1]["elapsed_ns"]
        with self.assertRaisesRegex(audit.AuditError, "overlap or move backwards"):
            audit.validate_observations(rows, contract)

    def test_profile_and_preflight_order_tampering_are_rejected(self) -> None:
        sources, rows = fixture()
        contract = {
            source.relative_path: {
                "status": source.status,
                "control_class": source.control_class,
                "selected": source.relative_path == runner.TARGET_PATH,
                "projection": source.projection,
            }
            for source in sources
        }
        candidate = next(
            row
            for row in rows
            if row["phase"] == "preflight" and row["arm"] == "candidate"
        )
        candidate["profile"] = {**candidate["profile"], "reason": "tampered"}
        with self.assertRaisesRegex(audit.AuditError, "differs from stderr"):
            audit.validate_observations(rows, contract)

        _, rows = fixture()
        first, second = rows[0], rows[1]
        for field in (
            "arm",
            "profile_kind",
            "profile",
            "result",
            "started_ns",
            "deadline_ns",
            "completed_ns",
            "elapsed_ns",
            "process_pid",
            "exit_code",
            "timed_out",
            "timeout_kill_sent",
            "kill_attempt_ns",
            "kill_errno",
            "waitid_pid",
            "waitid_code",
            "waitid_status",
            "output_limit_hit",
            "stdout_sha256",
            "stderr_sha256",
            "stdout_b64",
            "stderr_b64",
        ):
            first[field], second[field] = second[field], first[field]
        with self.assertRaisesRegex(audit.AuditError, "frozen global schedule"):
            audit.validate_observations(rows, contract)


class EvidenceBindingTests(unittest.TestCase):
    @staticmethod
    def contract(sources: list[runner.Source]) -> dict[str, dict[str, object]]:
        return {
            source.relative_path: {
                "status": source.status,
                "control_class": source.control_class,
                "selected": source.relative_path == runner.TARGET_PATH,
                "projection": source.projection,
            }
            for source in sources
        }

    def test_stream_hash_tampering_is_rejected(self) -> None:
        sources, rows = fixture()
        row = rows[0]
        row["stdout_b64"] = base64.b64encode(b"tampered\n").decode("ascii")
        with self.assertRaisesRegex(audit.AuditError, "stdout hash mismatch"):
            audit.validate_observations(rows, self.contract(sources))

    def test_nonzero_exit_cannot_publish_a_solver_answer(self) -> None:
        sources, rows = fixture()
        row = next(
            row
            for row in rows
            if row["relative_path"] == ANTI_PATH and row["phase"] == "preflight"
        )
        row["exit_code"] = 7
        with self.assertRaisesRegex(audit.AuditError, "exit code differs"):
            audit.validate_observations(rows, self.contract(sources))

    def test_conflicting_status_tokens_are_rejected(self) -> None:
        sources, rows = fixture()
        row = next(
            row
            for row in rows
            if row["relative_path"] == ANTI_PATH and row["phase"] == "preflight"
        )
        stdout = b"sat\nunsat\n"
        row["stdout_b64"] = base64.b64encode(stdout).decode("ascii")
        row["stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
        with self.assertRaisesRegex(audit.AuditError, "differs from complete stream"):
            audit.validate_observations(rows, self.contract(sources))

    def test_timeout_requires_successful_pidfd_kill_and_actual_wait_status(self) -> None:
        sources, rows = fixture()
        timeout = next(row for row in rows if row["result"] == "timeout")
        timeout["exit_code"] = 0
        with self.assertRaisesRegex(audit.AuditError, "exit code differs"):
            audit.validate_observations(rows, self.contract(sources))

        _, rows = fixture()
        timeout = next(row for row in rows if row["result"] == "timeout")
        timeout["timeout_kill_sent"] = False
        timeout["kill_attempt_ns"] = None
        timeout["kill_errno"] = None
        with self.assertRaisesRegex(audit.AuditError, "timeout marker differs"):
            audit.validate_observations(rows, self.contract(sources))

    def test_waitid_kernel_status_is_bound_to_pid_and_return_code(self) -> None:
        sources, rows = fixture()
        timeout = next(row for row in rows if row["result"] == "timeout")
        timeout["waitid_pid"] += 1
        with self.assertRaisesRegex(audit.AuditError, "another process"):
            audit.validate_observations(rows, self.contract(sources))

        _, rows = fixture()
        timeout = next(row for row in rows if row["result"] == "timeout")
        timeout["waitid_status"] = int(signal.SIGTERM)
        with self.assertRaisesRegex(audit.AuditError, "exit code differs"):
            audit.validate_observations(rows, self.contract(sources))

    def test_kill_syscall_errno_is_not_a_fabricated_boolean(self) -> None:
        sources, rows = fixture()
        timeout = next(row for row in rows if row["result"] == "timeout")
        timeout["kill_errno"] = errno.ESRCH
        with self.assertRaisesRegex(audit.AuditError, "kill marker differs"):
            audit.validate_observations(rows, self.contract(sources))

    def test_deadline_boundary_ambiguity_fails_closed(self) -> None:
        sources, rows = fixture()
        row = next(
            row
            for row in rows
            if row["relative_path"] == ANTI_PATH and row["phase"] == "preflight"
        )
        row["completed_ns"] = row["deadline_ns"]
        row["elapsed_ns"] = runner.TIMEOUT_NS
        with self.assertRaisesRegex(audit.AuditError, "differs from complete stream"):
            audit.validate_observations(rows, self.contract(sources))

    def test_elapsed_timestamps_are_independently_recomputed(self) -> None:
        sources, rows = fixture()
        rows[0]["elapsed_ns"] += 1
        with self.assertRaisesRegex(audit.AuditError, "elapsed interval"):
            audit.validate_observations(rows, self.contract(sources))

    def test_unsuccessful_deadline_kill_is_not_a_timeout(self) -> None:
        sources, rows = fixture()
        row = next(row for row in rows if row["result"] == "timeout")
        row["result"] = "deadline-overrun"
        row["exit_code"] = 0
        row["timed_out"] = False
        row["timeout_kill_sent"] = False
        row["kill_errno"] = errno.ESRCH
        row["waitid_code"] = runner.os.CLD_EXITED
        row["waitid_status"] = 0
        audit.validate_observations(rows, self.contract(sources))
        evaluation = runner.evaluate(sources, rows, {runner.TARGET_PATH})
        self.assertFalse(
            evaluation["checks"]["selected_baseline_all_timeout"]["passed"]
        )

    def test_output_overflow_marker_is_derived_from_retained_sentinel(self) -> None:
        sources, rows = fixture()
        row = next(
            row
            for row in rows
            if row["relative_path"] == ANTI_PATH and row["phase"] == "preflight"
        )
        stdout = b"sat\n" + b"x" * (runner.OUTPUT_FILE_LIMIT_BYTES - 4)
        row["stdout_b64"] = base64.b64encode(stdout).decode("ascii")
        row["stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
        row["output_limit_hit"] = True
        row["result"] = "output-limit"
        audit.validate_observations(rows, self.contract(sources))
        row["output_limit_hit"] = False
        with self.assertRaisesRegex(audit.AuditError, "output-limit marker"):
            audit.validate_observations(rows, self.contract(sources))


class ProcessContainmentTests(unittest.TestCase):
    def test_closed_standard_descriptor_is_rejected_before_handle_allocation(self) -> None:
        real_fstat = runner.os.fstat

        def fstat(descriptor: int):
            if descriptor == 1:
                raise OSError("closed for test")
            return real_fstat(descriptor)

        with mock.patch.object(runner.os, "fstat", side_effect=fstat):
            with self.assertRaisesRegex(runner.Stage1Error, "standard descriptor 1"):
                runner._validate_standard_descriptors()

    def test_nonzero_and_conflicting_results_are_derived_strictly(self) -> None:
        self.assertEqual(runner._parse_result(b"sat\n", 7), "exit-7")
        self.assertEqual(
            runner._parse_result(b"sat\nunsat\n", 0), "invalid-status-output"
        )

    @unittest.skipUnless(LINUX_X86_64, "requires the WMI Linux sandbox")
    def test_preexec_setup_is_inside_the_pidfd_deadline(self) -> None:
        timeout_ns = 50_000_000
        with mock.patch.object(runner, "_child_limits", lambda: time.sleep(1)):
            record, _ = runner.run_process(
                ["/bin/true"],
                runner.BASE_ENVIRONMENT,
                timeout_ns=timeout_ns,
            )
        self.assertEqual(record["result"], "timeout")
        self.assertEqual(record["exit_code"], -signal.SIGKILL)
        self.assertGreaterEqual(record["elapsed_ns"], timeout_ns)
        self.assertLess(record["elapsed_ns"], 500_000_000)

    @unittest.skipUnless(LINUX_X86_64, "requires the WMI Linux sandbox")
    def test_ignored_sigchld_is_replaced_before_pidfd_acquisition(self) -> None:
        previous = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        try:
            record, _ = runner.run_process(
                ["/bin/sh", "-c", "printf 'sat\\n'"], runner.BASE_ENVIRONMENT
            )
            self.assertEqual(record["result"], "sat")
            self.assertEqual(record["waitid_pid"], record["process_pid"])
        finally:
            signal.signal(signal.SIGCHLD, previous)

    @unittest.skipUnless(LINUX_X86_64, "requires the WMI Linux sandbox")
    def test_seccomp_kills_process_creation_before_session_escape(self) -> None:
        record, _ = runner.run_process(
            [
                "/bin/sh",
                "-c",
                "/usr/bin/setsid /bin/sleep 30 & printf 'sat\\n'",
            ],
            runner.BASE_ENVIRONMENT,
            timeout_ns=500_000_000,
        )
        self.assertEqual(record["exit_code"], -signal.SIGSYS)
        self.assertEqual(record["waitid_pid"], record["process_pid"])
        self.assertEqual(record["waitid_status"], signal.SIGSYS)
        self.assertEqual(record["result"], f"exit-{-signal.SIGSYS}")
        self.assertFalse(record["timed_out"])
        self.assertFalse(record["timeout_kill_sent"])

    @unittest.skipUnless(LINUX_X86_64, "requires the WMI Linux sandbox")
    def test_caught_output_limit_is_explicitly_invalid(self) -> None:
        program = (
            "import os,signal\n"
            "signal.signal(signal.SIGXFSZ, signal.SIG_IGN)\n"
            "os.write(1,b'sat\\n')\n"
            "chunk=b'x'*4096\n"
            "try:\n"
            "  while True: os.write(1,chunk)\n"
            "except OSError:\n"
            "  pass\n"
        )
        record, _ = runner.run_process(
            [sys.executable, "-c", program], runner.BASE_ENVIRONMENT
        )
        stdout = base64.b64decode(record["stdout_b64"], validate=True)
        self.assertEqual(len(stdout), runner.OUTPUT_FILE_LIMIT_BYTES)
        self.assertTrue(record["output_limit_hit"])
        self.assertEqual(record["exit_code"], 0)
        self.assertEqual(record["result"], "output-limit")

    @unittest.skipUnless(LINUX_X86_64, "requires the WMI Linux sandbox")
    def test_pidfd_kill_linearizes_the_wall_timeout(self) -> None:
        timeout_ns = 50_000_000
        record, _ = runner.run_process(
            ["/bin/sleep", "1"],
            runner.BASE_ENVIRONMENT,
            timeout_ns=timeout_ns,
        )
        self.assertTrue(record["timed_out"])
        self.assertEqual(record["result"], "timeout")
        self.assertEqual(record["exit_code"], -signal.SIGKILL)
        self.assertEqual(record["kill_errno"], 0)
        self.assertEqual(record["waitid_pid"], record["process_pid"])
        self.assertEqual(record["waitid_code"], runner.os.CLD_KILLED)
        self.assertEqual(record["waitid_status"], signal.SIGKILL)
        self.assertTrue(record["timeout_kill_sent"])
        self.assertGreaterEqual(record["kill_attempt_ns"], record["deadline_ns"])
        self.assertEqual(record["deadline_ns"] - record["started_ns"], timeout_ns)
        self.assertEqual(
            record["completed_ns"] - record["started_ns"], record["elapsed_ns"]
        )
        self.assertGreaterEqual(record["elapsed_ns"], timeout_ns)
        self.assertLess(record["elapsed_ns"], 500_000_000)

    @unittest.skipUnless(LINUX_X86_64, "requires the WMI Linux sandbox")
    def test_child_observes_the_exact_resource_contract(self) -> None:
        program = (
            "import json,resource\n"
            "print(json.dumps({\n"
            " 'as':resource.getrlimit(resource.RLIMIT_AS),\n"
            " 'core':resource.getrlimit(resource.RLIMIT_CORE),\n"
            " 'fsize':resource.getrlimit(resource.RLIMIT_FSIZE),\n"
            " 'nofile':resource.getrlimit(resource.RLIMIT_NOFILE)}))\n"
            "print('sat')\n"
        )
        record, _ = runner.run_process(
            [sys.executable, "-c", program], runner.BASE_ENVIRONMENT
        )
        lines = base64.b64decode(record["stdout_b64"], validate=True).splitlines()
        observed = json.loads(lines[0])
        self.assertEqual(
            observed,
            {
                "as": [runner.MAX_ADDRESS_SPACE_BYTES] * 2,
                "core": [0, 0],
                "fsize": [runner.OUTPUT_FILE_LIMIT_BYTES] * 2,
                "nofile": [runner.MAX_OPEN_FILES] * 2,
            },
        )
        self.assertEqual(record["result"], "sat")

    def test_changed_input_is_rejected_after_observations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input"
            path.write_bytes(b"before")
            expected = hashlib.sha256(b"before").hexdigest()
            path.write_bytes(b"after")
            with self.assertRaisesRegex(runner.Stage1Error, "identity changed"):
                runner.validate_input_identities(
                    [("test_input", path, expected, False)]
                )


class ExitSemanticsTests(unittest.TestCase):
    def test_scientific_failure_propagates_from_runner_and_auditor(self) -> None:
        with (
            mock.patch.object(runner, "parse_args", return_value=object()),
            mock.patch.object(
                runner, "run_stage1", return_value={"decision": "fail"}
            ),
        ):
            self.assertEqual(runner.main(), 3)
        with (
            mock.patch.object(audit, "parse_args", return_value=object()),
            mock.patch.object(
                audit,
                "audit",
                return_value={"status": "verified", "scientific_decision": "fail"},
            ),
        ):
            self.assertEqual(audit.main(), 3)

    def test_wmi_wrapper_preserves_and_propagates_scientific_failure(self) -> None:
        script = SBATCH.read_text(encoding="ascii")
        self.assertIn('case "$RUNNER_STATUS" in', script)
        self.assertIn('case "$AUDITOR_STATUS" in', script)
        self.assertIn('pass:0|fail:3)', script)
        self.assertIn('"status": f"completed_scientific_{summary[\'decision\']}"', script)
        self.assertIn('exit "$RUNNER_STATUS"', script)
        self.assertIn("harness checkout changed during Stage1", script)


class ProfileAndArtifactTests(unittest.TestCase):
    def test_stage1_binary_must_equal_the_stage0_census_binary(self) -> None:
        digest = "a" * 64
        stage0_summary = {
            "binary_sha256": digest,
            "provenance": {"git_revision": "b" * 40},
        }
        audit.validate_stage0_binary_identity(stage0_summary, digest, digest)
        with self.assertRaisesRegex(audit.AuditError, "differs from the Stage0"):
            audit.validate_stage0_binary_identity(stage0_summary, "c" * 64, digest)
        with self.assertRaisesRegex(audit.AuditError, "differs from the Stage0"):
            audit.validate_stage0_binary_identity(stage0_summary, digest, "d" * 64)

    def test_manifest_digest_is_exact_and_shared_by_all_three_layers(self) -> None:
        expected = (
            "32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4"
        )
        self.assertEqual(len(expected), 64)
        self.assertEqual(runner.MANIFEST_SHA256, expected)
        self.assertEqual(audit.MANIFEST_SHA256, expected)
        script = SBATCH.read_text(encoding="ascii")
        self.assertIn(f'MANIFEST_SHA256="{expected}"', script)

    def test_runtime_contract_is_exact_and_shared(self) -> None:
        self.assertEqual(runner.RUNTIME_CONTRACT, audit.RUNTIME_CONTRACT)
        self.assertEqual(
            runner.RUNTIME_CONTRACT["wait"], "pidfd-select-waitid-v2"
        )
        self.assertEqual(
            runner.RUNTIME_CONTRACT["process_creation"],
            "seccomp-kill-clone-fork-vfork-clone3-v1",
        )
        self.assertEqual(
            runner.RUNTIME_CONTRACT["launch"],
            "fork-pidfd-preexec-supervised-v1",
        )
        self.assertEqual(
            runner.RUNTIME_CONTRACT["sigchld"],
            "default-zombie-preserving-single-thread-v1",
        )
        self.assertEqual(
            runner.RUNTIME_CONTRACT["standard_fds"], "required-open-v1"
        )
        self.assertNotIn("process_count", runner.RUNTIME_CONTRACT)
        self.assertNotIn("SIGXFZ", Path(runner.__file__).read_text(encoding="ascii"))
        script = SBATCH.read_text(encoding="ascii")
        self.assertIn('"runtime_contract": summary["runtime_contract"]', script)
        self.assertIn('"euf-viper.t9-stage1-wmi-run.v2"', script)
        self.assertIn('"$(uname -m)" = x86_64', script)
        self.assertIn('"$PYTHON" -I -S -B', script)
        self.assertIn('"$STAGE0_BINARY_SHA256" = "$BINARY_SHA256"', script)

    def test_full_and_precheck_profiles_are_bound_to_stage0(self) -> None:
        projection = {
            "selected": True,
            "reason": "selected",
            "baseline_before_sha256": "a" * 64,
            "baseline_after_sha256": "a" * 64,
            "sat_calls": 0,
        }
        source = runner.Source(
            runner.TARGET_PATH,
            Path("/target"),
            "b" * 64,
            1,
            "unsat",
            "target",
            projection,
        )
        self.assertEqual(
            runner.validate_profile(source, runner.projection_strings(projection)),
            "selected_materialization",
        )
        rejected = runner.Source(
            ANTI_PATH,
            Path("/anti"),
            "c" * 64,
            1,
            "sat",
            "anti-target",
            {"selected": False, "reason": "finite_added_nonzero"},
        )
        self.assertEqual(
            runner.validate_profile(
                rejected,
                {"selected": "0", "reason": "finite_added_nonzero", "precheck": "1"},
            ),
            "precheck",
        )
        with self.assertRaises(runner.Stage1Error):
            runner.validate_profile(
                rejected,
                {"selected": "0", "reason": "backend_not_kissat", "precheck": "1"},
            )

    def test_timing_environments_are_closed_and_strict(self) -> None:
        self.assertEqual(runner.arm_environment("yices"), runner.BASE_ENVIRONMENT)
        self.assertEqual(
            runner.arm_environment("off")["EUF_VIPER_T9_ACKERMANN"], "off"
        )
        candidate = runner.arm_environment("candidate", profile=True)
        self.assertEqual(candidate["EUF_VIPER_T9_ACKERMANN"], "clique-auto")
        self.assertEqual(candidate["EUF_VIPER_PROFILE"], "1")
        self.assertNotIn("PATH", candidate)

    def test_immutable_write_refuses_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "artifact.json"
            runner.immutable_write(path, b"payload\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o400)
            self.assertEqual(
                hashlib.sha256(path.read_bytes()).hexdigest(),
                hashlib.sha256(b"payload\n").hexdigest(),
            )
            with self.assertRaises(runner.Stage1Error):
                runner.immutable_write(path, b"replacement\n")


if __name__ == "__main__":
    unittest.main()
