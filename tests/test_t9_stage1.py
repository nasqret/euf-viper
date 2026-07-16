from __future__ import annotations

import base64
import hashlib
import os
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
) -> dict[str, object]:
    if timed_out is None:
        timed_out = result == "timeout"
    if exit_code is None:
        exit_code = 124 if timed_out else 0
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
        "elapsed_ns": elapsed_ns,
        "exit_code": exit_code,
        "timed_out": timed_out,
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
        with self.assertRaisesRegex(audit.AuditError, "balanced ABBA"):
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
            "elapsed_ns",
            "exit_code",
            "timed_out",
            "stdout_sha256",
            "stderr_sha256",
            "stdout_b64",
            "stderr_b64",
        ):
            first[field], second[field] = second[field], first[field]
        with self.assertRaisesRegex(audit.AuditError, "warmup schedule"):
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
        with self.assertRaisesRegex(audit.AuditError, "differs from complete stream"):
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

    def test_timeout_requires_synthetic_exit_code_and_full_duration(self) -> None:
        sources, rows = fixture()
        timeout = next(row for row in rows if row["result"] == "timeout")
        timeout["exit_code"] = 0
        with self.assertRaisesRegex(audit.AuditError, "synthetic exit code 124"):
            audit.validate_observations(rows, self.contract(sources))

        _, rows = fixture()
        timeout = next(row for row in rows if row["result"] == "timeout")
        timeout["elapsed_ns"] = int(runner.TIMEOUT_SECONDS * 1e9) - 1
        with self.assertRaisesRegex(audit.AuditError, "elapsed less"):
            audit.validate_observations(rows, self.contract(sources))


class ProcessContainmentTests(unittest.TestCase):
    def test_nonzero_and_conflicting_results_are_derived_strictly(self) -> None:
        self.assertEqual(runner._parse_result(b"sat\n", 7), "exit-7")
        self.assertEqual(
            runner._parse_result(b"sat\nunsat\n", 0), "invalid-status-output"
        )

    def test_successful_leader_cannot_leave_a_descendant(self) -> None:
        with mock.patch.object(runner, "_child_limits", lambda: None):
            record, stderr = runner.run_process(
                [
                    "/bin/sh",
                    "-c",
                    "/bin/sleep 30 & child=$!; printf '%s\\n' \"$child\" >&2; printf 'sat\\n'",
                ],
                runner.BASE_ENVIRONMENT,
            )
        self.assertEqual(record["result"], "sat")
        child_pid = int(stderr.strip())
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            try:
                os.kill(child_pid, 0)
            except (ProcessLookupError, PermissionError):
                break
            time.sleep(0.01)
        else:
            self.fail("solver descendant survived the observation")

    def test_output_flood_is_file_bounded(self) -> None:
        program = (
            "import os\n"
            f"chunk=b'x'*{runner.MAX_OUTPUT_BYTES // 2}\n"
            "for _ in range(3): os.write(1, chunk)\n"
        )
        record, _ = runner.run_process(
            [sys.executable, "-c", program], runner.BASE_ENVIRONMENT
        )
        stdout = base64.b64decode(record["stdout_b64"], validate=True)
        self.assertLessEqual(len(stdout), runner.MAX_OUTPUT_BYTES)
        self.assertNotIn(record["result"], {"sat", "unsat"})

    def test_os_timer_enforces_the_wall_timeout(self) -> None:
        timeout = 0.05
        with mock.patch.object(runner, "TIMEOUT_SECONDS", timeout):
            record, _ = runner.run_process(
                ["/bin/sleep", "1"], runner.BASE_ENVIRONMENT
            )
        self.assertTrue(record["timed_out"])
        self.assertEqual(record["result"], "timeout")
        self.assertEqual(record["exit_code"], 124)
        self.assertGreaterEqual(record["elapsed_ns"], int(timeout * 1e9))
        self.assertLess(record["elapsed_ns"], 500_000_000)

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
