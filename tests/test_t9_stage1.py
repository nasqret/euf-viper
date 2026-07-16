from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts.bench import audit_t9_stage1 as audit
from scripts.bench import run_t9_stage1 as runner


ANTI_PATH = "QF_UF/QG-classification/qg5/anti.smt2"


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
) -> dict[str, object]:
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
        "exit_code": 124 if result == "timeout" else 0,
        "stdout_sha256": "0" * 64,
        "stderr_sha256": "1" * 64,
        "stdout": "",
        "stderr": "",
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
        with self.assertRaisesRegex(audit.AuditError, "differs from Stage0"):
            audit.validate_observations(rows, contract)

        _, rows = fixture()
        first, second = rows[0], rows[1]
        for field in ("arm", "profile_kind", "profile", "result", "exit_code"):
            first[field], second[field] = second[field], first[field]
        with self.assertRaisesRegex(audit.AuditError, "warmup schedule"):
            audit.validate_observations(rows, contract)


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
