from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "adjudicate_pgo_holdout.py"
CONTRACT = ROOT / "campaigns" / "viper-pgo-goel-holdout-v1.json"
SPEC = importlib.util.spec_from_file_location("adjudicate_pgo_holdout", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
DECISION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DECISION)


def synthetic_summary(
    *,
    instances: int = 40,
    baseline_time: float = 0.10,
    candidate_time: float = 0.08,
) -> dict[str, object]:
    repeats = 2
    arms = ["viper-standard", "viper-pgo", "z3"]
    paths = []
    for index in range(instances):
        paths.append(
            {
                "relative_path": f"QF_UF/holdout/case-{index}.smt2",
                "arms": {
                    "viper-standard": {
                        "correct": True,
                        "covered": True,
                        "correct_repeats": repeats,
                        "median_time_s": baseline_time,
                    },
                    "viper-pgo": {
                        "correct": True,
                        "covered": True,
                        "correct_repeats": repeats,
                        "median_time_s": candidate_time,
                    },
                },
            }
        )
    per_arm = {
        "runs": instances * repeats,
        "error_runs": 0,
        "timeout_runs": 0,
        "unexpected_runs": 0,
        "wrong_runs": 0,
    }
    return {
        "schema_version": 1,
        "status": "complete",
        "accounting": {
            "execution_errors": 0,
            "unexpected_results": 0,
            "wrong_answers": 0,
        },
        "arm_order": arms,
        "arms": {
            "viper-standard": dict(per_arm),
            "viper-pgo": dict(per_arm),
            "z3": dict(per_arm),
        },
        "instances": instances,
        "measured_runs": instances * repeats * len(arms),
        "paths": paths,
        "repeats": repeats,
    }


class PgoHoldoutDecisionTests(unittest.TestCase):
    def test_preregistered_policy_matches_implementation_constants(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        policy = contract["adjudication"]
        self.assertEqual(policy["bootstrap_iterations"], DECISION.BOOTSTRAP_ITERATIONS)
        self.assertEqual(policy["bootstrap_seed"], DECISION.BOOTSTRAP_SEED)
        self.assertEqual(policy["confidence_level"], DECISION.CONFIDENCE_LEVEL)
        self.assertEqual(policy["minimum_common_instances"], DECISION.MIN_COMMON_INSTANCES)
        self.assertEqual(
            policy["minimum_geometric_speedup_exclusive"], DECISION.MIN_SPEEDUP
        )
        self.assertEqual(policy["maximum_p95_slowdown"], DECISION.MAX_P95_SLOWDOWN)

    def test_uniform_measured_win_promotes(self) -> None:
        summary = synthetic_summary()
        report = DECISION.evaluate(
            summary, summary_sha256="a" * 64, expected_instances=40
        )
        self.assertEqual(report["decision"], "promote")
        self.assertAlmostEqual(report["timing"]["geometric_speedup"], 1.25)
        self.assertTrue(all(item["passed"] for item in report["checks"].values()))
        self.assertEqual(report["bootstrap"]["confidence_level"], 0.99)

    def test_slow_candidate_is_a_valid_rejection(self) -> None:
        summary = synthetic_summary(candidate_time=0.11)
        report = DECISION.evaluate(
            summary, summary_sha256="b" * 64, expected_instances=40
        )
        self.assertEqual(report["decision"], "reject")
        self.assertFalse(report["checks"]["geometric_point_speedup"]["passed"])
        self.assertFalse(report["checks"]["p95_slowdown_cap"]["passed"])

    def test_baseline_only_solve_rejects_even_when_common_pairs_are_fast(self) -> None:
        summary = synthetic_summary()
        candidate = summary["paths"][0]["arms"]["viper-pgo"]
        candidate.update(
            {
                "correct": False,
                "covered": False,
                "correct_repeats": 0,
                "median_time_s": 2.0,
            }
        )
        summary["arms"]["viper-pgo"]["timeout_runs"] = 2
        report = DECISION.evaluate(
            summary, summary_sha256="c" * 64, expected_instances=40
        )
        self.assertEqual(report["decision"], "reject")
        self.assertFalse(report["checks"]["coverage_nonregression"]["passed"])
        self.assertFalse(report["checks"]["timeout_nonregression"]["passed"])

    def test_incomplete_design_and_inconsistent_path_are_invalid(self) -> None:
        summary = synthetic_summary()
        summary["measured_runs"] -= 1
        with self.assertRaisesRegex(DECISION.DecisionError, "measured run"):
            DECISION.evaluate(
                summary, summary_sha256="d" * 64, expected_instances=40
            )

        summary = synthetic_summary()
        summary["paths"][0]["arms"]["viper-pgo"]["correct_repeats"] = 1
        with self.assertRaisesRegex(DECISION.DecisionError, "repeat coverage"):
            DECISION.evaluate(
                summary, summary_sha256="e" * 64, expected_instances=40
            )

    def test_malformed_arm_names_fail_closed(self) -> None:
        for malformed in (["viper-standard", ["viper-pgo"]], ["", "viper-pgo"]):
            with self.subTest(arm_order=malformed):
                summary = synthetic_summary()
                summary["arm_order"] = malformed
                with self.assertRaisesRegex(DECISION.DecisionError, "arm order"):
                    DECISION.evaluate(
                        summary, summary_sha256="f" * 64, expected_instances=40
                    )

    def test_bootstrap_is_deterministic(self) -> None:
        pairs = [(0.1 + index / 10_000, 0.09) for index in range(40)]
        first = DECISION.paired_bootstrap(pairs, iterations=128)
        second = DECISION.paired_bootstrap(pairs, iterations=128)
        self.assertEqual(first, second)

    def test_cli_publishes_a_canonical_hash_bound_decision(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pgo decision ") as temp:
            root = Path(temp)
            summary = root / "summary.json"
            output = root / "decision.json"
            summary.write_text(json.dumps(synthetic_summary()), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                result = DECISION.main(
                    [
                        str(summary),
                        "--expected-instances",
                        "40",
                        "--out",
                        str(output),
                    ]
                )
            self.assertEqual(result, 0)
            raw = output.read_bytes()
            report = DECISION.strict_json_loads(raw.decode("ascii"))
            self.assertEqual(raw, DECISION.canonical_json_bytes(report))
            self.assertEqual(report["decision"], "promote")


if __name__ == "__main__":
    unittest.main()
