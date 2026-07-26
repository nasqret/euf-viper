from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "run_fast_cycle.py"
SPEC = ROOT / "campaigns" / "quotient-jit-fast-cycle-2026-07.json"
MODULE_SPEC = importlib.util.spec_from_file_location("run_fast_cycle", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(RUNNER)


class FastCycleTests(unittest.TestCase):
    def test_repository_spec_is_valid_and_defaults_to_four_fast_stages(self) -> None:
        spec = RUNNER.load_spec(SPEC)
        stages = RUNNER.selected_stages(spec, [], None)

        self.assertEqual(
            [stage["id"] for stage in stages],
            ["Q1", "Q2P", "Q2G", "Q2M"],
        )
        self.assertFalse(spec["candidate"]["default_behavior_change_authorized"])
        self.assertEqual(
            spec["candidate"]["argv"][3],
            "quotient-portfolio",
        )

    def test_through_selection_is_ordered_and_unknown_ids_fail(self) -> None:
        spec = RUNNER.load_spec(SPEC)

        self.assertEqual(
            [stage["id"] for stage in RUNNER.selected_stages(spec, [], "Q3")],
            ["Q1", "Q2P", "Q2G", "Q2M", "Q2PF", "Q2SF", "Q2NF", "Q3"],
        )
        with self.assertRaisesRegex(RUNNER.FastCycleError, "unknown"):
            RUNNER.selected_stages(spec, ["missing"], None)

    def test_comparator_filter_is_strict_and_stage_local(self) -> None:
        spec = RUNNER.load_spec(SPEC)
        stages = RUNNER.selected_stages(spec, ["Q1", "Q2G"], None)

        selection = RUNNER.selected_comparators(spec, stages, ["yices2"])
        self.assertEqual(selection, {"Q1": ["yices2"], "Q2G": ["yices2"]})
        with self.assertRaisesRegex(RUNNER.FastCycleError, "unknown comparators"):
            RUNNER.selected_comparators(spec, stages, ["missing"])
        with self.assertRaisesRegex(RUNNER.FastCycleError, "supports none"):
            RUNNER.selected_comparators(spec, stages, ["z3"])

    def test_gate_rejects_wrong_answers_coverage_loss_and_slowdown(self) -> None:
        stage = {
            "require_no_coverage_loss": True,
            "minimum_common_aggregate_speedup": 1.0,
            "minimum_common_geometric_speedup": 1.0,
            "minimum_reference_aggregate_speedup": 1.0,
            "minimum_reference_geometric_speedup": 1.0,
        }
        valid = {
            "accounting": {"wrong_answers": 0, "execution_errors": 0},
            "coverage_delta": 0,
            "baseline_only_correct": 0,
            "common_correct": 3,
            "common_aggregate_speedup": 1.01,
            "common_geometric_speedup": 1.02,
        }
        self.assertEqual(RUNNER.gate_summary(valid, stage), [])

        invalid = dict(valid)
        invalid["accounting"] = {"wrong_answers": 1, "execution_errors": 2}
        invalid["coverage_delta"] = -1
        invalid["baseline_only_correct"] = 1
        invalid["common_aggregate_speedup"] = 0.99
        invalid["common_geometric_speedup"] = 0.98
        failures = "\n".join(RUNNER.gate_summary(invalid, stage))
        self.assertIn("wrong_answers=1", failures)
        self.assertIn("execution_errors=2", failures)
        self.assertIn("coverage_delta=-1", failures)
        self.assertIn("baseline_only_correct=1", failures)
        self.assertIn("common_aggregate_speedup", failures)
        self.assertIn("common_geometric_speedup", failures)

    def test_geometric_slowdown_cannot_hide_behind_an_aggregate_win(self) -> None:
        stage = {
            "require_no_coverage_loss": True,
            "minimum_common_aggregate_speedup": 1.0,
            "minimum_common_geometric_speedup": 1.0,
            "minimum_reference_aggregate_speedup": 1.0,
            "minimum_reference_geometric_speedup": 1.0,
        }
        summary = {
            "accounting": {"wrong_answers": 0, "execution_errors": 0},
            "coverage_delta": 0,
            "baseline_only_correct": 0,
            "common_correct": 3,
            "common_aggregate_speedup": 1.25,
            "common_geometric_speedup": 0.70,
        }

        failures = RUNNER.gate_summary(summary, stage)
        self.assertEqual(len(failures), 1)
        self.assertIn("common_geometric_speedup", failures[0])
        self.assertEqual(
            RUNNER.gate_summary(summary, stage, enforce_performance=False),
            [],
        )

    def test_strict_candidate_coverage_dominance_needs_no_common_timing(self) -> None:
        stage = {
            "require_no_coverage_loss": True,
            "minimum_common_aggregate_speedup": 1.0,
            "minimum_common_geometric_speedup": 1.0,
            "minimum_reference_aggregate_speedup": 1.0,
            "minimum_reference_geometric_speedup": 1.0,
        }
        summary = {
            "accounting": {"wrong_answers": 0, "execution_errors": 0},
            "coverage_delta": 1,
            "baseline_only_correct": 0,
            "candidate_only_correct": 1,
            "common_correct": 0,
            "common_aggregate_speedup": None,
            "common_geometric_speedup": None,
        }

        self.assertEqual(RUNNER.gate_summary(summary, stage), [])

        summary["coverage_delta"] = 0
        summary["candidate_only_correct"] = 0
        self.assertIn("no common correct instances", RUNNER.gate_summary(summary, stage))

    def test_authorizing_a_default_change_invalidates_the_contract(self) -> None:
        payload = json.loads(SPEC.read_text(encoding="ascii"))
        payload["candidate"]["default_behavior_change_authorized"] = True
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.json"
            path.write_text(json.dumps(payload), encoding="ascii")
            with self.assertRaisesRegex(RUNNER.FastCycleError, "not authorized"):
                RUNNER.load_spec(path)

    def test_relative_manifest_paths_are_bound_to_an_explicit_corpus_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = root / "corpus"
            corpus.mkdir()
            instance = corpus / "case.smt2"
            instance.write_text("(check-sat)\n", encoding="ascii")
            manifest = root / "manifest.jsonl"
            manifest.write_text(
                json.dumps(
                    {
                        "path": "case.smt2",
                        "relative_path": "case.smt2",
                        "status": "sat",
                    }
                )
                + "\n",
                encoding="ascii",
            )
            resolved = RUNNER.resolve_manifest(
                manifest,
                corpus,
                root / "resolved.jsonl",
            )
            row = json.loads(resolved.read_text(encoding="ascii"))
            self.assertEqual(row["path"], str(instance.resolve()))

    def test_shared_corpus_is_resolved_from_the_worktree_common_git_dir(self) -> None:
        spec = RUNNER.load_spec(SPEC)
        corpus = RUNNER.resolve_corpus_root(ROOT, spec["corpus_root"], None)

        self.assertTrue(corpus.is_dir())
        self.assertEqual(corpus.name, "QF_UF")

    def test_dry_run_writes_an_atomic_machine_readable_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(SPEC),
                    "--stage",
                    "Q1",
                    "--output",
                    str(output),
                    "--dry-run",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            ledger = json.loads((output / "ledger.json").read_text(encoding="ascii"))
            self.assertEqual(ledger["status"], "dry_run")
            self.assertEqual(ledger["selected_stages"], ["Q1"])
            self.assertEqual(
                ledger["selected_comparators"],
                {"Q1": ["yices2", "z3", "cvc5"]},
            )
            self.assertEqual(ledger["schema_version"], 2)
            self.assertIsNone(ledger["reference_binary"])
            self.assertIn("revision", ledger["repository"])


if __name__ == "__main__":
    unittest.main()
