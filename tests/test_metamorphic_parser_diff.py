from __future__ import annotations

import hashlib
import importlib.util
import json
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "metamorphic_parser_diff.py"
SPEC = importlib.util.spec_from_file_location("metamorphic_parser_diff", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CAMPAIGN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAMPAIGN)


FAKE_SOLVER = r'''from __future__ import annotations

import re
import sys
import time
from pathlib import Path

mode = sys.argv[1]
case_path = Path(sys.argv[-1])
if not case_path.is_file():
    print("missing case", file=sys.stderr)
    raise SystemExit(66)

source = case_path.read_text(encoding="utf-8")
expected_match = re.search(r"^; expected-result: (sat|unsat)$", source, re.MULTILINE)
policy_match = re.search(r"^; viper-policy: ([a-z-]+)$", source, re.MULTILINE)
if expected_match is None or policy_match is None:
    print("missing generated metadata", file=sys.stderr)
    raise SystemExit(65)
expected = expected_match.group(1)
policy = policy_match.group(1)

if mode == "reference":
    print(expected)
elif mode == "viper":
    if policy == "viper-rejects-post-query":
        print("command after check-sat is unsupported", file=sys.stderr)
        raise SystemExit(2)
    print(expected)
elif mode == "wrong":
    print("unsat" if expected == "sat" else "sat")
elif mode == "unknown":
    print("unknown")
elif mode == "malformed":
    print("success")
elif mode == "multiple":
    print(expected)
    print(expected)
elif mode == "error-stdout":
    print('(error "synthetic parser error")')
    print(expected)
elif mode == "error-stderr":
    print(expected)
    print('(error "synthetic parser error")', file=sys.stderr)
elif mode == "nonzero":
    print("synthetic failure", file=sys.stderr)
    raise SystemExit(7)
elif mode == "wrong-reject-exit":
    print("synthetic rejection", file=sys.stderr)
    raise SystemExit(3)
elif mode == "timeout":
    time.sleep(2.0)
else:
    raise SystemExit(64)
'''


def write_fake_solver(root: Path) -> Path:
    path = root / "fake solver launcher.py"
    path.write_text(FAKE_SOLVER, encoding="utf-8")
    return path


def fake_command(fake_solver: Path, mode: str) -> tuple[str, ...]:
    return (sys.executable, str(fake_solver), mode, "{file}")


def solver_result(
    classification: str,
    reason: str = "solver_result",
    exit_code: int | None = 0,
    result_lines: tuple[str, ...] | None = None,
) -> object:
    if result_lines is None:
        result_lines = (
            (classification,) if classification in CAMPAIGN.DECISIVE_RESULTS else ()
        )
    return CAMPAIGN.SolverResult(
        classification,
        reason,
        exit_code,
        result_lines,
        "",
        "",
    )


def complete_groups(
    cases: list[object], group_ids: set[str]
) -> list[object]:
    return [case for case in cases if case.group_id in group_ids]


class GenerationTests(unittest.TestCase):
    def test_generation_is_deterministic_and_seeded(self) -> None:
        first = CAMPAIGN.generate_cases(seed=9182, random_groups=4)
        second = CAMPAIGN.generate_cases(seed=9182, random_groups=4)
        changed = CAMPAIGN.generate_cases(seed=9183, random_groups=4)

        self.assertEqual(first, second)
        fixed_count = len(CAMPAIGN.generate_cases(seed=0, random_groups=0))
        self.assertEqual(len(first), fixed_count + 12)
        self.assertEqual(first[:fixed_count], changed[:fixed_count])
        self.assertNotEqual(first[fixed_count:], changed[fixed_count:])

    def test_fixed_corpus_covers_reserved_alias_and_ordering_boundaries(self) -> None:
        cases = CAMPAIGN.generate_cases(seed=0, random_groups=0)
        by_id = {case.case_id: case for case in cases}

        quoted_true = by_id["reserved-atom-true-quoted-reserved"]
        self.assertIn("(declare-fun |true| () Bool)", quoted_true.source)
        self.assertIn("(assert (not |true|))", quoted_true.source)
        quoted_not = by_id["reserved-head-not-quoted-reserved"]
        self.assertIn("(declare-fun |not| (Bool) Bool)", quoted_not.source)
        self.assertIn("(assert (|not| true))", quoted_not.source)
        alias = by_id["simple-quoted-nullary-alias-mixed-use"]
        self.assertEqual(alias.expected, "unsat")
        self.assertIn("(assert (not |p_alias|))", alias.source)
        quoted_bool = by_id["reserved-atom-bool-quoted-reserved"]
        self.assertIn("(declare-fun |Bool| () Bool)", quoted_bool.source)

        late = by_id["ordering-empty-prefix-late-unsat-body"]
        self.assertEqual(late.policy, CAMPAIGN.VIPER_REJECT_POLICY)
        check_offset = late.source.index("(check-sat)")
        self.assertGreater(late.source.index("(assert false)"), check_offset)
        self.assertEqual(
            sum(line.strip() == "(check-sat)" for line in late.source.splitlines()),
            1,
        )

    def test_every_case_belongs_to_a_nontrivial_result_preserving_group(self) -> None:
        cases = CAMPAIGN.generate_cases(seed=55, random_groups=5)
        groups: dict[str, list[object]] = {}
        for case in cases:
            groups.setdefault(case.group_id, []).append(case)
            digest = hashlib.sha256(case.source.encode("utf-8")).hexdigest()
            self.assertEqual(len(digest), 64)
            self.assertTrue(case.source.endswith("\n"))
        for members in groups.values():
            self.assertGreaterEqual(len(members), 2)
            self.assertEqual(len({case.expected for case in members}), 1)

    def test_generation_only_jsonl_and_case_files_are_byte_deterministic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="parser metamorphic generation ") as temp:
            root = Path(temp)
            outputs = [root / "first", root / "second"]
            cases = CAMPAIGN.generate_cases(seed=81, random_groups=2)
            for output in outputs:
                summary = CAMPAIGN.execute_campaign(
                    cases=cases,
                    output_dir=output,
                    seed=81,
                    random_groups=2,
                    generation_only=True,
                )
                self.assertTrue(summary["success"])

            def artifacts(output: Path) -> dict[str, bytes]:
                return {
                    path.relative_to(output).as_posix(): path.read_bytes()
                    for path in sorted(output.rglob("*"))
                    if path.is_file()
                }

            self.assertEqual(artifacts(outputs[0]), artifacts(outputs[1]))
            lines = (outputs[0] / "manifest.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
            records = [json.loads(line) for line in lines]
            self.assertEqual(records[0]["record_type"], "provenance")
            self.assertEqual(len(records), len(cases) + 1)
            for record in records[1:]:
                source = (outputs[0] / record["path"]).read_bytes()
                self.assertEqual(hashlib.sha256(source).hexdigest(), record["source_sha256"])


class ProcessClassificationTests(unittest.TestCase):
    def test_error_responses_are_rejected_on_both_streams(self) -> None:
        for stdout, stderr, return_code in (
            ('(error "bad term")\nsat\n', "", 0),
            ("sat\n", 'prefix (error "bad term")\n', 0),
            ('(error "bad term")\n', "", 2),
            ("SAT\n", '(ErRoR "bad term")\n', 0),
        ):
            with self.subTest(stdout=stdout, stderr=stderr, return_code=return_code):
                result = CAMPAIGN.classify_completed_process(
                    return_code, stdout, stderr
                )
                self.assertEqual(result.classification, "error")
                self.assertEqual(result.reason, "solver_error_output")

    def test_single_query_requires_exactly_one_result_line(self) -> None:
        decisive = CAMPAIGN.classify_completed_process(0, "diagnostic\nsat\n", "")
        self.assertEqual((decisive.classification, decisive.reason), ("sat", "solver_result"))
        unknown = CAMPAIGN.classify_completed_process(0, "unknown\n", "")
        self.assertEqual((unknown.classification, unknown.reason), ("unknown", "solver_unknown"))
        malformed = CAMPAIGN.classify_completed_process(0, "success\n", "")
        self.assertEqual(malformed.reason, "malformed_output")
        repeated = CAMPAIGN.classify_completed_process(0, "sat\nsat\n", "")
        self.assertEqual(repeated.reason, "multiple_results")
        ambiguous = CAMPAIGN.classify_completed_process(0, "sat\nunsat\n", "")
        self.assertEqual(ambiguous.reason, "multiple_results")

    def test_subprocess_runner_uses_fake_launcher_and_bounds_timeout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="parser metamorphic runner ") as temp:
            root = Path(temp)
            fake = write_fake_solver(root)
            case = CAMPAIGN.generate_cases(seed=0, random_groups=0)[0]
            case_path = root / "case with spaces.smt2"
            case_path.write_text(case.source, encoding="utf-8")

            result = CAMPAIGN.run_solver(fake_command(fake, "reference"), case_path, 1.0)
            self.assertEqual(result.classification, case.expected)
            timed_out = CAMPAIGN.run_solver(
                fake_command(fake, "timeout"), case_path, 0.03
            )
            self.assertEqual((timed_out.classification, timed_out.reason), ("unknown", "timeout"))
            missing = CAMPAIGN.run_solver(
                (str(root / "missing launcher"), "{file}"), case_path, 1.0
            )
            self.assertEqual((missing.classification, missing.reason), ("error", "spawn_error"))

    def test_command_parser_preserves_argv_and_rejects_embedded_placeholder(self) -> None:
        command = CAMPAIGN.parse_command(
            '"/path with spaces/solver" --flag "two words" {file}'
        )
        self.assertEqual(
            command,
            ("/path with spaces/solver", "--flag", "two words", "{file}"),
        )
        with self.assertRaises(ValueError):
            CAMPAIGN.parse_command("solver --input={file}")
        with self.assertRaises(ValueError):
            CAMPAIGN.parse_command("solver {file} {file}")


class PolicyTests(unittest.TestCase):
    def test_post_query_probe_accepts_only_clean_configured_viper_rejection(self) -> None:
        case = next(
            case
            for case in CAMPAIGN.generate_cases(seed=0, random_groups=0)
            if case.policy == CAMPAIGN.VIPER_REJECT_POLICY
        )
        references = {
            "z3": solver_result(case.expected),
            "cvc5": solver_result(case.expected),
        }
        clean_rejection = solver_result(
            "error", "nonzero_exit", exit_code=2, result_lines=()
        )
        anomalies = CAMPAIGN.evaluate_case(
            case,
            {"euf-viper": clean_rejection, **references},
            viper_reject_exit_code=2,
        )
        self.assertEqual(anomalies, [])

        for bad_result in (
            solver_result(case.expected),
            solver_result("error", "nonzero_exit", exit_code=3, result_lines=()),
            solver_result("error", "nonzero_exit", exit_code=2, result_lines=("sat",)),
            solver_result("error", "solver_error_output", exit_code=2, result_lines=()),
        ):
            with self.subTest(result=bad_result):
                anomalies = CAMPAIGN.evaluate_case(
                    case,
                    {"euf-viper": bad_result, **references},
                    viper_reject_exit_code=2,
                )
                self.assertTrue(anomalies)

    def test_hard_coded_expectation_prevents_shared_wrong_answer(self) -> None:
        case = CAMPAIGN.generate_cases(seed=0, random_groups=0)[0]
        wrong = "unsat" if case.expected == "sat" else "sat"
        anomalies = CAMPAIGN.evaluate_case(
            case,
            {
                "euf-viper": solver_result(wrong),
                "z3": solver_result(wrong),
                "cvc5": solver_result(wrong),
                "yices": solver_result(wrong),
            },
            viper_reject_exit_code=2,
        )
        self.assertIn(f"z3:expected-{case.expected}-got-{wrong}", anomalies)
        self.assertIn(f"euf-viper:expected-{case.expected}-got-{wrong}", anomalies)


class CampaignTests(unittest.TestCase):
    def test_four_solver_campaign_records_hashes_and_provenance_jsonl(self) -> None:
        with tempfile.TemporaryDirectory(prefix="parser metamorphic campaign ") as temp:
            root = Path(temp)
            fake = write_fake_solver(root)
            all_cases = CAMPAIGN.generate_cases(seed=4, random_groups=0)
            cases = complete_groups(
                all_cases,
                {"reserved-atom-true", "ordering-sat"},
            )
            commands = {
                "euf-viper": fake_command(fake, "viper"),
                "z3": fake_command(fake, "reference"),
                "cvc5": fake_command(fake, "reference"),
                "yices": fake_command(fake, "reference"),
            }
            output = root / "output"
            summary = CAMPAIGN.execute_campaign(
                cases=cases,
                output_dir=output,
                seed=4,
                random_groups=0,
                generation_only=False,
                commands=commands,
                timeout_s=1.0,
            )

            self.assertTrue(summary["success"])
            self.assertEqual(summary["counts"]["failed_cases"], 0)
            self.assertEqual(summary["counts"]["failed_groups"], 0)
            result_records = [
                json.loads(line)
                for line in (output / "results.jsonl").read_text(
                    encoding="utf-8"
                ).splitlines()
            ]
            provenance = result_records[0]
            self.assertEqual(provenance["record_type"], "provenance")
            self.assertEqual(
                list(provenance["execution"]["solvers"]),
                ["cvc5", "euf-viper", "yices", "z3"],
            )
            fake_digest = hashlib.sha256(fake.read_bytes()).hexdigest()
            for solver in provenance["execution"]["solvers"].values():
                artifact_hashes = {item["sha256"] for item in solver["artifacts"]}
                self.assertIn(fake_digest, artifact_hashes)
                self.assertEqual(len(solver["executable_sha256"]), 64)

            observations = [
                record for record in result_records if record["record_type"] == "observation"
            ]
            groups = [
                record
                for record in result_records
                if record["record_type"] == "metamorphic-group"
            ]
            self.assertEqual(len(observations), len(cases))
            self.assertEqual(len(groups), 2)
            self.assertTrue(all(record["passed"] for record in observations + groups))
            self.assertEqual(
                hashlib.sha256((output / "manifest.jsonl").read_bytes()).hexdigest(),
                summary["artifacts"]["manifest_sha256"],
            )
            self.assertEqual(
                hashlib.sha256((output / "results.jsonl").read_bytes()).hexdigest(),
                summary["artifacts"]["results_sha256"],
            )

    def test_yices_is_optional_but_supplied_yices_is_mandatory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="parser metamorphic optional yices ") as temp:
            root = Path(temp)
            fake = write_fake_solver(root)
            all_cases = CAMPAIGN.generate_cases(seed=1, random_groups=0)
            cases = complete_groups(all_cases, {"reserved-head-not"})
            commands = {
                "euf-viper": fake_command(fake, "viper"),
                "z3": fake_command(fake, "reference"),
                "cvc5": fake_command(fake, "reference"),
            }
            summary = CAMPAIGN.execute_campaign(
                cases=cases,
                output_dir=root / "without-yices",
                seed=1,
                random_groups=0,
                generation_only=False,
                commands=commands,
                timeout_s=1.0,
            )
            self.assertTrue(summary["success"])

            commands["yices"] = fake_command(fake, "error-stdout")
            summary = CAMPAIGN.execute_campaign(
                cases=cases,
                output_dir=root / "bad-yices",
                seed=1,
                random_groups=0,
                generation_only=False,
                commands=commands,
                timeout_s=1.0,
            )
            self.assertFalse(summary["success"])
            self.assertTrue(summary["candidate_success"])
            self.assertEqual(summary["counts"]["failed_cases"], len(cases))
            self.assertEqual(summary["counts"]["candidate_failed_cases"], 0)
            self.assertTrue(
                any(key.startswith("yices:") for key in summary["anomaly_counts"])
            )

    def test_solver_error_output_fails_closed_and_stale_output_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="parser metamorphic failures ") as temp:
            root = Path(temp)
            fake = write_fake_solver(root)
            cases = complete_groups(
                CAMPAIGN.generate_cases(seed=2, random_groups=0),
                {"reserved-atom-false"},
            )
            output = root / "failed-campaign"
            summary = CAMPAIGN.execute_campaign(
                cases=cases,
                output_dir=output,
                seed=2,
                random_groups=0,
                generation_only=False,
                commands={
                    "euf-viper": fake_command(fake, "viper"),
                    "z3": fake_command(fake, "reference"),
                    "cvc5": fake_command(fake, "error-stderr"),
                },
                timeout_s=1.0,
            )
            self.assertFalse(summary["success"])
            self.assertEqual(summary["counts"]["failed_cases"], len(cases))
            self.assertEqual(
                summary["anomaly_counts"]["cvc5:solver_error_output"], len(cases)
            )
            with self.assertRaisesRegex(ValueError, "non-empty output directory"):
                CAMPAIGN.execute_campaign(
                    cases=cases,
                    output_dir=output,
                    seed=2,
                    random_groups=0,
                    generation_only=True,
                )

    def test_cli_uses_fake_launchers_and_returns_nonzero_on_discrepancy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="parser metamorphic cli ") as temp:
            root = Path(temp)
            fake = write_fake_solver(root)

            def command(mode: str) -> str:
                return shlex.join(fake_command(fake, mode))

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--out",
                    str(root / "cli-output"),
                    "--random-groups",
                    "0",
                    "--timeout",
                    "1",
                    "--viper-command",
                    command("wrong"),
                    "--z3-command",
                    command("reference"),
                    "--cvc5-command",
                    command("reference"),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 1, completed.stderr)
            summary = json.loads(
                (root / "cli-output" / "summary.json").read_text(encoding="utf-8")
            )
            self.assertFalse(summary["success"])
            self.assertGreater(summary["counts"]["failed_cases"], 0)

    def test_candidate_gate_records_but_does_not_inherit_reference_failure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="parser metamorphic candidate gate ") as temp:
            root = Path(temp)
            fake = write_fake_solver(root)

            def command(mode: str) -> str:
                return shlex.join(fake_command(fake, mode))

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--out",
                    str(root / "candidate-output"),
                    "--random-groups",
                    "0",
                    "--timeout",
                    "1",
                    "--gate",
                    "candidate",
                    "--viper-command",
                    command("viper"),
                    "--z3-command",
                    command("reference"),
                    "--cvc5-command",
                    command("error-stdout"),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            summary = json.loads(
                (root / "candidate-output" / "summary.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertFalse(summary["success"])
            self.assertTrue(summary["candidate_success"])
            self.assertGreater(summary["counts"]["failed_cases"], 0)
            self.assertEqual(summary["counts"]["candidate_failed_cases"], 0)


if __name__ == "__main__":
    unittest.main()
