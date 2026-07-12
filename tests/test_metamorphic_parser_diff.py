from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "metamorphic_parser_diff.py"
WMI_SCRIPT = ROOT / "scripts" / "wmi" / "euf_viper_parser_diff.sbatch"
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

    def test_rejects_checkpoint_manifest_alias_and_nested_generated_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="parser generated path conflicts ") as temp:
            root = Path(temp)
            cases = CAMPAIGN.generate_cases(seed=0, random_groups=0)[:2]
            output = root / "output"
            with self.assertRaisesRegex(ValueError, "must not alias or be nested"):
                CAMPAIGN.execute_campaign(
                    cases=cases,
                    output_dir=output,
                    seed=0,
                    random_groups=0,
                    generation_only=True,
                    checkpoint_path=output / "manifest.jsonl",
                )
            self.assertFalse(output.exists())

            with self.assertRaisesRegex(ValueError, "must not alias or be nested"):
                CAMPAIGN.validate_generation_paths(
                    output_dir=root / "parent" / "output",
                    checkpoint_path=root / "parent",
                    cases=cases,
                    commands={},
                )

            bad_case = cases[0]._replace(case_id="../manifest")
            with self.assertRaisesRegex(ValueError, "unsafe case id"):
                CAMPAIGN.execute_campaign(
                    cases=[bad_case, cases[1]],
                    output_dir=root / "bad-case-output",
                    seed=0,
                    random_groups=0,
                    generation_only=True,
                )


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
            checkpoint_path = root / "persistent-checkpoint.json"
            summary = CAMPAIGN.execute_campaign(
                cases=cases,
                output_dir=output,
                seed=4,
                random_groups=0,
                generation_only=False,
                parser_mode="shadow",
                commands=commands,
                timeout_s=1.0,
                checkpoint_path=checkpoint_path,
                checkpoint_every=1,
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
                provenance["execution"]["candidate_parser_mode"], "shadow"
            )
            self.assertEqual(summary["candidate_parser_mode"], "shadow")
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
            checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            self.assertEqual(checkpoint["campaign_status"], "complete")
            self.assertEqual(checkpoint["candidate_parser_mode"], "shadow")
            self.assertEqual(checkpoint["completed_cases"], len(cases))
            encoded_records = "".join(
                CAMPAIGN._json_line(record)
                for record in checkpoint["result_records"]
            ).encode("utf-8")
            self.assertEqual(
                checkpoint["records_sha256"],
                hashlib.sha256(encoded_records).hexdigest(),
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
                parser_mode="shadow",
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
                parser_mode="shadow",
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

    def test_solver_and_generated_source_replacement_use_bound_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="parser bound byte race ") as temp:
            root = Path(temp)
            fake = write_fake_solver(root)
            fake_digest = hashlib.sha256(fake.read_bytes()).hexdigest()
            cases = complete_groups(
                CAMPAIGN.generate_cases(seed=7, random_groups=0),
                {"reserved-atom-true"},
            )
            output = root / "output"
            replacement_solver = root / "replacement-solver.py"
            replacement_solver.write_text("raise SystemExit(99)\n", encoding="utf-8")
            replacement_source = root / "replacement-source.smt2"
            replacement_source.write_text("; replacement path consumed\n", encoding="utf-8")
            real_run = subprocess.run
            replaced = False

            def replace_then_run(*args: object, **kwargs: object) -> object:
                nonlocal replaced
                first_case = output / "cases" / f"{cases[0].case_id}.smt2"
                if not replaced and first_case.exists():
                    os.replace(replacement_solver, fake)
                    os.replace(replacement_source, first_case)
                    if CAMPAIGN._command_artifacts_use_fd_paths():
                        for staged_path in (output / ".solver-stage").iterdir():
                            replacement = root / f"replacement-{staged_path.name}"
                            replacement.write_text(
                                "raise SystemExit(98)\n", encoding="utf-8"
                            )
                            os.replace(replacement, staged_path)
                    replaced = True
                return real_run(*args, **kwargs)

            with mock.patch.object(
                CAMPAIGN.subprocess, "run", side_effect=replace_then_run
            ):
                summary = CAMPAIGN.execute_campaign(
                    cases=cases,
                    output_dir=output,
                    seed=7,
                    random_groups=0,
                    generation_only=False,
                    parser_mode="shadow",
                    run_id="race-shadow",
                    commands={
                        "euf-viper": fake_command(fake, "viper"),
                        "z3": fake_command(fake, "reference"),
                        "cvc5": fake_command(fake, "reference"),
                    },
                    timeout_s=1.0,
                )

            self.assertTrue(replaced)
            self.assertTrue(summary["success"])
            result_records = [
                json.loads(line)
                for line in (output / "results.jsonl").read_text(
                    encoding="utf-8"
                ).splitlines()
            ]
            provenance = result_records[0]
            expected_transport = (
                "inherited-fd-for-verified-private-stage"
                if CAMPAIGN._command_artifacts_use_fd_paths()
                else "verified-private-stage-with-retained-fd"
            )
            for solver in provenance["execution"]["solvers"].values():
                self.assertTrue(
                    all(
                        artifact["consumed_via"] == expected_transport
                        for artifact in solver["artifacts"]
                    )
                )
                self.assertIn(
                    fake_digest,
                    {artifact["sha256"] for artifact in solver["artifacts"]},
                )
            first_observation = next(
                record
                for record in result_records
                if record.get("case_id") == cases[0].case_id
            )
            self.assertEqual(
                first_observation["source_consumed"]["sha256"],
                hashlib.sha256(cases[0].source.encode("utf-8")).hexdigest(),
            )
            self.assertNotEqual(
                hashlib.sha256(
                    (output / "cases" / f"{cases[0].case_id}.smt2").read_bytes()
                ).hexdigest(),
                first_observation["source_consumed"]["sha256"],
            )

    def test_persistent_checkpoint_advances_during_case_execution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="parser checkpoint generations ") as temp:
            root = Path(temp)
            fake = write_fake_solver(root)
            cases = complete_groups(
                CAMPAIGN.generate_cases(seed=3, random_groups=0),
                {"reserved-head-not"},
            )
            checkpoint = root / "persistent" / "checkpoint.json"
            snapshots: list[dict] = []
            durable_write = CAMPAIGN._durable_atomic_write

            def capture(path: Path, value: bytes) -> None:
                if path == checkpoint.resolve():
                    snapshots.append(json.loads(value))
                durable_write(path, value)

            with mock.patch.object(
                CAMPAIGN, "_durable_atomic_write", side_effect=capture
            ):
                CAMPAIGN.execute_campaign(
                    cases=cases,
                    output_dir=root / "output",
                    seed=3,
                    random_groups=0,
                    generation_only=False,
                    parser_mode="stream",
                    commands={
                        "euf-viper": fake_command(fake, "viper"),
                        "z3": fake_command(fake, "reference"),
                        "cvc5": fake_command(fake, "reference"),
                    },
                    timeout_s=1.0,
                    checkpoint_path=checkpoint,
                    checkpoint_every=1,
                )

            self.assertEqual(snapshots[0]["completed_cases"], 0)
            self.assertEqual(
                [item["completed_cases"] for item in snapshots[1:-1]],
                list(range(1, len(cases) + 1)),
            )
            self.assertEqual(snapshots[-1]["campaign_status"], "complete")
            self.assertEqual(snapshots[-1]["candidate_parser_mode"], "stream")
            self.assertEqual(
                [item["generation"] for item in snapshots],
                list(range(1, len(snapshots) + 1)),
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
                parser_mode="shadow",
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
                    "--parser-mode",
                    "shadow",
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
                    "--parser-mode",
                    "shadow",
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


class CrossModeTests(unittest.TestCase):
    def test_rejects_mode_directory_collision(self) -> None:
        with tempfile.TemporaryDirectory(prefix="parser mode collision ") as temp:
            root = Path(temp)
            with self.assertRaisesRegex(ValueError, "directories collide"):
                CAMPAIGN.compare_mode_campaigns(
                    root / "same-mode-output",
                    root / "same-mode-output",
                    root / "pair.json",
                )

    def test_generation_only_pair_cannot_pass_cross_mode_gate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="parser empty mode pair ") as temp:
            root = Path(temp)
            cases = complete_groups(
                CAMPAIGN.generate_cases(seed=0, random_groups=0),
                {"reserved-head-not"},
            )
            outputs = {mode: root / mode for mode in ("shadow", "stream")}
            for mode in ("shadow", "stream"):
                CAMPAIGN.execute_campaign(
                    cases=cases,
                    output_dir=outputs[mode],
                    seed=0,
                    random_groups=0,
                    generation_only=True,
                    parser_mode=mode,
                    run_id=f"empty-{mode}",
                )

            paired = CAMPAIGN.compare_mode_campaigns(
                outputs["shadow"],
                outputs["stream"],
                root / "pair-summary.json",
            )
            self.assertFalse(paired["gate_passed"])
            self.assertIn(
                "shadow:not-a-differential-campaign", paired["mismatches"]
            )
            self.assertIn(
                "stream:case-observation-order-mismatch", paired["mismatches"]
            )

    def test_paired_shadow_stream_gate_passes_and_detects_byte_changes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="parser paired modes ") as temp:
            root = Path(temp)
            fake = write_fake_solver(root)
            cases = complete_groups(
                CAMPAIGN.generate_cases(seed=11, random_groups=0),
                {"reserved-head-not"},
            )
            commands = {
                "euf-viper": fake_command(fake, "viper"),
                "z3": fake_command(fake, "reference"),
                "cvc5": fake_command(fake, "reference"),
            }
            outputs = {
                "shadow": root / "parser-diff-pair-shadow",
                "stream": root / "parser-diff-pair-stream",
            }
            for mode in ("shadow", "stream"):
                CAMPAIGN.execute_campaign(
                    cases=cases,
                    output_dir=outputs[mode],
                    seed=11,
                    random_groups=0,
                    generation_only=False,
                    parser_mode=mode,
                    run_id=f"pair-{mode}",
                    commands=commands,
                    timeout_s=1.0,
                )

            paired = CAMPAIGN.compare_mode_campaigns(
                outputs["shadow"],
                outputs["stream"],
                root / "pair-summary.json",
            )
            self.assertTrue(paired["gate_passed"])
            self.assertEqual(paired["base_run_id"], "pair")
            self.assertEqual(
                paired["mode_run_ids"],
                {"shadow": "pair-shadow", "stream": "pair-stream"},
            )

            stream_results = outputs["stream"] / "results.jsonl"
            records = [
                json.loads(line)
                for line in stream_results.read_text(encoding="utf-8").splitlines()
            ]
            observation = next(
                record for record in records if record.get("record_type") == "observation"
            )
            observation["observations"]["euf-viper"]["classification"] = "unsat"
            stream_results.write_text(
                "".join(CAMPAIGN._json_line(record) for record in records),
                encoding="utf-8",
            )
            failed = CAMPAIGN.compare_mode_campaigns(
                outputs["shadow"],
                outputs["stream"],
                root / "pair-summary-tampered.json",
            )
            self.assertFalse(failed["gate_passed"])
            self.assertIn("stream:results-hash-mismatch", failed["mismatches"])
            self.assertIn("candidate-observations-differ", failed["mismatches"])


class WmiWrapperTests(unittest.TestCase):
    def test_wrapper_runs_mode_qualified_pair_and_final_consistency_gate(self) -> None:
        self.assertTrue(SCRIPT.is_file())
        self.assertTrue((ROOT / "tests" / "test_metamorphic_parser_diff.py").is_file())
        wrapper = WMI_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("scripts/bench/metamorphic_parser_diff.py", wrapper)
        self.assertIn('mode_run_id="${BASE_RUN_ID}-${parser_mode}"', wrapper)
        self.assertIn("run_mode shadow &", wrapper)
        self.assertIn("run_mode stream &", wrapper)
        self.assertIn('--run-id "$mode_run_id"', wrapper)
        self.assertIn('--parser-mode "$parser_mode"', wrapper)
        self.assertIn("EUF_VIPER_PARSER_MODE=$parser_mode", wrapper)
        self.assertIn('--checkpoint "$checkpoint"', wrapper)
        self.assertIn("--cross-mode-shadow", wrapper)
        self.assertIn("--cross-mode-stream", wrapper)
        self.assertIn("--cross-mode-out", wrapper)
        self.assertIn('parser-diff-${BASE_RUN_ID}-pair', wrapper)
        self.assertIn("wrapper-failure.txt", wrapper)
        self.assertIn("pair-failure.txt", wrapper)
        self.assertNotIn("EUF_VIPER_PARSER_DIFF_MODE", wrapper)
        self.assertNotIn("UNCONDITIONAL_QUOTIENT", wrapper)
        self.assertNotIn("unconditional-quotient", wrapper.lower())
        completed = subprocess.run(
            ["bash", "-n", str(WMI_SCRIPT)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        match = re.search(r"^#SBATCH --time=(\d+):(\d+):(\d+)$", wrapper, re.MULTILINE)
        self.assertIsNotNone(match)
        assert match is not None
        hours, minutes, seconds = (int(value) for value in match.groups())
        self.assertGreaterEqual(hours * 3600 + minutes * 60 + seconds, 4.5 * 3600)
        self.assertIn("#SBATCH --cpus-per-task=2", wrapper)


if __name__ == "__main__":
    unittest.main()
