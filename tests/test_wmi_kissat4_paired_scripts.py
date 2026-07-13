from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WMI = ROOT / "scripts" / "wmi"
COMMON = WMI / "euf_viper_kissat4_paired_common.sh"
RUNNER = WMI / "euf_viper_kissat4_paired.sbatch"
MERGE = WMI / "euf_viper_kissat4_paired_merge.sbatch"
SUBMIT = WMI / "submit_kissat4_paired.sh"
SCRIPTS = (COMMON, RUNNER, MERGE, SUBMIT)

VALIDATION_REVISION = "d7c14dac90615717b06e063274c42296a46e01a3"
SC2021_SHA256 = "d7321602b8cc86683ccb41e90bea7b843a5059caad62d1eba347bb3e69c70362"
MODERN_SHA256 = "ecbcfebb1f39c725c1d0266442c7dcc80083b8347e3b77d90bfb5646bd4ea6b6"


def source_array(name: str) -> list[str]:
    command = (
        f"source {COMMON!s}; "
        f"printf '%s\\n' \"${{{name}[@]}}\""
    )
    completed = subprocess.run(
        ["bash", "-c", command],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return completed.stdout.splitlines()


class Kissat4PairedWmiScriptTests(unittest.TestCase):
    def text(self, path: Path) -> str:
        return path.read_text(encoding="ascii")

    def test_shell_syntax_and_executable_bits(self) -> None:
        completed = subprocess.run(
            ["bash", "-n", *(str(path) for path in SCRIPTS)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for path in SCRIPTS:
            self.assertTrue(os.access(path, os.X_OK), path)

    def test_embedded_python_blocks_compile(self) -> None:
        pattern = re.compile(
            r"<<'(?P<marker>PY_[A-Z0-9_]+)'\n(?P<body>.*?)\n(?P=marker)$",
            re.MULTILINE | re.DOTALL,
        )
        blocks = []
        for path in SCRIPTS:
            blocks.extend(
                (path, match.group("body"))
                for match in pattern.finditer(self.text(path))
            )
        self.assertGreaterEqual(len(blocks), 7)
        for path, body in blocks:
            compile(body, f"{path}:embedded-python", "exec")

    def test_validation_evidence_is_immutable_and_exact(self) -> None:
        text = self.text(COMMON)
        self.assertIn(f'KISSAT4_VALIDATION_REVISION="{VALIDATION_REVISION}"', text)
        self.assertIn('KISSAT4_VALIDATION_JOB_ID="144945"', text)
        self.assertIn(f'KISSAT4_SC2021_SHA256="{SC2021_SHA256}"', text)
        self.assertIn(f'KISSAT4_MODERN_SHA256="{MODERN_SHA256}"', text)
        self.assertIn("euf-viper 0.1.0 (sat=kissat-sc2021)", text)
        self.assertIn("euf-viper 0.1.0 (sat=kissat-4.0.4)", text)
        self.assertIn('"$sc2021" --version', text)
        self.assertIn('"$modern" --version', text)

    def test_every_solver_environment_key_is_fixed_or_explicitly_unset(self) -> None:
        settings = source_array("KISSAT4_RUNTIME_SETTINGS")
        fixed = [entry.split("=", 1)[0] for entry in settings]
        unset = source_array("KISSAT4_EXPLICITLY_UNSET")
        self.assertEqual(len(fixed), len(set(fixed)))
        self.assertEqual(len(unset), len(set(unset)))
        self.assertFalse(set(fixed) & set(unset))

        source_keys = set()
        for path in (ROOT / "src").glob("*.rs"):
            source_keys.update(re.findall(r"EUF_VIPER_[A-Z0-9_]+", path.read_text()))
        self.assertEqual(set(fixed) | set(unset), source_keys)

        parsed = dict(entry.split("=", 1) for entry in settings)
        self.assertEqual(parsed["EUF_VIPER_BACKEND"], "kissat")
        self.assertEqual(parsed["EUF_VIPER_KISSAT_MODE"], "default")
        self.assertEqual(parsed["EUF_VIPER_KISSAT_OPTIONS"], "")

    def test_runner_sanitizes_and_duplicates_the_same_runtime_settings(self) -> None:
        text = self.text(RUNNER)
        self.assertIn('env -i "${BASE_ENV[@]}"', text)
        self.assertIn(
            'AB_ENV_ARGS+=(--baseline-env "$setting" --candidate-env "$setting")',
            text,
        )
        self.assertNotIn("EUF_VIPER_BASELINE_", text)
        self.assertNotIn("EUF_VIPER_CANDIDATE_", text)
        self.assertIn('"arms_identical": True', text)

    def test_revision_clean_tree_script_and_manifest_checks_are_fail_closed(self) -> None:
        common = self.text(COMMON)
        runner = self.text(RUNNER)
        merge = self.text(MERGE)
        self.assertIn("git merge-base --is-ancestor", common)
        self.assertIn("git status --porcelain=v1 --untracked-files=all", common)
        self.assertIn("changes files outside scripts/wmi and tests", common)
        self.assertIn("campaign script bundle mismatch", common)
        self.assertIn("source SHA-256 mismatch", common)
        for text in (runner, merge):
            self.assertGreaterEqual(text.count("kissat4_check_repository"), 2)
            self.assertGreaterEqual(text.count("kissat4_check_script_bundle"), 2)
            self.assertGreaterEqual(text.count("kissat4_check_binaries"), 2)
            self.assertIn("source manifest changed after submission", text)

    def test_wrong_validated_binary_fails_before_version_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in (
                "euf-viper-kissat-sc2021",
                "euf-viper-kissat-4.0.4",
            ):
                path = root / name
                path.write_text("#!/bin/sh\necho wrong\n", encoding="ascii")
                path.chmod(0o755)
            completed = subprocess.run(
                [
                    "bash",
                    "-c",
                    f"source {COMMON!s}; kissat4_check_binaries {root!s}",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("SHA-256 mismatch", completed.stderr)

    def test_all_timed_stages_verify_single_cpu_slurm_affinity(self) -> None:
        for path in (RUNNER, MERGE):
            text = self.text(path)
            self.assertIn("#SBATCH --ntasks=1", text)
            self.assertIn("#SBATCH --cpus-per-task=1", text)
            self.assertIn("--cpu-bind=threads", text)
            self.assertIn("sched_getaffinity", text)
            self.assertIn("AFFINITY_COUNT", text)
            self.assertIn("SLURM_CPUS_PER_TASK must be exactly 1", text)

    def test_submission_graph_has_sample_gate_then_broad_array_then_merge(self) -> None:
        text = self.text(SUBMIT)
        self.assertIn("--dry-run", text)
        self.assertEqual(text.count("sbatch --parsable"), 3)
        self.assertGreaterEqual(text.count("--kill-on-invalid-dep=yes"), 3)
        self.assertIn("--dependency=afterok:'$SAMPLE_JOB'", text)
        self.assertIn("--dependency=afterok:'$BROAD_JOB'", text)
        self.assertNotIn("afterany:", text)
        self.assertIn("--array=0-$((SHARDS - 1))%'$MAX_ACTIVE'", text)
        self.assertIn("abort_partial_chain", text)
        self.assertIn("git ls-remote --exit-code", text)

    def test_sample_and_broad_results_are_machine_readable_and_hashed(self) -> None:
        runner = self.text(RUNNER)
        merge = self.text(MERGE)
        submit = self.text(SUBMIT)
        for field in (
            '"manifest"',
            '"binaries"',
            '"scripts"',
            '"environments"',
            '"slurm"',
            '"outputs"',
            '"artifacts"',
        ):
            self.assertIn(field, runner)
        self.assertIn('"shards": records', merge)
        self.assertIn('"stage": "broad-merge"', merge)
        self.assertIn('"status": os.environ["KISSAT4_SUBMISSION_STATUS"]', submit)
        self.assertIn("submission.json", submit)

    def test_sample_selection_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            source = work / "source.jsonl"
            rows = [
                {
                    "path": f"case-{index}.smt2",
                    "relative_path": f"family/case-{index}.smt2",
                    "sha256": "0" * 64,
                    "status": "sat" if index % 2 else "unsat",
                }
                for index in range(12)
            ]
            source.write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )
            first = work / "first.jsonl"
            second = work / "second.jsonl"
            command = (
                f"source {COMMON!s}; "
                f"kissat4_make_sample_manifest {source!s} 5 144945 {first!s}; "
                f"kissat4_make_sample_manifest {source!s} 5 144945 {second!s}"
            )
            completed = subprocess.run(
                ["bash", "-c", command],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(len(first.read_text().splitlines()), 5)


if __name__ == "__main__":
    unittest.main()
