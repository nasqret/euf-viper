from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WMI = ROOT / "scripts" / "wmi"
PREPARE = WMI / "euf_viper_rollback_prepare.sbatch"
CONTROL = WMI / "euf_viper_rollback_control.sbatch"
AUDIT = WMI / "euf_viper_rollback_audit.sbatch"
SUBMIT = WMI / "submit_rollback_control.sh"
SBATCH_FILES = [PREPARE, CONTROL, AUDIT]
ALL_SCRIPTS = [*SBATCH_FILES, SUBMIT]


class WmiRollbackControlScriptTests(unittest.TestCase):
    def text(self, path: Path) -> str:
        return path.read_text(encoding="ascii")

    def test_shell_syntax(self) -> None:
        completed = subprocess.run(
            ["/bin/bash", "-n", *(str(path) for path in ALL_SCRIPTS)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_embedded_python_blocks_compile(self) -> None:
        pattern = re.compile(
            r"<<'(?P<marker>PY_[A-Z0-9_]+)'\n(?P<body>.*?)\n(?P=marker)$",
            re.MULTILINE | re.DOTALL,
        )
        blocks = []
        for path in ALL_SCRIPTS:
            for match in pattern.finditer(self.text(path)):
                blocks.append((path, match.group("body")))
        self.assertGreaterEqual(len(blocks), 2)
        for path, body in blocks:
            compile(body, f"{path}:embedded-python", "exec")

    def test_all_slurm_stages_are_one_core_and_revision_clean(self) -> None:
        for path in SBATCH_FILES:
            text = self.text(path)
            self.assertIn("#SBATCH --ntasks=1", text)
            self.assertIn("#SBATCH --cpus-per-task=1", text)
            self.assertIn("SLURM_CPUS_PER_TASK", text)
            self.assertIn("git rev-parse HEAD", text)
            self.assertIn("git status --porcelain=v1 --untracked-files=all", text)
            self.assertIn("export OMP_NUM_THREADS=1", text)
            self.assertIn("export RAYON_NUM_THREADS=1", text)

    def test_prepare_freezes_binary_manifest_and_source_population(self) -> None:
        text = self.text(PREPARE)
        self.assertIn("cargo build --release --locked", text)
        self.assertIn("build_rollback_control_manifest.py", text)
        self.assertIn("EUF_VIPER_ROLLBACK_EXPECTED_SOURCES", text)
        self.assertIn("sha256_file", text)
        self.assertIn("binary_sha256", text)
        self.assertIn("manifest_sha256", text)
        self.assertIn("source_set_sha256", text)
        self.assertIn("target_count", text)
        self.assertIn("anti_target_count", text)
        self.assertIn("PREFLIGHT_JOURNAL", text)
        self.assertIn("--shard-index \"$TARGET_COUNT\"", text)
        self.assertIn("--shard-count \"$CONTROL_ROWS\"", text)
        self.assertIn('"candidate": {"correct": 2}', text)
        self.assertIn('"preflight": {', text)

    def test_array_is_exact_three_way_control_and_uses_pinned_binary(self) -> None:
        text = self.text(CONTROL)
        self.assertIn("COMPARISON_COUNT=3", text)
        self.assertIn("SLURM_ARRAY_TASK_ID", text)
        self.assertIn("compare_rollback_control.py", text)
        self.assertIn("CURRENT", text)
        self.assertIn("MODEL_CUTS", text)
        self.assertIn("DYNAMIC", text)
        self.assertIn("sha256_file", text)
        self.assertIn("/bin/bash", text)
        self.assertIn("srun", text)
        self.assertIn("--cpu-bind=cores", text)

    def test_audit_rechecks_hashes_and_enforces_preregistered_gate(self) -> None:
        text = self.text(AUDIT)
        self.assertIn("audit_rollback_control.py", text)
        self.assertIn("sha256sum", text)
        self.assertIn("--target-speedup", text)
        self.assertIn("--anti-target-overhead", text)
        self.assertIn("--minimum-multi-round-targets", text)
        self.assertIn("--require-single-cpu", text)
        self.assertIn("final-audit.json", text)

    def test_submitter_is_public_revision_bound_idempotent_afterok_chain(self) -> None:
        text = self.text(SUBMIT)
        self.assertIn("git ls-remote --exit-code", text)
        self.assertIn("refs/heads/research-rollback-propagator", text)
        self.assertIn("git status --porcelain=v1 --untracked-files=no", text)
        self.assertIn("EUF_VIPER_ROLLBACK_REVISION", text)
        self.assertIn("git merge-base --is-ancestor", text)
        self.assertIn('"submitter_revision": submitter_revision', text)
        self.assertIn("test ! -e '$RUN_ROOT'", text)
        self.assertIn('write_receipt "submission_intent"', text)
        self.assertIn('write_receipt "submitting"', text)
        self.assertIn('write_receipt "submitted"', text)
        self.assertIn("submission_state_may_be_incomplete", text)
        self.assertIn("--kill-on-invalid-dep=yes", text)
        self.assertEqual(text.count("afterok:"), 2)
        self.assertNotIn("afterany:", text)
        self.assertIn("COMPARISON_COUNT=3", text)
        self.assertIn("TOTAL_ARRAY_TASKS", text)
        self.assertIn("abort_partial_chain", text)


class RollbackSubmitterHermeticTests(unittest.TestCase):
    REVISION = "1" * 40

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "scripts" / "wmi").mkdir(parents=True)
        shutil.copy2(SUBMIT, self.root / "scripts" / "wmi" / SUBMIT.name)
        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        self.ssh_log = self.root / "ssh.log"
        self.ssh_counter = self.root / "ssh-counter"
        self.ssh_counter.write_text("0\n", encoding="ascii")
        self._write_executable(
            "git",
            f"""
            #!/bin/bash
            set -euo pipefail
            case "$1" in
              status) exit 0 ;;
              rev-parse) printf '%s\n' '{self.REVISION}' ;;
              ls-remote) printf '%s\t%s\n' '{self.REVISION}' "$4" ;;
              cat-file) exit 0 ;;
              merge-base) exit 0 ;;
              *) echo "unsupported fake git invocation: $*" >&2; exit 91 ;;
            esac
            """,
        )
        self._write_executable(
            "ssh",
            """
            #!/bin/bash
            set -euo pipefail
            host="$1"
            shift
            command="$*"
            printf '%s\n' "$command" >> "$TEST_SSH_LOG"
            if [[ "$command" == *"printf %s"* ]]; then
              printf '%s' /remote/home
              exit 0
            fi
            if [ "${command#mkdir }" != "$command" ] && [ "${TEST_FAIL_STAGE:-}" = mkdir ]; then
              exit 255
            fi
            if [[ "$command" == *"sbatch"* ]]; then
              count="$(cat "$TEST_SSH_COUNTER")"
              count=$((count + 1))
              printf '%s\n' "$count" > "$TEST_SSH_COUNTER"
              if [ "${TEST_FAIL_STAGE:-}" = array ] && [ "$count" = 2 ]; then
                printf '%s\n' not-a-job
              else
                printf '%s\n' "$((7000 + count))"
              fi
              exit 0
            fi
            exit 0
            """,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_executable(self, name: str, body: str) -> None:
        path = self.fake_bin / name
        path.write_text(textwrap.dedent(body).lstrip(), encoding="ascii")
        path.chmod(0o755)

    def run_submitter(
        self, *, fail_stage: str = "", campaign_revision: str = ""
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "PATH": f"{self.fake_bin}:{os.environ['PATH']}",
            "TEST_SSH_LOG": str(self.ssh_log),
            "TEST_SSH_COUNTER": str(self.ssh_counter),
            "TEST_FAIL_STAGE": fail_stage,
            "EUF_VIPER_WMI_HOST": "fake-wmi",
            "EUF_VIPER_WMI_CAMPAIGN_ROOT": "/remote/campaigns",
            "EUF_VIPER_ROLLBACK_CORPUS_ROOT": "/remote/corpus",
            "EUF_VIPER_ROLLBACK_CORPUS_MANIFEST": (
                "/remote/corpus/qf_uf_manifest.jsonl"
            ),
            "EUF_VIPER_ROLLBACK_RUN_ID": "hermetic-run",
        }
        if campaign_revision:
            environment["EUF_VIPER_ROLLBACK_REVISION"] = campaign_revision
        return subprocess.run(
            ["/bin/bash", str(self.root / "scripts" / "wmi" / SUBMIT.name)],
            cwd=self.root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def receipt(self) -> dict[str, object]:
        path = self.root / "results" / "rollback-control-submissions" / "hermetic-run.json"
        return json.loads(path.read_text(encoding="ascii"))

    def test_success_records_exact_afterok_chain(self) -> None:
        completed = self.run_submitter()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        receipt = self.receipt()
        self.assertEqual(receipt["status"], "submitted")
        self.assertEqual(
            receipt["jobs"],
            {"prepare": "7001", "control_array": "7002", "audit": "7003"},
        )
        log = self.ssh_log.read_text(encoding="ascii")
        self.assertIn("--array='0-11%8'", log)
        self.assertEqual(log.count("afterok:"), 2)

    def test_published_submitter_can_pin_ancestor_campaign_revision(self) -> None:
        campaign_revision = "2" * 40
        completed = self.run_submitter(campaign_revision=campaign_revision)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        receipt = self.receipt()
        self.assertEqual(receipt["revision"], campaign_revision)
        self.assertEqual(receipt["submitter_revision"], self.REVISION)

    def test_invalid_array_job_aborts_and_cancels_prepare(self) -> None:
        completed = self.run_submitter(fail_stage="array")
        self.assertEqual(completed.returncode, 2)
        receipt = self.receipt()
        self.assertEqual(receipt["status"], "submission_aborted")
        self.assertEqual(receipt["jobs"]["prepare"], "7001")
        self.assertIsNone(receipt["jobs"]["control_array"])
        self.assertIn("scancel 7001", self.ssh_log.read_text(encoding="ascii"))

    def test_ssh_loss_after_reservation_preserves_ambiguous_intent(self) -> None:
        completed = self.run_submitter(fail_stage="mkdir")
        self.assertEqual(completed.returncode, 255)
        receipt = self.receipt()
        self.assertEqual(receipt["status"], "submission_interrupted")
        self.assertTrue(receipt["submission_state_may_be_incomplete"])
        self.assertEqual(
            receipt["jobs"],
            {"prepare": None, "control_array": None, "audit": None},
        )


if __name__ == "__main__":
    unittest.main()
