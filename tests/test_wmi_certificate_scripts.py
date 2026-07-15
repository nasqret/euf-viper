from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WMI = ROOT / "scripts" / "wmi"
P0_PREPARE = WMI / "euf_viper_locked_prepare.sbatch"
SBATCH_FILES = [
    WMI / "euf_viper_certificate_prepare.sbatch",
    WMI / "euf_viper_certificate_shard.sbatch",
    WMI / "euf_viper_certificate_audit.sbatch",
    WMI / "euf_viper_certificate_staged_audit.sbatch",
]
SUBMIT = WMI / "submit_certificate_shadow.sh"
STAGED_SUBMIT = WMI / "submit_staged_certificate_audit.sh"
ALL_SCRIPTS = [*SBATCH_FILES, SUBMIT, STAGED_SUBMIT]


class WmiCertificateScriptTests(unittest.TestCase):
    def text(self, path: Path) -> str:
        return path.read_text(encoding="ascii")

    def test_shell_syntax(self) -> None:
        completed = subprocess.run(
            ["bash", "-n", *(str(path) for path in ALL_SCRIPTS)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_p0_times_the_same_binary_that_emits_certificates(self) -> None:
        text = self.text(P0_PREPARE)
        build = "cargo build --release --features certificates"
        self.assertIn(build, text)
        self.assertIn("target/release/euf-viper", text)
        self.assertLess(text.index(build), text.index("record_solver_config.py"))
        self.assertIn(".certificates", text)

    def test_embedded_python_blocks_compile(self) -> None:
        pattern = re.compile(
            r"<<'(?P<marker>PY_[A-Z0-9_]+)'\n(?P<body>.*?)\n(?P=marker)$",
            re.MULTILINE | re.DOTALL,
        )
        blocks = []
        for path in ALL_SCRIPTS:
            for match in pattern.finditer(self.text(path)):
                blocks.append((path, match.group("body")))
        self.assertGreaterEqual(len(blocks), 3)
        for path, body in blocks:
            compile(body, f"{path}:embedded-python", "exec")

    def test_every_slurm_stage_is_one_core_and_clean_revision_bound(self) -> None:
        for path in SBATCH_FILES:
            text = self.text(path)
            self.assertIn("#SBATCH --ntasks=1", text)
            self.assertIn("#SBATCH --cpus-per-task=1", text)
            self.assertIn("SLURM_CPUS_PER_TASK", text)
            self.assertIn("git rev-parse HEAD", text)
            self.assertIn(
                "git status --porcelain=v1 --untracked-files=all", text
            )

    def test_prepare_revalidates_complete_base_and_freezes_zero_work_shards(self) -> None:
        text = self.text(WMI / "euf_viper_certificate_prepare.sbatch")
        self.assertIn("discover_shard_pairs", text)
        self.assertIn("load_sharded_locked_campaign", text)
        self.assertIn("selected_instances\": len(works)", text)
        self.assertNotIn("has no selected certificate work", text)
        self.assertIn('base_lock["budgets_s"]] != [expected_budget_s]', text)
        self.assertIn('"scope": "single_physical_stage_certificate_coverage_only"', text)
        self.assertIn("checker SHA-256 mismatch", text)
        self.assertIn("drat-trim SHA-256 mismatch", text)
        self.assertIn("validate_independent_parser_workset", text)
        self.assertIn('"parser_canary": parser_canary', text)
        self.assertIn("independent parser canary selection cardinality mismatch", text)

    def test_array_uses_runner_and_auditor_layout_for_every_source_shard(self) -> None:
        text = self.text(WMI / "euf_viper_certificate_shard.sbatch")
        self.assertIn("scripts/cert/shadow_campaign.py", text)
        self.assertIn('source-shard-$PADDED', text)
        self.assertIn("--shard-index 0", text)
        self.assertIn("--shard-count 1", text)
        self.assertIn('record["selected_instances"] < 0', text)
        self.assertNotIn("selected_instances\", 0) < 1", text)
        self.assertNotIn("--journal", text)
        self.assertNotIn("--summary", text)

    def test_final_stage_delegates_strict_global_audit(self) -> None:
        text = self.text(WMI / "euf_viper_certificate_audit.sbatch")
        self.assertIn("scripts/cert/audit_shadow_campaign.py", text)
        self.assertIn('--shadow-output-root "$RUN_ROOT/shards"', text)
        self.assertIn('--out "$RUN_ROOT/$STAGE_LABEL-audit.json"', text)
        self.assertIn("ACTUAL_CHECKER_SHA256", text)
        self.assertIn("ACTUAL_DRAT_TRIM_SHA256", text)
        self.assertNotIn("validate_journal_attempts", text)
        self.assertNotIn("verified_instances", text)

    def test_submitter_pins_public_clean_revision_and_afterok_chain(self) -> None:
        text = self.text(SUBMIT)
        self.assertIn("git ls-remote --exit-code", text)
        self.assertIn("git status --porcelain=v1 --untracked-files=no", text)
        self.assertIn("EUF_VIPER_CERT_REVISION", text)
        self.assertIn("git merge-base --is-ancestor", text)
        self.assertIn('SHORT_REVISION="${REVISION:0:12}"', text)
        self.assertIn('"submitter_revision": submitter_revision', text)
        self.assertIn("EUF_VIPER_CERT_DRAT_TRIM_SHA256", text)
        self.assertIn("EUF_VIPER_CERT_CHECKER_SHA256", text)
        self.assertIn("--kill-on-invalid-dep=yes", text)
        self.assertIn('PREPARE_DEPENDENCY_OPTION=""', text)
        self.assertIn(
            'PREPARE_DEPENDENCY_OPTION="--dependency=afterok:$BASE_DEPENDENCY_JOB"',
            text,
        )
        self.assertNotIn("PREPARE_DEPENDENCY=()", text)
        self.assertNotIn("${PREPARE_DEPENDENCY[*]}", text)
        self.assertGreaterEqual(text.count("afterok:"), 3)
        self.assertNotIn("afterany:", text)
        self.assertIn("abort_partial_chain", text)
        self.assertIn("submission receipt already exists for run ID", text)
        self.assertIn("test ! -e '$RUN_ROOT'", text)
        self.assertIn('write_receipt "submission_intent"', text)
        self.assertIn('write_receipt "submitting"', text)
        self.assertIn('write_receipt "submitted"', text)
        self.assertIn('"submission_state_may_be_incomplete"', text)
        self.assertLess(
            text.index('write_receipt "submission_intent"'),
            text.index('PREPARE_SUBMISSION="'),
        )
        self.assertIn('"scope": "single_physical_stage_certificate_coverage_only"', text)
        self.assertIn('"performance_claims": []', text)

    def test_staged_join_binds_physical_audits_to_final_analysis(self) -> None:
        batch = self.text(WMI / "euf_viper_certificate_staged_audit.sbatch")
        submit = self.text(STAGED_SUBMIT)
        self.assertIn("audit_staged_shadow_campaign.py", batch)
        self.assertIn("--stage-audit", batch)
        self.assertIn("EUF_VIPER_CERT_STAGED_ANALYSIS", batch)
        self.assertIn("--dependency='afterok:$DEPENDENCY_JOBS'", submit)
        self.assertIn("git ls-remote --exit-code origin refs/heads/main", submit)
        self.assertIn(
            '"scope": "staged_physical_origin_certificate_union"', submit
        )


if __name__ == "__main__":
    unittest.main()
