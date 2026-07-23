from __future__ import annotations

import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "wmi" / "euf_viper_pgo_holdout.sbatch"
SUBMIT = ROOT / "scripts" / "wmi" / "submit_pgo_holdout.sh"
CONTRACT = ROOT / "campaigns" / "viper-pgo-goel-holdout-v1.json"


class WmiPgoHoldoutContractTests(unittest.TestCase):
    def test_machine_contract_matches_the_fixed_wrapper(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(contract["campaign_id"], "viper-pgo-goel-holdout-v1")
        self.assertIn(
            f"OFFICIAL_MANIFEST_SHA256={contract['corpus']['manifest_sha256']}",
            source,
        )
        self.assertIn(f"OFFICIAL_ROWS={contract['corpus']['manifest_rows']}", source)
        self.assertIn(f"TRAINING_ROWS={contract['split']['training_rows']}", source)
        self.assertIn(f"HOLDOUT_ROWS={contract['split']['holdout_rows']}", source)
        self.assertIn(
            f"MAX_TRAIN_PER_FAMILY={contract['split']['max_training_rows_per_family']}",
            source,
        )
        self.assertIn(
            f"MAX_TRAIN_SOURCE_BYTES={contract['split']['max_training_source_bytes']}",
            source,
        )
        self.assertIn(f"HOLDOUT_TIMEOUT_S={contract['measurement']['timeout_s']}", source)
        for key, value in contract["viper_environment"].items():
            self.assertEqual(source.count(f"{key}={value}"), 1)

    def test_script_is_valid_bash_and_default_off(self) -> None:
        syntax = subprocess.run(
            ["bash", "-n", str(SCRIPT)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        with tempfile.TemporaryDirectory(prefix="pgo sbatch off ") as temp:
            completed = subprocess.run(
                ["bash", str(SCRIPT)],
                cwd=temp,
                check=False,
                capture_output=True,
                text=True,
                env={"PATH": "/usr/bin:/bin"},
            )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("default-off", completed.stderr)

    def test_campaign_is_one_cpu_clean_revision_and_immutable_run_bound(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("#SBATCH --cpus-per-task=1", source)
        self.assertIn("requires exactly one allocated CPU", source)
        self.assertIn("git rev-parse --verify 'HEAD^{commit}'", source)
        self.assertIn("git status --porcelain=v1 --untracked-files=all", source)
        self.assertIn("pinned checkout must be completely clean", source)
        self.assertIn('mkdir "$RUN_ROOT" || die "fresh run root already exists', source)
        self.assertIn("ambient build override is forbidden", source)
        self.assertIn("RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_INCREMENTAL", source)
        self.assertNotIn("target-cpu=native", source)

    def test_split_is_size_bounded_and_goel_is_holdout_only(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            "OFFICIAL_MANIFEST_SHA256=ed00b0e2105ec9579b02448d161e7f04ceceaf816919535b48734c6525a2aaa6",
            source,
        )
        self.assertIn("TRAINING_ROWS=101", source)
        self.assertIn("HOLDOUT_ROWS=302", source)
        self.assertIn("--holdout-family 2018-Goel-hwbench", source)
        self.assertIn("--max-train-per-family \"$MAX_TRAIN_PER_FAMILY\"", source)
        self.assertIn(
            "--max-train-source-bytes \"$MAX_TRAIN_SOURCE_BYTES\"", source
        )
        self.assertIn("--rebase-root \"$CORPUS_ROOT\"", source)
        self.assertIn("Goel leaked into PGO training", source)

    def test_pgo_replays_unknowns_but_wrong_answers_still_abort(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("--allow-unknown-training", source)
        self.assertIn('summary["accounting"]["wrong_answers"]', source)
        self.assertIn('summary["accounting"]["execution_errors"]', source)
        self.assertIn('pgo["git"]["promotable"]', source)

    def test_accepted_viper_environment_is_shared_and_audited(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        settings = (
            "EUF_VIPER_FABRIC_DISEQUALITY_PROPAGATION=0",
            "EUF_VIPER_FABRIC_PROPAGATION_BATCH_UPDATES=4",
            "EUF_VIPER_FABRIC_LAZY_REASONS=1",
            "EUF_VIPER_FABRIC_INDEXED_CLASS_MEMBERS=1",
            "EUF_VIPER_FABRIC_PAIR_FILTERED_IMPACT=1",
            "EUF_VIPER_FABRIC_DEMAND_FLUSH=1",
            "EUF_VIPER_FABRIC_NARROW_MERGE_FRONTIER=1",
            "EUF_VIPER_FABRIC_SPARSE_ROOT=0",
            "EUF_VIPER_FABRIC_CONSTRUCTION_VALIDATION=0",
            "EUF_VIPER_FABRIC_ALLOCATION_FREE_ASSIGNMENTS=0",
        )
        for setting in settings:
            self.assertEqual(source.count(setting), 1)
        self.assertIn('PGO_SOLVER_ENV_ARGS+=(--solver-env "$setting")', source)
        self.assertIn('WILLIAMS_SOLVER_ENV_ARGS+=(--arm-env "$setting")', source)
        self.assertEqual(source.count('"${WILLIAMS_SOLVER_ENV_ARGS[@]}"'), 2)
        self.assertIn(
            'pgo["build_contract"]["solver_environment"] '
            "!= expected_viper_environment",
            source,
        )
        self.assertIn(
            'summary["environment_overrides"][arm] '
            "!= expected_viper_environment",
            source,
        )

    def test_toolchain_hashes_are_rechecked_and_embedded_after_timing(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        timing_end = source.index('--summary "$RESULTS_SUMMARY"')
        report_start = source.index('CAMPAIGN_REPORT="$ARTIFACTS/campaign.json"')
        post_timing = source[timing_end:report_start]
        for variable, label in (
            ("CARGO_BIN", "cargo"),
            ("RUSTC_BIN", "rustc"),
            ("LLVM_PROFDATA", "llvm-profdata"),
            ("PYTHON_BIN", "python"),
            ("Z3_BIN", "Z3"),
            ("YICES_BIN", "Yices2"),
            ("CVC5_BIN", "cvc5"),
        ):
            self.assertIn(f'check_tool "${variable}" "$', post_timing)
            self.assertIn(f'"{label}"', post_timing)
        for artifact_name in (
            "cargo_binary",
            "rustc_binary",
            "llvm_profdata_binary",
            "python_binary",
            "competitor_bundle_receipt",
        ):
            self.assertIn(f'"{artifact_name}": artifact(', source)
        self.assertIn('pgo["toolchain"][label]["sha256"]', source)

    def test_five_arm_williams_block_contains_all_required_competitors(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        arms = re.findall(r"^  --arm ([a-z0-9-]+) \\\s*$", source, re.MULTILINE)
        self.assertEqual(
            arms,
            ["viper-standard", "viper-pgo", "z3", "yices2", "cvc5"],
        )
        self.assertIn("--blocks 1", source)
        self.assertIn('HOLDOUT_TIMEOUT_S=2', source)
        self.assertIn('CAMPAIGN_REPORT="$ARTIFACTS/campaign.json"', source)
        self.assertLess(
            source.index('CAMPAIGN_REPORT="$ARTIFACTS/campaign.json"'),
            source.index("printf 'complete campaign="),
        )

    def test_frozen_pgo_adjudication_precedes_campaign_completion(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            'PGO_ADJUDICATOR="$ROOT/scripts/bench/adjudicate_pgo_holdout.py"',
            source,
        )
        self.assertIn('--expected-instances "$HOLDOUT_ROWS"', source)
        self.assertIn('PGO_DECISION="$ARTIFACTS/pgo-decision.json"', source)
        self.assertIn('"pgo_decision": decision["decision"]', source)
        self.assertIn('"pgo_decision": artifact(decision_raw)', source)
        self.assertIn(
            'decision["input"]["summary_sha256"] != summary_artifact["sha256"]',
            source,
        )
        self.assertLess(
            source.index('"$PYTHON_BIN" "$PGO_ADJUDICATOR"'),
            source.index('CAMPAIGN_REPORT="$ARTIFACTS/campaign.json"'),
        )


class WmiPgoSubmissionTests(unittest.TestCase):
    def test_submitter_is_macos_bash_compatible_and_default_off(self) -> None:
        syntax = subprocess.run(
            ["bash", "-n", str(SUBMIT)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        source = SUBMIT.read_text(encoding="utf-8")
        self.assertNotIn("mapfile", source)
        with tempfile.TemporaryDirectory(prefix="pgo submit off ") as temp:
            completed = subprocess.run(
                ["bash", str(SUBMIT)],
                cwd=temp,
                check=False,
                capture_output=True,
                text=True,
                env={"PATH": "/usr/bin:/bin"},
            )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("default-off", completed.stderr)

    def test_submitter_requires_clean_published_head_and_explicit_roots(self) -> None:
        source = SUBMIT.read_text(encoding="utf-8")
        self.assertIn("set EUF_VIPER_PGO_WORK_ROOT", source)
        self.assertIn("set EUF_VIPER_PGO_CORPUS_ROOT", source)
        self.assertIn("git status --porcelain=v1 --untracked-files=all", source)
        self.assertIn("git ls-remote --exit-code", source)
        self.assertIn("is not published at", source)
        self.assertIn("checkout --quiet --detach", source)

    def test_all_tool_hashes_are_bound_before_sbatch_and_receipted(self) -> None:
        source = SUBMIT.read_text(encoding="utf-8")
        self.assertIn("competitors-yices-2.7.0-cvc5-1.3.4", source)
        self.assertIn("yices-2.7.0/bin/yices-smt2", source)
        self.assertIn("cvc5-Linux-x86_64-static/bin/cvc5", source)
        self.assertIn("bin/llvm-profdata", source)
        for label in (
            "CARGO_SHA256",
            "RUSTC_SHA256",
            "PYTHON_SHA256",
            "LLVM_PROFDATA_SHA256",
            "Z3_SHA256",
            "YICES_SHA256",
            "CVC5_SHA256",
        ):
            self.assertIn(label, source)
            self.assertIn(f"{label}='$", source)
        self.assertIn("euf-viper.pgo-holdout-submission.v1", source)
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        frozen_hashes = {
            "EXPECTED_CARGO_SHA256": contract["wmi_tools"]["cargo_sha256"],
            "EXPECTED_RUSTC_SHA256": contract["wmi_tools"]["rustc_sha256"],
            "EXPECTED_LLVM_PROFDATA_SHA256": contract["wmi_tools"][
                "llvm_profdata_sha256"
            ],
            "EXPECTED_PYTHON_SHA256": contract["wmi_tools"]["python_sha256"],
            "EXPECTED_Z3_SHA256": contract["comparators"]["z3"][
                "wmi_binary_sha256"
            ],
            "EXPECTED_YICES_SHA256": contract["comparators"]["yices2"][
                "wmi_binary_sha256"
            ],
            "EXPECTED_CVC5_SHA256": contract["comparators"]["cvc5"][
                "wmi_binary_sha256"
            ],
        }
        for variable, digest in frozen_hashes.items():
            self.assertIn(f"{variable}={digest}", source)
            self.assertIn(f"${variable}", source)
        self.assertIn("does not match the frozen campaign hash", source)
        receipt_hash = contract["comparators"]["bundle_receipt_sha256"]
        self.assertIn(f"EXPECTED_COMPETITOR_RECEIPT_SHA256={receipt_hash}", source)
        self.assertIn("EUF_VIPER_PGO_COMPETITOR_RECEIPT=", source)
        self.assertIn("competitor_bundle_receipt", source)
        self.assertLess(
            source.index('submission receipt already exists: $RECEIPT'),
            source.index('SBATCH_OUTPUT="$(ssh'),
        )


if __name__ == "__main__":
    unittest.main()
