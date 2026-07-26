from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = ROOT / "scripts" / "helios" / "preflight.sh"
TOOLCHAIN = ROOT / "scripts" / "helios" / "toolchain_receipt.sh"
CORPUS = ROOT / "scripts" / "helios" / "corpus_snapshot.py"
SYNC_CORPUS = ROOT / "scripts" / "helios" / "sync_corpus.sh"
SUBMIT = ROOT / "scripts" / "helios" / "sync_and_submit.sh"
INSTALL_COMPETITORS = ROOT / "scripts" / "helios" / "install_competitors.sh"
TASK = ROOT / "scripts" / "helios" / "run_campaign_task.sh"
RESOURCE_WRAPPER = ROOT / "scripts" / "helios" / "run_with_resources.py"
PREPARE_LOCK = ROOT / "scripts" / "helios" / "prepare_campaign_lock.py"
SBATCH = ROOT / "slurm" / "helios" / "euf_viper_campaign.sbatch"

SHELL_FILES = (
    PREFLIGHT,
    TOOLCHAIN,
    SYNC_CORPUS,
    SUBMIT,
    INSTALL_COMPETITORS,
    TASK,
    SBATCH,
)
CANDIDATE_ARGV = [
    "{binary}",
    "fabric-solve",
    "--engine",
    "quotient-portfolio",
    "{instance}",
]
SOLVER_REVISION = "8368d21de96eec77f3bb5f6820c11d1363d3041b"


class HeliosShellContractTests(unittest.TestCase):
    def test_all_shell_entrypoints_have_valid_bash_syntax(self) -> None:
        for path in SHELL_FILES:
            with self.subTest(path=path):
                completed = subprocess.run(
                    ["bash", "-n", str(path)],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_preflight_remote_script_is_not_locally_expanded(self) -> None:
        preflight = PREFLIGHT.read_text(encoding="utf-8")
        submit = SUBMIT.read_text(encoding="utf-8")
        corpus = SYNC_CORPUS.read_text(encoding="utf-8")
        self.assertIn("remote_facts() {", preflight)
        self.assertIn('REMOTE_FACTS="$(remote_facts)"', preflight)
        self.assertIn("solver_report() {", submit)
        self.assertIn('SOLVER_REPORT="$(solver_report)"', submit)
        self.assertIn("remote_manifest_sha256() {", corpus)
        self.assertIn('REMOTE_MANIFEST_SHA256="$(remote_manifest_sha256)"', corpus)
        for source in (preflight, submit, corpus):
            self.assertNotIn('="$(ssh ', source)

    def test_live_helios_defaults_and_cpu_account_are_exact(self) -> None:
        preflight = PREFLIGHT.read_text(encoding="utf-8")
        batch = SBATCH.read_text(encoding="utf-8")
        self.assertIn('SSH_TARGET="${EUF_VIPER_HELIOS_SSH_TARGET:-helios}"', preflight)
        self.assertIn('EXPECTED_USER="${EUF_VIPER_HELIOS_USER:-plgnasqret}"', preflight)
        self.assertIn('GRANT="${EUF_VIPER_HELIOS_GRANT:-plgccaiautore2026}"', preflight)
        self.assertIn(
            'ACCOUNT="${EUF_VIPER_HELIOS_ACCOUNT:-plgccaiautore2026-cpu}"',
            preflight,
        )
        self.assertIn("/net/scratch/hscra/plgrid/plgnasqret", preflight)
        self.assertIn(
            r"$SCRATCH/codex-control/projects/euf-viper", preflight
        )
        self.assertIn("#SBATCH --account=plgccaiautore2026-cpu", batch)
        self.assertIn("#SBATCH --partition=plgrid", batch)

    def test_preflight_repairs_only_owned_mutable_namespaces(self) -> None:
        source = PREFLIGHT.read_text(encoding="utf-8")
        self.assertIn('test -O "$root"', source)
        self.assertIn('chmod u+rwx "$root"', source)
        self.assertIn("orchestration-checkouts", source)
        self.assertIn("solver-checkouts", source)
        self.assertIn('test ! -L "$path"', source)
        self.assertIn('chmod u+rwx "$path"', source)
        self.assertIn("content-addressed children are sealed", source)
        self.assertNotIn('chmod -R u+w "$root"', source)

    def test_exact_rust_stack_architecture_and_llvm_are_rechecked(self) -> None:
        toolchain = TOOLCHAIN.read_text(encoding="utf-8")
        task = TASK.read_text(encoding="utf-8")
        batch = SBATCH.read_text(encoding="utf-8")
        for source in (toolchain, task, batch):
            self.assertIn("module load GCCcore/14.3.0 Rust/1.88.0", source)
        self.assertIn("release: 1.88.0", toolchain)
        self.assertIn("host: x86_64-unknown-linux-gnu", toolchain)
        self.assertIn("LLVM version: 20.1.5", toolchain)
        self.assertIn('"$(uname -m)" = x86_64', toolchain)
        self.assertIn("module --redirect --location show", toolchain)
        self.assertIn("hash_file \"$location\"", toolchain)
        self.assertIn('done <<EOF\n$RUST_MODULE_GCC\n$RUST_MODULE\nEOF', toolchain)
        self.assertIn('gcc -print-file-name=include', toolchain)
        self.assertIn("header\\tstdbool.h", toolchain)
        self.assertIn("gcc:gcc", toolchain)
        self.assertIn('BINDGEN_EXTRA_CLANG_ARGS="-isystem $GCC_INTERNAL_INCLUDE"', task)

    def test_sync_requires_a_clean_exact_revision_and_uses_rsync(self) -> None:
        source = SUBMIT.read_text(encoding="utf-8")
        self.assertIn("git status --porcelain=v1 --untracked-files=all", source)
        self.assertIn("git rev-parse --verify 'HEAD^{commit}'", source)
        self.assertIn(
            "git clone --quiet --filter=blob:none --no-checkout --no-local", source
        )
        self.assertIn("sparse-checkout set campaigns scripts slurm", source)
        self.assertIn("sparse-checkout set src vendor", source)
        self.assertIn("checkout --quiet --detach", source)
        self.assertIn("rsync -az --delete", source)
        self.assertIn('mv -T "$INCOMING" "$REMOTE_CHECKOUT"', source)
        self.assertIn('chmod -R a-w "$REMOTE_CHECKOUT"', source)
        self.assertLess(
            source.index('mv -T "$INCOMING" "$REMOTE_CHECKOUT"'),
            source.rindex('chmod -R a-w "$REMOTE_CHECKOUT"'),
        )

    def test_submit_uses_split_checkout_and_revision_names_everywhere(self) -> None:
        source = SUBMIT.read_text(encoding="utf-8")
        stale = re.compile(
            r"\$(?:CHECKOUT|REVISION)\b|\$\{(?:CHECKOUT|REVISION)(?=[:}])"
        )
        self.assertIsNone(stale.search(source))
        for name in (
            "EUF_VIPER_HELIOS_ORCHESTRATION_CHECKOUT",
            "EUF_VIPER_HELIOS_SOLVER_CHECKOUT",
            "EUF_VIPER_HELIOS_ORCHESTRATION_REVISION",
            "EUF_VIPER_HELIOS_SOLVER_REVISION",
            "remote_orchestration_checkout",
            "remote_solver_checkout",
            "orchestration_revision",
            "solver_revision",
        ):
            self.assertIn(name, source)

    def test_corpus_is_separate_content_addressed_and_rebased(self) -> None:
        source = SYNC_CORPUS.read_text(encoding="utf-8")
        self.assertIn("/Users/airbartek/codex/z3/benchmarks", source)
        self.assertIn("corpora/$INVENTORY_SHA256", source)
        self.assertIn("manifest-sources/$MANIFEST_SOURCE_SHA256", source)
        self.assertIn("rebase-manifest", source)
        self.assertIn("verify-rebased-manifest", source)
        self.assertIn("--exclude=.DS_Store", source)
        self.assertIn('mv -T "$REMOTE_INCOMING" "$REMOTE_CORPUS"', source)
        self.assertIn('chmod -R a-w "$REMOTE_CORPUS"', source)
        self.assertLess(
            source.index('mv -T "$REMOTE_INCOMING" "$REMOTE_CORPUS"'),
            source.index('chmod -R a-w "$REMOTE_CORPUS"'),
        )

    def test_submission_is_test_only_unless_submit_is_explicit(self) -> None:
        source = SUBMIT.read_text(encoding="utf-8")
        self.assertIn("MODE=test-only", source)
        self.assertIn("TEST_ONLY_OUTPUT=\"$(remote_sbatch test-only)\"", source)
        self.assertIn("sbatch --test-only", source)
        self.assertIn("sbatch --parsable", source)
        self.assertLess(
            source.index("TEST_ONLY_OUTPUT=\"$(remote_sbatch test-only)\""),
            source.index("SBATCH_OUTPUT=\"$(remote_sbatch submit)\""),
        )
        completed = subprocess.run(
            ["bash", str(SUBMIT)],
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": os.environ.get("PATH", "")},
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("--manifest is required", completed.stderr)

    def test_one_cpu_binding_and_resource_wrapper_wrap_the_frozen_runner(self) -> None:
        batch = SBATCH.read_text(encoding="utf-8")
        task = TASK.read_text(encoding="utf-8")
        self.assertIn("#SBATCH --ntasks=1", batch)
        self.assertIn("#SBATCH --cpus-per-task=1", batch)
        self.assertIn("#SBATCH --hint=nomultithread", batch)
        self.assertIn("--cpu-bind=cores", batch)
        self.assertIn("len(os.sched_getaffinity(0))", task)
        self.assertIn("scripts/bench/bind_campaign_cpu.py", task)
        self.assertIn("scripts/bench/run_locked_campaign.py", task)
        self.assertIn("scripts/helios/run_with_resources.py", task)
        self.assertIn("resource-usage.json", task)
        self.assertNotIn("/usr/bin/time", task)
        self.assertIn("AMD EPYC 9654", task)
        self.assertNotIn("print $2; exit", task)
        self.assertNotIn("NF {print; exit}", PREFLIGHT.read_text(encoding="utf-8"))
        self.assertIn(
            '/bin/bash -l "$ORCHESTRATION_CHECKOUT/scripts/helios/run_campaign_task.sh"',
            batch,
        )

    def test_candidate_argv_is_exact_and_recorded_before_freezing(self) -> None:
        task = TASK.read_text(encoding="utf-8")
        preparer = PREPARE_LOCK.read_text(encoding="utf-8")
        required_tokens = (
            "--viper-arg '{binary}'",
            "--viper-arg fabric-solve",
            "--viper-arg=--engine",
            "--viper-arg quotient-portfolio",
            "--viper-arg '{instance}'",
            "--viper-configuration quotient-portfolio",
        )
        for token in required_tokens:
            self.assertIn(token, task)
        self.assertIn("record_solver_config.py", task)
        self.assertIn("prepare_campaign_lock.py", task)
        self.assertIn("freeze_campaign as freezer", preparer)
        self.assertIn('CANDIDATE_CONFIGURATION = "quotient-portfolio"', preparer)
        self.assertNotIn("compatibility_config", preparer)
        self.assertNotIn('candidate["configuration"] =', preparer)
        self.assertNotIn('lock["lock_sha256"] =', preparer)
        self.assertNotIn('"solve", "{instance}"', task)
        self.assertIn('--z3-env "LD_LIBRARY_PATH=$Z3_LIBRARY_PATH"', task)

    def test_comparator_bundle_is_hash_locked_and_executed(self) -> None:
        installer = INSTALL_COMPETITORS.read_text(encoding="utf-8")
        submit = SUBMIT.read_text(encoding="utf-8")
        task = TASK.read_text(encoding="utf-8")
        for source in (installer, submit, task):
            self.assertIn("verify_competitor_bundle.py", source)
            self.assertIn("--execute", source)
        self.assertIn("solver-bundles/$RECEIPT_SHA256", installer)
        self.assertIn("comparator_bundle_receipt_sha256", submit)
        self.assertIn("comparator_bundle_receipt_sha256", task)

    def test_comparator_tsv_parser_uses_path_and_sha256_columns(self) -> None:
        source = SUBMIT.read_text(encoding="utf-8")
        for binding in (
            'Z3_BIN="$(solver_value z3 3)"; Z3_SHA256="$(solver_value z3 4)"',
            'CVC5_BIN="$(solver_value cvc5 3)"; CVC5_SHA256="$(solver_value cvc5 4)"',
            'YICES_BIN="$(solver_value yices2 3)"; YICES_SHA256="$(solver_value yices2 4)"',
            'OPENSMT_BIN="$(solver_value opensmt 3)"; OPENSMT_SHA256="$(solver_value opensmt 4)"',
        ):
            self.assertIn(binding, source)

    def test_taxonomy_and_split_provenance_are_required(self) -> None:
        task = TASK.read_text(encoding="utf-8")
        preparer = PREPARE_LOCK.read_text(encoding="utf-8")
        self.assertIn("build_family_manifest.py", task)
        self.assertIn('--taxonomy "$TAXONOMY"', task)
        self.assertIn('parser.add_argument("--taxonomy", type=Path, required=True)', preparer)
        self.assertIn('lock["promotion_eligible"] is not True', preparer)
        self.assertIn('lock["corpus"]["taxonomy_sha256"]', preparer)

    def test_solver_and_orchestration_provenance_are_separate(self) -> None:
        submit = SUBMIT.read_text(encoding="utf-8")
        task = TASK.read_text(encoding="utf-8")
        batch = SBATCH.read_text(encoding="utf-8")
        for source in (submit, task):
            self.assertIn(SOLVER_REVISION, source)
        self.assertIn('$SOLVER_CHECKOUT/Cargo.toml', task)
        self.assertIn('--repository "$ORCHESTRATION_CHECKOUT"', task)
        self.assertIn(
            '"$ORCHESTRATION_CHECKOUT/scripts/helios/prepare_campaign_lock.py"',
            task,
        )
        for source in (submit, task, batch):
            self.assertIn("orchestration_revision", source)
            self.assertIn("solver_revision", source)

    def test_receipts_bind_modules_tools_inputs_and_candidate_command(self) -> None:
        submit = SUBMIT.read_text(encoding="utf-8")
        batch = SBATCH.read_text(encoding="utf-8")
        for field in (
            "toolchain_sha256",
            "gcc_module_sha256",
            "rust_module_sha256",
            "cargo_sha256",
            "rustc_sha256",
            "python_sha256",
            "resource_wrapper_sha256",
            "corpus_inventory_sha256",
            "manifest_sha256",
            "candidate_argv_json",
            "candidate_argv_sha256",
        ):
            self.assertIn(field, submit)
            self.assertIn(field, batch)
        self.assertIn("resource_capture_sha256", batch)
        for source in (submit, batch):
            self.assertIn("chmod 0444", source)
        self.assertIn('ln "$TEMPORARY_RECEIPT" "$RECEIPT"', submit)
        self.assertIn('ln "$temporary_receipt" "$receipt"', batch)

    def test_layer_has_no_accelerator_or_identity_based_dispatch(self) -> None:
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (SUBMIT, TASK, PREPARE_LOCK, SBATCH)
        ).lower()
        for forbidden in (
            "--gres",
            "--gpus",
            "cuda",
            "nvidia",
            "source_family",
            "benchmark_id",
            "train_binary_router",
            "train_structural_router",
        ):
            self.assertNotIn(forbidden, source)


class ResourceWrapperTests(unittest.TestCase):
    def test_records_child_resources_and_makes_the_record_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "usage.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(RESOURCE_WRAPPER),
                    "--out",
                    str(output),
                    "--",
                    sys.executable,
                    "-c",
                    "sum(range(10000))",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["schema_version"], "euf-viper.helios-resource-usage.v1"
            )
            self.assertEqual(payload["return_code"], 0)
            self.assertGreater(payload["wall_time_s"], 0)
            self.assertGreater(payload["max_rss_kib"], 0)
            self.assertGreaterEqual(payload["user_time_s"], 0)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o444)

    def test_preserves_failure_and_refuses_to_replace_a_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "usage.json"
            command = [
                sys.executable,
                str(RESOURCE_WRAPPER),
                "--out",
                str(output),
                "--",
                sys.executable,
                "-c",
                "raise SystemExit(7)",
            ]
            first = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(first.returncode, 7, first.stderr)
            self.assertEqual(json.loads(output.read_text())["return_code"], 7)
            second = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(second.returncode, 2)
            self.assertIn("refuse to replace resource record", second.stderr)


class CorpusSnapshotTests(unittest.TestCase):
    def test_absolute_manifest_paths_are_rebased_and_verified(self) -> None:
        with tempfile.TemporaryDirectory(prefix="helios corpus ") as temporary:
            root = Path(temporary) / "benchmarks"
            instance_root = root / "smtlib-2025" / "QF_UF"
            instance = instance_root / "QF_UF" / "sample" / "case.smt2"
            instance.parent.mkdir(parents=True)
            payload = b"(set-logic QF_UF)\n(check-sat)\n"
            instance.write_bytes(payload)
            manifest = Path(temporary) / "manifest.jsonl"
            row = {
                "bytes": len(payload),
                "id": 0,
                "path": "/Users/example/benchmarks/QF_UF/sample/case.smt2",
                "relative_path": "QF_UF/sample/case.smt2",
                "sha256": hashlib.sha256(payload).hexdigest(),
                "status": "sat",
            }
            manifest.write_text(json.dumps(row) + "\n", encoding="utf-8")
            inventory = Path(temporary) / "inventory.jsonl"
            rebased = Path(temporary) / "rebased.jsonl"

            for arguments in (
                ["inventory", "--root", str(root), "--out", str(inventory)],
                ["verify", "--root", str(root), "--inventory", str(inventory)],
                [
                    "rebase-manifest",
                    "--manifest",
                    str(manifest),
                    "--instance-root",
                    str(instance_root),
                    "--out",
                    str(rebased),
                ],
                [
                    "verify-rebased-manifest",
                    "--manifest",
                    str(manifest),
                    "--instance-root",
                    str(instance_root),
                    "--rebased",
                    str(rebased),
                ],
            ):
                completed = subprocess.run(
                    ["python3", str(CORPUS), *arguments],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

            rewritten = json.loads(rebased.read_text(encoding="ascii"))
            self.assertEqual(rewritten["path"], str(instance.resolve()))
            self.assertEqual(rewritten["relative_path"], row["relative_path"])


class CampaignLockSmokeTests(unittest.TestCase):
    def test_exact_config_taxonomy_and_split_revisions_freeze_directly(self) -> None:
        with tempfile.TemporaryDirectory(prefix="helios-lock-smoke-") as temporary:
            root = Path(temporary)
            repository = root / "orchestration"
            campaigns = repository / "campaigns"
            campaigns.mkdir(parents=True)
            campaign = campaigns / "best-overall-qf-uf-2026-07.json"
            release_lock = campaigns / "solver-releases-2026-07.json"
            campaign_payload = json.loads(
                (ROOT / "campaigns" / campaign.name).read_text(encoding="utf-8")
            )
            bound_manifest = campaigns / "fixture-official.jsonl"
            bound_manifest.write_text("{}\n", encoding="utf-8")
            for corpus_record in campaign_payload["corpora"]:
                if corpus_record["id"] == "smtcomp-2025-qf-uf":
                    corpus_record["manifest"] = "campaigns/fixture-official.jsonl"
                    corpus_record["manifest_sha256"] = hashlib.sha256(
                        bound_manifest.read_bytes()
                    ).hexdigest()
            campaign.write_text(
                json.dumps(campaign_payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            release_lock.write_bytes(
                (ROOT / "campaigns" / release_lock.name).read_bytes()
            )
            for arguments in (
                ("init", "--quiet"),
                ("config", "user.name", "Helios Test"),
                ("config", "user.email", "helios-test@example.invalid"),
                ("add", "campaigns"),
                ("commit", "--quiet", "-m", "clean orchestration fixture"),
            ):
                subprocess.run(
                    ["git", "-C", str(repository), *arguments],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            orchestration_revision = subprocess.run(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            self.assertNotEqual(orchestration_revision, SOLVER_REVISION)

            corpus = root / "corpus"
            instance = corpus / "family" / "case.smt2"
            instance.parent.mkdir(parents=True)
            instance.write_text(
                "(set-logic QF_UF)\n(declare-sort U 0)\n"
                "(declare-const x U)\n(assert (= x x))\n(check-sat)\n",
                encoding="utf-8",
            )
            instance_sha256 = hashlib.sha256(instance.read_bytes()).hexdigest()
            manifest = root / "manifest.jsonl"
            manifest.write_text(
                json.dumps(
                    {
                        "bytes": instance.stat().st_size,
                        "id": 7,
                        "path": str(instance),
                        "relative_path": "family/case.smt2",
                        "sha256": instance_sha256,
                        "status": "sat",
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            taxonomy = root / "taxonomy.jsonl"
            taxonomy.write_text(
                json.dumps(
                    {
                        "family": "family",
                        "lineage": "family/example",
                        "normalized_sha256": "1" * 64,
                        "relative_path": "family/case.smt2",
                        "split": "holdout",
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            binary = root / "fake-solver"
            binary.write_text(
                "#!/bin/sh\n"
                "if [ \"${1:-}\" = --version ]; then\n"
                "  echo 'euf-viper fake-solver'\n"
                "else\n"
                "  echo sat\n"
                "fi\n",
                encoding="utf-8",
            )
            binary.chmod(0o755)
            binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
            definitions = (
                (
                    "euf-viper",
                    "euf-viper",
                    "quotient-portfolio",
                    f"0.1.0+{SOLVER_REVISION}.quotient-portfolio",
                    CANDIDATE_ARGV,
                ),
                ("z3-default", "z3", "default", "4.16.0", ["{binary}", "{instance}"]),
                (
                    "z3-sat-euf",
                    "z3",
                    "sat.euf=true",
                    "4.16.0",
                    ["{binary}", "sat.euf=true", "{instance}"],
                ),
                ("cvc5", "cvc5", "default", "1.3.4", ["{binary}", "{instance}"]),
                ("yices2", "yices2", "default", "2.7.0", ["{binary}", "{instance}"]),
                ("opensmt", "opensmt", "default", "2.9.2", ["{binary}", "{instance}"]),
            )
            solver_config = root / "solver-config.json"
            solver_config.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "solvers": [
                            {
                                "argv_template": argv,
                                "binary": str(binary),
                                "comparator_id": comparator,
                                "configuration": configuration,
                                "environment": {},
                                "id": identifier,
                                "sha256": binary_sha256,
                                "version": version,
                                "version_argv": ["--version"],
                                "version_output_contains": "fake-solver",
                            }
                            for identifier, comparator, configuration, version, argv
                            in definitions
                        ],
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            lock_path = root / "campaign-lock.json"
            completed = subprocess.run(
                [
                    "python3",
                    str(PREPARE_LOCK),
                    "--spec",
                    str(campaign),
                    "--manifest",
                    str(manifest),
                    "--taxonomy",
                    str(taxonomy),
                    "--solver-config",
                    str(solver_config),
                    "--repository",
                    str(repository),
                    "--corpus-root",
                    str(corpus),
                    "--solver-revision",
                    SOLVER_REVISION,
                    "--orchestration-revision",
                    orchestration_revision,
                    "--budget",
                    "2",
                    "--memory-bytes",
                    "1073741824",
                    "--output-directory",
                    str(root / "output"),
                    "--out",
                    str(lock_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            lock = json.loads(lock_path.read_text(encoding="utf-8"))
            self.assertIs(lock["promotion_eligible"], True)
            self.assertEqual(
                lock["corpus"]["taxonomy_sha256"],
                hashlib.sha256(taxonomy.read_bytes()).hexdigest(),
            )
            self.assertEqual(lock["repository"]["commit"], orchestration_revision)
            candidate = next(
                record for record in lock["solvers"] if record["id"] == "euf-viper"
            )
            self.assertEqual(candidate["configuration"], "quotient-portfolio")
            self.assertEqual(candidate["argv_template"], CANDIDATE_ARGV)
            self.assertEqual(candidate["sha256"], binary_sha256)
            self.assertIn(SOLVER_REVISION, candidate["version"])


if __name__ == "__main__":
    unittest.main()
