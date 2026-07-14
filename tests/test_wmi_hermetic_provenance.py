from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts" / "wmi" / "hermetic_provenance.py"
SPEC = importlib.util.spec_from_file_location("hermetic_provenance_test", HELPER_PATH)
assert SPEC is not None and SPEC.loader is not None
PROVENANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVENANCE)
TEMPORARY_DIRECTORY = "/private/tmp" if sys.platform == "darwin" else None


class WmiHermeticProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=TEMPORARY_DIRECTORY)
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, repository: Path, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=True,
            text=True,
            capture_output=True,
        )
        return completed.stdout.strip()

    def make_repository(self, name: str) -> tuple[Path, Path, str, Path]:
        attempt = self.root / name
        attempt.mkdir(mode=0o700)
        checkout = attempt / "checkout"
        checkout.mkdir()
        self.git(checkout, "init", "--quiet")
        self.git(checkout, "config", "user.name", "Provenance Test")
        self.git(checkout, "config", "user.email", "provenance@example.invalid")
        helper = checkout / "scripts" / "wmi" / "hermetic_provenance.py"
        helper.parent.mkdir(parents=True)
        shutil.copyfile(HELPER_PATH, helper)
        tracked = checkout / "tracked.txt"
        tracked.write_text("bound source\n", encoding="ascii")
        self.git(checkout, "add", ".")
        self.git(checkout, "commit", "--quiet", "-m", "fixture")
        revision = self.git(checkout, "rev-parse", "HEAD")
        fake_tool = attempt / "bound-tool"
        fake_tool.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        fake_tool.chmod(0o755)
        return attempt, checkout, revision, fake_tool

    def create_args(
        self, attempt: Path, checkout: Path, revision: str, fake_tool: Path
    ) -> argparse.Namespace:
        git = shutil.which("git")
        assert git is not None
        tools = [
            f"{name}={git if name == 'git' else fake_tool}"
            for name in sorted(PROVENANCE.REQUIRED_RUNTIME_TOOLS)
        ]
        execution = {
            "CARGO_TARGET_DIR": str(attempt / "build"),
            "HOME": str(attempt / "home"),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "PYTHON_FLAGS": "-B -I -S",
            "RUSTUP_HOME": str(attempt / "rustup"),
            "TMPDIR": str(attempt / "tmp"),
            "TZ": "UTC",
            "XDG_CACHE_HOME": str(attempt / "cache"),
            "XDG_CONFIG_HOME": str(attempt / "config"),
        }
        return argparse.Namespace(
            attempt_id="0123456789abcdef0123456789abcdef",
            attempt_root=attempt,
            checkout=checkout,
            revision=revision,
            tool=tools,
            execution_env=[f"{key}={value}" for key, value in execution.items()],
            parameter=["shared_corpus=/srv/corpus", "shards=4"],
            out=attempt / "submission-provenance.json",
        )

    def verification_environment(
        self, args: argparse.Namespace, summary: dict[str, object], stage: str
    ) -> dict[str, str]:
        tools = summary["runtime_tools"]
        assert isinstance(tools, dict)
        python = tools["python"]
        sha256sum = tools["sha256sum"]
        assert isinstance(python, dict) and isinstance(sha256sum, dict)
        environment = {
            "EUF_VIPER_ATTEMPT_ID": args.attempt_id,
            "EUF_VIPER_ATTEMPT_ROOT": str(args.attempt_root.resolve()),
            "EUF_VIPER_CHECKOUT": str(args.checkout.resolve()),
            "EUF_VIPER_EXPECTED_REVISION": args.revision,
            "EUF_VIPER_PYTHON": str(python["path"]),
            "EUF_VIPER_PYTHON_SHA256": str(python["sha256"]),
            "EUF_VIPER_PROVENANCE_HELPER_SHA256": str(
                summary["provenance_helper_sha256"]
            ),
            "EUF_VIPER_SHA256SUM": str(sha256sum["path"]),
            "EUF_VIPER_SUBMISSION_MANIFEST": str(args.out.resolve()),
            "EUF_VIPER_SUBMISSION_MANIFEST_SHA256": str(
                summary["manifest_sha256"]
            ),
        }
        environment.update(
            {
                "prepare": {
                    "EUF_VIPER_LOCKED_SHARDS": "4",
                    "EUF_VIPER_SHARED_CORPUS": "/srv/corpus",
                },
                "shard": {
                    "EUF_VIPER_CORPUS_KIND": "full",
                    "EUF_VIPER_PREPARE_JOB_ID": "123",
                },
                "audit": {
                    "EUF_VIPER_LOCKED_SHARDS": "4",
                    "EUF_VIPER_PREPARE_JOB_ID": "123",
                },
            }[stage]
        )
        return environment

    def test_clean_attempt_round_trip_binds_every_source_and_runtime(self) -> None:
        attempt, checkout, revision, fake_tool = self.make_repository("clean")
        args = self.create_args(attempt, checkout, revision, fake_tool)
        summary = PROVENANCE.create_manifest(args)
        verify_args = argparse.Namespace(
            manifest=args.out,
            expected_sha256=summary["manifest_sha256"],
            stage="prepare",
        )
        environment = self.verification_environment(args, summary, "prepare")
        with mock.patch.dict(os.environ, environment, clear=True):
            verified = PROVENANCE.verify_manifest(verify_args)
        self.assertEqual(verified["attempt"]["id"], args.attempt_id)
        self.assertEqual(verified["source_blob_count"], 2)
        self.assertEqual(
            set(verified["runtime_tools"]), PROVENANCE.REQUIRED_RUNTIME_TOOLS
        )

    def assert_repository_rejected(self, checkout: Path, revision: str) -> None:
        git = shutil.which("git")
        assert git is not None
        with self.assertRaises(PROVENANCE.ProvenanceError):
            PROVENANCE.repository_manifest(checkout, revision, git_binary=git)

    def test_tracked_untracked_ignored_and_index_flags_are_rejected(self) -> None:
        attempt, checkout, revision, _ = self.make_repository("tracked")
        (checkout / "tracked.txt").write_text("mutated\n", encoding="ascii")
        self.assert_repository_rejected(checkout, revision)

        attempt, checkout, revision, _ = self.make_repository("untracked")
        (checkout / "untracked.txt").write_text("influence\n", encoding="ascii")
        self.assert_repository_rejected(checkout, revision)

        attempt, checkout, _, _ = self.make_repository("ignored")
        (checkout / ".gitignore").write_text("ignored.bin\n", encoding="ascii")
        self.git(checkout, "add", ".gitignore")
        self.git(checkout, "commit", "--quiet", "-m", "ignore fixture")
        revision = self.git(checkout, "rev-parse", "HEAD")
        (checkout / "ignored.bin").write_text("influence\n", encoding="ascii")
        self.assert_repository_rejected(checkout, revision)

        for flag in ("--skip-worktree", "--assume-unchanged"):
            with self.subTest(flag=flag):
                _, checkout, revision, _ = self.make_repository(
                    flag.removeprefix("--")
                )
                self.git(checkout, "update-index", flag, "tracked.txt")
                self.assert_repository_rejected(checkout, revision)

    def test_symlinked_roots_checkouts_and_manifests_are_rejected(self) -> None:
        attempt, checkout, revision, fake_tool = self.make_repository("symlinks")
        root_link = self.root / "attempt-link"
        root_link.symlink_to(attempt, target_is_directory=True)
        with self.assertRaisesRegex(PROVENANCE.ProvenanceError, "symlinks"):
            PROVENANCE.require_private_attempt_root(root_link)

        checkout_link = attempt / "checkout-link"
        checkout_link.symlink_to(checkout, target_is_directory=True)
        git = shutil.which("git")
        assert git is not None
        with self.assertRaisesRegex(PROVENANCE.ProvenanceError, "symlinks"):
            PROVENANCE.repository_manifest(checkout_link, revision, git_binary=git)

        args = self.create_args(attempt, checkout, revision, fake_tool)
        summary = PROVENANCE.create_manifest(args)
        manifest_link = attempt / "manifest-link.json"
        manifest_link.symlink_to(args.out)
        verify_args = argparse.Namespace(
            manifest=manifest_link,
            expected_sha256=summary["manifest_sha256"],
            stage="prepare",
        )
        environment = self.verification_environment(args, summary, "prepare")
        environment["EUF_VIPER_SUBMISSION_MANIFEST"] = str(manifest_link.absolute())
        with mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(PROVENANCE.ProvenanceError, "without symlinks"):
                PROVENANCE.verify_manifest(verify_args)

    def test_runtime_and_manifest_tampering_fail_closed(self) -> None:
        attempt, checkout, revision, fake_tool = self.make_repository("tamper")
        args = self.create_args(attempt, checkout, revision, fake_tool)
        summary = PROVENANCE.create_manifest(args)
        environment = self.verification_environment(args, summary, "prepare")
        verify_args = argparse.Namespace(
            manifest=args.out,
            expected_sha256=summary["manifest_sha256"],
            stage="prepare",
        )

        fake_tool.write_text("#!/bin/sh\nexit 1\n", encoding="ascii")
        fake_tool.chmod(0o755)
        with mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(PROVENANCE.ProvenanceError, "runtime"):
                PROVENANCE.verify_manifest(verify_args)

        attempt, checkout, revision, fake_tool = self.make_repository("manifest-tamper")
        args = self.create_args(attempt, checkout, revision, fake_tool)
        summary = PROVENANCE.create_manifest(args)
        args.out.write_bytes(args.out.read_bytes() + b" ")
        environment = self.verification_environment(args, summary, "prepare")
        verify_args = argparse.Namespace(
            manifest=args.out,
            expected_sha256=summary["manifest_sha256"],
            stage="prepare",
        )
        with mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(PROVENANCE.ProvenanceError, "SHA-256 mismatch"):
                PROVENANCE.verify_manifest(verify_args)

    def test_ambient_build_python_git_and_solver_controls_are_rejected(self) -> None:
        attacks = (
            "RUSTFLAGS",
            "RUSTC_WRAPPER",
            "CARGO_HOME",
            "CARGO_CONFIG",
            "PYTHONPATH",
            "PYTHONHOME",
            "BASH_ENV",
            "CC",
            "CFLAGS",
            "GIT_CONFIG_COUNT",
            "EUF_VIPER_BACKEND",
        )
        for name in attacks:
            with self.subTest(name=name):
                with self.assertRaisesRegex(PROVENANCE.ProvenanceError, name):
                    PROVENANCE.audit_submit_environment({name: "attack"})

        allowed = {
            name: "bound" for name in PROVENANCE.COMMON_EUF_ENV
        }
        allowed.update(
            {
                "EUF_VIPER_LOCKED_SHARDS": "4",
                "EUF_VIPER_SHARED_CORPUS": "/srv/corpus",
            }
        )
        self.assertEqual(set(PROVENANCE.audit_environment("prepare", allowed)), set(allowed))
        for name in attacks:
            with self.subTest(stage_attack=name):
                attacked = {**allowed, name: "attack"}
                with self.assertRaisesRegex(PROVENANCE.ProvenanceError, name):
                    PROVENANCE.audit_environment("prepare", attacked)
        with self.assertRaisesRegex(PROVENANCE.ProvenanceError, "required.*missing"):
            PROVENANCE.audit_environment(
                "prepare", {key: value for key, value in allowed.items() if key != "EUF_VIPER_PYTHON"}
            )

    def test_submitter_is_attempt_scoped_and_exports_only_receipt_bindings(self) -> None:
        text = (ROOT / "scripts" / "wmi" / "submit_locked_p0.sh").read_text(
            encoding="ascii"
        )
        self.assertIn('mktemp -d "$REMOTE_PARENT/attempt-$ATTEMPT_ID-XXXXXXXX"', text)
        self.assertIn("clone --quiet --no-hardlinks", text)
        self.assertIn("--ignored=matching", text)
        self.assertIn("git ls-files -v", text)
        self.assertIn("env -i", text)
        self.assertIn("-B -I -S", text)
        self.assertNotIn("--export=ALL", text)
        self.assertNotIn('REMOTE_PARENT/$SHORT_REVISION', text)
        self.assertIn("submission-provenance.json", text)
        self.assertIn("provenance_helper_sha256", text)
        self.assertIn("source_blobs_sha256", text)

    def test_preparation_receipt_rehashes_artifacts_and_rejects_ambiguity(self) -> None:
        attempt, checkout, revision, fake_tool = self.make_repository("preparation")
        args = self.create_args(attempt, checkout, revision, fake_tool)
        summary = PROVENANCE.create_manifest(args)
        verify_args = argparse.Namespace(
            manifest=args.out,
            expected_sha256=summary["manifest_sha256"],
            stage="prepare",
        )
        environment = self.verification_environment(args, summary, "prepare")
        with mock.patch.dict(os.environ, environment, clear=True):
            provenance = PROVENANCE.verify_manifest(verify_args)

        run_root = attempt / "results" / "p0-123"
        artifact_names = (
            "solver-config.json",
            "taxonomy/full.jsonl",
            "taxonomy/full-split.json",
            "taxonomy/official.jsonl",
            "taxonomy/official-split.json",
            "locks/full-parent.json",
            "locks/official-parent.json",
        )
        artifacts = {}
        for name in artifact_names:
            path = run_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"{name}\n", encoding="ascii")
            artifacts[name] = {
                "path": str(path.resolve()),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        corpus_root = attempt / "corpus"
        corpus_root.mkdir()
        corpus = {}
        for name in ("full_manifest", "official_manifest"):
            path = corpus_root / f"{name}.jsonl"
            path.write_text("{}\n", encoding="ascii")
            corpus[name] = {
                "path": str(path.resolve()),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        corpus["root"] = str(corpus_root.resolve())

        def executable(path: Path) -> dict[str, object]:
            resolved = path.resolve(strict=True)
            return {
                "path": str(path.absolute()),
                "realpath": str(resolved),
                "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
                "bytes": resolved.stat().st_size,
            }

        solver_ids = (
            "euf-viper",
            "z3-default",
            "z3-sat-euf",
            "cvc5",
            "yices2",
            "opensmt",
        )
        payload = {
            "schema": "euf-viper.locked-p0-preparation.v2",
            "status": "prepared",
            "attempt": provenance["attempt"],
            "artifacts": artifacts,
            "build_features": [
                "certificates",
                "default",
                "finite-symmetry",
                "production-evidence",
            ],
            "corpus": corpus,
            "environment": provenance["environment"],
            "execution_environment": provenance["execution_environment"],
            "feature_report": executable(fake_tool),
            "hostname": "fixture",
            "job": {"id": 123, "submit_directory": None},
            "paths": {
                "checkout": provenance["attempt"]["checkout"],
                "run_root": str(run_root.resolve()),
                "submission_manifest": provenance["manifest"],
            },
            "revision": provenance["revision"],
            "runtime_tools": provenance["runtime_tools"],
            "shards": 4,
            "solver_executables": {
                identifier: executable(fake_tool) for identifier in solver_ids
            },
            "source": {
                "blob_count": provenance["source_blob_count"],
                "blobs_sha256": provenance["source_blobs_sha256"],
                "tree": provenance["source_tree"],
            },
            "submission_manifest_sha256": provenance["manifest_sha256"],
            "viper": executable(fake_tool),
        }
        receipt = run_root / "prepare.json"
        receipt.write_bytes(PROVENANCE.canonical_bytes(payload))
        receipt_args = argparse.Namespace(
            receipt=receipt,
            provenance=json.dumps(provenance, sort_keys=True, separators=(",", ":")),
            run_root=run_root,
            prepare_job=123,
        )
        accepted = PROVENANCE.verify_preparation_receipt(receipt_args)
        self.assertEqual(accepted["status"], "accepted")

        original_artifact = run_root / "taxonomy/full.jsonl"
        original_artifact.write_text("tampered\n", encoding="ascii")
        with self.assertRaisesRegex(PROVENANCE.ProvenanceError, "SHA-256 drifted"):
            PROVENANCE.verify_preparation_receipt(receipt_args)

        original_artifact.write_text("taxonomy/full.jsonl\n", encoding="ascii")
        original_receipt = receipt.read_bytes()
        receipt.write_bytes(b'{"schema":1,"schema":2}\n')
        with self.assertRaisesRegex(PROVENANCE.ProvenanceError, "duplicate JSON key"):
            PROVENANCE.verify_preparation_receipt(receipt_args)
        receipt.write_bytes(original_receipt)

        payload["build_features"].append("production-evidence")
        receipt.write_bytes(PROVENANCE.canonical_bytes(payload))
        with self.assertRaisesRegex(PROVENANCE.ProvenanceError, "exact locked evidence features"):
            PROVENANCE.verify_preparation_receipt(receipt_args)
        payload["build_features"].pop()

        payload["attempt"] = {**payload["attempt"], "id": "f" * 32}
        receipt.write_bytes(PROVENANCE.canonical_bytes(payload))
        with self.assertRaisesRegex(PROVENANCE.ProvenanceError, "attempt mismatch"):
            PROVENANCE.verify_preparation_receipt(receipt_args)
        receipt.write_bytes(original_receipt)

        link = run_root / "prepare-link.json"
        link.symlink_to(receipt)
        receipt_args.receipt = link
        with self.assertRaisesRegex(PROVENANCE.ProvenanceError, "without symlinks"):
            PROVENANCE.verify_preparation_receipt(receipt_args)


if __name__ == "__main__":
    unittest.main()
