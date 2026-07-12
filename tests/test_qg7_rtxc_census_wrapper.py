from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "wmi" / "euf_viper_qg7_rtxc_census.sbatch"


def write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def write_valid_census_output(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    records = [
        {
            "record_type": "provenance",
            "schema": "euf-viper.qg7-rtxc-census.v1",
        },
        {
            "record_type": "case",
            "path": "/fixture/case.smt2",
            "status": "parse_error",
        },
    ]
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )


def install_fsync_probe(base: Path) -> tuple[Path, Path]:
    probe_dir = base / "fsync-probe"
    probe_dir.mkdir()
    log_path = base / "fsync.log"
    (probe_dir / "sitecustomize.py").write_text(
        """\
import os
import stat

_original_fsync = os.fsync


def _logged_fsync(descriptor):
    mode = os.fstat(descriptor).st_mode
    kind = "directory" if stat.S_ISDIR(mode) else "file"
    log_path = os.environ.get("FSYNC_LOG")
    if log_path:
        with open(log_path, "a", encoding="utf-8") as log:
            log.write(kind + "\\n")
    return _original_fsync(descriptor)


os.fsync = _logged_fsync
""",
        encoding="utf-8",
    )
    return probe_dir, log_path


def wrapper_environment(
    *, root: Path, corpus: Path, output: Path, scratch: Path, revision: str
) -> dict[str, str]:
    environment = os.environ.copy()
    for name in [
        "CARGO_TARGET_DIR",
        "EUF_VIPER_QG7_CENSUS_RUN_ID",
        "RUSTFLAGS",
    ]:
        environment.pop(name, None)
    environment.update(
        {
            "EUF_VIPER_ROOT": str(root),
            "EUF_VIPER_QG7_CENSUS_DIR": str(corpus),
            "EUF_VIPER_QG7_CENSUS_EXPECTED": "1",
            "EUF_VIPER_QG7_CENSUS_LIMIT": "1",
            "EUF_VIPER_QG7_CENSUS_OFFSET": "0",
            "EUF_VIPER_QG7_CENSUS_OUTPUT": str(output),
            "EUF_VIPER_GIT_REVISION": revision,
            "SLURM_JOB_ID": "wrapper-test",
            "SLURM_TMPDIR": str(scratch),
        }
    )
    return environment


class CensusWrapperTests(unittest.TestCase):
    def test_malformed_revision_removes_and_syncs_stale_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            output = base / "census.jsonl"
            write_valid_census_output(output)
            probe_dir, fsync_log = install_fsync_probe(base)
            environment = wrapper_environment(
                root=ROOT,
                corpus=ROOT / "tests" / "fixtures",
                output=output,
                scratch=base / "scratch",
                revision="deadbeef",
            )
            environment["PYTHONPATH"] = str(probe_dir)
            environment["FSYNC_LOG"] = str(fsync_log)

            completed = subprocess.run(
                ["bash", str(WRAPPER)],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertIn("exact 40-character commit", completed.stderr)
            self.assertFalse(output.exists())
            self.assertGreaterEqual(
                fsync_log.read_text(encoding="utf-8").splitlines().count(
                    "directory"
                ),
                1,
            )

    def test_home_cargo_path_is_available_before_tool_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "root"
            corpus = root / "corpus"
            corpus.mkdir(parents=True)
            output = base / "output" / "census.jsonl"
            write_valid_census_output(output)

            inherited_bin = base / "inherited-bin"
            inherited_bin.mkdir()
            for tool in [
                "basename",
                "dirname",
                "git",
                "mkdir",
                "rm",
                "sha256sum",
                "tar",
            ]:
                source = shutil.which(tool)
                self.assertIsNotNone(source, f"test requires {tool}")
                (inherited_bin / tool).symlink_to(source)
            (inherited_bin / "python3").symlink_to(sys.executable)

            home = base / "home"
            fake_cargo = home / ".cargo" / "bin" / "cargo"
            write_executable(fake_cargo, "#!/bin/sh\nexit 99\n")
            environment = wrapper_environment(
                root=root,
                corpus=corpus,
                output=output,
                scratch=base / "scratch",
                revision="0" * 40,
            )
            environment.update(
                {
                    "HOME": str(home),
                    "PATH": str(inherited_bin),
                }
            )

            completed = subprocess.run(
                ["/bin/bash", str(WRAPPER)],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 128, completed.stderr)
            self.assertIn("not a git repository", completed.stderr)
            self.assertNotIn("required tool is unavailable: cargo", completed.stderr)
            self.assertFalse(output.exists())

    def test_invalid_root_removes_valid_explicit_stale_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            output = base / "output" / "census.jsonl"
            write_valid_census_output(output)
            probe_dir, fsync_log = install_fsync_probe(base)
            missing_root = base / "missing-root"
            environment = wrapper_environment(
                root=missing_root,
                corpus=base / "corpus",
                output=output,
                scratch=base / "scratch",
                revision="0" * 40,
            )
            environment["PYTHONPATH"] = str(probe_dir)
            environment["FSYNC_LOG"] = str(fsync_log)

            completed = subprocess.run(
                ["bash", str(WRAPPER)],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertIn("cannot resolve EUF_VIPER_ROOT", completed.stderr)
            self.assertFalse(output.exists())
            self.assertIn(
                "directory", fsync_log.read_text(encoding="utf-8").splitlines()
            )

    def test_invalid_root_preserves_unrecognized_explicit_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            output = base / "output" / "census.jsonl"
            output.parent.mkdir()
            stale_content = '{"unrelated":true}\n'
            output.write_text(stale_content, encoding="utf-8")
            environment = wrapper_environment(
                root=base / "missing-root",
                corpus=base / "corpus",
                output=output,
                scratch=base / "scratch",
                revision="0" * 40,
            )

            completed = subprocess.run(
                ["bash", str(WRAPPER)],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertIn("unrecognized explicit census output", completed.stderr)
            self.assertEqual(output.read_text(encoding="utf-8"), stale_content)

    def test_rejected_repo_local_output_does_not_create_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            repository = base / "repository"
            repository.mkdir()
            forbidden_parent = repository / "generated" / "nested"
            output = forbidden_parent / "census.jsonl"
            environment = wrapper_environment(
                root=repository,
                corpus=base / "corpus",
                output=output,
                scratch=base / "scratch",
                revision="0" * 40,
            )

            completed = subprocess.run(
                ["bash", str(WRAPPER)],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertIn("repo-local census output is allowed only", completed.stderr)
            self.assertFalse(forbidden_parent.exists())

    def test_atomic_publication_fsyncs_file_then_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            repository = base / "repository"
            wrapper = (
                repository
                / "scripts"
                / "wmi"
                / "euf_viper_qg7_rtxc_census.sbatch"
            )
            wrapper.parent.mkdir(parents=True)
            shutil.copy2(WRAPPER, wrapper)
            wrapper.chmod(0o755)
            corpus = repository / "corpus"
            corpus.mkdir()
            (corpus / "case.smt2").write_text(
                "(set-logic QF_UF)\n(check-sat)\n", encoding="utf-8"
            )

            subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
            subprocess.run(["git", "add", "."], cwd=repository, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Wrapper Test",
                    "-c",
                    "user.email=wrapper-test@example.invalid",
                    "commit",
                    "-qm",
                    "wrapper fixture",
                ],
                cwd=repository,
                check=True,
            )
            revision = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository,
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip()

            fake_bin = base / "fake-bin"
            write_executable(
                fake_bin / "cargo",
                """#!/usr/bin/env python3
import json
import os

marker = "QG7_CENSUS_JSON:"
directory = os.path.realpath(os.environ["EUF_VIPER_QG7_CENSUS_DIR"])
revision = os.environ["EUF_VIPER_GIT_REVISION"]
provenance = {
    "record_type": "provenance",
    "schema": "euf-viper.qg7-rtxc-census.v1",
    "revision": revision,
    "directory": directory,
    "path_order": "lexicographic",
    "selection": "sorted_smt2_paths_skip_offset_take_limit",
    "offset": 0,
    "limit": 1,
    "expected_records": 1,
    "selected_records": 1,
    "parse_mode": "auto",
    "production_routing": False,
}
case = {
    "record_type": "case",
    "path": os.path.join(directory, "case.smt2"),
    "status": "parse_error",
    "reason": "fixture",
}
print(marker + json.dumps(provenance, separators=(",", ":")))
print(marker + json.dumps(case, separators=(",", ":")))
""",
            )

            output_dir = base / "output"
            output_dir.mkdir()
            output = output_dir / "census.jsonl"
            write_valid_census_output(output)
            scratch = base / "scratch"
            home = base / "home"
            home.mkdir()
            probe_dir, fsync_log = install_fsync_probe(base)
            environment = wrapper_environment(
                root=repository,
                corpus=corpus,
                output=output,
                scratch=scratch,
                revision=revision,
            )
            environment.update(
                {
                    "FSYNC_LOG": str(fsync_log),
                    "HOME": str(home),
                    "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
                    "PYTHONPATH": str(probe_dir),
                }
            )

            completed = subprocess.run(
                ["bash", str(wrapper)],
                cwd=repository,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            records = [
                json.loads(line)
                for line in output.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(
                [record["record_type"] for record in records],
                ["provenance", "case"],
            )
            self.assertEqual(records[0]["source_revision"], revision)
            events = fsync_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(events[-2:], ["file", "directory"])
            self.assertEqual(list(output_dir.glob(f".{output.name}.tmp.*")), [])
            self.assertEqual(list(scratch.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
