from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from scripts.bench import finalize_t11_stage0a as finalizer_contract


ROOT = Path(__file__).resolve().parents[1]
WMI = ROOT / "scripts" / "wmi"
SUBMIT = WMI / "submit_t11_stage0a.sh"
COMPUTE = WMI / "euf_viper_t11_stage0a.sbatch"
FINALIZER_RUNNER = WMI / "euf_viper_t11_stage0a_finalize.sbatch"
AUTHORIZATION_REQUEST_EXECUTOR = (
    ROOT / "scripts/bench/execute_t11_stage0a_authorization_request.py"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def controller_python() -> Path:
    system_python = Path("/usr/bin/python3")
    if sys.platform.startswith("linux") and system_python.is_file():
        return Path(os.path.realpath(system_python))
    return Path(sys.executable).resolve()


def write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")
    path.chmod(0o755)


class T11SubmissionStaticTests(unittest.TestCase):
    def test_shell_scripts_parse(self) -> None:
        completed = subprocess.run(
            ["bash", "-n", str(SUBMIT), str(FINALIZER_RUNNER)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_embedded_python_blocks_compile(self) -> None:
        for script in (SUBMIT, FINALIZER_RUNNER):
            lines = script.read_text(encoding="utf-8").splitlines()
            blocks: list[str] = []
            current: list[str] | None = None
            for line in lines:
                if current is None and "<<'PY'" in line:
                    current = []
                    continue
                if current is not None and line == "PY":
                    blocks.append("\n".join(current) + "\n")
                    current = None
                    continue
                if current is not None:
                    current.append(line)
            self.assertIsNone(current, f"unterminated Python heredoc in {script}")
            self.assertTrue(blocks, f"no Python heredocs found in {script}")
            for index, block in enumerate(blocks):
                compile(block, f"{script}:{index}", "exec")

    def test_submitter_is_held_record_first_and_fail_closed(self) -> None:
        source = SUBMIT.read_text(encoding="utf-8")
        self.assertGreaterEqual(source.count("--hold"), 2)
        self.assertGreaterEqual(source.count("--no-requeue"), 2)
        self.assertIn('--dependency="afterany:$COMPUTE_JOB_ID"', source)
        self.assertIn('--output="$COMPUTE_STDOUT"', source)
        self.assertIn('--error="$COMPUTE_STDERR"', source)
        self.assertIn('--output="$FINALIZER_STDOUT"', source)
        self.assertIn('--error="$FINALIZER_STDERR"', source)
        self.assertIn("os.link(", source)
        self.assertIn("os.fsync(parent_fd)", source)
        self.assertIn("held_at_publication", source)
        self.assertIn("revalidate_scheduler_record", source)
        finalizer_release = source.index(
            'sealed_control "$SCONTROL" "$SCONTROL_SHA256" release "$FINALIZER_JOB_ID"'
        )
        compute_release = source.index(
            'sealed_control "$SCONTROL" "$SCONTROL_SHA256" release "$COMPUTE_JOB_ID"'
        )
        record_publish = source.index("SUBMISSION_RECORD_SHA256=")
        self.assertLess(record_publish, finalizer_release)
        self.assertLess(finalizer_release, compute_release)
        self.assertIn("cancel_if_owned", source)
        self.assertIn("retaining job", source)
        self.assertIn("os.memfd_create", source)
        self.assertIn("F_ADD_SEALS", source)
        self.assertIn("FINALIZER_DEPENDENCY_READY", source)
        self.assertIn('"/proc/self/exe"', source)
        self.assertIn("AUTHORIZATION_REQUEST_EXECUTOR", source)
        self.assertIn('"$AUTHORIZATION_REQUEST_EXECUTOR_SHA256" create', source)
        self.assertIn('"$AUTHORIZATION_REQUEST_EXECUTOR_SHA256" execute', source)
        authorization_execute = source.index(
            '"$AUTHORIZATION_REQUEST_EXECUTOR_SHA256" execute'
        )
        submission_complete = source.index("SUBMISSION_COMPLETE=1", authorization_execute)
        self.assertLess(compute_release, authorization_execute)
        self.assertLess(authorization_execute, submission_complete)

    def test_finalizer_has_explicit_pins_and_sealed_isolated_execution(self) -> None:
        source = FINALIZER_RUNNER.read_text(encoding="utf-8")
        self.assertIn("EUF_VIPER_T11_FINALIZER_SHA256", source)
        self.assertIn("EUF_VIPER_T11_FINALIZER_SBATCH_SHA256", source)
        self.assertIn("EUF_VIPER_T11_SUBMISSION_RECORD", source)
        self.assertIn("EUF_VIPER_T11_COMPUTE_JOB_ID", source)
        self.assertIn("SLURM_JOB_ID", source)
        self.assertIn("os.memfd_create", source)
        self.assertIn("F_ADD_SEALS", source)
        self.assertIn("/proc/self/fd/", source)
        self.assertIn("exec /usr/bin/env -i", source)
        self.assertIn('"--submission"', source)
        self.assertIn('"--submission-sha256"', source)
        self.assertIn('"--candidate-root"', source)
        self.assertIn('"--output"', source)
        self.assertIn('"--poll-attempts"', source)
        self.assertIn('"--poll-interval-seconds"', source)
        self.assertIn('"--sacct-bin"', source)
        self.assertIn('"--scontrol-bin"', source)
        self.assertNotIn('"--submission-record-sha256"', source)
        self.assertNotIn("authorize_stage0b", source)


class T11SubmissionDynamicTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.work = Path(self.temporary.name).resolve()
        self.repo = self.work / "repo"
        self.input_root = self.work / "input"
        self.run_base = self.work / "runs"
        self.corpus = self.work / "corpus"
        self.fake_bin = self.work / "scheduler-bin"
        self.state_root = self.work / "scheduler-state"
        for directory in (
            self.repo,
            self.input_root,
            self.run_base,
            self.corpus,
            self.fake_bin,
            self.state_root,
        ):
            directory.mkdir(parents=True)

        self.submitter = self.repo / "scripts/wmi/submit_t11_stage0a.sh"
        self.compute = self.repo / "scripts/wmi/euf_viper_t11_stage0a.sbatch"
        self.finalizer_runner = (
            self.repo / "scripts/wmi/euf_viper_t11_stage0a_finalize.sbatch"
        )
        self.submitter.parent.mkdir(parents=True)
        shutil.copy2(SUBMIT, self.submitter)
        shutil.copy2(COMPUTE, self.compute)
        shutil.copy2(FINALIZER_RUNNER, self.finalizer_runner)

        self.validator = self.repo / "scripts/bench/validate_t11_stage0a.py"
        self.helper = self.repo / "scripts/bench/exec_t11_stage0a.py"
        self.finalizer = self.repo / "scripts/bench/finalize_t11_stage0a.py"
        self.authorizer = self.repo / "scripts/bench/authorize_t11_stage0a.py"
        self.authorization_request_executor = (
            self.repo / "scripts/bench/execute_t11_stage0a_authorization_request.py"
        )
        self.prebuilt_preparer = self.repo / "scripts/bench/prepare_t11_prebuilt.py"
        write_executable(self.validator, "#!/usr/bin/env python3\nraise SystemExit(0)\n")
        write_executable(self.helper, "#!/usr/bin/env python3\nraise SystemExit(0)\n")
        write_executable(
            self.prebuilt_preparer,
            "#!/usr/bin/env python3\nraise SystemExit(0)\n",
        )
        write_executable(
            self.authorizer,
            f"""
            #!/usr/bin/env python3
            import argparse
            import hashlib
            import json
            import os
            from pathlib import Path

            parser = argparse.ArgumentParser()
            parser.add_argument("--submission", required=True)
            parser.add_argument("--submission-sha256", required=True)
            parser.add_argument("--scheduler-candidate", required=True)
            parser.add_argument("--output", required=True)
            parser.add_argument("--finalizer-module", required=True)
            parser.add_argument("--finalizer-module-sha256", required=True)
            parser.add_argument("--sacct-bin", required=True)
            parser.add_argument("--poll-attempts", required=True)
            parser.add_argument("--poll-interval-seconds", required=True)
            arguments = vars(parser.parse_args())
            root = Path({os.fspath(self.state_root)!r})
            if (root / "authorization-fail").exists():
                raise SystemExit(73)
            (root / "authorization-invocation.json").write_text(
                json.dumps(arguments, sort_keys=True, separators=(",", ":")) + "\\n",
                encoding="ascii",
            )
            submission_bytes = Path(arguments["submission"]).read_bytes()
            submission = json.loads(submission_bytes)
            candidate_path = Path(arguments["scheduler_candidate"])
            candidate = {{
                "attempt_id": "d" * 64,
                "classification": "scientific_candidate",
                "policy": {{"sat_calls": 0}},
            }}
            candidate_bytes = (
                json.dumps(candidate, sort_keys=True, separators=(",", ":")) + "\\n"
            ).encode("ascii")
            candidate_descriptor = os.open(
                candidate_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400
            )
            try:
                os.write(candidate_descriptor, candidate_bytes)
                os.fchmod(candidate_descriptor, 0o400)
                os.fsync(candidate_descriptor)
            finally:
                os.close(candidate_descriptor)
            submission_stat = os.stat(arguments["submission"], follow_symlinks=False)
            candidate_stat = os.stat(candidate_path, follow_symlinks=False)
            submission_sha256 = hashlib.sha256(submission_bytes).hexdigest()
            candidate_sha256 = hashlib.sha256(candidate_bytes).hexdigest()
            raw_sha256 = {{"allocation": "e" * 64, "batch": "f" * 64}}
            root_binding = {{
                "device": 1,
                "inode": 1,
                "inventory_sha256": "1" * 64,
                "mode": "0500",
                "path": submission["candidate_root"],
            }}
            identity = {{
                "candidate_root": submission["candidate_root"],
                "candidate_root_binding": root_binding,
                "cluster": submission["slurm"]["cluster"],
                "finalizer_job_id": submission["slurm"]["finalizer_job_id"],
                "finalizer_scheduler_raw_sha256": raw_sha256,
                "launch_manifest_sha256": submission["launch_manifest_sha256"],
                "revision": submission["revision"],
                "run_nonce": submission["run_nonce"],
                "scheduler_candidate_sha256": candidate_sha256,
                "submission_sha256": submission_sha256,
            }}
            identity_bytes = (
                json.dumps(identity, sort_keys=True, separators=(",", ":")) + "\\n"
            ).encode("ascii")
            payload = {{
                "authorization_id": hashlib.sha256(identity_bytes).hexdigest(),
                "candidate_root": submission["candidate_root"],
                "candidate_root_binding": root_binding,
                "classification": candidate["classification"],
                "control": submission["control"],
                "decision": "authorize_stage0b",
                "finalizer_scheduler": {{
                    "allocation": {{
                        "Cluster": submission["slurm"]["cluster"],
                        "JobIDRaw": str(submission["slurm"]["finalizer_job_id"]),
                    }},
                    "batch": {{}},
                    "commands": {{}},
                    "raw_sha256": raw_sha256,
                }},
                "launch_manifest_sha256": submission["launch_manifest_sha256"],
                "policy": candidate["policy"],
                "revision": submission["revision"],
                "run_nonce": submission["run_nonce"],
                "scheduler_candidate": {{
                    "attempt_id": candidate["attempt_id"],
                    "bytes": len(candidate_bytes),
                    "mode": f"{{candidate_stat.st_mode & 0o7777:04o}}",
                    "path": str(candidate_path),
                    "sha256": candidate_sha256,
                }},
                "schema": "euf-viper.t11-stage0a-authorization.v1",
                "stage0b_authority": True,
                "status": "stage0b_authorized",
                "submission": {{
                    "bytes": len(submission_bytes),
                    "mode": f"{{submission_stat.st_mode & 0o7777:04o}}",
                    "path": arguments["submission"],
                    "sha256": submission_sha256,
                }},
                "submission_evidence": {{
                    "compute_held_record": submission["slurm"]["compute_held_record"],
                    "compute_sbatch_argv": submission["slurm"]["compute_sbatch_argv"],
                    "finalizer_held_record": submission["slurm"]["finalizer_held_record"],
                    "finalizer_sbatch_argv": submission["slurm"]["finalizer_sbatch_argv"],
                    "owner_uid": submission["slurm"]["owner_uid"],
                }},
            }}
            encoded = (
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\\n"
            ).encode("ascii")
            descriptor = os.open(
                arguments["output"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400
            )
            try:
                os.write(descriptor, encoded)
                os.fchmod(descriptor, 0o400)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.write(1, encoded)
            """,
        )
        write_executable(
            self.finalizer,
            """
                #!/usr/bin/env python3
                import argparse
                import json
                from pathlib import Path

                parser = argparse.ArgumentParser()
                parser.add_argument("--submission", required=True)
                parser.add_argument("--submission-sha256", required=True)
                parser.add_argument("--candidate-root", required=True)
                parser.add_argument("--output", required=True)
                parser.add_argument("--poll-attempts", required=True)
                parser.add_argument("--poll-interval-seconds", required=True)
                parser.add_argument("--sacct-bin", required=True)
                parser.add_argument("--scontrol-bin", required=True)
                arguments = vars(parser.parse_args())
                Path(arguments["output"]).write_text(
                    json.dumps(arguments, sort_keys=True) + "\\n", encoding="ascii"
                )
            """,
        )

        if sys.platform.startswith("linux") and hasattr(os, "memfd_create"):
            shutil.copy2(
                AUTHORIZATION_REQUEST_EXECUTOR, self.authorization_request_executor
            )
            self.authorization_request_executor.chmod(0o755)
        else:
            self._write_nonlinux_request_executor()

        self._install_fake_scheduler()
        self.git = Path(shutil.which("git") or "").resolve()
        if not self.git.is_file():
            self.skipTest("git is unavailable")
        self._run([str(self.git), "init", "-q"], cwd=self.repo)
        self._run(
            [str(self.git), "config", "user.name", "T11 Submission Test"],
            cwd=self.repo,
        )
        self._run(
            [
                str(self.git),
                "config",
                "user.email",
                "t11-submission@example.invalid",
            ],
            cwd=self.repo,
        )
        self._run([str(self.git), "add", "."], cwd=self.repo)
        self._run(
            [str(self.git), "commit", "-qm", "T11 submission fixture"],
            cwd=self.repo,
        )
        self.revision = self._run(
            [str(self.git), "rev-parse", "HEAD"], cwd=self.repo
        ).stdout.strip()

        self.python = controller_python()
        self.manifest = self.input_root / "launch-manifest.json"
        manifest = {
            "solver_revision": self.revision,
            "toolchain": {
                "python": {
                    "path": str(self.python),
                    "sha256": sha256(self.python),
                    "version": subprocess.run(
                        [str(self.python), "--version"],
                        check=True,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                    ).stdout.strip(),
                }
            },
            "control_tools": {
                name: {
                    "path": str(path),
                    "sha256": sha256(path),
                    "version": "fixture-1",
                }
                for name, path in {
                    "git": self.git,
                    "sbatch": self.fake_bin / "sbatch",
                    "scontrol": self.fake_bin / "scontrol",
                    "scancel": self.fake_bin / "scancel",
                    "sacct": self.fake_bin / "sacct",
                }.items()
            },
            "artifacts": {
                "submitter_sha256": sha256(self.submitter),
                "runner_sha256": sha256(self.compute),
                "finalizer_sbatch_sha256": sha256(self.finalizer_runner),
                "finalizer_sha256": sha256(self.finalizer),
                "authorizer_sha256": sha256(self.authorizer),
                "authorization_request_executor_sha256": sha256(
                    self.authorization_request_executor
                ),
                "validator_sha256": sha256(self.validator),
                "exec_helper_sha256": sha256(self.helper),
                "prebuilt_preparer_sha256": sha256(self.prebuilt_preparer),
            },
        }
        self.manifest.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        self.manifest.chmod(0o400)
        (self.state_root / "counter").write_text("4100\n", encoding="ascii")
        (self.state_root / "jobs.json").write_text("{}\n", encoding="ascii")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _run(
        argv: list[str], *, cwd: Path, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(
                f"command failed: {argv!r}\nstdout={completed.stdout}\nstderr={completed.stderr}"
            )
        return completed

    def _write_nonlinux_request_executor(self) -> None:
        write_executable(
            self.authorization_request_executor,
            f"""
            #!/usr/bin/env python3
            import argparse
            import hashlib
            import importlib.util
            import json
            import os
            import sys
            from pathlib import Path

            module_path = Path({os.fspath(AUTHORIZATION_REQUEST_EXECUTOR)!r})
            spec = importlib.util.spec_from_file_location("real_request_executor", module_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            if sys.argv[1] == "create":
                raise SystemExit(module.main(sys.argv[1:]))
            parser = argparse.ArgumentParser()
            parser.add_argument("command", choices=("execute",))
            parser.add_argument("--request", type=Path, required=True)
            parser.add_argument("--request-sha256", required=True)
            arguments = parser.parse_args()
            try:
                encoded_request = arguments.request.read_bytes()
                if hashlib.sha256(encoded_request).hexdigest() != arguments.request_sha256:
                    raise module.RequestError(
                        "authorization request SHA-256 differs from the caller binding"
                    )
                request = module.validate_request(
                    module._decode_canonical(encoded_request, "authorization request")
                )
                root = Path({os.fspath(self.state_root)!r})
                if (root / "authorization-fail").exists():
                    raise module.RequestError("test authorizer failed")
                invocation = {{
                    "poll_attempts": request["poll"]["attempts"],
                    "poll_interval_seconds": request["poll"]["interval_seconds"],
                    "sacct_bin": request["sacct"]["path"],
                }}
                (root / "authorization-invocation.json").write_text(
                    json.dumps(invocation, sort_keys=True, separators=(",", ":")) + "\\n",
                    encoding="ascii",
                )
                payload = {{
                    "decision": "authorize_stage0b",
                    "schema": "test.authorization.v1",
                    "stage0b_authority": True,
                    "status": "stage0b_authorized",
                }}
                encoded = (
                    json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\\n"
                ).encode("ascii")
                descriptor = os.open(
                    request["output_path"],
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o400,
                )
                try:
                    os.write(descriptor, encoded)
                    os.fchmod(descriptor, 0o400)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.write(1, encoded)
            except module.RequestError as error:
                print(f"authorization-request executor rejected: {{error}}", file=sys.stderr)
                raise SystemExit(2)
            """,
        )

    def _install_fake_scheduler(self) -> None:
        write_executable(
            self.fake_bin / "sbatch",
            r"""
            #!/usr/bin/env python3
            import json
            import os
            import sys
            from pathlib import Path

            root = Path.cwd().resolve().parent / "scheduler-state"
            arguments = sys.argv[1:]

            def setting(name, default=""):
                path = root / f"setting-{name}"
                return path.read_text(encoding="ascii").strip() if path.exists() else default

            observed_environment = {
                name: os.environ.get(name)
                for name in (
                    "GIT_CONFIG_GLOBAL",
                    "LD_LIBRARY_PATH",
                    "PYTHONPATH",
                    "SLURM_CONF",
                )
            }
            (root / "control-environment.json").write_text(
                json.dumps(observed_environment, sort_keys=True) + "\n",
                encoding="ascii",
            )

            def option(name):
                prefix = name + "="
                return next(value[len(prefix):] for value in arguments if value.startswith(prefix))

            name = option("--job-name")
            role = "finalizer" if name.endswith("finalize") else "compute"
            with (root / "sbatch.jsonl").open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(arguments) + "\n")
            if setting("TEST_SBATCH_FAIL_ROLE") == role:
                raise SystemExit(19)
            counter_path = root / "counter"
            job_id = int(counter_path.read_text()) + 1
            counter_path.write_text(f"{job_id}\n")
            jobs_path = root / "jobs.json"
            jobs = json.loads(jobs_path.read_text())
            dependency = next(
                (
                    value.split("=", 1)[1]
                    for value in arguments
                    if value.startswith("--dependency=")
                ),
                "(null)",
            )
            jobs[str(job_id)] = {
                "job_name": name,
                "held": True,
                "dependency": dependency,
                "comment": option("--comment"),
                "command": arguments[-1],
                "workdir": option("--chdir"),
                "stdout": option("--output"),
                "stderr": option("--error"),
                "canceled": False,
            }
            jobs_path.write_text(json.dumps(jobs, sort_keys=True) + "\n")
            print(f"{job_id};testcluster")
            """,
        )
        write_executable(
            self.fake_bin / "scontrol",
            r"""
            #!/usr/bin/env python3
            import json
            import os
            import sys
            from pathlib import Path

            root = Path.cwd().resolve().parent / "scheduler-state"
            jobs_path = root / "jobs.json"
            jobs = json.loads(jobs_path.read_text())

            def setting(name, default=""):
                path = root / f"setting-{name}"
                return path.read_text(encoding="ascii").strip() if path.exists() else default
            if sys.argv[1:4] == ["show", "job", "-o"]:
                job_id = sys.argv[4]
                job = jobs[job_id]
                count_path = root / "show-count"
                count = int(count_path.read_text()) + 1 if count_path.exists() else 1
                count_path.write_text(f"{count}\n")
                comment = job["comment"]
                mismatch_after = int(setting("TEST_SCONTROL_MISMATCH_AFTER", "0"))
                if (
                    mismatch_after
                    and count >= mismatch_after
                    and job["job_name"] == "euf-t11-stage0a"
                ):
                    comment = "not-owned"
                if job["held"]:
                    reason = "JobHeldUser"
                elif job["dependency"] != "(null)":
                    dependency_count_path = root / f"dependency-shows-{job_id}"
                    dependency_count = (
                        int(dependency_count_path.read_text()) + 1
                        if dependency_count_path.exists()
                        else 1
                    )
                    dependency_count_path.write_text(f"{dependency_count}\n")
                    transient_reads = int(
                        setting("TEST_SCONTROL_TRANSIENT_NONE_READS", "0")
                    )
                    reason = (
                        "None" if dependency_count <= transient_reads else "Dependency"
                    )
                else:
                    reason = "None"
                dependency = job["dependency"]
                if (
                    setting("TEST_SCONTROL_DEPENDENCY_OVERRIDE")
                    and job["job_name"] == "euf-t11-stage0a-finalize"
                ):
                    dependency = setting("TEST_SCONTROL_DEPENDENCY_OVERRIDE")
                fields = {
                    "JobId": job_id,
                    "JobName": job["job_name"],
                    "UserId": f"test({os.getuid()})",
                    "JobState": "PENDING",
                    "Reason": reason,
                    "Dependency": dependency,
                    "Comment": comment,
                    "Command": job["command"],
                    "WorkDir": job["workdir"],
                    "StdOut": job["stdout"],
                    "StdErr": job["stderr"],
                    "Requeue": "0",
                }
                print(" ".join(f"{name}={value}" for name, value in fields.items()))
                raise SystemExit(0)
            if sys.argv[1] == "release" and len(sys.argv) == 3:
                job_id = sys.argv[2]
                jobs[job_id]["held"] = False
                jobs_path.write_text(json.dumps(jobs, sort_keys=True) + "\n")
                with (root / "release.log").open("a", encoding="ascii") as handle:
                    handle.write(job_id + "\n")
                if jobs[job_id]["job_name"] == "euf-t11-stage0a":
                    control = Path(jobs[job_id]["command"]).parent
                    tamper = setting("TEST_TAMPER_AUTHORIZATION_REQUEST")
                    if tamper:
                        request_path = control / "authorization-request.json"
                        request_path.chmod(0o600)
                        if tamper == "argv":
                            request = json.loads(request_path.read_text(encoding="ascii"))
                            request["argv"].append("--tampered")
                            request_path.write_text(
                                json.dumps(request, sort_keys=True, separators=(",", ":"))
                                + "\n",
                                encoding="ascii",
                            )
                        else:
                            request_path.write_bytes(request_path.read_bytes() + b" ")
                        request_path.chmod(0o400)
                    if setting("TEST_REPLACE_AUTHORIZER_AFTER_RELEASE"):
                        authorizer = control / "authorize_t11_stage0a.py"
                        authorizer.chmod(0o700)
                        authorizer.write_text(
                            "raise SystemExit('replacement executed')\n",
                            encoding="ascii",
                        )
                        authorizer.chmod(0o500)
                raise SystemExit(0)
            raise SystemExit(91)
            """,
        )
        write_executable(
            self.fake_bin / "scancel",
            r"""
            #!/usr/bin/env python3
            import json
            import os
            import sys
            from pathlib import Path

            root = Path.cwd().resolve().parent / "scheduler-state"
            job_id = sys.argv[1]
            path = root / "jobs.json"
            jobs = json.loads(path.read_text())
            jobs[job_id]["canceled"] = True
            path.write_text(json.dumps(jobs, sort_keys=True) + "\n")
            with (root / "cancel.log").open("a", encoding="ascii") as handle:
                handle.write(job_id + "\n")
            """,
        )
        write_executable(
            self.fake_bin / "sacct",
            f"""
            #!/usr/bin/env python3
            import json
            import sys
            from pathlib import Path

            root = Path({str(self.state_root)!r})
            state_path = root / "finalizer-sacct.json"
            if not state_path.exists():
                raise SystemExit("sacct fixture was invoked before terminal evidence existed")
            state = json.loads(state_path.read_text(encoding="ascii"))
            fields = next(
                value.removeprefix("--format=").split(",")
                for value in sys.argv[1:]
                if value.startswith("--format=")
            )
            role = "allocation" if "--allocations" in sys.argv else "batch"
            record = state[role]
            with (root / "sacct-invocations.jsonl").open("a", encoding="ascii") as handle:
                handle.write(json.dumps(sys.argv[1:]) + "\\n")
            print("|".join(record[field] for field in fields))
            """,
        )

    def _environment(self, **updates: str) -> dict[str, str]:
        sbatch = self.fake_bin / "sbatch"
        scontrol = self.fake_bin / "scontrol"
        scancel = self.fake_bin / "scancel"
        sacct = self.fake_bin / "sacct"
        environment = os.environ.copy()
        environment.update(
            {
                "EUF_VIPER_T11_CONTROLLER_PYTHON": str(self.python),
                "EUF_VIPER_T11_CONTROLLER_PYTHON_SHA256": sha256(self.python),
                "EUF_VIPER_T11_GIT": str(self.git),
                "EUF_VIPER_T11_GIT_SHA256": sha256(self.git),
                "EUF_VIPER_T11_SBATCH": str(sbatch),
                "EUF_VIPER_T11_SBATCH_SHA256": sha256(sbatch),
                "EUF_VIPER_T11_SCONTROL": str(scontrol),
                "EUF_VIPER_T11_SCONTROL_SHA256": sha256(scontrol),
                "EUF_VIPER_T11_SCANCEL": str(scancel),
                "EUF_VIPER_T11_SCANCEL_SHA256": sha256(scancel),
                "EUF_VIPER_T11_SACCT": str(sacct),
                "EUF_VIPER_T11_SACCT_SHA256": sha256(sacct),
                "EUF_VIPER_T11_RUN_BASE": str(self.run_base),
                "EUF_VIPER_T11_CORPUS_ROOT": str(self.corpus),
                "EUF_VIPER_T11_LAUNCH_MANIFEST": str(self.manifest),
                "EUF_VIPER_T11_LAUNCH_MANIFEST_SHA256": sha256(self.manifest),
                "EUF_VIPER_T11_EXPECTED_REVISION": self.revision,
                "EUF_VIPER_T11_CLUSTER": "testcluster",
                "EUF_VIPER_T11_PARTITION": "test_idle",
                "EUF_VIPER_T11_RUN_NONCE": "0123456789abcdef0123456789abcdef",
                "EUF_VIPER_T11_FINALIZER_PATH": str(self.finalizer),
            }
        )
        environment.update(updates)
        return environment

    def _submit(self, **updates: str) -> subprocess.CompletedProcess[str]:
        environment_updates: dict[str, str] = {}
        for name, value in updates.items():
            if name.startswith("TEST_"):
                (self.state_root / f"setting-{name}").write_text(
                    value, encoding="ascii"
                )
            else:
                environment_updates[name] = value
        return subprocess.run(
            ["bash", str(self.submitter)],
            cwd=self.repo,
            env=self._environment(**environment_updates),
            text=True,
            capture_output=True,
            check=False,
        )

    def _jobs(self) -> dict[str, dict[str, object]]:
        return json.loads((self.state_root / "jobs.json").read_text())

    @staticmethod
    def _write_candidate_file(path: Path, data: bytes, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)

    def _compute_scheduler_runner(self, submission: dict[str, object]):
        slurm = submission["slurm"]
        job_id = slurm["compute_job_id"]
        allocation = {
            "Cluster": slurm["cluster"],
            "DBIndex": "8001",
            "JobIDRaw": str(job_id),
            "JobName": slurm["compute_job_name"],
            "User": "test",
            "UID": str(os.getuid()),
            "State": "COMPLETED",
            "ExitCode": "0:0",
            "DerivedExitCode": "0:0",
            "Submit": "2026-07-19T10:00:00",
            "Eligible": "2026-07-19T10:00:00",
            "Start": "2026-07-19T10:00:01",
            "End": "2026-07-19T10:00:11",
            "ElapsedRaw": "10",
            "Partition": slurm["partition"],
            "NodeList": "wmi-node01",
            "NNodes": "1",
            "ReqCPUS": "1",
            "AllocCPUS": "1",
            "ReqMem": "8Gn",
            "ReqTRES": "cpu=1,mem=8G,node=1,billing=1",
            "AllocTRES": "cpu=1,mem=8G,node=1,billing=1",
            "TimelimitRaw": "60",
            "Comment": slurm["compute_comment"],
            "SubmitLine": " ".join(slurm["compute_sbatch_argv"]),
            "WorkDir": slurm["work_dir"],
            "StdOut": slurm["stdout_path"],
            "StdErr": slurm["stderr_path"],
        }
        batch = {
            "Cluster": slurm["cluster"],
            "DBIndex": "8001",
            "JobIDRaw": f"{job_id}.batch",
            "JobName": "batch",
            "State": "COMPLETED",
            "ExitCode": "0:0",
            "DerivedExitCode": "",
            "Submit": "2026-07-19T10:00:01",
            "Start": "2026-07-19T10:00:01",
            "End": "2026-07-19T10:00:11",
            "ElapsedRaw": "10",
            "NodeList": "wmi-node01",
            "NNodes": "1",
            "ReqCPUS": "1",
            "AllocCPUS": "1",
            "AllocTRES": "cpu=1,mem=8G,node=1",
        }
        control = {
            "JobId": str(job_id),
            "JobName": slurm["compute_job_name"],
            "UserId": f"test({os.getuid()})",
            "JobState": "COMPLETED",
            "ExitCode": "0:0",
            "DerivedExitCode": "0:0",
            "Requeue": "0",
            "Restarts": "0",
            "Partition": slurm["partition"],
            "NumNodes": "1",
            "NumCPUs": "1",
            "NumTasks": "1",
            "CPUs/Task": "1",
            "MinMemoryNode": "8G",
            "TimeLimit": "01:00:00",
            "WorkDir": slurm["work_dir"],
            "StdOut": slurm["stdout_path"],
            "StdErr": slurm["stderr_path"],
            "Command": slurm["compute_script_path"],
            "BatchHost": "wmi-node01",
            "Comment": slurm["compute_comment"],
            "Dependency": "(null)",
        }

        def encode(record: dict[str, str], fields: tuple[str, ...]) -> bytes:
            return ("|".join(record[field] for field in fields) + "\n").encode(
                "ascii"
            )

        def runner(argv):
            command = tuple(argv)
            if "--allocations" in command:
                stdout = encode(allocation, finalizer_contract.ALLOCATION_FIELDS)
            elif any(item.startswith("--format=") for item in command):
                stdout = encode(batch, finalizer_contract.BATCH_FIELDS)
            else:
                stdout = (
                    " ".join(f"{key}={value}" for key, value in control.items())
                    + "\n"
                ).encode("ascii")
            return finalizer_contract.CommandOutput(command, 0, stdout, b"")

        return runner

    def _publish_compute_candidate(self, submission_path: Path) -> dict[str, object]:
        submission = json.loads(submission_path.read_bytes())
        slurm = submission["slurm"]
        root = Path(submission["candidate_root"])
        root.mkdir(mode=0o700)
        (root / "logs").mkdir(mode=0o700)
        semantic = {
            "schema": finalizer_contract.SEMANTIC_SCHEMA,
            "status": "validated_candidate",
            "decision": finalizer_contract.NONAUTHORIZING_DECISION,
            "stage0b_authority": False,
            "revision": submission["revision"],
            "launch_manifest_sha256": submission["launch_manifest_sha256"],
            "job_id": slurm["compute_job_id"],
            "resource_contract": {
                "cpus": 1,
                "memory_bytes": 8 * 1024**3,
                "sat_calls": 0,
            },
            "projection": {"outcome": "compiled", "proof_nodes": 17},
        }
        semantic_path = root / "metadata.json"
        self._write_candidate_file(
            semantic_path,
            finalizer_contract.canonical_json_bytes(semantic),
            0o400,
        )
        self._write_candidate_file(root / "logs/project.stdout", b"projected\n", 0o400)
        self._write_candidate_file(root / "logs/project.stderr", b"", 0o400)
        self._write_candidate_file(
            root / "candidate.bin", b"ELF integration candidate\n", 0o500
        )
        roles = {
            "candidate.bin": "binary",
            "logs/project.stderr": "project_stderr",
            "logs/project.stdout": "project_stdout",
            "metadata.json": "validation_candidate",
        }
        artifacts = []
        for relative, role in roles.items():
            path = root / relative
            payload = path.read_bytes()
            artifacts.append(
                {
                    "role": role,
                    "path_rel": relative,
                    "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}",
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
        artifacts.sort(key=lambda record: record["role"])
        index = {
            "schema": finalizer_contract.CANDIDATE_SCHEMA,
            "status": "candidate_complete",
            "decision": finalizer_contract.NONAUTHORIZING_DECISION,
            "stage0b_authority": False,
            "classification": "scientific_candidate",
            "candidate_outcome": "accept",
            "reason": None,
            "intended_exit_code": 0,
            "attempt": {
                "run_nonce": submission["run_nonce"],
                "cluster": slurm["cluster"],
                "job_id": slurm["compute_job_id"],
                "array_job_id": None,
                "array_task_id": None,
                "step_id": "batch",
                "restart_count": 0,
                "hostname": "wmi-node01",
                "submit_dir": slurm["work_dir"],
            },
            "revision": submission["revision"],
            "launch_manifest_sha256": submission["launch_manifest_sha256"],
            "validation_candidate_sha256": hashlib.sha256(
                semantic_path.read_bytes()
            ).hexdigest(),
            "root_mode": "0500",
            "semantic_metadata_path": "metadata.json",
            "artifacts": artifacts,
            "missing_expected": [],
        }
        self._write_candidate_file(
            root / finalizer_contract.COMPUTE_INDEX_NAME,
            finalizer_contract.canonical_json_bytes(index),
            0o400,
        )
        (root / "logs").chmod(0o500)
        root.chmod(0o500)
        scheduler_candidate = finalizer_contract.build_scheduler_candidate_payload(
            submission_path,
            root,
            command_runner=self._compute_scheduler_runner(submission),
            sacct_bin="/proc/self/fd/51",
            scontrol_bin="/proc/self/fd/52",
            submission_sha256=sha256(submission_path),
        )
        candidate_path = Path(submission["scheduler_candidate_path"])
        candidate_path.write_bytes(
            finalizer_contract.canonical_json_bytes(scheduler_candidate)
        )
        candidate_path.chmod(0o400)
        return submission

    def _write_finalizer_sacct(self, submission: dict[str, object]) -> None:
        slurm = submission["slurm"]
        job_id = slurm["finalizer_job_id"]
        state = {
            "allocation": {
                "Cluster": slurm["cluster"],
                "DBIndex": "9001",
                "JobIDRaw": str(job_id),
                "JobName": slurm["finalizer_job_name"],
                "User": "test",
                "UID": str(os.getuid()),
                "State": "COMPLETED",
                "ExitCode": "0:0",
                "DerivedExitCode": "0:0",
                "Submit": "2026-07-19T10:00:00",
                "Eligible": "2026-07-19T10:00:10",
                "Start": "2026-07-19T10:00:12",
                "End": "2026-07-19T10:00:20",
                "ElapsedRaw": "8",
                "Partition": slurm["partition"],
                "NodeList": "wmi-node02",
                "NNodes": "1",
                "ReqCPUS": "1",
                "AllocCPUS": "1",
                "ReqMem": "1Gn",
                "ReqTRES": "cpu=1,mem=1G,node=1,billing=1",
                "AllocTRES": "cpu=1,mem=1G,node=1,billing=1",
                "TimelimitRaw": "10",
                "Comment": slurm["finalizer_comment"],
                "SubmitLine": " ".join(slurm["finalizer_sbatch_argv"]),
                "WorkDir": slurm["finalizer_work_dir"],
                "StdOut": slurm["finalizer_stdout_path"],
                "StdErr": slurm["finalizer_stderr_path"],
                "Requeue": "0",
                "Restarts": "0",
            },
            "batch": {
                "Cluster": slurm["cluster"],
                "DBIndex": "9001",
                "JobIDRaw": f"{job_id}.batch",
                "JobName": "batch",
                "State": "COMPLETED",
                "ExitCode": "0:0",
                "DerivedExitCode": "",
                "Submit": "2026-07-19T10:00:10",
                "Start": "2026-07-19T10:00:12",
                "End": "2026-07-19T10:00:20",
                "ElapsedRaw": "8",
                "NodeList": "wmi-node02",
                "NNodes": "1",
                "ReqCPUS": "1",
                "AllocCPUS": "1",
                "AllocTRES": "cpu=1,mem=1G,node=1,billing=1",
            },
        }
        (self.state_root / "finalizer-sacct.json").write_text(
            json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )

    def test_success_publishes_canonical_record_then_releases_finalizer_first(self) -> None:
        completed = self._submit()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        campaign = (
            self.run_base
            / "t11-stage0a-submission-0123456789abcdef0123456789abcdef"
        )
        record_path = campaign / "control" / "submission.json"
        orchestration_path = campaign / "control" / "submission-orchestration.json"
        authorization_request_path = campaign / "control" / "authorization-request.json"
        decision_path = campaign / "stage0b-decision.json"
        encoded = record_path.read_bytes()
        record = json.loads(encoded)
        self.assertEqual(
            encoded,
            (
                json.dumps(
                    record,
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("ascii"),
        )
        self.assertEqual(stat.S_IMODE(record_path.stat().st_mode), 0o400)
        self.assertEqual(
            set(record),
            {
                "schema",
                "run_nonce",
                "revision",
                "launch_manifest_sha256",
                "candidate_root",
                "scheduler_candidate_path",
                "final_decision_path",
                "control",
                "slurm",
            },
        )
        self.assertEqual(
            set(record["control"]),
            {
                "submit_wrapper_sha256",
                "compute_script_sha256",
                "finalizer_script_sha256",
                "finalizer_sha256",
                "authorizer_sha256",
                "authorization_request_executor_sha256",
                "validator_sha256",
                "exec_helper_sha256",
                "controller_python_sha256",
                "git_sha256",
                "sbatch_sha256",
                "scontrol_sha256",
                "scancel_sha256",
                "sacct_sha256",
            },
        )
        self.assertEqual(
            set(record["slurm"]),
            {
                "cluster",
                "owner_uid",
                "compute_job_id",
                "finalizer_job_id",
                "finalizer_dependency",
                "compute_job_name",
                "compute_comment",
                "finalizer_job_name",
                "finalizer_comment",
                "partition",
                "requested_nodes",
                "requested_cpus",
                "requested_memory_bytes",
                "timelimit_seconds",
                "work_dir",
                "stdout_path",
                "stderr_path",
                "compute_script_path",
                "finalizer_requested_nodes",
                "finalizer_requested_cpus",
                "finalizer_requested_memory_bytes",
                "finalizer_timelimit_seconds",
                "finalizer_work_dir",
                "finalizer_stdout_path",
                "finalizer_stderr_path",
                "finalizer_script_path",
                "compute_sbatch_argv",
                "finalizer_sbatch_argv",
                "compute_held_record",
                "finalizer_held_record",
            },
        )
        self.assertEqual(finalizer_contract.validate_submission(record), record)
        self.assertEqual(record["slurm"]["compute_job_id"], 4101)
        self.assertEqual(record["slurm"]["finalizer_job_id"], 4102)
        self.assertEqual(record["slurm"]["finalizer_dependency"], "afterany:4101")
        self.assertEqual(
            record["candidate_root"],
            str(self.run_base.resolve() / "t11-stage0a-4101"),
        )
        self.assertNotIn("%j", record["slurm"]["stdout_path"])
        self.assertNotIn("%j", record["slurm"]["stderr_path"])
        self.assertEqual(
            record["control"]["finalizer_script_sha256"],
            sha256(self.finalizer_runner),
        )
        self.assertEqual(record["control"]["finalizer_sha256"], sha256(self.finalizer))
        self.assertEqual(record["control"]["authorizer_sha256"], sha256(self.authorizer))
        self.assertEqual(
            record["control"]["authorization_request_executor_sha256"],
            sha256(self.authorization_request_executor),
        )
        self.assertEqual(
            record["launch_manifest_sha256"], sha256(self.manifest)
        )
        orchestration = json.loads(orchestration_path.read_bytes())
        self.assertEqual(orchestration["status"], "submitted_held")
        self.assertEqual(orchestration["revision"], self.revision)
        self.assertEqual(
            orchestration["slurm"]["release_order"], ["finalizer", "compute"]
        )
        self.assertTrue(orchestration["slurm"]["held_at_publication"])
        self.assertEqual(
            orchestration["submission"]["sha256"], hashlib.sha256(encoded).hexdigest()
        )
        self.assertEqual(
            (self.state_root / "release.log").read_text().splitlines(),
            ["4102", "4101"],
        )
        self.assertFalse((self.state_root / "cancel.log").exists())
        outputs = dict(
            line.split("=", 1)
            for line in completed.stdout.splitlines()
            if "=" in line
        )
        self.assertEqual(
            outputs["t11_stage0a_submission_record"], str(record_path.resolve())
        )
        self.assertEqual(
            outputs["t11_stage0a_submission_sha256"], hashlib.sha256(encoded).hexdigest()
        )
        self.assertEqual(
            outputs["t11_stage0a_scheduler_candidate"],
            record["scheduler_candidate_path"],
        )
        self.assertEqual(
            outputs["t11_stage0a_authorization_output"],
            record["final_decision_path"],
        )
        self.assertEqual(
            outputs["t11_stage0a_authorization_output_sha256"],
            sha256(decision_path),
        )
        self.assertEqual(
            outputs["t11_stage0a_authorization_status"], "stage0b_authorized"
        )
        self.assertEqual(outputs["t11_stage0a_authorizer_sha256"], sha256(self.authorizer))
        request_bytes = authorization_request_path.read_bytes()
        request = json.loads(request_bytes)
        self.assertEqual(
            request_bytes,
            (
                json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("ascii"),
        )
        self.assertEqual(
            request["schema"], "euf-viper.t11-stage0a-authorization-request.v3"
        )
        self.assertEqual(request["submission"]["sha256"], hashlib.sha256(encoded).hexdigest())
        self.assertEqual(
            request["poll"], {"attempts": "17280", "interval_seconds": "5"}
        )
        self.assertEqual(request["argv"][0], str(self.python))
        self.assertEqual(request["argv"][4], "-c")
        compile(request["argv"][5], "authorization-bootstrap", "exec")
        self.assertIn("os.memfd_create", request["argv"][5])
        self.assertIn("executed controller Python digest mismatch", request["argv"][5])
        self.assertIn("sealed authorizer", request["argv"][5])
        self.assertIn("--submission-sha256", request["argv"])
        self.assertEqual(
            outputs["t11_stage0a_authorization_request"],
            str(authorization_request_path.resolve()),
        )
        self.assertEqual(
            outputs["t11_stage0a_authorization_request_sha256"],
            hashlib.sha256(request_bytes).hexdigest(),
        )
        self.assertEqual(
            outputs["t11_stage0a_authorization_request_executor"],
            str(
                (
                    campaign
                    / "control/execute_t11_stage0a_authorization_request.py"
                ).resolve()
            ),
        )
        self.assertEqual(
            outputs["t11_stage0a_authorization_request_executor_sha256"],
            sha256(self.authorization_request_executor),
        )

        calls = [
            json.loads(line)
            for line in (self.state_root / "sbatch.jsonl").read_text().splitlines()
        ]
        self.assertEqual(len(calls), 2)
        self.assertIn("--hold", calls[0])
        self.assertIn("--no-requeue", calls[0])
        self.assertIn("--clusters=testcluster", calls[0])
        self.assertIn("--clusters=testcluster", calls[1])
        self.assertIn("--dependency=afterany:4101", calls[1])
        self.assertIn("--kill-on-invalid-dep=yes", calls[1])
        compute_export = next(value for value in calls[0] if value.startswith("--export="))
        self.assertIn(
            "EUF_VIPER_T11_RUN_NONCE=0123456789abcdef0123456789abcdef",
            compute_export,
        )
        self.assertIn("SLURM_CLUSTER_NAME=testcluster", compute_export)
        self.assertIn("SLURM_RESTART_COUNT=0", compute_export)
        self.assertTrue(any(value.startswith("--output=") for value in calls[0]))
        self.assertTrue(any(value.startswith("--error=") for value in calls[1]))
        self.assertFalse(self._jobs()["4101"]["held"])
        self.assertFalse(self._jobs()["4102"]["held"])
        decision = json.loads(decision_path.read_bytes())
        self.assertEqual(decision["decision"], "authorize_stage0b")
        self.assertTrue(decision["stage0b_authority"])
        invocation = json.loads(
            (self.state_root / "authorization-invocation.json").read_text(
                encoding="ascii"
            )
        )
        self.assertEqual(invocation["poll_attempts"], "17280")
        self.assertEqual(invocation["poll_interval_seconds"], "5")
        self.assertEqual(invocation["sacct_bin"], os.fspath(self.fake_bin / "sacct"))

    def test_submit_control_environment_drops_hostile_inherited_values(self) -> None:
        completed = self._submit(
            GIT_CONFIG_GLOBAL="/poison/gitconfig",
            LD_LIBRARY_PATH="/poison/lib",
            PYTHONPATH="/poison/python",
            SLURM_CONF="/poison/slurm.conf",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        observed = json.loads(
            (self.state_root / "control-environment.json").read_text(
                encoding="ascii"
            )
        )
        self.assertEqual(
            observed,
            {
                "GIT_CONFIG_GLOBAL": None,
                "LD_LIBRARY_PATH": None,
                "PYTHONPATH": None,
                "SLURM_CONF": None,
            },
        )

    def test_authorization_poll_configuration_reaches_request_and_authorizer(self) -> None:
        completed = self._submit(
            EUF_VIPER_T11_FINALIZER_POLL_ATTEMPTS="37",
            EUF_VIPER_T11_FINALIZER_POLL_INTERVAL_SECONDS="0.25",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        campaign = (
            self.run_base
            / "t11-stage0a-submission-0123456789abcdef0123456789abcdef"
        )
        request = json.loads(
            (campaign / "control/authorization-request.json").read_bytes()
        )
        self.assertEqual(
            request["poll"], {"attempts": "37", "interval_seconds": "0.25"}
        )
        invocation = json.loads(
            (self.state_root / "authorization-invocation.json").read_text(
                encoding="ascii"
            )
        )
        self.assertEqual(invocation["poll_attempts"], "37")
        self.assertEqual(invocation["poll_interval_seconds"], "0.25")

    def test_authorization_failure_cancels_both_proven_owned_jobs(self) -> None:
        (self.state_root / "authorization-fail").write_text(
            "fail\n", encoding="ascii"
        )
        completed = self._submit()
        self.assertEqual(completed.returncode, 2)
        self.assertIn("authorization request execution failed", completed.stderr)
        self.assertEqual(
            (self.state_root / "cancel.log").read_text().splitlines(),
            ["4102", "4101"],
        )
        jobs = self._jobs()
        self.assertTrue(jobs["4101"]["canceled"])
        self.assertTrue(jobs["4102"]["canceled"])

    def test_authorization_request_digest_tamper_fails_closed(self) -> None:
        completed = self._submit(TEST_TAMPER_AUTHORIZATION_REQUEST="digest")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("SHA-256 differs from the caller binding", completed.stderr)
        self.assertIn("authorization request execution failed", completed.stderr)
        self.assertEqual(
            (self.state_root / "cancel.log").read_text().splitlines(),
            ["4102", "4101"],
        )

    def test_authorization_request_argv_tamper_fails_closed(self) -> None:
        completed = self._submit(TEST_TAMPER_AUTHORIZATION_REQUEST="argv")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("SHA-256 differs from the caller binding", completed.stderr)
        self.assertEqual(
            (self.state_root / "cancel.log").read_text().splitlines(),
            ["4102", "4101"],
        )

    def test_finalizer_submission_failure_cancels_only_proven_compute(self) -> None:
        completed = self._submit(TEST_SBATCH_FAIL_ROLE="finalizer")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("held afterany finalizer submission failed", completed.stderr)
        self.assertEqual(
            (self.state_root / "cancel.log").read_text().splitlines(), ["4101"]
        )
        self.assertFalse((self.state_root / "release.log").exists())
        self.assertTrue(self._jobs()["4101"]["held"])

    def test_release_polls_through_transient_none_reason(self) -> None:
        completed = self._submit(TEST_SCONTROL_TRANSIENT_NONE_READS="3")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertGreaterEqual(
            int((self.state_root / "dependency-shows-4102").read_text()), 4
        )

    def test_held_finalizer_dependency_mismatch_fails_before_release(self) -> None:
        completed = self._submit(TEST_SCONTROL_DEPENDENCY_OVERRIDE="afterany:9999")
        self.assertEqual(completed.returncode, 2)
        self.assertIn(
            "finalizer ownership or held state could not be established",
            completed.stderr,
        )
        self.assertFalse((self.state_root / "release.log").exists())

    def test_identity_drift_retains_unowned_compute_and_cancels_owned_finalizer(self) -> None:
        completed = self._submit(TEST_SCONTROL_MISMATCH_AFTER="3")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("scheduler identity drifted before release", completed.stderr)
        self.assertIn("retaining job 4101", completed.stderr)
        self.assertEqual(
            (self.state_root / "cancel.log").read_text().splitlines(), ["4102"]
        )
        self.assertFalse((self.state_root / "release.log").exists())
        jobs = self._jobs()
        self.assertTrue(jobs["4101"]["held"])
        self.assertFalse(jobs["4101"]["canceled"])
        self.assertTrue(jobs["4102"]["canceled"])

    @unittest.skipUnless(
        sys.platform.startswith("linux") and hasattr(os, "memfd_create"),
        "end-to-end authorization requires Linux memfd support",
    )
    def test_linux_submission_consumes_request_through_sealed_authorizer(self) -> None:
        completed = self._submit()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        campaign = (
            self.run_base.resolve()
            / "t11-stage0a-submission-0123456789abcdef0123456789abcdef"
        )
        request_path = campaign / "control/authorization-request.json"
        request = json.loads(request_path.read_bytes())
        decision_path = Path(request["output_path"])
        decision = json.loads(decision_path.read_bytes())
        invocation = json.loads(
            (self.state_root / "authorization-invocation.json").read_text(
                encoding="ascii"
            )
        )
        self.assertEqual(decision["status"], "stage0b_authorized")
        self.assertEqual(decision["decision"], "authorize_stage0b")
        self.assertTrue(decision["stage0b_authority"])
        self.assertEqual(stat.S_IMODE(decision_path.stat().st_mode), 0o400)
        self.assertEqual(invocation["poll_attempts"], request["poll"]["attempts"])
        self.assertEqual(
            invocation["poll_interval_seconds"],
            request["poll"]["interval_seconds"],
        )
        self.assertFalse((self.state_root / "sacct-invocations.jsonl").exists())

    @unittest.skipUnless(
        sys.platform.startswith("linux") and hasattr(os, "memfd_create"),
        "sealed authorization execution requires Linux memfd support",
    )
    def test_linux_authorizer_replacement_before_consumption_fails_closed(self) -> None:
        completed = self._submit(TEST_REPLACE_AUTHORIZER_AFTER_RELEASE="1")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("authorizer SHA-256 differs from the request", completed.stderr)
        self.assertNotIn("replacement executed", completed.stderr)
        self.assertEqual(
            (self.state_root / "cancel.log").read_text().splitlines(),
            ["4102", "4101"],
        )
    @unittest.skipUnless(
        sys.platform.startswith("linux") and hasattr(os, "memfd_create"),
        "sealed finalizer execution requires Linux memfd support",
    )
    def test_linux_finalizer_wrapper_executes_the_public_cli(self) -> None:
        submitted = self._submit()
        self.assertEqual(submitted.returncode, 0, submitted.stderr)
        calls = [
            json.loads(line)
            for line in (self.state_root / "sbatch.jsonl").read_text().splitlines()
        ]
        finalizer_export = next(
            value.removeprefix("--export=")
            for value in calls[1]
            if value.startswith("--export=")
        )
        environment = os.environ.copy()
        for assignment in finalizer_export.split(","):
            name, value = assignment.split("=", 1)
            environment[name] = value
        environment.update(
            {
                "SLURM_CLUSTER_NAME": "testcluster",
                "SLURM_JOB_ID": "4102",
            }
        )
        campaign = (
            self.run_base.resolve()
            / "t11-stage0a-submission-0123456789abcdef0123456789abcdef"
        )
        candidate_path = campaign / "scheduler-candidate.json"
        candidate_path.chmod(0o600)
        candidate_path.unlink()
        runner = campaign / "control/euf_viper_t11_stage0a_finalize.sbatch"
        completed = subprocess.run(
            ["bash", str(runner)],
            cwd=self.run_base,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        invocation = json.loads((campaign / "scheduler-candidate.json").read_text())
        self.assertEqual(
            invocation["candidate_root"],
            str(self.run_base.resolve() / "t11-stage0a-4101"),
        )
        self.assertEqual(invocation["poll_attempts"], "17280")
        self.assertEqual(invocation["poll_interval_seconds"], "5")
        self.assertRegex(invocation["sacct_bin"], r"\A/proc/self/fd/[0-9]+\Z")
        self.assertRegex(invocation["scontrol_bin"], r"\A/proc/self/fd/[0-9]+\Z")
        self.assertEqual(invocation["submission_sha256"], sha256(campaign / "control/submission.json"))
        decision = json.loads((campaign / "stage0b-decision.json").read_bytes())
        self.assertEqual(decision["decision"], "authorize_stage0b")
        self.assertTrue(decision["stage0b_authority"])


if __name__ == "__main__":
    unittest.main()
