from __future__ import annotations

import copy
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "wmi" / "euf_viper_t11_stage0a.sbatch"
VALIDATOR = ROOT / "scripts" / "bench" / "validate_t11_stage0a.py"


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_t11_stage0a", VALIDATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class T11Stage0AWmiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = SCRIPT.read_text(encoding="ascii")

    def test_script_is_valid_bash_and_single_core_no_sat(self) -> None:
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
        self.assertIn("#SBATCH --cpus-per-task=1", self.text)
        self.assertIn("#SBATCH --mem=8G", self.text)
        self.assertIn("euf-viper.t11-prebuilt-bundle.v1", self.text)
        self.assertIn("euf-viper.t11-prebuilt-materialization.v1", self.text)
        self.assertIn("candidate_sealed_before_exec", VALIDATOR.read_text(encoding="ascii"))
        for forbidden in (
            "RUSTUP_TOOLCHAIN",
            "CARGO_HOME",
            "RUSTUP_HOME",
            "cargo build",
            "source-tree",
            "rust-sysroot",
            "native-compiler",
        ):
            self.assertNotIn(forbidden, self.text)
        for namespace_option in (
            '"--user"',
            '"--map-root-user"',
            '"--mount"',
            '"--fork"',
        ):
            self.assertIn(namespace_option, self.text)
        self.assertIn("--make-rprivate /", self.text)
        self.assertIn("-t tmpfs -o nodev,nosuid", self.text)
        self.assertIn("prebuilt state escaped its mount namespace", self.text)
        self.assertIn("euf-viper.t11-prebuilt-materialization.v1", self.text)
        self.assertIn("project-t11", self.text)
        self.assertIn("audit-t11", self.text)
        self.assertIn("exec_t11_stage0a.py", self.text)
        self.assertIn('sealed_exec_request "$PROJECT_REQUEST"', self.text)
        self.assertIn('sealed_exec_request "$AUDIT_REQUEST"', self.text)
        self.assertIn('sealed_exec_request "$VALIDATION_REQUEST"', self.text)
        self.assertIn("--request-fd", self.text)
        self.assertIn("--self-fd", self.text)
        self.assertNotIn('pinned_python "$EXEC_HELPER', self.text)
        self.assertNotIn("compare_solvers.py", self.text)
        self.assertNotIn("YICES", self.text)
        self.assertNotIn("Z3", self.text)

    def test_exact_revision_toolchain_target_and_baseline_are_frozen(self) -> None:
        for required in (
            "EUF_VIPER_T11_LAUNCH_MANIFEST:?",
            "EUF_VIPER_T11_LAUNCH_MANIFEST_SHA256:?",
            "inspect-launch",
            "clean_git status --porcelain=v1 --untracked-files=all",
            "clean_git rev-parse HEAD^{tree}",
            "QF_UF_sokoban.2.prop1_ab_br_max.smt2",
            "cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112",
            "2fa9cabb8279cf59a9ca73cd254c0c60fe028753e8aa01d1794dd0c645167496",
            "adb6885f8ee5d5230e81a3293d183bd4ae14d985f3df5bba9bc6c9fcd9fb1bb0",
            "652e7b303accb7396dd9dfd5fdf40d17abd523f4a87897609390b6aa94d33597",
        ):
            self.assertIn(required, self.text)
        for forbidden in (
            "EUF_VIPER_EXPECTED_REVISION:?",
            "EUF_VIPER_CARGO_SHA256:?",
            "EUF_VIPER_RUSTC_SHA256:?",
            "EUF_VIPER_PYTHON_SHA256:?",
        ):
            self.assertNotIn(forbidden, self.text)

    def test_exit_and_evidence_contract_is_fail_closed(self) -> None:
        self.assertIn('case "$PROJECT_EXIT" in', self.text)
        self.assertIn("4|3) ;;", self.text)
        self.assertIn("projector_rejected 3 -1", self.text)
        self.assertIn('case "$AUDIT_EXIT" in', self.text)
        self.assertIn("external_auditor_rejected 4 3", self.text)
        self.assertIn(
            'die "independent validator rejected the candidate evidence"', self.text
        )
        self.assertIn('die "source identity changed after snapshotting"', self.text)
        self.assertIn('die "bundle identity changed between projection and audit"', self.text)
        self.assertIn('die "binary identity changed after execution"', self.text)
        self.assertIn("euf-viper.t11-stage0a-rejection.v2", self.text)
        self.assertIn(
            "euf-viper.t11-stage0a-infrastructure-rejection.v1", self.text
        )
        self.assertIn("stage0a_exit_trap", self.text)
        self.assertIn("infrastructure-rejection.json", self.text)
        self.assertIn("stop_before_stage0b", self.text)

    def test_outputs_are_external_fresh_immutable_and_directory_synced(self) -> None:
        self.assertIn("EUF_VIPER_T11_RUN_BASE:?", self.text)
        self.assertIn('RUN_ROOT="$RUN_BASE/t11-stage0a-$SLURM_JOB_ID"', self.text)
        self.assertIn('mkdir -m 700 "$RUN_ROOT"', self.text)
        self.assertIn('readonly BINARY="$PROVENANCE_ROOT/euf-viper"', self.text)
        self.assertIn('os.fchmod(output_fd, mode)', self.text)
        self.assertIn(
            "candidate_binary, binary_out, candidate_sha256, 0o500, \"binary\"",
            self.text,
        )
        self.assertIn("chmod -R a-w", self.text)
        self.assertIn("os.O_EXCL", self.text)
        self.assertGreaterEqual(self.text.count('fsync_path "$RUN_BASE"'), 2)
        self.assertIn('fsync_path "$RUN_ROOT"', self.text)
        self.assertNotIn('RUN_ROOT="$PWD/results/', self.text)

    def test_validator_closes_writable_staging_descriptor_before_readback(self) -> None:
        source = VALIDATOR.read_text(encoding="ascii")
        start = source.index("def _write_immutable_json(")
        end = source.index("\ndef ", start + 1)
        implementation = source[start:end]
        linked = implementation.index("os.link(")
        writable_closed = implementation.index("os.close(descriptor)", linked)
        readonly_flags = implementation.index("final_flags = os.O_RDONLY", writable_closed)
        readonly_opened = implementation.index("os.open(", readonly_flags)
        self.assertLess(linked, writable_closed)
        self.assertLess(writable_closed, readonly_flags)
        self.assertLess(readonly_flags, readonly_opened)

    def test_independent_validator_binds_full_evidence(self) -> None:
        for required in (
            "validate_t11_stage0a.py",
            "exec_t11_stage0a.py",
            "--launch-manifest-sha256",
            "--source-before-sha256",
            "--source-after-sha256",
            "--binary-before-sha256",
            "--binary-after-sha256",
            "--bundle-project-sha256",
            "--bundle-audit-sha256",
            "--project-exit",
            "--audit-exit",
            '--artifact bundle "$BUNDLE" @BUNDLE@',
            '--artifact audit_receipt "$RECEIPT" @RECEIPT@',
            '--artifact runner "$RUNNER_SNAPSHOT" @RUNNER@',
            '--artifact submitter "$SUBMITTER" @SUBMITTER@',
            '--artifact finalizer_sbatch "$FINALIZER_SBATCH" @FINALIZER_SBATCH@',
            '--artifact finalizer "$FINALIZER" @FINALIZER@',
            '--artifact authorizer "$AUTHORIZER" @AUTHORIZER@',
            '--artifact authorization_request_executor "$AUTHORIZATION_REQUEST_EXECUTOR" @AUTHORIZATION_REQUEST_EXECUTOR@',
            '--artifact validator "$VALIDATOR" @VALIDATOR@',
            '--artifact exec_helper "$EXEC_HELPER" @EXEC_HELPER@',
            '--artifact control_git "$CONTROL_GIT" @CONTROL_GIT@',
            '--artifact prebuilt_preparer "$PREBUILT_PREPARER" @PREBUILT_PREPARER@',
            '--artifact prebuilt_bundle_tool "$PREBUILT_BUNDLE_TOOL" @PREBUILT_BUNDLE_TOOL@',
            '--artifact prebuilt_bundle_stdout "$PREBUILT_BUNDLE_STDOUT" @PREBUILT_BUNDLE_STDOUT@',
            '--artifact prebuilt_bundle_stderr "$PREBUILT_BUNDLE_STDERR" @PREBUILT_BUNDLE_STDERR@',
            '--artifact prebuilt_bundle "$PREBUILT_BUNDLE" @PREBUILT_BUNDLE@',
            '--artifact prebuilt_preparation "$PREBUILT_PREPARATION" @PREBUILT_PREPARATION@',
            '--artifact python_runtime_inventory "$PYTHON_RUNTIME_INVENTORY" @PYTHON_RUNTIME_INVENTORY@',
            '--artifact build_receipt "$BUILD_RECEIPT" @BUILD_RECEIPT@',
            '--artifact dependency_inventory "$DEPENDENCY_INVENTORY" @DEPENDENCY_INVENTORY@',
            '--artifact launch_manifest "$LAUNCH_MANIFEST" @LAUNCH_MANIFEST@',
            '--artifact python "$PYTHON" @PYTHON_TOOL@',
        ):
            self.assertIn(required, self.text)

    def test_embedded_python_and_line_continuations_are_valid(self) -> None:
        programs = re.findall(r"<<'PY'\n(.*?)\nPY", self.text, flags=re.DOTALL)
        self.assertEqual(len(programs), 10)
        for index, program in enumerate(programs):
            compile(program, f"stage0-embedded-{index}.py", "exec")
        materialization_python = re.findall(
            r"<<'PREBUILT_MATERIALIZATION_REPORT_PY'\n(.*?)\nPREBUILT_MATERIALIZATION_REPORT_PY",
            self.text,
            flags=re.DOTALL,
        )
        self.assertEqual(len(materialization_python), 1)
        compile(
            materialization_python[0],
            "stage0-prebuilt-materialization-report.py",
            "exec",
        )
        materialization_bootstrap = re.findall(
            r"bootstrap_python -c '\n(.*?)\n' \\\n  \"\$UNSHARE_TOOL\"",
            self.text,
            flags=re.DOTALL,
        )
        self.assertEqual(len(materialization_bootstrap), 1)
        compile(
            materialization_bootstrap[0],
            "stage0-prebuilt-materialization-bootstrap.py",
            "exec",
        )
        materialization_shell = re.findall(
            r"<<'PREBUILT_MATERIALIZATION'\n(.*?)\nPREBUILT_MATERIALIZATION\n",
            self.text,
            flags=re.DOTALL,
        )
        self.assertEqual(len(materialization_shell), 1)
        subprocess.run(
            ["bash", "-n"],
            input=materialization_shell[0],
            text=True,
            check=True,
        )
        self.assertIn("while offset < len(data)", self.text)
        self.assertIn("while offset < len(encoded)", self.text)
        self.assertIn("while written < len(encoded)", self.text)
        self.assertIn("short runner-snapshot write", self.text)
        self.assertNotIn("+  ", self.text)


@unittest.skipUnless(
    sys.platform.startswith("linux")
    and Path("/usr/bin/python3").is_file()
    and Path("/proc/self/fd").is_dir()
    and shutil.which("git") is not None,
    "Stage 0A dynamic pipeline tests require Linux, /proc, Python, and Git",
)
class T11Stage0ADynamicPipelineTests(unittest.TestCase):
    TARGET_RELATIVE_PATH = (
        "QF_UF/2018-Goel-hwbench/"
        "QF_UF_sokoban.2.prop1_ab_br_max.smt2"
    )
    POISON = "EUF_VIPER_STAGE0A_INHERITED_POISON"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.fixture_index = 0

    def tearDown(self) -> None:
        for current, directories, files in os.walk(self.root, topdown=True):
            for name in directories:
                try:
                    (Path(current) / name).chmod(0o700)
                except FileNotFoundError:
                    pass
            for name in files:
                try:
                    (Path(current) / name).chmod(0o600)
                except FileNotFoundError:
                    pass
        self.temporary.cleanup()

    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def _write(path: Path, data: str | bytes, mode: int = 0o600) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        encoded = data.encode("ascii") if isinstance(data, str) else data
        path.write_bytes(encoded)
        path.chmod(mode)

    @staticmethod
    def _run_command(argv: list[str], *, cwd: Path) -> str:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={
                "HOME": str(cwd),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
        )
        return completed.stdout.strip()

    def _solver_source(self, python: Path, scenario: str) -> str:
        return textwrap.dedent(
            f"""\
            #!{python}
            import hashlib
            import json
            import os
            import sys

            SCENARIO = {scenario!r}
            POISON = {self.POISON!r}

            def write_fresh(path, payload):
                parent = os.path.dirname(path)
                parent_fd = os.open(
                    parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
                )
                try:
                    descriptor = os.open(
                        os.path.basename(path),
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                        0o600,
                        dir_fd=parent_fd,
                    )
                    try:
                        offset = 0
                        while offset < len(payload):
                            written = os.write(descriptor, payload[offset:])
                            if written <= 0:
                                raise RuntimeError("short fake-solver write")
                            offset += written
                        os.fsync(descriptor)
                        os.fchmod(descriptor, 0o400)
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)

            def emit_binding(path, artifact):
                metadata = os.stat(path, follow_symlinks=False)
                with open(path, "rb") as handle:
                    payload = handle.read()
                binding = {{
                    "artifact": artifact,
                    "bytes": len(payload),
                    "ctime_ns": metadata.st_ctime_ns,
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "links": metadata.st_nlink,
                    "mode": f"{{metadata.st_mode & 0o7777:04o}}",
                    "mtime_ns": metadata.st_mtime_ns,
                    "path": path,
                    "schema": "euf-viper.t11-publication-binding.v1",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }}
                print(json.dumps(binding, sort_keys=True, separators=(",", ":")))

            if POISON in os.environ:
                raise SystemExit(91)
            command = sys.argv[1]
            source = sys.argv[2]
            with open(source, "rb") as handle:
                if handle.read() != b"synthetic-stage0a-target\\n":
                    raise SystemExit(92)

            if command == "project-t11":
                if os.environ.get("EUF_VIPER_T11_EQRES") != "clique-er-auto":
                    raise SystemExit(93)
                output = sys.argv[sys.argv.index("--bundle-out") + 1]
                write_fresh(output, b"BUNDLE\\n")
                emit_binding(output, "bundle")
                if SCENARIO == "project_reject":
                    raise SystemExit(3)
                raise SystemExit(4)

            if command == "audit-t11":
                if "EUF_VIPER_T11_EQRES" in os.environ:
                    raise SystemExit(94)
                bundle = sys.argv[sys.argv.index("--bundle") + 1]
                with open(bundle, "rb") as handle:
                    if handle.read() != b"BUNDLE\\n":
                        raise SystemExit(95)
                if SCENARIO == "replace_bundle":
                    bundle_path = os.path.join(
                        os.path.dirname(os.environ["HOME"]),
                        "projection-bundle.json",
                    )
                    os.unlink(bundle_path)
                    write_fresh(bundle_path, b"REPLACED\\n")
                receipt = sys.argv[sys.argv.index("--receipt-out") + 1]
                write_fresh(receipt, b"RECEIPT\\n")
                emit_binding(receipt, "audit receipt")
                if SCENARIO == "audit_reject":
                    raise SystemExit(3)
                raise SystemExit(0)

            raise SystemExit(96)
            """
        )

    def _validator_source(self, python: Path) -> str:
        artifact_fields = (
            "submitter_sha256",
            "runner_sha256",
            "finalizer_sbatch_sha256",
            "finalizer_sha256",
            "authorizer_sha256",
            "authorization_request_executor_sha256",
            "validator_sha256",
            "exec_helper_sha256",
            "prebuilt_preparer_sha256",
            "prebuilt_bundle_tool_sha256",
            "design_note_sha256",
            "hash_contract_sha256",
            "audit_contract_sha256",
        )
        return textwrap.dedent(
            f"""\
            #!{python}
            import hashlib
            import json
            import os
            import sys

            POISON = {self.POISON!r}
            ARTIFACT_FIELDS = {artifact_fields!r}
            def write_all(descriptor, payload):
                offset = 0
                while offset < len(payload):
                    written = os.write(descriptor, payload[offset:])
                    if written <= 0:
                        raise RuntimeError("short fake-validator write")
                    offset += written

            def value_after(name):
                return sys.argv[sys.argv.index(name) + 1]

            def load_manifest(path, expected):
                with open(path, "rb") as handle:
                    encoded = handle.read()
                if hashlib.sha256(encoded).hexdigest() != expected:
                    raise RuntimeError("manifest hash mismatch")
                return json.loads(encoded)

            if POISON in os.environ:
                raise SystemExit(71)

            if len(sys.argv) > 1 and sys.argv[1] == "inspect-launch":
                manifest = load_manifest(
                    value_after("--launch-manifest"),
                    value_after("--launch-manifest-sha256"),
                )
                if manifest.get("inspect_reject"):
                    print("synthetic manifest contract mismatch", file=sys.stderr)
                    raise SystemExit(3)
                values = [
                    manifest["solver_revision"],
                    manifest["solver_source"]["tree"],
                    manifest["toolchain"]["python"]["path"],
                    manifest["toolchain"]["python"]["sha256"],
                    manifest["toolchain"]["python"]["version"],
                ]
                values.extend(manifest["artifacts"][name] for name in ARTIFACT_FIELDS)
                prebuilt = manifest["prebuilt_bundle"]
                values.extend(
                    [
                        prebuilt["path"],
                        prebuilt["sha256"],
                        prebuilt["manifest_sha256"],
                        prebuilt["schema"],
                        prebuilt["source_commit"],
                        prebuilt["source_tree"],
                        prebuilt["candidate_sha256"],
                        str(prebuilt["candidate_bytes"]),
                        prebuilt["build_receipt_sha256"],
                        prebuilt["dependency_inventory_sha256"],
                    ]
                )
                preparation = manifest["prebuilt_preparation"]
                values.extend(
                    [
                        preparation["path"],
                        preparation["sha256"],
                        preparation["schema"],
                        preparation["python_runtime_inventory_path"],
                        preparation["python_runtime_inventory_sha256"],
                    ]
                )
                for label in ("git", "sbatch", "scontrol", "scancel", "sacct"):
                    tool = manifest["control_tools"][label]
                    values.extend([tool["path"], tool["sha256"], tool["version"]])
                output = b"\\0".join(item.encode("ascii") for item in values) + b"\\0"
                write_all(1, output)
                raise SystemExit(0)

            source = value_after("--source")
            bundle = value_after("--bundle")
            receipt = value_after("--receipt")
            with open(source, "rb") as handle:
                if handle.read() != b"synthetic-stage0a-target\\n":
                    raise SystemExit(72)
            with open(bundle, "rb") as handle:
                if handle.read() != b"BUNDLE\\n":
                    raise SystemExit(73)
            with open(receipt, "rb") as handle:
                if handle.read() != b"RECEIPT\\n":
                    raise SystemExit(74)
            if value_after("--project-exit") != "4":
                raise SystemExit(75)
            if value_after("--audit-exit") != "0":
                raise SystemExit(76)
            output = value_after("--metadata-out")
            payload = (
                json.dumps(
                    {{
                        "schema": "euf-viper.t11-stage0a-dynamic-test.v1",
                        "status": "validated_candidate",
                        "decision": "requires_scheduler_finalization",
                        "stage0b_authority": False,
                        "environment_isolated": True,
                    }},
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\\n"
            ).encode("ascii")
            parent_fd = os.open(
                os.path.dirname(output), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            )
            try:
                descriptor = os.open(
                    os.path.basename(output),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                    0o600,
                    dir_fd=parent_fd,
                )
                try:
                    write_all(descriptor, payload)
                    os.fsync(descriptor)
                    os.fchmod(descriptor, 0o400)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            metadata = os.stat(output, follow_symlinks=False)
            binding = {{
                "artifact": "validation metadata",
                "bytes": len(payload),
                "ctime_ns": metadata.st_ctime_ns,
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "links": metadata.st_nlink,
                "mode": f"{{metadata.st_mode & 0o7777:04o}}",
                "mtime_ns": metadata.st_mtime_ns,
                "path": output,
                "schema": "euf-viper.t11-publication-binding.v1",
                "sha256": hashlib.sha256(payload).hexdigest(),
            }}
            print(json.dumps(binding, sort_keys=True, separators=(",", ":")))
            """
        )

    def _make_fixture(
        self,
        scenario: str,
        *,
        inspect_reject: bool = False,
        mutate_prebuilt_after_manifest: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        self.fixture_index += 1
        case = self.root / f"case-{self.fixture_index}-{scenario}"
        repo = case / "repo"
        run_base = case / "runs"
        corpus = case / "corpus"
        tools = case / "tools"
        for directory in (
            repo,
            run_base,
            corpus,
            tools,
        ):
            directory.mkdir(parents=True, mode=0o700, exist_ok=True)

        python = Path(os.path.realpath("/usr/bin/python3"))
        python_version_result = subprocess.run(
            [str(python), "--version"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        python_version = python_version_result.stdout.strip()

        target = corpus / self.TARGET_RELATIVE_PATH
        self._write(target, b"synthetic-stage0a-target\n", 0o400)
        target_sha256 = self._sha256(target)
        runner_text, replacements = re.subn(
            r'readonly TARGET_SHA256="[0-9a-f]{64}"',
            f'readonly TARGET_SHA256="{target_sha256}"',
            SCRIPT.read_text(encoding="ascii"),
            count=1,
        )
        self.assertEqual(replacements, 1)

        runner = repo / "scripts/wmi/euf_viper_t11_stage0a.sbatch"
        submitter = repo / "scripts/wmi/submit_t11_stage0a.sh"
        finalizer_sbatch = repo / "scripts/wmi/euf_viper_t11_stage0a_finalize.sbatch"
        finalizer = repo / "scripts/bench/finalize_t11_stage0a.py"
        authorizer = repo / "scripts/bench/authorize_t11_stage0a.py"
        authorization_request_executor = (
            repo / "scripts/bench/execute_t11_stage0a_authorization_request.py"
        )
        validator = repo / "scripts/bench/validate_t11_stage0a.py"
        exec_helper = repo / "scripts/bench/exec_t11_stage0a.py"
        prebuilt_preparer = repo / "scripts/bench/prepare_t11_prebuilt.py"
        prebuilt_bundle_tool = repo / "scripts/bench/t11_build_closure.py"
        candidate = tools / "euf-viper"
        self._write(runner, runner_text, 0o755)
        self._write(submitter, "#!/bin/sh\nexit 0\n", 0o755)
        self._write(finalizer_sbatch, "#!/bin/sh\nexit 0\n", 0o755)
        self._write(finalizer, "#!/usr/bin/python3\n", 0o755)
        self._write(authorizer, "#!/usr/bin/python3\n", 0o755)
        self._write(authorization_request_executor, "#!/usr/bin/python3\n", 0o755)
        self._write(validator, self._validator_source(python), 0o755)
        self._write(exec_helper, (ROOT / "scripts/bench/exec_t11_stage0a.py").read_bytes(), 0o755)
        self._write(prebuilt_preparer, "#!/usr/bin/python3\n", 0o755)
        self._write(
            prebuilt_bundle_tool,
            (ROOT / "scripts/bench/t11_build_closure.py").read_bytes(),
            0o755,
        )
        self._write(candidate, self._solver_source(python, scenario), 0o755)

        cargo_toml = repo / "Cargo.toml"
        cargo_lock = repo / "Cargo.lock"
        design_note = repo / "research-vault/02-design/2026-07-17-t11-bounded-equality-resolution-compiler.md"
        hash_contract = repo / "research-vault/02-design/2026-07-17-t11-canonical-hash-contract.md"
        audit_contract = repo / "research-vault/02-design/2026-07-17-t11-external-audit-receipt.md"
        self._write(cargo_toml, "[package]\nname='stage0a-fake'\nversion='0.0.0'\n")
        self._write(cargo_lock, "# stage0a fake lock\n")
        self._write(design_note, "stage0a fake design\n")
        self._write(hash_contract, "stage0a fake hash contract\n")
        self._write(audit_contract, "stage0a fake audit contract\n")

        self._run_command(["git", "init", "-q"], cwd=repo)
        self._run_command(["git", "config", "user.name", "Stage0A Test"], cwd=repo)
        self._run_command(
            ["git", "config", "user.email", "stage0a-test@example.invalid"], cwd=repo
        )
        self._run_command(["git", "add", "."], cwd=repo)
        self._run_command(["git", "commit", "-qm", "stage0a fixture"], cwd=repo)
        revision = self._run_command(["git", "rev-parse", "HEAD"], cwd=repo)
        source_tree = self._run_command(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=repo
        )
        candidate_sha256 = self._sha256(candidate)
        dependency_inventory = case / "dependency-inventory.json"
        self._write(
            dependency_inventory,
            (
                json.dumps(
                    {
                        "candidate_sha256": candidate_sha256,
                        "platform": "linux-x86_64",
                        "runtime_files": [
                            {"path": str(python), "sha256": self._sha256(python)}
                        ],
                        "schema": "euf-viper.t11-binary-dependencies.v1",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("ascii"),
        )
        python_runtime_inventory = case / "python-runtime-inventory.json"
        self._write(
            python_runtime_inventory,
            (
                json.dumps(
                    {
                        "candidate_sha256": self._sha256(python),
                        "platform": "linux-x86_64",
                        "runtime_files": [
                            {"path": str(python), "sha256": self._sha256(python)}
                        ],
                        "schema": "euf-viper.t11-binary-dependencies.v1",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("ascii"),
            0o400,
        )
        build_receipt = case / "build-receipt.json"
        self._write(
            build_receipt,
            (
                json.dumps(
                    {
                        "binary_dependencies_sha256": self._sha256(
                            dependency_inventory
                        ),
                        "build_command": [
                            "cargo", "build", "--locked", "--features",
                            "certificates", "--release", "--target",
                            "x86_64-unknown-linux-gnu",
                        ],
                        "candidate_bytes": candidate.stat().st_size,
                        "candidate_sha256": candidate_sha256,
                        "cargo_lock_sha256": self._sha256(cargo_lock),
                        "cargo_toml_sha256": self._sha256(cargo_toml),
                        "features": ["certificates"],
                        "profile": "release",
                        "rust_target": "x86_64-unknown-linux-gnu",
                        "schema": "euf-viper.t11-prebuilt-build-receipt.v1",
                        "source_commit": revision,
                        "source_tree": source_tree,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("ascii"),
        )
        prebuilt_bundle = case / "prebuilt-bundle.tar"
        closure_report = json.loads(
            self._run_command(
                [
                    str(python),
                    str(prebuilt_bundle_tool),
                    "create",
                    "--output",
                    str(prebuilt_bundle),
                    "--source-repository",
                    str(repo),
                    "--input",
                    f"candidate-binary={candidate}",
                    "--input",
                    f"build-receipt={build_receipt}",
                    "--input",
                    f"dependency-inventory={dependency_inventory}",
                ],
                cwd=case,
            )
        )

        prebuilt_preparation = case / "prebuilt-preparation.json"
        self._write(
            prebuilt_preparation,
            b'{"schema":"euf-viper.t11-prebuilt-preparation.v2","status":"verified"}\n',
            0o400,
        )

        artifact_paths = {
            "submitter_sha256": submitter,
            "runner_sha256": runner,
            "finalizer_sbatch_sha256": finalizer_sbatch,
            "finalizer_sha256": finalizer,
            "authorizer_sha256": authorizer,
            "authorization_request_executor_sha256": authorization_request_executor,
            "validator_sha256": validator,
            "exec_helper_sha256": exec_helper,
            "prebuilt_preparer_sha256": prebuilt_preparer,
            "prebuilt_bundle_tool_sha256": prebuilt_bundle_tool,
            "design_note_sha256": design_note,
            "hash_contract_sha256": hash_contract,
            "audit_contract_sha256": audit_contract,
        }
        manifest = {
            "schema": "euf-viper.t11-stage0a-launch.v6",
            "solver_revision": revision,
            "solver_source": {"commit": revision, "tree": source_tree},
            "inspect_reject": inspect_reject,
            "toolchain": {
                "python": {
                    "path": str(python),
                    "sha256": self._sha256(python),
                    "version": python_version,
                },
            },
            "control_tools": {
                label: {
                    "path": str(Path(shutil.which("git") or "").resolve()),
                    "sha256": self._sha256(Path(shutil.which("git") or "").resolve()),
                    "version": self._run_command(
                        [str(Path(shutil.which("git") or "").resolve()), "--version"],
                        cwd=case,
                    ),
                }
                for label in ("git", "sbatch", "scontrol", "scancel", "sacct")
            },
            "prebuilt_bundle": {
                "path": str(prebuilt_bundle),
                "sha256": closure_report["archive_sha256"],
                "manifest_sha256": closure_report["manifest_sha256"],
                "schema": closure_report["schema"],
                "source_commit": closure_report["source_commit"],
                "source_tree": closure_report["source_tree"],
                "candidate_sha256": closure_report["candidate_sha256"],
                "candidate_bytes": candidate.stat().st_size,
                "build_receipt_sha256": closure_report["build_receipt_sha256"],
                "dependency_inventory_sha256": closure_report[
                    "dependency_inventory_sha256"
                ],
            },
            "prebuilt_preparation": {
                "path": str(prebuilt_preparation),
                "python_runtime_inventory_path": str(python_runtime_inventory),
                "python_runtime_inventory_sha256": self._sha256(
                    python_runtime_inventory
                ),
                "schema": "euf-viper.t11-prebuilt-preparation.v2",
                "sha256": self._sha256(prebuilt_preparation),
            },
            "artifacts": {
                name: self._sha256(path) for name, path in artifact_paths.items()
            },
        }
        launch_manifest = case / "launch-manifest.json"
        self._write(
            launch_manifest,
            (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode(
                "ascii"
            ),
            0o400,
        )
        launch_manifest_sha256 = self._sha256(launch_manifest)
        if mutate_prebuilt_after_manifest:
            prebuilt_bundle.chmod(0o600)
            prebuilt_bundle.write_bytes(
                prebuilt_bundle.read_bytes() + b"post-manifest mutation\n"
            )
            prebuilt_bundle.chmod(0o400)

        job_id = str(9100 + self.fixture_index)
        environment = os.environ.copy()
        environment.update(
            {
                "EUF_VIPER_T11_REPO_ROOT": str(repo),
                "EUF_VIPER_T11_RUN_BASE": str(run_base),
                "EUF_VIPER_T11_CORPUS_ROOT": str(corpus),
                "EUF_VIPER_T11_LAUNCH_MANIFEST": str(launch_manifest),
                "EUF_VIPER_T11_LAUNCH_MANIFEST_SHA256": launch_manifest_sha256,
                "EUF_VIPER_T11_RUN_NONCE": f"{self.fixture_index:032x}",
                "SLURM_JOB_ID": job_id,
                "SLURM_CLUSTER_NAME": "stage0a-test-cluster",
                "SLURM_RESTART_COUNT": "0",
                "SLURM_SUBMIT_DIR": str(run_base),
                self.POISON: "must-not-reach-any-executed-tool",
                "PYTHON": "/definitely/not/the/pinned/python",
                "CARGO_HOME": "/definitely/not/the/pinned/cargo-home",
                "RUSTUP_HOME": "/definitely/not/the/pinned/rustup-home",
                "GIT_DIR": "/definitely/not/a/git-dir",
            }
        )
        completed = subprocess.run(
            ["bash", str(runner)],
            cwd=run_base,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        return completed, run_base / f"t11-stage0a-{job_id}"

    def assertSealed(self, path: Path) -> None:
        self.assertTrue(path.exists(), path)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o222, 0, path)

    def test_success_project_4_audit_0_and_inherited_environment_isolation(self) -> None:
        completed, run_root = self._make_fixture("success")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(f"t11_stage0a_root={run_root}", completed.stdout)
        self.assertFalse((run_root / "rejection.json").exists())
        self.assertFalse((run_root / "infrastructure-rejection.json").exists())
        metadata = json.loads((run_root / "metadata.json").read_text(encoding="ascii"))
        self.assertEqual(metadata["decision"], "requires_scheduler_finalization")
        self.assertEqual(metadata["status"], "validated_candidate")
        self.assertFalse(metadata["stage0b_authority"])
        self.assertTrue(metadata["environment_isolated"])
        compute_index = json.loads(
            (run_root / "compute-index.json").read_text(encoding="ascii")
        )
        self.assertEqual(compute_index["status"], "candidate_complete")
        self.assertEqual(
            compute_index["decision"], "requires_scheduler_finalization"
        )
        self.assertFalse(compute_index["stage0b_authority"])
        self.assertNotIn("authorize_stage0b", json.dumps(compute_index))
        self.assertSealed(run_root)
        self.assertSealed(run_root / "metadata.json")
        self.assertSealed(run_root / "compute-index.json")

    def test_scientific_project_and_audit_rejections_are_sealed(self) -> None:
        for scenario, expected_reason in (
            ("project_reject", "projector_rejected"),
            ("audit_reject", "external_auditor_rejected"),
        ):
            with self.subTest(scenario=scenario):
                completed, run_root = self._make_fixture(scenario)
                self.assertEqual(completed.returncode, 3, completed.stderr)
                rejection = json.loads(
                    (run_root / "rejection.json").read_text(encoding="ascii")
                )
                self.assertEqual(rejection["reason"], expected_reason)
                self.assertEqual(rejection["decision"], "stop_before_stage0b")
                self.assertFalse(
                    (run_root / "infrastructure-rejection.json").exists()
                )
                self.assertSealed(run_root)
                self.assertSealed(run_root / "rejection.json")

    def test_manifest_and_tool_mismatches_leave_sealed_infrastructure_records(self) -> None:
        cases = (
            ({"inspect_reject": True}, "strict launch-manifest inspection failed"),
            (
                {"mutate_prebuilt_after_manifest": True},
                "prebuilt bundle SHA-256 mismatch",
            ),
        )
        for options, expected_reason in cases:
            with self.subTest(options=options):
                completed, run_root = self._make_fixture("success", **options)
                self.assertEqual(completed.returncode, 2, completed.stderr)
                record_path = run_root / "infrastructure-rejection.json"
                record = json.loads(record_path.read_text(encoding="ascii"))
                self.assertEqual(record["classification"], "infrastructure")
                self.assertEqual(record["decision"], "stop_before_stage0b")
                self.assertIn(expected_reason, record["reason"])
                self.assertSealed(record_path)
                self.assertSealed(run_root)

    def test_prebuilt_materialization_failure_is_captured_as_infrastructure(self) -> None:
        completed, run_root = self._make_fixture(
            "success", mutate_prebuilt_after_manifest=True
        )
        self.assertNotEqual(completed.returncode, 0, completed.stderr)
        record_path = run_root / "infrastructure-rejection.json"
        record = json.loads(record_path.read_text(encoding="ascii"))
        self.assertEqual(record["classification"], "infrastructure")
        self.assertEqual(record["phase"], "verify_toolchain_and_artifacts")
        self.assertEqual(record["reason"], "prebuilt bundle SHA-256 mismatch")
        self.assertEqual(record["record_file"], record_path.name)
        self.assertSealed(record_path)
        self.assertSealed(run_root)

    def test_bundle_path_replacement_is_an_infrastructure_rejection(self) -> None:
        completed, run_root = self._make_fixture("replace_bundle")
        self.assertEqual(completed.returncode, 2, completed.stderr)
        rejection = json.loads(
            (run_root / "infrastructure-rejection.json").read_text(encoding="ascii")
        )
        self.assertEqual(rejection["classification"], "infrastructure")
        self.assertEqual(
            rejection["reason"], "bundle changed during external audit"
        )
        self.assertEqual((run_root / "projection-bundle.json").read_bytes(), b"REPLACED\n")
        self.assertFalse((run_root / "rejection.json").exists())
        self.assertSealed(run_root)


class T11Stage0AValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.validator = load_validator()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "target.smt2"
        self.source.write_bytes(b"synthetic frozen target\n")
        self.source_sha256 = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.original_target_sha256 = self.validator.TARGET_SHA256
        self.validator.TARGET_SHA256 = self.source_sha256
        self.bundle_path = self.root / "bundle.json"
        self.receipt_path = self.root / "receipt.json"

    def tearDown(self) -> None:
        self.validator.TARGET_SHA256 = self.original_target_sha256
        self.temporary.cleanup()

    @staticmethod
    def _digest(label: str) -> str:
        return hashlib.sha256(label.encode("ascii")).hexdigest()

    def test_prebuilt_receipt_and_runtime_inventory_are_strictly_validated(self) -> None:
        candidate_sha256 = self._digest("candidate")
        source = {"commit": "1" * 40, "tree": "2" * 40}
        dependency_sha256 = self._digest("dependency-inventory")
        prebuilt = {
            "candidate_bytes": 123,
            "candidate_sha256": candidate_sha256,
            "dependency_inventory_sha256": dependency_sha256,
        }
        receipt = {
            "binary_dependencies_sha256": dependency_sha256,
            "build_command": list(self.validator.PREBUILT_BUILD_COMMAND),
            "candidate_bytes": 123,
            "candidate_sha256": candidate_sha256,
            "cargo_lock_sha256": self._digest("Cargo.lock"),
            "cargo_toml_sha256": self._digest("Cargo.toml"),
            "features": ["certificates"],
            "profile": "release",
            "rust_target": "x86_64-unknown-linux-gnu",
            "schema": self.validator.BUILD_RECEIPT_SCHEMA,
            "source_commit": source["commit"],
            "source_tree": source["tree"],
        }
        self.assertEqual(
            self.validator._validate_prebuilt_build_receipt(
                receipt, source, prebuilt
            ),
            receipt,
        )
        forged_receipt = copy.deepcopy(receipt)
        forged_receipt["build_command"] = ["cargo", "build"]
        with self.assertRaisesRegex(
            self.validator.ValidationError, "build_command differs"
        ):
            self.validator._validate_prebuilt_build_receipt(
                forged_receipt, source, prebuilt
            )

        runtime_path = self.root.resolve() / "runtime-dependency"
        runtime_path.write_bytes(b"exact runtime bytes\n")
        runtime_sha256 = hashlib.sha256(runtime_path.read_bytes()).hexdigest()
        inventory = {
            "candidate_sha256": candidate_sha256,
            "platform": "linux-x86_64",
            "runtime_files": [
                {"path": str(runtime_path), "sha256": runtime_sha256}
            ],
            "schema": self.validator.DEPENDENCY_INVENTORY_SCHEMA,
        }
        self.assertEqual(
            self.validator._validate_binary_dependency_inventory(
                inventory, candidate_sha256
            ),
            inventory,
        )
        for count in (0, self.validator.MAX_RUNTIME_FILES + 1):
            oversized = copy.deepcopy(inventory)
            oversized["runtime_files"] = [
                {"path": f"/runtime/{index}", "sha256": "0" * 64}
                for index in range(count)
            ]
            with self.assertRaisesRegex(
                self.validator.ValidationError, "must contain between"
            ):
                self.validator._validate_binary_dependency_inventory(
                    oversized, candidate_sha256
                )
        runtime_path.write_bytes(b"changed runtime bytes\n")
        with self.assertRaisesRegex(
            self.validator.ValidationError, "runtime dependency SHA-256 differs"
        ):
            self.validator._validate_binary_dependency_inventory(
                inventory, candidate_sha256
            )

    def _hashes(self) -> dict[str, str]:
        values = {
            field: self._digest(field) for field in self.validator.INTERNAL_HASH_FIELDS
        }
        values.update({field: self.validator.ZERO_SHA256 for field in self.validator.EXTERNAL_HASH_FIELDS})
        values["source_sha256"] = self.source_sha256
        values["root_cnf_mode_sha256"] = self.validator.ROOT_CNF_MODE_SHA256
        values["atom_map_sha256"] = self.validator.ATOM_MAP_SHA256
        values["baseline_cnf_sha256"] = self.validator.BASELINE_CNF_SHA256
        values["baseline_problem_sha256"] = self.validator.BASELINE_PROBLEM_SHA256
        values["materialized_lemmas_sha256"] = values["lemma_sequence_sha256"]
        return values

    def _counters(self) -> dict[str, object]:
        inputs = {
            "terms": 8_682,
            "baseline_variables": 21_744,
            "baseline_atom_entries": 18_082,
            "baseline_clauses": 89_470,
            "baseline_literal_slots": 147_132,
            "applications": 138,
            "application_pairs": 3_686,
            "maximum_arity": 2,
            "application_argument_slots": 268,
        }
        accepted_rules = dict.fromkeys(self.validator.RULE_COUNTER_FIELDS, 0)
        accepted_rules["reflexivity"] = 1
        accepted_rules["congruence"] = 1
        accepted_rules["conflict"] = 1
        attempted_rules = dict(accepted_rules)
        attempted_rules["seed"] = 1
        search = {
            "attempted_events": attempted_rules,
            "accepted_events": accepted_rules,
            "events_popped": 3,
            "distinct_event_keys_inserted": 3,
            "duplicate_event_keys": 0,
            "worklist_pushes": 3,
            "live_worklist_entries": 0,
            "peak_live_worklist_entries": 1,
            "queued_events_discarded_at_theory_empty": 0,
            "accepted_equality_nodes": 2,
            "accepted_conflict_clauses": 1,
            "proof_parent_references": 2,
            "maximum_proof_depth": 2,
            "accepted_trace_literal_slots": 1,
            "canonical_proof_work_literal_charge": 147_132,
            "retained_antichain_entries": 1,
            "peak_retained_antichain_entries": 1,
            "registered_negative_equality_occurrences": 1,
            "logical_incremental_memory_bytes": 119_420,
            "suppressed_missing_equality_congruence_events": 0,
        }
        pruning = dict.fromkeys(self.validator.PRUNING_COUNTER_FIELDS, 0)
        output = {
            "emitted_lemmas": 1,
            "emitted_literal_slots": 1,
            "emitted_p95_width": 1,
            "emitted_maximum_width": 1,
            "emitted_with_missing_equality_congruence": 1,
        }
        return {"input": inputs, "search": search, "pruning": pruning, "output": output}

    def _records(self) -> tuple[dict[str, object], dict[str, object]]:
        hashes = self._hashes()
        counters = self._counters()
        checker_counters = {
            "replayed_equality_nodes": 2,
            "replayed_conflict_clauses": 1,
            "replayed_emitted_lemmas": 1,
            "replay_failures": 0,
        }
        selector = {
            "mode": "clique-er-auto",
            "facts": dict(self.validator.EXPECTED_SELECTOR_FACTS),
            "decision": {"decision": "selected"},
        }
        compiler = {
            "variant": "ordinary",
            "status": {
                "status": "completed",
                "detail": {
                    "outcome": "lemmas",
                    "output": [{"source_clause_id": 89_470, "clause": [1]}],
                },
            },
            "trace": [
                {
                    "record_kind": "equality",
                    "record": {
                        "event_id": 0,
                        "node_id": 0,
                        "depth": 0,
                        "conclusion": {"left": 0, "right": 0},
                        "side_clause": [],
                        "rule": {
                            "rule": "reflexivity",
                            "premises": {"term": 0},
                        },
                    },
                },
                {
                    "record_kind": "equality",
                    "record": {
                        "event_id": 1,
                        "node_id": 1,
                        "depth": 1,
                        "conclusion": {"left": 1, "right": 2},
                        "side_clause": [],
                        "rule": {
                            "rule": "congruence",
                            "premises": {
                                "applications": [1, 2],
                                "arguments": [
                                    {"argument_index": 0, "parent": 0}
                                ],
                            },
                        },
                    },
                },
                {
                    "record_kind": "conflict",
                    "record": {
                        "event_id": 2,
                        "clause_id": 89_470,
                        "depth": 2,
                        "clause": [1],
                        "rule": {
                            "equality_parent": 1,
                            "negative_source": {
                                "clause": {"id": 0, "origin": "baseline"},
                                "literal_offset": 0,
                            },
                        },
                    },
                },
            ],
            "counters": counters,
            "hashes": hashes,
        }
        _, _, trace_sha256, _ = self.validator._validate_trace(
            compiler["trace"], 1, counters
        )
        hashes["trace_sha256"] = trace_sha256
        emitted_sha256 = self.validator._emitted_clause_digest([[1]])
        hashes["lemma_sequence_sha256"] = emitted_sha256
        hashes["materialized_lemmas_sha256"] = emitted_sha256
        checker = {
            "status": {"status": "accepted"},
            "counters": checker_counters,
            "recomputed_hashes": copy.deepcopy(hashes),
        }
        report = {
            "schema_version": 1,
            "selector": copy.deepcopy(selector),
            "compiler_variant": "ordinary",
            "outcome": "lemmas",
            "counters": copy.deepcopy(counters),
            "checker_counters": copy.deepcopy(checker_counters),
            "cap_attempt": None,
            "forbidden_growth": dict.fromkeys(self.validator.FORBIDDEN_GROWTH_FIELDS, 0),
            "integrity": {
                "baseline_unchanged": True,
                "trace_materialization_equal": True,
                "compiler_checker_agree": True,
                "output_canonical": True,
                "external_audit_accepted": False,
                "off_path_unchanged": False,
            },
            "sat_calls": 0,
            "hashes": copy.deepcopy(hashes),
        }
        bundle = {
            "selector": selector,
            "compiler": compiler,
            "materialized_lemmas": {"end_offsets": [0, 1], "literals": [1]},
            "checker": checker,
            "report": report,
        }
        receipt = {
            "schema_version": 1,
            "exact_bundle_sha256": "",
            "source_sha256": hashes["source_sha256"],
            "baseline_problem_sha256": hashes["baseline_problem_sha256"],
            "trace_sha256": hashes["trace_sha256"],
            "lemma_sequence_sha256": hashes["lemma_sequence_sha256"],
            "materialized_lemmas_sha256": hashes[
                "materialized_lemmas_sha256"
            ],
            "materialized_candidate_sha256": hashes[
                "materialized_candidate_sha256"
            ],
            "hashes": copy.deepcopy(hashes),
            "result": {
                "status": {"status": "accepted"},
                "counters": copy.deepcopy(counters),
                "checker_counters": copy.deepcopy(checker_counters),
                "cap_attempt": None,
                "recomputed_hashes": copy.deepcopy(hashes),
            },
        }
        return bundle, receipt

    @staticmethod
    def _encode(record: object) -> bytes:
        return (json.dumps(record, separators=(",", ":")) + "\n").encode("ascii")

    def _write_records(
        self, bundle: dict[str, object], receipt: dict[str, object]
    ) -> None:
        bundle_bytes = self._encode(bundle)
        receipt["exact_bundle_sha256"] = hashlib.sha256(bundle_bytes).hexdigest()
        self.bundle_path.write_bytes(bundle_bytes)
        self.receipt_path.write_bytes(self._encode(receipt))
        self.bundle_path.chmod(0o400)
        self.receipt_path.chmod(0o400)

    def test_accepts_coherent_full_source_only_evidence(self) -> None:
        bundle, receipt = self._records()
        self._write_records(bundle, receipt)
        result = self.validator.validate_evidence(
            source_path=self.source,
            bundle_path=self.bundle_path,
            receipt_path=self.receipt_path,
        )
        self.assertEqual(result["outcome"], "lemmas")
        self.assertEqual(result["checker_counters"]["replay_failures"], 0)
        self.assertEqual(result["hashes"]["source_sha256"], self.source_sha256)

    def test_rejects_reversed_json_object_fields(self) -> None:
        for record_name in ("bundle", "receipt"):
            with self.subTest(record=record_name):
                bundle, receipt = self._records()
                if record_name == "bundle":
                    bundle = dict(reversed(tuple(bundle.items())))
                else:
                    receipt = dict(reversed(tuple(receipt.items())))
                self._write_records(bundle, receipt)
                with self.assertRaisesRegex(
                    self.validator.ValidationError,
                    "fields are not in canonical Rust serialization order",
                ):
                    self.validator.validate_evidence(
                        source_path=self.source,
                        bundle_path=self.bundle_path,
                        receipt_path=self.receipt_path,
                    )
                self.bundle_path.chmod(0o600)
                self.receipt_path.chmod(0o600)

    def test_rejects_integer_in_boolean_integrity_field(self) -> None:
        bundle, receipt = self._records()
        bundle["report"]["integrity"]["baseline_unchanged"] = 1
        self._write_records(bundle, receipt)
        with self.assertRaisesRegex(
            self.validator.ValidationError,
            r"report\.integrity\.baseline_unchanged must be a Boolean",
        ):
            self.validator.validate_evidence(
                source_path=self.source,
                bundle_path=self.bundle_path,
                receipt_path=self.receipt_path,
            )

    def test_rejects_every_frozen_search_cap_overflow(self) -> None:
        self.assertIn(
            "canonical_proof_work_literal_charge", self.validator.SEARCH_LIMITS
        )
        for field, limit in self.validator.SEARCH_LIMITS.items():
            with self.subTest(field=field, limit=limit):
                bundle, receipt = self._records()
                bundle["compiler"]["counters"]["search"][field] = limit + 1
                self._write_records(bundle, receipt)
                with self.assertRaisesRegex(
                    self.validator.ValidationError,
                    rf"counters\.search\.{re.escape(field)} exceeds the frozen limit",
                ):
                    self.validator.validate_evidence(
                        source_path=self.source,
                        bundle_path=self.bundle_path,
                        receipt_path=self.receipt_path,
                    )
                self.bundle_path.chmod(0o600)
                self.receipt_path.chmod(0o600)

    def test_rejects_mismatched_logical_incremental_memory(self) -> None:
        bundle, receipt = self._records()
        memory = bundle["compiler"]["counters"]["search"]
        self.assertEqual(memory["logical_incremental_memory_bytes"], 119_420)
        memory["logical_incremental_memory_bytes"] += 1
        self._write_records(bundle, receipt)
        with self.assertRaisesRegex(
            self.validator.ValidationError,
            "logical incremental memory differs from the frozen accounting equation",
        ):
            self.validator.validate_evidence(
                source_path=self.source,
                bundle_path=self.bundle_path,
                receipt_path=self.receipt_path,
            )

    def test_rejects_attempted_total_below_distinct_worklist_pushes(self) -> None:
        bundle, receipt = self._records()
        search = bundle["compiler"]["counters"]["search"]
        search["attempted_events"]["seed"] = 0
        search["attempted_events"]["conflict"] = 0
        search["accepted_events"]["conflict"] = 0
        self.assertLess(
            sum(search["attempted_events"].values()), search["worklist_pushes"]
        )
        self.assertTrue(
            all(
                search["accepted_events"][field]
                <= search["attempted_events"][field]
                for field in self.validator.RULE_COUNTER_FIELDS
            )
        )
        self._write_records(bundle, receipt)
        with self.assertRaisesRegex(
            self.validator.ValidationError,
            "attempted rule counters are below distinct worklist pushes",
        ):
            self.validator.validate_evidence(
                source_path=self.source,
                bundle_path=self.bundle_path,
                receipt_path=self.receipt_path,
            )

    def test_rejects_coherent_forgery_of_previously_omitted_hash(self) -> None:
        bundle, receipt = self._records()
        for record in (
            bundle["compiler"]["hashes"],
            bundle["checker"]["recomputed_hashes"],
            bundle["report"]["hashes"],
            receipt["hashes"],
            receipt["result"]["recomputed_hashes"],
        ):
            record["term_dag_sha256"] = self.validator.ZERO_SHA256
        self._write_records(bundle, receipt)
        with self.assertRaisesRegex(self.validator.ValidationError, "term_dag_sha256 must be nonzero"):
            self.validator.validate_evidence(
                source_path=self.source,
                bundle_path=self.bundle_path,
                receipt_path=self.receipt_path,
            )

    def test_rejects_coherent_counter_forgery(self) -> None:
        bundle, receipt = self._records()
        bundle["compiler"]["counters"]["output"]["emitted_lemmas"] = 2
        bundle["report"]["counters"]["output"]["emitted_lemmas"] = 2
        receipt["result"]["counters"]["output"]["emitted_lemmas"] = 2
        bundle["checker"]["counters"]["replayed_emitted_lemmas"] = 2
        bundle["report"]["checker_counters"]["replayed_emitted_lemmas"] = 2
        receipt["result"]["checker_counters"]["replayed_emitted_lemmas"] = 2
        self._write_records(bundle, receipt)
        with self.assertRaisesRegex(self.validator.ValidationError, "emitted lemma count"):
            self.validator.validate_evidence(
                source_path=self.source,
                bundle_path=self.bundle_path,
                receipt_path=self.receipt_path,
            )

    def test_rejects_malformed_or_nontopological_trace_records(self) -> None:
        mutations = (
            (
                lambda bundle: bundle["compiler"]["trace"][0]["record"].__setitem__(
                    "unexpected", 0
                ),
                "keys differ",
            ),
            (
                lambda bundle: bundle["compiler"]["trace"][1]["record"]["rule"][
                    "premises"
                ]["arguments"][0].__setitem__("parent", 1),
                "not topological",
            ),
            (
                lambda bundle: bundle["compiler"]["trace"][2]["record"].__setitem__(
                    "clause_id", 89_471
                ),
                "not sequential",
            ),
        )
        for index, (mutate, message) in enumerate(mutations):
            with self.subTest(index=index):
                bundle, receipt = self._records()
                mutate(bundle)
                self._write_records(bundle, receipt)
                with self.assertRaisesRegex(self.validator.ValidationError, message):
                    self.validator.validate_evidence(
                        source_path=self.source,
                        bundle_path=self.bundle_path,
                        receipt_path=self.receipt_path,
                    )
                self.bundle_path.chmod(0o600)
                self.receipt_path.chmod(0o600)

    def test_rejects_trace_hash_and_real_receipt_schema_forgery(self) -> None:
        bundle, receipt = self._records()
        bundle["compiler"]["hashes"]["trace_sha256"] = self._digest("forged-trace")
        bundle["checker"]["recomputed_hashes"]["trace_sha256"] = self._digest(
            "forged-trace"
        )
        bundle["report"]["hashes"]["trace_sha256"] = self._digest("forged-trace")
        receipt["hashes"]["trace_sha256"] = self._digest("forged-trace")
        receipt["result"]["recomputed_hashes"]["trace_sha256"] = self._digest(
            "forged-trace"
        )
        receipt["trace_sha256"] = self._digest("forged-trace")
        self._write_records(bundle, receipt)
        with self.assertRaisesRegex(self.validator.ValidationError, "recomputed trace hash"):
            self.validator.validate_evidence(
                source_path=self.source,
                bundle_path=self.bundle_path,
                receipt_path=self.receipt_path,
            )

        self.bundle_path.chmod(0o600)
        self.receipt_path.chmod(0o600)
        bundle, receipt = self._records()
        del receipt["materialized_candidate_sha256"]
        self._write_records(bundle, receipt)
        with self.assertRaisesRegex(self.validator.ValidationError, "receipt keys differ"):
            self.validator.validate_evidence(
                source_path=self.source,
                bundle_path=self.bundle_path,
                receipt_path=self.receipt_path,
            )

    def test_rejects_sat_call_cap_and_missing_mechanism_evidence(self) -> None:
        mutations = (
            (lambda bundle: bundle["report"].__setitem__("sat_calls", 1), "dispatched SAT"),
            (lambda bundle: bundle["report"].__setitem__("cap_attempt", {}), "hard cap"),
            (
                lambda bundle: bundle["compiler"]["counters"]["output"].__setitem__(
                    "emitted_with_missing_equality_congruence", 0
                ),
                "lacks missing-equality",
            ),
        )
        for index, (mutate, message) in enumerate(mutations):
            with self.subTest(index=index):
                bundle, receipt = self._records()
                mutate(bundle)
                if index == 2:
                    bundle["report"]["counters"] = copy.deepcopy(bundle["compiler"]["counters"])
                    receipt["result"]["counters"] = copy.deepcopy(bundle["compiler"]["counters"])
                self._write_records(bundle, receipt)
                with self.assertRaisesRegex(self.validator.ValidationError, message):
                    self.validator.validate_evidence(
                        source_path=self.source,
                        bundle_path=self.bundle_path,
                        receipt_path=self.receipt_path,
                    )
                self.bundle_path.chmod(0o600)
                self.receipt_path.chmod(0o600)

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and hasattr(os, "memfd_create")
        and Path("/proc/self/fd").is_dir(),
        "sealed validator integration requires Linux memfd support",
    )
    def test_main_writes_fresh_immutable_hash_bound_metadata(self) -> None:
        bundle, receipt = self._records()
        self._write_records(bundle, receipt)
        binary = self.root / "euf-viper"
        python_tool = Path(sys.executable).resolve()
        binary.write_bytes(python_tool.read_bytes())
        binary.chmod(0o500)
        binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
        python_sha256 = hashlib.sha256(python_tool.read_bytes()).hexdigest()
        runtime_record = {
            "path": str(python_tool),
            "sha256": python_sha256,
        }
        dependency_inventory = self.root / "dependency_inventory"
        dependency_inventory.write_bytes(
            self._encode(
                {
                    "candidate_sha256": binary_sha256,
                    "platform": "linux-x86_64",
                    "runtime_files": [runtime_record],
                    "schema": self.validator.DEPENDENCY_INVENTORY_SCHEMA,
                }
            )
        )
        dependency_inventory.chmod(0o400)
        python_runtime_inventory = self.root / "python_runtime_inventory"
        python_runtime_inventory.write_bytes(
            self._encode(
                {
                    "candidate_sha256": python_sha256,
                    "platform": "linux-x86_64",
                    "runtime_files": [runtime_record],
                    "schema": self.validator.DEPENDENCY_INVENTORY_SCHEMA,
                }
            )
        )
        python_runtime_inventory.chmod(0o400)
        build_receipt = self.root / "build_receipt"
        build_receipt.write_bytes(
            self._encode(
                {
                    "binary_dependencies_sha256": hashlib.sha256(
                        dependency_inventory.read_bytes()
                    ).hexdigest(),
                    "build_command": list(self.validator.PREBUILT_BUILD_COMMAND),
                    "candidate_bytes": binary.stat().st_size,
                    "candidate_sha256": binary_sha256,
                    "cargo_lock_sha256": self._digest("Cargo.lock"),
                    "cargo_toml_sha256": self._digest("Cargo.toml"),
                    "features": ["certificates"],
                    "profile": "release",
                    "rust_target": "x86_64-unknown-linux-gnu",
                    "schema": self.validator.BUILD_RECEIPT_SCHEMA,
                    "source_commit": "a" * 40,
                    "source_tree": "b" * 40,
                }
            )
        )
        build_receipt.chmod(0o400)
        prebuilt_bundle = self.root / "prebuilt-bundle.tar"
        prebuilt_bundle.write_bytes(b"synthetic prebuilt bundle\n")
        prebuilt_bundle.chmod(0o400)
        retained_builds: dict[str, dict[str, dict[str, object]]] = {}
        for label in ("build_a", "build_b"):
            retained_candidate = self.root / f"{label}-candidate"
            retained_stdout = self.root / f"{label}-stdout"
            retained_stderr = self.root / f"{label}-stderr"
            retained_candidate.write_bytes(binary.read_bytes())
            retained_stdout.write_bytes(f"{label} stdout\n".encode("ascii"))
            retained_stderr.write_bytes(f"{label} stderr\n".encode("ascii"))
            for path in (retained_candidate, retained_stdout, retained_stderr):
                path.chmod(0o400)
            retained_builds[label] = {
                "candidate": {
                    "bytes": retained_candidate.stat().st_size,
                    "path": str(retained_candidate),
                    "sha256": hashlib.sha256(
                        retained_candidate.read_bytes()
                    ).hexdigest(),
                },
                "stdout": {
                    "path": str(retained_stdout),
                    "sha256": hashlib.sha256(retained_stdout.read_bytes()).hexdigest(),
                },
                "stderr": {
                    "path": str(retained_stderr),
                    "sha256": hashlib.sha256(retained_stderr.read_bytes()).hexdigest(),
                },
            }
        artifacts = {
            "source": self.source,
            "binary": binary,
            "build_receipt": build_receipt,
            "dependency_inventory": dependency_inventory,
            "prebuilt_bundle": prebuilt_bundle,
            "python_runtime_inventory": python_runtime_inventory,
            "python": python_tool,
            "bundle": self.bundle_path,
            "audit_receipt": self.receipt_path,
        }
        for name in self.validator.REQUIRED_ARTIFACTS - set(artifacts) - {
            "launch_manifest",
            "prebuilt_preparation",
        }:
            path = self.root / name
            path.write_bytes((name + "\n").encode("ascii"))
            artifacts[name] = path

        preparation_report = {
            "artifacts": {
                "build_a_candidate": retained_builds["build_a"]["candidate"],
                "build_a_stderr": retained_builds["build_a"]["stderr"],
                "build_a_stdout": retained_builds["build_a"]["stdout"],
                "build_b_candidate": retained_builds["build_b"]["candidate"],
                "build_b_stderr": retained_builds["build_b"]["stderr"],
                "build_b_stdout": retained_builds["build_b"]["stdout"],
                "build_receipt": {
                    "path": str(build_receipt),
                    "sha256": hashlib.sha256(build_receipt.read_bytes()).hexdigest(),
                },
                "candidate": {
                    "bytes": binary.stat().st_size,
                    "path": str(binary),
                    "sha256": binary_sha256,
                },
                "dependency_inventory": {
                    "path": str(dependency_inventory),
                    "sha256": hashlib.sha256(
                        dependency_inventory.read_bytes()
                    ).hexdigest(),
                },
                "prebuilt_bundle": {
                    "manifest_sha256": self._digest("prebuilt-manifest"),
                    "path": str(prebuilt_bundle),
                    "sha256": hashlib.sha256(prebuilt_bundle.read_bytes()).hexdigest(),
                },
                "python_runtime_inventory": {
                    "path": str(python_runtime_inventory),
                    "sha256": hashlib.sha256(
                        python_runtime_inventory.read_bytes()
                    ).hexdigest(),
                },
            },
            "build": {
                "command": list(self.validator.PREBUILT_BUILD_COMMAND),
                "first": {
                    "candidate_sha256": binary_sha256,
                    "stderr_sha256": retained_builds["build_a"]["stderr"]["sha256"],
                    "stdout_sha256": retained_builds["build_a"]["stdout"]["sha256"],
                },
                "reproducible": True,
                "second": {
                    "candidate_sha256": binary_sha256,
                    "stderr_sha256": retained_builds["build_b"]["stderr"]["sha256"],
                    "stdout_sha256": retained_builds["build_b"]["stdout"]["sha256"],
                },
            },
            "elf": {
                label: {
                    "interpreter": str(python_tool),
                    "needed": ["runtime"],
                    "resolved": {"runtime": str(python_tool)},
                    "runtime_files": 1,
                }
                for label in ("candidate", "controller_python")
            },
            "schema": self.validator.PREBUILT_PREPARATION_SCHEMA,
            "smoke": {
                "help_sha256": self._digest("help"),
                "python_sha256": self._digest("python-smoke"),
                "version": "euf-viper 0.1.0",
                "version_sha256": self._digest("version"),
            },
            "source": {"commit": "a" * 40, "tree": "b" * 40},
            "status": "verified",
            "tools": {
                "bundle_tool": {
                    "path": str(artifacts["prebuilt_bundle_tool"]),
                    "sha256": hashlib.sha256(
                        artifacts["prebuilt_bundle_tool"].read_bytes()
                    ).hexdigest(),
                },
                "cargo": {
                    "path": str(python_tool),
                    "sha256": python_sha256,
                    "version": "cargo test-version",
                },
                "preparer": {
                    "path": str(artifacts["prebuilt_preparer"]),
                    "sha256": hashlib.sha256(
                        artifacts["prebuilt_preparer"].read_bytes()
                    ).hexdigest(),
                },
                "python": {
                    "path": str(python_tool),
                    "sha256": python_sha256,
                    "version": "python test-version",
                },
                "rustc": {
                    "path": str(python_tool),
                    "sha256": python_sha256,
                    "version": "rustc test-version",
                },
            },
        }
        prebuilt_preparation = self.root / "prebuilt_preparation"
        prebuilt_preparation.write_bytes(self._encode(preparation_report))
        prebuilt_preparation.chmod(0o400)
        artifacts["prebuilt_preparation"] = prebuilt_preparation
        launch_manifest = self.root / "launch_manifest.json"
        manifest = {
            "schema": self.validator.LAUNCH_SCHEMA,
            "solver_revision": "a" * 40,
            "solver_source": {"commit": "a" * 40, "tree": "b" * 40},
            "target": {
                "relative_path": self.validator.TARGET_RELATIVE_PATH,
                "sha256": self.source_sha256,
            },
            "baseline": {
                **self.validator.EXPECTED_INPUT_COUNTERS,
                "atom_map_sha256": self.validator.ATOM_MAP_SHA256,
                "baseline_cnf_sha256": self.validator.BASELINE_CNF_SHA256,
                "baseline_problem_sha256": self.validator.BASELINE_PROBLEM_SHA256,
            },
            "toolchain": {
                "python": {
                    "path": str(python_tool),
                    "sha256": hashlib.sha256(python_tool.read_bytes()).hexdigest(),
                    "version": "python test-version",
                },
            },
            "prebuilt_bundle": {
                "build_receipt_sha256": hashlib.sha256(
                    build_receipt.read_bytes()
                ).hexdigest(),
                "candidate_bytes": binary.stat().st_size,
                "candidate_sha256": binary_sha256,
                "dependency_inventory_sha256": hashlib.sha256(
                    dependency_inventory.read_bytes()
                ).hexdigest(),
                "manifest_sha256": self._digest("prebuilt-manifest"),
                "path": str(prebuilt_bundle),
                "schema": self.validator.PREBUILT_BUNDLE_SCHEMA,
                "sha256": hashlib.sha256(prebuilt_bundle.read_bytes()).hexdigest(),
                "source_commit": "a" * 40,
                "source_tree": "b" * 40,
            },
            "prebuilt_preparation": {
                "path": str(prebuilt_preparation),
                "schema": self.validator.PREBUILT_PREPARATION_SCHEMA,
                "sha256": hashlib.sha256(
                    prebuilt_preparation.read_bytes()
                ).hexdigest(),
            },
            "control_tools": {
                label: {
                    "path": str(artifacts["control_git"]),
                    "sha256": hashlib.sha256(
                        artifacts["control_git"].read_bytes()
                    ).hexdigest(),
                    "version": f"{label} test-version",
                }
                for label in ("git", "sbatch", "scontrol", "scancel", "sacct")
            },
            "artifacts": {
                manifest_field: hashlib.sha256(
                    artifacts[artifact_name].read_bytes()
                ).hexdigest()
                for manifest_field, artifact_name in self.validator.PINNED_ARTIFACT_HASH_FIELDS.items()
            },
        }
        launch_manifest.write_bytes(self._encode(manifest))
        artifacts["launch_manifest"] = launch_manifest
        metadata = self.root / "metadata.json"
        bundle_sha256 = hashlib.sha256(self.bundle_path.read_bytes()).hexdigest()

        descriptors: list[int] = []
        snapshots: dict[str, Path] = {}

        def seal_snapshot(name: str, path: Path) -> Path:
            descriptor = os.memfd_create(
                f"t11-validator-test-{name}",
                flags=os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC,
            )
            descriptors.append(descriptor)
            encoded = path.read_bytes()
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                self.assertGreater(written, 0)
                offset += written
            os.fchmod(descriptor, 0o400)
            fcntl.fcntl(
                descriptor,
                fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_WRITE
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_SEAL,
            )
            os.set_inheritable(descriptor, True)
            return Path(f"/proc/self/fd/{descriptor}")

        for name, path in artifacts.items():
            snapshots[name] = seal_snapshot(name, path)

        argv = [
            "--source",
            str(snapshots["source"]),
            "--bundle",
            str(snapshots["bundle"]),
            "--receipt",
            str(snapshots["audit_receipt"]),
            "--binary",
            str(snapshots["binary"]),
            "--metadata-out",
            str(metadata),
            "--launch-manifest",
            str(snapshots["launch_manifest"]),
            "--launch-manifest-sha256",
            hashlib.sha256(launch_manifest.read_bytes()).hexdigest(),
            "--job-id",
            "17",
            "--source-before-sha256",
            self.source_sha256,
            "--source-after-sha256",
            self.source_sha256,
            "--binary-before-sha256",
            binary_sha256,
            "--binary-after-sha256",
            binary_sha256,
            "--bundle-project-sha256",
            bundle_sha256,
            "--bundle-audit-sha256",
            bundle_sha256,
            "--project-exit",
            "4",
            "--audit-exit",
            "0",
        ]
        for name, path in sorted(artifacts.items()):
            argv.extend(
                ["--artifact", name, str(path), str(snapshots[name])]
            )
        previous_argv0 = sys.argv[0]
        try:
            sys.argv[0] = str(snapshots["validator"])
            self.assertEqual(self.validator.main(argv), 0)
        finally:
            sys.argv[0] = previous_argv0
            for descriptor in descriptors:
                os.close(descriptor)
        self.assertEqual(stat.S_IMODE(metadata.stat().st_mode), 0o400)
        payload = json.loads(metadata.read_text(encoding="ascii"))
        self.assertEqual(payload["decision"], "requires_scheduler_finalization")
        self.assertEqual(payload["status"], "validated_candidate")
        self.assertFalse(payload["stage0b_authority"])
        self.assertNotIn("authorize_stage0b", json.dumps(payload))
        self.assertEqual(payload["projection"]["project_exit"], 4)
        self.assertEqual(payload["projection"]["audit_exit"], 0)
        self.assertEqual(payload["artifacts"]["binary"]["sha256"], binary_sha256)
        self.assertTrue(
            payload["execution_contract"][
                "candidate_loader_closure_inventory_validated"
            ]
        )
        self.assertFalse(
            payload["execution_contract"][
                "dynamic_loader_objects_descriptor_bound"
            ]
        )
        self.assertTrue(
            payload["execution_contract"][
                "python_loader_closure_inventory_validated"
            ]
        )
        self.assertNotIn("elapsed", json.dumps(payload))
        self.assertNotIn("timing", json.dumps(payload))

    @unittest.skipUnless(
        sys.platform.startswith("linux") and hasattr(os, "O_TMPFILE"),
        "anonymous metadata publication requires Linux O_TMPFILE support",
    )
    def test_metadata_publication_never_replaces_an_existing_entry(self) -> None:
        destination = self.root / "existing-metadata.json"
        original = b"preexisting\n"
        destination.write_bytes(original)
        destination.chmod(0o400)
        with self.assertRaisesRegex(
            self.validator.ValidationError, "metadata output path must be fresh"
        ):
            self.validator._write_immutable_json(destination, {"status": "new"})
        self.assertEqual(destination.read_bytes(), original)

    @unittest.skipUnless(
        sys.platform.startswith("linux") and hasattr(os, "O_TMPFILE"),
        "anonymous metadata publication requires Linux O_TMPFILE support",
    )
    def test_metadata_publication_loses_a_no_replace_race_fail_closed(self) -> None:
        destination = self.root / "raced-metadata.json"
        competitor = b"competitor\n"
        real_link = self.validator.os.link

        def racing_link(source, target, *args, **kwargs):
            directory_fd = kwargs["dst_dir_fd"]
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600,
                dir_fd=directory_fd,
            )
            try:
                self.assertEqual(os.write(descriptor, competitor), len(competitor))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return real_link(source, target, *args, **kwargs)

        self.validator.os.link = racing_link
        try:
            with self.assertRaisesRegex(
                self.validator.ValidationError,
                "metadata output path ceased to be fresh",
            ):
                self.validator._write_immutable_json(destination, {"status": "new"})
        finally:
            self.validator.os.link = real_link
        self.assertEqual(destination.read_bytes(), competitor)


if __name__ == "__main__":
    unittest.main()
