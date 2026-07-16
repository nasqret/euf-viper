from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "campaign-contract.yml"
SMOKE = ROOT / "scripts" / "ci" / "release_evidence_smoke.py"
CLI_CONTRACT = ROOT / "scripts" / "ci" / "check_ordinary_cli_contract.py"
CLI_BASELINE = ROOT / "scripts" / "ci" / "build_cli_baseline.py"
CLI_CASES = ROOT / "scripts" / "ci" / "ordinary_cli_cases.py"
CLI_ORACLE = ROOT / "scripts" / "ci" / "record_cli_oracle.py"
CLI_CONTRACT_SPEC = importlib.util.spec_from_file_location(
    "check_ordinary_cli_contract_test", CLI_CONTRACT
)
assert CLI_CONTRACT_SPEC is not None and CLI_CONTRACT_SPEC.loader is not None
CLI_CONTRACT_MODULE = importlib.util.module_from_spec(CLI_CONTRACT_SPEC)
CLI_CONTRACT_SPEC.loader.exec_module(CLI_CONTRACT_MODULE)
CLI_BASELINE_SPEC = importlib.util.spec_from_file_location(
    "build_cli_baseline_test", CLI_BASELINE
)
assert CLI_BASELINE_SPEC is not None and CLI_BASELINE_SPEC.loader is not None
CLI_BASELINE_MODULE = importlib.util.module_from_spec(CLI_BASELINE_SPEC)
CLI_BASELINE_SPEC.loader.exec_module(CLI_BASELINE_MODULE)
SMOKE_SPEC = importlib.util.spec_from_file_location(
    "release_evidence_smoke_test", SMOKE
)
assert SMOKE_SPEC is not None and SMOKE_SPEC.loader is not None
SMOKE_MODULE = importlib.util.module_from_spec(SMOKE_SPEC)
SMOKE_SPEC.loader.exec_module(SMOKE_MODULE)


def sealed_build_step_text() -> str:
    text = WORKFLOW.read_text(encoding="ascii")
    start = text.index("      - name: Build exact combined release\n")
    end = text.index("      - name: Build independent f8d9205 CLI baseline\n")
    return text[start:end]


def sealed_userns_function_text() -> str:
    step = sealed_build_step_text()
    start = step.index("            run_with_sealed_userns_policy() {\n")
    call = "            run_with_sealed_userns_policy " + "\\\n"
    end = step.index(call, start)
    return textwrap.dedent(step[start:end])


class ReleaseEvidenceWorkflowTests(unittest.TestCase):
    def test_hosted_rust_matrix_is_complete_and_sequential(self) -> None:
        text = WORKFLOW.read_text(encoding="ascii")
        commands = [
            "cargo fmt --all -- --check",
            "cargo test --locked\n",
            "cargo test --locked --no-default-features\n",
            "cargo test --locked --no-default-features --features certificates\n",
            "cargo test --locked --no-default-features --features production-evidence\n",
            "cargo test --locked --no-default-features --features certificates,production-evidence\n",
            "cargo test --locked --all-features\n",
            "sealed_linux_build.py build",
            "python3 -B scripts/ci/build_cli_baseline.py",
        ]
        positions = []
        for command in commands:
            self.assertEqual(text.count(command), 1, command)
            positions.append(text.index(command))
        self.assertEqual(positions, sorted(positions))
        self.assertIn("euf-viper-build-features", text)
        self.assertIn("release_evidence_smoke.py", text)
        self.assertIn("check_ordinary_cli_contract.py", text)

    def test_release_smoke_uses_real_artifacts_and_full_locked_path(self) -> None:
        text = SMOKE.read_text(encoding="ascii")
        for required in (
            "record_solver_config.py",
            "check_production_evidence.py",
            "freeze_campaign.py",
            "shard_campaign_lock.py",
            "bind_campaign_cpu.py",
            "run_locked_campaign.py",
            "analyze_campaign.py",
            "finalize_locked_audit.py",
            "--validate-analysis",
            "--expected-analysis-exit",
            "--write-scheduler-receipt",
            "--preparation-receipt-sha256",
            "--scheduler-receipt-sha256",
            "analysis-sha256",
            "analysis-exit",
            "--smoke-instance",
            "--evidence-out",
            "accepted_decisive_statuses",
            "subprocess.Popen",
        ):
            self.assertIn(required, text)
        self.assertNotIn("#!/bin/sh", text)
        self.assertNotIn("fake solver", text.lower())
        self.assertIn("allowed={1}", text)
        self.assertIn("evidence status mismatch: expected 'sat', got 'unsupported'", text)
        self.assertIn('for kind in ("full", "official")', text)
        self.assertIn('for index in range(2)', text)
        self.assertIn('manifests["full"]', text)
        self.assertIn('manifests["official"]', text)
        self.assertIn('taxonomies["full"]', text)
        self.assertIn('taxonomies["official"]', text)
        self.assertNotIn("--preparation-binding", text)
        self.assertIn("ubuntu-24.04", WORKFLOW.read_text(encoding="ascii"))

    def test_release_smoke_corpus_views_are_distinct_valid_two_shard_inputs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = [
                root / "sat-shared.smt2",
                root / "sat-full.smt2",
                root / "sat-official.smt2",
            ]
            for index, source in enumerate(sources):
                source.write_text(
                    f"(set-logic QF_UF)\n; instance {index}\n(check-sat)\n",
                    encoding="ascii",
                )
            views = SMOKE_MODULE.release_smoke_corpus_views(*sources)
            paths = {
                kind: {
                    name: root / name / f"{kind}.{suffix}"
                    for name, suffix in (
                        ("manifest", "jsonl"),
                        ("taxonomy", "jsonl"),
                        ("split", "json"),
                    )
                }
                for kind in ("full", "official")
            }
            for kind in ("full", "official"):
                SMOKE_MODULE.write_corpus_view(
                    kind,
                    views[kind],
                    paths[kind]["manifest"],
                    paths[kind]["taxonomy"],
                    paths[kind]["split"],
                )
            self.assertNotEqual(
                SMOKE_MODULE.sha256(paths["full"]["manifest"]),
                SMOKE_MODULE.sha256(paths["official"]["manifest"]),
            )
            self.assertNotEqual(
                SMOKE_MODULE.sha256(paths["full"]["taxonomy"]),
                SMOKE_MODULE.sha256(paths["official"]["taxonomy"]),
            )
            full_records = paths["full"]["manifest"].read_text(
                encoding="ascii"
            ).splitlines()
            official_records = paths["official"]["manifest"].read_text(
                encoding="ascii"
            ).splitlines()
            self.assertEqual(len(full_records), 2)
            self.assertEqual(len(official_records), 2)
            split = json.loads(paths["official"]["split"].read_bytes())
            self.assertEqual(
                split["manifest_sha256"],
                SMOKE_MODULE.sha256(paths["official"]["manifest"]),
            )

            for kind in ("full", "official"):
                parent = {
                    "schema_version": 1,
                    "campaign_id": f"release-smoke-{kind}",
                    "lock_sha256": "",
                    "created_from_commit_time": "fixture",
                    "promotion_eligible": False,
                    "spec": {},
                    "repository": {},
                    "host": {},
                    "corpus": {
                        "instances": [
                            {
                                "id": str(index),
                                "relative_path": source.name,
                            }
                            for index, source in enumerate(views[kind])
                        ]
                    },
                    "solver_config": {},
                    "solver_release_lock": {},
                    "solvers": [],
                    "budgets_s": [2.0],
                    "execution": {},
                    "output": {"directory": str(root / f"{kind}-results")},
                }
                parent["lock_sha256"] = hashlib.sha256(
                    SMOKE_MODULE.canonical(parent)
                ).hexdigest()
                parent_path = root / f"{kind}-parent.json"
                parent_path.write_bytes(SMOKE_MODULE.canonical(parent))
                shard_root = root / f"{kind}-shards"
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        str(ROOT / "scripts/bench/shard_campaign_lock.py"),
                        str(parent_path),
                        "--count",
                        "2",
                        "--out-dir",
                        str(shard_root),
                    ],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                shards = sorted(shard_root.glob("lock-*.json"))
                self.assertEqual(len(shards), 2)
                self.assertEqual(
                    [
                        len(json.loads(path.read_bytes())["corpus"]["instances"])
                        for path in shards
                    ],
                    [1, 1],
                )

    def test_release_smoke_canonical_json_is_literal_utf8(self) -> None:
        encoded = SMOKE_MODULE.canonical({"label": "zażółć-α"})
        self.assertEqual(encoded, b'{"label":"za\xc5\xbc\xc3\xb3\xc5\x82\xc4\x87-\xce\xb1"}\n')
        self.assertNotIn(b"\\u", encoded)

    def test_cli_contract_uses_an_independently_built_baseline(self) -> None:
        text = CLI_CONTRACT.read_text(encoding="ascii")
        case_text = CLI_CASES.read_text(encoding="ascii")
        oracle_text = CLI_ORACLE.read_text(encoding="ascii")
        self.assertIn("f8d9205", text)
        self.assertIn("--baseline-binary", text)
        self.assertIn("--baseline-receipt", text)
        self.assertIn("--oracle", text)
        self.assertIn("cli-baseline-build.v2", text)
        self.assertIn("f8d9205e8a18e3496d236fb9b94ed181add93e80", text)
        self.assertIn("effective_compiler", text)
        self.assertIn("completed.stdout", text)
        self.assertIn("completed.stderr", text)
        self.assertNotIn("BASE_USAGE", text)
        self.assertNotIn("CERTIFICATE_USAGE", text)
        self.assertIn("ordinary-cli-oracle.v1", text)
        self.assertIn("open_verified_sealed_memfd", oracle_text)
        self.assertNotIn("execute(baseline", text)
        for case in (
            "no arguments",
            "unknown top-level command",
            "legacy unknown and extra solve arguments",
            "parse-check stdin",
            "missing file",
        ):
            self.assertIn(case, case_text)

    def test_hosted_dependencies_are_pinned_and_non_attesting(self) -> None:
        text = WORKFLOW.read_text(encoding="ascii")
        self.assertIn(
            "actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8",
            text,
        )
        self.assertIn(
            "actions/setup-python@e797f83bcb11b83ae66e0230d6156d7c80228e7c",
            text,
        )
        self.assertIn('python-version: "3.12.11"', text)
        self.assertIn("diagnostic", text)
        self.assertIn("not production attestation", text)
        self.assertNotIn("ubuntu-latest", text)
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', text)

    def test_sealed_build_userns_policy_is_hosted_ubuntu_only_and_restored(
        self,
    ) -> None:
        step = sealed_build_step_text()
        ordered_contract = (
            'test "${RUNNER_ENVIRONMENT:-}" = "github-hosted"',
            'test "${RUNNER_OS:-}" = "Linux"',
            'test "$(/usr/bin/id -u)" != "0"',
            ". /etc/os-release",
            'test "${ID:-}" = "ubuntu"',
            'test "${VERSION_ID:-}" = "24.04"',
            "run_with_sealed_userns_policy() {",
            "trap finish_userns_policy EXIT",
            "trap 'signal_userns_policy 129' HUP",
            "trap 'signal_userns_policy 130' INT",
            "trap 'signal_userns_policy 143' TERM",
            "run_with_sealed_userns_policy \\",
            "python3 -B scripts/wmi/sealed_linux_build.py build",
        )
        positions = []
        for item in ordered_contract:
            self.assertEqual(step.count(item), 1, item)
            positions.append(step.index(item))
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(step.count("IFS= builtin read -r"), 4)
        self.assertNotIn("cat ", step)
        self.assertEqual(
            step.count("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
            2,
        )
        self.assertEqual(step.count("/usr/bin/sudo"), 2)
        self.assertEqual(step.count("/usr/sbin/sysctl"), 2)
        self.assertEqual(
            step.count(
                '"$SEALED_USERNS_SUDO" --non-interactive'
            ),
            2,
        )
        self.assertEqual(
            step.count("kernel.apparmor_restrict_unprivileged_userns="),
            2,
        )
        self.assertIn("trap '' HUP INT TERM", step)
        self.assertIn("trap - EXIT HUP INT TERM", step)
        self.assertIn('--unshare "$(command -v unshare)"', step)
        self.assertNotIn("unsealed", step.lower())
        self.assertIn(
            '          )\n          echo "SEALED_RELEASE=$SEALED_ROOT/release"',
            step,
        )

    @staticmethod
    def _write_executable(path: Path, content: str) -> None:
        path.write_text(content, encoding="ascii")
        path.chmod(0o700)

    def _sealed_userns_fixture(
        self,
        root: Path,
        *,
        original: str,
        behavior: str = "ok",
        build_command: str = "exit 0",
        shell_exit_status: int | None = None,
    ) -> tuple[str, dict[str, str], Path, Path, Path]:
        policy = root / "userns-policy"
        policy.write_text(f"{original}\n", encoding="ascii")
        sysctl_log = root / "sysctl.log"
        sysctl_log.touch()
        cat_marker = root / "path-cat-ran"
        fake_sudo = root / "sudo"
        fake_sysctl = root / "sysctl"
        self._write_executable(
            fake_sudo,
            "#!/bin/sh\n"
            "set -eu\n"
            'test "$1" = "--non-interactive"\n'
            "shift\n"
            'exec "$@"\n',
        )
        self._write_executable(
            fake_sysctl,
            "#!/bin/sh\n"
            "set -eu\n"
            'test "$1" = "-q"\n'
            'test "$2" = "-w"\n'
            'case "$3" in\n'
            "  kernel.apparmor_restrict_unprivileged_userns=0) value=0 ;;\n"
            "  kernel.apparmor_restrict_unprivileged_userns=1) value=1 ;;\n"
            "  *) exit 64 ;;\n"
            "esac\n"
            'printf "%s\\n" "$value" >> "$FAKE_SYSCTL_LOG"\n'
            'case "$FAKE_SYSCTL_BEHAVIOR:$value" in\n'
            "  fail-zero:0|fail-one:1) exit 19 ;;\n"
            "  ignore-zero:0|ignore-one:1) exit 0 ;;\n"
            "esac\n"
            'printf "%s\\n" "$value" > "$FAKE_USERNS_POLICY"\n',
        )
        spoof_bin = root / "spoof-bin"
        spoof_bin.mkdir()
        self._write_executable(
            spoof_bin / "cat",
            "#!/bin/sh\n"
            'printf spoofed > "$FAKE_CAT_MARKER"\n'
            "exit 77\n",
        )
        environment = os.environ.copy()
        environment.update(
            {
                "FAKE_BUILD_COMMAND": build_command,
                "FAKE_CAT_MARKER": str(cat_marker),
                "FAKE_SYSCTL_BEHAVIOR": behavior,
                "FAKE_SYSCTL_LOG": str(sysctl_log),
                "FAKE_USERNS_POLICY": str(policy),
                "PATH": f"{spoof_bin}:{environment.get('PATH', '')}",
                "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Linux",
                "VERSION_ID": "24.04",
            }
        )
        if shell_exit_status is None:
            build_fixture = ""
            build_invocation = '  /bin/sh -c "$FAKE_BUILD_COMMAND"\n'
        else:
            build_fixture = (
                "fixture_shell_exit() { "
                f"exit {shell_exit_status}; "
                "}\n"
            )
            build_invocation = "  fixture_shell_exit\n"
        script = (
            "set -euo pipefail\n"
            f"{sealed_userns_function_text()}\n"
            f"{build_fixture}"
            "run_with_sealed_userns_policy "
            "\\\n"
            '  "$FAKE_USERNS_POLICY" '
            "\\\n"
            f'  "{fake_sudo}" '
            "\\\n"
            f'  "{fake_sysctl}" '
            "\\\n"
            f"{build_invocation}"
        )
        return script, environment, policy, sysctl_log, cat_marker

    def _assert_userns_fixture_state(
        self,
        policy: Path,
        sysctl_log: Path,
        cat_marker: Path,
        *,
        expected_policy: str,
        expected_writes: list[str],
    ) -> None:
        self.assertEqual(policy.read_text(encoding="ascii").strip(), expected_policy)
        self.assertEqual(sysctl_log.read_text(encoding="ascii").splitlines(), expected_writes)
        self.assertFalse(cat_marker.exists(), "PATH-spoofed cat executed")

    def test_sealed_userns_shell_restores_original_zero_and_one(self) -> None:
        for original, writes in (("0", []), ("1", ["0", "1"])):
            with self.subTest(original=original), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                script, environment, policy, sysctl_log, cat_marker = (
                    self._sealed_userns_fixture(root, original=original)
                )
                completed = subprocess.run(
                    ["/bin/bash", "-c", script],
                    text=True,
                    capture_output=True,
                    check=False,
                    env=environment,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self._assert_userns_fixture_state(
                    policy,
                    sysctl_log,
                    cat_marker,
                    expected_policy=original,
                    expected_writes=writes,
                )

    def test_sealed_userns_shell_restores_after_build_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, environment, policy, sysctl_log, cat_marker = (
                self._sealed_userns_fixture(
                    root, original="1", build_command="exit 23"
                )
            )
            completed = subprocess.run(
                ["/bin/bash", "-c", script],
                text=True,
                capture_output=True,
                check=False,
                env=environment,
            )
            self.assertEqual(completed.returncode, 23, completed.stderr)
            self._assert_userns_fixture_state(
                policy,
                sysctl_log,
                cat_marker,
                expected_policy="1",
                expected_writes=["0", "1"],
            )

    def test_sealed_userns_shell_exit_fallback_restores_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, environment, policy, sysctl_log, cat_marker = (
                self._sealed_userns_fixture(
                    root, original="1", shell_exit_status=37
                )
            )
            completed = subprocess.run(
                ["/bin/bash", "-c", script],
                text=True,
                capture_output=True,
                check=False,
                env=environment,
            )
            self.assertEqual(completed.returncode, 37, completed.stderr)
            self._assert_userns_fixture_state(
                policy,
                sysctl_log,
                cat_marker,
                expected_policy="1",
                expected_writes=["0", "1"],
            )

    def test_sealed_userns_shell_fails_closed_on_policy_write_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, environment, policy, sysctl_log, cat_marker = (
                self._sealed_userns_fixture(
                    root, original="1", behavior="fail-zero"
                )
            )
            completed = subprocess.run(
                ["/bin/bash", "-c", script],
                text=True,
                capture_output=True,
                check=False,
                env=environment,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertIn("sealed userns policy write failed", completed.stderr)
            self._assert_userns_fixture_state(
                policy,
                sysctl_log,
                cat_marker,
                expected_policy="1",
                expected_writes=["0"],
            )

    def test_sealed_userns_shell_fails_closed_on_restore_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, environment, policy, sysctl_log, cat_marker = (
                self._sealed_userns_fixture(
                    root, original="1", behavior="ignore-one"
                )
            )
            completed = subprocess.run(
                ["/bin/bash", "-c", script],
                text=True,
                capture_output=True,
                check=False,
                env=environment,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertIn("sealed userns policy restoration mismatch", completed.stderr)
            self._assert_userns_fixture_state(
                policy,
                sysctl_log,
                cat_marker,
                expected_policy="0",
                expected_writes=["0", "1", "1"],
            )

    @unittest.skipUnless(hasattr(os, "killpg"), "POSIX process groups required")
    def test_sealed_userns_shell_restores_on_catchable_signals(self) -> None:
        for caught_signal, expected_status, behavior, expected_policy in (
            (signal.SIGHUP, 129, "ok", "1"),
            (signal.SIGINT, 130, "ok", "1"),
            (signal.SIGTERM, 143, "ok", "1"),
            (signal.SIGTERM, 143, "ignore-one", "0"),
        ):
            with self.subTest(
                signal=caught_signal, behavior=behavior
            ), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                started = root / "build-started"
                script, environment, policy, sysctl_log, cat_marker = (
                    self._sealed_userns_fixture(
                        root,
                        original="1",
                        behavior=behavior,
                        build_command=(
                            'printf started > "$FAKE_BUILD_STARTED"; '
                            "exec /bin/sleep 30"
                        ),
                    )
                )
                environment["FAKE_BUILD_STARTED"] = str(started)
                process = subprocess.Popen(
                    ["/bin/bash", "-c", script],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=environment,
                    start_new_session=True,
                )
                try:
                    deadline = time.monotonic() + 5
                    while not started.exists() and time.monotonic() < deadline:
                        if process.poll() is not None:
                            break
                        time.sleep(0.01)
                    if not started.exists():
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL)
                        stdout, stderr = process.communicate()
                        self.fail(f"fixture build did not start: {stderr}")
                    os.killpg(process.pid, caught_signal)
                    stdout, stderr = process.communicate(timeout=5)
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.communicate()
                self.assertEqual(process.returncode, expected_status, stderr)
                self.assertIn("sealed-userns-policy phase=restored", stdout)
                if behavior != "ok":
                    self.assertIn(
                        "sealed userns policy signal restoration failed", stderr
                    )
                self._assert_userns_fixture_state(
                    policy,
                    sysctl_log,
                    cat_marker,
                    expected_policy=expected_policy,
                    expected_writes=["0", "1"],
                )

    def test_cli_baseline_forces_effective_compiler_and_sanitizes_ambient_controls(self) -> None:
        text = CLI_BASELINE.read_text(encoding="ascii")
        self.assertIn(
            'REVISION = "f8d9205e8a18e3496d236fb9b94ed181add93e80"',
            text,
        )
        self.assertIn('"RUSTC": str(rustc_path)', text)
        self.assertIn("effective_rustc_invocations", text)
        self.assertIn("verbose_invocations", text)
        self.assertIn("EXPECTED_TREE", text)
        self.assertIn("EXPECTED_CARGO_LOCK_SHA256", text)
        self.assertIn("reject_ambient_cargo_configs", text)
        self.assertNotIn("**os.environ", text)
        for control in (
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
        ):
            self.assertIn(control, text)

    def test_cli_baseline_rejects_cargo_config_in_a_checkout_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "output" / "source"
            checkout.mkdir(parents=True)
            CLI_BASELINE_MODULE.reject_ambient_cargo_configs(checkout)
            cargo_directory = root / "output" / ".cargo"
            cargo_directory.mkdir()
            (cargo_directory / "config.toml").write_text(
                "[build]\nrustc-wrapper = '/attacker'\n", encoding="ascii"
            )
            with self.assertRaisesRegex(SystemExit, "config search path"):
                CLI_BASELINE_MODULE.reject_ambient_cargo_configs(checkout)

    def test_cli_checker_reparses_the_bound_effective_compiler_log(self) -> None:
        rustc = Path("/bound/toolchain/bin/rustc")
        build_log = b"Running `/bound/toolchain/bin/rustc --crate-name baseline`\n"
        self.assertEqual(
            CLI_CONTRACT_MODULE.effective_rustc_invocations(build_log, rustc),
            1,
        )
        with self.assertRaisesRegex(SystemExit, "other than supplied RUSTC"):
            CLI_CONTRACT_MODULE.effective_rustc_invocations(
                b"Running `/attacker/bin/rustc --crate-name baseline`\n",
                rustc,
            )


if __name__ == "__main__":
    unittest.main()
