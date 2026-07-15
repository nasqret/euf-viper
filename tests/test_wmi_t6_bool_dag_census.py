from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
JOB = ROOT / "scripts" / "wmi" / "euf_viper_t6_bool_dag_census.sbatch"
SUBMIT = ROOT / "scripts" / "wmi" / "submit_t6_bool_dag_census.sh"
CONSUMER = ROOT / "src" / "t6_bool_dag_census.rs"
WORKFLOW = ROOT / ".github" / "workflows" / "campaign-contract.yml"
MANIFEST = ROOT / "campaigns" / "t6-theory-dag-p0-qg12-v1.json"
OLD_MANIFEST = ROOT / "campaigns" / "t6-theory-dag-hard10-v1.json"
TOOLCHAIN_CONTRACT = ROOT / "campaigns" / "t6-wmi-rust-toolchain-1.96.0-v1.json"
JOB_DISPOSITION = ROOT / "campaigns" / "t6-wmi-job-146075-disposition-v1.json"
TOOLCHAIN_SCRIPT = ROOT / "scripts" / "bench" / "validate_t6_wmi_toolchain.py"
REPORT_SCRIPT = ROOT / "scripts" / "bench" / "validate_t6_census_report.py"
MANIFEST_SHA256 = "33a9f0016570dc07dc4c9aed2f575633eb5a2ee10d21177c97a4e86b65507c78"
PATH_LIST_SHA256 = "1fd24c2c5fa8eafd07a39f28c96d828e0e0aa1072fd032db413c60f34270b6fa"
SOURCE_RECORDS_SHA256 = "f274424dcfdf3bd155fe12f7aedb99f8a80dfcb54c0625899dfba8377fff5b0b"
TOOLCHAIN_CONTRACT_SHA256 = (
    "db825fa64cf03e20d07842d063638ecdf7193a1eba4966be5d9e5f7e5c108baa"
)
JOB_DISPOSITION_SHA256 = (
    "b22f3bfdb10d2a379d5777e206eacd1e85453ee69c7380d8b68d995bda3fcbda"
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOOLCHAIN = load_module("validate_t6_wmi_toolchain", TOOLCHAIN_SCRIPT)
REPORT = load_module("validate_t6_census_report", REPORT_SCRIPT)


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def projection(literal_slots: int) -> dict:
    return {
        "source_occurrences": 1,
        "assertion_roots": 1,
        "boolean_data_roots": 0,
        "gate_definitions": 1,
        "gate_edges": 2,
        "cnf": {
            "atom_variables": 1,
            "constant_variables": 0,
            "tseitin_variables": 1,
            "variables": 2,
            "clauses": 2,
            "literal_slots": literal_slots,
            "unit_clauses": 1,
            "two_watch_entries": 2,
        },
    }


def report_row(manifest_source: dict, qualifies: bool) -> dict:
    d_slots = 70 if qualifies else 80
    d = 300_000 if qualifies else 200_000
    increment = 100_000 if qualifies else 0
    return {
        "sequence": manifest_source["sequence"],
        "relative_path": manifest_source["relative_path"],
        "source_bytes": manifest_source["source_bytes"],
        "source_sha256": manifest_source["source_sha256"],
        "taxonomy": manifest_source["taxonomy"],
        "shape": {
            "sorts": 1,
            "function_declarations": 1,
            "terms": 1,
            "applications": 0,
            "assertion_roots": 1,
            "boolean_data_roots": 0,
            "source_occurrences": 1,
        },
        "theory": {
            "unconditional_equality_facts": 0,
            "root_equality_unions": 0,
            "congruence_unions": 0,
            "congruence_rounds": 0,
            "congruence_signature_entries": 0,
        },
        "projections": {
            "A_tree_no_sharing": projection(100),
            "B_generic_source_dag": projection(80),
            "C_root_union_dag": projection(80),
            "D_full_typed_euf_dag": projection(d_slots),
        },
        "reductions": {
            "b_reduction_from_a_ppm": 200_000,
            "c_reduction_from_a_ppm": 200_000,
            "d_reduction_from_a_ppm": d,
            "d_increment_over_b_ppm": increment,
            "d_increment_over_c_ppm": increment,
            "qualifies": qualifies,
        },
    }


def synthetic_report(manifest: dict, qualifying: int = 10) -> dict:
    sources = [
        report_row(source, index < qualifying)
        for index, source in enumerate(manifest["sources"])
    ]
    return {
        "schema": "euf-viper.t6-theory-dag-census.v2",
        "analysis_revision": "0123456789abcdef0123456789abcdef01234567",
        "contract": {
            "analysis": "source-only structural projection; no search engine is invoked",
            "parser_mode": "production typed parser with scoped-let auto mode",
            "primary_measure": "literal_slots",
            "result_semantics": (
                "counts are structural opportunity evidence, not timing or novelty evidence"
            ),
        },
        "manifest": {
            "file_sha256": MANIFEST_SHA256,
            "canonical_path_list_sha256": PATH_LIST_SHA256,
            "source_records_sha256": SOURCE_RECORDS_SHA256,
            "sources": 12,
        },
        "gate": {
            "scope": "current_p0_qg7_derived_10_of_12",
            "decision": "pass" if qualifying >= 10 else "reject",
            "pass_semantics": "source_only_projection_gate_no_implementation_or_promotion",
            "qualifying_sources": qualifying,
            "required_qualifying_sources": 10,
            "required_d_reduction_from_a_ppm": 250_000,
            "required_increment_over_b_ppm": 50_000,
            "required_increment_over_c_ppm": 50_000,
        },
        "implementation_or_promotion_eligible": False,
        "population_status": "accepted",
        "projection_status": "completed",
        "sources": sources,
    }


class T6BooleanDagWmiTests(unittest.TestCase):
    def test_shell_scripts_are_syntactically_valid(self) -> None:
        for script in (JOB, SUBMIT):
            subprocess.run(["bash", "-n", str(script)], check=True)

    def test_hosted_workflow_binds_head_and_runs_exact_t6_python_and_rust(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        head_expression = "${{ github.event.pull_request.head.sha || github.sha }}"
        repository_expression = (
            "${{ github.event.pull_request.head.repo.full_name || github.repository }}"
        )
        self.assertIn(f"repository: {repository_expression}", text)
        self.assertIn(f"ref: {head_expression}", text)
        self.assertIn(f"EXPECTED_HEAD_SHA: {head_expression}", text)
        self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_HEAD_SHA"', text)
        self.assertIn("tests.test_derive_t6_p0_qg_manifest", text)
        self.assertIn("tests.test_wmi_t6_bool_dag_census", text)
        self.assertIn("dtolnay/rust-toolchain@1.96.0", text)
        self.assertIn(
            "cargo +1.96.0 test --locked --all-features\n          t6_bool_dag_census::tests::",
            text,
        )
        self.assertIn("run: cargo +1.96.0 test --locked --all-features", text)
        self.assertNotIn("run: cargo test --all-features", text)

    def test_job_is_exact_revision_source_only_and_fail_closed(self) -> None:
        text = JOB.read_text(encoding="utf-8")
        self.assertIn("#SBATCH --ntasks=1", text)
        self.assertIn("#SBATCH --cpus-per-task=1", text)
        self.assertIn(MANIFEST_SHA256, text)
        self.assertIn(TOOLCHAIN_CONTRACT_SHA256, text)
        self.assertIn(JOB_DISPOSITION_SHA256, text)
        self.assertIn("git status --porcelain=v1 --untracked-files=no", text)
        self.assertIn("t6-theory-dag-p0-qg12-v1.json", text)
        self.assertIn("validate_t6_wmi_toolchain.py require-ready", text)
        self.assertIn("validate_t6_wmi_toolchain.py run-census", text)
        self.assertIn("validate_t6_census_report.py", text)
        self.assertIn('ATTEMPT_ROOT="$SLURM_TMPDIR/euf-viper-t6-${SLURM_JOB_ID}"', text)
        self.assertNotIn("t6-theory-dag-hard10-v1.json", text)
        self.assertNotIn("rustup toolchain", text)
        self.assertNotIn("rustup update", text)
        self.assertNotIn("rustup default", text)
        self.assertNotIn("+1.96.0", text)
        self.assertNotIn("EUF_VIPER_CARGO", text)

    def test_submitter_uses_none_export_and_stops_before_ssh_while_ineligible(self) -> None:
        text = SUBMIT.read_text(encoding="utf-8")
        readiness = text.index("validate_t6_wmi_toolchain.py require-ready")
        first_ssh = text.index('ssh "$REMOTE_HOST"')
        self.assertLess(readiness, first_ssh)
        self.assertIn("--export=NONE", text)
        self.assertIn("research-t6-theory-dag", text)
        self.assertIn('git rev-parse "origin/$REMOTE_BRANCH"', text)
        self.assertIn("validate_t6_wmi_toolchain.py inspect-host", text)
        self.assertIn('"projection_status": "not_executed"', text)
        self.assertIn('"implementation_or_promotion_eligible": False', text)
        self.assertIn("HISTORICAL_HARD10_JOB_ID=146075", text)
        self.assertNotIn("scancel", text)
        self.assertNotIn("--export=ALL", text)
        self.assertNotIn("rustup toolchain", text)
        self.assertNotIn("rustup update", text)
        self.assertNotIn("rustup default", text)
        self.assertNotIn("+1.96.0", text)

    def test_manifest_remains_exact_accepted_unexecuted_population(self) -> None:
        self.assertEqual(file_sha256(MANIFEST), MANIFEST_SHA256)
        manifest = json.loads(MANIFEST.read_text(encoding="ascii"))
        self.assertEqual(manifest["schema"], "euf-viper.t6-theory-dag-manifest.v2")
        self.assertEqual(manifest["population_status"], "accepted")
        self.assertEqual(manifest["projection_status"], "not_executed")
        self.assertEqual(manifest["gate"]["population_sources"], 12)
        self.assertEqual(manifest["gate"]["minimum_qualifying_sources"], 10)
        self.assertEqual(len(manifest["sources"]), 12)
        self.assertFalse(manifest["implementation_or_promotion_eligible"])

    def test_toolchain_contract_is_pinned_pending_and_strict(self) -> None:
        self.assertEqual(file_sha256(TOOLCHAIN_CONTRACT), TOOLCHAIN_CONTRACT_SHA256)
        contract, _ = TOOLCHAIN.load_pinned_contract()
        self.assertEqual(contract["eligibility"], "ineligible")
        self.assertEqual(contract["independent_verification"]["status"], "pending")
        self.assertTrue(all(value is None for value in contract["binaries"].values()))
        with self.assertRaisesRegex(TOOLCHAIN.ToolchainError, "remains ineligible"):
            TOOLCHAIN.require_eligible(contract)

        raw = TOOLCHAIN_CONTRACT.read_bytes()
        duplicate = raw.replace(b'{\n  "binaries"', b'{\n  "schema": "x",\n  "binaries"', 1)
        with self.assertRaisesRegex(TOOLCHAIN.ToolchainError, "duplicate JSON key"):
            TOOLCHAIN.strict_json_bytes(duplicate, "duplicate")
        for token in (b"NaN", b"Infinity", b"-Infinity"):
            nonfinite = raw.replace(b'{\n  "binaries"', b'{\n  "extra": ' + token + b',\n  "binaries"', 1)
            with self.assertRaisesRegex(TOOLCHAIN.ToolchainError, "non-finite"):
                TOOLCHAIN.strict_json_bytes(nonfinite, "nonfinite")

    def test_direct_toolchain_inspection_rejects_rustup_style_proxy_identity(self) -> None:
        base_contract, _ = TOOLCHAIN.load_pinned_contract()
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name).resolve()
            provision = temporary / "provision"
            repository = temporary / "repository"
            provision.mkdir()
            repository.mkdir()
            versions = {
                "cargo": "cargo 1.96.0 (abc123 2026-06-01)",
                "rustc": (
                    "rustc 1.96.0 (def456 2026-06-01)\n"
                    "binary: rustc\ncommit-hash: def456\ncommit-date: 2026-06-01\n"
                    "host: x86_64-unknown-linux-gnu\nrelease: 1.96.0\nLLVM version: 21.0.0"
                ),
                "ar": "ar fixture 1",
                "cc": "cc fixture 1",
                "cxx": "cxx fixture 1",
                "ranlib": "ranlib fixture 1",
                "rust_linker": "linker fixture 1",
            }
            records = {}
            for name, version in versions.items():
                path = provision / name
                path.write_text(
                    "#!/bin/sh\nprintf '%b\\n' " + repr(version) + "\n",
                    encoding="ascii",
                )
                path.chmod(0o755)
                records[name] = {
                    "path": str(path),
                    "sha256": file_sha256(path),
                    "version": version,
                }
            contract = copy.deepcopy(base_contract)
            contract.update(
                {
                    "binaries": records,
                    "eligibility": "eligible",
                    "independent_verification": {
                        "evidence_sha256": hashlib.sha256(b"review").hexdigest(),
                        "reviewer": "independent-review-fixture",
                        "status": "independently_verified",
                    },
                    "ineligibility_reason": None,
                    "provision_root": str(provision),
                    "target": "x86_64-unknown-linux-gnu",
                }
            )
            TOOLCHAIN.validate_contract(contract)
            inspection = TOOLCHAIN.inspect_host(contract, repository)
            self.assertEqual(inspection["binaries"]["cargo"]["sha256"], records["cargo"]["sha256"])
            self.assertEqual(inspection["binaries"]["rustc"]["version"], versions["rustc"])
            environment, attempt = TOOLCHAIN.create_attempt(
                contract,
                inspection,
                temporary / "attempt",
                {
                    "revision": "0" * 40,
                    "corpus_root": "/corpus",
                    "manifest": "/manifest.json",
                    "output": "/report.json",
                },
            )
            self.assertEqual(
                tuple(sorted(environment)),
                tuple(sorted(TOOLCHAIN.BUILD_ENVIRONMENT_ALLOWLIST)),
            )
            self.assertTrue(environment["CARGO_HOME"].startswith(str(temporary / "attempt")))
            self.assertTrue(environment["CARGO_TARGET_DIR"].startswith(str(temporary / "attempt")))
            self.assertEqual(attempt["wrappers"], {
                "RUSTC_WRAPPER": None,
                "RUSTC_WORKSPACE_WRAPPER": None,
            })
            config = attempt["cargo_config"]
            self.assertEqual(
                hashlib.sha256(config["content"].encode("ascii")).hexdigest(),
                config["sha256"],
            )
            self.assertFalse(
                set(TOOLCHAIN.REQUIRED_ABSENT_ENVIRONMENT).intersection(environment)
            )
            attestation = TOOLCHAIN.attestation(contract, inspection, repository)
            attestation.update(
                {
                    "state": "completed",
                    "attempt": attempt,
                    "cargo_exit_code": 0,
                    "command": [
                        records["cargo"]["path"],
                        "test",
                        "--release",
                        "--locked",
                        "--all-features",
                        "t6_bool_dag_census::tests::p0_qg12_census_from_env",
                        "--",
                        "--ignored",
                        "--exact",
                        "--nocapture",
                    ],
                }
            )
            attested_environment = REPORT.validate_attestation(attestation)
            REPORT.validate_runtime_bindings(
                attested_environment,
                "0" * 40,
                Path("/corpus"),
                Path("/manifest.json"),
                Path("/report.json"),
            )
            with self.assertRaisesRegex(REPORT.ReportError, "evidence-path binding drift"):
                REPORT.validate_runtime_bindings(
                    attested_environment,
                    "1" * 40,
                    Path("/corpus"),
                    Path("/manifest.json"),
                    Path("/report.json"),
                )
            leaked_environment = copy.deepcopy(attestation)
            leaked_environment["attempt"]["environment"]["RUSTFLAGS"] = "-C target-cpu=native"
            with self.assertRaisesRegex(REPORT.ReportError, "allowlist drift"):
                REPORT.validate_attestation(leaked_environment)

            os.unlink(records["rustc"]["path"])
            os.link(records["cargo"]["path"], records["rustc"]["path"])
            contract["binaries"]["rustc"].update(
                {
                    "sha256": records["cargo"]["sha256"],
                    "version": versions["cargo"],
                }
            )
            with self.assertRaisesRegex(TOOLCHAIN.ToolchainError, "proxy binary"):
                TOOLCHAIN.inspect_host(contract, repository)

    def test_report_validator_recomputes_all_rows_and_aggregate_gate(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="ascii"))
        report = synthetic_report(manifest, qualifying=10)
        revision = report["analysis_revision"]
        result = REPORT.validate_report(report, manifest, revision)
        self.assertEqual(result, {"decision": "pass", "qualifying_sources": 10})
        rejected = synthetic_report(manifest, qualifying=9)
        self.assertEqual(
            REPORT.validate_report(rejected, manifest, rejected["analysis_revision"]),
            {"decision": "reject", "qualifying_sources": 9},
        )

        forged_row = copy.deepcopy(report)
        forged_row["sources"][10]["reductions"] = {
            "b_reduction_from_a_ppm": 200_000,
            "c_reduction_from_a_ppm": 200_000,
            "d_reduction_from_a_ppm": 300_000,
            "d_increment_over_b_ppm": 100_000,
            "d_increment_over_c_ppm": 100_000,
            "qualifies": True,
        }
        forged_row["gate"]["qualifying_sources"] = 11
        with self.assertRaisesRegex(REPORT.ReportError, "reduction/qualification drift"):
            REPORT.validate_report(forged_row, manifest, revision)

        forged_arm = copy.deepcopy(report)
        forged_arm["sources"][0]["projections"]["D_full_typed_euf_dag"]["cnf"][
            "literal_slots"
        ] = 75
        with self.assertRaisesRegex(REPORT.ReportError, "reduction/qualification drift"):
            REPORT.validate_report(forged_arm, manifest, revision)

        forged_gate = copy.deepcopy(report)
        forged_gate["gate"]["qualifying_sources"] = 12
        with self.assertRaisesRegex(REPORT.ReportError, "aggregate gate"):
            REPORT.validate_report(forged_gate, manifest, revision)

        forged_status = copy.deepcopy(report)
        forged_status["projection_status"] = "not_executed"
        with self.assertRaisesRegex(REPORT.ReportError, "evidence-state drift"):
            REPORT.validate_report(forged_status, manifest, revision)

    def test_report_strict_json_rejects_duplicate_and_nonfinite_values(self) -> None:
        raw = b'{"schema":"x"}'
        with tempfile.TemporaryDirectory() as temporary_name:
            path = Path(temporary_name) / "report.json"
            path.write_bytes(b'{"schema":"x","schema":"y"}')
            with self.assertRaisesRegex(REPORT.ReportError, "duplicate JSON key"):
                REPORT.strict_load(path)
            for token in (b"NaN", b"Infinity", b"-Infinity"):
                path.write_bytes(raw[:-1] + b',"extra":' + token + b"}")
                with self.assertRaisesRegex(REPORT.ReportError, "non-finite"):
                    REPORT.strict_load(path)

    def test_consumer_uses_descriptor_relative_nofollow_opened_snapshots(self) -> None:
        consumer = CONSUMER.read_text(encoding="utf-8")
        for digest in (MANIFEST_SHA256, PATH_LIST_SHA256, SOURCE_RECORDS_SHA256):
            self.assertIn(digest, consumer)
        self.assertIn("openat(directory.as_raw_fd()", consumer)
        self.assertIn("O_NOFOLLOW_FLAG", consumer)
        self.assertIn("metadata_state(&before) != metadata_state(&after)", consumer)
        self.assertIn("duplicate physical source identity", consumer)
        self.assertNotIn("File::open", consumer)
        self.assertNotIn("corpus_root.join(&source.relative_path)", consumer)
        self.assertIn('include_bytes!("../campaigns/t6-theory-dag-hard10-v1.json")', consumer)
        self.assertTrue(OLD_MANIFEST.is_file())

    def test_job_146075_is_historical_hard10_and_never_auto_cancelled(self) -> None:
        self.assertEqual(file_sha256(JOB_DISPOSITION), JOB_DISPOSITION_SHA256)
        disposition = json.loads(JOB_DISPOSITION.read_text(encoding="ascii"))
        self.assertEqual(disposition["job_id"], 146075)
        self.assertEqual(disposition["classification"], "historical_hard10")
        self.assertFalse(disposition["automatic_cancellation_allowed"])
        self.assertEqual(disposition["current_state"], "not_queried")
        REPORT.validate_disposition(JOB_DISPOSITION)
        all_text = JOB.read_text() + SUBMIT.read_text() + REPORT_SCRIPT.read_text()
        self.assertNotIn("scancel", all_text)


if __name__ == "__main__":
    unittest.main()
