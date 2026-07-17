from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import tempfile
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
        self.assertIn("export RUSTUP_TOOLCHAIN=1.93.0", self.text)
        self.assertIn("build --locked --features certificates --release", self.text)
        self.assertIn("project-t11", self.text)
        self.assertIn("audit-t11", self.text)
        self.assertNotIn("compare_solvers.py", self.text)
        self.assertNotIn("YICES", self.text)
        self.assertNotIn("Z3", self.text)

    def test_exact_revision_toolchain_target_and_baseline_are_frozen(self) -> None:
        for required in (
            "EUF_VIPER_EXPECTED_REVISION:?",
            "EUF_VIPER_CARGO_SHA256:?",
            "EUF_VIPER_RUSTC_SHA256:?",
            "EUF_VIPER_PYTHON_SHA256:?",
            "git status --porcelain=v1 --untracked-files=all",
            "QF_UF_sokoban.2.prop1_ab_br_max.smt2",
            "cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112",
            "2fa9cabb8279cf59a9ca73cd254c0c60fe028753e8aa01d1794dd0c645167496",
            "adb6885f8ee5d5230e81a3293d183bd4ae14d985f3df5bba9bc6c9fcd9fb1bb0",
            "652e7b303accb7396dd9dfd5fdf40d17abd523f4a87897609390b6aa94d33597",
        ):
            self.assertIn(required, self.text)

    def test_exit_and_evidence_contract_is_fail_closed(self) -> None:
        self.assertIn('case "$PROJECT_EXIT" in', self.text)
        self.assertIn("4) ;;", self.text)
        self.assertIn("projector_rejected 3 -1", self.text)
        self.assertIn('case "$AUDIT_EXIT" in', self.text)
        self.assertIn("external_auditor_rejected 4 3", self.text)
        self.assertIn("independent_validation_rejected 4 0", self.text)
        self.assertIn("source_identity_changed", self.text)
        self.assertIn("euf-viper.t11-stage0a-rejection.v1", self.text)
        self.assertIn("stop_before_stage0b", self.text)

    def test_outputs_are_external_fresh_immutable_and_directory_synced(self) -> None:
        self.assertIn("EUF_VIPER_T11_RUN_BASE:?", self.text)
        self.assertIn('RUN_ROOT="$RUN_BASE/t11-stage0a-$SLURM_JOB_ID"', self.text)
        self.assertIn('mkdir -m 700 "$RUN_ROOT"', self.text)
        self.assertIn('chmod 500 "$BINARY"', self.text)
        self.assertIn("chmod -R a-w", self.text)
        self.assertIn("os.O_EXCL", self.text)
        self.assertIn("os.fsync(parent_fd)", self.text)
        self.assertNotIn('RUN_ROOT="$PWD/results/', self.text)

    def test_independent_validator_binds_full_evidence(self) -> None:
        for required in (
            "validate_t11_stage0a.py",
            "--source-before-sha256",
            "--source-after-sha256",
            "--project-exit",
            "--audit-exit",
            'artifact "bundle=$BUNDLE"',
            'artifact "audit_receipt=$RECEIPT"',
            'artifact "runner=$RUNNER"',
            'artifact "validator=$VALIDATOR"',
        ):
            self.assertIn(required, self.text)


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
            "application_argument_slots": 276,
        }
        rules = dict.fromkeys(self.validator.RULE_COUNTER_FIELDS, 0)
        rules["congruence"] = 1
        rules["conflict"] = 1
        search = {
            "attempted_events": dict(rules),
            "accepted_events": dict(rules),
            "events_popped": 2,
            "distinct_event_keys_inserted": 2,
            "duplicate_event_keys": 0,
            "worklist_pushes": 2,
            "live_worklist_entries": 0,
            "peak_live_worklist_entries": 1,
            "queued_events_discarded_at_theory_empty": 0,
            "accepted_equality_nodes": 1,
            "accepted_conflict_clauses": 1,
            "proof_parent_references": 1,
            "maximum_proof_depth": 1,
            "accepted_trace_literal_slots": 1,
            "canonical_proof_work_literal_charge": 1,
            "retained_antichain_entries": 1,
            "peak_retained_antichain_entries": 1,
            "registered_negative_equality_occurrences": 1,
            "logical_incremental_memory_bytes": 64,
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
            "replayed_equality_nodes": 1,
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
                    "output": [{"source_clause_id": 1, "clause": [1]}],
                },
            },
            "trace": [
                {
                    "record_kind": "equality",
                    "record": {"rule": {"rule": "congruence", "premises": {}}},
                },
                {"record_kind": "conflict", "record": {}},
            ],
            "counters": counters,
            "hashes": hashes,
        }
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

    def test_main_writes_fresh_immutable_hash_bound_metadata(self) -> None:
        bundle, receipt = self._records()
        self._write_records(bundle, receipt)
        binary = self.root / "euf-viper"
        binary.write_bytes(b"binary")
        binary.chmod(0o500)
        tools = {}
        for name in ("cargo", "rustc", "python"):
            path = self.root / name
            path.write_bytes(name.encode("ascii"))
            path.chmod(0o500)
            tools[name] = path
        artifacts = {
            "source": self.source,
            "binary": binary,
            "bundle": self.bundle_path,
            "audit_receipt": self.receipt_path,
        }
        for name in self.validator.REQUIRED_ARTIFACTS - set(artifacts):
            path = self.root / name
            path.write_bytes((name + "\n").encode("ascii"))
            artifacts[name] = path
        metadata = self.root / "metadata.json"
        argv = [
            "--source",
            str(self.source),
            "--bundle",
            str(self.bundle_path),
            "--receipt",
            str(self.receipt_path),
            "--binary",
            str(binary),
            "--metadata-out",
            str(metadata),
            "--revision",
            "a" * 40,
            "--job-id",
            "17",
            "--target-relative-path",
            self.validator.TARGET_RELATIVE_PATH,
            "--source-before-sha256",
            self.source_sha256,
            "--source-after-sha256",
            self.source_sha256,
            "--project-exit",
            "4",
            "--audit-exit",
            "0",
        ]
        for name in ("cargo", "rustc", "python"):
            argv.extend(
                [
                    f"--{name}",
                    str(tools[name]),
                    f"--{name}-sha256",
                    hashlib.sha256(tools[name].read_bytes()).hexdigest(),
                    f"--{name}-version",
                    f"{name} test-version",
                ]
            )
        for name, path in sorted(artifacts.items()):
            argv.extend(["--artifact", f"{name}={path}"])
        self.assertEqual(self.validator.main(argv), 0)
        self.assertEqual(stat.S_IMODE(metadata.stat().st_mode), 0o400)
        payload = json.loads(metadata.read_text(encoding="ascii"))
        self.assertEqual(payload["decision"], "authorize_stage0b")
        self.assertEqual(payload["projection"]["project_exit"], 4)
        self.assertEqual(payload["projection"]["audit_exit"], 0)
        self.assertEqual(payload["artifacts"]["binary"]["sha256"], hashlib.sha256(b"binary").hexdigest())
        self.assertNotIn("elapsed", json.dumps(payload))
        self.assertNotIn("timing", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
