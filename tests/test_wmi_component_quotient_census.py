from __future__ import annotations

import ast
import copy
import errno
import hashlib
import io
import json
import os
import platform
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scripts.bench import census_component_quotient_ram as census
from scripts.bench import component_quotient_contract as contract
from scripts.bench import independent_component_quotient_verifier as independent
from scripts.bench import t5_linux_publication as publication
from scripts.bench import verify_component_quotient_publication as consumer


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / contract.LOCK_RELATIVE_PATH
SBATCH = ROOT / "scripts/wmi/euf_viper_component_quotient_census.sbatch"
SUBMIT = ROOT / "scripts/wmi/submit_component_quotient_census.sh"
CHECKOUT_GUARD = ROOT / "scripts/wmi/check_component_quotient_checkout.sh"
FINALIZER = ROOT / "scripts/bench/finalize_component_quotient_ram_metadata.py"
CONSUMER = ROOT / "scripts/bench/verify_component_quotient_publication.py"
WORKFLOW = ROOT / ".github/workflows/campaign-contract.yml"


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def clean_environment(home: Path | str = "/nonexistent") -> dict[str, str]:
    return {
        "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
    }


def smt_query(body: str) -> str:
    return f"(set-logic QF_UF)\n{body}\n(check-sat)\n"


class ComponentQuotientStaticContractTests(unittest.TestCase):
    def test_shell_scripts_are_syntactically_valid(self) -> None:
        completed = subprocess.run(
            ["bash", "-n", str(CHECKOUT_GUARD), str(SBATCH), str(SUBMIT)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_publication_is_unnamed_descriptor_only_and_has_no_cleanup(self) -> None:
        primitive = (ROOT / "scripts/bench/t5_linux_publication.py").read_text()
        finalizer_text = FINALIZER.read_text()
        consumer_text = CONSUMER.read_text()
        analyzer_text = (ROOT / "scripts/bench/census_component_quotient_ram.py").read_text()
        self.assertIn("os.O_TMPFILE", primitive)
        self.assertIn("AT_EMPTY_PATH", primitive)
        self.assertIn('linkat(source_descriptor', primitive)
        self.assertIn("reopen_linked_inode_read_only", primitive)
        self.assertNotIn("AT_SYMLINK_FOLLOW", primitive)
        self.assertNotIn('f"/proc/self/fd/', primitive)
        self.assertNotIn("os.unlink", primitive)
        self.assertNotIn("os.replace", primitive)
        self.assertNotIn("os.symlink", finalizer_text)
        self.assertNotIn("os.unlink", finalizer_text)
        self.assertNotIn("os.replace", finalizer_text)
        self.assertNotIn("os.unlink", consumer_text)
        self.assertNotIn("os.replace", consumer_text)
        self.assertNotIn("_atomic_write", analyzer_text)
        self.assertNotIn("os.replace", analyzer_text)

    def test_at_empty_path_permission_failure_has_no_proc_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "unnamed"
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            os.unlink(path)
            directory = os.open(temporary, os.O_RDONLY | os.O_CLOEXEC)
            try:
                with mock.patch.object(publication, "_call_linkat", return_value=errno.EPERM):
                    with self.assertRaisesRegex(
                        publication.PublicationError,
                        "requires CAP_DAC_READ_SEARCH.*forbids the /proc/self/fd",
                    ):
                        publication.link_unnamed_inode_no_replace(
                            descriptor, directory, "final.tar"
                        )
                self.assertEqual(os.fstat(descriptor).st_nlink, 0)
                self.assertEqual(list(Path(temporary).iterdir()), [])
            finally:
                os.close(directory)
                os.close(descriptor)

    def test_job_is_hermetic_and_execs_finalizer_as_last_process(self) -> None:
        text = SBATCH.read_text()
        self.assertTrue(text.startswith("#!/bin/bash\n"))
        self.assertLess(text.index("reject_hostile_environment"), text.index("JOB_ID="))
        self.assertIn("exec env -i", text)
        self.assertIn("-I -B -S", text)
        self.assertNotIn("PYTHONDONTWRITEBYTECODE", text)
        self.assertNotRegex(text, r"(?m)^\s*rm(?:\s|$)")
        self.assertIn('--submission-nonce "$SUBMISSION_NONCE"', text)
        self.assertIn('--namespace-id "$NAMESPACE_ID"', text)
        self.assertIn('--expected-manifest-sha256 "$MANIFEST_SHA256"', text)
        self.assertIn("verify_runtime_identity analyzer", text)
        self.assertIn("verify_runtime_identity verifier", text)
        self.assertIn("verify_runtime_identity finalizer", text)

    def test_submitter_exports_only_explicit_bindings_and_writes_pending_receipt(self) -> None:
        text = SUBMIT.read_text()
        self.assertNotIn("--export=ALL", text)
        self.assertNotIn("ALL,EUF_", text)
        self.assertIn('--export="$export_list"', text)
        self.assertIn("submitted_pending_nondecisive", text)
        self.assertIn('"decisive": False', text)
        self.assertIn('"authoritative": False', text)
        self.assertIn("O_EXCL", text)
        self.assertIn("submission_nonce", text)
        self.assertIn("namespace_id", text)
        self.assertIn("--hold", text)
        self.assertIn("scontrol --quiet release", text)
        self.assertNotIn("git clean", text)
        self.assertNotIn("git reset", text)
        self.assertNotRegex(text, r"(?m)^\s*rm(?:\s|$)")

    def test_independent_verifier_does_not_import_or_call_analyzer(self) -> None:
        text = (ROOT / "scripts/bench/independent_component_quotient_verifier.py").read_text()
        imported_modules = {
            node.module
            for node in ast.walk(ast.parse(text))
            if isinstance(node, ast.ImportFrom)
        } | {
            alias.name
            for node in ast.walk(ast.parse(text))
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertNotIn(
            "scripts.bench.census_component_quotient_ram", imported_modules
        )
        self.assertNotIn("analyze_source", text)
        self.assertIn("def independent_projection", text)
        self.assertIn("def _independent_gates", text)
        self.assertIn("def snapshot_from_bytes", text)

    def test_fixed_runtime_inventory_matches_checkout_guard(self) -> None:
        text = CHECKOUT_GUARD.read_text()
        body = text.split("PROJECT_RUNTIME_FILES=(\n", 1)[1].split("\n)", 1)[0]
        listed = tuple(line.strip() for line in body.splitlines() if line.strip())
        self.assertEqual(listed, contract.RUNTIME_PROJECT_FILES)
        self.assertIn("cat-file blob", text)
        self.assertIn("--git-dir=", text)
        self.assertNotIn("update-index --no-", text)

    def test_runtime_inventory_covers_transitive_project_imports(self) -> None:
        inventory = set(contract.RUNTIME_PROJECT_FILES)
        for relative_path in contract.RUNTIME_PROJECT_FILES:
            if not relative_path.endswith(".py"):
                continue
            tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
            imported: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module is not None:
                    if node.module in {"scripts.bench", "scripts.cert"}:
                        imported.update(
                            f"{node.module}.{alias.name}" for alias in node.names
                        )
                    else:
                        imported.add(node.module)
            for module in imported:
                if not module.startswith("scripts."):
                    continue
                candidate = module.replace(".", "/") + ".py"
                if (ROOT / candidate).is_file():
                    self.assertIn(candidate, inventory, (relative_path, candidate))

    def test_linux_ci_exercises_focused_python_and_shell_surface(self) -> None:
        text = WORKFLOW.read_text()
        self.assertIn("tests.test_wmi_component_quotient_census", text)
        self.assertIn("tests.test_census_component_quotient_ram", text)
        self.assertIn("check_component_quotient_checkout.sh", text)
        self.assertIn("bash -n", text)
        self.assertIn('PYTHONDONTWRITEBYTECODE: "1"', text)
        self.assertNotRegex(text, r"(?m)^\s*python3 (?!-B(?:\s|$))")


class FixedLockTests(unittest.TestCase):
    def test_exact_lock_and_all_preregistered_constants_are_accepted(self) -> None:
        value = contract.require_exact_lock_bytes(LOCK.read_bytes())
        self.assertEqual(value["selector"]["minimum_total_applications"], 64)
        self.assertEqual(value["selector"]["minimum_max_symbol_applications"], 32)
        self.assertEqual(value["gates"]["broadness"]["minimum_generator_lineages"], 8)
        self.assertEqual(value["gates"]["ram_control"]["percentile"], 95)

    def test_every_lock_mutation_is_rejected_before_semantic_use(self) -> None:
        original = json.loads(LOCK.read_text(encoding="ascii"))
        mutations = (
            (("selector", "minimum_total_applications"), 1),
            (("selector", "minimum_max_symbol_applications"), 1),
            (("gates", "broadness", "minimum_generator_lineages"), 1),
            (("gates", "ram_control", "percentile"), 999),
            (("gates", "opportunity", "minimum_reduction", "numerator"), 0),
        )
        for keys, replacement in mutations:
            with self.subTest(keys=keys):
                changed = copy.deepcopy(original)
                selected = changed
                for key in keys[:-1]:
                    selected = selected[key]
                selected[keys[-1]] = replacement
                payload = contract.canonical_json_bytes(changed)
                with self.assertRaisesRegex(contract.ContractError, "lock SHA-256 drift"):
                    contract.require_exact_lock_bytes(payload)

    def test_hostile_environment_detection_covers_all_influence_classes(self) -> None:
        hostile = contract.hostile_environment_names(
            {
                "GIT_CONFIG_GLOBAL": "/tmp/config",
                "BASH_ENV": "/tmp/bash",
                "PYTHONPATH": "/tmp/python",
                "CARGO_HOME": "/tmp/cargo",
                "LD_PRELOAD": "/tmp/loader",
                "DYLD_INSERT_LIBRARIES": "/tmp/dyld",
                "RUSTFLAGS": "-Ctarget-cpu=native",
                "LANG": "C",
            }
        )
        self.assertEqual(
            set(hostile),
            {
                "GIT_CONFIG_GLOBAL",
                "BASH_ENV",
                "PYTHONPATH",
                "CARGO_HOME",
                "LD_PRELOAD",
                "DYLD_INSERT_LIBRARIES",
                "RUSTFLAGS",
            },
        )

    def test_namespace_identity_digest_binds_nonce_path_and_both_inodes(self) -> None:
        nonce = "a" * 64
        expected = digest(b"/remote/attempt\x001\x002\x003\x004\x00" + nonce.encode() + b"\x00")
        actual = contract.namespace_identity_sha256(
            namespace_path="/remote/attempt",
            namespace_device=1,
            namespace_inode=2,
            results_device=3,
            results_inode=4,
            submission_nonce=nonce,
        )
        self.assertEqual(actual, expected)
        self.assertNotEqual(
            actual,
            contract.namespace_identity_sha256(
                namespace_path="/remote/attempt",
                namespace_device=1,
                namespace_inode=2,
                results_device=3,
                results_inode=5,
                submission_nonce=nonce,
            ),
        )


class IndependentSemanticDifferentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lock = census.load_campaign_lock(LOCK)
        cls.oracle = census.run_bounded_decoder_oracle()

    def assert_same_projection(self, source: str) -> None:
        analyzer_problem = census.qfuf.parse_and_encode(source)
        independent_problem = independent.qfuf.parse_and_encode(source)
        analyzer_projection = census.project_problem(
            analyzer_problem, self.lock.caps, self.oracle
        )
        independent_projection = independent.independent_projection(independent_problem)
        for field in (
            "shape",
            "components",
            "symbols",
            "counts",
            "decoder",
            "ratios_ppm",
        ):
            self.assertEqual(
                analyzer_projection[field],
                independent_projection[field],
                field,
            )
        shape = analyzer_projection["shape"]
        expected_selector = {
            "eligible": shape["applications"] >= 64
            and shape["maximum_symbol_applications"] >= 32,
            "minimum_total_applications": 64,
            "minimum_max_symbol_applications": 32,
        }
        self.assertEqual(independent_projection["selector"], expected_selector)

    def test_exhaustive_small_equality_graphs_match_analyzer(self) -> None:
        cases = 0
        for size in range(1, 5):
            names = [f"a{index}" for index in range(size)]
            edges = [
                (left, right)
                for left in range(size)
                for right in range(left + 1, size)
            ]
            for mask in range(1 << len(edges)):
                declarations = ["(declare-sort U 0)", "(declare-fun f (U) U)"]
                declarations.extend(f"(declare-const {name} U)" for name in names)
                assertions = [f"(assert (= (f {name}) (f {name})))" for name in names]
                assertions.extend(
                    f"(assert (= {names[left]} {names[right]}))"
                    for bit, (left, right) in enumerate(edges)
                    if mask & (1 << bit)
                )
                self.assert_same_projection(
                    smt_query("\n".join((*declarations, *assertions)))
                )
                cases += 1
        self.assertEqual(cases, 75)

    def test_generated_boolean_multisort_and_padding_cases_match(self) -> None:
        cases = (
            """
            (declare-sort U 0)
            (declare-sort V 0)
            (declare-fun f (U) V)
            (declare-fun p (V) Bool)
            (declare-const a U)
            (declare-const b U)
            (assert (= (f a) (f b)))
            (assert (= (p (f a)) (p (f b))))
            """,
            """
            (declare-sort U 0)
            (declare-fun f (U U) U)
            (declare-const a U)
            (declare-const b U)
            (declare-const c U)
            (assert (= (f a b) (f b c)))
            (assert (distinct (f c a) (f a b)))
            """,
            """
            (declare-sort U 0)
            (declare-fun p (U) Bool)
            (declare-const a U)
            (declare-const b U)
            (assert (or (p a) (not (p b))))
            (assert (= (p a) (p b)))
            """,
        )
        for body in cases:
            with self.subTest(body=body):
                self.assert_same_projection(smt_query(body))

    def test_rechained_projection_and_provenance_tampering_is_rejected(self) -> None:
        source_bytes = smt_query(
            """
            (declare-sort U 0)
            (declare-fun f (U) U)
            (declare-const a U)
            (declare-const b U)
            (assert (= (f a) (f b)))
            """
        ).encode("ascii")
        relative = "QF_UF/QG-classification/qg1/demo1.smt2"
        taxonomy = independent._taxonomy(relative)
        manifest_source = census.ManifestSource(
            0,
            1,
            relative,
            Path(relative),
            source_bytes,
            digest(source_bytes),
            *taxonomy,
        )
        source_snapshot = independent.SourceSnapshot(
            0,
            1,
            relative,
            Path(relative),
            source_bytes,
            digest(source_bytes),
            *taxonomy,
        )
        record = census.analyze_source(
            manifest_source,
            self.lock,
            "a" * 64,
            "b" * 64,
            self.oracle,
        )
        record = census.chain_records([record])[0]
        verification_arguments = {
            "campaign_id": self.lock.campaign_id,
            "manifest_sha256": "a" * 64,
            "parser_sha256": "b" * 64,
            "taxonomy_builder_sha256": census.sha256_path(census.TAXONOMY_PATH),
        }
        independent._require_record_projection(
            source_snapshot,
            record,
            None,
            0,
            **verification_arguments,
        )
        mutations = {
            "count": lambda value: value["counts"]["component_quotient_ram"][
                "total"
            ].__setitem__("clauses", 999),
            "component": lambda value: value["components"][0].__setitem__(
                "width", 99
            ),
            "symbol": lambda value: value["symbols"][0]["cqram"].__setitem__(
                "record_width", 99
            ),
            "decoder": lambda value: value["decoder"]["counts"].__setitem__(
                "total_operations", 0
            ),
            "ratio": lambda value: value["ratios_ppm"].__setitem__("clauses", 0),
            "provenance": lambda value: value.__setitem__("parser_sha256", "c" * 64),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                tampered = copy.deepcopy(record)
                mutate(tampered)
                tampered = census.chain_records([tampered])[0]
                with self.assertRaisesRegex(
                    independent.IndependentVerificationError,
                    "full independent record mismatch",
                ):
                    independent._require_record_projection(
                        source_snapshot,
                        tampered,
                        None,
                        0,
                        **verification_arguments,
                    )

    def test_archive_snapshot_binds_every_captured_source_and_rejects_extras(self) -> None:
        relative = "QF_UF/QG-classification/qg1/demo1.smt2"
        source = smt_query("(assert true)").encode("ascii")
        row = {
            "id": 0,
            "path": relative,
            "relative_path": relative,
            "bytes": len(source),
            "sha256": digest(source),
        }
        manifest = contract.canonical_json_bytes(row)
        portable = contract.canonical_json_bytes(
            {
                "relative_path": relative,
                "bytes": len(source),
                "sha256": digest(source),
            }
        )
        with (
            mock.patch.object(contract, "EXPECTED_SOURCES", 1),
            mock.patch.object(contract, "PORTABLE_SOURCE_SET_SHA256", digest(portable)),
            mock.patch.object(
                contract,
                "require_exact_lock_bytes",
                return_value={"fixture": "one-source archive"},
            ),
        ):
            snapshot = independent.snapshot_from_bytes(
                repository_root=ROOT,
                lock_bytes=LOCK.read_bytes(),
                manifest_bytes=manifest,
                records_bytes=b"",
                aggregate_bytes=b"{}\n",
                targets_bytes=b"",
                source_bytes={relative: source},
                expected_manifest_sha256=digest(manifest),
            )
            self.assertEqual(snapshot.sources[0].source_bytes, source)
            self.assertEqual(snapshot.portable_source_bytes, portable)
            with self.assertRaisesRegex(
                independent.IndependentVerificationError,
                "unbound captured source",
            ):
                independent.snapshot_from_bytes(
                    repository_root=ROOT,
                    lock_bytes=LOCK.read_bytes(),
                    manifest_bytes=manifest,
                    records_bytes=b"",
                    aggregate_bytes=b"{}\n",
                    targets_bytes=b"",
                    source_bytes={relative: source, "QF_UF/extra.smt2": source},
                    expected_manifest_sha256=digest(manifest),
                )

    def test_independent_decoder_oracle_has_frozen_exhaustive_receipt(self) -> None:
        receipt = independent.run_independent_decoder_oracle()
        self.assertTrue(receipt["passed"])
        self.assertEqual(
            receipt["sha256"],
            "d869fe2de073014dcef83160535318c976897d1da946590e19f0912bc658d4f5",
        )
        self.assertEqual(receipt["counts"]["record_assignments_examined"], 255)

    def test_full_snapshot_reconstruction_rejects_nongating_aggregate_tampering(
        self,
    ) -> None:
        relative = "QF_UF/QG-classification/qg1/demo1.smt2"
        source_bytes = smt_query("(assert true)").encode("ascii")
        source_sha256 = digest(source_bytes)
        manifest_row = {
            "id": 0,
            "path": relative,
            "relative_path": relative,
            "bytes": len(source_bytes),
            "sha256": source_sha256,
        }
        manifest_bytes = contract.canonical_json_bytes(manifest_row)
        manifest_sha256 = digest(manifest_bytes)
        portable_bytes = contract.canonical_json_bytes(
            {
                "relative_path": relative,
                "bytes": len(source_bytes),
                "sha256": source_sha256,
            }
        )
        portable_sha256 = digest(portable_bytes)
        taxonomy = independent._taxonomy(relative)
        source = census.ManifestSource(
            0,
            1,
            relative,
            Path(relative),
            source_bytes,
            source_sha256,
            *taxonomy,
        )
        fixture_lock = replace(
            self.lock,
            expected_sources=1,
            portable_source_set_sha256=portable_sha256,
            families=(
                census.FamilyLock("goel", "QF_UF/2018-Goel-hwbench", 0),
                census.FamilyLock("qg", "QF_UF/QG-classification", 1),
            ),
        )
        parser_sha256 = census.sha256_path(census.PARSER_PATH)
        taxonomy_sha256 = census.sha256_path(census.TAXONOMY_PATH)
        analyzer_sha256 = census.sha256_path(Path(census.__file__))
        records = census.chain_records(
            [
                census.analyze_source(
                    source,
                    fixture_lock,
                    manifest_sha256,
                    parser_sha256,
                    self.oracle,
                )
            ]
        )
        records_bytes = b"".join(
            contract.canonical_json_bytes(record) for record in records
        )
        targets = census._target_rows(records)
        targets_bytes = b"".join(
            contract.canonical_json_bytes(target) for target in targets
        )
        aggregate = census.aggregate_records(
            records,
            fixture_lock,
            manifest_sha256=manifest_sha256,
            portable_source_set_sha256=portable_sha256,
            records_sha256=digest(records_bytes),
            terminal_record_sha256=records[-1]["record_sha256"],
            targets_sha256=digest(targets_bytes),
            parser_sha256=parser_sha256,
            taxonomy_builder_sha256=taxonomy_sha256,
            analyzer_sha256=analyzer_sha256,
            decoder_oracle=self.oracle,
        )
        aggregate_bytes = contract.canonical_json_bytes(aggregate)

        with (
            mock.patch.object(contract, "EXPECTED_SOURCES", 1),
            mock.patch.object(
                contract,
                "EXPECTED_FAMILY_POPULATIONS",
                {"goel": 0, "qg": 1},
            ),
            mock.patch.object(
                contract, "PORTABLE_SOURCE_SET_SHA256", portable_sha256
            ),
            mock.patch.object(
                contract,
                "require_exact_lock_bytes",
                return_value=json.loads(LOCK.read_text(encoding="ascii")),
            ),
        ):
            snapshot = independent.snapshot_from_bytes(
                repository_root=ROOT,
                lock_bytes=LOCK.read_bytes(),
                manifest_bytes=manifest_bytes,
                records_bytes=records_bytes,
                aggregate_bytes=aggregate_bytes,
                targets_bytes=targets_bytes,
                source_bytes={relative: source_bytes},
                expected_manifest_sha256=manifest_sha256,
            )
            receipt = independent.verify_snapshot(snapshot)
            self.assertTrue(receipt["decisive"])
            self.assertTrue(receipt["full_artifact_reconstruction"])
            self.assertEqual(receipt["decision"], "reject_t5")

            tampered_aggregate = copy.deepcopy(aggregate)
            tampered_aggregate["sources"]["decoder_incomplete"] = 1
            tampered_snapshot = replace(
                snapshot,
                aggregate_bytes=contract.canonical_json_bytes(tampered_aggregate),
            )
            with self.assertRaisesRegex(
                independent.IndependentVerificationError,
                "full aggregate differs",
            ):
                independent.verify_snapshot(tampered_snapshot)

    def test_full_population_gate_recomputation_matches_all_analyzer_decisions(self) -> None:
        count_fields = ("variables", "clauses", "literal_slots", "unit_clauses", "watch_entries")

        def make_record(index: int, family: str) -> dict[str, object]:
            eager_clauses = 120 + index % 11
            candidate_clauses = eager_clauses // 2
            eager = {
                "variables": 100 + index % 7,
                "clauses": eager_clauses,
                "literal_slots": 3 * eager_clauses,
                "unit_clauses": 0,
                "watch_entries": 2 * eager_clauses,
            }
            candidate = {
                "variables": eager["variables"],
                "clauses": candidate_clauses,
                "literal_slots": 3 * candidate_clauses,
                "unit_clauses": 0,
                "watch_entries": 2 * candidate_clauses,
            }
            self.assertEqual(set(eager), set(count_fields))
            return {
                "status": "projected",
                "cap_events": [],
                "decoder": {
                    "complete": True,
                    "oracle": self.oracle.reference_json(),
                },
                "independent_decoder_complete": True,
                "taxonomy": {
                    "source_family": family,
                    "generator_lineage": f"lineage-{index % 16}",
                },
                "selector": {"eligible": True},
                "counts": {
                    "eager": {"total": eager},
                    "component_quotient_ram": {"total": candidate},
                },
            }

        records: list[dict[str, object]] = []
        for index in range(contract.EXPECTED_FAMILY_POPULATIONS["goel"]):
            records.append(make_record(index, "QF_UF/2018-Goel-hwbench"))
        for index in range(contract.EXPECTED_FAMILY_POPULATIONS["qg"]):
            records.append(make_record(index, "QF_UF/QG-classification"))
        while len(records) < contract.EXPECTED_SOURCES:
            records.append(make_record(len(records), "QF_UF/control-family"))

        variants = []
        variants.append(copy.deepcopy(records))
        one_ineligible = copy.deepcopy(records)
        one_ineligible[0]["selector"]["eligible"] = False
        variants.append(one_ineligible)
        one_regression = copy.deepcopy(records)
        totals = one_regression[800]["counts"]["component_quotient_ram"]["total"]
        totals["variables"] *= 3
        totals["clauses"] *= 3
        totals["literal_slots"] *= 3
        totals["watch_entries"] *= 3
        variants.append(one_regression)
        one_parse_error = copy.deepcopy(records)
        one_parse_error[-1]["status"] = "parse_error"
        variants.append(one_parse_error)

        for index, variant in enumerate(variants):
            with self.subTest(variant=index):
                analyzer_aggregate = census.aggregate_records(
                    variant,
                    self.lock,
                    manifest_sha256="1" * 64,
                    portable_source_set_sha256=contract.PORTABLE_SOURCE_SET_SHA256,
                    records_sha256="2" * 64,
                    terminal_record_sha256="3" * 64,
                    targets_sha256="4" * 64,
                    parser_sha256="5" * 64,
                    taxonomy_builder_sha256="6" * 64,
                    analyzer_sha256="7" * 64,
                    decoder_oracle=self.oracle,
                )
                independent_gates = independent._independent_gates(variant)
                self.assertEqual(analyzer_aggregate["gates"], independent_gates)


class CheckoutGuardFixture:
    def __init__(self, root: Path):
        self.root = root
        for relative_path in contract.RUNTIME_PROJECT_FILES:
            source = ROOT / relative_path
            destination = root / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
            destination.chmod(stat.S_IMODE(source.stat().st_mode))
        (root / "smoke_test.py").write_text(
            "import unittest\n\n"
            "class Smoke(unittest.TestCase):\n"
            "    def test_true(self):\n"
            "        self.assertTrue(True)\n",
            encoding="ascii",
        )
        (root / ".gitignore").write_text(
            "scripts/bench/injected.py\n"
            "tests/__pycache__/\n"
            ".cargo/\n"
            "config/pyproject.toml\n"
            "target/\n",
            encoding="ascii",
        )
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=T5 Test",
                "-c",
                "user.email=t5@example.invalid",
                "commit",
                "-q",
                "-m",
                "fixture",
            ],
            cwd=root,
            check=True,
        )
        self.revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    @property
    def guard(self) -> Path:
        return self.root / "scripts/wmi/check_component_quotient_checkout.sh"

    def run_guard(
        self, extra_environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        environment = clean_environment(self.root / "home")
        if extra_environment:
            environment.update(extra_environment)
        return subprocess.run(
            [str(self.guard), self.revision],
            cwd=self.root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )


class CheckoutGuardBehaviorTests(unittest.TestCase):
    def test_exact_clean_post_test_checkout_passes_without_import_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CheckoutGuardFixture(Path(temporary))
            tested = subprocess.run(
                [sys.executable, "-B", "-m", "unittest", "-q", "smoke_test"],
                cwd=fixture.root,
                env=clean_environment(fixture.root / "home"),
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(tested.returncode, 0, tested.stderr)
            self.assertEqual(list(fixture.root.rglob("__pycache__")), [])
            guarded = fixture.run_guard()
            self.assertEqual(guarded.returncode, 0, guarded.stderr)

    def test_exact_revision_blob_checks_reject_runtime_lock_and_manifest_mutations(
        self,
    ) -> None:
        targets = (
            "scripts/bench/independent_component_quotient_verifier.py",
            contract.LOCK_RELATIVE_PATH,
            contract.MANIFEST_RELATIVE_PATH,
        )
        for target in targets:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                fixture = CheckoutGuardFixture(Path(temporary))
                bindings = contract.verify_runtime_revision_blobs(
                    fixture.root, fixture.revision
                )
                self.assertIn(target, bindings)
                path = fixture.root / target
                path.write_bytes(path.read_bytes() + b"\nrevision drift\n")
                with self.assertRaisesRegex(
                    contract.ContractError, "runtime bytes differ from revision"
                ):
                    contract.verify_runtime_revision_blobs(
                        fixture.root, fixture.revision
                    )

    def test_ignored_python_config_and_build_influence_is_rejected(self) -> None:
        influence_paths = (
            Path("scripts/bench/injected.py"),
            Path("tests/__pycache__/injected.pyc"),
            Path(".cargo/config.toml"),
            Path("config/pyproject.toml"),
            Path("target/release/euf-viper"),
        )
        for relative_path in influence_paths:
            with self.subTest(path=relative_path), tempfile.TemporaryDirectory() as temporary:
                fixture = CheckoutGuardFixture(Path(temporary))
                path = fixture.root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"hostile ignored influence\n")
                guarded = fixture.run_guard()
                self.assertNotEqual(guarded.returncode, 0)
                self.assertIn("ignored Python, configuration, or build influence", guarded.stderr)

    def test_hidden_index_mutation_is_rejected_without_clearing_the_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CheckoutGuardFixture(Path(temporary))
            target = "scripts/bench/component_quotient_contract.py"
            subprocess.run(
                ["git", "update-index", "--assume-unchanged", "--", target],
                cwd=fixture.root,
                check=True,
            )
            (fixture.root / target).write_bytes(b"hidden replacement\n")
            guarded = fixture.run_guard()
            self.assertNotEqual(guarded.returncode, 0)
            self.assertIn("assume-unchanged index flags are forbidden", guarded.stderr)
            flag = subprocess.run(
                ["git", "ls-files", "-v", "--", target],
                cwd=fixture.root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout[0]
            self.assertTrue(flag.islower())

    def test_hostile_git_environment_is_rejected_before_git_use(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = CheckoutGuardFixture(Path(temporary))
            guarded = fixture.run_guard({"GIT_DIR": "/attacker/repository"})
            self.assertNotEqual(guarded.returncode, 0)
            self.assertIn("hostile ambient environment is forbidden: GIT_DIR", guarded.stderr)


class PublicationPlatformTests(unittest.TestCase):
    def test_pending_receipt_is_immutable_fixed_and_explicitly_nondecisive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "pending.json"
            value = {
                "schema": contract.SUBMISSION_SCHEMA,
                "status": "submitted_pending_nondecisive",
                "decisive": False,
                "authoritative": False,
                "revision": "a" * 40,
                "published_ref": "origin/main",
                "remote_host": "wmicluster",
                "remote_namespace": {
                    "id": "b" * 64,
                    "path": "/remote/attempt",
                    "device": 1,
                    "inode": 2,
                    "results_path": "/remote/attempt/results",
                    "results_device": 1,
                    "results_inode": 3,
                },
                "attempt_id": "attempt-123456",
                "submission_nonce": "c" * 64,
                "dependency": None,
                "job_id": 123,
                "expected_marker_name": "component-quotient-census-123.current",
                "contract": {
                    "expected_sources": contract.EXPECTED_SOURCES,
                    "lock_sha256": contract.LOCK_SHA256,
                    "manifest_sha256": contract.MANIFEST_SHA256,
                    "portable_source_set_sha256": contract.PORTABLE_SOURCE_SET_SHA256,
                },
                "python": {
                    "realpath": "/usr/bin/python3",
                    "version": "3.12.0",
                    "sha256": "d" * 64,
                },
            }
            value["receipt_sha256"] = digest(contract.canonical_json_bytes(value))
            path.write_bytes(contract.canonical_json_bytes(value))
            path.chmod(0o444)
            self.assertEqual(consumer.read_pending_submission(path), value)

            path.chmod(0o644)
            with self.assertRaisesRegex(
                consumer.ConsumerVerificationError, "immutable mode-0444"
            ):
                consumer.read_pending_submission(path)

    def test_non_linux_platform_fails_without_calling_open(self) -> None:
        with mock.patch.object(publication.sys, "platform", "darwin"), mock.patch.object(
            publication.os, "open"
        ) as opened:
            with self.assertRaisesRegex(publication.PublicationError, "requires Linux O_TMPFILE"):
                publication.open_unnamed_linkable_file(9)
            opened.assert_not_called()

    def test_unsupported_filesystem_fails_closed_without_path_fallback(self) -> None:
        with (
            mock.patch.object(publication.sys, "platform", "linux"),
            mock.patch.object(publication.os, "O_TMPFILE", 0x410000, create=True),
            mock.patch.object(
                publication.os,
                "open",
                side_effect=OSError(errno.EOPNOTSUPP, "not supported"),
            ),
        ):
            with self.assertRaisesRegex(
                publication.PublicationError, "does not provide linkable O_TMPFILE"
            ):
                publication.open_unnamed_linkable_file(9)

    def test_file_fsync_failure_is_fatal_for_an_unlinked_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "temporary"
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            os.unlink(path)
            try:
                os.write(descriptor, b"payload")
                with mock.patch.object(
                    publication.os, "fsync", side_effect=OSError(errno.EIO, "fsync failed")
                ):
                    with self.assertRaisesRegex(
                        publication.PublicationError, "cannot seal unnamed publication inode"
                    ):
                        publication.seal_unnamed_file(descriptor)
                self.assertEqual(os.fstat(descriptor).st_nlink, 0)
            finally:
                os.close(descriptor)


@unittest.skipUnless(sys.platform.startswith("linux"), "real Linux publication required")
class LinuxPublicationContractTests(unittest.TestCase):
    def open_directory(self, path: Path) -> int:
        return os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)

    def test_real_unprivileged_otmpfile_linkat_has_one_link_and_no_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = self.open_directory(root)
            descriptor = None
            try:
                descriptor, expected, unlinked = publication.prepare_unnamed_bytes(
                    directory, b"authoritative bytes"
                )
                self.assertEqual(unlinked.st_nlink, 0)
                self.assertEqual(list(root.iterdir()), [])
                linked = publication.link_unnamed_inode_no_replace(
                    descriptor, directory, "final.tar"
                )
                publication.fsync_directory(directory)
                self.assertEqual(linked.st_nlink, 1)
                self.assertEqual([path.name for path in root.iterdir()], ["final.tar"])
                verified = publication.verify_named_file(
                    directory_descriptor=directory,
                    name="final.tar",
                    expected_descriptor=descriptor,
                    expected_sha256=expected,
                    expected_payload=b"authoritative bytes",
                )
                self.assertEqual(verified.st_nlink, 1)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                os.close(directory)

    def test_final_path_is_absent_until_complete_descriptor_is_linked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = self.open_directory(root)
            descriptor = None
            payload = b"x" * (4 * 1024 * 1024)
            try:
                descriptor, expected, _ = publication.prepare_unnamed_bytes(directory, payload)
                self.assertFalse((root / "final.tar").exists())
                self.assertEqual(list(root.iterdir()), [])
                publication.link_unnamed_inode_no_replace(descriptor, directory, "final.tar")
                self.assertEqual((root / "final.tar").read_bytes(), payload)
                self.assertEqual(digest((root / "final.tar").read_bytes()), expected)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                os.close(directory)

    def test_destination_creation_race_preserves_foreign_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = self.open_directory(root)
            descriptor = None
            try:
                descriptor, _, _ = publication.prepare_unnamed_bytes(directory, b"ours")
                foreign = root / "final.tar"
                foreign.write_bytes(b"foreign")
                with self.assertRaisesRegex(publication.PublicationError, "already exists"):
                    publication.link_unnamed_inode_no_replace(
                        descriptor, directory, "final.tar"
                    )
                self.assertEqual(foreign.read_bytes(), b"foreign")
                self.assertEqual(os.fstat(descriptor).st_nlink, 0)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                os.close(directory)

    def test_marker_creation_race_preserves_foreign_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = self.open_directory(root)
            foreign = b"foreign marker from another publisher\n"

            def create_foreign(label: str) -> None:
                if label == "marker_ready":
                    (root / "job.current").write_bytes(foreign)

            try:
                with self.assertRaisesRegex(publication.PublicationError, "already exists"):
                    publication.publish_bytes_no_replace(
                        directory_descriptor=directory,
                        name="job.current",
                        payload=b"our canonical marker\n",
                        boundary_hook=create_foreign,
                        hook_prefix="marker",
                    )
                self.assertEqual((root / "job.current").read_bytes(), foreign)
                self.assertEqual(len(list(root.iterdir())), 1)
            finally:
                os.close(directory)

    def test_concurrent_publishers_have_exactly_one_immutable_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            barrier = threading.Barrier(2)
            outcomes: list[tuple[str, bytes]] = []

            def publish(payload: bytes) -> None:
                directory = self.open_directory(root)
                descriptor = None
                try:
                    descriptor, _, _ = publication.prepare_unnamed_bytes(directory, payload)
                    barrier.wait(timeout=5)
                    publication.link_unnamed_inode_no_replace(
                        descriptor, directory, "winner.tar"
                    )
                    outcomes.append(("published", payload))
                except publication.PublicationError:
                    outcomes.append(("lost", payload))
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
                    os.close(directory)

            threads = [
                threading.Thread(target=publish, args=(b"first",)),
                threading.Thread(target=publish, args=(b"second",)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual([status for status, _ in outcomes].count("published"), 1)
            winner = next(payload for status, payload in outcomes if status == "published")
            self.assertEqual((root / "winner.tar").read_bytes(), winner)
            self.assertEqual((root / "winner.tar").stat().st_nlink, 1)
            self.assertEqual(len(list(root.iterdir())), 1)

    def test_directory_fsync_failure_leaves_only_a_nonauthoritative_orphan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = self.open_directory(root)
            try:
                with mock.patch.object(
                    publication,
                    "fsync_directory",
                    side_effect=OSError(errno.EIO, "directory fsync failed"),
                ):
                    with self.assertRaisesRegex(
                        publication.PublicationError, "cannot fsync archive publication directory"
                    ):
                        publication.publish_bytes_no_replace(
                            directory_descriptor=directory,
                            name="orphan.tar",
                            payload=b"complete but nondurable",
                            hook_prefix="archive",
                        )
                self.assertEqual((root / "orphan.tar").read_bytes(), b"complete but nondurable")
                self.assertEqual((root / "orphan.tar").stat().st_nlink, 1)
            finally:
                os.close(directory)

    def test_pinned_parent_replacement_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            namespace = parent / "attempt"
            (namespace / "results").mkdir(parents=True)
            pinned = publication.PinnedResultRoot.open(namespace)
            try:
                displaced = parent / "displaced"
                namespace.rename(displaced)
                (namespace / "results").mkdir(parents=True)
                with self.assertRaisesRegex(
                    publication.PublicationError, "namespace no longer matches"
                ):
                    pinned.verify_paths()
            finally:
                pinned.close()


class ConsumerFixture:
    def __init__(self, root: Path):
        self.root = root
        self.namespace = root / "component-quotient-attempt"
        self.results = self.namespace / "results"
        self.results.mkdir(parents=True)
        self.job_id = 81234
        self.attempt_id = "component-quotient-abcdef123456-attempt.A1B2C3D4"
        self.nonce = "1" * 64
        namespace_stat = self.namespace.stat()
        results_stat = self.results.stat()
        self.namespace_id = contract.namespace_identity_sha256(
            namespace_path=str(self.namespace),
            namespace_device=namespace_stat.st_dev,
            namespace_inode=namespace_stat.st_ino,
            results_device=results_stat.st_dev,
            results_inode=results_stat.st_ino,
            submission_nonce=self.nonce,
        )
        self.manifest_sha256 = contract.MANIFEST_SHA256
        self.runtime_sha256 = "4" * 64
        self.decision_sha256 = "5" * 64
        self.metadata_bytes = b"{}\n"
        self.metadata_sha256 = digest(self.metadata_bytes)
        self.archive_name = (
            f"component-quotient-census-{self.job_id}-attempt-{self.attempt_id}.tar"
        )
        self.marker_name = f"component-quotient-census-{self.job_id}.current"
        self.pending_path = self.results / (
            f"component-quotient-census-submission-{self.attempt_id}-{self.job_id}.json"
        )
        self.archive_path = self.results / self.archive_name
        self.marker_path = self.results / self.marker_name
        self._publish_fixture()

    @staticmethod
    def _tar_bytes(name: str, payload: bytes) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o444
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(payload))
        return output.getvalue()

    def _publish(self, name: str, payload: bytes) -> publication.PublishedFile:
        directory = os.open(self.results, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
        try:
            return publication.publish_bytes_no_replace(
                directory_descriptor=directory,
                name=name,
                payload=payload,
            )
        finally:
            os.close(directory)

    def _namespace_json(self) -> dict[str, object]:
        namespace_stat = self.namespace.stat()
        results_stat = self.results.stat()
        return {
            "id": self.namespace_id,
            "path": str(self.namespace),
            "device": namespace_stat.st_dev,
            "inode": namespace_stat.st_ino,
            "results_path": str(self.results),
            "results_device": results_stat.st_dev,
            "results_inode": results_stat.st_ino,
        }

    def _publish_fixture(self) -> None:
        archive_payload = self._tar_bytes("metadata.json", self.metadata_bytes)
        archive = self._publish(self.archive_name, archive_payload)
        marker = {
            "schema": contract.MARKER_SCHEMA,
            "status": "verified_publication_nondecisive_without_scheduler_status",
            "authoritative_without_successful_job_status": False,
            "final_archive": {
                "name": self.archive_name,
                "sha256": archive.sha256,
                "bytes": archive.stat.st_size,
                "device": archive.stat.st_dev,
                "inode": archive.stat.st_ino,
                "mode": "0444",
                "link_count": 1,
            },
            "revision": "a" * 40,
            "job_id": self.job_id,
            "attempt_id": self.attempt_id,
            "submission_nonce": self.nonce,
            "remote_namespace": self._namespace_json(),
            "contract": {
                "lock_sha256": contract.LOCK_SHA256,
                "manifest_sha256": self.manifest_sha256,
                "portable_source_set_sha256": contract.PORTABLE_SOURCE_SET_SHA256,
                "runtime_revision_blobs_sha256": self.runtime_sha256,
            },
            "independent_receipt_sha256": self.decision_sha256,
            "bundle_metadata_sha256": self.metadata_sha256,
        }
        self._publish(self.marker_name, contract.canonical_json_bytes(marker))
        pending = {
            "schema": contract.SUBMISSION_SCHEMA,
            "status": "submitted_pending_nondecisive",
            "decisive": False,
            "authoritative": False,
            "revision": "a" * 40,
            "published_ref": "origin/main",
            "remote_host": "wmicluster",
            "remote_namespace": self._namespace_json(),
            "attempt_id": self.attempt_id,
            "submission_nonce": self.nonce,
            "dependency": None,
            "job_id": self.job_id,
            "expected_marker_name": self.marker_name,
            "contract": {
                "expected_sources": contract.EXPECTED_SOURCES,
                "lock_sha256": contract.LOCK_SHA256,
                "manifest_sha256": self.manifest_sha256,
                "portable_source_set_sha256": contract.PORTABLE_SOURCE_SET_SHA256,
            },
            "python": {
                "realpath": "/usr/bin/python3",
                "version": platform.python_version(),
                "sha256": "6" * 64,
            },
        }
        pending["receipt_sha256"] = digest(contract.canonical_json_bytes(pending))
        self.pending_path.write_bytes(contract.canonical_json_bytes(pending))
        self.pending_path.chmod(0o444)

    def verify(
        self,
        *,
        scheduler: consumer.SchedulerEvidence | None = None,
        hook=None,
        consumer_attempt_id: str | None = None,
    ) -> publication.PublishedFile:
        evidence = scheduler or consumer.SchedulerEvidence(self.job_id, "COMPLETED", "0:0")
        decision = {
            "schema": contract.INDEPENDENT_RECEIPT_SCHEMA,
            "decisive": True,
            "validity_pass": True,
            "receipt_sha256": self.decision_sha256,
        }
        with (
            mock.patch.dict(os.environ, clean_environment(self.root / "home"), clear=True),
            mock.patch.object(
                consumer,
                "_verify_archive_semantics",
                return_value=({"schema": contract.BUNDLE_METADATA_SCHEMA}, decision),
            ),
        ):
            return consumer.verify_publication(
                submission_receipt=self.pending_path,
                repository_root=ROOT,
                scheduler_query=lambda job_id: evidence,
                boundary_hook=hook,
                consumer_attempt_id=consumer_attempt_id,
            )


@unittest.skipUnless(sys.platform.startswith("linux"), "real Linux publication required")
class LinuxConsumerRevalidationTests(unittest.TestCase):
    def test_successful_job_plus_fresh_rehash_publishes_bound_final_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ConsumerFixture(Path(temporary))
            published = fixture.verify()
            receipt = json.loads((fixture.results / published.name).read_text(encoding="ascii"))
            self.assertEqual(
                receipt["status"],
                "verified_complete_requires_successful_consumer_exit",
            )
            self.assertTrue(receipt["decisive"])
            self.assertFalse(receipt["authoritative_without_successful_consumer_exit"])
            self.assertEqual(receipt["submission_nonce"], fixture.nonce)
            self.assertEqual(
                receipt["publication"]["archive"]["sha256"],
                digest(fixture.archive_path.read_bytes()),
            )
            self.assertEqual(
                receipt["publication"]["marker"]["sha256"],
                digest(fixture.marker_path.read_bytes()),
            )
            self.assertEqual((fixture.results / published.name).stat().st_nlink, 1)
            self.assertEqual(
                stat.S_IMODE((fixture.results / published.name).stat().st_mode),
                0o444,
            )

    def test_marker_alone_never_overrides_failed_scheduler_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ConsumerFixture(Path(temporary))
            failed = consumer.SchedulerEvidence(fixture.job_id, "FAILED", "1:0")
            with self.assertRaisesRegex(
                consumer.ConsumerVerificationError, "did not prove successful root job"
            ):
                fixture.verify(scheduler=failed)
            self.assertEqual(
                list(fixture.results.glob("*.receipt.json")),
                [],
            )

    def test_archive_mutation_after_marker_is_rejected_by_fresh_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ConsumerFixture(Path(temporary))
            fixture.archive_path.chmod(0o644)
            with fixture.archive_path.open("ab") as handle:
                handle.write(b"post-job mutation")
                handle.flush()
                os.fsync(handle.fileno())
            fixture.archive_path.chmod(0o444)
            with self.assertRaisesRegex(
                consumer.ConsumerVerificationError, "fresh archive digest differs"
            ):
                fixture.verify()

    def test_receipt_fsync_orphan_does_not_block_a_new_consumer_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ConsumerFixture(Path(temporary))
            with mock.patch.object(
                publication,
                "fsync_directory",
                side_effect=OSError(errno.EIO, "receipt directory fsync failed"),
            ):
                with self.assertRaisesRegex(
                    consumer.ConsumerVerificationError,
                    "cannot fsync receipt publication directory",
                ):
                    fixture.verify(consumer_attempt_id="a" * 32)
            orphan = fixture.results / (
                f"component-quotient-census-{fixture.job_id}-consumer-"
                f"{'a' * 32}.receipt.json"
            )
            self.assertTrue(orphan.exists())
            orphan_payload = json.loads(orphan.read_text(encoding="ascii"))
            self.assertFalse(
                orphan_payload["authoritative_without_successful_consumer_exit"]
            )
            published = fixture.verify(consumer_attempt_id="b" * 32)
            self.assertNotEqual(published.name, orphan.name)
            self.assertTrue((fixture.results / published.name).exists())

    def test_swaps_at_every_consumer_boundary_fail_closed(self) -> None:
        cases = (
            ("directories_opened", "parent"),
            ("marker_opened", "marker"),
            ("marker_hashed", "marker"),
            ("archive_opened", "archive"),
            ("archive_hashed", "archive"),
            ("archive_parsed", "archive"),
            ("semantic_verified", "marker"),
            ("receipt_ready", "archive"),
            ("receipt_linked", "marker"),
            ("receipt_verified", "receipt"),
            ("before_return", "parent"),
        )
        for boundary, target in cases:
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary:
                fixture = ConsumerFixture(Path(temporary))
                triggered = False

                def swap(label: str) -> None:
                    nonlocal triggered
                    if triggered or label != boundary:
                        return
                    triggered = True
                    if target == "parent":
                        displaced = fixture.root / "displaced-namespace"
                        fixture.namespace.rename(displaced)
                        (fixture.namespace / "results").mkdir(parents=True)
                    else:
                        if target == "marker":
                            victim = fixture.marker_path
                        elif target == "archive":
                            victim = fixture.archive_path
                        else:
                            receipt_paths = list(
                                fixture.results.glob(
                                    "component-quotient-census-"
                                    f"{fixture.job_id}-consumer-*.receipt.json"
                                )
                            )
                            self.assertEqual(len(receipt_paths), 1)
                            victim = receipt_paths[0]
                        replacement = fixture.results / f"foreign-{target}"
                        replacement.write_bytes(b"foreign immutable replacement\n")
                        replacement.chmod(0o444)
                        os.replace(replacement, victim)

                with self.assertRaises(
                    (consumer.ConsumerVerificationError, publication.PublicationError)
                ):
                    fixture.verify(hook=swap)
                self.assertTrue(triggered)
                receipt_paths = list(
                    fixture.results.glob(
                        f"component-quotient-census-{fixture.job_id}-consumer-*.receipt.json"
                    )
                )
                self.assertLessEqual(len(receipt_paths), 1)
                if receipt_paths:
                    receipt_path = receipt_paths[0]
                    stale = json.loads(receipt_path.read_text(encoding="ascii"))
                    self.assertFalse(stale["authoritative_without_successful_consumer_exit"])


if __name__ == "__main__":
    unittest.main()
