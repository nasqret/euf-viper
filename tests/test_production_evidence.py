from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from tests.sealed_build_fixture import independent_attestation


ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "scripts" / "cert" / "check_production_evidence.py"
SPEC = importlib.util.spec_from_file_location("check_production_evidence", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


SAT_SOURCE = """\
(set-logic QF_UF)
(declare-sort U 0)
(declare-fun a () U)
(declare-fun b () U)
(declare-fun p () Bool)
(declare-fun h (Bool U) U)
(assert (and p (distinct a b)
  (= (h (ite p true false) a) (h true a))))
(check-sat)
"""

UNSAT_SOURCE = """\
(set-logic QF_UF)
(declare-sort U 0)
(declare-fun a () U)
(assert (distinct a a))
(check-sat)
"""

CLOSURE_SAT_SOURCE = """\
(set-logic QF_UF)
(declare-sort U 0)
(declare-fun a () U)
(declare-fun b () U)
(check-sat)
"""

BACKEND_SAT_SOURCE = """\
(set-logic QF_UF)
(declare-sort U 0)
(declare-fun a () U)
(declare-fun b () U)
(assert (distinct a b))
(check-sat)
"""

DYNAMIC_SAT_SOURCE = (ROOT / "tests" / "fixtures" / "production_dynamic_sat.smt2").read_text(
    encoding="utf-8"
)
TEMPORARY_DIRECTORY = "/private/tmp" if sys.platform == "darwin" else None


class SealedReceiptCheckerSchemaTests(unittest.TestCase):
    def test_checker_rejects_a_forged_toolchain_key(self) -> None:
        executable_sha256 = "4" * 64
        revision = "5" * 40
        receipt = {
            "artifacts": {
                "euf-viper": {
                    "bytes": 1,
                    "mode": "0500",
                    "sha256": executable_sha256,
                },
                "euf-viper-build-features": {
                    "bytes": 1,
                    "mode": "0500",
                    "sha256": "6" * 64,
                },
            },
            "build": {
                "execution_closure_sha256": "2" * 64,
                "features": ["production-evidence"],
                "profile": "release",
                "target": "x86_64-unknown-linux-gnu",
                "toolchain": {"compiler": "forged"},
            },
            "schema": "euf-viper.sealed-build-receipt.v3",
            "sealed_build_manifest_sha256": "3" * 64,
            "source": {
                "dirty": False,
                "revision": revision,
                "snapshot_manifest_sha256": "1" * 64,
                "tree": "7" * 40,
            },
            "status": "accepted",
        }
        receipt["independent_attestation"] = independent_attestation(
            artifacts=receipt["artifacts"],
            features=receipt["build"]["features"],
            toolchain=receipt["build"]["toolchain"],
            revision=revision,
            tree=receipt["source"]["tree"],
            source_manifest_sha256=receipt["source"]["snapshot_manifest_sha256"],
            closure_sha256=receipt["build"]["execution_closure_sha256"],
            build_manifest_sha256=receipt["sealed_build_manifest_sha256"],
        )
        receipt_sha256 = hashlib.sha256(
            CHECKER.canonical_bytes(receipt)
        ).hexdigest()
        with self.assertRaisesRegex(
            CHECKER.ProductionEvidenceError, "toolchain is incomplete"
        ):
            CHECKER._validate_sealed_build_receipt(
                {
                    "receipt": receipt,
                    "receipt_sha256": receipt_sha256,
                },
                expected_receipt_sha256=receipt_sha256,
                executable_sha256=executable_sha256,
                revision=revision,
                dirty=False,
                diagnostic_build={
                    "execution_closure_sha256": "2" * 64,
                    "features": ["production-evidence"],
                    "profile": "release",
                    "sealed_source_manifest_sha256": "1" * 64,
                    "target": "x86_64-unknown-linux-gnu",
                },
            )


@unittest.skipUnless(sys.platform.startswith("linux"), "sealed evidence runtime is Linux-only")
class ProductionEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.clean_build = tempfile.TemporaryDirectory(
            prefix="euf-viper-evidence-build-", dir=TEMPORARY_DIRECTORY
        )
        cls.clean_root = Path(cls.clean_build.name) / "repository"
        shutil.copytree(
            ROOT,
            cls.clean_root,
            ignore=shutil.ignore_patterns(".git", "target", "__pycache__"),
        )
        for command in (
            ["git", "init", "-q"],
            ["git", "add", "."],
            [
                "git",
                "-c",
                "user.name=Evidence Test",
                "-c",
                "user.email=evidence@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "test snapshot",
            ],
        ):
            completed = subprocess.run(
                command,
                cwd=cls.clean_root,
                text=True,
                capture_output=True,
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError(completed.stderr)
        completed = subprocess.run(
            [
                "cargo",
                "+1.96.0",
                "build",
                "--quiet",
                "--release",
                "--no-default-features",
                "--features",
                "production-evidence",
            ],
            cwd=cls.clean_root,
            text=True,
            capture_output=True,
            check=False,
            env={
                **os.environ,
                "CARGO_TARGET_DIR": str(Path(cls.clean_build.name) / "target"),
                "EUF_VIPER_BUILD_CONTEXT": "clean-production-evidence-test",
                "EUF_VIPER_BUILD_EXECUTION_CLOSURE_SHA256": "2" * 64,
                "EUF_VIPER_SEALED_GIT_REVISION": subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=cls.clean_root,
                    text=True,
                    capture_output=True,
                    check=True,
                ).stdout.strip(),
                "EUF_VIPER_SEALED_SOURCE_MANIFEST_SHA256": "1" * 64,
                "EUF_VIPER_SEALED_SOURCE_TREE": subprocess.run(
                    ["git", "rev-parse", "HEAD^{tree}"],
                    cwd=cls.clean_root,
                    text=True,
                    capture_output=True,
                    check=True,
                ).stdout.strip(),
            },
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr)
        cls.binary = Path(cls.clean_build.name) / "target" / "release" / "euf-viper"
        cls.feature_report = (
            Path(cls.clean_build.name)
            / "target"
            / "release"
            / "euf-viper-build-features"
        )
        cls.binary.chmod(0o500)
        cls.feature_report.chmod(0o500)
        cls.binary_sha256 = hashlib.sha256(cls.binary.read_bytes()).hexdigest()
        cls.feature_report_sha256 = hashlib.sha256(
            cls.feature_report.read_bytes()
        ).hexdigest()
        features = subprocess.run(
            [str(cls.feature_report)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip().split(",")
        rustc = subprocess.run(
            ["rustc", "+1.96.0", "-Vv"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        cargo = subprocess.run(
            ["cargo", "+1.96.0", "-V"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        target = next(
            line.partition(":")[2].strip()
            for line in rustc.splitlines()
            if line.startswith("host:")
        )
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=cls.clean_root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        tree = subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"],
            cwd=cls.clean_root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        receipt = {
            "artifacts": {
                "euf-viper": {
                    "bytes": cls.binary.stat().st_size,
                    "mode": "0500",
                    "sha256": cls.binary_sha256,
                },
                "euf-viper-build-features": {
                    "bytes": cls.feature_report.stat().st_size,
                    "mode": "0500",
                    "sha256": cls.feature_report_sha256,
                },
            },
            "build": {
                "execution_closure_sha256": "2" * 64,
                "features": features,
                "profile": "release",
                "target": target,
                "toolchain": {"cargo": cargo, "rustc": rustc},
            },
            "schema": "euf-viper.sealed-build-receipt.v3",
            "sealed_build_manifest_sha256": "3" * 64,
            "source": {
                "dirty": False,
                "revision": revision,
                "snapshot_manifest_sha256": "1" * 64,
                "tree": tree,
            },
            "status": "accepted",
        }
        receipt["independent_attestation"] = independent_attestation(
            artifacts=receipt["artifacts"],
            features=receipt["build"]["features"],
            toolchain=receipt["build"]["toolchain"],
            revision=revision,
            tree=tree,
            source_manifest_sha256=receipt["source"]["snapshot_manifest_sha256"],
            closure_sha256=receipt["build"]["execution_closure_sha256"],
            build_manifest_sha256=receipt["sealed_build_manifest_sha256"],
        )
        cls.sealed_receipt = Path(cls.clean_build.name) / "sealed-build-receipt.json"
        cls.sealed_receipt.write_bytes(CHECKER.canonical_bytes(receipt))
        (Path(cls.clean_build.name) / "sealed-build-attestation.json").write_bytes(
            CHECKER.canonical_bytes(receipt["independent_attestation"])
        )
        cls.sealed_receipt_sha256 = hashlib.sha256(
            cls.sealed_receipt.read_bytes()
        ).hexdigest()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.clean_build.cleanup()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="euf-viper-evidence-test-", dir=TEMPORARY_DIRECTORY
        )
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def solve(
        self,
        source_text: str,
        name: str = "case",
        *,
        environment: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        source = self.root / f"{name}.smt2"
        evidence = self.root / f"{name}.evidence.json"
        source.write_text(source_text, encoding="utf-8")
        child_environment = {
            **os.environ,
            "EUF_VIPER_RUN_NONCE": secrets.token_hex(32),
            "EUF_VIPER_TRUSTED_EXECUTABLE_SHA256": self.binary_sha256,
            "EUF_VIPER_SEALED_BUILD_RECEIPT": str(self.sealed_receipt),
            "EUF_VIPER_SEALED_BUILD_RECEIPT_SHA256": self.sealed_receipt_sha256,
            **(environment or {}),
        }
        completed = subprocess.run(
            [
                str(self.binary),
                "solve",
                str(source),
                "--evidence-out",
                str(evidence),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            env=child_environment,
        )
        return completed, source, evidence

    def test_real_clean_binary_records_and_smokes_production_evidence(self) -> None:
        comparator = self.root / "comparator"
        comparator.write_text(
            "#!/bin/sh\n"
            'case "$*" in\n'
            "  *version*) echo '4.16.0 1.3.4 2.7.0 2.9.2' ;;\n"
            "  *) echo sat ;;\n"
            "esac\n",
            encoding="ascii",
        )
        comparator.chmod(0o755)
        source = ROOT / "generated" / "synthetic" / "chain1000_sat.smt2"
        output = self.root / "solver-config.json"
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "bench" / "record_solver_config.py"),
                "--campaign",
                str(ROOT / "campaigns" / "best-overall-qf-uf-2026-07.json"),
                "--viper",
                str(self.binary),
                "--viper-feature-report",
                str(self.feature_report),
                "--viper-sealed-build-receipt",
                str(self.sealed_receipt),
                "--viper-version",
                "clean-production-evidence-test",
                "--z3",
                str(comparator),
                "--cvc5",
                str(comparator),
                "--yices2",
                str(comparator),
                "--opensmt",
                str(comparator),
                "--smoke-instance",
                str(source),
                "--smoke-expected",
                "sat",
                "--out",
                str(output),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(output.read_text(encoding="utf-8"))
        candidate = next(
            record for record in payload["solvers"] if record["id"] == "euf-viper"
        )
        self.assertEqual(candidate["binary"], str(self.binary.resolve()))
        self.assertEqual(
            candidate["evidence"]["accepted_decisive_statuses"], ["sat"]
        )

    def validate(self, evidence: Path, source: Path, **kwargs: object) -> dict[str, object]:
        return CHECKER.validate_production_evidence(
            evidence,
            source,
            expected_executable_sha256=self.binary_sha256,
            expected_sealed_build_receipt_sha256=self.sealed_receipt_sha256,
            allow_dirty=True,
            **kwargs,
        )

    def test_build_environment_strings_alone_cannot_authorize_evidence(self) -> None:
        source = self.root / "forged-markers.smt2"
        evidence = self.root / "forged-markers.evidence.json"
        source.write_text(SAT_SOURCE, encoding="utf-8")
        environment = {
            **os.environ,
            "EUF_VIPER_RUN_NONCE": secrets.token_hex(32),
            "EUF_VIPER_TRUSTED_EXECUTABLE_SHA256": self.binary_sha256,
        }
        completed = subprocess.run(
            [
                str(self.binary),
                "solve",
                str(source),
                "--evidence-out",
                str(evidence),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertFalse(evidence.exists())
        self.assertIn("EUF_VIPER_SEALED_BUILD_RECEIPT", completed.stderr)

    def test_sealed_receipt_requires_the_exact_toolchain_set(self) -> None:
        receipt = json.loads(self.sealed_receipt.read_text(encoding="utf-8"))
        receipt["build"]["toolchain"] = {"compiler": "forged"}
        forged_receipt = self.root / "forged-toolchain-receipt.json"
        forged_receipt.write_bytes(CHECKER.canonical_bytes(receipt))
        completed, _, evidence = self.solve(
            SAT_SOURCE,
            "forged-toolchain",
            environment={
                "EUF_VIPER_SEALED_BUILD_RECEIPT": str(forged_receipt),
                "EUF_VIPER_SEALED_BUILD_RECEIPT_SHA256": hashlib.sha256(
                    forged_receipt.read_bytes()
                ).hexdigest(),
            },
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertFalse(evidence.exists())
        self.assertIn("incomplete toolchain binding", completed.stderr)

    @staticmethod
    def rewrite(evidence: Path, payload: dict[str, object]) -> None:
        evidence.write_bytes(CHECKER.canonical_bytes(payload))

    @staticmethod
    def refresh_backend_hashes(payload: dict[str, object]) -> None:
        backend = payload["backend_cnf"]
        assert isinstance(backend, dict)
        for prefix in ("initial", "final"):
            clauses = backend[f"{prefix}_clauses"]
            backend[f"{prefix}_clause_count"] = len(clauses)
            backend[f"{prefix}_clauses_sha256"] = hashlib.sha256(
                CHECKER.canonical_bytes(clauses)
            ).hexdigest()
        transcript = backend["transcript"]
        backend["transcript_event_count"] = len(transcript)
        backend["transcript_sha256"] = hashlib.sha256(
            CHECKER.canonical_bytes(transcript)
        ).hexdigest()

    def test_sat_sidecar_validates_the_literal_assignment_and_model(self) -> None:
        completed, source, evidence = self.solve(SAT_SOURCE, "sat")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "sat\n")
        result = self.validate(
            evidence,
            source,
            expected_status="sat",
        )
        self.assertEqual(result["status"], "sat")
        self.assertGreater(result["terms"], 0)
        self.assertGreater(result["assignment_variables"], 0)

        payload = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertNotIn("origin", payload["model"])
        self.assertIn(
            payload["solver"]["backend"],
            {"kissat", "cadical", "cadical-refine", "varisat", "dpll-t"},
        )
        self.assertTrue(payload["model"]["atoms"])
        self.assertGreater(result["backend_clauses"], 0)

    def test_cnf_auxiliary_flip_is_rejected_by_clause_replay(self) -> None:
        completed, source, evidence = self.solve(SAT_SOURCE, "aux-flip")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        assignment = payload["model"]["assignment"]
        clauses = payload["backend_cnf"]["final_clauses"]
        selected = None
        for variable in payload["backend_cnf"]["variables"]:
            if variable["kind"] != "auxiliary":
                continue
            candidate = variable["variable"]
            trial = list(assignment)
            trial[candidate - 1] = -trial[candidate - 1]
            values = {abs(literal): literal > 0 for literal in trial}
            if any(
                not any(values[abs(literal)] == (literal > 0) for literal in clause)
                for clause in clauses
            ):
                selected = candidate
                assignment = trial
                break
        self.assertIsNotNone(selected, "fixture needs a clause-constrained auxiliary")
        payload["model"]["assignment"] = assignment
        payload["model"]["assignment_sha256"] = hashlib.sha256(
            CHECKER.canonical_bytes(assignment)
        ).hexdigest()
        final_assignment = next(
            event
            for event in reversed(payload["backend_cnf"]["transcript"])
            if event["kind"] == "assignment"
        )
        final_assignment["assignment"] = assignment
        self.refresh_backend_hashes(payload)
        self.rewrite(evidence, payload)
        with self.assertRaisesRegex(
            CHECKER.ProductionEvidenceError,
            "final transcript assignment differs|falsifies the replayed clause stream",
        ):
            self.validate(evidence, source, expected_status="sat")

    def test_removed_and_added_clauses_are_rejected_after_rehash(self) -> None:
        for mutation in ("removed", "added"):
            with self.subTest(mutation=mutation):
                completed, source, evidence = self.solve(SAT_SOURCE, f"clause-{mutation}")
                self.assertEqual(completed.returncode, 0, completed.stderr)
                payload = json.loads(evidence.read_text(encoding="utf-8"))
                backend = payload["backend_cnf"]
                if mutation == "removed":
                    removed = backend["initial_clauses"].pop(0)
                    self.assertEqual(backend["final_clauses"].pop(0), removed)
                else:
                    satisfying = [payload["model"]["assignment"][0]]
                    backend["final_clauses"].append(satisfying)
                self.refresh_backend_hashes(payload)
                self.rewrite(evidence, payload)
                with self.assertRaisesRegex(
                    CHECKER.ProductionEvidenceError,
                    "initial production CNF differs|final backend clause stream",
                ):
                    self.validate(evidence, source, expected_status="sat")

    def test_dynamic_theory_clause_transcript_is_replayed_exactly(self) -> None:
        for backend in ("varisat", "cadical-refine"):
            with self.subTest(backend=backend):
                environment = {"EUF_VIPER_BACKEND": backend}
                if backend == "varisat":
                    environment["EUF_VIPER_EAGER_CONGRUENCE"] = "0"
                completed, source, evidence = self.solve(
                    DYNAMIC_SAT_SOURCE,
                    f"dynamic-clause-{backend}",
                    environment=environment,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                payload = json.loads(evidence.read_text(encoding="utf-8"))
                transcript = payload["backend_cnf"]["transcript"]
                self.validate(evidence, source, expected_status="sat")
                theory_indices = [
                    index
                    for index, event in enumerate(transcript)
                    if event["kind"] == "clause" and event["phase"] == "theory"
                ]
                if backend == "cadical-refine" and not theory_indices:
                    self.assertEqual(
                        sum(event["kind"] == "solve" for event in transcript), 1
                    )
                    continue
                self.assertEqual(
                    sum(event["kind"] == "solve" for event in transcript), 2
                )
                self.assertEqual(len(theory_indices), 1)
                theory_index = theory_indices[0]
                theory_clause = transcript.pop(theory_index)["clause"]
                self.assertEqual(
                    payload["backend_cnf"]["final_clauses"].pop(), theory_clause
                )
                self.refresh_backend_hashes(payload)
                self.rewrite(evidence, payload)
                with self.assertRaisesRegex(
                    CHECKER.ProductionEvidenceError,
                    "transcript.*keys differ|validation conflict is omitted|backend theory-clause event differs",
                ):
                    self.validate(evidence, source, expected_status="sat")

    def test_extra_variable_is_rejected_even_when_all_assignments_are_extended(self) -> None:
        completed, source, evidence = self.solve(SAT_SOURCE, "extra-variable")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        backend = payload["backend_cnf"]
        variable = backend["var_count"] + 1
        backend["var_count"] = variable
        backend["variables"].append({"kind": "auxiliary", "variable": variable})
        payload["model"]["assignment"].append(variable)
        payload["model"]["assignment_sha256"] = hashlib.sha256(
            CHECKER.canonical_bytes(payload["model"]["assignment"])
        ).hexdigest()
        for event in backend["transcript"]:
            if event["kind"] == "assignment":
                event["assignment"].append(variable)
        self.refresh_backend_hashes(payload)
        self.rewrite(evidence, payload)
        with self.assertRaisesRegex(
            CHECKER.ProductionEvidenceError,
            "must assign all .* variables|variable count differs",
        ):
            self.validate(evidence, source, expected_status="sat")

    def test_invented_and_duplicated_atom_identities_are_rejected(self) -> None:
        for mutation in ("invented", "duplicated"):
            with self.subTest(mutation=mutation):
                completed, source, evidence = self.solve(SAT_SOURCE, f"atom-{mutation}")
                self.assertEqual(completed.returncode, 0, completed.stderr)
                payload = json.loads(evidence.read_text(encoding="utf-8"))
                atoms = payload["model"]["atoms"]
                variables = payload["backend_cnf"]["variables"]
                if mutation == "invented":
                    target = atoms[0]
                    value = payload["model"]["assignment"][target["variable"] - 1] > 0
                    left = payload["model"]["true_term"]
                    right = left if value else payload["model"]["false_term"]
                    replacement = {
                        "kind": "equality",
                        "variable": target["variable"],
                        "left": min(left, right),
                        "right": max(left, right),
                    }
                    variables[target["variable"] - 1] = replacement
                    target.clear()
                    target.update({**replacement, "value": value})
                else:
                    groups: dict[bool, list[dict[str, object]]] = {True: [], False: []}
                    for atom in atoms:
                        groups[bool(atom["value"])].append(atom)
                    pair = next(group[:2] for group in groups.values() if len(group) >= 2)
                    first, second = pair
                    identity = {
                        key: value
                        for key, value in first.items()
                        if key != "value"
                    }
                    identity["variable"] = second["variable"]
                    variables[second["variable"] - 1] = dict(identity)
                    second.clear()
                    second.update({**identity, "value": first["value"]})
                self.rewrite(evidence, payload)
                with self.assertRaisesRegex(
                    CHECKER.ProductionEvidenceError,
                    "variable namespace/map differs|atom identities differ",
                ):
                    self.validate(evidence, source, expected_status="sat")

    def test_atom_omission_is_rejected_by_exact_variable_coverage(self) -> None:
        completed, source, evidence = self.solve(SAT_SOURCE, "atom-omission")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        p_term = next(
            term["id"]
            for term in payload["model"]["terms"]
            if term["function"] == "p"
        )
        omitted = next(
            atom
            for atom in payload["model"]["atoms"]
            if atom["kind"] == "bool_term" and atom["term"] == p_term
        )
        payload["model"]["atoms"].remove(omitted)
        variable = omitted["variable"]
        payload["backend_cnf"]["variables"][variable - 1] = {
            "kind": "auxiliary",
            "variable": variable,
        }
        self.rewrite(evidence, payload)
        with self.assertRaisesRegex(
            CHECKER.ProductionEvidenceError,
            "variable namespace/map differs|atom identities differ",
        ):
            self.validate(evidence, source, expected_status="sat")

    def test_utf8_runtime_configuration_has_a_stable_hash(self) -> None:
        completed, source, evidence = self.solve(
            SAT_SOURCE,
            "utf8-config",
            environment={"EUF_VIPER_TEST_UNICODE": "alpha-\u03b1"},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = self.validate(
            evidence,
            source,
            expected_status="sat",
        )
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(
            payload["solver"]["config"]["EUF_VIPER_TEST_UNICODE"],
            "alpha-\u03b1",
        )
        self.assertEqual(
            result["solver_config_sha256"],
            payload["solver"]["config_sha256"],
        )
        self.assertIn("α".encode("utf-8"), evidence.read_bytes())
        self.assertNotIn(b"\\u03b1", evidence.read_bytes())

    def test_direct_closure_sat_is_always_unsupported(self) -> None:
        completed, source, evidence = self.solve(CLOSURE_SAT_SOURCE, "closure")
        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertEqual(completed.stdout, "unsupported\n")
        result = self.validate(
            evidence,
            source,
            expected_status="unsupported",
        )
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(payload["solver"]["backend"], "congruence-closure")
        self.assertEqual(payload["backend_status"], "sat")
        self.assertIsNone(payload["model"])
        self.assertIsNone(payload["backend_cnf"])
        self.assertEqual(result["status"], "unsupported")

    def test_every_sat_backend_exports_its_same_run_model(self) -> None:
        backends = {
            "kissat": "kissat",
            "cadical": "cadical",
            "cadical-refine": "cadical-refine",
            "varisat": "varisat",
            "dpll": "dpll-t",
        }
        for selected, expected in backends.items():
            with self.subTest(backend=selected):
                completed, source, evidence = self.solve(
                    BACKEND_SAT_SOURCE,
                    f"backend-{selected}",
                    environment={"EUF_VIPER_BACKEND": selected},
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                result = self.validate(
                    evidence,
                    source,
                    expected_status="sat",
                )
                payload = json.loads(evidence.read_text(encoding="utf-8"))
                self.assertEqual(payload["solver"]["backend"], expected)
                self.assertGreater(result["assignment_variables"], 0)

    def test_tampered_atom_and_source_are_rejected(self) -> None:
        completed, source, evidence = self.solve(SAT_SOURCE, "tamper")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(evidence.read_text(encoding="ascii"))
        payload["model"]["atoms"][0]["value"] = not payload["model"]["atoms"][0]["value"]
        evidence.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        with self.assertRaisesRegex(CHECKER.ProductionEvidenceError, "atom .* disagrees"):
            self.validate(evidence, source, expected_status="sat")

        source.write_text(SAT_SOURCE + "; changed\n", encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.ProductionEvidenceError, "source SHA-256 mismatch"):
            self.validate(evidence, source, expected_status="sat")

    def test_boolean_model_rejects_a_third_value(self) -> None:
        completed, source, evidence = self.solve(SAT_SOURCE, "third-bool-value")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        true_term = payload["model"]["true_term"]
        false_term = payload["model"]["false_term"]
        candidate = next(
            term
            for term in payload["model"]["terms"]
            if term["sort"] == "Bool" and term["id"] not in {true_term, false_term}
        )
        candidate["class"] = max(
            term["class"] for term in payload["model"]["terms"]
        ) + 1
        evidence.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(CHECKER.ProductionEvidenceError, "third value"):
            self.validate(evidence, source, expected_status="sat")

    def test_dirty_decisive_evidence_is_rejected_by_default(self) -> None:
        completed, source, evidence = self.solve(SAT_SOURCE, "dirty")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        payload["solver"]["dirty"] = True
        self.rewrite(evidence, payload)
        with self.assertRaisesRegex(CHECKER.ProductionEvidenceError, "dirty build"):
            CHECKER.validate_production_evidence(
                evidence,
                source,
                expected_status="sat",
                expected_executable_sha256=self.binary_sha256,
            )

    def test_decisive_checker_requires_a_trusted_executable_hash(self) -> None:
        completed, source, evidence = self.solve(SAT_SOURCE, "trusted-executable")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        payload["solver"]["dirty"] = False
        self.rewrite(evidence, payload)
        with self.assertRaisesRegex(
            CHECKER.ProductionEvidenceError, "trusted executable SHA-256 is required"
        ):
            CHECKER.validate_production_evidence(
                evidence,
                source,
                expected_status="sat",
                allow_dirty=True,
            )

    def test_emitter_rejects_an_untrusted_executable_hash_before_stdout(self) -> None:
        completed, _, evidence = self.solve(
            SAT_SOURCE,
            "untrusted-emitter",
            environment={"EUF_VIPER_TRUSTED_EXECUTABLE_SHA256": "0" * 64},
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertIn("production executable SHA-256 mismatch", completed.stderr)
        self.assertFalse(evidence.exists())

    def test_symlinked_production_evidence_parent_is_rejected(self) -> None:
        source = self.root / "parent-symlink.smt2"
        source.write_text(SAT_SOURCE, encoding="utf-8")
        real_directory = self.root / "real-evidence"
        real_directory.mkdir()
        linked_directory = self.root / "production-evidence"
        linked_directory.symlink_to(real_directory, target_is_directory=True)
        evidence = linked_directory / "run.json"
        completed = subprocess.run(
            [
                str(self.binary),
                "solve",
                str(source),
                "--evidence-out",
                str(evidence),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            env={
                **os.environ,
                "EUF_VIPER_RUN_NONCE": secrets.token_hex(32),
                "EUF_VIPER_TRUSTED_EXECUTABLE_SHA256": self.binary_sha256,
            },
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("no-follow traversal", completed.stderr)
        self.assertFalse((real_directory / "run.json").exists())

    def test_incoherent_status_pair_is_rejected(self) -> None:
        completed, source, evidence = self.solve(SAT_SOURCE, "status-pair")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        payload["backend_status"] = "unsat"
        self.rewrite(evidence, payload)
        with self.assertRaisesRegex(CHECKER.ProductionEvidenceError, "incoherent"):
            self.validate(evidence, source, expected_status="sat")

    def test_source_path_swap_during_descriptor_read_is_rejected(self) -> None:
        completed, source, evidence = self.solve(SAT_SOURCE, "toctou")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        source_inode = source.stat().st_ino
        original_read = CHECKER.os.read
        replaced = False

        def racing_read(descriptor: int, count: int) -> bytes:
            nonlocal replaced
            block = original_read(descriptor, count)
            if not replaced and block and os.fstat(descriptor).st_ino == source_inode:
                replacement = source.with_suffix(".replacement")
                replacement.write_text(SAT_SOURCE + "; replaced\n", encoding="utf-8")
                os.replace(replacement, source)
                replaced = True
            return block

        with mock.patch.object(CHECKER.os, "read", side_effect=racing_read):
            with self.assertRaisesRegex(
                CHECKER.ProductionEvidenceError, "source.*(changed|path was replaced)"
            ):
                self.validate(evidence, source, expected_status="sat")
        self.assertTrue(replaced)

    def test_sidecar_path_swap_during_descriptor_read_is_rejected(self) -> None:
        completed, source, evidence = self.solve(SAT_SOURCE, "sidecar-toctou")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        evidence_inode = evidence.stat().st_ino
        original_bytes = evidence.read_bytes()
        original_read = CHECKER.os.read
        replaced = False

        def racing_read(descriptor: int, count: int) -> bytes:
            nonlocal replaced
            block = original_read(descriptor, count)
            if not replaced and block and os.fstat(descriptor).st_ino == evidence_inode:
                replacement = evidence.with_suffix(".replacement")
                replacement.write_bytes(original_bytes)
                os.replace(replacement, evidence)
                replaced = True
            return block

        with mock.patch.object(CHECKER.os, "read", side_effect=racing_read):
            with self.assertRaisesRegex(
                CHECKER.ProductionEvidenceError,
                "evidence.*(changed|path was replaced)",
            ):
                self.validate(evidence, source, expected_status="sat")
        self.assertTrue(replaced)

    def test_sidecar_is_immutable_and_never_replaced(self) -> None:
        completed, source, evidence = self.solve(SAT_SOURCE, "immutable")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        original = evidence.read_bytes()
        rerun = subprocess.run(
            [
                str(self.binary),
                "solve",
                str(source),
                "--evidence-out",
                str(evidence),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            env={
                **os.environ,
                "EUF_VIPER_RUN_NONCE": secrets.token_hex(32),
                "EUF_VIPER_TRUSTED_EXECUTABLE_SHA256": self.binary_sha256,
            },
        )
        self.assertEqual(rerun.returncode, 2)
        self.assertNotIn("sat", rerun.stdout.split())
        self.assertIn("refusing to replace immutable evidence", rerun.stderr)
        self.assertEqual(
            hashlib.sha256(evidence.read_bytes()).digest(),
            hashlib.sha256(original).digest(),
        )
        self.assertFalse(list(self.root.glob(".*.tmp-*")))

    def test_unsat_without_same_run_proof_fails_closed(self) -> None:
        completed, source, evidence = self.solve(UNSAT_SOURCE, "unsat")
        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertEqual(completed.stdout, "unsupported\n")
        payload = json.loads(evidence.read_text(encoding="ascii"))
        self.assertEqual(payload["status"], "unsupported")
        self.assertEqual(payload["backend_status"], "unsat")
        self.assertIsNone(payload["model"])
        result = self.validate(
            evidence,
            source,
            expected_status="unsupported",
        )
        self.assertEqual(result["backend_status"], "unsat")


if __name__ == "__main__":
    unittest.main()
