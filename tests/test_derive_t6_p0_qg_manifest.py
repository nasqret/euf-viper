from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "derive_t6_p0_qg_manifest.py"
COMMITTED = ROOT / "campaigns" / "t6-theory-dag-p0-qg12-v1.json"
SPEC = importlib.util.spec_from_file_location("derive_t6_p0_qg_manifest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
T6 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(T6)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def source(source_id: int, relative_path: str, status: str = "unsat") -> dict:
    return {
        "bytes": T6.MINIMUM_SOURCE_BYTES + source_id,
        "id": source_id,
        "logic": "QF_UF",
        "relative_path": relative_path,
        "sha256": digest(f"source-{source_id}"),
        "status": status,
    }


def observation(
    budget: float,
    solver: str,
    path: str,
    result: str,
    *,
    carried_forward: bool,
    origin_budget: float,
    evidence: str,
) -> dict:
    return {
        "budget_s": budget,
        "carried_forward": carried_forward,
        "origin_budget_s": origin_budget,
        "relative_path": path,
        "result": result,
        "solver_id": solver,
        "source_lock_sha256": digest(f"{evidence}-lock"),
        "source_raw_sha256": digest(f"{evidence}-raw"),
        "source_record_sha256s": [digest(f"{evidence}-record")],
    }


def observation_digest(audit: dict) -> str:
    return hashlib.sha256(
        T6.canonical_json_bytes(audit["inputs"]["observation_provenance"])
    ).hexdigest()


def rehash_observations(audit: dict) -> str:
    observed = observation_digest(audit)
    audit["input_hashes"]["observation_provenance_sha256"] = observed
    return observed


def fixture() -> tuple[dict, list[dict], str]:
    rows = [
        source(0, "QF_UF/QG-classification/qg7/iso_icl_nogen001.smt2"),
        source(1, "QF_UF/QG-classification/qg7/iso_icl_nogen_sk001.smt2"),
        source(2, "QF_UF/PEQ/PEQ001_size1.smt2"),
    ]
    first_by_key: dict[tuple[str, str], dict] = {}
    observations: list[dict] = []
    for row in rows:
        for solver in T6.SOLVERS:
            result = row["status"]
            if solver == "euf-viper" and row["relative_path"].startswith(T6.QG7_PREFIX):
                result = "timeout"
            first = observation(
                2.0,
                solver,
                row["relative_path"],
                result,
                carried_forward=False,
                origin_budget=2.0,
                evidence=f"2-{row['id']}-{solver}",
            )
            observations.append(first)
            first_by_key[(row["relative_path"], solver)] = first
    for row in rows:
        for solver in T6.SOLVERS:
            first = first_by_key[(row["relative_path"], solver)]
            if first["result"] in T6.SOLVED_RESULTS:
                final = copy.deepcopy(first)
                final["budget_s"] = 60.0
                final["carried_forward"] = True
            else:
                final = observation(
                    60.0,
                    solver,
                    row["relative_path"],
                    first["result"],
                    carried_forward=False,
                    origin_budget=60.0,
                    evidence=f"60-{row['id']}-{solver}",
                )
            observations.append(final)
    audit = {
        "input_hashes": {
            "manifest_sha256": T6.P0_AUDIT_MANIFEST_SHA256,
            "observation_provenance_sha256": "0" * 64,
            "solver_binary_sha256": copy.deepcopy(T6.SOLVER_BINARY_SHA256S),
        },
        "inputs": {
            "baseline_ids": list(T6.BASELINE_SOLVERS),
            "budgets_s": [2.0, 60.0],
            "campaign_id": "best-overall-qf-uf-2026-07",
            "candidate_id": "euf-viper",
            "instances": len(rows),
            "observation_provenance": observations,
        },
        "schema_version": 1,
        "status": "rejected",
    }
    return audit, rows, rehash_observations(audit)


def projection_template() -> dict:
    return {
        "schema": "euf-viper.t6-theory-dag-manifest.v1",
        "selection": {"candidate_count": 10},
        "gate": {
            "decision_rule": "pass iff at least 8 of 10 sources qualify; otherwise reject",
            "minimum_qualifying_sources": 8,
            "qualifying_source_rule": (
                "D reduction from A is at least 250000 ppm and exceeds both B and C "
                "reductions from A by at least 50000 ppm"
            ),
            "required_d_reduction_from_a_ppm": 250_000,
            "required_increment_over_b_ppm": 50_000,
            "required_increment_over_c_ppm": 50_000,
        },
        "projection_contract": {"arms": {"A": "a", "B": "b", "C": "c", "D": "d"}},
    }


def valid_metrics(source_bytes: int) -> dict[str, int]:
    return {
        "binary_table_apps": 49,
        "closed_table_functions": 1,
        "domain_size": 7,
        "guarded_disequality_clauses": 0,
        "parentheses": T6.MINIMUM_PARENTHESES,
        "source_bytes": source_bytes,
    }


def physical_evidence(rows: list[dict]) -> dict[str, T6.PhysicalSource]:
    return {
        row["relative_path"]: T6.PhysicalSource(
            row["bytes"], row["sha256"], valid_metrics(row["bytes"])
        )
        for row in rows
        if row["relative_path"].startswith(T6.QG7_PREFIX)
    }


def domain_table_source(domain_size: int = 7, *, guarded: bool = False) -> bytes:
    lines = [
        "(set-logic QF_UF)",
        "(set-info :source |fake (assert (distinct bogus names)) source|)",
        "; (assert (distinct comment0 comment1))",
        "(declare-sort U 0)",
        "(declare-fun f (U U) U)",
    ]
    lines.extend(f"(declare-fun e{index} () U)" for index in range(domain_size))
    for left in range(domain_size):
        for right in range(left + 1, domain_size):
            lines.append(f"(assert (not (= e{left} e{right})))")
    for left in range(domain_size):
        for right in range(domain_size):
            choices = " ".join(
                f"(= (f e{left} e{right}) e{value})"
                for value in range(domain_size)
            )
            lines.append(f"(assert (or {choices}))")
    if guarded and domain_size >= 2:
        lines.append("(assert (or (= e0 e1) (not (= (f e0 e0) (f e0 e1)))))")
    lines.append("(check-sat)")
    return ("\n".join(lines) + "\n").encode("ascii")


def huge_domain_table_source() -> bytes:
    data = domain_table_source()
    missing_parentheses = max(0, T6.MINIMUM_PARENTHESES - data.count(b"("))
    data += b";" + (b"(" * missing_parentheses)
    if len(data) < T6.MINIMUM_SOURCE_BYTES:
        data += b"x" * (T6.MINIMUM_SOURCE_BYTES - len(data))
    return data


class T6P0ManifestTests(unittest.TestCase):
    def derive(self, audit: dict, rows: list[dict], provenance_sha256: str) -> dict:
        selection = T6.select_p0_sources(
            audit,
            rows,
            expected_provenance_sha256=provenance_sha256,
            expected_selected=2,
        )
        contract, rule = T6.validate_projection_template(projection_template())
        return T6.build_manifest(
            selection,
            contract,
            rule,
            physical_evidence(rows),
            audit_sha256="d" * 64,
            local_manifest_sha256="e" * 64,
            projection_template_sha256="f" * 64,
        )

    def test_derivation_is_structural_deterministic_and_ratio_bound(self) -> None:
        audit, rows, provenance = fixture()
        first = self.derive(audit, rows, provenance)
        second = self.derive(copy.deepcopy(audit), copy.deepcopy(rows), provenance)
        self.assertEqual(first, second)
        self.assertEqual(first["selection"]["candidate_count"], 2)
        self.assertFalse(first["implementation_or_promotion_eligible"])
        self.assertEqual(first["gate"]["population_sources"], 2)
        self.assertEqual(first["gate"]["minimum_qualifying_sources"], 2)
        self.assertEqual(first["gate"]["threshold_derivation"], "ceil(8 * 2 / 10)")
        self.assertEqual(
            [row["relative_path"] for row in first["sources"]],
            sorted(row["relative_path"] for row in rows[:2]),
        )
        self.assertTrue(
            all(row["source_structure"]["domain_size"] == 7 for row in first["sources"])
        )

    def test_committed_manifest_is_the_exact_current_12_source_output(self) -> None:
        raw = COMMITTED.read_bytes()
        manifest = json.loads(raw)
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "1b3f4e52c8c856e09205baf88b4cff8604f6d864e93373a980ba8d974e205c21",
        )
        expected_paths_and_hashes = [
            ("QF_UF/QG-classification/qg7/iso_icl_nogen001.smt2", "6e9ea0786a672c467f853bf8964283bbdc53c2b51c41e0b0e6fc1fbd8ba34be0"),
            ("QF_UF/QG-classification/qg7/iso_icl_nogen002.smt2", "05295ac0b0b9d7757b3c2b68184ab0504fc90d56582fb97cc891b8a990bf23ac"),
            ("QF_UF/QG-classification/qg7/iso_icl_nogen003.smt2", "5143c7d94d43c5dc077fb8c92dcc7bce4c672c79c03dcbeef901dd8a8532f5a8"),
            ("QF_UF/QG-classification/qg7/iso_icl_nogen004.smt2", "5d487c7da1e60eb8b28ba24d8dc7bc79f40915318ec62d38b44771420d30fc8b"),
            ("QF_UF/QG-classification/qg7/iso_icl_nogen005.smt2", "42ec7341e7b5294e44042572702f6346a990b151fe47d48deb6595d679645ed5"),
            ("QF_UF/QG-classification/qg7/iso_icl_nogen007.smt2", "a6c8c7c8a2a8d1b67574674ea78570977245a728743eca52768b52f9ef165675"),
            ("QF_UF/QG-classification/qg7/iso_icl_nogen_sk001.smt2", "175547f0f09d2238085f5621dfede32190411257315b215abcc2857d96d7e78f"),
            ("QF_UF/QG-classification/qg7/iso_icl_nogen_sk002.smt2", "dbcbdc19201c2a39ce2839becb61f4f4191ff1e9738396d894da962b33611c2b"),
            ("QF_UF/QG-classification/qg7/iso_icl_nogen_sk003.smt2", "a9f9ba690dc07f211035fc43da019da8baff81c6366d51467fd64fff016d9514"),
            ("QF_UF/QG-classification/qg7/iso_icl_nogen_sk004.smt2", "72b5e5242f0de636f031840d9e04e4d1cf55203ac1d0653c10e3576d7561e1b8"),
            ("QF_UF/QG-classification/qg7/iso_icl_nogen_sk005.smt2", "d0c7fd4c118d0f4eafec0851bdf82e52508c08ea6c12a962f1e48045aacdd5c8"),
            ("QF_UF/QG-classification/qg7/iso_icl_nogen_sk007.smt2", "fe3693b6f59618083ca4734c299a200c4cfd5b3edcd15457add15e04663781f7"),
        ]
        self.assertEqual(manifest["schema"], T6.SCHEMA)
        self.assertEqual(
            [(row["relative_path"], row["source_sha256"]) for row in manifest["sources"]],
            expected_paths_and_hashes,
        )
        self.assertEqual(manifest["gate"]["population_sources"], 12)
        self.assertEqual(manifest["gate"]["minimum_qualifying_sources"], 10)
        self.assertEqual(
            manifest["selection"]["audit"]["observation_provenance_sha256"],
            T6.P0_OBSERVATION_PROVENANCE_SHA256,
        )
        paths = [row["relative_path"] for row in manifest["sources"]]
        self.assertEqual(T6.canonical_path_digest(paths), manifest["selection"]["canonical_path_list_sha256"])
        self.assertEqual(T6.canonical_source_digest(manifest["sources"]), manifest["selection"]["source_records_sha256"])
        for row in manifest["sources"]:
            T6.require_domain7_huge(row["source_structure"], row["relative_path"])

    def test_observation_omission_replacement_and_duplicate_are_rejected(self) -> None:
        audit, rows, _ = fixture()
        audit["inputs"]["observation_provenance"].pop()
        tampered = rehash_observations(audit)
        with self.assertRaisesRegex(T6.DerivationError, "observation count"):
            T6.observation_index(audit, {row["relative_path"] for row in rows}, tampered)

        audit, rows, _ = fixture()
        audit["inputs"]["observation_provenance"][0]["relative_path"] = "QF_UF/replaced.smt2"
        tampered = rehash_observations(audit)
        with self.assertRaisesRegex(T6.DerivationError, "outside the frozen corpus"):
            T6.observation_index(audit, {row["relative_path"] for row in rows}, tampered)

        audit, rows, _ = fixture()
        audit["inputs"]["observation_provenance"].append(
            copy.deepcopy(audit["inputs"]["observation_provenance"][0])
        )
        tampered = rehash_observations(audit)
        with self.assertRaisesRegex(T6.DerivationError, "observation count"):
            T6.observation_index(audit, {row["relative_path"] for row in rows}, tampered)

    def test_swapped_or_tampered_provenance_fails_after_outer_hash_override(self) -> None:
        audit, rows, frozen = fixture()
        observations = audit["inputs"]["observation_provenance"]
        observations[0], observations[1] = observations[1], observations[0]
        rehash_observations(audit)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "audit.json"
            path.write_text(json.dumps(audit), encoding="utf-8")
            blob = T6.read_immutable_file(path, "tampered audit")
            self.assertEqual(T6.require_hash(blob, blob.sha256, "P0 audit"), blob.sha256)
            parsed = T6.parse_json_bytes(blob.data, "tampered audit")
        with self.assertRaisesRegex(T6.DerivationError, "frozen observation provenance"):
            T6.select_p0_sources(
                parsed,
                rows,
                expected_provenance_sha256=frozen,
                expected_selected=2,
            )

        audit, rows, frozen = fixture()
        audit["inputs"]["observation_provenance"][0]["source_raw_sha256"] = "9" * 64
        rehash_observations(audit)
        with self.assertRaisesRegex(T6.DerivationError, "frozen observation provenance"):
            T6.observation_index(audit, {row["relative_path"] for row in rows}, frozen)

    def test_observation_row_schema_and_carry_semantics_are_independently_checked(self) -> None:
        audit, rows, _ = fixture()
        final = next(
            row
            for row in audit["inputs"]["observation_provenance"]
            if row["budget_s"] == 60.0 and row["solver_id"] == "z3-default"
        )
        final["carried_forward"] = False
        final["origin_budget_s"] = 60.0
        tampered = rehash_observations(audit)
        with self.assertRaisesRegex(T6.DerivationError, "was not carried forward exactly"):
            T6.observation_index(audit, {row["relative_path"] for row in rows}, tampered)

        audit, rows, _ = fixture()
        audit["inputs"]["observation_provenance"][0]["injected"] = True
        tampered = rehash_observations(audit)
        with self.assertRaisesRegex(T6.DerivationError, "field drift"):
            T6.observation_index(audit, {row["relative_path"] for row in rows}, tampered)

    def test_comparator_loss_or_candidate_solve_changes_the_exact_selection(self) -> None:
        target = "QF_UF/QG-classification/qg7/iso_icl_nogen001.smt2"
        for solver, result in (("z3-default", "timeout"), ("euf-viper", "unsat")):
            audit, rows, _ = fixture()
            pair = [
                row
                for row in audit["inputs"]["observation_provenance"]
                if row["relative_path"] == target and row["solver_id"] == solver
            ]
            first = next(row for row in pair if row["budget_s"] == 2.0)
            final = next(row for row in pair if row["budget_s"] == 60.0)
            first["result"] = result
            if result in T6.SOLVED_RESULTS:
                replacement = copy.deepcopy(first)
                replacement["budget_s"] = 60.0
                replacement["carried_forward"] = True
                final.clear()
                final.update(replacement)
            else:
                final["result"] = result
                final["carried_forward"] = False
                final["origin_budget_s"] = 60.0
            tampered = rehash_observations(audit)
            with self.assertRaisesRegex(T6.DerivationError, "shared-deficit count"):
                T6.select_p0_sources(
                    audit,
                    rows,
                    expected_provenance_sha256=tampered,
                    expected_selected=2,
                )

    def test_paths_reject_every_alias_control_and_traversal_form(self) -> None:
        bad_paths = (
            "QF_UF//x.smt2",
            "./QF_UF/x.smt2",
            "QF_UF/./x.smt2",
            "QF_UF/../x.smt2",
            "QF_UF/..",
            "/QF_UF/x.smt2",
            "QF_UF\\x.smt2",
            "QF_UF/x.smt2/",
            "QF_UF/\x00x.smt2",
            "QF_UF/\x7fx.smt2",
            "QF_UF/\u202ex.smt2",
            "QF_UF/e\u0301.smt2",
        )
        for value in bad_paths:
            with self.subTest(value=repr(value)):
                with self.assertRaises(T6.DerivationError):
                    T6.canonical_relative_path(value, "attack path")
        self.assertEqual(
            T6.canonical_relative_path("QF_UF/a/b.smt2", "valid path"),
            "QF_UF/a/b.smt2",
        )

    def test_corpus_rows_require_canonical_paths_and_id_order(self) -> None:
        row = source(0, "QF_UF/a.smt2")
        data = (json.dumps(row) + "\n").encode("utf-8")
        self.assertEqual(T6.load_corpus_manifest(data, 1), [row])
        for bad in ("QF_UF//a.smt2", "QF_UF/./a.smt2", "QF_UF/../a.smt2"):
            changed = dict(row, relative_path=bad)
            with self.assertRaises(T6.DerivationError):
                T6.load_corpus_manifest((json.dumps(changed) + "\n").encode(), 1)
        changed = dict(row, id=1)
        with self.assertRaisesRegex(T6.DerivationError, "id/order drift"):
            T6.load_corpus_manifest((json.dumps(changed) + "\n").encode(), 1)

    def test_all_input_types_are_hashed_and_parsed_from_one_snapshot(self) -> None:
        corpus_row = source(0, "QF_UF/a.smt2")
        cases = (
            (b'{"value": 1}\n', lambda data: T6.parse_json_bytes(data, "audit")),
            ((json.dumps(corpus_row) + "\n").encode(), lambda data: T6.load_corpus_manifest(data, 1)),
            (json.dumps(projection_template()).encode(), lambda data: T6.parse_json_bytes(data, "template")),
        )
        with tempfile.TemporaryDirectory() as temporary:
            for index, (original, parser) in enumerate(cases):
                path = Path(temporary) / f"input-{index}"
                path.write_bytes(original)
                blob = T6.read_immutable_file(path, f"input {index}")
                path.write_bytes(b"tampered after snapshot")
                self.assertEqual(blob.sha256, hashlib.sha256(original).hexdigest())
                parser(blob.data)

    def test_structured_parser_proves_table_shape_and_ignores_fake_text(self) -> None:
        metrics = T6.analyze_smt2_source(domain_table_source(), "synthetic qg7")
        self.assertEqual(metrics["domain_size"], 7)
        self.assertEqual(metrics["closed_table_functions"], 1)
        self.assertEqual(metrics["binary_table_apps"], 49)
        self.assertEqual(metrics["guarded_disequality_clauses"], 0)

        guarded = T6.analyze_smt2_source(
            domain_table_source(guarded=True), "guarded synthetic qg7"
        )
        self.assertEqual(guarded["guarded_disequality_clauses"], 1)
        domain_six = T6.analyze_smt2_source(domain_table_source(6), "domain six")
        self.assertEqual(domain_six["domain_size"], 6)

    def test_every_domain7_huge_predicate_is_mandatory(self) -> None:
        baseline = valid_metrics(T6.MINIMUM_SOURCE_BYTES)
        attacks = {
            "domain_size = 7": ("domain_size", 6),
            "closed_table_functions >= 1": ("closed_table_functions", 0),
            "binary_table_apps >= 49": ("binary_table_apps", 48),
            "guarded_disequality_clauses = 0": ("guarded_disequality_clauses", 1),
            "parens >= 80000": ("parentheses", T6.MINIMUM_PARENTHESES - 1),
            "bytes >= 6000000": ("source_bytes", T6.MINIMUM_SOURCE_BYTES - 1),
        }
        T6.require_domain7_huge(baseline, "valid")
        for message, (field, value) in attacks.items():
            with self.subTest(field=field):
                changed = dict(baseline, **{field: value})
                with self.assertRaisesRegex(T6.DerivationError, message):
                    T6.require_domain7_huge(changed, "attack")

    def test_physical_source_hash_structure_and_identity_are_verified(self) -> None:
        data = huge_domain_table_source()
        path_one = "QF_UF/QG-classification/qg7/one001.smt2"
        path_two = "QF_UF/QG-classification/qg7/two001.smt2"
        path_symlink = "QF_UF/QG-classification/qg7/link001.smt2"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file_one = root / path_one
            file_two = root / path_two
            file_symlink = root / path_symlink
            file_one.parent.mkdir(parents=True)
            file_one.write_bytes(data)
            row_one = source(0, path_one)
            row_one.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            verified = T6.verify_selected_sources(root, [path_one], {path_one: row_one})
            self.assertEqual(verified[path_one].metrics["binary_table_apps"], 49)

            wrong_hash = dict(row_one, sha256="0" * 64)
            with self.assertRaisesRegex(T6.DerivationError, "SHA-256 mismatch"):
                T6.verify_selected_sources(root, [path_one], {path_one: wrong_hash})

            file_symlink.symlink_to(file_one)
            row_symlink = source(1, path_symlink)
            row_symlink.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            with self.assertRaisesRegex(T6.DerivationError, "cannot open physical source"):
                T6.verify_selected_sources(
                    root, [path_symlink], {path_symlink: row_symlink}
                )

            os.link(file_one, file_two)
            row_two = source(1, path_two)
            row_two.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            with self.assertRaisesRegex(T6.DerivationError, "duplicate physical source identity"):
                T6.verify_selected_sources(
                    root,
                    [path_one, path_two],
                    {path_one: row_one, path_two: row_two},
                )

    def test_qg_filename_cannot_substitute_for_physical_structure(self) -> None:
        relative_path = "QF_UF/QG-classification/qg7/fake001.smt2"
        data = b"(set-logic QF_UF)\n(assert true)\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / relative_path
            path.parent.mkdir(parents=True)
            path.write_bytes(data)
            row = source(0, relative_path)
            row.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            with self.assertRaisesRegex(T6.DerivationError, "outside DOMAIN7_HUGE"):
                T6.verify_selected_sources(root, [relative_path], {relative_path: row})

    def test_physical_source_snapshot_survives_path_replacement(self) -> None:
        original = domain_table_source()
        relative_path = "QF_UF/QG-classification/qg7/race001.smt2"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / relative_path
            path.parent.mkdir(parents=True)
            path.write_bytes(original)
            root_descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                blob = T6._read_relative_source(root_descriptor, relative_path, relative_path)
            finally:
                os.close(root_descriptor)
            path.write_bytes(b"(set-logic QF_UF)\n(assert false)\n")
            self.assertEqual(blob.sha256, hashlib.sha256(original).hexdigest())
            self.assertEqual(T6.analyze_smt2_source(blob.data, relative_path)["domain_size"], 7)

    def test_parent_ratio_and_production_counts_cannot_be_reconfigured(self) -> None:
        expected = {1: 1, 2: 2, 10: 8, 11: 9, 12: 10, 13: 11}
        for population, threshold in expected.items():
            self.assertEqual(T6.qualifying_threshold(population), threshold)
        T6.require_frozen_counts(7_503, 12)
        for corpus_count, selected_count in ((7_502, 12), (7_503, 11), (3, 2)):
            with self.assertRaisesRegex(T6.DerivationError, "incompatible"):
                T6.require_frozen_counts(corpus_count, selected_count)

        changed = projection_template()
        changed["selection"]["candidate_count"] = 11
        changed["gate"]["minimum_qualifying_sources"] = 9
        with self.assertRaisesRegex(T6.DerivationError, "parent 8/10 gate drift"):
            T6.validate_projection_template(changed)

    def test_source_status_and_physical_evidence_are_bound(self) -> None:
        audit, rows, provenance = fixture()
        rows[0]["status"] = "sat"
        with self.assertRaisesRegex(T6.DerivationError, "comparator/source status"):
            self.derive(audit, rows, provenance)

        audit, rows, provenance = fixture()
        selection = T6.select_p0_sources(
            audit,
            rows,
            expected_provenance_sha256=provenance,
            expected_selected=2,
        )
        contract, rule = T6.validate_projection_template(projection_template())
        evidence = physical_evidence(rows)
        first = selection.selected_paths[0]
        bad_metrics = dict(evidence[first].metrics, binary_table_apps=48)
        evidence[first] = T6.PhysicalSource(
            evidence[first].source_bytes, evidence[first].source_sha256, bad_metrics
        )
        with self.assertRaisesRegex(T6.DerivationError, "binary_table_apps"):
            T6.build_manifest(
                selection,
                contract,
                rule,
                evidence,
                audit_sha256="d" * 64,
                local_manifest_sha256="e" * 64,
                projection_template_sha256="f" * 64,
            )

    def test_atomic_output_is_canonical_deterministic_and_replaces_existing_file(self) -> None:
        audit, rows, provenance = fixture()
        payload = self.derive(audit, rows, provenance)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text("stale", encoding="ascii")
            first_digest = T6.atomic_write_json(path, payload)
            first = path.read_bytes()
            second_digest = T6.atomic_write_json(path, payload)
            self.assertEqual(path.read_bytes(), first)
            self.assertEqual(first_digest, second_digest)
            self.assertEqual(first_digest, hashlib.sha256(first).hexdigest())
            self.assertEqual(json.loads(first), payload)
            self.assertTrue(first.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
