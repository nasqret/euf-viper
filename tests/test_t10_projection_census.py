from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scripts.bench import audit_t10_projection_census as audit
from scripts.bench import run_t10_projection_census as census


FROG_ONE = "QF_UF/2018-Goel-hwbench/QF_UF_frogs.1.prop1_ab_br_max.smt2"
QG_PATH = "QF_UF/QG-classification/qg5/iso_icl001.smt2"
ADDITIONAL_PATH = "QF_UF/tests/additional.smt2"


FAKE_PROJECTOR_TEMPLATE = r'''#!__PYTHON__
import hashlib
import os
import sys
import time

EXPECTED_ENV = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
if sys.platform == "darwin":
    os.environ.pop("__CF_USER_TEXT_ENCODING", None)
if dict(os.environ) != EXPECTED_ENV:
    print(f"ambient environment leaked: {sorted(os.environ)}", file=sys.stderr)
    raise SystemExit(9)
if sys.argv[1:] != ["project-t10", "source.smt2"]:
    print(f"unexpected argv: {sys.argv!r}", file=sys.stderr)
    raise SystemExit(9)
if os.path.exists("QF_UF"):
    print("projector cwd leaked the corpus", file=sys.stderr)
    raise SystemExit(9)

source = open(sys.argv[2], "rb").read()
marker = source.decode("ascii").strip()
if marker == "FLOOD":
    os.write(1, b"x" * (__OUTPUT_LIMIT__ + 4096))
    raise SystemExit(9)
if marker == "DESCEND":
    try:
        child = os.fork()
    except OSError as error:
        print(f"descendant denied: {error}", file=sys.stderr)
        raise SystemExit(9)
    if child == 0:
        time.sleep(60)
        os._exit(0)

selected = marker in {"SELECT", "EXTRA", "DESCEND"}
baseline = hashlib.sha256(b"baseline\0" + source).hexdigest()
atom_map = hashlib.sha256(b"atom-map\0" + source).hexdigest()
clauses = hashlib.sha256(b"closed-clauses\0" + source).hexdigest()
values = {
    "mode": "closed-atom-auto",
    "selector_selected": selected,
    "selected": selected,
    "reason": "selected" if selected else "finite_added_nonzero",
    "finite_added": 0 if selected else 1,
    "covered_finite_terms": 0,
    "closed_table_functions": 0,
    "all_different_clique_lb": 48,
    "disequality_graph_edges": 1128,
    "disequality_clique_excess_edges": 0,
    "equality_graph_vertices": 2500,
    "equality_graph_edges": 10000,
    "applications": 2,
    "backend": "kissat",
    "terms": 100,
    "baseline_vars": 10,
    "baseline_clauses": 20,
    "baseline_literal_slots": 30,
    "baseline_before_sha256": baseline,
    "baseline_after_sha256": baseline,
    "atom_map_before_sha256": atom_map,
    "atom_map_after_sha256": atom_map,
    "projected_closed_clauses": 2 if selected else 0,
    "projected_literal_slots": 6 if selected else 0,
    "projected_max_clause_width": 3 if selected else 0,
    "projected_added_vars": 0,
    "projected_new_atoms": 0,
    "projected_fill_edges": 0,
    "projected_transitivity_clauses": 0,
    "materialized_closed_clauses": 2 if selected else 0,
    "materialized_literal_slots": 6 if selected else 0,
    "materialized_max_clause_width": 3 if selected else 0,
    "materialized_added_vars": 0,
    "materialized_new_atoms": 0,
    "materialized_fill_edges": 0,
    "materialized_transitivity_clauses": 0,
    "projected_clauses_sha256": clauses if selected else "0" * 64,
    "materialized_clauses_sha256": clauses if selected else "0" * 64,
    "ackermann_replay_clauses": 2 if selected else 0,
    "ackermann_replay_failures": 0,
    "parse_errors": 0,
    "hash_errors": 0,
    "arithmetic_errors": 0,
    "allocation_errors": 0,
    "planning_errors": 0,
    "sat_calls": 1 if marker == "SAT_CALL" else 0,
}
print("t10_projection_version 1")
for key in sorted(values):
    value = values[key]
    if isinstance(value, bool):
        value = int(value)
    print(f"{key} {value}")
raise SystemExit(0 if selected else 3)
'''


def expected_projection(source: bytes, selected: bool) -> dict[str, object]:
    baseline = hashlib.sha256(b"baseline\0" + source).hexdigest()
    atom_map = hashlib.sha256(b"atom-map\0" + source).hexdigest()
    clauses = hashlib.sha256(b"closed-clauses\0" + source).hexdigest()
    projection: dict[str, object] = {
        "mode": "closed-atom-auto",
        "selector_selected": selected,
        "selected": selected,
        "reason": "selected" if selected else "finite_added_nonzero",
        "finite_added": 0 if selected else 1,
        "covered_finite_terms": 0,
        "closed_table_functions": 0,
        "all_different_clique_lb": 48,
        "disequality_graph_edges": 1128,
        "disequality_clique_excess_edges": 0,
        "equality_graph_vertices": 2500,
        "equality_graph_edges": 10000,
        "applications": 2,
        "backend": "kissat",
        "terms": 100,
        "baseline_vars": 10,
        "baseline_clauses": 20,
        "baseline_literal_slots": 30,
        "baseline_before_sha256": baseline,
        "baseline_after_sha256": baseline,
        "atom_map_before_sha256": atom_map,
        "atom_map_after_sha256": atom_map,
        "projected_closed_clauses": 2 if selected else 0,
        "projected_literal_slots": 6 if selected else 0,
        "projected_max_clause_width": 3 if selected else 0,
        "projected_added_vars": 0,
        "projected_new_atoms": 0,
        "projected_fill_edges": 0,
        "projected_transitivity_clauses": 0,
        "materialized_closed_clauses": 2 if selected else 0,
        "materialized_literal_slots": 6 if selected else 0,
        "materialized_max_clause_width": 3 if selected else 0,
        "materialized_added_vars": 0,
        "materialized_new_atoms": 0,
        "materialized_fill_edges": 0,
        "materialized_transitivity_clauses": 0,
        "projected_clauses_sha256": clauses if selected else census.ZERO_SHA256,
        "materialized_clauses_sha256": clauses if selected else census.ZERO_SHA256,
        "ackermann_replay_clauses": 2 if selected else 0,
        "ackermann_replay_failures": 0,
        "parse_errors": 0,
        "hash_errors": 0,
        "arithmetic_errors": 0,
        "allocation_errors": 0,
        "planning_errors": 0,
        "sat_calls": 0,
    }
    return projection


def render_projection(projection: dict[str, object]) -> bytes:
    lines = ["t10_projection_version 1"]
    for key in sorted(projection):
        value = projection[key]
        if type(value) is bool:
            value = int(value)
        lines.append(f"{key} {value}")
    return ("\n".join(lines) + "\n").encode("ascii")


class CensusFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.corpus = root / "corpus"
        self.rows: list[dict[str, object]] = []
        self.payloads: dict[str, bytes] = {}

    def add(self, relative_path: str, marker: str) -> str:
        path = self.corpus / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = (marker + "\n").encode("ascii")
        path.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        self.payloads[relative_path] = payload
        self.rows.append(
            {
                "id": len(self.rows),
                "path": f"/ambient/not/trusted/{relative_path}",
                "relative_path": relative_path,
                "bytes": len(payload),
                "sha256": digest,
            }
        )
        return digest

    def manifest(self, name: str = "manifest.jsonl", *, reverse: bool = False) -> Path:
        path = self.root / name
        rows = list(reversed(self.rows)) if reverse else self.rows
        path.write_bytes(b"".join(census.canonical_json_bytes(row) for row in rows))
        return path

    def binary(self, name: str = "fake-projector.py") -> Path:
        path = self.root / name
        script = (
            FAKE_PROJECTOR_TEMPLATE.replace("__PYTHON__", sys.executable)
            .replace("__OUTPUT_LIMIT__", str(census.MAX_PROJECTOR_OUTPUT_BYTES))
        )
        path.write_text(script, encoding="ascii")
        path.chmod(0o755)
        return path

    def sources(self) -> list[census.ManifestSource]:
        payload = b"".join(census.canonical_json_bytes(row) for row in self.rows)
        return census.parse_manifest(payload)

    def contract(
        self,
        manifest: Path,
        *,
        selected_paths: tuple[str, ...] = (census.TARGET_PATH,),
        control_paths: tuple[str, ...] = (FROG_ONE, QG_PATH),
        required_paths: tuple[str, ...] = (census.TARGET_PATH, FROG_ONE),
        expected_qg_sources: int | None = None,
    ) -> census.EvidenceContract:
        sources = self.sources()
        by_path = {source.relative_path: source for source in sources}
        controls = tuple(
            sorted((path, by_path[path].source_sha256) for path in control_paths)
        )
        control_payload = census._test_control_payload(controls)
        control = census.ControlBinding(
            census.sha256_bytes(control_payload),
            len(control_payload),
            len(controls),
            controls,
        )
        if expected_qg_sources is None:
            expected_qg_sources = sum(
                source.relative_path.startswith(census.QG_PREFIX) for source in sources
            )
        return census.EvidenceContract(
            kind="test",
            expected_sources=len(sources),
            manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
            source_set_sha256=census.canonical_hash(census.source_set_value(sources)),
            expected_qg_sources=expected_qg_sources,
            required_sources=tuple(
                sorted((path, by_path[path].source_sha256) for path in required_paths)
            ),
            control=control,
            expected_selected_sources=tuple(
                sorted((path, by_path[path].source_sha256) for path in selected_paths)
            ),
            require_clean_git=False,
        )

    def run(
        self,
        manifest: Path,
        contract: census.EvidenceContract,
        *,
        suffix: str = "",
    ) -> tuple[Path, Path, list[dict[str, object]], dict[str, object]]:
        records = self.root / f"records{suffix}.jsonl"
        summary = self.root / f"summary{suffix}.json"
        rows, aggregate = census.run_census(
            manifest,
            self.corpus,
            self.binary(),
            records,
            summary,
            timeout_seconds=2.0,
            contract=contract,
        )
        return records, summary, rows, aggregate


def complete_fixture(root: Path) -> tuple[CensusFixture, Path, census.EvidenceContract]:
    fixture = CensusFixture(root)
    fixture.add(census.TARGET_PATH, "SELECT")
    fixture.add(FROG_ONE, "REJECT")
    fixture.add(QG_PATH, "REJECT")
    fixture.add(ADDITIONAL_PATH, "REJECT")
    manifest = fixture.manifest()
    return fixture, manifest, fixture.contract(manifest)


def audit_fixture(
    fixture: CensusFixture,
    contract: census.EvidenceContract,
    manifest: Path,
    records: Path,
    summary: Path,
    receipt_name: str = "receipt.json",
) -> dict[str, object]:
    return audit.audit_census(
        manifest,
        fixture.corpus,
        fixture.binary(),
        records,
        summary,
        fixture.root / receipt_name,
        contract=contract,
    )


def read_records(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines()]


def write_immutable(path: Path, payload: bytes) -> None:
    path.chmod(0o600)
    path.write_bytes(payload)
    path.chmod(0o400)


def rewrite_chain(records_path: Path, summary_path: Path, mutation) -> None:
    records = read_records(records_path)
    mutation(records)
    previous = census.ZERO_SHA256
    for record in records:
        record["previous_record_sha256"] = previous
        record.pop("record_sha256", None)
        digest = census.canonical_hash(record)
        record["record_sha256"] = digest
        previous = digest
    records_payload = census.encode_records(records)
    summary = json.loads(summary_path.read_text(encoding="ascii"))
    summary["records_bytes"] = len(records_payload)
    summary["records_sha256"] = census.sha256_bytes(records_payload)
    summary["record_chain_head"] = previous
    write_immutable(records_path, records_payload)
    write_immutable(summary_path, census.canonical_json_bytes(summary))


class ProductionContractTests(unittest.TestCase):
    def test_production_population_target_and_design_are_frozen(self) -> None:
        self.assertEqual(census.PRODUCTION_SOURCE_COUNT, 7503)
        self.assertEqual(
            census.PRODUCTION_MANIFEST_SHA256,
            "32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4",
        )
        self.assertEqual(
            census.TARGET_SHA256,
            "cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112",
        )
        self.assertEqual(
            census.PRODUCTION_CONTRACT.expected_selected_sources,
            ((census.TARGET_PATH, census.TARGET_SHA256),),
        )
        self.assertEqual(census.DESIGN_COMMIT, "05de7841ac005e2a251d71e1a2394f8980cbdd17")
        design = census._run_git_bytes(["cat-file", "blob", census.DESIGN_BLOB], "test design")
        self.assertEqual(hashlib.sha256(design).hexdigest(), census.DESIGN_SHA256)

    def test_projection_schema_is_centralized_and_independently_duplicated(self) -> None:
        self.assertEqual(
            census.ACCEPTED_PROJECTION_KEYS,
            census.COUNT_FIELDS | census.BOOLEAN_FIELDS | census.HASH_FIELDS | census.TOKEN_FIELDS,
        )
        self.assertEqual(census.projection_schema_sha256(), audit.projection_schema_sha256())
        audit._assert_runner_contract_match()
        with mock.patch.object(
            census,
            "ACCEPTED_PROJECTION_KEYS",
            census.ACCEPTED_PROJECTION_KEYS | {"elapsed_ns"},
        ):
            with self.assertRaisesRegex(audit.AuditError, "accepted projection keys"):
                audit._assert_runner_contract_match()

    def test_production_cli_has_no_population_or_mode_override(self) -> None:
        runner_options = {action.dest for action in census.build_argument_parser()._actions}
        auditor_options = {action.dest for action in audit.build_argument_parser()._actions}
        self.assertNotIn("expected_sources", runner_options)
        self.assertNotIn("expected_sources", auditor_options)
        self.assertNotIn("mode", runner_options)
        self.assertIn("corpus_root", runner_options)

    def test_callers_cannot_weaken_the_production_contract(self) -> None:
        weakened = replace(census.PRODUCTION_CONTRACT, manifest_sha256="f" * 64)
        with self.assertRaisesRegex(census.CensusError, "alter.*production"):
            census._assert_contract_ready(weakened)
        with self.assertRaisesRegex(audit.AuditError, "alter.*production"):
            audit._normalize_contract(weakened)


class ProjectionParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.projection = expected_projection(b"SELECT\n", True)

    def test_exact_projection_parses(self) -> None:
        parsed = census.parse_projection_report(render_projection(self.projection), 0)
        self.assertEqual(parsed, self.projection)

    def test_unknown_missing_duplicate_and_timing_fields_fail_closed(self) -> None:
        rendered = render_projection(self.projection).decode("ascii")
        duplicate = rendered + "reason selected\n"
        with self.assertRaisesRegex(census.CensusError, "duplicate key"):
            census.parse_projection_report(duplicate.encode("ascii"), 0)
        for field in ("elapsed_ns", "result", "expected_status", "solver_calls", "mode_source"):
            lines = rendered.splitlines()
            lines.append(f"{field} 0")
            with self.subTest(field=field):
                with self.assertRaisesRegex(census.CensusError, "unknown fields"):
                    census.parse_projection_report(("\n".join(lines) + "\n").encode("ascii"), 0)
        missing = "\n".join(
            line for line in rendered.splitlines() if not line.startswith("planning_errors ")
        ) + "\n"
        with self.assertRaisesRegex(census.CensusError, "missing fields"):
            census.parse_projection_report(missing.encode("ascii"), 0)

    def test_noncanonical_counts_booleans_and_return_codes_fail(self) -> None:
        cases = (
            ("projected_closed_clauses", "02"),
            ("projected_closed_clauses", "-1"),
            ("projected_closed_clauses", "2.0"),
            ("selected", "true"),
        )
        for field, value in cases:
            projection = dict(self.projection)
            projection[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(census.CensusError):
                    census.parse_projection_report(render_projection(projection), 0)
        with self.assertRaisesRegex(census.CensusError, "return code"):
            census.parse_projection_report(render_projection(self.projection), 3)

    def test_sat_and_error_counts_fail_closed(self) -> None:
        projection = dict(self.projection)
        projection["sat_calls"] = 1
        with self.assertRaisesRegex(census.CensusError, "SAT call"):
            census.parse_projection_report(render_projection(projection), 0)
        for field in census.ERROR_COUNT_FIELDS:
            projection = dict(self.projection)
            projection[field] = 1
            with self.subTest(field=field):
                with self.assertRaisesRegex(census.CensusError, field):
                    census.validate_projection_semantics(projection, "adversarial")

    def test_strict_json_rejects_duplicate_and_nonfinite_values(self) -> None:
        with self.assertRaisesRegex(census.CensusError, "duplicate JSON key"):
            census.strict_json_loads('{"id":1,"id":2}', "duplicate")
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant):
                with self.assertRaisesRegex(census.CensusError, "non-finite"):
                    census.strict_json_loads(f'{{"value":{constant}}}', "nonfinite")


class ProjectionSemanticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.projection = expected_projection(b"SELECT\n", True)

    def test_baseline_and_atom_hashes_must_be_nonzero_and_unchanged(self) -> None:
        for field in ("baseline_after_sha256", "atom_map_after_sha256"):
            projection = dict(self.projection)
            projection[field] = "f" * 64
            with self.subTest(field=field):
                with self.assertRaisesRegex(census.CensusError, "hash changed"):
                    census.validate_projection_semantics(projection, "hash-drift")
        projection = dict(self.projection)
        projection["baseline_before_sha256"] = census.ZERO_SHA256
        projection["baseline_after_sha256"] = census.ZERO_SHA256
        with self.assertRaisesRegex(census.CensusError, "cannot be zero"):
            census.validate_projection_semantics(projection, "zero-hash")

    def test_selected_bounds_side_effects_and_exact_materialization(self) -> None:
        cases = (
            ("projected_closed_clauses", 0, "closed-clause"),
            ("projected_closed_clauses", 4097, "closed-clause"),
            ("projected_literal_slots", 16385, "literal-slot"),
            ("projected_max_clause_width", 5, "clause width"),
            ("projected_added_vars", 1, "materialized_added_vars differs"),
            ("projected_new_atoms", 1, "materialized_new_atoms differs"),
            ("projected_fill_edges", 1, "materialized_fill_edges differs"),
            ("projected_transitivity_clauses", 1, "materialized_transitivity_clauses differs"),
            ("materialized_closed_clauses", 3, "differs from exact"),
            ("ackermann_replay_clauses", 1, "replay count"),
        )
        for field, value, pattern in cases:
            projection = dict(self.projection)
            projection[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(census.CensusError, pattern):
                    census.validate_projection_semantics(projection, "bounds")

    def test_clause_hashes_must_be_nonzero_and_equal(self) -> None:
        projection = dict(self.projection)
        projection["projected_clauses_sha256"] = census.ZERO_SHA256
        projection["materialized_clauses_sha256"] = census.ZERO_SHA256
        with self.assertRaisesRegex(census.CensusError, "zero clause hash"):
            census.validate_projection_semantics(projection, "zero")
        projection = dict(self.projection)
        projection["materialized_clauses_sha256"] = "f" * 64
        with self.assertRaisesRegex(census.CensusError, "hashes differ"):
            census.validate_projection_semantics(projection, "mismatch")

    def test_selector_false_negative_and_rejected_plan_data_fail(self) -> None:
        projection = dict(self.projection)
        projection["selector_selected"] = False
        projection["selected"] = False
        projection["reason"] = "finite_added_nonzero"
        with self.assertRaisesRegex(census.CensusError, "every selector condition"):
            census.validate_projection_semantics(projection, "false-negative")
        rejected = expected_projection(b"REJECT\n", False)
        rejected["projected_closed_clauses"] = 1
        with self.assertRaisesRegex(census.CensusError, "rejected row"):
            census.validate_projection_semantics(rejected, "reject-data")

    def test_selector_rejection_order_matches_the_frozen_t9_facts(self) -> None:
        cases = (
            ({"finite_added": 1}, "finite_added_nonzero"),
            ({"applications": 257}, "application_count_cap"),
            ({"backend": "fallback"}, "backend_not_kissat"),
            ({"covered_finite_terms": 1}, "covered_finite_terms_nonzero"),
            ({"closed_table_functions": 1}, "closed_table_functions_nonzero"),
            (
                {
                    "all_different_clique_lb": 47,
                    "disequality_graph_edges": 1081,
                },
                "all_different_clique_below_minimum",
            ),
            (
                {
                    "disequality_clique_excess_edges": 9,
                    "disequality_graph_edges": 1137,
                },
                "disequality_clique_excess_edges",
            ),
            (
                {"equality_graph_vertices": 2499},
                "equality_graph_vertices_below_minimum",
            ),
            (
                {"equality_graph_edges": 9999},
                "equality_graph_edges_below_minimum",
            ),
        )
        for changes, expected in cases:
            projection = dict(self.projection)
            projection.update(changes)
            with self.subTest(expected=expected):
                self.assertEqual(
                    census.selector_reason(projection, "selector-order"),
                    expected,
                )


class CensusAndAuditTests(unittest.TestCase):
    def test_deterministic_census_and_independent_selected_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, manifest, contract = complete_fixture(root)
            first_records, first_summary, rows, aggregate = fixture.run(
                manifest, contract, suffix="-first"
            )
            second_records, second_summary, _, second_aggregate = fixture.run(
                manifest, contract, suffix="-second"
            )
            self.assertEqual(len(rows), 4)
            self.assertEqual(aggregate, second_aggregate)
            self.assertEqual(first_records.read_bytes(), second_records.read_bytes())
            self.assertEqual(first_summary.read_bytes(), second_summary.read_bytes())
            self.assertEqual(stat.S_IMODE(first_records.stat().st_mode), 0o400)
            record = next(
                row for row in rows if row["source"]["relative_path"] == census.TARGET_PATH
            )
            self.assertEqual(
                record["source"]["opened_sha256"],
                contract.expected_selected_sources[0][1],
            )
            self.assertEqual(aggregate["opened_source_count"], 4)
            self.assertIn("python", aggregate["provenance"])

            receipt = audit_fixture(
                fixture,
                contract,
                manifest,
                first_records,
                first_summary,
            )
            self.assertEqual(receipt["status"], "pass_test_only")
            self.assertEqual(receipt["replayed_selected_count"], 1)
            self.assertEqual(
                receipt["selected_projection_sha256"],
                receipt["replayed_selected_projection_sha256"],
            )
            self.assertEqual(receipt["selected_projection_bindings"][0]["closed_clauses"], 2)
            self.assertEqual(stat.S_IMODE((root / "receipt.json").stat().st_mode), 0o400)

    def test_exact_selected_population_rejects_missing_and_extra_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, manifest, contract = complete_fixture(root)
            missing = replace(
                contract,
                expected_selected_sources=(
                    (FROG_ONE, hashlib.sha256(b"REJECT\n").hexdigest()),
                ),
            )
            with self.assertRaisesRegex(census.CensusError, "selected population mismatch"):
                fixture.run(manifest, missing, suffix="-missing")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = CensusFixture(root)
            fixture.add(census.TARGET_PATH, "SELECT")
            fixture.add(FROG_ONE, "REJECT")
            fixture.add(QG_PATH, "REJECT")
            fixture.add(ADDITIONAL_PATH, "EXTRA")
            manifest = fixture.manifest()
            contract = fixture.contract(manifest)
            with self.assertRaisesRegex(census.CensusError, "selected population mismatch"):
                fixture.run(manifest, contract)

    def test_manifest_bytes_and_source_set_are_both_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, manifest, contract = complete_fixture(root)
            drifted = fixture.manifest("drifted.jsonl", reverse=True)
            with self.assertRaisesRegex(census.CensusError, "manifest SHA-256 mismatch"):
                fixture.run(drifted, contract)
            source_contract = replace(contract, source_set_sha256="f" * 64)
            with self.assertRaisesRegex(census.CensusError, "source-set digest mismatch"):
                fixture.run(manifest, source_contract, suffix="-source-set")

    def test_ambient_environment_and_physical_source_path_do_not_leak(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, manifest, contract = complete_fixture(root)
            hostile = {
                "HOME": "/ambient/home",
                "PATH": "/ambient/path",
                "EUF_VIPER_T10_ACKERMANN": "timing",
                "EUF_VIPER_RESULT": "sat",
            }
            with mock.patch.dict(os.environ, hostile, clear=False):
                records, summary, _, _ = fixture.run(manifest, contract)
            receipt = audit_fixture(fixture, contract, manifest, records, summary)
            self.assertEqual(receipt["status"], "pass_test_only")

    def test_output_flood_descendant_and_existing_outputs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = CensusFixture(root)
            binary = fixture.binary()
            with census.ProjectorSnapshot(binary) as projector:
                with self.assertRaises(census.CensusError):
                    census.run_projection(projector, b"FLOOD\n", "flood", 2.0)
                with self.assertRaises(census.CensusError):
                    census.run_projection(projector, b"DESCEND\n", "descendant", 2.0)
            existing = root / "existing.json"
            existing.write_bytes(b"preserve\n")
            with self.assertRaisesRegex(census.CensusError, "overwrite"):
                census.immutable_write_new(existing, b"replace\n")
            self.assertEqual(existing.read_bytes(), b"preserve\n")


class AdversarialAuditTests(unittest.TestCase):
    def _run(self, root: Path):
        fixture, manifest, contract = complete_fixture(root)
        records, summary, _, _ = fixture.run(manifest, contract)
        return fixture, manifest, contract, records, summary

    @staticmethod
    def _target(records: list[dict[str, object]]) -> dict[str, object]:
        return next(
            record["projection"]
            for record in records
            if record["source"]["relative_path"] == census.TARGET_PATH
        )

    def _assert_rejects(self, mutation, pattern: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, manifest, contract, records, summary = self._run(root)
            rewrite_chain(records, summary, mutation)
            with self.assertRaisesRegex(audit.AuditError, pattern):
                audit_fixture(fixture, contract, manifest, records, summary)

    def test_recomputed_chain_cannot_hide_unknown_or_ambiguous_fields(self) -> None:
        def unknown(records):
            self._target(records)["elapsed_ns"] = 0

        self._assert_rejects(unknown, "unknown elapsed_ns")

        def bool_as_int(records):
            self._target(records)["selected"] = 1

        self._assert_rejects(bool_as_int, "JSON Boolean")

    def test_recomputed_chain_cannot_hide_side_effect_or_hash_drift(self) -> None:
        def side_effect(records):
            target = self._target(records)
            target["projected_new_atoms"] = 1
            target["materialized_new_atoms"] = 1

        self._assert_rejects(side_effect, "side effect")

        def atom_hash(records):
            self._target(records)["atom_map_after_sha256"] = "f" * 64

        self._assert_rejects(atom_hash, "atom map hash changed")

    def test_independent_replay_rejects_plausible_forged_counts(self) -> None:
        def forge(records):
            target = self._target(records)
            target["projected_closed_clauses"] = 3
            target["materialized_closed_clauses"] = 3
            target["ackermann_replay_clauses"] = 3

        self._assert_rejects(forge, "selected replay mismatch")

    def test_opened_source_binding_and_summary_schema_are_exact(self) -> None:
        def opened(records):
            records[0]["source"]["opened_sha256"] = "f" * 64

        self._assert_rejects(opened, "source/opened identity mismatch")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, manifest, contract, records, summary = self._run(root)
            payload = summary.read_text(encoding="ascii").rstrip("\n")
            duplicate = payload[:-1] + ',"sat_calls":NaN}\n'
            write_immutable(summary, duplicate.encode("ascii"))
            with self.assertRaisesRegex(audit.AuditError, "non-finite"):
                audit_fixture(fixture, contract, manifest, records, summary)


if __name__ == "__main__":
    unittest.main()
