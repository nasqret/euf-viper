from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from collections import Counter
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scripts.bench import audit_t9_projection_census as audit
from scripts.bench import run_t9_projection_census as census


FROG_ONE = "QF_UF/2018-Goel-hwbench/QF_UF_frogs.1.prop1_ab_br_max.smt2"
FROG_FOUR = "QF_UF/2018-Goel-hwbench/QF_UF_frogs.4.prop1_ab_br_max.smt2"
QG_PATH = "QF_UF/QG-classification/qg5/iso_icl001.smt2"
ADDITIONAL_PATH = "QF_UF/tests/additional.smt2"


FAKE_PROJECTOR_TEMPLATE = r'''#!__PYTHON__
import hashlib
import os
import sys
import time

EXPECTED_ENV = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
if sys.platform == "darwin":
    # CPython inserts this key during interpreter startup even when execve's
    # envp contains only EXPECTED_ENV. It is not supplied by the runner.
    os.environ.pop("__CF_USER_TEXT_ENCODING", None)
if dict(os.environ) != EXPECTED_ENV:
    print(f"ambient environment leaked: {sorted(os.environ)}", file=sys.stderr)
    raise SystemExit(9)
if sys.argv[1:] != ["project-t9", "-"]:
    print(f"unexpected argv: {sys.argv!r}", file=sys.stderr)
    raise SystemExit(9)
if os.path.exists("QF_UF"):
    print("projector cwd leaked the corpus", file=sys.stderr)
    raise SystemExit(9)

source = sys.stdin.buffer.read()
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

selected = marker in {"SELECT", "DESCEND"}
reason = "selected" if selected else "finite_added_nonzero"
finite_added = 0 if selected else 1
baseline = hashlib.sha256(b"baseline\0" + source).hexdigest()
candidate = hashlib.sha256(b"candidate\0" + source).hexdigest()
values = {
    "mode": "clique-auto",
    "selector_selected": selected,
    "selected": selected,
    "reason": reason,
    "finite_added": finite_added,
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
    "triangle_visits_definition": "eligible_third_vertex_probes",
    "baseline_before_sha256": baseline,
    "baseline_after_sha256": baseline,
    "materialized_candidate_sha256": candidate if selected else "0" * 64,
    "sat_calls": 1 if marker == "SAT_CALL" else 0,
}
planned = {
    "planned_max_arity": 2,
    "planned_application_argument_slots": 4,
    "planned_ackermann_function_pairs": 1,
    "planned_ackermann_predicate_pairs": 0,
    "planned_ackermann_candidate_pairs": 1,
    "planned_ackermann_function_differing_argument_pairs": 2,
    "planned_ackermann_predicate_differing_argument_pairs": 0,
    "planned_ackermann_clauses": 1,
    "planned_ackermann_literal_slots": 3,
    "planned_fill_edges": 1,
    "planned_fill_pair_examinations": 1,
    "planned_added_vars": 2,
    "planned_transitivity_clauses": 3,
    "planned_triangle_visits": 1,
    "planned_transitivity_literal_slots": 9,
    "planned_candidate_vars": 12,
    "planned_candidate_clauses": 21,
    "planned_candidate_literal_slots": 33,
    "planned_added_literal_slots": 12,
}
materialized = {
    "materialized_ackermann_clauses": 1,
    "materialized_ackermann_literal_slots": 3,
    "materialized_fill_edges": 1,
    "materialized_added_vars": 2,
    "materialized_transitivity_clauses": 3,
    "materialized_triangle_visits": 1,
    "materialized_transitivity_literal_slots": 9,
    "materialized_candidate_vars": 12,
    "materialized_candidate_clauses": 21,
    "materialized_candidate_literal_slots": 33,
    "materialized_added_literal_slots": 12,
}
for field in __PLANNED_FIELDS__:
    values[field] = planned[field] if selected else 0
    values[field + "_state"] = "exact" if selected else "not_computed"
for field in __MATERIALIZED_FIELDS__:
    values[field] = materialized[field] if selected else 0
    values[field + "_state"] = "exact" if selected else "not_computed"

print("t9_projection_version 1")
for key in sorted(values):
    value = values[key]
    if isinstance(value, bool):
        value = int(value)
    print(f"{key} {value}")
raise SystemExit(0 if selected else 3)
'''


def expected_projection(source: bytes, selected: bool) -> dict[str, object]:
    baseline = hashlib.sha256(b"baseline\0" + source).hexdigest()
    candidate = hashlib.sha256(b"candidate\0" + source).hexdigest()
    projection: dict[str, object] = {
        "mode": "clique-auto",
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
        "triangle_visits_definition": "eligible_third_vertex_probes",
        "baseline_before_sha256": baseline,
        "baseline_after_sha256": baseline,
        "materialized_candidate_sha256": candidate if selected else census.ZERO_SHA256,
        "sat_calls": 0,
    }
    planned = {
        "planned_max_arity": 2,
        "planned_application_argument_slots": 4,
        "planned_ackermann_function_pairs": 1,
        "planned_ackermann_predicate_pairs": 0,
        "planned_ackermann_candidate_pairs": 1,
        "planned_ackermann_function_differing_argument_pairs": 2,
        "planned_ackermann_predicate_differing_argument_pairs": 0,
        "planned_ackermann_clauses": 1,
        "planned_ackermann_literal_slots": 3,
        "planned_fill_edges": 1,
        "planned_fill_pair_examinations": 1,
        "planned_added_vars": 2,
        "planned_transitivity_clauses": 3,
        "planned_triangle_visits": 1,
        "planned_transitivity_literal_slots": 9,
        "planned_candidate_vars": 12,
        "planned_candidate_clauses": 21,
        "planned_candidate_literal_slots": 33,
        "planned_added_literal_slots": 12,
    }
    materialized = {
        "materialized_ackermann_clauses": 1,
        "materialized_ackermann_literal_slots": 3,
        "materialized_fill_edges": 1,
        "materialized_added_vars": 2,
        "materialized_transitivity_clauses": 3,
        "materialized_triangle_visits": 1,
        "materialized_transitivity_literal_slots": 9,
        "materialized_candidate_vars": 12,
        "materialized_candidate_clauses": 21,
        "materialized_candidate_literal_slots": 33,
        "materialized_added_literal_slots": 12,
    }
    for field in census.PLANNED_COUNT_FIELDS:
        projection[field] = planned[field] if selected else 0
        projection[f"{field}_state"] = "exact" if selected else "not_computed"
    for field in census.MATERIALIZED_COUNT_FIELDS:
        projection[field] = materialized[field] if selected else 0
        projection[f"{field}_state"] = "exact" if selected else "not_computed"
    return projection


def render_projection(projection: dict[str, object]) -> bytes:
    lines = ["t9_projection_version 1"]
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
        path.write_bytes(
            b"".join(census.canonical_json_bytes(row) for row in rows)
        )
        return path

    def binary(self, name: str = "fake-projector.py") -> Path:
        path = self.root / name
        script = (
            FAKE_PROJECTOR_TEMPLATE.replace("__PYTHON__", sys.executable)
            .replace("__OUTPUT_LIMIT__", str(census.MAX_PROJECTOR_OUTPUT_BYTES))
            .replace("__PLANNED_FIELDS__", repr(sorted(census.PLANNED_COUNT_FIELDS)))
            .replace(
                "__MATERIALIZED_FIELDS__",
                repr(sorted(census.MATERIALIZED_COUNT_FIELDS)),
            )
        )
        path.write_text(script, encoding="ascii")
        path.chmod(0o755)
        return path

    def sources(self) -> list[census.ManifestSource]:
        return census.parse_manifest(
            b"".join(census.canonical_json_bytes(row) for row in self.rows)
        )

    def contract(
        self,
        *,
        control_paths: tuple[str, ...] = (FROG_ONE, FROG_FOUR, QG_PATH),
        required_paths: tuple[str, ...] = (census.TARGET_PATH, FROG_ONE, FROG_FOUR),
        expected_qg_sources: int | None = None,
        target_projection: dict[str, object] | None = None,
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
        required = tuple(
            sorted((path, by_path[path].source_sha256) for path in required_paths)
        )
        if expected_qg_sources is None:
            expected_qg_sources = sum(
                source.relative_path.startswith(census.QG_PREFIX) for source in sources
            )
        if target_projection is None:
            target_projection = expected_projection(
                self.payloads[census.TARGET_PATH], True
            )
        return census.EvidenceContract(
            kind="test",
            expected_sources=len(sources),
            source_set_sha256=census.canonical_hash(census.source_set_value(sources)),
            expected_qg_sources=expected_qg_sources,
            required_sources=required,
            control=control,
            target_path=census.TARGET_PATH,
            target_projection=target_projection,
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


def complete_fixture(root: Path) -> tuple[CensusFixture, census.EvidenceContract]:
    fixture = CensusFixture(root)
    fixture.add(census.TARGET_PATH, "SELECT")
    fixture.add(FROG_ONE, "REJECT")
    fixture.add(FROG_FOUR, "REJECT")
    fixture.add(QG_PATH, "REJECT")
    fixture.add(ADDITIONAL_PATH, "SELECT")
    return fixture, fixture.contract()


def _read_records(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines()]


def _write_immutable(path: Path, payload: bytes) -> None:
    path.chmod(0o600)
    path.write_bytes(payload)
    path.chmod(0o400)


def rewrite_chain(
    records_path: Path,
    summary_path: Path,
    mutation,
) -> None:
    records = _read_records(records_path)
    mutation(records)
    previous = census.ZERO_SHA256
    selected_paths: list[str] = []
    reason_counts: Counter[str] = Counter()
    for record in records:
        record["previous_record_sha256"] = previous
        record.pop("record_sha256", None)
        digest = census.canonical_hash(record)
        record["record_sha256"] = digest
        previous = digest
        projection = record["projection"]
        if projection.get("selected") is True:
            selected_paths.append(record["source"]["relative_path"])
        reason = projection.get("reason")
        if type(reason) is str:
            reason_counts[reason] += 1
    records_payload = census.encode_records(records)
    summary = json.loads(summary_path.read_text(encoding="ascii"))
    summary["records_sha256"] = census.sha256_bytes(records_payload)
    summary["record_chain_head"] = previous
    summary["selected_paths"] = selected_paths
    summary["selected_count"] = len(selected_paths)
    summary["selected_set_sha256"] = census.canonical_hash(selected_paths)
    summary["reason_counts"] = dict(sorted(reason_counts.items()))
    _write_immutable(records_path, records_payload)
    _write_immutable(summary_path, census.canonical_json_bytes(summary))


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


class ProductionContractTests(unittest.TestCase):
    def test_production_constants_and_control_bytes_are_frozen(self) -> None:
        self.assertEqual(census.PRODUCTION_SOURCE_COUNT, 7503)
        self.assertEqual(
            census.PRODUCTION_SOURCE_SET_SHA256,
            "6b3c316cd90d8093bba184522dd3238892e06b6215fc2a8e8b510e1b5b19ba60",
        )
        payload = census.CONTROL_MANIFEST_PATH.read_bytes()
        self.assertEqual(len(payload), 12998)
        self.assertEqual(len(payload.splitlines()), 24)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), census.CONTROL_MANIFEST_SHA256)

    def test_production_cli_has_no_source_count_override(self) -> None:
        runner_options = {action.dest for action in census.build_argument_parser()._actions}
        auditor_options = {action.dest for action in audit.build_argument_parser()._actions}
        self.assertNotIn("expected_sources", runner_options)
        self.assertNotIn("expected_sources", auditor_options)
        self.assertIn("corpus_root", runner_options)
        self.assertIn("corpus_root", auditor_options)

    def test_production_target_anchor_is_exact_and_ready(self) -> None:
        runner_projection = dict(census.PRODUCTION_CONTRACT.target_projection or {})
        auditor_projection = dict(audit.PRODUCTION_CONTRACT.target_projection or {})
        self.assertEqual(runner_projection, auditor_projection)
        self.assertEqual(
            census.canonical_hash(runner_projection),
            "2388efca35cebbcfe161a43c45a75351719682babef4fae2875e42296cb8b3e3",
        )
        census._assert_contract_ready(census.PRODUCTION_CONTRACT)
        audit._assert_contract_ready(audit.PRODUCTION_CONTRACT)

    def test_auditor_rejects_runner_cap_and_schema_drift(self) -> None:
        with mock.patch.object(
            census, "MAX_ACKERMANN_CLAUSES", census.MAX_ACKERMANN_CLAUSES + 1
        ):
            with self.assertRaisesRegex(audit.AuditError, "Ackermann cap"):
                audit._assert_runner_contract_match()
        with mock.patch.object(
            census,
            "REQUIRED_FIELDS",
            set(census.REQUIRED_FIELDS) | {"observed_result"},
        ):
            with self.assertRaisesRegex(audit.AuditError, "projection schema"):
                audit._assert_runner_contract_match()

    def test_target_only_mini_corpus_cannot_reach_production(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = CensusFixture(root)
            fixture.add(census.TARGET_PATH, "SELECT")
            with self.assertRaisesRegex(census.CensusError, "source count mismatch"):
                census.run_census(
                    fixture.manifest(),
                    fixture.corpus,
                    fixture.binary(),
                    root / "records.jsonl",
                    root / "summary.json",
                    timeout_seconds=2.0,
                )


class ProjectionParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = b"SELECT\n"
        self.projection = expected_projection(self.payload, True)

    def test_exact_projection_parses(self) -> None:
        parsed = census.parse_projection_report(render_projection(self.projection), 0)
        self.assertIs(parsed["selected"], True)
        self.assertEqual(parsed, self.projection)

    def test_non_projector_backend_routes_are_rejected(self) -> None:
        for backend in ("dpll", "varisat", "cadical-refine"):
            projection = dict(self.projection)
            projection["backend"] = backend
            with self.subTest(backend=backend, validator="runner"):
                with self.assertRaisesRegex(
                    census.CensusError, "outside the frozen vocabulary"
                ):
                    census.parse_projection_report(render_projection(projection), 0)
            with self.subTest(backend=backend, validator="auditor"):
                with self.assertRaisesRegex(
                    audit.AuditError, "outside the frozen vocabulary"
                ):
                    audit._validate_projection_shape(projection, "adversarial")

    def test_duplicate_unknown_and_misleading_clique_keys_are_rejected(self) -> None:
        rendered = render_projection(self.projection).decode("ascii")
        duplicate = rendered + "reason selected\n"
        with self.assertRaisesRegex(census.CensusError, "duplicate key"):
            census.parse_projection_report(duplicate.encode("ascii"), 0)
        for field in (
            "observed_result",
            "expected_status",
            "elapsed",
            "time",
            "parser_error",
            "max_missing_clique_edges",
            "materialization_match",
            "off_path_unchanged",
        ):
            lines = rendered.splitlines()
            lines.append(f"{field} 0")
            with self.subTest(field=field):
                with self.assertRaisesRegex(census.CensusError, "unknown fields"):
                    census.parse_projection_report(
                        ("\n".join(lines) + "\n").encode("ascii"), 0
                    )

    def test_invalid_count_states_and_values_are_rejected(self) -> None:
        cases = (
            ("planned_fill_edges_state", "bogus", "invalid"),
            ("planned_fill_edges_state", "not_computed", "must have value zero"),
            ("planned_fill_edges_state", "lower_bound", None),
        )
        for state_field, state, _ in cases:
            mutated = dict(self.projection)
            mutated[state_field] = state
            if state == "lower_bound":
                mutated["planned_fill_edges"] = 0
            with self.subTest(state=state):
                with self.assertRaises(census.CensusError):
                    census.parse_projection_report(render_projection(mutated), 0)

    def test_sat_call_is_rejected_at_parse_boundary(self) -> None:
        projection = dict(self.projection)
        projection["sat_calls"] = 1
        with self.assertRaisesRegex(census.CensusError, "reported a SAT call"):
            census.parse_projection_report(render_projection(projection), 0)

    def test_transitivity_literal_slots_accept_reflexive_units(self) -> None:
        projection = dict(self.projection)
        projection["planned_transitivity_literal_slots"] = 7
        projection["materialized_transitivity_literal_slots"] = 7
        projection["planned_added_literal_slots"] = 10
        projection["materialized_added_literal_slots"] = 10
        audit._validate_projection_semantics(projection, "unit-transitivity")
        self.assertEqual(projection["planned_candidate_literal_slots"], 33)


class PopulationTests(unittest.TestCase):
    def test_missing_frog_control_and_qg_populations_fail_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, contract = complete_fixture(root)
            sources = fixture.sources()
            control, _ = census.resolve_control_binding(contract)

            without_frog = [source for source in sources if source.relative_path != FROG_ONE]
            frog_contract = replace(
                contract,
                expected_sources=len(without_frog),
                source_set_sha256=census.canonical_hash(
                    census.source_set_value(without_frog)
                ),
            )
            with self.assertRaisesRegex(census.CensusError, "required frozen source is absent"):
                census.validate_source_population(without_frog, frog_contract, control)

            missing_control = census.ControlBinding(
                control.sha256,
                control.byte_count,
                control.row_count,
                control.identities + (("QF_UF/tests/missing-control.smt2", "f" * 64),),
            )
            with self.assertRaisesRegex(census.CensusError, "frozen control source is absent"):
                census.validate_source_population(sources, contract, missing_control)

            qg_contract = replace(contract, expected_qg_sources=2)
            with self.assertRaisesRegex(census.CensusError, "QG population mismatch"):
                census.validate_source_population(sources, qg_contract, control)


class CensusAndAuditTests(unittest.TestCase):
    def test_exact_deterministic_valid_test_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, contract = complete_fixture(root)
            manifest = fixture.manifest()
            first_records, first_summary, rows, aggregate = fixture.run(
                manifest, contract, suffix="-first"
            )
            second_records, second_summary, _, second_aggregate = fixture.run(
                manifest, contract, suffix="-second"
            )
            self.assertEqual(len(rows), 5)
            self.assertEqual(aggregate, second_aggregate)
            self.assertEqual(first_records.read_bytes(), second_records.read_bytes())
            self.assertEqual(first_summary.read_bytes(), second_summary.read_bytes())
            self.assertEqual(stat.S_IMODE(first_records.stat().st_mode), 0o400)
            self.assertEqual(stat.S_IMODE(first_summary.stat().st_mode), 0o400)
            first_receipt = audit_fixture(
                fixture,
                contract,
                manifest,
                first_records,
                first_summary,
                "receipt-first.json",
            )
            second_receipt = audit_fixture(
                fixture,
                contract,
                manifest,
                second_records,
                second_summary,
                "receipt-second.json",
            )
            self.assertEqual(first_receipt, second_receipt)
            self.assertEqual(first_receipt["status"], "pass_test_only")
            self.assertEqual(first_receipt["contract_kind"], "test")
            self.assertIn("defense_in_depth", first_receipt["evidence_boundary"])
            self.assertEqual(
                stat.S_IMODE((root / "receipt-first.json").stat().st_mode), 0o400
            )

    def test_test_contract_artifacts_cannot_pass_production_auditor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, contract = complete_fixture(root)
            manifest = fixture.manifest()
            records, summary, _, _ = fixture.run(manifest, contract)
            with self.assertRaisesRegex(audit.AuditError, "source count mismatch"):
                audit.audit_census(
                    manifest,
                    fixture.corpus,
                    fixture.binary(),
                    records,
                    summary,
                    root / "receipt.json",
                )

    def test_ambient_environment_and_physical_source_path_do_not_leak(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, contract = complete_fixture(root)
            manifest = fixture.manifest()
            hostile = {
                "HOME": "/ambient/home",
                "PATH": "/ambient/path",
                "LD_PRELOAD": "/ambient/loader.so",
                "DYLD_LIBRARY_PATH": "/ambient/dyld",
                "EUF_VIPER_RESULT": "sat",
                "COMPARATOR_STATUS": "winner",
            }
            with mock.patch.dict(os.environ, hostile, clear=False):
                records, summary, _, _ = fixture.run(manifest, contract)
            receipt = audit_fixture(
                fixture, contract, manifest, records, summary
            )
            self.assertEqual(receipt["status"], "pass_test_only")

    def test_source_replacement_after_snapshot_cannot_change_projected_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = CensusFixture(root)
            fixture.add(census.TARGET_PATH, "SELECT")
            source = fixture.sources()[0]
            with census.CorpusRoot(fixture.corpus) as corpus:
                snapshot = corpus.snapshot(source)
                physical = fixture.corpus / source.relative_path
                physical.unlink()
                physical.write_text("REJECT\n", encoding="ascii")
                with census.ProjectorSnapshot(fixture.binary()) as projector:
                    projection = census.run_projection(
                        projector, snapshot, source.relative_path, 2.0
                    )
            self.assertIs(projection["selected"], True)

    def test_output_flood_and_descendant_attempt_are_denied(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = CensusFixture(root)
            binary = fixture.binary()
            with census.ProjectorSnapshot(binary) as projector:
                with self.assertRaises(census.CensusError):
                    census.run_projection(projector, b"FLOOD\n", "flood", 2.0)
                with self.assertRaises(census.CensusError):
                    census.run_projection(projector, b"DESCEND\n", "descendant", 2.0)

    def test_create_new_publication_never_overwrites_or_unlinks_replacements(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            existing = root / "existing.json"
            existing.write_bytes(b"existing\n")
            with self.assertRaisesRegex(census.CensusError, "overwrite"):
                census.immutable_write_new(existing, b"new\n")
            self.assertEqual(existing.read_bytes(), b"existing\n")

            stages = (
                "after_create",
                "after_write_verify",
                "after_mode_freeze",
                "after_named_verify",
                "after_named_reopen_verify",
                "after_parent_verify",
            )
            for stage in stages:
                attacked = root / f"attacked-{stage}.json"
                replacement = f"replacement-{stage}\n".encode("ascii")
                replaced = False

                def checkpoint(actual_stage, path, parent_fd, final_name):
                    nonlocal replaced
                    if actual_stage != stage or replaced:
                        return
                    replaced = True
                    os.unlink(final_name, dir_fd=parent_fd)
                    descriptor = os.open(
                        final_name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o400,
                        dir_fd=parent_fd,
                    )
                    try:
                        os.write(descriptor, replacement)
                    finally:
                        os.close(descriptor)

                with self.subTest(stage=stage):
                    with mock.patch.object(
                        census, "_publication_checkpoint", side_effect=checkpoint
                    ):
                        with self.assertRaisesRegex(census.CensusError, "replaced"):
                            census.immutable_write_new(attacked, b"intended\n")
                    self.assertTrue(replaced)
                    self.assertEqual(attacked.read_bytes(), replacement)

    def test_partial_publication_stays_mutable_and_parent_replacement_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            partial = root / "partial.json"

            def partial_write(descriptor, payload, context):
                os.write(descriptor, payload[:3])
                raise census.CensusError("injected write failure")

            with mock.patch.object(census, "_write_all", side_effect=partial_write):
                with self.assertRaisesRegex(census.CensusError, "injected write failure"):
                    census.immutable_write_new(partial, b"complete\n")
            self.assertTrue(partial.exists())
            self.assertNotEqual(stat.S_IMODE(partial.stat().st_mode), 0o400)
            self.assertEqual(partial.read_bytes(), b"com")

            parent = root / "parent"
            parent.mkdir()
            output = parent / "artifact.json"
            moved_parent = root / "parent-held"
            replacement_parent = root / "parent"

            def replace_parent(stage, path, parent_fd, final_name):
                if stage != "after_create":
                    return
                parent.rename(moved_parent)
                replacement_parent.mkdir()
                (replacement_parent / "sentinel").write_text("preserve", encoding="ascii")

            with mock.patch.object(
                census, "_publication_checkpoint", side_effect=replace_parent
            ):
                with self.assertRaisesRegex(census.CensusError, "parent path was replaced"):
                    census.immutable_write_new(output, b"payload\n")
            self.assertEqual(
                (replacement_parent / "sentinel").read_text(encoding="ascii"),
                "preserve",
            )
            self.assertTrue((moved_parent / "artifact.json").exists())

            real_parent = root / "real-parent"
            real_parent.mkdir()
            symlink_parent = root / "symlink-parent"
            symlink_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(census.CensusError, "cannot open artifact parent"):
                census.immutable_write_new(symlink_parent / "artifact.json", b"payload\n")
            self.assertFalse((real_parent / "artifact.json").exists())


class AdversarialAuditTests(unittest.TestCase):
    def _run(self, root: Path):
        fixture, contract = complete_fixture(root)
        manifest = fixture.manifest()
        records, summary, _, _ = fixture.run(manifest, contract)
        return fixture, contract, manifest, records, summary

    def _target(self, records: list[dict[str, object]]) -> dict[str, object]:
        return next(
            record["projection"]
            for record in records
            if record["source"]["relative_path"] == census.TARGET_PATH
        )

    def _assert_audit_rejects(self, mutation, pattern: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, contract, manifest, records, summary = self._run(root)
            rewrite_chain(records, summary, mutation)
            with self.assertRaisesRegex(audit.AuditError, pattern):
                audit_fixture(fixture, contract, manifest, records, summary)

    def test_selector_false_negative_is_rejected(self) -> None:
        def mutate(records):
            target = self._target(records)
            target["selector_selected"] = False
            target["selected"] = False
            target["reason"] = "equality_graph_vertices_below_minimum"
            target["materialized_candidate_sha256"] = census.ZERO_SHA256
            for field in census.PLANNED_COUNT_FIELDS | census.MATERIALIZED_COUNT_FIELDS:
                target[field] = 0
                target[f"{field}_state"] = "not_computed"

        self._assert_audit_rejects(mutate, "selector false although")

    def test_fallback_route_rejects_before_uncomputed_structural_thresholds(self) -> None:
        projection = expected_projection(b"fallback-route\n", False)
        projection.update(
            {
                "finite_added": 0,
                "reason": "backend_not_kissat",
                "backend": "fallback",
                "all_different_clique_lb": 0,
                "disequality_graph_edges": 0,
                "disequality_clique_excess_edges": 0,
                "equality_graph_vertices": 0,
                "equality_graph_edges": 0,
            }
        )
        self.assertEqual(
            audit._selector_reason(projection, "fallback-route"),
            "backend_not_kissat",
        )

    def test_impossible_clique_and_candidate_equations_are_rejected(self) -> None:
        def clique(records):
            self._target(records)["disequality_clique_excess_edges"] = 1

        self._assert_audit_rejects(clique, "disequality_graph_edges must equal")

        def candidate(records):
            self._target(records)["planned_candidate_clauses"] = 22

        self._assert_audit_rejects(candidate, "candidate clause equation failed")

    def test_planned_materialized_mismatch_is_rejected(self) -> None:
        def mutate(records):
            self._target(records)["materialized_ackermann_clauses"] = 2

        self._assert_audit_rejects(mutate, "differs from accepted")

    def test_huge_ackermann_literals_are_rejected(self) -> None:
        def mutate(records):
            target = self._target(records)
            target["planned_ackermann_function_differing_argument_pairs"] = census.MAX_U64
            target["planned_ackermann_literal_slots"] = census.MAX_U64
            target["materialized_ackermann_literal_slots"] = census.MAX_U64

        self._assert_audit_rejects(mutate, "differing-argument count is impossible")

    def test_result_timing_parser_and_record_extras_fail_after_recomputed_chain(self) -> None:
        for field in (
            "observed_result",
            "expected_status",
            "elapsed",
            "time",
            "parser_error",
        ):
            def mutate(records, field=field):
                self._target(records)[field] = 0

            with self.subTest(field=field):
                self._assert_audit_rejects(mutate, "schema mismatch")

        def record_extra(records):
            records[0]["observed_result"] = "sat"

        self._assert_audit_rejects(record_extra, "record.*schema mismatch")

    def test_bool_as_int_alias_is_rejected(self) -> None:
        def mutate(records):
            self._target(records)["selected"] = 1

        self._assert_audit_rejects(mutate, "must be a JSON Boolean")

    def test_recomputed_hash_chain_cannot_bypass_exact_schema(self) -> None:
        def mutate(records):
            target = self._target(records)
            target["parser_error"] = "none"
            target["observed_result"] = "unsat"

        self._assert_audit_rejects(mutate, "unknown observed_result, parser_error")


if __name__ == "__main__":
    unittest.main()
