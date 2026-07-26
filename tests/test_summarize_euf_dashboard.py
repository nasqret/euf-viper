from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_SCRIPT = ROOT / "scripts" / "bench" / "build_euf_dashboard.py"
SCORECARD_SCRIPT = ROOT / "scripts" / "bench" / "summarize_euf_dashboard.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DASHBOARD = load_module("scorecard_dashboard_fixture", DASHBOARD_SCRIPT)
SCORECARD = load_module("summarize_euf_dashboard", SCORECARD_SCRIPT)

REVISION_OLD = "1" * 40
REVISION_CURRENT = "2" * 40
SOURCE_HASH = "a" * 64


def observation(solver_id: str, status: str, time_s: float | None) -> dict:
    return {"solver_id": solver_id, "status": status, "time_s": time_s}


def evidence(
    identifier: str,
    *,
    revision: str = REVISION_CURRENT,
    scope: str = "broad",
    corpus_id: str = "full",
    corpus_label: str = "Full corpus",
    family_id: str = "all",
    family_label: str = "All families",
    timeout_s: float = 2.0,
    viper_time: float | None = 1.0,
    competitor_time: float | None = 2.0,
    viper_status: str = "solved",
    competitor_status: str = "solved",
    evidence_status: str = "verified",
    host_id: str = "host-a",
    expected_status: str = "all",
) -> dict:
    return {
        "id": identifier,
        "scope": scope,
        "evidence_class": "fixture-campaign",
        "evidence_status": evidence_status,
        "revision": revision,
        "solver_ids": ["euf-viper", "competitor"],
        "host": {"id": host_id, "label": host_id},
        "corpus": {"id": corpus_id, "label": corpus_label},
        "timeout_s": timeout_s,
        "family": {"id": family_id, "label": family_label},
        "expected_status": expected_status,
        "source": {"path": f"fixtures/{identifier}.json", "sha256": SOURCE_HASH},
        "instances": [
            {
                "id": f"{identifier}.smt2",
                "results": [
                    observation("euf-viper", viper_status, viper_time),
                    observation("competitor", competitor_status, competitor_time),
                ],
            }
        ],
    }


def model(*items: dict) -> dict:
    registry = {
        "schema_version": DASHBOARD.REGISTRY_SCHEMA_VERSION,
        "registry_id": "scorecard-fixture",
        "title": "Scorecard fixture",
        "updated_at": "2026-07-27T00:00:00Z",
        "viper_solver_id": "euf-viper",
        "solvers": [
            {"id": "euf-viper", "label": "Viper"},
            {"id": "competitor", "label": "Competitor"},
        ],
        "evidence": list(items),
    }
    return DASHBOARD.build_dashboard(registry)


def contract(*, revision: str = REVISION_CURRENT, budgets: list[float] | None = None) -> dict:
    return {
        "schema_version": SCORECARD.CONTRACT_SCHEMA_VERSION,
        "campaign_id": "fixture-world-campaign",
        "scope": {"candidate_revision": revision},
        "score_policy": {"candidate_id": "euf-viper"},
        "comparators": {"mandatory": [{"id": "competitor"}]},
        "benchmark_space": {
            "corpora": [
                {"id": "full", "role": "full_library_regression"},
                {"id": "official", "role": "official_primary"},
            ],
            "budgets_s": budgets or [2.0, 60.0, 1200.0],
        },
        "victory_contract": {
            "V0_validity": "valid",
            "V1_official_coverage": "official coverage",
            "V2_full_coverage": "full coverage",
            "V3_time": "timing",
            "V4_resources": "resources",
            "V5_generalization": "generalization",
            "V6_quality": "quality",
            "claim": "best_overall_QF_UF_solver",
        },
    }


def full_campaign_evidence(*, competitor_time: float = 2.0) -> list[dict]:
    rows = []
    for corpus_id, corpus_label in (("full", "Full corpus"), ("official", "Official corpus")):
        for timeout_s in (2.0, 60.0, 1200.0):
            rows.append(
                evidence(
                    f"{corpus_id}-{timeout_s:g}",
                    corpus_id=corpus_id,
                    corpus_label=corpus_label,
                    timeout_s=timeout_s,
                    competitor_time=competitor_time,
                )
            )
    return rows


class StrictModelTests(unittest.TestCase):
    def test_rejects_schema_drift_and_inconsistent_metric(self) -> None:
        dashboard_model = model(evidence("base"))
        drifted = copy.deepcopy(dashboard_model)
        drifted["new_metric"] = {}
        with self.assertRaisesRegex(SCORECARD.ScorecardInputError, "unexpected keys"):
            SCORECARD.validate_model(drifted)

        inconsistent = copy.deepcopy(dashboard_model)
        inconsistent["panels"][0]["comparisons"][0]["metrics"]["par2"][
            "signed_performance_index"
        ] = 99.0
        with self.assertRaisesRegex(SCORECARD.ScorecardInputError, "inconsistent"):
            SCORECARD.validate_model(inconsistent)

    def test_strict_loader_rejects_duplicate_keys_and_nonfinite_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.json"
            path.write_text('{"schema_version":1,"schema_version":2}', encoding="utf-8")
            with self.assertRaisesRegex(SCORECARD.ScorecardInputError, "duplicate JSON key"):
                SCORECARD.load_model(path)
            path.write_text('{"schema_version":NaN}', encoding="utf-8")
            with self.assertRaisesRegex(SCORECARD.ScorecardInputError, "non-finite"):
                SCORECARD.load_model(path)

    def test_loaded_objects_can_be_passed_directly_to_builder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            model_path = root / "model.json"
            contract_path = root / "contract.json"
            model_path.write_text(json.dumps(model(evidence("base"))), encoding="utf-8")
            contract_path.write_text(json.dumps(contract()), encoding="utf-8")
            scorecard = SCORECARD.build_scorecard(
                SCORECARD.load_model(model_path),
                SCORECARD.load_campaign_contract(contract_path),
            )
            self.assertEqual(scorecard["schema_version"], SCORECARD.SCORECARD_SCHEMA_VERSION)

    def test_exact_legacy_v1_dialect_is_labeled_and_not_used_for_gate_passes(self) -> None:
        legacy = model(*full_campaign_evidence())
        legacy["filter_options"].pop("expected_statuses")
        for panel in legacy["panels"]:
            panel["claim_boundary"].pop("expected_status")
        scorecard = SCORECARD.build_scorecard(legacy, contract())
        self.assertEqual(
            scorecard["source_model"]["expected_status_dimension"],
            "legacy-unstratified",
        )
        self.assertTrue(
            all(
                panel["claim_boundary"]["expected_status"]
                == "legacy-unstratified"
                for panel in scorecard["panels"]
            )
        )
        states = {gate["id"]: gate["state"] for gate in scorecard["victory"]["gates"]}
        self.assertEqual(states["V1"], "unknown")
        self.assertEqual(states["V2"], "unknown")
        self.assertEqual(states["V3"], "unknown")


class SelectionAndMetricTests(unittest.TestCase):
    def test_selects_only_requested_panel_kinds_without_pooling(self) -> None:
        dashboard_model = model(
            evidence("broad-all", revision=REVISION_OLD),
            evidence(
                "broad-family",
                revision=REVISION_OLD,
                family_id="peq",
                family_label="PEQ",
            ),
            evidence(
                "target-combined",
                scope="targeted",
                corpus_id="structural",
                corpus_label="Structural",
                family_id="structural-combined",
                family_label="PEQ + SEQ + NEQ",
            ),
            evidence(
                "target-peq",
                scope="targeted",
                corpus_id="structural",
                corpus_label="Structural",
                family_id="peq",
                family_label="PEQ",
            ),
        )
        scorecard = SCORECARD.build_scorecard(dashboard_model, contract())
        self.assertEqual(scorecard["selection"]["selected_panels"], 2)
        self.assertEqual(scorecard["selection"]["excluded_panels"], 2)
        self.assertFalse(scorecard["selection"]["claim_boundaries_pooled"])
        self.assertEqual(
            {panel["kind"] for panel in scorecard["panels"]},
            {"broad_whole_corpus", "targeted_structural_combined"},
        )
        self.assertEqual(len({panel["id"] for panel in scorecard["panels"]}), 2)

    def test_emits_ratio_signed_percent_and_required_reduction(self) -> None:
        dashboard_model = model(
            evidence("slower-viper", viper_time=4.0, competitor_time=2.0)
        )
        scorecard = SCORECARD.build_scorecard(dashboard_model, contract())
        panel = scorecard["panels"][0]
        summaries = {row["solver_id"]: row for row in panel["solvers"]}
        self.assertEqual(summaries["euf-viper"]["solved"], 1)
        self.assertEqual(summaries["euf-viper"]["coverage"]["value"], 1.0)
        comparison = panel["comparisons"][0]
        for metric_name in SCORECARD.PRIMARY_TIME_METRICS:
            metric = comparison["metrics"][metric_name]
            self.assertEqual(metric["ratio"], 0.5)
            self.assertEqual(metric["signed_percent"], -50.0)
            self.assertEqual(metric["required_viper_reduction_percent"], 50.0)

    def test_output_is_deterministic_under_input_panel_order(self) -> None:
        first = model(
            evidence("old", revision=REVISION_OLD),
            evidence(
                "target",
                scope="targeted",
                corpus_id="structural",
                corpus_label="Structural",
                family_id="structural-combined",
                family_label="Combined",
            ),
        )
        second = copy.deepcopy(first)
        second["panels"].reverse()
        one = SCORECARD.build_scorecard(first, contract())
        two = SCORECARD.build_scorecard(second, contract())
        self.assertEqual(SCORECARD.canonical_json_bytes(one), SCORECARD.canonical_json_bytes(two))
        self.assertEqual(SCORECARD.render_markdown(one), SCORECARD.render_markdown(two))

    def test_expected_status_claim_boundaries_remain_separate(self) -> None:
        dashboard_model = model(
            evidence("sat", expected_status="sat"),
            evidence("unsat", expected_status="unsat"),
        )
        scorecard = SCORECARD.build_scorecard(dashboard_model, contract())
        # Status-stratified broad panels are not whole-corpus panels and cannot
        # be substituted for them in the compact primary scorecard.
        self.assertEqual(scorecard["selection"]["selected_panels"], 0)
        self.assertEqual(scorecard["selection"]["excluded_panels"], 2)
        self.assertEqual(scorecard["broad_current_route_baseline"]["state"], "missing")


class BaselineAndVictoryTests(unittest.TestCase):
    def test_marks_current_broad_baseline_missing_and_gates_unknown(self) -> None:
        scorecard = SCORECARD.build_scorecard(
            model(evidence("historical", revision=REVISION_OLD)), contract()
        )
        baseline = scorecard["broad_current_route_baseline"]
        self.assertEqual(baseline["state"], "missing")
        self.assertEqual(baseline["candidate_revision"], REVISION_CURRENT)
        self.assertIn("No broad whole-corpus panel", baseline["reason"])
        states = {gate["id"]: gate["state"] for gate in scorecard["victory"]["gates"]}
        self.assertEqual(states, {f"V{index}": "unknown" for index in range(7)})
        self.assertEqual(scorecard["victory"]["state"], "unknown")

    def test_coverage_and_time_gates_pass_only_with_complete_exact_panels(self) -> None:
        scorecard = SCORECARD.build_scorecard(
            model(*full_campaign_evidence()), contract()
        )
        states = {gate["id"]: gate["state"] for gate in scorecard["victory"]["gates"]}
        self.assertEqual(states["V1"], "pass")
        self.assertEqual(states["V2"], "pass")
        self.assertEqual(states["V3"], "pass")
        self.assertEqual(states["V0"], "unknown")
        self.assertEqual(scorecard["broad_current_route_baseline"]["state"], "available")

    def test_negative_available_evidence_fails_time_and_bad_rows_fail_validity(self) -> None:
        slow = full_campaign_evidence()
        slow[0] = evidence(
            "full-2-slow",
            corpus_id="full",
            corpus_label="Full corpus",
            timeout_s=2.0,
            viper_time=2.0,
            competitor_time=1.0,
        )
        time_scorecard = SCORECARD.build_scorecard(model(*slow), contract())
        time_states = {
            gate["id"]: gate["state"] for gate in time_scorecard["victory"]["gates"]
        }
        self.assertEqual(time_states["V3"], "fail")
        self.assertEqual(time_scorecard["victory"]["state"], "fail")

        bad = evidence(
            "bad-answer",
            viper_time=None,
            viper_status="wrong-answer",
        )
        validity_scorecard = SCORECARD.build_scorecard(model(bad), contract())
        validity_states = {
            gate["id"]: gate["state"]
            for gate in validity_scorecard["victory"]["gates"]
        }
        self.assertEqual(validity_states["V0"], "fail")


class CliAndAtomicOutputTests(unittest.TestCase):
    def test_cli_writes_json_and_markdown_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            model_path = root / "model.json"
            contract_path = root / "contract.json"
            json_out = root / "out" / "scorecard.json"
            markdown_out = root / "out" / "scorecard.md"
            model_path.write_text(json.dumps(model(evidence("base"))), encoding="utf-8")
            contract_path.write_text(json.dumps(contract()), encoding="utf-8")
            result = SCORECARD.main(
                [
                    str(model_path),
                    "--campaign-contract",
                    str(contract_path),
                    "--json-out",
                    str(json_out),
                    "--markdown-out",
                    str(markdown_out),
                ]
            )
            self.assertEqual(result, 0)
            payload = json.loads(json_out.read_text(encoding="ascii"))
            self.assertEqual(payload["schema_version"], SCORECARD.SCORECARD_SCHEMA_VERSION)
            self.assertIn("# EUF Campaign Scorecard", markdown_out.read_text(encoding="utf-8"))
            self.assertEqual(list((root / "out").glob("*.tmp")), [])

    def test_failure_does_not_clobber_existing_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            model_path = root / "model.json"
            contract_path = root / "contract.json"
            json_out = root / "scorecard.json"
            markdown_out = root / "scorecard.md"
            model_path.write_text("{}", encoding="utf-8")
            contract_path.write_text(json.dumps(contract()), encoding="utf-8")
            json_out.write_text("old-json", encoding="utf-8")
            markdown_out.write_text("old-markdown", encoding="utf-8")
            stderr = StringIO()
            with redirect_stderr(stderr):
                result = SCORECARD.main(
                    [
                        str(model_path),
                        "--campaign-contract",
                        str(contract_path),
                        "--json-out",
                        str(json_out),
                        "--markdown-out",
                        str(markdown_out),
                    ]
                )
            self.assertEqual(result, 2)
            self.assertIn("error:", stderr.getvalue())
            self.assertEqual(json_out.read_text(encoding="utf-8"), "old-json")
            self.assertEqual(markdown_out.read_text(encoding="utf-8"), "old-markdown")


if __name__ == "__main__":
    unittest.main()
