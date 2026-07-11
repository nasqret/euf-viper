from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "analyze_euf_bva.py"
SPEC = importlib.util.spec_from_file_location("analyze_euf_bva", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ANALYZER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ANALYZER
SPEC.loader.exec_module(ANALYZER)


LEFTS = (1, 2, 3)
TAILS = ((4, 5), (6, 7))


def rectangle_clauses(
    lefts: tuple[int, ...] = LEFTS,
    tails: tuple[tuple[int, ...], ...] = TAILS,
) -> list[list[int]]:
    return [[left, *tail] for left in lefts for tail in tails]


def winning_cnf() -> object:
    return ANALYZER.Cnf.from_clauses(7, rectangle_clauses())


def table_payload() -> dict[str, object]:
    return {
        "schema": ANALYZER.METADATA_SCHEMA,
        "literals": {
            str(literal): {"table": "mul", "cell": [0, 1], "value": value}
            for value, literal in enumerate(LEFTS)
        },
    }


def accepted_candidate(report: dict[str, object]) -> dict[str, object]:
    accepted = [
        candidate
        for candidate in report["candidates"]
        if candidate["decision"] == "accepted"
    ]
    if len(accepted) != 1:
        raise AssertionError(f"expected one accepted candidate, found {len(accepted)}")
    return accepted[0]


class DimacsTests(unittest.TestCase):
    def test_parses_multiline_clauses_and_canonicalizes_order(self) -> None:
        parsed = ANALYZER.parse_dimacs(
            """c example
p cnf 4 3
4 -1
2 0
0
3 0
"""
        )

        self.assertEqual(parsed.variables, 4)
        self.assertEqual(parsed.clauses, ((), (-1, 2, 4), (3,)))

    def test_rejects_bad_headers_counts_literals_and_termination(self) -> None:
        malformed = [
            "1 0\np cnf 1 1\n",
            "p sat 1 1\n1 0\n",
            "p cnf 1 2\n1 0\n",
            "p cnf 1 1\n2 0\n",
            "p cnf 1 1\n1\n",
            "p cnf 1 1\n1 0\np cnf 1 0\n",
        ]
        for text in malformed:
            with self.subTest(text=text):
                with self.assertRaises(ANALYZER.DimacsError):
                    ANALYZER.parse_dimacs(text)


class CandidateTests(unittest.TestCase):
    def test_syntactic_rectangle_wins_and_certificate_replays(self) -> None:
        report = ANALYZER.analyze_cnf(winning_cnf())
        candidate = accepted_candidate(report)

        self.assertEqual(report["schema"], ANALYZER.REPORT_SCHEMA)
        self.assertEqual(candidate["classification"], "syntactic")
        self.assertIsNone(candidate["table_evidence"])
        self.assertEqual(candidate["left_literals"], list(LEFTS))
        self.assertEqual(candidate["tails"], [list(tail) for tail in TAILS])
        self.assertEqual(candidate["metrics"]["literal_reduction"], 6)
        self.assertEqual(candidate["metrics"]["clause_reduction"], 1)
        self.assertEqual(report["original"]["variables"], 7)
        self.assertEqual(report["original"]["clauses"], 6)
        self.assertEqual(report["original"]["literal_count"], 18)
        self.assertEqual(report["projected"]["variables"], 8)
        self.assertEqual(report["projected"]["clauses"], 5)
        self.assertEqual(report["projected"]["literal_count"], 12)
        self.assertEqual(report["projected"]["added_variables"], 1)
        self.assertEqual(report["summary"]["literal_reduction"], 6)
        self.assertEqual(report["verification"]["structural"], "verified")
        self.assertEqual(
            report["verification"]["exhaustive"]["status"], "verified"
        )

        replay = ANALYZER.verify_certificate(
            winning_cnf(), report["certificate"], exhaustive_max_variables=8
        )
        self.assertEqual(replay, report["verification"])

    def test_metadata_distinguishes_finite_table_axis(self) -> None:
        metadata = ANALYZER.parse_metadata(table_payload(), 7)
        report = ANALYZER.analyze_cnf(winning_cnf(), metadata)
        candidate = accepted_candidate(report)

        self.assertEqual(candidate["classification"], "table-aware")
        self.assertEqual(
            candidate["table_evidence"]["pattern"],
            "same_cell_distinct_values",
        )
        self.assertEqual(candidate["table_evidence"]["table"], "mul")
        self.assertEqual(candidate["table_evidence"]["values"], [0, 1, 2])
        self.assertEqual(report["summary"]["accepted_table_aware"], 1)
        self.assertEqual(report["summary"]["accepted_syntactic"], 0)
        self.assertEqual(report["metadata"]["mapped_literals"], 3)
        self.assertEqual(len(report["metadata"]["sha256"]), 64)

    def test_partial_or_incoherent_metadata_remains_syntactic(self) -> None:
        partial = ANALYZER.parse_metadata(
            {
                "literals": {
                    "1": {"table": "f", "cell": [0], "value": 0},
                    "2": {"table": "g", "cell": [0], "value": 1},
                }
            },
            7,
        )
        report = ANALYZER.analyze_cnf(winning_cnf(), partial)

        self.assertEqual(accepted_candidate(report)["classification"], "syntactic")

    def test_table_metadata_can_classify_the_tail_axis(self) -> None:
        tails = ((4,), (5,), (6,))
        cnf = ANALYZER.Cnf.from_clauses(
            6, rectangle_clauses(tails=tails)
        )
        metadata = ANALYZER.parse_metadata(
            {
                "literals": {
                    str(literal): {
                        "table": "inverse",
                        "cell": [2],
                        "value": value,
                    }
                    for value, literal in enumerate((4, 5, 6))
                }
            },
            6,
        )

        report = ANALYZER.analyze_cnf(cnf, metadata)
        candidate = accepted_candidate(report)

        self.assertEqual(candidate["classification"], "table-aware")
        self.assertEqual(candidate["table_evidence"]["axis"], "tails")
        self.assertEqual(
            candidate["table_evidence"]["pattern"],
            "same_cell_distinct_values",
        )
        self.assertEqual(candidate["table_evidence"]["common_tail"], [])

    def test_non_improving_rectangle_is_retained_and_rejected(self) -> None:
        cnf = ANALYZER.Cnf.from_clauses(3, [[1, 3], [2, 3]])
        report = ANALYZER.analyze_cnf(cnf)
        target = next(
            candidate
            for candidate in report["candidates"]
            if candidate["left_literals"] == [1, 2]
            and candidate["tails"] == [[3]]
        )

        self.assertEqual(target["decision"], "rejected")
        self.assertEqual(target["reason"], "no_literal_reduction")
        self.assertLess(target["metrics"]["literal_reduction"], 0)
        self.assertEqual(report["summary"]["accepted"], 0)
        self.assertEqual(report["original"], report["certificate"]["projected"])

    def test_width_cap_rejects_a_profitable_rectangle(self) -> None:
        report = ANALYZER.analyze_cnf(winning_cnf(), width_cap=2)
        target = next(
            candidate
            for candidate in report["candidates"]
            if candidate["left_literals"] == list(LEFTS)
            and candidate["tails"] == [list(tail) for tail in TAILS]
        )

        self.assertGreater(target["metrics"]["literal_reduction"], 0)
        self.assertEqual(target["metrics"]["max_added_width"], 3)
        self.assertEqual(target["decision"], "rejected")
        self.assertEqual(target["reason"], "width_cap")
        self.assertEqual(report["summary"]["accepted"], 0)
        self.assertEqual(report["projected"]["added_variables"], 0)

    def test_added_variable_and_candidate_caps_are_explicit(self) -> None:
        variable_capped = ANALYZER.analyze_cnf(
            winning_cnf(), max_added_variables=0
        )
        target = next(
            candidate
            for candidate in variable_capped["candidates"]
            if candidate["left_literals"] == list(LEFTS)
            and candidate["tails"] == [list(tail) for tail in TAILS]
        )
        self.assertEqual(target["reason"], "added_variable_cap")

        candidate_capped = ANALYZER.analyze_cnf(winning_cnf(), candidate_cap=0)
        self.assertEqual(candidate_capped["candidates"], [])
        self.assertTrue(candidate_capped["enumeration"]["truncated"])
        self.assertEqual(candidate_capped["projected"]["added_variables"], 0)

    def test_exhaustive_cap_skips_but_structural_replay_still_runs(self) -> None:
        report = ANALYZER.analyze_cnf(
            winning_cnf(), exhaustive_max_variables=7
        )

        self.assertEqual(report["verification"]["structural"], "verified")
        self.assertEqual(report["verification"]["exhaustive"]["status"], "skipped")
        self.assertEqual(
            report["verification"]["exhaustive"]["projected_variables"], 8
        )


class MetadataTests(unittest.TestCase):
    def test_rejects_malformed_metadata(self) -> None:
        malformed = [
            [],
            {"schema": "wrong", "literals": {}},
            {"literals": []},
            {"literals": {1: {"table": "f", "cell": [0], "value": 0}}},
            {"literals": {"01": {"table": "f", "cell": [0], "value": 0}}},
            {"literals": {"8": {"table": "f", "cell": [0], "value": 0}}},
            {"literals": {"1": {"table": "f", "cell": [], "value": 0}}},
            {"literals": {"1": {"table": "f", "cell": [0], "value": True}}},
            {
                "literals": {
                    "1": {"table": "f", "cell": [0], "value": 0},
                    "2": {"table": "f", "cell": [0], "value": 0},
                }
            },
            {
                "literals": {
                    "1": {
                        "table": "f",
                        "cell": [0],
                        "value": 0,
                        "extra": 1,
                    }
                }
            },
        ]
        for payload in malformed:
            with self.subTest(payload=payload):
                with self.assertRaises(ANALYZER.MetadataError):
                    ANALYZER.parse_metadata(payload, 7)

    def test_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bva metadata ") as temp_dir:
            path = Path(temp_dir) / "metadata.json"
            path.write_text(
                '{"literals":{"1":{"table":"f","cell":[0],"value":0},'
                '"1":{"table":"f","cell":[0],"value":1}}}',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ANALYZER.MetadataError, "duplicate JSON"):
                ANALYZER.load_metadata_json(path)

    def test_literal_sign_is_exact(self) -> None:
        negative_cnf = ANALYZER.Cnf.from_clauses(
            7, rectangle_clauses(lefts=(-1, -2, -3))
        )
        positive_metadata = ANALYZER.parse_metadata(table_payload(), 7)
        positive_report = ANALYZER.analyze_cnf(negative_cnf, positive_metadata)
        self.assertEqual(
            accepted_candidate(positive_report)["classification"], "syntactic"
        )

        negative_payload = table_payload()
        negative_payload["literals"] = {
            str(-literal): record
            for literal, record in [
                (int(key), value)
                for key, value in negative_payload["literals"].items()
            ]
        }
        negative_metadata = ANALYZER.parse_metadata(negative_payload, 7)
        negative_report = ANALYZER.analyze_cnf(negative_cnf, negative_metadata)
        self.assertEqual(
            accepted_candidate(negative_report)["classification"], "table-aware"
        )


class DeterminismTests(unittest.TestCase):
    def test_clause_and_metadata_insertion_order_do_not_change_report(self) -> None:
        first_cnf = winning_cnf()
        second_cnf = ANALYZER.Cnf.from_clauses(
            7, [reversed(clause) for clause in reversed(rectangle_clauses())]
        )
        first_payload = table_payload()
        second_payload = {
            "literals": dict(reversed(list(first_payload["literals"].items()))),
            "schema": ANALYZER.METADATA_SCHEMA,
        }
        first_metadata = ANALYZER.parse_metadata(first_payload, 7)
        second_metadata = ANALYZER.parse_metadata(second_payload, 7)

        first = ANALYZER.analyze_cnf(first_cnf, first_metadata, candidate_cap=32)
        second = ANALYZER.analyze_cnf(second_cnf, second_metadata, candidate_cap=32)

        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first, sort_keys=True, separators=(",", ":")),
            json.dumps(second, sort_keys=True, separators=(",", ":")),
        )

    def test_candidate_cap_retains_same_best_candidate(self) -> None:
        first = ANALYZER.analyze_cnf(winning_cnf(), candidate_cap=1)
        second = ANALYZER.analyze_cnf(winning_cnf(), candidate_cap=1)

        self.assertEqual(first, second)
        self.assertEqual(first["summary"]["accepted"], 1)
        self.assertEqual(
            accepted_candidate(first)["left_literals"], list(LEFTS)
        )


class CertificateTests(unittest.TestCase):
    def test_rejects_tampered_added_clause_id_hash_and_projection(self) -> None:
        report = ANALYZER.analyze_cnf(winning_cnf())
        certificate = report["certificate"]

        tampered_added = copy.deepcopy(certificate)
        tampered_added["steps"][0]["added_clauses"][0][0] -= 1
        tampered_id = copy.deepcopy(certificate)
        tampered_id["steps"][0]["candidate_id"] = "bva-deadbeef"
        tampered_hash = copy.deepcopy(certificate)
        tampered_hash["steps"][0]["after"]["sha256"] = "0" * 64
        tampered_projection = copy.deepcopy(certificate)
        tampered_projection["projected_clauses"].pop()

        for altered in (
            tampered_added,
            tampered_id,
            tampered_hash,
            tampered_projection,
        ):
            with self.subTest(altered=altered):
                with self.assertRaises(ANALYZER.CertificateError):
                    ANALYZER.verify_certificate(winning_cnf(), altered)

    def test_rejects_certificate_for_a_different_original_multiset(self) -> None:
        report = ANALYZER.analyze_cnf(winning_cnf())
        different = ANALYZER.Cnf.from_clauses(
            7, [*rectangle_clauses(), [1]]
        )

        with self.assertRaisesRegex(ANALYZER.CertificateError, "original"):
            ANALYZER.verify_certificate(different, report["certificate"])

    def test_independent_checker_finds_non_equivalent_projection(self) -> None:
        original = ANALYZER.Cnf.from_clauses(1, [[1]])
        projected = ANALYZER.Cnf.from_clauses(2, [[2]])

        result = ANALYZER.exhaustive_projective_check(
            original, projected, max_variables=2
        )

        self.assertEqual(result["status"], "mismatch")
        self.assertFalse(result["equivalent"])
        self.assertEqual(result["witness"]["original_true_variables"], [])
        self.assertFalse(result["witness"]["original_result"])
        self.assertTrue(result["witness"]["projected_has_extension"])


class CliTests(unittest.TestCase):
    def test_cli_emits_stable_machine_readable_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="euf bva cli ") as temp_dir:
            base = Path(temp_dir)
            cnf_path = base / "input with spaces.cnf"
            metadata_path = base / "metadata with spaces.json"
            output_path = base / "report with spaces.json"
            clauses = rectangle_clauses()
            cnf_path.write_text(
                "p cnf 7 6\n"
                + "\n".join(" ".join(map(str, clause)) + " 0" for clause in clauses)
                + "\n",
                encoding="utf-8",
            )
            metadata_path.write_text(
                json.dumps(table_payload()), encoding="utf-8"
            )

            command = [
                sys.executable,
                str(SCRIPT),
                str(cnf_path),
                "--metadata",
                str(metadata_path),
                "--candidate-cap",
                "32",
            ]
            first = subprocess.run(command, text=True, capture_output=True, check=False)
            second = subprocess.run(command, text=True, capture_output=True, check=False)

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(first.stdout, second.stdout)
            payload = json.loads(first.stdout)
            self.assertEqual(payload["schema"], ANALYZER.REPORT_SCHEMA)
            self.assertEqual(payload["summary"]["accepted_table_aware"], 1)

            written = subprocess.run(
                [*command, "--output", str(output_path)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(written.returncode, 0, written.stderr)
            self.assertEqual(written.stdout, "")
            self.assertEqual(output_path.read_text(encoding="utf-8"), first.stdout)

    def test_cli_reports_malformed_metadata_without_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="euf bva bad metadata ") as temp_dir:
            base = Path(temp_dir)
            cnf_path = base / "input.cnf"
            metadata_path = base / "metadata.json"
            cnf_path.write_text("p cnf 1 1\n1 0\n", encoding="utf-8")
            metadata_path.write_text('{"literals":[]}', encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(cnf_path),
                    "--metadata",
                    str(metadata_path),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertIn("error:", result.stderr)
            self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
