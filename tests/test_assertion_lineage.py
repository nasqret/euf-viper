from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "cert" / "verify_assertion_lineage.py"
FIXTURE = ROOT / "tests" / "fixtures" / "assertion_lineage" / "adversarial.smt2"
MODULE_SPEC = importlib.util.spec_from_file_location("verify_assertion_lineage", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = VERIFIER
MODULE_SPEC.loader.exec_module(VERIFIER)


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class AssertionLineageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(
            ["cargo", "+1.96.0", "build", "--features", "lineage"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        cls.binary = ROOT / "target" / "debug" / "euf-viper"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="euf-viper-lineage-test-")
        self.directory = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def produce(self, source: Path, *, expected: bytes | None = None) -> Path:
        content = source.read_bytes() if expected is None else expected
        ledger = self.directory / f"{source.stem}.lineage.json"
        environment = dict(os.environ)
        environment["EUF_VIPER_SCOPED_LET"] = "on"
        subprocess.run(
            [
                str(self.binary),
                "lineage",
                str(source),
                "--source-sha256",
                sha256_bytes(content),
                "--source-bytes",
                str(len(content)),
                "--out",
                str(ledger),
            ],
            cwd=ROOT,
            env=environment,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return ledger

    def fixture_ledger(self) -> Path:
        return self.produce(FIXTURE)

    def rewrite(
        self,
        ledger: Path,
        mutation: Callable[[dict[str, Any]], None],
        *,
        refresh_commitment: bool = False,
    ) -> Path:
        value = json.loads(ledger.read_text(encoding="utf-8"))
        mutation(value)
        if refresh_commitment:
            commitment = copy.deepcopy(value)
            commitment.pop("lineage_sha256")
            value["lineage_sha256"] = sha256_bytes(VERIFIER.canonical_bytes(commitment))
        output = self.directory / f"mutation-{len(list(self.directory.iterdir()))}.json"
        output.write_bytes(VERIFIER.canonical_bytes(value))
        return output

    def assert_rejected(
        self,
        ledger: Path,
        message: str,
        *,
        source: Path = FIXTURE,
        reconstruct: bool = False,
    ) -> None:
        with self.assertRaises(VERIFIER.LineageError) as caught:
            VERIFIER.validate_ledger(source, ledger, reconstruct=reconstruct)
        self.assertIn(message, str(caught.exception))

    def test_independent_reconstructor_accepts_adversarial_fixture(self) -> None:
        ledger = self.fixture_ledger()
        result = VERIFIER.validate_ledger(FIXTURE, ledger, reconstruct=True)

        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["source_assertions"], 4)
        self.assertEqual(result["objects"], 11)
        self.assertTrue(result["independent_reconstruction"])

        value = json.loads(ledger.read_text(encoding="utf-8"))
        repeated = value["assertions"][1:3]
        self.assertEqual(repeated[0]["raw_ast_sha256"], repeated[1]["raw_ast_sha256"])
        self.assertNotEqual(repeated[0]["span"], repeated[1]["span"])
        shared = [
            obj
            for obj in value["objects"]
            if obj["transformation_kind"]
            in {"bool_materialization_axiom", "bool_materialization_term"}
        ]
        self.assertEqual(len(shared), 2)
        for obj in shared:
            self.assertEqual(
                [origin["assertion_id"] for origin in obj["origins"]],
                ["assertion-000001", "assertion-000002"],
            )

    def test_crlf_comments_and_repeated_assertions_reconstruct(self) -> None:
        source = self.directory / "crlf.smt2"
        source.write_bytes(
            b"; leading\r\n(set-logic QF_UF)\r\n"
            b"(assert true) ; inside line\r\n"
            b"(assert true)\r\n(check-sat)\r\n"
        )
        ledger = self.produce(source)
        result = VERIFIER.validate_ledger(source, ledger)
        self.assertEqual(result["source_assertions"], 2)
        value = json.loads(ledger.read_text(encoding="utf-8"))
        first, second = value["assertions"]
        self.assertEqual(first["raw_ast_sha256"], second["raw_ast_sha256"])
        self.assertNotEqual(first["span"], second["span"])

    def test_current_push_pop_unsupported_diagnostics_are_exactly_accounted(self) -> None:
        source = self.directory / "push-pop.smt2"
        source.write_bytes(
            b"(set-logic QF_UF)\n(push 1)\n(assert true)\n(pop 1)\n(check-sat)\n"
        )
        ledger = self.produce(source)
        result = VERIFIER.validate_ledger(source, ledger)
        self.assertEqual(result["diagnostics"], 2)
        value = json.loads(ledger.read_text(encoding="utf-8"))
        self.assertEqual(
            [diagnostic["message"] for diagnostic in value["diagnostics"]],
            ["unsupported top-level command push", "unsupported top-level command pop"],
        )
        self.assertEqual(
            [diagnostic["command_id"] for diagnostic in value["diagnostics"]],
            ["command-000001", "command-000003"],
        )

    def test_producer_rejects_stale_expected_source(self) -> None:
        content = FIXTURE.read_bytes()
        with self.assertRaises(subprocess.CalledProcessError) as caught:
            self.produce(FIXTURE, expected=content + b" ")
        self.assertIn("stale-source", caught.exception.stderr.decode("utf-8"))

    def test_verifier_rejects_zero_length_truncated_and_overlapping_spans(self) -> None:
        ledger = self.fixture_ledger()
        zero = self.rewrite(
            ledger,
            lambda value: value["assertions"][0]["span"].update(
                {"end": value["assertions"][0]["span"]["start"]}
            ),
        )
        self.assert_rejected(zero, "assertion reconstruction mismatch")

        truncated = self.rewrite(
            ledger,
            lambda value: value["commands"][0]["span"].update({"end": 10**9}),
        )
        self.assert_rejected(truncated, "command reconstruction mismatch")

        def overlap(value: dict[str, Any]) -> None:
            value["assertions"][1]["span"] = dict(value["assertions"][0]["span"])

        overlapping = self.rewrite(ledger, overlap)
        self.assert_rejected(overlapping, "assertion reconstruction mismatch")

    def test_verifier_rejects_lineage_loss_duplicate_and_unsupported_kind(self) -> None:
        ledger = self.fixture_ledger()

        def lose_object(value: dict[str, Any]) -> None:
            removed = value["objects"].pop(0)
            value["counts"]["objects"] -= 1
            value["counts"]["boolean_assertions"] -= int(
                removed["object_kind"] == "boolean_assertion"
            )
            for ordinal, obj in enumerate(value["objects"]):
                obj["id"] = f"object-{ordinal:06}"
                transform = obj["transformation_kind"]
                obj["local_index"] = sum(
                    previous["transformation_kind"] == transform
                    for previous in value["objects"][:ordinal]
                )

        lost = self.rewrite(ledger, lose_object, refresh_commitment=True)
        self.assert_rejected(
            lost,
            "independent Boolean/EUF auxiliary reconstruction mismatch",
            reconstruct=True,
        )

        duplicate = self.rewrite(
            ledger,
            lambda value: value["objects"][1].update(
                {"id": value["objects"][0]["id"]}
            ),
        )
        self.assert_rejected(duplicate, "non-canonical ID order")

        unsupported = self.rewrite(
            ledger,
            lambda value: value["objects"][0].update(
                {"transformation_kind": "frontier_search"}
            ),
        )
        self.assert_rejected(unsupported, "unsupported transformation")

    def test_verifier_rejects_duplicate_origins_and_ambiguous_assertion_identity(self) -> None:
        ledger = self.fixture_ledger()
        duplicate_origin = self.rewrite(
            ledger,
            lambda value: value["objects"][0]["origins"].append(
                copy.deepcopy(value["objects"][0]["origins"][0])
            ),
        )
        self.assert_rejected(duplicate_origin, "duplicate or non-canonical origins")

        ambiguous = self.rewrite(
            ledger,
            lambda value: value["assertions"][1].update(
                {"id": value["assertions"][0]["id"]}
            ),
        )
        self.assert_rejected(ambiguous, "assertion reconstruction mismatch")

    def test_verifier_rejects_boolean_or_negative_integer_bindings(self) -> None:
        ledger = self.fixture_ledger()

        boolean_ordinal = self.rewrite(
            ledger,
            lambda value: value["assertions"][0].update({"ordinal": False}),
            refresh_commitment=True,
        )
        self.assert_rejected(boolean_ordinal, "expected non-negative integer")

        negative_let_count = self.rewrite(
            ledger,
            lambda value: value["parser"].update({"bounded_let_count": -1}),
            refresh_commitment=True,
        )
        self.assert_rejected(negative_let_count, "expected non-negative integer")

    def test_verifier_rejects_noncanonical_duplicate_key_and_nonfinite_json(self) -> None:
        ledger = self.fixture_ledger()
        value = json.loads(ledger.read_text(encoding="utf-8"))

        pretty = self.directory / "pretty.json"
        pretty.write_text(json.dumps(value, indent=2), encoding="utf-8")
        self.assert_rejected(pretty, "not strict canonical JSON")

        duplicate_key = self.directory / "duplicate-key.json"
        raw = ledger.read_bytes()
        duplicate_key.write_bytes(raw.replace(b'{"active_check_sat":', b'{"schema":"duplicate","active_check_sat":', 1))
        self.assert_rejected(duplicate_key, "duplicate JSON key")

        nonfinite = self.directory / "nonfinite.json"
        nonfinite.write_bytes(raw.replace(b'"commands":', b'"unexpected":NaN,"commands":', 1))
        self.assert_rejected(nonfinite, "non-finite JSON number")

    def test_verifier_rejects_source_mutation_after_ledger_generation(self) -> None:
        source = self.directory / "mutable.smt2"
        source.write_bytes(FIXTURE.read_bytes())
        ledger = self.produce(source)
        source.write_bytes(source.read_bytes().replace(b"(assert |m|)", b"(assert false)", 1))
        self.assert_rejected(ledger, "source size mismatch", source=source)


if __name__ == "__main__":
    unittest.main()
