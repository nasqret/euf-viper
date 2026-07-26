from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "merge_euf_dashboard_registries.py"
MODULE_SPEC = importlib.util.spec_from_file_location(
    "merge_euf_dashboard_registries", SCRIPT
)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
MERGER = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(MERGER)


REVISION = "1" * 40
SOURCE_HASH = "a" * 64
UPDATED_AT = "2026-07-26T12:00:00Z"


def evidence(
    identifier: str,
    viper_id: str,
    competitor_id: str,
    *,
    host_label: str = "Test host",
) -> dict:
    return {
        "id": identifier,
        "scope": "targeted",
        "evidence_class": "pairwise-canary",
        "evidence_status": "provisional",
        "revision": REVISION,
        "solver_ids": [competitor_id, viper_id],
        "host": {"id": "test-host", "label": host_label},
        "corpus": {"id": "test-corpus", "label": "Test corpus"},
        "timeout_s": 2.0,
        "family": {"id": "all", "label": "All families"},
        "expected_status": "all",
        "source": {
            "path": f"fixtures/{identifier}.json",
            "sha256": SOURCE_HASH,
        },
        "instances": [
            {
                "id": f"case-{identifier}",
                "results": [
                    {
                        "solver_id": competitor_id,
                        "status": "solved",
                        "time_s": 0.2,
                    },
                    {
                        "solver_id": viper_id,
                        "status": "solved",
                        "time_s": 0.1,
                    },
                ],
            }
        ],
    }


def registry(
    identifier: str,
    competitor_id: str,
    competitor_label: str,
    *,
    evidence_id: str | None = None,
    viper_id: str = "viper",
    viper_label: str = "Viper",
    host_label: str = "Test host",
) -> dict:
    item = evidence(
        evidence_id or f"evidence-{identifier}",
        viper_id,
        competitor_id,
        host_label=host_label,
    )
    return {
        "schema_version": MERGER.DASHBOARD.REGISTRY_SCHEMA_VERSION,
        "registry_id": identifier,
        "title": f"Input {identifier}",
        "updated_at": UPDATED_AT,
        "viper_solver_id": viper_id,
        "solvers": [
            {"id": competitor_id, "label": competitor_label},
            {"id": viper_id, "label": viper_label},
        ],
        "evidence": [item],
    }


class MergerTests(unittest.TestCase):
    def test_union_is_deterministic_and_preserves_pairwise_solver_ids(self) -> None:
        yices = registry("yices-input", "yices", "Yices 2")
        z3 = registry("z3-input", "z3", "Z3")

        first = MERGER.merge_registries(
            [yices, z3],
            registry_id="merged",
            title="Merged \N{GREEK SMALL LETTER MU} campaign",
            updated_at=UPDATED_AT,
        )

        reordered_yices = copy.deepcopy(yices)
        reordered_z3 = copy.deepcopy(z3)
        for item in (reordered_yices, reordered_z3):
            item["solvers"].reverse()
            item["evidence"].reverse()
            for record in item["evidence"]:
                record["solver_ids"].reverse()
                record["instances"].reverse()
                for observed in record["instances"]:
                    observed["results"].reverse()
        second = MERGER.merge_registries(
            [reordered_z3, reordered_yices],
            registry_id="merged",
            title="Merged \N{GREEK SMALL LETTER MU} campaign",
            updated_at=UPDATED_AT,
        )

        self.assertEqual(
            MERGER.DASHBOARD.pretty_json_bytes(first),
            MERGER.DASHBOARD.pretty_json_bytes(second),
        )
        self.assertEqual(first["registry_id"], "merged")
        self.assertEqual(first["title"], "Merged \N{GREEK SMALL LETTER MU} campaign")
        self.assertEqual(first["updated_at"], UPDATED_AT)
        self.assertEqual(
            [solver["id"] for solver in first["solvers"]],
            ["viper", "yices", "z3"],
        )
        subsets = {item["id"]: item["solver_ids"] for item in first["evidence"]}
        self.assertEqual(subsets["evidence-yices-input"], ["viper", "yices"])
        self.assertEqual(subsets["evidence-z3-input"], ["viper", "z3"])
        self.assertNotIn(
            ["viper", "yices", "z3"],
            [item["solver_ids"] for item in first["evidence"]],
        )

    def test_rejects_identity_duplicates_and_cross_registry_label_conflicts(self) -> None:
        yices = registry("yices-input", "yices", "Yices 2")
        z3 = registry("z3-input", "z3", "Z3")

        cases = []
        different_viper = registry(
            "other-viper", "z3", "Z3", viper_id="viper-next"
        )
        cases.append(("viper", [yices, different_viper], "viper_solver_id"))

        conflicting_solver = registry("conflict", "yices", "Yices Two")
        cases.append(("solver", [yices, conflicting_solver], "solver labels"))

        duplicate = registry(
            "duplicate", "z3", "Z3", evidence_id="evidence-yices-input"
        )
        cases.append(("evidence", [yices, duplicate], "duplicate evidence ID"))

        conflicting_host = registry(
            "host-conflict", "z3", "Z3", host_label="Different host"
        )
        cases.append(("host", [yices, conflicting_host], "host labels"))

        for name, inputs, message in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    MERGER.DASHBOARD.DashboardInputError, message
                ):
                    MERGER.merge_registries(
                        inputs,
                        registry_id="merged",
                        title="Merged campaign",
                        updated_at=UPDATED_AT,
                    )

        merged = MERGER.merge_registries(
            [yices, z3],
            registry_id="merged",
            title="Merged campaign",
            updated_at=UPDATED_AT,
        )
        MERGER.DASHBOARD.validate_registry(merged)

    def test_rejects_too_few_empty_and_invalid_inputs(self) -> None:
        valid = registry("valid", "yices", "Yices 2")
        with self.assertRaisesRegex(
            MERGER.DASHBOARD.DashboardInputError, "at least two"
        ):
            MERGER.merge_registries(
                [valid],
                registry_id="merged",
                title="Merged campaign",
                updated_at=UPDATED_AT,
            )

        empty = copy.deepcopy(valid)
        empty["evidence"] = []
        with self.assertRaisesRegex(
            MERGER.DASHBOARD.DashboardInputError, "must not be empty"
        ):
            MERGER.merge_registries(
                [valid, empty],
                registry_id="merged",
                title="Merged campaign",
                updated_at=UPDATED_AT,
            )

        invalid = copy.deepcopy(valid)
        invalid["schema_version"] = "invalid"
        with self.assertRaisesRegex(
            MERGER.DASHBOARD.DashboardInputError, "schema_version"
        ):
            MERGER.merge_registries(
                [valid, invalid],
                registry_id="merged",
                title="Merged campaign",
                updated_at=UPDATED_AT,
            )

    def test_cli_writes_atomic_ascii_json_and_preserves_output_on_failure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="euf merger ") as temp_dir:
            root = Path(temp_dir)
            yices_path = root / "yices.json"
            z3_path = root / "z3.json"
            output = root / "merged.json"
            yices_path.write_text(
                json.dumps(registry("yices", "yices", "Yices 2")),
                encoding="utf-8",
            )
            z3_path.write_text(
                json.dumps(registry("z3", "z3", "Z3")), encoding="utf-8"
            )

            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = MERGER.main(
                    [
                        str(yices_path),
                        str(z3_path),
                        "--output",
                        str(output),
                        "--registry-id",
                        "merged",
                        "--title",
                        "Merged \N{GREEK SMALL LETTER MU} campaign",
                        "--updated-at",
                        UPDATED_AT,
                    ]
                )
            self.assertEqual(exit_code, 0)
            receipt = json.loads(stdout.getvalue())
            self.assertEqual(receipt["evidence"], 2)
            payload = output.read_bytes()
            payload.decode("ascii")
            self.assertIn(b"\\u03bc", payload)
            merged = json.loads(payload)
            MERGER.DASHBOARD.validate_registry(merged)
            self.assertFalse(list(root.glob(".merged.json.*.tmp")))

            original = payload
            z3_path.write_text(
                json.dumps(registry("bad", "yices", "Conflicting Yices")),
                encoding="utf-8",
            )
            stderr = StringIO()
            with redirect_stderr(stderr), redirect_stdout(StringIO()):
                exit_code = MERGER.main(
                    [
                        str(yices_path),
                        str(z3_path),
                        "--output",
                        str(output),
                        "--registry-id",
                        "merged",
                        "--title",
                        "Merged campaign",
                        "--updated-at",
                        UPDATED_AT,
                    ]
                )
            self.assertEqual(exit_code, 2)
            self.assertIn("conflicting solver labels", stderr.getvalue())
            self.assertEqual(output.read_bytes(), original)
            self.assertFalse(list(root.glob(".merged.json.*.tmp")))


if __name__ == "__main__":
    unittest.main()
