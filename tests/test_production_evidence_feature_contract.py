from __future__ import annotations

import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ProductionEvidenceFeatureContractTests(unittest.TestCase):
    def test_production_evidence_is_never_activated_implicitly(self) -> None:
        manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        features = manifest["features"]

        self.assertEqual(features["default"], ["finite-symmetry"])
        self.assertNotIn("production-evidence", features["default"])
        self.assertNotIn("production-evidence", features["certificates"])
        self.assertEqual(
            set(features["production-evidence"]),
            {"dep:libc", "dep:serde", "dep:serde_json", "dep:sha2"},
        )

    def test_documentation_scopes_the_mode_and_denies_default_claims(self) -> None:
        text = (ROOT / "docs" / "book" / "production-evidence.md").read_text(
            encoding="utf-8"
        )
        for required in (
            "restricted SAT-only certifying mode",
            "not enabled by the default Cargo features",
            "deterministic canonical routes",
            "Congruence-closure SAT and UNSAT",
            "does not establish a coverage result",
        ):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
