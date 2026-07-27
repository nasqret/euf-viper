from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "collect_cadical_probe.py"
SPEC = importlib.util.spec_from_file_location("collect_cadical_probe", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class CadicalProbeCollectorTests(unittest.TestCase):
    def test_parses_strict_integer_and_symbolic_fields(self) -> None:
        fields = PROBE.parse_fields(
            "profile_probe outcome=interrupted limit=100 conflicts=100",
            "profile_probe ",
        )
        self.assertEqual(
            fields,
            {"outcome": "interrupted", "limit": 100, "conflicts": 100},
        )

    def test_rejects_malformed_and_repeated_fields(self) -> None:
        with self.assertRaisesRegex(PROBE.ProbeError, "malformed"):
            PROBE.parse_fields("profile_probe bad", "profile_probe ")
        with self.assertRaisesRegex(PROBE.ProbeError, "repeated"):
            PROBE.parse_fields(
                "profile_probe conflicts=1 conflicts=2", "profile_probe "
            )

    def test_parses_phase_measurement(self) -> None:
        self.assertEqual(
            PROBE.parse_phase("profile_cnf_ns=123 count=456", "profile_cnf_ns="),
            {"elapsed_ns": 123, "count": 456},
        )
        with self.assertRaisesRegex(PROBE.ProbeError, "malformed phase"):
            PROBE.parse_phase("profile_cnf_ns=123 size=456", "profile_cnf_ns=")


if __name__ == "__main__":
    unittest.main()
