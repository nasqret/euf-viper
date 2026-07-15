from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CERTIFICATE_DIRECTORY = ROOT / "scripts" / "cert"
SPEC = importlib.util.spec_from_file_location(
    "check_certificate_under_test", CERTIFICATE_DIRECTORY / "check_certificate.py"
)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(CERTIFICATE_DIRECTORY))
try:
    SPEC.loader.exec_module(CHECKER)
finally:
    sys.path.pop(0)


class DescriptorInheritanceTests(unittest.TestCase):
    def test_all_descriptor_bound_checker_inputs_are_inherited(self) -> None:
        self.assertEqual(
            CHECKER.inherited_procfd_descriptors(
                [
                    ("drat-trim", "/proc/self/fd/11"),
                    ("DIMACS", "/proc/self/fd/7"),
                    ("proof", "/proc/self/fd/9"),
                    ("duplicate", "/proc/self/fd/7"),
                    ("ordinary", "/opt/checker"),
                ]
            ),
            (7, 9, 11),
        )

    def test_malformed_procfd_path_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "descriptor-bound proof"):
            CHECKER.inherited_procfd_descriptors(
                [("proof", "/proc/self/fd/not-a-number")]
            )


if __name__ == "__main__":
    unittest.main()
