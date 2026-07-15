#!/usr/bin/env python3
"""Run mandatory Linux T5 publication tests and reject every test skip."""

from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.bench import record_t5_ci_identity as identity  # noqa: E402


TEST_NAMES = (
    "tests.test_wmi_component_quotient_census.LinuxPublicationContractTests",
    "tests.test_wmi_component_quotient_census.LinuxConsumerRevalidationTests",
    "tests.test_t5_environment_canary.LinuxEnvironmentCanaryTests",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity-output", type=Path, required=True)
    parser.add_argument("--require-hosted-image", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        value = identity.capture_identity(
            scope="ordinary_linux_publication_procfs_diagnostic",
            scheduler_evidence="not_queried",
            require_hosted_image=arguments.require_hosted_image,
        )
        identity.write_identity_no_replace(arguments.identity_output, value)
    except (OSError, identity.CiIdentityError) as error:
        print(f"mandatory T5 Linux diagnostic identity failed: {error}", file=sys.stderr)
        return 2
    if not sys.platform.startswith("linux"):
        print("mandatory T5 publication diagnostic requires Linux", file=sys.stderr)
        return 2
    suite = unittest.defaultTestLoader.loadTestsFromNames(TEST_NAMES)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.skipped:
        for test, reason in result.skipped:
            print(f"unexpected mandatory diagnostic skip: {test}: {reason}", file=sys.stderr)
        return 2
    if result.unexpectedSuccesses:
        print("unexpected successes are forbidden in the mandatory diagnostic", file=sys.stderr)
        return 2
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
