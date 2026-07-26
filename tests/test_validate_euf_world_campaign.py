from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "validate_euf_world_campaign.py"
CONTRACT = ROOT / "campaigns" / "euf-world-leader-2026-07.json"
SPEC = importlib.util.spec_from_file_location("validate_euf_world_campaign", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class WorldLeaderCampaignContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_checked_in_contract_is_valid(self) -> None:
        validated = VALIDATOR.validate_contract(self.contract)
        self.assertEqual(validated["scope"]["primary_logic"], "QF_UF")
        self.assertEqual(len(validated["technical_lanes"]), 11)

    def test_missing_yices_is_rejected(self) -> None:
        broken = copy.deepcopy(self.contract)
        broken["comparators"]["mandatory"] = [
            row for row in broken["comparators"]["mandatory"] if row["id"] != "yices2"
        ]
        with self.assertRaisesRegex(VALIDATOR.ContractError, "comparator set"):
            VALIDATOR.validate_contract(broken)

    def test_unsorted_budgets_are_rejected(self) -> None:
        broken = copy.deepcopy(self.contract)
        broken["benchmark_space"]["budgets_s"] = [2, 0.2, 60, 1200]
        with self.assertRaisesRegex(VALIDATOR.ContractError, "unique and increasing"):
            VALIDATOR.validate_contract(broken)

    def test_lane_rank_drift_is_rejected(self) -> None:
        broken = copy.deepcopy(self.contract)
        broken["technical_lanes"][4]["rank"] = 7
        with self.assertRaisesRegex(VALIDATOR.ContractError, "ranks"):
            VALIDATOR.validate_contract(broken)

    def test_identity_routing_prohibition_is_mandatory(self) -> None:
        broken = copy.deepcopy(self.contract)
        broken["forbidden"] = [
            "duplicate_nonrouting_prohibition"
            if "routing" in item and "family" in item
            else item
            for item in broken["forbidden"]
        ]
        with self.assertRaisesRegex(VALIDATOR.ContractError, "routing prohibition"):
            VALIDATOR.validate_contract(broken)

    def test_helios_account_is_bound(self) -> None:
        broken = copy.deepcopy(self.contract)
        broken["compute_policy"]["Helios"]["account"] = "wrong-account"
        with self.assertRaisesRegex(VALIDATOR.ContractError, "Helios CPU account"):
            VALIDATOR.validate_contract(broken)


if __name__ == "__main__":
    unittest.main()
