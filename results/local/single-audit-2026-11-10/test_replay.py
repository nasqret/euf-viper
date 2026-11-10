"""Negative controls for the public witness-count replay."""
import copy
import unittest
from verify import HERE, STATUS, load, read, reduce_case, verify


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.packet = read(load(HERE/"raw/724/audit.json"))
        self.row = read(load(HERE/"runs.json"))["cases"]["724"]
        self.catalog = read(load(HERE/"members-724.json"))

    def test_raw_replay(self):
        self.assertEqual(verify(), read(load(STATUS))["cases"])

    def test_rejects_wrong_process_and_outcome(self):
        for key, value in (("pid", self.packet["pid"] + 1), ("terminal_outcome", "unsat"), ("complete", False)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                reduce_case("724", dict(self.packet, **{key: value}), self.row, self.catalog)

    def test_rejects_unmatched_duplicate_even_if_total_is_plausible(self):
        packet = copy.deepcopy(self.packet)
        packet["post"]["duplicated_physical"] -= 1
        with self.assertRaisesRegex(ValueError, "physical ID join"):
            reduce_case("724", packet, self.row, self.catalog)

    def test_rejects_boolean_counter_and_shifted_member_order(self):
        packet = copy.deepcopy(self.packet)
        packet["fixed"]["id_join_errors"] = False
        with self.assertRaisesRegex(ValueError, "counter schema"):
            reduce_case("724", packet, self.row, self.catalog)
        packet = copy.deepcopy(self.packet)
        packet["member_terms"].reverse()
        with self.assertRaisesRegex(ValueError, "catalogue"):
            reduce_case("724", packet, self.row, self.catalog)


if __name__ == "__main__":
    unittest.main()
