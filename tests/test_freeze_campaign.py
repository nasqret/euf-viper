from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "freeze_campaign.py"
CAMPAIGN = ROOT / "campaigns" / "best-overall-qf-uf-2026-07.json"
MODULE_SPEC = importlib.util.spec_from_file_location("freeze_campaign", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
FREEZER = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(FREEZER)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FreezeCampaignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.corpus = self.root / "corpus"
        self.corpus.mkdir()
        self.instance = self.corpus / "family" / "case.smt2"
        self.instance.parent.mkdir()
        self.instance.write_text(
            "(set-logic QF_UF)\n(declare-const x U)\n(assert (= x x))\n(check-sat)\n",
            encoding="utf-8",
        )
        self.manifest = self.root / "manifest.jsonl"
        self.manifest.write_text(
            json.dumps(
                {
                    "id": 7,
                    "relative_path": "family/case.smt2",
                    "path": str(self.instance),
                    "sha256": digest(self.instance),
                    "bytes": self.instance.stat().st_size,
                    "status": "sat",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.taxonomy = self.root / "taxonomy.jsonl"
        self.taxonomy.write_text(
            json.dumps(
                {
                    "relative_path": "family/case.smt2",
                    "family": "family",
                    "lineage": "family/example",
                    "normalized_sha256": "1" * 64,
                    "split": "holdout",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.binary = self.root / "solver"
        self.binary.write_text(
            "#!/bin/sh\nif [ \"${1:-}\" = --version ]; then echo fake-1; else echo sat; fi\n",
            encoding="utf-8",
        )
        self.binary.chmod(0o755)
        self.solver_config = self.root / "solvers.json"
        self._write_solver_config()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_solver_config(self, omit: str | None = None) -> None:
        binary_hash = digest(self.binary)
        records = [
            ("euf-viper", "euf-viper", "default", "test-build", ["{binary}", "{instance}"]),
            ("z3-default", "z3", "default", "4.16.0", ["{binary}", "{instance}"]),
            ("z3-sat-euf", "z3", "sat.euf=true", "4.16.0", ["{binary}", "{instance}"]),
            ("cvc5", "cvc5", "default", "1.3.4", ["{binary}", "{instance}"]),
            ("yices2", "yices2", "default", "2.7.0", ["{binary}", "{instance}"]),
            ("opensmt", "opensmt", "default", "2.9.2", ["{binary}", "{instance}"]),
        ]
        solvers = []
        for identifier, comparator, configuration, version, template in records:
            if identifier == omit:
                continue
            solvers.append(
                {
                    "id": identifier,
                    "comparator_id": comparator,
                    "configuration": configuration,
                    "version": version,
                    "binary": str(self.binary),
                    "sha256": binary_hash,
                    "argv_template": template,
                    "version_argv": ["--version"],
                    "version_output_contains": "fake-1",
                }
            )
        self.solver_config.write_text(
            json.dumps({"schema_version": 1, "solvers": solvers}, sort_keys=True),
            encoding="utf-8",
        )

    def _freeze(self, taxonomy: Path | None = None) -> dict:
        return FREEZER.make_lock(
            spec_path=CAMPAIGN,
            manifest_path=self.manifest,
            solver_config_path=self.solver_config,
            repository=ROOT,
            corpus_root=self.corpus,
            taxonomy_path=taxonomy,
            budgets_s=[2],
            cpu_ids=[0],
            memory_bytes=1024 * 1024 * 1024,
            order="balanced_latin_square",
            output_directory=self.root / "results",
            timeout_grace_s=0.1,
            allow_dirty=True,
        )

    def test_lock_is_deterministic_and_self_hashing(self) -> None:
        first = self._freeze(self.taxonomy)
        second = self._freeze(self.taxonomy)

        self.assertEqual(first, second)
        self.assertEqual(len(first["solvers"]), 6)
        self.assertEqual(first["corpus"]["instances"][0]["family"], "family")
        unsigned = {**first, "lock_sha256": ""}
        self.assertEqual(
            first["lock_sha256"],
            FREEZER.sha256_bytes(FREEZER.canonical_bytes(unsigned)),
        )

    def test_lock_without_taxonomy_is_not_promotion_eligible(self) -> None:
        lock = self._freeze()
        self.assertFalse(lock["promotion_eligible"])

    def test_instance_hash_drift_is_rejected(self) -> None:
        self.instance.write_text("(check-sat)\n", encoding="utf-8")
        with self.assertRaisesRegex(FREEZER.FreezeError, "hash drift"):
            self._freeze(self.taxonomy)

    def test_solver_hash_drift_is_rejected(self) -> None:
        self.binary.write_text("#!/bin/sh\necho unsat\n", encoding="utf-8")
        self.binary.chmod(0o755)
        with self.assertRaisesRegex(FREEZER.FreezeError, "binary hash drift"):
            self._freeze(self.taxonomy)

    def test_missing_required_configuration_is_rejected(self) -> None:
        self._write_solver_config(omit="z3-sat-euf")
        with self.assertRaisesRegex(FREEZER.FreezeError, "missing"):
            self._freeze(self.taxonomy)

    def test_duplicate_manifest_path_is_rejected(self) -> None:
        original = self.manifest.read_text(encoding="utf-8")
        self.manifest.write_text(original + original, encoding="utf-8")
        with self.assertRaisesRegex(FREEZER.FreezeError, "duplicate manifest"):
            self._freeze(self.taxonomy)

    def test_abba_rejects_more_than_two_solvers(self) -> None:
        with self.assertRaisesRegex(FREEZER.FreezeError, "exactly two"):
            FREEZER.make_lock(
                spec_path=CAMPAIGN,
                manifest_path=self.manifest,
                solver_config_path=self.solver_config,
                repository=ROOT,
                corpus_root=self.corpus,
                taxonomy_path=self.taxonomy,
                budgets_s=[2],
                cpu_ids=[0],
                memory_bytes=1024 * 1024 * 1024,
                order="abba",
                output_directory=self.root / "results-abba",
                timeout_grace_s=0.1,
                allow_dirty=True,
            )

    def test_undeclared_or_unsorted_budget_subset_is_rejected(self) -> None:
        for budgets in ([3], [60, 2], []):
            with self.subTest(budgets=budgets):
                with self.assertRaisesRegex(FREEZER.FreezeError, "sorted non-empty subset"):
                    FREEZER.make_lock(
                        spec_path=CAMPAIGN,
                        manifest_path=self.manifest,
                        solver_config_path=self.solver_config,
                        repository=ROOT,
                        corpus_root=self.corpus,
                        taxonomy_path=self.taxonomy,
                        budgets_s=budgets,
                        cpu_ids=[0],
                        memory_bytes=1024 * 1024 * 1024,
                        order="balanced_latin_square",
                        output_directory=self.root / "results-budget",
                        timeout_grace_s=0.1,
                        allow_dirty=True,
                    )


if __name__ == "__main__":
    unittest.main()
