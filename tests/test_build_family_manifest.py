from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "build_family_manifest.py"
SPEC = importlib.util.spec_from_file_location("build_family_manifest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


FORMULA_A = """\
(set-logic QF_UF)
(declare-sort U 0)
(declare-fun f (U) U)
(declare-const x U)
(assert (= (f x) x))
(check-sat)
"""

FORMULA_B = """\
; alpha-renamed near duplicate
( set-logic QF_UF )
(declare-sort |Sort with ; punctuation| 0)
(declare-fun |function (renamed)| (|Sort with ; punctuation|)
  |Sort with ; punctuation|)
(declare-const |argument renamed| |Sort with ; punctuation|)
(assert (= (|function (renamed)| |argument renamed|) |argument renamed|))
(check-sat) ; trailing comment
"""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_source(root: Path, relative_path: str, source: str) -> Path:
    path = root / "corpus" / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def manifest_row(identifier: int, path: Path, relative_path: str) -> dict:
    source = path.read_bytes()
    return {
        "id": identifier,
        "path": str(path),
        "relative_path": relative_path,
        "logic": "QF_UF",
        "status": "sat",
        "bytes": len(source),
        "sha256": digest(source),
    }


def write_manifest(root: Path, cases: list[tuple[str, str]]) -> Path:
    rows = []
    for identifier, (relative_path, source) in enumerate(cases):
        path = write_source(root, relative_path, source)
        rows.append(manifest_row(identifier, path, relative_path))
    manifest = root / "manifest.jsonl"
    manifest.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    return manifest


def run_builder(
    root: Path,
    manifest: Path,
    taxonomy: Path,
    split: Path,
    *extra: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            str(manifest),
            "--repository-root",
            str(root),
            "--taxonomy-out",
            str(taxonomy),
            "--split-out",
            str(split),
            *extra,
        ],
        check=False,
        capture_output=True,
        text=True,
    )


class TokenFingerprintTests(unittest.TestCase):
    def test_comments_whitespace_and_symbol_spelling_are_irrelevant(self) -> None:
        self.assertNotEqual(digest(FORMULA_A.encode()), digest(FORMULA_B.encode()))
        self.assertEqual(
            BUILDER.normalized_smtlib_fingerprint(FORMULA_A),
            BUILDER.normalized_smtlib_fingerprint(FORMULA_B),
        )

    def test_strings_and_quoted_symbols_are_lexed_without_comment_damage(self) -> None:
        source = '''
        ; real comment
        (set-info :source "text; (not a comment) and ""quoted""")
        (declare-fun |name; with (punctuation)| () Bool)
        (assert |name; with (punctuation)|)
        '''
        tokens = BUILDER.tokenize_smtlib(source)

        strings = [token.value for token in tokens if token.kind == "STRING"]
        quoted = [
            token.value
            for token in tokens
            if token.kind == "SYMBOL" and token.quoted
        ]
        self.assertEqual(strings, ['text; (not a comment) and "quoted"'])
        self.assertEqual(
            quoted,
            ["name; with (punctuation)", "name; with (punctuation)"],
        )

        changed_string = source.replace("not a comment", "different literal")
        self.assertNotEqual(
            BUILDER.normalized_smtlib_fingerprint(source),
            BUILDER.normalized_smtlib_fingerprint(changed_string),
        )

    def test_bound_names_and_simple_quoted_aliases_are_canonical(self) -> None:
        first = """
        (declare-sort S 0)
        (declare-fun value () S)
        (assert (let ((x value)) (= x value)))
        """
        second = """
        (declare-sort |T| 0)
        (declare-fun |renamed| () |T|)
        (assert (let ((|local renamed| |renamed|))
                  (= |local renamed| renamed)))
        """
        self.assertEqual(
            BUILDER.normalized_smtlib_fingerprint(first),
            BUILDER.normalized_smtlib_fingerprint(second),
        )

    def test_quoted_reserved_symbol_does_not_alias_builtin(self) -> None:
        quoted_true = """
        (declare-fun |true| () Bool)
        (assert (not |true|))
        """
        renamed = """
        (declare-fun flag () Bool)
        (assert (not flag))
        """
        builtin = """
        (declare-fun flag () Bool)
        (assert (not true))
        """
        self.assertEqual(
            BUILDER.normalized_smtlib_fingerprint(quoted_true),
            BUILDER.normalized_smtlib_fingerprint(renamed),
        )
        self.assertNotEqual(
            BUILDER.normalized_smtlib_fingerprint(quoted_true),
            BUILDER.normalized_smtlib_fingerprint(builtin),
        )

    def test_syntax_and_arity_remain_significant(self) -> None:
        unary = "(declare-fun f (Bool) Bool) (assert (f true))"
        binary = "(declare-fun g (Bool Bool) Bool) (assert (g true true))"
        reordered = "(declare-fun f (Bool) Bool) (assert (not (f true)))"
        fingerprint = BUILDER.normalized_smtlib_fingerprint(unary)
        self.assertNotEqual(fingerprint, BUILDER.normalized_smtlib_fingerprint(binary))
        self.assertNotEqual(
            fingerprint, BUILDER.normalized_smtlib_fingerprint(reordered)
        )

    def test_unbalanced_or_unterminated_sources_are_rejected(self) -> None:
        for source in ('(assert true', '(echo "unterminated)', "(assert true))"):
            with self.subTest(source=source):
                with self.assertRaises(BUILDER.SMTLIBError):
                    BUILDER.normalized_smtlib_fingerprint(source)


class PathTaxonomyTests(unittest.TestCase):
    def test_known_path_rules_derive_stable_families_and_lineages(self) -> None:
        cases = {
            "QF_UF/QG-classification/qg7/gensys_brn003.smt2": (
                "QF_UF/QG-classification",
                "QF_UF/QG-classification/gensys_brn003",
                "qg-size-variant",
            ),
            "QF_UF/NEQ/NEQ004_size9.smt2": (
                "QF_UF/NEQ",
                "QF_UF/NEQ/NEQ004",
                "finite-size-series",
            ),
            "QF_UF/2018-Goel-hwbench/QF_UF_brp2.6.prop3_ab_reg_max.smt2": (
                "QF_UF/2018-Goel-hwbench",
                "QF_UF/2018-Goel-hwbench/brp2",
                "goel-model-series",
            ),
            "QF_UF/20190906-CLEARSY/0016/00415.smt2": (
                "QF_UF/20190906-CLEARSY",
                "QF_UF/20190906-CLEARSY/0016",
                "clearsy-model-directory",
            ),
            "QF_UF/eq_diamond/eq_diamond99.smt2": (
                "QF_UF/eq_diamond",
                "QF_UF/eq_diamond",
                "eq-diamond-size-series",
            ),
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(tuple(BUILDER.derive_path_taxonomy(path)), expected)

    def test_known_family_with_malformed_layout_is_rejected(self) -> None:
        for path in (
            "QF_UF/NEQ/not-a-size.smt2",
            "QF_UF/QG-classification/random/gensys_brn003.smt2",
            "QF_UF/2018-Goel-hwbench/unknown.smt2",
            "../QF_UF/NEQ/NEQ004_size4.smt2",
        ):
            with self.subTest(path=path):
                with self.assertRaises(BUILDER.ManifestError):
                    BUILDER.derive_path_taxonomy(path)


class ManifestValidationTests(unittest.TestCase):
    def test_malformed_missing_duplicate_and_non_file_records_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="family manifest invalid ") as temp:
            root = Path(temp)
            relative = "QF_UF/NEQ/NEQ004_size4.smt2"
            source = write_source(root, relative, FORMULA_A)
            valid = manifest_row(0, source, relative)

            directory_relative = "QF_UF/PEQ/PEQ002_size5.smt2"
            directory = root / "corpus" / directory_relative
            directory.mkdir(parents=True)
            invalid_cases = {
                "malformed": '{"id": 0,',
                "duplicate-key": json.dumps(valid).replace(
                    '"id": 0', '"id": 0, "id": 1', 1
                ),
                "missing-field": json.dumps(
                    {key: value for key, value in valid.items() if key != "path"}
                ),
                "non-file": json.dumps(
                    {
                        "id": 0,
                        "path": str(directory),
                        "relative_path": directory_relative,
                    }
                ),
                "duplicate-record": "\n".join(
                    (json.dumps(valid), json.dumps(valid))
                ),
            }
            for name, contents in invalid_cases.items():
                with self.subTest(name=name):
                    manifest = root / f"{name}.jsonl"
                    manifest.write_text(contents + "\n", encoding="utf-8")
                    with self.assertRaises(BUILDER.ManifestError):
                        BUILDER.load_manifest(manifest, root)

    def test_missing_source_and_stale_integrity_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="family manifest stale ") as temp:
            root = Path(temp)
            relative = "QF_UF/SEQ/SEQ004_size5.smt2"
            source = write_source(root, relative, FORMULA_A)
            row = manifest_row(0, source, relative)

            cases = []
            missing = dict(row)
            missing["path"] = str(root / "corpus" / "QF_UF/SEQ/SEQ999_size5.smt2")
            missing["relative_path"] = "QF_UF/SEQ/SEQ999_size5.smt2"
            cases.append(missing)
            bad_hash = dict(row)
            bad_hash["sha256"] = "0" * 64
            cases.append(bad_hash)
            bad_size = dict(row)
            bad_size["bytes"] = row["bytes"] + 1
            cases.append(bad_size)

            for index, invalid in enumerate(cases):
                with self.subTest(index=index):
                    manifest = root / f"stale-{index}.jsonl"
                    manifest.write_text(json.dumps(invalid) + "\n", encoding="utf-8")
                    with self.assertRaises(BUILDER.ManifestError):
                        BUILDER.load_manifest(manifest, root)


class SplitBuilderTests(unittest.TestCase):
    def test_cli_outputs_are_byte_deterministic_and_hash_verifiable(self) -> None:
        cases = [
            ("QF_UF/NEQ/NEQ004_size4.smt2", FORMULA_A),
            ("QF_UF/NEQ/NEQ004_size5.smt2", FORMULA_B),
            (
                "QF_UF/PEQ/PEQ002_size5.smt2",
                "(set-logic QF_UF) (declare-fun p () Bool) (assert p)",
            ),
            (
                "QF_UF/SEQ/SEQ004_size5.smt2",
                "(set-logic QF_UF) (assert true) (check-sat)",
            ),
        ]
        with tempfile.TemporaryDirectory(prefix="family manifest deterministic ") as temp:
            root = Path(temp)
            manifest = write_manifest(root, cases)
            sealed = root / "sealed.json"
            sealed.write_text(
                json.dumps({"holdout_families": ["QF_UF/SEQ"]}) + "\n",
                encoding="utf-8",
            )
            outputs = []
            for label in ("first", "second"):
                taxonomy = root / label / "taxonomy.jsonl"
                split = root / label / "split.json"
                completed = run_builder(
                    root,
                    manifest,
                    taxonomy,
                    split,
                    "--sealed-holdout-families",
                    str(sealed),
                    "--seed",
                    "declared-test-seed",
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                outputs.append((taxonomy.read_bytes(), split.read_bytes()))

            self.assertEqual(outputs[0], outputs[1])
            taxonomy_bytes, split_bytes = outputs[0]
            rows = [
                json.loads(line)
                for line in taxonomy_bytes.decode("utf-8").splitlines()
            ]
            summary = json.loads(split_bytes)
            self.assertEqual(summary["selection"]["mode"], "sealed")
            self.assertEqual(
                summary["assignments"]["families"]["holdout"], ["QF_UF/SEQ"]
            )
            self.assertEqual(summary["counts"]["records"], 4)
            self.assertEqual(summary["counts"]["holdout_records"], 1)
            self.assertEqual(
                summary["hashes"]["input_manifest_sha256"],
                digest(manifest.read_bytes()),
            )
            self.assertEqual(
                summary["hashes"]["taxonomy_jsonl_sha256"], digest(taxonomy_bytes)
            )
            self.assertEqual(
                summary["hashes"]["sealed_holdout_family_list_sha256"],
                digest(sealed.read_bytes()),
            )
            split_core = dict(summary)
            hashes = split_core.pop("hashes")
            self.assertEqual(
                hashes["split_payload_sha256"],
                digest(BUILDER.canonical_json_bytes(split_core)),
            )

            neq_rows = [row for row in rows if row["source_family"] == "QF_UF/NEQ"]
            self.assertEqual(len({row["raw_sha256"] for row in neq_rows}), 2)
            self.assertEqual(
                len({row["normalized_token_sha256"] for row in neq_rows}), 1
            )
            self.assertEqual(
                {row["near_duplicate_group_size"] for row in neq_rows}, {2}
            )
            self.assertEqual({row["split"] for row in neq_rows}, {"dev"})
            BUILDER.validate_no_leakage(rows)

    def test_fallback_depends_on_sorted_families_and_seed_not_instances(self) -> None:
        families = ["QF_UF/SEQ", "QF_UF/NEQ", "QF_UF/PEQ", "QF_UF/custom"]
        first = BUILDER.deterministic_holdout_families(
            families,
            seed="family-only-seed",
            holdout_count=2,
        )
        second = BUILDER.deterministic_holdout_families(
            reversed(families),
            seed="family-only-seed",
            holdout_count=2,
        )
        self.assertEqual(first, second)

        with tempfile.TemporaryDirectory(prefix="family fallback one ") as one_temp:
            with tempfile.TemporaryDirectory(prefix="family fallback two ") as two_temp:
                summaries = []
                for root, marker in ((Path(one_temp), "one"), (Path(two_temp), "two")):
                    manifest = write_manifest(
                        root,
                        [
                            (
                                "QF_UF/NEQ/NEQ004_size4.smt2",
                                f'(set-info :source "{marker}-n") (assert true)',
                            ),
                            (
                                "QF_UF/PEQ/PEQ002_size5.smt2",
                                f'(set-info :source "{marker}-p") (assert false)',
                            ),
                            (
                                "QF_UF/SEQ/SEQ004_size5.smt2",
                                f'(set-info :source "{marker}-s") (assert (= true true))',
                            ),
                        ],
                    )
                    _, summary, _ = BUILDER.build_taxonomy_and_split(
                        manifest,
                        repository_root=root,
                        seed="family-only-seed",
                        holdout_count=1,
                    )
                    summaries.append(summary)
                self.assertEqual(
                    summaries[0]["assignments"]["families"],
                    summaries[1]["assignments"]["families"],
                )

    def test_explicit_split_rejects_normalized_duplicate_leakage(self) -> None:
        with tempfile.TemporaryDirectory(prefix="family manifest leakage ") as temp:
            root = Path(temp)
            manifest = write_manifest(
                root,
                [
                    ("QF_UF/NEQ/NEQ004_size4.smt2", FORMULA_A),
                    ("QF_UF/PEQ/PEQ002_size5.smt2", FORMULA_B),
                    (
                        "QF_UF/SEQ/SEQ004_size5.smt2",
                        "(set-logic QF_UF) (assert false)",
                    ),
                ],
            )
            taxonomy = root / "taxonomy.jsonl"
            split = root / "split.json"
            completed = run_builder(
                root,
                manifest,
                taxonomy,
                split,
                "--holdout-family",
                "QF_UF/NEQ",
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("leakage", completed.stderr)
            self.assertFalse(taxonomy.exists())
            self.assertFalse(split.exists())

    def test_duplicate_sealed_family_and_unknown_family_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="family manifest sealed ") as temp:
            root = Path(temp)
            manifest = write_manifest(
                root,
                [
                    ("QF_UF/NEQ/NEQ004_size4.smt2", FORMULA_A),
                    ("QF_UF/PEQ/PEQ002_size5.smt2", "(assert true)"),
                ],
            )
            for label, families in (
                ("duplicate", ["QF_UF/NEQ", "QF_UF/NEQ"]),
                ("unknown", ["QF_UF/MISSING"]),
            ):
                with self.subTest(label=label):
                    taxonomy = root / label / "taxonomy.jsonl"
                    split = root / label / "split.json"
                    completed = run_builder(
                        root,
                        manifest,
                        taxonomy,
                        split,
                        *sum(
                            (
                                ("--holdout-family", family)
                                for family in families
                            ),
                            (),
                        ),
                    )
                    self.assertEqual(completed.returncode, 2)
                    self.assertFalse(taxonomy.exists())
                    self.assertFalse(split.exists())


if __name__ == "__main__":
    unittest.main()
