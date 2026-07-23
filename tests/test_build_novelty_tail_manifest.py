from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "build_novelty_tail_manifest.py"
SPEC = importlib.util.spec_from_file_location("build_novelty_tail_manifest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def formula(status: str = "sat", *, body: str = "(assert true)") -> bytes:
    return (
        "; fake status in a comment: (set-info :status unknown)\n"
        "(set-info :source |text (set-info :status unknown); still text|)\n"
        "(set-info :category \"crafted; not a comment\")\n"
        "(set-logic QF_UF)\n"
        f"(set-info :status {status})\n"
        f"{body}\n"
        "(check-sat)\n"
    ).encode("utf-8")


def write_source(corpus: Path, relative_path: str, source: bytes) -> Path:
    path = corpus.joinpath(*relative_path.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(source)
    return path


def manifest_row(
    identifier: int | str,
    source_path: Path,
    relative_path: str,
    status: str,
    *,
    declared_path: str | None = None,
) -> dict[str, object]:
    source = source_path.read_bytes()
    return {
        "archive_md5": "0" * 32,
        "bytes": len(source),
        "id": identifier,
        "logic": "QF_UF",
        "path": str(source_path) if declared_path is None else declared_path,
        "relative_path": relative_path,
        "sha256": digest(source),
        "status": status,
    }


def write_manifest(path: Path, rows: list[dict[str, object]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        b"".join(BUILDER.canonical_json_bytes(row) for row in rows)
    )
    return path


class Fixture:
    PATH_A = "QF_UF/family/a.smt2"
    PATH_B = "QF_UF/family/b.smt2"
    PATH_C = "QF_UF/other/c.smt2"

    def __init__(self, root: Path) -> None:
        self.root = root
        self.corpus = root / "corpus"
        source_a = write_source(self.corpus, self.PATH_A, formula("sat"))
        source_b = write_source(
            self.corpus, self.PATH_B, formula("unsat", body="(assert false)")
        )
        source_c = write_source(
            self.corpus,
            self.PATH_C,
            formula("sat", body="(assert (= true true))"),
        )
        self.rows = [
            manifest_row(10, source_a, self.PATH_A, "sat"),
            manifest_row(11, source_b, self.PATH_B, "unsat"),
            manifest_row("twelve", source_c, self.PATH_C, "sat"),
        ]
        self.manifest = write_manifest(root / "full.jsonl", self.rows)


class NamedSelectionTests(unittest.TestCase):
    def test_current_deficit_is_exactly_bound_and_ordered(self) -> None:
        selection = BUILDER.SHARED_Z3_YICES_DEFICIT_22
        paths = [item.relative_path for item in selection]

        self.assertEqual(len(selection), 22)
        self.assertEqual(len(set(paths)), 22)
        self.assertEqual(
            Counter(item.status for item in selection),
            Counter({"sat": 6, "unsat": 16}),
        )
        self.assertEqual(
            Counter(path.split("/")[1] for path in paths),
            Counter(
                {
                    "2018-Goel-hwbench": 9,
                    "PEQ": 1,
                    "QG-classification": 12,
                }
            ),
        )
        self.assertTrue(paths[0].endswith("firewire_tree.5.prop1_ab_reg_max.smt2"))
        self.assertTrue(paths[-1].endswith("iso_icl_nogen_sk007.smt2"))
        for item in selection:
            self.assertGreater(item.bytes, 0)
            self.assertRegex(item.sha256, r"^[0-9a-f]{64}$")
            self.assertEqual(
                BUILDER.validate_relative_path(item.relative_path), item.relative_path
            )

    def test_aliases_resolve_to_the_canonical_checked_name(self) -> None:
        for alias in BUILDER.NAMED_SELECTION_ALIASES:
            self.assertEqual(
                BUILDER.canonical_selection_name(alias),
                BUILDER.CANONICAL_DEFICIT_SELECTION,
            )
        with self.assertRaisesRegex(BUILDER.SelectionError, "unknown named selection"):
            BUILDER.canonical_selection_name("not-a-selection")


class PathValidationTests(unittest.TestCase):
    def test_only_canonical_qf_uf_smt2_relative_paths_are_accepted(self) -> None:
        valid = "QF_UF/family/case.smt2"
        self.assertEqual(BUILDER.validate_relative_path(valid), valid)
        invalid = (
            "",
            "/QF_UF/family/case.smt2",
            "QF_UF/family/../case.smt2",
            "QF_UF/./family/case.smt2",
            "QF_UF//family/case.smt2",
            "QF_UF\\family\\case.smt2",
            "QF_UF/case.smt2",
            "QF_LIA/family/case.smt2",
            "QF_UF/family/case.SMT2",
            "QF_UF/family/case.txt",
            "QF_UF/family/case.smt2/",
            "QF_UF/family/case.smt2\x00suffix",
        )
        for path in invalid:
            with self.subTest(path=path):
                with self.assertRaises(BUILDER.SelectionError):
                    BUILDER.validate_relative_path(path)

    def test_explicit_duplicates_and_empty_requests_are_rejected(self) -> None:
        path = "QF_UF/family/case.smt2"
        with self.assertRaisesRegex(BUILDER.SelectionError, "at least one"):
            BUILDER.validate_requested_paths([])
        with self.assertRaisesRegex(BUILDER.SelectionError, "duplicates"):
            BUILDER.validate_requested_paths([path, path])

    def test_paths_file_preserves_order_and_rejects_blank_lines(self) -> None:
        with tempfile.TemporaryDirectory(prefix="novelty path list ") as temp:
            root = Path(temp)
            path_list = root / "paths.txt"
            path_list.write_text(
                f"{Fixture.PATH_C}\n{Fixture.PATH_A}\n", encoding="utf-8"
            )
            self.assertEqual(
                BUILDER.read_requested_paths(path_list),
                [Fixture.PATH_C, Fixture.PATH_A],
            )
            path_list.write_text(
                f"{Fixture.PATH_C}\n\n{Fixture.PATH_A}\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(BUILDER.SelectionError, "blank line"):
                BUILDER.read_requested_paths(path_list)


class ManifestValidationTests(unittest.TestCase):
    def test_valid_manifest_retains_input_order_and_raw_hash(self) -> None:
        with tempfile.TemporaryDirectory(prefix="novelty valid manifest ") as temp:
            fixture = Fixture(Path(temp))
            records, raw = BUILDER.load_hashed_manifest(fixture.manifest)
            self.assertEqual(
                [record.row["relative_path"] for record in records],
                [Fixture.PATH_A, Fixture.PATH_B, Fixture.PATH_C],
            )
            self.assertEqual(raw, fixture.manifest.read_bytes())

    def test_jsonl_structure_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="novelty malformed jsonl ") as temp:
            fixture = Fixture(Path(temp))
            valid = fixture.rows[0]
            cases = {
                "empty": b"",
                "blank": BUILDER.canonical_json_bytes(valid) + b"\n",
                "malformed": b'{"id":1,\n',
                "non-object": b"[]\n",
                "duplicate-key": (
                    json.dumps(valid, sort_keys=True).replace(
                        '"id": 10', '"id": 10, "id": 20', 1
                    )
                    + "\n"
                ).encode(),
                "non-finite": (
                    json.dumps({**valid, "bytes": float("nan")}, sort_keys=True)
                    + "\n"
                ).encode(),
                "invalid-utf8": b"\xff\n",
            }
            for name, data in cases.items():
                with self.subTest(name=name):
                    path = fixture.root / f"{name}.jsonl"
                    path.write_bytes(data)
                    with self.assertRaises(BUILDER.SelectionError):
                        BUILDER.load_hashed_manifest(path)

    def test_required_field_types_and_values_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="novelty bad fields ") as temp:
            fixture = Fixture(Path(temp))
            valid = fixture.rows[0]
            variants: list[tuple[str, dict[str, object]]] = []

            missing = dict(valid)
            missing.pop("sha256")
            variants.append(("missing", missing))
            for label, field, value in (
                ("bool-id", "id", True),
                ("empty-id", "id", ""),
                ("logic", "logic", "QF_LIA"),
                ("status", "status", "unknown"),
                ("non-string-status", "status", ["sat"]),
                ("bool-bytes", "bytes", True),
                ("negative-bytes", "bytes", -1),
                ("short-hash", "sha256", "0" * 63),
                ("uppercase-hash", "sha256", "A" * 64),
                ("bad-relative", "relative_path", "../case.smt2"),
                ("bad-path", "path", "/tmp/not-the-relative-path.smt2"),
            ):
                row = dict(valid)
                row[field] = value
                variants.append((label, row))

            for label, row in variants:
                with self.subTest(label=label):
                    path = write_manifest(fixture.root / f"{label}.jsonl", [row])
                    with self.assertRaises(BUILDER.SelectionError):
                        BUILDER.load_hashed_manifest(path)

    def test_duplicate_ids_and_relative_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="novelty duplicate manifest ") as temp:
            fixture = Fixture(Path(temp))
            duplicate_id = dict(fixture.rows[1])
            duplicate_id["id"] = fixture.rows[0]["id"]
            duplicate_path = dict(fixture.rows[1])
            duplicate_path["relative_path"] = fixture.rows[0]["relative_path"]
            duplicate_path["path"] = fixture.rows[0]["path"]
            for label, row in (
                ("id", duplicate_id),
                ("relative", duplicate_path),
            ):
                with self.subTest(label=label):
                    manifest = write_manifest(
                        fixture.root / f"duplicate-{label}.jsonl",
                        [fixture.rows[0], row],
                    )
                    with self.assertRaisesRegex(BUILDER.SelectionError, "duplicates"):
                        BUILDER.load_hashed_manifest(manifest)


class SourceStatusTests(unittest.TestCase):
    def test_complete_scanner_ignores_comments_strings_and_quoted_source(self) -> None:
        source = formula(
            "unsat",
            body='(assert (= |symbol; (set-info :status sat)| "text; )"))',
        )
        self.assertEqual(BUILDER.extract_qf_uf_status(source), "unsat")

    def test_missing_duplicate_invalid_or_mismatched_metadata_is_rejected(self) -> None:
        cases = (
            b"(set-logic QF_UF) (assert true)",
            b"(set-logic QF_UF) (set-info :status sat) (set-info :status sat)",
            b"(set-logic QF_UF) (set-info :status unknown)",
            b"(set-logic QF_LIA) (set-info :status sat)",
            b"(set-logic QF_UF QF_UF) (set-info :status sat)",
            b"(set-logic QF_UF) (set-info :status (sat))",
        )
        for source in cases:
            with self.subTest(source=source):
                with self.assertRaises(BUILDER.SelectionError):
                    BUILDER.extract_qf_uf_status(source)

    def test_lexical_and_parenthesis_damage_is_rejected(self) -> None:
        cases = (
            b"(set-logic QF_UF) (set-info :status sat",
            b"(set-logic QF_UF)) (set-info :status sat)",
            b'(set-logic QF_UF) (set-info :status sat) (echo "unterminated)',
            b"(set-logic QF_UF) (set-info :status sat) (echo |unterminated)",
            b"outside (set-logic QF_UF) (set-info :status sat)",
            b"\xff",
        )
        for source in cases:
            with self.subTest(source=source):
                with self.assertRaises(BUILDER.SelectionError):
                    BUILDER.extract_qf_uf_status(source)


class ArtifactBuilderTests(unittest.TestCase):
    def test_portable_output_preserves_explicit_order_and_is_hash_bound(self) -> None:
        with tempfile.TemporaryDirectory(prefix="novelty portable ") as temp:
            fixture = Fixture(Path(temp))
            requested = [Fixture.PATH_C, Fixture.PATH_A]
            output, report_bytes, report = BUILDER.build_selection_artifacts(
                fixture.manifest,
                requested_paths=requested,
                source_root=fixture.corpus,
            )
            rows = [json.loads(line) for line in output.decode().splitlines()]

            self.assertEqual([row["relative_path"] for row in rows], requested)
            self.assertEqual([row["path"] for row in rows], requested)
            self.assertEqual([row["id"] for row in rows], ["twelve", 10])
            self.assertEqual(report["selection"]["mode"], "explicit")
            self.assertIsNone(report["selection"]["name"])
            self.assertEqual(report["selection"]["relative_paths"], requested)
            self.assertEqual(report["counts"]["input_records"], 3)
            self.assertEqual(report["counts"]["selected_records"], 2)
            self.assertEqual(report["counts"]["sat"], 2)
            self.assertEqual(report["counts"]["unsat"], 0)
            self.assertEqual(
                report["hashes"]["input_manifest_sha256"],
                digest(fixture.manifest.read_bytes()),
            )
            self.assertEqual(report["hashes"]["output_manifest_sha256"], digest(output))
            self.assertEqual(
                [item["ordinal"] for item in report["records"]], [0, 1]
            )
            self.assertEqual(report_bytes, BUILDER.canonical_json_bytes(report))

    def test_rebased_output_uses_exact_absolute_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="novelty rebased ") as temp:
            fixture = Fixture(Path(temp))
            output, _, report = BUILDER.build_selection_artifacts(
                fixture.manifest,
                requested_paths=[Fixture.PATH_B],
                source_root=fixture.corpus,
                path_mode="rebased",
                rebase_root=Path("/cluster/read-only/qf-uf"),
            )
            row = json.loads(output)
            expected = "/cluster/read-only/qf-uf/" + Fixture.PATH_B
            self.assertEqual(row["path"], expected)
            self.assertEqual(report["path_rewrite"]["mode"], "rebased")
            self.assertEqual(
                report["path_rewrite"]["rebase_root"],
                "/cluster/read-only/qf-uf",
            )
            self.assertEqual(report["records"][0]["path"], expected)

    def test_output_mode_contract_rejects_ambiguous_or_relative_rebases(self) -> None:
        with tempfile.TemporaryDirectory(prefix="novelty mode ") as temp:
            fixture = Fixture(Path(temp))
            verified = BUILDER.verify_selected_sources(
                BUILDER.select_records(
                    BUILDER.load_hashed_manifest(fixture.manifest)[0],
                    [Fixture.PATH_A],
                ),
                source_root=fixture.corpus,
            )
            cases = (
                {"path_mode": "portable", "rebase_root": Path("/root")},
                {"path_mode": "rebased", "rebase_root": None},
                {"path_mode": "rebased", "rebase_root": Path("relative")},
                {"path_mode": "other", "rebase_root": None},
            )
            for kwargs in cases:
                with self.subTest(kwargs=kwargs):
                    with self.assertRaises(BUILDER.SelectionError):
                        BUILDER.serialize_selected_manifest(verified, **kwargs)

    def test_source_root_ignores_stale_well_formed_host_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="novelty stale host ") as temp:
            fixture = Fixture(Path(temp))
            rows = []
            for row in fixture.rows:
                stale = dict(row)
                stale["path"] = "/old/machine/corpus/" + str(row["relative_path"])
                rows.append(stale)
            manifest = write_manifest(fixture.root / "stale.jsonl", rows)

            output, _, report = BUILDER.build_selection_artifacts(
                manifest,
                requested_paths=[Fixture.PATH_B],
                source_root=fixture.corpus,
            )
            self.assertEqual(json.loads(output)["path"], Fixture.PATH_B)
            self.assertEqual(
                report["verification"]["source_resolution"],
                "source_root_relative_path",
            )

    def test_relative_declared_path_uses_explicit_repository_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="novelty repository root ") as temp:
            fixture = Fixture(Path(temp))
            row = dict(fixture.rows[0])
            row["path"] = "corpus/" + Fixture.PATH_A
            manifest = write_manifest(fixture.root / "relative.jsonl", [row])
            output, _, report = BUILDER.build_selection_artifacts(
                manifest,
                requested_paths=[Fixture.PATH_A],
                repository_root=fixture.root,
            )
            self.assertEqual(json.loads(output)["relative_path"], Fixture.PATH_A)
            self.assertEqual(
                report["verification"]["source_resolution"],
                "manifest_declared_path",
            )

    def test_unknown_request_and_named_identity_drift_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="novelty unknown ") as temp:
            fixture = Fixture(Path(temp))
            records, _ = BUILDER.load_hashed_manifest(fixture.manifest)
            with self.assertRaisesRegex(BUILDER.SelectionError, "absent"):
                BUILDER.select_records(records, ["QF_UF/family/unknown.smt2"])

            row = fixture.rows[0]
            expected = BUILDER.ExpectedSource(
                Fixture.PATH_A,
                "sat",
                int(row["bytes"]),
                "f" * 64,
            )
            with self.assertRaisesRegex(BUILDER.SelectionError, "binding mismatch"):
                BUILDER.select_records(records, [Fixture.PATH_A], expected=[expected])

    def test_missing_size_hash_and_status_drift_are_each_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="novelty source drift ") as temp:
            fixture = Fixture(Path(temp))
            base = fixture.rows[0]
            variants: list[tuple[str, dict[str, object]]] = []
            for label, field, value in (
                ("size", "bytes", int(base["bytes"]) + 1),
                ("hash", "sha256", "0" * 64),
                ("status", "status", "unsat"),
            ):
                row = dict(base)
                row[field] = value
                variants.append((label, row))
            missing = dict(base)
            Path(str(missing["path"])).unlink()
            missing_manifest = write_manifest(fixture.root / "missing.jsonl", [missing])
            with self.assertRaisesRegex(BUILDER.SelectionError, "missing source"):
                BUILDER.build_selection_artifacts(
                    missing_manifest,
                    requested_paths=[Fixture.PATH_A],
                )

            # Restore the source for the independent integrity cases.
            restored = write_source(fixture.corpus, Fixture.PATH_A, formula("sat"))
            self.assertEqual(str(restored), str(base["path"]))
            for label, row in variants:
                with self.subTest(label=label):
                    manifest = write_manifest(fixture.root / f"{label}.jsonl", [row])
                    with self.assertRaises(BUILDER.SelectionError):
                        BUILDER.build_selection_artifacts(
                            manifest,
                            requested_paths=[Fixture.PATH_A],
                        )

    def test_same_physical_source_and_source_root_escape_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="novelty identity ") as temp:
            root = Path(temp)
            corpus = root / "corpus"
            first = write_source(corpus, Fixture.PATH_A, formula("sat"))
            second = corpus.joinpath(*Fixture.PATH_B.split("/"))
            second.parent.mkdir(parents=True, exist_ok=True)
            os.link(first, second)
            rows = [
                manifest_row(1, first, Fixture.PATH_A, "sat"),
                manifest_row(2, second, Fixture.PATH_B, "sat"),
            ]
            manifest = write_manifest(root / "hardlinks.jsonl", rows)
            with self.assertRaisesRegex(BUILDER.SelectionError, "same file"):
                BUILDER.build_selection_artifacts(
                    manifest,
                    requested_paths=[Fixture.PATH_A, Fixture.PATH_B],
                    source_root=corpus,
                )

            outside = root / "outside.smt2"
            outside.write_bytes(formula("sat"))
            escaped = corpus.joinpath(*Fixture.PATH_C.split("/"))
            escaped.parent.mkdir(parents=True, exist_ok=True)
            escaped.symlink_to(outside)
            escape_row = manifest_row(3, outside, Fixture.PATH_C, "sat")
            escape_row["path"] = "/stale/" + Fixture.PATH_C
            escape_manifest = write_manifest(root / "escape.jsonl", [escape_row])
            with self.assertRaisesRegex(BUILDER.SelectionError, "escapes source root"):
                BUILDER.build_selection_artifacts(
                    escape_manifest,
                    requested_paths=[Fixture.PATH_C],
                    source_root=corpus,
                )


class AtomicAndCliTests(unittest.TestCase):
    def run_cli(
        self, fixture: Fixture, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(fixture.manifest), *arguments],
            cwd=fixture.root,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_cli_is_byte_deterministic_and_preserves_repeated_argument_order(self) -> None:
        with tempfile.TemporaryDirectory(prefix="novelty deterministic ") as temp:
            fixture = Fixture(Path(temp))
            artifacts: list[tuple[bytes, bytes]] = []
            for label in ("first", "second"):
                output = fixture.root / label / "tail.jsonl"
                report = fixture.root / label / "selection.json"
                completed = self.run_cli(
                    fixture,
                    "--source-root",
                    str(fixture.corpus),
                    "--relative-path",
                    Fixture.PATH_C,
                    "--relative-path",
                    Fixture.PATH_A,
                    "--out",
                    str(output),
                    "--report-out",
                    str(report),
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("selected=2", completed.stdout)
                artifacts.append((output.read_bytes(), report.read_bytes()))

            self.assertEqual(artifacts[0], artifacts[1])
            rows = [json.loads(line) for line in artifacts[0][0].decode().splitlines()]
            self.assertEqual(
                [row["relative_path"] for row in rows],
                [Fixture.PATH_C, Fixture.PATH_A],
            )

    def test_cli_paths_file_and_implicit_rebased_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="novelty cli path file ") as temp:
            fixture = Fixture(Path(temp))
            paths = fixture.root / "paths.txt"
            paths.write_text(Fixture.PATH_B + "\n", encoding="utf-8")
            output = fixture.root / "tail.jsonl"
            report = fixture.root / "selection.json"
            completed = self.run_cli(
                fixture,
                "--source-root",
                str(fixture.corpus),
                "--paths-file",
                str(paths),
                "--rebase-root",
                "/remote/qf-uf",
                "--out",
                str(output),
                "--report-out",
                str(report),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                json.loads(output.read_text())["path"],
                "/remote/qf-uf/" + Fixture.PATH_B,
            )

    def test_validation_failure_leaves_existing_outputs_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory(prefix="novelty fail closed ") as temp:
            fixture = Fixture(Path(temp))
            output = fixture.root / "tail.jsonl"
            report = fixture.root / "selection.json"
            output.write_bytes(b"old manifest\n")
            report.write_bytes(b"old report\n")
            completed = self.run_cli(
                fixture,
                "--source-root",
                str(fixture.corpus),
                "--relative-path",
                "QF_UF/family/unknown.smt2",
                "--out",
                str(output),
                "--report-out",
                str(report),
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("absent from manifest", completed.stderr)
            self.assertEqual(output.read_bytes(), b"old manifest\n")
            self.assertEqual(report.read_bytes(), b"old report\n")
            self.assertEqual(list(fixture.root.glob(".*.tmp")), [])

    def test_both_files_are_staged_before_replacement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="novelty atomic stage ") as temp:
            root = Path(temp)
            output = root / "tail.jsonl"
            output.write_bytes(b"old\n")
            blocker = root / "not-a-directory"
            blocker.write_bytes(b"block\n")
            with self.assertRaises(OSError):
                BUILDER.write_artifacts_atomic(
                    output,
                    blocker / "report.json",
                    b"new manifest\n",
                    b"new report\n",
                )
            self.assertEqual(output.read_bytes(), b"old\n")
            self.assertEqual(list(root.glob(".tail.jsonl.*.tmp")), [])

    def test_cli_rejects_selection_ambiguity_and_output_aliasing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="novelty cli arguments ") as temp:
            fixture = Fixture(Path(temp))
            output = fixture.root / "same.json"
            for arguments in (
                (
                    "--relative-path",
                    Fixture.PATH_A,
                    "--paths-file",
                    str(fixture.root / "missing.txt"),
                    "--out",
                    str(output),
                    "--report-out",
                    str(fixture.root / "report.json"),
                ),
                (
                    "--relative-path",
                    Fixture.PATH_A,
                    "--out",
                    str(output),
                    "--report-out",
                    str(output),
                ),
                (
                    "--relative-path",
                    Fixture.PATH_A,
                    "--path-mode",
                    "rebased",
                    "--out",
                    str(output),
                    "--report-out",
                    str(fixture.root / "report.json"),
                ),
            ):
                with self.subTest(arguments=arguments):
                    completed = self.run_cli(fixture, *arguments)
                    self.assertEqual(completed.returncode, 2)


if __name__ == "__main__":
    unittest.main()
