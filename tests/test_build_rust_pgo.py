from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "build_rust_pgo.py"
SPEC = importlib.util.spec_from_file_location("build_rust_pgo", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PGO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PGO)


def source_row(
    identifier: int,
    family: str,
    name: str,
    data: bytes,
    status: str,
) -> dict[str, object]:
    return {
        "bytes": len(data),
        "id": identifier,
        "logic": "QF_UF",
        "relative_path": f"QF_UF/{family}/{name}.smt2",
        "sha256": hashlib.sha256(data).hexdigest(),
        "status": status,
    }


def write_source(root: Path, row: dict[str, object], data: bytes) -> Path:
    path = root.joinpath(*str(row["relative_path"]).split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def split_report(training_hash: str) -> dict[str, object]:
    return {
        "counts": {"training": 2},
        "definition_sha256": "d" * 64,
        "families": {
            "holdout": ["gamma"],
            "training": ["alpha", "beta"],
            "training_selected_counts": {"alpha": 1, "beta": 1},
        },
        "family_disjoint": True,
        "outputs": {"training_manifest_sha256": training_hash},
        "schema_version": PGO.SPLITTER.SCHEMA_VERSION,
    }


class EnvironmentContractTests(unittest.TestCase):
    def test_program_resolution_preserves_multicall_symlink_basename(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pgo program symlink ") as temp:
            root = Path(temp)
            multicall = root / "multicall"
            multicall.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            multicall.chmod(0o755)
            shim = root / "rustc"
            shim.symlink_to(multicall)
            self.assertEqual(PGO.resolve_program(str(shim), "rustc"), shim)

    def test_solver_environment_is_namespaced_unique_and_exact(self) -> None:
        self.assertEqual(
            PGO.parse_solver_env(
                ["EUF_VIPER_FABRIC_LAZY_REASONS=1", "EUF_VIPER_MODE=a=b"]
            ),
            {
                "EUF_VIPER_FABRIC_LAZY_REASONS": "1",
                "EUF_VIPER_MODE": "a=b",
            },
        )
        for values in (
            ["NO_EQUALS"],
            ["PATH=/tmp"],
            ["EUF_VIPER_X=1", "EUF_VIPER_X=2"],
            ["EUF-viper-X=1"],
        ):
            with self.subTest(values=values):
                with self.assertRaises(PGO.PgoError):
                    PGO.parse_solver_env(values)

    def test_ambient_compiler_and_cargo_overrides_are_rejected(self) -> None:
        PGO.reject_ambient_build_overrides({"PATH": "/bin"})
        for key in (
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_TARGET_DIR",
            "LLVM_PROFILE_FILE",
            "RUSTC_WRAPPER",
            "CARGO_PROFILE_RELEASE_LTO",
        ):
            with self.subTest(key=key):
                with self.assertRaisesRegex(PGO.PgoError, key):
                    PGO.reject_ambient_build_overrides({key: ""})

    def test_build_environment_uses_encoded_flags_and_fixed_epoch(self) -> None:
        environment = PGO.build_environment(
            {"PATH": "/bin"},
            rustc=Path("/tool/rustc"),
            target=Path("/tmp/target with spaces"),
            rustflags=["-Cprofile-use=/tmp/profile with spaces", "-Copt-level=3"],
            source_date_epoch=123,
        )
        self.assertEqual(
            environment["CARGO_ENCODED_RUSTFLAGS"],
            "-Cprofile-use=/tmp/profile with spaces\x1f-Copt-level=3",
        )
        self.assertEqual(environment["CARGO_INCREMENTAL"], "0")
        self.assertEqual(environment["SOURCE_DATE_EPOCH"], "123")

    def test_llvm_profdata_must_exactly_match_rustc_llvm(self) -> None:
        rustc = "rustc 1.93.0\nhost: x86_64\nLLVM version: 21.1.8"
        profdata = "LLVM (http://llvm.org/):\n  LLVM version 21.1.8-rust-1.93.0-stable"
        self.assertEqual(PGO.require_matching_llvm(rustc, profdata), "21.1.8")
        with self.assertRaisesRegex(PGO.PgoError, "incompatible"):
            PGO.require_matching_llvm(
                rustc,
                "Apple LLVM version 17.0.0\n  Optimized build.",
            )
        with self.assertRaisesRegex(PGO.PgoError, "did not report"):
            PGO.require_matching_llvm("rustc without LLVM metadata", profdata)


class SplitAndSourceContractTests(unittest.TestCase):
    def test_split_report_is_canonical_hash_bound_and_disjoint(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pgo split report ") as temp:
            root = Path(temp)
            training_hash = "a" * 64
            report = split_report(training_hash)
            path = root / "split.json"
            path.write_bytes(PGO.SPLITTER.canonical_json_bytes(report))
            loaded = PGO.load_split_report(path, training_hash)
            self.assertEqual(loaded["report"], report)
            self.assertEqual(
                loaded["raw_sha256"], hashlib.sha256(path.read_bytes()).hexdigest()
            )

            with self.assertRaisesRegex(PGO.PgoError, "hash does not match"):
                PGO.load_split_report(path, "b" * 64)

            path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            with self.assertRaisesRegex(PGO.PgoError, "not canonical"):
                PGO.load_split_report(path, training_hash)

            damaged = split_report(training_hash)
            damaged["families"]["holdout"] = ["alpha"]  # type: ignore[index]
            path.write_bytes(PGO.SPLITTER.canonical_json_bytes(damaged))
            with self.assertRaisesRegex(PGO.PgoError, "leaks"):
                PGO.load_split_report(path, training_hash)

    def test_sources_are_size_hash_and_physical_identity_bound(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pgo sources ") as temp:
            root = Path(temp)
            first_data = b"(set-logic QF_UF)\n(set-info :status sat)\n(check-sat)\n"
            second_data = b"(set-logic QF_UF)\n(set-info :status unsat)\n(assert false)\n"
            first = source_row(1, "alpha", "one", first_data, "sat")
            second = source_row(2, "beta", "two", second_data, "unsat")
            first_path = write_source(root, first, first_data)
            second_path = write_source(root, second, second_data)

            validated = PGO.validate_training_sources([first, second], root)
            self.assertEqual(
                [item["family"] for item in validated], ["alpha", "beta"]
            )
            self.assertEqual(validated[0]["resolved_path"], str(first_path.resolve()))

            second_path.write_bytes(second_data + b"; drift\n")
            with self.assertRaisesRegex(PGO.PgoError, "size drift"):
                PGO.validate_training_sources([first, second], root)
            second_path.write_bytes(second_data)

            alias = dict(second)
            alias["bytes"] = len(first_data)
            alias["sha256"] = hashlib.sha256(first_data).hexdigest()
            second_path.unlink()
            os.link(first_path, second_path)
            with self.assertRaisesRegex(PGO.PgoError, "same physical file"):
                PGO.validate_training_sources([first, alias], root)

    def test_source_root_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pgo source escape ") as temp:
            base = Path(temp)
            root = base / "corpus"
            data = b"outside"
            row = source_row(1, "alpha", "escape", data, "sat")
            outside = base / "outside.smt2"
            outside.write_bytes(data)
            link = root.joinpath(*str(row["relative_path"]).split("/"))
            link.parent.mkdir(parents=True)
            link.symlink_to(outside)
            with self.assertRaisesRegex(PGO.PgoError, "escapes source root"):
                PGO.validate_training_sources([row], root)


class SolverAndArtifactTests(unittest.TestCase):
    def test_solver_output_must_be_one_exact_expected_status(self) -> None:
        good = subprocess.CompletedProcess([], 0, stdout=b"sat\n", stderr=b"")
        self.assertEqual(PGO.classify_solver_output(good, "sat"), "sat")
        unknown = subprocess.CompletedProcess([], 0, stdout=b"unknown\n", stderr=b"")
        self.assertEqual(
            PGO.classify_solver_output(unknown, "sat", allow_unknown=True),
            "unknown",
        )
        with self.assertRaisesRegex(PGO.PgoError, "mismatch"):
            PGO.classify_solver_output(unknown, "sat")
        wrong = subprocess.CompletedProcess([], 0, stdout=b"unsat\n", stderr=b"")
        with self.assertRaisesRegex(PGO.PgoError, "mismatch"):
            PGO.classify_solver_output(wrong, "sat", allow_unknown=True)
        cases = (
            subprocess.CompletedProcess([], 1, stdout=b"sat\n", stderr=b"error"),
            subprocess.CompletedProcess([], 0, stdout=b"sat\nextra\n", stderr=b""),
            subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""),
        )
        for completed in cases:
            with self.subTest(completed=completed):
                with self.assertRaises(PGO.PgoError):
                    PGO.classify_solver_output(completed, "sat")

    def test_internal_output_collisions_and_existing_outputs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pgo outputs ") as temp:
            base = Path(temp)
            root = base / "attempt"
            PGO.ensure_output_contract(root, base / "viper", base / "report.json")
            for binary, report in (
                (root, base / "report.json"),
                (root / "raw" / "viper", base / "report.json"),
                (base / "viper", root / "merged.profdata"),
                (base / "same", base / "same"),
            ):
                with self.subTest(binary=binary, report=report):
                    with self.assertRaises(PGO.PgoError):
                        PGO.ensure_output_contract(root, binary, report)

            existing = base / "existing"
            existing.write_bytes(b"old")
            with self.assertRaisesRegex(PGO.PgoError, "already exists"):
                PGO.ensure_output_contract(root, existing, base / "report.json")

            root.mkdir()
            (root / "partial").write_bytes(b"state")
            with self.assertRaisesRegex(PGO.PgoError, "not empty"):
                PGO.ensure_output_contract(root, base / "viper", base / "report.json")

    def test_binary_and_report_are_staged_before_publication(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pgo publish ") as temp:
            root = Path(temp)
            source = root / "source-viper"
            source.write_bytes(b"binary payload")
            source.chmod(0o755)
            binary = root / "published" / "euf-viper"
            report = root / "published" / "report.json"
            PGO.publish_artifacts(source, binary, report, b'{"ok":true}\n')
            self.assertEqual(binary.read_bytes(), b"binary payload")
            self.assertEqual(report.read_bytes(), b'{"ok":true}\n')
            self.assertTrue(stat.S_IMODE(binary.stat().st_mode) & stat.S_IXUSR)

    def test_report_staging_failure_does_not_publish_binary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pgo publish failure ") as temp:
            root = Path(temp)
            source = root / "source-viper"
            source.write_bytes(b"binary payload")
            source.chmod(0o755)
            binary = root / "published" / "euf-viper"
            blocker = root / "blocker"
            blocker.write_bytes(b"not a directory")
            with self.assertRaises(OSError):
                PGO.publish_artifacts(
                    source,
                    binary,
                    blocker / "report.json",
                    b'{"ok":true}\n',
                )
            self.assertFalse(binary.exists())
            self.assertEqual(list(binary.parent.glob(".euf-viper.*")), [])


if __name__ == "__main__":
    unittest.main()
