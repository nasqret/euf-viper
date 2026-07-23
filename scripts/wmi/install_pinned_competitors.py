#!/usr/bin/env python3
"""Install the pinned Yices2 and cvc5 WMI benchmark bundle atomically."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Sequence


SCHEMA_VERSION = "euf-viper.competitor-bundle.v1"
BUNDLE_NAME = "competitors-yices-2.7.0-cvc5-1.3.4"
MAX_ARCHIVE_MEMBERS = 20_000
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
PACKAGES = {
    "yices2": {
        "archive": "yices-2.7.0-x86_64-pc-linux-gnu-static-gmp.tar.gz",
        "archive_sha256": "49566b6f817692820538df78fe406878400d79810631c9372b2495bc81d3e00a",
        "archive_type": "tar.gz",
        "binary": "yices-smt2",
        "url": (
            "https://github.com/SRI-CSL/yices2/releases/download/yices-2.7.0/"
            "yices-2.7.0-x86_64-pc-linux-gnu-static-gmp.tar.gz"
        ),
        "version": "2.7.0",
    },
    "cvc5": {
        "archive": "cvc5-Linux-x86_64-static.zip",
        "archive_sha256": "dcdbfada0ce493ee98259c0816e0daafc561c223aadb3af298c2968e73ea39c6",
        "archive_type": "zip",
        "binary": "cvc5",
        "url": (
            "https://github.com/cvc5/cvc5/releases/download/cvc5-1.3.4/"
            "cvc5-Linux-x86_64-static.zip"
        ),
        "version": "1.3.4",
    },
}


class InstallError(RuntimeError):
    """Raised when a bundle cannot be installed without ambiguity."""


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def strict_json_loads(text: str) -> Any:
    def object_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"non-finite JSON number {value}")

    return json.loads(
        text, object_pairs_hook=object_hook, parse_constant=reject_constant
    )


def safe_member_path(name: str, *, directory: bool = False) -> PurePosixPath:
    normalized = name[:-1] if directory and name.endswith("/") else name
    pure = PurePosixPath(normalized)
    if (
        not normalized
        or pure.is_absolute()
        or pure.as_posix() != normalized
        or normalized.startswith("//")
        or "\\" in normalized
        or "\0" in normalized
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise InstallError(f"unsafe archive member path: {name!r}")
    return pure


def safe_symlink_target(name: str, target: str) -> str:
    pure = PurePosixPath(target)
    if (
        not target
        or pure.is_absolute()
        or "\\" in target
        or "\0" in target
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise InstallError(f"unsafe symlink target for {name!r}: {target!r}")
    return target


def copy_exact(source: BinaryIO, destination: Path, declared_size: int) -> None:
    if declared_size < 0 or declared_size > MAX_MEMBER_BYTES:
        raise InstallError(f"archive member size is outside bounds: {declared_size}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with destination.open("xb") as output:
        while chunk := source.read(min(1024 * 1024, declared_size - written + 1)):
            written += len(chunk)
            if written > declared_size:
                raise InstallError(f"archive member exceeds declared size: {destination}")
            output.write(chunk)
        output.flush()
        os.fsync(output.fileno())
    if written != declared_size:
        raise InstallError(
            f"archive member size mismatch for {destination}: {written} != {declared_size}"
        )


def extraction_mode(mode: int) -> int:
    return 0o755 if mode & 0o111 else 0o644


def extract_tar(archive: Path, destination: Path) -> None:
    seen: set[str] = set()
    symlinks: list[tuple[Path, str]] = []
    total = 0
    with tarfile.open(archive, mode="r:gz") as bundle:
        members = bundle.getmembers()
        if not 1 <= len(members) <= MAX_ARCHIVE_MEMBERS:
            raise InstallError("tar member count is outside bounds")
        for member in members:
            relative = safe_member_path(member.name, directory=member.isdir())
            key = relative.as_posix()
            if key in seen:
                raise InstallError(f"duplicate tar member: {key}")
            seen.add(key)
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if member.isfile():
                total += member.size
                if total > MAX_TOTAL_BYTES:
                    raise InstallError("tar expanded size exceeds limit")
                source = bundle.extractfile(member)
                if source is None:
                    raise InstallError(f"cannot read tar member: {member.name}")
                with source:
                    copy_exact(source, target, member.size)
                target.chmod(extraction_mode(member.mode))
                continue
            if member.issym():
                symlinks.append(
                    (target, safe_symlink_target(member.name, member.linkname))
                )
                continue
            raise InstallError(f"unsupported tar member type: {member.name}")
    for target, link in symlinks:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(link)


def zip_mode(info: zipfile.ZipInfo) -> int:
    return (info.external_attr >> 16) & 0o777777


def extract_zip(archive: Path, destination: Path) -> None:
    seen: set[str] = set()
    symlinks: list[tuple[Path, str]] = []
    total = 0
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if not 1 <= len(members) <= MAX_ARCHIVE_MEMBERS:
            raise InstallError("zip member count is outside bounds")
        for info in members:
            relative = safe_member_path(info.filename, directory=info.is_dir())
            key = relative.as_posix()
            if key in seen:
                raise InstallError(f"duplicate zip member: {key}")
            seen.add(key)
            target = destination.joinpath(*relative.parts)
            mode = zip_mode(info)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if stat.S_ISLNK(mode):
                if info.file_size > MAX_MEMBER_BYTES:
                    raise InstallError(f"zip symlink target exceeds limit: {info.filename}")
                total += info.file_size
                if total > MAX_TOTAL_BYTES:
                    raise InstallError("zip expanded size exceeds limit")
                raw_target = bundle.read(info)
                try:
                    link = raw_target.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise InstallError(f"non-UTF-8 zip symlink: {info.filename}") from error
                symlinks.append(
                    (target, safe_symlink_target(info.filename, link))
                )
                continue
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise InstallError("zip expanded size exceeds limit")
            with bundle.open(info, "r") as source:
                copy_exact(source, target, info.file_size)
            target.chmod(extraction_mode(mode))
    for target, link in symlinks:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(link)


def find_unique_binary(root: Path, name: str) -> Path:
    matches = sorted(
        path
        for path in root.rglob(name)
        if path.is_file() and not path.is_symlink() and os.access(path, os.X_OK)
    )
    if len(matches) != 1:
        raise InstallError(f"expected one executable {name!r}, found {len(matches)}")
    return matches[0]


def run_version(binary: Path, version: str) -> str:
    completed = subprocess.run(
        [str(binary), "--version"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    output = (completed.stdout + completed.stderr).decode("utf-8", errors="replace").strip()
    if completed.returncode != 0 or version not in output:
        raise InstallError(
            f"version check failed for {binary}: exit={completed.returncode} output={output!r}"
        )
    return output


def ldd_metadata(binary: Path) -> dict[str, Any]:
    ldd = shutil.which("ldd")
    if ldd is None:
        return {"available": False}
    completed = subprocess.run(
        [ldd, str(binary)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    return {
        "available": True,
        "output": (completed.stdout + completed.stderr).decode(
            "utf-8", errors="replace"
        ).strip(),
        "returncode": completed.returncode,
    }


def tree_manifest(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative == "receipt.json":
            continue
        if path.is_symlink():
            records.append(
                {"path": relative, "target": os.readlink(path), "type": "symlink"}
            )
        elif path.is_dir():
            continue
        elif path.is_file():
            records.append(
                {
                    "bytes": path.stat().st_size,
                    "mode": stat.S_IMODE(path.stat().st_mode),
                    "path": relative,
                    "sha256": sha256_file(path),
                    "type": "file",
                }
            )
        else:
            raise InstallError(f"unsupported installed object: {path}")
    return records


def download(curl: Path, url: str, destination: Path) -> None:
    completed = subprocess.run(
        [
            str(curl),
            "--proto",
            "=https",
            "--tlsv1.2",
            "--fail",
            "--location",
            "--retry",
            "3",
            "--silent",
            "--show-error",
            "--output",
            str(destination),
            url,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=900,
    )
    if completed.returncode != 0:
        error = completed.stderr.decode("utf-8", errors="replace")[-4096:]
        raise InstallError(f"download failed for {url}: {error}")


def validate_existing(target: Path) -> dict[str, Any]:
    receipt_path = target / "receipt.json"
    try:
        raw = receipt_path.read_bytes()
        receipt = strict_json_loads(raw.decode("ascii"))
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise InstallError(f"invalid existing bundle receipt: {error}") from error
    if type(receipt) is not dict or receipt.get("schema_version") != SCHEMA_VERSION:
        raise InstallError("existing bundle receipt schema mismatch")
    if canonical_json_bytes(receipt) != raw:
        raise InstallError("existing bundle receipt is not canonical JSON")
    if receipt.get("bundle_name") != BUNDLE_NAME:
        raise InstallError("existing bundle name mismatch")
    if receipt.get("packages") != PACKAGES:
        raise InstallError("existing bundle package contract mismatch")
    if receipt.get("tree") != tree_manifest(target):
        raise InstallError("existing bundle tree no longer matches its receipt")
    binaries = receipt.get("binaries")
    if type(binaries) is not dict or set(binaries) != set(PACKAGES):
        raise InstallError("existing bundle binary records mismatch")
    for label, package in PACKAGES.items():
        archive = target / "archives" / package["archive"]
        if not archive.is_file() or archive.is_symlink():
            raise InstallError(f"existing {label} archive is missing or unsafe")
        if sha256_file(archive) != package["archive_sha256"]:
            raise InstallError(f"existing {label} archive hash drift")
        metadata = binaries[label]
        if type(metadata) is not dict:
            raise InstallError(f"existing {label} binary record is invalid")
        relative_raw = metadata.get("relative_path")
        if type(relative_raw) is not str:
            raise InstallError(f"existing {label} binary path is invalid")
        relative = safe_member_path(relative_raw)
        expected_prefix = PurePosixPath("packages") / label
        if relative.parent != expected_prefix and expected_prefix not in relative.parents:
            raise InstallError(f"existing {label} binary escaped its package root")
        if relative.name != package["binary"]:
            raise InstallError(f"existing {label} binary name mismatch")
        binary = target.joinpath(*relative.parts)
        if not binary.is_file() or binary.is_symlink() or not os.access(binary, os.X_OK):
            raise InstallError(f"existing {label} binary is missing or unsafe")
        if metadata.get("bytes") != binary.stat().st_size:
            raise InstallError(f"existing {label} binary size drift")
        if metadata.get("sha256") != sha256_file(binary):
            raise InstallError(f"existing {label} binary hash drift")
        run_version(binary, package["version"])
    return receipt


def install(tools_root: Path, curl: Path) -> tuple[Path, dict[str, Any]]:
    target = tools_root / BUNDLE_NAME
    if target.exists() or target.is_symlink():
        if not target.is_dir() or target.is_symlink():
            raise InstallError(f"bundle target exists but is unsafe: {target}")
        return target, validate_existing(target)

    staging = Path(tempfile.mkdtemp(prefix=f".{BUNDLE_NAME}.", dir=tools_root))
    try:
        archives = staging / "archives"
        packages_root = staging / "packages"
        archives.mkdir()
        packages_root.mkdir()
        binaries: dict[str, dict[str, Any]] = {}
        for label, package in PACKAGES.items():
            archive = archives / package["archive"]
            download(curl, package["url"], archive)
            actual_archive_hash = sha256_file(archive)
            if actual_archive_hash != package["archive_sha256"]:
                raise InstallError(
                    f"{label} archive SHA-256 mismatch: {actual_archive_hash}"
                )
            package_root = packages_root / label
            package_root.mkdir()
            if package["archive_type"] == "tar.gz":
                extract_tar(archive, package_root)
            elif package["archive_type"] == "zip":
                extract_zip(archive, package_root)
            else:
                raise InstallError(f"unsupported archive type for {label}")
            binary = find_unique_binary(package_root, package["binary"])
            version_output = run_version(binary, package["version"])
            binaries[label] = {
                "bytes": binary.stat().st_size,
                "ldd": ldd_metadata(binary),
                "relative_path": binary.relative_to(staging).as_posix(),
                "sha256": sha256_file(binary),
                "version_output": version_output,
            }

        receipt = {
            "schema_version": SCHEMA_VERSION,
            "bundle_name": BUNDLE_NAME,
            "binaries": binaries,
            "installed_at": datetime.now(timezone.utc).isoformat(),
            "packages": PACKAGES,
            "tree": tree_manifest(staging),
        }
        receipt_path = staging / "receipt.json"
        receipt_path.write_bytes(canonical_json_bytes(receipt))
        with receipt_path.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(staging, target)
        return target, receipt
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools-root", type=Path, required=True)
    parser.add_argument("--curl", default="curl")
    return parser.parse_args(argv)


def prepare_tools_root(value: Path) -> Path:
    tools_root = value.expanduser()
    if (
        not tools_root.is_absolute()
        or len(tools_root.parts) < 3
        or tools_root.parts[0] != "/"
        or tools_root.parts[1] != "work"
        or any(part in {"", ".", ".."} for part in tools_root.parts)
    ):
        raise InstallError("tools root must be a canonical absolute path below /work")
    cursor = Path("/")
    for part in tools_root.parts[1:]:
        cursor /= part
        if cursor.is_symlink():
            raise InstallError(f"tools root traverses a symlink: {cursor}")
    tools_root.mkdir(parents=True, exist_ok=True)
    resolved = tools_root.resolve(strict=True)
    if resolved != tools_root:
        raise InstallError(f"tools root is not canonical: {resolved}")
    return resolved


def main(argv: Sequence[str] | None = None) -> int:
    if os.environ.get("EUF_VIPER_INSTALL_COMPETITORS") != "1":
        raise InstallError(
            "competitor installation is default-off; set "
            "EUF_VIPER_INSTALL_COMPETITORS=1"
        )
    args = parse_args(argv)
    tools_root = prepare_tools_root(args.tools_root)
    curl_raw = shutil.which(args.curl)
    if curl_raw is None:
        raise InstallError(f"cannot find curl executable {args.curl!r}")
    curl = Path(curl_raw)
    target, receipt = install(tools_root, curl)
    paths = {
        label: str(target / metadata["relative_path"])
        for label, metadata in receipt["binaries"].items()
    }
    print(canonical_json_bytes({"bundle": str(target), "binaries": paths}).decode(), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InstallError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
