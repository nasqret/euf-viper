"""Verify the measured Rust sources. Optional: compare to a local Git object database."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
REVISION = "967d4d0bce9cb55a9b889e2cda5e8619ff512810"


def need(ok, message):
    if not ok:
        raise ValueError(message)


def blob_id(data):
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def verify(repo=None):
    manifest = json.loads((ROOT / "BLOBS.json").read_bytes())
    need(manifest["source_commit"] == REVISION and manifest["git_object_format"] == "sha1",
         "unexpected revision or object format")
    expected = manifest["files"]
    actual = {}
    for p in (ROOT / "src/fabric").rglob("*"):
        need(not p.is_symlink(), "symbolic link in extracted sources")
        if p.is_file():
            actual[p.relative_to(ROOT).as_posix()] = blob_id(p.read_bytes())
    need(actual == expected, "measured module set or content differs from BLOBS.json")

    if repo is not None:
        def git(*args):
            return subprocess.check_output(["git", "--git-dir", str(repo), *args])

        need(git("rev-parse", REVISION + "^{commit}").decode().strip() == REVISION,
             "source commit unavailable")
        for name, oid in expected.items():
            need(git("rev-parse", REVISION + ":" + name).decode().strip() == oid,
                 "manifest does not match commit: " + name)
            need(git("cat-file", "blob", oid) == (ROOT / name).read_bytes(),
                 "extraction differs from source bytes: " + name)
        import tomllib
        upstream = git("show", REVISION + ":Cargo.lock")
        need(blob_id(upstream) == manifest["upstream_cargo_lock_blob"], "upstream lock identity")
        def registry_ids(data):
            return {(p["name"], p["version"], p["source"], p["checksum"])
                    for p in tomllib.loads(data.decode())["package"] if "source" in p}
        locked = registry_ids((ROOT / "Cargo.lock").read_bytes())
        need(locked <= registry_ids(upstream), "fixture registry lock differs from measured source")
        print(f"Verified {len(locked)} registry package versions and checksums against the source lock.")
    print(f"Verified {len(actual)} unchanged source blobs at {REVISION}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--git-dir", type=Path, help="optional local Git object database (Python 3.11+)")
    args = parser.parse_args()
    try:
        verify(args.git_dir)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        sys.exit("verification failed: " + str(exc))
