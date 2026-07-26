#!/usr/bin/env python3
"""Strictly merge two or more EUF dashboard evidence registries.

Every input and the merged result are validated against
``euf-viper.dashboard-evidence.v1`` by ``build_euf_dashboard``.  The merger
only combines evidence; output identity and timestamp metadata must be supplied
explicitly by the caller.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping, Sequence


def _load_dashboard_module() -> ModuleType:
    path = Path(__file__).with_name("build_euf_dashboard.py")
    spec = importlib.util.spec_from_file_location("_euf_dashboard_builder", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load dashboard validator from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DASHBOARD = _load_dashboard_module()


def _remember_label(
    labels: dict[str, str],
    named: Mapping[str, str],
    *,
    namespace: str,
    input_index: int,
) -> None:
    identifier = named["id"]
    label = named["label"]
    existing = labels.get(identifier)
    if existing is not None and existing != label:
        raise DASHBOARD.DashboardInputError(
            f"conflicting {namespace} labels for ID {identifier!r}: "
            f"{existing!r} and {label!r} (input registry {input_index})"
        )
    labels[identifier] = label


def merge_registries(
    registries: Sequence[object],
    *,
    registry_id: object,
    title: object,
    updated_at: object,
) -> dict[str, Any]:
    """Validate and deterministically merge normalized registry objects."""

    if isinstance(registries, (str, bytes)) or len(registries) < 2:
        raise DASHBOARD.DashboardInputError(
            "at least two input registries are required"
        )

    normalized: list[dict[str, Any]] = []
    for index, registry in enumerate(registries):
        try:
            normalized.append(DASHBOARD.validate_registry(registry))
        except DASHBOARD.DashboardInputError as error:
            raise DASHBOARD.DashboardInputError(
                f"input registry {index}: {error}"
            ) from error

    viper_solver_id = normalized[0]["viper_solver_id"]
    mismatched_viper = [
        index
        for index, registry in enumerate(normalized[1:], start=1)
        if registry["viper_solver_id"] != viper_solver_id
    ]
    if mismatched_viper:
        details = ", ".join(
            f"{index}={normalized[index]['viper_solver_id']!r}"
            for index in mismatched_viper
        )
        raise DASHBOARD.DashboardInputError(
            "input registries have different viper_solver_id values: "
            f"0={viper_solver_id!r}, {details}"
        )

    solver_labels: dict[str, str] = {}
    host_labels: dict[str, str] = {}
    corpus_labels: dict[str, str] = {}
    family_labels: dict[str, str] = {}
    evidence_by_id: dict[str, dict[str, Any]] = {}

    for input_index, registry in enumerate(normalized):
        for solver in registry["solvers"]:
            _remember_label(
                solver_labels,
                solver,
                namespace="solver",
                input_index=input_index,
            )
        for evidence in registry["evidence"]:
            identifier = evidence["id"]
            if identifier in evidence_by_id:
                raise DASHBOARD.DashboardInputError(
                    f"duplicate evidence ID {identifier!r} across input registries"
                )
            evidence_by_id[identifier] = evidence
            for namespace, labels in (
                ("host", host_labels),
                ("corpus", corpus_labels),
                ("family", family_labels),
            ):
                _remember_label(
                    labels,
                    evidence[namespace],
                    namespace=namespace,
                    input_index=input_index,
                )

    candidate = {
        "schema_version": DASHBOARD.REGISTRY_SCHEMA_VERSION,
        "registry_id": registry_id,
        "title": title,
        "updated_at": updated_at,
        "viper_solver_id": viper_solver_id,
        "solvers": [
            {"id": identifier, "label": label}
            for identifier, label in sorted(solver_labels.items())
        ],
        "evidence": [evidence_by_id[key] for key in sorted(evidence_by_id)],
    }
    return DASHBOARD.validate_registry(candidate)


def merge_registry_paths(
    paths: Sequence[Path],
    *,
    output: Path,
    registry_id: object,
    title: object,
    updated_at: object,
) -> tuple[dict[str, Any], bytes]:
    """Load, merge, and atomically publish registries as ASCII JSON."""

    if len(paths) < 2:
        raise DASHBOARD.DashboardInputError(
            "at least two input registry paths are required"
        )
    loaded: list[dict[str, Any]] = []
    for index, path in enumerate(paths):
        try:
            loaded.append(DASHBOARD.load_registry(path))
        except DASHBOARD.DashboardInputError as error:
            raise DASHBOARD.DashboardInputError(
                f"input registry path {index} ({path}): {error}"
            ) from error

    merged = merge_registries(
        loaded,
        registry_id=registry_id,
        title=title,
        updated_at=updated_at,
    )
    payload = DASHBOARD.pretty_json_bytes(merged)
    payload.decode("ascii")
    DASHBOARD.write_artifacts_atomic([(output, payload)])
    return merged, payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "registries",
        nargs="+",
        type=Path,
        help="two or more euf-viper.dashboard-evidence.v1 registry files",
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--registry-id", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--updated-at", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        merged, payload = merge_registry_paths(
            args.registries,
            output=args.output,
            registry_id=args.registry_id,
            title=args.title,
            updated_at=args.updated_at,
        )
    except (DASHBOARD.DashboardInputError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    receipt = {
        "evidence": len(merged["evidence"]),
        "output": str(args.output),
        "output_sha256": hashlib.sha256(payload).hexdigest(),
        "registry_id": merged["registry_id"],
        "schema_version": merged["schema_version"],
        "solvers": len(merged["solvers"]),
    }
    print(
        json.dumps(
            receipt,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
