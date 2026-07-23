#!/usr/bin/env python3
"""Generate deterministic Williams schedules with audited balance counts.

Each output row is one complete ordering of the named arms. Carryover counts
cover adjacent arms within a row; row boundaries are not transitions.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping, Sequence
from typing import Any


SCHEMA_VERSION = 1
MIN_ARMS = 2
MAX_ARMS = 16
DESIGN_NAME = "williams_first_order_carryover"


class DesignError(ValueError):
    """Raised when a requested schedule cannot satisfy its contract."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "invalid_design",
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})

    def as_json(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "details": self.details,
            "message": str(self),
        }


def validate_arms(arms: Iterable[str]) -> tuple[str, ...]:
    """Return validated arm IDs without normalizing or reordering them."""

    if isinstance(arms, (str, bytes, Mapping)):
        raise DesignError(
            "arms must be an ordered collection of arm IDs",
            code="invalid_arms",
        )
    try:
        values = tuple(arms)
    except TypeError as error:
        raise DesignError(
            "arms must be an ordered collection of arm IDs",
            code="invalid_arms",
        ) from error

    if not MIN_ARMS <= len(values) <= MAX_ARMS:
        raise DesignError(
            f"arm count must be between {MIN_ARMS} and {MAX_ARMS}; "
            f"got {len(values)}",
            code="invalid_arm_count",
            details={
                "actual": len(values),
                "maximum": MAX_ARMS,
                "minimum": MIN_ARMS,
            },
        )

    seen: set[str] = set()
    duplicates: list[str] = []
    for index, arm in enumerate(values):
        if not isinstance(arm, str):
            raise DesignError(
                f"arm ID at index {index} must be a string; "
                f"got {type(arm).__name__}",
                code="invalid_arm_id",
                details={"index": index, "type": type(arm).__name__},
            )
        if not arm.strip():
            raise DesignError(
                f"arm ID at index {index} must be nonempty",
                code="invalid_arm_id",
                details={"index": index},
            )
        if arm in seen and arm not in duplicates:
            duplicates.append(arm)
        seen.add(arm)
    if duplicates:
        raise DesignError(
            f"arm IDs must be unique; duplicates: {duplicates!r}",
            code="duplicate_arm_id",
            details={"duplicates": duplicates},
        )
    return values


def _validate_arm_count(arm_count: int) -> int:
    if isinstance(arm_count, bool) or not isinstance(arm_count, int):
        raise DesignError(
            "arm count must be an integer",
            code="invalid_arm_count",
            details={"type": type(arm_count).__name__},
        )
    if not MIN_ARMS <= arm_count <= MAX_ARMS:
        raise DesignError(
            f"arm count must be between {MIN_ARMS} and {MAX_ARMS}; "
            f"got {arm_count}",
            code="invalid_arm_count",
            details={
                "actual": arm_count,
                "maximum": MAX_ARMS,
                "minimum": MIN_ARMS,
            },
        )
    return arm_count


def _validate_repeats(repeats: int) -> int:
    if isinstance(repeats, bool) or not isinstance(repeats, int):
        raise DesignError(
            "repeats must be a positive integer",
            code="invalid_repeats",
            details={"type": type(repeats).__name__},
        )
    if repeats < 1:
        raise DesignError(
            f"repeats must be positive; got {repeats}",
            code="invalid_repeats",
            details={"actual": repeats, "minimum": 1},
        )
    return repeats


def complete_block_rows(arm_count: int) -> int:
    """Return the smallest Williams block that has both declared balances."""

    arm_count = _validate_arm_count(arm_count)
    return arm_count if arm_count % 2 == 0 else 2 * arm_count


def _seed_indices(arm_count: int) -> tuple[int, ...]:
    indices = [0]
    for position in range(1, arm_count):
        if position % 2:
            indices.append((position + 1) // 2)
        else:
            indices.append(arm_count - position // 2)
    return tuple(indices)


def williams_block(arms: Iterable[str]) -> list[list[str]]:
    """Construct one minimum complete Williams block for the given arms."""

    arm_ids = validate_arms(arms)
    arm_count = len(arm_ids)
    seed = _seed_indices(arm_count)
    rows = [
        [arm_ids[(index + shift) % arm_count] for index in seed]
        for shift in range(arm_count)
    ]
    if arm_count % 2:
        reflected_seed = tuple(reversed(seed))
        rows.extend(
            [arm_ids[(index - shift) % arm_count] for index in reflected_seed]
            for shift in range(arm_count)
        )

    report = balance_report(arm_ids, rows)
    if not report["balanced"]:
        raise RuntimeError("internal error: constructed Williams block is unbalanced")
    return rows


def _normalize_rows(
    arm_ids: tuple[str, ...], rows: Iterable[Sequence[str]]
) -> list[list[str]]:
    if isinstance(rows, (str, bytes, Mapping)):
        raise DesignError(
            "schedule rows must be an ordered collection",
            code="invalid_schedule",
        )
    try:
        raw_rows = list(rows)
    except TypeError as error:
        raise DesignError(
            "schedule rows must be an ordered collection",
            code="invalid_schedule",
        ) from error
    if not raw_rows:
        raise DesignError(
            "schedule must contain at least one row",
            code="invalid_schedule",
        )

    expected_set = set(arm_ids)
    normalized: list[list[str]] = []
    for row_index, raw_row in enumerate(raw_rows):
        if isinstance(raw_row, (str, bytes, Mapping)):
            raise DesignError(
                f"row {row_index} must be an ordered collection of arm IDs",
                code="invalid_schedule_row",
                details={"row": row_index},
            )
        try:
            row = list(raw_row)
        except TypeError as error:
            raise DesignError(
                f"row {row_index} must be an ordered collection of arm IDs",
                code="invalid_schedule_row",
                details={"row": row_index},
            ) from error
        if len(row) != len(arm_ids):
            raise DesignError(
                f"row {row_index} has length {len(row)}; "
                f"expected exactly {len(arm_ids)}",
                code="invalid_row_length",
                details={
                    "actual": len(row),
                    "expected": len(arm_ids),
                    "row": row_index,
                },
            )
        for position, arm in enumerate(row):
            if not isinstance(arm, str):
                raise DesignError(
                    f"row {row_index} position {position} must be a string",
                    code="invalid_schedule_arm_id",
                    details={
                        "position": position,
                        "row": row_index,
                        "type": type(arm).__name__,
                    },
                )

        counts: dict[str, int] = {}
        for arm in row:
            counts[arm] = counts.get(arm, 0) + 1
        duplicates = [arm for arm in arm_ids if counts.get(arm, 0) > 1]
        missing = [arm for arm in arm_ids if arm not in counts]
        unknown = [arm for arm in counts if arm not in expected_set]
        if duplicates or missing or unknown:
            raise DesignError(
                f"row {row_index} must contain every arm exactly once",
                code="invalid_row_permutation",
                details={
                    "duplicates": duplicates,
                    "missing": missing,
                    "row": row_index,
                    "unknown": unknown,
                },
            )
        normalized.append(row)
    return normalized


def balance_report(
    arms: Iterable[str], rows: Iterable[Sequence[str]]
) -> dict[str, Any]:
    """Validate rows and return exact position and predecessor counts."""

    arm_ids = validate_arms(arms)
    normalized = _normalize_rows(arm_ids, rows)
    arm_count = len(arm_ids)
    row_count = len(normalized)

    position_counts = {arm: [0] * arm_count for arm in arm_ids}
    predecessor_counts = {
        (predecessor, successor): 0
        for predecessor in arm_ids
        for successor in arm_ids
        if predecessor != successor
    }
    for row in normalized:
        for position, arm in enumerate(row):
            position_counts[arm][position] += 1
        for predecessor, successor in zip(row, row[1:]):
            predecessor_counts[(predecessor, successor)] += 1

    integral_target = row_count % arm_count == 0
    expected_count = row_count // arm_count if integral_target else None
    flat_positions = [
        count for arm in arm_ids for count in position_counts[arm]
    ]
    flat_predecessors = [
        predecessor_counts[(predecessor, successor)]
        for predecessor in arm_ids
        for successor in arm_ids
        if predecessor != successor
    ]
    position_balanced = expected_count is not None and all(
        count == expected_count for count in flat_positions
    )
    predecessor_balanced = expected_count is not None and all(
        count == expected_count for count in flat_predecessors
    )

    return {
        "balanced": position_balanced and predecessor_balanced,
        "directed_predecessor": {
            "balanced": predecessor_balanced,
            "counts": [
                {
                    "count": predecessor_counts[(predecessor, successor)],
                    "predecessor": predecessor,
                    "successor": successor,
                }
                for predecessor in arm_ids
                for successor in arm_ids
                if predecessor != successor
            ],
            "expected_count_per_pair": expected_count,
            "observed_max": max(flat_predecessors),
            "observed_min": min(flat_predecessors),
            "orientation": "predecessor_to_successor",
            "self_pairs_included": False,
            "spread": max(flat_predecessors) - min(flat_predecessors),
            "target": {
                "denominator": arm_count,
                "integer": integral_target,
                "numerator": row_count,
            },
            "transitions_per_row": arm_count - 1,
        },
        "position": {
            "balanced": position_balanced,
            "counts": [
                {"arm": arm, "by_position": position_counts[arm]}
                for arm in arm_ids
            ],
            "expected_count_per_arm_position": expected_count,
            "observed_max": max(flat_positions),
            "observed_min": min(flat_positions),
            "spread": max(flat_positions) - min(flat_positions),
            "target": {
                "denominator": arm_count,
                "integer": integral_target,
                "numerator": row_count,
            },
        },
        "rows": {
            "all_exact_length": True,
            "all_permutations": True,
            "count": row_count,
            "expected_length": arm_count,
        },
    }


def validate_schedule(
    arms: Iterable[str],
    rows: Iterable[Sequence[str]],
    *,
    require_balance: bool = True,
) -> dict[str, Any]:
    """Validate schedule structure and optionally require aggregate balance."""

    report = balance_report(arms, rows)
    if require_balance and not report["balanced"]:
        failed = [
            name
            for name in ("position", "directed_predecessor")
            if not report[name]["balanced"]
        ]
        raise DesignError(
            "schedule does not preserve declared balance: " + ", ".join(failed),
            code="unbalanced_schedule",
            details={"failed": failed, "report": report},
        )
    return report


def _incomplete_block_error(
    arm_count: int, repeats: int, block_rows: int
) -> DesignError:
    remainder = repeats % block_rows
    previous = repeats - remainder
    next_valid = previous + block_rows
    return DesignError(
        f"{repeats} repeats cannot preserve complete Williams balance for "
        f"{arm_count} arms; repeats must be a positive multiple of {block_rows}",
        code="incomplete_balance_block",
        details={
            "arm_count": arm_count,
            "next_valid_repeats": next_valid,
            "previous_valid_repeats": previous if previous > 0 else None,
            "required_multiple": block_rows,
            "requested_repeats": repeats,
        },
    )


def generate_schedule(
    arms: Iterable[str], repeats: int, *, allow_prefix: bool = False
) -> list[list[str]]:
    """Generate rows, rejecting incomplete blocks unless explicitly allowed."""

    arm_ids = validate_arms(arms)
    repeats = _validate_repeats(repeats)
    block_rows = complete_block_rows(len(arm_ids))
    if repeats % block_rows and not allow_prefix:
        raise _incomplete_block_error(len(arm_ids), repeats, block_rows)

    block = williams_block(arm_ids)
    rows = [list(block[index % block_rows]) for index in range(repeats)]
    validate_schedule(
        arm_ids,
        rows,
        require_balance=repeats % block_rows == 0,
    )
    return rows


def build_design(
    arms: Iterable[str], repeats: int, *, allow_prefix: bool = False
) -> dict[str, Any]:
    """Build the versioned JSON-ready schedule payload."""

    arm_ids = validate_arms(arms)
    repeats = _validate_repeats(repeats)
    block_rows = complete_block_rows(len(arm_ids))
    rows = generate_schedule(arm_ids, repeats, allow_prefix=allow_prefix)
    report = balance_report(arm_ids, rows)
    prefix_rows = repeats % block_rows
    complete = prefix_rows == 0
    declared_balance_preserved = complete and report["balanced"]
    return {
        "arm_count": len(arm_ids),
        "arms": list(arm_ids),
        "balance": report,
        "complete_block_rows": block_rows,
        "complete_blocks": repeats // block_rows,
        "complete_design": complete,
        "declared_balance_preserved": declared_balance_preserved,
        "design": DESIGN_NAME,
        "prefix_rows": prefix_rows,
        "repeats": repeats,
        "rows": [
            {"order": row, "repeat": repeat}
            for repeat, row in enumerate(rows)
        ],
        "schema_version": SCHEMA_VERSION,
        "status": "balanced" if declared_balance_preserved else "prefix_only",
    }


def _write_json(value: Mapping[str, Any], stream: Any) -> None:
    json.dump(value, stream, ensure_ascii=True, indent=2, sort_keys=True)
    stream.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    arm_group = parser.add_mutually_exclusive_group(required=True)
    arm_group.add_argument("--arms", nargs="+", help="ordered arm IDs")
    arm_group.add_argument(
        "--arm",
        action="append",
        dest="arm_list",
        help="one arm ID; repeat this option in the desired order",
    )
    parser.add_argument("--repeats", required=True, type=int)
    parser.add_argument(
        "--allow-prefix",
        action="store_true",
        help="emit an explicitly reported incomplete prefix instead of failing",
    )
    args = parser.parse_args(argv)
    arms = args.arms if args.arms is not None else args.arm_list
    try:
        payload = build_design(
            arms,
            args.repeats,
            allow_prefix=args.allow_prefix,
        )
    except DesignError as error:
        _write_json(
            {
                "error": error.as_json(),
                "schema_version": SCHEMA_VERSION,
                "status": "error",
            },
            sys.stderr,
        )
        return 2
    _write_json(payload, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
