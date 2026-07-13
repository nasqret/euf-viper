#!/usr/bin/env python3
"""Project a component-local quotient RAM against eager QF_UF completion.

This analyzer is deliberately source-only.  It reconstructs typed QF_UF with
``scripts.cert.independent_qfuf.parse_and_encode``, computes exact integer CNF
counts for two declared encodings, and never invokes a solver or reports a
satisfiability result.  Every output record is provenance-bound and chained.
"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import os
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from fractions import Fraction
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.bench import build_family_manifest as family_manifest  # noqa: E402
from scripts.cert import independent_qfuf as qfuf  # noqa: E402


RECORD_SCHEMA = "euf-viper.component-quotient-ram-source-projection.v1"
AGGREGATE_SCHEMA = "euf-viper.component-quotient-ram-census-summary.v1"
TARGET_SCHEMA = "euf-viper.component-quotient-ram-target.v1"
LOCK_SCHEMA = "euf-viper.component-quotient-ram-census-lock.v1"
PARSER_API = "scripts.cert.independent_qfuf.parse_and_encode"
PARSER_PATH = ROOT / "scripts" / "cert" / "independent_qfuf.py"
TAXONOMY_PATH = ROOT / "scripts" / "bench" / "build_family_manifest.py"
DEFAULT_LOCK_PATH = ROOT / "campaigns" / "component-quotient-ram-census-v1.json"
INTERPRETATION = "structural_projection_only_no_solver_invocation_no_timing_claim"
GENESIS_HASH: str | None = None
PPM = 1_000_000


class CensusError(ValueError):
    """Raised when an input, lock, or output fails closed."""


class ProjectionCap(CensusError):
    """A named preregistered projection cap was exceeded."""

    def __init__(self, code: str, limit: int, observed: int) -> None:
        super().__init__(f"{code} cap exceeded: limit {limit}, observed {observed}")
        self.code = code
        self.limit = limit
        self.observed = observed


class ProjectionInvariant(CensusError):
    """The proposed encoding cannot satisfy its typed decoder contract."""


@dataclass(frozen=True)
class Counts:
    variables: int = 0
    clauses: int = 0
    literal_slots: int = 0
    unit_clauses: int = 0
    watch_entries: int = 0

    def __post_init__(self) -> None:
        values = asdict(self)
        if any(type(value) is not int or value < 0 for value in values.values()):
            raise CensusError(f"invalid structural count: {values}")
        if self.unit_clauses > self.clauses:
            raise CensusError("unit clauses cannot exceed clauses")
        if self.literal_slots < self.unit_clauses:
            raise CensusError("literal slots cannot be smaller than unit clauses")
        if self.watch_entries != 2 * (self.clauses - self.unit_clauses):
            raise CensusError("watch count must be two per non-unit clause")

    def __add__(self, other: Counts) -> Counts:
        if not isinstance(other, Counts):
            return NotImplemented
        return Counts(
            self.variables + other.variables,
            self.clauses + other.clauses,
            self.literal_slots + other.literal_slots,
            self.unit_clauses + other.unit_clauses,
            self.watch_entries + other.watch_entries,
        )

    def scale(self, multiplier: int) -> Counts:
        if type(multiplier) is not int or multiplier < 0:
            raise CensusError("count multiplier must be a non-negative integer")
        return Counts(
            self.variables * multiplier,
            self.clauses * multiplier,
            self.literal_slots * multiplier,
            self.unit_clauses * multiplier,
            self.watch_entries * multiplier,
        )

    def to_json(self) -> dict[str, int]:
        return asdict(self)


ZERO_COUNTS = Counts()
UNIT = Counts(variables=0, clauses=1, literal_slots=1, unit_clauses=1)
UNIT_WITH_VARIABLE = Counts(
    variables=1, clauses=1, literal_slots=1, unit_clauses=1
)
AND2 = Counts(variables=1, clauses=3, literal_slots=7, watch_entries=6)
OR2 = Counts(variables=1, clauses=3, literal_slots=7, watch_entries=6)
XOR2 = Counts(variables=1, clauses=4, literal_slots=12, watch_entries=8)
XNOR2 = Counts(variables=1, clauses=4, literal_slots=12, watch_entries=8)
MUX2 = Counts(variables=1, clauses=4, literal_slots=12, watch_entries=8)


@dataclass(frozen=True)
class Caps:
    max_source_bytes: int
    max_terms: int
    max_applications: int
    max_symbols: int
    max_component_terms: int
    max_ackermann_pairs: int
    max_equality_edges: int
    max_fill_edges: int
    max_sorter_records: int
    max_sorter_comparators: int
    max_packed_record_bits: int
    max_decoder_operations: int
    max_projected_count: int

    def validate(self) -> None:
        for name, value in asdict(self).items():
            if type(value) is not int or value < 1:
                raise CensusError(f"lock caps.{name} must be a positive integer")


@dataclass(frozen=True)
class Ratio:
    numerator: int
    denominator: int

    def validate(self, context: str) -> None:
        if type(self.numerator) is not int or self.numerator < 0:
            raise CensusError(f"{context}.numerator must be non-negative")
        if type(self.denominator) is not int or self.denominator < 1:
            raise CensusError(f"{context}.denominator must be positive")


@dataclass(frozen=True)
class FamilyLock:
    key: str
    source_family: str
    expected_population: int


@dataclass(frozen=True)
class CampaignLock:
    raw: dict[str, object]
    path: Path
    raw_bytes: bytes
    sha256: str
    campaign_id: str
    expected_sources: int
    families: tuple[FamilyLock, ...]
    caps: Caps
    minimum_total_applications: int
    minimum_max_symbol_applications: int
    broadness_fraction: Ratio
    minimum_generator_lineages: int
    opportunity_reduction: Ratio
    minimum_individual_fraction: Ratio
    opportunity_metrics: tuple[str, ...]
    variable_maximum: Ratio
    variable_percentile: int


@dataclass(frozen=True)
class ManifestSource:
    record_id: int | str
    line_number: int
    relative_path: str
    source_path: Path
    source_bytes: bytes
    source_sha256: str
    source_family: str
    generator_lineage: str
    taxonomy_rule: str


@dataclass(frozen=True)
class Component:
    id: int
    sort: int
    terms: tuple[int, ...]
    width: int


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _is_lower_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _exact_keys(value: object, expected: set[str], context: str) -> dict[str, object]:
    if type(value) is not dict:
        raise CensusError(f"{context} must be a JSON object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise CensusError(f"{context} keys differ: missing={missing}, extra={extra}")
    return value


def _positive_int(value: object, context: str) -> int:
    if type(value) is not int or value < 1:
        raise CensusError(f"{context} must be a positive integer")
    return value


def _ratio(value: object, context: str) -> Ratio:
    row = _exact_keys(value, {"numerator", "denominator"}, context)
    ratio = Ratio(row["numerator"], row["denominator"])  # type: ignore[arg-type]
    ratio.validate(context)
    return ratio


def load_campaign_lock(path: Path = DEFAULT_LOCK_PATH) -> CampaignLock:
    path = Path(path)
    try:
        raw_bytes = path.read_bytes()
    except OSError as error:
        raise CensusError(f"cannot read campaign lock {path}: {error}") from error
    try:
        text = raw_bytes.decode("ascii")
    except UnicodeDecodeError as error:
        raise CensusError("campaign lock must be ASCII") from error
    try:
        raw_value = family_manifest.strict_json_loads(text)
    except (json.JSONDecodeError, ValueError) as error:
        raise CensusError(f"malformed campaign lock: {error}") from error
    raw = _exact_keys(
        raw_value,
        {
            "schema",
            "campaign_id",
            "status",
            "logic",
            "interpretation",
            "parser_api",
            "corpus",
            "projection",
            "caps",
            "selector",
            "gates",
        },
        "campaign lock",
    )
    if raw["schema"] != LOCK_SCHEMA:
        raise CensusError(f"unsupported campaign lock schema {raw['schema']!r}")
    if raw["status"] != "preregistered_source_only":
        raise CensusError("campaign lock is not preregistered source-only")
    if raw["logic"] != "QF_UF" or raw["parser_api"] != PARSER_API:
        raise CensusError("campaign lock logic or parser API drift")
    if raw["interpretation"] != INTERPRETATION:
        raise CensusError("campaign lock interpretation drift")
    campaign_id = raw["campaign_id"]
    if not isinstance(campaign_id, str) or not campaign_id:
        raise CensusError("campaign_id must be a nonempty string")

    corpus = _exact_keys(
        raw["corpus"], {"manifest", "expected_sources", "families"}, "corpus"
    )
    expected_sources = _positive_int(corpus["expected_sources"], "expected_sources")
    families_value = corpus["families"]
    if type(families_value) is not dict or not families_value:
        raise CensusError("corpus.families must be a nonempty object")
    families: list[FamilyLock] = []
    seen_source_families: set[str] = set()
    for key in sorted(families_value):
        if not isinstance(key, str) or not key:
            raise CensusError("family lock key must be a nonempty string")
        row = _exact_keys(
            families_value[key],
            {"source_family", "expected_population"},
            f"family {key}",
        )
        source_family = row["source_family"]
        if not isinstance(source_family, str) or not source_family:
            raise CensusError(f"family {key}.source_family must be nonempty")
        if source_family in seen_source_families:
            raise CensusError("family source identifiers must be unique")
        seen_source_families.add(source_family)
        families.append(
            FamilyLock(
                key,
                source_family,
                _positive_int(row["expected_population"], f"family {key} population"),
            )
        )

    cap_values = _exact_keys(raw["caps"], set(Caps.__dataclass_fields__), "caps")
    caps = Caps(**cap_values)  # type: ignore[arg-type]
    caps.validate()

    selector = _exact_keys(
        raw["selector"],
        {
            "kind",
            "minimum_total_applications",
            "minimum_max_symbol_applications",
        },
        "selector",
    )
    if selector["kind"] != "structural_only":
        raise CensusError("selector must remain structural-only")

    gates = _exact_keys(
        raw["gates"],
        {"validity", "broadness", "opportunity", "variable_control"},
        "gates",
    )
    validity = _exact_keys(
        gates["validity"],
        {
            "required_sources",
            "allowed_parse_errors",
            "allowed_unknown_projections",
            "allowed_cap_events",
            "require_complete_decoder",
        },
        "validity gate",
    )
    if validity != {
        "required_sources": expected_sources,
        "allowed_parse_errors": 0,
        "allowed_unknown_projections": 0,
        "allowed_cap_events": 0,
        "require_complete_decoder": True,
    }:
        raise CensusError("validity gate must require exact complete coverage")
    broadness = _exact_keys(
        gates["broadness"],
        {"minimum_family_fraction", "minimum_generator_lineages"},
        "broadness gate",
    )
    opportunity = _exact_keys(
        gates["opportunity"],
        {
            "minimum_reduction",
            "minimum_individual_fraction",
            "metrics",
            "require_weighted_and_median_and_individual",
        },
        "opportunity gate",
    )
    if opportunity["require_weighted_and_median_and_individual"] is not True:
        raise CensusError("opportunity gate conjunction may not be weakened")
    metrics = opportunity["metrics"]
    if metrics != ["clauses", "watch_entries"]:
        raise CensusError("opportunity metrics must be clauses and watch_entries")
    variable = _exact_keys(
        gates["variable_control"],
        {"maximum_ratio", "percentile", "require_weighted_and_percentile"},
        "variable gate",
    )
    if variable["require_weighted_and_percentile"] is not True:
        raise CensusError("variable gate conjunction may not be weakened")
    percentile = _positive_int(variable["percentile"], "variable percentile")
    if percentile > 100:
        raise CensusError("variable percentile cannot exceed 100")

    projection = _exact_keys(
        raw["projection"],
        {"eager", "component_quotient_ram", "cnf_templates"},
        "projection",
    )
    templates = _exact_keys(
        projection["cnf_templates"],
        {
            "and2",
            "or2",
            "xnor2",
            "xor2",
            "mux2",
            "increment",
            "unsigned_greater",
            "equality_atom_link",
        },
        "CNF templates",
    )
    for name, expected in (
        ("and2", AND2),
        ("or2", OR2),
        ("xnor2", XNOR2),
        ("xor2", XOR2),
        ("mux2", MUX2),
    ):
        if templates[name] != expected.to_json():
            raise CensusError(f"campaign lock {name} template drift")

    return CampaignLock(
        raw=raw,
        path=path,
        raw_bytes=raw_bytes,
        sha256=sha256_bytes(raw_bytes),
        campaign_id=campaign_id,
        expected_sources=expected_sources,
        families=tuple(families),
        caps=caps,
        minimum_total_applications=_positive_int(
            selector["minimum_total_applications"], "minimum_total_applications"
        ),
        minimum_max_symbol_applications=_positive_int(
            selector["minimum_max_symbol_applications"],
            "minimum_max_symbol_applications",
        ),
        broadness_fraction=_ratio(
            broadness["minimum_family_fraction"], "minimum_family_fraction"
        ),
        minimum_generator_lineages=_positive_int(
            broadness["minimum_generator_lineages"], "minimum_generator_lineages"
        ),
        opportunity_reduction=_ratio(
            opportunity["minimum_reduction"], "minimum_reduction"
        ),
        minimum_individual_fraction=_ratio(
            opportunity["minimum_individual_fraction"],
            "minimum_individual_fraction",
        ),
        opportunity_metrics=tuple(metrics),
        variable_maximum=_ratio(variable["maximum_ratio"], "maximum_ratio"),
        variable_percentile=percentile,
    )


def _portable_source_set_bytes(sources: Sequence[ManifestSource]) -> bytes:
    return b"".join(
        canonical_json_bytes(
            {
                "relative_path": source.relative_path,
                "bytes": len(source.source_bytes),
                "sha256": source.source_sha256,
            }
        )
        for source in sources
    )


def load_manifest(
    manifest_path: Path, repository_root: Path, expected_sources: int
) -> tuple[list[ManifestSource], bytes, bytes]:
    """Load and hash the exact source set without host-specific path leakage."""

    try:
        manifest_bytes = Path(manifest_path).read_bytes()
    except OSError as error:
        raise CensusError(f"cannot read manifest {manifest_path}: {error}") from error
    try:
        text = manifest_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CensusError(f"manifest is not UTF-8: {error}") from error
    lines = text.splitlines()
    if len(lines) != expected_sources:
        raise CensusError(
            f"manifest cardinality mismatch: expected {expected_sources}, got {len(lines)}"
        )
    if any(not line.strip() for line in lines):
        raise CensusError("manifest contains a blank JSONL record")

    root = Path(repository_root).resolve()
    sources: list[ManifestSource] = []
    seen_ids: set[int | str] = set()
    seen_relative_paths: set[str] = set()
    seen_paths: set[Path] = set()
    for line_number, line in enumerate(lines, 1):
        try:
            row = family_manifest.strict_json_loads(line)
        except (json.JSONDecodeError, ValueError) as error:
            raise CensusError(f"line {line_number}: malformed JSON: {error}") from error
        if type(row) is not dict:
            raise CensusError(f"line {line_number}: record must be an object")
        for field in ("id", "path", "relative_path", "bytes", "sha256"):
            if field not in row:
                raise CensusError(f"line {line_number}: missing field {field!r}")
        record_id = row["id"]
        if isinstance(record_id, bool) or not isinstance(record_id, (int, str)):
            raise CensusError(f"line {line_number}: invalid id")
        if record_id in seen_ids:
            raise CensusError(f"line {line_number}: duplicate id {record_id!r}")
        seen_ids.add(record_id)
        try:
            relative_path = family_manifest._validated_relative_path(
                row["relative_path"], line_number=line_number
            )
            source_path = family_manifest._resolve_source_path(
                row["path"], root, line_number=line_number
            )
            taxonomy = family_manifest.derive_path_taxonomy(relative_path)
        except family_manifest.ManifestError as error:
            raise CensusError(str(error)) from error
        if relative_path in seen_relative_paths:
            raise CensusError(
                f"line {line_number}: duplicate relative_path {relative_path!r}"
            )
        seen_relative_paths.add(relative_path)
        if source_path in seen_paths:
            raise CensusError(f"line {line_number}: duplicate source {source_path}")
        seen_paths.add(source_path)
        parts = PurePosixPath(relative_path).parts
        if tuple(source_path.parts[-len(parts) :]) != parts:
            raise CensusError(
                f"line {line_number}: path does not end in relative_path"
            )
        try:
            source_bytes = source_path.read_bytes()
        except OSError as error:
            raise CensusError(
                f"line {line_number}: cannot read {source_path}: {error}"
            ) from error
        source_sha256 = sha256_bytes(source_bytes)
        if not _is_lower_sha256(row["sha256"]):
            raise CensusError(f"line {line_number}: invalid source SHA-256")
        if row["sha256"] != source_sha256:
            raise CensusError(
                f"line {line_number}: sha256 mismatch for {relative_path!r}"
            )
        if type(row["bytes"]) is not int or row["bytes"] != len(source_bytes):
            raise CensusError(
                f"line {line_number}: byte-count mismatch for {relative_path!r}"
            )
        sources.append(
            ManifestSource(
                record_id=record_id,
                line_number=line_number,
                relative_path=relative_path,
                source_path=source_path,
                source_bytes=source_bytes,
                source_sha256=source_sha256,
                source_family=taxonomy.source_family,
                generator_lineage=taxonomy.generator_lineage,
                taxonomy_rule=taxonomy.rule,
            )
        )
    sources.sort(key=lambda source: source.relative_path)
    portable = _portable_source_set_bytes(sources)
    return sources, manifest_bytes, portable


def _checked(value: int, limit: int, code: str) -> int:
    if type(value) is not int or value < 0:
        raise ProjectionInvariant(f"{code} produced a negative or non-integer count")
    if value > limit:
        raise ProjectionCap(code, limit, value)
    return value


def choose2(value: int) -> int:
    return value * (value - 1) // 2


def choose3(value: int) -> int:
    return value * (value - 1) * (value - 2) // 6


def component_width(term_count: int) -> int:
    if type(term_count) is not int or term_count < 1:
        raise CensusError("component term count must be positive")
    return max(1, (term_count - 1).bit_length())


def next_power_of_two(value: int) -> int:
    if type(value) is not int or value < 1:
        raise CensusError("sorter size must be positive")
    return 1 << (value - 1).bit_length()


def increment_counts(width: int) -> Counts:
    if type(width) is not int or width < 1:
        raise CensusError("increment width must be positive")
    if width == 1:
        return ZERO_COUNTS
    return XOR2.scale(width - 1) + AND2.scale(width - 2)


def unsigned_greater_counts(width: int) -> Counts:
    if type(width) is not int or width < 1:
        raise CensusError("comparison width must be positive")
    if width == 1:
        return AND2
    return (
        AND2.scale(width)
        + MUX2.scale(width - 1)
        + XNOR2.scale(width - 1)
        + AND2.scale(width - 2)
    )


def equality_link_counts(width: int) -> Counts:
    if type(width) is not int or width < 1:
        raise CensusError("equality-link width must be positive")
    xnor = XNOR2.scale(width)
    channel_clauses = width + 1
    channel_literals = 2 * width + width + 1
    channel = Counts(
        clauses=channel_clauses,
        literal_slots=channel_literals,
        watch_entries=2 * channel_clauses,
    )
    return xnor + channel


def restricted_growth_counts(term_count: int, width: int) -> Counts:
    if term_count < 1 or width != component_width(term_count):
        raise CensusError("restricted-growth shape is inconsistent")
    counts = UNIT.scale(width)
    for index in range(1, term_count):
        counts += increment_counts(width)
        counts += unsigned_greater_counts(width)
        counts += UNIT
        if index + 1 < term_count:
            counts += unsigned_greater_counts(width)
            counts += MUX2.scale(width)
    return counts


def bitonic_comparator_count(records: int) -> int:
    if records < 1 or records & (records - 1):
        raise CensusError("bitonic record count must be a positive power of two")
    log_records = records.bit_length() - 1
    return records * log_records * (log_records + 1) // 4


def bitonic_network(records: int) -> tuple[tuple[int, int, bool], ...]:
    """Return deterministic compare-exchanges; ties need not move for soundness."""

    bitonic_comparator_count(records)
    network: list[tuple[int, int, bool]] = []
    span = 2
    while span <= records:
        distance = span // 2
        while distance:
            for left in range(records):
                right = left ^ distance
                if right > left:
                    network.append((left, right, (left & span) == 0))
            distance //= 2
        span *= 2
    if len(network) != bitonic_comparator_count(records):
        raise ProjectionInvariant("bitonic network comparator formula drift")
    return tuple(network)


def simulate_bitonic_sort(
    records: Sequence[tuple[object, object]],
) -> list[tuple[object, object]]:
    output = list(records)
    for left, right, ascending in bitonic_network(len(output)):
        left_key = output[left][0]
        right_key = output[right][0]
        swap = left_key > right_key if ascending else left_key < right_key
        if swap:
            output[left], output[right] = output[right], output[left]
    return output


class CnfCircuit:
    """Small executable Tseitin builder used to verify projection templates."""

    def __init__(self) -> None:
        self.input_variables: list[int] = []
        self.operations: list[tuple[str, int, tuple[int, ...]]] = []
        self.clauses: list[tuple[int, ...]] = []
        self._next_variable = 1

    def input(self) -> int:
        variable = self._next_variable
        self._next_variable += 1
        self.input_variables.append(variable)
        return variable

    def _output(self, operation: str, arguments: tuple[int, ...]) -> int:
        output = self._next_variable
        self._next_variable += 1
        self.operations.append((operation, output, arguments))
        return output

    def unit(self, literal: int) -> None:
        self.clauses.append((literal,))

    def and2(self, left: int, right: int) -> int:
        output = self._output("and", (left, right))
        self.clauses.extend(((-output, left), (-output, right), (output, -left, -right)))
        return output

    def or2(self, left: int, right: int) -> int:
        output = self._output("or", (left, right))
        self.clauses.extend(((output, -left), (output, -right), (-output, left, right)))
        return output

    def xor2(self, left: int, right: int) -> int:
        output = self._output("xor", (left, right))
        self.clauses.extend(
            (
                (left, right, -output),
                (-left, -right, -output),
                (left, -right, output),
                (-left, right, output),
            )
        )
        return output

    def xnor2(self, left: int, right: int) -> int:
        output = self._output("xnor", (left, right))
        self.clauses.extend(
            (
                (-left, -right, output),
                (left, right, output),
                (-left, right, -output),
                (left, -right, -output),
            )
        )
        return output

    def mux2(self, selector: int, when_true: int, when_false: int) -> int:
        output = self._output("mux", (selector, when_true, when_false))
        self.clauses.extend(
            (
                (-selector, -when_true, output),
                (-selector, when_true, -output),
                (selector, -when_false, output),
                (selector, when_false, -output),
            )
        )
        return output

    def counts(self) -> Counts:
        clauses = len(self.clauses)
        units = sum(len(clause) == 1 for clause in self.clauses)
        return Counts(
            variables=self._next_variable - 1 - len(self.input_variables),
            clauses=clauses,
            literal_slots=sum(map(len, self.clauses)),
            unit_clauses=units,
            watch_entries=2 * (clauses - units),
        )

    @staticmethod
    def _literal_value(literal: int, assignment: Mapping[int, bool]) -> bool:
        value = assignment[abs(literal)]
        return value if literal > 0 else not value

    def evaluate(self, inputs: Mapping[int, bool]) -> dict[int, bool]:
        if set(inputs) != set(self.input_variables):
            raise CensusError("circuit input assignment is incomplete")
        assignment = dict(inputs)
        for operation, output, arguments in self.operations:
            values = [self._literal_value(argument, assignment) for argument in arguments]
            if operation == "and":
                result = values[0] and values[1]
            elif operation == "or":
                result = values[0] or values[1]
            elif operation == "xor":
                result = values[0] != values[1]
            elif operation == "xnor":
                result = values[0] == values[1]
            elif operation == "mux":
                result = values[1] if values[0] else values[2]
            else:
                raise ProjectionInvariant(f"unknown circuit operation {operation}")
            assignment[output] = result
        return assignment

    def clauses_hold(self, assignment: Mapping[int, bool]) -> bool:
        return all(
            any(self._literal_value(literal, assignment) for literal in clause)
            for clause in self.clauses
        )


def build_increment_circuit(circuit: CnfCircuit, bits: Sequence[int]) -> tuple[int, ...]:
    if not bits:
        raise CensusError("increment circuit needs at least one bit")
    output = [-bits[0]]
    carry = bits[0]
    for index, bit in enumerate(bits[1:], start=1):
        output.append(circuit.xor2(bit, carry))
        if index + 1 < len(bits):
            carry = circuit.and2(bit, carry)
    return tuple(output)


def build_unsigned_greater_circuit(
    circuit: CnfCircuit, left: Sequence[int], right: Sequence[int]
) -> int:
    if not left or len(left) != len(right):
        raise CensusError("greater-than inputs must have the same positive width")
    high = len(left) - 1
    greater = circuit.and2(left[high], -right[high])
    if high == 0:
        return greater
    equal = circuit.xnor2(left[high], right[high])
    for index in range(high - 1, -1, -1):
        bit_greater = circuit.and2(left[index], -right[index])
        greater = circuit.mux2(equal, bit_greater, greater)
        if index:
            bit_equal = circuit.xnor2(left[index], right[index])
            equal = circuit.and2(equal, bit_equal)
    return greater


def build_restricted_growth_circuit(
    circuit: CnfCircuit, codes: Sequence[Sequence[int]]
) -> None:
    if not codes or any(len(code) != len(codes[0]) for code in codes):
        raise CensusError("restricted-growth codes must have one common width")
    width = len(codes[0])
    if width != component_width(len(codes)):
        raise CensusError("restricted-growth circuit width drift")
    for bit in codes[0]:
        circuit.unit(-bit)
    prefix_max = tuple(codes[0])
    for index, code in enumerate(codes[1:], start=1):
        bound = build_increment_circuit(circuit, prefix_max)
        violation = build_unsigned_greater_circuit(circuit, code, bound)
        circuit.unit(-violation)
        if index + 1 < len(codes):
            is_greater = build_unsigned_greater_circuit(circuit, code, prefix_max)
            prefix_max = tuple(
                circuit.mux2(is_greater, bit, old)
                for bit, old in zip(code, prefix_max)
            )


def build_equality_link_circuit(
    circuit: CnfCircuit,
    equality: int,
    left: Sequence[int],
    right: Sequence[int],
) -> None:
    if not left or len(left) != len(right):
        raise CensusError("equality-link inputs must have the same positive width")
    equal_bits = [circuit.xnor2(a, b) for a, b in zip(left, right)]
    circuit.clauses.extend((-equality, equal_bit) for equal_bit in equal_bits)
    circuit.clauses.append((equality, *(-equal_bit for equal_bit in equal_bits)))


class TypedUnionFind:
    def __init__(self, problem: qfuf.EncodedProblem) -> None:
        self.problem = problem
        self.parent = list(range(len(problem.terms)))
        self.size = [1] * len(problem.terms)

    def find(self, item: int) -> int:
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != item:
            parent = self.parent[item]
            self.parent[item] = root
            item = parent
        return root

    def union(self, left: int, right: int) -> None:
        if self.problem.terms[left].sort != self.problem.terms[right].sort:
            raise ProjectionInvariant(
                f"component union crosses sorts at terms {left} and {right}"
            )
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        if self.size[left_root] < self.size[right_root] or (
            self.size[left_root] == self.size[right_root]
            and left_root > right_root
        ):
            left_root, right_root = right_root, left_root
        self.parent[right_root] = left_root
        self.size[left_root] += self.size[right_root]

    def union_all(self, terms: Iterable[int]) -> None:
        ordered = sorted(set(terms))
        if not ordered:
            return
        first = ordered[0]
        for term in ordered[1:]:
            self.union(first, term)


class EqualityGraph:
    def __init__(self, term_count: int, edge_cap: int) -> None:
        self.adjacency = [set() for _ in range(term_count)]
        self.edge_cap = edge_cap
        self.edges = 0

    def add_edge(self, left: int, right: int) -> bool:
        if left == right:
            return False
        if right in self.adjacency[left]:
            return False
        observed = self.edges + 1
        if observed > self.edge_cap:
            raise ProjectionCap("equality_edges", self.edge_cap, observed)
        self.adjacency[left].add(right)
        self.adjacency[right].add(left)
        self.edges = observed
        return True

    def add_clique(self, terms: Iterable[int]) -> int:
        ordered = sorted(set(terms))
        added = 0
        for left_index, left in enumerate(ordered):
            for right in ordered[left_index + 1 :]:
                added += int(self.add_edge(left, right))
        return added


def chordal_complete(
    graph: EqualityGraph, caps: Caps
) -> tuple[int, int, tuple[int, ...]]:
    """Replicate deterministic minimum-degree fill and count final triangles."""

    active = [bool(neighbors) for neighbors in graph.adjacency]
    degree = [len(neighbors) for neighbors in graph.adjacency]
    queue = [
        (degree[vertex], vertex)
        for vertex in range(len(active))
        if active[vertex]
    ]
    heapq.heapify(queue)
    fill_edges = 0
    triangles = 0
    elimination: list[int] = []
    while queue:
        queued_degree, vertex = heapq.heappop(queue)
        if not active[vertex] or degree[vertex] != queued_degree:
            continue
        neighbors = sorted(
            neighbor for neighbor in graph.adjacency[vertex] if active[neighbor]
        )
        if len(neighbors) != degree[vertex]:
            raise ProjectionInvariant("active equality degree drift")
        for left_index, left in enumerate(neighbors):
            for right in neighbors[left_index + 1 :]:
                if graph.add_edge(left, right):
                    fill_edges += 1
                    if fill_edges > caps.max_fill_edges:
                        raise ProjectionCap(
                            "fill_edges", caps.max_fill_edges, fill_edges
                        )
                    degree[left] += 1
                    degree[right] += 1
                    heapq.heappush(queue, (degree[left], left))
                    heapq.heappush(queue, (degree[right], right))
        triangles += choose2(len(neighbors))
        _checked(triangles, caps.max_projected_count, "equality_triangles")
        active[vertex] = False
        elimination.append(vertex)
        for neighbor in neighbors:
            degree[neighbor] -= 1
            heapq.heappush(queue, (degree[neighbor], neighbor))
    return fill_edges, triangles, tuple(elimination)


def _application_groups(
    problem: qfuf.EncodedProblem,
) -> dict[int, tuple[int, ...]]:
    groups: dict[int, list[int]] = defaultdict(list)
    for term in problem.terms:
        if term.args:
            groups[term.function].append(term.id)
    return {
        function: tuple(sorted(term_ids))
        for function, term_ids in sorted(groups.items())
    }


def build_components(
    problem: qfuf.EncodedProblem,
    groups: Mapping[int, Sequence[int]],
    caps: Caps,
) -> tuple[tuple[Component, ...], dict[int, Component]]:
    union_find = TypedUnionFind(problem)
    for atom in problem.atoms:
        if atom.kind != "equality":
            continue
        if atom.left is None or atom.right is None:
            raise ProjectionInvariant("typed equality atom is incomplete")
        union_find.union(atom.left, atom.right)

    for function_id, applications in groups.items():
        function = problem.functions[function_id]
        if function.result_sort != qfuf.BOOL_SORT:
            union_find.union_all(applications)
        for position, sort_id in enumerate(function.arg_sorts):
            if sort_id == qfuf.BOOL_SORT:
                continue
            union_find.union_all(problem.terms[term].args[position] for term in applications)

    by_root: dict[int, list[int]] = defaultdict(list)
    for term in problem.terms:
        if term.sort != qfuf.BOOL_SORT:
            by_root[union_find.find(term.id)].append(term.id)
    ordered_groups = sorted(
        (problem.terms[terms[0]].sort, tuple(sorted(terms)))
        for terms in by_root.values()
    )
    components: list[Component] = []
    term_components: dict[int, Component] = {}
    for component_id, (sort_id, terms) in enumerate(ordered_groups):
        if len(terms) > caps.max_component_terms:
            raise ProjectionCap(
                "component_terms", caps.max_component_terms, len(terms)
            )
        if any(problem.terms[term].sort != sort_id for term in terms):
            raise ProjectionInvariant("component contains mixed sorts")
        component = Component(
            component_id, sort_id, terms, component_width(len(terms))
        )
        components.append(component)
        for term in terms:
            if term in term_components:
                raise ProjectionInvariant("term belongs to two components")
            term_components[term] = component
    expected_non_boolean = {
        term.id for term in problem.terms if term.sort != qfuf.BOOL_SORT
    }
    if set(term_components) != expected_non_boolean:
        raise ProjectionInvariant("component map does not cover non-Boolean terms")
    return tuple(components), term_components


def _term_channel(
    problem: qfuf.EncodedProblem,
    term_id: int,
    term_components: Mapping[int, Component],
    bool_variables: Mapping[int, int],
) -> tuple[str, int, int | None]:
    term = problem.terms[term_id]
    if term.sort == qfuf.BOOL_SORT:
        if term_id not in bool_variables:
            raise ProjectionInvariant(
                f"Boolean term {term_id} lacks an independent Boolean atom"
            )
        return "boolean", 1, None
    component = term_components.get(term_id)
    if component is None or component.sort != term.sort:
        raise ProjectionInvariant(f"term {term_id} lacks a typed component")
    return "component", component.width, component.id


def _counts_within_cap(counts: Counts, caps: Caps, context: str) -> Counts:
    for field, value in asdict(counts).items():
        _checked(value, caps.max_projected_count, f"{context}_{field}")
    return counts


def _sum_categories(
    categories: Mapping[str, Counts], caps: Caps, context: str
) -> Counts:
    total = ZERO_COUNTS
    for name in sorted(categories):
        total += categories[name]
        _counts_within_cap(total, caps, f"{context}_{name}")
    return total


def _ppm_ratio(candidate: int, baseline: int) -> int | None:
    if baseline == 0:
        return 0 if candidate == 0 else None
    return candidate * PPM // baseline


def _base_record(
    source: ManifestSource,
    lock: CampaignLock,
    manifest_sha256: str,
    parser_sha256: str,
) -> dict[str, object]:
    return {
        "schema": RECORD_SCHEMA,
        "sequence": -1,
        "previous_record_sha256": None,
        "record_sha256": "",
        "lock_sha256": lock.sha256,
        "campaign_id": lock.campaign_id,
        "interpretation": INTERPRETATION,
        "parser_api": PARSER_API,
        "parser_sha256": parser_sha256,
        "taxonomy_builder_sha256": sha256_path(TAXONOMY_PATH),
        "manifest": {
            "sha256": manifest_sha256,
            "record_line": source.line_number,
        },
        "source": {
            "id": source.record_id,
            "relative_path": source.relative_path,
            "bytes": len(source.source_bytes),
            "sha256": source.source_sha256,
        },
        "taxonomy": {
            "source_family": source.source_family,
            "generator_lineage": source.generator_lineage,
            "rule": source.taxonomy_rule,
        },
        "status": "unprocessed",
        "reason": None,
        "cap_events": [],
        "shape": {},
        "components": [],
        "symbols": [],
        "counts": {"eager": {}, "component_quotient_ram": {}},
        "decoder": {"complete": False, "reason": "not_projected"},
        "selector": {
            "eligible": False,
            "minimum_total_applications": lock.minimum_total_applications,
            "minimum_max_symbol_applications": lock.minimum_max_symbol_applications,
        },
        "ratios_ppm": {},
    }


def _mark_unknown(
    record: dict[str, object], reason: str, cap: ProjectionCap | None = None
) -> dict[str, object]:
    record["status"] = "unknown_projection"
    record["reason"] = reason
    record["decoder"] = {"complete": False, "reason": reason}
    if cap is not None:
        record["cap_events"] = [
            {"code": cap.code, "limit": cap.limit, "observed": cap.observed}
        ]
    return record


def project_problem(
    problem: qfuf.EncodedProblem, caps: Caps
) -> dict[str, object]:
    term_count = len(problem.terms)
    if term_count > caps.max_terms:
        raise ProjectionCap("terms", caps.max_terms, term_count)
    groups = _application_groups(problem)
    applications = sum(map(len, groups.values()))
    if applications > caps.max_applications:
        raise ProjectionCap("applications", caps.max_applications, applications)
    if len(groups) > caps.max_symbols:
        raise ProjectionCap("symbols", caps.max_symbols, len(groups))
    argument_slots = sum(
        len(problem.terms[term_id].args)
        for term_ids in groups.values()
        for term_id in term_ids
    )

    bool_variables = {
        atom.term: atom.variable
        for atom in problem.atoms
        if atom.kind == "bool_term" and atom.term is not None
    }
    components, term_components = build_components(problem, groups, caps)
    component_rows: list[dict[str, object]] = []
    quotient_class_bits = 0
    canonicalization = ZERO_COUNTS
    for component in components:
        class_bits = len(component.terms) * component.width
        quotient_class_bits += class_bits
        _checked(quotient_class_bits, caps.max_projected_count, "class_bits")
        component_canonicalization = restricted_growth_counts(
            len(component.terms), component.width
        )
        canonicalization += component_canonicalization
        _counts_within_cap(canonicalization, caps, "canonicalization")
        sort = problem.sorts[component.sort]
        component_rows.append(
            {
                "id": component.id,
                "sort": {
                    "id": sort.id,
                    "name": sort.name,
                    "quoted": sort.quoted,
                },
                "terms": len(component.terms),
                "first_term": component.terms[0],
                "last_term": component.terms[-1],
                "width": component.width,
                "class_bits": class_bits,
                "canonicalization": component_canonicalization.to_json(),
            }
        )

    eager_graph = EqualityGraph(term_count, caps.max_equality_edges)
    reflexive_atoms: set[int] = set()
    source_equality_pairs: set[tuple[int, int]] = set()
    equality_atoms = 0
    for atom in problem.atoms:
        if atom.kind != "equality":
            continue
        equality_atoms += 1
        if atom.left is None or atom.right is None:
            raise ProjectionInvariant("equality atom is incomplete")
        left, right = sorted((atom.left, atom.right))
        if left == right:
            reflexive_atoms.add(left)
        else:
            source_equality_pairs.add((left, right))
            eager_graph.add_edge(left, right)
    initial_equality_edges = eager_graph.edges

    eager_ackermann_clauses = 0
    eager_ackermann_literals = 0
    ackermann_pairs = 0
    symbol_rows: list[dict[str, object]] = []
    cqram_sorter = ZERO_COUNTS
    cqram_adjacency = ZERO_COUNTS
    sorter_comparators = 0
    padded_record_bits = 0
    logical_record_bits = 0
    needs_sorter_constant = False

    for function_id, term_ids in groups.items():
        function = problem.functions[function_id]
        application_count = len(term_ids)
        pairs = choose2(application_count)
        ackermann_pairs += pairs
        if ackermann_pairs > caps.max_ackermann_pairs:
            raise ProjectionCap(
                "ackermann_pairs", caps.max_ackermann_pairs, ackermann_pairs
            )
        differing_by_position: list[int] = []
        argument_rows: list[dict[str, object]] = []
        for position, sort_id in enumerate(function.arg_sorts):
            values = [problem.terms[term_id].args[position] for term_id in term_ids]
            frequencies = Counter(values)
            differing = pairs - sum(choose2(count) for count in frequencies.values())
            differing_by_position.append(differing)
            eager_graph.add_clique(values)
            channel, width, component_id = _term_channel(
                problem, values[0], term_components, bool_variables
            )
            if any(
                _term_channel(problem, value, term_components, bool_variables)
                != (channel, width, component_id)
                for value in values
            ):
                raise ProjectionInvariant(
                    f"function {function_id} argument position {position} spans namespaces"
                )
            argument_rows.append(
                {
                    "position": position,
                    "sort": sort_id,
                    "channel": channel,
                    "component_id": component_id,
                    "width": width,
                    "distinct_terms": len(frequencies),
                    "differing_application_pairs": differing,
                }
            )

        result_channel, result_width, result_component_id = _term_channel(
            problem, term_ids[0], term_components, bool_variables
        )
        if any(
            _term_channel(problem, term_id, term_components, bool_variables)
            != (result_channel, result_width, result_component_id)
            for term_id in term_ids
        ):
            raise ProjectionInvariant(f"function {function_id} results span namespaces")
        differing_total = sum(differing_by_position)
        if function.result_sort == qfuf.BOOL_SORT:
            ackermann_clauses = 2 * pairs
            ackermann_literals = 4 * pairs + 2 * differing_total
        else:
            eager_graph.add_clique(term_ids)
            ackermann_clauses = pairs
            ackermann_literals = pairs + differing_total
        eager_ackermann_clauses += ackermann_clauses
        eager_ackermann_literals += ackermann_literals
        _checked(
            eager_ackermann_clauses,
            caps.max_projected_count,
            "ackermann_clauses",
        )
        _checked(
            eager_ackermann_literals,
            caps.max_projected_count,
            "ackermann_literal_slots",
        )

        key_width = sum(int(row["width"]) for row in argument_rows)
        value_width = result_width
        symbol_sorter = ZERO_COUNTS
        symbol_adjacency = ZERO_COUNTS
        padded_records = application_count
        comparators = 0
        record_width = key_width + value_width + 1
        logical_record_bits += application_count * record_width
        if application_count >= 2:
            needs_sorter_constant = True
            padded_records = next_power_of_two(application_count)
            if padded_records > caps.max_sorter_records:
                raise ProjectionCap(
                    "sorter_records", caps.max_sorter_records, padded_records
                )
            comparators = bitonic_comparator_count(padded_records)
            sorter_comparators += comparators
            if sorter_comparators > caps.max_sorter_comparators:
                raise ProjectionCap(
                    "sorter_comparators",
                    caps.max_sorter_comparators,
                    sorter_comparators,
                )
            comparison_width = key_width + 1
            comparator = unsigned_greater_counts(comparison_width) + MUX2.scale(
                2 * record_width
            )
            symbol_sorter = comparator.scale(comparators)
            one_adjacency = XNOR2.scale(key_width) + Counts(
                clauses=2 * value_width,
                literal_slots=2 * value_width * (key_width + 4),
                watch_entries=4 * value_width,
            )
            symbol_adjacency = one_adjacency.scale(padded_records - 1)
            cqram_sorter += symbol_sorter
            cqram_adjacency += symbol_adjacency
        padded_record_bits += padded_records * record_width
        if padded_record_bits > caps.max_packed_record_bits:
            raise ProjectionCap(
                "packed_record_bits",
                caps.max_packed_record_bits,
                padded_record_bits,
            )
        symbol_rows.append(
            {
                "function": {
                    "id": function.id,
                    "name": function.name,
                    "quoted": function.quoted,
                    "internal": function.internal,
                },
                "signature": {
                    "argument_sorts": list(function.arg_sorts),
                    "result_sort": function.result_sort,
                },
                "applications": application_count,
                "ackermann_pairs": pairs,
                "arguments": argument_rows,
                "result": {
                    "channel": result_channel,
                    "component_id": result_component_id,
                    "width": result_width,
                },
                "eager_ackermann": {
                    "clauses": ackermann_clauses,
                    "literal_slots": ackermann_literals,
                },
                "cqram": {
                    "key_width": key_width,
                    "value_width": value_width,
                    "record_width": record_width,
                    "padded_records": padded_records,
                    "comparators": comparators,
                    "network_depth": (
                        (padded_records.bit_length() - 1)
                        * padded_records.bit_length()
                        // 2
                    ),
                    "sorter": symbol_sorter.to_json(),
                    "adjacency": symbol_adjacency.to_json(),
                },
            }
        )

    ackermann_equality_edges = eager_graph.edges - initial_equality_edges
    fill_edges, triangle_count, elimination = chordal_complete(eager_graph, caps)
    eager_categories = {
        "ackermann": Counts(
            variables=ackermann_equality_edges,
            clauses=eager_ackermann_clauses,
            literal_slots=eager_ackermann_literals,
            watch_entries=2 * eager_ackermann_clauses,
        ),
        "chordal_fill": Counts(variables=fill_edges),
        "transitivity": UNIT.scale(len(reflexive_atoms))
        + Counts(
            clauses=3 * triangle_count,
            literal_slots=9 * triangle_count,
            watch_entries=6 * triangle_count,
        ),
    }
    eager_total = _sum_categories(eager_categories, caps, "eager")

    equality_links = ZERO_COUNTS
    for atom in problem.atoms:
        if atom.kind != "equality":
            continue
        assert atom.left is not None and atom.right is not None
        if atom.left == atom.right:
            equality_links += UNIT
            continue
        left_term = problem.terms[atom.left]
        right_term = problem.terms[atom.right]
        if left_term.sort != right_term.sort:
            raise ProjectionInvariant("source equality crosses sorts")
        if left_term.sort == qfuf.BOOL_SORT:
            _term_channel(problem, atom.left, term_components, bool_variables)
            _term_channel(problem, atom.right, term_components, bool_variables)
            equality_links += XNOR2 + Counts(
                clauses=2, literal_slots=4, watch_entries=4
            )
        else:
            left_component = term_components[atom.left]
            right_component = term_components[atom.right]
            if left_component.id != right_component.id:
                raise ProjectionInvariant("equality endpoints occupy different components")
            equality_links += equality_link_counts(left_component.width)

    bool_domain = ZERO_COUNTS
    if problem.true_term in bool_variables:
        bool_domain += UNIT
    if problem.false_term in bool_variables:
        bool_domain += UNIT
    cqram_categories = {
        "class_codes": Counts(variables=quotient_class_bits),
        "restricted_growth": canonicalization,
        "equality_links": equality_links,
        "boolean_domain": bool_domain,
        "sorter_constant": UNIT_WITH_VARIABLE if needs_sorter_constant else ZERO_COUNTS,
        "sorters": cqram_sorter,
        "adjacent_consistency": cqram_adjacency,
    }
    cqram_total = _sum_categories(cqram_categories, caps, "cqram")

    relevant_bool_terms: set[int] = set()
    for term_ids in groups.values():
        for term_id in term_ids:
            term = problem.terms[term_id]
            if term.sort == qfuf.BOOL_SORT:
                relevant_bool_terms.add(term_id)
            relevant_bool_terms.update(
                argument
                for argument in term.args
                if problem.terms[argument].sort == qfuf.BOOL_SORT
            )
    if not relevant_bool_terms.issubset(bool_variables):
        missing = sorted(relevant_bool_terms - set(bool_variables))
        raise ProjectionInvariant(f"decoder lacks Boolean terms {missing[:8]}")

    decoder_counts = {
        "assignment_bits_read": quotient_class_bits + len(bool_variables),
        "term_codes_materialized": len(problem.terms),
        "equality_atoms_checked": equality_atoms,
        "argument_code_lookups": argument_slots,
        "result_code_lookups": applications,
        "records_checked": applications,
        "map_probes": 2 * applications,
        "logical_record_bits": logical_record_bits,
        "padded_record_bits": padded_record_bits,
        "sorter_comparators_replayed": sorter_comparators,
        "maximum_symbol_records": max(map(len, groups.values()), default=0),
        "sort_defaults_materialized": len(problem.sorts),
    }
    decoder_operations = sum(
        value
        for key, value in decoder_counts.items()
        if key not in {"maximum_symbol_records", "padded_record_bits"}
    )
    if decoder_operations > caps.max_decoder_operations:
        raise ProjectionCap(
            "decoder_operations", caps.max_decoder_operations, decoder_operations
        )
    decoder_counts["total_operations"] = decoder_operations

    shape = {
        "sorts": len(problem.sorts),
        "terms": term_count,
        "non_boolean_terms": sum(
            term.sort != qfuf.BOOL_SORT for term in problem.terms
        ),
        "boolean_terms": sum(term.sort == qfuf.BOOL_SORT for term in problem.terms),
        "applications": applications,
        "application_symbols": len(groups),
        "maximum_symbol_applications": max(map(len, groups.values()), default=0),
        "argument_slots": argument_slots,
        "source_equality_atoms": equality_atoms,
        "source_boolean_atoms": len(bool_variables),
        "components": len(components),
        "maximum_component_terms": max(
            (len(component.terms) for component in components), default=0
        ),
        "ackermann_pairs": ackermann_pairs,
        "initial_equality_edges": initial_equality_edges,
        "ackermann_equality_edges": ackermann_equality_edges,
        "chordal_fill_edges": fill_edges,
        "completed_equality_edges": eager_graph.edges,
        "completed_equality_triangles": triangle_count,
        "eliminated_equality_vertices": len(elimination),
    }
    return {
        "shape": shape,
        "components": component_rows,
        "symbols": symbol_rows,
        "counts": {
            "eager": {
                "categories": {
                    name: counts.to_json()
                    for name, counts in sorted(eager_categories.items())
                },
                "total": eager_total.to_json(),
            },
            "component_quotient_ram": {
                "categories": {
                    name: counts.to_json()
                    for name, counts in sorted(cqram_categories.items())
                },
                "total": cqram_total.to_json(),
            },
        },
        "decoder": {
            "complete": True,
            "domain_value": "typed_tuple_sort_id_component_id_class_code",
            "boolean_carrier": "false_true",
            "unobserved_function_completion": "typed_arbitrary_default",
            "counts": decoder_counts,
        },
        "ratios_ppm": {
            field: _ppm_ratio(
                getattr(cqram_total, field), getattr(eager_total, field)
            )
            for field in Counts.__dataclass_fields__
        },
    }


def analyze_source(
    source: ManifestSource,
    lock: CampaignLock,
    manifest_sha256: str,
    parser_sha256: str,
) -> dict[str, object]:
    record = _base_record(source, lock, manifest_sha256, parser_sha256)
    if len(source.source_bytes) > lock.caps.max_source_bytes:
        cap = ProjectionCap(
            "source_bytes", lock.caps.max_source_bytes, len(source.source_bytes)
        )
        return _mark_unknown(record, "source_byte_cap", cap)
    try:
        source_text = source.source_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        record["status"] = "parse_error"
        record["reason"] = f"source is not UTF-8: {error}"
        return record
    try:
        problem = qfuf.parse_and_encode(source_text)
    except qfuf.IndependentQfufError as error:
        record["status"] = "parse_error"
        record["reason"] = str(error)
        return record
    try:
        projection = project_problem(problem, lock.caps)
    except ProjectionCap as error:
        return _mark_unknown(record, error.code, error)
    except ProjectionInvariant as error:
        return _mark_unknown(record, f"typed_projection_invariant: {error}")
    record.update(projection)
    record["status"] = "projected"
    record["reason"] = None
    shape = record["shape"]
    assert isinstance(shape, dict)
    selector = record["selector"]
    assert isinstance(selector, dict)
    selector["eligible"] = (
        int(shape["applications"]) >= lock.minimum_total_applications
        and int(shape["maximum_symbol_applications"])
        >= lock.minimum_max_symbol_applications
    )
    return record


def _record_digest(record: Mapping[str, object]) -> str:
    unhashed = dict(record)
    unhashed.pop("record_sha256", None)
    return sha256_bytes(canonical_json_bytes(unhashed))


def chain_records(records: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    chained: list[dict[str, object]] = []
    previous: str | None = GENESIS_HASH
    for sequence, source_record in enumerate(records):
        record = dict(source_record)
        record["sequence"] = sequence
        record["previous_record_sha256"] = previous
        record["record_sha256"] = _record_digest(record)
        previous = str(record["record_sha256"])
        chained.append(record)
    return chained


def verify_record_stream(
    records_bytes: bytes, expected_sources: int, lock_sha256: str
) -> list[dict[str, object]]:
    try:
        text = records_bytes.decode("ascii")
    except UnicodeDecodeError as error:
        raise CensusError("record stream must be ASCII") from error
    if records_bytes and not text.endswith("\n"):
        raise CensusError("record stream ends with a partial line")
    lines = text.splitlines()
    if len(lines) != expected_sources:
        raise CensusError(
            f"record cardinality mismatch: expected {expected_sources}, got {len(lines)}"
        )
    previous: str | None = GENESIS_HASH
    records: list[dict[str, object]] = []
    seen_paths: set[str] = set()
    last_path: str | None = None
    for line_number, line in enumerate(lines, 1):
        if not line:
            raise CensusError(f"record stream line {line_number} is blank")
        try:
            value = family_manifest.strict_json_loads(line)
        except (json.JSONDecodeError, ValueError) as error:
            raise CensusError(
                f"record stream line {line_number} is malformed: {error}"
            ) from error
        if type(value) is not dict:
            raise CensusError(f"record stream line {line_number} is not an object")
        record = value
        if record.get("schema") != RECORD_SCHEMA:
            raise CensusError(f"record stream line {line_number} has schema drift")
        if record.get("sequence") != line_number - 1:
            raise CensusError(f"record stream line {line_number} breaks sequence")
        if record.get("lock_sha256") != lock_sha256:
            raise CensusError(f"record stream line {line_number} has lock drift")
        if record.get("previous_record_sha256") != previous:
            raise CensusError(f"record stream line {line_number} breaks hash chain")
        record_hash = record.get("record_sha256")
        if not _is_lower_sha256(record_hash):
            raise CensusError(f"record stream line {line_number} has invalid hash")
        if _record_digest(record) != record_hash:
            raise CensusError(f"record stream line {line_number} has hash drift")
        source = record.get("source")
        if type(source) is not dict or not isinstance(source.get("relative_path"), str):
            raise CensusError(f"record stream line {line_number} lacks source path")
        relative_path = source["relative_path"]
        if relative_path in seen_paths:
            raise CensusError(f"record stream duplicates {relative_path!r}")
        if last_path is not None and relative_path <= last_path:
            raise CensusError("record stream is not in strict source-path order")
        seen_paths.add(relative_path)
        last_path = relative_path
        previous = record_hash
        records.append(record)
    return records


def _total_counts(record: Mapping[str, object], encoding: str) -> dict[str, int]:
    counts = record.get("counts")
    if type(counts) is not dict:
        raise CensusError("projected record lacks counts")
    encoding_counts = counts.get(encoding)
    if type(encoding_counts) is not dict or type(encoding_counts.get("total")) is not dict:
        raise CensusError(f"projected record lacks {encoding} total")
    total = encoding_counts["total"]
    expected = set(Counts.__dataclass_fields__)
    if set(total) != expected or any(type(total[field]) is not int for field in expected):
        raise CensusError(f"projected record has malformed {encoding} total")
    return total


def _ceil_fraction(value: int, ratio: Ratio) -> int:
    return (value * ratio.numerator + ratio.denominator - 1) // ratio.denominator


def _candidate_within_reduction(
    candidate: int, baseline: int, reduction: Ratio
) -> bool:
    if baseline <= 0:
        return False
    return candidate * reduction.denominator <= baseline * (
        reduction.denominator - reduction.numerator
    )


def _ratio_fraction(candidate: int, baseline: int) -> Fraction | None:
    if baseline == 0:
        return Fraction(0, 1) if candidate == 0 else None
    return Fraction(candidate, baseline)


def _fraction_ppm(value: Fraction | None) -> int | None:
    if value is None:
        return None
    return value.numerator * PPM // value.denominator


def _median_ratio(values: Sequence[tuple[int, int]]) -> Fraction | None:
    if not values:
        return None
    ratios = [_ratio_fraction(candidate, baseline) for candidate, baseline in values]
    ratios.sort(
        key=lambda ratio: (ratio is None, Fraction(0, 1) if ratio is None else ratio)
    )
    middle = len(ratios) // 2
    if len(ratios) % 2:
        return ratios[middle]
    left = ratios[middle - 1]
    right = ratios[middle]
    if left is None or right is None:
        return None
    return (left + right) / 2


def _percentile_ratio(
    values: Sequence[tuple[int, int]], percentile: int
) -> Fraction | None:
    if not values:
        return None
    ratios = [_ratio_fraction(candidate, baseline) for candidate, baseline in values]
    ratios.sort(
        key=lambda ratio: (ratio is None, Fraction(0, 1) if ratio is None else ratio)
    )
    rank = (percentile * len(ratios) + 99) // 100
    return ratios[max(0, rank - 1)]


def _at_most(value: Fraction | None, maximum: Ratio) -> bool:
    return value is not None and value <= Fraction(
        maximum.numerator, maximum.denominator
    )


def _opportunity_metric_gate(
    records: Sequence[Mapping[str, object]], metric: str, lock: CampaignLock
) -> dict[str, object]:
    pairs = [
        (
            _total_counts(record, "component_quotient_ram")[metric],
            _total_counts(record, "eager")[metric],
        )
        for record in records
    ]
    candidate_total = sum(candidate for candidate, _ in pairs)
    eager_total = sum(eager for _, eager in pairs)
    median = _median_ratio(pairs)
    target_ratio = Fraction(
        lock.opportunity_reduction.denominator
        - lock.opportunity_reduction.numerator,
        lock.opportunity_reduction.denominator,
    )
    individual = sum(
        _candidate_within_reduction(candidate, eager, lock.opportunity_reduction)
        for candidate, eager in pairs
    )
    required_individual = _ceil_fraction(
        len(records), lock.minimum_individual_fraction
    )
    weighted_pass = _candidate_within_reduction(
        candidate_total, eager_total, lock.opportunity_reduction
    )
    median_pass = median is not None and median <= target_ratio
    individual_pass = individual >= required_individual
    return {
        "metric": metric,
        "candidate_total": candidate_total,
        "eager_total": eager_total,
        "weighted_ratio_ppm": _ppm_ratio(candidate_total, eager_total),
        "median_ratio_ppm": _fraction_ppm(median),
        "individual_passing": individual,
        "individual_required": required_individual,
        "weighted_pass": weighted_pass,
        "median_pass": median_pass,
        "individual_pass": individual_pass,
        "pass": weighted_pass and median_pass and individual_pass,
    }


def _variable_gate(
    records: Sequence[Mapping[str, object]], lock: CampaignLock
) -> dict[str, object]:
    pairs = [
        (
            _total_counts(record, "component_quotient_ram")["variables"],
            _total_counts(record, "eager")["variables"],
        )
        for record in records
    ]
    candidate_total = sum(candidate for candidate, _ in pairs)
    eager_total = sum(eager for _, eager in pairs)
    weighted = _ratio_fraction(candidate_total, eager_total)
    percentile = _percentile_ratio(pairs, lock.variable_percentile)
    weighted_pass = _at_most(weighted, lock.variable_maximum)
    percentile_pass = _at_most(percentile, lock.variable_maximum)
    return {
        "candidate_total": candidate_total,
        "eager_total": eager_total,
        "weighted_ratio_ppm": _fraction_ppm(weighted),
        "percentile": lock.variable_percentile,
        "percentile_ratio_ppm": _fraction_ppm(percentile),
        "weighted_pass": weighted_pass,
        "percentile_pass": percentile_pass,
        "pass": weighted_pass and percentile_pass,
    }


def _target_rows(records: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    for record in records:
        selector = record.get("selector")
        if type(selector) is not dict or selector.get("eligible") is not True:
            continue
        source = record["source"]
        taxonomy = record["taxonomy"]
        shape = record["shape"]
        assert isinstance(source, dict)
        assert isinstance(taxonomy, dict)
        assert isinstance(shape, dict)
        targets.append(
            {
                "schema": TARGET_SCHEMA,
                "sequence": record["sequence"],
                "source": {
                    "id": source["id"],
                    "relative_path": source["relative_path"],
                    "sha256": source["sha256"],
                },
                "taxonomy": taxonomy,
                "shape": {
                    "applications": shape["applications"],
                    "maximum_symbol_applications": shape[
                        "maximum_symbol_applications"
                    ],
                },
                "record_sha256": record["record_sha256"],
            }
        )
    return targets


def aggregate_records(
    records: Sequence[dict[str, object]],
    lock: CampaignLock,
    *,
    manifest_sha256: str,
    portable_source_set_sha256: str,
    records_sha256: str,
    terminal_record_sha256: str | None,
    targets_sha256: str,
    parser_sha256: str,
    taxonomy_builder_sha256: str,
    analyzer_sha256: str,
) -> dict[str, object]:
    statuses = Counter(str(record.get("status")) for record in records)
    cap_events = Counter(
        str(event["code"])
        for record in records
        for event in record.get("cap_events", [])  # type: ignore[union-attr]
    )
    decoder_incomplete = sum(
        type(record.get("decoder")) is not dict
        or record["decoder"].get("complete") is not True  # type: ignore[union-attr]
        for record in records
    )
    family_population_match = True
    family_gates: dict[str, object] = {}
    for family in lock.families:
        population_records = [
            record
            for record in records
            if record["taxonomy"]["source_family"] == family.source_family  # type: ignore[index]
        ]
        targets = [
            record
            for record in population_records
            if record["selector"]["eligible"] is True  # type: ignore[index]
        ]
        population_match = len(population_records) == family.expected_population
        family_population_match &= population_match
        required_targets = _ceil_fraction(
            family.expected_population, lock.broadness_fraction
        )
        lineages = {
            str(record["taxonomy"]["generator_lineage"])  # type: ignore[index]
            for record in targets
        }
        broadness_pass = (
            population_match
            and len(targets) >= required_targets
            and len(lineages) >= lock.minimum_generator_lineages
        )
        metric_gates = {
            metric: _opportunity_metric_gate(targets, metric, lock)
            for metric in lock.opportunity_metrics
        }
        opportunity_pass = any(
            bool(metric_gate["pass"]) for metric_gate in metric_gates.values()
        )
        variable_gate = _variable_gate(targets, lock)
        family_gates[family.key] = {
            "source_family": family.source_family,
            "expected_population": family.expected_population,
            "observed_population": len(population_records),
            "population_match": population_match,
            "target_sources": len(targets),
            "required_target_sources": required_targets,
            "target_generator_lineages": len(lineages),
            "required_generator_lineages": lock.minimum_generator_lineages,
            "broadness_pass": broadness_pass,
            "opportunity": metric_gates,
            "opportunity_pass": opportunity_pass,
            "variable_control": variable_gate,
            "pass": broadness_pass and opportunity_pass and bool(variable_gate["pass"]),
        }

    validity_checks = {
        "source_cardinality": len(records) == lock.expected_sources,
        "all_sources_projected": statuses == Counter({"projected": len(records)}),
        "zero_parse_errors": statuses.get("parse_error", 0) == 0,
        "zero_unknown_projections": statuses.get("unknown_projection", 0) == 0,
        "zero_cap_events": not cap_events,
        "complete_decoder_for_every_source": decoder_incomplete == 0,
        "family_populations_match": family_population_match,
    }
    validity_pass = all(validity_checks.values())
    implementation_allowed = validity_pass and all(
        isinstance(family_gate, dict) and family_gate.get("pass") is True
        for family_gate in family_gates.values()
    )

    aggregate_counts: dict[str, object] = {}
    projected_records = [record for record in records if record["status"] == "projected"]
    for encoding in ("eager", "component_quotient_ram"):
        aggregate_counts[encoding] = {
            field: sum(_total_counts(record, encoding)[field] for record in projected_records)
            for field in Counts.__dataclass_fields__
        }

    return {
        "schema": AGGREGATE_SCHEMA,
        "campaign_id": lock.campaign_id,
        "interpretation": INTERPRETATION,
        "parser_api": PARSER_API,
        "hashes": {
            "lock_sha256": lock.sha256,
            "input_manifest_sha256": manifest_sha256,
            "portable_source_set_sha256": portable_source_set_sha256,
            "analyzer_sha256": analyzer_sha256,
            "parser_sha256": parser_sha256,
            "taxonomy_builder_sha256": taxonomy_builder_sha256,
            "records_jsonl_sha256": records_sha256,
            "terminal_record_sha256": terminal_record_sha256,
            "derived_target_manifest_sha256": targets_sha256,
        },
        "sources": {
            "expected": lock.expected_sources,
            "observed": len(records),
            "statuses": dict(sorted(statuses.items())),
            "cap_events": dict(sorted(cap_events.items())),
            "decoder_incomplete": decoder_incomplete,
        },
        "aggregate_counts": aggregate_counts,
        "gates": {
            "validity": {"checks": validity_checks, "pass": validity_pass},
            "families": family_gates,
            "implementation_allowed": implementation_allowed,
        },
    }


def _atomic_write(artifacts: Sequence[tuple[Path, bytes]]) -> None:
    resolved = [Path(path).resolve(strict=False) for path, _ in artifacts]
    if len(set(resolved)) != len(resolved):
        raise CensusError("output paths must be distinct")
    staged: list[tuple[Path, Path]] = []
    try:
        for path, payload in artifacts:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
            )
            temporary = Path(temporary_name)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            staged.append((temporary, path))
        for temporary, path in staged:
            os.replace(temporary, path)
    finally:
        for temporary, _ in staged:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def run_census(
    manifest_path: Path,
    records_out: Path,
    aggregate_out: Path,
    targets_out: Path,
    *,
    repository_root: Path,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> tuple[list[dict[str, object]], dict[str, object], list[dict[str, object]]]:
    lock = load_campaign_lock(lock_path)
    protected = {
        Path(manifest_path).resolve(strict=False),
        Path(lock_path).resolve(strict=False),
        PARSER_PATH.resolve(strict=False),
        Path(__file__).resolve(strict=False),
    }
    outputs = {
        Path(records_out).resolve(strict=False),
        Path(aggregate_out).resolve(strict=False),
        Path(targets_out).resolve(strict=False),
    }
    if len(outputs) != 3 or protected & outputs:
        raise CensusError("outputs must be distinct and must not overwrite inputs")
    sources, manifest_bytes, portable_bytes = load_manifest(
        manifest_path, repository_root, lock.expected_sources
    )
    manifest_sha256 = sha256_bytes(manifest_bytes)
    parser_sha256 = sha256_path(PARSER_PATH)
    analyzed = [
        analyze_source(source, lock, manifest_sha256, parser_sha256)
        for source in sources
    ]
    records = chain_records(analyzed)
    records_bytes = b"".join(canonical_json_bytes(record) for record in records)
    verified = verify_record_stream(records_bytes, lock.expected_sources, lock.sha256)
    if verified != records:
        raise ProjectionInvariant("record stream changed during verification")
    targets = _target_rows(records)
    targets_bytes = b"".join(canonical_json_bytes(target) for target in targets)
    aggregate = aggregate_records(
        records,
        lock,
        manifest_sha256=manifest_sha256,
        portable_source_set_sha256=sha256_bytes(portable_bytes),
        records_sha256=sha256_bytes(records_bytes),
        terminal_record_sha256=(
            str(records[-1]["record_sha256"]) if records else None
        ),
        targets_sha256=sha256_bytes(targets_bytes),
        parser_sha256=parser_sha256,
        taxonomy_builder_sha256=sha256_path(TAXONOMY_PATH),
        analyzer_sha256=sha256_path(Path(__file__)),
    )
    _atomic_write(
        (
            (Path(records_out), records_bytes),
            (Path(targets_out), targets_bytes),
            (Path(aggregate_out), canonical_json_bytes(aggregate)),
        )
    )
    return records, aggregate, targets


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK_PATH)
    parser.add_argument("--records-out", type=Path, required=True)
    parser.add_argument("--aggregate-out", type=Path, required=True)
    parser.add_argument("--targets-out", type=Path, required=True)
    parser.add_argument(
        "--require-validity",
        action="store_true",
        help="return failure after writing diagnostics unless all sources project",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        records, aggregate, targets = run_census(
            args.manifest,
            args.records_out,
            args.aggregate_out,
            args.targets_out,
            repository_root=args.repository_root,
            lock_path=args.lock,
        )
    except CensusError as error:
        parser.exit(2, f"component quotient RAM census failed: {error}\n")
    validity = aggregate["gates"]["validity"]["pass"]  # type: ignore[index]
    print(
        f"sources={len(records)} targets={len(targets)} validity={str(validity).lower()} "
        "implementation_allowed="
        f"{str(aggregate['gates']['implementation_allowed']).lower()} "  # type: ignore[index]
        f"records_sha256={aggregate['hashes']['records_jsonl_sha256']}"  # type: ignore[index]
    )
    if args.require_validity and validity is not True:
        parser.exit(2, "component quotient RAM census validity gate failed\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
