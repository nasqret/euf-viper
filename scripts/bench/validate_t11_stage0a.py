#!/usr/bin/env python3
"""Validate and seal the frozen T11 Stage 0A no-SAT projection evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SCHEMA = "euf-viper.t11-stage0a.v1"
TARGET_RELATIVE_PATH = (
    "QF_UF/2018-Goel-hwbench/"
    "QF_UF_sokoban.2.prop1_ab_br_max.smt2"
)
TARGET_SHA256 = "cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112"
ROOT_CNF_MODE_SHA256 = hashlib.sha256(
    b"direct-root;negated-root=false;v1"
).hexdigest()
ATOM_MAP_SHA256 = "2fa9cabb8279cf59a9ca73cd254c0c60fe028753e8aa01d1794dd0c645167496"
BASELINE_CNF_SHA256 = "adb6885f8ee5d5230e81a3293d183bd4ae14d985f3df5bba9bc6c9fcd9fb1bb0"
BASELINE_PROBLEM_SHA256 = (
    "652e7b303accb7396dd9dfd5fdf40d17abd523f4a87897609390b6aa94d33597"
)
ZERO_SHA256 = "0" * 64
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")

EXPECTED_INPUT_COUNTERS = {
    "terms": 8_682,
    "baseline_variables": 21_744,
    "baseline_atom_entries": 18_082,
    "baseline_clauses": 89_470,
    "baseline_literal_slots": 147_132,
    "applications": 138,
}
EXPECTED_SELECTOR_FACTS = {
    "finite_added_clauses": 0,
    "covered_finite_terms": 0,
    "closed_table_functions": 0,
    "all_different_clique_lower_bound": 60,
    "disequality_graph_edges": 1_773,
    "equality_graph_vertices": 4_838,
    "equality_graph_edges": 14_241,
    "applications": 138,
    "boolean_valued_application_pairs": 0,
    "backend": "kissat",
}

HASH_FIELDS = (
    "source_sha256",
    "root_cnf_mode_sha256",
    "term_dag_sha256",
    "atom_map_sha256",
    "baseline_cnf_sha256",
    "baseline_problem_sha256",
    "trace_sha256",
    "lemma_sequence_sha256",
    "materialized_lemmas_sha256",
    "materialized_candidate_sha256",
    "candidate_binary_sha256",
    "revision_sha256",
    "corpus_manifest_sha256",
    "projection_record_sha256",
    "checker_record_sha256",
    "observation_record_sha256",
    "dimacs_sha256",
    "invocation_sha256",
    "drat_sha256",
)
INTERNAL_HASH_FIELDS = HASH_FIELDS[:10]
EXTERNAL_HASH_FIELDS = HASH_FIELDS[10:]
RULE_COUNTER_FIELDS = (
    "seed",
    "reflexivity",
    "transitivity",
    "congruence",
    "conflict",
)
INPUT_COUNTER_FIELDS = (
    "terms",
    "baseline_variables",
    "baseline_atom_entries",
    "baseline_clauses",
    "baseline_literal_slots",
    "applications",
    "application_pairs",
    "maximum_arity",
    "application_argument_slots",
)
SEARCH_COUNTER_FIELDS = (
    "attempted_events",
    "accepted_events",
    "events_popped",
    "distinct_event_keys_inserted",
    "duplicate_event_keys",
    "worklist_pushes",
    "live_worklist_entries",
    "peak_live_worklist_entries",
    "queued_events_discarded_at_theory_empty",
    "accepted_equality_nodes",
    "accepted_conflict_clauses",
    "proof_parent_references",
    "maximum_proof_depth",
    "accepted_trace_literal_slots",
    "canonical_proof_work_literal_charge",
    "retained_antichain_entries",
    "peak_retained_antichain_entries",
    "registered_negative_equality_occurrences",
    "logical_incremental_memory_bytes",
    "suppressed_missing_equality_congruence_events",
)
PRUNING_COUNTER_FIELDS = (
    "support_subset_discards",
    "support_capacity_discards",
    "support_removed_supersets",
    "duplicate_derived_clauses",
    "tautological_derived_clauses",
    "final_base_subsumption_discards",
    "final_output_subsumption_discards",
)
OUTPUT_COUNTER_FIELDS = (
    "emitted_lemmas",
    "emitted_literal_slots",
    "emitted_p95_width",
    "emitted_maximum_width",
    "emitted_with_missing_equality_congruence",
)
CHECKER_COUNTER_FIELDS = (
    "replayed_equality_nodes",
    "replayed_conflict_clauses",
    "replayed_emitted_lemmas",
    "replay_failures",
)
FORBIDDEN_GROWTH_FIELDS = (
    "added_terms",
    "added_atoms",
    "added_variables",
    "fill_edges",
    "generic_transitivity_clauses",
)
INTEGRITY_FIELDS = (
    "baseline_unchanged",
    "trace_materialization_equal",
    "compiler_checker_agree",
    "output_canonical",
    "external_audit_accepted",
    "off_path_unchanged",
)
REQUIRED_ARTIFACTS = {
    "source",
    "binary",
    "cargo_toml",
    "cargo_lock",
    "design_note",
    "hash_contract",
    "audit_contract",
    "runner",
    "validator",
    "build_stdout",
    "build_stderr",
    "bundle",
    "audit_receipt",
    "project_stdout",
    "project_stderr",
    "audit_stdout",
    "audit_stderr",
}

MAX_JSON_BYTES = 256 * 1024 * 1024
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024


class ValidationError(RuntimeError):
    pass


def _fail(message: str) -> None:
    raise ValidationError(message)


def _exact_keys(value: object, expected: Iterable[str], context: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{context} must be an object")
    expected_set = set(expected)
    actual_set = set(value)
    if actual_set != expected_set:
        missing = sorted(expected_set - actual_set)
        extra = sorted(actual_set - expected_set)
        _fail(f"{context} keys differ: missing={missing}, extra={extra}")
    return value


def _u64(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**64:
        _fail(f"{context} must be a u64")
    return value


def _i32(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not -(2**31) <= value < 2**31:
        _fail(f"{context} must be an i32")
    return value


def _canonical_sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail(f"{context} must be 64 lowercase hexadecimal digits")
    return value


def _no_duplicate_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_stable_regular(
    path: Path,
    *,
    maximum_bytes: int,
    reject_symlink: bool = True,
) -> tuple[bytes, os.stat_result, Path]:
    if not path.is_absolute():
        _fail(f"artifact path must be absolute: {path}")
    try:
        initial_lstat = path.lstat()
    except OSError as error:
        _fail(f"cannot inspect artifact {path}: {error}")
    if reject_symlink and stat.S_ISLNK(initial_lstat.st_mode):
        _fail(f"artifact must not be a symbolic link: {path}")
    resolved = path.resolve(strict=True)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if reject_symlink:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as error:
        _fail(f"cannot open artifact {resolved}: {error}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _fail(f"artifact is not a regular file: {resolved}")
        if before.st_size < 0 or before.st_size > maximum_bytes:
            _fail(f"artifact size is outside the bound: {resolved}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                _fail(f"artifact was truncated while reading: {resolved}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _fail(f"artifact grew while reading: {resolved}")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        named = resolved.stat()
    except OSError as error:
        _fail(f"cannot re-inspect artifact {resolved}: {error}")
    identity = lambda item: (item.st_dev, item.st_ino)
    stable_fields = lambda item: (item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if identity(before) != identity(after) or identity(before) != identity(named):
        _fail(f"artifact identity changed while reading: {resolved}")
    if stable_fields(before) != stable_fields(after) or stable_fields(before) != stable_fields(named):
        _fail(f"artifact metadata changed while reading: {resolved}")
    return b"".join(chunks), before, resolved


def _load_exact_json(path: Path) -> tuple[dict[str, Any], bytes, os.stat_result, Path]:
    data, metadata, resolved = _read_stable_regular(
        path, maximum_bytes=MAX_JSON_BYTES
    )
    if not data.endswith(b"\n") or data.endswith(b"\n\n") or b"\n" in data[:-1]:
        _fail(f"JSON artifact must be one record with one terminal newline: {resolved}")
    try:
        body = data[:-1].decode("ascii")
    except UnicodeDecodeError:
        _fail(f"JSON artifact is not ASCII: {resolved}")
    try:
        value = json.loads(body, object_pairs_hook=_no_duplicate_object)
    except (json.JSONDecodeError, ValidationError) as error:
        _fail(f"cannot decode exact JSON artifact {resolved}: {error}")
    if not isinstance(value, dict):
        _fail(f"JSON artifact root must be an object: {resolved}")
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    if encoded != body:
        _fail(f"JSON artifact is not compact canonical JSON: {resolved}")
    return value, data, metadata, resolved


def _validate_hash_bindings(value: object, source_sha256: str, context: str) -> dict[str, str]:
    bindings = dict(_exact_keys(value, HASH_FIELDS, context))
    for field in HASH_FIELDS:
        bindings[field] = _canonical_sha256(bindings[field], f"{context}.{field}")
    for field in INTERNAL_HASH_FIELDS:
        if bindings[field] == ZERO_SHA256:
            _fail(f"{context}.{field} must be nonzero")
    for field in EXTERNAL_HASH_FIELDS:
        if bindings[field] != ZERO_SHA256:
            _fail(f"{context}.{field} must remain zero in Stage 0A projection")
    expected = {
        "source_sha256": source_sha256,
        "root_cnf_mode_sha256": ROOT_CNF_MODE_SHA256,
        "atom_map_sha256": ATOM_MAP_SHA256,
        "baseline_cnf_sha256": BASELINE_CNF_SHA256,
        "baseline_problem_sha256": BASELINE_PROBLEM_SHA256,
    }
    for field, digest in expected.items():
        if bindings[field] != digest:
            _fail(f"{context}.{field} differs from the frozen identity")
    if bindings["lemma_sequence_sha256"] != bindings["materialized_lemmas_sha256"]:
        _fail(f"{context} lemma and materialized-lemma hashes differ")
    return bindings


def _validate_rule_counters(value: object, context: str) -> dict[str, int]:
    counters = dict(_exact_keys(value, RULE_COUNTER_FIELDS, context))
    for field in RULE_COUNTER_FIELDS:
        counters[field] = _u64(counters[field], f"{context}.{field}")
    return counters


def _validate_counters(value: object) -> dict[str, Any]:
    counters = dict(_exact_keys(value, ("input", "search", "pruning", "output"), "counters"))
    inputs = dict(_exact_keys(counters["input"], INPUT_COUNTER_FIELDS, "counters.input"))
    for field in INPUT_COUNTER_FIELDS:
        inputs[field] = _u64(inputs[field], f"counters.input.{field}")
    for field, expected in EXPECTED_INPUT_COUNTERS.items():
        if inputs[field] != expected:
            _fail(f"counters.input.{field} differs from the frozen baseline")

    search = dict(_exact_keys(counters["search"], SEARCH_COUNTER_FIELDS, "counters.search"))
    search["attempted_events"] = _validate_rule_counters(
        search["attempted_events"], "counters.search.attempted_events"
    )
    search["accepted_events"] = _validate_rule_counters(
        search["accepted_events"], "counters.search.accepted_events"
    )
    for field in SEARCH_COUNTER_FIELDS[2:]:
        search[field] = _u64(search[field], f"counters.search.{field}")

    pruning = dict(
        _exact_keys(counters["pruning"], PRUNING_COUNTER_FIELDS, "counters.pruning")
    )
    for field in PRUNING_COUNTER_FIELDS:
        pruning[field] = _u64(pruning[field], f"counters.pruning.{field}")

    output = dict(_exact_keys(counters["output"], OUTPUT_COUNTER_FIELDS, "counters.output"))
    for field in OUTPUT_COUNTER_FIELDS:
        output[field] = _u64(output[field], f"counters.output.{field}")
    if not 1 <= output["emitted_lemmas"] <= 8_192:
        _fail("Stage 0A requires between 1 and 8192 emitted lemmas")
    if output["emitted_literal_slots"] > 65_536:
        _fail("Stage 0A emitted-literal cap exceeded")
    if output["emitted_p95_width"] > 8 or output["emitted_maximum_width"] > 32:
        _fail("Stage 0A emitted-width gate failed")
    if output["emitted_with_missing_equality_congruence"] == 0:
        _fail("Stage 0A lacks missing-equality Congruence evidence")
    if output["emitted_with_missing_equality_congruence"] > output["emitted_lemmas"]:
        _fail("missing-equality Congruence count exceeds emitted lemmas")
    counters["input"] = inputs
    counters["search"] = search
    counters["pruning"] = pruning
    counters["output"] = output
    return counters


def _validate_clause(value: object, context: str) -> list[int]:
    if not isinstance(value, list):
        _fail(f"{context} must be a literal array")
    clause = [_i32(literal, f"{context}[{index}]") for index, literal in enumerate(value)]
    if any(literal == 0 for literal in clause):
        _fail(f"{context} contains zero")
    if any(left >= right for left, right in zip(clause, clause[1:])):
        _fail(f"{context} is not strictly sorted")
    seen = set(clause)
    if any(-literal in seen for literal in clause):
        _fail(f"{context} is tautological")
    return clause


def _extract_output(status: object) -> tuple[str, list[list[int]]]:
    status_record = _exact_keys(status, ("status", "detail"), "compiler.status")
    if status_record["status"] != "completed":
        _fail("compiler did not complete")
    detail = status_record["detail"]
    if not isinstance(detail, dict) or set(detail) != {"outcome", "output"}:
        _fail("compiler completed output has the wrong shape")
    outcome = detail["outcome"]
    output = detail["output"]
    if outcome == "lemmas":
        if not isinstance(output, list) or not output:
            _fail("lemma outcome must contain a nonempty lemma sequence")
        clauses: list[list[int]] = []
        for index, lemma_value in enumerate(output):
            lemma = _exact_keys(
                lemma_value, ("source_clause_id", "clause"), f"compiler.lemma[{index}]"
            )
            _u64(lemma["source_clause_id"], f"compiler.lemma[{index}].source_clause_id")
            clause = _validate_clause(lemma["clause"], f"compiler.lemma[{index}].clause")
            if not clause:
                _fail("ordinary emitted lemmas must be nonempty")
            clauses.append(clause)
        return outcome, clauses
    if outcome == "theory_empty":
        record = _exact_keys(output, ("terminal_event_id", "lemma"), "compiler.theory_empty")
        _u64(record["terminal_event_id"], "compiler.theory_empty.terminal_event_id")
        lemma = _exact_keys(
            record["lemma"], ("source_clause_id", "clause"), "compiler.theory_empty.lemma"
        )
        _u64(lemma["source_clause_id"], "compiler.theory_empty.lemma.source_clause_id")
        clause = _validate_clause(lemma["clause"], "compiler.theory_empty.lemma.clause")
        if clause:
            _fail("theory-empty output must contain exactly one empty clause")
        return outcome, [clause]
    _fail("Stage 0A output must be lemmas or theory_empty")
    raise AssertionError("unreachable")


def _validate_trace(trace: object, output_count: int) -> tuple[dict[str, int], dict[str, int]]:
    if not isinstance(trace, list):
        _fail("compiler.trace must be an array")
    rules = {field: 0 for field in RULE_COUNTER_FIELDS}
    equality_nodes = 0
    conflict_clauses = 0
    for index, value in enumerate(trace):
        if not isinstance(value, dict):
            _fail(f"compiler.trace[{index}] must be an object")
        kind = value.get("record_kind")
        record = value.get("record")
        if set(value) != {"record_kind", "record"} or not isinstance(record, dict):
            _fail(f"compiler.trace[{index}] has the wrong tagged shape")
        if kind == "equality":
            equality_nodes += 1
            rule = record.get("rule")
            if not isinstance(rule, dict) or rule.get("rule") not in rules:
                _fail(f"compiler.trace[{index}] has an invalid equality rule")
            rule_name = rule["rule"]
            if rule_name == "conflict":
                _fail(f"compiler.trace[{index}] uses conflict as an equality rule")
            rules[rule_name] += 1
        elif kind == "conflict":
            conflict_clauses += 1
            rules["conflict"] += 1
        else:
            _fail(f"compiler.trace[{index}] has an invalid record_kind")
    checker = {
        "replayed_equality_nodes": equality_nodes,
        "replayed_conflict_clauses": conflict_clauses,
        "replayed_emitted_lemmas": output_count,
        "replay_failures": 0,
    }
    return rules, checker


def _validate_checker_counters(value: object, context: str) -> dict[str, int]:
    counters = dict(_exact_keys(value, CHECKER_COUNTER_FIELDS, context))
    for field in CHECKER_COUNTER_FIELDS:
        counters[field] = _u64(counters[field], f"{context}.{field}")
    if counters["replay_failures"] != 0:
        _fail(f"{context}.replay_failures must be zero")
    return counters


def validate_evidence(
    *,
    source_path: Path,
    bundle_path: Path,
    receipt_path: Path,
) -> dict[str, Any]:
    source, source_stat, source_resolved = _read_stable_regular(
        source_path, maximum_bytes=MAX_ARTIFACT_BYTES
    )
    source_sha256 = hashlib.sha256(source).hexdigest()
    if source_sha256 != TARGET_SHA256:
        _fail("source SHA-256 differs from the frozen T11 target")

    bundle, bundle_bytes, bundle_stat, bundle_resolved = _load_exact_json(bundle_path)
    receipt, receipt_bytes, receipt_stat, receipt_resolved = _load_exact_json(receipt_path)
    identities = {
        (source_stat.st_dev, source_stat.st_ino),
        (bundle_stat.st_dev, bundle_stat.st_ino),
        (receipt_stat.st_dev, receipt_stat.st_ino),
    }
    if len(identities) != 3:
        _fail("source, bundle, and receipt must have distinct file identities")
    if stat.S_IMODE(bundle_stat.st_mode) != 0o400 or stat.S_IMODE(receipt_stat.st_mode) != 0o400:
        _fail("bundle and receipt must be immutable mode 0400")

    bundle_record = _exact_keys(
        bundle,
        ("selector", "compiler", "materialized_lemmas", "checker", "report"),
        "bundle",
    )
    selector = _exact_keys(bundle_record["selector"], ("mode", "facts", "decision"), "selector")
    if selector["mode"] != "clique-er-auto":
        _fail("selector mode is not clique-er-auto")
    facts = dict(
        _exact_keys(selector["facts"], EXPECTED_SELECTOR_FACTS, "selector.facts")
    )
    for field, expected in EXPECTED_SELECTOR_FACTS.items():
        actual = facts[field]
        if isinstance(expected, int):
            actual = _u64(actual, f"selector.facts.{field}")
        elif not isinstance(actual, str):
            _fail(f"selector.facts.{field} must be text")
        if actual != expected:
            _fail(f"selector.facts.{field} differs from the frozen target")
        facts[field] = actual
    decision = _exact_keys(selector["decision"], ("decision",), "selector.decision")
    if decision["decision"] != "selected":
        _fail("frozen selector did not select the target")

    compiler = _exact_keys(
        bundle_record["compiler"], ("variant", "status", "trace", "counters", "hashes"), "compiler"
    )
    if compiler["variant"] != "ordinary":
        _fail("Stage 0A requires the ordinary compiler variant")
    outcome, output_clauses = _extract_output(compiler["status"])
    counters = _validate_counters(compiler["counters"])
    hashes = _validate_hash_bindings(compiler["hashes"], source_sha256, "compiler.hashes")
    trace_rules, expected_checker_counters = _validate_trace(
        compiler["trace"], len(output_clauses)
    )
    if counters["search"]["accepted_events"] != trace_rules:
        _fail("accepted rule counters do not match the sealed trace")
    if counters["search"]["accepted_equality_nodes"] != expected_checker_counters[
        "replayed_equality_nodes"
    ]:
        _fail("accepted equality-node count does not match the sealed trace")
    if counters["search"]["accepted_conflict_clauses"] != expected_checker_counters[
        "replayed_conflict_clauses"
    ]:
        _fail("accepted conflict count does not match the sealed trace")
    if counters["output"]["emitted_lemmas"] != len(output_clauses):
        _fail("emitted lemma count does not match compiler output")
    literal_slots = sum(map(len, output_clauses))
    if counters["output"]["emitted_literal_slots"] != literal_slots:
        _fail("emitted literal count does not match compiler output")

    materialized = _exact_keys(
        bundle_record["materialized_lemmas"], ("end_offsets", "literals"), "materialized_lemmas"
    )
    offsets_value = materialized["end_offsets"]
    literals_value = materialized["literals"]
    if not isinstance(offsets_value, list) or not isinstance(literals_value, list):
        _fail("materialized lemma store must contain arrays")
    offsets = [_u64(value, f"materialized_lemmas.end_offsets[{index}]") for index, value in enumerate(offsets_value)]
    literals = [_i32(value, f"materialized_lemmas.literals[{index}]") for index, value in enumerate(literals_value)]
    expected_offsets = [0]
    expected_literals: list[int] = []
    for clause in output_clauses:
        expected_literals.extend(clause)
        expected_offsets.append(len(expected_literals))
    if offsets != expected_offsets or literals != expected_literals:
        _fail("materialized lemma bytes differ from compiler output")

    checker = _exact_keys(
        bundle_record["checker"], ("status", "counters", "recomputed_hashes"), "checker"
    )
    checker_status = _exact_keys(checker["status"], ("status",), "checker.status")
    if checker_status["status"] != "accepted":
        _fail("logical checker did not accept")
    checker_counters = _validate_checker_counters(checker["counters"], "checker.counters")
    if checker_counters != expected_checker_counters:
        _fail("checker counters do not match trace and output")
    checker_hashes = _validate_hash_bindings(
        checker["recomputed_hashes"], source_sha256, "checker.recomputed_hashes"
    )
    if checker_hashes != hashes:
        _fail("compiler and checker hashes differ")

    report = _exact_keys(
        bundle_record["report"],
        (
            "schema_version",
            "selector",
            "compiler_variant",
            "outcome",
            "counters",
            "checker_counters",
            "cap_attempt",
            "forbidden_growth",
            "integrity",
            "sat_calls",
            "hashes",
        ),
        "report",
    )
    if _u64(report["schema_version"], "report.schema_version") != 1 \
        or report["selector"] != selector:
        _fail("report schema or selector binding differs")
    if report["compiler_variant"] != "ordinary" or report["outcome"] != outcome:
        _fail("report compiler variant or outcome differs")
    if report["counters"] != counters or report["checker_counters"] != checker_counters:
        _fail("report counters differ from compiler or checker")
    if report["cap_attempt"] is not None:
        _fail("Stage 0A reached a hard cap")
    forbidden = _exact_keys(
        report["forbidden_growth"], FORBIDDEN_GROWTH_FIELDS, "report.forbidden_growth"
    )
    if any(_u64(forbidden[field], f"report.forbidden_growth.{field}") != 0 for field in FORBIDDEN_GROWTH_FIELDS):
        _fail("Stage 0A performed forbidden formula growth")
    integrity = _exact_keys(report["integrity"], INTEGRITY_FIELDS, "report.integrity")
    expected_integrity = {
        "baseline_unchanged": True,
        "trace_materialization_equal": True,
        "compiler_checker_agree": True,
        "output_canonical": True,
        "external_audit_accepted": False,
        "off_path_unchanged": False,
    }
    if dict(integrity) != expected_integrity:
        _fail("report integrity flags differ from the Stage 0A contract")
    if _u64(report["sat_calls"], "report.sat_calls") != 0:
        _fail("Stage 0A dispatched SAT")
    report_hashes = _validate_hash_bindings(report["hashes"], source_sha256, "report.hashes")
    if report_hashes != hashes:
        _fail("report hashes differ from compiler hashes")

    receipt_record = _exact_keys(
        receipt, ("schema_version", "exact_bundle_sha256", "hashes", "result"), "receipt"
    )
    if _u64(receipt_record["schema_version"], "receipt.schema_version") != 1:
        _fail("audit receipt schema version differs")
    bundle_sha256 = hashlib.sha256(bundle_bytes).hexdigest()
    if _canonical_sha256(receipt_record["exact_bundle_sha256"], "receipt.exact_bundle_sha256") != bundle_sha256:
        _fail("audit receipt does not bind the exact bundle bytes")
    receipt_hashes = _validate_hash_bindings(receipt_record["hashes"], source_sha256, "receipt.hashes")
    if receipt_hashes != hashes:
        _fail("receipt hashes differ from compiler hashes")
    result = _exact_keys(
        receipt_record["result"],
        ("status", "counters", "checker_counters", "cap_attempt", "recomputed_hashes"),
        "receipt.result",
    )
    audit_status = _exact_keys(result["status"], ("status",), "receipt.result.status")
    if audit_status["status"] != "accepted":
        _fail("external scheduling auditor did not accept")
    if result["counters"] != counters:
        _fail("auditor counters differ from compiler counters")
    audit_checker_counters = _validate_checker_counters(
        result["checker_counters"], "receipt.result.checker_counters"
    )
    if audit_checker_counters != checker_counters:
        _fail("auditor checker counters differ")
    if result["cap_attempt"] is not None:
        _fail("auditor reconstructed a hard cap")
    audit_hashes = _validate_hash_bindings(
        result["recomputed_hashes"], source_sha256, "receipt.result.recomputed_hashes"
    )
    if audit_hashes != hashes:
        _fail("auditor hashes differ from compiler hashes")

    return {
        "source_path": str(source_resolved),
        "source_sha256": source_sha256,
        "source_bytes": len(source),
        "bundle_path": str(bundle_resolved),
        "bundle_sha256": bundle_sha256,
        "bundle_bytes": len(bundle_bytes),
        "receipt_path": str(receipt_resolved),
        "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "receipt_bytes": len(receipt_bytes),
        "outcome": outcome,
        "counters": counters,
        "checker_counters": checker_counters,
        "hashes": hashes,
    }


def _parse_artifacts(values: Sequence[str]) -> dict[str, Path]:
    artifacts: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            _fail(f"artifact binding must be NAME=PATH: {value}")
        name, raw_path = value.split("=", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", name) or name in artifacts:
            _fail(f"invalid or duplicate artifact name: {name}")
        artifacts[name] = Path(raw_path)
    if set(artifacts) != REQUIRED_ARTIFACTS:
        _fail(
            "artifact set differs: "
            f"missing={sorted(REQUIRED_ARTIFACTS - set(artifacts))}, "
            f"extra={sorted(set(artifacts) - REQUIRED_ARTIFACTS)}"
        )
    return artifacts


def _artifact_record(path: Path) -> dict[str, Any]:
    data, metadata, resolved = _read_stable_regular(
        path, maximum_bytes=MAX_ARTIFACT_BYTES, reject_symlink=False
    )
    return {
        "path": str(resolved),
        "bytes": len(data),
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _write_immutable_json(path: Path, payload: Mapping[str, Any]) -> None:
    if not path.is_absolute():
        _fail("metadata output path must be absolute")
    parent = path.parent.resolve(strict=True)
    if path.name in {"", ".", ".."}:
        _fail("metadata output path has no canonical file name")
    encoded = (
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    directory_fd = os.open(parent, directory_flags)
    try:
        parent_before = os.fstat(directory_fd)
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path.name, flags, 0o600, dir_fd=directory_fd)
        try:
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    _fail("short metadata write")
                offset += written
            os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.read(descriptor, len(encoded) + 1) != encoded:
                _fail("metadata descriptor verification failed")
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
            created = os.fstat(descriptor)
            named = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
            if (created.st_dev, created.st_ino) != (named.st_dev, named.st_ino):
                _fail("metadata pathname was replaced")
            if stat.S_IMODE(named.st_mode) != 0o400:
                _fail("metadata mode is not 0400")
        finally:
            os.close(descriptor)
        os.fsync(directory_fd)
        parent_after = os.fstat(directory_fd)
        if (parent_before.st_dev, parent_before.st_ino) != (
            parent_after.st_dev,
            parent_after.st_ino,
        ):
            _fail("metadata parent identity changed")
    finally:
        os.close(directory_fd)


def _tool_record(path: Path, expected_sha256: str, version: str, label: str) -> dict[str, Any]:
    record = _artifact_record(path)
    if record["sha256"] != _canonical_sha256(expected_sha256, f"{label} SHA-256"):
        _fail(f"{label} bytes differ from the pinned SHA-256")
    if not isinstance(version, str) or not version or "\n" in version:
        _fail(f"{label} version is not one exact line")
    record["version"] = version
    return record


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--metadata-out", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--target-relative-path", required=True)
    parser.add_argument("--source-before-sha256", required=True)
    parser.add_argument("--source-after-sha256", required=True)
    parser.add_argument("--project-exit", type=int, required=True)
    parser.add_argument("--audit-exit", type=int, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--cargo-sha256", required=True)
    parser.add_argument("--cargo-version", required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--rustc-sha256", required=True)
    parser.add_argument("--rustc-version", required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--python-sha256", required=True)
    parser.add_argument("--python-version", required=True)
    parser.add_argument("--artifact", action="append", default=[])
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if REVISION_RE.fullmatch(args.revision) is None:
            _fail("revision must be an exact 40-character lowercase Git commit")
        if not args.job_id.isascii() or not args.job_id.isdecimal():
            _fail("SLURM job ID must be a nonempty decimal integer")
        if args.target_relative_path != TARGET_RELATIVE_PATH:
            _fail("target relative path differs from the frozen T11 target")
        before = _canonical_sha256(args.source_before_sha256, "source-before SHA-256")
        after = _canonical_sha256(args.source_after_sha256, "source-after SHA-256")
        if before != TARGET_SHA256 or after != TARGET_SHA256 or before != after:
            _fail("source identity changed across Stage 0A")
        if args.project_exit != 4 or args.audit_exit != 0:
            _fail("Stage 0A command exit contract was not satisfied")

        evidence = validate_evidence(
            source_path=args.source,
            bundle_path=args.bundle,
            receipt_path=args.receipt,
        )
        artifacts = _parse_artifacts(args.artifact)
        artifact_records = {
            name: _artifact_record(path) for name, path in sorted(artifacts.items())
        }
        if artifact_records["source"]["sha256"] != TARGET_SHA256:
            _fail("metadata source artifact differs from the frozen target")
        if artifact_records["bundle"]["sha256"] != evidence["bundle_sha256"]:
            _fail("metadata bundle artifact differs from validated evidence")
        if artifact_records["audit_receipt"]["sha256"] != evidence["receipt_sha256"]:
            _fail("metadata receipt artifact differs from validated evidence")

        binary_record = artifact_records["binary"]
        if Path(binary_record["path"]) != args.binary.resolve(strict=True):
            _fail("binary artifact binding differs from --binary")
        binary_mode = int(binary_record["mode"], 8)
        if binary_mode & 0o222 or not binary_mode & 0o100:
            _fail("Stage 0A binary must be owner-executable and immutable")

        toolchain = {
            "cargo": _tool_record(
                args.cargo, args.cargo_sha256, args.cargo_version, "cargo"
            ),
            "rustc": _tool_record(
                args.rustc, args.rustc_sha256, args.rustc_version, "rustc"
            ),
            "python": _tool_record(
                args.python, args.python_sha256, args.python_version, "python"
            ),
            "rustup_toolchain": "1.93.0",
        }
        payload = {
            "schema": SCHEMA,
            "status": "completed",
            "decision": "authorize_stage0b",
            "revision": args.revision,
            "job_id": int(args.job_id),
            "hostname": platform.node(),
            "resource_contract": {
                "cpus": 1,
                "memory_bytes": 8 * 1024**3,
                "sat_calls": 0,
            },
            "build_contract": {
                "command": "cargo build --locked --features certificates --release",
                "rustup_toolchain": "1.93.0",
            },
            "target": {
                "relative_path": TARGET_RELATIVE_PATH,
                "source_sha256": TARGET_SHA256,
                "source_bytes": evidence["source_bytes"],
            },
            "baseline": {
                **EXPECTED_INPUT_COUNTERS,
                "atom_map_sha256": ATOM_MAP_SHA256,
                "baseline_cnf_sha256": BASELINE_CNF_SHA256,
                "baseline_problem_sha256": BASELINE_PROBLEM_SHA256,
            },
            "projection": {
                "project_exit": args.project_exit,
                "audit_exit": args.audit_exit,
                "outcome": evidence["outcome"],
                "counters": evidence["counters"],
                "checker_counters": evidence["checker_counters"],
                "hashes": evidence["hashes"],
                "exact_bundle_sha256": evidence["bundle_sha256"],
                "audit_receipt_sha256": evidence["receipt_sha256"],
            },
            "toolchain": toolchain,
            "artifacts": artifact_records,
        }
        _write_immutable_json(args.metadata_out, payload)
        return 0
    except ValidationError as error:
        print(f"T11 Stage 0A rejected: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
