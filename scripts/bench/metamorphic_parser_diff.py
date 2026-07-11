#!/usr/bin/env python3
"""Fail-closed metamorphic differential campaign for QF_UF parser boundaries.

The generated corpus targets two classes of parser mistakes:

* quoted symbols that spell reserved identifiers, plus quoted/simple aliases;
* commands following the sole ``check-sat`` in euf-viper's single-query mode.

Every ordinary case has a generator-known result.  Z3, cvc5, optional Yices,
and euf-viper are checked independently against it.  Negative command-ordering
probes instead require euf-viper to reject the unsupported suffix with a
configured process exit.  No oracle majority is used.  Strict mode fails on
any solver anomaly.  Candidate mode still records every comparator anomaly but
gates only euf-viper's expected-result and metamorphic obligations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Mapping, NamedTuple, Sequence


SCHEMA_VERSION = 2
GENERATOR_VERSION = "metamorphic-parser-diff-v1"
FILE_PLACEHOLDER = "{file}"
OUTPUT_LIMIT = 8192
DECISIVE_RESULTS = {"sat", "unsat"}
CONSENSUS_POLICY = "consensus"
VIPER_REJECT_POLICY = "viper-rejects-post-query"
STRICT_GATE = "strict"
CANDIDATE_GATE = "candidate"
ACCEPTANCE_PARSER_MODES = ("shadow", "stream")
SOLVER_ORDER = ("euf-viper", "z3", "cvc5", "yices")
MANDATORY_SOLVERS = ("euf-viper", "z3", "cvc5")
CASE_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
ERROR_OUTPUT_PATTERN = re.compile(r"\(\s*error(?:\s|[\"')])", re.IGNORECASE)


class FormulaCase(NamedTuple):
    case_id: str
    group_id: str
    family: str
    variant: str
    policy: str
    expected: str
    source: str
    metadata: dict[str, object]


class SolverResult(NamedTuple):
    classification: str
    reason: str
    exit_code: int | None
    result_lines: tuple[str, ...]
    stdout: str
    stderr: str


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_line(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _durable_atomic_write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.tmp-", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(
            path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def _atomic_write_text(path: Path, value: str) -> None:
    _durable_atomic_write(path, value.encode("utf-8"))


def _limited(value: str) -> str:
    if len(value) <= OUTPUT_LIMIT:
        return value
    return value[:OUTPUT_LIMIT] + "\n...[truncated]"


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _quoted(symbol: str) -> str:
    if not symbol or "|" in symbol or "\\" in symbol:
        raise ValueError(f"symbol cannot be quoted safely: {symbol!r}")
    return f"|{symbol}|"


def _script(
    *,
    expected: str,
    policy: str,
    commands: Sequence[str],
) -> str:
    lines = [
        f"; generated-by: {GENERATOR_VERSION}",
        f"; expected-result: {expected}",
        f"; viper-policy: {policy}",
        *commands,
    ]
    return "\n".join(lines) + "\n"


def _standard_script(
    *,
    expected: str,
    declarations: Sequence[str],
    assertions: Sequence[str],
    suffix: Sequence[str] = (),
    policy: str = CONSENSUS_POLICY,
) -> str:
    commands = ["(set-logic QF_UF)"]
    commands.extend(declarations)
    commands.extend(f"(assert {assertion})" for assertion in assertions)
    commands.append("(check-sat)")
    commands.extend(suffix)
    return _script(expected=expected, policy=policy, commands=commands)


def _case(
    *,
    case_id: str,
    group_id: str,
    family: str,
    variant: str,
    expected: str,
    source: str,
    policy: str = CONSENSUS_POLICY,
    metadata: Mapping[str, object] | None = None,
) -> FormulaCase:
    return FormulaCase(
        case_id,
        group_id,
        family,
        variant,
        policy,
        expected,
        source,
        dict(metadata or {}),
    )


def _symbol_atom_groups() -> list[FormulaCase]:
    cases: list[FormulaCase] = []
    reserved = (
        ("true", "true", "negative"),
        ("false", "false", "positive"),
        ("not", "not", "negative"),
        ("and", "and", "negative"),
        ("or", "or", "negative"),
        ("xor", "xor", "negative"),
        ("implies", "=>", "negative"),
        ("ite", "ite", "negative"),
        ("let", "let", "negative"),
        ("equals", "=", "negative"),
        ("distinct", "distinct", "negative"),
        ("bool", "Bool", "negative"),
        ("assert", "assert", "negative"),
        ("check-sat", "check-sat", "negative"),
        ("declare-fun", "declare-fun", "negative"),
        ("declare-sort", "declare-sort", "negative"),
        ("set-logic", "set-logic", "negative"),
        ("set-option", "set-option", "negative"),
        ("push", "push", "negative"),
        ("pop", "pop", "negative"),
        ("exit", "exit", "negative"),
        ("get-model", "get-model", "negative"),
        ("get-value", "get-value", "negative"),
    )
    for slug, spelling, polarity in reserved:
        group_id = f"reserved-atom-{slug}"
        for variant, symbol in (
            ("safe-alpha", f"safe_{slug.replace('-', '_')}_atom"),
            ("quoted-reserved", _quoted(spelling)),
        ):
            assertion = symbol if polarity == "positive" else f"(not {symbol})"
            source = _standard_script(
                expected="sat",
                declarations=[f"(declare-fun {symbol} () Bool)"],
                assertions=[assertion],
            )
            cases.append(
                _case(
                    case_id=f"{group_id}-{variant}",
                    group_id=group_id,
                    family="reserved-atom-alpha-renaming",
                    variant=variant,
                    expected="sat",
                    source=source,
                    metadata={"reserved_spelling": spelling},
                )
            )
    return cases


def _operator_head_groups() -> list[FormulaCase]:
    cases: list[FormulaCase] = []
    operators = (
        ("not", "not", "(Bool)", ("true",), "positive"),
        ("and", "and", "(Bool Bool)", ("false", "false"), "positive"),
        ("or", "or", "(Bool Bool)", ("true", "false"), "negative"),
        ("xor", "xor", "(Bool Bool)", ("false", "false"), "positive"),
        ("implies", "=>", "(Bool Bool)", ("false", "false"), "negative"),
        ("ite", "ite", "(Bool Bool Bool)", ("true", "true", "false"), "negative"),
        ("equals", "=", "(Bool Bool)", ("true", "true"), "negative"),
        ("distinct", "distinct", "(Bool Bool)", ("true", "true"), "positive"),
    )
    for slug, spelling, domain, arguments, polarity in operators:
        group_id = f"reserved-head-{slug}"
        for variant, symbol in (
            ("safe-alpha", f"safe_{slug}_head"),
            ("quoted-reserved", _quoted(spelling)),
        ):
            application = f"({symbol} {' '.join(arguments)})"
            assertion = application if polarity == "positive" else f"(not {application})"
            source = _standard_script(
                expected="sat",
                declarations=[f"(declare-fun {symbol} {domain} Bool)"],
                assertions=[assertion],
            )
            cases.append(
                _case(
                    case_id=f"{group_id}-{variant}",
                    group_id=group_id,
                    family="reserved-head-alpha-renaming",
                    variant=variant,
                    expected="sat",
                    source=source,
                    metadata={"reserved_spelling": spelling, "arity": len(arguments)},
                )
            )
    return cases


def _alias_groups() -> list[FormulaCase]:
    cases: list[FormulaCase] = []

    group_id = "simple-quoted-nullary-alias"
    for variant, declaration, positive, negative in (
        ("simple-only", "p_alias", "p_alias", "p_alias"),
        ("mixed-use", "p_alias", "p_alias", _quoted("p_alias")),
        ("quoted-declaration", _quoted("p_alias"), "p_alias", _quoted("p_alias")),
    ):
        cases.append(
            _case(
                case_id=f"{group_id}-{variant}",
                group_id=group_id,
                family="simple-quoted-alias",
                variant=variant,
                expected="unsat",
                source=_standard_script(
                    expected="unsat",
                    declarations=[f"(declare-fun {declaration} () Bool)"],
                    assertions=[positive, f"(not {negative})"],
                ),
            )
        )

    group_id = "simple-quoted-function-alias"
    for variant, declaration, first_use, second_use in (
        ("simple-only", "f_alias", "f_alias", "f_alias"),
        ("mixed-use", "f_alias", "f_alias", _quoted("f_alias")),
        ("quoted-declaration", _quoted("f_alias"), "f_alias", _quoted("f_alias")),
    ):
        cases.append(
            _case(
                case_id=f"{group_id}-{variant}",
                group_id=group_id,
                family="simple-quoted-alias",
                variant=variant,
                expected="unsat",
                source=_standard_script(
                    expected="unsat",
                    declarations=[
                        "(declare-sort U_alias 0)",
                        "(declare-fun a_alias () U_alias)",
                        f"(declare-fun {declaration} (U_alias) Bool)",
                    ],
                    assertions=[
                        f"({first_use} a_alias)",
                        f"(not ({second_use} a_alias))",
                    ],
                ),
            )
        )

    cases.extend(
        [
            _case(
                case_id="simple-quoted-sort-alias-simple-only",
                group_id="simple-quoted-sort-alias",
                family="simple-quoted-alias",
                variant="simple-only",
                expected="sat",
                source=_standard_script(
                    expected="sat",
                    declarations=[
                        "(declare-sort U_sort_alias 0)",
                        "(declare-fun a_sort_alias () U_sort_alias)",
                        "(declare-fun b_sort_alias () U_sort_alias)",
                    ],
                    assertions=["(distinct a_sort_alias b_sort_alias)"],
                ),
            ),
            _case(
                case_id="simple-quoted-sort-alias-mixed-use",
                group_id="simple-quoted-sort-alias",
                family="simple-quoted-alias",
                variant="mixed-use",
                expected="sat",
                source=_standard_script(
                    expected="sat",
                    declarations=[
                        "(declare-sort U_sort_alias 0)",
                        "(declare-fun a_sort_alias () |U_sort_alias|)",
                        "(declare-fun b_sort_alias () U_sort_alias)",
                    ],
                    assertions=["(distinct |a_sort_alias| b_sort_alias)"],
                ),
            ),
        ]
    )

    group_id = "quoted-whitespace-alpha-renaming"
    for variant, symbol in (
        ("safe-alpha", "safe_whitespace_name"),
        ("quoted-whitespace", _quoted("name with spaces")),
    ):
        cases.append(
            _case(
                case_id=f"{group_id}-{variant}",
                group_id=group_id,
                family="quoted-symbol-lexing",
                variant=variant,
                expected="sat",
                source=_standard_script(
                    expected="sat",
                    declarations=[f"(declare-fun {symbol} () Bool)"],
                    assertions=[symbol],
                ),
            )
        )
    return cases


def _ordering_groups() -> list[FormulaCase]:
    cases: list[FormulaCase] = []

    def add(
        group_id: str,
        variant: str,
        expected: str,
        declarations: Sequence[str],
        assertions: Sequence[str],
        suffix: Sequence[str] = (),
        policy: str = CONSENSUS_POLICY,
    ) -> None:
        cases.append(
            _case(
                case_id=f"{group_id}-{variant}",
                group_id=group_id,
                family="single-query-command-ordering",
                variant=variant,
                expected=expected,
                policy=policy,
                source=_standard_script(
                    expected=expected,
                    declarations=declarations,
                    assertions=assertions,
                    suffix=suffix,
                    policy=policy,
                ),
                metadata={"suffix_commands": list(suffix)},
            )
        )

    declarations = ["(declare-fun ordering_p () Bool)"]
    add("ordering-sat", "base", "sat", declarations, ["ordering_p"])
    add("ordering-sat", "exit-after-query", "sat", declarations, ["ordering_p"], ["(exit)"])
    add(
        "ordering-sat",
        "post-query-contradiction",
        "sat",
        declarations,
        ["ordering_p"],
        ["(assert false)"],
        VIPER_REJECT_POLICY,
    )
    add(
        "ordering-sat",
        "post-query-declaration",
        "sat",
        declarations,
        ["ordering_p"],
        ["(declare-fun late_p () Bool)"],
        VIPER_REJECT_POLICY,
    )
    add(
        "ordering-sat",
        "post-exit-contradiction",
        "sat",
        declarations,
        ["ordering_p"],
        ["(exit)", "(assert false)"],
        VIPER_REJECT_POLICY,
    )

    assertions = ["ordering_u", "(not ordering_u)"]
    add("ordering-unsat", "base", "unsat", ["(declare-fun ordering_u () Bool)"], assertions)
    add(
        "ordering-unsat",
        "assertions-reordered",
        "unsat",
        ["(declare-fun ordering_u () Bool)"],
        list(reversed(assertions)),
    )
    add(
        "ordering-unsat",
        "exit-after-query",
        "unsat",
        ["(declare-fun ordering_u () Bool)"],
        assertions,
        ["(exit)"],
    )
    add(
        "ordering-unsat",
        "post-query-assertion",
        "unsat",
        ["(declare-fun ordering_u () Bool)"],
        assertions,
        ["(assert true)"],
        VIPER_REJECT_POLICY,
    )

    add("ordering-empty-prefix", "base", "sat", [], [])
    add("ordering-empty-prefix", "exit-after-query", "sat", [], [], ["(exit)"])
    add(
        "ordering-empty-prefix",
        "late-unsat-body",
        "sat",
        [],
        [],
        ["(declare-fun late_empty () Bool)", "(assert false)"],
        VIPER_REJECT_POLICY,
    )
    return cases


def _derived_seed(seed: int, index: int, variant: str) -> int:
    material = f"{GENERATOR_VERSION}:{seed}:{index}:{variant}".encode("ascii")
    return int.from_bytes(hashlib.sha256(material).digest()[:16], "big")


def _random_group(seed: int, index: int) -> list[FormulaCase]:
    group_id = f"random-alias-{index:05d}"
    expected = "sat" if _derived_seed(seed, index, "result") & 1 else "unsat"
    raw = {
        "sort": f"U_r{index}",
        "a": f"a_r{index}",
        "b": f"b_r{index}",
        "p": f"p_r{index}",
        "q": f"q_r{index}",
        "f": f"f_r{index}",
        "pred": f"pred_r{index}",
    }
    cases: list[FormulaCase] = []
    for variant in ("simple", "all-quoted", "mixed-alias"):
        if variant == "simple":
            declaration = dict(raw)
            use = dict(raw)
        elif variant == "all-quoted":
            declaration = {key: _quoted(value) for key, value in raw.items()}
            use = dict(declaration)
        else:
            declaration = dict(raw)
            use = {key: _quoted(value) for key, value in raw.items()}

        declarations = [
            f"(declare-sort {declaration['sort']} 0)",
            f"(declare-fun {declaration['a']} () {use['sort']})",
            f"(declare-fun {declaration['b']} () {declaration['sort']})",
            f"(declare-fun {declaration['p']} () Bool)",
            f"(declare-fun {declaration['q']} () Bool)",
            f"(declare-fun {declaration['f']} ({use['sort']}) {declaration['sort']})",
            f"(declare-fun {declaration['pred']} ({declaration['sort']}) Bool)",
        ]
        if expected == "sat":
            assertions = [
                use["p"],
                f"(not {use['q']})",
                f"(= ({use['f']} {use['a']}) ({use['f']} {use['a']}))",
                f"(or ({use['pred']} {use['b']}) (not ({use['pred']} {use['b']})))",
            ]
        else:
            assertions = [
                f"(= {use['a']} {use['b']})",
                f"(distinct ({use['f']} {use['a']}) ({use['f']} {use['b']}))",
            ]
        rng = random.Random(_derived_seed(seed, index, variant))
        rng.shuffle(assertions)
        cases.append(
            _case(
                case_id=f"{group_id}-{variant}",
                group_id=group_id,
                family="deterministic-random-alias",
                variant=variant,
                expected=expected,
                source=_standard_script(
                    expected=expected,
                    declarations=declarations,
                    assertions=assertions,
                ),
                metadata={
                    "seed": seed,
                    "index": index,
                    "derived_seed": _derived_seed(seed, index, variant),
                    "assertion_order": assertions,
                },
            )
        )
    return cases


def generate_cases(seed: int, random_groups: int) -> list[FormulaCase]:
    if random_groups < 0:
        raise ValueError("random group count must be non-negative")
    cases = [
        *_symbol_atom_groups(),
        *_operator_head_groups(),
        *_alias_groups(),
        *_ordering_groups(),
    ]
    for index in range(random_groups):
        cases.extend(_random_group(seed, index))
    _validate_cases(cases)
    return cases


def _validate_cases(cases: Sequence[FormulaCase]) -> None:
    if not cases:
        raise ValueError("campaign selection is empty")
    case_ids: set[str] = set()
    sources: set[str] = set()
    groups: dict[str, list[FormulaCase]] = defaultdict(list)
    for case in cases:
        if not CASE_ID_PATTERN.fullmatch(case.case_id):
            raise ValueError(f"unsafe case id: {case.case_id!r}")
        if not CASE_ID_PATTERN.fullmatch(case.group_id):
            raise ValueError(f"unsafe group id: {case.group_id!r}")
        if case.case_id in case_ids:
            raise ValueError(f"duplicate case id: {case.case_id}")
        if case.source in sources:
            raise ValueError(f"duplicate source: {case.case_id}")
        if case.expected not in DECISIVE_RESULTS:
            raise ValueError(f"non-decisive expected result: {case.case_id}")
        if case.policy not in {CONSENSUS_POLICY, VIPER_REJECT_POLICY}:
            raise ValueError(f"unknown policy: {case.policy}")
        if not case.source.endswith("\n"):
            raise ValueError(f"case lacks final newline: {case.case_id}")
        if sum(line.strip() == "(check-sat)" for line in case.source.splitlines()) != 1:
            raise ValueError(f"case must contain exactly one check-sat: {case.case_id}")
        case_ids.add(case.case_id)
        sources.add(case.source)
        groups[case.group_id].append(case)
    for group_id, members in groups.items():
        if len(members) < 2:
            raise ValueError(f"metamorphic group has fewer than two cases: {group_id}")
        if len({case.expected for case in members}) != 1:
            raise ValueError(f"metamorphic group changes expected result: {group_id}")


def parse_command(value: str) -> tuple[str, ...]:
    try:
        command = tuple(shlex.split(value))
    except ValueError as error:
        raise ValueError(f"invalid command: {error}") from error
    if not command:
        raise ValueError("solver command cannot be empty")
    if command.count(FILE_PLACEHOLDER) > 1:
        raise ValueError("solver command may contain at most one {file} token")
    if any(FILE_PLACEHOLDER in token and token != FILE_PLACEHOLDER for token in command):
        raise ValueError("{file} must be a standalone command token")
    return command


def materialize_command(command: Sequence[str], case_path: Path) -> list[str]:
    if FILE_PLACEHOLDER in command:
        return [str(case_path) if token == FILE_PLACEHOLDER else token for token in command]
    return [*command, str(case_path)]


def _resolve_executable(value: str) -> Path:
    candidate: str | None
    if os.sep in value or (os.altsep is not None and os.altsep in value):
        candidate = str(Path(value).expanduser().resolve())
    else:
        candidate = shutil.which(value)
    if candidate is None:
        raise ValueError(f"solver executable is not resolvable: {value}")
    path = Path(candidate).resolve()
    if not path.is_file():
        raise ValueError(f"solver executable is not a regular file: {path}")
    return path


def command_provenance(command: Sequence[str]) -> dict[str, object]:
    executable = _resolve_executable(command[0])
    artifacts: list[dict[str, object]] = []
    seen: set[Path] = set()
    for index, token in enumerate(command):
        if token == FILE_PLACEHOLDER:
            continue
        candidate = Path(token).expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if not resolved.is_file() or resolved in seen:
            continue
        seen.add(resolved)
        artifacts.append(
            {
                "token_index": index,
                "path": str(resolved),
                "size_bytes": resolved.stat().st_size,
                "sha256": sha256_file(resolved),
            }
        )
    if executable not in seen:
        artifacts.insert(
            0,
            {
                "token_index": 0,
                "path": str(executable),
                "size_bytes": executable.stat().st_size,
                "sha256": sha256_file(executable),
            },
        )
    return {
        "argv_template": list(command),
        "resolved_executable": str(executable),
        "executable_sha256": sha256_file(executable),
        "artifacts": artifacts,
    }


def classify_completed_process(
    return_code: int, stdout: str, stderr: str
) -> SolverResult:
    combined = f"{stdout}\n{stderr}"
    result_lines = tuple(
        line.strip().lower()
        for line in stdout.splitlines()
        if line.strip().lower() in {"sat", "unsat", "unknown"}
    )
    if ERROR_OUTPUT_PATTERN.search(combined):
        return SolverResult(
            "error",
            "solver_error_output",
            return_code,
            result_lines,
            _limited(stdout),
            _limited(stderr),
        )
    if return_code != 0:
        return SolverResult(
            "error",
            "nonzero_exit",
            return_code,
            result_lines,
            _limited(stdout),
            _limited(stderr),
        )
    if not result_lines:
        return SolverResult(
            "error", "malformed_output", return_code, (), _limited(stdout), _limited(stderr)
        )
    if len(result_lines) != 1:
        return SolverResult(
            "error",
            "multiple_results",
            return_code,
            result_lines,
            _limited(stdout),
            _limited(stderr),
        )
    classification = result_lines[0]
    reason = "solver_unknown" if classification == "unknown" else "solver_result"
    return SolverResult(
        classification,
        reason,
        return_code,
        result_lines,
        _limited(stdout),
        _limited(stderr),
    )


def run_solver(command: Sequence[str], case_path: Path, timeout_s: float) -> SolverResult:
    argv = materialize_command(command, case_path)
    try:
        completed = subprocess.run(
            argv,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        return SolverResult(
            "unknown",
            "timeout",
            124,
            (),
            _limited(_text(error.stdout)),
            _limited(_text(error.stderr)),
        )
    except OSError as error:
        return SolverResult("error", "spawn_error", None, (), "", str(error))
    return classify_completed_process(completed.returncode, completed.stdout, completed.stderr)


def solver_result_record(result: SolverResult) -> dict[str, object]:
    return {
        "classification": result.classification,
        "reason": result.reason,
        "exit_code": result.exit_code,
        "result_lines": list(result.result_lines),
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def evaluate_case(
    case: FormulaCase,
    observations: Mapping[str, SolverResult],
    *,
    viper_reject_exit_code: int,
) -> list[str]:
    expected_solvers = set(MANDATORY_SOLVERS)
    if "yices" in observations:
        expected_solvers.add("yices")
    if set(observations) != expected_solvers:
        raise ValueError(
            f"observation set mismatch for {case.case_id}: {sorted(observations)}"
        )

    anomalies: list[str] = []
    for name in SOLVER_ORDER:
        if name not in observations:
            continue
        result = observations[name]
        if result.reason == "solver_error_output":
            anomalies.append(f"{name}:solver_error_output")

    references = [name for name in ("z3", "cvc5", "yices") if name in observations]
    decisive_reference_results: list[str] = []
    for name in references:
        result = observations[name]
        if result.classification not in DECISIVE_RESULTS:
            anomalies.append(f"{name}:nondecisive:{result.reason}")
        else:
            decisive_reference_results.append(result.classification)
            if result.classification != case.expected:
                anomalies.append(f"{name}:expected-{case.expected}-got-{result.classification}")
    if len(set(decisive_reference_results)) > 1:
        anomalies.append("reference-disagreement")

    viper = observations["euf-viper"]
    if case.policy == CONSENSUS_POLICY:
        if viper.classification not in DECISIVE_RESULTS:
            anomalies.append(f"euf-viper:nondecisive:{viper.reason}")
        elif viper.classification != case.expected:
            anomalies.append(
                f"euf-viper:expected-{case.expected}-got-{viper.classification}"
            )
    else:
        valid_rejection = (
            viper.classification == "error"
            and viper.reason == "nonzero_exit"
            and viper.exit_code == viper_reject_exit_code
            and not viper.result_lines
        )
        if not valid_rejection:
            anomalies.append(
                "euf-viper:expected-clean-rejection-"
                f"exit-{viper_reject_exit_code}-got-{viper.reason}-"
                f"exit-{viper.exit_code}"
            )
    return anomalies


def candidate_anomalies(anomalies: Sequence[str]) -> list[str]:
    """Select obligations owned by euf-viper from the full differential audit."""

    return [anomaly for anomaly in anomalies if anomaly.startswith("euf-viper:")]


def analyze_metamorphic_groups(
    cases: Sequence[FormulaCase],
    observations: Mapping[str, Mapping[str, SolverResult]],
) -> list[dict[str, object]]:
    groups: dict[str, list[FormulaCase]] = defaultdict(list)
    for case in cases:
        groups[case.group_id].append(case)

    records: list[dict[str, object]] = []
    for group_id in sorted(groups):
        members = groups[group_id]
        anomalies: list[str] = []
        solver_results: dict[str, list[dict[str, str]]] = {}
        available = [name for name in SOLVER_ORDER if name in observations[members[0].case_id]]
        for name in available:
            eligible = [
                case
                for case in members
                if name != "euf-viper" or case.policy == CONSENSUS_POLICY
            ]
            values = [observations[case.case_id][name].classification for case in eligible]
            solver_results[name] = [
                {"case_id": case.case_id, "classification": value}
                for case, value in zip(eligible, values, strict=True)
            ]
            if any(value not in DECISIVE_RESULTS for value in values):
                anomalies.append(f"{name}:metamorphic-nondecisive")
            elif len(set(values)) > 1:
                anomalies.append(f"{name}:metamorphic-disagreement")
            elif values and values[0] != members[0].expected:
                anomalies.append(f"{name}:metamorphic-wrong-result")
        records.append(
            {
                "schema_version": SCHEMA_VERSION,
                "record_type": "metamorphic-group",
                "group_id": group_id,
                "expected": members[0].expected,
                "case_ids": [case.case_id for case in members],
                "solver_results": solver_results,
                "anomalies": anomalies,
                "passed": not anomalies,
                "candidate_anomalies": candidate_anomalies(anomalies),
                "candidate_passed": not candidate_anomalies(anomalies),
            }
        )
    return records


def _case_record(case: FormulaCase) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": "case",
        "case_id": case.case_id,
        "group_id": case.group_id,
        "family": case.family,
        "variant": case.variant,
        "policy": case.policy,
        "expected": case.expected,
        "path": f"cases/{case.case_id}.smt2",
        "source_sha256": sha256_bytes(case.source.encode("utf-8")),
        "source_size_bytes": len(case.source.encode("utf-8")),
        "metadata": case.metadata,
    }


def _provenance_record(
    *,
    mode: str,
    parser_mode: str | None,
    seed: int,
    random_groups: int,
    timeout_s: float | None,
    commands: Mapping[str, Sequence[str]],
    viper_reject_exit_code: int,
) -> dict[str, object]:
    script_path = Path(__file__).resolve()
    solver_provenance = {
        name: command_provenance(commands[name])
        for name in SOLVER_ORDER
        if name in commands
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": "provenance",
        "mode": mode,
        "generator": {
            "name": GENERATOR_VERSION,
            "seed": seed,
            "random_groups": random_groups,
            "script_path": str(script_path),
            "script_sha256": sha256_file(script_path),
        },
        "execution": {
            "candidate_parser_mode": parser_mode,
            "timeout_s": timeout_s,
            "viper_reject_exit_code": viper_reject_exit_code,
            "solvers": solver_provenance,
        },
        "runtime": {
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "platform": platform.platform(),
        },
    }


def _prepare_output_dir(output_dir: Path) -> None:
    if output_dir.exists():
        if not output_dir.is_dir():
            raise ValueError(f"output path is not a directory: {output_dir}")
        if any(output_dir.iterdir()):
            raise ValueError(f"refusing non-empty output directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)


def execute_campaign(
    *,
    cases: Sequence[FormulaCase],
    output_dir: Path,
    seed: int,
    random_groups: int,
    generation_only: bool,
    parser_mode: str | None = None,
    commands: Mapping[str, Sequence[str]] | None = None,
    timeout_s: float | None = None,
    viper_reject_exit_code: int = 2,
    checkpoint_path: Path | None = None,
    checkpoint_every: int = 1,
) -> dict[str, object]:
    _validate_cases(cases)
    commands = dict(commands or {})
    required = set() if generation_only else set(MANDATORY_SOLVERS)
    allowed = set(SOLVER_ORDER)
    if set(commands) - allowed:
        raise ValueError(f"unknown solver commands: {sorted(set(commands) - allowed)}")
    if not generation_only and not required.issubset(commands):
        raise ValueError(f"missing solver commands: {sorted(required - set(commands))}")
    if not generation_only and (timeout_s is None or timeout_s <= 0):
        raise ValueError("timeout must be positive")
    if not generation_only and parser_mode not in ACCEPTANCE_PARSER_MODES:
        raise ValueError("differential campaign requires parser mode shadow or stream")
    if parser_mode is not None and parser_mode not in ACCEPTANCE_PARSER_MODES:
        raise ValueError("parser mode must be shadow or stream")
    if not 1 <= viper_reject_exit_code <= 255:
        raise ValueError("viper reject exit code must be in [1, 255]")
    if checkpoint_every < 1:
        raise ValueError("checkpoint interval must be at least one")

    _prepare_output_dir(output_dir)
    mode = "generation-only" if generation_only else "differential"
    provenance = _provenance_record(
        mode=mode,
        parser_mode=parser_mode,
        seed=seed,
        random_groups=random_groups,
        timeout_s=None if generation_only else timeout_s,
        commands={} if generation_only else commands,
        viper_reject_exit_code=viper_reject_exit_code,
    )

    case_records = [_case_record(case) for case in cases]
    case_paths: dict[str, Path] = {}
    for case in cases:
        case_path = output_dir / "cases" / f"{case.case_id}.smt2"
        _atomic_write_text(case_path, case.source)
        case_paths[case.case_id] = case_path
    manifest_text = _json_line(provenance) + "".join(_json_line(record) for record in case_records)
    manifest_path = output_dir / "manifest.jsonl"
    _atomic_write_text(manifest_path, manifest_text)

    observations_by_case: dict[str, dict[str, SolverResult]] = {}
    result_records: list[dict[str, object]] = []
    checkpoint_generation = 0

    def write_checkpoint(
        campaign_status: str,
        *,
        metamorphic_records: Sequence[dict[str, object]] = (),
        summary: Mapping[str, object] | None = None,
    ) -> None:
        nonlocal checkpoint_generation
        if checkpoint_path is None:
            return
        checkpoint_generation += 1
        encoded_records = "".join(_json_line(record) for record in result_records).encode(
            "utf-8"
        )
        payload = {
            "schema_version": SCHEMA_VERSION,
            "artifact_type": "metamorphic-parser-checkpoint",
            "campaign_status": campaign_status,
            "generation": checkpoint_generation,
            "candidate_parser_mode": parser_mode,
            "generated_cases": len(cases),
            "completed_cases": len(result_records),
            "remaining_cases": len(cases) - len(result_records),
            "checkpoint_every_cases": checkpoint_every,
            "manifest_sha256": sha256_file(manifest_path),
            "records_sha256": sha256_bytes(encoded_records),
            "provenance": provenance,
            "case_records": case_records,
            "result_records": result_records,
            "metamorphic_records": list(metamorphic_records),
            "summary": dict(summary) if summary is not None else None,
        }
        _durable_atomic_write(checkpoint_path, _json_bytes(payload))

    write_checkpoint("running")
    if not generation_only:
        assert timeout_s is not None
        names = [name for name in SOLVER_ORDER if name in commands]
        for case in cases:
            observations = {
                name: run_solver(commands[name], case_paths[case.case_id], timeout_s)
                for name in names
            }
            observations_by_case[case.case_id] = observations
            anomalies = evaluate_case(
                case,
                observations,
                viper_reject_exit_code=viper_reject_exit_code,
            )
            result_records.append(
                {
                    **_case_record(case),
                    "record_type": "observation",
                    "observations": {
                        name: solver_result_record(observations[name]) for name in names
                    },
                    "anomalies": anomalies,
                    "passed": not anomalies,
                    "candidate_anomalies": candidate_anomalies(anomalies),
                    "candidate_passed": not candidate_anomalies(anomalies),
                }
            )
            if (
                len(result_records) % checkpoint_every == 0
                or result_records[-1]["anomalies"]
                or len(result_records) == len(cases)
            ):
                write_checkpoint("running")

    metamorphic_records = (
        []
        if generation_only
        else analyze_metamorphic_groups(cases, observations_by_case)
    )
    results_text = _json_line(provenance)
    results_text += "".join(_json_line(record) for record in result_records)
    results_text += "".join(_json_line(record) for record in metamorphic_records)
    results_path = output_dir / "results.jsonl"
    _atomic_write_text(results_path, results_text)

    anomaly_counts: Counter[str] = Counter()
    for record in result_records:
        anomaly_counts.update(record["anomalies"])
    for record in metamorphic_records:
        anomaly_counts.update(record["anomalies"])
    failed_cases = sum(not record["passed"] for record in result_records)
    failed_groups = sum(not record["passed"] for record in metamorphic_records)
    candidate_failed_cases = sum(
        not record["candidate_passed"] for record in result_records
    )
    candidate_failed_groups = sum(
        not record["candidate_passed"] for record in metamorphic_records
    )
    success = generation_only or (failed_cases == 0 and failed_groups == 0)
    candidate_success = generation_only or (
        candidate_failed_cases == 0 and candidate_failed_groups == 0
    )
    summary: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "mode": mode,
        "candidate_parser_mode": parser_mode,
        "success": success,
        "candidate_success": candidate_success,
        "counts": {
            "generated_cases": len(cases),
            "executed_cases": len(result_records),
            "metamorphic_groups": len({case.group_id for case in cases}),
            "failed_cases": failed_cases,
            "failed_groups": failed_groups,
            "candidate_failed_cases": candidate_failed_cases,
            "candidate_failed_groups": candidate_failed_groups,
        },
        "anomaly_counts": dict(sorted(anomaly_counts.items())),
        "artifacts": {
            "manifest_jsonl": "manifest.jsonl",
            "manifest_sha256": sha256_file(manifest_path),
            "results_jsonl": "results.jsonl",
            "results_sha256": sha256_file(results_path),
        },
    }
    _atomic_write_text(
        output_dir / "summary.json",
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
    )
    write_checkpoint(
        "complete", metamorphic_records=metamorphic_records, summary=summary
    )
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--random-groups", type=int, default=32)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--generate-only", action="store_true")
    parser.add_argument("--parser-mode", choices=ACCEPTANCE_PARSER_MODES)
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--checkpoint-every", type=int, default=1)
    parser.add_argument("--viper-reject-exit-code", type=int, default=2)
    parser.add_argument(
        "--gate",
        choices=(STRICT_GATE, CANDIDATE_GATE),
        default=STRICT_GATE,
        help=(
            "strict fails on any solver anomaly; candidate records comparator "
            "anomalies but gates only euf-viper"
        ),
    )
    parser.add_argument(
        "--viper-command",
        default="target/release/euf-viper solve {file}",
        help="argv string; append the case path unless {file} is a standalone token",
    )
    parser.add_argument("--z3-command", default="z3 -smt2 {file}")
    parser.add_argument("--cvc5-command", default="cvc5 --lang=smt2 {file}")
    parser.add_argument(
        "--yices-command",
        help="optional Yices argv string, for example 'yices-smt2 {file}'",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.random_groups < 0:
        parser.error("--random-groups must be non-negative")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if not args.generate_only and args.parser_mode is None:
        parser.error("--parser-mode is required for differential campaigns")
    if args.checkpoint_every < 1:
        parser.error("--checkpoint-every must be at least one")
    if not 1 <= args.viper_reject_exit_code <= 255:
        parser.error("--viper-reject-exit-code must be in [1, 255]")

    try:
        commands = {
            "euf-viper": parse_command(args.viper_command),
            "z3": parse_command(args.z3_command),
            "cvc5": parse_command(args.cvc5_command),
        }
        if args.yices_command:
            commands["yices"] = parse_command(args.yices_command)
        cases = generate_cases(args.seed, args.random_groups)
        summary = execute_campaign(
            cases=cases,
            output_dir=args.out,
            seed=args.seed,
            random_groups=args.random_groups,
            generation_only=args.generate_only,
            parser_mode=args.parser_mode,
            commands=None if args.generate_only else commands,
            timeout_s=None if args.generate_only else args.timeout,
            viper_reject_exit_code=args.viper_reject_exit_code,
            checkpoint_path=args.checkpoint,
            checkpoint_every=args.checkpoint_every,
        )
    except (OSError, ValueError) as error:
        print(f"metamorphic parser campaign error: {error}", file=sys.stderr)
        return 2

    counts = summary["counts"]
    if args.generate_only:
        print(f"generated {counts['generated_cases']} cases in {args.out}")
        return 0
    print(
        f"executed {counts['executed_cases']} cases in "
        f"{counts['metamorphic_groups']} groups; "
        f"failed cases {counts['failed_cases']}; "
        f"failed groups {counts['failed_groups']}; "
        f"candidate failed cases {counts['candidate_failed_cases']}; "
        f"candidate failed groups {counts['candidate_failed_groups']}"
    )
    gate_key = "success" if args.gate == STRICT_GATE else "candidate_success"
    return 0 if summary[gate_key] else 1


if __name__ == "__main__":
    raise SystemExit(main())
