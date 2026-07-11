#!/usr/bin/env python3
"""Differential QF_UF campaign for Boolean terms used as UF data.

The campaign deliberately treats Z3 and cvc5 as a two-solver oracle.  A case is
eligible for euf-viper comparison only when both references return the same
decisive result.  Timeouts are classified as ``unknown``; malformed output,
spawn failures, and non-zero exits are classified as ``error``.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import random
import re
import shlex
import subprocess
from collections import Counter
from pathlib import Path
from typing import Mapping, NamedTuple, Sequence


DECISIVE_RESULTS = {"sat", "unsat"}
RESULT_CLASSES = {"sat", "unsat", "unknown", "error"}
SOLVER_NAMES = ("euf-viper", "z3", "cvc5")
REFERENCE_NAMES = ("z3", "cvc5")
FILE_PLACEHOLDER = "{file}"
OUTPUT_LIMIT = 8192
CASE_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]*\Z")


class FormulaCase(NamedTuple):
    case_id: str
    family: str
    source: str
    metadata: dict[str, object]


class SolverResult(NamedTuple):
    classification: str
    reason: str
    exit_code: int | None
    stdout: str
    stderr: str


def _render_formula(declarations: Sequence[str], assertions: Sequence[str]) -> str:
    lines = ["(set-logic QF_UF)", "(declare-sort U 0)"]
    lines.extend(declarations)
    lines.extend(f"(assert {assertion})" for assertion in assertions)
    lines.append("(check-sat)")
    return "\n".join(lines) + "\n"


def _truth_assertion(symbol: str, value: bool) -> str:
    return symbol if value else f"(not {symbol})"


def generate_exhaustive_cases() -> list[FormulaCase]:
    """Instantiate every member of several finite, soundness-focused templates."""

    cases: list[FormulaCase] = []

    # Unconstrained Bool terms have a two-element semantic domain even when they
    # occur only beneath an uninterpreted function application.
    for term_family in ("symbols", "nested", "predicates"):
        for count in range(2, 5):
            declarations: list[str] = []
            if term_family == "symbols":
                declarations.extend(
                    f"(declare-fun p{i} () Bool)" for i in range(count)
                )
                terms = [f"p{i}" for i in range(count)]
            elif term_family == "nested":
                declarations.extend(
                    f"(declare-fun p{i} () Bool)" for i in range(count)
                )
                declarations.append("(declare-fun h (Bool) Bool)")
                terms = [f"(h p{i})" for i in range(count)]
            else:
                declarations.extend(
                    f"(declare-fun a{i} () U)" for i in range(count)
                )
                declarations.append("(declare-fun pred (U) Bool)")
                terms = [f"(pred a{i})" for i in range(count)]
            declarations.append("(declare-fun f (Bool) U)")
            images = " ".join(f"(f {term})" for term in terms)
            cases.append(
                FormulaCase(
                    f"exhaustive-unary-{term_family}-{count}",
                    "exhaustive-unary-domain",
                    _render_formula(declarations, [f"(distinct {images})"]),
                    {
                        "generator": "exhaustive",
                        "template": "unary-domain",
                        "term_family": term_family,
                        "image_count": count,
                    },
                )
            )

    # Exhaust all truth assignments and both output relations for two inputs.
    for left, right in itertools.product((False, True), repeat=2):
        for relation in ("equal", "distinct"):
            operator = "=" if relation == "equal" else "distinct"
            assertions = [
                _truth_assertion("p0", left),
                _truth_assertion("p1", right),
                f"({operator} (f p0) (f p1))",
            ]
            bits = f"{int(left)}{int(right)}"
            cases.append(
                FormulaCase(
                    f"exhaustive-forced-{bits}-{relation}",
                    "exhaustive-forced-values",
                    _render_formula(
                        [
                            "(declare-fun p0 () Bool)",
                            "(declare-fun p1 () Bool)",
                            "(declare-fun f (Bool) U)",
                        ],
                        assertions,
                    ),
                    {
                        "generator": "exhaustive",
                        "template": "forced-values",
                        "left": left,
                        "right": right,
                        "output_relation": relation,
                    },
                )
            )

    # Equality and its complement are Boolean expressions materialized as data.
    for relation in ("equal", "distinct"):
        operator = "=" if relation == "equal" else "distinct"
        cases.append(
            FormulaCase(
                f"exhaustive-bool-expression-{relation}",
                "exhaustive-bool-expression-data",
                _render_formula(
                    [
                        "(declare-fun a0 () U)",
                        "(declare-fun a1 () U)",
                        "(declare-fun f (Bool) U)",
                    ],
                    [
                        f"({operator} (f (= a0 a1)) "
                        "(f (distinct a0 a1)))"
                    ],
                ),
                {
                    "generator": "exhaustive",
                    "template": "bool-expression-data",
                    "output_relation": relation,
                },
            )
        )

    # Exhaust all assignments to a Boolean ite and compare its image to p.
    for condition, then_value, else_value in itertools.product(
        (False, True), repeat=3
    ):
        for relation in ("equal", "distinct"):
            operator = "=" if relation == "equal" else "distinct"
            bits = f"{int(condition)}{int(then_value)}{int(else_value)}"
            cases.append(
                FormulaCase(
                    f"exhaustive-ite-{bits}-{relation}",
                    "exhaustive-ite-data",
                    _render_formula(
                        [
                            "(declare-fun c () Bool)",
                            "(declare-fun p () Bool)",
                            "(declare-fun q () Bool)",
                            "(declare-fun f (Bool) U)",
                        ],
                        [
                            _truth_assertion("c", condition),
                            _truth_assertion("p", then_value),
                            _truth_assertion("q", else_value),
                            f"({operator} (f (ite c p q)) (f p))",
                        ],
                    ),
                    {
                        "generator": "exhaustive",
                        "template": "ite-data",
                        "condition": condition,
                        "then_value": then_value,
                        "else_value": else_value,
                        "output_relation": relation,
                    },
                )
            )

    # A k-argument Bool tuple has exactly 2**k possible values.  Independent
    # applications exercise both satisfiable and pigeonhole-sized instances.
    for image_count in range(2, 6):
        declarations = [
            f"(declare-fun p{i} () Bool)" for i in range(2 * image_count)
        ]
        declarations.append("(declare-fun f (Bool Bool) U)")
        images = " ".join(
            f"(f p{2 * i} p{2 * i + 1})" for i in range(image_count)
        )
        cases.append(
            FormulaCase(
                f"exhaustive-binary-domain-{image_count}",
                "exhaustive-binary-domain",
                _render_formula(declarations, [f"(distinct {images})"]),
                {
                    "generator": "exhaustive",
                    "template": "binary-domain",
                    "arity": 2,
                    "image_count": image_count,
                },
            )
        )

    for relation in ("equal", "distinct"):
        operator = "=" if relation == "equal" else "distinct"
        cases.append(
            FormulaCase(
                f"exhaustive-let-{relation}",
                "exhaustive-let-data",
                _render_formula(
                    [
                        "(declare-fun p () Bool)",
                        "(declare-fun f (Bool) U)",
                    ],
                    [f"({operator} (f (let ((bound p)) bound)) (f p))"],
                ),
                {
                    "generator": "exhaustive",
                    "template": "let-data",
                    "output_relation": relation,
                },
            )
        )

    _validate_cases(cases)
    return cases


def _derived_seed(seed: int, index: int, attempt: int) -> int:
    material = f"bool-data-v1:{seed}:{index}:{attempt}".encode("ascii")
    return int.from_bytes(hashlib.sha256(material).digest()[:16], "big")


def _random_formula(rng: random.Random) -> tuple[str, dict[str, object]]:
    bool_count = rng.randint(2, 6)
    u_count = rng.randint(1, 4)
    bool_fun_count = rng.randint(0, 2)
    predicate_count = rng.randint(0, 2)
    arity = rng.choice((1, 1, 1, 2))

    declarations = [
        *(f"(declare-fun p{i} () Bool)" for i in range(bool_count)),
        *(f"(declare-fun a{i} () U)" for i in range(u_count)),
        *(
            f"(declare-fun h{i} (Bool) Bool)"
            for i in range(bool_fun_count)
        ),
        *(
            f"(declare-fun pred{i} (U) Bool)"
            for i in range(predicate_count)
        ),
        f"(declare-fun f ({' '.join(['Bool'] * arity)}) U)",
    ]

    symbols = [f"p{i}" for i in range(bool_count)]
    bool_terms = [*symbols, "true", "false"]
    for function_index in range(bool_fun_count):
        function = f"h{function_index}"
        for symbol in symbols[: min(3, len(symbols))]:
            bool_terms.append(f"({function} {symbol})")
        if function_index:
            bool_terms.append(f"({function} (h0 {symbols[0]}))")
    for predicate_index in range(predicate_count):
        for constant_index in range(min(3, u_count)):
            bool_terms.append(f"(pred{predicate_index} a{constant_index})")
    bool_terms.extend(
        [
            f"(not {rng.choice(symbols)})",
            f"(ite {rng.choice(symbols)} {rng.choice(symbols)} "
            f"{rng.choice(symbols)})",
            f"(let ((bound {rng.choice(symbols)})) bound)",
            f"(= a{rng.randrange(u_count)} a{rng.randrange(u_count)})",
            f"(distinct a{rng.randrange(u_count)} a{rng.randrange(u_count)})",
        ]
    )

    def application() -> str:
        arguments = [rng.choice(bool_terms) for _ in range(arity)]
        return f"(f {' '.join(arguments)})"

    image_count = rng.randint(2, (2**arity) + 2)
    applications = [application() for _ in range(image_count)]
    primary_relation = rng.choice(("=", "distinct", "distinct"))
    assertions = [f"({primary_relation} {' '.join(applications)})"]

    for _ in range(rng.randint(0, 6)):
        choice = rng.randrange(8)
        left_bool = rng.choice(bool_terms)
        right_bool = rng.choice(bool_terms)
        if choice == 0:
            assertions.append(left_bool)
        elif choice == 1:
            assertions.append(f"(not {left_bool})")
        elif choice == 2:
            assertions.append(f"(= {left_bool} {right_bool})")
        elif choice == 3:
            assertions.append(f"(distinct {left_bool} {right_bool})")
        elif choice == 4:
            assertions.append(f"(or {left_bool} (not {right_bool}))")
        elif choice == 5:
            assertions.append(f"(and {left_bool} {right_bool})")
        elif choice == 6:
            left = f"a{rng.randrange(u_count)}"
            right = f"a{rng.randrange(u_count)}"
            operator = rng.choice(("=", "distinct"))
            assertions.append(f"({operator} {left} {right})")
        else:
            operator = rng.choice(("=", "distinct"))
            assertions.append(f"({operator} {application()} {application()})")

    source = _render_formula(declarations, assertions)
    metadata: dict[str, object] = {
        "generator": "random",
        "bool_constants": bool_count,
        "u_constants": u_count,
        "bool_functions": bool_fun_count,
        "predicates": predicate_count,
        "data_arity": arity,
        "primary_image_count": image_count,
        "assertions": len(assertions),
    }
    return source, metadata


def generate_random_cases(seed: int, count: int) -> list[FormulaCase]:
    if count < 0:
        raise ValueError("random case count must be non-negative")

    cases: list[FormulaCase] = []
    seen_sources: set[str] = set()
    for index in range(count):
        attempt = 0
        while True:
            derived_seed = _derived_seed(seed, index, attempt)
            source, metadata = _random_formula(random.Random(derived_seed))
            if source not in seen_sources:
                break
            attempt += 1
        seen_sources.add(source)
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        cases.append(
            FormulaCase(
                f"random-{index:05d}-{digest[:12]}",
                "random-bool-data",
                source,
                {
                    **metadata,
                    "index": index,
                    "seed": seed,
                    "derived_seed": derived_seed,
                },
            )
        )
    _validate_cases(cases)
    return cases


def generate_cases(
    seed: int, random_count: int, include_exhaustive: bool = True
) -> list[FormulaCase]:
    cases = generate_exhaustive_cases() if include_exhaustive else []
    random_cases = generate_random_cases(seed, random_count)
    seen_sources = {case.source for case in cases}
    cases.extend(case for case in random_cases if case.source not in seen_sources)
    _validate_cases(cases)
    return cases


def _validate_cases(cases: Sequence[FormulaCase]) -> None:
    case_ids: set[str] = set()
    for case in cases:
        if not CASE_ID_PATTERN.fullmatch(case.case_id):
            raise ValueError(f"unsafe case id: {case.case_id!r}")
        if case.case_id in case_ids:
            raise ValueError(f"duplicate case id: {case.case_id}")
        case_ids.add(case.case_id)
        if not case.source.endswith("\n"):
            raise ValueError(f"case lacks final newline: {case.case_id}")
        if case.source.count("(check-sat)") != 1:
            raise ValueError(f"case must contain one check-sat: {case.case_id}")
        if case.source.count("(") != case.source.count(")"):
            raise ValueError(f"unbalanced parentheses: {case.case_id}")


def parse_command(value: str) -> tuple[str, ...]:
    try:
        command = tuple(shlex.split(value))
    except ValueError as error:
        raise ValueError(f"invalid command: {error}") from error
    if not command:
        raise ValueError("solver command cannot be empty")
    placeholder_count = command.count(FILE_PLACEHOLDER)
    if placeholder_count > 1:
        raise ValueError("solver command may contain at most one {file} token")
    if any(FILE_PLACEHOLDER in token and token != FILE_PLACEHOLDER for token in command):
        raise ValueError("{file} must be a standalone command token")
    return command


def materialize_command(command: Sequence[str], case_path: Path) -> list[str]:
    if FILE_PLACEHOLDER in command:
        return [str(case_path) if token == FILE_PLACEHOLDER else token for token in command]
    return [*command, str(case_path)]


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _limited(value: str) -> str:
    if len(value) <= OUTPUT_LIMIT:
        return value
    return value[:OUTPUT_LIMIT] + "\n...[truncated]"


def classify_completed_process(
    return_code: int, stdout: str, stderr: str
) -> SolverResult:
    if return_code != 0:
        return SolverResult(
            "error",
            "nonzero_exit",
            return_code,
            _limited(stdout),
            _limited(stderr),
        )

    error_lines = [
        line.strip()
        for line in (*stdout.splitlines(), *stderr.splitlines())
        if line.strip().lower().startswith("(error")
    ]
    if error_lines:
        return SolverResult(
            "error",
            "solver_error_output",
            return_code,
            _limited(stdout),
            _limited(stderr),
        )

    recognized = [
        line.strip().lower()
        for line in stdout.splitlines()
        if line.strip().lower() in {"sat", "unsat", "unknown"}
    ]
    unique = set(recognized)
    if len(unique) > 1:
        return SolverResult(
            "error", "ambiguous_output", return_code, _limited(stdout), _limited(stderr)
        )
    if not recognized:
        return SolverResult(
            "error", "malformed_output", return_code, _limited(stdout), _limited(stderr)
        )
    classification = recognized[0]
    reason = "solver_unknown" if classification == "unknown" else "solver_result"
    return SolverResult(
        classification,
        reason,
        return_code,
        _limited(stdout),
        _limited(stderr),
    )


def run_solver(
    command: Sequence[str], case_path: Path, timeout_s: float
) -> SolverResult:
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
            _limited(_text(error.stdout)),
            _limited(_text(error.stderr)),
        )
    except OSError as error:
        return SolverResult("error", "spawn_error", None, "", str(error))
    return classify_completed_process(
        completed.returncode, completed.stdout, completed.stderr
    )


def solver_result_record(result: SolverResult) -> dict[str, object]:
    if result.classification not in RESULT_CLASSES:
        raise ValueError(f"invalid result classification: {result.classification}")
    return {
        "classification": result.classification,
        "reason": result.reason,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def analyze_observations(
    observations: Mapping[str, SolverResult]
) -> tuple[dict[str, object], list[str]]:
    missing = set(SOLVER_NAMES) - set(observations)
    if missing:
        raise ValueError(f"missing solver observations: {sorted(missing)}")

    z3_result = observations["z3"].classification
    cvc5_result = observations["cvc5"].classification
    references_agree = z3_result == cvc5_result
    references_decisive = references_agree and z3_result in DECISIVE_RESULTS
    expected = z3_result if references_decisive else None
    anomalies: list[str] = []
    if not references_agree:
        anomalies.append("reference_disagreement")
    elif not references_decisive:
        anomalies.append("reference_nondecisive")
    elif observations["euf-viper"].classification != expected:
        anomalies.append("viper_discrepancy")

    reference = {
        "agree": references_agree,
        "decisive": references_decisive,
        "classification": expected,
    }
    return reference, anomalies


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def _case_base_record(case: FormulaCase) -> dict[str, object]:
    digest = hashlib.sha256(case.source.encode("utf-8")).hexdigest()
    return {
        "id": case.case_id,
        "family": case.family,
        "path": f"cases/{case.case_id}.smt2",
        "sha256": digest,
        "metadata": case.metadata,
    }


def write_case_files(output_dir: Path, cases: Sequence[FormulaCase]) -> dict[str, Path]:
    _validate_cases(cases)
    paths: dict[str, Path] = {}
    for case in cases:
        path = output_dir / "cases" / f"{case.case_id}.smt2"
        _atomic_write_text(path, case.source)
        paths[case.case_id] = path
    return paths


def _build_summary(
    *,
    cases: Sequence[FormulaCase],
    case_records: list[dict[str, object]],
    mode: str,
    seed: int,
    requested_random_cases: int,
    timeout_s: float | None,
    commands: Mapping[str, Sequence[str]] | None,
) -> dict[str, object]:
    anomaly_counter: Counter[str] = Counter()
    outcome_counts = {name: Counter() for name in SOLVER_NAMES}
    reference_agreements = 0
    reference_decisive = 0
    anomalous_cases = 0
    for record in case_records:
        anomalies = record.get("anomalies", [])
        if isinstance(anomalies, list):
            anomaly_counter.update(str(item) for item in anomalies)
            anomalous_cases += bool(anomalies)
        observations = record.get("observations")
        if isinstance(observations, dict):
            for name in SOLVER_NAMES:
                observation = observations[name]
                outcome_counts[name][observation["classification"]] += 1
            reference = record["reference"]
            reference_agreements += bool(reference["agree"])
            reference_decisive += bool(reference["decisive"])

    exhaustive_count = sum(
        case.metadata.get("generator") == "exhaustive" for case in cases
    )
    random_count = sum(case.metadata.get("generator") == "random" for case in cases)
    summary: dict[str, object] = {
        "schema_version": 1,
        "mode": mode,
        "generation": {
            "seed": seed,
            "requested_random_cases": requested_random_cases,
            "exhaustive_cases": exhaustive_count,
            "random_cases": random_count,
        },
        "counts": {
            "generated_cases": len(cases),
            "executed_cases": len(cases) if mode == "differential" else 0,
            "reference_agreements": reference_agreements,
            "reference_decisive_agreements": reference_decisive,
            "reference_disagreements": anomaly_counter["reference_disagreement"],
            "reference_nondecisive": anomaly_counter["reference_nondecisive"],
            "viper_discrepancies": anomaly_counter["viper_discrepancy"],
            "anomalous_cases": anomalous_cases,
            "discrepancy_formulas": anomalous_cases,
        },
        "outcomes": {
            name: dict(sorted(outcome_counts[name].items())) for name in SOLVER_NAMES
        },
        "cases": case_records,
    }
    if mode == "differential":
        assert commands is not None and timeout_s is not None
        summary["execution"] = {
            "timeout_s": timeout_s,
            "commands": {name: list(commands[name]) for name in SOLVER_NAMES},
        }
    return summary


def execute_campaign(
    *,
    cases: Sequence[FormulaCase],
    output_dir: Path,
    seed: int,
    requested_random_cases: int,
    generation_only: bool,
    commands: Mapping[str, Sequence[str]] | None = None,
    timeout_s: float | None = None,
) -> dict[str, object]:
    case_paths = write_case_files(output_dir, cases)
    case_records: list[dict[str, object]] = []

    if generation_only:
        case_records = [_case_base_record(case) for case in cases]
        mode = "generation-only"
    else:
        if commands is None or set(commands) != set(SOLVER_NAMES):
            raise ValueError(f"commands must define exactly {list(SOLVER_NAMES)}")
        if timeout_s is None or timeout_s <= 0:
            raise ValueError("timeout must be positive")
        mode = "differential"
        for case in cases:
            observations = {
                name: run_solver(commands[name], case_paths[case.case_id], timeout_s)
                for name in SOLVER_NAMES
            }
            reference, anomalies = analyze_observations(observations)
            record = {
                **_case_base_record(case),
                "observations": {
                    name: solver_result_record(observations[name])
                    for name in SOLVER_NAMES
                },
                "reference": reference,
                "anomalies": anomalies,
            }
            if anomalies:
                discrepancy_path = (
                    output_dir / "discrepancies" / f"{case.case_id}.smt2"
                )
                _atomic_write_text(discrepancy_path, case.source)
                record["discrepancy_path"] = (
                    f"discrepancies/{case.case_id}.smt2"
                )
            case_records.append(record)

    summary = _build_summary(
        cases=cases,
        case_records=case_records,
        mode=mode,
        seed=seed,
        requested_random_cases=requested_random_cases,
        timeout_s=timeout_s,
        commands=commands,
    )
    _atomic_write_text(
        output_dir / "summary.json",
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
    )
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--random-cases", type=int, default=256)
    parser.add_argument("--no-exhaustive", action="store_true")
    parser.add_argument("--generate-only", action="store_true")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument(
        "--viper-command",
        default="target/release/euf-viper solve {file}",
        help="argv string; append the case path unless a standalone {file} token is present",
    )
    parser.add_argument(
        "--z3-command",
        default="z3 -smt2 {file}",
        help="argv string; append the case path unless a standalone {file} token is present",
    )
    parser.add_argument(
        "--cvc5-command",
        default="cvc5 --lang=smt2 {file}",
        help="argv string; append the case path unless a standalone {file} token is present",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.random_cases < 0:
        parser.error("--random-cases must be non-negative")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.no_exhaustive and args.random_cases == 0:
        parser.error("campaign selection is empty")

    try:
        commands = {
            "euf-viper": parse_command(args.viper_command),
            "z3": parse_command(args.z3_command),
            "cvc5": parse_command(args.cvc5_command),
        }
    except ValueError as error:
        parser.error(str(error))

    cases = generate_cases(
        seed=args.seed,
        random_count=args.random_cases,
        include_exhaustive=not args.no_exhaustive,
    )
    summary = execute_campaign(
        cases=cases,
        output_dir=args.out,
        seed=args.seed,
        requested_random_cases=args.random_cases,
        generation_only=args.generate_only,
        commands=None if args.generate_only else commands,
        timeout_s=None if args.generate_only else args.timeout,
    )

    counts = summary["counts"]
    if args.generate_only:
        print(f"generated {counts['generated_cases']} cases in {args.out}")
        return 0
    print(
        f"executed {counts['executed_cases']} cases; "
        f"reference failures "
        f"{counts['reference_disagreements'] + counts['reference_nondecisive']}; "
        f"euf-viper discrepancies {counts['viper_discrepancies']}"
    )
    if counts["reference_disagreements"] or counts["reference_nondecisive"]:
        return 2
    return 1 if counts["viper_discrepancies"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
