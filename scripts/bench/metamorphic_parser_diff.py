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
import contextlib
import hashlib
import json
import os
import platform
import random
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterator, Mapping, NamedTuple, Sequence


SCHEMA_VERSION = 3
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
RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
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


class StagedArtifact(NamedTuple):
    original_path: Path
    consumed_path: Path
    fd: int
    fd_path: str
    size_bytes: int
    sha256: str
    device: int
    inode: int


class BoundCommand(NamedTuple):
    argv_template: tuple[str, ...]
    pass_fds: tuple[int, ...]
    artifacts: tuple[StagedArtifact, ...]
    provenance: dict[str, object]


class PinnedSource(NamedTuple):
    original_path: Path
    fd: int
    fd_path: str
    size_bytes: int
    sha256: str
    device: int
    inode: int


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fd_identity(fd: int) -> tuple[int, str]:
    if os.name != "posix" or not hasattr(os, "pread"):
        raise ValueError("byte-bound solver campaigns require POSIX pread support")
    size = 0
    offset = 0
    digest = hashlib.sha256()
    while True:
        chunk = os.pread(fd, 1024 * 1024, offset)
        if not chunk:
            break
        size += len(chunk)
        offset += len(chunk)
        digest.update(chunk)
    return size, digest.hexdigest()


def _inherited_fd_path(fd: int) -> str:
    for root in (Path("/proc/self/fd"), Path("/dev/fd")):
        if root.is_dir():
            return str(root / str(fd))
    raise ValueError("cannot expose source descriptor through /proc/self/fd or /dev/fd")


def _command_artifacts_use_fd_paths() -> bool:
    return os.name == "posix" and Path("/proc/self/fd").is_dir()


def _copy_fd_to_stage(source_fd: int, size_bytes: int, destination: Path) -> None:
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o700,
    )
    try:
        offset = 0
        while offset < size_bytes:
            chunk = os.pread(source_fd, min(1024 * 1024, size_bytes - offset), offset)
            if not chunk:
                raise ValueError("opened command artifact changed size while staging")
            view = memoryview(chunk)
            while view:
                written = os.write(descriptor, view)
                if written == 0:
                    raise OSError("short write while staging command artifact")
                view = view[written:]
            offset += len(chunk)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _stage_artifact(
    original: Path,
    stage_root: Path,
    cache: dict[Path, StagedArtifact],
) -> StagedArtifact:
    resolved = original.expanduser().resolve()
    if resolved in cache:
        return cache[resolved]
    descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"command artifact is not a regular file: {resolved}")
        size_bytes, digest = _fd_identity(descriptor)
        staged_path = stage_root / f"artifact-{len(cache):04d}"
        _copy_fd_to_stage(descriptor, size_bytes, staged_path)
    finally:
        os.close(descriptor)
    os.chmod(staged_path, 0o500 if metadata.st_mode & 0o111 else 0o400)
    consumed_descriptor = os.open(
        staged_path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        consumed_metadata = os.fstat(consumed_descriptor)
        consumed_size, consumed_sha256 = _fd_identity(consumed_descriptor)
        if consumed_size != size_bytes or consumed_sha256 != digest:
            raise ValueError(
                f"staged command artifact differs from opened bytes: {resolved}"
            )
        consumed_fd_path = _inherited_fd_path(consumed_descriptor)
    except BaseException:
        os.close(consumed_descriptor)
        raise
    artifact = StagedArtifact(
        original_path=resolved,
        consumed_path=staged_path,
        fd=consumed_descriptor,
        fd_path=consumed_fd_path,
        size_bytes=consumed_size,
        sha256=consumed_sha256,
        device=consumed_metadata.st_dev,
        inode=consumed_metadata.st_ino,
    )
    cache[resolved] = artifact
    return artifact


def _command_file_tokens(command: Sequence[str]) -> dict[int, Path]:
    files = {0: _resolve_executable(command[0])}
    for index, token in enumerate(command[1:], start=1):
        if token == FILE_PLACEHOLDER:
            continue
        candidate = Path(token).expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved.is_file():
            files[index] = resolved
    return files


def bind_command(
    command: Sequence[str],
    stage_root: Path,
    cache: dict[Path, StagedArtifact],
) -> BoundCommand:
    rewritten = list(command)
    artifact_records = []
    bound_artifacts = []
    use_fd_paths = _command_artifacts_use_fd_paths()
    file_tokens = _command_file_tokens(command)
    for token_index, path in sorted(file_tokens.items()):
        artifact = _stage_artifact(path, stage_root, cache)
        rewritten[token_index] = (
            artifact.fd_path if use_fd_paths else str(artifact.consumed_path)
        )
        bound_artifacts.append(artifact)
        artifact_records.append(
            {
                "token_index": token_index,
                "original_path": str(artifact.original_path),
                "consumed_path": str(artifact.consumed_path),
                "consumed_fd_path": artifact.fd_path,
                "size_bytes": artifact.size_bytes,
                "sha256": artifact.sha256,
                "device": artifact.device,
                "inode": artifact.inode,
                "consumed_via": (
                    "inherited-fd-for-verified-private-stage"
                    if use_fd_paths
                    else "verified-private-stage-with-retained-fd"
                ),
            }
        )
    executable = next(
        item for item in artifact_records if item["token_index"] == 0
    )
    return BoundCommand(
        argv_template=tuple(rewritten),
        pass_fds=tuple(
            sorted(
                {cache[path.expanduser().resolve()].fd for path in file_tokens.values()}
                if use_fd_paths
                else ()
            )
        ),
        artifacts=tuple(bound_artifacts),
        provenance={
            "argv_template": list(command),
            "bound_argv_template": rewritten,
            "resolved_executable": executable["original_path"],
            "executable_sha256": executable["sha256"],
            "artifacts": artifact_records,
        },
    )


def release_staged_artifacts(
    cache: Mapping[Path, StagedArtifact],
    stage_root: Path,
    *,
    verify: bool,
) -> None:
    mismatch: Path | None = None
    try:
        if verify:
            for artifact in cache.values():
                size_bytes, digest = _fd_identity(artifact.fd)
                if size_bytes != artifact.size_bytes or digest != artifact.sha256:
                    mismatch = artifact.original_path
                    break
    finally:
        for artifact in cache.values():
            os.close(artifact.fd)
        shutil.rmtree(stage_root, ignore_errors=True)
    if mismatch is not None:
        raise ValueError(f"staged command artifact changed during campaign: {mismatch}")


def verify_bound_command_paths(command: BoundCommand) -> None:
    if command.pass_fds:
        return
    for artifact in command.artifacts:
        metadata = artifact.consumed_path.stat()
        if metadata.st_dev != artifact.device or metadata.st_ino != artifact.inode:
            raise ValueError(
                "staged command path no longer names the verified object: "
                f"{artifact.consumed_path}"
            )


@contextlib.contextmanager
def open_pinned_source(path: Path) -> Iterator[PinnedSource]:
    resolved = path.expanduser().resolve()
    descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"generated source is not a regular file: {resolved}")
        size_bytes, digest = _fd_identity(descriptor)
        yield PinnedSource(
            original_path=resolved,
            fd=descriptor,
            fd_path=_inherited_fd_path(descriptor),
            size_bytes=size_bytes,
            sha256=digest,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
    finally:
        os.close(descriptor)


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


def run_solver(
    command: Sequence[str] | BoundCommand,
    case_path: Path | PinnedSource,
    timeout_s: float,
) -> SolverResult:
    if isinstance(command, BoundCommand):
        bound_command = command
        template = command.argv_template
        inherited_fds = set(command.pass_fds)
        verify_bound_command_paths(command)
    else:
        bound_command = None
        template = command
        inherited_fds = set()
    if isinstance(case_path, PinnedSource):
        os.lseek(case_path.fd, 0, os.SEEK_SET)
        materialized_path = Path(case_path.fd_path)
        inherited_fds.add(case_path.fd)
    else:
        materialized_path = case_path
    argv = materialize_command(template, materialized_path)
    try:
        try:
            completed = subprocess.run(
                argv,
                pass_fds=tuple(sorted(inherited_fds)),
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
        return classify_completed_process(
            completed.returncode, completed.stdout, completed.stderr
        )
    finally:
        if bound_command is not None:
            verify_bound_command_paths(bound_command)


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
    run_id: str | None,
    seed: int,
    random_groups: int,
    timeout_s: float | None,
    commands: Mapping[str, BoundCommand],
    viper_reject_exit_code: int,
) -> dict[str, object]:
    script_path = Path(__file__).resolve()
    solver_provenance = {
        name: commands[name].provenance
        for name in SOLVER_ORDER
        if name in commands
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": "provenance",
        "mode": mode,
        "run_id": run_id,
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


def _paths_conflict(first: Path, second: Path) -> bool:
    return (
        first == second
        or first in second.parents
        or second in first.parents
    )


def validate_generation_paths(
    *,
    output_dir: Path,
    checkpoint_path: Path | None,
    cases: Sequence[FormulaCase],
    commands: Mapping[str, Sequence[str]],
) -> tuple[Path, Path | None]:
    output = output_dir.expanduser().resolve()
    checkpoint = (
        checkpoint_path.expanduser().resolve()
        if checkpoint_path is not None
        else None
    )
    generated_files = [
        output / "manifest.jsonl",
        output / "results.jsonl",
        output / "summary.json",
        *(output / "cases" / f"{case.case_id}.smt2" for case in cases),
    ]
    if len(set(generated_files)) != len(generated_files):
        raise ValueError("generated campaign destinations are not unique")
    for index, path in enumerate(generated_files):
        for other in generated_files[:index]:
            if _paths_conflict(path, other):
                raise ValueError(
                    "generated campaign destinations have an "
                    f"ancestor/descendant conflict: {path} vs {other}"
                )
    if checkpoint is not None:
        if _paths_conflict(output, checkpoint):
            raise ValueError(
                "checkpoint and output directory must not alias or be nested: "
                f"{checkpoint} vs {output}"
            )
        if checkpoint.exists():
            raise ValueError(f"refusing stale checkpoint destination: {checkpoint}")

    protected = {
        path
        for command in commands.values()
        for path in _command_file_tokens(command).values()
    }
    for protected_path in protected:
        if _paths_conflict(output, protected_path):
            raise ValueError(
                "output directory conflicts with a command artifact: "
                f"{output} vs {protected_path}"
            )
        if checkpoint is not None and _paths_conflict(checkpoint, protected_path):
            raise ValueError(
                "checkpoint conflicts with a command artifact: "
                f"{checkpoint} vs {protected_path}"
            )
        if (
            checkpoint is not None
            and checkpoint.exists()
            and os.path.samefile(checkpoint, protected_path)
        ):
            raise ValueError("checkpoint aliases a command artifact inode")
    return output, checkpoint


def execute_campaign(
    *,
    cases: Sequence[FormulaCase],
    output_dir: Path,
    seed: int,
    random_groups: int,
    generation_only: bool,
    parser_mode: str | None = None,
    run_id: str | None = None,
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
    if run_id is not None and RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise ValueError(f"unsafe run id: {run_id!r}")
    if not 1 <= viper_reject_exit_code <= 255:
        raise ValueError("viper reject exit code must be in [1, 255]")
    if checkpoint_every < 1:
        raise ValueError("checkpoint interval must be at least one")

    output_dir, checkpoint_path = validate_generation_paths(
        output_dir=output_dir,
        checkpoint_path=checkpoint_path,
        cases=cases,
        commands=commands,
    )
    _prepare_output_dir(output_dir)
    stage_root = output_dir / ".solver-stage"
    stage_root.mkdir(mode=0o700)
    artifact_cache: dict[Path, StagedArtifact] = {}
    try:
        bound_commands = {
            name: bind_command(commands[name], stage_root, artifact_cache)
            for name in SOLVER_ORDER
            if name in commands
        }
    except BaseException:
        release_staged_artifacts(artifact_cache, stage_root, verify=False)
        raise
    mode = "generation-only" if generation_only else "differential"
    provenance = _provenance_record(
        mode=mode,
        parser_mode=parser_mode,
        run_id=run_id,
        seed=seed,
        random_groups=random_groups,
        timeout_s=None if generation_only else timeout_s,
        commands={} if generation_only else bound_commands,
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
            "run_id": run_id,
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
        names = [name for name in SOLVER_ORDER if name in bound_commands]
        for case in cases:
            expected_source = _case_record(case)
            with open_pinned_source(case_paths[case.case_id]) as pinned_source:
                if (
                    pinned_source.size_bytes != expected_source["source_size_bytes"]
                    or pinned_source.sha256 != expected_source["source_sha256"]
                ):
                    raise ValueError(
                        f"generated source bytes do not match manifest: {case.case_id}"
                    )
                observations = {
                    name: run_solver(
                        bound_commands[name], pinned_source, timeout_s
                    )
                    for name in names
                }
                final_size, final_sha256 = _fd_identity(pinned_source.fd)
                if (
                    final_size != pinned_source.size_bytes
                    or final_sha256 != pinned_source.sha256
                ):
                    raise ValueError(
                        f"generated source changed during execution: {case.case_id}"
                    )
                source_binding = {
                    "original_path": str(pinned_source.original_path),
                    "size_bytes": pinned_source.size_bytes,
                    "sha256": pinned_source.sha256,
                    "device": pinned_source.device,
                    "inode": pinned_source.inode,
                    "consumed_via": "inherited-posix-fd",
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
                    "source_consumed": source_binding,
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

    release_staged_artifacts(artifact_cache, stage_root, verify=True)
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
        "run_id": run_id,
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


def _read_jsonl(path: Path, snapshot: bytes | None = None) -> list[dict[str, object]]:
    try:
        value = path.read_bytes() if snapshot is None else snapshot
        lines = value.decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ValueError(f"cannot read cross-mode artifact {path}: {error}") from error
    records = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{line_number}: invalid JSON: {error}") from error
        if not isinstance(record, dict):
            raise ValueError(f"{path}:{line_number}: record must be an object")
        records.append(record)
    return records


def _candidate_observation_projection(record: Mapping[str, object]) -> dict[str, object]:
    observations = record.get("observations")
    if not isinstance(observations, dict) or "euf-viper" not in observations:
        raise ValueError(f"missing euf-viper observation for {record.get('case_id')}")
    euf_result = observations["euf-viper"]
    if not isinstance(euf_result, dict):
        raise ValueError(f"malformed euf-viper observation for {record.get('case_id')}")
    return {
        "case_id": record.get("case_id"),
        "expected": record.get("expected"),
        "policy": record.get("policy"),
        "source_sha256": record.get("source_sha256"),
        "source_size_bytes": record.get("source_size_bytes"),
        "candidate_passed": record.get("candidate_passed"),
        "candidate_anomalies": record.get("candidate_anomalies"),
        "euf-viper": {
            key: euf_result.get(key)
            for key in ("classification", "reason", "exit_code", "result_lines")
        },
    }


def _candidate_group_projection(record: Mapping[str, object]) -> dict[str, object]:
    solver_results = record.get("solver_results")
    if not isinstance(solver_results, dict) or "euf-viper" not in solver_results:
        raise ValueError(f"missing euf-viper group results for {record.get('group_id')}")
    return {
        "group_id": record.get("group_id"),
        "expected": record.get("expected"),
        "case_ids": record.get("case_ids"),
        "candidate_passed": record.get("candidate_passed"),
        "candidate_anomalies": record.get("candidate_anomalies"),
        "euf-viper": solver_results["euf-viper"],
    }


def compare_mode_campaigns(
    shadow_dir: Path,
    stream_dir: Path,
    output_path: Path,
) -> dict[str, object]:
    shadow = shadow_dir.expanduser().resolve()
    stream = stream_dir.expanduser().resolve()
    output = output_path.expanduser().resolve()
    if _paths_conflict(shadow, stream):
        raise ValueError(
            f"shadow and stream campaign directories collide: {shadow} vs {stream}"
        )
    if _paths_conflict(output, shadow) or _paths_conflict(output, stream):
        raise ValueError("cross-mode output must not alias or nest with mode outputs")
    if output.exists():
        raise ValueError(f"refusing stale cross-mode output: {output}")

    artifacts: dict[str, dict[str, object]] = {}
    loaded: dict[str, tuple[dict[str, object], list[dict[str, object]], list[dict[str, object]]]] = {}
    for mode, directory in (("shadow", shadow), ("stream", stream)):
        summary_path = directory / "summary.json"
        manifest_path = directory / "manifest.jsonl"
        results_path = directory / "results.jsonl"
        try:
            summary_snapshot = summary_path.read_bytes()
            manifest_snapshot = manifest_path.read_bytes()
            results_snapshot = results_path.read_bytes()
            summary = json.loads(summary_snapshot.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"cannot read {mode} summary: {error}") from error
        if not isinstance(summary, dict):
            raise ValueError(f"{mode} summary must be an object")
        loaded[mode] = (
            summary,
            _read_jsonl(manifest_path, manifest_snapshot),
            _read_jsonl(results_path, results_snapshot),
        )
        artifacts[mode] = {
            "directory": str(directory),
            "manifest_sha256": sha256_bytes(manifest_snapshot),
            "results_sha256": sha256_bytes(results_snapshot),
            "summary_sha256": sha256_bytes(summary_snapshot),
        }

    mismatches: list[str] = []
    shadow_summary, shadow_manifest, shadow_results = loaded["shadow"]
    stream_summary, stream_manifest, stream_results = loaded["stream"]
    mode_views: dict[
        str,
        tuple[
            list[dict[str, object]],
            list[dict[str, object]],
            list[dict[str, object]],
        ],
    ] = {}
    for mode, (summary, manifest, results) in loaded.items():
        if summary.get("mode") != "differential":
            mismatches.append(f"{mode}:not-a-differential-campaign")
        if summary.get("candidate_parser_mode") != mode:
            mismatches.append(f"{mode}:parser-mode-mismatch")
        if summary.get("candidate_success") is not True:
            mismatches.append(f"{mode}:candidate-gate-failed")
        declared_artifacts = summary.get("artifacts")
        if not isinstance(declared_artifacts, dict):
            mismatches.append(f"{mode}:missing-artifact-hashes")
        else:
            if (
                declared_artifacts.get("manifest_sha256")
                != artifacts[mode]["manifest_sha256"]
            ):
                mismatches.append(f"{mode}:manifest-hash-mismatch")
            if (
                declared_artifacts.get("results_sha256")
                != artifacts[mode]["results_sha256"]
            ):
                mismatches.append(f"{mode}:results-hash-mismatch")

        manifest_provenance = [
            record for record in manifest if record.get("record_type") == "provenance"
        ]
        results_provenance = [
            record for record in results if record.get("record_type") == "provenance"
        ]
        cases = [record for record in manifest if record.get("record_type") == "case"]
        observation_records = [
            record for record in results if record.get("record_type") == "observation"
        ]
        group_records = [
            record
            for record in results
            if record.get("record_type") == "metamorphic-group"
        ]
        mode_views[mode] = (cases, observation_records, group_records)

        if len(manifest_provenance) != 1 or len(results_provenance) != 1:
            mismatches.append(f"{mode}:provenance-cardinality-mismatch")
        elif manifest_provenance[0] != results_provenance[0]:
            mismatches.append(f"{mode}:provenance-records-differ")
        else:
            provenance = manifest_provenance[0]
            execution = provenance.get("execution")
            if provenance.get("mode") != "differential":
                mismatches.append(f"{mode}:provenance-mode-mismatch")
            if provenance.get("run_id") != summary.get("run_id"):
                mismatches.append(f"{mode}:provenance-run-id-mismatch")
            if (
                not isinstance(execution, dict)
                or execution.get("candidate_parser_mode") != mode
            ):
                mismatches.append(f"{mode}:provenance-parser-mode-mismatch")

        expected_record_types = {"provenance", "case"}
        if any(record.get("record_type") not in expected_record_types for record in manifest):
            mismatches.append(f"{mode}:unexpected-manifest-record")
        expected_result_types = {"provenance", "observation", "metamorphic-group"}
        if any(record.get("record_type") not in expected_result_types for record in results):
            mismatches.append(f"{mode}:unexpected-results-record")

        case_ids = [record.get("case_id") for record in cases]
        observation_ids = [record.get("case_id") for record in observation_records]
        if not case_ids or observation_ids != case_ids:
            mismatches.append(f"{mode}:case-observation-order-mismatch")
        case_group_ids = [record.get("group_id") for record in cases]
        if any(not isinstance(group_id, str) for group_id in case_group_ids):
            mismatches.append(f"{mode}:invalid-case-group-id")
        expected_group_ids = sorted(
            {group_id for group_id in case_group_ids if isinstance(group_id, str)}
        )
        group_ids = [record.get("group_id") for record in group_records]
        if group_ids != expected_group_ids:
            mismatches.append(f"{mode}:metamorphic-group-coverage-mismatch")
        if any(record.get("candidate_passed") is not True for record in observation_records):
            mismatches.append(f"{mode}:candidate-observation-failed")
        if any(record.get("candidate_passed") is not True for record in group_records):
            mismatches.append(f"{mode}:candidate-group-failed")
        for record in observation_records:
            source_consumed = record.get("source_consumed")
            if (
                not isinstance(source_consumed, dict)
                or source_consumed.get("sha256") != record.get("source_sha256")
                or source_consumed.get("size_bytes") != record.get("source_size_bytes")
            ):
                mismatches.append(f"{mode}:source-byte-binding-mismatch")
                break

        counts = summary.get("counts")
        expected_counts = {
            "generated_cases": len(cases),
            "executed_cases": len(observation_records),
            "metamorphic_groups": len(group_records),
        }
        if not isinstance(counts, dict):
            mismatches.append(f"{mode}:missing-counts")
        else:
            for name, expected in expected_counts.items():
                if counts.get(name) != expected:
                    mismatches.append(f"{mode}:{name}-count-mismatch")

    shadow_run_id = shadow_summary.get("run_id")
    stream_run_id = stream_summary.get("run_id")
    if not isinstance(shadow_run_id, str) or not shadow_run_id.endswith("-shadow"):
        mismatches.append("shadow:run-id-not-mode-qualified")
        shadow_base = None
    else:
        shadow_base = shadow_run_id.removesuffix("-shadow")
    if not isinstance(stream_run_id, str) or not stream_run_id.endswith("-stream"):
        mismatches.append("stream:run-id-not-mode-qualified")
        stream_base = None
    else:
        stream_base = stream_run_id.removesuffix("-stream")
    if shadow_base is not None and stream_base is not None and shadow_base != stream_base:
        mismatches.append("mode-run-ids-have-different-base")

    shadow_cases = [
        record for record in shadow_manifest if record.get("record_type") == "case"
    ]
    stream_cases = [
        record for record in stream_manifest if record.get("record_type") == "case"
    ]
    if shadow_cases != stream_cases:
        mismatches.append("generated-case-manifests-differ")

    def observations(records: Sequence[dict[str, object]]) -> list[dict[str, object]]:
        return [
            _candidate_observation_projection(record)
            for record in records
            if record.get("record_type") == "observation"
        ]

    def groups(records: Sequence[dict[str, object]]) -> list[dict[str, object]]:
        return [
            _candidate_group_projection(record)
            for record in records
            if record.get("record_type") == "metamorphic-group"
        ]

    if observations(shadow_results) != observations(stream_results):
        mismatches.append("candidate-observations-differ")
    if groups(shadow_results) != groups(stream_results):
        mismatches.append("candidate-metamorphic-groups-differ")

    payload: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "metamorphic-parser-cross-mode-gate",
        "campaign_status": "complete",
        "gate_passed": not mismatches,
        "base_run_id": shadow_base if shadow_base == stream_base else None,
        "mode_run_ids": {
            "shadow": shadow_run_id,
            "stream": stream_run_id,
        },
        "counts": {
            "generated_cases": len(shadow_cases),
            "candidate_observations": len(observations(shadow_results)),
            "candidate_groups": len(groups(shadow_results)),
        },
        "mismatches": mismatches,
        "artifacts": artifacts,
    }
    _durable_atomic_write(output, _json_bytes(payload))
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--run-id")
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
    parser.add_argument("--cross-mode-shadow", type=Path)
    parser.add_argument("--cross-mode-stream", type=Path)
    parser.add_argument("--cross-mode-out", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cross_mode_values = (
        args.cross_mode_shadow,
        args.cross_mode_stream,
        args.cross_mode_out,
    )
    if any(value is not None for value in cross_mode_values):
        if not all(value is not None for value in cross_mode_values):
            parser.error("all three --cross-mode-* paths are required")
        try:
            cross_mode = compare_mode_campaigns(
                args.cross_mode_shadow,
                args.cross_mode_stream,
                args.cross_mode_out,
            )
        except (OSError, ValueError) as error:
            print(f"metamorphic cross-mode gate error: {error}", file=sys.stderr)
            return 2
        print(
            f"cross_mode_gate_passed={str(cross_mode['gate_passed']).lower()} "
            f"mismatches={len(cross_mode['mismatches'])}"
        )
        return 0 if cross_mode["gate_passed"] else 1

    if args.out is None:
        parser.error("--out is required for generation or differential campaigns")
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
            run_id=args.run_id,
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
