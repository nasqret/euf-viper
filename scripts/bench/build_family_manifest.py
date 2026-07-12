#!/usr/bin/env python3
"""Build a deterministic QF_UF source taxonomy and family holdout.

Path taxonomy rules (``relative_path`` is POSIX and normally starts with
``QF_UF/``):

* the first directory below ``QF_UF`` is the source family;
* QG ``qgN``/``loopsN`` variants with the same file stem share a lineage;
* ``NEQ``/``PEQ``/``SEQ`` lineages remove the trailing ``_sizeN``;
* Goel lineages remove the abstraction suffix and ``.N.propN`` size/property;
* ClearSy lineages are its numbered model directory; Rodin, TypeSafe, and
  ``eq_diamond`` each form one lineage;
* unknown layouts use the source family plus the repository-relative stem.

The normalized fingerprint is computed from an SMT-LIB token stream and
balanced S-expressions, not regular-expression rewriting.  Comments and token
separating whitespace disappear.  Declared and bound identifiers are renamed
by structural occurrence while strings, keywords, commands, built-ins,
parentheses, and argument counts remain.  Thus the fingerprint is insensitive
to alpha-renaming but remains sensitive to syntax and arity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import tempfile
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Iterable, NamedTuple, Sequence


SCHEMA_VERSION = "euf-viper.source-family-taxonomy.v1"
SPLIT_SCHEMA_VERSION = "euf-viper.source-family-split.v1"
NORMALIZATION_VERSION = "smtlib-token-alpha-v1"
DEFAULT_SEED = "euf-viper-qf-uf-family-holdout-v1"
DEFAULT_HOLDOUT_FRACTION = 0.20

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FINITE_RE = re.compile(r"^(?P<problem>(?:NEQ|PEQ|SEQ)[0-9]+)_size[0-9]+$")
QG_STEM_RE = re.compile(r"^(?P<kind>.*?)[0-9]+$")
QG_VARIANT_RE = re.compile(r"^(?:qg|loops)[0-9]+$")
GOEL_RE = re.compile(
    r"^QF_UF_(?P<instance>.+)_ab_(?:br|cti|fp|reg)_max$"
)
GOEL_SIZE_PROPERTY_RE = re.compile(r"\.[0-9]+(?:\.prop[0-9]+)?$")
RODIN_RE = re.compile(r"^smt[0-9]+$")
TYPESAFE_RE = re.compile(r"^z3\.[0-9]+$")
EQ_DIAMOND_RE = re.compile(r"^eq_diamond[0-9]+$")

TAXONOMY_RULES = (
    "source-family:first-directory-below-QF_UF",
    "qg-lineage:drop-qgN-or-loopsN-directory-keep-stem",
    "finite-lineage:drop-_sizeN",
    "goel-lineage:drop-abstraction-size-and-property",
    "clearsy-lineage:numbered-model-directory",
    "single-lineage:Rodin-TypeSafe-eq_diamond",
    "fallback-lineage:source-family-plus-relative-stem",
)

# Unquoted reserved words, commands, built-ins, and standard sort/theory names
# are semantically relevant.  A quoted spelling of one of these words is still
# a user symbol and is eligible for alpha-renaming.
PRESERVED_UNQUOTED_SYMBOLS = frozenset(
    {
        "!",
        "_",
        "as",
        "let",
        "exists",
        "forall",
        "lambda",
        "match",
        "par",
        "assert",
        "check-sat",
        "check-sat-assuming",
        "declare-const",
        "declare-codatatype",
        "declare-codatatypes",
        "declare-datatype",
        "declare-datatypes",
        "declare-fun",
        "declare-sort",
        "define-fun",
        "define-fun-rec",
        "define-funs-rec",
        "define-sort",
        "echo",
        "exit",
        "get-assertions",
        "get-assignment",
        "get-info",
        "get-model",
        "get-option",
        "get-proof",
        "get-unsat-assumptions",
        "get-unsat-core",
        "get-value",
        "pop",
        "push",
        "reset",
        "reset-assertions",
        "set-info",
        "set-logic",
        "set-option",
        "Bool",
        "Int",
        "Real",
        "String",
        "RegLan",
        "Array",
        "BitVec",
        "FloatingPoint",
        "RoundingMode",
        "true",
        "false",
        "not",
        "=>",
        "and",
        "or",
        "xor",
        "=",
        "distinct",
        "ite",
        "select",
        "store",
        "const",
        "concat",
        "extract",
        "sat",
        "unsat",
        "unknown",
        "success",
        "unsupported",
        "QF_UF",
    }
)


class FamilyManifestError(ValueError):
    """Base class for closed-failure validation errors."""


class ManifestError(FamilyManifestError):
    """The input manifest or one of its records is invalid."""


class SMTLIBError(FamilyManifestError):
    """An SMT-LIB source cannot be tokenized or structurally normalized."""


class LeakageError(FamilyManifestError):
    """A family, lineage, or duplicate group crosses the split boundary."""


class Token(NamedTuple):
    kind: str
    value: str
    quoted: bool = False


class PathTaxonomy(NamedTuple):
    source_family: str
    generator_lineage: str
    rule: str


class LoadedRecord(NamedTuple):
    row: dict[str, object]
    source_path: Path
    raw_sha256: str
    normalized_token_sha256: str
    taxonomy: PathTaxonomy


SExpr = Token | list["SExpr"]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def strict_json_loads(text: str) -> object:
    def reject_constant(value: str) -> object:
        raise ValueError(f"non-finite JSON number {value}")

    return json.loads(
        text,
        object_pairs_hook=_strict_object,
        parse_constant=reject_constant,
    )


def tokenize_smtlib(source: str) -> list[Token]:
    """Tokenize SMT-LIB while respecting comments, strings, and quoted names."""

    tokens: list[Token] = []
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        if char.isspace():
            index += 1
            continue
        if char == ";":
            newline = source.find("\n", index + 1)
            index = length if newline < 0 else newline + 1
            continue
        if char == "(":
            tokens.append(Token("LPAREN", "("))
            index += 1
            continue
        if char == ")":
            tokens.append(Token("RPAREN", ")"))
            index += 1
            continue
        if char == '"':
            start = index
            index += 1
            value: list[str] = []
            while index < length:
                if source[index] != '"':
                    value.append(source[index])
                    index += 1
                    continue
                if index + 1 < length and source[index + 1] == '"':
                    value.append('"')
                    index += 2
                    continue
                index += 1
                tokens.append(Token("STRING", "".join(value)))
                break
            else:
                raise SMTLIBError(
                    f"unterminated string starting at character {start}"
                )
            continue
        if char == "|":
            start = index
            index += 1
            end = source.find("|", index)
            if end < 0:
                raise SMTLIBError(
                    f"unterminated quoted symbol starting at character {start}"
                )
            value = source[index:end]
            if "\\" in value:
                raise SMTLIBError(
                    f"backslash in quoted symbol starting at character {start}"
                )
            tokens.append(Token("SYMBOL", value, True))
            index = end + 1
            continue

        start = index
        while index < length:
            current = source[index]
            if current.isspace() or current in "();\"|":
                break
            index += 1
        if start == index:
            raise SMTLIBError(f"unexpected character {source[index]!r} at {index}")
        value = source[start:index]
        kind = "KEYWORD" if value.startswith(":") else "SYMBOL"
        tokens.append(Token(kind, value))

    if not tokens:
        raise SMTLIBError("SMT-LIB source has no tokens")
    return tokens


def parse_smtlib(tokens: Sequence[Token]) -> tuple[list[SExpr], int]:
    """Parse a token sequence into balanced S-expressions without recursion."""

    roots: list[SExpr] = []
    stack: list[list[SExpr]] = []
    max_depth = 0
    for token in tokens:
        if token.kind == "LPAREN":
            stack.append([])
            max_depth = max(max_depth, len(stack))
        elif token.kind == "RPAREN":
            if not stack:
                raise SMTLIBError("unmatched closing parenthesis")
            completed: SExpr = stack.pop()
            if stack:
                stack[-1].append(completed)
            else:
                roots.append(completed)
        elif stack:
            stack[-1].append(token)
        else:
            roots.append(token)
    if stack:
        raise SMTLIBError(f"{len(stack)} unclosed parenthesis level(s)")
    return roots, max_depth


def _symbol_key(token: Token) -> tuple[str, str]:
    if token.quoted and token.value in PRESERVED_UNQUOTED_SYMBOLS:
        return ("quoted-reserved", token.value)
    return ("symbol", token.value)


def _head(node: SExpr) -> str | None:
    if not isinstance(node, list) or not node:
        return None
    first = node[0]
    if isinstance(first, Token) and first.kind == "SYMBOL" and not first.quoted:
        return first.value
    return None


class _Canonicalizer:
    def __init__(self, roots: Sequence[SExpr]) -> None:
        self.global_terms: dict[tuple[str, str], str] = {}
        self.global_sorts: dict[tuple[str, str], str] = {}
        self.labels: dict[tuple[str, str], str] = {}
        self.bound_term_counter = 0
        self.bound_sort_counter = 0
        self._collect_globals(roots)

    @staticmethod
    def _identifier(node: SExpr) -> Token | None:
        if isinstance(node, Token) and node.kind == "SYMBOL":
            return node
        return None

    def _register(
        self,
        mapping: dict[tuple[str, str], str],
        node: SExpr,
        prefix: str,
    ) -> None:
        token = self._identifier(node)
        if token is None:
            return
        key = _symbol_key(token)
        if key not in mapping:
            mapping[key] = f"@{prefix}{len(mapping)}"

    def _collect_datatype_terms(self, node: SExpr) -> None:
        if not isinstance(node, list):
            return
        for constructor in node:
            if not isinstance(constructor, list) or not constructor:
                continue
            self._register(self.global_terms, constructor[0], "g")
            for selector in constructor[1:]:
                if isinstance(selector, list) and selector:
                    self._register(self.global_terms, selector[0], "g")

    def _collect_globals(self, roots: Sequence[SExpr]) -> None:
        for form in roots:
            head = _head(form)
            if not isinstance(form, list):
                continue
            if head in {"declare-sort", "define-sort"} and len(form) > 1:
                self._register(self.global_sorts, form[1], "s")
            elif head in {
                "declare-const",
                "declare-fun",
                "define-fun",
                "define-fun-rec",
            } and len(form) > 1:
                self._register(self.global_terms, form[1], "g")
            elif head in {"declare-datatype", "declare-codatatype"}:
                if len(form) > 1:
                    self._register(self.global_sorts, form[1], "s")
                if len(form) > 2:
                    self._collect_datatype_terms(form[2])
            elif head in {"declare-datatypes", "declare-codatatypes"}:
                if len(form) > 1 and isinstance(form[1], list):
                    for declaration in form[1]:
                        if isinstance(declaration, list) and declaration:
                            self._register(self.global_sorts, declaration[0], "s")
                if len(form) > 2 and isinstance(form[2], list):
                    for datatype in form[2]:
                        self._collect_datatype_terms(datatype)
            elif head == "define-funs-rec" and len(form) > 1:
                declarations = form[1]
                if isinstance(declarations, list):
                    for declaration in declarations:
                        if isinstance(declaration, list) and declaration:
                            self._register(self.global_terms, declaration[0], "g")

    @staticmethod
    def _lookup(
        scopes: Sequence[dict[tuple[str, str], str]], token: Token
    ) -> str | None:
        key = _symbol_key(token)
        for scope in reversed(scopes):
            if key in scope:
                return scope[key]
        return None

    @staticmethod
    def _mapped_token(value: str) -> Token:
        return Token("SYMBOL", value)

    def _term_atom(
        self,
        token: Token,
        term_scopes: Sequence[dict[tuple[str, str], str]],
    ) -> Token:
        if token.kind != "SYMBOL":
            return token
        if not token.quoted and token.value in PRESERVED_UNQUOTED_SYMBOLS:
            return token
        local = self._lookup(term_scopes, token)
        if local is not None:
            return self._mapped_token(local)
        global_name = self.global_terms.get(_symbol_key(token))
        if global_name is not None:
            return self._mapped_token(global_name)
        return token

    def _sort_atom(
        self,
        token: Token,
        sort_scopes: Sequence[dict[tuple[str, str], str]],
    ) -> Token:
        if token.kind != "SYMBOL":
            return token
        if not token.quoted and token.value in PRESERVED_UNQUOTED_SYMBOLS:
            return token
        local = self._lookup(sort_scopes, token)
        if local is not None:
            return self._mapped_token(local)
        global_name = self.global_sorts.get(_symbol_key(token))
        if global_name is not None:
            return self._mapped_token(global_name)
        return token

    def _canonical_sort(
        self,
        node: SExpr,
        sort_scopes: Sequence[dict[tuple[str, str], str]],
    ) -> SExpr:
        if isinstance(node, Token):
            return self._sort_atom(node, sort_scopes)
        return [self._canonical_sort(item, sort_scopes) for item in node]

    def _bind_terms(
        self,
        bindings: SExpr,
        term_scopes: Sequence[dict[tuple[str, str], str]],
        sort_scopes: Sequence[dict[tuple[str, str], str]],
    ) -> tuple[SExpr, list[dict[tuple[str, str], str]]]:
        if not isinstance(bindings, list):
            return self._canonical_term(bindings, term_scopes, sort_scopes), list(
                term_scopes
            )
        scope: dict[tuple[str, str], str] = {}
        result: list[SExpr] = []
        for binding in bindings:
            if not isinstance(binding, list) or len(binding) < 2:
                result.append(self._canonical_term(binding, term_scopes, sort_scopes))
                continue
            identifier = self._identifier(binding[0])
            if identifier is None:
                result.append(self._canonical_term(binding, term_scopes, sort_scopes))
                continue
            canonical_name = f"@b{self.bound_term_counter}"
            self.bound_term_counter += 1
            scope[_symbol_key(identifier)] = canonical_name
            result.append(
                [
                    self._mapped_token(canonical_name),
                    self._canonical_sort(binding[1], sort_scopes),
                    *[
                        self._canonical_term(item, term_scopes, sort_scopes)
                        for item in binding[2:]
                    ],
                ]
            )
        return result, [*term_scopes, scope]

    def _canonical_let(
        self,
        node: list[SExpr],
        term_scopes: Sequence[dict[tuple[str, str], str]],
        sort_scopes: Sequence[dict[tuple[str, str], str]],
    ) -> SExpr:
        if len(node) < 3 or not isinstance(node[1], list):
            return [
                self._canonical_term(item, term_scopes, sort_scopes) for item in node
            ]
        scope: dict[tuple[str, str], str] = {}
        bindings: list[SExpr] = []
        for binding in node[1]:
            if not isinstance(binding, list) or len(binding) != 2:
                bindings.append(
                    self._canonical_term(binding, term_scopes, sort_scopes)
                )
                continue
            identifier = self._identifier(binding[0])
            if identifier is None:
                bindings.append(
                    self._canonical_term(binding, term_scopes, sort_scopes)
                )
                continue
            canonical_name = f"@b{self.bound_term_counter}"
            self.bound_term_counter += 1
            scope[_symbol_key(identifier)] = canonical_name
            bindings.append(
                [
                    self._mapped_token(canonical_name),
                    self._canonical_term(binding[1], term_scopes, sort_scopes),
                ]
            )
        inner_scopes = [*term_scopes, scope]
        return [
            node[0],
            bindings,
            *[
                self._canonical_term(item, inner_scopes, sort_scopes)
                for item in node[2:]
            ],
        ]

    def _canonical_quantifier(
        self,
        node: list[SExpr],
        term_scopes: Sequence[dict[tuple[str, str], str]],
        sort_scopes: Sequence[dict[tuple[str, str], str]],
    ) -> SExpr:
        if len(node) < 3:
            return [
                self._canonical_term(item, term_scopes, sort_scopes) for item in node
            ]
        bindings, inner_scopes = self._bind_terms(
            node[1], term_scopes, sort_scopes
        )
        return [
            node[0],
            bindings,
            *[
                self._canonical_term(item, inner_scopes, sort_scopes)
                for item in node[2:]
            ],
        ]

    def _canonical_annotation(
        self,
        node: list[SExpr],
        term_scopes: Sequence[dict[tuple[str, str], str]],
        sort_scopes: Sequence[dict[tuple[str, str], str]],
    ) -> SExpr:
        if len(node) < 2:
            return list(node)
        result: list[SExpr] = [node[0], self._canonical_term(node[1], term_scopes, sort_scopes)]
        index = 2
        while index < len(node):
            item = node[index]
            result.append(item)
            if isinstance(item, Token) and item.kind == "KEYWORD" and index + 1 < len(node):
                value = node[index + 1]
                if item.value == ":named" and isinstance(value, Token) and value.kind == "SYMBOL":
                    key = _symbol_key(value)
                    label = self.labels.setdefault(key, f"@n{len(self.labels)}")
                    result.append(self._mapped_token(label))
                else:
                    result.append(
                        self._canonical_term(value, term_scopes, sort_scopes)
                    )
                index += 2
            else:
                index += 1
        return result

    def _canonical_term(
        self,
        node: SExpr,
        term_scopes: Sequence[dict[tuple[str, str], str]],
        sort_scopes: Sequence[dict[tuple[str, str], str]],
    ) -> SExpr:
        if isinstance(node, Token):
            return self._term_atom(node, term_scopes)
        head = _head(node)
        if head == "let":
            return self._canonical_let(node, term_scopes, sort_scopes)
        if head in {"forall", "exists", "lambda"}:
            return self._canonical_quantifier(node, term_scopes, sort_scopes)
        if head == "!":
            return self._canonical_annotation(node, term_scopes, sort_scopes)
        if head == "as" and len(node) >= 3:
            return [
                node[0],
                self._canonical_term(node[1], term_scopes, sort_scopes),
                self._canonical_sort(node[2], sort_scopes),
                *[
                    self._canonical_term(item, term_scopes, sort_scopes)
                    for item in node[3:]
                ],
            ]
        return [
            self._canonical_term(item, term_scopes, sort_scopes) for item in node
        ]

    def _canonical_define_fun(
        self,
        form: list[SExpr],
        term_scopes: Sequence[dict[tuple[str, str], str]],
        sort_scopes: Sequence[dict[tuple[str, str], str]],
    ) -> SExpr:
        if len(form) < 5:
            return self._canonical_term(form, term_scopes, sort_scopes)
        name = form[1]
        if isinstance(name, Token):
            mapped = self.global_terms.get(_symbol_key(name))
            canonical_name: SExpr = self._mapped_token(mapped) if mapped else name
        else:
            canonical_name = name
        bindings, inner_scopes = self._bind_terms(
            form[2], term_scopes, sort_scopes
        )
        return [
            form[0],
            canonical_name,
            bindings,
            self._canonical_sort(form[3], sort_scopes),
            self._canonical_term(form[4], inner_scopes, sort_scopes),
            *[
                self._canonical_term(item, term_scopes, sort_scopes)
                for item in form[5:]
            ],
        ]

    def _canonical_define_sort(
        self,
        form: list[SExpr],
        sort_scopes: Sequence[dict[tuple[str, str], str]],
    ) -> SExpr:
        if len(form) < 4 or not isinstance(form[2], list):
            return [self._canonical_sort(item, sort_scopes) for item in form]
        name = form[1]
        if isinstance(name, Token):
            mapped = self.global_sorts.get(_symbol_key(name))
            canonical_name: SExpr = self._mapped_token(mapped) if mapped else name
        else:
            canonical_name = name
        scope: dict[tuple[str, str], str] = {}
        parameters: list[SExpr] = []
        for parameter in form[2]:
            token = self._identifier(parameter)
            if token is None:
                parameters.append(parameter)
                continue
            canonical = f"@p{self.bound_sort_counter}"
            self.bound_sort_counter += 1
            scope[_symbol_key(token)] = canonical
            parameters.append(self._mapped_token(canonical))
        inner_scopes = [*sort_scopes, scope]
        return [
            form[0],
            canonical_name,
            parameters,
            self._canonical_sort(form[3], inner_scopes),
            *[self._canonical_sort(item, sort_scopes) for item in form[4:]],
        ]

    def canonical_command(self, form: SExpr) -> SExpr:
        if not isinstance(form, list):
            return form
        head = _head(form)
        empty_terms: list[dict[tuple[str, str], str]] = []
        empty_sorts: list[dict[tuple[str, str], str]] = []
        if head == "assert" and len(form) > 1:
            return [
                form[0],
                *[
                    self._canonical_term(item, empty_terms, empty_sorts)
                    for item in form[1:]
                ],
            ]
        if head in {"define-fun", "define-fun-rec"}:
            return self._canonical_define_fun(form, empty_terms, empty_sorts)
        if head == "define-sort":
            return self._canonical_define_sort(form, empty_sorts)
        if head == "declare-sort" and len(form) > 1:
            name = form[1]
            if isinstance(name, Token):
                mapped = self.global_sorts.get(_symbol_key(name))
                name = self._mapped_token(mapped) if mapped else name
            return [form[0], name, *form[2:]]
        if head == "declare-const" and len(form) > 2:
            name = form[1]
            if isinstance(name, Token):
                mapped = self.global_terms.get(_symbol_key(name))
                name = self._mapped_token(mapped) if mapped else name
            return [form[0], name, self._canonical_sort(form[2], empty_sorts), *form[3:]]
        if head == "declare-fun" and len(form) > 3:
            name = form[1]
            if isinstance(name, Token):
                mapped = self.global_terms.get(_symbol_key(name))
                name = self._mapped_token(mapped) if mapped else name
            arguments = form[2]
            if isinstance(arguments, list):
                arguments = [
                    self._canonical_sort(item, empty_sorts) for item in arguments
                ]
            return [
                form[0],
                name,
                arguments,
                self._canonical_sort(form[3], empty_sorts),
                *form[4:],
            ]
        if head in {"check-sat-assuming", "get-value"} and len(form) > 1:
            return [
                form[0],
                *[
                    self._canonical_term(item, empty_terms, empty_sorts)
                    for item in form[1:]
                ],
            ]
        if head in {
            "set-logic",
            "set-info",
            "set-option",
            "get-info",
            "get-option",
            "echo",
            "push",
            "pop",
            "check-sat",
            "get-model",
            "get-proof",
            "get-unsat-core",
            "get-unsat-assumptions",
            "exit",
            "reset",
            "reset-assertions",
        }:
            return list(form)
        return self._canonical_term(form, empty_terms, empty_sorts)


def _emit_normalized(node: SExpr, output: list[tuple[str, str]]) -> None:
    if isinstance(node, Token):
        kind = "QUOTED_SYMBOL" if node.kind == "SYMBOL" and node.quoted else node.kind
        output.append((kind, node.value))
        return
    output.append(("LPAREN", "("))
    for item in node:
        _emit_normalized(item, output)
    output.append(("RPAREN", ")"))


def normalized_smtlib_tokens(source: str | bytes) -> tuple[tuple[str, str], ...]:
    if isinstance(source, bytes):
        try:
            text = source.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SMTLIBError(f"SMT-LIB source is not UTF-8: {error}") from error
    else:
        text = source
    tokens = tokenize_smtlib(text)
    roots, max_depth = parse_smtlib(tokens)
    canonicalizer = _Canonicalizer(roots)

    previous_limit = sys.getrecursionlimit()
    requested_limit = max(previous_limit, min(100_000, max_depth * 8 + 1_000))
    if requested_limit != previous_limit:
        sys.setrecursionlimit(requested_limit)
    try:
        normalized: list[tuple[str, str]] = []
        for root in roots:
            _emit_normalized(canonicalizer.canonical_command(root), normalized)
        return tuple(normalized)
    except RecursionError as error:
        raise SMTLIBError(
            f"SMT-LIB nesting depth {max_depth} exceeds normalization capacity"
        ) from error
    finally:
        if requested_limit != previous_limit:
            sys.setrecursionlimit(previous_limit)


def normalized_smtlib_fingerprint(source: str | bytes) -> str:
    digest = hashlib.sha256()
    digest.update(NORMALIZATION_VERSION.encode("ascii") + b"\0")
    for kind, value in normalized_smtlib_tokens(source):
        kind_bytes = kind.encode("ascii")
        value_bytes = value.encode("utf-8")
        digest.update(len(kind_bytes).to_bytes(2, "big"))
        digest.update(kind_bytes)
        digest.update(len(value_bytes).to_bytes(8, "big"))
        digest.update(value_bytes)
    return digest.hexdigest()


def _validated_relative_path(value: object, *, line_number: int | None = None) -> str:
    where = f"line {line_number}: " if line_number is not None else ""
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{where}relative_path must be a nonempty string")
    if "\\" in value:
        raise ManifestError(f"{where}relative_path must use POSIX separators")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ManifestError(f"{where}relative_path is not a safe relative path: {value!r}")
    if pure.suffix.lower() != ".smt2":
        raise ManifestError(f"{where}relative_path is not an .smt2 file: {value!r}")
    return pure.as_posix()


def derive_path_taxonomy(relative_path: str) -> PathTaxonomy:
    relative_path = _validated_relative_path(relative_path)
    parts = PurePosixPath(relative_path).parts
    if len(parts) < 2:
        raise ManifestError(
            f"relative_path has no source-family directory: {relative_path!r}"
        )
    if parts[0] == "QF_UF":
        prefix = (parts[0],)
        body = parts[1:]
    else:
        prefix = ()
        body = parts
    if len(body) < 2:
        raise ManifestError(
            f"relative_path has no file below a source family: {relative_path!r}"
        )

    family_name = body[0]
    source_family = "/".join((*prefix, family_name))
    stem = PurePosixPath(body[-1]).stem

    if family_name == "QG-classification":
        if len(body) != 3 or not QG_VARIANT_RE.fullmatch(body[1]):
            raise ManifestError(f"unrecognized QG path layout: {relative_path!r}")
        match = QG_STEM_RE.fullmatch(stem)
        if match is None or not match.group("kind"):
            raise ManifestError(f"unrecognized QG filename: {relative_path!r}")
        lineage = "/".join((*prefix, family_name, stem))
        return PathTaxonomy(source_family, lineage, "qg-size-variant")

    if family_name in {"NEQ", "PEQ", "SEQ"}:
        if len(body) != 2:
            raise ManifestError(f"unrecognized finite-family path: {relative_path!r}")
        match = FINITE_RE.fullmatch(stem)
        if match is None or not stem.startswith(family_name):
            raise ManifestError(f"unrecognized finite-family filename: {relative_path!r}")
        lineage = "/".join((*prefix, family_name, match.group("problem")))
        return PathTaxonomy(source_family, lineage, "finite-size-series")

    if family_name == "2018-Goel-hwbench":
        if len(body) != 2:
            raise ManifestError(f"unrecognized Goel path layout: {relative_path!r}")
        match = GOEL_RE.fullmatch(stem)
        if match is None:
            raise ManifestError(f"unrecognized Goel filename: {relative_path!r}")
        instance = match.group("instance")
        model = GOEL_SIZE_PROPERTY_RE.sub("", instance)
        if not model:
            raise ManifestError(f"empty Goel model lineage: {relative_path!r}")
        lineage = "/".join((*prefix, family_name, model))
        return PathTaxonomy(source_family, lineage, "goel-model-series")

    if family_name == "20190906-CLEARSY":
        if len(body) != 3 or not body[1].isdigit() or not stem.isdigit():
            raise ManifestError(f"unrecognized ClearSy path layout: {relative_path!r}")
        lineage = "/".join((*prefix, family_name, body[1]))
        return PathTaxonomy(source_family, lineage, "clearsy-model-directory")

    if family_name == "20170829-Rodin":
        if len(body) != 2 or RODIN_RE.fullmatch(stem) is None:
            raise ManifestError(f"unrecognized Rodin path layout: {relative_path!r}")
        return PathTaxonomy(source_family, source_family, "rodin-source-batch")

    if family_name == "TypeSafe":
        if len(body) != 2 or TYPESAFE_RE.fullmatch(stem) is None:
            raise ManifestError(f"unrecognized TypeSafe path layout: {relative_path!r}")
        return PathTaxonomy(source_family, source_family, "typesafe-source-batch")

    if family_name == "eq_diamond":
        if len(body) != 2 or EQ_DIAMOND_RE.fullmatch(stem) is None:
            raise ManifestError(f"unrecognized eq_diamond path layout: {relative_path!r}")
        return PathTaxonomy(source_family, source_family, "eq-diamond-size-series")

    lineage_parts = (*prefix, *body[:-1], stem)
    return PathTaxonomy(
        source_family,
        "/".join(lineage_parts),
        "fallback-relative-stem",
    )


def _resolve_source_path(
    value: object,
    repository_root: Path,
    *,
    line_number: int,
) -> Path:
    if not isinstance(value, str) or not value:
        raise ManifestError(f"line {line_number}: path must be a nonempty string")
    path = Path(value)
    if not path.is_absolute():
        path = repository_root / path
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as error:
        raise ManifestError(f"line {line_number}: missing file: {path}") from error
    except OSError as error:
        raise ManifestError(f"line {line_number}: cannot resolve {path}: {error}") from error
    if not resolved.is_file():
        raise ManifestError(f"line {line_number}: path is not a file: {path}")
    return resolved


def load_manifest(
    manifest_path: Path,
    repository_root: Path | None = None,
) -> tuple[list[LoadedRecord], bytes]:
    manifest_path = Path(manifest_path)
    repository_root = (
        Path(repository_root) if repository_root is not None else Path.cwd()
    ).resolve()
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as error:
        raise ManifestError(f"cannot read manifest {manifest_path}: {error}") from error
    try:
        text = manifest_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ManifestError(f"manifest is not UTF-8: {error}") from error

    lines = text.splitlines()
    if not lines:
        raise ManifestError("manifest has no records")

    records: list[LoadedRecord] = []
    seen_ids: set[object] = set()
    seen_relative_paths: set[str] = set()
    seen_source_paths: set[Path] = set()
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            raise ManifestError(f"line {line_number}: blank JSONL record")
        try:
            value = strict_json_loads(line)
        except (json.JSONDecodeError, ValueError) as error:
            raise ManifestError(f"line {line_number}: malformed JSON: {error}") from error
        if not isinstance(value, dict):
            raise ManifestError(f"line {line_number}: record must be a JSON object")
        for required in ("id", "path", "relative_path"):
            if required not in value:
                raise ManifestError(f"line {line_number}: missing field {required!r}")
        record_id = value["id"]
        if isinstance(record_id, bool) or not isinstance(record_id, (int, str)):
            raise ManifestError(f"line {line_number}: id must be an integer or string")
        if record_id in seen_ids:
            raise ManifestError(f"line {line_number}: duplicate id {record_id!r}")
        seen_ids.add(record_id)

        relative_path = _validated_relative_path(
            value["relative_path"], line_number=line_number
        )
        if relative_path in seen_relative_paths:
            raise ManifestError(
                f"line {line_number}: duplicate relative_path {relative_path!r}"
            )
        seen_relative_paths.add(relative_path)

        source_path = _resolve_source_path(
            value["path"], repository_root, line_number=line_number
        )
        if source_path in seen_source_paths:
            raise ManifestError(
                f"line {line_number}: duplicate source file {source_path}"
            )
        seen_source_paths.add(source_path)
        relative_parts = PurePosixPath(relative_path).parts
        if tuple(source_path.parts[-len(relative_parts) :]) != relative_parts:
            raise ManifestError(
                f"line {line_number}: path does not end in relative_path: "
                f"{source_path} vs {relative_path!r}"
            )

        try:
            source = source_path.read_bytes()
        except OSError as error:
            raise ManifestError(
                f"line {line_number}: cannot read source file {source_path}: {error}"
            ) from error
        raw_sha256 = sha256_bytes(source)
        existing_sha256 = value.get("sha256")
        if existing_sha256 is not None:
            if (
                not isinstance(existing_sha256, str)
                or SHA256_RE.fullmatch(existing_sha256) is None
            ):
                raise ManifestError(f"line {line_number}: sha256 is not a lowercase SHA-256")
            if existing_sha256 != raw_sha256:
                raise ManifestError(
                    f"line {line_number}: sha256 mismatch for {relative_path!r}"
                )
        existing_bytes = value.get("bytes")
        if existing_bytes is not None:
            if isinstance(existing_bytes, bool) or not isinstance(existing_bytes, int):
                raise ManifestError(f"line {line_number}: bytes must be an integer")
            if existing_bytes != len(source):
                raise ManifestError(
                    f"line {line_number}: byte-count mismatch for {relative_path!r}"
                )
        try:
            normalized = normalized_smtlib_fingerprint(source)
        except SMTLIBError as error:
            raise ManifestError(
                f"line {line_number}: cannot normalize {relative_path!r}: {error}"
            ) from error
        taxonomy = derive_path_taxonomy(relative_path)
        row = dict(value)
        row["relative_path"] = relative_path
        records.append(
            LoadedRecord(row, source_path, raw_sha256, normalized, taxonomy)
        )
    return records, manifest_bytes


def deterministic_holdout_families(
    family_identifiers: Iterable[str],
    *,
    seed: str,
    holdout_fraction: float = DEFAULT_HOLDOUT_FRACTION,
    holdout_count: int | None = None,
) -> list[str]:
    families = sorted(set(family_identifiers))
    if len(families) < 2:
        raise FamilyManifestError("at least two source families are required")
    if not isinstance(seed, str) or not seed:
        raise FamilyManifestError("seed must be a nonempty string")
    if holdout_count is None:
        if not 0.0 < holdout_fraction < 1.0:
            raise FamilyManifestError("holdout_fraction must be between zero and one")
        holdout_count = math.ceil(len(families) * holdout_fraction)
    if not 1 <= holdout_count < len(families):
        raise FamilyManifestError(
            "holdout_count must leave at least one dev and one holdout family"
        )

    def selection_key(family: str) -> tuple[str, str]:
        material = f"family-holdout-v1\0{seed}\0{family}".encode("utf-8")
        return hashlib.sha256(material).hexdigest(), family

    return sorted(sorted(families, key=selection_key)[:holdout_count])


def load_sealed_holdout_families(path: Path) -> tuple[list[str], str]:
    try:
        data = Path(path).read_bytes()
    except OSError as error:
        raise FamilyManifestError(f"cannot read sealed family list {path}: {error}") from error
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FamilyManifestError(f"sealed family list is not UTF-8: {error}") from error
    stripped = text.lstrip()
    try:
        if stripped.startswith("[") or stripped.startswith("{"):
            parsed = strict_json_loads(text)
            if isinstance(parsed, dict):
                if "holdout_families" not in parsed:
                    raise FamilyManifestError(
                        "sealed JSON object must contain holdout_families"
                    )
                parsed = parsed["holdout_families"]
            if not isinstance(parsed, list):
                raise FamilyManifestError("sealed JSON family list must be an array")
            families = parsed
        else:
            families = [line.strip() for line in text.splitlines() if line.strip()]
    except (json.JSONDecodeError, ValueError) as error:
        if isinstance(error, FamilyManifestError):
            raise
        raise FamilyManifestError(f"malformed sealed family list: {error}") from error
    if not families:
        raise FamilyManifestError("sealed holdout family list is empty")
    if any(not isinstance(item, str) or not item or item != item.strip() for item in families):
        raise FamilyManifestError(
            "sealed holdout families must be nonempty, trimmed strings"
        )
    if len(set(families)) != len(families):
        raise FamilyManifestError("sealed holdout family list contains duplicates")
    return sorted(families), sha256_bytes(data)


def _linked_family_components(records: Sequence[LoadedRecord]) -> list[set[str]]:
    families = sorted({record.taxonomy.source_family for record in records})
    parent = {family: family for family in families}

    def find(family: str) -> str:
        while parent[family] != family:
            parent[family] = parent[parent[family]]
            family = parent[family]
        return family

    def union(left: str, right: str) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root == right_root:
            return
        if left_root < right_root:
            parent[right_root] = left_root
        else:
            parent[left_root] = right_root

    for attribute in ("normalized_token_sha256", "raw_sha256"):
        groups: dict[str, set[str]] = defaultdict(set)
        for record in records:
            groups[getattr(record, attribute)].add(record.taxonomy.source_family)
        for group_families in groups.values():
            ordered = sorted(group_families)
            for family in ordered[1:]:
                union(ordered[0], family)

    lineages: dict[str, set[str]] = defaultdict(set)
    for record in records:
        lineages[record.taxonomy.generator_lineage].add(
            record.taxonomy.source_family
        )
    for lineage_families in lineages.values():
        ordered = sorted(lineage_families)
        for family in ordered[1:]:
            union(ordered[0], family)

    components: dict[str, set[str]] = defaultdict(set)
    for family in families:
        components[find(family)].add(family)
    return sorted(components.values(), key=lambda item: sorted(item))


def _close_fallback_holdout(
    records: Sequence[LoadedRecord], selected: Iterable[str]
) -> tuple[list[str], list[str]]:
    holdout = set(selected)
    before = set(holdout)
    for component in _linked_family_components(records):
        if component & holdout:
            holdout.update(component)
    return sorted(holdout), sorted(holdout - before)


def validate_no_leakage(rows: Sequence[dict[str, object]]) -> None:
    violations: list[str] = []
    for field in (
        "source_family",
        "generator_lineage",
        "near_duplicate_group",
        "raw_sha256",
    ):
        observed: dict[object, set[object]] = defaultdict(set)
        for row in rows:
            if field not in row or "split" not in row:
                raise LeakageError(f"row is missing {field!r} or 'split'")
            observed[row[field]].add(row["split"])
        leaking = sorted(str(key) for key, splits in observed.items() if len(splits) > 1)
        if leaking:
            preview = ", ".join(leaking[:3])
            suffix = " ..." if len(leaking) > 3 else ""
            violations.append(f"{field}: {preview}{suffix}")
    if violations:
        raise LeakageError("dev/holdout leakage detected: " + "; ".join(violations))


def build_taxonomy_and_split(
    manifest_path: Path,
    *,
    repository_root: Path | None = None,
    sealed_holdout_families: Sequence[str] | None = None,
    sealed_list_sha256: str | None = None,
    seed: str = DEFAULT_SEED,
    holdout_fraction: float = DEFAULT_HOLDOUT_FRACTION,
    holdout_count: int | None = None,
) -> tuple[list[dict[str, object]], dict[str, object], bytes]:
    records, manifest_bytes = load_manifest(manifest_path, repository_root)
    families = sorted({record.taxonomy.source_family for record in records})

    if sealed_holdout_families is not None:
        sealed = list(sealed_holdout_families)
        if not sealed or any(not isinstance(item, str) or not item for item in sealed):
            raise FamilyManifestError("sealed holdout families must be nonempty strings")
        if len(set(sealed)) != len(sealed):
            raise FamilyManifestError("sealed holdout families contain duplicates")
        unknown = sorted(set(sealed) - set(families))
        if unknown:
            raise FamilyManifestError(
                "sealed holdout contains unknown families: " + ", ".join(unknown)
            )
        if len(sealed) == len(families):
            raise FamilyManifestError("sealed holdout leaves no development families")
        holdout_families = sorted(sealed)
        selection_mode = "sealed"
        expanded_families: list[str] = []
    else:
        initial = deterministic_holdout_families(
            families,
            seed=seed,
            holdout_fraction=holdout_fraction,
            holdout_count=holdout_count,
        )
        holdout_families, expanded_families = _close_fallback_holdout(
            records, initial
        )
        if len(holdout_families) == len(families):
            raise LeakageError(
                "normalized duplicate linkage leaves no development family"
            )
        selection_mode = "deterministic_family_fallback"

    holdout_set = set(holdout_families)
    normalized_sizes: dict[str, int] = defaultdict(int)
    raw_sizes: dict[str, int] = defaultdict(int)
    for record in records:
        normalized_sizes[record.normalized_token_sha256] += 1
        raw_sizes[record.raw_sha256] += 1

    rows: list[dict[str, object]] = []
    for record in sorted(records, key=lambda item: str(item.row["relative_path"])):
        row = dict(record.row)
        normalized_group = (
            f"{NORMALIZATION_VERSION}:{record.normalized_token_sha256}"
        )
        row.update(
            {
                "schema_version": SCHEMA_VERSION,
                "sha256": record.raw_sha256,
                "raw_sha256": record.raw_sha256,
                "normalized_token_sha256": record.normalized_token_sha256,
                "near_duplicate_group": normalized_group,
                "near_duplicate_group_size": normalized_sizes[
                    record.normalized_token_sha256
                ],
                "raw_duplicate_group_size": raw_sizes[record.raw_sha256],
                "source_family": record.taxonomy.source_family,
                "generator_lineage": record.taxonomy.generator_lineage,
                "taxonomy_rule": record.taxonomy.rule,
                "split": (
                    "holdout"
                    if record.taxonomy.source_family in holdout_set
                    else "dev"
                ),
            }
        )
        rows.append(row)

    validate_no_leakage(rows)
    dev_families = sorted(set(families) - holdout_set)
    dev_paths = sorted(
        str(row["relative_path"]) for row in rows if row["split"] == "dev"
    )
    holdout_paths = sorted(
        str(row["relative_path"]) for row in rows if row["split"] == "holdout"
    )
    assignments: dict[str, object] = {
        "families": {"dev": dev_families, "holdout": holdout_families},
        "relative_paths": {"dev": dev_paths, "holdout": holdout_paths},
    }
    counts = {
        "records": len(rows),
        "source_families": len(families),
        "generator_lineages": len(
            {str(row["generator_lineage"]) for row in rows}
        ),
        "normalized_groups": len(normalized_sizes),
        "near_duplicate_groups": sum(
            size > 1 for size in normalized_sizes.values()
        ),
        "near_duplicate_records": sum(
            size for size in normalized_sizes.values() if size > 1
        ),
        "raw_duplicate_groups": sum(size > 1 for size in raw_sizes.values()),
        "dev_families": len(dev_families),
        "holdout_families": len(holdout_families),
        "dev_records": len(dev_paths),
        "holdout_records": len(holdout_paths),
    }
    split_core: dict[str, object] = {
        "schema_version": SPLIT_SCHEMA_VERSION,
        "normalization_version": NORMALIZATION_VERSION,
        "taxonomy_rules": list(TAXONOMY_RULES),
        "selection": {
            "mode": selection_mode,
            "seed": seed,
            "holdout_fraction": (
                holdout_fraction if sealed_holdout_families is None else None
            ),
            "requested_holdout_count": holdout_count,
            "expanded_families_for_group_integrity": expanded_families,
        },
        "counts": counts,
        "assignments": assignments,
    }
    hashes: dict[str, object] = {
        "input_manifest_sha256": sha256_bytes(manifest_bytes),
        "split_payload_sha256": sha256_bytes(canonical_json_bytes(split_core)),
    }
    if sealed_list_sha256 is not None:
        hashes["sealed_holdout_family_list_sha256"] = sealed_list_sha256
    split_core["hashes"] = hashes
    return rows, split_core, manifest_bytes


def serialize_taxonomy(rows: Sequence[dict[str, object]]) -> bytes:
    return b"".join(canonical_json_bytes(row) for row in rows)


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def write_taxonomy_and_split(
    taxonomy_path: Path,
    split_path: Path,
    rows: Sequence[dict[str, object]],
    split: dict[str, object],
) -> tuple[str, str]:
    taxonomy_path = Path(taxonomy_path)
    split_path = Path(split_path)
    if taxonomy_path.resolve() == split_path.resolve():
        raise FamilyManifestError("taxonomy and split outputs must be different files")
    taxonomy_bytes = serialize_taxonomy(rows)
    hashes = split.get("hashes")
    if not isinstance(hashes, dict):
        raise FamilyManifestError("split summary has no hashes object")
    taxonomy_sha256 = sha256_bytes(taxonomy_bytes)
    hashes["taxonomy_jsonl_sha256"] = taxonomy_sha256
    split_bytes = canonical_json_bytes(split)
    _write_atomic(taxonomy_path, taxonomy_bytes)
    _write_atomic(split_path, split_bytes)
    return taxonomy_sha256, sha256_bytes(split_bytes)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument(
        "--taxonomy-out", "--out", dest="taxonomy_out", type=Path, required=True
    )
    parser.add_argument(
        "--split-out", "--summary-out", dest="split_out", type=Path, required=True
    )
    parser.add_argument(
        "--repository-root", "--repo-root", dest="repository_root", type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    parser.add_argument(
        "--sealed-holdout-families", "--holdout-families",
        dest="sealed_holdout_families", type=Path,
    )
    parser.add_argument("--holdout-family", action="append", default=[])
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument(
        "--holdout-fraction", type=float, default=DEFAULT_HOLDOUT_FRACTION
    )
    parser.add_argument("--holdout-count", type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    if args.sealed_holdout_families and args.holdout_family:
        parser.error(
            "--sealed-holdout-families and --holdout-family are mutually exclusive"
        )
    if args.manifest.resolve() in {
        args.taxonomy_out.resolve(),
        args.split_out.resolve(),
    }:
        parser.error("outputs must not overwrite the input manifest")

    sealed_families: Sequence[str] | None = None
    sealed_sha256: str | None = None
    try:
        if args.sealed_holdout_families:
            sealed_families, sealed_sha256 = load_sealed_holdout_families(
                args.sealed_holdout_families
            )
        elif args.holdout_family:
            sealed_families = args.holdout_family
        rows, split, _ = build_taxonomy_and_split(
            args.manifest,
            repository_root=args.repository_root,
            sealed_holdout_families=sealed_families,
            sealed_list_sha256=sealed_sha256,
            seed=args.seed,
            holdout_fraction=args.holdout_fraction,
            holdout_count=args.holdout_count,
        )
        taxonomy_sha256, split_file_sha256 = write_taxonomy_and_split(
            args.taxonomy_out, args.split_out, rows, split
        )
    except (FamilyManifestError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    counts = split["counts"]
    assert isinstance(counts, dict)
    print(
        f"taxonomy={args.taxonomy_out} split={args.split_out} "
        f"records={counts['records']} dev={counts['dev_records']} "
        f"holdout={counts['holdout_records']} "
        f"taxonomy_sha256={taxonomy_sha256} split_sha256={split_file_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
