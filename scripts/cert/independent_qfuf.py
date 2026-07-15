#!/usr/bin/env python3
"""Independent SMT-LIB QF_UF reconstruction for certificate checking.

This module deliberately shares no parser, term arena, or encoding code with the
solver.  It accepts one small, typed, single-query SMT-LIB fragment and rebuilds
the Boolean CNF and EUF atoms from source text alone.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final


class IndependentQfufError(Exception):
    """Deterministic rejection raised by every public validation entry point."""


QfufError = IndependentQfufError

BOOL_SORT: Final = 0
V2_FORMAT: Final = "euf-viper-euf-cnf-v2"
V3_FORMAT: Final = "euf-viper-euf-cnf-v3"
V3_ENCODING: Final = (
    "canonical-tseitin-v1+finite-closure-v1+guarded-euf-v1+"
    "adjacent-orbit-lex-v1"
)

_ORBIT_MAX_DOMAIN: Final = 32
_ORBIT_MAX_MEMBERSHIP_CELLS: Final = 262_144
_ORBIT_MAX_EFFECTIVE_LEX_COORDINATES: Final = 262_144
_ORBIT_MAX_GUARDED_CLAUSES: Final = 262_144
_ORBIT_MAX_GUARDED_LITERALS: Final = 1_048_576
_ORBIT_MAX_TUPLES_PER_APPLICATION: Final = 4_096


@dataclass(frozen=True)
class Sort:
    id: int
    name: str
    quoted: bool = False


@dataclass(frozen=True)
class Function:
    id: int
    name: str
    arg_sorts: tuple[int, ...]
    result_sort: int
    quoted: bool = False
    internal: bool = False
    macro: bool = False


@dataclass(frozen=True)
class Term:
    id: int
    function: int
    args: tuple[int, ...]
    sort: int


@dataclass(frozen=True)
class BoolExpr:
    op: str
    arguments: tuple[object, ...]


@dataclass(frozen=True)
class Atom:
    variable: int
    kind: str
    left: int | None = None
    right: int | None = None
    term: int | None = None


@dataclass(frozen=True)
class EncodedProblem:
    sorts: tuple[Sort, ...]
    functions: tuple[Function, ...]
    terms: tuple[Term, ...]
    atoms: tuple[Atom, ...]
    clauses: tuple[tuple[int, ...], ...]
    true_term: int
    false_term: int
    assertions: tuple[BoolExpr, ...]
    bool_data_terms: tuple[int, ...]

    @property
    def variable_count(self) -> int:
        return len(self.atoms)

    @property
    def base_count(self) -> int:
        return len(self.clauses)

    @property
    def atoms_by_variable(self) -> tuple[Atom | None, ...]:
        return (None, *self.atoms)

    def atom_for_variable(self, variable: int) -> Atom:
        if type(variable) is not int:
            raise IndependentQfufError("variable ID must be an integer")
        if not 1 <= variable <= self.variable_count:
            raise IndependentQfufError(f"variable {variable} is out of range")
        return self.atoms[variable - 1]


@dataclass(frozen=True)
class _Token:
    kind: str
    text: str
    line: int
    column: int


@dataclass(frozen=True)
class _AtomSexp:
    token: _Token


@dataclass(frozen=True)
class _ListSexp:
    items: tuple[_Sexp, ...]
    line: int
    column: int


_Sexp = _AtomSexp | _ListSexp


_SIMPLE_INITIAL = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~!@$%^&*_-+=<>.?/"
)
_SIMPLE_SUBSEQUENT = _SIMPLE_INITIAL | frozenset("0123456789")


class _Lexer:
    def __init__(self, source: str) -> None:
        self.source = source
        self.index = 0
        self.line = 1
        self.column = 1

    def _raise(self, message: str, line: int | None = None, column: int | None = None) -> None:
        raise IndependentQfufError(
            f"{self.line if line is None else line}:"
            f"{self.column if column is None else column}: {message}"
        )

    def _advance(self) -> str:
        char = self.source[self.index]
        self.index += 1
        if char == "\n":
            self.line += 1
            self.column = 1
        else:
            self.column += 1
        return char

    def _quoted_symbol(self) -> _Token:
        line, column = self.line, self.column
        self._advance()
        value: list[str] = []
        while self.index < len(self.source):
            char = self.source[self.index]
            if char == "|":
                self._advance()
                return _Token("QUOTED_SYMBOL", "".join(value), line, column)
            if char == "\\":
                self._advance()
                if self.index == len(self.source):
                    self._raise("unterminated escape in quoted symbol", line, column)
                value.append(self._advance())
                continue
            if ord(char) < 0x20 and char not in "\t\r\n":
                self._raise("control character in quoted symbol", line, column)
            value.append(self._advance())
        self._raise("unterminated quoted symbol", line, column)

    def _string(self) -> _Token:
        line, column = self.line, self.column
        self._advance()
        value: list[str] = []
        while self.index < len(self.source):
            char = self.source[self.index]
            if char == '"':
                self._advance()
                if self.index < len(self.source) and self.source[self.index] == '"':
                    self._advance()
                    value.append('"')
                    continue
                return _Token("STRING", "".join(value), line, column)
            if char == "\x00":
                self._raise("NUL in string literal", line, column)
            value.append(self._advance())
        self._raise("unterminated string literal", line, column)

    def _bare_token(self) -> _Token:
        line, column = self.line, self.column
        start = self.index
        while self.index < len(self.source):
            char = self.source[self.index]
            if char.isspace() or char in "();|\"":
                break
            self._advance()
        text = self.source[start : self.index]
        if not text:
            self._raise("invalid token", line, column)

        if text.startswith(":"):
            suffix = text[1:]
            if suffix and suffix[0] in _SIMPLE_INITIAL and all(
                char in _SIMPLE_SUBSEQUENT for char in suffix[1:]
            ):
                return _Token("KEYWORD", text, line, column)
            self._raise(f"invalid keyword `{text}`", line, column)

        if re.fullmatch(r"0|[1-9][0-9]*", text):
            return _Token("NUMERAL", text, line, column)
        if re.fullmatch(r"(?:0|[1-9][0-9]*)\.[0-9]+", text):
            return _Token("DECIMAL", text, line, column)
        if text[0] in _SIMPLE_INITIAL and all(
            char in _SIMPLE_SUBSEQUENT for char in text[1:]
        ):
            return _Token("SYMBOL", text, line, column)
        self._raise(f"invalid SMT-LIB token `{text}`", line, column)

    def tokens(self) -> tuple[_Token, ...]:
        tokens: list[_Token] = []
        while self.index < len(self.source):
            char = self.source[self.index]
            if char.isspace():
                self._advance()
            elif char == ";":
                while self.index < len(self.source) and self.source[self.index] not in "\r\n":
                    self._advance()
            elif char == "(":
                tokens.append(_Token("LPAREN", char, self.line, self.column))
                self._advance()
            elif char == ")":
                tokens.append(_Token("RPAREN", char, self.line, self.column))
                self._advance()
            elif char == "|":
                tokens.append(self._quoted_symbol())
            elif char == '"':
                tokens.append(self._string())
            else:
                tokens.append(self._bare_token())
        return tuple(tokens)


def _parse_sexps(source: str) -> tuple[_Sexp, ...]:
    stack: list[tuple[_Token, list[_Sexp]]] = []
    top_level: list[_Sexp] = []
    for token in _Lexer(source).tokens():
        if token.kind == "LPAREN":
            stack.append((token, []))
            continue
        if token.kind == "RPAREN":
            if not stack:
                raise IndependentQfufError(
                    f"{token.line}:{token.column}: unexpected ')'"
                )
            opening, items = stack.pop()
            form = _ListSexp(tuple(items), opening.line, opening.column)
            if stack:
                stack[-1][1].append(form)
            else:
                top_level.append(form)
            continue
        atom = _AtomSexp(token)
        if stack:
            stack[-1][1].append(atom)
        else:
            top_level.append(atom)
    if stack:
        opening, _ = stack[-1]
        raise IndependentQfufError(
            f"{opening.line}:{opening.column}: unclosed '('"
        )
    return tuple(top_level)


def _location(sexp: _Sexp) -> tuple[int, int]:
    if isinstance(sexp, _AtomSexp):
        return sexp.token.line, sexp.token.column
    return sexp.line, sexp.column


def _reject(sexp: _Sexp, message: str) -> None:
    line, column = _location(sexp)
    raise IndependentQfufError(f"{line}:{column}: {message}")


def _symbol_token(sexp: _Sexp, context: str) -> _Token:
    if not isinstance(sexp, _AtomSexp) or sexp.token.kind not in {
        "SYMBOL",
        "QUOTED_SYMBOL",
    }:
        _reject(sexp, f"{context} must be a symbol")
    return sexp.token


def _syntax_symbol(sexp: _Sexp) -> str | None:
    if isinstance(sexp, _AtomSexp) and sexp.token.kind == "SYMBOL":
        return sexp.token.text
    return None


_RESERVED_NAMES: Final = frozenset(
    {
        "!",
        "_",
        "as",
        "Bool",
        "true",
        "false",
        "not",
        "and",
        "or",
        "=>",
        "xor",
        "=",
        "distinct",
        "ite",
        "let",
        "forall",
        "exists",
        "match",
        "par",
        "set-logic",
        "set-option",
        "set-info",
        "declare-sort",
        "declare-const",
        "declare-fun",
        "define-fun",
        "define-fun-rec",
        "define-funs-rec",
        "assert",
        "check-sat",
        "check-sat-assuming",
        "push",
        "pop",
        "reset",
        "reset-assertions",
        "get-model",
        "get-value",
        "exit",
    }
)


def _declared_name(sexp: _Sexp, context: str) -> _Token:
    token = _symbol_token(sexp, context)
    if token.kind == "SYMBOL" and token.text in _RESERVED_NAMES:
        _reject(sexp, f"reserved symbol `{token.text}` must be quoted in {context}")
    return token


@dataclass(frozen=True)
class _AtomKey:
    kind: str
    left: int | None = None
    right: int | None = None
    term: int | None = None


@dataclass(frozen=True)
class _Value:
    sort: int
    term: int | None = None
    expression: BoolExpr | None = None


@dataclass(frozen=True)
class _Macro:
    function: int
    parameters: tuple[tuple[str, int], ...]
    body: _Sexp


def _const(value: bool) -> BoolExpr:
    return BoolExpr("const", (value,))


def _atom(key: _AtomKey) -> BoolExpr:
    return BoolExpr("atom", (key,))


def _not(child: BoolExpr) -> BoolExpr:
    return BoolExpr("not", (child,))


def _and(children: Sequence[BoolExpr]) -> BoolExpr:
    return BoolExpr("and", tuple(children))


def _or(children: Sequence[BoolExpr]) -> BoolExpr:
    return BoolExpr("or", tuple(children))


def _iff(children: Sequence[BoolExpr]) -> BoolExpr:
    return BoolExpr("iff", tuple(children))


def _ite(condition: BoolExpr, then_expr: BoolExpr, else_expr: BoolExpr) -> BoolExpr:
    return BoolExpr("ite", (condition, then_expr, else_expr))


class _Builder:
    def __init__(self) -> None:
        self.sorts: list[Sort] = [Sort(BOOL_SORT, "Bool")]
        self.sort_by_name: dict[str, int] = {"Bool": BOOL_SORT}
        self.functions: list[Function] = []
        self.function_by_name: dict[str, int] = {}
        self.macros: dict[int, _Macro] = {}
        self.terms: list[Term] = []
        self.term_ids: dict[tuple[int, tuple[int, ...]], int] = {}
        self.assertions: list[BoolExpr] = []
        self.bool_data_terms: set[int] = set()
        self.internal_counter = 0
        self.logic_seen = False
        self.check_sat_seen = False
        self.exit_seen = False
        self.substantive_seen = False

        true_function = self._new_function(
            "@independent_true", (), BOOL_SORT, internal=True, bind_name=False
        )
        false_function = self._new_function(
            "@independent_false", (), BOOL_SORT, internal=True, bind_name=False
        )
        self.true_term = self._intern_term(true_function, ())
        self.false_term = self._intern_term(false_function, ())

    def _new_function(
        self,
        name: str,
        arg_sorts: Sequence[int],
        result_sort: int,
        *,
        quoted: bool = False,
        internal: bool = False,
        macro: bool = False,
        bind_name: bool = True,
    ) -> int:
        if bind_name and name in self.function_by_name:
            raise IndependentQfufError(f"function `{name}` is already declared")
        function_id = len(self.functions)
        self.functions.append(
            Function(
                function_id,
                name,
                tuple(arg_sorts),
                result_sort,
                quoted=quoted,
                internal=internal,
                macro=macro,
            )
        )
        if bind_name:
            self.function_by_name[name] = function_id
        return function_id

    def _intern_term(self, function_id: int, args: Sequence[int]) -> int:
        if not 0 <= function_id < len(self.functions):
            raise IndependentQfufError("internal function ID is out of range")
        function = self.functions[function_id]
        arguments = tuple(args)
        if len(arguments) != len(function.arg_sorts):
            raise IndependentQfufError(
                f"arity mismatch in application `{function.name}`: expected "
                f"{len(function.arg_sorts)} arguments, found {len(arguments)}"
            )
        for index, (term_id, expected_sort) in enumerate(
            zip(arguments, function.arg_sorts), start=1
        ):
            if not 0 <= term_id < len(self.terms):
                raise IndependentQfufError(
                    f"application `{function.name}` argument {index} has an invalid term ID"
                )
            found_sort = self.terms[term_id].sort
            if found_sort != expected_sort:
                raise IndependentQfufError(
                    f"sort mismatch in application `{function.name}` argument {index}: "
                    f"expected `{self.sorts[expected_sort].name}`, "
                    f"found `{self.sorts[found_sort].name}`"
                )
        key = (function_id, arguments)
        previous = self.term_ids.get(key)
        if previous is not None:
            return previous
        term_id = len(self.terms)
        self.terms.append(Term(term_id, function_id, arguments, function.result_sort))
        self.term_ids[key] = term_id
        return term_id

    def _fresh_term(self, kind: str, sort: int) -> int:
        name = f"@independent_{kind}_{self.internal_counter}"
        self.internal_counter += 1
        function = self._new_function(
            name, (), sort, internal=True, bind_name=False
        )
        return self._intern_term(function, ())

    def _sort(self, sexp: _Sexp, context: str) -> int:
        token = _symbol_token(sexp, context)
        sort_id = self.sort_by_name.get(token.text)
        if sort_id is None:
            _reject(sexp, f"unknown sort `{token.text}` in {context}")
        return sort_id

    def _bool_value(self, expression: BoolExpr) -> _Value:
        return _Value(BOOL_SORT, expression=expression)

    def _term_value(self, term: int) -> _Value:
        return _Value(self.terms[term].sort, term=term)

    def _bool_term_expr(self, term: int) -> BoolExpr:
        if self.terms[term].sort != BOOL_SORT:
            raise IndependentQfufError("internal BoolTerm has a non-Boolean sort")
        return _atom(_AtomKey("bool_term", term=term))

    def _materialize_bool(self, expression: BoolExpr) -> int:
        if expression.op == "const":
            value = expression.arguments[0]
            term = self.true_term if value is True else self.false_term
        elif expression.op == "atom":
            key = expression.arguments[0]
            if isinstance(key, _AtomKey) and key.kind == "bool_term" and key.term is not None:
                term = key.term
            else:
                term = self._fresh_term("bool_expr", BOOL_SORT)
                self.assertions.append(_iff((self._bool_term_expr(term), expression)))
        else:
            term = self._fresh_term("bool_expr", BOOL_SORT)
            self.assertions.append(_iff((self._bool_term_expr(term), expression)))
        self.bool_data_terms.add(term)
        return term

    def _as_argument_term(self, value: _Value, context: str) -> int:
        if value.sort == BOOL_SORT:
            if value.expression is None:
                raise IndependentQfufError(f"internal Boolean value missing in {context}")
            return self._materialize_bool(value.expression)
        if value.term is None:
            raise IndependentQfufError(f"internal term value missing in {context}")
        return value.term

    def _expect_bool(self, value: _Value, sexp: _Sexp, context: str) -> BoolExpr:
        if value.sort != BOOL_SORT or value.expression is None:
            found = self.sorts[value.sort].name
            _reject(sexp, f"sort mismatch in {context}: expected `Bool`, found `{found}`")
        return value.expression

    def _equal_values(self, values: Sequence[_Value], sexp: _Sexp) -> BoolExpr:
        expected = values[0].sort
        for value in values[1:]:
            if value.sort != expected:
                _reject(
                    sexp,
                    "sort mismatch in equality: expected "
                    f"`{self.sorts[expected].name}`, found `{self.sorts[value.sort].name}`",
                )
        if expected == BOOL_SORT:
            expressions = [
                self._expect_bool(value, sexp, "Boolean equality") for value in values
            ]
            return _iff(expressions)
        first = values[0].term
        if first is None:
            raise IndependentQfufError("internal equality term is missing")
        equalities: list[BoolExpr] = []
        for value in values[1:]:
            if value.term is None:
                raise IndependentQfufError("internal equality term is missing")
            equalities.append(_atom(_AtomKey("equality", first, value.term)))
        return equalities[0] if len(equalities) == 1 else _and(equalities)

    def _distinct_values(self, values: Sequence[_Value], sexp: _Sexp) -> BoolExpr:
        expected = values[0].sort
        for value in values[1:]:
            if value.sort != expected:
                _reject(
                    sexp,
                    "sort mismatch in distinct: expected "
                    f"`{self.sorts[expected].name}`, found `{self.sorts[value.sort].name}`",
                )
        if expected == BOOL_SORT:
            expressions = [
                self._expect_bool(value, sexp, "Boolean distinct") for value in values
            ]
            if len(expressions) == 2:
                return _not(_iff(expressions))
            return _const(False)
        terms: list[int] = []
        for value in values:
            if value.term is None:
                raise IndependentQfufError("internal distinct term is missing")
            terms.append(value.term)
        disequalities: list[BoolExpr] = []
        for left_index in range(len(terms)):
            for right_index in range(left_index + 1, len(terms)):
                disequalities.append(
                    _not(
                        _atom(
                            _AtomKey(
                                "equality", terms[left_index], terms[right_index]
                            )
                        )
                    )
                )
        return _and(disequalities)

    def _enter_let_scope(
        self,
        sexp: _ListSexp,
        env: Mapping[str, _Value],
        expansion_stack: tuple[int, ...],
    ) -> tuple[_Sexp, Mapping[str, _Value]]:
        if len(sexp.items) != 3:
            _reject(sexp, "let expression must have bindings and one body")
        bindings = sexp.items[1]
        if not isinstance(bindings, _ListSexp):
            _reject(bindings, "let binding block must be a list")
        parsed: list[tuple[str, _Value]] = []
        seen: set[str] = set()
        for binding in bindings.items:
            if not isinstance(binding, _ListSexp) or len(binding.items) != 2:
                _reject(binding, "let binding must be a pair")
            name_token = _declared_name(binding.items[0], "let binding")
            if name_token.text in seen:
                _reject(binding.items[0], f"duplicate let binding `{name_token.text}`")
            seen.add(name_token.text)
            # SMT-LIB let right-hand sides are all evaluated in the outer scope.
            value = self._parse_value(binding.items[1], env, expansion_stack)
            parsed.append((name_token.text, value))
        local = dict(env)
        local.update(parsed)
        return sexp.items[2], local

    def _parse_ite(
        self,
        sexp: _ListSexp,
        env: Mapping[str, _Value],
        expansion_stack: tuple[int, ...],
    ) -> _Value:
        if len(sexp.items) != 4:
            _reject(sexp, "ite must have exactly three arguments")
        condition_value = self._parse_value(sexp.items[1], env, expansion_stack)
        condition = self._expect_bool(condition_value, sexp.items[1], "ite condition")
        then_value = self._parse_value(sexp.items[2], env, expansion_stack)
        else_value = self._parse_value(sexp.items[3], env, expansion_stack)
        if then_value.sort != else_value.sort:
            _reject(
                sexp,
                "sort mismatch in ite branches: expected "
                f"`{self.sorts[then_value.sort].name}`, "
                f"found `{self.sorts[else_value.sort].name}`",
            )
        if then_value.sort == BOOL_SORT:
            then_expr = self._expect_bool(then_value, sexp.items[2], "ite branch")
            else_expr = self._expect_bool(else_value, sexp.items[3], "ite branch")
            return self._bool_value(_ite(condition, then_expr, else_expr))
        if then_value.term is None or else_value.term is None:
            raise IndependentQfufError("internal ite branch term is missing")
        if then_value.term == else_value.term:
            return then_value
        ite_term = self._fresh_term("ite", then_value.sort)
        then_equality = _atom(_AtomKey("equality", ite_term, then_value.term))
        else_equality = _atom(_AtomKey("equality", ite_term, else_value.term))
        self.assertions.append(_or((_not(condition), then_equality)))
        self.assertions.append(_or((condition, else_equality)))
        return self._term_value(ite_term)

    def _apply(
        self,
        head: _Token,
        argument_sexps: Sequence[_Sexp],
        env: Mapping[str, _Value],
        expansion_stack: tuple[int, ...],
        location: _Sexp,
    ) -> _Value:
        function_id = self.function_by_name.get(head.text)
        if function_id is None:
            _reject(location, f"undeclared function `{head.text}`")
        function = self.functions[function_id]
        if len(argument_sexps) != len(function.arg_sorts):
            _reject(
                location,
                f"arity mismatch in application `{head.text}`: expected "
                f"{len(function.arg_sorts)} arguments, found {len(argument_sexps)}",
            )
        values = [
            self._parse_value(argument, env, expansion_stack)
            for argument in argument_sexps
        ]
        for index, (value, expected) in enumerate(
            zip(values, function.arg_sorts), start=1
        ):
            if value.sort != expected:
                _reject(
                    argument_sexps[index - 1],
                    f"sort mismatch in application `{head.text}` argument {index}: "
                    f"expected `{self.sorts[expected].name}`, "
                    f"found `{self.sorts[value.sort].name}`",
                )

        macro = self.macros.get(function_id)
        if macro is not None:
            if function_id in expansion_stack:
                _reject(location, f"recursive expansion of define-fun `{head.text}`")
            local = dict(env)
            for (name, _), value in zip(macro.parameters, values):
                local[name] = value
            expanded = self._parse_value(
                macro.body, local, (*expansion_stack, function_id)
            )
            if expanded.sort != function.result_sort:
                raise IndependentQfufError(
                    f"internal result-sort mismatch while expanding `{head.text}`"
                )
            return expanded

        terms = [
            self._as_argument_term(value, f"application `{head.text}`")
            for value in values
        ]
        term = self._intern_term(function_id, terms)
        if function.result_sort == BOOL_SORT:
            return self._bool_value(self._bool_term_expr(term))
        return self._term_value(term)

    def _parse_value(
        self,
        sexp: _Sexp,
        env: Mapping[str, _Value],
        expansion_stack: tuple[int, ...] = (),
    ) -> _Value:
        # Generated NEQ instances contain hundreds of nested lets. Enter their
        # scopes iteratively so valid input does not depend on Python's process-
        # global recursion limit. Binding right-hand sides still use the outer
        # scope, preserving SMT-LIB's simultaneous-binding semantics.
        while isinstance(sexp, _ListSexp) and sexp.items:
            head = _symbol_token(sexp.items[0], "expression head")
            if head.kind != "SYMBOL" or head.text != "let":
                break
            sexp, env = self._enter_let_scope(sexp, env, expansion_stack)

        if isinstance(sexp, _AtomSexp):
            token = sexp.token
            if token.kind not in {"SYMBOL", "QUOTED_SYMBOL"}:
                _reject(sexp, f"unsupported expression token `{token.text}`")
            if token.kind == "SYMBOL" and token.text == "true":
                return self._bool_value(_const(True))
            if token.kind == "SYMBOL" and token.text == "false":
                return self._bool_value(_const(False))
            bound = env.get(token.text)
            if bound is not None:
                return bound
            return self._apply(token, (), env, expansion_stack, sexp)

        if not sexp.items:
            _reject(sexp, "empty expression list")
        head = _symbol_token(sexp.items[0], "expression head")
        syntax = head.text if head.kind == "SYMBOL" else None
        arguments = sexp.items[1:]

        if syntax == "ite":
            return self._parse_ite(sexp, env, expansion_stack)
        if syntax == "!":
            if len(arguments) < 2:
                _reject(sexp, "annotation must contain a term and at least one attribute")
            index = 1
            while index < len(arguments):
                attribute = arguments[index]
                if (
                    not isinstance(attribute, _AtomSexp)
                    or attribute.token.kind != "KEYWORD"
                ):
                    _reject(attribute, "annotation attribute name must be a keyword")
                name = attribute.token.text
                value = None
                if index + 1 < len(arguments):
                    following = arguments[index + 1]
                    if not (
                        isinstance(following, _AtomSexp)
                        and following.token.kind == "KEYWORD"
                    ):
                        value = following
                        index += 1
                if name == ":named":
                    if (
                        not isinstance(value, _AtomSexp)
                        or value.token.kind not in {"SYMBOL", "QUOTED_SYMBOL"}
                    ):
                        _reject(attribute, "`:named` annotation must have a symbol value")
                index += 1
            return self._parse_value(arguments[0], env, expansion_stack)
        if syntax in {"and", "or"}:
            children = [
                self._expect_bool(
                    self._parse_value(argument, env, expansion_stack),
                    argument,
                    f"`{syntax}` argument",
                )
                for argument in arguments
            ]
            return self._bool_value(_and(children) if syntax == "and" else _or(children))
        if syntax == "not":
            if len(arguments) != 1:
                _reject(sexp, "not must have exactly one argument")
            child = self._expect_bool(
                self._parse_value(arguments[0], env, expansion_stack),
                arguments[0],
                "`not` argument",
            )
            return self._bool_value(_not(child))
        if syntax == "=>":
            if len(arguments) < 2:
                _reject(sexp, "=> must have at least two arguments")
            children = [
                self._expect_bool(
                    self._parse_value(argument, env, expansion_stack),
                    argument,
                    "`=>` argument",
                )
                for argument in arguments
            ]
            conclusion = children.pop()
            premise = children[0] if len(children) == 1 else _and(children)
            return self._bool_value(_or((_not(premise), conclusion)))
        if syntax == "xor":
            if len(arguments) < 2:
                _reject(sexp, "xor must have at least two arguments")
            expressions = [
                self._expect_bool(
                    self._parse_value(argument, env, expansion_stack),
                    argument,
                    "`xor` argument",
                )
                for argument in arguments
            ]
            expression = expressions[0]
            for right in expressions[1:]:
                expression = _not(_iff((expression, right)))
            return self._bool_value(expression)
        if syntax in {"=", "distinct"}:
            if len(arguments) < 2:
                _reject(sexp, f"{syntax} must have at least two arguments")
            values = [
                self._parse_value(argument, env, expansion_stack)
                for argument in arguments
            ]
            expression = (
                self._equal_values(values, sexp)
                if syntax == "="
                else self._distinct_values(values, sexp)
            )
            return self._bool_value(expression)
        if syntax in {"as", "_", "forall", "exists", "match"}:
            _reject(sexp, f"unsupported expression form `{syntax}`")
        return self._apply(head, arguments, env, expansion_stack, sexp)

    def _placeholder_value(self, name: str, sort: int) -> _Value:
        term = self._fresh_term(f"parameter_{name}", sort)
        if sort == BOOL_SORT:
            return self._bool_value(self._bool_term_expr(term))
        return self._term_value(term)

    def _declare_sort(self, command: _ListSexp) -> None:
        if len(command.items) != 3:
            _reject(command, "declare-sort must have a name and arity")
        name = _declared_name(command.items[1], "sort declaration")
        arity = command.items[2]
        if (
            not isinstance(arity, _AtomSexp)
            or arity.token.kind != "NUMERAL"
            or arity.token.text != "0"
        ):
            _reject(arity, f"sort `{name.text}` must have arity 0")
        if name.text in self.sort_by_name:
            _reject(command.items[1], f"sort `{name.text}` is already declared")
        sort_id = len(self.sorts)
        self.sorts.append(
            Sort(sort_id, name.text, quoted=name.kind == "QUOTED_SYMBOL")
        )
        self.sort_by_name[name.text] = sort_id

    def _declare_fun(self, command: _ListSexp, constant: bool) -> None:
        expected = 3 if constant else 4
        command_name = "declare-const" if constant else "declare-fun"
        if len(command.items) != expected:
            _reject(command, f"{command_name} has an invalid arity")
        name = _declared_name(command.items[1], f"{command_name} declaration")
        if name.text in self.function_by_name:
            _reject(command.items[1], f"function `{name.text}` is already declared")
        if constant:
            arg_sorts: list[int] = []
            result_sexp = command.items[2]
        else:
            arguments = command.items[2]
            if not isinstance(arguments, _ListSexp):
                _reject(arguments, f"argument sorts for `{name.text}` must be a list")
            arg_sorts = [
                self._sort(sort, f"argument {index} of `{name.text}`")
                for index, sort in enumerate(arguments.items, start=1)
            ]
            result_sexp = command.items[3]
        result_sort = self._sort(result_sexp, f"result of `{name.text}`")
        self._new_function(
            name.text,
            arg_sorts,
            result_sort,
            quoted=name.kind == "QUOTED_SYMBOL",
        )

    def _define_fun(self, command: _ListSexp) -> None:
        if len(command.items) != 5:
            _reject(command, "define-fun must have name, parameters, result sort, and body")
        name = _declared_name(command.items[1], "define-fun declaration")
        if name.text in self.function_by_name:
            _reject(command.items[1], f"function `{name.text}` is already declared")
        parameter_list = command.items[2]
        if not isinstance(parameter_list, _ListSexp):
            _reject(parameter_list, "define-fun parameters must be a list")
        parameters: list[tuple[str, int]] = []
        seen: set[str] = set()
        for parameter in parameter_list.items:
            if not isinstance(parameter, _ListSexp) or len(parameter.items) != 2:
                _reject(parameter, "define-fun parameter must be a name/sort pair")
            parameter_name = _declared_name(
                parameter.items[0], "define-fun parameter"
            )
            if parameter_name.text in seen:
                _reject(
                    parameter.items[0],
                    f"duplicate define-fun parameter `{parameter_name.text}`",
                )
            seen.add(parameter_name.text)
            parameters.append(
                (
                    parameter_name.text,
                    self._sort(
                        parameter.items[1],
                        f"parameter `{parameter_name.text}` of `{name.text}`",
                    ),
                )
            )
        result_sort = self._sort(command.items[3], f"result of `{name.text}`")

        # Validate even an unused macro body without polluting canonical IDs.
        validator = copy.deepcopy(self)
        validation_env = {
            parameter_name: validator._placeholder_value(parameter_name, sort)
            for parameter_name, sort in parameters
        }
        body_value = validator._parse_value(command.items[4], validation_env)
        if body_value.sort != result_sort:
            _reject(
                command.items[4],
                f"sort mismatch in body of `{name.text}`: expected "
                f"`{self.sorts[result_sort].name}`, "
                f"found `{self.sorts[body_value.sort].name}`",
            )

        function_id = self._new_function(
            name.text,
            [sort for _, sort in parameters],
            result_sort,
            quoted=name.kind == "QUOTED_SYMBOL",
            macro=True,
        )
        self.macros[function_id] = _Macro(
            function_id, tuple(parameters), command.items[4]
        )

    def _command(self, sexp: _Sexp) -> None:
        if not isinstance(sexp, _ListSexp) or not sexp.items:
            _reject(sexp, "top-level command must be a non-empty list")
        head = _syntax_symbol(sexp.items[0])
        if head is None:
            _reject(sexp.items[0], "top-level command head must be an unquoted symbol")
        if self.exit_seen:
            _reject(sexp, f"command `{head}` appears after exit")
        if self.check_sat_seen and head != "exit":
            _reject(sexp, f"command `{head}` appears after check-sat")

        if head == "set-logic":
            if len(sexp.items) != 2:
                _reject(sexp, "set-logic must have exactly one argument")
            if self.logic_seen:
                _reject(sexp, "set-logic may appear only once")
            if self.substantive_seen:
                _reject(sexp, "set-logic must precede declarations and assertions")
            logic = _syntax_symbol(sexp.items[1])
            if logic != "QF_UF":
                _reject(sexp.items[1], "only logic QF_UF is supported")
            self.logic_seen = True
            return
        if head == "set-info":
            if len(sexp.items) not in {2, 3}:
                _reject(sexp, "set-info must contain one SMT-LIB attribute")
            key = sexp.items[1]
            if not isinstance(key, _AtomSexp) or key.token.kind != "KEYWORD":
                _reject(key, "set-info attribute name must be a keyword")
            return
        if head == "set-option":
            if len(sexp.items) != 3:
                _reject(sexp, "set-option must have a keyword and value")
            key = sexp.items[1]
            if not isinstance(key, _AtomSexp) or key.token.kind != "KEYWORD":
                _reject(key, "set-option name must be a keyword")
            return
        if head == "declare-sort":
            self.substantive_seen = True
            self._declare_sort(sexp)
            return
        if head == "declare-const":
            self.substantive_seen = True
            self._declare_fun(sexp, True)
            return
        if head == "declare-fun":
            self.substantive_seen = True
            self._declare_fun(sexp, False)
            return
        if head == "define-fun":
            self.substantive_seen = True
            self._define_fun(sexp)
            return
        if head == "assert":
            if len(sexp.items) != 2:
                _reject(sexp, "assert must have exactly one argument")
            self.substantive_seen = True
            value = self._parse_value(sexp.items[1], {})
            expression = self._expect_bool(value, sexp.items[1], "assertion")
            self.assertions.append(expression)
            return
        if head == "check-sat":
            if len(sexp.items) != 1:
                _reject(sexp, "check-sat must not have arguments")
            self.check_sat_seen = True
            return
        if head == "exit":
            if len(sexp.items) != 1:
                _reject(sexp, "exit must not have arguments")
            if not self.check_sat_seen:
                _reject(sexp, "exit before check-sat is unsupported")
            self.exit_seen = True
            return
        _reject(sexp, f"unsupported top-level command `{head}`")

    def parse(self, sexps: Sequence[_Sexp]) -> None:
        for sexp in sexps:
            self._command(sexp)
        if not self.check_sat_seen:
            raise IndependentQfufError(
                "single-query QF_UF input must contain exactly one check-sat"
            )


class _Encoder:
    def __init__(self, builder: _Builder) -> None:
        self.builder = builder
        self.clauses: list[tuple[int, ...]] = []
        self.var_atoms: list[_AtomKey | None] = [None]
        self.atom_vars: dict[_AtomKey, int] = {}
        self.true_lit: int | None = None

    def _new_var(self, atom: _AtomKey | None) -> int:
        variable = len(self.var_atoms)
        self.var_atoms.append(atom)
        return variable

    def _literal_const(self, value: bool) -> int:
        if self.true_lit is None:
            self.true_lit = self._new_var(None)
            self.clauses.append((self.true_lit,))
        return self.true_lit if value else -self.true_lit

    def _atom_lit(self, atom: _AtomKey) -> int:
        if atom.kind == "equality":
            if atom.left is None or atom.right is None:
                raise IndependentQfufError("internal equality atom is incomplete")
            left, right = sorted((atom.left, atom.right))
            atom = _AtomKey("equality", left, right)
        variable = self.atom_vars.get(atom)
        if variable is not None:
            return variable
        variable = self._new_var(atom)
        self.atom_vars[atom] = variable
        return variable

    def _encode_and(self, children: Sequence[BoolExpr]) -> int:
        if not children:
            return self._literal_const(True)
        if len(children) == 1:
            return self._encode(children[0])
        literals = [self._encode(child) for child in children]
        variable = self._new_var(None)
        for literal in literals:
            self.clauses.append((-variable, literal))
        self.clauses.append((variable, *(-literal for literal in literals)))
        return variable

    def _encode_or(self, children: Sequence[BoolExpr]) -> int:
        if not children:
            return self._literal_const(False)
        if len(children) == 1:
            return self._encode(children[0])
        literals = [self._encode(child) for child in children]
        variable = self._new_var(None)
        for literal in literals:
            self.clauses.append((variable, -literal))
        self.clauses.append((-variable, *literals))
        return variable

    def _encode_iff(self, children: Sequence[BoolExpr]) -> int:
        if len(children) < 2:
            return self._literal_const(True)
        if len(children) == 2:
            left = self._encode(children[0])
            right = self._encode(children[1])
            variable = self._new_var(None)
            self.clauses.append((-variable, -left, right))
            self.clauses.append((-variable, left, -right))
            self.clauses.append((variable, -left, -right))
            self.clauses.append((variable, left, right))
            return variable
        first = children[0]
        pairs = [_iff((first, child)) for child in children[1:]]
        return self._encode_and(pairs)

    def _encode(self, expression: BoolExpr) -> int:
        if expression.op == "const":
            return self._literal_const(expression.arguments[0] is True)
        if expression.op == "atom":
            atom = expression.arguments[0]
            if not isinstance(atom, _AtomKey):
                raise IndependentQfufError("internal Boolean atom is malformed")
            return self._atom_lit(atom)
        if expression.op == "not":
            child = expression.arguments[0]
            if not isinstance(child, BoolExpr):
                raise IndependentQfufError("internal not expression is malformed")
            return -self._encode(child)
        children = expression.arguments
        if not all(isinstance(child, BoolExpr) for child in children):
            raise IndependentQfufError(
                f"internal `{expression.op}` expression is malformed"
            )
        typed_children = tuple(child for child in children if isinstance(child, BoolExpr))
        if expression.op == "and":
            return self._encode_and(typed_children)
        if expression.op == "or":
            return self._encode_or(typed_children)
        if expression.op == "iff":
            return self._encode_iff(typed_children)
        if expression.op == "ite":
            if len(typed_children) != 3:
                raise IndependentQfufError("internal ite expression has invalid arity")
            condition = self._encode(typed_children[0])
            then_lit = self._encode(typed_children[1])
            else_lit = self._encode(typed_children[2])
            variable = self._new_var(None)
            self.clauses.append((-condition, -then_lit, variable))
            self.clauses.append((-condition, then_lit, -variable))
            self.clauses.append((condition, -else_lit, variable))
            self.clauses.append((condition, else_lit, -variable))
            return variable
        raise IndependentQfufError(f"unknown internal Boolean operator `{expression.op}`")

    def finish(self) -> EncodedProblem:
        for term in sorted(self.builder.bool_data_terms):
            self._atom_lit(_AtomKey("bool_term", term=term))
        for assertion in self.builder.assertions:
            root = self._encode(assertion)
            self.clauses.append((root,))

        atoms: list[Atom] = []
        for variable, key in enumerate(self.var_atoms[1:], start=1):
            if key is None:
                atoms.append(Atom(variable, "auxiliary"))
            elif key.kind == "equality":
                atoms.append(
                    Atom(variable, "equality", left=key.left, right=key.right)
                )
            elif key.kind == "bool_term":
                atoms.append(Atom(variable, "bool_term", term=key.term))
            else:
                raise IndependentQfufError(f"unknown internal atom kind `{key.kind}`")
        return EncodedProblem(
            tuple(self.builder.sorts),
            tuple(self.builder.functions),
            tuple(self.builder.terms),
            tuple(atoms),
            tuple(self.clauses),
            self.builder.true_term,
            self.builder.false_term,
            tuple(self.builder.assertions),
            tuple(sorted(self.builder.bool_data_terms)),
        )


def parse_and_encode(source: str) -> EncodedProblem:
    """Parse one QF_UF query and reconstruct its canonical base CNF."""

    if not isinstance(source, str):
        raise IndependentQfufError("SMT-LIB source must be text")
    try:
        builder = _Builder()
        builder.parse(_parse_sexps(source))
        return _Encoder(builder).finish()
    except IndependentQfufError:
        raise
    except RecursionError as error:
        raise IndependentQfufError("SMT-LIB expression nesting is too deep") from error


class _UnionFind:
    def __init__(self, problem: EncodedProblem) -> None:
        self.problem = problem
        self.parent = list(range(len(problem.terms)))
        self.rank = [0] * len(problem.terms)

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: int, right: int) -> bool:
        if self.problem.terms[left].sort != self.problem.terms[right].sort:
            raise IndependentQfufError(
                f"cannot merge terms {left} and {right} of different sorts"
            )
        left = self.find(left)
        right = self.find(right)
        if left == right:
            return False
        if self.rank[left] < self.rank[right]:
            left, right = right, left
        self.parent[right] = left
        if self.rank[left] == self.rank[right]:
            self.rank[left] += 1
        return True


def _clone_assertions(
    assertions: tuple[BoolExpr, ...], terms: tuple[Term, ...]
) -> tuple[BoolExpr, ...]:
    clones: dict[int, BoolExpr] = {}
    states: dict[int, int] = {}

    def clone_atom_key(key: object) -> _AtomKey:
        if type(key) is not _AtomKey or type(key.kind) is not str:
            raise IndependentQfufError("assertion atom is not canonical and immutable")
        if key.kind == "equality":
            if (
                type(key.left) is not int
                or type(key.right) is not int
                or key.term is not None
                or not 0 <= key.left < len(terms)
                or not 0 <= key.right < len(terms)
                or terms[key.left].sort != terms[key.right].sort
            ):
                raise IndependentQfufError("assertion equality atom is malformed")
        elif key.kind == "bool_term":
            if (
                key.left is not None
                or key.right is not None
                or type(key.term) is not int
                or not 0 <= key.term < len(terms)
                or terms[key.term].sort != BOOL_SORT
            ):
                raise IndependentQfufError("assertion Boolean atom is malformed")
        else:
            raise IndependentQfufError(f"unknown assertion atom kind `{key.kind}`")
        return _AtomKey(key.kind, key.left, key.right, key.term)

    for root in assertions:
        stack: list[tuple[BoolExpr, bool]] = [(root, False)]
        while stack:
            expression, expanded = stack.pop()
            if type(expression) is not BoolExpr:
                raise IndependentQfufError(
                    "assertion table is not canonical and immutable"
                )
            identity = id(expression)
            if expanded:
                children = tuple(clones[id(child)] for child in expression.arguments)
                clones[identity] = BoolExpr(expression.op, children)
                states[identity] = 2
                continue

            state = states.get(identity, 0)
            if state == 2:
                continue
            if state == 1:
                raise IndependentQfufError("assertion graph contains a cycle")
            if type(expression.op) is not str or type(expression.arguments) is not tuple:
                raise IndependentQfufError(
                    "assertion table is not canonical and immutable"
                )

            op = expression.op
            arguments = expression.arguments
            if op == "const":
                if len(arguments) != 1 or type(arguments[0]) is not bool:
                    raise IndependentQfufError("constant assertion is malformed")
                clones[identity] = BoolExpr(op, (arguments[0],))
                states[identity] = 2
                continue
            if op == "atom":
                if len(arguments) != 1:
                    raise IndependentQfufError("atomic assertion is malformed")
                clones[identity] = BoolExpr(op, (clone_atom_key(arguments[0]),))
                states[identity] = 2
                continue
            if op == "not":
                valid_shape = len(arguments) == 1
            elif op == "ite":
                valid_shape = len(arguments) == 3
            elif op in {"and", "or"}:
                valid_shape = True
            elif op == "iff":
                valid_shape = len(arguments) >= 2
            else:
                raise IndependentQfufError(f"unknown assertion operator `{op}`")
            if not valid_shape or any(type(child) is not BoolExpr for child in arguments):
                raise IndependentQfufError(f"{op} assertion is malformed")

            states[identity] = 1
            stack.append((expression, True))
            stack.extend((child, False) for child in reversed(arguments))

    return tuple(clones[id(assertion)] for assertion in assertions)


def _canonical_problem_snapshot(problem: EncodedProblem) -> EncodedProblem:
    """Detach trusted validation state from caller-owned container identity."""

    if type(problem) is not EncodedProblem:
        raise IndependentQfufError("expected an EncodedProblem")
    tuple_fields = (
        ("sorts", problem.sorts),
        ("functions", problem.functions),
        ("terms", problem.terms),
        ("atoms", problem.atoms),
        ("clauses", problem.clauses),
        ("assertions", problem.assertions),
        ("bool_data_terms", problem.bool_data_terms),
    )
    for name, value in tuple_fields:
        if type(value) is not tuple:
            raise IndependentQfufError(
                f"EncodedProblem.{name} must be an immutable tuple"
            )
    if type(problem.true_term) is not int or type(problem.false_term) is not int:
        raise IndependentQfufError("Boolean value term IDs must be integers")

    sorts: list[Sort] = []
    for sort in problem.sorts:
        if (
            type(sort) is not Sort
            or type(sort.id) is not int
            or type(sort.name) is not str
            or type(sort.quoted) is not bool
        ):
            raise IndependentQfufError("sort table is not canonical and immutable")
        sorts.append(Sort(sort.id, sort.name, sort.quoted))

    functions: list[Function] = []
    for function in problem.functions:
        if (
            type(function) is not Function
            or type(function.id) is not int
            or type(function.name) is not str
            or type(function.arg_sorts) is not tuple
            or any(type(sort) is not int for sort in function.arg_sorts)
            or type(function.result_sort) is not int
            or type(function.quoted) is not bool
            or type(function.internal) is not bool
            or type(function.macro) is not bool
        ):
            raise IndependentQfufError("function table is not canonical and immutable")
        functions.append(
            Function(
                function.id,
                function.name,
                tuple(function.arg_sorts),
                function.result_sort,
                function.quoted,
                function.internal,
                function.macro,
            )
        )

    terms: list[Term] = []
    for term in problem.terms:
        if (
            type(term) is not Term
            or type(term.id) is not int
            or type(term.function) is not int
            or type(term.args) is not tuple
            or any(type(argument) is not int for argument in term.args)
            or type(term.sort) is not int
        ):
            raise IndependentQfufError("term table is not canonical and immutable")
        terms.append(Term(term.id, term.function, tuple(term.args), term.sort))

    atoms: list[Atom] = []
    for atom in problem.atoms:
        if (
            type(atom) is not Atom
            or type(atom.variable) is not int
            or type(atom.kind) is not str
            or any(
                value is not None and type(value) is not int
                for value in (atom.left, atom.right, atom.term)
            )
        ):
            raise IndependentQfufError("atom table is not canonical and immutable")
        atoms.append(Atom(atom.variable, atom.kind, atom.left, atom.right, atom.term))

    clauses: list[tuple[int, ...]] = []
    for clause in problem.clauses:
        if type(clause) is not tuple or any(
            type(literal) is not int for literal in clause
        ):
            raise IndependentQfufError("base clauses are not canonical and immutable")
        clauses.append(tuple(clause))

    assertions = _clone_assertions(problem.assertions, tuple(terms))
    if any(type(term) is not int for term in problem.bool_data_terms):
        raise IndependentQfufError("Bool-as-data term table is not canonical")

    return EncodedProblem(
        tuple(sorts),
        tuple(functions),
        tuple(terms),
        tuple(atoms),
        tuple(clauses),
        problem.true_term,
        problem.false_term,
        assertions,
        tuple(problem.bool_data_terms),
    )


def _validate_problem(problem: EncodedProblem) -> EncodedProblem:
    problem = _canonical_problem_snapshot(problem)
    if [sort.id for sort in problem.sorts] != list(range(len(problem.sorts))):
        raise IndependentQfufError("sort IDs must be contiguous and ordered")
    if not problem.sorts or problem.sorts[BOOL_SORT].name != "Bool":
        raise IndependentQfufError("Boolean sort is missing")
    if [function.id for function in problem.functions] != list(
        range(len(problem.functions))
    ):
        raise IndependentQfufError("function IDs must be contiguous and ordered")
    for function in problem.functions:
        if not 0 <= function.result_sort < len(problem.sorts) or any(
            not 0 <= sort < len(problem.sorts) for sort in function.arg_sorts
        ):
            raise IndependentQfufError(
                f"function {function.id} has an invalid sort signature"
            )
    if [term.id for term in problem.terms] != list(range(len(problem.terms))):
        raise IndependentQfufError("term IDs must be contiguous and ordered")
    for term in problem.terms:
        if not 0 <= term.function < len(problem.functions):
            raise IndependentQfufError(f"term {term.id} has an invalid function ID")
        function = problem.functions[term.function]
        if term.sort != function.result_sort or len(term.args) != len(function.arg_sorts):
            raise IndependentQfufError(f"term {term.id} does not match its function signature")
        for argument, expected_sort in zip(term.args, function.arg_sorts):
            if not 0 <= argument < term.id:
                raise IndependentQfufError(f"term {term.id} has an invalid argument")
            if problem.terms[argument].sort != expected_sort:
                raise IndependentQfufError(f"term {term.id} has an ill-sorted argument")
    if (
        not isinstance(problem.true_term, int)
        or isinstance(problem.true_term, bool)
        or not isinstance(problem.false_term, int)
        or isinstance(problem.false_term, bool)
        or not 0 <= problem.true_term < len(problem.terms)
        or not 0 <= problem.false_term < len(problem.terms)
    ):
        raise IndependentQfufError("Boolean value term is out of range")
    if problem.true_term == problem.false_term:
        raise IndependentQfufError("true and false must be distinct terms")
    true_term = problem.terms[problem.true_term]
    false_term = problem.terms[problem.false_term]
    if true_term.sort != BOOL_SORT or false_term.sort != BOOL_SORT:
        raise IndependentQfufError("true and false must have Boolean sort")
    if true_term.args or false_term.args or true_term.function == false_term.function:
        raise IndependentQfufError("true and false must be distinct zero-arity symbols")
    if [atom.variable for atom in problem.atoms] != list(
        range(1, problem.variable_count + 1)
    ):
        raise IndependentQfufError("atom variables must be contiguous and ordered")
    for atom in problem.atoms:
        if atom.kind == "auxiliary":
            if atom.left is not None or atom.right is not None or atom.term is not None:
                raise IndependentQfufError(
                    f"auxiliary variable {atom.variable} carries term metadata"
                )
        elif atom.kind == "equality":
            if atom.left is None or atom.right is None:
                raise IndependentQfufError(
                    f"equality variable {atom.variable} is incomplete"
                )
            if atom.term is not None:
                raise IndependentQfufError(
                    f"equality variable {atom.variable} carries BoolTerm metadata"
                )
            if not 0 <= atom.left < len(problem.terms) or not 0 <= atom.right < len(
                problem.terms
            ):
                raise IndependentQfufError(
                    f"equality variable {atom.variable} references an invalid term"
                )
            if problem.terms[atom.left].sort != problem.terms[atom.right].sort:
                raise IndependentQfufError(
                    f"equality variable {atom.variable} is ill-sorted"
                )
        elif atom.kind == "bool_term":
            if atom.term is None or not 0 <= atom.term < len(problem.terms):
                raise IndependentQfufError(
                    f"BoolTerm variable {atom.variable} references an invalid term"
                )
            if atom.left is not None or atom.right is not None:
                raise IndependentQfufError(
                    f"BoolTerm variable {atom.variable} carries equality metadata"
                )
            if problem.terms[atom.term].sort != BOOL_SORT:
                raise IndependentQfufError(
                    f"BoolTerm variable {atom.variable} references a non-Boolean term"
                )
        else:
            raise IndependentQfufError(
                f"variable {atom.variable} has unknown atom kind `{atom.kind}`"
            )
    for clause_index, clause in enumerate(problem.clauses, start=1):
        for literal in clause:
            if (
                not isinstance(literal, int)
                or isinstance(literal, bool)
                or literal == 0
                or abs(literal) > problem.variable_count
            ):
                raise IndependentQfufError(
                    f"base clause {clause_index} has invalid literal `{literal}`"
                )
    return problem


def _close_congruence(problem: EncodedProblem, union_find: _UnionFind) -> None:
    while True:
        changed = False
        signatures: dict[tuple[int, int, tuple[int, ...]], int] = {}
        for term in problem.terms:
            signature = (
                term.sort,
                term.function,
                tuple(union_find.find(argument) for argument in term.args),
            )
            previous = signatures.get(signature)
            if previous is None:
                signatures[signature] = term.id
            else:
                changed |= union_find.union(previous, term.id)
        if not changed:
            return


def _assignment_values(
    problem: EncodedProblem, assignment: Sequence[int]
) -> tuple[bool, ...]:
    if isinstance(assignment, (str, bytes)) or not isinstance(assignment, Sequence):
        raise IndependentQfufError("assignment must be a sequence of signed literals")
    if len(assignment) != problem.variable_count:
        raise IndependentQfufError(
            f"assignment has {len(assignment)} literals, expected {problem.variable_count}"
        )
    values = [False] * (problem.variable_count + 1)
    for variable, literal in enumerate(assignment, start=1):
        if type(literal) is not int:
            raise IndependentQfufError(
                f"assignment entry {variable} is not an exact integer literal"
            )
        if literal == 0:
            raise IndependentQfufError(
                f"assignment entry {variable} is not a nonzero integer literal"
            )
        if abs(literal) != variable:
            raise IndependentQfufError(
                f"assignment entry {variable} must assign variable {variable}, got {literal}"
            )
        values[variable] = literal > 0
    return tuple(values)


def validate_total_assignment(
    problem: EncodedProblem, assignment: Sequence[int]
) -> tuple[bool, ...]:
    """Validate an exact DIMACS assignment as a total QF_UF model."""

    problem = _validate_problem(problem)
    values = _assignment_values(problem, assignment)
    for clause_index, clause in enumerate(problem.clauses, start=1):
        if not any((literal > 0) == values[abs(literal)] for literal in clause):
            raise IndependentQfufError(
                f"assignment falsifies base clause {clause_index}"
            )

    union_find = _UnionFind(problem)
    disequalities: list[tuple[int, int, str]] = [
        (problem.true_term, problem.false_term, "true and false")
    ]
    for atom in problem.atoms:
        if atom.kind == "auxiliary":
            continue
        value = values[atom.variable]
        if atom.kind == "equality":
            assert atom.left is not None and atom.right is not None
            if value:
                union_find.union(atom.left, atom.right)
            else:
                disequalities.append(
                    (atom.left, atom.right, f"equality variable {atom.variable}")
                )
        elif atom.kind == "bool_term":
            assert atom.term is not None
            union_find.union(
                atom.term, problem.true_term if value else problem.false_term
            )
    _close_congruence(problem, union_find)
    for left, right, label in disequalities:
        if union_find.find(left) == union_find.find(right):
            raise IndependentQfufError(f"assignment violates {label} disequality")
    return values


def validate_sat_assignment(
    problem: EncodedProblem, assignment: Sequence[int]
) -> tuple[bool, ...]:
    return validate_total_assignment(problem, assignment)


def _clause_literals(
    problem: EncodedProblem, clause: Sequence[int], context: str
) -> tuple[int, ...]:
    if isinstance(clause, (str, bytes)) or not isinstance(clause, Sequence):
        raise IndependentQfufError(f"{context} must be a sequence of literals")
    literals: list[int] = []
    for position, literal in enumerate(clause, start=1):
        if type(literal) is not int:
            raise IndependentQfufError(
                f"{context} has a non-integer literal at position {position}"
            )
        if literal == 0 or abs(literal) > problem.variable_count:
            raise IndependentQfufError(
                f"{context} has invalid literal `{literal}` at position {position}"
            )
        literals.append(literal)
    return tuple(literals)


def _validate_euf_lemma_literals(
    problem: EncodedProblem, literals: Sequence[int]
) -> None:
    """Replay a normalized EUF lemma against an already validated problem."""

    union_find = _UnionFind(problem)
    disequalities: list[tuple[int, int]] = [
        (problem.true_term, problem.false_term)
    ]
    for literal in literals:
        atom = problem.atom_for_variable(abs(literal))
        if atom.kind == "auxiliary":
            raise IndependentQfufError(
                f"EUF lemma references auxiliary variable {atom.variable}"
            )
        if atom.kind == "equality":
            assert atom.left is not None and atom.right is not None
            if literal < 0:
                union_find.union(atom.left, atom.right)
            else:
                disequalities.append((atom.left, atom.right))
        elif atom.kind == "bool_term":
            assert atom.term is not None
            union_find.union(
                atom.term, problem.true_term if literal < 0 else problem.false_term
            )
    if any(
        union_find.find(left) == union_find.find(right)
        for left, right in disequalities
    ):
        return
    _close_congruence(problem, union_find)
    if any(
        union_find.find(left) == union_find.find(right)
        for left, right in disequalities
    ):
        return
    raise IndependentQfufError("clause is not a valid EUF lemma")


def validate_euf_lemma(problem: EncodedProblem, clause: Sequence[int]) -> None:
    """Validate a clause by refuting its negation in reconstructed EUF."""

    problem = _validate_problem(problem)
    literals = _clause_literals(problem, clause, "EUF lemma")
    _validate_euf_lemma_literals(problem, literals)


def euf_lemma_is_valid(problem: EncodedProblem, clause: Sequence[int]) -> bool:
    try:
        validate_euf_lemma(problem, clause)
    except IndependentQfufError:
        return False
    return True


def theory_clause_is_valid(problem: EncodedProblem, clause: Sequence[int]) -> bool:
    return euf_lemma_is_valid(problem, clause)


_DIMACS_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")


def parse_dimacs(source: str) -> tuple[int, tuple[tuple[int, ...], ...]]:
    """Parse strict DIMACS text without relying on a solver-side reader."""

    if not isinstance(source, str):
        raise IndependentQfufError("DIMACS source must be text")
    try:
        source.encode("ascii")
    except UnicodeEncodeError as error:
        raise IndependentQfufError("DIMACS source must be ASCII") from error
    variables: int | None = None
    expected_clauses: int | None = None
    clauses: list[tuple[int, ...]] = []
    current: list[int] = []
    for line_number, raw_line in enumerate(source.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("c"):
            continue
        fields = line.split()
        if fields[0] == "p":
            if variables is not None:
                raise IndependentQfufError(
                    f"DIMACS line {line_number}: duplicate header"
                )
            if fields[:2] != ["p", "cnf"] or len(fields) != 4:
                raise IndependentQfufError(
                    f"DIMACS line {line_number}: malformed header"
                )
            if not fields[2].isdigit() or not fields[3].isdigit():
                raise IndependentQfufError(
                    f"DIMACS line {line_number}: invalid header count"
                )
            variables = int(fields[2])
            expected_clauses = int(fields[3])
            continue
        if variables is None:
            raise IndependentQfufError(
                f"DIMACS line {line_number}: clause precedes header"
            )
        for field in fields:
            if not _DIMACS_INTEGER.fullmatch(field):
                raise IndependentQfufError(
                    f"DIMACS line {line_number}: invalid literal `{field}`"
                )
            literal = int(field)
            if literal == 0:
                clauses.append(tuple(current))
                current.clear()
            else:
                if abs(literal) > variables:
                    raise IndependentQfufError(
                        f"DIMACS line {line_number}: literal {literal} exceeds variable count"
                    )
                current.append(literal)
    if variables is None or expected_clauses is None:
        raise IndependentQfufError("DIMACS header is missing")
    if current:
        raise IndependentQfufError("DIMACS final clause is unterminated")
    if len(clauses) != expected_clauses:
        raise IndependentQfufError(
            f"DIMACS contains {len(clauses)} clauses, expected {expected_clauses}"
        )
    return variables, tuple(clauses)


def _v2_manifest(manifest: Mapping[str, object], result: str) -> None:
    if type(manifest) is not dict:
        raise IndependentQfufError("certificate manifest must be an object")
    if any(type(key) is not str for key in manifest):
        raise IndependentQfufError("certificate manifest keys must be exact strings")
    manifest_format = manifest.get("format")
    if type(manifest_format) is not str or manifest_format != V2_FORMAT:
        raise IndependentQfufError("unsupported certificate manifest format")
    manifest_result = manifest.get("result")
    if type(manifest_result) is not str or manifest_result != result:
        raise IndependentQfufError(
            f"certificate manifest does not claim {result.upper()}"
        )


def validate_v2_sat_manifest(
    manifest: Mapping[str, object], problem: EncodedProblem
) -> tuple[bool, ...]:
    """Validate only checker-owned v2 SAT fields; ignore solver term metadata."""

    _v2_manifest(manifest, "sat")
    assignment = manifest.get("assignment")
    if isinstance(assignment, (str, bytes)) or not isinstance(assignment, Sequence):
        raise IndependentQfufError("SAT manifest assignment must be a literal list")
    return validate_total_assignment(problem, assignment)


def validate_sat_manifest(
    manifest: Mapping[str, object], problem: EncodedProblem
) -> tuple[bool, ...]:
    return validate_v2_sat_manifest(manifest, problem)


def validate_unsat_dimacs(
    problem: EncodedProblem,
    variables: int,
    clauses: Sequence[Sequence[int]],
) -> int:
    """Check the exact local base prefix and every EUF-only suffix clause."""

    problem, normalized = _validated_unsat_clause_stream(problem, variables, clauses)
    base_count = len(problem.clauses)
    _validate_euf_suffix(problem, normalized, base_count)
    return len(normalized) - base_count


def _validated_unsat_clause_stream(
    problem: EncodedProblem,
    variables: int,
    clauses: Sequence[Sequence[int]],
) -> tuple[EncodedProblem, tuple[tuple[int, ...], ...]]:
    """Return one detached problem snapshot and its normalized DIMACS stream."""

    problem = _validate_problem(problem)
    if type(variables) is not int or variables < 0:
        raise IndependentQfufError("DIMACS variable count must be a nonnegative integer")
    if variables != problem.variable_count:
        raise IndependentQfufError(
            f"DIMACS has {variables} variables, reconstructed base has "
            f"{problem.variable_count}"
        )
    if isinstance(clauses, (str, bytes)) or not isinstance(clauses, Sequence):
        raise IndependentQfufError("DIMACS clauses must be a sequence")
    normalized = tuple(
        _clause_literals(problem, clause, f"DIMACS clause {index}")
        for index, clause in enumerate(clauses, start=1)
    )
    base_count = len(problem.clauses)
    if len(normalized) < base_count:
        raise IndependentQfufError(
            f"DIMACS has {len(normalized)} clauses, fewer than local base count {base_count}"
        )
    for index, expected in enumerate(problem.clauses):
        if normalized[index] != expected:
            raise IndependentQfufError(
                f"DIMACS base clause {index + 1} differs from reconstruction"
            )
    return problem, normalized


def _validate_euf_suffix(
    problem: EncodedProblem,
    clauses: Sequence[tuple[int, ...]],
    base_count: int,
) -> None:
    for index, clause in enumerate(clauses[base_count:], start=base_count + 1):
        try:
            _validate_euf_lemma_literals(problem, clause)
        except IndependentQfufError as error:
            raise IndependentQfufError(
                f"DIMACS clause {index} is not a valid EUF theory clause: {error}"
            ) from error


def _certificate_theory_variables(
    problem: EncodedProblem,
) -> tuple[dict[tuple[int, int], int], dict[int, int]]:
    equality_variables: dict[tuple[int, int], int] = {}
    bool_variables: dict[int, int] = {}
    for atom in problem.atoms:
        if atom.kind == "equality":
            assert atom.left is not None and atom.right is not None
            key = tuple(sorted((atom.left, atom.right)))
            if key in equality_variables:
                raise IndependentQfufError(
                    f"duplicate equality atom metadata for terms {key[0]} and {key[1]}"
                )
            equality_variables[key] = atom.variable
        elif atom.kind == "bool_term":
            assert atom.term is not None
            if atom.term in bool_variables:
                raise IndependentQfufError(
                    f"duplicate BoolTerm atom metadata for term {atom.term}"
                )
            bool_variables[atom.term] = atom.variable
    return equality_variables, bool_variables


_CERTIFICATE_EAGER_CLAUSE_BUDGET: Final = 262_144
_CERTIFICATE_EAGER_LITERAL_BUDGET: Final = 1_048_576
_CERTIFICATE_MAX_CANDIDATES_PER_APPLICATION: Final = 4_096
_CERTIFICATE_MAX_CANDIDATE_VISITS: Final = 4_194_304


class _CertificateSeedBudgetExceeded(Exception):
    pass


def _normalized_term_pair(left: int, right: int) -> tuple[int, int]:
    return (left, right) if left <= right else (right, left)


def _append_certificate_seed(
    target: list[tuple[int, ...]] | None,
    clause: Sequence[int],
    totals: list[int],
    *,
    normalize: bool = False,
) -> None:
    if normalize:
        normalized = tuple(sorted(set(clause)))
        if any(-literal in normalized for literal in normalized):
            return
    else:
        normalized = tuple(clause)
    next_clauses = totals[0] + 1
    next_literals = totals[1] + len(normalized)
    if (
        next_clauses > _CERTIFICATE_EAGER_CLAUSE_BUDGET
        or next_literals > _CERTIFICATE_EAGER_LITERAL_BUDGET
    ):
        raise _CertificateSeedBudgetExceeded
    totals[0] = next_clauses
    totals[1] = next_literals
    if target is not None:
        target.append(normalized)


def _reconstruct_certificate_transitivity(
    problem: EncodedProblem,
    equality_variables: Mapping[tuple[int, int], int],
    totals: list[int],
    *,
    materialize: bool,
) -> list[tuple[int, ...]]:
    clauses: list[tuple[int, ...]] | None = [] if materialize else None
    edges = sorted(
        (left, right, variable)
        for (left, right), variable in equality_variables.items()
    )
    adjacency: list[list[tuple[int, int]]] = [
        [] for _ in range(len(problem.terms))
    ]
    for left, right, variable in edges:
        if left == right:
            _append_certificate_seed(clauses, (variable,), totals)
            continue
        adjacency[left].append((right, variable))
        adjacency[right].append((left, variable))
    for term, neighbors in enumerate(adjacency):
        neighbors.sort()
        if len({neighbor for neighbor, _ in neighbors}) != len(neighbors):
            raise IndependentQfufError(
                f"duplicate equality neighbor metadata for term {term}"
            )

    for left, right, left_right in edges:
        if left == right:
            continue
        incident = (
            adjacency[left]
            if len(adjacency[left]) <= len(adjacency[right])
            else adjacency[right]
        )
        for third, _ in incident:
            if third <= right:
                continue
            left_third = equality_variables.get(_normalized_term_pair(left, third))
            right_third = equality_variables.get(_normalized_term_pair(right, third))
            if left_third is None or right_third is None:
                continue
            _append_certificate_seed(
                clauses, (-left_right, -left_third, right_third), totals
            )
            _append_certificate_seed(
                clauses, (-left_right, -right_third, left_third), totals
            )
            _append_certificate_seed(
                clauses, (-left_third, -right_third, left_right), totals
            )
    if clauses is None:
        return []
    clauses.sort()
    return clauses


def _reconstruct_certificate_congruence(
    problem: EncodedProblem,
    equality_variables: Mapping[tuple[int, int], int],
    bool_variables: Mapping[int, int],
    totals: list[int],
    *,
    materialize: bool,
) -> list[tuple[int, ...]]:
    clauses: list[tuple[int, ...]] | None = [] if materialize else None
    equality_neighbors: list[list[tuple[int, int]]] = [
        [] for _ in range(len(problem.terms))
    ]
    degree = [0] * len(problem.terms)
    for (left, right), variable in equality_variables.items():
        if left == right:
            continue
        equality_neighbors[left].append((right, variable))
        equality_neighbors[right].append((left, variable))
        degree[left] += 1
        degree[right] += 1
    for neighbors in equality_neighbors:
        neighbors.sort()

    applications = [term.id for term in problem.terms if term.args]
    canonical_values = {
        term.id
        for term in problem.terms
        if not term.args and degree[term.id] >= 16
    }
    canonical_only = len(canonical_values) >= 3 and (
        len(applications) > 1_000
        or any(problem.terms[term].args for term in bool_variables)
    )
    term_ids: dict[tuple[int, tuple[int, ...]], int] = {}
    for term in problem.terms:
        key = (term.function, term.args)
        if key in term_ids:
            raise IndependentQfufError(
                f"duplicate canonical term metadata for term {term.id}"
            )
        term_ids[key] = term.id

    candidate_counts: dict[int, int] = {}
    candidate_visits = 0
    for application in applications:
        count = 1
        for argument in problem.terms[application].args:
            choices = len(equality_neighbors[argument]) + 1
            if count > _CERTIFICATE_MAX_CANDIDATES_PER_APPLICATION // choices:
                count = 0
                break
            count *= choices
        if count == 0:
            continue
        candidate_visits += max(count - 1, 0)
        if candidate_visits > _CERTIFICATE_MAX_CANDIDATE_VISITS:
            raise _CertificateSeedBudgetExceeded
        candidate_counts[application] = count

    for left_id in applications:
        candidate_count = candidate_counts.get(left_id)
        if candidate_count is None:
            continue
        left = problem.terms[left_id]
        for ordinal in range(1, candidate_count):
            remainder = ordinal
            digits = [0] * len(left.args)
            for position in range(len(left.args) - 1, -1, -1):
                radix = len(equality_neighbors[left.args[position]]) + 1
                digits[position] = remainder % radix
                remainder //= radix
            if remainder:
                raise IndependentQfufError("certificate candidate enumeration overflow")
            arguments: list[int] = []
            conditions: list[int] = []
            for argument, digit in zip(left.args, digits):
                if digit == 0:
                    arguments.append(argument)
                else:
                    neighbor, equality = equality_neighbors[argument][digit - 1]
                    arguments.append(neighbor)
                    conditions.append(-equality)
            right_id = term_ids.get((left.function, tuple(arguments)))
            if right_id is None or right_id == left_id:
                continue
            if left_id > right_id and right_id in candidate_counts:
                continue
            right = problem.terms[right_id]
            if canonical_only and not (
                all(argument in canonical_values for argument in left.args)
                or all(argument in canonical_values for argument in right.args)
            ):
                continue

            result = equality_variables.get(_normalized_term_pair(left_id, right_id))
            if result is not None:
                _append_certificate_seed(
                    clauses, (*conditions, result), totals, normalize=True
                )
            left_bool = bool_variables.get(left_id)
            right_bool = bool_variables.get(right_id)
            if left_bool is None or right_bool is None:
                continue
            _append_certificate_seed(
                clauses,
                (*conditions, -left_bool, right_bool),
                totals,
                normalize=True,
            )
            _append_certificate_seed(
                clauses,
                (*conditions, left_bool, -right_bool),
                totals,
                normalize=True,
            )
    if clauses is None:
        return []
    clauses.sort()
    return clauses


def _reconstruct_certificate_static_prefix(
    problem: EncodedProblem,
) -> tuple[tuple[tuple[int, ...], ...], tuple[tuple[int, ...], ...]]:
    equality_variables, bool_variables = _certificate_theory_variables(problem)
    planned_totals = [0, 0]
    try:
        _reconstruct_certificate_transitivity(
            problem,
            equality_variables,
            planned_totals,
            materialize=False,
        )
        _reconstruct_certificate_congruence(
            problem,
            equality_variables,
            bool_variables,
            planned_totals,
            materialize=False,
        )
    except _CertificateSeedBudgetExceeded:
        return (), ()

    materialized_totals = [0, 0]
    try:
        transitivity = _reconstruct_certificate_transitivity(
            problem,
            equality_variables,
            materialized_totals,
            materialize=True,
        )
        congruence = _reconstruct_certificate_congruence(
            problem,
            equality_variables,
            bool_variables,
            materialized_totals,
            materialize=True,
        )
    except _CertificateSeedBudgetExceeded:
        raise IndependentQfufError(
            "certificate seed materialization differs from the planning pass"
        ) from None
    if materialized_totals != planned_totals:
        raise IndependentQfufError(
            "certificate seed materialization count differs from the planning pass"
        )
    return tuple(transitivity), tuple(congruence)


_UNSAT_CLAUSE_CATEGORIES: Final = (
    "base",
    "transitivity",
    "congruence",
    "theory_conflicts",
    "total",
)


def _unsat_manifest_counts(
    manifest: Mapping[str, object],
    problem: EncodedProblem,
    variables: int,
    clauses: Sequence[tuple[int, ...]],
) -> dict[str, int]:
    if type(manifest.get("variables")) is not int or manifest["variables"] != variables:
        raise IndependentQfufError(
            "UNSAT manifest variable count differs from DIMACS reconstruction"
        )
    finite_domain_axioms = manifest.get("finite_domain_axioms")
    if type(finite_domain_axioms) is not int or finite_domain_axioms != 0:
        raise IndependentQfufError(
            "UNSAT manifest finite_domain_axioms must be the integer zero"
        )
    raw_counts = manifest.get("clauses")
    if type(raw_counts) is not dict:
        raise IndependentQfufError("UNSAT manifest clauses must be an object")
    if any(type(key) is not str for key in raw_counts):
        raise IndependentQfufError(
            "UNSAT manifest clause category keys must be exact strings"
        )
    if set(raw_counts) != set(_UNSAT_CLAUSE_CATEGORIES):
        raise IndependentQfufError(
            "UNSAT manifest clauses must contain exactly base, transitivity, "
            "congruence, theory_conflicts, and total"
        )
    counts: dict[str, int] = {}
    for category in _UNSAT_CLAUSE_CATEGORIES:
        value = raw_counts[category]
        if type(value) is not int or value < 0:
            raise IndependentQfufError(
                f"UNSAT manifest clause count {category} must be a nonnegative integer"
            )
        counts[category] = value
    if counts["base"] != problem.base_count:
        raise IndependentQfufError(
            "UNSAT manifest base count differs from independent reconstruction"
        )
    if counts["total"] != len(clauses):
        raise IndependentQfufError(
            "UNSAT manifest total count differs from DIMACS reconstruction"
        )
    if sum(counts[name] for name in _UNSAT_CLAUSE_CATEGORIES[:-1]) != counts["total"]:
        raise IndependentQfufError(
            "UNSAT manifest clause categories do not sum to total"
        )
    return counts


def _validate_unsat_clause_categories(
    problem: EncodedProblem,
    clauses: Sequence[tuple[int, ...]],
    counts: Mapping[str, int],
) -> None:
    transitivity_start = counts["base"]
    congruence_start = transitivity_start + counts["transitivity"]
    theory_start = congruence_start + counts["congruence"]
    expected_transitivity, expected_congruence = (
        _reconstruct_certificate_static_prefix(problem)
    )
    if counts["transitivity"] != len(expected_transitivity):
        raise IndependentQfufError(
            "UNSAT manifest transitivity count differs from independent regeneration"
        )
    if counts["congruence"] != len(expected_congruence):
        raise IndependentQfufError(
            "UNSAT manifest congruence count differs from independent regeneration"
        )
    if tuple(clauses[transitivity_start:congruence_start]) != expected_transitivity:
        raise IndependentQfufError(
            "DIMACS transitivity prefix differs from independent regeneration"
        )
    if tuple(clauses[congruence_start:theory_start]) != expected_congruence:
        raise IndependentQfufError(
            "DIMACS congruence prefix differs from independent regeneration"
        )


def validate_v2_unsat_manifest(
    manifest: Mapping[str, object],
    problem: EncodedProblem,
    variables: int,
    clauses: Sequence[Sequence[int]],
) -> int:
    """Validate v2 UNSAT data and independently bind its clause accounting."""

    _v2_manifest(manifest, "unsat")
    problem, normalized = _validated_unsat_clause_stream(problem, variables, clauses)
    counts = _unsat_manifest_counts(manifest, problem, variables, normalized)
    _validate_unsat_clause_categories(problem, normalized, counts)
    _validate_euf_suffix(problem, normalized, problem.base_count)
    return len(normalized) - problem.base_count


_V3_TOP_LEVEL_KEYS: Final = frozenset(
    {
        "format",
        "result",
        "encoding",
        "source",
        "source_sha256",
        "dimacs",
        "dimacs_sha256",
        "proof",
        "proof_sha256",
        "variables",
        "clauses",
        "finite_orbit",
    }
)
_V3_CLAUSE_CATEGORIES: Final = (
    "base",
    "guarded_rows",
    "finite_coverage",
    "equality_channels",
    "predicate_channels",
    "orbit_lex",
    "guarded_channels",
)
_V3_CLAUSE_KEYS: Final = frozenset((*_V3_CLAUSE_CATEGORIES, "total"))
_V3_WITNESS_KEYS: Final = frozenset(
    {"domain_terms", "membership_terms", "lex_terms"}
)
_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")


def _require_exact_keys(
    value: object, expected: frozenset[str], context: str
) -> dict[str, object]:
    if type(value) is not dict:
        raise IndependentQfufError(f"{context} must be an object")
    if any(type(key) is not str for key in value):
        raise IndependentQfufError(f"{context} keys must be exact strings")
    found = set(value)
    if found != expected:
        missing = sorted(expected - found)
        unknown = sorted(found - expected)
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unknown:
            details.append(f"unknown {', '.join(unknown)}")
        raise IndependentQfufError(
            f"{context} has invalid keys ({'; '.join(details)})"
        )
    return value


def validate_v3_manifest_shape(manifest: Mapping[str, object]) -> None:
    """Reject any v3 field not emitted by the fixed finite-orbit producer."""

    manifest = _require_exact_keys(
        manifest, _V3_TOP_LEVEL_KEYS, "v3 certificate manifest"
    )
    if type(manifest["format"]) is not str or manifest["format"] != V3_FORMAT:
        raise IndependentQfufError("unsupported v3 certificate manifest format")
    if type(manifest["result"]) is not str or manifest["result"] != "unsat":
        raise IndependentQfufError("v3 certificate manifest must claim UNSAT")
    if (
        type(manifest["encoding"]) is not str
        or manifest["encoding"] != V3_ENCODING
    ):
        raise IndependentQfufError("unsupported v3 finite-orbit encoding")
    for field in ("source", "dimacs", "proof"):
        if type(manifest[field]) is not str or not manifest[field]:
            raise IndependentQfufError(
                f"v3 certificate manifest field {field!r} must be a nonempty string"
            )
    for field in ("source_sha256", "dimacs_sha256", "proof_sha256"):
        value = manifest[field]
        if type(value) is not str or _SHA256_HEX.fullmatch(value) is None:
            raise IndependentQfufError(
                f"v3 certificate manifest field {field!r} must be lowercase SHA-256 hex"
            )
    variables = manifest["variables"]
    if type(variables) is not int or variables < 0:
        raise IndependentQfufError(
            "v3 certificate manifest variables must be a nonnegative exact integer"
        )

    counts = _require_exact_keys(
        manifest["clauses"], _V3_CLAUSE_KEYS, "v3 clause counts"
    )
    for category in (*_V3_CLAUSE_CATEGORIES, "total"):
        value = counts[category]
        if type(value) is not int or value < 0:
            raise IndependentQfufError(
                f"v3 clause count {category} must be a nonnegative exact integer"
            )

    witness = _require_exact_keys(
        manifest["finite_orbit"], _V3_WITNESS_KEYS, "v3 finite_orbit witness"
    )
    for field in ("domain_terms", "membership_terms", "lex_terms"):
        terms = witness[field]
        if type(terms) is not list:
            raise IndependentQfufError(
                f"v3 finite_orbit {field} must be an exact JSON array"
            )
        if any(type(term) is not int or term < 0 for term in terms):
            raise IndependentQfufError(
                f"v3 finite_orbit {field} must contain nonnegative exact integers"
            )


def _mandatory_disequalities(
    assertions: Sequence[BoolExpr],
) -> set[tuple[int, int]]:
    edges: set[tuple[int, int]] = set()
    stack = list(assertions)
    while stack:
        expression = stack.pop()
        if expression.op == "and":
            stack.extend(expression.arguments)
            continue
        if expression.op != "not":
            continue
        child = expression.arguments[0]
        if type(child) is not BoolExpr or child.op != "atom":
            continue
        atom = child.arguments[0]
        if (
            type(atom) is _AtomKey
            and atom.kind == "equality"
            and atom.left is not None
            and atom.right is not None
            and atom.left != atom.right
        ):
            edges.add(_normalized_term_pair(atom.left, atom.right))
    return edges


def _flatten_equality_disjunction(
    expression: BoolExpr,
) -> tuple[tuple[int, int], ...] | None:
    pairs: list[tuple[int, int]] = []
    stack = [expression]
    while stack:
        child = stack.pop()
        if child.op == "or":
            stack.extend(reversed(child.arguments))
            continue
        if child.op != "atom":
            return None
        atom = child.arguments[0]
        if (
            type(atom) is not _AtomKey
            or atom.kind != "equality"
            or atom.left is None
            or atom.right is None
        ):
            return None
        pairs.append((atom.left, atom.right))
    return tuple(pairs)


def _mandatory_coverages(
    assertions: Sequence[BoolExpr], domain: frozenset[int]
) -> frozenset[int]:
    covered: set[int] = set()
    stack = list(assertions)
    while stack:
        expression = stack.pop()
        if expression.op == "and":
            stack.extend(expression.arguments)
            continue
        if expression.op != "or":
            continue
        pairs = _flatten_equality_disjunction(expression)
        if pairs is None:
            continue
        candidate: int | None = None
        values: set[int] = set()
        valid = True
        for left, right in pairs:
            if left in domain and right not in domain:
                term, value = right, left
            elif right in domain and left not in domain:
                term, value = left, right
            else:
                valid = False
                break
            if candidate is not None and candidate != term:
                valid = False
                break
            candidate = term
            values.add(value)
        if valid and candidate is not None and values == domain:
            covered.add(candidate)
    return frozenset(covered)


def _term_index(problem: EncodedProblem) -> dict[tuple[int, tuple[int, ...]], int]:
    index: dict[tuple[int, tuple[int, ...]], int] = {}
    for term in problem.terms:
        key = (term.function, term.args)
        if key in index:
            raise IndependentQfufError(
                f"duplicate canonical term for function {term.function} and arguments {term.args}"
            )
        index[key] = term.id
    return index


def _closed_table_functions(
    problem: EncodedProblem,
    domain: tuple[int, ...],
    covered: frozenset[int],
) -> frozenset[int]:
    domain_set = frozenset(domain)
    candidates = {
        problem.terms[term].function
        for term in covered
        if problem.terms[term].args
        and all(argument in domain_set for argument in problem.terms[term].args)
    }
    closed: set[int] = set()
    for function in candidates:
        arity = len(problem.functions[function].arg_sorts)
        expected = 1
        for _ in range(arity):
            if expected > len(covered) // len(domain):
                expected = len(covered) + 1
                break
            expected *= len(domain)
        table = {
            problem.terms[term].args
            for term in covered
            if problem.terms[term].function == function
            and len(problem.terms[term].args) == arity
            and all(argument in domain_set for argument in problem.terms[term].args)
        }
        if len(table) == expected:
            closed.add(function)
    return frozenset(closed)


def _finite_closure(
    problem: EncodedProblem,
    domain: tuple[int, ...],
    covered: frozenset[int],
    closed_functions: frozenset[int],
) -> frozenset[int]:
    finite = set(domain)
    finite.update(covered)
    applications = tuple(term for term in problem.terms if term.args)
    while True:
        changed = False
        for term in applications:
            if (
                term.function in closed_functions
                and all(argument in finite for argument in term.args)
                and term.id not in finite
            ):
                finite.add(term.id)
                changed = True
        if not changed:
            return frozenset(finite)


def _canonical_assertion_key(
    expression: BoolExpr,
    term_map: Sequence[int],
    memo: dict[int, tuple[object, ...]],
) -> tuple[object, ...]:
    cached = memo.get(id(expression))
    if cached is not None:
        return cached
    if expression.op == "const":
        key: tuple[object, ...] = ("const", expression.arguments[0])
    elif expression.op == "atom":
        atom = expression.arguments[0]
        if type(atom) is not _AtomKey:
            raise IndependentQfufError("source assertion atom is malformed")
        if atom.kind == "equality":
            assert atom.left is not None and atom.right is not None
            left, right = _normalized_term_pair(
                term_map[atom.left], term_map[atom.right]
            )
            key = ("atom", "equality", left, right)
        elif atom.kind == "bool_term":
            assert atom.term is not None
            key = ("atom", "bool_term", term_map[atom.term])
        else:
            raise IndependentQfufError(
                f"unknown source assertion atom kind `{atom.kind}`"
            )
    elif expression.op == "not":
        child = expression.arguments[0]
        assert type(child) is BoolExpr
        key = ("not", _canonical_assertion_key(child, term_map, memo))
    elif expression.op in {"and", "or", "iff"}:
        children = tuple(
            sorted(
                _canonical_assertion_key(child, term_map, memo)
                for child in expression.arguments
                if type(child) is BoolExpr
            )
        )
        if len(children) != len(expression.arguments):
            raise IndependentQfufError("source assertion child is malformed")
        key = (expression.op, children)
    elif expression.op == "ite":
        children = tuple(
            _canonical_assertion_key(child, term_map, memo)
            for child in expression.arguments
            if type(child) is BoolExpr
        )
        if len(children) != 3:
            raise IndependentQfufError("source ite assertion is malformed")
        key = ("ite", *children)
    else:
        raise IndependentQfufError(
            f"unknown source assertion operator `{expression.op}`"
        )
    memo[id(expression)] = key
    return key


def _assertion_multiset(
    assertions: Sequence[BoolExpr], term_map: Sequence[int]
) -> tuple[tuple[object, ...], ...]:
    memo: dict[int, tuple[object, ...]] = {}
    return tuple(
        sorted(
            _canonical_assertion_key(assertion, term_map, memo)
            for assertion in assertions
        )
    )


def _adjacent_swap_maps(
    problem: EncodedProblem,
    domain: tuple[int, ...],
    term_ids: Mapping[tuple[int, tuple[int, ...]], int],
) -> tuple[tuple[int, ...], ...]:
    identity = tuple(range(len(problem.terms)))
    baseline = _assertion_multiset(problem.assertions, identity)
    maps: list[tuple[int, ...]] = []
    for left, right in zip(domain, domain[1:]):
        mapped = [-1] * len(problem.terms)
        mapped[left] = right
        mapped[right] = left
        for term in problem.terms:
            if mapped[term.id] >= 0:
                continue
            if not term.args:
                mapped[term.id] = term.id
                continue
            arguments = tuple(mapped[argument] for argument in term.args)
            if any(argument < 0 for argument in arguments):
                raise IndependentQfufError(
                    "adjacent domain swap encountered a non-topological term"
                )
            image = term_ids.get((term.function, arguments))
            if image is None:
                raise IndependentQfufError(
                    "adjacent domain swap is not total on the source term arena"
                )
            mapped[term.id] = image
        if any(image < 0 for image in mapped):
            raise IndependentQfufError("adjacent domain swap is not total")
        if len(set(mapped)) != len(mapped):
            raise IndependentQfufError("adjacent domain swap is not bijective")
        if any(mapped[mapped[term]] != term for term in identity):
            raise IndependentQfufError("adjacent domain swap is not involutive")
        if any(
            problem.terms[term].sort != problem.terms[mapped[term]].sort
            for term in identity
        ):
            raise IndependentQfufError("adjacent domain swap is not sort-preserving")
        if _assertion_multiset(problem.assertions, mapped) != baseline:
            raise IndependentQfufError(
                "adjacent domain swap is not a source assertion-multiset automorphism"
            )
        maps.append(tuple(mapped))
    return tuple(maps)


class _OrbitCnfBuilder:
    def __init__(self, problem: EncodedProblem) -> None:
        self.var_atoms: list[_AtomKey | None] = [None]
        self.atom_vars: dict[_AtomKey, int] = {}
        for atom in problem.atoms:
            if atom.kind == "auxiliary":
                key = None
            elif atom.kind == "equality":
                assert atom.left is not None and atom.right is not None
                left, right = _normalized_term_pair(atom.left, atom.right)
                key = _AtomKey("equality", left, right)
            elif atom.kind == "bool_term":
                assert atom.term is not None
                key = _AtomKey("bool_term", term=atom.term)
            else:
                raise IndependentQfufError(
                    f"unknown base atom kind `{atom.kind}`"
                )
            self.var_atoms.append(key)
            if key is not None:
                if key in self.atom_vars:
                    raise IndependentQfufError(
                        "base atom table contains duplicate canonical atoms"
                    )
                self.atom_vars[key] = atom.variable

    @property
    def variable_count(self) -> int:
        return len(self.var_atoms) - 1

    def atom_lit(self, atom: _AtomKey) -> int:
        if atom.kind == "equality":
            assert atom.left is not None and atom.right is not None
            left, right = _normalized_term_pair(atom.left, atom.right)
            atom = _AtomKey("equality", left, right)
        previous = self.atom_vars.get(atom)
        if previous is not None:
            return previous
        variable = len(self.var_atoms)
        self.var_atoms.append(atom)
        self.atom_vars[atom] = variable
        return variable

    def new_auxiliary(self) -> int:
        variable = len(self.var_atoms)
        self.var_atoms.append(None)
        return variable


def _domain_tuples(
    arguments: Sequence[int], domain: tuple[int, ...], domain_set: frozenset[int]
) -> tuple[tuple[int, ...], ...]:
    tuples: list[tuple[int, ...]] = [()]
    for argument in arguments:
        choices = (argument,) if argument in domain_set else domain
        tuples = [prefix + (choice,) for prefix in tuples for choice in choices]
    return tuple(tuples)


def _tuple_count_with_cap(
    arguments: Sequence[int], domain_size: int, domain_set: frozenset[int]
) -> int | None:
    count = 1
    for argument in arguments:
        choices = 1 if argument in domain_set else domain_size
        if count > _ORBIT_MAX_TUPLES_PER_APPLICATION // choices:
            return None
        count *= choices
    return count


def _guarded_budget(
    category: str, clause_count: int, literal_count: int
) -> None:
    if (
        clause_count > _ORBIT_MAX_GUARDED_CLAUSES
        or literal_count > _ORBIT_MAX_GUARDED_LITERALS
    ):
        raise IndependentQfufError(f"v3 {category} budget exceeded")


def _lex_counts(coordinates: int) -> tuple[int, int]:
    if coordinates == 0:
        return 0, 0
    if coordinates == 1:
        return 1, 2
    return coordinates * 6 - 6, coordinates * 19 - 21


def _add_lex_less_or_equal(
    builder: _OrbitCnfBuilder, comparison: Sequence[tuple[int, int]]
) -> tuple[tuple[int, ...], ...]:
    effective = tuple((left, right) for left, right in comparison if left != right)
    clauses: list[tuple[int, ...]] = []
    equal_prefix: int | None = None
    for index, (left, right) in enumerate(effective):
        if equal_prefix is None:
            clauses.append((-left, right))
        else:
            clauses.append((-equal_prefix, -left, right))
        if index + 1 == len(effective):
            break
        next_prefix = builder.new_auxiliary()
        if equal_prefix is None:
            clauses.append((-next_prefix, -left, right))
            clauses.append((-next_prefix, left, -right))
            clauses.append((-left, -right, next_prefix))
            clauses.append((left, right, next_prefix))
        else:
            clauses.append((-next_prefix, equal_prefix))
            clauses.append((-next_prefix, -left, right))
            clauses.append((-next_prefix, left, -right))
            clauses.append((-equal_prefix, -left, -right, next_prefix))
            clauses.append((-equal_prefix, left, right, next_prefix))
        equal_prefix = next_prefix
    return tuple(clauses)


@dataclass(frozen=True)
class _OrbitReconstruction:
    variables: int
    categories: Mapping[str, tuple[tuple[int, ...], ...]]


def _reconstruct_v3_orbit_kernel(
    problem: EncodedProblem, witness: Mapping[str, object]
) -> _OrbitReconstruction:
    raw_domain = witness["domain_terms"]
    assert type(raw_domain) is list
    if not 2 <= len(raw_domain) <= _ORBIT_MAX_DOMAIN:
        raise IndependentQfufError(
            f"v3 domain must contain 2..={_ORBIT_MAX_DOMAIN} terms"
        )
    domain = tuple(raw_domain)
    if tuple(sorted(set(domain))) != domain:
        raise IndependentQfufError(
            "v3 domain_terms must be strictly increasing and duplicate-free"
        )
    if any(term >= len(problem.terms) for term in domain):
        raise IndependentQfufError("v3 domain term is outside the source term arena")
    raw_membership_terms = witness["membership_terms"]
    assert type(raw_membership_terms) is list
    raw_membership_cells = len(raw_membership_terms) * len(domain)
    if raw_membership_cells > _ORBIT_MAX_MEMBERSHIP_CELLS:
        raise IndependentQfufError(
            f"v3 membership cell cap exceeded: {raw_membership_cells}"
        )
    domain_sort = problem.terms[domain[0]].sort
    if any(
        problem.terms[term].sort != domain_sort or problem.terms[term].args
        for term in domain
    ):
        raise IndependentQfufError(
            "v3 domain_terms must be same-sort nullary source terms"
        )
    mandatory_disequalities = _mandatory_disequalities(problem.assertions)
    if any(
        _normalized_term_pair(domain[left], domain[right])
        not in mandatory_disequalities
        for left in range(len(domain))
        for right in range(left + 1, len(domain))
    ):
        raise IndependentQfufError(
            "v3 domain_terms are not a mandatory top-level disequality clique"
        )

    domain_set = frozenset(domain)
    covered = _mandatory_coverages(problem.assertions, domain_set)
    closed_functions = _closed_table_functions(problem, domain, covered)
    finite_terms = _finite_closure(
        problem, domain, covered, closed_functions
    )
    membership_terms = tuple(sorted(finite_terms))
    if raw_membership_terms != list(membership_terms):
        raise IndependentQfufError(
            "v3 membership_terms differ from independent finite closure"
        )
    membership_cells = len(membership_terms) * len(domain)
    if membership_cells > _ORBIT_MAX_MEMBERSHIP_CELLS:
        raise IndependentQfufError(
            f"v3 membership cell cap exceeded: {membership_cells}"
        )

    lex_terms = tuple(
        sorted(covered, key=lambda term: (bool(problem.terms[term].args), term))
    )
    if not lex_terms:
        raise IndependentQfufError("v3 lex_terms must not be empty")
    if witness["lex_terms"] != list(lex_terms):
        raise IndependentQfufError(
            "v3 lex_terms differ from independent Rust-order reconstruction"
        )
    if any(term not in finite_terms for term in lex_terms):
        raise IndependentQfufError("v3 lex_terms are outside finite closure")

    term_ids = _term_index(problem)
    swap_maps = _adjacent_swap_maps(problem, domain, term_ids)
    lex_set = frozenset(lex_terms)
    if any(
        term_map[term] not in lex_set
        for term_map in swap_maps
        for term in lex_terms
    ):
        raise IndependentQfufError(
            "v3 lex_terms are not closed under adjacent generators"
        )

    original_equalities = tuple(
        (atom.variable, atom.left, atom.right)
        for atom in problem.atoms
        if atom.kind == "equality"
        and atom.left is not None
        and atom.right is not None
    )
    original_predicates = tuple(
        sorted(
            {
                atom.term
                for atom in problem.atoms
                if atom.kind == "bool_term"
                and atom.term is not None
                and problem.terms[atom.term].args
            }
        )
    )

    builder = _OrbitCnfBuilder(problem)
    membership: dict[tuple[int, int], int] = {}
    for term in membership_terms:
        for value in domain:
            membership[(term, value)] = builder.atom_lit(
                _AtomKey("equality", term, value)
            )

    non_domain_terms = tuple(
        term for term in membership_terms if term not in domain_set
    )
    domain_pairs = len(domain) * (len(domain) - 1) // 2
    guarded_rows_count = len(non_domain_terms) * domain_pairs + len(domain)
    guarded_rows_literals = len(non_domain_terms) * domain_pairs * 3 + len(domain)
    _guarded_budget(
        "guarded_rows", guarded_rows_count, guarded_rows_literals
    )
    guarded_rows: list[tuple[int, ...]] = []
    for term in membership_terms:
        if term in domain_set:
            guarded_rows.append((membership[(term, term)],))
            continue
        for left in range(len(domain)):
            for right in range(left + 1, len(domain)):
                guarded_rows.append(
                    (
                        membership[(domain[left], domain[right])],
                        -membership[(term, domain[left])],
                        -membership[(term, domain[right])],
                    )
                )
    if len(guarded_rows) != guarded_rows_count:
        raise IndependentQfufError("v3 guarded_rows reconstruction mismatch")

    finite_coverage_count = len(non_domain_terms)
    finite_coverage_literals = finite_coverage_count * len(domain)
    _guarded_budget(
        "finite_coverage", finite_coverage_count, finite_coverage_literals
    )
    finite_coverage = tuple(
        tuple(membership[(term, value)] for value in domain)
        for term in non_domain_terms
    )

    channeled_equalities = tuple(
        (variable, left, right)
        for variable, left, right in original_equalities
        if left != right
        and left in finite_terms
        and right in finite_terms
        and left not in domain_set
        and right not in domain_set
    )
    equality_channel_count = len(channeled_equalities) * len(domain) * 3
    _guarded_budget(
        "equality_channels", equality_channel_count, equality_channel_count * 3
    )
    equality_channels: list[tuple[int, ...]] = []
    for equality, left, right in channeled_equalities:
        for value in domain:
            left_value = membership[(left, value)]
            right_value = membership[(right, value)]
            equality_channels.append((-equality, -left_value, right_value))
            equality_channels.append((-equality, left_value, -right_value))
            equality_channels.append((-left_value, -right_value, equality))

    predicate_clause_bound = 0
    predicate_literal_bound = 0
    predicate_tuple_counts: dict[int, int] = {}
    for term_id in original_predicates:
        term = problem.terms[term_id]
        if any(argument not in finite_terms for argument in term.args):
            raise IndependentQfufError(
                "v3 predicate arguments are outside finite closure"
            )
        tuple_count = _tuple_count_with_cap(
            term.args, len(domain), domain_set
        )
        if tuple_count is None:
            raise IndependentQfufError(
                "v3 predicate per-application tuple cap exceeded"
            )
        predicate_tuple_counts[term_id] = tuple_count
        clauses = tuple_count * 2
        predicate_clause_bound += clauses
        predicate_literal_bound += clauses * (len(term.args) + 2)
        _guarded_budget(
            "predicate_channels",
            predicate_clause_bound,
            predicate_literal_bound,
        )

    predicate_clause_set: set[tuple[int, ...]] = set()
    for term_id in original_predicates:
        term = problem.terms[term_id]
        tuples = _domain_tuples(term.args, domain, domain_set)
        if len(tuples) != predicate_tuple_counts[term_id]:
            raise IndependentQfufError(
                "v3 predicate tuple reconstruction mismatch"
            )
        for values in tuples:
            canonical = term_ids.get((term.function, values))
            if canonical is None:
                raise IndependentQfufError(
                    "v3 predicate canonical table application is missing"
                )
            application_lit = builder.atom_lit(
                _AtomKey("bool_term", term=term_id)
            )
            canonical_lit = builder.atom_lit(
                _AtomKey("bool_term", term=canonical)
            )
            if application_lit == canonical_lit:
                continue
            conditions = tuple(
                membership[(argument, value)]
                for argument, value in zip(term.args, values)
                if argument != value
            )
            for suffix in (
                (-application_lit, canonical_lit),
                (application_lit, -canonical_lit),
            ):
                clause = tuple(
                    sorted({*(-condition for condition in conditions), *suffix})
                )
                literals = frozenset(clause)
                if any(-literal in literals for literal in literals):
                    continue
                predicate_clause_set.add(clause)
    predicate_channels = tuple(sorted(predicate_clause_set))
    _guarded_budget(
        "predicate_channels",
        len(predicate_channels),
        sum(len(clause) for clause in predicate_channels),
    )
    if len(predicate_channels) > predicate_clause_bound:
        raise IndependentQfufError(
            "v3 predicate channel materialization exceeds planned bound"
        )

    effective_coordinates = 0
    planned_lex_clauses = 0
    planned_lex_literals = 0
    generator_coordinates: list[int] = []
    for term_map in swap_maps:
        coordinates = 0
        for term in lex_terms:
            for value in domain:
                left = membership[(term, value)]
                right = membership[(term_map[term], term_map[value])]
                if left != right:
                    coordinates += 1
                    effective_coordinates += 1
                    if (
                        effective_coordinates
                        > _ORBIT_MAX_EFFECTIVE_LEX_COORDINATES
                    ):
                        raise IndependentQfufError(
                            "v3 effective lex coordinate cap exceeded"
                        )
        generator_coordinates.append(coordinates)
        clauses, literals = _lex_counts(coordinates)
        planned_lex_clauses += clauses
        planned_lex_literals += literals
        _guarded_budget(
            "orbit_lex", planned_lex_clauses, planned_lex_literals
        )

    orbit_lex: list[tuple[int, ...]] = []
    for term_map, coordinates in zip(swap_maps, generator_coordinates):
        comparison = tuple(
            (
                -membership[(term, value)],
                -membership[(term_map[term], term_map[value])],
            )
            for term in lex_terms
            for value in domain
        )
        generated = _add_lex_less_or_equal(builder, comparison)
        expected_clauses, _ = _lex_counts(coordinates)
        if len(generated) != expected_clauses:
            raise IndependentQfufError("v3 orbit_lex Tseitin mismatch")
        orbit_lex.extend(generated)
    if (
        len(orbit_lex) != planned_lex_clauses
        or sum(len(clause) for clause in orbit_lex) != planned_lex_literals
    ):
        raise IndependentQfufError("v3 orbit_lex materialization mismatch")

    guarded_channels: list[tuple[int, ...]] = []
    guarded_channel_literals = 0
    for term in problem.terms:
        if (
            not term.args
            or term.id not in finite_terms
            or term.function not in closed_functions
        ):
            continue
        tuple_count = _tuple_count_with_cap(
            term.args, len(domain), domain_set
        )
        # The 51d residual app class intentionally skips over-cap expansions.
        if tuple_count is None:
            continue
        tuples = _domain_tuples(term.args, domain, domain_set)
        if len(tuples) != tuple_count:
            raise IndependentQfufError(
                "v3 guarded channel tuple reconstruction mismatch"
            )
        for values in tuples:
            canonical = term_ids.get((term.function, values))
            # Missing residual app channels are also exact producer skips.
            if canonical is None or canonical == term.id:
                continue
            conditions = tuple(
                membership[(argument, value)]
                for argument, value in zip(term.args, values)
                if argument != value
            )
            for output in domain:
                clause = tuple(
                    sorted(
                        {
                            *(-condition for condition in conditions),
                            -membership[(canonical, output)],
                            membership[(term.id, output)],
                        }
                    )
                )
                guarded_channels.append(clause)
                guarded_channel_literals += len(clause)
                _guarded_budget(
                    "guarded_channels",
                    len(guarded_channels),
                    guarded_channel_literals,
                )

    categories: dict[str, tuple[tuple[int, ...], ...]] = {
        "base": problem.clauses,
        "guarded_rows": tuple(guarded_rows),
        "finite_coverage": finite_coverage,
        "equality_channels": tuple(equality_channels),
        "predicate_channels": predicate_channels,
        "orbit_lex": tuple(orbit_lex),
        "guarded_channels": tuple(guarded_channels),
    }
    return _OrbitReconstruction(builder.variable_count, categories)


def _normalize_v3_dimacs(
    variables: int, clauses: Sequence[Sequence[int]]
) -> tuple[tuple[int, ...], ...]:
    if type(variables) is not int or variables < 0:
        raise IndependentQfufError(
            "v3 DIMACS variable count must be a nonnegative exact integer"
        )
    if isinstance(clauses, (str, bytes)) or not isinstance(clauses, Sequence):
        raise IndependentQfufError("v3 DIMACS clauses must be a sequence")
    normalized: list[tuple[int, ...]] = []
    for index, clause in enumerate(clauses, start=1):
        if isinstance(clause, (str, bytes)) or not isinstance(clause, Sequence):
            raise IndependentQfufError(
                f"v3 DIMACS clause {index} must be a literal sequence"
            )
        literals: list[int] = []
        for literal in clause:
            if (
                type(literal) is not int
                or literal == 0
                or abs(literal) > variables
            ):
                raise IndependentQfufError(
                    f"v3 DIMACS clause {index} has invalid literal `{literal}`"
                )
            literals.append(literal)
        normalized.append(tuple(literals))
    return tuple(normalized)


def validate_v3_unsat_manifest(
    manifest: Mapping[str, object],
    problem: EncodedProblem,
    variables: int,
    clauses: Sequence[Sequence[int]],
) -> int:
    """Regenerate and match the complete v3 finite-orbit certificate CNF."""

    validate_v3_manifest_shape(manifest)
    problem = _validate_problem(problem)
    normalized = _normalize_v3_dimacs(variables, clauses)
    if manifest["variables"] != variables:
        raise IndependentQfufError(
            "v3 manifest and DIMACS variable counts differ"
        )
    counts = manifest["clauses"]
    assert type(counts) is dict
    if counts["base"] != problem.base_count:
        raise IndependentQfufError(
            "v3 base count differs from independent reconstruction"
        )
    if counts["total"] != len(normalized):
        raise IndependentQfufError(
            "v3 total count differs from DIMACS reconstruction"
        )
    if sum(counts[category] for category in _V3_CLAUSE_CATEGORIES) != counts[
        "total"
    ]:
        raise IndependentQfufError("v3 clause categories do not sum to total")

    witness = manifest["finite_orbit"]
    assert type(witness) is dict
    try:
        reconstruction = _reconstruct_v3_orbit_kernel(problem, witness)
    except RecursionError as error:
        raise IndependentQfufError(
            "v3 source assertions are too deeply nested for orbit reconstruction"
        ) from error
    if reconstruction.variables != variables:
        raise IndependentQfufError(
            "v3 variable count differs from deterministic atom allocation"
        )

    offset = 0
    for category in _V3_CLAUSE_CATEGORIES:
        expected = reconstruction.categories[category]
        if counts[category] != len(expected):
            raise IndependentQfufError(
                f"v3 {category} count differs from independent regeneration"
            )
        end = offset + len(expected)
        if normalized[offset:end] != expected:
            raise IndependentQfufError(
                f"v3 DIMACS {category} boundary differs from independent regeneration"
            )
        offset = end
    if offset != len(normalized):
        raise IndependentQfufError(
            "v3 reconstructed category boundaries do not cover DIMACS"
        )
    return len(normalized) - problem.base_count


def validate_unsat_manifest(
    manifest: Mapping[str, object],
    problem: EncodedProblem,
    variables: int,
    clauses: Sequence[Sequence[int]],
) -> int:
    if type(manifest) is dict and manifest.get("format") == V3_FORMAT:
        return validate_v3_unsat_manifest(manifest, problem, variables, clauses)
    return validate_v2_unsat_manifest(manifest, problem, variables, clauses)


__all__ = [
    "Atom",
    "BOOL_SORT",
    "BoolExpr",
    "EncodedProblem",
    "Function",
    "IndependentQfufError",
    "QfufError",
    "Sort",
    "Term",
    "V2_FORMAT",
    "V3_ENCODING",
    "V3_FORMAT",
    "euf_lemma_is_valid",
    "parse_and_encode",
    "parse_dimacs",
    "theory_clause_is_valid",
    "validate_euf_lemma",
    "validate_sat_assignment",
    "validate_sat_manifest",
    "validate_total_assignment",
    "validate_unsat_dimacs",
    "validate_unsat_manifest",
    "validate_v2_sat_manifest",
    "validate_v2_unsat_manifest",
    "validate_v3_manifest_shape",
    "validate_v3_unsat_manifest",
]
