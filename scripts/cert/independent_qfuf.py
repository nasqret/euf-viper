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
        if not isinstance(variable, int) or isinstance(variable, bool):
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
                escaped = self.source[self.index]
                if escaped in "\r\n":
                    self._raise("newline escape in quoted symbol", line, column)
                value.append(self._advance())
                continue
            if char in "\r\n":
                self._raise("newline in quoted symbol", line, column)
            if ord(char) < 0x20:
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

    def _parse_let(
        self,
        sexp: _ListSexp,
        env: Mapping[str, _Value],
        expansion_stack: tuple[int, ...],
    ) -> _Value:
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
        return self._parse_value(sexp.items[2], local, expansion_stack)

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

        if syntax == "let":
            return self._parse_let(sexp, env, expansion_stack)
        if syntax == "ite":
            return self._parse_ite(sexp, env, expansion_stack)
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
        if syntax in {"!", "as", "_", "forall", "exists", "match"}:
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


def _validate_problem(problem: EncodedProblem) -> None:
    if not isinstance(problem, EncodedProblem):
        raise IndependentQfufError("expected an EncodedProblem")
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
        if not isinstance(literal, int) or isinstance(literal, bool) or literal == 0:
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

    _validate_problem(problem)
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
        if (
            not isinstance(literal, int)
            or isinstance(literal, bool)
            or literal == 0
            or abs(literal) > problem.variable_count
        ):
            raise IndependentQfufError(
                f"{context} has invalid literal `{literal}` at position {position}"
            )
        literals.append(literal)
    return tuple(literals)


def validate_euf_lemma(problem: EncodedProblem, clause: Sequence[int]) -> None:
    """Validate a clause by refuting its negation in reconstructed EUF."""

    _validate_problem(problem)
    literals = _clause_literals(problem, clause, "EUF lemma")
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
    _close_congruence(problem, union_find)
    if not any(
        union_find.find(left) == union_find.find(right)
        for left, right in disequalities
    ):
        raise IndependentQfufError("clause is not a valid EUF lemma")


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
    if not isinstance(manifest, Mapping):
        raise IndependentQfufError("certificate manifest must be an object")
    if manifest.get("format") != V2_FORMAT:
        raise IndependentQfufError("unsupported certificate manifest format")
    if manifest.get("result") != result:
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

    _validate_problem(problem)
    if not isinstance(variables, int) or isinstance(variables, bool) or variables < 0:
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
    for index, clause in enumerate(normalized[base_count:], start=base_count + 1):
        try:
            validate_euf_lemma(problem, clause)
        except IndependentQfufError as error:
            raise IndependentQfufError(
                f"DIMACS clause {index} is not a valid EUF theory clause: {error}"
            ) from error
    return len(normalized) - base_count


def validate_v2_unsat_manifest(
    manifest: Mapping[str, object],
    problem: EncodedProblem,
    variables: int,
    clauses: Sequence[Sequence[int]],
) -> int:
    """Validate v2 UNSAT data while distrusting all manifest counts/term maps."""

    _v2_manifest(manifest, "unsat")
    return validate_unsat_dimacs(problem, variables, clauses)


def validate_unsat_manifest(
    manifest: Mapping[str, object],
    problem: EncodedProblem,
    variables: int,
    clauses: Sequence[Sequence[int]],
) -> int:
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
]
