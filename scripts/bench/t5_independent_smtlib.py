#!/usr/bin/env python3
"""A separate QF_UF reader for the T5 projection audit.

The candidate analyzer uses ``scripts.cert.independent_qfuf``.  This module does
not import it and does not build its encoded CNF.  It records structural term
keys, semantic equality pairs, and Boolean carrier terms in compact parallel
arrays so the T5 verifier has a genuinely separate parsing representation.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import TypeAlias


BOOL_SORT = 0


class AuditParseError(ValueError):
    """The source is outside the fixed single-query QF_UF audit fragment."""


@dataclass(frozen=True)
class Lexeme:
    text: str
    kind: str


Sexp: TypeAlias = Lexeme | tuple["Sexp", ...]
BoolExpr: TypeAlias = tuple[object, ...]
Value: TypeAlias = tuple[int, int | None, BoolExpr | None]


@dataclass(frozen=True)
class AuditSort:
    name: str
    quoted: bool


@dataclass(frozen=True)
class AuditSignature:
    name: str
    argument_sorts: tuple[int, ...]
    result_sort: int
    quoted: bool
    internal: bool
    macro: bool


@dataclass(frozen=True)
class AuditProblem:
    sorts: tuple[AuditSort, ...]
    signatures: tuple[AuditSignature, ...]
    term_functions: tuple[int, ...]
    term_arguments: tuple[tuple[int, ...], ...]
    term_sorts: tuple[int, ...]
    equality_pairs: tuple[tuple[int, int], ...]
    boolean_carriers: tuple[int, ...]
    true_term: int
    false_term: int

    @property
    def term_count(self) -> int:
        return len(self.term_functions)


def _scan(source: str) -> tuple[Lexeme, ...]:
    tokens: list[Lexeme] = []
    index = 0
    while index < len(source):
        character = source[index]
        if character.isspace():
            index += 1
            continue
        if character == ";":
            index += 1
            while index < len(source) and source[index] not in "\r\n":
                index += 1
            continue
        if character in "()":
            tokens.append(Lexeme(character, character))
            index += 1
            continue
        if character == "|":
            index += 1
            value: list[str] = []
            while index < len(source) and source[index] != "|":
                if source[index] == "\\":
                    index += 1
                    if index == len(source):
                        raise AuditParseError("unterminated quoted-symbol escape")
                value.append(source[index])
                index += 1
            if index == len(source):
                raise AuditParseError("unterminated quoted symbol")
            index += 1
            tokens.append(Lexeme("".join(value), "quoted"))
            continue
        if character == '"':
            index += 1
            value = []
            while index < len(source):
                if source[index] == '"':
                    index += 1
                    if index < len(source) and source[index] == '"':
                        value.append('"')
                        index += 1
                        continue
                    break
                if source[index] == "\x00":
                    raise AuditParseError("NUL in string")
                value.append(source[index])
                index += 1
            else:
                raise AuditParseError("unterminated string")
            tokens.append(Lexeme("".join(value), "string"))
            continue
        start = index
        while index < len(source) and not source[index].isspace() and source[index] not in "();|\"":
            index += 1
        if start == index:
            raise AuditParseError("unsupported token")
        text = source[start:index]
        if text.startswith(":"):
            kind = "keyword"
        elif text.isdecimal():
            kind = "numeral"
        else:
            kind = "symbol"
        tokens.append(Lexeme(text, kind))
    return tuple(tokens)


def _forms(source: str) -> tuple[Sexp, ...]:
    stack: list[list[Sexp]] = []
    output: list[Sexp] = []
    for token in _scan(source):
        if token.kind == "(":
            stack.append([])
        elif token.kind == ")":
            if not stack:
                raise AuditParseError("unexpected closing parenthesis")
            value: Sexp = tuple(stack.pop())
            (stack[-1] if stack else output).append(value)
        else:
            (stack[-1] if stack else output).append(token)
    if stack:
        raise AuditParseError("unclosed parenthesis")
    return tuple(output)


def _symbol(value: Sexp, context: str, *, unquoted: bool = False) -> Lexeme:
    if not isinstance(value, Lexeme) or value.kind not in {"symbol", "quoted"}:
        raise AuditParseError(f"{context} must be a symbol")
    if unquoted and value.kind != "symbol":
        raise AuditParseError(f"{context} must be unquoted")
    return value


def _list(value: Sexp, context: str) -> tuple[Sexp, ...]:
    if not isinstance(value, tuple):
        raise AuditParseError(f"{context} must be a list")
    return value


def _bool(op: str, *children: object) -> BoolExpr:
    return (op, *children)


@dataclass(frozen=True)
class _Macro:
    parameters: tuple[tuple[str, int], ...]
    body: Sexp


class _AuditBuilder:
    def __init__(self) -> None:
        self.sorts = [AuditSort("Bool", False)]
        self.sort_ids = {"Bool": BOOL_SORT}
        self.signatures: list[AuditSignature] = []
        self.signature_ids: dict[str, int] = {}
        self.macros: dict[int, _Macro] = {}
        self.term_functions: list[int] = []
        self.term_arguments: list[tuple[int, ...]] = []
        self.term_sorts: list[int] = []
        self.term_ids: dict[tuple[int, tuple[int, ...]], int] = {}
        self.assertions: list[BoolExpr] = []
        self.boolean_data: set[int] = set()
        self.internal_counter = 0
        self.logic_seen = False
        self.check_seen = False
        self.exit_seen = False
        self.substantive_seen = False
        true_symbol = self._new_signature(
            "@audit_true", (), BOOL_SORT, internal=True, bind=False
        )
        false_symbol = self._new_signature(
            "@audit_false", (), BOOL_SORT, internal=True, bind=False
        )
        self.true_term = self._term(true_symbol, ())
        self.false_term = self._term(false_symbol, ())

    def _new_signature(
        self,
        name: str,
        arguments: tuple[int, ...],
        result: int,
        *,
        quoted: bool = False,
        internal: bool = False,
        macro: bool = False,
        bind: bool = True,
    ) -> int:
        if bind and name in self.signature_ids:
            raise AuditParseError(f"duplicate function {name!r}")
        identifier = len(self.signatures)
        self.signatures.append(
            AuditSignature(name, arguments, result, quoted, internal, macro)
        )
        if bind:
            self.signature_ids[name] = identifier
        return identifier

    def _term(self, function: int, arguments: tuple[int, ...]) -> int:
        signature = self.signatures[function]
        if len(arguments) != len(signature.argument_sorts):
            raise AuditParseError(f"arity mismatch for {signature.name!r}")
        for term, expected in zip(arguments, signature.argument_sorts):
            if not 0 <= term < len(self.term_sorts) or self.term_sorts[term] != expected:
                raise AuditParseError(f"sort mismatch for {signature.name!r}")
        key = (function, arguments)
        previous = self.term_ids.get(key)
        if previous is not None:
            return previous
        identifier = len(self.term_functions)
        self.term_ids[key] = identifier
        self.term_functions.append(function)
        self.term_arguments.append(arguments)
        self.term_sorts.append(signature.result_sort)
        return identifier

    def _fresh(self, kind: str, sort_id: int) -> int:
        name = f"@audit_{kind}_{self.internal_counter}"
        self.internal_counter += 1
        function = self._new_signature(name, (), sort_id, internal=True, bind=False)
        return self._term(function, ())

    def _sort(self, value: Sexp, context: str) -> int:
        name = _symbol(value, context).text
        try:
            return self.sort_ids[name]
        except KeyError as error:
            raise AuditParseError(f"unknown sort {name!r}") from error

    @staticmethod
    def _term_value(sort_id: int, term: int) -> Value:
        return sort_id, term, None

    @staticmethod
    def _boolean_value(expression: BoolExpr) -> Value:
        return BOOL_SORT, None, expression

    def _boolean_expression(self, value: Value, context: str) -> BoolExpr:
        if value[0] != BOOL_SORT or value[2] is None:
            raise AuditParseError(f"{context} requires Bool")
        return value[2]

    def _boolean_term(self, term: int) -> BoolExpr:
        if self.term_sorts[term] != BOOL_SORT:
            raise AuditParseError("Boolean carrier has a non-Boolean sort")
        return _bool("carrier", term)

    def _materialize_boolean(self, expression: BoolExpr) -> int:
        if expression[0] == "constant":
            term = self.true_term if expression[1] is True else self.false_term
        elif expression[0] == "carrier":
            term = int(expression[1])
        else:
            term = self._fresh("boolean_expression", BOOL_SORT)
            self.assertions.append(_bool("iff", self._boolean_term(term), expression))
        self.boolean_data.add(term)
        return term

    def _argument_term(self, value: Value) -> int:
        if value[0] == BOOL_SORT:
            return self._materialize_boolean(self._boolean_expression(value, "argument"))
        if value[1] is None:
            raise AuditParseError("non-Boolean value lacks a term")
        return value[1]

    def _application(
        self,
        head: Lexeme,
        arguments: tuple[Sexp, ...],
        environment: dict[str, Value],
        expansion: tuple[int, ...],
    ) -> Value:
        try:
            function = self.signature_ids[head.text]
        except KeyError as error:
            raise AuditParseError(f"undeclared function {head.text!r}") from error
        signature = self.signatures[function]
        if len(arguments) != len(signature.argument_sorts):
            raise AuditParseError(f"arity mismatch for {head.text!r}")
        values = tuple(self._value(item, environment, expansion) for item in arguments)
        if tuple(value[0] for value in values) != signature.argument_sorts:
            raise AuditParseError(f"sort mismatch for {head.text!r}")
        macro = self.macros.get(function)
        if macro is not None:
            if function in expansion:
                raise AuditParseError(f"recursive macro {head.text!r}")
            # A define-fun body is closed over the global namespace.  The
            # caller environment contains only lexical let/macro bindings and
            # must not cross the macro boundary.
            local = {
                name: value
                for (name, _), value in zip(macro.parameters, values)
            }
            expanded = self._value(macro.body, local, (*expansion, function))
            if expanded[0] != signature.result_sort:
                raise AuditParseError(f"macro result drift for {head.text!r}")
            return expanded
        terms = tuple(self._argument_term(value) for value in values)
        term = self._term(function, terms)
        if signature.result_sort == BOOL_SORT:
            return self._boolean_value(self._boolean_term(term))
        return self._term_value(signature.result_sort, term)

    def _equal(self, values: tuple[Value, ...]) -> BoolExpr:
        if len({value[0] for value in values}) != 1:
            raise AuditParseError("equality crosses sorts")
        if values[0][0] == BOOL_SORT:
            return _bool(
                "iff", *(self._boolean_expression(value, "equality") for value in values)
            )
        first = values[0][1]
        if first is None:
            raise AuditParseError("equality lacks a term")
        pairs = tuple(_bool("equality", first, value[1]) for value in values[1:])
        return pairs[0] if len(pairs) == 1 else _bool("and", *pairs)

    def _distinct(self, values: tuple[Value, ...]) -> BoolExpr:
        if len({value[0] for value in values}) != 1:
            raise AuditParseError("distinct crosses sorts")
        if values[0][0] == BOOL_SORT:
            expressions = tuple(
                self._boolean_expression(value, "distinct") for value in values
            )
            return (
                _bool("not", _bool("iff", *expressions))
                if len(expressions) == 2
                else _bool("constant", False)
            )
        terms = tuple(value[1] for value in values)
        clauses = tuple(
            _bool("not", _bool("equality", terms[left], terms[right]))
            for left in range(len(terms))
            for right in range(left + 1, len(terms))
        )
        return _bool("and", *clauses)

    def _value(
        self,
        expression: Sexp,
        environment: dict[str, Value],
        expansion: tuple[int, ...] = (),
    ) -> Value:
        if isinstance(expression, Lexeme):
            if expression.kind not in {"symbol", "quoted"}:
                raise AuditParseError("unsupported atomic expression")
            if expression.kind == "symbol" and expression.text in {"true", "false"}:
                return self._boolean_value(
                    _bool("constant", expression.text == "true")
                )
            if expression.text in environment:
                return environment[expression.text]
            return self._application(expression, (), environment, expansion)
        if not expression:
            raise AuditParseError("empty expression")
        head = _symbol(expression[0], "expression head")
        syntax = head.text if head.kind == "symbol" else None
        arguments = expression[1:]
        if syntax == "let":
            if len(arguments) != 2:
                raise AuditParseError("let arity")
            bindings = _list(arguments[0], "let bindings")
            parsed: list[tuple[str, Value]] = []
            seen: set[str] = set()
            for binding_value in bindings:
                binding = _list(binding_value, "let binding")
                if len(binding) != 2:
                    raise AuditParseError("let binding arity")
                name = _symbol(binding[0], "let name").text
                if name in seen:
                    raise AuditParseError("duplicate let binding")
                seen.add(name)
                parsed.append((name, self._value(binding[1], environment, expansion)))
            local = dict(environment)
            local.update(parsed)
            return self._value(arguments[1], local, expansion)
        if syntax == "ite":
            if len(arguments) != 3:
                raise AuditParseError("ite arity")
            condition = self._boolean_expression(
                self._value(arguments[0], environment, expansion), "ite condition"
            )
            then_value = self._value(arguments[1], environment, expansion)
            else_value = self._value(arguments[2], environment, expansion)
            if then_value[0] != else_value[0]:
                raise AuditParseError("ite branches cross sorts")
            if then_value[0] == BOOL_SORT:
                return self._boolean_value(
                    _bool(
                        "ite",
                        condition,
                        self._boolean_expression(then_value, "ite branch"),
                        self._boolean_expression(else_value, "ite branch"),
                    )
                )
            if then_value[1] == else_value[1]:
                return then_value
            term = self._fresh("ite", then_value[0])
            self.assertions.append(
                _bool("or", _bool("not", condition), _bool("equality", term, then_value[1]))
            )
            self.assertions.append(
                _bool("or", condition, _bool("equality", term, else_value[1]))
            )
            return self._term_value(then_value[0], term)
        if syntax == "!":
            if len(arguments) < 2:
                raise AuditParseError("annotation arity")
            index = 1
            while index < len(arguments):
                attribute = arguments[index]
                if not isinstance(attribute, Lexeme) or attribute.kind != "keyword":
                    raise AuditParseError("annotation attribute must be a keyword")
                index += 1
                if index < len(arguments) and not (
                    isinstance(arguments[index], Lexeme)
                    and arguments[index].kind == "keyword"
                ):
                    index += 1
            return self._value(arguments[0], environment, expansion)
        if syntax in {"and", "or"}:
            return self._boolean_value(
                _bool(
                    syntax,
                    *(
                        self._boolean_expression(
                            self._value(item, environment, expansion), syntax
                        )
                        for item in arguments
                    ),
                )
            )
        if syntax == "not":
            if len(arguments) != 1:
                raise AuditParseError("not arity")
            return self._boolean_value(
                _bool(
                    "not",
                    self._boolean_expression(
                        self._value(arguments[0], environment, expansion), "not"
                    ),
                )
            )
        if syntax == "=>":
            if len(arguments) < 2:
                raise AuditParseError("implication arity")
            children = [
                self._boolean_expression(
                    self._value(item, environment, expansion), "implication"
                )
                for item in arguments
            ]
            conclusion = children.pop()
            premise = children[0] if len(children) == 1 else _bool("and", *children)
            return self._boolean_value(_bool("or", _bool("not", premise), conclusion))
        if syntax == "xor":
            if len(arguments) < 2:
                raise AuditParseError("xor arity")
            children = [
                self._boolean_expression(self._value(item, environment, expansion), "xor")
                for item in arguments
            ]
            result = children[0]
            for child in children[1:]:
                result = _bool("not", _bool("iff", result, child))
            return self._boolean_value(result)
        if syntax in {"=", "distinct"}:
            if len(arguments) < 2:
                raise AuditParseError(f"{syntax} arity")
            values = tuple(self._value(item, environment, expansion) for item in arguments)
            return self._boolean_value(
                self._equal(values) if syntax == "=" else self._distinct(values)
            )
        if syntax in {"as", "_", "forall", "exists", "match"}:
            raise AuditParseError(f"unsupported expression form {syntax!r}")
        return self._application(head, arguments, environment, expansion)

    def _declare_sort(self, command: tuple[Sexp, ...]) -> None:
        if len(command) != 3:
            raise AuditParseError("declare-sort arity")
        name = _symbol(command[1], "sort name")
        arity = command[2]
        if not isinstance(arity, Lexeme) or arity.kind != "numeral" or arity.text != "0":
            raise AuditParseError("only arity-zero sorts are supported")
        if name.text in self.sort_ids:
            raise AuditParseError("duplicate sort")
        self.sort_ids[name.text] = len(self.sorts)
        self.sorts.append(AuditSort(name.text, name.kind == "quoted"))

    def _declare_function(self, command: tuple[Sexp, ...], constant: bool) -> None:
        if len(command) != (3 if constant else 4):
            raise AuditParseError("function declaration arity")
        name = _symbol(command[1], "function name")
        if constant:
            arguments: tuple[int, ...] = ()
            result_value = command[2]
        else:
            arguments = tuple(
                self._sort(item, "argument sort")
                for item in _list(command[2], "argument sorts")
            )
            result_value = command[3]
        result = self._sort(result_value, "result sort")
        self._new_signature(
            name.text,
            arguments,
            result,
            quoted=name.kind == "quoted",
        )

    def _define_function(self, command: tuple[Sexp, ...]) -> None:
        if len(command) != 5:
            raise AuditParseError("define-fun arity")
        name = _symbol(command[1], "macro name")
        parameter_rows = _list(command[2], "macro parameters")
        parameters: list[tuple[str, int]] = []
        seen: set[str] = set()
        for row_value in parameter_rows:
            row = _list(row_value, "macro parameter")
            if len(row) != 2:
                raise AuditParseError("macro parameter arity")
            parameter_name = _symbol(row[0], "macro parameter name").text
            if parameter_name in seen:
                raise AuditParseError("duplicate macro parameter")
            seen.add(parameter_name)
            parameters.append((parameter_name, self._sort(row[1], "macro parameter sort")))
        result = self._sort(command[3], "macro result")
        validator = copy.deepcopy(self)
        validation_environment = {
            parameter_name: (
                validator._boolean_value(validator._boolean_term(term))
                if sort_id == BOOL_SORT
                else validator._term_value(sort_id, term)
            )
            for parameter_name, sort_id in parameters
            for term in [validator._fresh(f"parameter_{parameter_name}", sort_id)]
        }
        if validator._value(command[4], validation_environment)[0] != result:
            raise AuditParseError("macro body result sort drift")
        function = self._new_signature(
            name.text,
            tuple(sort_id for _, sort_id in parameters),
            result,
            quoted=name.kind == "quoted",
            macro=True,
        )
        self.macros[function] = _Macro(tuple(parameters), command[4])

    def command(self, value: Sexp) -> None:
        command = _list(value, "top-level command")
        if not command:
            raise AuditParseError("empty top-level command")
        head = _symbol(command[0], "command head", unquoted=True).text
        if self.exit_seen or (self.check_seen and head != "exit"):
            raise AuditParseError("command after query termination")
        if head == "set-logic":
            if len(command) != 2 or _symbol(command[1], "logic", unquoted=True).text != "QF_UF":
                raise AuditParseError("only QF_UF is supported")
            if self.logic_seen or self.substantive_seen:
                raise AuditParseError("set-logic order drift")
            self.logic_seen = True
        elif head in {"set-info", "set-option"}:
            if len(command) not in ({2, 3} if head == "set-info" else {3}):
                raise AuditParseError(f"{head} arity")
            if not isinstance(command[1], Lexeme) or command[1].kind != "keyword":
                raise AuditParseError(f"{head} requires a keyword")
        elif head == "declare-sort":
            self.substantive_seen = True
            self._declare_sort(command)
        elif head == "declare-const":
            self.substantive_seen = True
            self._declare_function(command, True)
        elif head == "declare-fun":
            self.substantive_seen = True
            self._declare_function(command, False)
        elif head == "define-fun":
            self.substantive_seen = True
            self._define_function(command)
        elif head == "assert":
            if len(command) != 2:
                raise AuditParseError("assert arity")
            self.substantive_seen = True
            self.assertions.append(
                self._boolean_expression(self._value(command[1], {}), "assert")
            )
        elif head == "check-sat":
            if len(command) != 1:
                raise AuditParseError("check-sat arity")
            self.check_seen = True
        elif head == "exit":
            if len(command) != 1 or not self.check_seen:
                raise AuditParseError("exit order or arity")
            self.exit_seen = True
        else:
            raise AuditParseError(f"unsupported top-level command {head!r}")

    def finish(self) -> AuditProblem:
        if not self.check_seen:
            raise AuditParseError("single query lacks check-sat")
        equalities: set[tuple[int, int]] = set()
        carriers = set(self.boolean_data)

        def visit(expression: BoolExpr) -> None:
            operation = expression[0]
            if operation == "equality":
                left = int(expression[1])
                right = int(expression[2])
                equalities.add((min(left, right), max(left, right)))
            elif operation == "carrier":
                carriers.add(int(expression[1]))
            elif operation != "constant":
                for child in expression[1:]:
                    if not isinstance(child, tuple):
                        raise AuditParseError("malformed Boolean audit expression")
                    visit(child)

        for assertion in self.assertions:
            visit(assertion)
        if any(self.term_sorts[term] != BOOL_SORT for term in carriers):
            raise AuditParseError("Boolean carrier set crosses sorts")
        return AuditProblem(
            tuple(self.sorts),
            tuple(self.signatures),
            tuple(self.term_functions),
            tuple(self.term_arguments),
            tuple(self.term_sorts),
            tuple(sorted(equalities)),
            tuple(sorted(carriers)),
            self.true_term,
            self.false_term,
        )


def parse_qfuf_for_audit(source: str) -> AuditProblem:
    if type(source) is not str:
        raise AuditParseError("SMT-LIB source must be text")
    builder = _AuditBuilder()
    try:
        for form in _forms(source):
            builder.command(form)
        return builder.finish()
    except RecursionError as error:
        raise AuditParseError("SMT-LIB nesting exceeds the audit bound") from error
