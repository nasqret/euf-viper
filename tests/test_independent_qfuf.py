from __future__ import annotations

import copy
import hashlib
import importlib.util
import itertools
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "cert" / "independent_qfuf.py"
SPEC = importlib.util.spec_from_file_location("independent_qfuf", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
QFUF = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = QFUF
SPEC.loader.exec_module(QFUF)


def query(commands: str) -> str:
    return f"(set-logic QF_UF)\n{commands.strip()}\n(check-sat)\n"


V3_GOLDEN_SOURCE = query(
    """
    (declare-sort U 0)
    (declare-fun c0 () U)
    (declare-fun c1 () U)
    (declare-fun f (U) U)
    (declare-fun p (U) Bool)
    (assert (distinct c0 c1))
    (assert (or (= (f c0) c0) (= (f c0) c1)))
    (assert (or (= (f c1) c0) (= (f c1) c1)))
    (assert (= (f c0) (f c1)))
    (assert (or (p c0) (not (p c0)) (p c1) (not (p c1))))
    (assert
      (or
        (and (p (f c0)) (not (p (f c1))))
        (and (not (p (f c0))) (p (f c1)))))
    (assert
      (or
        (= (f (f c0)) (f (f c0)))
        (= (f (f c1)) (f (f c1)))))
    """
)

# Exact output of the 51d0d4d finite-orbit kernel for V3_GOLDEN_SOURCE.
V3_GOLDEN_DIMACS = """\
p cnf 28 80
-1 0
4 -2 0
4 -3 0
-4 2 3 0
4 0
7 -5 0
7 -6 0
-7 5 6 0
7 0
8 0
11 -9 0
11 9 0
11 -10 0
11 10 0
-11 9 -9 10 -10 0
11 0
-14 12 0
-14 -13 0
14 -12 13 0
-15 -12 0
-15 13 0
15 12 -13 0
16 -14 0
16 -15 0
-16 14 15 0
16 0
19 -17 0
19 -18 0
-19 17 18 0
19 0
20 0
21 0
1 -2 -3 0
1 -5 -6 0
1 -22 -23 0
1 -24 -25 0
2 3 0
5 6 0
22 23 0
24 25 0
-8 -2 5 0
-8 2 -5 0
-2 -5 8 0
-8 -3 6 0
-8 3 -6 0
-3 -6 8 0
-13 -6 10 0
-13 -5 9 0
-12 -3 10 0
-12 -2 9 0
-10 -6 13 0
-10 -3 12 0
-9 -5 13 0
-9 -2 12 0
2 -6 0
-26 2 -6 0
-26 -2 6 0
2 6 26 0
-2 -6 26 0
-26 3 -5 0
-27 26 0
-27 3 -5 0
-27 -3 5 0
-26 3 5 27 0
-26 -3 -5 27 0
-27 5 -3 0
-28 27 0
-28 5 -3 0
-28 -5 3 0
-27 5 3 28 0
-27 -5 -3 28 0
-28 6 -2 0
-2 22 0
-3 -2 23 0
-5 -3 22 0
-6 -3 23 0
-5 -2 24 0
-5 -3 25 0
-6 -5 24 0
-6 25 0
"""


def v3_manifest(
    problem: object,
    witness: dict[str, list[int]],
    *,
    reconstruction: object | None = None,
) -> dict[str, object]:
    categories = (
        reconstruction.categories
        if reconstruction is not None
        else {
            category: problem.clauses if category == "base" else ()
            for category in QFUF._V3_CLAUSE_CATEGORIES
        }
    )
    counts = {
        category: len(categories[category])
        for category in QFUF._V3_CLAUSE_CATEGORIES
    }
    counts["total"] = sum(counts.values())
    return {
        "format": QFUF.V3_FORMAT,
        "result": "unsat",
        "encoding": QFUF.V3_ENCODING,
        "source": "input.smt2",
        "source_sha256": "0" * 64,
        "dimacs": "certificate.cnf",
        "dimacs_sha256": "1" * 64,
        "proof": "certificate.drat",
        "proof_sha256": "2" * 64,
        "variables": (
            reconstruction.variables
            if reconstruction is not None
            else problem.variable_count
        ),
        "clauses": counts,
        "finite_orbit": witness,
    }


def clauses_hold(problem: object, assignment: list[int]) -> bool:
    values = [False, *(literal > 0 for literal in assignment)]
    return all(
        any((literal > 0) == values[abs(literal)] for literal in clause)
        for clause in problem.clauses
    )


def atom_function_name(problem: object, atom: object) -> str | None:
    if atom.kind != "bool_term":
        return None
    term = problem.terms[atom.term]
    return problem.functions[term.function].name


def find_base_assignment(
    problem: object,
    fixed: dict[int, bool] | None = None,
    *,
    require_model: bool = False,
) -> list[int] | None:
    fixed = fixed or {}
    for bits in itertools.product((False, True), repeat=problem.variable_count):
        if any(bits[variable - 1] != value for variable, value in fixed.items()):
            continue
        assignment = [
            variable if bits[variable - 1] else -variable
            for variable in range(1, problem.variable_count + 1)
        ]
        if not clauses_hold(problem, assignment):
            continue
        if require_model:
            try:
                QFUF.validate_total_assignment(problem, assignment)
            except QFUF.IndependentQfufError:
                continue
        return assignment
    return None


def bool_variables(problem: object) -> dict[str, int]:
    return {
        name: atom.variable
        for atom in problem.atoms
        if (name := atom_function_name(problem, atom)) is not None
        and not problem.functions[problem.terms[atom.term].function].internal
    }


class LexerAndParserTests(unittest.TestCase):
    def test_comments_quoted_escapes_and_doubled_quote_strings(self) -> None:
        problem = QFUF.parse_and_encode(
            r'''
            ; a comment with () and "ignored text"
            (set-info :source "a string with ""quotes""")
            (set-logic QF_UF)
            (declare-const |true| Bool)
            (declare-fun |not| (Bool) Bool)
            (declare-const |x\|y| Bool)
            (assert (and (|not| |true|) |x\|y|)) ; trailing comment
            (check-sat)
            (exit)
            '''
        )
        declarations = {
            function.name: function
            for function in problem.functions
            if not function.internal
        }
        self.assertEqual(set(declarations), {"true", "not", "x|y"})
        self.assertTrue(all(function.quoted for function in declarations.values()))
        self.assertIsNotNone(find_base_assignment(problem, require_model=True))

    def test_multiline_source_metadata_and_annotations_are_transparent(self) -> None:
        annotated = QFUF.parse_and_encode(
            """
            (set-info :smt-lib-version 2.6)
            (set-logic QF_UF)
            (set-info :source |
            Generated by a corpus producer.
            Vertical-bar metadata spans lines.
            |)
            (declare-sort U 0)
            (declare-const a U)
            (declare-const b U)
            (declare-fun f (U) U)
            (declare-const p Bool)
            (assert (! (= a b) :named same :origin |line one
            line two|))
            (assert (! (distinct (! (f a) :named lhs) (f b)) :named different))
            (assert (! p :named positive))
            (assert (! (not p) :named negative))
            (check-sat)
            """
        )
        plain = QFUF.parse_and_encode(
            query(
                """
                (declare-sort U 0)
                (declare-const a U)
                (declare-const b U)
                (declare-fun f (U) U)
                (declare-const p Bool)
                (assert (= a b))
                (assert (distinct (f a) (f b)))
                (assert p)
                (assert (not p))
                """
            )
        )
        self.assertEqual(annotated.sorts, plain.sorts)
        self.assertEqual(annotated.functions, plain.functions)
        self.assertEqual(annotated.terms, plain.terms)
        self.assertEqual(annotated.atoms, plain.atoms)
        self.assertEqual(annotated.clauses, plain.clauses)

    def test_declare_const_fun_sorts_and_structural_term_identity(self) -> None:
        problem = QFUF.parse_and_encode(
            query(
                """
                (declare-sort U 0)
                (declare-const a U)
                (declare-fun b () U)
                (declare-fun f (U U) U)
                (assert (= (f a b) (f a b)))
                """
            )
        )
        equality = next(atom for atom in problem.atoms if atom.kind == "equality")
        self.assertEqual(equality.left, equality.right)
        self.assertEqual([sort.name for sort in problem.sorts], ["Bool", "U"])

    def test_parameterized_and_zero_arity_define_fun_expansion(self) -> None:
        problem = QFUF.parse_and_encode(
            query(
                """
                (declare-sort U 0)
                (declare-const a U)
                (declare-const b U)
                (declare-const p Bool)
                (define-fun same ((x U) (y U)) Bool (= x y))
                (define-fun choose ((c Bool) (x U) (y U)) U (ite c x y))
                (define-fun yes () Bool true)
                (assert (same (choose p a b) a))
                (assert p)
                (assert yes)
                """
            )
        )
        macros = {function.name for function in problem.functions if function.macro}
        self.assertEqual(macros, {"same", "choose", "yes"})
        self.assertTrue(any(function.name.startswith("@independent_ite_") for function in problem.functions))
        self.assertIsNotNone(find_base_assignment(problem, require_model=True))

    def test_invalid_unused_macro_body_is_rejected(self) -> None:
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "body of `bad`"):
            QFUF.parse_and_encode(
                query(
                    """
                    (declare-sort U 0)
                    (declare-const a U)
                    (define-fun bad () Bool a)
                    """
                )
            )

    def test_malformed_lexing_parsing_commands_arities_and_types_fail_closed(self) -> None:
        malformed = {
            "unterminated quoted symbol": "(set-logic QF_UF) (declare-const |x Bool)",
            "unterminated string": '(set-info :source "x) (check-sat)',
            "unclosed list": "(set-logic QF_UF) (check-sat",
            "wrong logic": "(set-logic QF_LIA) (check-sat)",
            "unsupported command": "(set-logic QF_UF) (push 1) (check-sat)",
            "missing query": "(set-logic QF_UF)",
            "duplicate query": "(set-logic QF_UF) (check-sat) (check-sat)",
            "post-query assertion": "(set-logic QF_UF) (check-sat) (assert true)",
            "sort arity": "(set-logic QF_UF) (declare-sort U 1) (check-sat)",
            "unknown sort": "(set-logic QF_UF) (declare-const a U) (check-sat)",
            "reserved declaration": "(set-logic QF_UF) (declare-const true Bool) (check-sat)",
            "non-Boolean assertion": query("(declare-sort U 0) (declare-const a U) (assert a)"),
            "wrong function arity": query("(declare-fun p (Bool) Bool) (assert (p))"),
            "wrong argument sort": query(
                "(declare-sort U 0) (declare-const a U) "
                "(declare-fun p (Bool) Bool) (assert (p a))"
            ),
            "equality sort mismatch": query(
                "(declare-sort U 0) (declare-const a U) (assert (= a true))"
            ),
            "unary equality": query("(declare-const p Bool) (assert (= p))"),
            "unary distinct": query("(declare-const p Bool) (assert (distinct p))"),
            "bad not": query("(assert (not true false))"),
            "bad ite branches": query(
                "(declare-sort U 0) (declare-const a U) (assert (ite true a false))"
            ),
            "string expression": query('(assert "not a formula")'),
            "recursive macro": query(
                "(declare-sort U 0) (define-fun loop ((x U)) U (loop x))"
            ),
            "annotation without attribute": query("(assert (! true))"),
            "annotation non-keyword": query("(assert (! true named a))"),
            "named annotation without value": query("(assert (! true :named))"),
            "named annotation non-symbol value": query("(assert (! true :named 7))"),
        }
        for label, source in malformed.items():
            with self.subTest(label=label):
                with self.assertRaises(QFUF.IndependentQfufError):
                    QFUF.parse_and_encode(source)


class TseitinEncodingTests(unittest.TestCase):
    def test_exact_and_or_not_encoding_order(self) -> None:
        problem = QFUF.parse_and_encode(
            query(
                """
                (declare-const p Bool)
                (declare-const q Bool)
                (declare-const r Bool)
                (assert (and p (or (not q) r)))
                """
            )
        )
        self.assertEqual(
            problem.clauses,
            (
                (4, 2),
                (4, -3),
                (-4, -2, 3),
                (-5, 1),
                (-5, 4),
                (5, -1, -4),
                (5,),
            ),
        )
        self.assertEqual([atom.kind for atom in problem.atoms], [
            "bool_term", "bool_term", "bool_term", "auxiliary", "auxiliary"
        ])

    def test_iff_and_ite_clause_shapes(self) -> None:
        iff_problem = QFUF.parse_and_encode(
            query(
                """
                (declare-const p Bool)
                (declare-const q Bool)
                (assert (= p q))
                """
            )
        )
        self.assertEqual(
            iff_problem.clauses,
            (
                (-3, -1, 2),
                (-3, 1, -2),
                (3, -1, -2),
                (3, 1, 2),
                (3,),
            ),
        )
        ite_problem = QFUF.parse_and_encode(
            query(
                """
                (declare-const p Bool)
                (declare-const q Bool)
                (declare-const r Bool)
                (assert (ite p q r))
                """
            )
        )
        self.assertEqual(
            ite_problem.clauses,
            (
                (-1, -2, 4),
                (-1, 2, -4),
                (1, -3, 4),
                (1, 3, -4),
                (4,),
            ),
        )

    def test_boolean_operator_truth_tables(self) -> None:
        cases = {
            "(and p (or (not q) r))": lambda p, q, r: p and (not q or r),
            "(= p q)": lambda p, q, _r: p == q,
            "(ite p q r)": lambda p, q, r: q if p else r,
            "(=> p q r)": lambda p, q, r: (not (p and q)) or r,
            "(xor p q r)": lambda p, q, r: p ^ q ^ r,
        }
        for expression, expected in cases.items():
            with self.subTest(expression=expression):
                problem = QFUF.parse_and_encode(
                    query(
                        f"""
                        (declare-const p Bool)
                        (declare-const q Bool)
                        (declare-const r Bool)
                        (assert {expression})
                        """
                    )
                )
                variables = bool_variables(problem)
                for p, q, r in itertools.product((False, True), repeat=3):
                    requested = {"p": p, "q": q, "r": r}
                    fixed = {
                        variable: requested[name]
                        for name, variable in variables.items()
                    }
                    actual = find_base_assignment(problem, fixed) is not None
                    self.assertEqual(actual, expected(p, q, r), (p, q, r))

    def test_empty_connectives_use_shared_literal_constant(self) -> None:
        true_problem = QFUF.parse_and_encode(query("(assert (and))"))
        false_problem = QFUF.parse_and_encode(query("(assert (or))"))
        self.assertEqual(true_problem.clauses, ((1,), (1,)))
        self.assertEqual(false_problem.clauses, ((1,), (-1,)))

    def test_simultaneous_let_rhs_and_nested_shadowing(self) -> None:
        swapped = QFUF.parse_and_encode(
            query(
                """
                (declare-const p Bool)
                (declare-const q Bool)
                (assert (let ((p q) (q p)) (and p (not q))))
                """
            )
        )
        variables = bool_variables(swapped)
        self.assertIsNotNone(
            find_base_assignment(
                swapped, {variables["p"]: False, variables["q"]: True}
            )
        )
        self.assertIsNone(
            find_base_assignment(
                swapped, {variables["p"]: True, variables["q"]: False}
            )
        )

        nested = QFUF.parse_and_encode(
            query(
                """
                (declare-const p Bool)
                (declare-const q Bool)
                (declare-const r Bool)
                (assert (let ((p q)) (let ((p r) (q p)) (= p q))))
                """
            )
        )
        variables = bool_variables(nested)
        self.assertIsNone(
            find_base_assignment(
                nested, {variables["q"]: False, variables["r"]: True}
            )
        )
        self.assertIsNotNone(
            find_base_assignment(
                nested, {variables["q"]: True, variables["r"]: True}
            )
        )

    def test_deep_let_chain_is_independent_of_python_recursion_limit(self) -> None:
        body = "p"
        for _ in range(600):
            body = f"(let ((p p)) {body})"
        deep = QFUF.parse_and_encode(
            query(f"(declare-const p Bool) (assert {body})")
        )
        plain = QFUF.parse_and_encode(query("(declare-const p Bool) (assert p)"))

        self.assertEqual(deep.atoms, plain.atoms)
        self.assertEqual(deep.clauses, plain.clauses)


class ModelAndTheoryTests(unittest.TestCase):
    def test_basic_equality_sat_and_congruence_unsat_assignment(self) -> None:
        sat_problem = QFUF.parse_and_encode(
            query(
                """
                (declare-sort U 0)
                (declare-const a U)
                (declare-const b U)
                (declare-fun f (U) U)
                (assert (= a b))
                (assert (= (f a) (f b)))
                """
            )
        )
        self.assertEqual(QFUF.validate_total_assignment(sat_problem, [1, 2]), (False, True, True))

        unsat_problem = QFUF.parse_and_encode(
            query(
                """
                (declare-sort U 0)
                (declare-const a U)
                (declare-const b U)
                (declare-fun f (U) U)
                (assert (= a b))
                (assert (distinct (f a) (f b)))
                """
            )
        )
        self.assertTrue(clauses_hold(unsat_problem, [1, -2]))
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "disequality"):
            QFUF.validate_total_assignment(unsat_problem, [1, -2])

    def test_distinct_pairwise_and_boolean_cardinality(self) -> None:
        problem = QFUF.parse_and_encode(
            query(
                """
                (declare-sort U 0)
                (declare-const a U)
                (declare-const b U)
                (declare-const c U)
                (assert (distinct a b c))
                """
            )
        )
        self.assertEqual(sum(atom.kind == "equality" for atom in problem.atoms), 3)
        assignment = find_base_assignment(
            problem,
            {
                atom.variable: False
                for atom in problem.atoms
                if atom.kind == "equality"
            },
            require_model=True,
        )
        self.assertIsNotNone(assignment)

        impossible = QFUF.parse_and_encode(
            query(
                """
                (declare-const p Bool)
                (declare-const q Bool)
                (declare-const r Bool)
                (assert (distinct p q r))
                """
            )
        )
        self.assertIsNone(find_base_assignment(impossible))

    def test_bool_valued_function_congruence(self) -> None:
        problem = QFUF.parse_and_encode(
            query(
                """
                (declare-sort U 0)
                (declare-const a U)
                (declare-const b U)
                (declare-fun p (U) Bool)
                (assert (= a b))
                (assert (p a))
                (assert (not (p b)))
                """
            )
        )
        self.assertEqual([atom.kind for atom in problem.atoms], [
            "equality", "bool_term", "bool_term"
        ])
        self.assertTrue(clauses_hold(problem, [1, 2, -3]))
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "true and false"):
            QFUF.validate_total_assignment(problem, [1, 2, -3])

    def test_bool_as_data_is_atomized_before_formula_encoding(self) -> None:
        problem = QFUF.parse_and_encode(
            query(
                """
                (declare-sort U 0)
                (declare-const p Bool)
                (declare-const q Bool)
                (declare-const r Bool)
                (declare-fun f (Bool) U)
                (assert (distinct (f p) (f q) (f r)))
                """
            )
        )
        self.assertEqual([atom.kind for atom in problem.atoms[:3]], [
            "bool_term", "bool_term", "bool_term"
        ])
        names = bool_variables(problem)
        fixed = {names["p"]: True, names["q"]: False, names["r"]: True}
        fixed.update(
            {
                atom.variable: False
                for atom in problem.atoms
                if atom.kind == "equality"
            }
        )
        assignment = find_base_assignment(problem, fixed)
        self.assertIsNotNone(assignment)
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "disequality"):
            QFUF.validate_total_assignment(problem, assignment)

    def test_true_false_terms_remain_distinct(self) -> None:
        problem = QFUF.parse_and_encode(
            query(
                """
                (declare-sort U 0)
                (declare-fun f (Bool) U)
                (assert (= (f true) (f false)))
                """
            )
        )
        self.assertEqual([atom.kind for atom in problem.atoms], [
            "bool_term", "bool_term", "equality"
        ])
        QFUF.validate_total_assignment(problem, [1, -2, 3])
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "true and false"):
            QFUF.validate_total_assignment(problem, [-1, -2, 3])

    def test_term_ite_guard_constraints(self) -> None:
        impossible = QFUF.parse_and_encode(
            query(
                """
                (declare-sort U 0)
                (declare-const a U)
                (declare-const b U)
                (declare-const p Bool)
                (assert (distinct (ite p a b) a))
                (assert p)
                """
            )
        )
        self.assertIsNone(find_base_assignment(impossible))
        self.assertTrue(
            any(function.name.startswith("@independent_ite_") for function in impossible.functions)
        )

        possible = QFUF.parse_and_encode(
            query(
                """
                (declare-sort U 0)
                (declare-const a U)
                (declare-const b U)
                (declare-const p Bool)
                (assert (distinct (ite p a b) a))
                (assert (not p))
                """
            )
        )
        self.assertIsNotNone(find_base_assignment(possible, require_model=True))

    def test_valid_invalid_and_auxiliary_euf_lemmas(self) -> None:
        problem = QFUF.parse_and_encode(
            query(
                """
                (declare-sort U 0)
                (declare-const a U)
                (declare-const b U)
                (declare-fun f (U) U)
                (assert (or (= a b) (= (f a) (f b))))
                """
            )
        )
        equality_variables = [
            atom.variable for atom in problem.atoms if atom.kind == "equality"
        ]
        auxiliary = next(
            atom.variable for atom in problem.atoms if atom.kind == "auxiliary"
        )
        premise, consequence = equality_variables
        QFUF.validate_euf_lemma(problem, [-premise, consequence])
        self.assertTrue(QFUF.euf_lemma_is_valid(problem, [-premise, consequence]))
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "not a valid EUF"):
            QFUF.validate_euf_lemma(problem, [premise])
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "auxiliary"):
            QFUF.validate_euf_lemma(problem, [auxiliary])


class ManifestAndTamperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.problem = QFUF.parse_and_encode(
            query(
                """
                (declare-sort U 0)
                (declare-const a U)
                (declare-const b U)
                (declare-fun f (U) U)
                (assert (or (= a b) (= (f a) (f b))))
                """
            )
        )
        self.equalities = [
            atom.variable for atom in self.problem.atoms if atom.kind == "equality"
        ]

    def test_sat_manifest_requires_complete_ordered_untampered_assignment(self) -> None:
        assignment = find_base_assignment(self.problem, require_model=True)
        self.assertIsNotNone(assignment)
        manifest = {
            "format": QFUF.V2_FORMAT,
            "result": "sat",
            "assignment": assignment,
            "variables": 999,
            "terms": "ignored solver metadata",
        }
        QFUF.validate_v2_sat_manifest(manifest, self.problem)

        with self.assertRaises(QFUF.IndependentQfufError):
            QFUF.validate_total_assignment(self.problem, assignment[:-1])
        reordered = assignment.copy()
        reordered[0], reordered[1] = reordered[1], reordered[0]
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "must assign variable"):
            QFUF.validate_total_assignment(self.problem, reordered)
        tampered = assignment.copy()
        root_variable = self.problem.variable_count
        tampered[root_variable - 1] *= -1
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "base clause"):
            QFUF.validate_total_assignment(self.problem, tampered)

    def test_unsat_helper_uses_local_exact_prefix_and_checks_suffix(self) -> None:
        premise, consequence = self.equalities
        valid_lemma = (-premise, consequence)
        clauses = (*self.problem.clauses, valid_lemma)
        manifest = {
            "format": QFUF.V2_FORMAT,
            "result": "unsat",
            "variables": self.problem.variable_count,
            "terms": [{"tampered": True}],
            "atoms": "untrusted",
            "finite_domain_axioms": 0,
            "clauses": {
                "base": self.problem.base_count,
                "transitivity": 0,
                "congruence": 1,
                "theory_conflicts": 0,
                "total": len(clauses),
            },
        }
        self.assertEqual(
            QFUF.validate_v2_unsat_manifest(
                manifest, self.problem, self.problem.variable_count, clauses
            ),
            1,
        )

        tampered = list(clauses)
        first = list(tampered[0])
        first[0] *= -1
        tampered[0] = tuple(first)
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "base clause 1"):
            QFUF.validate_v2_unsat_manifest(
                manifest, self.problem, self.problem.variable_count, tampered
            )

        invalid_suffix = (*self.problem.clauses, (premise,))
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "theory clause"):
            QFUF.validate_unsat_dimacs(
                self.problem, self.problem.variable_count, invalid_suffix
            )

    def test_unsat_manifest_rejects_count_and_finite_domain_tampering(self) -> None:
        premise, consequence = self.equalities
        clauses = (*self.problem.clauses, (-premise, consequence))
        manifest = {
            "format": QFUF.V2_FORMAT,
            "result": "unsat",
            "variables": self.problem.variable_count,
            "finite_domain_axioms": 0,
            "clauses": {
                "base": self.problem.base_count,
                "transitivity": 0,
                "congruence": 1,
                "theory_conflicts": 0,
                "total": len(clauses),
            },
        }
        QFUF.validate_v2_unsat_manifest(
            manifest, self.problem, self.problem.variable_count, clauses
        )

        mutations = (
            ("Boolean finite-domain count", {**manifest, "finite_domain_axioms": False}),
            ("wrong variable count", {**manifest, "variables": self.problem.variable_count + 1}),
            (
                "missing category",
                {
                    **manifest,
                    "clauses": {
                        key: value
                        for key, value in manifest["clauses"].items()
                        if key != "congruence"
                    },
                },
            ),
            (
                "extra category",
                {**manifest, "clauses": {**manifest["clauses"], "other": 0}},
            ),
            (
                "Boolean category count",
                {**manifest, "clauses": {**manifest["clauses"], "congruence": True}},
            ),
            (
                "wrong base count",
                {
                    **manifest,
                    "clauses": {
                        **manifest["clauses"],
                        "base": self.problem.base_count - 1,
                    },
                },
            ),
            (
                "wrong total count",
                {**manifest, "clauses": {**manifest["clauses"], "total": len(clauses) + 1}},
            ),
            (
                "category sum mismatch",
                {**manifest, "clauses": {**manifest["clauses"], "theory_conflicts": 1}},
            ),
        )
        for label, mutation in mutations:
            with self.subTest(label=label):
                with self.assertRaises(QFUF.IndependentQfufError):
                    QFUF.validate_v2_unsat_manifest(
                        mutation, self.problem, self.problem.variable_count, clauses
                    )

        class AlwaysEqual:
            def __eq__(self, other: object) -> bool:
                return True

        class HostileComparison:
            def __eq__(self, other: object) -> bool:
                raise RuntimeError("hostile comparison executed")

        class StringSubclass(str):
            pass

        for field in ("format", "result"):
            for value in (AlwaysEqual(), HostileComparison()):
                with self.subTest(field=field, value=type(value).__name__):
                    with self.assertRaises(QFUF.IndependentQfufError):
                        QFUF.validate_v2_unsat_manifest(
                            {**manifest, field: value},
                            self.problem,
                            self.problem.variable_count,
                            clauses,
                        )
        subclass_counts = dict(manifest["clauses"])
        base = subclass_counts.pop("base")
        subclass_counts[StringSubclass("base")] = base
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "exact strings"):
            QFUF.validate_v2_unsat_manifest(
                {**manifest, "clauses": subclass_counts},
                self.problem,
                self.problem.variable_count,
                clauses,
            )
        subclass_manifest = dict(manifest)
        manifest_format = subclass_manifest.pop("format")
        subclass_manifest[StringSubclass("format")] = manifest_format
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "exact strings"):
            QFUF.validate_v2_unsat_manifest(
                subclass_manifest,
                self.problem,
                self.problem.variable_count,
                clauses,
            )

    def test_unsat_manifest_rejects_redistributed_seed_categories(self) -> None:
        premise, consequence = self.equalities
        congruence = (-premise, consequence)
        clauses = (*self.problem.clauses, congruence)
        manifest = {
            "format": QFUF.V2_FORMAT,
            "result": "unsat",
            "variables": self.problem.variable_count,
            "finite_domain_axioms": 0,
            "clauses": {
                "base": self.problem.base_count,
                "transitivity": 1,
                "congruence": 0,
                "theory_conflicts": 0,
                "total": len(clauses),
            },
        }
        with self.assertRaisesRegex(
            QFUF.IndependentQfufError, "transitivity count"
        ):
            QFUF.validate_v2_unsat_manifest(
                manifest, self.problem, self.problem.variable_count, clauses
            )

        triangle = QFUF.parse_and_encode(
            query(
                """
                (declare-sort U 0)
                (declare-const a U)
                (declare-const b U)
                (declare-const c U)
                (assert (or (= a b) (= b c) (= a c)))
                """
            )
        )
        pairs = {}
        for atom in triangle.atoms:
            if atom.kind == "equality":
                assert atom.left is not None and atom.right is not None
                pairs[frozenset((atom.left, atom.right))] = atom.variable
        terms = [
            term.id
            for term in triangle.terms
            if triangle.functions[term.function].name in {"a", "b", "c"}
        ]
        a, b, c = terms
        ab = pairs[frozenset((a, b))]
        ac = pairs[frozenset((a, c))]
        bc = pairs[frozenset((b, c))]
        transitivity = tuple(
            sorted(
                (
                    (-ab, -ac, bc),
                    (-ab, -bc, ac),
                    (-ac, -bc, ab),
                )
            )
        )
        triangle_clauses = (*triangle.clauses, *transitivity)
        triangle_manifest = {
            "format": QFUF.V2_FORMAT,
            "result": "unsat",
            "variables": triangle.variable_count,
            "finite_domain_axioms": 0,
            "clauses": {
                "base": triangle.base_count,
                "transitivity": 3,
                "congruence": 0,
                "theory_conflicts": 0,
                "total": len(triangle_clauses),
            },
        }
        QFUF.validate_v2_unsat_manifest(
            triangle_manifest, triangle, triangle.variable_count, triangle_clauses
        )
        reordered = (
            *triangle.clauses,
            transitivity[1],
            transitivity[0],
            *transitivity[2:],
        )
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "prefix differs"):
            QFUF.validate_v2_unsat_manifest(
                triangle_manifest, triangle, triangle.variable_count, reordered
            )
        triangle_manifest["clauses"] = {
            **triangle_manifest["clauses"],
            "transitivity": 0,
            "congruence": 3,
        }
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "transitivity count"):
            QFUF.validate_v2_unsat_manifest(
                triangle_manifest, triangle, triangle.variable_count, triangle_clauses
            )

        congruence_manifest = {
            "format": QFUF.V2_FORMAT,
            "result": "unsat",
            "variables": self.problem.variable_count,
            "finite_domain_axioms": 0,
            "clauses": {
                "base": self.problem.base_count,
                "transitivity": 0,
                "congruence": 0,
                "theory_conflicts": 1,
                "total": len(clauses),
            },
        }
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "congruence count"):
            QFUF.validate_v2_unsat_manifest(
                congruence_manifest,
                self.problem,
                self.problem.variable_count,
                clauses,
            )
        triangle_manifest["clauses"] = {
            **triangle_manifest["clauses"],
            "congruence": 0,
            "theory_conflicts": 3,
        }
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "transitivity count"):
            QFUF.validate_v2_unsat_manifest(
                triangle_manifest, triangle, triangle.variable_count, triangle_clauses
            )

    def test_static_prefix_regeneration_falls_back_before_dense_materialization(
        self,
    ) -> None:
        size = 82
        declarations = "\n".join(
            f"(declare-const c{index} U)" for index in range(size)
        )
        equalities = " ".join(
            f"(= c{left} c{right})"
            for left in range(size)
            for right in range(left + 1, size)
        )
        problem = QFUF._validate_problem(
            QFUF.parse_and_encode(
                query(
                    f"""
                    (declare-sort U 0)
                    {declarations}
                    (assert (and {equalities}))
                    """
                )
            )
        )
        self.assertEqual(QFUF._reconstruct_certificate_static_prefix(problem), ((), ()))

    def test_candidate_product_cap_skips_high_arity_without_global_fallback(
        self,
    ) -> None:
        declarations = "\n".join(
            f"(declare-const {name}{index} U)"
            for name in ("a", "b")
            for index in range(64)
        )
        signature = " ".join("U" for _ in range(64))
        equalities = "\n".join(
            f"(assert (= a{index} b{index}))" for index in range(64)
        )
        left = " ".join(f"a{index}" for index in range(64))
        right = " ".join(f"b{index}" for index in range(64))
        problem = QFUF._validate_problem(
            QFUF.parse_and_encode(
                query(
                    f"""
                    (declare-sort U 0)
                    {declarations}
                    (declare-fun f (U) U)
                    (declare-fun h ({signature}) U)
                    {equalities}
                    (assert (= (f a0) (f b0)))
                    (assert (= (h {left}) (h {right})))
                    """
                )
            )
        )
        transitivity, congruence = QFUF._reconstruct_certificate_static_prefix(problem)
        self.assertEqual(transitivity, ())
        self.assertEqual(len(congruence), 1)

    def test_aggregate_candidate_visit_cap_discards_the_whole_static_prefix(
        self,
    ) -> None:
        declarations = "\n".join(
            f"(declare-const {name}{index} U)"
            for name in ("a", "b")
            for index in range(12)
        )
        equalities = "\n".join(
            f"(assert (= a{index} b{index}))" for index in range(12)
        )
        signature = " ".join("U" for _ in range(12))
        arguments = " ".join(f"a{index}" for index in range(12))
        functions = "\n".join(
            f"(declare-fun f{index} ({signature}) U)" for index in range(1_025)
        )
        applications = "\n".join(
            f"(assert (= (f{index} {arguments}) (f{index} {arguments})))"
            for index in range(1_025)
        )
        problem = QFUF._validate_problem(
            QFUF.parse_and_encode(
                query(
                    f"""
                    (declare-sort U 0)
                    {declarations}
                    {functions}
                    {equalities}
                    {applications}
                    """
                )
            )
        )
        self.assertEqual(QFUF._reconstruct_certificate_static_prefix(problem), ((), ()))

    def test_unsat_manifest_accepts_boolean_predicate_congruence_seeds(self) -> None:
        problem = QFUF.parse_and_encode(
            query(
                """
                (declare-sort U 0)
                (declare-const a U)
                (declare-const b U)
                (declare-fun p (U) Bool)
                (assert (or (= a b) (p a) (p b)))
                """
            )
        )
        equality = next(
            atom.variable for atom in problem.atoms if atom.kind == "equality"
        )
        predicates = {}
        for atom in problem.atoms:
            if atom.kind != "bool_term":
                continue
            assert atom.term is not None
            term = problem.terms[atom.term]
            if not term.args:
                continue
            argument = problem.terms[term.args[0]]
            predicates[problem.functions[argument.function].name] = atom.variable
        forward = (-equality, -predicates["a"], predicates["b"])
        backward = (-equality, predicates["a"], -predicates["b"])
        congruence = sorted((tuple(sorted(forward)), tuple(sorted(backward))))
        clauses = (*problem.clauses, *congruence)
        manifest = {
            "format": QFUF.V2_FORMAT,
            "result": "unsat",
            "variables": problem.variable_count,
            "finite_domain_axioms": 0,
            "clauses": {
                "base": problem.base_count,
                "transitivity": 0,
                "congruence": 2,
                "theory_conflicts": 0,
                "total": len(clauses),
            },
        }
        self.assertEqual(
            QFUF.validate_v2_unsat_manifest(
                manifest, problem, problem.variable_count, clauses
            ),
            2,
        )

    def test_unsat_helper_validates_the_problem_once_for_all_theory_lemmas(self) -> None:
        premise, consequence = self.equalities
        valid_lemma = (-premise, consequence)
        clauses = (*self.problem.clauses, valid_lemma, valid_lemma, valid_lemma)

        with mock.patch.object(
            QFUF, "_validate_problem", wraps=QFUF._validate_problem
        ) as validate_problem:
            self.assertEqual(
                QFUF.validate_unsat_dimacs(
                    self.problem, self.problem.variable_count, clauses
                ),
                3,
            )

        self.assertEqual(validate_problem.call_count, 1)

    def test_unsat_helper_uses_a_detached_problem_snapshot(self) -> None:
        premise, consequence = self.equalities
        problem = QFUF.EncodedProblem(
            self.problem.sorts,
            self.problem.functions,
            self.problem.terms,
            self.problem.atoms,
            self.problem.clauses,
            self.problem.true_term,
            self.problem.false_term,
            self.problem.assertions,
            self.problem.bool_data_terms,
        )
        mutated = False

        class MutatingClauses(list[tuple[int, ...]]):
            def __iter__(inner_self):
                nonlocal mutated
                mutated = True
                object.__setattr__(problem, "atoms", tuple(reversed(problem.atoms)))
                return super().__iter__()

        clauses = MutatingClauses((*problem.clauses, (-premise, consequence)))
        self.assertEqual(
            QFUF.validate_unsat_dimacs(problem, problem.variable_count, clauses),
            1,
        )
        self.assertTrue(mutated)

    def test_problem_rejects_mutable_nested_containers(self) -> None:
        fields = {
            name: getattr(self.problem, name)
            for name in self.problem.__dataclass_fields__
        }
        fields["atoms"] = list(self.problem.atoms)
        mutable_atoms = QFUF.EncodedProblem(**fields)
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "atoms.*immutable"):
            QFUF.validate_euf_lemma(mutable_atoms, self.equalities)

        fields["atoms"] = self.problem.atoms
        first_term = self.problem.terms[0]
        fields["terms"] = (
            QFUF.Term(
                first_term.id,
                first_term.function,
                list(first_term.args),
                first_term.sort,
            ),
            *self.problem.terms[1:],
        )
        mutable_term = QFUF.EncodedProblem(**fields)
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "term table"):
            QFUF.validate_euf_lemma(mutable_term, self.equalities)

        fields["terms"] = self.problem.terms
        fields["clauses"] = (list(self.problem.clauses[0]), *self.problem.clauses[1:])
        mutable_clause = QFUF.EncodedProblem(**fields)
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "base clauses"):
            QFUF.validate_euf_lemma(mutable_clause, self.equalities)

    def test_assertion_snapshot_is_detached_cycle_safe_and_shape_checked(self) -> None:
        fields = {
            name: getattr(self.problem, name)
            for name in self.problem.__dataclass_fields__
        }
        leaf = QFUF.BoolExpr("const", (True,))
        root = leaf
        for _ in range(28):
            root = QFUF.BoolExpr("and", (root, root))
        fields["assertions"] = (root,)
        shared_dag = QFUF.EncodedProblem(**fields)
        snapshot = QFUF._validate_problem(shared_dag)
        self.assertIsNot(snapshot.assertions, shared_dag.assertions)
        self.assertIsNot(snapshot.assertions[0], root)
        self.assertIs(
            snapshot.assertions[0].arguments[0],
            snapshot.assertions[0].arguments[1],
        )
        object.__setattr__(root, "op", "or")
        self.assertEqual(snapshot.assertions[0].op, "and")

        cycle = QFUF.BoolExpr("not", ())
        object.__setattr__(cycle, "arguments", (cycle,))
        fields["assertions"] = (cycle,)
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "cycle"):
            QFUF.validate_euf_lemma(
                QFUF.EncodedProblem(**fields), self.equalities
            )

        malformed = (
            QFUF.BoolExpr("unknown", ()),
            QFUF.BoolExpr("not", ()),
            QFUF.BoolExpr("const", (True, False)),
            QFUF.BoolExpr("atom", (True,)),
            QFUF.BoolExpr("atom", (QFUF._AtomKey("unknown"),)),
            QFUF.BoolExpr("and", (True,)),
            QFUF.BoolExpr("iff", ()),
            QFUF.BoolExpr("iff", (QFUF.BoolExpr("const", (True,)),)),
        )
        for assertion in malformed:
            with self.subTest(assertion=assertion):
                fields["assertions"] = (assertion,)
                with self.assertRaises(QFUF.IndependentQfufError):
                    QFUF.validate_euf_lemma(
                        QFUF.EncodedProblem(**fields), self.equalities
                    )

    def test_public_validators_reject_integer_subclasses(self) -> None:
        premise, consequence = self.equalities

        class ExecutableInt(int):
            def __abs__(self) -> int:
                return premise

        literal = ExecutableInt(-999)
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "non-integer literal"):
            QFUF.validate_euf_lemma(self.problem, (literal, consequence))
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "non-integer literal"):
            QFUF.validate_unsat_dimacs(
                self.problem,
                self.problem.variable_count,
                (*self.problem.clauses, (literal, consequence)),
            )

        assignment = find_base_assignment(self.problem, require_model=True)
        self.assertIsNotNone(assignment)
        assignment[0] = ExecutableInt(999)
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "exact integer"):
            QFUF.validate_total_assignment(self.problem, assignment)

        class HostileFormatInt(int):
            def __format__(self, format_spec: str) -> str:
                raise RuntimeError("hostile __format__ executed")

        hostile = HostileFormatInt(premise)
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "non-integer literal"):
            QFUF.validate_euf_lemma(self.problem, (hostile, consequence))
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "non-integer literal"):
            QFUF.validate_unsat_dimacs(
                self.problem,
                self.problem.variable_count,
                (*self.problem.clauses, (hostile, consequence)),
            )
        assignment = find_base_assignment(self.problem, require_model=True)
        self.assertIsNotNone(assignment)
        assignment[0] = hostile
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "exact integer"):
            QFUF.validate_total_assignment(self.problem, assignment)

    def test_atom_shapes_reject_metadata_for_the_wrong_kind(self) -> None:
        fields = {
            name: getattr(self.problem, name)
            for name in self.problem.__dataclass_fields__
        }
        equality_index = next(
            index
            for index, atom in enumerate(self.problem.atoms)
            if atom.kind == "equality"
        )
        equality = self.problem.atoms[equality_index]
        atoms = list(self.problem.atoms)
        atoms[equality_index] = QFUF.Atom(
            equality.variable,
            equality.kind,
            equality.left,
            equality.right,
            self.problem.true_term,
        )
        fields["atoms"] = tuple(atoms)
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "BoolTerm metadata"):
            QFUF.validate_euf_lemma(
                QFUF.EncodedProblem(**fields), self.equalities
            )

        bool_problem = QFUF.parse_and_encode(
            query("(declare-const p Bool)\n(assert p)")
        )
        bool_fields = {
            name: getattr(bool_problem, name)
            for name in bool_problem.__dataclass_fields__
        }
        bool_index = next(
            index
            for index, atom in enumerate(bool_problem.atoms)
            if atom.kind == "bool_term"
        )
        bool_atom = bool_problem.atoms[bool_index]
        bool_atoms = list(bool_problem.atoms)
        bool_atoms[bool_index] = QFUF.Atom(
            bool_atom.variable,
            bool_atom.kind,
            bool_problem.true_term,
            None,
            bool_atom.term,
        )
        bool_fields["atoms"] = tuple(bool_atoms)
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "equality metadata"):
            QFUF.validate_total_assignment(
                QFUF.EncodedProblem(**bool_fields),
                find_base_assignment(bool_problem),
            )

    def test_equality_conflict_skips_unneeded_congruence_closure(self) -> None:
        triangle = QFUF.parse_and_encode(
            query(
                """
                (declare-sort U 0)
                (declare-const a U)
                (declare-const b U)
                (declare-const c U)
                (assert (or (= a b) (= b c) (= a c)))
                """
            )
        )
        equalities = {}
        for atom in triangle.atoms:
            if atom.kind != "equality":
                continue
            names = frozenset(
                triangle.functions[triangle.terms[term].function].name
                for term in (atom.left, atom.right)
            )
            equalities[names] = atom.variable
        lemma = (
            -equalities[frozenset(("a", "b"))],
            -equalities[frozenset(("b", "c"))],
            equalities[frozenset(("a", "c"))],
        )
        with mock.patch.object(
            QFUF,
            "_close_congruence",
            side_effect=AssertionError("closure should be skipped"),
        ) as close_congruence:
            QFUF.validate_euf_lemma(triangle, lemma)
        close_congruence.assert_not_called()

        premise, consequence = self.equalities
        with mock.patch.object(
            QFUF, "_close_congruence", wraps=QFUF._close_congruence
        ) as close_congruence:
            QFUF.validate_euf_lemma(self.problem, (-premise, consequence))
        self.assertEqual(close_congruence.call_count, 1)

    def test_dimacs_parser_is_strict_and_supports_split_clauses(self) -> None:
        variables, clauses = QFUF.parse_dimacs(
            "c comment\np cnf 3 2\n1 -2\n3 0\n0\n"
        )
        self.assertEqual(variables, 3)
        self.assertEqual(clauses, ((1, -2, 3), ()))
        for malformed in (
            "1 0\np cnf 1 1\n",
            "p cnf 1 2\n1 0\n",
            "p cnf 1 1\n2 0\n",
            "p cnf 1 1\n1\n",
        ):
            with self.subTest(source=malformed):
                with self.assertRaises(QFUF.IndependentQfufError):
                    QFUF.parse_dimacs(malformed)

    def test_reconstruction_matches_checked_in_rust_base_prefixes(self) -> None:
        golden_path = ROOT / "tests" / "fixtures" / "cert-v2" / "base_prefixes.json"
        golden = json.loads(golden_path.read_text(encoding="utf-8"))
        self.assertEqual(golden["schema_version"], 1)
        self.assertEqual(golden["format"], QFUF.V2_FORMAT)
        self.assertRegex(golden["producer_revision"], r"^[0-9a-f]{40}$")
        for name, case in sorted(golden["cases"].items()):
            with self.subTest(name=name):
                source_path = ROOT / case["source"]
                source_bytes = source_path.read_bytes()
                self.assertEqual(
                    hashlib.sha256(source_bytes).hexdigest(), case["source_sha256"]
                )
                source = source_bytes.decode("utf-8")
                reconstructed = QFUF.parse_and_encode(source)
                expected_clauses = tuple(
                    tuple(clause) for clause in case["base_clauses"]
                )
                self.assertEqual(reconstructed.variable_count, case["variables"])
                self.assertEqual(reconstructed.base_count, len(expected_clauses))
                self.assertEqual(reconstructed.clauses, expected_clauses)


class V3FiniteOrbitCertificateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.problem = QFUF.parse_and_encode(V3_GOLDEN_SOURCE)
        self.variables, self.clauses = QFUF.parse_dimacs(V3_GOLDEN_DIMACS)
        self.witness = {
            "domain_terms": [2, 3],
            "membership_terms": [2, 3, 4, 5, 10, 11],
            "lex_terms": [4, 5],
        }
        self.reconstruction = QFUF._reconstruct_v3_orbit_kernel(
            QFUF._validate_problem(self.problem), self.witness
        )
        self.manifest = v3_manifest(
            self.problem, self.witness, reconstruction=self.reconstruction
        )

    def _source_manifest(
        self, source: str, witness: dict[str, list[int]]
    ) -> tuple[object, dict[str, object]]:
        problem = QFUF.parse_and_encode(source)
        return problem, v3_manifest(problem, witness)

    def test_exact_51d_stream_with_all_kernel_categories_is_accepted(self) -> None:
        regenerated = tuple(
            clause
            for category in QFUF._V3_CLAUSE_CATEGORIES
            for clause in self.reconstruction.categories[category]
        )
        self.assertEqual(self.variables, 28)
        self.assertEqual(self.problem.base_count, 30)
        self.assertEqual(regenerated, self.clauses)
        self.assertNotIn((), self.clauses)
        self.assertEqual(
            self.manifest["clauses"],
            {
                "base": 30,
                "guarded_rows": 6,
                "finite_coverage": 4,
                "equality_channels": 6,
                "predicate_channels": 8,
                "orbit_lex": 18,
                "guarded_channels": 8,
                "total": 80,
            },
        )
        self.assertEqual(
            QFUF.validate_v3_unsat_manifest(
                self.manifest, self.problem, self.variables, self.clauses
            ),
            50,
        )

    def test_v3_shape_rejects_unknown_keys_and_type_edges(self) -> None:
        mutations: list[tuple[str, dict[str, object]]] = []

        extra_root = copy.deepcopy(self.manifest)
        extra_root["terms"] = []
        mutations.append(("unknown top-level key", extra_root))

        extra_count = copy.deepcopy(self.manifest)
        extra_count["clauses"]["theory_conflicts"] = 0
        mutations.append(("unknown clause key", extra_count))

        extra_witness = copy.deepcopy(self.manifest)
        extra_witness["finite_orbit"]["swap_maps"] = []
        mutations.append(("unknown witness key", extra_witness))

        for label, field, value in (
            ("SAT result", "result", "sat"),
            ("wrong encoding", "encoding", "canonical-tseitin-v1"),
            ("Boolean variables", "variables", True),
            ("empty source", "source", ""),
            ("uppercase hash", "source_sha256", "A" * 64),
        ):
            mutation = copy.deepcopy(self.manifest)
            mutation[field] = value
            mutations.append((label, mutation))

        float_count = copy.deepcopy(self.manifest)
        float_count["clauses"]["guarded_rows"] = 6.0
        mutations.append(("floating count", float_count))

        tuple_witness = copy.deepcopy(self.manifest)
        tuple_witness["finite_orbit"]["domain_terms"] = (2, 3)
        mutations.append(("tuple witness", tuple_witness))

        boolean_witness = copy.deepcopy(self.manifest)
        boolean_witness["finite_orbit"]["domain_terms"] = [2, True]
        mutations.append(("Boolean witness ID", boolean_witness))

        for label, mutation in mutations:
            with self.subTest(label=label):
                with self.assertRaises(QFUF.IndependentQfufError):
                    QFUF.validate_v3_manifest_shape(mutation)

    def test_v3_witness_order_and_finite_closure_are_exact(self) -> None:
        mutations = []
        reversed_domain = copy.deepcopy(self.manifest)
        reversed_domain["finite_orbit"]["domain_terms"] = [3, 2]
        mutations.append(("domain order", reversed_domain, "strictly increasing"))

        reordered_membership = copy.deepcopy(self.manifest)
        reordered_membership["finite_orbit"]["membership_terms"][:2] = [3, 2]
        mutations.append(
            ("membership order", reordered_membership, "finite closure")
        )

        missing_membership = copy.deepcopy(self.manifest)
        missing_membership["finite_orbit"]["membership_terms"].pop()
        mutations.append(
            ("membership omission", missing_membership, "finite closure")
        )

        reversed_lex = copy.deepcopy(self.manifest)
        reversed_lex["finite_orbit"]["lex_terms"] = [5, 4]
        mutations.append(("lex order", reversed_lex, "Rust-order"))

        for label, mutation, diagnostic in mutations:
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    QFUF.IndependentQfufError, diagnostic
                ):
                    QFUF.validate_v3_unsat_manifest(
                        mutation, self.problem, self.variables, self.clauses
                    )

    def test_domain_requires_a_same_sort_nullary_mandatory_clique(self) -> None:
        source = query(
            """
            (declare-sort U 0)
            (declare-fun c0 () U)
            (declare-fun c1 () U)
            (declare-fun c2 () U)
            (assert (distinct c0 c1))
            (assert (= c2 c2))
            (assert false)
            """
        )
        problem, manifest = self._source_manifest(
            source,
            {
                "domain_terms": [2, 4],
                "membership_terms": [],
                "lex_terms": [],
            },
        )
        with self.assertRaisesRegex(
            QFUF.IndependentQfufError, "mandatory top-level disequality clique"
        ):
            QFUF.validate_v3_unsat_manifest(
                manifest,
                problem,
                problem.variable_count,
                problem.clauses,
            )

    def test_missing_mandatory_coverage_changes_exact_closure(self) -> None:
        removed = "    (assert (or (= (f c1) c0) (= (f c1) c1)))\n"
        self.assertIn(removed, V3_GOLDEN_SOURCE)
        source = V3_GOLDEN_SOURCE.replace(removed, "", 1)
        problem, manifest = self._source_manifest(source, self.witness)
        with self.assertRaisesRegex(
            QFUF.IndependentQfufError, "finite closure"
        ):
            QFUF.validate_v3_unsat_manifest(
                manifest,
                problem,
                problem.variable_count,
                problem.clauses,
            )

    def test_adjacent_swap_must_preserve_the_assertion_multiset(self) -> None:
        source = V3_GOLDEN_SOURCE.replace(
            "(check-sat)", "(assert (p c0))\n(check-sat)", 1
        )
        problem, manifest = self._source_manifest(source, self.witness)
        with self.assertRaisesRegex(
            QFUF.IndependentQfufError, "assertion-multiset automorphism"
        ):
            QFUF.validate_v3_unsat_manifest(
                manifest,
                problem,
                problem.variable_count,
                problem.clauses,
            )

    def test_every_category_count_and_clause_boundary_is_exact(self) -> None:
        redistributed = copy.deepcopy(self.manifest)
        redistributed["clauses"]["equality_channels"] += 1
        redistributed["clauses"]["predicate_channels"] -= 1
        with self.assertRaisesRegex(
            QFUF.IndependentQfufError, "equality_channels count"
        ):
            QFUF.validate_v3_unsat_manifest(
                redistributed, self.problem, self.variables, self.clauses
            )

        offset = 0
        for category in QFUF._V3_CLAUSE_CATEGORIES:
            count = self.manifest["clauses"][category]
            self.assertGreater(count, 0)
            tampered = list(self.clauses)
            clause = list(tampered[offset])
            clause[0] = -clause[0]
            tampered[offset] = tuple(clause)
            with self.subTest(category=category):
                with self.assertRaisesRegex(
                    QFUF.IndependentQfufError, f"DIMACS {category} boundary"
                ):
                    QFUF.validate_v3_unsat_manifest(
                        self.manifest, self.problem, self.variables, tampered
                    )
            offset += count

    def test_auxiliary_allocation_and_final_variable_count_are_exact(self) -> None:
        lex_start = sum(
            self.manifest["clauses"][category]
            for category in QFUF._V3_CLAUSE_CATEGORIES
            if category
            in {
                "base",
                "guarded_rows",
                "finite_coverage",
                "equality_channels",
                "predicate_channels",
            }
        )
        tampered = list(self.clauses)
        helper_clause = list(tampered[lex_start + 1])
        self.assertIn(-26, helper_clause)
        helper_clause[helper_clause.index(-26)] = -27
        tampered[lex_start + 1] = tuple(helper_clause)
        with self.assertRaisesRegex(
            QFUF.IndependentQfufError, "orbit_lex boundary"
        ):
            QFUF.validate_v3_unsat_manifest(
                self.manifest, self.problem, self.variables, tampered
            )

        variable_manifest = copy.deepcopy(self.manifest)
        variable_manifest["variables"] = self.variables + 1
        with self.assertRaisesRegex(
            QFUF.IndependentQfufError, "deterministic atom allocation"
        ):
            QFUF.validate_v3_unsat_manifest(
                variable_manifest,
                self.problem,
                self.variables + 1,
                self.clauses,
            )

    def test_v3_hard_caps_reject_before_unbounded_materialization(self) -> None:
        cap_cases = (
            ("_ORBIT_MAX_MEMBERSHIP_CELLS", 11, "membership cell cap"),
            (
                "_ORBIT_MAX_EFFECTIVE_LEX_COORDINATES",
                3,
                "lex coordinate cap",
            ),
            ("_ORBIT_MAX_GUARDED_CLAUSES", 5, "guarded_rows budget"),
            ("_ORBIT_MAX_GUARDED_LITERALS", 5, "guarded_rows budget"),
            (
                "_ORBIT_MAX_TUPLES_PER_APPLICATION",
                1,
                "predicate per-application tuple cap",
            ),
        )
        for constant, limit, diagnostic in cap_cases:
            with self.subTest(constant=constant):
                with mock.patch.object(QFUF, constant, limit):
                    with self.assertRaisesRegex(
                        QFUF.IndependentQfufError, diagnostic
                    ):
                        QFUF.validate_v3_unsat_manifest(
                            self.manifest,
                            self.problem,
                            self.variables,
                            self.clauses,
                        )

        oversized_domain = copy.deepcopy(self.manifest)
        oversized_domain["finite_orbit"]["domain_terms"] = list(range(33))
        with self.assertRaisesRegex(QFUF.IndependentQfufError, "2..=32"):
            QFUF.validate_v3_unsat_manifest(
                oversized_domain, self.problem, self.variables, self.clauses
            )

    def test_residual_function_tuple_cap_is_an_exact_skip(self) -> None:
        source = query(
            """
            (declare-sort U 0)
            (declare-fun c0 () U)
            (declare-fun c1 () U)
            (declare-fun f (U) U)
            (assert (distinct c0 c1))
            (assert (or (= (f c0) c0) (= (f c0) c1)))
            (assert (or (= (f c1) c0) (= (f c1) c1)))
            (assert
              (or
                (= (f (f c0)) (f (f c0)))
                (= (f (f c1)) (f (f c1)))))
            (assert false)
            """
        )
        problem = QFUF._validate_problem(QFUF.parse_and_encode(source))
        domain = (2, 3)
        domain_set = frozenset(domain)
        covered = QFUF._mandatory_coverages(problem.assertions, domain_set)
        closed = QFUF._closed_table_functions(problem, domain, covered)
        finite = QFUF._finite_closure(problem, domain, covered, closed)
        witness = {
            "domain_terms": list(domain),
            "membership_terms": sorted(finite),
            "lex_terms": sorted(
                covered, key=lambda term: (bool(problem.terms[term].args), term)
            ),
        }
        complete = QFUF._reconstruct_v3_orbit_kernel(problem, witness)
        self.assertGreater(len(complete.categories["guarded_channels"]), 0)
        with mock.patch.object(QFUF, "_ORBIT_MAX_TUPLES_PER_APPLICATION", 1):
            skipped = QFUF._reconstruct_v3_orbit_kernel(problem, witness)
        self.assertEqual(skipped.categories["guarded_channels"], ())

    def test_predicate_incompleteness_conditions_reject_exactly(self) -> None:
        missing_canonical = query(
            """
            (declare-sort U 0)
            (declare-fun c0 () U)
            (declare-fun c1 () U)
            (declare-fun f (U) U)
            (declare-fun p (U) Bool)
            (assert (distinct c0 c1))
            (assert (or (= (f c0) c0) (= (f c0) c1)))
            (assert (or (= (f c1) c0) (= (f c1) c1)))
            (assert (or (p (f c0)) (p (f c1))))
            (assert false)
            """
        )
        problem, manifest = self._source_manifest(
            missing_canonical,
            {
                "domain_terms": [2, 3],
                "membership_terms": [2, 3, 4, 5],
                "lex_terms": [4, 5],
            },
        )
        with self.assertRaisesRegex(
            QFUF.IndependentQfufError, "canonical table application is missing"
        ):
            QFUF.validate_v3_unsat_manifest(
                manifest, problem, problem.variable_count, problem.clauses
            )

        outside_closure = query(
            """
            (declare-sort U 0)
            (declare-fun c0 () U)
            (declare-fun c1 () U)
            (declare-fun x () U)
            (declare-fun f (U) U)
            (declare-fun p (U) Bool)
            (assert (distinct c0 c1))
            (assert (or (= (f c0) c0) (= (f c0) c1)))
            (assert (or (= (f c1) c0) (= (f c1) c1)))
            (assert (or (p x) (not (p x))))
            (assert false)
            """
        )
        problem, manifest = self._source_manifest(
            outside_closure,
            {
                "domain_terms": [2, 3],
                "membership_terms": [2, 3, 4, 5],
                "lex_terms": [4, 5],
            },
        )
        with self.assertRaisesRegex(
            QFUF.IndependentQfufError, "predicate arguments are outside finite closure"
        ):
            QFUF.validate_v3_unsat_manifest(
                manifest, problem, problem.variable_count, problem.clauses
            )


if __name__ == "__main__":
    unittest.main()
