#![forbid(unsafe_code)]

//! Deterministic definitional CNF for the semantic Boolean shell.
//!
//! Source atom identifiers are retained verbatim. Fresh definition atoms are
//! assigned in deterministic postorder immediately after the registered source
//! atoms. Clauses and their literals are canonicalized, so repeated clauses and
//! tautologies never consume the caller's resource caps.

use super::native_clause::{AtomId, Lit};
use super::semantic::{RootLiteral, SemanticExpr, SemanticProblem};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

/// Number of distinct atom identifiers representable by [`AtomId`].
pub(crate) const MAX_NATIVE_ATOMS: u64 = u32::MAX as u64 + 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeFormula {
    pub(crate) atom_count: usize,
    pub(crate) clauses: Box<[Box<[Lit]>]>,
    pub(crate) source_atom_count: usize,
    pub(crate) auxiliary_atom_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LoweringCaps {
    pub(crate) max_atoms: usize,
    pub(crate) max_clauses: usize,
    pub(crate) max_literals: usize,
}

impl LoweringCaps {
    pub(crate) const fn new(max_atoms: usize, max_clauses: usize, max_literals: usize) -> Self {
        Self {
            max_atoms,
            max_clauses,
            max_literals,
        }
    }

    pub(crate) const fn unlimited() -> Self {
        Self::new(usize::MAX, usize::MAX, usize::MAX)
    }
}

impl Default for LoweringCaps {
    fn default() -> Self {
        Self::unlimited()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LoweringError {
    AtomIdSpaceExhausted {
        requested: usize,
        maximum: u64,
    },
    SourceAtomOutOfRange {
        atom: AtomId,
        source_atom_count: usize,
    },
    AtomCapExceeded {
        requested: usize,
        cap: usize,
    },
    ClauseCapExceeded {
        requested: usize,
        cap: usize,
    },
    LiteralCapExceeded {
        requested: usize,
        cap: usize,
    },
    CountOverflow {
        resource: &'static str,
    },
}

impl fmt::Display for LoweringError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtomIdSpaceExhausted { requested, maximum } => write!(
                output,
                "native CNF needs {requested} atoms, but AtomId represents at most {maximum}"
            ),
            Self::SourceAtomOutOfRange {
                atom,
                source_atom_count,
            } => write!(
                output,
                "semantic atom {} is outside the registered source range 0..{source_atom_count}",
                atom.index()
            ),
            Self::AtomCapExceeded { requested, cap } => {
                write!(output, "native CNF atom cap {cap} exceeded by {requested}")
            }
            Self::ClauseCapExceeded { requested, cap } => {
                write!(
                    output,
                    "native CNF clause cap {cap} exceeded by {requested}"
                )
            }
            Self::LiteralCapExceeded { requested, cap } => write!(
                output,
                "native CNF literal-occurrence cap {cap} exceeded by {requested}"
            ),
            Self::CountOverflow { resource } => {
                write!(output, "native CNF {resource} count overflowed usize")
            }
        }
    }
}

impl Error for LoweringError {}

pub(crate) fn lower(
    problem: &SemanticProblem,
    caps: LoweringCaps,
) -> Result<NativeFormula, LoweringError> {
    lower_assertions(
        problem.atoms.len(),
        &problem.assertions,
        &problem.root_literals,
        caps,
    )
}

pub(crate) fn lower_assertions(
    source_atom_count: usize,
    assertions: &[SemanticExpr],
    root_literals: &[RootLiteral],
    caps: LoweringCaps,
) -> Result<NativeFormula, LoweringError> {
    validate_atom_count(source_atom_count, caps)?;
    validate_source_atoms(source_atom_count, assertions, root_literals)?;

    let mut builder = FormulaBuilder::new(source_atom_count, caps);
    for assertion in assertions {
        let literal = encode_expression(assertion, &mut builder)?;
        builder.add_clause([literal])?;
    }
    for fact in root_literals {
        let literal = if fact.positive {
            Lit::positive(fact.atom)
        } else {
            Lit::negative(fact.atom)
        };
        builder.add_clause([Encoded::Lit(literal)])?;
    }
    Ok(builder.finish())
}

fn validate_atom_count(source_atom_count: usize, caps: LoweringCaps) -> Result<(), LoweringError> {
    let representable =
        u64::try_from(source_atom_count).is_ok_and(|count| count <= MAX_NATIVE_ATOMS);
    if !representable {
        return Err(LoweringError::AtomIdSpaceExhausted {
            requested: source_atom_count,
            maximum: MAX_NATIVE_ATOMS,
        });
    }
    if source_atom_count > caps.max_atoms {
        return Err(LoweringError::AtomCapExceeded {
            requested: source_atom_count,
            cap: caps.max_atoms,
        });
    }
    Ok(())
}

fn validate_source_atoms(
    source_atom_count: usize,
    assertions: &[SemanticExpr],
    root_literals: &[RootLiteral],
) -> Result<(), LoweringError> {
    let mut pending = assertions.iter().rev().collect::<Vec<_>>();
    while let Some(expression) = pending.pop() {
        match expression {
            SemanticExpr::Const(_) => {}
            SemanticExpr::Atom(atom) => validate_source_atom(*atom, source_atom_count)?,
            SemanticExpr::Not(child) => pending.push(child),
            SemanticExpr::And(children)
            | SemanticExpr::Or(children)
            | SemanticExpr::Iff(children) => pending.extend(children.iter().rev()),
            SemanticExpr::Ite(condition, then_expression, else_expression) => {
                pending.push(else_expression);
                pending.push(then_expression);
                pending.push(condition);
            }
        }
    }
    for fact in root_literals {
        validate_source_atom(fact.atom, source_atom_count)?;
    }
    Ok(())
}

fn validate_source_atom(atom: AtomId, source_atom_count: usize) -> Result<(), LoweringError> {
    if atom.index() >= source_atom_count {
        return Err(LoweringError::SourceAtomOutOfRange {
            atom,
            source_atom_count,
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Encoded {
    Const(bool),
    Lit(Lit),
}

impl Encoded {
    const fn negate(self) -> Self {
        match self {
            Self::Const(value) => Self::Const(!value),
            Self::Lit(literal) => Self::Lit(literal.negate()),
        }
    }
}

struct FormulaBuilder {
    source_atom_count: usize,
    atom_count: usize,
    clauses: BTreeSet<Box<[Lit]>>,
    literal_count: usize,
    caps: LoweringCaps,
}

impl FormulaBuilder {
    fn new(source_atom_count: usize, caps: LoweringCaps) -> Self {
        Self {
            source_atom_count,
            atom_count: source_atom_count,
            clauses: BTreeSet::new(),
            literal_count: 0,
            caps,
        }
    }

    fn fresh_literal(&mut self) -> Result<Encoded, LoweringError> {
        let requested = self
            .atom_count
            .checked_add(1)
            .ok_or(LoweringError::CountOverflow { resource: "atom" })?;
        if u64::try_from(requested).map_or(true, |count| count > MAX_NATIVE_ATOMS) {
            return Err(LoweringError::AtomIdSpaceExhausted {
                requested,
                maximum: MAX_NATIVE_ATOMS,
            });
        }
        if requested > self.caps.max_atoms {
            return Err(LoweringError::AtomCapExceeded {
                requested,
                cap: self.caps.max_atoms,
            });
        }
        let raw =
            u32::try_from(self.atom_count).map_err(|_| LoweringError::AtomIdSpaceExhausted {
                requested,
                maximum: MAX_NATIVE_ATOMS,
            })?;

        self.atom_count = requested;
        Ok(Encoded::Lit(Lit::positive(AtomId::new(raw))))
    }

    fn add_clause(
        &mut self,
        terms: impl IntoIterator<Item = Encoded>,
    ) -> Result<(), LoweringError> {
        let mut literals = Vec::new();
        for term in terms {
            match term {
                Encoded::Const(true) => return Ok(()),
                Encoded::Const(false) => {}
                Encoded::Lit(literal) => literals.push(literal),
            }
        }
        literals.sort_unstable();
        literals.dedup();
        if literals.windows(2).any(|pair| {
            pair[0].atom() == pair[1].atom() && pair[0].is_positive() != pair[1].is_positive()
        }) {
            return Ok(());
        }

        let clause = literals.into_boxed_slice();
        if self.clauses.contains(&clause) {
            return Ok(());
        }
        let clause_count = self
            .clauses
            .len()
            .checked_add(1)
            .ok_or(LoweringError::CountOverflow { resource: "clause" })?;
        if clause_count > self.caps.max_clauses {
            return Err(LoweringError::ClauseCapExceeded {
                requested: clause_count,
                cap: self.caps.max_clauses,
            });
        }
        let literal_count =
            self.literal_count
                .checked_add(clause.len())
                .ok_or(LoweringError::CountOverflow {
                    resource: "literal",
                })?;
        if literal_count > self.caps.max_literals {
            return Err(LoweringError::LiteralCapExceeded {
                requested: literal_count,
                cap: self.caps.max_literals,
            });
        }

        let inserted = self.clauses.insert(clause);
        debug_assert!(inserted, "duplicate clauses were handled before mutation");
        self.literal_count = literal_count;
        Ok(())
    }

    fn define_and(&mut self, children: &[Encoded]) -> Result<Encoded, LoweringError> {
        debug_assert!(children.len() >= 2);
        let definition = self.fresh_literal()?;
        for &child in children {
            self.add_clause([definition.negate(), child])?;
        }
        let mut reverse = Vec::with_capacity(children.len() + 1);
        reverse.push(definition);
        reverse.extend(children.iter().copied().map(Encoded::negate));
        self.add_clause(reverse)?;
        Ok(definition)
    }

    fn define_or(&mut self, children: &[Encoded]) -> Result<Encoded, LoweringError> {
        debug_assert!(children.len() >= 2);
        let definition = self.fresh_literal()?;
        for &child in children {
            self.add_clause([definition, child.negate()])?;
        }
        let mut forward = Vec::with_capacity(children.len() + 1);
        forward.push(definition.negate());
        forward.extend(children.iter().copied());
        self.add_clause(forward)?;
        Ok(definition)
    }

    fn define_iff(&mut self, children: &[Encoded]) -> Result<Encoded, LoweringError> {
        debug_assert!(children.len() >= 2);
        let definition = self.fresh_literal()?;
        let first = children[0];
        for &child in &children[1..] {
            self.add_clause([definition.negate(), first.negate(), child])?;
            self.add_clause([definition.negate(), first, child.negate()])?;
        }

        let mut all_true = Vec::with_capacity(children.len() + 1);
        all_true.push(definition);
        all_true.extend(children.iter().copied().map(Encoded::negate));
        self.add_clause(all_true)?;

        let mut all_false = Vec::with_capacity(children.len() + 1);
        all_false.push(definition);
        all_false.extend(children.iter().copied());
        self.add_clause(all_false)?;
        Ok(definition)
    }

    fn define_ite(
        &mut self,
        condition: Encoded,
        then_expression: Encoded,
        else_expression: Encoded,
    ) -> Result<Encoded, LoweringError> {
        let definition = self.fresh_literal()?;
        self.add_clause([condition.negate(), then_expression.negate(), definition])?;
        self.add_clause([condition.negate(), then_expression, definition.negate()])?;
        self.add_clause([condition, else_expression.negate(), definition])?;
        self.add_clause([condition, else_expression, definition.negate()])?;
        Ok(definition)
    }

    fn finish(self) -> NativeFormula {
        NativeFormula {
            atom_count: self.atom_count,
            clauses: self
                .clauses
                .into_iter()
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            source_atom_count: self.source_atom_count,
            auxiliary_atom_count: self.atom_count - self.source_atom_count,
        }
    }
}

#[derive(Clone, Copy)]
enum NaryOperator {
    And,
    Or,
    Iff,
}

enum EncodeTask<'a> {
    Expression(&'a SemanticExpr),
    FinishNot,
    FinishNary {
        operator: NaryOperator,
        arity: usize,
    },
    FinishIte,
}

fn encode_expression(
    expression: &SemanticExpr,
    builder: &mut FormulaBuilder,
) -> Result<Encoded, LoweringError> {
    let mut tasks = vec![EncodeTask::Expression(expression)];
    let mut values = Vec::new();

    while let Some(task) = tasks.pop() {
        match task {
            EncodeTask::Expression(expression) => match expression {
                SemanticExpr::Const(value) => values.push(Encoded::Const(*value)),
                SemanticExpr::Atom(atom) => values.push(Encoded::Lit(Lit::positive(*atom))),
                SemanticExpr::Not(child) => {
                    tasks.push(EncodeTask::FinishNot);
                    tasks.push(EncodeTask::Expression(child));
                }
                SemanticExpr::And(children) => schedule_nary(
                    children,
                    NaryOperator::And,
                    Encoded::Const(true),
                    &mut tasks,
                    &mut values,
                ),
                SemanticExpr::Or(children) => schedule_nary(
                    children,
                    NaryOperator::Or,
                    Encoded::Const(false),
                    &mut tasks,
                    &mut values,
                ),
                SemanticExpr::Iff(children) if children.len() <= 1 => {
                    values.push(Encoded::Const(true));
                }
                SemanticExpr::Iff(children) => schedule_nary(
                    children,
                    NaryOperator::Iff,
                    Encoded::Const(true),
                    &mut tasks,
                    &mut values,
                ),
                SemanticExpr::Ite(condition, then_expression, else_expression) => {
                    tasks.push(EncodeTask::FinishIte);
                    tasks.push(EncodeTask::Expression(else_expression));
                    tasks.push(EncodeTask::Expression(then_expression));
                    tasks.push(EncodeTask::Expression(condition));
                }
            },
            EncodeTask::FinishNot => {
                let child = values
                    .pop()
                    .expect("a scheduled negation has one encoded child");
                values.push(child.negate());
            }
            EncodeTask::FinishNary { operator, arity } => {
                let start = values
                    .len()
                    .checked_sub(arity)
                    .expect("a scheduled connective has all encoded children");
                let children = values.split_off(start);
                let definition = match operator {
                    NaryOperator::And => builder.define_and(&children)?,
                    NaryOperator::Or => builder.define_or(&children)?,
                    NaryOperator::Iff => builder.define_iff(&children)?,
                };
                values.push(definition);
            }
            EncodeTask::FinishIte => {
                let else_expression = values
                    .pop()
                    .expect("a scheduled conditional has an else child");
                let then_expression = values
                    .pop()
                    .expect("a scheduled conditional has a then child");
                let condition = values
                    .pop()
                    .expect("a scheduled conditional has a condition child");
                values.push(builder.define_ite(condition, then_expression, else_expression)?);
            }
        }
    }

    debug_assert_eq!(values.len(), 1);
    Ok(values
        .pop()
        .expect("encoding one expression produces one value"))
}

fn schedule_nary<'a>(
    children: &'a [SemanticExpr],
    operator: NaryOperator,
    empty: Encoded,
    tasks: &mut Vec<EncodeTask<'a>>,
    values: &mut Vec<Encoded>,
) {
    match children {
        [] => values.push(empty),
        [single] => tasks.push(EncodeTask::Expression(single)),
        _ => {
            tasks.push(EncodeTask::FinishNary {
                operator,
                arity: children.len(),
            });
            tasks.extend(children.iter().rev().map(EncodeTask::Expression));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn atom(index: u32) -> SemanticExpr {
        SemanticExpr::Atom(AtomId::new(index))
    }

    fn not(expression: SemanticExpr) -> SemanticExpr {
        SemanticExpr::Not(Box::new(expression))
    }

    fn and(children: Vec<SemanticExpr>) -> SemanticExpr {
        SemanticExpr::And(children.into_boxed_slice())
    }

    fn or(children: Vec<SemanticExpr>) -> SemanticExpr {
        SemanticExpr::Or(children.into_boxed_slice())
    }

    fn iff(children: Vec<SemanticExpr>) -> SemanticExpr {
        SemanticExpr::Iff(children.into_boxed_slice())
    }

    fn ite(
        condition: SemanticExpr,
        then_expression: SemanticExpr,
        else_expression: SemanticExpr,
    ) -> SemanticExpr {
        SemanticExpr::Ite(
            Box::new(condition),
            Box::new(then_expression),
            Box::new(else_expression),
        )
    }

    fn p(index: u32) -> Lit {
        Lit::positive(AtomId::new(index))
    }

    fn n(index: u32) -> Lit {
        Lit::negative(AtomId::new(index))
    }

    fn test_caps() -> LoweringCaps {
        LoweringCaps::new(128, 4_096, 32_768)
    }

    fn evaluate(expression: &SemanticExpr, assignment: &[bool]) -> bool {
        match expression {
            SemanticExpr::Const(value) => *value,
            SemanticExpr::Atom(atom) => assignment[atom.index()],
            SemanticExpr::Not(child) => !evaluate(child, assignment),
            SemanticExpr::And(children) => children.iter().all(|child| evaluate(child, assignment)),
            SemanticExpr::Or(children) => children.iter().any(|child| evaluate(child, assignment)),
            SemanticExpr::Iff(children) => children.split_first().is_none_or(|(first, rest)| {
                let first = evaluate(first, assignment);
                rest.iter()
                    .all(|child| evaluate(child, assignment) == first)
            }),
            SemanticExpr::Ite(condition, then_expression, else_expression) => {
                if evaluate(condition, assignment) {
                    evaluate(then_expression, assignment)
                } else {
                    evaluate(else_expression, assignment)
                }
            }
        }
    }

    fn satisfies(formula: &NativeFormula, assignment: &[bool]) -> bool {
        formula.clauses.iter().all(|clause| {
            clause
                .iter()
                .any(|literal| assignment[literal.atom().index()] == literal.is_positive())
        })
    }

    fn assignment(bits: usize, count: usize) -> Vec<bool> {
        (0..count).map(|index| bits & (1 << index) != 0).collect()
    }

    fn assert_exact_truth_table(expression: &SemanticExpr, source_atom_count: usize) {
        let formula = lower_assertions(
            source_atom_count,
            std::slice::from_ref(expression),
            &[],
            test_caps(),
        )
        .unwrap();
        assert!(formula.atom_count < usize::BITS as usize);

        for source_bits in 0..(1usize << source_atom_count) {
            let source_assignment = assignment(source_bits, source_atom_count);
            let expected = evaluate(expression, &source_assignment);
            let mut satisfying_extensions = 0usize;
            for auxiliary_bits in 0..(1usize << formula.auxiliary_atom_count) {
                let mut full_assignment = source_assignment.clone();
                full_assignment.extend(assignment(auxiliary_bits, formula.auxiliary_atom_count));
                satisfying_extensions += usize::from(satisfies(&formula, &full_assignment));
            }
            assert_eq!(
                satisfying_extensions,
                usize::from(expected),
                "source assignment {source_bits:b} for {expression:?}"
            );
        }
    }

    #[test]
    fn exact_truth_tables_cover_every_expression_form_and_edge_arity() {
        assert_exact_truth_table(&SemanticExpr::Const(true), 0);
        assert_exact_truth_table(&SemanticExpr::Const(false), 0);
        assert_exact_truth_table(&atom(0), 1);
        assert_exact_truth_table(&not(atom(0)), 1);

        for arity in 0..=4u32 {
            let children = (0..arity).map(atom).collect::<Vec<_>>();
            assert_exact_truth_table(&and(children.clone()), 4);
            assert_exact_truth_table(&or(children.clone()), 4);
            assert_exact_truth_table(&iff(children), 4);
        }

        assert_exact_truth_table(&ite(atom(0), atom(1), atom(2)), 3);
        assert_exact_truth_table(
            &and(vec![
                SemanticExpr::Const(true),
                or(vec![atom(0), not(atom(1)), SemanticExpr::Const(false)]),
                iff(vec![atom(0), atom(1), atom(2)]),
                ite(not(atom(2)), and(vec![atom(0), atom(3)]), or(vec![])),
            ]),
            4,
        );
        assert_exact_truth_table(
            &ite(
                iff(vec![atom(0), SemanticExpr::Const(false)]),
                or(vec![atom(1), atom(2)]),
                and(vec![not(atom(1)), atom(2)]),
            ),
            3,
        );
    }

    #[test]
    fn unary_iff_is_true_without_lowering_its_child() {
        let expression = iff(vec![and(vec![atom(0), atom(1)])]);
        let formula = lower_assertions(2, &[expression], &[], test_caps()).unwrap();

        assert_eq!(formula.atom_count, 2);
        assert_eq!(formula.auxiliary_atom_count, 0);
        assert!(formula.clauses.is_empty());
    }

    #[test]
    fn source_ids_are_preserved_and_auxiliaries_are_contiguous_postorder() {
        let expression = and(vec![atom(2), or(vec![atom(0), not(atom(1))])]);
        let roots = [
            RootLiteral {
                atom: AtomId::new(1),
                positive: false,
            },
            RootLiteral {
                atom: AtomId::new(0),
                positive: true,
            },
        ];
        let formula = lower_assertions(3, &[expression], &roots, test_caps()).unwrap();

        assert_eq!(formula.source_atom_count, 3);
        assert_eq!(formula.auxiliary_atom_count, 2);
        assert_eq!(formula.atom_count, 5);

        let mut expected = vec![
            vec![p(3), n(0)],
            vec![p(3), p(1)],
            vec![n(3), p(0), n(1)],
            vec![n(4), p(2)],
            vec![n(4), p(3)],
            vec![p(4), n(2), n(3)],
            vec![p(4)],
            vec![n(1)],
            vec![p(0)],
        ];
        for clause in &mut expected {
            clause.sort_unstable();
        }
        expected.sort();
        let expected = expected
            .into_iter()
            .map(Vec::into_boxed_slice)
            .collect::<Vec<_>>();
        assert_eq!(formula.clauses.as_ref(), expected.as_slice());

        let auxiliaries = formula
            .clauses
            .iter()
            .flat_map(|clause| clause.iter())
            .filter_map(|literal| {
                (literal.atom().index() >= formula.source_atom_count)
                    .then_some(literal.atom().index())
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(auxiliaries, BTreeSet::from([3, 4]));
    }

    #[test]
    fn nary_iff_uses_all_equal_source_semantics() {
        let expression = iff(vec![atom(0), atom(1), atom(2), atom(3)]);
        let formula = lower_assertions(4, &[expression.clone()], &[], test_caps()).unwrap();

        assert_eq!(formula.auxiliary_atom_count, 1);
        assert_eq!(formula.clauses.len(), 9);
        assert_exact_truth_table(&expression, 4);
    }

    #[test]
    fn constants_and_root_facts_have_canonical_clause_forms() {
        let assertions = [
            SemanticExpr::Const(true),
            and(Vec::new()),
            iff(Vec::new()),
            iff(vec![SemanticExpr::Const(false)]),
            SemanticExpr::Const(false),
            or(Vec::new()),
        ];
        let roots = [
            RootLiteral {
                atom: AtomId::new(0),
                positive: true,
            },
            RootLiteral {
                atom: AtomId::new(0),
                positive: true,
            },
            RootLiteral {
                atom: AtomId::new(1),
                positive: false,
            },
        ];
        let formula = lower_assertions(2, &assertions, &roots, test_caps()).unwrap();

        assert_eq!(formula.auxiliary_atom_count, 0);
        assert_eq!(
            formula.clauses.as_ref(),
            &[
                Vec::<Lit>::new().into_boxed_slice(),
                vec![p(0)].into_boxed_slice(),
                vec![n(1)].into_boxed_slice(),
            ]
        );
    }

    #[test]
    fn clauses_are_sorted_deduplicated_tautology_free_and_repeatable() {
        let assertions = [
            and(vec![atom(0), atom(0)]),
            or(vec![atom(1), not(atom(1))]),
            ite(atom(0), atom(1), atom(1)),
        ];
        let roots = [
            RootLiteral {
                atom: AtomId::new(0),
                positive: true,
            },
            RootLiteral {
                atom: AtomId::new(0),
                positive: true,
            },
        ];
        let first = lower_assertions(2, &assertions, &roots, test_caps()).unwrap();
        let second = lower_assertions(2, &assertions, &roots, test_caps()).unwrap();
        assert_eq!(first, second);

        assert!(first.clauses.windows(2).all(|pair| pair[0] < pair[1]));
        for clause in &first.clauses {
            assert!(clause.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(!clause.windows(2).any(|pair| {
                pair[0].atom() == pair[1].atom() && pair[0].is_positive() != pair[1].is_positive()
            }));
        }
    }

    #[test]
    fn opposite_root_facts_remain_an_explicit_contradiction() {
        let roots = [
            RootLiteral {
                atom: AtomId::new(0),
                positive: true,
            },
            RootLiteral {
                atom: AtomId::new(0),
                positive: false,
            },
        ];
        let formula = lower_assertions(1, &[], &roots, test_caps()).unwrap();
        assert_eq!(
            formula.clauses.as_ref(),
            &[vec![n(0)].into_boxed_slice(), vec![p(0)].into_boxed_slice()]
        );
        assert!(!satisfies(&formula, &[false]));
        assert!(!satisfies(&formula, &[true]));
    }

    #[test]
    fn rejects_unknown_expression_and_root_atoms() {
        assert_eq!(
            lower_assertions(1, &[atom(1)], &[], test_caps()).unwrap_err(),
            LoweringError::SourceAtomOutOfRange {
                atom: AtomId::new(1),
                source_atom_count: 1,
            }
        );
        assert_eq!(
            lower_assertions(
                1,
                &[],
                &[RootLiteral {
                    atom: AtomId::new(9),
                    positive: false,
                }],
                test_caps(),
            )
            .unwrap_err(),
            LoweringError::SourceAtomOutOfRange {
                atom: AtomId::new(9),
                source_atom_count: 1,
            }
        );
    }

    #[test]
    fn caps_are_checked_before_each_formula_mutation() {
        assert_eq!(
            lower_assertions(2, &[], &[], LoweringCaps::new(1, 10, 10)).unwrap_err(),
            LoweringError::AtomCapExceeded {
                requested: 2,
                cap: 1,
            }
        );
        assert_eq!(
            lower_assertions(
                1,
                &[and(vec![atom(0), atom(0)])],
                &[],
                LoweringCaps::new(1, 10, 10),
            )
            .unwrap_err(),
            LoweringError::AtomCapExceeded {
                requested: 2,
                cap: 1,
            }
        );
        assert_eq!(
            lower_assertions(1, &[atom(0)], &[], LoweringCaps::new(1, 0, 10),).unwrap_err(),
            LoweringError::ClauseCapExceeded {
                requested: 1,
                cap: 0,
            }
        );
        assert_eq!(
            lower_assertions(1, &[atom(0)], &[], LoweringCaps::new(1, 1, 0),).unwrap_err(),
            LoweringError::LiteralCapExceeded {
                requested: 1,
                cap: 0,
            }
        );

        let duplicate_roots = [
            RootLiteral {
                atom: AtomId::new(0),
                positive: true,
            },
            RootLiteral {
                atom: AtomId::new(0),
                positive: true,
            },
        ];
        let formula =
            lower_assertions(1, &[], &duplicate_roots, LoweringCaps::new(1, 1, 1)).unwrap();
        assert_eq!(formula.clauses.len(), 1);
    }

    #[test]
    fn rejects_source_counts_outside_atom_id_space_without_allocating() {
        if usize::BITS > 32 {
            let requested = u32::MAX as usize + 2;
            assert_eq!(
                lower_assertions(requested, &[], &[], LoweringCaps::unlimited()).unwrap_err(),
                LoweringError::AtomIdSpaceExhausted {
                    requested,
                    maximum: MAX_NATIVE_ATOMS,
                }
            );
        }
    }

    #[test]
    fn iterative_lowering_handles_deep_negation_without_recursion() {
        let mut expression = atom(0);
        for _ in 0..50_000 {
            expression = not(expression);
        }
        let assertions = [expression];
        let formula = lower_assertions(1, &assertions, &[], test_caps()).unwrap();

        assert_eq!(formula.atom_count, 1);
        assert_eq!(formula.clauses.as_ref(), &[vec![p(0)].into_boxed_slice()]);

        let [mut expression] = assertions;
        loop {
            match expression {
                SemanticExpr::Not(child) => expression = *child,
                leaf => {
                    drop(leaf);
                    break;
                }
            }
        }
    }
}
