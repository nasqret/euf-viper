use super::super::{BoolAtomKey, BoolExpr, Problem};
use super::component::{ComponentBuilder, ComponentError, ComponentGraph, ComponentId};
use super::native_clause::AtomId;
use super::partition::TermId;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SemanticTerm {
    pub(crate) function: u32,
    pub(crate) sort: u32,
    pub(crate) arguments: Box<[TermId]>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SemanticAtom {
    Equality(TermId, TermId),
    BoolTerm(TermId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SemanticExpr {
    Const(bool),
    Atom(AtomId),
    Not(Box<SemanticExpr>),
    And(Box<[SemanticExpr]>),
    Or(Box<[SemanticExpr]>),
    Iff(Box<[SemanticExpr]>),
    Ite(Box<SemanticExpr>, Box<SemanticExpr>, Box<SemanticExpr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RootLiteral {
    pub(crate) atom: AtomId,
    pub(crate) positive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SemanticStats {
    pub(crate) terms: usize,
    pub(crate) applications: usize,
    pub(crate) atoms: usize,
    pub(crate) assertions: usize,
    pub(crate) root_literals: usize,
    pub(crate) components: usize,
    pub(crate) max_component_terms: usize,
    pub(crate) cross_component_boolean_nodes: usize,
    pub(crate) unsupported_fragments: usize,
    pub(crate) contradiction: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SemanticProblem {
    pub(crate) terms: Box<[SemanticTerm]>,
    pub(crate) atoms: Box<[SemanticAtom]>,
    pub(crate) assertions: Box<[SemanticExpr]>,
    pub(crate) root_literals: Box<[RootLiteral]>,
    pub(crate) boolean_values: Option<(TermId, TermId)>,
    pub(crate) atom_components: Box<[ComponentId]>,
    pub(crate) components: ComponentGraph,
    pub(crate) stats: SemanticStats,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SemanticError {
    IllSortedSource,
    TooManyAtoms(usize),
    UnknownSourceTerm { term: usize, term_count: usize },
    MissingAtom(SemanticAtom),
    Component(ComponentError),
}

impl fmt::Display for SemanticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllSortedSource => {
                write!(formatter, "cannot project an ill-sorted source problem")
            }
            Self::TooManyAtoms(count) => {
                write!(
                    formatter,
                    "Fabric supports at most {} atoms, got {count}",
                    u32::MAX
                )
            }
            Self::UnknownSourceTerm { term, term_count } => {
                write!(
                    formatter,
                    "source term {term} is outside the term range 0..{term_count}"
                )
            }
            Self::MissingAtom(atom) => {
                write!(formatter, "semantic atom {atom:?} was not registered")
            }
            Self::Component(error) => error.fmt(formatter),
        }
    }
}

impl From<ComponentError> for SemanticError {
    fn from(error: ComponentError) -> Self {
        Self::Component(error)
    }
}

pub(crate) fn project(problem: &Problem) -> Result<SemanticProblem, SemanticError> {
    if !problem.terms_are_well_sorted() {
        return Err(SemanticError::IllSortedSource);
    }

    let term_count = problem.arena.terms.len();
    let mut terms = Vec::with_capacity(term_count);
    let mut component_builder = ComponentBuilder::new(term_count)?;
    for (source_id, source) in problem.arena.terms.iter().enumerate() {
        let id = source_term(source_id, term_count)?;
        let arguments = source
            .args
            .iter()
            .map(|&argument| source_term(argument, term_count))
            .collect::<Result<Vec<_>, _>>()?;
        component_builder.connect_all(id, arguments.iter().copied())?;
        terms.push(SemanticTerm {
            function: source.fun,
            sort: source.sort.0,
            arguments: arguments.into_boxed_slice(),
        });
    }

    let mut atom_set = BTreeSet::new();
    for &(left, right) in problem.eqs.iter().chain(&problem.diseqs) {
        atom_set.insert(equality_atom(left, right, term_count)?);
    }
    let boolean_values = problem
        .bool_problem
        .as_ref()
        .map(|bool_problem| -> Result<(TermId, TermId), SemanticError> {
            Ok((
                source_term(bool_problem.true_term, term_count)?,
                source_term(bool_problem.false_term, term_count)?,
            ))
        })
        .transpose()?;
    if let Some(bool_problem) = &problem.bool_problem {
        for assertion in &bool_problem.assertions {
            collect_atoms(assertion, term_count, &mut atom_set)?;
        }
        for &term in &bool_problem.data_terms {
            atom_set.insert(SemanticAtom::BoolTerm(source_term(term, term_count)?));
        }
    }

    if atom_set.len() > u32::MAX as usize {
        return Err(SemanticError::TooManyAtoms(atom_set.len()));
    }
    let atoms = atom_set.into_iter().collect::<Vec<_>>();
    let atom_ids = atoms
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, atom)| (atom, AtomId::new(index as u32)))
        .collect::<BTreeMap<_, _>>();

    if let Some(bool_problem) = &problem.bool_problem {
        let true_term = source_term(bool_problem.true_term, term_count)?;
        let false_term = source_term(bool_problem.false_term, term_count)?;
        component_builder.connect(true_term, false_term)?;
        for atom in &atoms {
            match atom {
                SemanticAtom::Equality(left, right) => component_builder.connect(*left, *right)?,
                SemanticAtom::BoolTerm(term) => {
                    component_builder.connect(*term, true_term)?;
                    component_builder.connect(*term, false_term)?;
                }
            }
        }
    } else {
        for atom in &atoms {
            if let SemanticAtom::Equality(left, right) = atom {
                component_builder.connect(*left, *right)?;
            }
        }
    }
    let components = component_builder.finish();
    let atom_components = atoms
        .iter()
        .map(|atom| {
            components
                .owner(atom.anchor())
                .expect("registered atoms contain registered terms")
        })
        .collect::<Vec<_>>();

    let assertions = problem
        .bool_problem
        .as_ref()
        .map(|bool_problem| {
            bool_problem
                .assertions
                .iter()
                .map(|assertion| project_expr(assertion, term_count, &atom_ids))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    let mut root_literals = Vec::with_capacity(problem.eqs.len() + problem.diseqs.len());
    for &(left, right) in &problem.eqs {
        root_literals.push(RootLiteral {
            atom: lookup_atom(equality_atom(left, right, term_count)?, &atom_ids)?,
            positive: true,
        });
    }
    for &(left, right) in &problem.diseqs {
        root_literals.push(RootLiteral {
            atom: lookup_atom(equality_atom(left, right, term_count)?, &atom_ids)?,
            positive: false,
        });
    }

    let cross_component_boolean_nodes = assertions
        .iter()
        .map(|assertion| count_cross_component_nodes(assertion, &atom_components).0)
        .sum();
    let unsupported_fragments = problem.unsupported.len()
        + problem
            .bool_problem
            .as_ref()
            .map_or(0, |bool_problem| bool_problem.unsupported.len());
    let stats = SemanticStats {
        terms: terms.len(),
        applications: problem.arena.app_count(),
        atoms: atoms.len(),
        assertions: assertions.len(),
        root_literals: root_literals.len(),
        components: components.component_count(),
        max_component_terms: components.max_component_size(),
        cross_component_boolean_nodes,
        unsupported_fragments,
        contradiction: problem.contradiction,
    };

    Ok(SemanticProblem {
        terms: terms.into_boxed_slice(),
        atoms: atoms.into_boxed_slice(),
        assertions: assertions.into_boxed_slice(),
        root_literals: root_literals.into_boxed_slice(),
        boolean_values,
        atom_components: atom_components.into_boxed_slice(),
        components,
        stats,
    })
}

pub(crate) fn render_census_json(
    projection: &SemanticProblem,
    source_bytes: usize,
    parse_ns: u128,
    projection_ns: u128,
) -> String {
    let stats = &projection.stats;
    format!(
        concat!(
            "{{\"schema_version\":1,",
            "\"mode\":\"fabric_shadow\",",
            "\"solver_result_emitted\":false,",
            "\"source_bytes\":{},",
            "\"parse_ns\":{},",
            "\"projection_ns\":{},",
            "\"terms\":{},",
            "\"applications\":{},",
            "\"atoms\":{},",
            "\"assertions\":{},",
            "\"root_literals\":{},",
            "\"components\":{},",
            "\"max_component_terms\":{},",
            "\"cross_component_boolean_nodes\":{},",
            "\"unsupported_fragments\":{},",
            "\"contradiction\":{}",
            "}}\n"
        ),
        source_bytes,
        parse_ns,
        projection_ns,
        stats.terms,
        stats.applications,
        stats.atoms,
        stats.assertions,
        stats.root_literals,
        stats.components,
        stats.max_component_terms,
        stats.cross_component_boolean_nodes,
        stats.unsupported_fragments,
        stats.contradiction,
    )
}

impl SemanticAtom {
    fn anchor(&self) -> TermId {
        match self {
            Self::Equality(left, _) => *left,
            Self::BoolTerm(term) => *term,
        }
    }
}

fn source_term(term: usize, term_count: usize) -> Result<TermId, SemanticError> {
    if term >= term_count {
        return Err(SemanticError::UnknownSourceTerm { term, term_count });
    }
    TermId::try_from(term)
        .map_err(|_| ComponentError::TooManyTerms(term_count))
        .map_err(Into::into)
}

fn equality_atom(
    left: usize,
    right: usize,
    term_count: usize,
) -> Result<SemanticAtom, SemanticError> {
    let left = source_term(left, term_count)?;
    let right = source_term(right, term_count)?;
    Ok(if left <= right {
        SemanticAtom::Equality(left, right)
    } else {
        SemanticAtom::Equality(right, left)
    })
}

fn collect_atoms(
    expression: &BoolExpr,
    term_count: usize,
    atoms: &mut BTreeSet<SemanticAtom>,
) -> Result<(), SemanticError> {
    match expression {
        BoolExpr::Const(_) => {}
        BoolExpr::Atom(atom) => {
            atoms.insert(project_atom(atom, term_count)?);
        }
        BoolExpr::Not(child) => collect_atoms(child, term_count, atoms)?,
        BoolExpr::And(children) | BoolExpr::Or(children) | BoolExpr::Iff(children) => {
            for child in children {
                collect_atoms(child, term_count, atoms)?;
            }
        }
        BoolExpr::Ite(condition, then_expression, else_expression) => {
            collect_atoms(condition, term_count, atoms)?;
            collect_atoms(then_expression, term_count, atoms)?;
            collect_atoms(else_expression, term_count, atoms)?;
        }
    }
    Ok(())
}

fn project_atom(atom: &BoolAtomKey, term_count: usize) -> Result<SemanticAtom, SemanticError> {
    match atom {
        BoolAtomKey::Eq(left, right) => equality_atom(*left, *right, term_count),
        BoolAtomKey::BoolTerm(term) => Ok(SemanticAtom::BoolTerm(source_term(*term, term_count)?)),
    }
}

fn lookup_atom(
    atom: SemanticAtom,
    atom_ids: &BTreeMap<SemanticAtom, AtomId>,
) -> Result<AtomId, SemanticError> {
    atom_ids
        .get(&atom)
        .copied()
        .ok_or(SemanticError::MissingAtom(atom))
}

fn project_expr(
    expression: &BoolExpr,
    term_count: usize,
    atom_ids: &BTreeMap<SemanticAtom, AtomId>,
) -> Result<SemanticExpr, SemanticError> {
    Ok(match expression {
        BoolExpr::Const(value) => SemanticExpr::Const(*value),
        BoolExpr::Atom(atom) => {
            SemanticExpr::Atom(lookup_atom(project_atom(atom, term_count)?, atom_ids)?)
        }
        BoolExpr::Not(child) => {
            SemanticExpr::Not(Box::new(project_expr(child, term_count, atom_ids)?))
        }
        BoolExpr::And(children) => {
            SemanticExpr::And(project_children(children, term_count, atom_ids)?)
        }
        BoolExpr::Or(children) => {
            SemanticExpr::Or(project_children(children, term_count, atom_ids)?)
        }
        BoolExpr::Iff(children) => {
            SemanticExpr::Iff(project_children(children, term_count, atom_ids)?)
        }
        BoolExpr::Ite(condition, then_expression, else_expression) => SemanticExpr::Ite(
            Box::new(project_expr(condition, term_count, atom_ids)?),
            Box::new(project_expr(then_expression, term_count, atom_ids)?),
            Box::new(project_expr(else_expression, term_count, atom_ids)?),
        ),
    })
}

fn project_children(
    children: &[BoolExpr],
    term_count: usize,
    atom_ids: &BTreeMap<SemanticAtom, AtomId>,
) -> Result<Box<[SemanticExpr]>, SemanticError> {
    children
        .iter()
        .map(|child| project_expr(child, term_count, atom_ids))
        .collect::<Result<Vec<_>, _>>()
        .map(Vec::into_boxed_slice)
}

fn count_cross_component_nodes(
    expression: &SemanticExpr,
    atom_components: &[ComponentId],
) -> (usize, BTreeSet<ComponentId>) {
    match expression {
        SemanticExpr::Const(_) => (0, BTreeSet::new()),
        SemanticExpr::Atom(atom) => (
            0,
            atom_components
                .get(atom.index())
                .copied()
                .into_iter()
                .collect(),
        ),
        SemanticExpr::Not(child) => count_cross_component_nodes(child, atom_components),
        SemanticExpr::And(children) | SemanticExpr::Or(children) | SemanticExpr::Iff(children) => {
            count_children(children.iter(), atom_components)
        }
        SemanticExpr::Ite(condition, then_expression, else_expression) => count_children(
            [
                condition.as_ref(),
                then_expression.as_ref(),
                else_expression.as_ref(),
            ],
            atom_components,
        ),
    }
}

fn count_children<'a>(
    children: impl IntoIterator<Item = &'a SemanticExpr>,
    atom_components: &[ComponentId],
) -> (usize, BTreeSet<ComponentId>) {
    let mut count = 0;
    let mut components = BTreeSet::new();
    for child in children {
        let (child_count, child_components) = count_cross_component_nodes(child, atom_components);
        count += child_count;
        components.extend(child_components);
    }
    count += usize::from(components.len() > 1);
    (count, components)
}

#[cfg(test)]
mod tests {
    use super::super::super::parse_problem;
    use super::*;

    fn evaluate_projected(expression: &SemanticExpr, assignment: &[bool]) -> bool {
        match expression {
            SemanticExpr::Const(value) => *value,
            SemanticExpr::Atom(atom) => assignment[atom.index()],
            SemanticExpr::Not(child) => !evaluate_projected(child, assignment),
            SemanticExpr::And(children) => children
                .iter()
                .all(|child| evaluate_projected(child, assignment)),
            SemanticExpr::Or(children) => children
                .iter()
                .any(|child| evaluate_projected(child, assignment)),
            SemanticExpr::Iff(children) => children.first().is_none_or(|first| {
                let value = evaluate_projected(first, assignment);
                children
                    .iter()
                    .skip(1)
                    .all(|child| evaluate_projected(child, assignment) == value)
            }),
            SemanticExpr::Ite(condition, then_expression, else_expression) => {
                if evaluate_projected(condition, assignment) {
                    evaluate_projected(then_expression, assignment)
                } else {
                    evaluate_projected(else_expression, assignment)
                }
            }
        }
    }

    fn evaluate_source(
        expression: &BoolExpr,
        term_count: usize,
        atoms: &[SemanticAtom],
        assignment: &[bool],
    ) -> bool {
        match expression {
            BoolExpr::Const(value) => *value,
            BoolExpr::Atom(atom) => {
                let projected = project_atom(atom, term_count).unwrap();
                let index = atoms.binary_search(&projected).unwrap();
                assignment[index]
            }
            BoolExpr::Not(child) => !evaluate_source(child, term_count, atoms, assignment),
            BoolExpr::And(children) => children
                .iter()
                .all(|child| evaluate_source(child, term_count, atoms, assignment)),
            BoolExpr::Or(children) => children
                .iter()
                .any(|child| evaluate_source(child, term_count, atoms, assignment)),
            BoolExpr::Iff(children) => children.first().is_none_or(|first| {
                let value = evaluate_source(first, term_count, atoms, assignment);
                children
                    .iter()
                    .skip(1)
                    .all(|child| evaluate_source(child, term_count, atoms, assignment) == value)
            }),
            BoolExpr::Ite(condition, then_expression, else_expression) => {
                if evaluate_source(condition, term_count, atoms, assignment) {
                    evaluate_source(then_expression, term_count, atoms, assignment)
                } else {
                    evaluate_source(else_expression, term_count, atoms, assignment)
                }
            }
        }
    }

    #[test]
    fn projection_is_deterministic_and_atoms_are_canonical() {
        let source = "(set-logic QF_UF)\n\
            (declare-sort U 0)\n\
            (declare-const a U)\n\
            (declare-const b U)\n\
            (assert (or (= b a) (not (= a b))))\n\
            (check-sat)";
        let problem = parse_problem(source).unwrap();

        let first = project(&problem).unwrap();
        let second = project(&problem).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.stats.atoms, 1);
        assert_eq!(first.atoms.len(), 1);
        assert!(matches!(first.atoms[0], SemanticAtom::Equality(left, right) if left <= right));
    }

    #[test]
    fn independent_theory_regions_remain_separate_under_boolean_shell() {
        let source = "(set-logic QF_UF)\n\
            (declare-sort U 0)\n\
            (declare-const a U) (declare-const b U)\n\
            (declare-const c U) (declare-const d U)\n\
            (assert (or (= a b) (= c d)))\n\
            (check-sat)";
        let projection = project(&parse_problem(source).unwrap()).unwrap();

        let equality_components = projection
            .atoms
            .iter()
            .enumerate()
            .filter_map(|(index, atom)| {
                matches!(atom, SemanticAtom::Equality(_, _))
                    .then_some(projection.atom_components[index])
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(equality_components.len(), 2);
        assert!(projection.stats.cross_component_boolean_nodes >= 1);
    }

    #[test]
    fn boolean_terms_share_the_true_false_theory_region() {
        let source = "(set-logic QF_UF)\n\
            (declare-sort U 0)\n\
            (declare-const a U) (declare-const b U)\n\
            (declare-fun p (U) Bool)\n\
            (assert (or (p a) (p b)))\n\
            (check-sat)";
        let projection = project(&parse_problem(source).unwrap()).unwrap();
        let bool_components = projection
            .atoms
            .iter()
            .enumerate()
            .filter_map(|(index, atom)| {
                matches!(atom, SemanticAtom::BoolTerm(_))
                    .then_some(projection.atom_components[index])
            })
            .collect::<BTreeSet<_>>();

        assert_eq!(bool_components.len(), 1);
        let (true_term, false_term) = projection.boolean_values.unwrap();
        assert_ne!(true_term, false_term);
    }

    #[test]
    fn census_receipt_is_single_line_json_without_a_solver_claim() {
        let source = "(set-logic QF_UF)\n(assert true)\n(check-sat)\n";
        let projection = project(&parse_problem(source).unwrap()).unwrap();
        let receipt = render_census_json(&projection, source.len(), 11, 13);

        assert!(receipt.starts_with("{\"schema_version\":1,\"mode\":\"fabric_shadow\","));
        assert!(receipt.contains("\"solver_result_emitted\":false"));
        assert!(receipt.contains("\"parse_ns\":11"));
        assert!(receipt.contains("\"projection_ns\":13"));
        assert_eq!(receipt.lines().count(), 1);
        assert!(!receipt.contains("\"result\""));
    }

    #[test]
    fn every_boolean_operator_has_exhaustive_source_truth_parity() {
        let source = "(set-logic QF_UF)\n\
            (declare-sort U 0)\n\
            (declare-const a U) (declare-const b U)\n\
            (declare-const c U) (declare-const d U)\n\
            (assert (not (= a b)))\n\
            (assert (and (= a b) (= c d)))\n\
            (assert (or (= a b) (= c d)))\n\
            (assert (= (= a b) (= c d) (= a c)))\n\
            (assert (ite (= a b) (= c d) (= a c)))\n\
            (check-sat)";
        let problem = parse_problem(source).unwrap();
        let bool_problem = problem.bool_problem.as_ref().unwrap();
        let projection = project(&problem).unwrap();
        assert_eq!(bool_problem.assertions.len(), projection.assertions.len());
        assert!(projection.atoms.len() <= 8);

        for encoded in 0..(1usize << projection.atoms.len()) {
            let assignment = (0..projection.atoms.len())
                .map(|bit| encoded & (1 << bit) != 0)
                .collect::<Vec<_>>();
            for (source_expression, projected_expression) in bool_problem
                .assertions
                .iter()
                .zip(projection.assertions.iter())
            {
                assert_eq!(
                    evaluate_projected(projected_expression, &assignment),
                    evaluate_source(
                        source_expression,
                        problem.arena.terms.len(),
                        &projection.atoms,
                        &assignment,
                    ),
                    "assignment {encoded}"
                );
            }
        }
    }
}
