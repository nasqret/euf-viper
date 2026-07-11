//! Deterministic reference compiler for sets of forbidden Boolean tables.
//!
//! Each input row is one complete assignment, written as signed DIMACS-style
//! atom literals in strictly increasing atom order.  The outer slice denotes a
//! set: its order is immaterial, while duplicate rows are rejected.  A separate
//! variable order controls the reduced ordered suffix DAG.
//!
//! A DAG node denotes the predicate "the remaining assignment is forbidden".
//! Its auxiliary variable is defined by an ITE over the tested atom.  The root
//! constraint negates that predicate, so the resulting existential CNF accepts
//! exactly the assignments not present in the input set.
//!
//! This module is deliberately self-contained and is not wired into production
//! solver code.  It can be checked directly with:
//!
//! ```text
//! rustc --edition=2021 --test src/forbidden_table_mdd.rs
//! ```

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

pub type AtomId = u32;
pub type SignedAtomLiteral = i32;

const MAX_DIMACS_VARIABLE: AtomId = i32::MAX as AtomId;

/// Fail-closed limits for both intermediate and emitted structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstructionCap {
    pub max_variables: usize,
    pub max_assignments: usize,
    pub max_input_literals: usize,
    pub max_trie_nodes: usize,
    pub max_mdd_nodes: usize,
    pub max_mdd_edges: usize,
    pub max_cnf_clauses: usize,
    pub max_cnf_literals: usize,
}

impl Default for ConstructionCap {
    fn default() -> Self {
        Self {
            max_variables: 4_096,
            max_assignments: 1_000_000,
            max_input_literals: 100_000_000,
            max_trie_nodes: 10_000_000,
            max_mdd_nodes: 2_000_000,
            max_mdd_edges: 4_000_000,
            max_cnf_clauses: 8_000_001,
            max_cnf_literals: 24_000_001,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CappedResource {
    Variables,
    Assignments,
    InputLiterals,
    TrieNodes,
    MddNodes,
    MddEdges,
    CnfClauses,
    CnfLiterals,
}

impl fmt::Display for CappedResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Variables => "variables",
            Self::Assignments => "assignments",
            Self::InputLiterals => "input literals",
            Self::TrieNodes => "trie nodes",
            Self::MddNodes => "MDD nodes",
            Self::MddEdges => "MDD edges",
            Self::CnfClauses => "CNF clauses",
            Self::CnfLiterals => "CNF literals",
        };
        output.write_str(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    CapExceeded {
        resource: CappedResource,
        limit: usize,
        attempted: usize,
    },
    InvalidOrderAtom {
        position: usize,
        atom: AtomId,
    },
    DuplicateOrderAtom {
        atom: AtomId,
        first_position: usize,
        second_position: usize,
    },
    AssignmentLength {
        assignment: usize,
        expected: usize,
        actual: usize,
    },
    InvalidLiteral {
        assignment: usize,
        position: usize,
        literal: SignedAtomLiteral,
    },
    NonCanonicalAssignment {
        assignment: usize,
        position: usize,
        previous_atom: AtomId,
        atom: AtomId,
    },
    WrongAssignmentAtom {
        assignment: usize,
        position: usize,
        expected: AtomId,
        actual: AtomId,
    },
    DuplicateAssignment {
        first_assignment: usize,
        second_assignment: usize,
    },
    AuxiliaryNamespaceCollision {
        first_auxiliary: AtomId,
        greatest_input_atom: AtomId,
    },
    AuxiliaryNamespaceExhausted {
        first_auxiliary: AtomId,
        node_count: usize,
    },
    ArithmeticOverflow,
}

impl fmt::Display for CompileError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapExceeded {
                resource,
                limit,
                attempted,
            } => write!(
                output,
                "construction cap for {resource} is {limit}, attempted {attempted}"
            ),
            Self::InvalidOrderAtom { position, atom } => write!(
                output,
                "variable-order atom {atom} at position {position} is outside 1..={MAX_DIMACS_VARIABLE}"
            ),
            Self::DuplicateOrderAtom {
                atom,
                first_position,
                second_position,
            } => write!(
                output,
                "variable-order atom {atom} occurs at positions {first_position} and {second_position}"
            ),
            Self::AssignmentLength {
                assignment,
                expected,
                actual,
            } => write!(
                output,
                "assignment {assignment} has {actual} literals, expected {expected}"
            ),
            Self::InvalidLiteral {
                assignment,
                position,
                literal,
            } => write!(
                output,
                "assignment {assignment} has invalid literal {literal} at position {position}"
            ),
            Self::NonCanonicalAssignment {
                assignment,
                position,
                previous_atom,
                atom,
            } => write!(
                output,
                "assignment {assignment} is not in strictly increasing atom order at position {position}: {previous_atom} then {atom}"
            ),
            Self::WrongAssignmentAtom {
                assignment,
                position,
                expected,
                actual,
            } => write!(
                output,
                "assignment {assignment} has atom {actual} at canonical position {position}, expected {expected}"
            ),
            Self::DuplicateAssignment {
                first_assignment,
                second_assignment,
            } => write!(
                output,
                "assignments {first_assignment} and {second_assignment} are identical"
            ),
            Self::AuxiliaryNamespaceCollision {
                first_auxiliary,
                greatest_input_atom,
            } => write!(
                output,
                "first auxiliary {first_auxiliary} must be greater than input atom {greatest_input_atom}"
            ),
            Self::AuxiliaryNamespaceExhausted {
                first_auxiliary,
                node_count,
            } => write!(
                output,
                "{node_count} MDD nodes starting at auxiliary {first_auxiliary} exceed the DIMACS variable range"
            ),
            Self::ArithmeticOverflow => {
                output.write_str("arithmetic overflow during MDD construction")
            }
        }
    }
}

impl Error for CompileError {}

/// An outgoing MDD edge.  Terminal values are values of the forbidden-set
/// predicate, not satisfiability results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MddTarget {
    Terminal(bool),
    Node(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MddNode {
    pub auxiliary: AtomId,
    pub tested_atom: AtomId,
    pub when_false: MddTarget,
    pub when_true: MddTarget,
}

/// The single condition that rejects the forbidden predicate at the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootConstraint {
    /// The forbidden set is empty, so no root clause is necessary.
    Tautology,
    /// Every assignment is forbidden; the root clause is empty.
    Contradiction,
    /// A unit clause containing this signed literal is required.
    Literal(SignedAtomLiteral),
}

impl RootConstraint {
    pub fn append_clause(self, clauses: &mut Vec<Vec<SignedAtomLiteral>>) {
        match self {
            Self::Tautology => {}
            Self::Contradiction => clauses.push(Vec::new()),
            Self::Literal(literal) => clauses.push(vec![literal]),
        }
    }

    fn clause_count(self) -> usize {
        usize::from(!matches!(self, Self::Tautology))
    }

    fn literal_count(self) -> usize {
        usize::from(matches!(self, Self::Literal(_)))
    }
}

/// Counts refer to the final reduced MDD and to the complete CNF including the
/// separate root constraint.  Every nonterminal MDD node has exactly two edges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Telemetry {
    pub variables: usize,
    pub forbidden_assignments: usize,
    pub input_literals: usize,
    pub raw_forbidden_clauses: usize,
    pub raw_forbidden_literals: usize,
    pub trie_nodes: usize,
    pub eliminated_tests: usize,
    pub hash_cons_hits: usize,
    pub mdd_nodes: usize,
    pub mdd_edges: usize,
    pub definition_clauses: usize,
    pub root_clauses: usize,
    pub cnf_clauses: usize,
    pub cnf_literals: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledForbiddenMdd {
    pub variable_order: Vec<AtomId>,
    pub first_auxiliary: AtomId,
    /// Child node indices always precede their parents.
    pub nodes: Vec<MddNode>,
    /// Definitional clauses only; append `root_constraint` to enforce the root.
    pub definition_clauses: Vec<Vec<SignedAtomLiteral>>,
    pub root_constraint: RootConstraint,
    pub telemetry: Telemetry,
}

impl CompiledForbiddenMdd {
    pub fn clauses_with_root(&self) -> Vec<Vec<SignedAtomLiteral>> {
        let mut clauses = self.definition_clauses.clone();
        self.root_constraint.append_clause(&mut clauses);
        clauses
    }
}

#[derive(Debug, Clone, Copy)]
struct TrieNode {
    depth: usize,
    children: [Option<usize>; 2],
}

impl TrieNode {
    fn new(depth: usize) -> Self {
        Self {
            depth,
            children: [None, None],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum StateRef {
    False,
    True,
    Node(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct NodeKey {
    atom: AtomId,
    low: StateRef,
    high: StateRef,
}

#[derive(Debug, Clone, Copy)]
struct RawNode {
    atom: AtomId,
    low: StateRef,
    high: StateRef,
}

/// Compiles complete forbidden assignments under `variable_order`.
///
/// Each assignment must contain every ordered atom exactly once and must list
/// literals by increasing absolute atom ID, independent of `variable_order`.
/// `first_auxiliary` must be fresh for the caller's entire CNF namespace.
pub fn compile_forbidden_table_mdd(
    forbidden_assignments: &[Vec<SignedAtomLiteral>],
    variable_order: &[AtomId],
    first_auxiliary: AtomId,
    cap: ConstructionCap,
) -> Result<CompiledForbiddenMdd, CompileError> {
    check_cap(
        CappedResource::Variables,
        variable_order.len(),
        cap.max_variables,
    )?;
    check_cap(
        CappedResource::Assignments,
        forbidden_assignments.len(),
        cap.max_assignments,
    )?;

    let input_literals = forbidden_assignments
        .iter()
        .try_fold(0usize, |total, assignment| {
            total
                .checked_add(assignment.len())
                .ok_or(CompileError::ArithmeticOverflow)
        })?;
    check_cap(
        CappedResource::InputLiterals,
        input_literals,
        cap.max_input_literals,
    )?;

    let (canonical_atoms, order_positions, greatest_input_atom) =
        validate_variable_order(variable_order)?;
    if first_auxiliary == 0
        || first_auxiliary > MAX_DIMACS_VARIABLE
        || first_auxiliary <= greatest_input_atom
    {
        return Err(CompileError::AuxiliaryNamespaceCollision {
            first_auxiliary,
            greatest_input_atom,
        });
    }

    let mut indexed_patterns = Vec::with_capacity(forbidden_assignments.len());
    for (assignment_index, assignment) in forbidden_assignments.iter().enumerate() {
        if assignment.len() != variable_order.len() {
            return Err(CompileError::AssignmentLength {
                assignment: assignment_index,
                expected: variable_order.len(),
                actual: assignment.len(),
            });
        }

        let mut pattern = vec![false; variable_order.len()];
        let mut previous_atom = None;
        for (position, &literal) in assignment.iter().enumerate() {
            let atom = literal_atom(literal).ok_or(CompileError::InvalidLiteral {
                assignment: assignment_index,
                position,
                literal,
            })?;
            if let Some(previous) = previous_atom {
                if atom <= previous {
                    return Err(CompileError::NonCanonicalAssignment {
                        assignment: assignment_index,
                        position,
                        previous_atom: previous,
                        atom,
                    });
                }
            }
            previous_atom = Some(atom);
            let expected = canonical_atoms[position];
            if atom != expected {
                return Err(CompileError::WrongAssignmentAtom {
                    assignment: assignment_index,
                    position,
                    expected,
                    actual: atom,
                });
            }
            pattern[order_positions[&atom]] = literal > 0;
        }
        indexed_patterns.push((pattern, assignment_index));
    }

    indexed_patterns.sort_by(|left, right| left.0.cmp(&right.0));
    for duplicate in indexed_patterns.windows(2) {
        if duplicate[0].0 == duplicate[1].0 {
            return Err(CompileError::DuplicateAssignment {
                first_assignment: duplicate[0].1.min(duplicate[1].1),
                second_assignment: duplicate[0].1.max(duplicate[1].1),
            });
        }
    }
    let patterns = indexed_patterns
        .into_iter()
        .map(|(pattern, _)| pattern)
        .collect::<Vec<_>>();

    let (raw_nodes, root, trie_nodes, eliminated_tests, hash_cons_hits) =
        build_reduced_mdd(&patterns, variable_order, cap)?;
    validate_auxiliary_range(first_auxiliary, raw_nodes.len())?;

    let nodes = raw_nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            Ok(MddNode {
                auxiliary: auxiliary_at(first_auxiliary, index)?,
                tested_atom: node.atom,
                when_false: public_target(node.low),
                when_true: public_target(node.high),
            })
        })
        .collect::<Result<Vec<_>, CompileError>>()?;

    let mut definition_clauses = Vec::new();
    let mut cnf_literal_count = 0usize;
    for (index, node) in raw_nodes.iter().enumerate() {
        let atom = atom_literal(node.atom)?;
        let auxiliary = atom_literal(auxiliary_at(first_auxiliary, index)?)?;
        let low = cnf_term(node.low, first_auxiliary)?;
        let high = cnf_term(node.high, first_auxiliary)?;

        push_simplified_clause(
            &mut definition_clauses,
            &mut cnf_literal_count,
            vec![CnfTerm::Literal(-atom), CnfTerm::Literal(-auxiliary), high],
            cap,
        )?;
        push_simplified_clause(
            &mut definition_clauses,
            &mut cnf_literal_count,
            vec![
                CnfTerm::Literal(-atom),
                CnfTerm::Literal(auxiliary),
                high.negated(),
            ],
            cap,
        )?;
        push_simplified_clause(
            &mut definition_clauses,
            &mut cnf_literal_count,
            vec![CnfTerm::Literal(atom), CnfTerm::Literal(-auxiliary), low],
            cap,
        )?;
        push_simplified_clause(
            &mut definition_clauses,
            &mut cnf_literal_count,
            vec![
                CnfTerm::Literal(atom),
                CnfTerm::Literal(auxiliary),
                low.negated(),
            ],
            cap,
        )?;
    }

    let root_constraint = match root {
        StateRef::False => RootConstraint::Tautology,
        StateRef::True => RootConstraint::Contradiction,
        StateRef::Node(index) => {
            RootConstraint::Literal(-atom_literal(auxiliary_at(first_auxiliary, index)?)?)
        }
    };
    let root_clauses = root_constraint.clause_count();
    let root_literals = root_constraint.literal_count();
    check_cap(
        CappedResource::CnfClauses,
        definition_clauses
            .len()
            .checked_add(root_clauses)
            .ok_or(CompileError::ArithmeticOverflow)?,
        cap.max_cnf_clauses,
    )?;
    cnf_literal_count = cnf_literal_count
        .checked_add(root_literals)
        .ok_or(CompileError::ArithmeticOverflow)?;
    check_cap(
        CappedResource::CnfLiterals,
        cnf_literal_count,
        cap.max_cnf_literals,
    )?;

    let mdd_edges = raw_nodes
        .len()
        .checked_mul(2)
        .ok_or(CompileError::ArithmeticOverflow)?;
    let telemetry = Telemetry {
        variables: variable_order.len(),
        forbidden_assignments: forbidden_assignments.len(),
        input_literals,
        raw_forbidden_clauses: forbidden_assignments.len(),
        raw_forbidden_literals: input_literals,
        trie_nodes,
        eliminated_tests,
        hash_cons_hits,
        mdd_nodes: raw_nodes.len(),
        mdd_edges,
        definition_clauses: definition_clauses.len(),
        root_clauses,
        cnf_clauses: definition_clauses.len() + root_clauses,
        cnf_literals: cnf_literal_count,
    };

    Ok(CompiledForbiddenMdd {
        variable_order: variable_order.to_vec(),
        first_auxiliary,
        nodes,
        definition_clauses,
        root_constraint,
        telemetry,
    })
}

fn validate_variable_order(
    variable_order: &[AtomId],
) -> Result<(Vec<AtomId>, BTreeMap<AtomId, usize>, AtomId), CompileError> {
    let mut positions = BTreeMap::new();
    for (position, &atom) in variable_order.iter().enumerate() {
        if atom == 0 || atom > MAX_DIMACS_VARIABLE {
            return Err(CompileError::InvalidOrderAtom { position, atom });
        }
        if let Some(first_position) = positions.insert(atom, position) {
            return Err(CompileError::DuplicateOrderAtom {
                atom,
                first_position,
                second_position: position,
            });
        }
    }
    let canonical_atoms = positions.keys().copied().collect::<Vec<_>>();
    let greatest_input_atom = canonical_atoms.last().copied().unwrap_or(0);
    Ok((canonical_atoms, positions, greatest_input_atom))
}

fn literal_atom(literal: SignedAtomLiteral) -> Option<AtomId> {
    if literal == 0 || literal == i32::MIN {
        return None;
    }
    Some(literal.unsigned_abs())
}

fn build_reduced_mdd(
    patterns: &[Vec<bool>],
    variable_order: &[AtomId],
    cap: ConstructionCap,
) -> Result<(Vec<RawNode>, StateRef, usize, usize, usize), CompileError> {
    if patterns.is_empty() {
        return Ok((Vec::new(), StateRef::False, 0, 0, 0));
    }

    check_cap(CappedResource::TrieNodes, 1, cap.max_trie_nodes)?;
    let mut trie = vec![TrieNode::new(0)];
    for pattern in patterns {
        let mut current = 0usize;
        for (depth, &value) in pattern.iter().enumerate() {
            let branch = usize::from(value);
            let next = match trie[current].children[branch] {
                Some(next) => next,
                None => {
                    let attempted = trie
                        .len()
                        .checked_add(1)
                        .ok_or(CompileError::ArithmeticOverflow)?;
                    check_cap(CappedResource::TrieNodes, attempted, cap.max_trie_nodes)?;
                    let next = trie.len();
                    trie.push(TrieNode::new(depth + 1));
                    trie[current].children[branch] = Some(next);
                    next
                }
            };
            current = next;
        }
    }

    let mut states = vec![StateRef::False; trie.len()];
    let mut unique = BTreeMap::<NodeKey, StateRef>::new();
    let mut nodes = Vec::<RawNode>::new();
    let mut eliminated_tests = 0usize;
    let mut hash_cons_hits = 0usize;

    for trie_index in (0..trie.len()).rev() {
        let trie_node = trie[trie_index];
        if trie_node.depth == variable_order.len() {
            states[trie_index] = StateRef::True;
            continue;
        }

        let low = trie_node.children[0]
            .map(|child| states[child])
            .unwrap_or(StateRef::False);
        let high = trie_node.children[1]
            .map(|child| states[child])
            .unwrap_or(StateRef::False);
        if low == high {
            eliminated_tests += 1;
            states[trie_index] = low;
            continue;
        }

        let key = NodeKey {
            atom: variable_order[trie_node.depth],
            low,
            high,
        };
        if let Some(&prior) = unique.get(&key) {
            hash_cons_hits += 1;
            states[trie_index] = prior;
            continue;
        }

        let attempted_nodes = nodes
            .len()
            .checked_add(1)
            .ok_or(CompileError::ArithmeticOverflow)?;
        check_cap(CappedResource::MddNodes, attempted_nodes, cap.max_mdd_nodes)?;
        let attempted_edges = attempted_nodes
            .checked_mul(2)
            .ok_or(CompileError::ArithmeticOverflow)?;
        check_cap(CappedResource::MddEdges, attempted_edges, cap.max_mdd_edges)?;

        let state = StateRef::Node(nodes.len());
        nodes.push(RawNode {
            atom: key.atom,
            low: key.low,
            high: key.high,
        });
        unique.insert(key, state);
        states[trie_index] = state;
    }

    Ok((
        nodes,
        states[0],
        trie.len(),
        eliminated_tests,
        hash_cons_hits,
    ))
}

fn validate_auxiliary_range(
    first_auxiliary: AtomId,
    node_count: usize,
) -> Result<(), CompileError> {
    if node_count == 0 {
        return Ok(());
    }
    let offset = AtomId::try_from(node_count - 1).map_err(|_| {
        CompileError::AuxiliaryNamespaceExhausted {
            first_auxiliary,
            node_count,
        }
    })?;
    let last =
        first_auxiliary
            .checked_add(offset)
            .ok_or(CompileError::AuxiliaryNamespaceExhausted {
                first_auxiliary,
                node_count,
            })?;
    if last > MAX_DIMACS_VARIABLE {
        return Err(CompileError::AuxiliaryNamespaceExhausted {
            first_auxiliary,
            node_count,
        });
    }
    Ok(())
}

fn auxiliary_at(first_auxiliary: AtomId, index: usize) -> Result<AtomId, CompileError> {
    let offset = AtomId::try_from(index).map_err(|_| CompileError::ArithmeticOverflow)?;
    first_auxiliary
        .checked_add(offset)
        .ok_or(CompileError::ArithmeticOverflow)
}

fn atom_literal(atom: AtomId) -> Result<SignedAtomLiteral, CompileError> {
    SignedAtomLiteral::try_from(atom).map_err(|_| CompileError::ArithmeticOverflow)
}

fn public_target(state: StateRef) -> MddTarget {
    match state {
        StateRef::False => MddTarget::Terminal(false),
        StateRef::True => MddTarget::Terminal(true),
        StateRef::Node(node) => MddTarget::Node(node),
    }
}

#[derive(Debug, Clone, Copy)]
enum CnfTerm {
    Constant(bool),
    Literal(SignedAtomLiteral),
}

impl CnfTerm {
    fn negated(self) -> Self {
        match self {
            Self::Constant(value) => Self::Constant(!value),
            Self::Literal(literal) => Self::Literal(-literal),
        }
    }
}

fn cnf_term(state: StateRef, first_auxiliary: AtomId) -> Result<CnfTerm, CompileError> {
    match state {
        StateRef::False => Ok(CnfTerm::Constant(false)),
        StateRef::True => Ok(CnfTerm::Constant(true)),
        StateRef::Node(index) => Ok(CnfTerm::Literal(atom_literal(auxiliary_at(
            first_auxiliary,
            index,
        )?)?)),
    }
}

fn push_simplified_clause(
    clauses: &mut Vec<Vec<SignedAtomLiteral>>,
    literal_count: &mut usize,
    terms: Vec<CnfTerm>,
    cap: ConstructionCap,
) -> Result<(), CompileError> {
    let mut literals = Vec::with_capacity(terms.len());
    for term in terms {
        match term {
            CnfTerm::Constant(true) => return Ok(()),
            CnfTerm::Constant(false) => {}
            CnfTerm::Literal(literal) => {
                if literals.contains(&-literal) {
                    return Ok(());
                }
                if !literals.contains(&literal) {
                    literals.push(literal);
                }
            }
        }
    }
    literals.sort_by_key(|literal| (literal.unsigned_abs(), *literal < 0));

    let attempted_clauses = clauses
        .len()
        .checked_add(1)
        .ok_or(CompileError::ArithmeticOverflow)?;
    check_cap(
        CappedResource::CnfClauses,
        attempted_clauses,
        cap.max_cnf_clauses,
    )?;
    let attempted_literals = literal_count
        .checked_add(literals.len())
        .ok_or(CompileError::ArithmeticOverflow)?;
    check_cap(
        CappedResource::CnfLiterals,
        attempted_literals,
        cap.max_cnf_literals,
    )?;
    *literal_count = attempted_literals;
    clauses.push(literals);
    Ok(())
}

fn check_cap(resource: CappedResource, attempted: usize, limit: usize) -> Result<(), CompileError> {
    if attempted > limit {
        return Err(CompileError::CapExceeded {
            resource,
            limit,
            attempted,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn assignment_row(variable_count: usize, valuation: usize) -> Vec<SignedAtomLiteral> {
        (0..variable_count)
            .map(|offset| {
                let atom = SignedAtomLiteral::try_from(offset + 1).unwrap();
                if valuation & (1 << offset) == 0 {
                    -atom
                } else {
                    atom
                }
            })
            .collect()
    }

    fn raw_allows(forbidden: &[Vec<SignedAtomLiteral>], values: &BTreeMap<AtomId, bool>) -> bool {
        !forbidden.iter().any(|assignment| {
            assignment.iter().all(|&literal| {
                let value = values[&literal.unsigned_abs()];
                value == (literal > 0)
            })
        })
    }

    fn literal_value(
        literal: SignedAtomLiteral,
        atom_values: &BTreeMap<AtomId, bool>,
        compiled: &CompiledForbiddenMdd,
        auxiliary_mask: usize,
    ) -> bool {
        let variable = literal.unsigned_abs();
        let value = if variable >= compiled.first_auxiliary {
            let offset = usize::try_from(variable - compiled.first_auxiliary).unwrap();
            assert!(offset < compiled.nodes.len());
            auxiliary_mask & (1 << offset) != 0
        } else {
            atom_values[&variable]
        };
        value == (literal > 0)
    }

    fn cnf_allows(compiled: &CompiledForbiddenMdd, atom_values: &BTreeMap<AtomId, bool>) -> bool {
        assert!(compiled.nodes.len() < usize::BITS as usize);
        let clauses = compiled.clauses_with_root();
        (0..(1usize << compiled.nodes.len())).any(|auxiliary_mask| {
            clauses.iter().all(|clause| {
                clause
                    .iter()
                    .any(|&literal| literal_value(literal, atom_values, compiled, auxiliary_mask))
            })
        })
    }

    fn assert_truth_tables_equal(
        forbidden: &[Vec<SignedAtomLiteral>],
        order: &[AtomId],
        compiled: &CompiledForbiddenMdd,
    ) {
        let variable_count = order.len();
        assert!(variable_count < usize::BITS as usize);
        let mut canonical_atoms = order.to_vec();
        canonical_atoms.sort_unstable();
        for valuation in 0..(1usize << variable_count) {
            let values = canonical_atoms
                .iter()
                .enumerate()
                .map(|(offset, &atom)| (atom, valuation & (1 << offset) != 0))
                .collect::<BTreeMap<_, _>>();
            assert_eq!(
                cnf_allows(compiled, &values),
                raw_allows(forbidden, &values),
                "valuation {valuation:0width$b}, order {order:?}, forbidden {forbidden:?}",
                width = variable_count
            );
        }
    }

    #[test]
    fn exhaustive_all_forbidden_sets_through_three_variables() {
        for variable_count in 0..=3 {
            let assignment_count = 1usize << variable_count;
            let universe = (0..assignment_count)
                .map(|valuation| assignment_row(variable_count, valuation))
                .collect::<Vec<_>>();
            let order = match variable_count {
                0 => vec![],
                1 => vec![1],
                2 => vec![2, 1],
                3 => vec![2, 3, 1],
                _ => unreachable!(),
            };
            for forbidden_mask in 0..(1usize << assignment_count) {
                let forbidden = universe
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| forbidden_mask & (1 << index) != 0)
                    .map(|(_, assignment)| assignment.clone())
                    .collect::<Vec<_>>();
                let compiled = compile_forbidden_table_mdd(
                    &forbidden,
                    &order,
                    (variable_count + 1) as AtomId,
                    ConstructionCap::default(),
                )
                .unwrap();
                assert_truth_tables_equal(&forbidden, &order, &compiled);
            }
        }
    }

    #[test]
    fn permutation_orbit_set_is_deterministic_and_compressed() {
        // This is the complete S_5 orbit of the seed 11000 under atom relabeling.
        let mut orbit = (0usize..(1 << 5))
            .filter(|valuation| valuation.count_ones() == 2)
            .map(|valuation| assignment_row(5, valuation))
            .collect::<Vec<_>>();
        assert_eq!(orbit.len(), 10);
        let order = [5, 2, 4, 1, 3];
        let forward =
            compile_forbidden_table_mdd(&orbit, &order, 6, ConstructionCap::default()).unwrap();
        orbit.reverse();
        let reversed =
            compile_forbidden_table_mdd(&orbit, &order, 6, ConstructionCap::default()).unwrap();

        assert_eq!(forward, reversed);
        assert!(forward.telemetry.hash_cons_hits > 0);
        assert!(forward.telemetry.trie_nodes > forward.telemetry.mdd_nodes);
        assert_truth_tables_equal(&orbit, &order, &forward);
    }

    #[test]
    fn telemetry_matches_emitted_artifacts_and_topology() {
        let forbidden = vec![assignment_row(4, 1), assignment_row(4, 9)];
        let compiled =
            compile_forbidden_table_mdd(&forbidden, &[4, 2, 1, 3], 10, ConstructionCap::default())
                .unwrap();
        let all_clauses = compiled.clauses_with_root();

        assert_eq!(compiled.telemetry.mdd_nodes, compiled.nodes.len());
        assert_eq!(compiled.telemetry.mdd_edges, compiled.nodes.len() * 2);
        assert_eq!(compiled.telemetry.raw_forbidden_clauses, 2);
        assert_eq!(compiled.telemetry.raw_forbidden_literals, 8);
        assert_eq!(compiled.telemetry.cnf_clauses, all_clauses.len());
        assert_eq!(
            compiled.telemetry.cnf_literals,
            all_clauses.iter().map(Vec::len).sum::<usize>()
        );
        for (index, node) in compiled.nodes.iter().enumerate() {
            for target in [node.when_false, node.when_true] {
                if let MddTarget::Node(child) = target {
                    assert!(child < index);
                }
            }
        }
        assert_truth_tables_equal(&forbidden, &[4, 2, 1, 3], &compiled);
    }

    #[test]
    fn sparse_atom_ids_are_reordered_without_changing_row_canonicality() {
        let forbidden = vec![vec![-2, 7, -11], vec![2, -7, 11]];
        let order = [11, 2, 7];
        let compiled =
            compile_forbidden_table_mdd(&forbidden, &order, 20, ConstructionCap::default())
                .unwrap();

        assert_eq!(compiled.variable_order, order);
        assert!(
            compiled
                .nodes
                .iter()
                .all(|node| order.contains(&node.tested_atom))
        );
        assert_truth_tables_equal(&forbidden, &order, &compiled);
    }

    #[test]
    fn empty_and_complete_forbidden_sets_have_constant_roots() {
        let empty =
            compile_forbidden_table_mdd(&[], &[1, 2], 3, ConstructionCap::default()).unwrap();
        assert_eq!(empty.root_constraint, RootConstraint::Tautology);
        assert!(empty.nodes.is_empty());

        let complete = (0..4)
            .map(|valuation| assignment_row(2, valuation))
            .collect::<Vec<_>>();
        let compiled =
            compile_forbidden_table_mdd(&complete, &[1, 2], 3, ConstructionCap::default()).unwrap();
        assert_eq!(compiled.root_constraint, RootConstraint::Contradiction);
        assert!(compiled.nodes.is_empty());
        assert_eq!(compiled.clauses_with_root(), vec![Vec::<i32>::new()]);
        assert_truth_tables_equal(&complete, &[1, 2], &compiled);
    }

    #[test]
    fn malformed_or_noncanonical_inputs_fail_closed() {
        let cap = ConstructionCap::default();
        assert!(matches!(
            compile_forbidden_table_mdd(&[vec![1]], &[1, 2], 3, cap),
            Err(CompileError::AssignmentLength { .. })
        ));
        assert!(matches!(
            compile_forbidden_table_mdd(&[vec![1, -1]], &[1, 2], 3, cap),
            Err(CompileError::NonCanonicalAssignment { .. })
        ));
        assert!(matches!(
            compile_forbidden_table_mdd(&[vec![0]], &[1], 2, cap),
            Err(CompileError::InvalidLiteral { .. })
        ));
        assert!(matches!(
            compile_forbidden_table_mdd(&[vec![1, -3]], &[1, 2], 4, cap),
            Err(CompileError::WrongAssignmentAtom { .. })
        ));
        assert!(matches!(
            compile_forbidden_table_mdd(&[vec![-1], vec![-1]], &[1], 2, cap),
            Err(CompileError::DuplicateAssignment { .. })
        ));
        assert!(matches!(
            compile_forbidden_table_mdd(&[vec![-1]], &[1, 1], 2, cap),
            Err(CompileError::DuplicateOrderAtom { .. })
        ));
        assert!(matches!(
            compile_forbidden_table_mdd(&[vec![-1]], &[1], 1, cap),
            Err(CompileError::AuxiliaryNamespaceCollision { .. })
        ));
    }

    #[test]
    fn every_construction_stage_obeys_its_cap() {
        let forbidden = vec![assignment_row(3, 0)];

        let mut cap = ConstructionCap::default();
        cap.max_input_literals = 2;
        assert!(matches!(
            compile_forbidden_table_mdd(&forbidden, &[1, 2, 3], 4, cap),
            Err(CompileError::CapExceeded {
                resource: CappedResource::InputLiterals,
                ..
            })
        ));

        let mut cap = ConstructionCap::default();
        cap.max_trie_nodes = 3;
        assert!(matches!(
            compile_forbidden_table_mdd(&forbidden, &[1, 2, 3], 4, cap),
            Err(CompileError::CapExceeded {
                resource: CappedResource::TrieNodes,
                ..
            })
        ));

        let mut cap = ConstructionCap::default();
        cap.max_mdd_nodes = 2;
        assert!(matches!(
            compile_forbidden_table_mdd(&forbidden, &[1, 2, 3], 4, cap),
            Err(CompileError::CapExceeded {
                resource: CappedResource::MddNodes,
                ..
            })
        ));

        let mut cap = ConstructionCap::default();
        cap.max_cnf_clauses = 0;
        assert!(matches!(
            compile_forbidden_table_mdd(&forbidden, &[1, 2, 3], 4, cap),
            Err(CompileError::CapExceeded {
                resource: CappedResource::CnfClauses,
                ..
            })
        ));

        let mut cap = ConstructionCap::default();
        cap.max_cnf_literals = 0;
        assert!(matches!(
            compile_forbidden_table_mdd(&forbidden, &[1, 2, 3], 4, cap),
            Err(CompileError::CapExceeded {
                resource: CappedResource::CnfLiterals,
                ..
            })
        ));
    }

    #[test]
    fn auxiliary_namespace_exhaustion_fails_before_emission() {
        let forbidden = vec![vec![-1]];
        assert!(matches!(
            compile_forbidden_table_mdd(
                &forbidden,
                &[1],
                MAX_DIMACS_VARIABLE,
                ConstructionCap::default()
            ),
            Ok(_)
        ));

        let forbidden = vec![vec![-1, -2]];
        assert!(matches!(
            compile_forbidden_table_mdd(
                &forbidden,
                &[1, 2],
                MAX_DIMACS_VARIABLE,
                ConstructionCap::default()
            ),
            Err(CompileError::AuxiliaryNamespaceExhausted { .. })
        ));
    }
}
