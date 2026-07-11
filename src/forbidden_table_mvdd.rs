//! Deterministic reduced multi-valued decision diagrams for forbidden tables.
//!
//! A forbidden row is a complete operation-table assignment: `row[cell]` is a
//! value in `0..degree`.  `one_hot_atoms[cell][value]` gives the caller-owned
//! DIMACS atom for that equality.  The emitted CNF is equisatisfiable with the
//! raw forbidden-row clauses **only under the precondition that, for every
//! cell, exactly one atom in `one_hot_atoms[cell]` is true**.  This module does
//! not emit those exactly-one constraints; a caller may already have stronger
//! finite-domain constraints and must establish the precondition separately.
//!
//! Every MVDD auxiliary defines the forbidden-suffix predicate at one cell.
//! Equal suffix states are hash-consed, tests with identical successors are
//! removed, and a separate root constraint rejects the forbidden predicate.
//! The compiler is self-contained and intentionally not wired into production.
//!
//! ```text
//! rustc --edition=2021 -O -D warnings --test src/forbidden_table_mvdd.rs
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

pub type AtomId = u32;
pub type SignedAtomLiteral = i32;

const MAX_DIMACS_VARIABLE: AtomId = i32::MAX as AtomId;
const MAX_REPRESENTABLE_DEGREE: usize = (u8::MAX as usize) + 1;

/// Fail-closed limits for input, intermediate, and emitted structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstructionCap {
    pub max_cells: usize,
    pub max_degree: usize,
    pub max_forbidden_rows: usize,
    pub max_input_values: usize,
    pub max_mapping_atoms: usize,
    pub max_trie_nodes: usize,
    pub max_trie_edges: usize,
    pub max_mvdd_nodes: usize,
    pub max_mvdd_edges: usize,
    pub max_cnf_clauses: usize,
    pub max_cnf_literals: usize,
}

impl Default for ConstructionCap {
    fn default() -> Self {
        Self {
            max_cells: 4_096,
            max_degree: MAX_REPRESENTABLE_DEGREE,
            max_forbidden_rows: 1_000_000,
            max_input_values: 100_000_000,
            max_mapping_atoms: 1_048_576,
            max_trie_nodes: 10_000_000,
            max_trie_edges: 10_000_000,
            max_mvdd_nodes: 2_000_000,
            max_mvdd_edges: 16_000_000,
            max_cnf_clauses: 32_000_001,
            max_cnf_literals: 96_000_001,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CappedResource {
    Cells,
    Degree,
    ForbiddenRows,
    InputValues,
    MappingAtoms,
    TrieNodes,
    TrieEdges,
    MvddNodes,
    MvddEdges,
    CnfClauses,
    CnfLiterals,
}

impl fmt::Display for CappedResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Cells => "cells",
            Self::Degree => "degree",
            Self::ForbiddenRows => "forbidden rows",
            Self::InputValues => "input values",
            Self::MappingAtoms => "one-hot mapping atoms",
            Self::TrieNodes => "trie nodes",
            Self::TrieEdges => "trie edges",
            Self::MvddNodes => "MVDD nodes",
            Self::MvddEdges => "MVDD edges",
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
    InvalidDegree {
        degree: usize,
        maximum: usize,
    },
    CellOrderLength {
        expected: usize,
        actual: usize,
    },
    InvalidOrderCell {
        position: usize,
        cell: usize,
        cell_count: usize,
    },
    DuplicateOrderCell {
        cell: usize,
        first_position: usize,
        second_position: usize,
    },
    MappingCellCount {
        expected: usize,
        actual: usize,
    },
    MappingDegree {
        cell: usize,
        expected: usize,
        actual: usize,
    },
    InvalidMappingAtom {
        cell: usize,
        value: usize,
        atom: AtomId,
    },
    DuplicateMappingAtom {
        atom: AtomId,
        first_cell: usize,
        first_value: usize,
        second_cell: usize,
        second_value: usize,
    },
    RowLength {
        row: usize,
        expected: usize,
        actual: usize,
    },
    RowValueOutOfRange {
        row: usize,
        cell: usize,
        value: u8,
        degree: usize,
    },
    DuplicateRow {
        first_row: usize,
        second_row: usize,
    },
    AuxiliaryNamespaceCollision {
        first_auxiliary: AtomId,
        greatest_mapping_atom: AtomId,
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
            Self::InvalidDegree { degree, maximum } => write!(
                output,
                "degree {degree} is invalid for u8 rows; expected 1..={maximum}"
            ),
            Self::CellOrderLength { expected, actual } => write!(
                output,
                "cell order has length {actual}, expected {expected}"
            ),
            Self::InvalidOrderCell {
                position,
                cell,
                cell_count,
            } => write!(
                output,
                "cell-order entry {cell} at position {position} is outside 0..{cell_count}"
            ),
            Self::DuplicateOrderCell {
                cell,
                first_position,
                second_position,
            } => write!(
                output,
                "cell {cell} occurs at order positions {first_position} and {second_position}"
            ),
            Self::MappingCellCount { expected, actual } => write!(
                output,
                "one-hot mapping has {actual} cells, expected {expected}"
            ),
            Self::MappingDegree {
                cell,
                expected,
                actual,
            } => write!(
                output,
                "one-hot mapping for cell {cell} has {actual} values, expected {expected}"
            ),
            Self::InvalidMappingAtom { cell, value, atom } => write!(
                output,
                "one-hot atom {atom} for cell {cell}, value {value} is outside 1..={MAX_DIMACS_VARIABLE}"
            ),
            Self::DuplicateMappingAtom {
                atom,
                first_cell,
                first_value,
                second_cell,
                second_value,
            } => write!(
                output,
                "one-hot atom {atom} is shared by ({first_cell}, {first_value}) and ({second_cell}, {second_value})"
            ),
            Self::RowLength {
                row,
                expected,
                actual,
            } => write!(
                output,
                "forbidden row {row} has length {actual}, expected {expected}"
            ),
            Self::RowValueOutOfRange {
                row,
                cell,
                value,
                degree,
            } => write!(
                output,
                "forbidden row {row} has value {value} at cell {cell}, outside 0..{degree}"
            ),
            Self::DuplicateRow {
                first_row,
                second_row,
            } => write!(
                output,
                "forbidden rows {first_row} and {second_row} are identical"
            ),
            Self::AuxiliaryNamespaceCollision {
                first_auxiliary,
                greatest_mapping_atom,
            } => write!(
                output,
                "first auxiliary {first_auxiliary} must be greater than one-hot atom {greatest_mapping_atom}"
            ),
            Self::AuxiliaryNamespaceExhausted {
                first_auxiliary,
                node_count,
            } => write!(
                output,
                "{node_count} MVDD nodes starting at auxiliary {first_auxiliary} exceed the DIMACS range"
            ),
            Self::ArithmeticOverflow => {
                output.write_str("arithmetic overflow during MVDD construction")
            }
        }
    }
}

impl Error for CompileError {}

/// A branch target.  Terminal values denote the forbidden-suffix predicate,
/// not the final satisfiability result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MvddTarget {
    Terminal(bool),
    Node(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MvddNode {
    pub auxiliary: AtomId,
    pub tested_cell: usize,
    /// One branch for every value in `0..degree`.
    pub branches: Vec<MvddTarget>,
}

/// The condition that rejects the forbidden predicate at the MVDD root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootConstraint {
    /// No rows are forbidden.
    Tautology,
    /// Every complete row is forbidden.
    Contradiction,
    /// A unit clause containing this literal is required.
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

/// Exact counts for the accepted input, reduced graph, and emitted CNF.
/// `mvdd_edges` counts all `degree` outgoing branches of each retained node.
/// CNF counts include the root constraint but exclude the caller-owned
/// exactly-one precondition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Telemetry {
    pub cells: usize,
    pub degree: usize,
    pub forbidden_rows: usize,
    pub input_values: usize,
    pub mapping_atoms: usize,
    pub raw_forbidden_clauses: usize,
    pub raw_forbidden_literals: usize,
    pub trie_nodes: usize,
    pub trie_edges: usize,
    pub eliminated_tests: usize,
    pub hash_cons_hits: usize,
    pub mvdd_nodes: usize,
    pub mvdd_edges: usize,
    pub definition_clauses: usize,
    pub root_clauses: usize,
    pub cnf_clauses: usize,
    pub cnf_literals: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledForbiddenMvdd {
    pub cell_count: usize,
    pub degree: usize,
    pub cell_order: Vec<usize>,
    pub one_hot_atoms: Vec<Vec<AtomId>>,
    pub first_auxiliary: AtomId,
    /// Child node indices always precede their parents.
    pub nodes: Vec<MvddNode>,
    /// Definitional clauses only.  They rely on the exactly-one precondition.
    pub definition_clauses: Vec<Vec<SignedAtomLiteral>>,
    pub root_constraint: RootConstraint,
    pub telemetry: Telemetry,
}

impl CompiledForbiddenMvdd {
    /// Returns the MVDD definitions followed by the root rejection constraint.
    /// The caller must additionally enforce exactly one mapped atom per cell.
    pub fn clauses_with_root(&self) -> Vec<Vec<SignedAtomLiteral>> {
        let mut clauses = self.definition_clauses.clone();
        self.root_constraint.append_clause(&mut clauses);
        clauses
    }
}

#[derive(Debug, Clone)]
struct TrieNode {
    depth: usize,
    children: BTreeMap<u8, usize>,
}

impl TrieNode {
    fn new(depth: usize) -> Self {
        Self {
            depth,
            children: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum StateRef {
    False,
    True,
    Node(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NodeKey {
    cell: usize,
    branches: Vec<StateRef>,
}

#[derive(Debug, Clone)]
struct RawNode {
    cell: usize,
    branches: Vec<StateRef>,
}

/// Compiles complete forbidden operation-table rows into a reduced MVDD CNF.
///
/// `cell_order` must be a permutation of `0..cell_count`, and
/// `one_hot_atoms` must have shape `[cell_count][degree]` with globally unique,
/// nonzero DIMACS atoms.  `first_auxiliary` must be fresh for the caller's
/// entire namespace.
///
/// # Exactly-one precondition
///
/// For each cell, exactly one atom in `one_hot_atoms[cell]` must be true.  The
/// returned CNF does not encode that condition.  Subject to it, the CNF plus
/// its root constraint is satisfiable exactly for complete rows not listed in
/// `forbidden_rows`.
pub fn compile_forbidden_table_mvdd(
    forbidden_rows: &[Vec<u8>],
    cell_count: usize,
    degree: usize,
    cell_order: &[usize],
    one_hot_atoms: &[Vec<AtomId>],
    first_auxiliary: AtomId,
    cap: ConstructionCap,
) -> Result<CompiledForbiddenMvdd, CompileError> {
    check_cap(CappedResource::Cells, cell_count, cap.max_cells)?;
    if degree == 0 || degree > MAX_REPRESENTABLE_DEGREE {
        return Err(CompileError::InvalidDegree {
            degree,
            maximum: MAX_REPRESENTABLE_DEGREE,
        });
    }
    check_cap(CappedResource::Degree, degree, cap.max_degree)?;
    check_cap(
        CappedResource::ForbiddenRows,
        forbidden_rows.len(),
        cap.max_forbidden_rows,
    )?;

    let input_values = forbidden_rows.iter().try_fold(0usize, |total, row| {
        total
            .checked_add(row.len())
            .ok_or(CompileError::ArithmeticOverflow)
    })?;
    check_cap(
        CappedResource::InputValues,
        input_values,
        cap.max_input_values,
    )?;
    let mapping_atoms = cell_count
        .checked_mul(degree)
        .ok_or(CompileError::ArithmeticOverflow)?;
    check_cap(
        CappedResource::MappingAtoms,
        mapping_atoms,
        cap.max_mapping_atoms,
    )?;

    validate_cell_order(cell_count, cell_order)?;
    let greatest_mapping_atom = validate_atom_mapping(cell_count, degree, one_hot_atoms)?;
    if first_auxiliary == 0
        || first_auxiliary > MAX_DIMACS_VARIABLE
        || first_auxiliary <= greatest_mapping_atom
    {
        return Err(CompileError::AuxiliaryNamespaceCollision {
            first_auxiliary,
            greatest_mapping_atom,
        });
    }

    let mut indexed_patterns = Vec::with_capacity(forbidden_rows.len());
    for (row_index, row) in forbidden_rows.iter().enumerate() {
        if row.len() != cell_count {
            return Err(CompileError::RowLength {
                row: row_index,
                expected: cell_count,
                actual: row.len(),
            });
        }
        for (cell, &value) in row.iter().enumerate() {
            if usize::from(value) >= degree {
                return Err(CompileError::RowValueOutOfRange {
                    row: row_index,
                    cell,
                    value,
                    degree,
                });
            }
        }
        let pattern = cell_order.iter().map(|&cell| row[cell]).collect::<Vec<_>>();
        indexed_patterns.push((pattern, row_index));
    }
    indexed_patterns.sort_by(|left, right| left.0.cmp(&right.0));
    for duplicate in indexed_patterns.windows(2) {
        if duplicate[0].0 == duplicate[1].0 {
            return Err(CompileError::DuplicateRow {
                first_row: duplicate[0].1.min(duplicate[1].1),
                second_row: duplicate[0].1.max(duplicate[1].1),
            });
        }
    }
    let patterns = indexed_patterns
        .into_iter()
        .map(|(pattern, _)| pattern)
        .collect::<Vec<_>>();

    let (raw_nodes, root, trie_nodes, trie_edges, eliminated_tests, hash_cons_hits) =
        build_reduced_mvdd(&patterns, degree, cell_order, cap)?;
    validate_auxiliary_range(first_auxiliary, raw_nodes.len())?;

    let nodes = raw_nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            Ok(MvddNode {
                auxiliary: auxiliary_at(first_auxiliary, index)?,
                tested_cell: node.cell,
                branches: node.branches.iter().copied().map(public_target).collect(),
            })
        })
        .collect::<Result<Vec<_>, CompileError>>()?;

    let mut definition_clauses = Vec::new();
    let mut cnf_literal_count = 0usize;
    for (index, node) in raw_nodes.iter().enumerate() {
        let auxiliary = atom_literal(auxiliary_at(first_auxiliary, index)?)?;
        for (value, &child) in node.branches.iter().enumerate() {
            let selected = atom_literal(one_hot_atoms[node.cell][value])?;
            let child = cnf_term(child, first_auxiliary)?;
            // Under selected(cell,value), auxiliary iff the chosen child.
            push_simplified_clause(
                &mut definition_clauses,
                &mut cnf_literal_count,
                vec![
                    CnfTerm::Literal(-selected),
                    CnfTerm::Literal(-auxiliary),
                    child,
                ],
                cap,
            )?;
            push_simplified_clause(
                &mut definition_clauses,
                &mut cnf_literal_count,
                vec![
                    CnfTerm::Literal(-selected),
                    CnfTerm::Literal(auxiliary),
                    child.negated(),
                ],
                cap,
            )?;
        }
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
    let cnf_clauses = definition_clauses
        .len()
        .checked_add(root_clauses)
        .ok_or(CompileError::ArithmeticOverflow)?;
    check_cap(CappedResource::CnfClauses, cnf_clauses, cap.max_cnf_clauses)?;
    cnf_literal_count = cnf_literal_count
        .checked_add(root_literals)
        .ok_or(CompileError::ArithmeticOverflow)?;
    check_cap(
        CappedResource::CnfLiterals,
        cnf_literal_count,
        cap.max_cnf_literals,
    )?;

    let raw_forbidden_literals = forbidden_rows
        .len()
        .checked_mul(cell_count)
        .ok_or(CompileError::ArithmeticOverflow)?;
    let mvdd_edges = raw_nodes
        .len()
        .checked_mul(degree)
        .ok_or(CompileError::ArithmeticOverflow)?;
    let telemetry = Telemetry {
        cells: cell_count,
        degree,
        forbidden_rows: forbidden_rows.len(),
        input_values,
        mapping_atoms,
        raw_forbidden_clauses: forbidden_rows.len(),
        raw_forbidden_literals,
        trie_nodes,
        trie_edges,
        eliminated_tests,
        hash_cons_hits,
        mvdd_nodes: raw_nodes.len(),
        mvdd_edges,
        definition_clauses: definition_clauses.len(),
        root_clauses,
        cnf_clauses,
        cnf_literals: cnf_literal_count,
    };

    Ok(CompiledForbiddenMvdd {
        cell_count,
        degree,
        cell_order: cell_order.to_vec(),
        one_hot_atoms: one_hot_atoms.to_vec(),
        first_auxiliary,
        nodes,
        definition_clauses,
        root_constraint,
        telemetry,
    })
}

fn validate_cell_order(cell_count: usize, cell_order: &[usize]) -> Result<(), CompileError> {
    if cell_order.len() != cell_count {
        return Err(CompileError::CellOrderLength {
            expected: cell_count,
            actual: cell_order.len(),
        });
    }
    let mut positions = BTreeMap::new();
    for (position, &cell) in cell_order.iter().enumerate() {
        if cell >= cell_count {
            return Err(CompileError::InvalidOrderCell {
                position,
                cell,
                cell_count,
            });
        }
        if let Some(first_position) = positions.insert(cell, position) {
            return Err(CompileError::DuplicateOrderCell {
                cell,
                first_position,
                second_position: position,
            });
        }
    }
    Ok(())
}

fn validate_atom_mapping(
    cell_count: usize,
    degree: usize,
    one_hot_atoms: &[Vec<AtomId>],
) -> Result<AtomId, CompileError> {
    if one_hot_atoms.len() != cell_count {
        return Err(CompileError::MappingCellCount {
            expected: cell_count,
            actual: one_hot_atoms.len(),
        });
    }
    let mut seen = BTreeMap::<AtomId, (usize, usize)>::new();
    let mut greatest = 0;
    for (cell, atoms) in one_hot_atoms.iter().enumerate() {
        if atoms.len() != degree {
            return Err(CompileError::MappingDegree {
                cell,
                expected: degree,
                actual: atoms.len(),
            });
        }
        for (value, &atom) in atoms.iter().enumerate() {
            if atom == 0 || atom > MAX_DIMACS_VARIABLE {
                return Err(CompileError::InvalidMappingAtom { cell, value, atom });
            }
            if let Some(&(first_cell, first_value)) = seen.get(&atom) {
                return Err(CompileError::DuplicateMappingAtom {
                    atom,
                    first_cell,
                    first_value,
                    second_cell: cell,
                    second_value: value,
                });
            }
            seen.insert(atom, (cell, value));
            greatest = greatest.max(atom);
        }
    }
    Ok(greatest)
}

fn build_reduced_mvdd(
    patterns: &[Vec<u8>],
    degree: usize,
    cell_order: &[usize],
    cap: ConstructionCap,
) -> Result<(Vec<RawNode>, StateRef, usize, usize, usize, usize), CompileError> {
    if patterns.is_empty() {
        return Ok((Vec::new(), StateRef::False, 0, 0, 0, 0));
    }

    check_cap(CappedResource::TrieNodes, 1, cap.max_trie_nodes)?;
    let mut trie = vec![TrieNode::new(0)];
    let mut trie_edges = 0usize;
    for pattern in patterns {
        let mut current = 0usize;
        for (depth, &value) in pattern.iter().enumerate() {
            let next = match trie[current].children.get(&value).copied() {
                Some(next) => next,
                None => {
                    let attempted_nodes = trie
                        .len()
                        .checked_add(1)
                        .ok_or(CompileError::ArithmeticOverflow)?;
                    check_cap(
                        CappedResource::TrieNodes,
                        attempted_nodes,
                        cap.max_trie_nodes,
                    )?;
                    let attempted_edges = trie_edges
                        .checked_add(1)
                        .ok_or(CompileError::ArithmeticOverflow)?;
                    check_cap(
                        CappedResource::TrieEdges,
                        attempted_edges,
                        cap.max_trie_edges,
                    )?;
                    let next = trie.len();
                    trie.push(TrieNode::new(depth + 1));
                    trie[current].children.insert(value, next);
                    trie_edges = attempted_edges;
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
        let trie_node = &trie[trie_index];
        if trie_node.depth == cell_order.len() {
            states[trie_index] = StateRef::True;
            continue;
        }

        let branches = (0..degree)
            .map(|value| {
                trie_node
                    .children
                    .get(&(value as u8))
                    .map(|&child| states[child])
                    .unwrap_or(StateRef::False)
            })
            .collect::<Vec<_>>();
        if branches.iter().all(|&branch| branch == branches[0]) {
            eliminated_tests += 1;
            states[trie_index] = branches[0];
            continue;
        }

        let key = NodeKey {
            cell: cell_order[trie_node.depth],
            branches,
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
        check_cap(
            CappedResource::MvddNodes,
            attempted_nodes,
            cap.max_mvdd_nodes,
        )?;
        let attempted_edges = attempted_nodes
            .checked_mul(degree)
            .ok_or(CompileError::ArithmeticOverflow)?;
        check_cap(
            CappedResource::MvddEdges,
            attempted_edges,
            cap.max_mvdd_edges,
        )?;

        let state = StateRef::Node(nodes.len());
        nodes.push(RawNode {
            cell: key.cell,
            branches: key.branches.clone(),
        });
        unique.insert(key, state);
        states[trie_index] = state;
    }

    Ok((
        nodes,
        states[0],
        trie.len(),
        trie_edges,
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

fn public_target(state: StateRef) -> MvddTarget {
    match state {
        StateRef::False => MvddTarget::Terminal(false),
        StateRef::True => MvddTarget::Terminal(true),
        StateRef::Node(node) => MvddTarget::Node(node),
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

/// Independent limits for the exhaustive semantic checker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EquivalenceCheckCap {
    pub max_complete_tables: usize,
    pub max_dpll_decisions: usize,
}

impl Default for EquivalenceCheckCap {
    fn default() -> Self {
        Self {
            max_complete_tables: 100_000,
            max_dpll_decisions: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EquivalenceTelemetry {
    pub complete_tables_checked: usize,
    pub exactly_one_cells_checked: usize,
    pub raw_allowed: usize,
    pub raw_rejected: usize,
    pub cnf_allowed: usize,
    pub cnf_rejected: usize,
    pub dpll_decisions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EquivalenceError {
    TableSpaceCapExceeded {
        limit: usize,
        attempted: usize,
    },
    DecisionCapExceeded {
        limit: usize,
        attempted: usize,
    },
    RebuildFailed(CompileError),
    ArtifactMismatch,
    UnknownCnfAtom {
        atom: AtomId,
    },
    SemanticMismatch {
        table: Vec<u8>,
        raw_allows: bool,
        cnf_allows: bool,
    },
    ArithmeticOverflow,
}

impl fmt::Display for EquivalenceError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TableSpaceCapExceeded { limit, attempted } => write!(
                output,
                "exhaustive table cap is {limit}, attempted {attempted}"
            ),
            Self::DecisionCapExceeded { limit, attempted } => write!(
                output,
                "DPLL decision cap is {limit}, attempted {attempted}"
            ),
            Self::RebuildFailed(error) => write!(output, "artifact rebuild failed: {error}"),
            Self::ArtifactMismatch => {
                output.write_str("compiled artifact differs from deterministic rebuild")
            }
            Self::UnknownCnfAtom { atom } => {
                write!(output, "CNF contains unmapped atom {atom}")
            }
            Self::SemanticMismatch {
                table,
                raw_allows,
                cnf_allows,
            } => write!(
                output,
                "semantic mismatch for table {table:?}: raw={raw_allows}, CNF={cnf_allows}"
            ),
            Self::ArithmeticOverflow => {
                output.write_str("arithmetic overflow during exhaustive checking")
            }
        }
    }
}

impl Error for EquivalenceError {}

/// Exhaustively checks raw forbidden-row semantics against the emitted CNF.
///
/// This checker is intended for small `degree^cell_count` instances.  It
/// enumerates complete tables, fixes exactly one mapped atom true at every cell
/// (and every other mapped atom false), then independently checks whether some
/// auxiliary assignment satisfies the definitions and root constraint.
pub fn exhaustively_check_one_hot_equivalence(
    forbidden_rows: &[Vec<u8>],
    compiled: &CompiledForbiddenMvdd,
    cap: EquivalenceCheckCap,
) -> Result<EquivalenceTelemetry, EquivalenceError> {
    let mut table_count = 1usize;
    for _ in 0..compiled.cell_count {
        table_count = table_count
            .checked_mul(compiled.degree)
            .ok_or(EquivalenceError::ArithmeticOverflow)?;
        if table_count > cap.max_complete_tables {
            return Err(EquivalenceError::TableSpaceCapExceeded {
                limit: cap.max_complete_tables,
                attempted: table_count,
            });
        }
    }

    let rebuilt = compile_forbidden_table_mvdd(
        forbidden_rows,
        compiled.cell_count,
        compiled.degree,
        &compiled.cell_order,
        &compiled.one_hot_atoms,
        compiled.first_auxiliary,
        unlimited_construction_cap(),
    )
    .map_err(EquivalenceError::RebuildFailed)?;
    if rebuilt != *compiled {
        return Err(EquivalenceError::ArtifactMismatch);
    }

    let forbidden = forbidden_rows.iter().cloned().collect::<BTreeSet<_>>();
    let clauses = compiled.clauses_with_root();
    let mut telemetry = EquivalenceTelemetry::default();
    let mut table = vec![0u8; compiled.cell_count];
    for ordinal in 0..table_count {
        let mut remainder = ordinal;
        for value in &mut table {
            *value = u8::try_from(remainder % compiled.degree)
                .map_err(|_| EquivalenceError::ArithmeticOverflow)?;
            remainder /= compiled.degree;
        }

        let mut fixed_atoms = BTreeMap::<AtomId, bool>::new();
        for (cell, atoms) in compiled.one_hot_atoms.iter().enumerate() {
            let chosen = usize::from(table[cell]);
            let mut true_count = 0usize;
            for (value, &atom) in atoms.iter().enumerate() {
                let selected = value == chosen;
                true_count += usize::from(selected);
                fixed_atoms.insert(atom, selected);
            }
            if true_count != 1 {
                return Err(EquivalenceError::ArtifactMismatch);
            }
        }

        let raw_allows = !forbidden.contains(&table);
        let cnf_allows = cnf_satisfiable_with_fixed_atoms(
            &clauses,
            &fixed_atoms,
            compiled.first_auxiliary,
            compiled.nodes.len(),
            &mut telemetry.dpll_decisions,
            cap.max_dpll_decisions,
        )?;
        if raw_allows != cnf_allows {
            return Err(EquivalenceError::SemanticMismatch {
                table: table.clone(),
                raw_allows,
                cnf_allows,
            });
        }

        telemetry.complete_tables_checked += 1;
        telemetry.exactly_one_cells_checked = telemetry
            .exactly_one_cells_checked
            .checked_add(compiled.cell_count)
            .ok_or(EquivalenceError::ArithmeticOverflow)?;
        if raw_allows {
            telemetry.raw_allowed += 1;
        } else {
            telemetry.raw_rejected += 1;
        }
        if cnf_allows {
            telemetry.cnf_allowed += 1;
        } else {
            telemetry.cnf_rejected += 1;
        }
    }
    Ok(telemetry)
}

fn unlimited_construction_cap() -> ConstructionCap {
    ConstructionCap {
        max_cells: usize::MAX,
        max_degree: usize::MAX,
        max_forbidden_rows: usize::MAX,
        max_input_values: usize::MAX,
        max_mapping_atoms: usize::MAX,
        max_trie_nodes: usize::MAX,
        max_trie_edges: usize::MAX,
        max_mvdd_nodes: usize::MAX,
        max_mvdd_edges: usize::MAX,
        max_cnf_clauses: usize::MAX,
        max_cnf_literals: usize::MAX,
    }
}

fn cnf_satisfiable_with_fixed_atoms(
    clauses: &[Vec<SignedAtomLiteral>],
    fixed_atoms: &BTreeMap<AtomId, bool>,
    first_auxiliary: AtomId,
    auxiliary_count: usize,
    decisions: &mut usize,
    decision_limit: usize,
) -> Result<bool, EquivalenceError> {
    let mut reduced = Vec::<Vec<SignedAtomLiteral>>::with_capacity(clauses.len());
    for clause in clauses {
        let mut reduced_clause = Vec::new();
        let mut satisfied = false;
        for &literal in clause {
            let atom = literal.unsigned_abs();
            if let Some(&value) = fixed_atoms.get(&atom) {
                if value == (literal > 0) {
                    satisfied = true;
                    break;
                }
                continue;
            }
            let offset = atom.checked_sub(first_auxiliary).and_then(|difference| {
                let offset = usize::try_from(difference).ok()?;
                (offset < auxiliary_count).then_some(offset)
            });
            let Some(offset) = offset else {
                return Err(EquivalenceError::UnknownCnfAtom { atom });
            };
            let local_atom = SignedAtomLiteral::try_from(offset + 1)
                .map_err(|_| EquivalenceError::ArithmeticOverflow)?;
            reduced_clause.push(if literal > 0 { local_atom } else { -local_atom });
        }
        if !satisfied {
            reduced.push(reduced_clause);
        }
    }

    let mut assignment = vec![0i8; auxiliary_count];
    dpll(&reduced, &mut assignment, decisions, decision_limit)
}

fn dpll(
    clauses: &[Vec<SignedAtomLiteral>],
    assignment: &mut [i8],
    decisions: &mut usize,
    decision_limit: usize,
) -> Result<bool, EquivalenceError> {
    loop {
        let mut changed = false;
        for clause in clauses {
            let mut satisfied = false;
            let mut unit = None;
            let mut unassigned = 0usize;
            for &literal in clause {
                let variable = usize::try_from(literal.unsigned_abs())
                    .map_err(|_| EquivalenceError::ArithmeticOverflow)?
                    - 1;
                match assignment[variable] {
                    0 => {
                        unassigned += 1;
                        unit = Some(literal);
                    }
                    value if (value > 0) == (literal > 0) => {
                        satisfied = true;
                        break;
                    }
                    _ => {}
                }
            }
            if satisfied {
                continue;
            }
            if unassigned == 0 {
                return Ok(false);
            }
            if unassigned == 1 {
                let literal = unit.expect("unit literal must exist");
                let variable = usize::try_from(literal.unsigned_abs())
                    .map_err(|_| EquivalenceError::ArithmeticOverflow)?
                    - 1;
                let required = if literal > 0 { 1 } else { -1 };
                if assignment[variable] == -required {
                    return Ok(false);
                }
                if assignment[variable] == 0 {
                    assignment[variable] = required;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }

    let mut branch_variable = None;
    for clause in clauses {
        let mut satisfied = false;
        let mut clause_variable = None;
        for &literal in clause {
            let variable = usize::try_from(literal.unsigned_abs())
                .map_err(|_| EquivalenceError::ArithmeticOverflow)?
                - 1;
            let value = assignment[variable];
            if value != 0 && (value > 0) == (literal > 0) {
                satisfied = true;
                break;
            }
            if value == 0 && clause_variable.is_none() {
                clause_variable = Some(variable);
            }
        }
        if !satisfied {
            let Some(variable) = clause_variable else {
                return Ok(false);
            };
            branch_variable.get_or_insert(variable);
        }
    }
    let Some(variable) = branch_variable else {
        return Ok(true);
    };

    for value in [-1, 1] {
        let attempted = decisions
            .checked_add(1)
            .ok_or(EquivalenceError::ArithmeticOverflow)?;
        if attempted > decision_limit {
            return Err(EquivalenceError::DecisionCapExceeded {
                limit: decision_limit,
                attempted,
            });
        }
        *decisions = attempted;
        let mut branch = assignment.to_vec();
        branch[variable] = value;
        if dpll(clauses, &mut branch, decisions, decision_limit)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dense_mapping(cell_count: usize, degree: usize) -> Vec<Vec<AtomId>> {
        (0..cell_count)
            .map(|cell| {
                (0..degree)
                    .map(|value| AtomId::try_from(cell * degree + value + 1).unwrap())
                    .collect()
            })
            .collect()
    }

    fn table_from_ordinal(cell_count: usize, degree: usize, mut ordinal: usize) -> Vec<u8> {
        (0..cell_count)
            .map(|_| {
                let value = u8::try_from(ordinal % degree).unwrap();
                ordinal /= degree;
                value
            })
            .collect()
    }

    fn compile(
        forbidden: &[Vec<u8>],
        cell_count: usize,
        degree: usize,
        order: &[usize],
    ) -> CompiledForbiddenMvdd {
        let mapping = dense_mapping(cell_count, degree);
        compile_forbidden_table_mvdd(
            forbidden,
            cell_count,
            degree,
            order,
            &mapping,
            AtomId::try_from(cell_count * degree + 1).unwrap(),
            ConstructionCap::default(),
        )
        .unwrap()
    }

    fn exhaustive_check(
        forbidden: &[Vec<u8>],
        compiled: &CompiledForbiddenMvdd,
        maximum_tables: usize,
    ) -> EquivalenceTelemetry {
        exhaustively_check_one_hot_equivalence(
            forbidden,
            compiled,
            EquivalenceCheckCap {
                max_complete_tables: maximum_tables,
                max_dpll_decisions: 1_000_000,
            },
        )
        .unwrap()
    }

    #[test]
    fn all_forbidden_subsets_match_raw_semantics_under_two_orders() {
        let universe = (0..4)
            .map(|ordinal| table_from_ordinal(2, 2, ordinal))
            .collect::<Vec<_>>();
        for forbidden_mask in 0..(1usize << universe.len()) {
            let forbidden = universe
                .iter()
                .enumerate()
                .filter(|(index, _)| forbidden_mask & (1 << index) != 0)
                .map(|(_, row)| row.clone())
                .collect::<Vec<_>>();
            for order in [[0, 1], [1, 0]] {
                let compiled = compile(&forbidden, 2, 2, &order);
                let checked = exhaustive_check(&forbidden, &compiled, 4);
                assert_eq!(checked.complete_tables_checked, 4);
                assert_eq!(checked.exactly_one_cells_checked, 8);
                assert_eq!(checked.raw_rejected, forbidden.len());
                assert_eq!(checked.raw_allowed, 4 - forbidden.len());
                assert_eq!(checked.raw_allowed, checked.cnf_allowed);
                assert_eq!(checked.raw_rejected, checked.cnf_rejected);
            }
        }

        let ternary_universe = (0..3)
            .map(|ordinal| table_from_ordinal(1, 3, ordinal))
            .collect::<Vec<_>>();
        for forbidden_mask in 0..(1usize << ternary_universe.len()) {
            let forbidden = ternary_universe
                .iter()
                .enumerate()
                .filter(|(index, _)| forbidden_mask & (1 << index) != 0)
                .map(|(_, row)| row.clone())
                .collect::<Vec<_>>();
            let compiled = compile(&forbidden, 1, 3, &[0]);
            exhaustive_check(&forbidden, &compiled, 3);
        }
    }

    #[test]
    fn equal_suffixes_are_hash_consed_and_input_order_is_irrelevant() {
        let mut forbidden = vec![vec![0, 0, 0], vec![0, 1, 1], vec![1, 0, 0], vec![1, 1, 1]];
        let forward = compile(&forbidden, 3, 2, &[0, 1, 2]);
        forbidden.reverse();
        let reversed = compile(&forbidden, 3, 2, &[0, 1, 2]);

        assert_eq!(forward, reversed);
        assert!(forward.telemetry.hash_cons_hits > 0);
        assert!(forward.telemetry.eliminated_tests > 0);
        assert!(forward.telemetry.trie_nodes > forward.telemetry.mvdd_nodes);
        exhaustive_check(&forbidden, &forward, 8);
    }

    #[test]
    fn telemetry_matches_every_emitted_artifact() {
        let forbidden = vec![vec![0, 1, 2], vec![2, 1, 0]];
        let compiled = compile(&forbidden, 3, 3, &[2, 0, 1]);
        let clauses = compiled.clauses_with_root();

        assert_eq!(compiled.telemetry.cells, 3);
        assert_eq!(compiled.telemetry.degree, 3);
        assert_eq!(compiled.telemetry.input_values, 6);
        assert_eq!(compiled.telemetry.mapping_atoms, 9);
        assert_eq!(compiled.telemetry.raw_forbidden_clauses, 2);
        assert_eq!(compiled.telemetry.raw_forbidden_literals, 6);
        assert_eq!(
            compiled.telemetry.trie_edges + 1,
            compiled.telemetry.trie_nodes
        );
        assert_eq!(compiled.telemetry.mvdd_nodes, compiled.nodes.len());
        assert_eq!(compiled.telemetry.mvdd_edges, compiled.nodes.len() * 3);
        assert_eq!(
            compiled.telemetry.definition_clauses,
            compiled.definition_clauses.len()
        );
        assert_eq!(compiled.telemetry.cnf_clauses, clauses.len());
        assert_eq!(
            compiled.telemetry.cnf_literals,
            clauses.iter().map(Vec::len).sum::<usize>()
        );
        for (index, node) in compiled.nodes.iter().enumerate() {
            assert_eq!(node.auxiliary, compiled.first_auxiliary + index as AtomId);
            assert_eq!(node.branches.len(), compiled.degree);
            for target in &node.branches {
                if let MvddTarget::Node(child) = target {
                    assert!(*child < index);
                }
            }
        }
        exhaustive_check(&forbidden, &compiled, 27);
    }

    #[test]
    fn empty_and_complete_sets_reduce_to_constant_roots() {
        let empty = compile(&[], 2, 2, &[0, 1]);
        assert_eq!(empty.root_constraint, RootConstraint::Tautology);
        assert!(empty.nodes.is_empty());
        exhaustive_check(&[], &empty, 4);

        let complete = (0..4)
            .map(|ordinal| table_from_ordinal(2, 2, ordinal))
            .collect::<Vec<_>>();
        let compiled = compile(&complete, 2, 2, &[0, 1]);
        assert_eq!(compiled.root_constraint, RootConstraint::Contradiction);
        assert!(compiled.nodes.is_empty());
        assert_eq!(compiled.clauses_with_root(), vec![Vec::<i32>::new()]);
        exhaustive_check(&complete, &compiled, 4);
    }

    #[test]
    fn malformed_rows_orders_mappings_and_namespaces_fail_closed() {
        let cap = ConstructionCap::default();
        let mapping = dense_mapping(2, 2);
        assert!(matches!(
            compile_forbidden_table_mvdd(&[], 2, 0, &[0, 1], &[vec![], vec![]], 1, cap),
            Err(CompileError::InvalidDegree { .. })
        ));
        assert!(matches!(
            compile_forbidden_table_mvdd(&[], 2, 257, &[0, 1], &[], 1, cap),
            Err(CompileError::InvalidDegree { .. })
        ));
        assert!(matches!(
            compile_forbidden_table_mvdd(&[vec![0]], 2, 2, &[0, 1], &mapping, 5, cap),
            Err(CompileError::RowLength { .. })
        ));
        assert!(matches!(
            compile_forbidden_table_mvdd(&[vec![0, 2]], 2, 2, &[0, 1], &mapping, 5, cap),
            Err(CompileError::RowValueOutOfRange { .. })
        ));
        assert!(matches!(
            compile_forbidden_table_mvdd(
                &[vec![0, 1], vec![0, 1]],
                2,
                2,
                &[0, 1],
                &mapping,
                5,
                cap
            ),
            Err(CompileError::DuplicateRow { .. })
        ));
        assert!(matches!(
            compile_forbidden_table_mvdd(&[], 2, 2, &[0], &mapping, 5, cap),
            Err(CompileError::CellOrderLength { .. })
        ));
        assert!(matches!(
            compile_forbidden_table_mvdd(&[], 2, 2, &[0, 2], &mapping, 5, cap),
            Err(CompileError::InvalidOrderCell { .. })
        ));
        assert!(matches!(
            compile_forbidden_table_mvdd(&[], 2, 2, &[0, 0], &mapping, 5, cap),
            Err(CompileError::DuplicateOrderCell { .. })
        ));
        assert!(matches!(
            compile_forbidden_table_mvdd(&[], 2, 2, &[0, 1], &[vec![1, 2]], 5, cap),
            Err(CompileError::MappingCellCount { .. })
        ));
        assert!(matches!(
            compile_forbidden_table_mvdd(&[], 2, 2, &[0, 1], &[vec![1], vec![2, 3]], 4, cap),
            Err(CompileError::MappingDegree { .. })
        ));
        assert!(matches!(
            compile_forbidden_table_mvdd(&[], 2, 2, &[0, 1], &[vec![0, 2], vec![3, 4]], 5, cap),
            Err(CompileError::InvalidMappingAtom { .. })
        ));
        assert!(matches!(
            compile_forbidden_table_mvdd(&[], 2, 2, &[0, 1], &[vec![1, 2], vec![2, 4]], 5, cap),
            Err(CompileError::DuplicateMappingAtom { .. })
        ));
        assert!(matches!(
            compile_forbidden_table_mvdd(&[], 2, 2, &[0, 1], &mapping, 4, cap),
            Err(CompileError::AuxiliaryNamespaceCollision { .. })
        ));
    }

    #[test]
    fn every_construction_stage_obeys_its_cap() {
        let forbidden = vec![vec![0, 0], vec![1, 1]];
        let mapping = dense_mapping(2, 2);
        let order = [0, 1];
        let run = |cap| compile_forbidden_table_mvdd(&forbidden, 2, 2, &order, &mapping, 5, cap);

        let checks = [
            (CappedResource::Cells, {
                let mut cap = ConstructionCap::default();
                cap.max_cells = 1;
                cap
            }),
            (CappedResource::Degree, {
                let mut cap = ConstructionCap::default();
                cap.max_degree = 1;
                cap
            }),
            (CappedResource::ForbiddenRows, {
                let mut cap = ConstructionCap::default();
                cap.max_forbidden_rows = 1;
                cap
            }),
            (CappedResource::InputValues, {
                let mut cap = ConstructionCap::default();
                cap.max_input_values = 3;
                cap
            }),
            (CappedResource::MappingAtoms, {
                let mut cap = ConstructionCap::default();
                cap.max_mapping_atoms = 3;
                cap
            }),
            (CappedResource::TrieNodes, {
                let mut cap = ConstructionCap::default();
                cap.max_trie_nodes = 1;
                cap
            }),
            (CappedResource::TrieEdges, {
                let mut cap = ConstructionCap::default();
                cap.max_trie_edges = 0;
                cap
            }),
            (CappedResource::MvddNodes, {
                let mut cap = ConstructionCap::default();
                cap.max_mvdd_nodes = 0;
                cap
            }),
            (CappedResource::MvddEdges, {
                let mut cap = ConstructionCap::default();
                cap.max_mvdd_edges = 1;
                cap
            }),
            (CappedResource::CnfClauses, {
                let mut cap = ConstructionCap::default();
                cap.max_cnf_clauses = 0;
                cap
            }),
            (CappedResource::CnfLiterals, {
                let mut cap = ConstructionCap::default();
                cap.max_cnf_literals = 0;
                cap
            }),
        ];
        for (resource, cap) in checks {
            assert!(matches!(
                run(cap),
                Err(CompileError::CapExceeded {
                    resource: actual,
                    ..
                }) if actual == resource
            ));
        }
    }

    #[test]
    fn exhaustive_checker_rejects_tampering_and_obeys_its_cap() {
        let forbidden = vec![vec![0, 1]];
        let compiled = compile(&forbidden, 2, 2, &[0, 1]);

        assert!(matches!(
            exhaustively_check_one_hot_equivalence(
                &forbidden,
                &compiled,
                EquivalenceCheckCap {
                    max_complete_tables: 3,
                    max_dpll_decisions: 100
                }
            ),
            Err(EquivalenceError::TableSpaceCapExceeded { .. })
        ));

        let mut tampered_clause = compiled.clone();
        tampered_clause.definition_clauses[0][0] *= -1;
        assert!(matches!(
            exhaustively_check_one_hot_equivalence(
                &forbidden,
                &tampered_clause,
                EquivalenceCheckCap::default()
            ),
            Err(EquivalenceError::ArtifactMismatch)
        ));

        let mut tampered_mapping = compiled.clone();
        tampered_mapping.one_hot_atoms[1][0] = tampered_mapping.one_hot_atoms[0][0];
        assert!(matches!(
            exhaustively_check_one_hot_equivalence(
                &forbidden,
                &tampered_mapping,
                EquivalenceCheckCap::default()
            ),
            Err(EquivalenceError::RebuildFailed(
                CompileError::DuplicateMappingAtom { .. }
            ))
        ));

        assert!(matches!(
            exhaustively_check_one_hot_equivalence(
                &[vec![1, 1]],
                &compiled,
                EquivalenceCheckCap::default()
            ),
            Err(EquivalenceError::ArtifactMismatch)
        ));

        let branching_formula = vec![vec![1, 2], vec![-1, -2]];
        assert!(matches!(
            dpll(&branching_formula, &mut [0, 0], &mut 0, 0),
            Err(EquivalenceError::DecisionCapExceeded {
                limit: 0,
                attempted: 1
            })
        ));
    }

    fn permutations(n: usize) -> Vec<Vec<usize>> {
        fn generate(position: usize, permutation: &mut [usize], output: &mut Vec<Vec<usize>>) {
            if position == permutation.len() {
                output.push(permutation.to_vec());
                return;
            }
            for swap in position..permutation.len() {
                permutation.swap(position, swap);
                generate(position + 1, permutation, output);
                permutation.swap(position, swap);
            }
        }

        let mut permutation = (0..n).collect::<Vec<_>>();
        let mut output = Vec::new();
        generate(0, &mut permutation, &mut output);
        output
    }

    fn conjugate_binary_table(seed: &[u8], degree: usize, permutation: &[usize]) -> Vec<u8> {
        let mut inverse = vec![0usize; degree];
        for (old, &new) in permutation.iter().enumerate() {
            inverse[new] = old;
        }
        let mut image = vec![0u8; degree * degree];
        for new_left in 0..degree {
            for new_right in 0..degree {
                let old_left = inverse[new_left];
                let old_right = inverse[new_right];
                let old_value = usize::from(seed[old_left * degree + old_right]);
                image[new_left * degree + new_right] =
                    u8::try_from(permutation[old_value]).unwrap();
            }
        }
        image
    }

    #[test]
    fn s3_conjugacy_orbit_is_deterministic_and_semantically_exact() {
        let degree = 3;
        // This deliberately asymmetric table has a trivial stabilizer in S3.
        let seed = vec![1, 0, 0, 0, 0, 0, 0, 0, 0];
        let orbit = permutations(degree)
            .iter()
            .map(|permutation| conjugate_binary_table(&seed, degree, permutation))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(orbit.len(), 6);

        let cell_count = degree * degree;
        let order = [4, 0, 8, 2, 6, 1, 3, 5, 7];
        let compiled = compile(&orbit, cell_count, degree, &order);
        let mut reversed = orbit.clone();
        reversed.reverse();
        let reversed_compiled = compile(&reversed, cell_count, degree, &order);

        assert_eq!(compiled, reversed_compiled);
        assert!(compiled.telemetry.hash_cons_hits > 0);
        assert!(compiled.telemetry.trie_nodes > compiled.telemetry.mvdd_nodes);
        let checked = exhaustive_check(&orbit, &compiled, 19_683);
        assert_eq!(checked.complete_tables_checked, 19_683);
        assert_eq!(checked.raw_rejected, orbit.len());
        assert_eq!(checked.cnf_rejected, orbit.len());
        assert_eq!(checked.dpll_decisions, 0);
    }

    #[test]
    fn auxiliary_range_is_checked_before_cnf_emission() {
        let mapping = vec![vec![1, 2]];
        assert!(
            compile_forbidden_table_mvdd(
                &[vec![0]],
                1,
                2,
                &[0],
                &mapping,
                MAX_DIMACS_VARIABLE,
                ConstructionCap::default()
            )
            .is_ok()
        );

        let mapping = vec![vec![1, 2], vec![3, 4]];
        assert!(matches!(
            compile_forbidden_table_mvdd(
                &[vec![0, 0]],
                2,
                2,
                &[0, 1],
                &mapping,
                MAX_DIMACS_VARIABLE,
                ConstructionCap::default()
            ),
            Err(CompileError::AuxiliaryNamespaceExhausted { .. })
        ));
    }
}
