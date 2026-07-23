#![forbid(unsafe_code)]

//! Exhaustive, independently checked UNSAT covers for the Fabric reference.
//!
//! This is a correctness oracle, not a competitive proof format. It covers
//! every total source-atom assignment and asks the independent model checker
//! to reject every leaf. Explicit caps make exponential growth an abstention.

use super::bool_cnf::{self, LoweringCaps, LoweringError};
use super::model::{
    self, LiteralConjunctionValidation, ModelCaps, ModelError, ModelLimit, ModelValidation,
};
use super::native_clause::AtomId;
use super::semantic::{RootLiteral, SemanticExpr, SemanticProblem};
use std::error::Error;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CoverNodeId(u32);

impl CoverNodeId {
    pub(crate) const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub(crate) const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CoverNode {
    Leaf,
    RootLiteralConflict {
        atom: AtomId,
    },
    RootTheoryConflict,
    RootDisjunctionConflict {
        disjunction: u32,
    },
    RootPropagationConflict,
    PartialConflict,
    PrunedSplit {
        atom: AtomId,
        when_false: CoverNodeId,
        when_true: CoverNodeId,
    },
    Split {
        atom: AtomId,
        when_false: CoverNodeId,
        when_true: CoverNodeId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoverProof {
    pub(crate) source_atom_count: usize,
    pub(crate) root: CoverNodeId,
    pub(crate) nodes: Box<[CoverNode]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoverCaps {
    pub(crate) max_source_atoms: usize,
    pub(crate) max_depth: usize,
    pub(crate) max_pruned_depth: usize,
    pub(crate) max_expression_depth: usize,
    pub(crate) max_nodes: usize,
    pub(crate) max_check_work: usize,
    pub(crate) model: ModelCaps,
}

impl Default for CoverCaps {
    fn default() -> Self {
        Self {
            max_source_atoms: 18,
            max_depth: 18,
            max_pruned_depth: 512,
            max_expression_depth: 256,
            max_nodes: 1_000_000,
            max_check_work: 16_000_000,
            model: ModelCaps::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoverResource {
    SourceAtoms,
    Depth,
    PrunedDepth,
    ExpressionDepth,
    Nodes,
    CheckWork,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoverLimit {
    pub(crate) resource: CoverResource,
    pub(crate) attempted: usize,
    pub(crate) limit: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoverAbstention {
    Cover(CoverLimit),
    Model(ModelLimit),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CoverBuild {
    Built(CoverProof),
    Abstained(CoverLimit),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PrunedCoverBuild {
    Built(CoverProof),
    Abstained(CoverAbstention),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoverReceipt {
    pub(crate) source_atom_count: usize,
    pub(crate) nodes_checked: usize,
    pub(crate) leaves_closed: usize,
    pub(crate) maximum_depth: usize,
    pub(crate) check_work: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoverCheck {
    Valid(CoverReceipt),
    Abstained(CoverAbstention),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CoverError {
    SourceAtomCountMismatch {
        declared: usize,
        actual: usize,
    },
    RootOutOfRange {
        root: CoverNodeId,
        node_count: usize,
    },
    ChildOutOfRange {
        parent: CoverNodeId,
        child: CoverNodeId,
        node_count: usize,
    },
    NonPostorderChild {
        parent: CoverNodeId,
        child: CoverNodeId,
    },
    ReusedNode {
        node: CoverNodeId,
    },
    UnreachableNodes {
        reachable: usize,
        total: usize,
    },
    PrematureLeaf {
        node: CoverNodeId,
        depth: usize,
        expected_depth: usize,
    },
    SplitAfterCompleteAssignment {
        node: CoverNodeId,
        depth: usize,
    },
    NonCanonicalSplit {
        node: CoverNodeId,
        atom: AtomId,
        expected: AtomId,
    },
    OpenLeaf {
        node: CoverNodeId,
        assignment: Box<[bool]>,
    },
    RootLiteralConflictHasExtraNodes {
        nodes: usize,
    },
    RootLiteralConflictAtomOutOfRange {
        atom: AtomId,
        atom_count: usize,
    },
    RootLiteralConflictNotProved {
        atom: AtomId,
    },
    RootTheoryConflictHasExtraNodes {
        nodes: usize,
    },
    RootTheoryConflictNotProved,
    RootDisjunctionConflictHasExtraNodes {
        nodes: usize,
    },
    RootDisjunctionOutOfRange {
        disjunction: u32,
        count: usize,
    },
    RootDisjunctionConflictNotProved {
        disjunction: u32,
    },
    RootDisjunctionIdSpaceExhausted {
        count: usize,
    },
    RootPropagationConflictHasExtraNodes {
        nodes: usize,
    },
    RootPropagationConflictNotProved,
    PrunedUnexpectedNode {
        node: CoverNodeId,
    },
    RepeatedPrunedSplit {
        node: CoverNodeId,
        atom: AtomId,
    },
    OpenPartialLeaf {
        node: CoverNodeId,
        assignment: Box<[RootLiteral]>,
    },
    PrunedBuilderFoundOpenAssignment {
        assignment: Box<[RootLiteral]>,
    },
    PartialExpressionAtomOutOfRange {
        atom: AtomId,
        atom_count: usize,
    },
    AllocationFailed {
        context: &'static str,
    },
    Model(ModelError),
    Lowering(LoweringError),
    NodeIdSpaceExhausted {
        nodes: usize,
    },
}

impl fmt::Display for CoverError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceAtomCountMismatch { declared, actual } => write!(
                output,
                "cover declares {declared} source atoms, but the problem has {actual}"
            ),
            Self::RootOutOfRange { root, node_count } => write!(
                output,
                "cover root {} is outside 0..{node_count}",
                root.index()
            ),
            Self::ChildOutOfRange {
                parent,
                child,
                node_count,
            } => write!(
                output,
                "cover node {} references child {} outside 0..{node_count}",
                parent.index(),
                child.index()
            ),
            Self::NonPostorderChild { parent, child } => write!(
                output,
                "cover node {} has non-earlier child {}",
                parent.index(),
                child.index()
            ),
            Self::ReusedNode { node } => {
                write!(
                    output,
                    "cover node {} is reached more than once",
                    node.index()
                )
            }
            Self::UnreachableNodes { reachable, total } => {
                write!(output, "cover reaches {reachable} of {total} nodes")
            }
            Self::PrematureLeaf {
                node,
                depth,
                expected_depth,
            } => write!(
                output,
                "cover leaf {} closes at depth {depth}, expected {expected_depth}",
                node.index()
            ),
            Self::SplitAfterCompleteAssignment { node, depth } => write!(
                output,
                "cover node {} splits after a complete assignment at depth {depth}",
                node.index()
            ),
            Self::NonCanonicalSplit {
                node,
                atom,
                expected,
            } => write!(
                output,
                "cover node {} splits atom {}, expected {}",
                node.index(),
                atom.index(),
                expected.index()
            ),
            Self::OpenLeaf { node, .. } => write!(
                output,
                "cover leaf {} contains a valid source model",
                node.index()
            ),
            Self::RootLiteralConflictHasExtraNodes { nodes } => write!(
                output,
                "root-literal conflict proof must contain exactly one node, got {nodes}"
            ),
            Self::RootLiteralConflictAtomOutOfRange { atom, atom_count } => write!(
                output,
                "root-literal conflict atom {} is outside 0..{atom_count}",
                atom.index()
            ),
            Self::RootLiteralConflictNotProved { atom } => write!(
                output,
                "root literals do not contain both polarities of atom {}",
                atom.index()
            ),
            Self::RootTheoryConflictHasExtraNodes { nodes } => write!(
                output,
                "root-theory conflict proof must contain exactly one node, got {nodes}"
            ),
            Self::RootTheoryConflictNotProved => {
                output.write_str("asserted root literals are EUF-consistent")
            }
            Self::RootDisjunctionConflictHasExtraNodes { nodes } => write!(
                output,
                "root-disjunction conflict proof must contain exactly one node, got {nodes}"
            ),
            Self::RootDisjunctionOutOfRange { disjunction, count } => write!(
                output,
                "root disjunction {disjunction} is outside 0..{count}"
            ),
            Self::RootDisjunctionConflictNotProved { disjunction } => write!(
                output,
                "root disjunction {disjunction} has an EUF-consistent or unsupported branch"
            ),
            Self::RootDisjunctionIdSpaceExhausted { count } => write!(
                output,
                "{count} asserted root disjunctions do not fit in the proof format"
            ),
            Self::RootPropagationConflictHasExtraNodes { nodes } => write!(
                output,
                "root-propagation conflict proof must contain exactly one node, got {nodes}"
            ),
            Self::RootPropagationConflictNotProved => output.write_str(
                "root Boolean unit propagation and independent EUF replay reach no conflict",
            ),
            Self::PrunedUnexpectedNode { node } => write!(
                output,
                "pruned cover contains an incompatible node at {}",
                node.index()
            ),
            Self::RepeatedPrunedSplit { node, atom } => write!(
                output,
                "pruned cover node {} splits already assigned atom {}",
                node.index(),
                atom.index()
            ),
            Self::OpenPartialLeaf { node, .. } => write!(
                output,
                "pruned cover leaf {} is not closed by Boolean or EUF conflict",
                node.index()
            ),
            Self::PrunedBuilderFoundOpenAssignment { .. } => output.write_str(
                "pruned cover producer found a source assignment with no Boolean or EUF conflict",
            ),
            Self::PartialExpressionAtomOutOfRange { atom, atom_count } => write!(
                output,
                "partial expression references atom {} outside 0..{atom_count}",
                atom.index()
            ),
            Self::AllocationFailed { context } => {
                write!(output, "allocation failed while building {context}")
            }
            Self::Model(error) => error.fmt(output),
            Self::Lowering(error) => error.fmt(output),
            Self::NodeIdSpaceExhausted { nodes } => {
                write!(output, "cover has {nodes} nodes, exceeding CoverNodeId")
            }
        }
    }
}

impl Error for CoverError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Model(error) => Some(error),
            Self::Lowering(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ModelError> for CoverError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<LoweringError> for CoverError {
    fn from(error: LoweringError) -> Self {
        Self::Lowering(error)
    }
}

pub(crate) fn build_complete_cover(source_atom_count: usize, caps: CoverCaps) -> CoverBuild {
    let required_nodes = match required_node_count(source_atom_count) {
        Some(count) => count,
        None => {
            return CoverBuild::Abstained(CoverLimit {
                resource: CoverResource::Nodes,
                attempted: usize::MAX,
                limit: caps.max_nodes,
            });
        }
    };
    for (resource, attempted, limit) in [
        (
            CoverResource::SourceAtoms,
            source_atom_count,
            caps.max_source_atoms,
        ),
        (CoverResource::Depth, source_atom_count, caps.max_depth),
        (CoverResource::Nodes, required_nodes, caps.max_nodes),
    ] {
        if attempted > limit {
            return CoverBuild::Abstained(CoverLimit {
                resource,
                attempted,
                limit,
            });
        }
    }
    if required_nodes > u32::MAX as usize + 1 {
        return CoverBuild::Abstained(CoverLimit {
            resource: CoverResource::Nodes,
            attempted: required_nodes,
            limit: u32::MAX as usize + 1,
        });
    }

    let mut nodes = Vec::new();
    if nodes.try_reserve_exact(required_nodes).is_err() {
        return CoverBuild::Abstained(CoverLimit {
            resource: CoverResource::Nodes,
            attempted: required_nodes,
            limit: nodes.capacity(),
        });
    }
    let root = build_subtree(0, source_atom_count, &mut nodes)
        .expect("node count and identifier space were checked before construction");
    debug_assert_eq!(nodes.len(), required_nodes);
    CoverBuild::Built(CoverProof {
        source_atom_count,
        root,
        nodes: nodes.into_boxed_slice(),
    })
}

/// Build a constant-size proof when one stable source atom is asserted with
/// both polarities at the root. The checker rediscovers the conflict from the
/// projected root-literal list.
pub(crate) fn build_root_literal_conflict(
    problem: &SemanticProblem,
) -> Result<Option<CoverProof>, CoverError> {
    let mut polarities = Vec::new();
    polarities
        .try_reserve_exact(problem.atoms.len())
        .map_err(|_| CoverError::AllocationFailed {
            context: "root-literal conflict polarities",
        })?;
    polarities.resize(problem.atoms.len(), 0u8);
    for literal in &problem.root_literals {
        let Some(slot) = polarities.get_mut(literal.atom.index()) else {
            return Err(CoverError::RootLiteralConflictAtomOutOfRange {
                atom: literal.atom,
                atom_count: problem.atoms.len(),
            });
        };
        *slot |= if literal.positive { 1 } else { 2 };
    }
    scan_asserted_root_literals(problem, |atom, positive| {
        let slot = polarities.get_mut(atom.index()).ok_or(
            CoverError::RootLiteralConflictAtomOutOfRange {
                atom,
                atom_count: problem.atoms.len(),
            },
        )?;
        *slot |= if positive { 1 } else { 2 };
        Ok(())
    })?;
    let Some(index) = polarities.iter().position(|&value| value == 3) else {
        return Ok(None);
    };
    Ok(Some(CoverProof {
        source_atom_count: problem.atoms.len(),
        root: CoverNodeId::new(0),
        nodes: vec![CoverNode::RootLiteralConflict {
            atom: AtomId::new(index as u32),
        }]
        .into_boxed_slice(),
    }))
}

pub(crate) fn build_root_theory_conflict(
    problem: &SemanticProblem,
    caps: CoverCaps,
) -> Result<Option<CoverProof>, CoverError> {
    Ok(match prove_root_theory_conflict(problem, caps)? {
        CompactAttempt::Proved(_) => Some(single_node_proof(
            problem.atoms.len(),
            CoverNode::RootTheoryConflict,
        )),
        CompactAttempt::NotProved | CompactAttempt::Abstained(_) => None,
    })
}

pub(crate) fn build_root_disjunction_conflict(
    problem: &SemanticProblem,
    caps: CoverCaps,
) -> Result<Option<CoverProof>, CoverError> {
    build_root_disjunction_conflict_with_min_branches(problem, caps, 0)
}

pub(crate) fn build_root_disjunction_conflict_with_min_branches(
    problem: &SemanticProblem,
    caps: CoverCaps,
    min_branches: usize,
) -> Result<Option<CoverProof>, CoverError> {
    let context = collect_root_assertion_context(problem)?;
    if context.disjunctions.len() > u32::MAX as usize {
        return Err(CoverError::RootDisjunctionIdSpaceExhausted {
            count: context.disjunctions.len(),
        });
    }
    for disjunction in 0..context.disjunctions.len() {
        if context.disjunctions[disjunction].len() < min_branches {
            continue;
        }
        let encoded = disjunction as u32;
        if matches!(
            prove_root_disjunction_conflict(problem, encoded, caps)?,
            CompactAttempt::Proved(_)
        ) {
            return Ok(Some(single_node_proof(
                problem.atoms.len(),
                CoverNode::RootDisjunctionConflict {
                    disjunction: encoded,
                },
            )));
        }
    }
    Ok(None)
}

pub(crate) fn build_root_propagation_conflict(
    problem: &SemanticProblem,
    caps: CoverCaps,
) -> Result<Option<CoverProof>, CoverError> {
    Ok(match prove_root_propagation_conflict(problem, caps)? {
        CompactAttempt::Proved(_) => Some(single_node_proof(
            problem.atoms.len(),
            CoverNode::RootPropagationConflict,
        )),
        CompactAttempt::NotProved | CompactAttempt::Abstained(_) => None,
    })
}

fn single_node_proof(source_atom_count: usize, node: CoverNode) -> CoverProof {
    CoverProof {
        source_atom_count,
        root: CoverNodeId::new(0),
        nodes: vec![node].into_boxed_slice(),
    }
}

struct RootAssertionContext<'problem> {
    literals: Vec<RootLiteral>,
    disjunctions: Vec<&'problem [SemanticExpr]>,
    structurally_false: bool,
    work: usize,
}

fn collect_root_assertion_context(
    problem: &SemanticProblem,
) -> Result<RootAssertionContext<'_>, CoverError> {
    let mut literals = Vec::new();
    let mut disjunctions = Vec::new();
    let mut stack = Vec::new();
    stack
        .try_reserve(problem.assertions.len())
        .map_err(|_| CoverError::AllocationFailed {
            context: "root assertion proof stack",
        })?;
    stack.extend(problem.assertions.iter().rev());
    let mut structurally_false = false;
    let mut work = 0usize;
    while let Some(expression) = stack.pop() {
        work = work.saturating_add(1);
        match expression {
            SemanticExpr::Const(false) => structurally_false = true,
            SemanticExpr::Const(true) => {}
            SemanticExpr::Atom(atom) => literals.push(RootLiteral {
                atom: *atom,
                positive: true,
            }),
            SemanticExpr::Not(child) => {
                if let SemanticExpr::Atom(atom) = child.as_ref() {
                    literals.push(RootLiteral {
                        atom: *atom,
                        positive: false,
                    });
                }
            }
            SemanticExpr::And(children) => {
                stack
                    .try_reserve(children.len())
                    .map_err(|_| CoverError::AllocationFailed {
                        context: "root assertion proof stack",
                    })?;
                stack.extend(children.iter().rev());
            }
            SemanticExpr::Or(children) => disjunctions.push(children.as_ref()),
            SemanticExpr::Iff(_) | SemanticExpr::Ite(_, _, _) => {}
        }
    }
    if problem.assertions.is_empty() {
        literals
            .try_reserve(problem.root_literals.len())
            .map_err(|_| CoverError::AllocationFailed {
                context: "legacy root proof literals",
            })?;
        literals.extend_from_slice(&problem.root_literals);
        work = work.saturating_add(problem.root_literals.len());
    }
    Ok(RootAssertionContext {
        literals,
        disjunctions,
        structurally_false,
        work,
    })
}

enum BranchConjunction {
    Literals(Vec<RootLiteral>),
    StructurallyFalse,
    Unsupported,
}

fn collect_branch_conjunction(
    expression: &SemanticExpr,
    work: &mut usize,
) -> Result<BranchConjunction, CoverError> {
    let mut literals = Vec::new();
    let mut stack = Vec::new();
    stack
        .try_reserve(1)
        .map_err(|_| CoverError::AllocationFailed {
            context: "disjunction branch proof stack",
        })?;
    stack.push(expression);
    while let Some(current) = stack.pop() {
        *work = work.saturating_add(1);
        match current {
            SemanticExpr::Const(true) => {}
            SemanticExpr::Const(false) => return Ok(BranchConjunction::StructurallyFalse),
            SemanticExpr::Atom(atom) => literals.push(RootLiteral {
                atom: *atom,
                positive: true,
            }),
            SemanticExpr::Not(child) => {
                let SemanticExpr::Atom(atom) = child.as_ref() else {
                    return Ok(BranchConjunction::Unsupported);
                };
                literals.push(RootLiteral {
                    atom: *atom,
                    positive: false,
                });
            }
            SemanticExpr::And(children) => {
                stack
                    .try_reserve(children.len())
                    .map_err(|_| CoverError::AllocationFailed {
                        context: "disjunction branch proof stack",
                    })?;
                stack.extend(children.iter().rev());
            }
            SemanticExpr::Or(_) | SemanticExpr::Iff(_) | SemanticExpr::Ite(_, _, _) => {
                return Ok(BranchConjunction::Unsupported);
            }
        }
    }
    Ok(BranchConjunction::Literals(literals))
}

enum CompactAttempt {
    Proved(usize),
    NotProved,
    Abstained(CoverAbstention),
}

fn charge_compact_work(
    used: &mut usize,
    additional: usize,
    caps: CoverCaps,
) -> Option<CoverAbstention> {
    let attempted = used.checked_add(additional).unwrap_or(usize::MAX);
    if attempted > caps.max_check_work {
        Some(CoverAbstention::Cover(CoverLimit {
            resource: CoverResource::CheckWork,
            attempted,
            limit: caps.max_check_work,
        }))
    } else {
        *used = attempted;
        None
    }
}

fn validate_compact_conjunction(
    problem: &SemanticProblem,
    literals: &[RootLiteral],
    used: &mut usize,
    caps: CoverCaps,
) -> Result<CompactAttempt, CoverError> {
    match model::validate_literal_conjunction(problem, literals, caps.model)? {
        LiteralConjunctionValidation::Consistent { work } => {
            if let Some(reason) = charge_compact_work(used, work, caps) {
                Ok(CompactAttempt::Abstained(reason))
            } else {
                Ok(CompactAttempt::NotProved)
            }
        }
        LiteralConjunctionValidation::Conflict { work } => {
            if let Some(reason) = charge_compact_work(used, work, caps) {
                Ok(CompactAttempt::Abstained(reason))
            } else {
                Ok(CompactAttempt::Proved(*used))
            }
        }
        LiteralConjunctionValidation::Abstained(limit) => {
            Ok(CompactAttempt::Abstained(CoverAbstention::Model(limit)))
        }
    }
}

fn prove_root_theory_conflict(
    problem: &SemanticProblem,
    caps: CoverCaps,
) -> Result<CompactAttempt, CoverError> {
    let context = collect_root_assertion_context(problem)?;
    let mut work = 0usize;
    if let Some(reason) = charge_compact_work(&mut work, context.work, caps) {
        return Ok(CompactAttempt::Abstained(reason));
    }
    if context.structurally_false {
        return Ok(CompactAttempt::Proved(work));
    }
    validate_compact_conjunction(problem, &context.literals, &mut work, caps)
}

fn prove_root_disjunction_conflict(
    problem: &SemanticProblem,
    disjunction: u32,
    caps: CoverCaps,
) -> Result<CompactAttempt, CoverError> {
    let context = collect_root_assertion_context(problem)?;
    let Some(branches) = context.disjunctions.get(disjunction as usize) else {
        return Err(CoverError::RootDisjunctionOutOfRange {
            disjunction,
            count: context.disjunctions.len(),
        });
    };
    let mut work = 0usize;
    if let Some(reason) = charge_compact_work(&mut work, context.work, caps) {
        return Ok(CompactAttempt::Abstained(reason));
    }
    if context.structurally_false {
        return Ok(CompactAttempt::Proved(work));
    }
    for branch in branches.iter() {
        let branch = collect_branch_conjunction(branch, &mut work)?;
        if work > caps.max_check_work {
            return Ok(CompactAttempt::Abstained(CoverAbstention::Cover(
                CoverLimit {
                    resource: CoverResource::CheckWork,
                    attempted: work,
                    limit: caps.max_check_work,
                },
            )));
        }
        let BranchConjunction::Literals(branch_literals) = branch else {
            match branch {
                BranchConjunction::StructurallyFalse => continue,
                BranchConjunction::Unsupported => return Ok(CompactAttempt::NotProved),
                BranchConjunction::Literals(_) => unreachable!(),
            }
        };
        let mut literals = Vec::new();
        literals
            .try_reserve_exact(context.literals.len().saturating_add(branch_literals.len()))
            .map_err(|_| CoverError::AllocationFailed {
                context: "disjunction branch proof literals",
            })?;
        literals.extend_from_slice(&context.literals);
        literals.extend(branch_literals);
        match validate_compact_conjunction(problem, &literals, &mut work, caps)? {
            CompactAttempt::Proved(_) => {}
            CompactAttempt::NotProved => return Ok(CompactAttempt::NotProved),
            CompactAttempt::Abstained(reason) => {
                return Ok(CompactAttempt::Abstained(reason));
            }
        }
    }
    Ok(CompactAttempt::Proved(work))
}

fn prove_root_propagation_conflict(
    problem: &SemanticProblem,
    caps: CoverCaps,
) -> Result<CompactAttempt, CoverError> {
    let formula = bool_cnf::lower(problem, LoweringCaps::new(2_000_000, 5_000_000, 20_000_000))?;
    let mut assignments = Vec::new();
    assignments
        .try_reserve_exact(formula.atom_count)
        .map_err(|_| CoverError::AllocationFailed {
            context: "root propagation assignment",
        })?;
    assignments.resize(formula.atom_count, PARTIAL_UNKNOWN);
    let mut work = 0usize;
    if let Some(reason) = charge_compact_work(&mut work, formula.atom_count, caps) {
        return Ok(CompactAttempt::Abstained(reason));
    }

    loop {
        let mut changed = false;
        for clause in formula.clauses.iter() {
            let mut satisfied = false;
            let mut unknown = None;
            let mut unknown_count = 0usize;
            for &literal in clause.iter() {
                if let Some(reason) = charge_compact_work(&mut work, 1, caps) {
                    return Ok(CompactAttempt::Abstained(reason));
                }
                let Some(&assignment) = assignments.get(literal.atom().index()) else {
                    return Err(CoverError::PartialExpressionAtomOutOfRange {
                        atom: literal.atom(),
                        atom_count: assignments.len(),
                    });
                };
                if assignment == PARTIAL_UNKNOWN {
                    unknown = Some(literal);
                    unknown_count = unknown_count.saturating_add(1);
                } else if (assignment == 1) == literal.is_positive() {
                    satisfied = true;
                    break;
                }
            }
            if satisfied {
                continue;
            }
            match (unknown_count, unknown) {
                (0, _) => return Ok(CompactAttempt::Proved(work)),
                (1, Some(literal)) => {
                    let slot = &mut assignments[literal.atom().index()];
                    let required = i8::from(literal.is_positive());
                    if *slot == PARTIAL_UNKNOWN {
                        *slot = required;
                        changed = true;
                    } else if *slot != required {
                        return Ok(CompactAttempt::Proved(work));
                    }
                }
                _ => {}
            }
        }
        if !changed {
            break;
        }
    }

    let context = collect_root_assertion_context(problem)?;
    if let Some(reason) = charge_compact_work(&mut work, context.work, caps) {
        return Ok(CompactAttempt::Abstained(reason));
    }
    let source_assignments = assigned_literals(&assignments[..formula.source_atom_count])?;
    let mut literals = Vec::new();
    literals
        .try_reserve_exact(
            context
                .literals
                .len()
                .saturating_add(source_assignments.len()),
        )
        .map_err(|_| CoverError::AllocationFailed {
            context: "root propagation source literals",
        })?;
    literals.extend_from_slice(&context.literals);
    literals.extend_from_slice(&source_assignments);
    validate_compact_conjunction(problem, &literals, &mut work, caps)
}

const PARTIAL_FALSE: u8 = 1;
const PARTIAL_TRUE: u8 = 2;
const PARTIAL_BOTH: u8 = PARTIAL_FALSE | PARTIAL_TRUE;
const PARTIAL_UNKNOWN: i8 = -1;

enum PartialConflictStatus {
    Conflict,
    Open,
    Abstained(CoverAbstention),
}

enum PartialMaskStatus {
    Mask(u8),
    Abstained(CoverAbstention),
}

pub(crate) fn build_pruned_cover(
    problem: &SemanticProblem,
    caps: CoverCaps,
) -> Result<PrunedCoverBuild, CoverError> {
    let context = collect_root_assertion_context(problem)?;
    let mut initial_work = 0usize;
    if let Some(reason) = charge_compact_work(&mut initial_work, context.work, caps) {
        return Ok(PrunedCoverBuild::Abstained(reason));
    }
    let mut assignments = Vec::new();
    assignments
        .try_reserve_exact(problem.atoms.len())
        .map_err(|_| CoverError::AllocationFailed {
            context: "pruned cover assignment",
        })?;
    assignments.resize(problem.atoms.len(), PARTIAL_UNKNOWN);
    let order = pruned_atom_order(problem)?;
    let mut builder = PrunedCoverBuilder {
        problem,
        caps,
        root_literals: &context.literals,
        order: &order,
        nodes: Vec::new(),
        work: initial_work,
    };
    builder
        .nodes
        .try_reserve(caps.max_nodes.min(4_096))
        .map_err(|_| CoverError::AllocationFailed {
            context: "pruned cover nodes",
        })?;
    let root = match builder.build_node(&mut assignments, 0)? {
        PrunedBuildNode::Node(root) => root,
        PrunedBuildNode::Abstained(reason) => {
            return Ok(PrunedCoverBuild::Abstained(reason));
        }
    };
    Ok(PrunedCoverBuild::Built(CoverProof {
        source_atom_count: problem.atoms.len(),
        root,
        nodes: builder.nodes.into_boxed_slice(),
    }))
}

fn pruned_atom_order(problem: &SemanticProblem) -> Result<Vec<AtomId>, CoverError> {
    let mut occurrences = Vec::new();
    occurrences
        .try_reserve_exact(problem.atoms.len())
        .map_err(|_| CoverError::AllocationFailed {
            context: "pruned cover occurrence counts",
        })?;
    occurrences.resize(problem.atoms.len(), 0usize);
    for literal in &problem.root_literals {
        let Some(count) = occurrences.get_mut(literal.atom.index()) else {
            return Err(CoverError::PartialExpressionAtomOutOfRange {
                atom: literal.atom,
                atom_count: problem.atoms.len(),
            });
        };
        *count = count.saturating_add(1);
    }
    let mut stack = Vec::new();
    stack
        .try_reserve(problem.assertions.len())
        .map_err(|_| CoverError::AllocationFailed {
            context: "pruned cover occurrence stack",
        })?;
    stack.extend(problem.assertions.iter());
    while let Some(expression) = stack.pop() {
        match expression {
            SemanticExpr::Atom(atom) => {
                let Some(count) = occurrences.get_mut(atom.index()) else {
                    return Err(CoverError::PartialExpressionAtomOutOfRange {
                        atom: *atom,
                        atom_count: problem.atoms.len(),
                    });
                };
                *count = count.saturating_add(1);
            }
            SemanticExpr::Not(child) => stack.push(child),
            SemanticExpr::And(children)
            | SemanticExpr::Or(children)
            | SemanticExpr::Iff(children) => {
                stack
                    .try_reserve(children.len())
                    .map_err(|_| CoverError::AllocationFailed {
                        context: "pruned cover occurrence stack",
                    })?;
                stack.extend(children.iter());
            }
            SemanticExpr::Ite(condition, then_expression, else_expression) => {
                stack
                    .try_reserve(3)
                    .map_err(|_| CoverError::AllocationFailed {
                        context: "pruned cover occurrence stack",
                    })?;
                stack.push(condition);
                stack.push(then_expression);
                stack.push(else_expression);
            }
            SemanticExpr::Const(_) => {}
        }
    }
    let mut order = Vec::new();
    order
        .try_reserve_exact(problem.atoms.len())
        .map_err(|_| CoverError::AllocationFailed {
            context: "pruned cover atom order",
        })?;
    for index in 0..problem.atoms.len() {
        order.push(AtomId::new(index as u32));
    }
    order.sort_unstable_by(|left, right| {
        occurrences[right.index()]
            .cmp(&occurrences[left.index()])
            .then_with(|| left.cmp(right))
    });
    Ok(order)
}

enum PrunedBuildNode {
    Node(CoverNodeId),
    Abstained(CoverAbstention),
}

struct PrunedCoverBuilder<'problem, 'context> {
    problem: &'problem SemanticProblem,
    caps: CoverCaps,
    root_literals: &'context [RootLiteral],
    order: &'context [AtomId],
    nodes: Vec<CoverNode>,
    work: usize,
}

impl PrunedCoverBuilder<'_, '_> {
    fn build_node(
        &mut self,
        assignments: &mut [i8],
        depth: usize,
    ) -> Result<PrunedBuildNode, CoverError> {
        if depth > self.caps.max_pruned_depth {
            return Ok(PrunedBuildNode::Abstained(CoverAbstention::Cover(
                CoverLimit {
                    resource: CoverResource::PrunedDepth,
                    attempted: depth,
                    limit: self.caps.max_pruned_depth,
                },
            )));
        }
        match partial_conflict(
            self.problem,
            self.root_literals,
            assignments,
            &mut self.work,
            self.caps,
        )? {
            PartialConflictStatus::Conflict => return self.push_node(CoverNode::PartialConflict),
            PartialConflictStatus::Abstained(reason) => {
                return Ok(PrunedBuildNode::Abstained(reason));
            }
            PartialConflictStatus::Open => {}
        }

        let Some(atom) = self
            .order
            .iter()
            .copied()
            .find(|atom| assignments[atom.index()] == PARTIAL_UNKNOWN)
        else {
            return Err(CoverError::PrunedBuilderFoundOpenAssignment {
                assignment: assigned_literals(assignments)?,
            });
        };

        assignments[atom.index()] = 0;
        let when_false = match self.build_node(assignments, depth.saturating_add(1))? {
            PrunedBuildNode::Node(node) => node,
            PrunedBuildNode::Abstained(reason) => {
                assignments[atom.index()] = PARTIAL_UNKNOWN;
                return Ok(PrunedBuildNode::Abstained(reason));
            }
        };
        assignments[atom.index()] = 1;
        let when_true = match self.build_node(assignments, depth.saturating_add(1))? {
            PrunedBuildNode::Node(node) => node,
            PrunedBuildNode::Abstained(reason) => {
                assignments[atom.index()] = PARTIAL_UNKNOWN;
                return Ok(PrunedBuildNode::Abstained(reason));
            }
        };
        assignments[atom.index()] = PARTIAL_UNKNOWN;
        self.push_node(CoverNode::PrunedSplit {
            atom,
            when_false,
            when_true,
        })
    }

    fn push_node(&mut self, node: CoverNode) -> Result<PrunedBuildNode, CoverError> {
        let attempted = self.nodes.len().checked_add(1).unwrap_or(usize::MAX);
        if attempted > self.caps.max_nodes {
            return Ok(PrunedBuildNode::Abstained(CoverAbstention::Cover(
                CoverLimit {
                    resource: CoverResource::Nodes,
                    attempted,
                    limit: self.caps.max_nodes,
                },
            )));
        }
        let raw =
            u32::try_from(self.nodes.len()).map_err(|_| CoverError::NodeIdSpaceExhausted {
                nodes: self.nodes.len(),
            })?;
        self.nodes.push(node);
        Ok(PrunedBuildNode::Node(CoverNodeId::new(raw)))
    }
}

fn partial_conflict(
    problem: &SemanticProblem,
    root_literals: &[RootLiteral],
    assignments: &[i8],
    work: &mut usize,
    caps: CoverCaps,
) -> Result<PartialConflictStatus, CoverError> {
    for literal in &problem.root_literals {
        if let Some(reason) = charge_compact_work(work, 1, caps) {
            return Ok(PartialConflictStatus::Abstained(reason));
        }
        let Some(&assigned) = assignments.get(literal.atom.index()) else {
            return Err(CoverError::PartialExpressionAtomOutOfRange {
                atom: literal.atom,
                atom_count: assignments.len(),
            });
        };
        if assigned != PARTIAL_UNKNOWN && (assigned == 1) != literal.positive {
            return Ok(PartialConflictStatus::Conflict);
        }
    }
    for assertion in &problem.assertions {
        match partial_expression_mask(problem, assertion, assignments, 0, work, caps)? {
            PartialMaskStatus::Mask(mask) if mask & PARTIAL_TRUE == 0 => {
                return Ok(PartialConflictStatus::Conflict);
            }
            PartialMaskStatus::Mask(_) => {}
            PartialMaskStatus::Abstained(reason) => {
                return Ok(PartialConflictStatus::Abstained(reason));
            }
        }
    }

    let assigned = assigned_literals(assignments)?;
    let mut literals = Vec::new();
    literals
        .try_reserve_exact(root_literals.len().saturating_add(assigned.len()))
        .map_err(|_| CoverError::AllocationFailed {
            context: "partial conflict literals",
        })?;
    literals.extend_from_slice(root_literals);
    literals.extend_from_slice(&assigned);
    match validate_compact_conjunction(problem, &literals, work, caps)? {
        CompactAttempt::Proved(_) => Ok(PartialConflictStatus::Conflict),
        CompactAttempt::NotProved => Ok(PartialConflictStatus::Open),
        CompactAttempt::Abstained(reason) => Ok(PartialConflictStatus::Abstained(reason)),
    }
}

fn assigned_literals(assignments: &[i8]) -> Result<Box<[RootLiteral]>, CoverError> {
    let assigned_count = assignments
        .iter()
        .filter(|&&value| value != PARTIAL_UNKNOWN)
        .count();
    let mut literals = Vec::new();
    literals
        .try_reserve_exact(assigned_count)
        .map_err(|_| CoverError::AllocationFailed {
            context: "partial assignment literals",
        })?;
    for (index, &value) in assignments.iter().enumerate() {
        if value != PARTIAL_UNKNOWN {
            literals.push(RootLiteral {
                atom: AtomId::new(index as u32),
                positive: value == 1,
            });
        }
    }
    Ok(literals.into_boxed_slice())
}

fn partial_expression_mask(
    problem: &SemanticProblem,
    expression: &SemanticExpr,
    assignments: &[i8],
    depth: usize,
    work: &mut usize,
    caps: CoverCaps,
) -> Result<PartialMaskStatus, CoverError> {
    if depth > caps.max_expression_depth {
        return Ok(PartialMaskStatus::Abstained(CoverAbstention::Cover(
            CoverLimit {
                resource: CoverResource::ExpressionDepth,
                attempted: depth,
                limit: caps.max_expression_depth,
            },
        )));
    }
    if let Some(reason) = charge_compact_work(work, 1, caps) {
        return Ok(PartialMaskStatus::Abstained(reason));
    }
    let child_depth = depth.saturating_add(1);
    let mask = match expression {
        SemanticExpr::Const(false) => PARTIAL_FALSE,
        SemanticExpr::Const(true) => PARTIAL_TRUE,
        SemanticExpr::Atom(atom) => {
            let Some(&assignment) = assignments.get(atom.index()) else {
                return Err(CoverError::PartialExpressionAtomOutOfRange {
                    atom: *atom,
                    atom_count: problem.atoms.len(),
                });
            };
            match assignment {
                0 => PARTIAL_FALSE,
                1 => PARTIAL_TRUE,
                PARTIAL_UNKNOWN => PARTIAL_BOTH,
                _ => {
                    return Err(CoverError::AllocationFailed {
                        context: "invalid partial truth value",
                    });
                }
            }
        }
        SemanticExpr::Not(child) => {
            let child = match partial_expression_mask(
                problem,
                child,
                assignments,
                child_depth,
                work,
                caps,
            )? {
                PartialMaskStatus::Mask(mask) => mask,
                PartialMaskStatus::Abstained(reason) => {
                    return Ok(PartialMaskStatus::Abstained(reason));
                }
            };
            ((child & PARTIAL_FALSE) << 1) | ((child & PARTIAL_TRUE) >> 1)
        }
        SemanticExpr::And(children) => {
            let mut true_possible = true;
            let mut false_possible = false;
            for child in children.iter() {
                let child = match partial_expression_mask(
                    problem,
                    child,
                    assignments,
                    child_depth,
                    work,
                    caps,
                )? {
                    PartialMaskStatus::Mask(mask) => mask,
                    PartialMaskStatus::Abstained(reason) => {
                        return Ok(PartialMaskStatus::Abstained(reason));
                    }
                };
                true_possible &= child & PARTIAL_TRUE != 0;
                false_possible |= child & PARTIAL_FALSE != 0;
            }
            u8::from(false_possible) | (u8::from(true_possible) << 1)
        }
        SemanticExpr::Or(children) => {
            let mut true_possible = false;
            let mut false_possible = true;
            for child in children.iter() {
                let child = match partial_expression_mask(
                    problem,
                    child,
                    assignments,
                    child_depth,
                    work,
                    caps,
                )? {
                    PartialMaskStatus::Mask(mask) => mask,
                    PartialMaskStatus::Abstained(reason) => {
                        return Ok(PartialMaskStatus::Abstained(reason));
                    }
                };
                true_possible |= child & PARTIAL_TRUE != 0;
                false_possible &= child & PARTIAL_FALSE != 0;
            }
            u8::from(false_possible) | (u8::from(true_possible) << 1)
        }
        SemanticExpr::Iff(children) => {
            let mut masks = Vec::new();
            masks
                .try_reserve_exact(children.len())
                .map_err(|_| CoverError::AllocationFailed {
                    context: "partial iff masks",
                })?;
            for child in children.iter() {
                match partial_expression_mask(problem, child, assignments, child_depth, work, caps)?
                {
                    PartialMaskStatus::Mask(mask) => masks.push(mask),
                    PartialMaskStatus::Abstained(reason) => {
                        return Ok(PartialMaskStatus::Abstained(reason));
                    }
                }
            }
            if masks.len() <= 1 {
                PARTIAL_TRUE
            } else {
                let all_false = masks.iter().all(|mask| mask & PARTIAL_FALSE != 0);
                let all_true = masks.iter().all(|mask| mask & PARTIAL_TRUE != 0);
                let first_false = masks.iter().position(|mask| mask & PARTIAL_FALSE != 0);
                let first_true = masks.iter().position(|mask| mask & PARTIAL_TRUE != 0);
                let false_count = masks
                    .iter()
                    .filter(|mask| *mask & PARTIAL_FALSE != 0)
                    .count();
                let true_count = masks
                    .iter()
                    .filter(|mask| *mask & PARTIAL_TRUE != 0)
                    .count();
                let unequal = first_false.is_some()
                    && first_true.is_some()
                    && (first_false != first_true || false_count > 1 || true_count > 1);
                u8::from(unequal) | (u8::from(all_false || all_true) << 1)
            }
        }
        SemanticExpr::Ite(condition, then_expression, else_expression) => {
            let condition = match partial_expression_mask(
                problem,
                condition,
                assignments,
                child_depth,
                work,
                caps,
            )? {
                PartialMaskStatus::Mask(mask) => mask,
                PartialMaskStatus::Abstained(reason) => {
                    return Ok(PartialMaskStatus::Abstained(reason));
                }
            };
            let mut result = 0u8;
            if condition & PARTIAL_TRUE != 0 {
                match partial_expression_mask(
                    problem,
                    then_expression,
                    assignments,
                    child_depth,
                    work,
                    caps,
                )? {
                    PartialMaskStatus::Mask(mask) => result |= mask,
                    PartialMaskStatus::Abstained(reason) => {
                        return Ok(PartialMaskStatus::Abstained(reason));
                    }
                }
            }
            if condition & PARTIAL_FALSE != 0 {
                match partial_expression_mask(
                    problem,
                    else_expression,
                    assignments,
                    child_depth,
                    work,
                    caps,
                )? {
                    PartialMaskStatus::Mask(mask) => result |= mask,
                    PartialMaskStatus::Abstained(reason) => {
                        return Ok(PartialMaskStatus::Abstained(reason));
                    }
                }
            }
            result
        }
    };
    Ok(PartialMaskStatus::Mask(mask))
}

fn required_node_count(source_atom_count: usize) -> Option<usize> {
    let mut level_width = 1usize;
    let mut total = 1usize;
    for _ in 0..source_atom_count {
        level_width = level_width.checked_mul(2)?;
        total = total.checked_add(level_width)?;
    }
    Some(total)
}

fn build_subtree(
    depth: usize,
    source_atom_count: usize,
    nodes: &mut Vec<CoverNode>,
) -> Option<CoverNodeId> {
    if depth == source_atom_count {
        let id = CoverNodeId::new(u32::try_from(nodes.len()).ok()?);
        nodes.push(CoverNode::Leaf);
        return Some(id);
    }
    let when_false = build_subtree(depth + 1, source_atom_count, nodes)?;
    let when_true = build_subtree(depth + 1, source_atom_count, nodes)?;
    let id = CoverNodeId::new(u32::try_from(nodes.len()).ok()?);
    nodes.push(CoverNode::Split {
        atom: AtomId::new(u32::try_from(depth).ok()?),
        when_false,
        when_true,
    });
    Some(id)
}

pub(crate) fn check_cover(
    problem: &SemanticProblem,
    proof: &CoverProof,
    caps: CoverCaps,
) -> Result<CoverCheck, CoverError> {
    let atom_count = problem.atoms.len();
    if proof.source_atom_count != atom_count {
        return Err(CoverError::SourceAtomCountMismatch {
            declared: proof.source_atom_count,
            actual: atom_count,
        });
    }
    if proof.root.index() >= proof.nodes.len() {
        return Err(CoverError::RootOutOfRange {
            root: proof.root,
            node_count: proof.nodes.len(),
        });
    }
    match &proof.nodes[proof.root.index()] {
        CoverNode::RootLiteralConflict { atom } => {
            return check_root_literal_conflict(problem, proof, *atom, caps);
        }
        CoverNode::RootTheoryConflict => {
            return check_root_theory_conflict(problem, proof, caps);
        }
        CoverNode::RootDisjunctionConflict { disjunction } => {
            return check_root_disjunction_conflict(problem, proof, *disjunction, caps);
        }
        CoverNode::RootPropagationConflict => {
            return check_root_propagation_conflict(problem, proof, caps);
        }
        CoverNode::PartialConflict | CoverNode::PrunedSplit { .. } => {
            return check_pruned_cover(problem, proof, caps);
        }
        CoverNode::Leaf | CoverNode::Split { .. } => {}
    }
    for (resource, attempted, limit) in [
        (
            CoverResource::SourceAtoms,
            atom_count,
            caps.max_source_atoms,
        ),
        (CoverResource::Depth, atom_count, caps.max_depth),
        (CoverResource::Nodes, proof.nodes.len(), caps.max_nodes),
    ] {
        if attempted > limit {
            return Ok(CoverCheck::Abstained(CoverAbstention::Cover(CoverLimit {
                resource,
                attempted,
                limit,
            })));
        }
    }
    let mut visited = Vec::new();
    visited
        .try_reserve_exact(proof.nodes.len())
        .map_err(|_| CoverError::AllocationFailed {
            context: "cover visited set",
        })?;
    visited.resize(proof.nodes.len(), false);
    let mut stack = Vec::<(CoverNodeId, Box<[bool]>)>::new();
    stack
        .try_reserve_exact(atom_count.saturating_add(1))
        .map_err(|_| CoverError::AllocationFailed {
            context: "cover traversal stack",
        })?;
    stack.push((proof.root, Box::new([])));

    let mut receipt = CoverReceipt {
        source_atom_count: atom_count,
        nodes_checked: 0,
        leaves_closed: 0,
        maximum_depth: 0,
        check_work: 0,
    };
    while let Some((node_id, assignment)) = stack.pop() {
        let node_index = node_id.index();
        let Some(node) = proof.nodes.get(node_index) else {
            return Err(CoverError::ChildOutOfRange {
                parent: proof.root,
                child: node_id,
                node_count: proof.nodes.len(),
            });
        };
        if visited[node_index] {
            return Err(CoverError::ReusedNode { node: node_id });
        }
        visited[node_index] = true;
        receipt.nodes_checked += 1;
        receipt.maximum_depth = receipt.maximum_depth.max(assignment.len());
        let charge = assignment.len().checked_add(1).unwrap_or(usize::MAX);
        let attempted = receipt.check_work.checked_add(charge).unwrap_or(usize::MAX);
        if attempted > caps.max_check_work {
            return Ok(CoverCheck::Abstained(CoverAbstention::Cover(CoverLimit {
                resource: CoverResource::CheckWork,
                attempted,
                limit: caps.max_check_work,
            })));
        }
        receipt.check_work = attempted;

        match node {
            CoverNode::Leaf => {
                if assignment.len() != atom_count {
                    return Err(CoverError::PrematureLeaf {
                        node: node_id,
                        depth: assignment.len(),
                        expected_depth: atom_count,
                    });
                }
                match model::validate_complete(problem, &assignment, caps.model)? {
                    ModelValidation::Valid(_) => {
                        return Err(CoverError::OpenLeaf {
                            node: node_id,
                            assignment,
                        });
                    }
                    ModelValidation::Invalid(_) => receipt.leaves_closed += 1,
                    ModelValidation::Abstained(limit) => {
                        return Ok(CoverCheck::Abstained(CoverAbstention::Model(limit)));
                    }
                }
            }
            CoverNode::RootLiteralConflict { .. } => {
                return Err(CoverError::RootLiteralConflictHasExtraNodes {
                    nodes: proof.nodes.len(),
                });
            }
            CoverNode::RootTheoryConflict => {
                return Err(CoverError::RootTheoryConflictHasExtraNodes {
                    nodes: proof.nodes.len(),
                });
            }
            CoverNode::RootDisjunctionConflict { .. } => {
                return Err(CoverError::RootDisjunctionConflictHasExtraNodes {
                    nodes: proof.nodes.len(),
                });
            }
            CoverNode::RootPropagationConflict => {
                return Err(CoverError::RootPropagationConflictHasExtraNodes {
                    nodes: proof.nodes.len(),
                });
            }
            CoverNode::PartialConflict | CoverNode::PrunedSplit { .. } => {
                return Err(CoverError::PrunedUnexpectedNode { node: node_id });
            }
            CoverNode::Split {
                atom,
                when_false,
                when_true,
            } => {
                let depth = assignment.len();
                if depth >= atom_count {
                    return Err(CoverError::SplitAfterCompleteAssignment {
                        node: node_id,
                        depth,
                    });
                }
                let expected = AtomId::new(depth as u32);
                if *atom != expected {
                    return Err(CoverError::NonCanonicalSplit {
                        node: node_id,
                        atom: *atom,
                        expected,
                    });
                }
                for child in [*when_false, *when_true] {
                    if child.index() >= proof.nodes.len() {
                        return Err(CoverError::ChildOutOfRange {
                            parent: node_id,
                            child,
                            node_count: proof.nodes.len(),
                        });
                    }
                    if child.index() >= node_index {
                        return Err(CoverError::NonPostorderChild {
                            parent: node_id,
                            child,
                        });
                    }
                }
                let false_assignment = extend_assignment(&assignment, false)?;
                let true_assignment = extend_assignment(&assignment, true)?;
                stack.push((*when_true, true_assignment));
                stack.push((*when_false, false_assignment));
            }
        }
    }

    let reachable = visited.iter().filter(|&&value| value).count();
    if reachable != proof.nodes.len() {
        return Err(CoverError::UnreachableNodes {
            reachable,
            total: proof.nodes.len(),
        });
    }
    Ok(CoverCheck::Valid(receipt))
}

fn check_root_literal_conflict(
    problem: &SemanticProblem,
    proof: &CoverProof,
    atom: AtomId,
    caps: CoverCaps,
) -> Result<CoverCheck, CoverError> {
    if proof.root.index() != 0 || proof.nodes.len() != 1 {
        return Err(CoverError::RootLiteralConflictHasExtraNodes {
            nodes: proof.nodes.len(),
        });
    }
    if atom.index() >= problem.atoms.len() {
        return Err(CoverError::RootLiteralConflictAtomOutOfRange {
            atom,
            atom_count: problem.atoms.len(),
        });
    }
    let mut positive = false;
    let mut negative = false;
    for literal in &problem.root_literals {
        if literal.atom == atom {
            if literal.positive {
                positive = true;
            } else {
                negative = true;
            }
        }
    }
    let assertion_work = scan_asserted_root_literals(problem, |asserted, polarity| {
        if asserted == atom {
            if polarity {
                positive = true;
            } else {
                negative = true;
            }
        }
        Ok(())
    })?;
    let attempted_work = problem
        .root_literals
        .len()
        .saturating_add(assertion_work)
        .saturating_add(1);
    if proof.nodes.len() > caps.max_nodes {
        return Ok(CoverCheck::Abstained(CoverAbstention::Cover(CoverLimit {
            resource: CoverResource::Nodes,
            attempted: proof.nodes.len(),
            limit: caps.max_nodes,
        })));
    }
    if attempted_work > caps.max_check_work {
        return Ok(CoverCheck::Abstained(CoverAbstention::Cover(CoverLimit {
            resource: CoverResource::CheckWork,
            attempted: attempted_work,
            limit: caps.max_check_work,
        })));
    }
    if !positive || !negative {
        return Err(CoverError::RootLiteralConflictNotProved { atom });
    }
    Ok(CoverCheck::Valid(CoverReceipt {
        source_atom_count: problem.atoms.len(),
        nodes_checked: 1,
        leaves_closed: 1,
        maximum_depth: 0,
        check_work: attempted_work,
    }))
}

fn check_root_theory_conflict(
    problem: &SemanticProblem,
    proof: &CoverProof,
    caps: CoverCaps,
) -> Result<CoverCheck, CoverError> {
    if proof.root.index() != 0 || proof.nodes.len() != 1 {
        return Err(CoverError::RootTheoryConflictHasExtraNodes {
            nodes: proof.nodes.len(),
        });
    }
    if proof.nodes.len() > caps.max_nodes {
        return Ok(CoverCheck::Abstained(CoverAbstention::Cover(CoverLimit {
            resource: CoverResource::Nodes,
            attempted: proof.nodes.len(),
            limit: caps.max_nodes,
        })));
    }
    match prove_root_theory_conflict(problem, caps)? {
        CompactAttempt::Proved(work) => Ok(compact_receipt(problem, work)),
        CompactAttempt::NotProved => Err(CoverError::RootTheoryConflictNotProved),
        CompactAttempt::Abstained(reason) => Ok(CoverCheck::Abstained(reason)),
    }
}

fn check_root_disjunction_conflict(
    problem: &SemanticProblem,
    proof: &CoverProof,
    disjunction: u32,
    caps: CoverCaps,
) -> Result<CoverCheck, CoverError> {
    if proof.root.index() != 0 || proof.nodes.len() != 1 {
        return Err(CoverError::RootDisjunctionConflictHasExtraNodes {
            nodes: proof.nodes.len(),
        });
    }
    if proof.nodes.len() > caps.max_nodes {
        return Ok(CoverCheck::Abstained(CoverAbstention::Cover(CoverLimit {
            resource: CoverResource::Nodes,
            attempted: proof.nodes.len(),
            limit: caps.max_nodes,
        })));
    }
    match prove_root_disjunction_conflict(problem, disjunction, caps)? {
        CompactAttempt::Proved(work) => Ok(compact_receipt(problem, work)),
        CompactAttempt::NotProved => {
            Err(CoverError::RootDisjunctionConflictNotProved { disjunction })
        }
        CompactAttempt::Abstained(reason) => Ok(CoverCheck::Abstained(reason)),
    }
}

fn check_root_propagation_conflict(
    problem: &SemanticProblem,
    proof: &CoverProof,
    caps: CoverCaps,
) -> Result<CoverCheck, CoverError> {
    if proof.root.index() != 0 || proof.nodes.len() != 1 {
        return Err(CoverError::RootPropagationConflictHasExtraNodes {
            nodes: proof.nodes.len(),
        });
    }
    if proof.nodes.len() > caps.max_nodes {
        return Ok(CoverCheck::Abstained(CoverAbstention::Cover(CoverLimit {
            resource: CoverResource::Nodes,
            attempted: proof.nodes.len(),
            limit: caps.max_nodes,
        })));
    }
    match prove_root_propagation_conflict(problem, caps)? {
        CompactAttempt::Proved(work) => Ok(compact_receipt(problem, work)),
        CompactAttempt::NotProved => Err(CoverError::RootPropagationConflictNotProved),
        CompactAttempt::Abstained(reason) => Ok(CoverCheck::Abstained(reason)),
    }
}

fn compact_receipt(problem: &SemanticProblem, work: usize) -> CoverCheck {
    CoverCheck::Valid(CoverReceipt {
        source_atom_count: problem.atoms.len(),
        nodes_checked: 1,
        leaves_closed: 1,
        maximum_depth: 0,
        check_work: work,
    })
}

enum PrunedCheckFrame {
    Visit {
        node: CoverNodeId,
        depth: usize,
    },
    AfterFalse {
        parent: CoverNodeId,
        atom: AtomId,
        when_true: CoverNodeId,
        depth: usize,
    },
    AfterTrue {
        atom: AtomId,
    },
}

fn check_pruned_cover(
    problem: &SemanticProblem,
    proof: &CoverProof,
    caps: CoverCaps,
) -> Result<CoverCheck, CoverError> {
    if proof.nodes.len() > caps.max_nodes {
        return Ok(CoverCheck::Abstained(CoverAbstention::Cover(CoverLimit {
            resource: CoverResource::Nodes,
            attempted: proof.nodes.len(),
            limit: caps.max_nodes,
        })));
    }
    let context = collect_root_assertion_context(problem)?;
    let mut receipt = CoverReceipt {
        source_atom_count: problem.atoms.len(),
        nodes_checked: 0,
        leaves_closed: 0,
        maximum_depth: 0,
        check_work: 0,
    };
    if let Some(reason) = charge_compact_work(&mut receipt.check_work, context.work, caps) {
        return Ok(CoverCheck::Abstained(reason));
    }
    let mut assignments = Vec::new();
    assignments
        .try_reserve_exact(problem.atoms.len())
        .map_err(|_| CoverError::AllocationFailed {
            context: "pruned cover checker assignment",
        })?;
    assignments.resize(problem.atoms.len(), PARTIAL_UNKNOWN);
    let mut visited = Vec::new();
    visited
        .try_reserve_exact(proof.nodes.len())
        .map_err(|_| CoverError::AllocationFailed {
            context: "pruned cover visited set",
        })?;
    visited.resize(proof.nodes.len(), false);
    let mut stack = Vec::new();
    stack
        .try_reserve(caps.max_pruned_depth.min(4_096).saturating_add(1))
        .map_err(|_| CoverError::AllocationFailed {
            context: "pruned cover checker stack",
        })?;
    stack.push(PrunedCheckFrame::Visit {
        node: proof.root,
        depth: 0,
    });

    while let Some(frame) = stack.pop() {
        match frame {
            PrunedCheckFrame::Visit { node, depth } => {
                if depth > caps.max_pruned_depth {
                    return Ok(CoverCheck::Abstained(CoverAbstention::Cover(CoverLimit {
                        resource: CoverResource::PrunedDepth,
                        attempted: depth,
                        limit: caps.max_pruned_depth,
                    })));
                }
                let Some(entry) = proof.nodes.get(node.index()) else {
                    return Err(CoverError::ChildOutOfRange {
                        parent: proof.root,
                        child: node,
                        node_count: proof.nodes.len(),
                    });
                };
                if visited[node.index()] {
                    return Err(CoverError::ReusedNode { node });
                }
                visited[node.index()] = true;
                receipt.nodes_checked = receipt.nodes_checked.saturating_add(1);
                receipt.maximum_depth = receipt.maximum_depth.max(depth);
                if let Some(reason) = charge_compact_work(&mut receipt.check_work, 1, caps) {
                    return Ok(CoverCheck::Abstained(reason));
                }
                match entry {
                    CoverNode::PartialConflict => match partial_conflict(
                        problem,
                        &context.literals,
                        &assignments,
                        &mut receipt.check_work,
                        caps,
                    )? {
                        PartialConflictStatus::Conflict => {
                            receipt.leaves_closed = receipt.leaves_closed.saturating_add(1);
                        }
                        PartialConflictStatus::Open => {
                            return Err(CoverError::OpenPartialLeaf {
                                node,
                                assignment: assigned_literals(&assignments)?,
                            });
                        }
                        PartialConflictStatus::Abstained(reason) => {
                            return Ok(CoverCheck::Abstained(reason));
                        }
                    },
                    CoverNode::PrunedSplit {
                        atom,
                        when_false,
                        when_true,
                    } => {
                        let Some(slot) = assignments.get_mut(atom.index()) else {
                            return Err(CoverError::PartialExpressionAtomOutOfRange {
                                atom: *atom,
                                atom_count: assignments.len(),
                            });
                        };
                        if *slot != PARTIAL_UNKNOWN {
                            return Err(CoverError::RepeatedPrunedSplit { node, atom: *atom });
                        }
                        for child in [*when_false, *when_true] {
                            if child.index() >= proof.nodes.len() {
                                return Err(CoverError::ChildOutOfRange {
                                    parent: node,
                                    child,
                                    node_count: proof.nodes.len(),
                                });
                            }
                            if child.index() >= node.index() {
                                return Err(CoverError::NonPostorderChild {
                                    parent: node,
                                    child,
                                });
                            }
                        }
                        *slot = 0;
                        stack.push(PrunedCheckFrame::AfterFalse {
                            parent: node,
                            atom: *atom,
                            when_true: *when_true,
                            depth,
                        });
                        stack.push(PrunedCheckFrame::Visit {
                            node: *when_false,
                            depth: depth.saturating_add(1),
                        });
                    }
                    CoverNode::Leaf
                    | CoverNode::RootLiteralConflict { .. }
                    | CoverNode::RootTheoryConflict
                    | CoverNode::RootDisjunctionConflict { .. }
                    | CoverNode::RootPropagationConflict
                    | CoverNode::Split { .. } => {
                        return Err(CoverError::PrunedUnexpectedNode { node });
                    }
                }
            }
            PrunedCheckFrame::AfterFalse {
                parent,
                atom,
                when_true,
                depth,
            } => {
                let Some(slot) = assignments.get_mut(atom.index()) else {
                    return Err(CoverError::PartialExpressionAtomOutOfRange {
                        atom,
                        atom_count: assignments.len(),
                    });
                };
                if *slot != 0 {
                    return Err(CoverError::RepeatedPrunedSplit { node: parent, atom });
                }
                *slot = 1;
                stack.push(PrunedCheckFrame::AfterTrue { atom });
                stack.push(PrunedCheckFrame::Visit {
                    node: when_true,
                    depth: depth.saturating_add(1),
                });
            }
            PrunedCheckFrame::AfterTrue { atom } => {
                let Some(slot) = assignments.get_mut(atom.index()) else {
                    return Err(CoverError::PartialExpressionAtomOutOfRange {
                        atom,
                        atom_count: assignments.len(),
                    });
                };
                *slot = PARTIAL_UNKNOWN;
            }
        }
    }

    let reachable = visited.iter().filter(|&&value| value).count();
    if reachable != proof.nodes.len() {
        return Err(CoverError::UnreachableNodes {
            reachable,
            total: proof.nodes.len(),
        });
    }
    Ok(CoverCheck::Valid(receipt))
}

fn scan_asserted_root_literals<F>(
    problem: &SemanticProblem,
    mut visit: F,
) -> Result<usize, CoverError>
where
    F: FnMut(AtomId, bool) -> Result<(), CoverError>,
{
    let mut stack = Vec::new();
    stack
        .try_reserve(problem.assertions.len())
        .map_err(|_| CoverError::AllocationFailed {
            context: "root-literal assertion stack",
        })?;
    stack.extend(problem.assertions.iter());
    let mut work = 0usize;
    while let Some(expression) = stack.pop() {
        work = work.saturating_add(1);
        match expression {
            SemanticExpr::Atom(atom) => visit(*atom, true)?,
            SemanticExpr::Not(child) => {
                if let SemanticExpr::Atom(atom) = child.as_ref() {
                    visit(*atom, false)?;
                }
            }
            SemanticExpr::And(children) => {
                stack
                    .try_reserve(children.len())
                    .map_err(|_| CoverError::AllocationFailed {
                        context: "root-literal assertion stack",
                    })?;
                stack.extend(children.iter());
            }
            SemanticExpr::Const(_)
            | SemanticExpr::Or(_)
            | SemanticExpr::Iff(_)
            | SemanticExpr::Ite(_, _, _) => {}
        }
    }
    Ok(work)
}

fn extend_assignment(values: &[bool], value: bool) -> Result<Box<[bool]>, CoverError> {
    let mut extended = Vec::new();
    extended
        .try_reserve_exact(values.len().saturating_add(1))
        .map_err(|_| CoverError::AllocationFailed {
            context: "cover branch assignment",
        })?;
    extended.extend_from_slice(values);
    extended.push(value);
    Ok(extended.into_boxed_slice())
}

#[cfg(test)]
mod tests {
    use super::super::super::parse_problem;
    use super::super::semantic::project;
    use super::*;

    fn projected(source: &str) -> SemanticProblem {
        project(&parse_problem(source).unwrap()).unwrap()
    }

    fn equality_problem(assertions: &str) -> SemanticProblem {
        projected(&format!(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-fun a () U)\n\
             (declare-fun b () U)\n\
             {assertions}\n\
             (check-sat)"
        ))
    }

    fn built(problem: &SemanticProblem) -> CoverProof {
        match build_complete_cover(problem.atoms.len(), CoverCaps::default()) {
            CoverBuild::Built(proof) => proof,
            CoverBuild::Abstained(limit) => panic!("unexpected cover cap: {limit:?}"),
        }
    }

    #[test]
    fn complete_cover_accepts_unsat_and_rejects_sat() {
        let unsat = equality_problem("(assert (= a b)) (assert (distinct a b))");
        let proof = built(&unsat);
        let receipt = check_cover(&unsat, &proof, CoverCaps::default()).unwrap();
        assert!(matches!(receipt, CoverCheck::Valid(_)));

        let sat = equality_problem("(assert (or (= a b) (distinct a b)))");
        let error = check_cover(&sat, &built(&sat), CoverCaps::default()).unwrap_err();
        assert!(matches!(error, CoverError::OpenLeaf { .. }));
    }

    #[test]
    fn root_literal_conflict_is_constant_size_and_independently_checked() {
        let mut source = String::from("(set-logic QF_UF)\n(declare-sort U 0)\n");
        for index in 0..21 {
            source.push_str(&format!("(declare-fun a{index} () U)\n"));
        }
        for index in 1..20 {
            source.push_str(&format!("(assert (= a0 a{index}))\n"));
        }
        source.push_str("(assert (distinct a0 a1))\n(check-sat)\n");
        let problem = projected(&source);
        assert!(problem.atoms.len() > CoverCaps::default().max_source_atoms);

        let proof = build_root_literal_conflict(&problem)
            .unwrap()
            .expect("opposite root literals must be detected");
        assert_eq!(proof.nodes.len(), 1);
        let CoverCheck::Valid(receipt) =
            check_cover(&problem, &proof, CoverCaps::default()).unwrap()
        else {
            panic!("compact root conflict unexpectedly abstained");
        };
        assert_eq!(receipt.nodes_checked, 1);
        assert_eq!(receipt.maximum_depth, 0);

        let mut mutated = proof;
        let CoverNode::RootLiteralConflict { atom } = &mut mutated.nodes[0] else {
            panic!("expected root conflict node");
        };
        *atom = AtomId::new(problem.atoms.len() as u32);
        assert!(matches!(
            check_cover(&problem, &mutated, CoverCaps::default()),
            Err(CoverError::RootLiteralConflictAtomOutOfRange { .. })
        ));
    }

    #[test]
    fn root_theory_conflict_is_constant_size_and_ignores_parser_flag() {
        let mut problem = projected(
            "(set-logic QF_UF)\n\
             (declare-sort U 0)\n\
             (declare-fun a () U)\n\
             (declare-fun b () U)\n\
             (declare-fun f (U) U)\n\
             (assert (= a b))\n\
             (assert (distinct (f a) (f b)))\n\
             (check-sat)",
        );
        problem.stats.contradiction = false;
        let proof = build_root_theory_conflict(&problem, CoverCaps::default())
            .unwrap()
            .expect("asserted congruence conflict must have a compact proof");
        assert_eq!(proof.nodes.as_ref(), &[CoverNode::RootTheoryConflict]);
        assert!(matches!(
            check_cover(&problem, &proof, CoverCaps::default()).unwrap(),
            CoverCheck::Valid(_)
        ));

        let mut weakened = problem.clone();
        weakened.assertions[0] = SemanticExpr::Const(true);
        assert!(matches!(
            check_cover(&weakened, &proof, CoverCaps::default()),
            Err(CoverError::RootTheoryConflictNotProved)
        ));
    }

    #[test]
    fn disjunctive_theory_conflict_closes_all_branches_without_a_cube() {
        let mut source = String::from(
            "(set-logic QF_UF)\n(declare-sort U 0)\n\
             (declare-fun x0 () U)\n(declare-fun x1 () U)\n",
        );
        for branch in 0..24 {
            source.push_str(&format!("(declare-fun d{branch} () U)\n"));
        }
        source.push_str("(assert (distinct x0 x1))\n(assert (or\n");
        for branch in 0..24 {
            source.push_str(&format!("  (and (= x0 d{branch}) (= d{branch} x1))\n"));
        }
        source.push_str("))\n(check-sat)\n");
        let mut problem = projected(&source);
        problem.stats.contradiction = false;
        assert!(problem.atoms.len() > CoverCaps::default().max_source_atoms);

        let proof = build_root_disjunction_conflict(&problem, CoverCaps::default())
            .unwrap()
            .expect("every asserted disjunct must close against the root disequality");
        let CoverNode::RootDisjunctionConflict { disjunction } = proof.nodes[0] else {
            panic!("expected a compact root-disjunction proof");
        };
        assert_eq!(disjunction, 0);
        let CoverCheck::Valid(receipt) =
            check_cover(&problem, &proof, CoverCaps::default()).unwrap()
        else {
            panic!("compact disjunction proof unexpectedly abstained");
        };
        assert_eq!(receipt.nodes_checked, 1);
        assert_eq!(receipt.maximum_depth, 0);

        let mut weakened = problem.clone();
        let SemanticExpr::Or(branches) = &mut weakened.assertions[1] else {
            panic!("second assertion must be the tested disjunction");
        };
        branches[0] = SemanticExpr::Const(true);
        assert!(matches!(
            check_cover(&weakened, &proof, CoverCaps::default()),
            Err(CoverError::RootDisjunctionConflictNotProved { disjunction: 0 })
        ));

        let bad_id = single_node_proof(
            problem.atoms.len(),
            CoverNode::RootDisjunctionConflict {
                disjunction: u32::MAX,
            },
        );
        assert!(matches!(
            check_cover(&problem, &bad_id, CoverCaps::default()),
            Err(CoverError::RootDisjunctionOutOfRange { .. })
        ));

        let mut capped = CoverCaps::default();
        capped.max_check_work = 0;
        assert!(
            build_root_disjunction_conflict(&problem, capped)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            check_cover(&problem, &proof, capped).unwrap(),
            CoverCheck::Abstained(CoverAbstention::Cover(CoverLimit {
                resource: CoverResource::CheckWork,
                ..
            }))
        ));
    }

    #[test]
    fn pruned_cover_closes_large_boolean_euf_formula_before_irrelevant_atoms() {
        let mut source = String::from(
            "(set-logic QF_UF)\n\
             (declare-fun p () Bool)\n\
             (declare-fun q () Bool)\n\
             (assert (= p q))\n\
             (assert p)\n\
             (assert (not q))\n",
        );
        for index in 0..20 {
            source.push_str(&format!("(declare-fun r{index} () Bool)\n"));
            source.push_str(&format!("(assert (or r{index} (not r{index})))\n"));
        }
        source.push_str("(check-sat)\n");
        let mut problem = projected(&source);
        problem.stats.contradiction = false;
        assert!(problem.atoms.len() > CoverCaps::default().max_source_atoms);
        assert!(
            build_root_theory_conflict(&problem, CoverCaps::default())
                .unwrap()
                .is_none()
        );
        assert!(
            build_root_disjunction_conflict(&problem, CoverCaps::default())
                .unwrap()
                .is_none()
        );

        let PrunedCoverBuild::Built(proof) =
            build_pruned_cover(&problem, CoverCaps::default()).unwrap()
        else {
            panic!("bounded pruned cover unexpectedly abstained");
        };
        assert!(proof.nodes.len() < 16);
        let CoverCheck::Valid(receipt) =
            check_cover(&problem, &proof, CoverCaps::default()).unwrap()
        else {
            panic!("pruned cover unexpectedly abstained");
        };
        assert!(receipt.leaves_closed >= 2);
        assert!(receipt.maximum_depth < problem.atoms.len());

        let mut weakened = problem.clone();
        weakened.assertions[0] = SemanticExpr::Const(true);
        assert!(matches!(
            check_cover(&weakened, &proof, CoverCaps::default()),
            Err(CoverError::OpenPartialLeaf { .. })
        ));

        let mut capped = CoverCaps::default();
        capped.max_nodes = 0;
        assert!(matches!(
            build_pruned_cover(&problem, capped).unwrap(),
            PrunedCoverBuild::Abstained(CoverAbstention::Cover(CoverLimit {
                resource: CoverResource::Nodes,
                ..
            }))
        ));
    }

    #[test]
    fn root_propagation_proof_replays_boolean_units_and_rejects_mutation() {
        let mut problem = projected(
            "(set-logic QF_UF)\n\
             (declare-fun p () Bool)\n\
             (declare-fun q () Bool)\n\
             (assert (= p q))\n\
             (assert p)\n\
             (assert (not q))\n\
             (check-sat)",
        );
        problem.stats.contradiction = false;
        let proof = build_root_propagation_conflict(&problem, CoverCaps::default())
            .unwrap()
            .expect("root unit propagation must derive the Boolean conflict");
        assert_eq!(proof.nodes.as_ref(), &[CoverNode::RootPropagationConflict]);
        assert!(matches!(
            check_cover(&problem, &proof, CoverCaps::default()).unwrap(),
            CoverCheck::Valid(_)
        ));

        let mut weakened = problem.clone();
        weakened.assertions[0] = SemanticExpr::Const(true);
        assert!(matches!(
            check_cover(&weakened, &proof, CoverCaps::default()),
            Err(CoverError::RootPropagationConflictNotProved)
        ));

        let mut capped = CoverCaps::default();
        capped.max_check_work = 0;
        assert!(
            build_root_propagation_conflict(&problem, capped)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            check_cover(&problem, &proof, capped).unwrap(),
            CoverCheck::Abstained(CoverAbstention::Cover(CoverLimit {
                resource: CoverResource::CheckWork,
                ..
            }))
        ));
    }

    #[test]
    fn partial_boolean_masks_equal_all_consistent_completions() {
        let problem = projected(
            "(set-logic QF_UF)\n\
             (declare-fun p () Bool)\n\
             (declare-fun q () Bool)\n\
             (assert (or p q))\n\
             (check-sat)",
        );
        assert_eq!(problem.atoms.len(), 2);
        let p = SemanticExpr::Atom(AtomId::new(0));
        let q = SemanticExpr::Atom(AtomId::new(1));
        let expressions = vec![
            SemanticExpr::Const(false),
            SemanticExpr::Const(true),
            p.clone(),
            SemanticExpr::Not(Box::new(p.clone())),
            SemanticExpr::And(vec![p.clone(), q.clone()].into_boxed_slice()),
            SemanticExpr::Or(vec![p.clone(), q.clone()].into_boxed_slice()),
            SemanticExpr::Iff(vec![p.clone(), q.clone()].into_boxed_slice()),
            SemanticExpr::Ite(
                Box::new(p.clone()),
                Box::new(q.clone()),
                Box::new(SemanticExpr::Not(Box::new(q))),
            ),
        ];
        for first in [PARTIAL_UNKNOWN, 0, 1] {
            for second in [PARTIAL_UNKNOWN, 0, 1] {
                let assignments = [first, second];
                for expression in &expressions {
                    let mut work = 0usize;
                    let PartialMaskStatus::Mask(actual) = partial_expression_mask(
                        &problem,
                        expression,
                        &assignments,
                        0,
                        &mut work,
                        CoverCaps::default(),
                    )
                    .unwrap() else {
                        panic!("tiny partial expression unexpectedly abstained");
                    };
                    let mut expected = 0u8;
                    for p_value in [false, true] {
                        if first != PARTIAL_UNKNOWN && (first == 1) != p_value {
                            continue;
                        }
                        for q_value in [false, true] {
                            if second != PARTIAL_UNKNOWN && (second == 1) != q_value {
                                continue;
                            }
                            let value = evaluate_test_expression(expression, &[p_value, q_value]);
                            expected |= if value { PARTIAL_TRUE } else { PARTIAL_FALSE };
                        }
                    }
                    assert_eq!(actual, expected, "{expression:?} under {assignments:?}");
                }
            }
        }
    }

    fn evaluate_test_expression(expression: &SemanticExpr, values: &[bool]) -> bool {
        match expression {
            SemanticExpr::Const(value) => *value,
            SemanticExpr::Atom(atom) => values[atom.index()],
            SemanticExpr::Not(child) => !evaluate_test_expression(child, values),
            SemanticExpr::And(children) => children
                .iter()
                .all(|child| evaluate_test_expression(child, values)),
            SemanticExpr::Or(children) => children
                .iter()
                .any(|child| evaluate_test_expression(child, values)),
            SemanticExpr::Iff(children) => children.first().is_none_or(|first| {
                let expected = evaluate_test_expression(first, values);
                children[1..]
                    .iter()
                    .all(|child| evaluate_test_expression(child, values) == expected)
            }),
            SemanticExpr::Ite(condition, then_expression, else_expression) => {
                if evaluate_test_expression(condition, values) {
                    evaluate_test_expression(then_expression, values)
                } else {
                    evaluate_test_expression(else_expression, values)
                }
            }
        }
    }

    #[test]
    fn builder_is_deterministic_and_canonical() {
        let problem = equality_problem("(assert (= a b))");
        let first = built(&problem);
        let second = built(&problem);
        assert_eq!(first, second);
        assert_eq!(first.nodes.len(), 3);
        assert_eq!(first.root.index(), 2);
    }

    #[test]
    fn checker_rejects_wrong_split_reuse_unreachable_and_bad_children() {
        let problem = equality_problem("(assert (= a b)) (assert (distinct a b))");
        let proof = built(&problem);

        let mut wrong_split = proof.clone();
        let CoverNode::Split { atom, .. } = &mut wrong_split.nodes[wrong_split.root.index()] else {
            panic!("root must split");
        };
        *atom = AtomId::new(1);
        assert!(matches!(
            check_cover(&problem, &wrong_split, CoverCaps::default()),
            Err(CoverError::NonCanonicalSplit { .. })
        ));

        let mut reused = proof.clone();
        let CoverNode::Split {
            when_false,
            when_true,
            ..
        } = &mut reused.nodes[reused.root.index()]
        else {
            panic!("root must split");
        };
        *when_true = *when_false;
        assert!(matches!(
            check_cover(&problem, &reused, CoverCaps::default()),
            Err(CoverError::ReusedNode { .. })
        ));

        let mut bad_child = proof.clone();
        let bad_child_count = bad_child.nodes.len();
        let CoverNode::Split { when_true, .. } = &mut bad_child.nodes[bad_child.root.index()]
        else {
            panic!("root must split");
        };
        *when_true = CoverNodeId::new(bad_child_count as u32);
        assert!(matches!(
            check_cover(&problem, &bad_child, CoverCaps::default()),
            Err(CoverError::ChildOutOfRange { .. })
        ));

        let mut unreachable_nodes = proof.nodes.to_vec();
        unreachable_nodes.push(CoverNode::Leaf);
        let unreachable = CoverProof {
            nodes: unreachable_nodes.into_boxed_slice(),
            ..proof
        };
        assert!(matches!(
            check_cover(&problem, &unreachable, CoverCaps::default()),
            Err(CoverError::UnreachableNodes { .. })
        ));
    }

    #[test]
    fn checker_rejects_premature_leaf_and_source_count_tampering() {
        let problem = equality_problem("(assert (= a b)) (assert (distinct a b))");
        let proof = CoverProof {
            source_atom_count: problem.atoms.len(),
            root: CoverNodeId::new(0),
            nodes: vec![CoverNode::Leaf].into_boxed_slice(),
        };
        assert!(matches!(
            check_cover(&problem, &proof, CoverCaps::default()),
            Err(CoverError::PrematureLeaf { .. })
        ));
        let mut wrong_count = proof;
        wrong_count.source_atom_count += 1;
        assert!(matches!(
            check_cover(&problem, &wrong_count, CoverCaps::default()),
            Err(CoverError::SourceAtomCountMismatch { .. })
        ));
    }

    #[test]
    fn explicit_caps_abstain_without_validating_unsat() {
        let problem = equality_problem("(assert (= a b)) (assert (distinct a b))");
        let mut caps = CoverCaps::default();
        caps.max_nodes = 2;
        assert!(matches!(
            build_complete_cover(problem.atoms.len(), caps),
            CoverBuild::Abstained(CoverLimit {
                resource: CoverResource::Nodes,
                ..
            })
        ));

        let proof = built(&problem);
        caps = CoverCaps::default();
        caps.max_check_work = 0;
        assert!(matches!(
            check_cover(&problem, &proof, caps).unwrap(),
            CoverCheck::Abstained(CoverAbstention::Cover(CoverLimit {
                resource: CoverResource::CheckWork,
                ..
            }))
        ));
    }

    #[test]
    fn model_checker_cap_propagates_as_cover_abstention() {
        let problem = equality_problem("(assert (= a b)) (assert (distinct a b))");
        let proof = built(&problem);
        let mut caps = CoverCaps::default();
        caps.model.max_work = 0;
        assert!(matches!(
            check_cover(&problem, &proof, caps).unwrap(),
            CoverCheck::Abstained(CoverAbstention::Model(_))
        ));
    }

    #[test]
    fn all_one_atom_formulas_have_the_expected_cover_status() {
        for (assertions, expected_unsat) in [
            ("(assert (= a b))", false),
            ("(assert (distinct a b))", false),
            ("(assert (= a b)) (assert (distinct a b))", true),
            ("(assert (or (= a b) (distinct a b)))", false),
        ] {
            let problem = equality_problem(assertions);
            let result = check_cover(&problem, &built(&problem), CoverCaps::default());
            assert_eq!(result.is_ok(), expected_unsat, "{assertions}");
        }
    }
}
