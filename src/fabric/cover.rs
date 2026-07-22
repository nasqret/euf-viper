#![forbid(unsafe_code)]

//! Exhaustive, independently checked UNSAT covers for the Fabric reference.
//!
//! This is a correctness oracle, not a competitive proof format. It covers
//! every total source-atom assignment and asks the independent model checker
//! to reject every leaf. Explicit caps make exponential growth an abstention.

use super::model::{self, ModelCaps, ModelError, ModelLimit, ModelValidation};
use super::native_clause::AtomId;
use super::semantic::SemanticProblem;
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
    pub(crate) max_nodes: usize,
    pub(crate) max_check_work: usize,
    pub(crate) model: ModelCaps,
}

impl Default for CoverCaps {
    fn default() -> Self {
        Self {
            max_source_atoms: 18,
            max_depth: 18,
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
    AllocationFailed {
        context: &'static str,
    },
    Model(ModelError),
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
            Self::AllocationFailed { context } => {
                write!(output, "allocation failed while building {context}")
            }
            Self::Model(error) => error.fmt(output),
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
            _ => None,
        }
    }
}

impl From<ModelError> for CoverError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
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
    if proof.root.index() >= proof.nodes.len() {
        return Err(CoverError::RootOutOfRange {
            root: proof.root,
            node_count: proof.nodes.len(),
        });
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
