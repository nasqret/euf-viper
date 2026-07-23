#![forbid(unsafe_code)]

//! Canonical existing-class-or-fresh actions for partition-native search.

use super::partition::{Partition, PartitionError, Relation, TermId};
use super::semantic::SemanticTerm;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PartitionAction {
    Merge {
        pivot: TermId,
        target: TermId,
    },
    Fresh {
        pivot: TermId,
        separate_from: Box<[TermId]>,
    },
}

impl PartitionAction {
    pub(crate) const fn pivot(&self) -> TermId {
        match self {
            Self::Merge { pivot, .. } | Self::Fresh { pivot, .. } => *pivot,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ActionSet {
    pub(crate) pivot: TermId,
    pub(crate) alternatives: Box<[PartitionAction]>,
    pub(crate) relation_queries: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ActionCaps {
    pub(crate) max_active_terms: usize,
    pub(crate) max_classes: usize,
    pub(crate) max_relation_queries: usize,
    pub(crate) max_alternatives: usize,
}

impl Default for ActionCaps {
    fn default() -> Self {
        Self {
            max_active_terms: 1_000_000,
            max_classes: 1_000_000,
            max_relation_queries: 10_000_000,
            max_alternatives: 1_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActionResource {
    ActiveTerms,
    Classes,
    RelationQueries,
    Alternatives,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ActionLimit {
    pub(crate) resource: ActionResource,
    pub(crate) attempted: usize,
    pub(crate) limit: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ActionOutcome {
    Complete { relation_queries: usize },
    Actions(ActionSet),
    Abstained(ActionLimit),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ActionError {
    TermUniverseMismatch {
        partition_terms: usize,
        semantic_terms: usize,
    },
    ActiveTermOutOfRange {
        term: TermId,
        term_count: usize,
    },
    Partition(PartitionError),
    AllocationFailed,
}

impl fmt::Display for ActionError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TermUniverseMismatch {
                partition_terms,
                semantic_terms,
            } => write!(
                output,
                "partition has {partition_terms} terms but semantics has {semantic_terms}"
            ),
            Self::ActiveTermOutOfRange { term, term_count } => {
                write!(output, "active term {term} is outside 0..{term_count}")
            }
            Self::Partition(error) => error.fmt(output),
            Self::AllocationFailed => output.write_str("canonical action allocation failed"),
        }
    }
}

impl Error for ActionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Partition(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PartitionError> for ActionError {
    fn from(error: PartitionError) -> Self {
        Self::Partition(error)
    }
}

/// Return the next restricted-growth action set over the live term frontier.
///
/// Active classes are ordered by minimum stable term. The first class with an
/// unknown relation to an earlier same-sort active class can merge with each
/// such class or take one fresh action separating it from all of them.
pub(crate) fn next_actions(
    partition: &Partition,
    terms: &[SemanticTerm],
    active_terms: &[TermId],
    caps: ActionCaps,
) -> Result<ActionOutcome, ActionError> {
    if partition.term_count() != terms.len() {
        return Err(ActionError::TermUniverseMismatch {
            partition_terms: partition.term_count(),
            semantic_terms: terms.len(),
        });
    }
    if active_terms.len() > caps.max_active_terms {
        return Ok(ActionOutcome::Abstained(ActionLimit {
            resource: ActionResource::ActiveTerms,
            attempted: active_terms.len(),
            limit: caps.max_active_terms,
        }));
    }

    let mut active = BTreeSet::new();
    for &term in active_terms {
        if term.index() >= terms.len() {
            return Err(ActionError::ActiveTermOutOfRange {
                term,
                term_count: terms.len(),
            });
        }
        active.insert(partition.canonical_representative(term)?);
    }

    let classes = partition.classes()?;
    if classes.len() > caps.max_classes {
        return Ok(ActionOutcome::Abstained(ActionLimit {
            resource: ActionResource::Classes,
            attempted: classes.len(),
            limit: caps.max_classes,
        }));
    }
    let active_classes = classes
        .iter()
        .filter(|class| active.contains(&class.representative))
        .collect::<Vec<_>>();
    let mut relation_queries = 0usize;

    for (pivot_index, pivot_class) in active_classes.iter().enumerate() {
        let pivot = pivot_class.representative;
        let pivot_sort = terms[pivot.index()].sort;
        let mut candidates = Vec::new();
        candidates
            .try_reserve(pivot_index)
            .map_err(|_| ActionError::AllocationFailed)?;
        for earlier in &active_classes[..pivot_index] {
            let target = earlier.representative;
            if terms[target.index()].sort != pivot_sort {
                continue;
            }
            relation_queries = relation_queries.checked_add(1).unwrap_or(usize::MAX);
            if relation_queries > caps.max_relation_queries {
                return Ok(ActionOutcome::Abstained(ActionLimit {
                    resource: ActionResource::RelationQueries,
                    attempted: relation_queries,
                    limit: caps.max_relation_queries,
                }));
            }
            match partition.relation(pivot, target)? {
                Relation::Unknown => candidates.push(target),
                Relation::Disequal => {}
                Relation::Equal => {
                    return Err(ActionError::Partition(PartitionError::InvariantViolation(
                        "distinct canonical classes compare equal",
                    )));
                }
            }
        }
        if candidates.is_empty() {
            continue;
        }

        let alternative_count = candidates.len().checked_add(1).unwrap_or(usize::MAX);
        if alternative_count > caps.max_alternatives {
            return Ok(ActionOutcome::Abstained(ActionLimit {
                resource: ActionResource::Alternatives,
                attempted: alternative_count,
                limit: caps.max_alternatives,
            }));
        }
        let mut alternatives = Vec::new();
        alternatives
            .try_reserve_exact(alternative_count)
            .map_err(|_| ActionError::AllocationFailed)?;
        alternatives.extend(
            candidates
                .iter()
                .copied()
                .map(|target| PartitionAction::Merge { pivot, target }),
        );
        alternatives.push(PartitionAction::Fresh {
            pivot,
            separate_from: candidates.into_boxed_slice(),
        });
        return Ok(ActionOutcome::Actions(ActionSet {
            pivot,
            alternatives: alternatives.into_boxed_slice(),
            relation_queries,
        }));
    }
    Ok(ActionOutcome::Complete { relation_queries })
}

#[cfg(test)]
mod tests {
    use super::super::partition::{ReasonId, SeparationOutcome};
    use super::*;

    fn semantic_terms(sorts: &[u32]) -> Vec<SemanticTerm> {
        sorts
            .iter()
            .copied()
            .enumerate()
            .map(|(index, sort)| SemanticTerm {
                function: index as u32,
                sort,
                arguments: Box::new([]),
            })
            .collect()
    }

    fn active(count: usize) -> Vec<TermId> {
        (0..count).map(|index| TermId::new(index as u32)).collect()
    }

    fn explore(
        partition: &mut Partition,
        terms: &[SemanticTerm],
        active: &[TermId],
        leaves: &mut BTreeSet<Vec<Vec<TermId>>>,
        next_reason: &mut u64,
    ) {
        match next_actions(partition, terms, active, ActionCaps::default()).unwrap() {
            ActionOutcome::Complete { .. } => {
                assert!(
                    leaves.insert(partition.canonical_classes().unwrap()),
                    "canonical action search reached one partition twice"
                );
            }
            ActionOutcome::Abstained(limit) => panic!("unexpected cap: {limit:?}"),
            ActionOutcome::Actions(actions) => {
                for action in actions.alternatives.iter() {
                    let snapshot = partition.snapshot();
                    match action {
                        PartitionAction::Merge { pivot, target } => {
                            partition
                                .merge(*pivot, *target, ReasonId::new(*next_reason))
                                .unwrap();
                            *next_reason += 1;
                        }
                        PartitionAction::Fresh {
                            pivot,
                            separate_from,
                        } => {
                            for &target in separate_from.iter() {
                                let outcome = partition
                                    .separate(*pivot, target, ReasonId::new(*next_reason))
                                    .unwrap();
                                assert!(matches!(outcome, SeparationOutcome::Added { .. }));
                                *next_reason += 1;
                            }
                        }
                    }
                    explore(partition, terms, active, leaves, next_reason);
                    partition.rollback(snapshot).unwrap();
                }
            }
        }
    }

    #[test]
    fn enumerates_each_untyped_partition_once_through_five_terms() {
        for (count, bell) in [(0, 1), (1, 1), (2, 2), (3, 5), (4, 15), (5, 52)] {
            let terms = semantic_terms(&vec![0; count]);
            let active = active(count);
            let mut partition = Partition::new(count).unwrap();
            let mut leaves = BTreeSet::new();
            let mut reason = 1;
            explore(&mut partition, &terms, &active, &mut leaves, &mut reason);
            assert_eq!(leaves.len(), bell, "term count {count}");
        }
    }

    #[test]
    fn sorts_form_independent_restricted_growth_sequences() {
        let terms = semantic_terms(&[0, 1, 0, 1]);
        let active = active(4);
        let mut partition = Partition::new(4).unwrap();
        let mut leaves = BTreeSet::new();
        let mut reason = 1;
        explore(&mut partition, &terms, &active, &mut leaves, &mut reason);
        assert_eq!(leaves.len(), 4);
        assert!(leaves.iter().all(|classes| classes.iter().all(|class| {
            class
                .iter()
                .all(|term| terms[term.index()].sort == terms[class[0].index()].sort)
        })));
    }

    #[test]
    fn disequalities_prune_forbidden_merges_and_merged_terms_share_a_class() {
        let terms = semantic_terms(&[0, 0, 0]);
        let active = active(3);
        let mut partition = Partition::new(3).unwrap();
        partition
            .separate(TermId::new(0), TermId::new(1), ReasonId::new(1))
            .unwrap();
        let ActionOutcome::Actions(actions) =
            next_actions(&partition, &terms, &active, ActionCaps::default()).unwrap()
        else {
            panic!("term 2 still requires placement");
        };
        assert_eq!(actions.pivot, TermId::new(2));
        assert_eq!(actions.alternatives.len(), 3);

        let mut merged = Partition::new(3).unwrap();
        merged
            .merge(TermId::new(0), TermId::new(1), ReasonId::new(1))
            .unwrap();
        let ActionOutcome::Actions(actions) =
            next_actions(&merged, &terms, &active, ActionCaps::default()).unwrap()
        else {
            panic!("term 2 requires placement");
        };
        assert_eq!(actions.alternatives.len(), 2);
        assert_eq!(actions.alternatives[0].pivot(), TermId::new(2));
    }

    #[test]
    fn malformed_frontiers_and_every_cap_fail_closed() {
        let terms = semantic_terms(&[0, 0, 0]);
        let partition = Partition::new(3).unwrap();
        assert!(matches!(
            next_actions(&partition, &terms, &[TermId::new(3)], ActionCaps::default()),
            Err(ActionError::ActiveTermOutOfRange { .. })
        ));
        let active = active(3);
        for (resource, caps) in [
            (
                ActionResource::ActiveTerms,
                ActionCaps {
                    max_active_terms: 2,
                    ..ActionCaps::default()
                },
            ),
            (
                ActionResource::Classes,
                ActionCaps {
                    max_classes: 2,
                    ..ActionCaps::default()
                },
            ),
            (
                ActionResource::RelationQueries,
                ActionCaps {
                    max_relation_queries: 0,
                    ..ActionCaps::default()
                },
            ),
            (
                ActionResource::Alternatives,
                ActionCaps {
                    max_alternatives: 1,
                    ..ActionCaps::default()
                },
            ),
        ] {
            assert!(matches!(
                next_actions(&partition, &terms, &active, caps).unwrap(),
                ActionOutcome::Abstained(ActionLimit { resource: got, .. }) if got == resource
            ));
        }
    }
}
