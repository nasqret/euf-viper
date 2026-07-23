#![deny(unsafe_code)]

//! Stable theory-impact frontiers for incremental source-atom scheduling.
//!
//! A class merge can import a disequality edge from either operand. It is not
//! enough to revisit atoms mentioning only the explicit merge endpoints: an
//! atom between the surviving class and an imported neighbor may also become
//! false. This module conservatively returns every member of the post-update
//! endpoint classes and every member of their disequality-neighbor classes.

use super::partition::{Partition, PartitionError, TermId};
use std::error::Error;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ImpactCaps {
    pub(crate) max_seed_relations: usize,
    pub(crate) max_seed_classes: usize,
    pub(crate) max_neighbor_edges: usize,
    pub(crate) max_class_member_visits: usize,
    pub(crate) max_affected_terms: usize,
}

impl ImpactCaps {
    pub(crate) const fn unlimited() -> Self {
        Self {
            max_seed_relations: usize::MAX,
            max_seed_classes: usize::MAX,
            max_neighbor_edges: usize::MAX,
            max_class_member_visits: usize::MAX,
            max_affected_terms: usize::MAX,
        }
    }
}

impl Default for ImpactCaps {
    fn default() -> Self {
        Self {
            max_seed_relations: 1_000_000,
            max_seed_classes: 1_000_000,
            max_neighbor_edges: 10_000_000,
            max_class_member_visits: 50_000_000,
            max_affected_terms: 10_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ImpactResource {
    SeedRelations,
    SeedClasses,
    NeighborEdges,
    ClassMemberVisits,
    AffectedTerms,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ImpactLimit {
    pub(crate) resource: ImpactResource,
    pub(crate) attempted: usize,
    pub(crate) limit: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ImpactStats {
    pub(crate) seed_relations: usize,
    pub(crate) seed_classes: usize,
    pub(crate) neighbor_edges: usize,
    pub(crate) class_member_visits: usize,
    pub(crate) affected_terms: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ImpactOutcome {
    Complete {
        terms: Box<[TermId]>,
        stats: ImpactStats,
    },
    Abstained {
        limit: ImpactLimit,
        stats: ImpactStats,
    },
}

#[derive(Debug)]
pub(crate) enum ImpactError {
    Partition(PartitionError),
    AllocationFailed(&'static str),
    CounterOverflow(ImpactResource),
}

impl fmt::Display for ImpactError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Partition(error) => error.fmt(output),
            Self::AllocationFailed(resource) => {
                write!(output, "allocation failed while building {resource}")
            }
            Self::CounterOverflow(resource) => {
                write!(output, "theory-impact {resource:?} counter overflowed")
            }
        }
    }
}

impl Error for ImpactError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Partition(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PartitionError> for ImpactError {
    fn from(error: PartitionError) -> Self {
        Self::Partition(error)
    }
}

/// Computes a conservative stable-term frontier after one or more successful
/// partition updates. `seeds` are the original endpoints of every merge or
/// separation committed since the previous scheduling point.
pub(crate) fn affected_terms(
    partition: &Partition,
    seeds: &[(TermId, TermId)],
    caps: ImpactCaps,
) -> Result<ImpactOutcome, ImpactError> {
    affected_terms_with_member_index(partition, seeds, caps, true)
}

pub(crate) fn affected_terms_with_member_index(
    partition: &Partition,
    seeds: &[(TermId, TermId)],
    caps: ImpactCaps,
    indexed_class_members: bool,
) -> Result<ImpactOutcome, ImpactError> {
    let mut stats = ImpactStats::default();
    if let Some(limit) = set_count(
        &mut stats.seed_relations,
        seeds.len(),
        caps.max_seed_relations,
        ImpactResource::SeedRelations,
    )? {
        return Ok(ImpactOutcome::Abstained { limit, stats });
    }

    let seed_capacity = seeds
        .len()
        .checked_mul(2)
        .ok_or(ImpactError::CounterOverflow(ImpactResource::SeedClasses))?;
    let mut seed_classes = Vec::new();
    seed_classes
        .try_reserve_exact(seed_capacity)
        .map_err(|_| ImpactError::AllocationFailed("theory-impact seed classes"))?;
    for &(left, right) in seeds {
        seed_classes.push(partition.canonical_representative(left)?);
        seed_classes.push(partition.canonical_representative(right)?);
    }
    seed_classes.sort_unstable();
    seed_classes.dedup();
    if let Some(limit) = set_count(
        &mut stats.seed_classes,
        seed_classes.len(),
        caps.max_seed_classes,
        ImpactResource::SeedClasses,
    )? {
        return Ok(ImpactOutcome::Abstained { limit, stats });
    }

    let mut touched_classes = Vec::new();
    touched_classes
        .try_reserve_exact(seed_classes.len())
        .map_err(|_| ImpactError::AllocationFailed("theory-impact touched classes"))?;
    touched_classes.extend_from_slice(&seed_classes);
    for representative in seed_classes {
        let neighbors = partition.disequal_class_representatives(representative)?;
        let attempted = stats
            .neighbor_edges
            .checked_add(neighbors.len())
            .ok_or(ImpactError::CounterOverflow(ImpactResource::NeighborEdges))?;
        if attempted > caps.max_neighbor_edges {
            return Ok(ImpactOutcome::Abstained {
                limit: ImpactLimit {
                    resource: ImpactResource::NeighborEdges,
                    attempted,
                    limit: caps.max_neighbor_edges,
                },
                stats,
            });
        }
        stats.neighbor_edges = attempted;
        touched_classes
            .try_reserve(neighbors.len())
            .map_err(|_| ImpactError::AllocationFailed("theory-impact touched classes"))?;
        touched_classes.extend_from_slice(&neighbors);
    }
    touched_classes.sort_unstable();
    touched_classes.dedup();

    let mut terms = Vec::new();
    for representative in touched_classes {
        let members = if indexed_class_members {
            partition.class_members(representative)?
        } else {
            partition.class_members_by_scan(representative)?
        };
        let visits = stats.class_member_visits.checked_add(members.len()).ok_or(
            ImpactError::CounterOverflow(ImpactResource::ClassMemberVisits),
        )?;
        if visits > caps.max_class_member_visits {
            return Ok(ImpactOutcome::Abstained {
                limit: ImpactLimit {
                    resource: ImpactResource::ClassMemberVisits,
                    attempted: visits,
                    limit: caps.max_class_member_visits,
                },
                stats,
            });
        }
        stats.class_member_visits = visits;
        terms
            .try_reserve(members.len())
            .map_err(|_| ImpactError::AllocationFailed("theory-impact terms"))?;
        terms.extend_from_slice(&members);
    }
    terms.sort_unstable();
    terms.dedup();
    if terms.len() > caps.max_affected_terms {
        return Ok(ImpactOutcome::Abstained {
            limit: ImpactLimit {
                resource: ImpactResource::AffectedTerms,
                attempted: terms.len(),
                limit: caps.max_affected_terms,
            },
            stats,
        });
    }
    stats.affected_terms = terms.len();
    Ok(ImpactOutcome::Complete {
        terms: terms.into_boxed_slice(),
        stats,
    })
}

fn set_count(
    counter: &mut usize,
    attempted: usize,
    limit: usize,
    resource: ImpactResource,
) -> Result<Option<ImpactLimit>, ImpactError> {
    if attempted > limit {
        return Ok(Some(ImpactLimit {
            resource,
            attempted,
            limit,
        }));
    }
    *counter = attempted;
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::super::partition::{ReasonId, Relation};
    use super::*;

    fn term(raw: u32) -> TermId {
        TermId::new(raw)
    }

    fn reason(raw: u64) -> ReasonId {
        ReasonId::new(raw)
    }

    fn complete(outcome: ImpactOutcome) -> Box<[TermId]> {
        match outcome {
            ImpactOutcome::Complete { terms, .. } => terms,
            other => panic!("expected complete impact frontier, got {other:?}"),
        }
    }

    #[test]
    fn carried_disequality_marks_surviving_class_and_neighbor() {
        let mut partition = Partition::new(4).unwrap();
        partition.separate(term(1), term(2), reason(1)).unwrap();
        partition.merge(term(0), term(1), reason(2)).unwrap();

        assert_eq!(
            partition.relation(term(0), term(2)).unwrap(),
            Relation::Disequal
        );
        assert_eq!(
            complete(
                affected_terms(&partition, &[(term(0), term(1))], ImpactCaps::unlimited(),)
                    .unwrap(),
            )
            .as_ref(),
            &[term(0), term(1), term(2)]
        );
    }

    #[test]
    fn endpoint_and_merge_order_do_not_change_stable_frontier() {
        let build = |reverse: bool| {
            let mut partition = Partition::new(6).unwrap();
            partition.separate(term(1), term(5), reason(1)).unwrap();
            if reverse {
                partition.merge(term(3), term(2), reason(2)).unwrap();
                partition.merge(term(3), term(1), reason(3)).unwrap();
            } else {
                partition.merge(term(2), term(3), reason(2)).unwrap();
                partition.merge(term(1), term(2), reason(3)).unwrap();
            }
            complete(
                affected_terms(
                    &partition,
                    &[(term(3), term(2)), (term(3), term(1))],
                    ImpactCaps::unlimited(),
                )
                .unwrap(),
            )
        };
        assert_eq!(build(false), build(true));
        assert_eq!(build(false).as_ref(), &[term(1), term(2), term(3), term(5)]);
    }

    #[test]
    fn every_changed_four_term_relation_touches_frontier() {
        for equality_mask in 0u32..64 {
            let pairs = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];
            let base = partition_from_mask(equality_mask);
            for &(left, right) in &pairs {
                if !matches!(
                    base.relation(term(left), term(right)).unwrap(),
                    Relation::Unknown
                ) {
                    continue;
                }
                for equality in [true, false] {
                    let mut changed = partition_from_mask(equality_mask);
                    let before = pair_relations(&changed);
                    if equality {
                        changed.merge(term(left), term(right), reason(100)).unwrap();
                    } else {
                        changed
                            .separate(term(left), term(right), reason(101))
                            .unwrap();
                    }
                    let after = pair_relations(&changed);
                    let frontier = complete(
                        affected_terms(
                            &changed,
                            &[(term(left), term(right))],
                            ImpactCaps::unlimited(),
                        )
                        .unwrap(),
                    );
                    for (index, (&old, &new)) in before.iter().zip(&after).enumerate() {
                        if old == new {
                            continue;
                        }
                        let (first, second) = pairs[index];
                        assert!(
                            frontier.contains(&term(first)) && frontier.contains(&term(second)),
                            "mask={equality_mask:b} update=({left},{right},{equality}) changed ({first},{second}) outside {frontier:?}"
                        );
                    }
                }
            }
        }
    }

    fn pair_relations(partition: &Partition) -> Vec<Relation> {
        [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)]
            .into_iter()
            .map(|(left, right)| partition.relation(term(left), term(right)).unwrap())
            .collect()
    }

    fn partition_from_mask(equality_mask: u32) -> Partition {
        let pairs = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];
        let mut partition = Partition::new(4).unwrap();
        for (bit, &(left, right)) in pairs.iter().enumerate() {
            if equality_mask & (1 << bit) != 0
                && matches!(
                    partition.relation(term(left), term(right)).unwrap(),
                    Relation::Unknown
                )
            {
                partition
                    .merge(term(left), term(right), reason(bit as u64 + 1))
                    .unwrap();
            }
        }
        partition
    }

    #[test]
    fn every_cap_abstains_without_partition_mutation() {
        let mut partition = Partition::new(4).unwrap();
        partition.separate(term(0), term(2), reason(1)).unwrap();
        partition.merge(term(0), term(1), reason(2)).unwrap();
        let before = partition.snapshot();
        let caps = [
            ImpactCaps {
                max_seed_relations: 0,
                ..ImpactCaps::unlimited()
            },
            ImpactCaps {
                max_seed_classes: 0,
                ..ImpactCaps::unlimited()
            },
            ImpactCaps {
                max_neighbor_edges: 0,
                ..ImpactCaps::unlimited()
            },
            ImpactCaps {
                max_class_member_visits: 0,
                ..ImpactCaps::unlimited()
            },
            ImpactCaps {
                max_affected_terms: 0,
                ..ImpactCaps::unlimited()
            },
        ];
        for cap in caps {
            assert!(matches!(
                affected_terms(&partition, &[(term(0), term(1))], cap).unwrap(),
                ImpactOutcome::Abstained { .. }
            ));
            assert_eq!(partition.snapshot(), before);
        }
    }

    #[test]
    fn invalid_seed_fails_without_exposing_partial_terms() {
        let partition = Partition::new(2).unwrap();
        assert!(matches!(
            affected_terms(&partition, &[(term(0), term(2))], ImpactCaps::unlimited(),),
            Err(ImpactError::Partition(PartitionError::InvalidTerm { .. }))
        ));
    }
}
