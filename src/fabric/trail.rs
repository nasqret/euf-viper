#![deny(unsafe_code)]

//! Deterministic implication trail shared by native Boolean and equality atoms.

use super::native_clause::{AtomId, ClauseId, Interpretation, Lit, Truth};
use std::error::Error;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TheoryReasonId(u32);

impl TheoryReasonId {
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Root,
    Decision,
    Clause(ClauseId),
    Theory(TheoryReasonId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Assignment {
    value: bool,
    level: u32,
    reason: Reason,
    trail_index: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Assigned,
    AlreadyAssigned,
    Conflict {
        existing: Lit,
        existing_level: u32,
        existing_reason: Reason,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrailError {
    AtomOutOfRange { atom: AtomId, atom_count: usize },
    TooManyDecisionLevels,
    InvalidBacktrack { target: u32, current: u32 },
}

impl fmt::Display for TrailError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtomOutOfRange { atom, atom_count } => write!(
                output,
                "trail atom {} is outside 0..{atom_count}",
                atom.index()
            ),
            Self::TooManyDecisionLevels => write!(output, "decision-level space exhausted"),
            Self::InvalidBacktrack { target, current } => {
                write!(output, "cannot backtrack from level {current} to {target}")
            }
        }
    }
}

impl Error for TrailError {}

#[derive(Clone, Debug)]
pub struct Trail {
    assignments: Vec<Option<Assignment>>,
    order: Vec<Lit>,
    /// Start offset for each level. Entry zero is always the root level.
    level_starts: Vec<usize>,
}

impl Trail {
    pub fn new(atom_count: usize) -> Self {
        Self {
            assignments: vec![None; atom_count],
            order: Vec::new(),
            level_starts: vec![0],
        }
    }

    pub fn atom_count(&self) -> usize {
        self.assignments.len()
    }

    pub fn current_level(&self) -> u32 {
        (self.level_starts.len() - 1) as u32
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    pub fn assigned_literals(&self) -> &[Lit] {
        &self.order
    }

    pub fn new_decision_level(&mut self) -> Result<u32, TrailError> {
        let next = u32::try_from(self.level_starts.len())
            .map_err(|_| TrailError::TooManyDecisionLevels)?;
        self.level_starts.push(self.order.len());
        Ok(next)
    }

    pub fn enqueue(&mut self, literal: Lit, reason: Reason) -> Result<EnqueueOutcome, TrailError> {
        let atom_index = literal.atom().index();
        let atom_count = self.assignments.len();
        let current_level = self.current_level();
        let slot = self
            .assignments
            .get_mut(atom_index)
            .ok_or(TrailError::AtomOutOfRange {
                atom: literal.atom(),
                atom_count,
            })?;
        if let Some(existing) = *slot {
            if existing.value == literal.is_positive() {
                return Ok(EnqueueOutcome::AlreadyAssigned);
            }
            let existing_literal = if existing.value {
                Lit::positive(literal.atom())
            } else {
                Lit::negative(literal.atom())
            };
            return Ok(EnqueueOutcome::Conflict {
                existing: existing_literal,
                existing_level: existing.level,
                existing_reason: existing.reason,
            });
        }
        let assignment = Assignment {
            value: literal.is_positive(),
            level: current_level,
            reason,
            trail_index: self.order.len(),
        };
        *slot = Some(assignment);
        self.order.push(literal);
        Ok(EnqueueOutcome::Assigned)
    }

    pub fn assignment(&self, atom: AtomId) -> Result<Option<(Lit, u32, Reason)>, TrailError> {
        let assignment = self
            .assignments
            .get(atom.index())
            .ok_or(TrailError::AtomOutOfRange {
                atom,
                atom_count: self.assignments.len(),
            })?;
        Ok(assignment.map(|entry| {
            let literal = if entry.value {
                Lit::positive(atom)
            } else {
                Lit::negative(atom)
            };
            (literal, entry.level, entry.reason)
        }))
    }

    pub fn trail_index(&self, atom: AtomId) -> Result<Option<usize>, TrailError> {
        self.assignments
            .get(atom.index())
            .map(|entry| entry.map(|assignment| assignment.trail_index))
            .ok_or(TrailError::AtomOutOfRange {
                atom,
                atom_count: self.assignments.len(),
            })
    }

    /// Backtrack to `target`, returning assignments in the order they were
    /// removed from newest to oldest.
    pub fn backtrack(&mut self, target: u32) -> Result<Vec<Lit>, TrailError> {
        let current = self.current_level();
        if target > current {
            return Err(TrailError::InvalidBacktrack { target, current });
        }
        let keep = if target == current {
            self.order.len()
        } else {
            self.level_starts[target as usize + 1]
        };
        let mut removed = Vec::with_capacity(self.order.len() - keep);
        while self.order.len() > keep {
            let literal = self.order.pop().expect("length checked above");
            self.assignments[literal.atom().index()] = None;
            removed.push(literal);
        }
        self.level_starts.truncate(target as usize + 1);
        Ok(removed)
    }
}

impl Interpretation for Trail {
    fn truth(&self, literal: Lit) -> Truth {
        let Some(assignment) = self
            .assignments
            .get(literal.atom().index())
            .and_then(|entry| *entry)
        else {
            return Truth::Unknown;
        };
        if assignment.value == literal.is_positive() {
            Truth::True
        } else {
            Truth::False
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::native_clause::{AddOutcome, NativeClauseDb};
    use super::*;

    fn p(index: u32) -> Lit {
        Lit::positive(AtomId::new(index))
    }

    fn n(index: u32) -> Lit {
        Lit::negative(AtomId::new(index))
    }

    #[test]
    fn enqueue_is_idempotent_and_reports_opposite_conflict() {
        let mut trail = Trail::new(2);
        assert_eq!(trail.atom_count(), 2);
        assert!(trail.is_empty());
        assert_eq!(
            trail.enqueue(p(0), Reason::Root).unwrap(),
            EnqueueOutcome::Assigned
        );
        assert_eq!(
            trail.enqueue(p(0), Reason::Root).unwrap(),
            EnqueueOutcome::AlreadyAssigned
        );
        assert_eq!(
            trail.enqueue(n(0), Reason::Decision).unwrap(),
            EnqueueOutcome::Conflict {
                existing: p(0),
                existing_level: 0,
                existing_reason: Reason::Root
            }
        );
        assert_eq!(trail.len(), 1);
    }

    #[test]
    fn backtrack_preserves_root_and_target_level_assignments() {
        let mut trail = Trail::new(4);
        trail.enqueue(p(0), Reason::Root).unwrap();
        trail.new_decision_level().unwrap();
        trail.enqueue(n(1), Reason::Decision).unwrap();
        trail.new_decision_level().unwrap();
        trail
            .enqueue(p(2), Reason::Theory(TheoryReasonId::new(9)))
            .unwrap();
        trail.enqueue(n(3), Reason::Decision).unwrap();

        assert_eq!(trail.backtrack(1).unwrap(), vec![n(3), p(2)]);
        assert_eq!(trail.current_level(), 1);
        assert_eq!(trail.assigned_literals(), &[p(0), n(1)]);
        assert_eq!(trail.truth(p(0)), Truth::True);
        assert_eq!(trail.truth(p(1)), Truth::False);
        assert_eq!(trail.truth(p(2)), Truth::Unknown);

        assert_eq!(trail.backtrack(0).unwrap(), vec![n(1)]);
        assert_eq!(trail.assigned_literals(), &[p(0)]);
    }

    #[test]
    fn assignment_metadata_and_indices_are_stable() {
        let mut trail = Trail::new(3);
        let mut clauses = NativeClauseDb::new(3);
        let clause = match clauses.add_clause(&[p(0), p(2)]).unwrap() {
            AddOutcome::Clause(id) => id,
            other => panic!("unexpected add outcome {other:?}"),
        };
        trail.enqueue(n(2), Reason::Root).unwrap();
        trail.new_decision_level().unwrap();
        trail.enqueue(p(0), Reason::Clause(clause)).unwrap();
        trail
            .enqueue(p(1), Reason::Theory(TheoryReasonId::new(4)))
            .unwrap();

        assert_eq!(trail.trail_index(AtomId::new(2)).unwrap(), Some(0));
        assert_eq!(trail.trail_index(AtomId::new(0)).unwrap(), Some(1));
        assert_eq!(
            trail.assignment(AtomId::new(1)).unwrap(),
            Some((p(1), 1, Reason::Theory(TheoryReasonId::new(4))))
        );
        assert_eq!(TheoryReasonId::new(4).index(), 4);
        assert_eq!(
            trail.assignment(AtomId::new(0)).unwrap(),
            Some((p(0), 1, Reason::Clause(clause)))
        );
    }

    #[test]
    fn invalid_atoms_and_backtracks_fail_without_mutation() {
        let mut trail = Trail::new(1);
        let before = trail.clone();
        assert!(matches!(
            trail.enqueue(p(1), Reason::Root),
            Err(TrailError::AtomOutOfRange { .. })
        ));
        assert_eq!(trail.assigned_literals(), before.assigned_literals());
        assert!(matches!(
            trail.backtrack(1),
            Err(TrailError::InvalidBacktrack { .. })
        ));
        assert_eq!(trail.current_level(), 0);
    }

    #[test]
    fn truth_table_matches_literal_polarity() {
        let mut trail = Trail::new(2);
        assert_eq!(trail.truth(p(0)), Truth::Unknown);
        trail.enqueue(p(0), Reason::Root).unwrap();
        trail.enqueue(n(1), Reason::Root).unwrap();
        assert_eq!(trail.truth(p(0)), Truth::True);
        assert_eq!(trail.truth(n(0)), Truth::False);
        assert_eq!(trail.truth(p(1)), Truth::False);
        assert_eq!(trail.truth(n(1)), Truth::True);
    }
}
