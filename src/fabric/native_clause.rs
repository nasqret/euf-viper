#![deny(unsafe_code)]

//! Watched clauses over semantic propositions.
//!
//! The database does not own an assignment. A caller supplies the current
//! three-valued interpretation, which may come from a Boolean trail, an
//! equality partition, or a proved finite-class assignment. This keeps the
//! watch machinery independent from the proof system used to decide atoms.

use std::error::Error;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AtomId(u32);

impl AtomId {
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lit {
    atom: AtomId,
    positive: bool,
}

impl Lit {
    pub const fn positive(atom: AtomId) -> Self {
        Self {
            atom,
            positive: true,
        }
    }

    pub const fn negative(atom: AtomId) -> Self {
        Self {
            atom,
            positive: false,
        }
    }

    pub const fn atom(self) -> AtomId {
        self.atom
    }

    pub const fn is_positive(self) -> bool {
        self.positive
    }

    pub const fn negate(self) -> Self {
        Self {
            atom: self.atom,
            positive: !self.positive,
        }
    }

    fn watch_index(self) -> usize {
        self.atom.index() * 2 + usize::from(self.positive)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Truth {
    False,
    Unknown,
    True,
}

pub trait Interpretation {
    fn truth(&self, literal: Lit) -> Truth;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClauseId(u32);

impl ClauseId {
    pub(crate) const MIN: Self = Self(0);
    pub(crate) const MAX: Self = Self(u32::MAX);

    pub(crate) const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub(crate) const fn raw(self) -> u32 {
        self.0
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for ClauseId {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(output)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClauseError {
    AtomOutOfRange { atom: AtomId, atom_count: usize },
    TooManyClauses,
}

impl fmt::Display for ClauseError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtomOutOfRange { atom, atom_count } => write!(
                output,
                "native clause atom {} is outside 0..{atom_count}",
                atom.index()
            ),
            Self::TooManyClauses => write!(output, "native clause identifier space exhausted"),
        }
    }
}

impl Error for ClauseError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddOutcome {
    Tautology,
    Empty,
    Unit(Lit),
    Clause(ClauseId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchEvent {
    Unit { clause: ClauseId, literal: Lit },
    Conflict { clause: ClauseId },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WatchTelemetry {
    pub clauses_added: usize,
    pub tautologies_skipped: usize,
    pub watch_entries_examined: usize,
    pub stale_entries_skipped: usize,
    pub watch_moves: usize,
    pub units_found: usize,
    pub conflicts_found: usize,
}

#[derive(Clone, Debug)]
struct Clause {
    literals: Box<[Lit]>,
    watches: [usize; 2],
}

impl Clause {
    fn watches_literal(&self, literal: Lit) -> Option<usize> {
        if self.literals[self.watches[0]] == literal {
            Some(0)
        } else if self.literals[self.watches[1]] == literal {
            Some(1)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug)]
pub struct NativeClauseDb {
    atom_count: usize,
    clauses: Vec<Clause>,
    watchers: Vec<Vec<ClauseId>>,
    telemetry: WatchTelemetry,
}

impl NativeClauseDb {
    pub fn new(atom_count: usize) -> Self {
        Self {
            atom_count,
            clauses: Vec::new(),
            watchers: vec![Vec::new(); atom_count.saturating_mul(2)],
            telemetry: WatchTelemetry::default(),
        }
    }

    pub fn atom_count(&self) -> usize {
        self.atom_count
    }

    pub fn len(&self) -> usize {
        self.clauses.len()
    }

    pub fn is_empty(&self) -> bool {
        self.clauses.is_empty()
    }

    pub fn telemetry(&self) -> WatchTelemetry {
        self.telemetry
    }

    pub fn clause(&self, id: ClauseId) -> Option<&[Lit]> {
        self.clauses
            .get(id.index())
            .map(|clause| clause.literals.as_ref())
    }

    pub fn add_clause(&mut self, literals: &[Lit]) -> Result<AddOutcome, ClauseError> {
        let mut canonical = literals.to_vec();
        for literal in &canonical {
            if literal.atom().index() >= self.atom_count {
                return Err(ClauseError::AtomOutOfRange {
                    atom: literal.atom(),
                    atom_count: self.atom_count,
                });
            }
        }
        canonical.sort_unstable();
        canonical.dedup();
        if canonical
            .windows(2)
            .any(|pair| pair[0].atom() == pair[1].atom() && pair[0] != pair[1])
        {
            self.telemetry.tautologies_skipped += 1;
            return Ok(AddOutcome::Tautology);
        }
        match canonical.len() {
            0 => return Ok(AddOutcome::Empty),
            1 => return Ok(AddOutcome::Unit(canonical[0])),
            _ => {}
        }

        let raw_id = u32::try_from(self.clauses.len()).map_err(|_| ClauseError::TooManyClauses)?;
        let id = ClauseId(raw_id);
        let clause = Clause {
            literals: canonical.into_boxed_slice(),
            watches: [0, 1],
        };
        let first = clause.literals[0].watch_index();
        let second = clause.literals[1].watch_index();
        self.clauses.push(clause);
        self.watchers[first].push(id);
        self.watchers[second].push(id);
        self.telemetry.clauses_added += 1;
        Ok(AddOutcome::Clause(id))
    }

    /// Reconsider clauses watching a literal that has just become false.
    ///
    /// Returned units are observations under `interpretation`; the caller must
    /// enqueue them and invoke this method again for any newly falsified
    /// literals. All watch updates are completed even if a conflict is found.
    pub fn propagate_false<I: Interpretation>(
        &mut self,
        false_literal: Lit,
        interpretation: &I,
    ) -> Result<Vec<WatchEvent>, ClauseError> {
        if false_literal.atom().index() >= self.atom_count {
            return Err(ClauseError::AtomOutOfRange {
                atom: false_literal.atom(),
                atom_count: self.atom_count,
            });
        }
        let watch_index = false_literal.watch_index();
        let pending = std::mem::take(&mut self.watchers[watch_index]);
        let mut retained = Vec::with_capacity(pending.len());
        let mut moved = Vec::<(usize, ClauseId)>::new();
        let mut events = Vec::new();

        for clause_id in pending {
            self.telemetry.watch_entries_examined += 1;
            let clause = &mut self.clauses[clause_id.index()];
            let Some(false_watch) = clause.watches_literal(false_literal) else {
                self.telemetry.stale_entries_skipped += 1;
                continue;
            };
            let other_watch = 1 - false_watch;
            let other_index = clause.watches[other_watch];
            let other_literal = clause.literals[other_index];

            if interpretation.truth(other_literal) == Truth::True {
                retained.push(clause_id);
                continue;
            }

            let replacement = clause
                .literals
                .iter()
                .enumerate()
                .find(|(index, literal)| {
                    *index != other_index && interpretation.truth(**literal) != Truth::False
                })
                .map(|(index, literal)| (index, *literal));

            if let Some((replacement_index, replacement_literal)) = replacement {
                clause.watches[false_watch] = replacement_index;
                moved.push((replacement_literal.watch_index(), clause_id));
                self.telemetry.watch_moves += 1;
                continue;
            }

            retained.push(clause_id);
            match interpretation.truth(other_literal) {
                Truth::False => {
                    events.push(WatchEvent::Conflict { clause: clause_id });
                    self.telemetry.conflicts_found += 1;
                }
                Truth::Unknown => {
                    events.push(WatchEvent::Unit {
                        clause: clause_id,
                        literal: other_literal,
                    });
                    self.telemetry.units_found += 1;
                }
                Truth::True => unreachable!("true watched literal was handled above"),
            }
        }

        self.watchers[watch_index] = retained;
        for (new_watch, clause_id) in moved {
            self.watchers[new_watch].push(clause_id);
        }
        Ok(events)
    }

    pub fn scan<I: Interpretation>(&self, interpretation: &I) -> Vec<WatchEvent> {
        let mut events = Vec::new();
        for (index, clause) in self.clauses.iter().enumerate() {
            let clause_id = ClauseId(index as u32);
            let mut unknown = None;
            let mut unknown_count = 0usize;
            let mut satisfied = false;
            for &literal in clause.literals.iter() {
                match interpretation.truth(literal) {
                    Truth::True => {
                        satisfied = true;
                        break;
                    }
                    Truth::Unknown => {
                        unknown = Some(literal);
                        unknown_count += 1;
                    }
                    Truth::False => {}
                }
            }
            if satisfied {
                continue;
            }
            match (unknown_count, unknown) {
                (0, _) => events.push(WatchEvent::Conflict { clause: clause_id }),
                (1, Some(literal)) => events.push(WatchEvent::Unit {
                    clause: clause_id,
                    literal,
                }),
                _ => {}
            }
        }
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug)]
    struct Assignment(Vec<Truth>);

    impl Interpretation for Assignment {
        fn truth(&self, literal: Lit) -> Truth {
            match (self.0[literal.atom().index()], literal.is_positive()) {
                (Truth::Unknown, _) => Truth::Unknown,
                (Truth::True, true) | (Truth::False, false) => Truth::True,
                (Truth::True, false) | (Truth::False, true) => Truth::False,
            }
        }
    }

    fn p(index: u32) -> Lit {
        Lit::positive(AtomId::new(index))
    }

    fn n(index: u32) -> Lit {
        Lit::negative(AtomId::new(index))
    }

    #[test]
    fn canonicalizes_duplicates_and_rejects_tautologies() {
        let mut db = NativeClauseDb::new(3);
        assert_eq!(db.atom_count(), 3);
        assert_eq!(db.add_clause(&[]).unwrap(), AddOutcome::Empty);
        assert_eq!(
            db.add_clause(&[p(0), p(0)]).unwrap(),
            AddOutcome::Unit(p(0))
        );
        assert_eq!(
            db.add_clause(&[p(1), n(1), p(2)]).unwrap(),
            AddOutcome::Tautology
        );
        assert_eq!(db.len(), 0);
        let clause = match db.add_clause(&[p(0), p(2)]).unwrap() {
            AddOutcome::Clause(id) => id,
            other => panic!("unexpected add outcome {other:?}"),
        };
        assert_eq!(db.clause(clause), Some(&[p(0), p(2)][..]));
        assert_eq!(p(0).negate(), n(0));
    }

    #[test]
    fn rejects_unknown_atoms_without_partial_mutation() {
        let mut db = NativeClauseDb::new(2);
        let error = db.add_clause(&[p(0), p(2)]).unwrap_err();
        assert!(matches!(error, ClauseError::AtomOutOfRange { .. }));
        assert!(db.is_empty());
    }

    #[test]
    fn moves_watch_then_reports_unit_and_conflict() {
        let mut db = NativeClauseDb::new(3);
        let clause = match db.add_clause(&[p(0), p(1), p(2)]).unwrap() {
            AddOutcome::Clause(id) => id,
            other => panic!("unexpected add outcome {other:?}"),
        };
        let mut assignment = Assignment(vec![Truth::False, Truth::Unknown, Truth::Unknown]);
        assert!(db.propagate_false(p(0), &assignment).unwrap().is_empty());
        assert_eq!(db.telemetry().watch_moves, 1);

        assignment.0[1] = Truth::False;
        assert_eq!(
            db.propagate_false(p(1), &assignment).unwrap(),
            vec![WatchEvent::Unit {
                clause,
                literal: p(2)
            }]
        );

        assignment.0[2] = Truth::Unknown;
        assert_eq!(
            db.scan(&assignment),
            vec![WatchEvent::Unit {
                clause,
                literal: p(2)
            }]
        );
        assignment.0[2] = Truth::False;
        assert_eq!(
            db.propagate_false(p(2), &assignment).unwrap(),
            vec![WatchEvent::Conflict { clause }]
        );
    }

    #[test]
    fn negative_literals_follow_the_external_interpretation() {
        let mut db = NativeClauseDb::new(2);
        let clause = match db.add_clause(&[n(0), p(1)]).unwrap() {
            AddOutcome::Clause(id) => id,
            other => panic!("unexpected add outcome {other:?}"),
        };
        let assignment = Assignment(vec![Truth::True, Truth::Unknown]);
        assert_eq!(
            db.propagate_false(n(0), &assignment).unwrap(),
            vec![WatchEvent::Unit {
                clause,
                literal: p(1)
            }]
        );
    }

    #[test]
    fn satisfied_clause_never_propagates() {
        let mut db = NativeClauseDb::new(3);
        db.add_clause(&[p(0), p(1), p(2)]).unwrap();
        let assignment = Assignment(vec![Truth::False, Truth::True, Truth::False]);
        assert!(db.propagate_false(p(0), &assignment).unwrap().is_empty());
        assert!(db.scan(&assignment).is_empty());
    }

    #[test]
    fn watched_results_match_full_scan_exhaustively() {
        let clauses = [
            vec![p(0), p(1), n(2)],
            vec![n(0), p(2)],
            vec![p(1), n(3), p(4)],
            vec![n(1), n(2), n(4)],
        ];
        for encoded in 0usize..3usize.pow(5) {
            let mut value = encoded;
            let mut states = Vec::new();
            for _ in 0..5 {
                states.push(match value % 3 {
                    0 => Truth::False,
                    1 => Truth::Unknown,
                    _ => Truth::True,
                });
                value /= 3;
            }
            let assignment = Assignment(states);
            let mut db = NativeClauseDb::new(5);
            for clause in &clauses {
                db.add_clause(clause).unwrap();
            }
            let mut expected = db.scan(&assignment);
            expected.sort_by_key(|event| match event {
                WatchEvent::Unit { clause, .. } | WatchEvent::Conflict { clause } => clause.index(),
            });

            let mut observed = Vec::new();
            for atom in 0..5u32 {
                match assignment.0[atom as usize] {
                    Truth::False => observed.extend(
                        db.propagate_false(p(atom), &assignment)
                            .expect("valid positive atom"),
                    ),
                    Truth::True => observed.extend(
                        db.propagate_false(n(atom), &assignment)
                            .expect("valid negative atom"),
                    ),
                    Truth::Unknown => {}
                }
            }
            observed.sort_by_key(|event| match event {
                WatchEvent::Unit { clause, .. } | WatchEvent::Conflict { clause } => clause.index(),
            });
            observed.dedup();
            assert_eq!(observed, expected, "assignment code {encoded}");
        }
    }
}
