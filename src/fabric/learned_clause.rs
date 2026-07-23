#![forbid(unsafe_code)]

//! Deterministic append-only storage for learned native clauses.
//!
//! The overlay assigns global [`ClauseId`] values after an immutable base
//! clause database. Empty and unit clauses are immediate solver actions and
//! are therefore reported without storage; every stored clause has at least
//! two canonical literals. Content lookup uses a sorted side index, while
//! iteration and scan order remain insertion order (and thus identifier order).
//!
//! The module deliberately contains no watches or engine policy. Its scan is a
//! bounded correctness path suitable for differential checking and for the
//! first learning integration before a dynamic watch database exists.

use super::native_clause::{AtomId, ClauseId, Interpretation, Lit, Truth};
use std::error::Error;
use std::fmt;

const CLAUSE_ID_CAPACITY: u64 = u32::MAX as u64 + 1;

/// Persistent resource limits, applied to canonical stored clauses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LearnedClauseCaps {
    pub(crate) max_learned_clauses: usize,
    pub(crate) max_total_literals: usize,
    pub(crate) max_clause_literals: usize,
}

impl LearnedClauseCaps {
    pub(crate) const fn new(
        max_learned_clauses: usize,
        max_total_literals: usize,
        max_clause_literals: usize,
    ) -> Self {
        Self {
            max_learned_clauses,
            max_total_literals,
            max_clause_literals,
        }
    }

    pub(crate) const fn unlimited() -> Self {
        Self::new(usize::MAX, usize::MAX, usize::MAX)
    }
}

impl Default for LearnedClauseCaps {
    fn default() -> Self {
        Self::new(1_000_000, 50_000_000, 1_000_000)
    }
}

/// Exact work limit for one immutable scan.
///
/// One unit is charged before visiting each clause and one before inspecting
/// each literal. A satisfied clause stops literal inspection at its first true
/// literal in canonical order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LearnedScanCaps {
    pub(crate) max_work: usize,
}

impl LearnedScanCaps {
    pub(crate) const fn new(max_work: usize) -> Self {
        Self { max_work }
    }

    pub(crate) const fn unlimited() -> Self {
        Self::new(usize::MAX)
    }
}

impl Default for LearnedScanCaps {
    fn default() -> Self {
        Self::new(50_000_000)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LearnedClauseResource {
    LearnedClauses,
    TotalLiterals,
    ClauseLiterals,
}

impl fmt::Display for LearnedClauseResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::LearnedClauses => "learned clauses",
            Self::TotalLiterals => "stored learned-clause literals",
            Self::ClauseLiterals => "learned-clause literals",
        };
        output.write_str(name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LearnedClauseError {
    AtomOutOfRange {
        atom: AtomId,
        atom_count: usize,
    },
    BaseClauseCountOutOfRange {
        count: usize,
        maximum: u64,
    },
    CapExceeded {
        resource: LearnedClauseResource,
        attempted: usize,
        limit: usize,
    },
    CountOverflow {
        resource: LearnedClauseResource,
    },
    ClauseIdSpaceExhausted {
        global_index: usize,
        maximum: u64,
    },
    ScanWorkCapExceeded {
        completed: usize,
        attempted: usize,
        limit: usize,
    },
    ScanWorkOverflow {
        completed: usize,
    },
    AllocationFailed {
        context: &'static str,
        requested: usize,
    },
}

impl fmt::Display for LearnedClauseError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtomOutOfRange { atom, atom_count } => write!(
                output,
                "learned-clause atom {} is outside 0..{atom_count}",
                atom.index()
            ),
            Self::BaseClauseCountOutOfRange { count, maximum } => write!(
                output,
                "base clause count {count} exceeds the {maximum}-entry ClauseId space"
            ),
            Self::CapExceeded {
                resource,
                attempted,
                limit,
            } => write!(
                output,
                "{resource} cap exceeded: attempted {attempted}, limit {limit}"
            ),
            Self::CountOverflow { resource } => {
                write!(output, "arithmetic overflow while counting {resource}")
            }
            Self::ClauseIdSpaceExhausted {
                global_index,
                maximum,
            } => write!(
                output,
                "global clause index {global_index} exceeds the {maximum}-entry ClauseId space"
            ),
            Self::ScanWorkCapExceeded {
                completed,
                attempted,
                limit,
            } => write!(
                output,
                "learned-clause scan work cap exceeded after {completed} units: attempted {attempted}, limit {limit}"
            ),
            Self::ScanWorkOverflow { completed } => write!(
                output,
                "learned-clause scan work overflow after {completed} units"
            ),
            Self::AllocationFailed { context, requested } => write!(
                output,
                "allocation failed for {context} while requesting {requested} entries"
            ),
        }
    }
}

impl Error for LearnedClauseError {}

/// Classification of one canonical insertion request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LearnedClauseInsert {
    /// Both polarities of at least one atom occur; nothing is stored.
    Tautology,
    /// The canonical clause is empty and is an immediate root conflict.
    Empty,
    /// The canonical clause is a unit and should be enqueued immediately.
    Unit(Lit),
    /// The canonical general clause already has this stable global ID.
    Existing(ClauseId),
    /// A new canonical general clause was assigned this stable global ID.
    Stored(ClauseId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LearnedScanOutcome {
    /// Every stored learned clause encountered a true literal.
    Satisfied,
    /// No clause is actionable, but at least one has two or more unknowns.
    Open,
    /// The first actionable clause in increasing global-ID order is unit.
    Unit { clause: ClauseId, literal: Lit },
    /// The first actionable clause in increasing global-ID order conflicts.
    Conflict { clause: ClauseId },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LearnedScanReport {
    pub(crate) outcome: LearnedScanOutcome,
    pub(crate) work: usize,
}

#[derive(Clone, Debug)]
struct ClauseRecord {
    id: ClauseId,
    literals: Vec<Lit>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AllocationSite {
    CanonicalClause,
    ClauseTable,
    DedupIndex,
}

impl AllocationSite {
    const fn context(self) -> &'static str {
        match self {
            Self::CanonicalClause => "canonical learned clause",
            Self::ClauseTable => "learned-clause table",
            Self::DedupIndex => "learned-clause dedup index",
        }
    }
}

/// Append-only learned clauses whose IDs follow an immutable native database.
#[derive(Debug)]
pub(crate) struct LearnedClauseDb {
    atom_count: usize,
    base_clause_count: usize,
    caps: LearnedClauseCaps,
    clauses: Vec<ClauseRecord>,
    /// Global IDs ordered lexicographically by canonical clause content.
    canonical_order: Vec<ClauseId>,
    total_literals: usize,
    #[cfg(test)]
    fail_allocation_at: Option<AllocationSite>,
    #[cfg(test)]
    next_local_index_override: Option<usize>,
}

impl LearnedClauseDb {
    pub(crate) fn new(
        atom_count: usize,
        base_clause_count: usize,
    ) -> Result<Self, LearnedClauseError> {
        Self::with_caps(atom_count, base_clause_count, LearnedClauseCaps::default())
    }

    pub(crate) fn with_caps(
        atom_count: usize,
        base_clause_count: usize,
        caps: LearnedClauseCaps,
    ) -> Result<Self, LearnedClauseError> {
        let base = u64::try_from(base_clause_count).map_err(|_| {
            LearnedClauseError::BaseClauseCountOutOfRange {
                count: base_clause_count,
                maximum: CLAUSE_ID_CAPACITY,
            }
        })?;
        if base > CLAUSE_ID_CAPACITY {
            return Err(LearnedClauseError::BaseClauseCountOutOfRange {
                count: base_clause_count,
                maximum: CLAUSE_ID_CAPACITY,
            });
        }
        Ok(Self {
            atom_count,
            base_clause_count,
            caps,
            clauses: Vec::new(),
            canonical_order: Vec::new(),
            total_literals: 0,
            #[cfg(test)]
            fail_allocation_at: None,
            #[cfg(test)]
            next_local_index_override: None,
        })
    }

    pub(crate) fn atom_count(&self) -> usize {
        self.atom_count
    }

    pub(crate) fn base_clause_count(&self) -> usize {
        self.base_clause_count
    }

    pub(crate) fn caps(&self) -> LearnedClauseCaps {
        self.caps
    }

    pub(crate) fn len(&self) -> usize {
        self.clauses.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.clauses.is_empty()
    }

    pub(crate) fn total_literals(&self) -> usize {
        self.total_literals
    }

    /// Look up a stored learned clause by global ID.
    pub(crate) fn clause(&self, id: ClauseId) -> Option<&[Lit]> {
        let local = id.index().checked_sub(self.base_clause_count)?;
        let record = self.clauses.get(local)?;
        (record.id == id).then_some(record.literals.as_slice())
    }

    /// Iterate in increasing global-ID order.
    pub(crate) fn iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = (ClauseId, &[Lit])> + ExactSizeIterator + '_ {
        self.clauses
            .iter()
            .map(|record| (record.id, record.literals.as_slice()))
    }

    /// Canonicalize and insert a learned clause.
    ///
    /// Existing clauses are reused before count and total-literal caps are
    /// checked. Every returned error leaves the logical database unchanged.
    pub(crate) fn insert(
        &mut self,
        literals: &[Lit],
    ) -> Result<LearnedClauseInsert, LearnedClauseError> {
        self.validate_atoms(literals)?;
        let mut canonical = self.copy_for_canonicalization(literals)?;
        canonical.sort_unstable();
        canonical.dedup();

        if canonical.windows(2).any(|pair| {
            pair[0].atom() == pair[1].atom() && pair[0].is_positive() != pair[1].is_positive()
        }) {
            return Ok(LearnedClauseInsert::Tautology);
        }

        check_cap(
            LearnedClauseResource::ClauseLiterals,
            canonical.len(),
            self.caps.max_clause_literals,
        )?;
        match canonical.as_slice() {
            [] => return Ok(LearnedClauseInsert::Empty),
            [literal] => return Ok(LearnedClauseInsert::Unit(*literal)),
            _ => {}
        }

        let insertion_index = match self.canonical_position(&canonical) {
            Ok(index) => return Ok(LearnedClauseInsert::Existing(self.canonical_order[index])),
            Err(index) => index,
        };

        let next_count = checked_add(self.clauses.len(), 1, LearnedClauseResource::LearnedClauses)?;
        check_cap(
            LearnedClauseResource::LearnedClauses,
            next_count,
            self.caps.max_learned_clauses,
        )?;
        let next_total_literals = checked_add(
            self.total_literals,
            canonical.len(),
            LearnedClauseResource::TotalLiterals,
        )?;
        check_cap(
            LearnedClauseResource::TotalLiterals,
            next_total_literals,
            self.caps.max_total_literals,
        )?;

        let local_index = self.next_local_index();
        let global_index = self.base_clause_count.checked_add(local_index).ok_or(
            LearnedClauseError::CountOverflow {
                resource: LearnedClauseResource::LearnedClauses,
            },
        )?;
        let raw_id = u32::try_from(global_index).map_err(|_| {
            LearnedClauseError::ClauseIdSpaceExhausted {
                global_index,
                maximum: CLAUSE_ID_CAPACITY,
            }
        })?;
        let id = ClauseId::new(raw_id);
        debug_assert_eq!(local_index, self.clauses.len());

        self.reserve_clause_slot(next_count)?;
        self.reserve_dedup_slot(next_count)?;
        self.clauses.push(ClauseRecord {
            id,
            literals: canonical,
        });
        self.canonical_order.insert(insertion_index, id);
        self.total_literals = next_total_literals;
        Ok(LearnedClauseInsert::Stored(id))
    }

    /// Scan stored clauses in global-ID order without changing the database.
    pub(crate) fn scan<I: Interpretation + ?Sized>(
        &self,
        interpretation: &I,
        caps: LearnedScanCaps,
    ) -> Result<LearnedScanReport, LearnedClauseError> {
        let mut work = 0usize;
        let mut saw_open = false;

        for record in &self.clauses {
            charge_scan_work(&mut work, caps.max_work)?;
            let mut first_unknown = None;
            let mut multiple_unknowns = false;
            let mut satisfied = false;

            for &literal in &record.literals {
                charge_scan_work(&mut work, caps.max_work)?;
                match interpretation.truth(literal) {
                    Truth::True => {
                        satisfied = true;
                        break;
                    }
                    Truth::Unknown => {
                        if first_unknown.is_some() {
                            multiple_unknowns = true;
                        } else {
                            first_unknown = Some(literal);
                        }
                    }
                    Truth::False => {}
                }
            }

            if satisfied {
                continue;
            }
            match (first_unknown, multiple_unknowns) {
                (None, _) => {
                    return Ok(LearnedScanReport {
                        outcome: LearnedScanOutcome::Conflict { clause: record.id },
                        work,
                    });
                }
                (Some(literal), false) => {
                    return Ok(LearnedScanReport {
                        outcome: LearnedScanOutcome::Unit {
                            clause: record.id,
                            literal,
                        },
                        work,
                    });
                }
                (Some(_), true) => saw_open = true,
            }
        }

        Ok(LearnedScanReport {
            outcome: if saw_open {
                LearnedScanOutcome::Open
            } else {
                LearnedScanOutcome::Satisfied
            },
            work,
        })
    }

    fn validate_atoms(&self, literals: &[Lit]) -> Result<(), LearnedClauseError> {
        for literal in literals {
            if literal.atom().index() >= self.atom_count {
                return Err(LearnedClauseError::AtomOutOfRange {
                    atom: literal.atom(),
                    atom_count: self.atom_count,
                });
            }
        }
        Ok(())
    }

    fn copy_for_canonicalization(
        &mut self,
        literals: &[Lit],
    ) -> Result<Vec<Lit>, LearnedClauseError> {
        self.allocation_gate(AllocationSite::CanonicalClause, literals.len())?;
        let mut canonical = Vec::new();
        try_reserve_exact(
            &mut canonical,
            literals.len(),
            AllocationSite::CanonicalClause.context(),
        )?;
        canonical.extend_from_slice(literals);
        Ok(canonical)
    }

    fn canonical_position(&self, canonical: &[Lit]) -> Result<usize, usize> {
        self.canonical_order.binary_search_by(|id| {
            self.clause(*id)
                .expect("dedup IDs must identify stored learned clauses")
                .cmp(canonical)
        })
    }

    fn reserve_clause_slot(&mut self, requested: usize) -> Result<(), LearnedClauseError> {
        self.allocation_gate(AllocationSite::ClauseTable, requested)?;
        try_reserve_additional(
            &mut self.clauses,
            1,
            requested,
            AllocationSite::ClauseTable.context(),
        )
    }

    fn reserve_dedup_slot(&mut self, requested: usize) -> Result<(), LearnedClauseError> {
        self.allocation_gate(AllocationSite::DedupIndex, requested)?;
        try_reserve_additional(
            &mut self.canonical_order,
            1,
            requested,
            AllocationSite::DedupIndex.context(),
        )
    }

    fn allocation_gate(
        &mut self,
        site: AllocationSite,
        requested: usize,
    ) -> Result<(), LearnedClauseError> {
        #[cfg(test)]
        if self.fail_allocation_at == Some(site) {
            self.fail_allocation_at = None;
            return Err(LearnedClauseError::AllocationFailed {
                context: site.context(),
                requested,
            });
        }
        let _ = (site, requested);
        Ok(())
    }

    fn next_local_index(&self) -> usize {
        #[cfg(test)]
        if let Some(index) = self.next_local_index_override {
            return index;
        }
        self.clauses.len()
    }

    #[cfg(test)]
    fn fail_next_allocation_at(&mut self, site: AllocationSite) {
        self.fail_allocation_at = Some(site);
    }

    #[cfg(test)]
    fn invariants_hold(&self) -> bool {
        if self.clauses.len() != self.canonical_order.len()
            || self.clauses.len() > self.caps.max_learned_clauses
            || self.total_literals > self.caps.max_total_literals
        {
            return false;
        }

        let mut observed_total = 0usize;
        for (local, record) in self.clauses.iter().enumerate() {
            let Some(global) = self.base_clause_count.checked_add(local) else {
                return false;
            };
            let Ok(raw) = u32::try_from(global) else {
                return false;
            };
            if record.id != ClauseId::new(raw)
                || record.literals.len() < 2
                || record.literals.len() > self.caps.max_clause_literals
                || record
                    .literals
                    .iter()
                    .any(|lit| lit.atom().index() >= self.atom_count)
                || record.literals.windows(2).any(|pair| {
                    pair[0] >= pair[1]
                        || (pair[0].atom() == pair[1].atom()
                            && pair[0].is_positive() != pair[1].is_positive())
                })
            {
                return false;
            }
            let Some(next_total) = observed_total.checked_add(record.literals.len()) else {
                return false;
            };
            observed_total = next_total;
        }
        if observed_total != self.total_literals
            || self
                .canonical_order
                .iter()
                .any(|id| self.clause(*id).is_none())
        {
            return false;
        }
        self.canonical_order.windows(2).all(|ids| {
            self.clause(ids[0]).expect("validated ID") < self.clause(ids[1]).expect("validated ID")
        })
    }
}

fn checked_add(
    current: usize,
    additional: usize,
    resource: LearnedClauseResource,
) -> Result<usize, LearnedClauseError> {
    current
        .checked_add(additional)
        .ok_or(LearnedClauseError::CountOverflow { resource })
}

fn check_cap(
    resource: LearnedClauseResource,
    attempted: usize,
    limit: usize,
) -> Result<(), LearnedClauseError> {
    if attempted > limit {
        Err(LearnedClauseError::CapExceeded {
            resource,
            attempted,
            limit,
        })
    } else {
        Ok(())
    }
}

fn charge_scan_work(work: &mut usize, limit: usize) -> Result<(), LearnedClauseError> {
    let attempted = work
        .checked_add(1)
        .ok_or(LearnedClauseError::ScanWorkOverflow { completed: *work })?;
    if attempted > limit {
        return Err(LearnedClauseError::ScanWorkCapExceeded {
            completed: *work,
            attempted,
            limit,
        });
    }
    *work = attempted;
    Ok(())
}

fn try_reserve_exact<T>(
    values: &mut Vec<T>,
    additional: usize,
    context: &'static str,
) -> Result<(), LearnedClauseError> {
    values
        .try_reserve_exact(additional)
        .map_err(|_| LearnedClauseError::AllocationFailed {
            context,
            requested: additional,
        })
}

fn try_reserve_additional<T>(
    values: &mut Vec<T>,
    additional: usize,
    requested: usize,
    context: &'static str,
) -> Result<(), LearnedClauseError> {
    values
        .try_reserve(additional)
        .map_err(|_| LearnedClauseError::AllocationFailed { context, requested })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct DbSnapshot {
        atom_count: usize,
        base_clause_count: usize,
        caps: LearnedClauseCaps,
        total_literals: usize,
        clauses: Vec<(ClauseId, Vec<Lit>)>,
    }

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

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum ReferenceInsert {
        Tautology,
        Empty,
        Unit(Lit),
        General(Vec<Lit>),
    }

    fn p(index: u32) -> Lit {
        Lit::positive(AtomId::new(index))
    }

    fn n(index: u32) -> Lit {
        Lit::negative(AtomId::new(index))
    }

    fn caps(clauses: usize, total: usize, clause: usize) -> LearnedClauseCaps {
        LearnedClauseCaps::new(clauses, total, clause)
    }

    fn stored(outcome: LearnedClauseInsert) -> ClauseId {
        match outcome {
            LearnedClauseInsert::Stored(id) => id,
            other => panic!("expected stored clause, got {other:?}"),
        }
    }

    fn snapshot(db: &LearnedClauseDb) -> DbSnapshot {
        DbSnapshot {
            atom_count: db.atom_count(),
            base_clause_count: db.base_clause_count(),
            caps: db.caps(),
            total_literals: db.total_literals(),
            clauses: db
                .iter()
                .map(|(id, clause)| (id, clause.to_vec()))
                .collect(),
        }
    }

    fn reference_canonical(literals: &[Lit]) -> ReferenceInsert {
        let mut canonical = literals.to_vec();
        canonical.sort_unstable();
        canonical.dedup();
        if canonical.windows(2).any(|pair| {
            pair[0].atom() == pair[1].atom() && pair[0].is_positive() != pair[1].is_positive()
        }) {
            return ReferenceInsert::Tautology;
        }
        match canonical.as_slice() {
            [] => ReferenceInsert::Empty,
            [literal] => ReferenceInsert::Unit(*literal),
            _ => ReferenceInsert::General(canonical),
        }
    }

    fn reference_scan(db: &LearnedClauseDb, assignment: &Assignment) -> LearnedScanReport {
        let mut work = 0usize;
        let mut saw_open = false;
        for (id, clause) in db.iter() {
            work += 1;
            let mut unknowns = Vec::new();
            let mut satisfied = false;
            for &literal in clause {
                work += 1;
                match assignment.truth(literal) {
                    Truth::True => {
                        satisfied = true;
                        break;
                    }
                    Truth::Unknown => unknowns.push(literal),
                    Truth::False => {}
                }
            }
            if satisfied {
                continue;
            }
            match unknowns.as_slice() {
                [] => {
                    return LearnedScanReport {
                        outcome: LearnedScanOutcome::Conflict { clause: id },
                        work,
                    };
                }
                [literal] => {
                    return LearnedScanReport {
                        outcome: LearnedScanOutcome::Unit {
                            clause: id,
                            literal: *literal,
                        },
                        work,
                    };
                }
                _ => saw_open = true,
            }
        }
        LearnedScanReport {
            outcome: if saw_open {
                LearnedScanOutcome::Open
            } else {
                LearnedScanOutcome::Satisfied
            },
            work,
        }
    }

    fn next_random(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state
    }

    #[test]
    fn reports_all_non_storing_shapes_explicitly() {
        let mut db = LearnedClauseDb::new(3, 5).unwrap();
        assert_eq!(db.insert(&[]).unwrap(), LearnedClauseInsert::Empty);
        assert_eq!(
            db.insert(&[p(1), p(1)]).unwrap(),
            LearnedClauseInsert::Unit(p(1))
        );
        assert_eq!(
            db.insert(&[p(0), n(0), p(2)]).unwrap(),
            LearnedClauseInsert::Tautology
        );
        assert!(db.is_empty());
        assert_eq!(db.total_literals(), 0);
        assert!(db.invariants_hold());
    }

    #[test]
    fn canonicalizes_and_reuses_general_clauses() {
        let mut db = LearnedClauseDb::new(4, 9).unwrap();
        let first = stored(db.insert(&[p(3), n(0), p(1), p(3), n(0)]).unwrap());
        assert_eq!(first, ClauseId::new(9));
        assert_eq!(db.clause(first), Some(&[n(0), p(1), p(3)][..]));
        assert_eq!(
            db.insert(&[p(1), p(3), n(0)]).unwrap(),
            LearnedClauseInsert::Existing(first)
        );
        assert_eq!(db.len(), 1);
        assert_eq!(db.total_literals(), 3);
        assert!(db.invariants_hold());
    }

    #[test]
    fn global_ids_start_after_base_and_iteration_is_id_order() {
        let mut db = LearnedClauseDb::new(5, 17).unwrap();
        let first = stored(db.insert(&[p(2), p(3)]).unwrap());
        let second = stored(db.insert(&[n(4), p(0)]).unwrap());
        let third = stored(db.insert(&[p(1), n(2), p(4)]).unwrap());
        assert_eq!(
            [first, second, third],
            [ClauseId::new(17), ClauseId::new(18), ClauseId::new(19),]
        );
        assert_eq!(db.clause(ClauseId::new(16)), None);
        assert_eq!(db.clause(ClauseId::new(20)), None);
        assert_eq!(
            db.iter().map(|(id, _)| id).collect::<Vec<_>>(),
            vec![first, second, third]
        );
        assert_eq!(db.iter().rev().next().map(|(id, _)| id), Some(third));
        assert!(db.invariants_hold());
    }

    #[test]
    fn exhaustive_short_inputs_match_canonicalization_oracle() {
        let alphabet = [n(0), p(0), n(1), p(1)];
        for length in 0..=5usize {
            let cases = alphabet.len().pow(length as u32);
            for mut code in 0..cases {
                let mut input = Vec::with_capacity(length);
                for _ in 0..length {
                    input.push(alphabet[code % alphabet.len()]);
                    code /= alphabet.len();
                }
                let expected = reference_canonical(&input);
                let mut db = LearnedClauseDb::with_caps(2, 3, caps(4, 16, 8)).unwrap();
                let actual = db.insert(&input).unwrap();
                match expected {
                    ReferenceInsert::Tautology => {
                        assert_eq!(actual, LearnedClauseInsert::Tautology)
                    }
                    ReferenceInsert::Empty => assert_eq!(actual, LearnedClauseInsert::Empty),
                    ReferenceInsert::Unit(literal) => {
                        assert_eq!(actual, LearnedClauseInsert::Unit(literal))
                    }
                    ReferenceInsert::General(canonical) => {
                        let id = stored(actual);
                        assert_eq!(db.clause(id), Some(canonical.as_slice()));
                    }
                }
                assert!(db.invariants_hold());
            }
        }
    }

    #[test]
    fn invalid_atoms_are_rejected_before_any_allocation_or_mutation() {
        let mut db = LearnedClauseDb::new(2, 0).unwrap();
        db.fail_next_allocation_at(AllocationSite::CanonicalClause);
        let before = snapshot(&db);
        assert_eq!(
            db.insert(&[p(2), n(2)]).unwrap_err(),
            LearnedClauseError::AtomOutOfRange {
                atom: p(2).atom(),
                atom_count: 2,
            }
        );
        assert_eq!(snapshot(&db), before);
        assert!(matches!(
            db.insert(&[p(0), p(1)]),
            Err(LearnedClauseError::AllocationFailed { .. })
        ));
    }

    #[test]
    fn every_persistent_cap_is_hard_and_transactional() {
        let mut count_limited = LearnedClauseDb::with_caps(4, 2, caps(1, 20, 10)).unwrap();
        let first = stored(count_limited.insert(&[p(0), p(1)]).unwrap());
        let before = snapshot(&count_limited);
        assert_eq!(
            count_limited.insert(&[p(2), p(3)]).unwrap_err(),
            LearnedClauseError::CapExceeded {
                resource: LearnedClauseResource::LearnedClauses,
                attempted: 2,
                limit: 1,
            }
        );
        assert_eq!(snapshot(&count_limited), before);
        assert_eq!(
            count_limited.insert(&[p(1), p(0)]).unwrap(),
            LearnedClauseInsert::Existing(first)
        );

        let mut total_limited = LearnedClauseDb::with_caps(4, 0, caps(4, 2, 10)).unwrap();
        stored(total_limited.insert(&[p(0), p(1)]).unwrap());
        let before = snapshot(&total_limited);
        assert_eq!(
            total_limited.insert(&[p(2), p(3)]).unwrap_err(),
            LearnedClauseError::CapExceeded {
                resource: LearnedClauseResource::TotalLiterals,
                attempted: 4,
                limit: 2,
            }
        );
        assert_eq!(snapshot(&total_limited), before);

        let mut length_limited = LearnedClauseDb::with_caps(4, 0, caps(4, 20, 2)).unwrap();
        let before = snapshot(&length_limited);
        assert_eq!(
            length_limited.insert(&[p(0), p(1), p(2)]).unwrap_err(),
            LearnedClauseError::CapExceeded {
                resource: LearnedClauseResource::ClauseLiterals,
                attempted: 3,
                limit: 2,
            }
        );
        assert_eq!(snapshot(&length_limited), before);
        assert!(count_limited.invariants_hold());
        assert!(total_limited.invariants_hold());
        assert!(length_limited.invariants_hold());
    }

    #[test]
    fn zero_caps_still_allow_empty_and_tautological_outcomes() {
        let mut db = LearnedClauseDb::with_caps(2, 0, caps(0, 0, 0)).unwrap();
        assert_eq!(db.insert(&[]).unwrap(), LearnedClauseInsert::Empty);
        assert_eq!(
            db.insert(&[p(0), n(0)]).unwrap(),
            LearnedClauseInsert::Tautology
        );
        assert!(matches!(
            db.insert(&[p(0)]),
            Err(LearnedClauseError::CapExceeded {
                resource: LearnedClauseResource::ClauseLiterals,
                ..
            })
        ));
        assert!(db.is_empty());
    }

    #[test]
    fn allocation_failures_are_transactional_and_retryable() {
        for site in [
            AllocationSite::CanonicalClause,
            AllocationSite::ClauseTable,
            AllocationSite::DedupIndex,
        ] {
            let mut db = LearnedClauseDb::new(3, 4).unwrap();
            stored(db.insert(&[p(0), p(1)]).unwrap());
            let before = snapshot(&db);
            db.fail_next_allocation_at(site);
            assert!(matches!(
                db.insert(&[n(1), p(2)]),
                Err(LearnedClauseError::AllocationFailed { .. })
            ));
            assert_eq!(snapshot(&db), before, "failed site {site:?}");
            let id = stored(db.insert(&[n(1), p(2)]).unwrap());
            assert_eq!(id, ClauseId::new(5));
            assert!(db.invariants_hold());
        }
    }

    #[test]
    fn actual_reservation_failure_is_reported() {
        let mut values = Vec::<Lit>::new();
        assert!(matches!(
            try_reserve_exact(&mut values, usize::MAX, "test allocation"),
            Err(LearnedClauseError::AllocationFailed {
                context: "test allocation",
                requested: usize::MAX,
            })
        ));
        assert!(values.is_empty());
    }

    #[test]
    fn clause_id_space_is_checked_at_the_global_offset() {
        let mut last =
            LearnedClauseDb::with_caps(4, u32::MAX as usize, LearnedClauseCaps::unlimited())
                .unwrap();
        let id = stored(last.insert(&[p(0), p(1)]).unwrap());
        assert_eq!(id, ClauseId::MAX);
        let before = snapshot(&last);
        assert!(matches!(
            last.insert(&[p(2), p(3)]),
            Err(LearnedClauseError::ClauseIdSpaceExhausted { .. })
        ));
        assert_eq!(snapshot(&last), before);

        last.next_local_index_override = Some(usize::MAX);
        assert!(matches!(
            last.insert(&[n(0), n(1)]),
            Err(LearnedClauseError::CountOverflow {
                resource: LearnedClauseResource::LearnedClauses,
            })
        ));
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn constructor_checks_the_complete_clause_id_capacity() {
        let capacity = CLAUSE_ID_CAPACITY as usize;
        let mut exhausted = LearnedClauseDb::new(2, capacity).unwrap();
        assert!(matches!(
            exhausted.insert(&[p(0), p(1)]),
            Err(LearnedClauseError::ClauseIdSpaceExhausted { .. })
        ));
        assert!(matches!(
            LearnedClauseDb::new(2, capacity + 1),
            Err(LearnedClauseError::BaseClauseCountOutOfRange { .. })
        ));
    }

    #[test]
    fn scan_reports_satisfied_open_unit_and_conflict() {
        let mut db = LearnedClauseDb::new(4, 11).unwrap();
        let first = stored(db.insert(&[p(0), p(1)]).unwrap());
        let second = stored(db.insert(&[n(0), p(2), p(3)]).unwrap());

        let satisfied = Assignment(vec![Truth::True, Truth::False, Truth::True, Truth::False]);
        assert_eq!(
            db.scan(&satisfied, LearnedScanCaps::unlimited()).unwrap(),
            LearnedScanReport {
                outcome: LearnedScanOutcome::Satisfied,
                work: 5,
            }
        );

        let open = Assignment(vec![Truth::Unknown; 4]);
        assert_eq!(
            db.scan(&open, LearnedScanCaps::unlimited()).unwrap(),
            LearnedScanReport {
                outcome: LearnedScanOutcome::Open,
                work: 7,
            }
        );

        let unit = Assignment(vec![
            Truth::False,
            Truth::Unknown,
            Truth::Unknown,
            Truth::Unknown,
        ]);
        assert_eq!(
            db.scan(&unit, LearnedScanCaps::unlimited())
                .unwrap()
                .outcome,
            LearnedScanOutcome::Unit {
                clause: first,
                literal: p(1),
            }
        );

        let conflict = Assignment(vec![Truth::False, Truth::False, Truth::True, Truth::True]);
        assert_eq!(
            db.scan(&conflict, LearnedScanCaps::unlimited())
                .unwrap()
                .outcome,
            LearnedScanOutcome::Conflict { clause: first }
        );
        assert_eq!(second, ClauseId::new(12));
    }

    #[test]
    fn scan_returns_first_actionable_clause_in_id_order() {
        let mut db = LearnedClauseDb::new(4, 30).unwrap();
        let open = stored(db.insert(&[p(0), p(1)]).unwrap());
        let unit = stored(db.insert(&[p(2), p(3)]).unwrap());
        let later_conflict = stored(db.insert(&[n(0), n(1)]).unwrap());
        let assignment = Assignment(vec![
            Truth::Unknown,
            Truth::Unknown,
            Truth::False,
            Truth::Unknown,
        ]);
        assert_eq!(
            db.scan(&assignment, LearnedScanCaps::unlimited())
                .unwrap()
                .outcome,
            LearnedScanOutcome::Unit {
                clause: unit,
                literal: p(3),
            }
        );
        assert_eq!(open, ClauseId::new(30));
        assert_eq!(later_conflict, ClauseId::new(32));
    }

    #[test]
    fn exhaustive_assignments_match_independent_scan_oracle() {
        let mut db = LearnedClauseDb::new(4, 7).unwrap();
        for clause in [
            vec![p(0), p(1), p(2)],
            vec![n(0), p(2)],
            vec![n(1), n(2), p(3)],
            vec![p(0), n(3)],
        ] {
            stored(db.insert(&clause).unwrap());
        }

        for mut code in 0..3usize.pow(4) {
            let mut values = Vec::with_capacity(4);
            for _ in 0..4 {
                values.push(match code % 3 {
                    0 => Truth::False,
                    1 => Truth::Unknown,
                    _ => Truth::True,
                });
                code /= 3;
            }
            let assignment = Assignment(values);
            assert_eq!(
                db.scan(&assignment, LearnedScanCaps::unlimited()).unwrap(),
                reference_scan(&db, &assignment)
            );
        }
    }

    #[test]
    fn scan_work_cap_is_exact_and_scan_never_mutates() {
        let mut db = LearnedClauseDb::new(2, 3).unwrap();
        stored(db.insert(&[p(0), p(1)]).unwrap());
        let before = snapshot(&db);
        let open = Assignment(vec![Truth::Unknown, Truth::Unknown]);
        assert_eq!(
            db.scan(&open, LearnedScanCaps::new(2)).unwrap_err(),
            LearnedClauseError::ScanWorkCapExceeded {
                completed: 2,
                attempted: 3,
                limit: 2,
            }
        );
        assert_eq!(snapshot(&db), before);
        assert_eq!(
            db.scan(&open, LearnedScanCaps::new(3)).unwrap(),
            LearnedScanReport {
                outcome: LearnedScanOutcome::Open,
                work: 3,
            }
        );

        let satisfied_early = Assignment(vec![Truth::True, Truth::False]);
        assert_eq!(
            db.scan(&satisfied_early, LearnedScanCaps::new(2)).unwrap(),
            LearnedScanReport {
                outcome: LearnedScanOutcome::Satisfied,
                work: 2,
            }
        );
        assert_eq!(
            db.scan(&satisfied_early, LearnedScanCaps::new(1))
                .unwrap_err(),
            LearnedClauseError::ScanWorkCapExceeded {
                completed: 1,
                attempted: 2,
                limit: 1,
            }
        );
        assert_eq!(snapshot(&db), before);
    }

    #[test]
    fn deterministic_random_streams_and_scans_match() {
        let mut left = LearnedClauseDb::with_caps(6, 13, caps(512, 4096, 12)).unwrap();
        let mut right = LearnedClauseDb::with_caps(6, 13, caps(512, 4096, 12)).unwrap();
        let mut state = 0x5eed_fade_cafe_babe;

        for _ in 0..500 {
            let length = (next_random(&mut state) % 9) as usize;
            let mut clause = Vec::with_capacity(length);
            for _ in 0..length {
                let atom = (next_random(&mut state) % 6) as u32;
                let positive = next_random(&mut state) & 1 == 0;
                clause.push(if positive { p(atom) } else { n(atom) });
            }
            let mut permuted = clause.clone();
            permuted.reverse();
            assert_eq!(left.insert(&clause), right.insert(&permuted));
            assert_eq!(snapshot(&left), snapshot(&right));
        }
        assert!(left.invariants_hold());
        assert!(right.invariants_hold());

        for _ in 0..500 {
            let assignment = Assignment(
                (0..6)
                    .map(|_| match next_random(&mut state) % 3 {
                        0 => Truth::False,
                        1 => Truth::Unknown,
                        _ => Truth::True,
                    })
                    .collect(),
            );
            let expected = reference_scan(&left, &assignment);
            assert_eq!(
                left.scan(&assignment, LearnedScanCaps::unlimited())
                    .unwrap(),
                expected
            );
        }
    }
}
