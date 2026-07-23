#![forbid(unsafe_code)]

//! Canonical, append-only storage for theory reason clauses.
//!
//! Theory reasons cross the theory/Boolean boundary only as stable native
//! literals.  The arena validates atom identifiers, canonicalizes each clause,
//! and never stores a tautology: a tautological clause cannot justify a
//! propagation even though it is logically true.  Empty clauses are rejected
//! because they cannot contain a propagated literal; unit theory facts are
//! accepted.
//!
//! IDs are insertion-order indices and remain valid for the arena's lifetime.
//! A sorted ID side index provides deterministic content deduplication without
//! relying on randomized hash iteration.  Every fallible persistent allocation
//! is reserved before either vector is changed, so failed insertions leave the
//! logical arena state untouched.

use super::learning::ReasonProvider;
use super::native_clause::{AtomId, ClauseId, Lit, NativeClauseDb};
use super::trail::TheoryReasonId;
use std::error::Error;
use std::fmt;

const MAX_REASON_IDS: u64 = u32::MAX as u64 + 1;

/// Resources protected by [`TheoryReasonCaps`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TheoryReasonResource {
    Reasons,
    TotalLiterals,
    ClauseLiterals,
    DuplicateReuses,
    TautologiesSkipped,
}

impl fmt::Display for TheoryReasonResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Reasons => "theory reasons",
            Self::TotalLiterals => "stored theory-reason literals",
            Self::ClauseLiterals => "theory-reason clause literals",
            Self::DuplicateReuses => "deduplicated theory-reason insertions",
            Self::TautologiesSkipped => "skipped tautological theory reasons",
        };
        output.write_str(name)
    }
}

/// Structural storage limits. All three limits are applied to canonical data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TheoryReasonCaps {
    pub(crate) max_reasons: usize,
    pub(crate) max_total_literals: usize,
    pub(crate) max_clause_literals: usize,
}

impl TheoryReasonCaps {
    pub(crate) const fn new(
        max_reasons: usize,
        max_total_literals: usize,
        max_clause_literals: usize,
    ) -> Self {
        Self {
            max_reasons,
            max_total_literals,
            max_clause_literals,
        }
    }

    pub(crate) const fn unlimited() -> Self {
        Self::new(usize::MAX, usize::MAX, usize::MAX)
    }
}

impl Default for TheoryReasonCaps {
    fn default() -> Self {
        Self::new(1_000_000, 50_000_000, 1_000_000)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TheoryReasonError {
    AtomOutOfRange {
        atom: AtomId,
        atom_count: usize,
    },
    EmptyClause,
    CapExceeded {
        resource: TheoryReasonResource,
        attempted: usize,
        limit: usize,
    },
    CountOverflow {
        resource: TheoryReasonResource,
    },
    ReasonIdSpaceExhausted {
        index: usize,
        maximum: u64,
    },
    AllocationFailed {
        context: &'static str,
        requested: usize,
    },
}

impl fmt::Display for TheoryReasonError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtomOutOfRange { atom, atom_count } => write!(
                output,
                "theory reason atom {} is outside 0..{atom_count}",
                atom.index()
            ),
            Self::EmptyClause => {
                output.write_str("an empty clause cannot be used as a theory reason")
            }
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
            Self::ReasonIdSpaceExhausted { index, maximum } => write!(
                output,
                "theory reason index {index} exceeds the {maximum}-entry TheoryReasonId space"
            ),
            Self::AllocationFailed { context, requested } => write!(
                output,
                "allocation failed for {context} while requesting {requested} entries"
            ),
        }
    }
}

impl Error for TheoryReasonError {}

/// Classification of a structurally valid insertion request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TheoryReasonInsert {
    Stored(TheoryReasonId),
    Existing(TheoryReasonId),
    /// The input contained both polarities of one atom and was not stored.
    Tautology,
}

/// Exact gauges and successful non-storing outcomes for one arena.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TheoryReasonTelemetry {
    pub(crate) reasons_stored: usize,
    pub(crate) literals_stored: usize,
    pub(crate) peak_clause_literals: usize,
    pub(crate) duplicate_reuses: usize,
    pub(crate) tautologies_skipped: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AllocationSite {
    CanonicalClause,
    ReasonTable,
    DedupIndex,
}

impl AllocationSite {
    const fn context(self) -> &'static str {
        match self {
            Self::CanonicalClause => "canonical theory reason clause",
            Self::ReasonTable => "theory reason table",
            Self::DedupIndex => "theory reason dedup index",
        }
    }
}

/// Append-only arena indexed by [`TheoryReasonId`].
#[derive(Debug)]
pub(crate) struct TheoryReasonArena {
    atom_count: usize,
    caps: TheoryReasonCaps,
    reasons: Vec<Vec<Lit>>,
    /// IDs ordered lexicographically by their canonical clauses.
    canonical_order: Vec<TheoryReasonId>,
    total_literals: usize,
    peak_clause_literals: usize,
    duplicate_reuses: usize,
    tautologies_skipped: usize,
    #[cfg(test)]
    fail_allocation_at: Option<AllocationSite>,
    #[cfg(test)]
    next_reason_index_override: Option<usize>,
}

impl TheoryReasonArena {
    pub(crate) fn new(atom_count: usize, caps: TheoryReasonCaps) -> Self {
        Self {
            atom_count,
            caps,
            reasons: Vec::new(),
            canonical_order: Vec::new(),
            total_literals: 0,
            peak_clause_literals: 0,
            duplicate_reuses: 0,
            tautologies_skipped: 0,
            #[cfg(test)]
            fail_allocation_at: None,
            #[cfg(test)]
            next_reason_index_override: None,
        }
    }

    pub(crate) fn atom_count(&self) -> usize {
        self.atom_count
    }

    pub(crate) fn caps(&self) -> TheoryReasonCaps {
        self.caps
    }

    pub(crate) fn len(&self) -> usize {
        self.reasons.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.reasons.is_empty()
    }

    pub(crate) fn total_literals(&self) -> usize {
        self.total_literals
    }

    /// Immutable lookup. Unknown or malformed IDs are reported as absent.
    pub(crate) fn get(&self, id: TheoryReasonId) -> Option<&[Lit]> {
        self.reasons.get(id.index()).map(Vec::as_slice)
    }

    pub(crate) fn telemetry(&self) -> TheoryReasonTelemetry {
        TheoryReasonTelemetry {
            reasons_stored: self.reasons.len(),
            literals_stored: self.total_literals,
            peak_clause_literals: self.peak_clause_literals,
            duplicate_reuses: self.duplicate_reuses,
            tautologies_skipped: self.tautologies_skipped,
        }
    }

    /// Build the immutable adapter consumed by first-UIP analysis.
    pub(crate) fn provider<'arena, 'clauses>(
        &'arena self,
        clauses: &'clauses NativeClauseDb,
    ) -> TheoryReasonProvider<'arena, 'clauses> {
        TheoryReasonProvider::new(self, clauses)
    }

    /// Canonicalize and insert one reason clause.
    ///
    /// Existing canonical clauses reuse their original ID even after a storage
    /// cap has been reached. Errors do not consume an ID or literal budget.
    pub(crate) fn insert(
        &mut self,
        literals: &[Lit],
    ) -> Result<TheoryReasonInsert, TheoryReasonError> {
        self.validate_atoms(literals)?;
        let mut canonical = self.copy_for_canonicalization(literals)?;
        canonical.sort_unstable();
        canonical.dedup();

        if canonical.windows(2).any(|pair| {
            pair[0].atom() == pair[1].atom() && pair[0].is_positive() != pair[1].is_positive()
        }) {
            let skipped = checked_add(
                self.tautologies_skipped,
                1,
                TheoryReasonResource::TautologiesSkipped,
            )?;
            self.tautologies_skipped = skipped;
            return Ok(TheoryReasonInsert::Tautology);
        }
        if canonical.is_empty() {
            return Err(TheoryReasonError::EmptyClause);
        }
        check_cap(
            TheoryReasonResource::ClauseLiterals,
            canonical.len(),
            self.caps.max_clause_literals,
        )?;

        let insertion_index = match self.canonical_position(&canonical) {
            Ok(index) => {
                let reused = checked_add(
                    self.duplicate_reuses,
                    1,
                    TheoryReasonResource::DuplicateReuses,
                )?;
                let id = self.canonical_order[index];
                self.duplicate_reuses = reused;
                return Ok(TheoryReasonInsert::Existing(id));
            }
            Err(index) => index,
        };

        let reason_index = self.next_reason_index();
        let id = reason_id_from_index(reason_index)?;
        let next_reason_count = checked_add(self.reasons.len(), 1, TheoryReasonResource::Reasons)?;
        check_cap(
            TheoryReasonResource::Reasons,
            next_reason_count,
            self.caps.max_reasons,
        )?;
        let next_total_literals = checked_add(
            self.total_literals,
            canonical.len(),
            TheoryReasonResource::TotalLiterals,
        )?;
        check_cap(
            TheoryReasonResource::TotalLiterals,
            next_total_literals,
            self.caps.max_total_literals,
        )?;

        debug_assert_eq!(id.index(), self.reasons.len());
        self.reserve_reason_slot(next_reason_count)?;
        self.reserve_dedup_slot(next_reason_count)?;

        let clause_len = canonical.len();
        self.reasons.push(canonical);
        self.canonical_order.insert(insertion_index, id);
        self.total_literals = next_total_literals;
        self.peak_clause_literals = self.peak_clause_literals.max(clause_len);
        Ok(TheoryReasonInsert::Stored(id))
    }

    fn validate_atoms(&self, literals: &[Lit]) -> Result<(), TheoryReasonError> {
        for literal in literals {
            if literal.atom().index() >= self.atom_count {
                return Err(TheoryReasonError::AtomOutOfRange {
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
    ) -> Result<Vec<Lit>, TheoryReasonError> {
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
        self.canonical_order
            .binary_search_by(|id| self.reasons[id.index()].as_slice().cmp(canonical))
    }

    fn reserve_reason_slot(&mut self, requested: usize) -> Result<(), TheoryReasonError> {
        self.allocation_gate(AllocationSite::ReasonTable, requested)?;
        try_reserve_additional(
            &mut self.reasons,
            1,
            requested,
            AllocationSite::ReasonTable.context(),
        )
    }

    fn reserve_dedup_slot(&mut self, requested: usize) -> Result<(), TheoryReasonError> {
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
    ) -> Result<(), TheoryReasonError> {
        #[cfg(test)]
        if self.fail_allocation_at == Some(site) {
            self.fail_allocation_at = None;
            return Err(TheoryReasonError::AllocationFailed {
                context: site.context(),
                requested,
            });
        }
        let _ = (site, requested);
        Ok(())
    }

    fn next_reason_index(&self) -> usize {
        #[cfg(test)]
        if let Some(index) = self.next_reason_index_override {
            return index;
        }
        self.reasons.len()
    }

    #[cfg(test)]
    fn fail_next_allocation_at(&mut self, site: AllocationSite) {
        self.fail_allocation_at = Some(site);
    }

    #[cfg(test)]
    fn invariants_hold(&self) -> bool {
        if self.reasons.len() != self.canonical_order.len()
            || self.reasons.len() > self.caps.max_reasons
            || self.total_literals > self.caps.max_total_literals
        {
            return false;
        }
        let mut observed_total = 0usize;
        for clause in &self.reasons {
            if clause.is_empty()
                || clause.len() > self.caps.max_clause_literals
                || clause
                    .iter()
                    .any(|lit| lit.atom().index() >= self.atom_count)
                || clause
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1] || pair[0].atom() == pair[1].atom())
            {
                return false;
            }
            let Some(next_total) = observed_total.checked_add(clause.len()) else {
                return false;
            };
            observed_total = next_total;
        }
        if observed_total != self.total_literals {
            return false;
        }
        if self
            .canonical_order
            .iter()
            .any(|id| id.index() >= self.reasons.len())
        {
            return false;
        }
        self.canonical_order.windows(2).all(|ids| {
            self.reasons[ids[0].index()].as_slice() < self.reasons[ids[1].index()].as_slice()
        })
    }
}

/// Immutable combination of native and theory clause stores.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TheoryReasonProvider<'arena, 'clauses> {
    arena: &'arena TheoryReasonArena,
    clauses: &'clauses NativeClauseDb,
}

impl<'arena, 'clauses> TheoryReasonProvider<'arena, 'clauses> {
    pub(crate) const fn new(
        arena: &'arena TheoryReasonArena,
        clauses: &'clauses NativeClauseDb,
    ) -> Self {
        Self { arena, clauses }
    }
}

impl ReasonProvider for TheoryReasonProvider<'_, '_> {
    fn clause_reason(&self, reason: ClauseId) -> Option<&[Lit]> {
        self.clauses.clause(reason)
    }

    fn theory_reason(&self, reason: TheoryReasonId) -> Option<&[Lit]> {
        self.arena.get(reason)
    }
}

fn reason_id_from_index(index: usize) -> Result<TheoryReasonId, TheoryReasonError> {
    u32::try_from(index).map(TheoryReasonId::new).map_err(|_| {
        TheoryReasonError::ReasonIdSpaceExhausted {
            index,
            maximum: MAX_REASON_IDS,
        }
    })
}

fn checked_add(
    current: usize,
    additional: usize,
    resource: TheoryReasonResource,
) -> Result<usize, TheoryReasonError> {
    current
        .checked_add(additional)
        .ok_or(TheoryReasonError::CountOverflow { resource })
}

fn check_cap(
    resource: TheoryReasonResource,
    attempted: usize,
    limit: usize,
) -> Result<(), TheoryReasonError> {
    if attempted > limit {
        Err(TheoryReasonError::CapExceeded {
            resource,
            attempted,
            limit,
        })
    } else {
        Ok(())
    }
}

fn try_reserve_exact<T>(
    values: &mut Vec<T>,
    additional: usize,
    context: &'static str,
) -> Result<(), TheoryReasonError> {
    values
        .try_reserve_exact(additional)
        .map_err(|_| TheoryReasonError::AllocationFailed {
            context,
            requested: additional,
        })
}

fn try_reserve_additional<T>(
    values: &mut Vec<T>,
    additional: usize,
    requested: usize,
    context: &'static str,
) -> Result<(), TheoryReasonError> {
    values
        .try_reserve(additional)
        .map_err(|_| TheoryReasonError::AllocationFailed { context, requested })
}

#[cfg(test)]
mod tests {
    use super::super::learning::{AnalysisCaps, AnalysisOutcome, ReasonProvider, analyze};
    use super::super::native_clause::{AddOutcome, NativeClauseDb};
    use super::super::trail::{Reason, Trail};
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ArenaSnapshot {
        atom_count: usize,
        caps: TheoryReasonCaps,
        total_literals: usize,
        telemetry: TheoryReasonTelemetry,
        reasons: Vec<Vec<Lit>>,
    }

    fn p(index: u32) -> Lit {
        Lit::positive(AtomId::new(index))
    }

    fn n(index: u32) -> Lit {
        Lit::negative(AtomId::new(index))
    }

    fn caps(reasons: usize, total: usize, clause: usize) -> TheoryReasonCaps {
        TheoryReasonCaps::new(reasons, total, clause)
    }

    fn stored(outcome: TheoryReasonInsert) -> TheoryReasonId {
        match outcome {
            TheoryReasonInsert::Stored(id) => id,
            other => panic!("expected stored reason, got {other:?}"),
        }
    }

    fn snapshot(arena: &TheoryReasonArena) -> ArenaSnapshot {
        ArenaSnapshot {
            atom_count: arena.atom_count(),
            caps: arena.caps(),
            total_literals: arena.total_literals(),
            telemetry: arena.telemetry(),
            reasons: (0..arena.len())
                .map(|index| {
                    arena
                        .get(TheoryReasonId::new(index as u32))
                        .expect("snapshot IDs are in range")
                        .to_vec()
                })
                .collect(),
        }
    }

    #[test]
    fn canonicalizes_and_deduplicates_without_changing_first_id() {
        let mut arena = TheoryReasonArena::new(4, caps(8, 24, 6));
        assert_eq!(arena.atom_count(), 4);
        assert_eq!(arena.caps(), caps(8, 24, 6));
        assert!(arena.is_empty());

        let first = stored(arena.insert(&[p(2), n(0), p(1), p(2), n(0)]).unwrap());
        assert_eq!(first.index(), 0);
        assert_eq!(arena.get(first), Some(&[n(0), p(1), p(2)][..]));
        assert_eq!(
            arena.insert(&[p(1), n(0), p(2)]).unwrap(),
            TheoryReasonInsert::Existing(first)
        );

        let second = stored(arena.insert(&[n(3), p(0)]).unwrap());
        assert_eq!(second.index(), 1);
        assert_eq!(arena.get(second), Some(&[p(0), n(3)][..]));
        assert_eq!(
            arena.telemetry(),
            TheoryReasonTelemetry {
                reasons_stored: 2,
                literals_stored: 5,
                peak_clause_literals: 3,
                duplicate_reuses: 1,
                tautologies_skipped: 0,
            }
        );
        assert!(arena.invariants_hold());
    }

    #[test]
    fn tautologies_are_explicit_and_never_consume_storage() {
        let mut arena = TheoryReasonArena::new(3, caps(0, 0, 0));
        assert_eq!(
            arena.insert(&[p(2), p(0), n(2), p(0)]).unwrap(),
            TheoryReasonInsert::Tautology
        );
        assert_eq!(
            arena.insert(&[n(1), p(1)]).unwrap(),
            TheoryReasonInsert::Tautology
        );
        assert!(arena.is_empty());
        assert_eq!(arena.total_literals(), 0);
        assert_eq!(arena.telemetry().tautologies_skipped, 2);
        assert!(arena.invariants_hold());
    }

    #[test]
    fn empty_clauses_are_rejected_and_units_are_stored() {
        let mut arena = TheoryReasonArena::new(2, caps(2, 2, 1));
        let before = snapshot(&arena);
        assert_eq!(arena.insert(&[]), Err(TheoryReasonError::EmptyClause));
        assert_eq!(snapshot(&arena), before);

        let unit = stored(arena.insert(&[n(1), n(1), n(1)]).unwrap());
        assert_eq!(unit.index(), 0);
        assert_eq!(arena.get(unit), Some(&[n(1)][..]));
        assert_eq!(arena.telemetry().peak_clause_literals, 1);
        assert!(arena.invariants_hold());
    }

    #[test]
    fn invalid_atoms_take_priority_and_are_transactional() {
        let mut arena = TheoryReasonArena::new(2, TheoryReasonCaps::unlimited());
        let before = snapshot(&arena);
        assert!(matches!(
            arena.insert(&[p(0), n(0), p(2)]),
            Err(TheoryReasonError::AtomOutOfRange {
                atom,
                atom_count: 2
            }) if atom == AtomId::new(2)
        ));
        assert_eq!(snapshot(&arena), before);
        assert_eq!(arena.telemetry().tautologies_skipped, 0);

        assert!(matches!(
            arena.insert(&[p(u32::MAX)]),
            Err(TheoryReasonError::AtomOutOfRange { atom, .. })
                if atom == AtomId::new(u32::MAX)
        ));
        assert_eq!(snapshot(&arena), before);

        let mut no_atoms = TheoryReasonArena::new(0, TheoryReasonCaps::unlimited());
        assert!(matches!(
            no_atoms.insert(&[n(0)]),
            Err(TheoryReasonError::AtomOutOfRange { atom_count: 0, .. })
        ));
        assert!(no_atoms.is_empty());
    }

    #[test]
    fn malformed_and_unknown_reason_ids_return_none() {
        let mut arena = TheoryReasonArena::new(1, TheoryReasonCaps::unlimited());
        assert_eq!(arena.get(TheoryReasonId::new(0)), None);
        assert_eq!(arena.get(TheoryReasonId::new(u32::MAX)), None);
        let id = stored(arena.insert(&[p(0)]).unwrap());
        assert_eq!(arena.get(id), Some(&[p(0)][..]));
        assert_eq!(arena.get(TheoryReasonId::new(1)), None);
        assert_eq!(arena.get(TheoryReasonId::new(u32::MAX)), None);
    }

    #[test]
    fn clause_length_cap_uses_canonical_length() {
        let mut arena = TheoryReasonArena::new(3, caps(3, 3, 1));
        let unit = vec![p(0); 64];
        assert_eq!(stored(arena.insert(&unit).unwrap()).index(), 0);

        let before = snapshot(&arena);
        assert_eq!(
            arena.insert(&[p(1), p(2)]),
            Err(TheoryReasonError::CapExceeded {
                resource: TheoryReasonResource::ClauseLiterals,
                attempted: 2,
                limit: 1,
            })
        );
        assert_eq!(snapshot(&arena), before);
        assert!(arena.invariants_hold());
    }

    #[test]
    fn reason_count_cap_is_transactional_but_allows_reuse() {
        let mut arena = TheoryReasonArena::new(2, caps(1, 4, 2));
        let first = stored(arena.insert(&[p(0)]).unwrap());
        let before = snapshot(&arena);
        assert_eq!(
            arena.insert(&[p(1)]),
            Err(TheoryReasonError::CapExceeded {
                resource: TheoryReasonResource::Reasons,
                attempted: 2,
                limit: 1,
            })
        );
        assert_eq!(snapshot(&arena), before);
        assert_eq!(
            arena.insert(&[p(0), p(0)]).unwrap(),
            TheoryReasonInsert::Existing(first)
        );
        assert_eq!(arena.len(), 1);
        assert!(arena.invariants_hold());
    }

    #[test]
    fn total_literal_cap_is_transactional_but_allows_reuse() {
        let mut arena = TheoryReasonArena::new(3, caps(3, 2, 2));
        let first = stored(arena.insert(&[p(0), n(1)]).unwrap());
        let before = snapshot(&arena);
        assert_eq!(
            arena.insert(&[p(2)]),
            Err(TheoryReasonError::CapExceeded {
                resource: TheoryReasonResource::TotalLiterals,
                attempted: 3,
                limit: 2,
            })
        );
        assert_eq!(snapshot(&arena), before);
        assert_eq!(
            arena.insert(&[n(1), p(0)]).unwrap(),
            TheoryReasonInsert::Existing(first)
        );
        assert_eq!(arena.total_literals(), 2);
        assert!(arena.invariants_hold());
    }

    #[test]
    fn zero_values_enforce_each_cap_independently() {
        let cases = [
            (caps(0, 1, 1), TheoryReasonResource::Reasons),
            (caps(1, 0, 1), TheoryReasonResource::TotalLiterals),
            (caps(1, 1, 0), TheoryReasonResource::ClauseLiterals),
        ];
        for (arena_caps, expected_resource) in cases {
            let mut arena = TheoryReasonArena::new(1, arena_caps);
            let before = snapshot(&arena);
            assert!(matches!(
                arena.insert(&[p(0)]),
                Err(TheoryReasonError::CapExceeded {
                    resource,
                    attempted: 1,
                    limit: 0,
                }) if resource == expected_resource
            ));
            assert_eq!(snapshot(&arena), before);
        }
    }

    #[test]
    fn checked_counters_and_id_space_report_overflow() {
        assert_eq!(
            checked_add(usize::MAX, 1, TheoryReasonResource::TotalLiterals),
            Err(TheoryReasonError::CountOverflow {
                resource: TheoryReasonResource::TotalLiterals
            })
        );
        assert_eq!(
            checked_add(usize::MAX, 1, TheoryReasonResource::Reasons),
            Err(TheoryReasonError::CountOverflow {
                resource: TheoryReasonResource::Reasons
            })
        );
        assert_eq!(
            reason_id_from_index(u32::MAX as usize)
                .expect("the maximum u32 index is representable")
                .index(),
            u32::MAX as usize
        );

        #[cfg(target_pointer_width = "64")]
        {
            let overflow_index = u32::MAX as usize + 1;
            assert_eq!(
                reason_id_from_index(overflow_index),
                Err(TheoryReasonError::ReasonIdSpaceExhausted {
                    index: overflow_index,
                    maximum: MAX_REASON_IDS,
                })
            );

            let mut arena = TheoryReasonArena::new(1, TheoryReasonCaps::unlimited());
            arena.next_reason_index_override = Some(overflow_index);
            let before = snapshot(&arena);
            assert_eq!(
                arena.insert(&[p(0)]),
                Err(TheoryReasonError::ReasonIdSpaceExhausted {
                    index: overflow_index,
                    maximum: MAX_REASON_IDS,
                })
            );
            assert_eq!(snapshot(&arena), before);
        }
    }

    #[test]
    fn insertion_counter_overflow_paths_are_transactional() {
        let mut total = TheoryReasonArena::new(1, TheoryReasonCaps::unlimited());
        total.total_literals = usize::MAX;
        let before_total = snapshot(&total);
        assert_eq!(
            total.insert(&[p(0)]),
            Err(TheoryReasonError::CountOverflow {
                resource: TheoryReasonResource::TotalLiterals,
            })
        );
        assert_eq!(snapshot(&total), before_total);

        let mut duplicate = TheoryReasonArena::new(1, TheoryReasonCaps::unlimited());
        duplicate.insert(&[p(0)]).unwrap();
        duplicate.duplicate_reuses = usize::MAX;
        let before_duplicate = snapshot(&duplicate);
        assert_eq!(
            duplicate.insert(&[p(0)]),
            Err(TheoryReasonError::CountOverflow {
                resource: TheoryReasonResource::DuplicateReuses,
            })
        );
        assert_eq!(snapshot(&duplicate), before_duplicate);

        let mut tautology = TheoryReasonArena::new(1, TheoryReasonCaps::unlimited());
        tautology.tautologies_skipped = usize::MAX;
        let before_tautology = snapshot(&tautology);
        assert_eq!(
            tautology.insert(&[p(0), n(0)]),
            Err(TheoryReasonError::CountOverflow {
                resource: TheoryReasonResource::TautologiesSkipped,
            })
        );
        assert_eq!(snapshot(&tautology), before_tautology);
    }

    #[test]
    fn every_persistent_allocation_failure_is_transactional_and_retryable() {
        for site in [
            AllocationSite::CanonicalClause,
            AllocationSite::ReasonTable,
            AllocationSite::DedupIndex,
        ] {
            let mut arena = TheoryReasonArena::new(3, caps(4, 8, 3));
            assert_eq!(stored(arena.insert(&[p(0)]).unwrap()).index(), 0);
            arena.fail_next_allocation_at(site);
            let before = snapshot(&arena);
            assert!(matches!(
                arena.insert(&[n(1), p(2)]),
                Err(TheoryReasonError::AllocationFailed { context, .. })
                    if context == site.context()
            ));
            assert_eq!(snapshot(&arena), before, "allocation site {site:?}");

            let retry = stored(arena.insert(&[n(1), p(2)]).unwrap());
            assert_eq!(retry.index(), 1, "allocation site {site:?}");
            assert!(arena.invariants_hold());
        }
    }

    #[test]
    fn actual_reservation_failure_is_mapped_explicitly() {
        let mut values = Vec::<u8>::new();
        assert!(matches!(
            try_reserve_exact(&mut values, usize::MAX, "test allocation"),
            Err(TheoryReasonError::AllocationFailed {
                context: "test allocation",
                requested: usize::MAX,
            })
        ));
        assert!(values.is_empty());
    }

    #[test]
    fn equivalent_insertion_streams_are_deterministic() {
        let left_stream = [
            vec![p(2), n(0), p(1), p(2)],
            vec![n(3), p(0)],
            vec![p(1), p(2), n(0)],
            vec![n(2)],
            vec![p(0), n(3), p(0)],
        ];
        let right_stream = [
            vec![p(1), n(0), p(2)],
            vec![p(0), n(3), n(3)],
            vec![n(0), p(2), p(1), n(0)],
            vec![n(2), n(2)],
            vec![n(3), p(0)],
        ];
        let mut left = TheoryReasonArena::new(4, caps(8, 24, 6));
        let mut right = TheoryReasonArena::new(4, caps(8, 24, 6));

        let left_outcomes = left_stream
            .iter()
            .map(|clause| left.insert(clause).unwrap())
            .collect::<Vec<_>>();
        let right_outcomes = right_stream
            .iter()
            .map(|clause| right.insert(clause).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(left_outcomes, right_outcomes);
        assert_eq!(snapshot(&left), snapshot(&right));
        assert!(left.invariants_hold());
        assert!(right.invariants_hold());
    }

    #[test]
    fn provider_serves_native_and_theory_reasons_to_learning() {
        let mut clauses = NativeClauseDb::new(3);
        let clause_id = match clauses.add_clause(&[n(0), p(1)]).unwrap() {
            AddOutcome::Clause(id) => id,
            other => panic!("expected native clause, got {other:?}"),
        };
        let mut arena = TheoryReasonArena::new(3, caps(4, 8, 3));
        let theory_id = stored(arena.insert(&[p(2), n(1)]).unwrap());
        let provider = arena.provider(&clauses);

        assert_eq!(
            ReasonProvider::clause_reason(&provider, clause_id),
            Some(&[n(0), p(1)][..])
        );
        assert_eq!(
            ReasonProvider::theory_reason(&provider, theory_id),
            Some(&[n(1), p(2)][..])
        );
        assert_eq!(
            ReasonProvider::theory_reason(&provider, TheoryReasonId::new(u32::MAX)),
            None
        );

        let mut trail = Trail::new(3);
        trail.new_decision_level().unwrap();
        trail.enqueue(p(0), Reason::Decision).unwrap();
        trail.enqueue(p(1), Reason::Clause(clause_id)).unwrap();
        trail.enqueue(p(2), Reason::Theory(theory_id)).unwrap();
        let result = analyze(
            &trail,
            &provider,
            &[n(0), n(1), n(2)],
            AnalysisCaps::unlimited(),
        )
        .unwrap();
        match result {
            AnalysisOutcome::Learned(learned) => {
                assert_eq!(learned.literals.as_ref(), &[n(0)]);
                assert_eq!(learned.asserting_literal, n(0));
                assert_eq!(learned.backjump_level, 0);
            }
            other => panic!("expected learned clause, got {other:?}"),
        }
    }

    #[test]
    fn exhaustive_small_inputs_match_reference_canonicalization() {
        let alphabet = [n(0), p(0), n(1), p(1), n(2), p(2)];
        for length in 0..=4u32 {
            let sequence_count = alphabet.len().pow(length);
            for encoded in 0..sequence_count {
                let mut code = encoded;
                let mut input = Vec::with_capacity(length as usize);
                for _ in 0..length {
                    input.push(alphabet[code % alphabet.len()]);
                    code /= alphabet.len();
                }

                let mut expected = input.clone();
                expected.sort_unstable();
                expected.dedup();
                let tautology = expected
                    .windows(2)
                    .any(|pair| pair[0].atom() == pair[1].atom());
                let mut arena = TheoryReasonArena::new(3, caps(1, 6, 6));
                match (expected.is_empty(), tautology) {
                    (true, _) => {
                        assert_eq!(arena.insert(&input), Err(TheoryReasonError::EmptyClause));
                    }
                    (false, true) => {
                        assert_eq!(arena.insert(&input).unwrap(), TheoryReasonInsert::Tautology);
                        assert!(arena.is_empty());
                    }
                    (false, false) => {
                        let id = stored(arena.insert(&input).unwrap());
                        assert_eq!(arena.get(id), Some(expected.as_slice()));
                        input.reverse();
                        assert_eq!(
                            arena.insert(&input).unwrap(),
                            TheoryReasonInsert::Existing(id)
                        );
                        assert!(arena.invariants_hold());
                    }
                }
            }
        }
    }
}
