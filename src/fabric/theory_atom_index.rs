#![forbid(unsafe_code)]

//! Flat reverse incidence index for source theory atoms.
//!
//! The index is built only from stable [`TermId`] and [`AtomId`] values. An
//! equality is incident to both endpoint terms, except that a reflexive
//! equality contributes one incidence. A Boolean-term atom is incident to its
//! term. Buckets and the pending queue are always ordered by source `AtomId`,
//! independently of the order in which affected terms are reported.
//!
//! No partition, union-find root, or transient class label is accepted by this
//! module. Marking is transactional: all IDs, caps, arithmetic, temporary
//! storage, telemetry, and final queue capacity are checked before queue
//! entries, pending flags, or counters are changed.

use super::native_clause::AtomId;
use super::partition::TermId;
use super::semantic::{SemanticAtom, SemanticProblem};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

const MAX_TERM_IDS: u64 = u32::MAX as u64 + 1;
const MAX_ATOM_IDS: u64 = u32::MAX as u64 + 1;

/// Hard structural and cumulative runtime limits for [`TheoryAtomIndex`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TheoryAtomIndexCaps {
    pub(crate) max_terms: usize,
    pub(crate) max_atoms: usize,
    pub(crate) max_incidence_entries: usize,
    /// Cumulative number of caller-supplied term IDs, including duplicates.
    pub(crate) max_term_marks: usize,
    /// Cumulative number of flat incidence entries examined by marking.
    pub(crate) max_incidence_visits: usize,
    pub(crate) max_pending_atoms: usize,
}

impl TheoryAtomIndexCaps {
    pub(crate) const fn unlimited() -> Self {
        Self {
            max_terms: usize::MAX,
            max_atoms: usize::MAX,
            max_incidence_entries: usize::MAX,
            max_term_marks: usize::MAX,
            max_incidence_visits: usize::MAX,
            max_pending_atoms: usize::MAX,
        }
    }
}

impl Default for TheoryAtomIndexCaps {
    fn default() -> Self {
        Self {
            max_terms: 1_000_000,
            max_atoms: 1_000_000,
            max_incidence_entries: 2_000_000,
            max_term_marks: 100_000_000,
            max_incidence_visits: 1_000_000_000,
            max_pending_atoms: 1_000_000,
        }
    }
}

/// A resource controlled by [`TheoryAtomIndexCaps`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TheoryAtomIndexResource {
    Terms,
    Atoms,
    IncidenceEntries,
    TermMarks,
    IncidenceVisits,
    PendingAtoms,
}

impl fmt::Display for TheoryAtomIndexResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Terms => "theory-index terms",
            Self::Atoms => "theory-index atoms",
            Self::IncidenceEntries => "theory-index incidence entries",
            Self::TermMarks => "theory-index term marks",
            Self::IncidenceVisits => "theory-index incidence visits",
            Self::PendingAtoms => "pending theory atoms",
        };
        output.write_str(name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TheoryAtomIndexError {
    CapExceeded {
        resource: TheoryAtomIndexResource,
        attempted: usize,
        limit: usize,
    },
    TooManyTerms {
        requested: usize,
        maximum: u64,
    },
    TooManyAtoms {
        requested: usize,
        maximum: u64,
    },
    InvalidSourceTerm {
        atom: AtomId,
        term: TermId,
        term_count: usize,
    },
    AffectedTermOutOfRange {
        term: TermId,
        term_count: usize,
    },
    AtomOutOfRange {
        atom: AtomId,
        atom_count: usize,
    },
    ArithmeticOverflow {
        context: &'static str,
    },
    AllocationFailed {
        context: &'static str,
        requested: usize,
    },
    InvariantViolation(&'static str),
}

impl fmt::Display for TheoryAtomIndexError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapExceeded {
                resource,
                attempted,
                limit,
            } => write!(
                output,
                "{resource} cap exceeded: attempted {attempted}, limit {limit}"
            ),
            Self::TooManyTerms { requested, maximum } => write!(
                output,
                "theory atom index requested {requested} terms, maximum is {maximum}"
            ),
            Self::TooManyAtoms { requested, maximum } => write!(
                output,
                "theory atom index requested {requested} atoms, maximum is {maximum}"
            ),
            Self::InvalidSourceTerm {
                atom,
                term,
                term_count,
            } => write!(
                output,
                "source atom {} refers to term {term} outside 0..{term_count}",
                atom.index()
            ),
            Self::AffectedTermOutOfRange { term, term_count } => {
                write!(output, "affected term {term} is outside 0..{term_count}")
            }
            Self::AtomOutOfRange { atom, atom_count } => write!(
                output,
                "theory atom {} is outside 0..{atom_count}",
                atom.index()
            ),
            Self::ArithmeticOverflow { context } => {
                write!(output, "theory atom index {context} count overflowed usize")
            }
            Self::AllocationFailed { context, requested } => write!(
                output,
                "theory atom index allocation for {context} failed at {requested} elements"
            ),
            Self::InvariantViolation(message) => {
                write!(output, "theory atom index invariant violation: {message}")
            }
        }
    }
}

impl Error for TheoryAtomIndexError {}

/// Exact construction and queue counters. Arithmetic is never saturating.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TheoryAtomIndexTelemetry {
    pub(crate) terms: usize,
    pub(crate) atoms: usize,
    pub(crate) equality_atoms: usize,
    pub(crate) boolean_term_atoms: usize,
    pub(crate) reflexive_equalities: usize,
    pub(crate) incidence_entries: usize,
    pub(crate) mark_calls: usize,
    pub(crate) term_marks: usize,
    pub(crate) unique_terms_marked: usize,
    pub(crate) duplicate_term_marks_suppressed: usize,
    pub(crate) incidence_visits: usize,
    pub(crate) ineligible_incidences_suppressed: usize,
    pub(crate) duplicate_incident_atoms_suppressed: usize,
    pub(crate) already_pending_atoms_suppressed: usize,
    pub(crate) atoms_enqueued: usize,
    pub(crate) drain_calls: usize,
    pub(crate) atoms_drained: usize,
    pub(crate) peak_pending_atoms: usize,
}

/// Per-call account of one successful affected-term transaction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TheoryAtomMark {
    pub(crate) term_marks: usize,
    pub(crate) unique_terms: usize,
    pub(crate) incidence_visits: usize,
    pub(crate) ineligible_incidences_suppressed: usize,
    pub(crate) duplicate_incident_atoms_suppressed: usize,
    pub(crate) already_pending_atoms_suppressed: usize,
    pub(crate) atoms_enqueued: usize,
    pub(crate) pending_atoms: usize,
}

/// A compressed sparse row index from stable terms to stable source atoms.
#[derive(Debug)]
pub(crate) struct TheoryAtomIndex {
    caps: TheoryAtomIndexCaps,
    term_count: usize,
    atom_count: usize,
    term_offsets: Box<[usize]>,
    incidences: Box<[AtomId]>,
    pending_flags: Box<[bool]>,
    pending: Vec<AtomId>,
    telemetry: TheoryAtomIndexTelemetry,
}

impl TheoryAtomIndex {
    pub(crate) fn new(problem: &SemanticProblem) -> Result<Self, TheoryAtomIndexError> {
        Self::with_caps(problem, TheoryAtomIndexCaps::default())
    }

    pub(crate) fn with_caps(
        problem: &SemanticProblem,
        caps: TheoryAtomIndexCaps,
    ) -> Result<Self, TheoryAtomIndexError> {
        Self::build(problem.terms.len(), &problem.atoms, caps)
    }

    fn build(
        term_count: usize,
        atoms: &[SemanticAtom],
        caps: TheoryAtomIndexCaps,
    ) -> Result<Self, TheoryAtomIndexError> {
        check_cap(TheoryAtomIndexResource::Terms, term_count, caps.max_terms)?;
        check_cap(TheoryAtomIndexResource::Atoms, atoms.len(), caps.max_atoms)?;
        if u64::try_from(term_count).map_or(true, |count| count > MAX_TERM_IDS) {
            return Err(TheoryAtomIndexError::TooManyTerms {
                requested: term_count,
                maximum: MAX_TERM_IDS,
            });
        }
        if u64::try_from(atoms.len()).map_or(true, |count| count > MAX_ATOM_IDS) {
            return Err(TheoryAtomIndexError::TooManyAtoms {
                requested: atoms.len(),
                maximum: MAX_ATOM_IDS,
            });
        }

        let offset_count = checked_add(term_count, 1, "term-offset")?;
        let mut term_offsets = try_filled_vec(offset_count, 0usize, "term offsets")?;
        let mut incidence_entries = 0usize;
        let mut equality_atoms = 0usize;
        let mut boolean_term_atoms = 0usize;
        let mut reflexive_equalities = 0usize;

        for (atom_index, atom) in atoms.iter().enumerate() {
            let atom_id = atom_id_from_index(atom_index, atoms.len())?;
            match atom {
                SemanticAtom::Equality(left, right) => {
                    equality_atoms = checked_add(equality_atoms, 1, "equality-atom")?;
                    let left_index = source_term_index(atom_id, *left, term_count)?;
                    let right_index = source_term_index(atom_id, *right, term_count)?;
                    add_incidence(&mut term_offsets, left_index, &mut incidence_entries, caps)?;
                    if left == right {
                        reflexive_equalities =
                            checked_add(reflexive_equalities, 1, "reflexive-equality")?;
                    } else {
                        add_incidence(
                            &mut term_offsets,
                            right_index,
                            &mut incidence_entries,
                            caps,
                        )?;
                    }
                }
                SemanticAtom::BoolTerm(term) => {
                    boolean_term_atoms = checked_add(boolean_term_atoms, 1, "Boolean-term atom")?;
                    let term_index = source_term_index(atom_id, *term, term_count)?;
                    add_incidence(&mut term_offsets, term_index, &mut incidence_entries, caps)?;
                }
            }
        }
        prefix_sum(&mut term_offsets)?;

        let mut cursors = try_copy_vec(&term_offsets[..term_count], "term-incidence cursors")?;
        let mut incidences =
            try_filled_vec(incidence_entries, AtomId::new(0), "flat term incidences")?;
        for (atom_index, atom) in atoms.iter().enumerate() {
            let atom_id = atom_id_from_index(atom_index, atoms.len())?;
            match atom {
                SemanticAtom::Equality(left, right) => {
                    place_incidence(
                        &mut incidences,
                        &term_offsets,
                        &mut cursors,
                        left.index(),
                        atom_id,
                    )?;
                    if left != right {
                        place_incidence(
                            &mut incidences,
                            &term_offsets,
                            &mut cursors,
                            right.index(),
                            atom_id,
                        )?;
                    }
                }
                SemanticAtom::BoolTerm(term) => place_incidence(
                    &mut incidences,
                    &term_offsets,
                    &mut cursors,
                    term.index(),
                    atom_id,
                )?,
            }
        }
        if cursors
            .iter()
            .zip(term_offsets[1..].iter())
            .any(|(cursor, end)| cursor != end)
        {
            return Err(TheoryAtomIndexError::InvariantViolation(
                "flat incidence fill did not consume every bucket",
            ));
        }

        let pending_flags =
            try_filled_vec(atoms.len(), false, "pending-atom flags")?.into_boxed_slice();
        Ok(Self {
            caps,
            term_count,
            atom_count: atoms.len(),
            term_offsets: term_offsets.into_boxed_slice(),
            incidences: incidences.into_boxed_slice(),
            pending_flags,
            pending: Vec::new(),
            telemetry: TheoryAtomIndexTelemetry {
                terms: term_count,
                atoms: atoms.len(),
                equality_atoms,
                boolean_term_atoms,
                reflexive_equalities,
                incidence_entries,
                ..TheoryAtomIndexTelemetry::default()
            },
        })
    }

    pub(crate) const fn caps(&self) -> TheoryAtomIndexCaps {
        self.caps
    }

    pub(crate) const fn term_count(&self) -> usize {
        self.term_count
    }

    pub(crate) const fn atom_count(&self) -> usize {
        self.atom_count
    }

    pub(crate) const fn telemetry(&self) -> TheoryAtomIndexTelemetry {
        self.telemetry
    }

    /// Returns one term's incident source atoms in ascending stable ID order.
    pub(crate) fn incident_atoms(&self, term: TermId) -> Result<&[AtomId], TheoryAtomIndexError> {
        let index = self.checked_term_index(term)?;
        Ok(&self.incidences[self.term_offsets[index]..self.term_offsets[index + 1]])
    }

    pub(crate) fn pending_atoms(&self) -> &[AtomId] {
        &self.pending
    }

    pub(crate) fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub(crate) fn is_pending(&self, atom: AtomId) -> Result<bool, TheoryAtomIndexError> {
        self.pending_flags
            .get(atom.index())
            .copied()
            .ok_or(TheoryAtomIndexError::AtomOutOfRange {
                atom,
                atom_count: self.atom_count,
            })
    }

    pub(crate) fn mark_term(
        &mut self,
        affected: TermId,
    ) -> Result<TheoryAtomMark, TheoryAtomIndexError> {
        self.mark_affected_terms(&[affected])
    }

    /// Marks every stable term. This is the conservative initialization and
    /// rollback path; forward updates should use an impact frontier instead.
    pub(crate) fn mark_all_terms(&mut self) -> Result<TheoryAtomMark, TheoryAtomIndexError> {
        self.mark_from_iter(
            self.term_count,
            (0..self.term_count).map(|index| TermId::new(index as u32)),
            |_| true,
        )
    }

    /// Marks a slice of affected stable terms. Duplicate terms are accepted.
    pub(crate) fn mark_affected_terms(
        &mut self,
        affected: &[TermId],
    ) -> Result<TheoryAtomMark, TheoryAtomIndexError> {
        self.mark_from_iter(affected.len(), affected.iter().copied(), |_| true)
    }

    pub(crate) fn mark_affected_terms_where(
        &mut self,
        affected: &[TermId],
        include: impl FnMut(AtomId) -> bool,
    ) -> Result<TheoryAtomMark, TheoryAtomIndexError> {
        self.mark_from_iter(affected.len(), affected.iter().copied(), include)
    }

    /// Marks an already deduplicated, stably ordered affected-term set.
    pub(crate) fn mark_affected_set(
        &mut self,
        affected: &BTreeSet<TermId>,
    ) -> Result<TheoryAtomMark, TheoryAtomIndexError> {
        self.mark_from_iter(affected.len(), affected.iter().copied(), |_| true)
    }

    fn mark_from_iter<F>(
        &mut self,
        input_count: usize,
        affected: impl Iterator<Item = TermId>,
        mut include: F,
    ) -> Result<TheoryAtomMark, TheoryAtomIndexError>
    where
        F: FnMut(AtomId) -> bool,
    {
        let total_term_marks = checked_add(
            self.telemetry.term_marks,
            input_count,
            "term-mark telemetry",
        )?;
        check_cap(
            TheoryAtomIndexResource::TermMarks,
            total_term_marks,
            self.caps.max_term_marks,
        )?;

        let mut unique_terms = try_vec_with_capacity(input_count, "affected-term transaction")?;
        for term in affected {
            self.checked_term_index(term)?;
            unique_terms.push(term);
        }
        if unique_terms.len() != input_count {
            return Err(TheoryAtomIndexError::InvariantViolation(
                "affected-term iterator length changed during marking",
            ));
        }
        unique_terms.sort_unstable();
        unique_terms.dedup();

        let mut incidence_visits = 0usize;
        for &term in &unique_terms {
            incidence_visits = checked_add(
                incidence_visits,
                self.incident_atoms(term)?.len(),
                "mark incidence visits",
            )?;
        }
        let total_incidence_visits = checked_add(
            self.telemetry.incidence_visits,
            incidence_visits,
            "incidence-visit telemetry",
        )?;
        check_cap(
            TheoryAtomIndexResource::IncidenceVisits,
            total_incidence_visits,
            self.caps.max_incidence_visits,
        )?;

        let candidate_capacity = incidence_visits.min(self.atom_count);
        let mut candidates = try_vec_with_capacity(candidate_capacity, "pending-atom candidates")?;
        let mut ineligible_incidences_suppressed = 0usize;
        for &term in &unique_terms {
            for &atom in self.incident_atoms(term)? {
                if include(atom) {
                    candidates.push(atom);
                } else {
                    ineligible_incidences_suppressed = checked_add(
                        ineligible_incidences_suppressed,
                        1,
                        "ineligible-incidence telemetry",
                    )?;
                }
            }
        }
        let eligible_incidence_visits = incidence_visits
            .checked_sub(ineligible_incidences_suppressed)
            .ok_or(TheoryAtomIndexError::InvariantViolation(
                "ineligible incidences exceed incidence visits",
            ))?;
        candidates.sort_unstable();
        candidates.dedup();
        let unique_candidate_count = candidates.len();
        let duplicate_incident_atoms_suppressed = eligible_incidence_visits
            .checked_sub(unique_candidate_count)
            .ok_or(TheoryAtomIndexError::InvariantViolation(
                "unique atom candidates exceed incidence visits",
            ))?;
        candidates.retain(|atom| !self.pending_flags[atom.index()]);
        let already_pending_atoms_suppressed = unique_candidate_count
            .checked_sub(candidates.len())
            .ok_or(TheoryAtomIndexError::InvariantViolation(
                "new atom candidates exceed unique candidates",
            ))?;
        let pending_count =
            checked_add(self.pending.len(), candidates.len(), "pending-atom queue")?;
        check_cap(
            TheoryAtomIndexResource::PendingAtoms,
            pending_count,
            self.caps.max_pending_atoms,
        )?;

        let duplicate_term_marks_suppressed = input_count.checked_sub(unique_terms.len()).ok_or(
            TheoryAtomIndexError::InvariantViolation("unique affected terms exceed supplied terms"),
        )?;
        let mut telemetry = self.telemetry;
        telemetry.mark_calls = checked_add(telemetry.mark_calls, 1, "mark-call telemetry")?;
        telemetry.term_marks = total_term_marks;
        telemetry.unique_terms_marked = checked_add(
            telemetry.unique_terms_marked,
            unique_terms.len(),
            "unique-term telemetry",
        )?;
        telemetry.duplicate_term_marks_suppressed = checked_add(
            telemetry.duplicate_term_marks_suppressed,
            duplicate_term_marks_suppressed,
            "duplicate-term telemetry",
        )?;
        telemetry.incidence_visits = total_incidence_visits;
        telemetry.ineligible_incidences_suppressed = checked_add(
            telemetry.ineligible_incidences_suppressed,
            ineligible_incidences_suppressed,
            "ineligible-incidence telemetry",
        )?;
        telemetry.duplicate_incident_atoms_suppressed = checked_add(
            telemetry.duplicate_incident_atoms_suppressed,
            duplicate_incident_atoms_suppressed,
            "duplicate-incidence telemetry",
        )?;
        telemetry.already_pending_atoms_suppressed = checked_add(
            telemetry.already_pending_atoms_suppressed,
            already_pending_atoms_suppressed,
            "already-pending telemetry",
        )?;
        telemetry.atoms_enqueued = checked_add(
            telemetry.atoms_enqueued,
            candidates.len(),
            "atom-enqueue telemetry",
        )?;
        telemetry.peak_pending_atoms = telemetry.peak_pending_atoms.max(pending_count);
        let atoms_enqueued = candidates.len();

        try_reserve_additional(&mut self.pending, candidates.len(), "pending atom queue")?;

        self.pending.extend_from_slice(&candidates);
        self.pending.sort_unstable();
        for atom in candidates {
            self.pending_flags[atom.index()] = true;
        }
        self.telemetry = telemetry;
        Ok(TheoryAtomMark {
            term_marks: input_count,
            unique_terms: unique_terms.len(),
            incidence_visits,
            ineligible_incidences_suppressed,
            duplicate_incident_atoms_suppressed,
            already_pending_atoms_suppressed,
            atoms_enqueued,
            pending_atoms: pending_count,
        })
    }

    /// Removes and returns all pending atoms without reallocating their payload.
    pub(crate) fn take_pending(&mut self) -> Result<Vec<AtomId>, TheoryAtomIndexError> {
        self.prepare_pending_removal()?;
        let pending = std::mem::take(&mut self.pending);
        Ok(pending)
    }

    /// Drains all pending atoms in ascending source order while retaining the
    /// queue allocation for later marks.
    pub(crate) fn drain_pending(
        &mut self,
    ) -> Result<std::vec::Drain<'_, AtomId>, TheoryAtomIndexError> {
        self.prepare_pending_removal()?;
        Ok(self.pending.drain(..))
    }

    fn checked_term_index(&self, term: TermId) -> Result<usize, TheoryAtomIndexError> {
        if term.index() >= self.term_count {
            return Err(TheoryAtomIndexError::AffectedTermOutOfRange {
                term,
                term_count: self.term_count,
            });
        }
        Ok(term.index())
    }

    fn prepare_pending_removal(&mut self) -> Result<(), TheoryAtomIndexError> {
        self.validate_pending_state()?;
        let mut telemetry = self.telemetry;
        telemetry.drain_calls = checked_add(telemetry.drain_calls, 1, "drain-call telemetry")?;
        telemetry.atoms_drained = checked_add(
            telemetry.atoms_drained,
            self.pending.len(),
            "drained-atom telemetry",
        )?;

        for atom in &self.pending {
            self.pending_flags[atom.index()] = false;
        }
        self.telemetry = telemetry;
        Ok(())
    }

    fn validate_pending_state(&self) -> Result<(), TheoryAtomIndexError> {
        let mut previous = None;
        for &atom in &self.pending {
            if atom.index() >= self.atom_count {
                return Err(TheoryAtomIndexError::InvariantViolation(
                    "pending queue contains an out-of-range atom",
                ));
            }
            if previous.is_some_and(|prior| prior >= atom) {
                return Err(TheoryAtomIndexError::InvariantViolation(
                    "pending queue is not strictly ordered",
                ));
            }
            if !self.pending_flags[atom.index()] {
                return Err(TheoryAtomIndexError::InvariantViolation(
                    "pending queue atom has no pending flag",
                ));
            }
            previous = Some(atom);
        }
        if self
            .pending_flags
            .iter()
            .enumerate()
            .any(|(index, pending)| {
                *pending
                    && self
                        .pending
                        .binary_search(&AtomId::new(index as u32))
                        .is_err()
            })
        {
            return Err(TheoryAtomIndexError::InvariantViolation(
                "pending flag has no queue atom",
            ));
        }
        Ok(())
    }
}

fn source_term_index(
    atom: AtomId,
    term: TermId,
    term_count: usize,
) -> Result<usize, TheoryAtomIndexError> {
    if term.index() >= term_count {
        return Err(TheoryAtomIndexError::InvalidSourceTerm {
            atom,
            term,
            term_count,
        });
    }
    Ok(term.index())
}

fn atom_id_from_index(index: usize, atom_count: usize) -> Result<AtomId, TheoryAtomIndexError> {
    u32::try_from(index)
        .map(AtomId::new)
        .map_err(|_| TheoryAtomIndexError::TooManyAtoms {
            requested: atom_count,
            maximum: MAX_ATOM_IDS,
        })
}

fn add_incidence(
    shifted_counts: &mut [usize],
    term_index: usize,
    incidence_entries: &mut usize,
    caps: TheoryAtomIndexCaps,
) -> Result<(), TheoryAtomIndexError> {
    let offset_index = checked_add(term_index, 1, "incidence-offset")?;
    shifted_counts[offset_index] =
        checked_add(shifted_counts[offset_index], 1, "term-incidence bucket")?;
    *incidence_entries = checked_add(*incidence_entries, 1, "incidence-entry")?;
    check_cap(
        TheoryAtomIndexResource::IncidenceEntries,
        *incidence_entries,
        caps.max_incidence_entries,
    )
}

fn prefix_sum(offsets: &mut [usize]) -> Result<(), TheoryAtomIndexError> {
    let mut total = 0usize;
    for offset in offsets {
        total = checked_add(total, *offset, "term-offset prefix sum")?;
        *offset = total;
    }
    Ok(())
}

fn place_incidence(
    incidences: &mut [AtomId],
    offsets: &[usize],
    cursors: &mut [usize],
    term_index: usize,
    atom: AtomId,
) -> Result<(), TheoryAtomIndexError> {
    let cursor = cursors
        .get_mut(term_index)
        .ok_or(TheoryAtomIndexError::InvariantViolation(
            "validated source term has no incidence cursor",
        ))?;
    let end =
        offsets
            .get(term_index + 1)
            .copied()
            .ok_or(TheoryAtomIndexError::InvariantViolation(
                "validated source term has no incidence boundary",
            ))?;
    if *cursor >= end {
        return Err(TheoryAtomIndexError::InvariantViolation(
            "flat incidence fill exceeded its term bucket",
        ));
    }
    let destination =
        incidences
            .get_mut(*cursor)
            .ok_or(TheoryAtomIndexError::InvariantViolation(
                "flat incidence destination is out of range",
            ))?;
    *destination = atom;
    *cursor += 1;
    Ok(())
}

fn check_cap(
    resource: TheoryAtomIndexResource,
    attempted: usize,
    limit: usize,
) -> Result<(), TheoryAtomIndexError> {
    if attempted > limit {
        return Err(TheoryAtomIndexError::CapExceeded {
            resource,
            attempted,
            limit,
        });
    }
    Ok(())
}

fn checked_add(
    left: usize,
    right: usize,
    context: &'static str,
) -> Result<usize, TheoryAtomIndexError> {
    left.checked_add(right)
        .ok_or(TheoryAtomIndexError::ArithmeticOverflow { context })
}

fn try_vec_with_capacity<T>(
    capacity: usize,
    context: &'static str,
) -> Result<Vec<T>, TheoryAtomIndexError> {
    let mut values = Vec::new();
    try_reserve_additional(&mut values, capacity, context)?;
    Ok(values)
}

fn try_filled_vec<T: Clone>(
    count: usize,
    value: T,
    context: &'static str,
) -> Result<Vec<T>, TheoryAtomIndexError> {
    let mut values = try_vec_with_capacity(count, context)?;
    values.resize(count, value);
    Ok(values)
}

fn try_copy_vec<T: Copy>(
    values: &[T],
    context: &'static str,
) -> Result<Vec<T>, TheoryAtomIndexError> {
    let mut copy = try_vec_with_capacity(values.len(), context)?;
    copy.extend_from_slice(values);
    Ok(copy)
}

fn try_reserve_additional<T>(
    values: &mut Vec<T>,
    additional: usize,
    context: &'static str,
) -> Result<(), TheoryAtomIndexError> {
    let requested = checked_add(values.len(), additional, "allocation request")?;
    if forced_allocation_failure(context) {
        return Err(TheoryAtomIndexError::AllocationFailed { context, requested });
    }
    values
        .try_reserve_exact(additional)
        .map_err(|_| TheoryAtomIndexError::AllocationFailed { context, requested })
}

#[cfg(not(test))]
fn forced_allocation_failure(_context: &'static str) -> bool {
    false
}

#[cfg(test)]
std::thread_local! {
    static FORCED_ALLOCATION_FAILURE: std::cell::Cell<Option<&'static str>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
fn forced_allocation_failure(context: &'static str) -> bool {
    FORCED_ALLOCATION_FAILURE.with(|slot| {
        if slot.get() == Some(context) {
            slot.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::super::super::parse_problem;
    use super::super::semantic::project;
    use super::*;

    fn term(raw: u32) -> TermId {
        TermId::new(raw)
    }

    fn atom(raw: u32) -> AtomId {
        AtomId::new(raw)
    }

    fn ids(raw: &[u32]) -> Vec<AtomId> {
        raw.iter().copied().map(atom).collect()
    }

    fn build(term_count: usize, atoms: &[SemanticAtom]) -> TheoryAtomIndex {
        TheoryAtomIndex::build(term_count, atoms, TheoryAtomIndexCaps::unlimited()).unwrap()
    }

    fn pending_snapshot(
        index: &TheoryAtomIndex,
    ) -> (Vec<AtomId>, Vec<bool>, TheoryAtomIndexTelemetry) {
        (
            index.pending.clone(),
            index.pending_flags.to_vec(),
            index.telemetry(),
        )
    }

    fn assert_cap(
        error: TheoryAtomIndexError,
        resource: TheoryAtomIndexResource,
        attempted: usize,
        limit: usize,
    ) {
        assert_eq!(
            error,
            TheoryAtomIndexError::CapExceeded {
                resource,
                attempted,
                limit,
            }
        );
    }

    fn oracle_atoms(atoms: &[SemanticAtom], affected: &BTreeSet<TermId>) -> BTreeSet<AtomId> {
        atoms
            .iter()
            .enumerate()
            .filter_map(|(index, source)| {
                let incident = match source {
                    SemanticAtom::Equality(left, right) => {
                        affected.contains(left) || affected.contains(right)
                    }
                    SemanticAtom::BoolTerm(term) => affected.contains(term),
                };
                incident.then_some(atom(index as u32))
            })
            .collect()
    }

    #[test]
    fn projected_problem_constructor_indexes_only_source_atoms() {
        let source = "(set-logic QF_UF)\n\
            (declare-sort U 0)\n\
            (declare-const a U) (declare-const b U)\n\
            (declare-fun p (U) Bool)\n\
            (assert (and (= a b) (p a)))\n\
            (check-sat)";
        let problem = project(&parse_problem(source).unwrap()).unwrap();
        let mut index = TheoryAtomIndex::new(&problem).unwrap();

        let affected = (0..problem.terms.len())
            .rev()
            .map(|raw| term(raw as u32))
            .collect::<Vec<_>>();
        index.mark_affected_terms(&affected).unwrap();

        assert_eq!(index.atom_count(), problem.atoms.len());
        assert_eq!(
            index.pending_atoms(),
            &(0..problem.atoms.len())
                .map(|raw| atom(raw as u32))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn flat_buckets_follow_source_atom_order() {
        let atoms = [
            SemanticAtom::Equality(term(0), term(1)),
            SemanticAtom::BoolTerm(term(0)),
            SemanticAtom::Equality(term(1), term(1)),
            SemanticAtom::Equality(term(1), term(2)),
            SemanticAtom::BoolTerm(term(2)),
        ];
        let index = build(4, &atoms);

        assert_eq!(index.incident_atoms(term(0)).unwrap(), ids(&[0, 1]));
        assert_eq!(index.incident_atoms(term(1)).unwrap(), ids(&[0, 2, 3]));
        assert_eq!(index.incident_atoms(term(2)).unwrap(), ids(&[3, 4]));
        assert!(index.incident_atoms(term(3)).unwrap().is_empty());
        assert_eq!(&*index.term_offsets, &[0, 2, 5, 7, 7]);
        assert_eq!(&*index.incidences, ids(&[0, 1, 0, 2, 3, 3, 4]));
    }

    #[test]
    fn eligibility_filter_excludes_atoms_before_queue_deduplication() {
        let atoms = [
            SemanticAtom::Equality(term(0), term(1)),
            SemanticAtom::BoolTerm(term(0)),
            SemanticAtom::Equality(term(1), term(1)),
            SemanticAtom::Equality(term(1), term(2)),
        ];
        let mut index = build(3, &atoms);

        let mark = index
            .mark_affected_terms_where(&[term(0), term(1)], |atom| atom.index() % 2 == 1)
            .unwrap();

        assert_eq!(index.pending_atoms(), ids(&[1, 3]));
        assert_eq!(mark.incidence_visits, 5);
        assert_eq!(mark.ineligible_incidences_suppressed, 3);
        assert_eq!(mark.duplicate_incident_atoms_suppressed, 0);
        assert_eq!(index.telemetry().ineligible_incidences_suppressed, 3);
    }

    #[test]
    fn reflexive_equality_has_exactly_one_incidence() {
        let atoms = [
            SemanticAtom::Equality(term(0), term(0)),
            SemanticAtom::Equality(term(0), term(1)),
        ];
        let mut index = build(2, &atoms);

        assert_eq!(index.telemetry().reflexive_equalities, 1);
        assert_eq!(index.telemetry().incidence_entries, 3);
        assert_eq!(index.incident_atoms(term(0)).unwrap(), ids(&[0, 1]));
        assert_eq!(index.mark_term(term(0)).unwrap().incidence_visits, 2);
        assert_eq!(index.take_pending().unwrap(), ids(&[0, 1]));
    }

    #[test]
    fn construction_and_marking_are_deterministic() {
        let atoms = [
            SemanticAtom::BoolTerm(term(3)),
            SemanticAtom::Equality(term(0), term(2)),
            SemanticAtom::Equality(term(1), term(3)),
            SemanticAtom::BoolTerm(term(0)),
            SemanticAtom::Equality(term(2), term(3)),
        ];
        let mut first = build(4, &atoms);
        let mut second = build(4, &atoms);

        assert_eq!(first.term_offsets, second.term_offsets);
        assert_eq!(first.incidences, second.incidences);
        first
            .mark_affected_terms(&[term(3), term(0), term(2), term(0)])
            .unwrap();
        second
            .mark_affected_terms(&[term(0), term(2), term(3)])
            .unwrap();
        assert_eq!(first.pending_atoms(), second.pending_atoms());
        assert_eq!(first.pending_atoms(), ids(&[0, 1, 2, 3, 4]));
    }

    #[test]
    fn malformed_semantic_references_are_rejected() {
        let left_error = TheoryAtomIndex::build(
            1,
            &[SemanticAtom::Equality(term(1), term(0))],
            TheoryAtomIndexCaps::unlimited(),
        )
        .unwrap_err();
        assert_eq!(
            left_error,
            TheoryAtomIndexError::InvalidSourceTerm {
                atom: atom(0),
                term: term(1),
                term_count: 1,
            }
        );

        let right_error = TheoryAtomIndex::build(
            1,
            &[SemanticAtom::Equality(term(0), term(7))],
            TheoryAtomIndexCaps::unlimited(),
        )
        .unwrap_err();
        assert_eq!(
            right_error,
            TheoryAtomIndexError::InvalidSourceTerm {
                atom: atom(0),
                term: term(7),
                term_count: 1,
            }
        );

        let bool_error = TheoryAtomIndex::build(
            1,
            &[SemanticAtom::BoolTerm(term(9))],
            TheoryAtomIndexCaps::unlimited(),
        )
        .unwrap_err();
        assert_eq!(
            bool_error,
            TheoryAtomIndexError::InvalidSourceTerm {
                atom: atom(0),
                term: term(9),
                term_count: 1,
            }
        );
    }

    #[test]
    fn every_structural_cap_is_hard() {
        let error = TheoryAtomIndex::build(
            1,
            &[],
            TheoryAtomIndexCaps {
                max_terms: 0,
                ..TheoryAtomIndexCaps::unlimited()
            },
        )
        .unwrap_err();
        assert_cap(error, TheoryAtomIndexResource::Terms, 1, 0);

        let error = TheoryAtomIndex::build(
            1,
            &[SemanticAtom::BoolTerm(term(0))],
            TheoryAtomIndexCaps {
                max_atoms: 0,
                ..TheoryAtomIndexCaps::unlimited()
            },
        )
        .unwrap_err();
        assert_cap(error, TheoryAtomIndexResource::Atoms, 1, 0);

        let error = TheoryAtomIndex::build(
            2,
            &[SemanticAtom::Equality(term(0), term(1))],
            TheoryAtomIndexCaps {
                max_incidence_entries: 1,
                ..TheoryAtomIndexCaps::unlimited()
            },
        )
        .unwrap_err();
        assert_cap(error, TheoryAtomIndexResource::IncidenceEntries, 2, 1);
    }

    #[test]
    fn every_runtime_cap_is_transactional() {
        let atoms = [
            SemanticAtom::Equality(term(0), term(1)),
            SemanticAtom::BoolTerm(term(0)),
        ];

        let mut term_cap = TheoryAtomIndex::build(
            3,
            &atoms,
            TheoryAtomIndexCaps {
                max_term_marks: 2,
                ..TheoryAtomIndexCaps::unlimited()
            },
        )
        .unwrap();
        term_cap.mark_term(term(2)).unwrap();
        let before = pending_snapshot(&term_cap);
        let error = term_cap
            .mark_affected_terms(&[term(0), term(1)])
            .unwrap_err();
        assert_cap(error, TheoryAtomIndexResource::TermMarks, 3, 2);
        assert_eq!(pending_snapshot(&term_cap), before);

        let mut visit_cap = TheoryAtomIndex::build(
            3,
            &atoms,
            TheoryAtomIndexCaps {
                max_incidence_visits: 1,
                ..TheoryAtomIndexCaps::unlimited()
            },
        )
        .unwrap();
        visit_cap.mark_term(term(2)).unwrap();
        let before = pending_snapshot(&visit_cap);
        let error = visit_cap.mark_term(term(0)).unwrap_err();
        assert_cap(error, TheoryAtomIndexResource::IncidenceVisits, 2, 1);
        assert_eq!(pending_snapshot(&visit_cap), before);

        let mut pending_cap = TheoryAtomIndex::build(
            2,
            &atoms,
            TheoryAtomIndexCaps {
                max_pending_atoms: 1,
                ..TheoryAtomIndexCaps::unlimited()
            },
        )
        .unwrap();
        pending_cap.mark_term(term(1)).unwrap();
        let before = pending_snapshot(&pending_cap);
        let error = pending_cap.mark_term(term(0)).unwrap_err();
        assert_cap(error, TheoryAtomIndexResource::PendingAtoms, 2, 1);
        assert_eq!(pending_snapshot(&pending_cap), before);
    }

    #[test]
    fn invalid_affected_term_is_transactional_even_after_valid_prefix() {
        let atoms = [
            SemanticAtom::Equality(term(0), term(1)),
            SemanticAtom::BoolTerm(term(0)),
        ];
        let mut index = build(2, &atoms);
        index.mark_term(term(1)).unwrap();
        let before = pending_snapshot(&index);

        let error = index
            .mark_affected_terms(&[term(0), term(99), term(1)])
            .unwrap_err();
        assert_eq!(
            error,
            TheoryAtomIndexError::AffectedTermOutOfRange {
                term: term(99),
                term_count: 2,
            }
        );
        assert_eq!(pending_snapshot(&index), before);
    }

    #[test]
    fn allocation_failures_leave_queue_flags_and_telemetry_unchanged() {
        let atoms = [
            SemanticAtom::Equality(term(0), term(1)),
            SemanticAtom::BoolTerm(term(0)),
        ];
        let mut index = build(2, &atoms);
        index.mark_term(term(1)).unwrap();
        let before = pending_snapshot(&index);

        FORCED_ALLOCATION_FAILURE.with(|slot| slot.set(Some("pending atom queue")));
        let error = index.mark_term(term(0)).unwrap_err();
        assert!(matches!(
            error,
            TheoryAtomIndexError::AllocationFailed {
                context: "pending atom queue",
                ..
            }
        ));
        assert_eq!(pending_snapshot(&index), before);

        FORCED_ALLOCATION_FAILURE.with(|slot| slot.set(Some("term offsets")));
        let error =
            TheoryAtomIndex::build(2, &atoms, TheoryAtomIndexCaps::unlimited()).unwrap_err();
        assert!(matches!(
            error,
            TheoryAtomIndexError::AllocationFailed {
                context: "term offsets",
                requested: 3,
            }
        ));
    }

    #[test]
    fn duplicate_terms_and_atoms_are_suppressed_exactly() {
        let atoms = [
            SemanticAtom::Equality(term(0), term(1)),
            SemanticAtom::BoolTerm(term(0)),
            SemanticAtom::BoolTerm(term(1)),
        ];
        let mut index = build(2, &atoms);

        let first = index
            .mark_affected_terms(&[term(1), term(0), term(1), term(0)])
            .unwrap();
        assert_eq!(first.term_marks, 4);
        assert_eq!(first.unique_terms, 2);
        assert_eq!(first.incidence_visits, 4);
        assert_eq!(first.duplicate_incident_atoms_suppressed, 1);
        assert_eq!(first.already_pending_atoms_suppressed, 0);
        assert_eq!(first.atoms_enqueued, 3);
        assert_eq!(index.pending_atoms(), ids(&[0, 1, 2]));

        let second = index
            .mark_affected_set(&[term(0), term(1)].into_iter().collect())
            .unwrap();
        assert_eq!(second.atoms_enqueued, 0);
        assert_eq!(second.already_pending_atoms_suppressed, 3);
        assert_eq!(index.pending_atoms(), ids(&[0, 1, 2]));

        let telemetry = index.telemetry();
        assert_eq!(telemetry.mark_calls, 2);
        assert_eq!(telemetry.term_marks, 6);
        assert_eq!(telemetry.unique_terms_marked, 4);
        assert_eq!(telemetry.duplicate_term_marks_suppressed, 2);
        assert_eq!(telemetry.incidence_visits, 8);
        assert_eq!(telemetry.duplicate_incident_atoms_suppressed, 2);
        assert_eq!(telemetry.already_pending_atoms_suppressed, 3);
        assert_eq!(telemetry.atoms_enqueued, 3);
        assert_eq!(telemetry.peak_pending_atoms, 3);
    }

    #[test]
    fn exhaustive_term_subsets_match_btree_oracle() {
        let mut atoms = Vec::new();
        for left in 0..4 {
            for right in left..4 {
                atoms.push(SemanticAtom::Equality(term(left), term(right)));
            }
        }
        for raw in 0..4 {
            atoms.push(SemanticAtom::BoolTerm(term(raw)));
        }
        let mut index = build(4, &atoms);

        for mask in 0u32..(1 << 4) {
            let affected = (0..4)
                .rev()
                .filter(|raw| mask & (1 << raw) != 0)
                .map(term)
                .collect::<Vec<_>>();
            let affected_set = affected.iter().copied().collect::<BTreeSet<_>>();
            let expected = oracle_atoms(&atoms, &affected_set)
                .into_iter()
                .collect::<Vec<_>>();

            index.mark_affected_terms(&affected).unwrap();
            assert_eq!(index.pending_atoms(), expected, "mask {mask:04b}");
            assert_eq!(index.take_pending().unwrap(), expected, "mask {mask:04b}");
        }
    }

    #[test]
    fn deterministic_random_sequences_match_btree_oracle() {
        let mut random = Lcg::new(0x7265_7665_7273_6521);
        for case in 0..256 {
            let term_count = 1 + random.usize(8);
            let atom_count = random.usize(33);
            let mut atoms = Vec::new();
            atoms.reserve(atom_count);
            for _ in 0..atom_count {
                if random.usize(3) == 0 {
                    atoms.push(SemanticAtom::BoolTerm(
                        term(random.usize(term_count) as u32),
                    ));
                } else {
                    atoms.push(SemanticAtom::Equality(
                        term(random.usize(term_count) as u32),
                        term(random.usize(term_count) as u32),
                    ));
                }
            }

            let mut index = build(term_count, &atoms);
            let mut oracle = BTreeSet::new();
            for step in 0..32 {
                let input_count = random.usize(term_count * 2 + 1);
                let affected = (0..input_count)
                    .map(|_| term(random.usize(term_count) as u32))
                    .collect::<Vec<_>>();
                let affected_set = affected.iter().copied().collect::<BTreeSet<_>>();
                oracle.extend(oracle_atoms(&atoms, &affected_set));

                if step % 2 == 0 {
                    index.mark_affected_terms(&affected).unwrap();
                } else {
                    index.mark_affected_set(&affected_set).unwrap();
                }
                assert_eq!(
                    index.pending_atoms(),
                    oracle.iter().copied().collect::<Vec<_>>(),
                    "random case {case}, step {step}"
                );

                if random.usize(5) == 0 {
                    assert_eq!(
                        index.take_pending().unwrap(),
                        oracle.iter().copied().collect::<Vec<_>>(),
                        "random drain case {case}, step {step}"
                    );
                    oracle.clear();
                }
            }
            assert_eq!(
                index.drain_pending().unwrap().collect::<Vec<_>>(),
                oracle.into_iter().collect::<Vec<_>>(),
                "final random drain case {case}"
            );
        }
    }

    #[test]
    fn rollback_style_remarking_after_drains_is_stable() {
        let atoms = [
            SemanticAtom::Equality(term(0), term(1)),
            SemanticAtom::Equality(term(1), term(2)),
            SemanticAtom::Equality(term(2), term(3)),
            SemanticAtom::BoolTerm(term(0)),
            SemanticAtom::BoolTerm(term(3)),
        ];
        let mut index = build(4, &atoms);
        let changed = [term(3), term(0), term(1)];
        let expected = ids(&[0, 1, 2, 3, 4]);

        for round in 0..64 {
            index.mark_affected_terms(&changed).unwrap();
            index.mark_affected_terms(&[term(1), term(0)]).unwrap();
            assert_eq!(index.pending_atoms(), expected, "forward round {round}");
            assert_eq!(
                index.take_pending().unwrap(),
                expected,
                "take round {round}"
            );
            assert!(index.pending_atoms().is_empty());
            assert!(index.pending_flags.iter().all(|pending| !pending));

            index
                .mark_affected_terms(&changed.iter().rev().copied().collect::<Vec<_>>())
                .unwrap();
            assert_eq!(
                index.drain_pending().unwrap().collect::<Vec<_>>(),
                expected,
                "rollback round {round}"
            );
        }

        let telemetry = index.telemetry();
        assert_eq!(telemetry.drain_calls, 128);
        assert_eq!(telemetry.atoms_drained, 128 * expected.len());
        assert_eq!(telemetry.peak_pending_atoms, expected.len());
    }

    #[test]
    fn checked_queries_reject_foreign_stable_ids_without_mutation() {
        let atoms = [SemanticAtom::BoolTerm(term(0))];
        let mut index = build(1, &atoms);
        index.mark_term(term(0)).unwrap();
        let before = pending_snapshot(&index);

        assert_eq!(
            index.incident_atoms(term(1)).unwrap_err(),
            TheoryAtomIndexError::AffectedTermOutOfRange {
                term: term(1),
                term_count: 1,
            }
        );
        assert_eq!(
            index.is_pending(atom(1)).unwrap_err(),
            TheoryAtomIndexError::AtomOutOfRange {
                atom: atom(1),
                atom_count: 1,
            }
        );
        assert_eq!(pending_snapshot(&index), before);
    }

    struct Lcg(u64);

    impl Lcg {
        const fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }

        fn usize(&mut self, upper: usize) -> usize {
            assert!(upper > 0);
            (self.next() % upper as u64) as usize
        }
    }
}
