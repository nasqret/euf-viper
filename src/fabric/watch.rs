#![forbid(unsafe_code)]

//! Deterministic incremental scheduling for [`NativeFormula`].
//!
//! Watch lists and atom-occurrence lists are stored as slices of flat buffers.
//! A truth transition therefore visits only clauses watching the newly false
//! literal and clauses containing the changed atom. Watch-list capacities are
//! fixed from literal occurrences, so moving a watch never allocates.
//!
//! Boolean-trail and theory-partition updates use the same checked queue. A
//! rollback is an ordinary transition to [`Truth::Unknown`]; watch positions
//! are deliberately not rolled back because making a literal non-false cannot
//! invalidate a two-watch position.

use super::bool_cnf::NativeFormula;
use super::native_clause::{AtomId, ClauseId, Lit, Truth};
use std::collections::VecDeque;
use std::error::Error;
use std::fmt;

const MAX_CLAUSE_IDS: u64 = u32::MAX as u64 + 1;
const MAX_ATOM_IDS: u64 = u32::MAX as u64 + 1;

/// Exact resources guarded by [`WatchCaps`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WatchResource {
    Atoms,
    Clauses,
    LiteralOccurrences,
    WatchEntries,
    PendingTruthEvents,
    PendingPropagations,
    TruthEvents,
    WatchEntriesExamined,
    LiteralProbes,
    ClauseUpdates,
    WatchMoves,
    PropagationDequeues,
}

impl fmt::Display for WatchResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Atoms => "watch atoms",
            Self::Clauses => "watch clauses",
            Self::LiteralOccurrences => "watch literal occurrences",
            Self::WatchEntries => "watch entries",
            Self::PendingTruthEvents => "pending truth events",
            Self::PendingPropagations => "pending propagations",
            Self::TruthEvents => "processed truth events",
            Self::WatchEntriesExamined => "examined watch entries",
            Self::LiteralProbes => "watch literal probes",
            Self::ClauseUpdates => "incremental clause updates",
            Self::WatchMoves => "watch moves",
            Self::PropagationDequeues => "propagation dequeues",
        };
        output.write_str(name)
    }
}

/// A hard-cap abstention. `attempted` is the exact total required by the
/// rejected initialization or transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WatchLimit {
    pub(crate) resource: WatchResource,
    pub(crate) attempted: usize,
    pub(crate) limit: usize,
}

impl fmt::Display for WatchLimit {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "{} cap exceeded: attempted {}, limit {}",
            self.resource, self.attempted, self.limit
        )
    }
}

/// Result of an operation which can stop at a configured semantic-work cap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Capped<T> {
    Complete(T),
    Abstained(WatchLimit),
}

/// Structural, queue, and cumulative work limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WatchCaps {
    pub(crate) max_atoms: usize,
    pub(crate) max_clauses: usize,
    pub(crate) max_literal_occurrences: usize,
    pub(crate) max_watch_entries: usize,
    pub(crate) max_pending_truth_events: usize,
    pub(crate) max_pending_propagations: usize,
    pub(crate) max_truth_events: usize,
    pub(crate) max_watch_entries_examined: usize,
    pub(crate) max_literal_probes: usize,
    pub(crate) max_clause_updates: usize,
    pub(crate) max_watch_moves: usize,
    pub(crate) max_propagation_dequeues: usize,
}

impl WatchCaps {
    pub(crate) const fn unlimited() -> Self {
        Self {
            max_atoms: usize::MAX,
            max_clauses: usize::MAX,
            max_literal_occurrences: usize::MAX,
            max_watch_entries: usize::MAX,
            max_pending_truth_events: usize::MAX,
            max_pending_propagations: usize::MAX,
            max_truth_events: usize::MAX,
            max_watch_entries_examined: usize::MAX,
            max_literal_probes: usize::MAX,
            max_clause_updates: usize::MAX,
            max_watch_moves: usize::MAX,
            max_propagation_dequeues: usize::MAX,
        }
    }
}

impl Default for WatchCaps {
    fn default() -> Self {
        Self {
            max_atoms: 1_000_000,
            max_clauses: 4_000_000,
            max_literal_occurrences: 64_000_000,
            max_watch_entries: 8_000_000,
            max_pending_truth_events: 4_000_000,
            max_pending_propagations: 4_000_000,
            max_truth_events: 100_000_000,
            max_watch_entries_examined: 1_000_000_000,
            max_literal_probes: 2_000_000_000,
            max_clause_updates: 1_000_000_000,
            max_watch_moves: 1_000_000_000,
            max_propagation_dequeues: 100_000_000,
        }
    }
}

/// Exact counters. No sampling or saturating arithmetic is used.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct WatchTelemetry {
    pub(crate) atoms: usize,
    pub(crate) clauses: usize,
    pub(crate) literal_occurrences: usize,
    pub(crate) empty_clauses: usize,
    pub(crate) unit_clauses: usize,
    pub(crate) general_clauses: usize,
    pub(crate) watch_entries: usize,
    pub(crate) watch_storage_slots: usize,
    pub(crate) initial_propagations: usize,
    pub(crate) truth_events_enqueued: usize,
    pub(crate) duplicate_truth_events_suppressed: usize,
    pub(crate) truth_events_processed: usize,
    pub(crate) boolean_events_processed: usize,
    pub(crate) theory_events_processed: usize,
    pub(crate) rollback_events_processed: usize,
    pub(crate) watch_entries_examined: usize,
    pub(crate) literal_probes: usize,
    pub(crate) clause_updates: usize,
    pub(crate) watch_moves: usize,
    pub(crate) propagation_events_queued: usize,
    pub(crate) duplicate_propagations_suppressed: usize,
    pub(crate) propagation_dequeues: usize,
    pub(crate) stale_propagations_dropped: usize,
    pub(crate) propagations_delivered: usize,
    pub(crate) peak_pending_truth_events: usize,
    pub(crate) peak_pending_propagations: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WatchError {
    AtomIdSpaceExhausted {
        requested: usize,
        maximum: u64,
    },
    ClauseIdSpaceExhausted {
        requested: usize,
        maximum: u64,
    },
    FormulaAtomCountMismatch {
        atom_count: usize,
        source_atom_count: usize,
        auxiliary_atom_count: usize,
    },
    InitialTruthCountMismatch {
        expected: usize,
        actual: usize,
    },
    AtomOutOfRange {
        atom: AtomId,
        atom_count: usize,
    },
    ClauseOutOfRange {
        clause: ClauseId,
        clause_count: usize,
    },
    NonCanonicalClause {
        clause: ClauseId,
        position: usize,
    },
    DuplicateLiteral {
        clause: ClauseId,
        literal: Lit,
    },
    TautologicalClause {
        clause: ClauseId,
        atom: AtomId,
    },
    TransitionMismatch {
        atom: AtomId,
        expected: Truth,
        supplied: Truth,
    },
    CountOverflow {
        resource: &'static str,
    },
    AllocationFailed {
        resource: &'static str,
        requested: usize,
    },
    InvariantViolation(&'static str),
}

impl fmt::Display for WatchError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtomIdSpaceExhausted { requested, maximum } => write!(
                output,
                "watched formula needs {requested} atoms, but AtomId represents at most {maximum}"
            ),
            Self::ClauseIdSpaceExhausted { requested, maximum } => write!(
                output,
                "watched formula needs {requested} clauses, but ClauseId represents at most {maximum}"
            ),
            Self::FormulaAtomCountMismatch {
                atom_count,
                source_atom_count,
                auxiliary_atom_count,
            } => write!(
                output,
                "watched formula atom count {atom_count} differs from source {source_atom_count} plus auxiliary {auxiliary_atom_count}"
            ),
            Self::InitialTruthCountMismatch { expected, actual } => write!(
                output,
                "watched formula expected {expected} initial atom truths, received {actual}"
            ),
            Self::AtomOutOfRange { atom, atom_count } => write!(
                output,
                "watch atom {} is outside 0..{atom_count}",
                atom.index()
            ),
            Self::ClauseOutOfRange {
                clause,
                clause_count,
            } => write!(output, "watch clause {clause} is outside 0..{clause_count}"),
            Self::NonCanonicalClause { clause, position } => write!(
                output,
                "native clause {clause} is not strictly ordered at literal position {position}"
            ),
            Self::DuplicateLiteral { clause, literal } => write!(
                output,
                "native clause {clause} repeats atom {} with polarity {}",
                literal.atom().index(),
                literal.is_positive()
            ),
            Self::TautologicalClause { clause, atom } => write!(
                output,
                "native clause {clause} contains both polarities of atom {}",
                atom.index()
            ),
            Self::TransitionMismatch {
                atom,
                expected,
                supplied,
            } => write!(
                output,
                "truth transition for atom {} starts at {supplied:?}, queued state is {expected:?}",
                atom.index()
            ),
            Self::CountOverflow { resource } => {
                write!(output, "watch {resource} count overflowed usize")
            }
            Self::AllocationFailed {
                resource,
                requested,
            } => write!(
                output,
                "watch allocation for {resource} failed at {requested} elements"
            ),
            Self::InvariantViolation(message) => {
                write!(output, "watch invariant violation: {message}")
            }
        }
    }
}

impl Error for WatchError {}

/// Origin of an atom truth transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TruthSource {
    BooleanTrail,
    TheoryPartition,
}

/// Positive-atom truth transition supplied by the owning engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TruthTransition {
    pub(crate) source: TruthSource,
    pub(crate) atom: AtomId,
    pub(crate) from: Truth,
    pub(crate) to: Truth,
}

impl TruthTransition {
    pub(crate) const fn boolean(atom: AtomId, from: Truth, to: Truth) -> Self {
        Self {
            source: TruthSource::BooleanTrail,
            atom,
            from,
            to,
        }
    }

    pub(crate) const fn theory(atom: AtomId, from: Truth, to: Truth) -> Self {
        Self {
            source: TruthSource::TheoryPartition,
            atom,
            from,
            to,
        }
    }

    pub(crate) const fn rollback(source: TruthSource, atom: AtomId, from: Truth) -> Self {
        Self {
            source,
            atom,
            from,
            to: Truth::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QueueOutcome {
    Enqueued,
    DuplicateSuppressed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessOutcome {
    Idle,
    Processed {
        transition: TruthTransition,
        propagations_queued: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClauseShape {
    Empty,
    Unit,
    General,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PropagationKind {
    Unit { literal: Lit },
    Conflict,
}

/// A deduplicated propagation observation. `shape` makes empty and structural
/// unit clauses explicit without changing the stable clause/literal payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PropagationEvent {
    pub(crate) clause: ClauseId,
    pub(crate) shape: ClauseShape,
    pub(crate) kind: PropagationKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClauseStatus {
    Open,
    Unit(Lit),
    Conflict,
}

impl ClauseStatus {
    const fn is_propagating(self) -> bool {
        !matches!(self, Self::Open)
    }

    const fn propagation_kind(self) -> Option<PropagationKind> {
        match self {
            Self::Open => None,
            Self::Unit(literal) => Some(PropagationKind::Unit { literal }),
            Self::Conflict => Some(PropagationKind::Conflict),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ClauseState {
    true_count: usize,
    unknown_count: usize,
    unknown_xor: usize,
    status: ClauseStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WatchPositions {
    count: u8,
    positions: [usize; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WatchEntry {
    clause: ClauseId,
    slot: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Occurrence {
    clause: ClauseId,
    position: usize,
    positive: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WatchAction {
    Retain(WatchEntry),
    Move {
        entry: WatchEntry,
        replacement: usize,
        target_list: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StateUpdate {
    clause: ClauseId,
    true_count: usize,
    unknown_count: usize,
    unknown_xor: usize,
    status: ClauseStatus,
}

#[derive(Debug)]
struct TransitionPlan {
    transition: TruthTransition,
    source_list: Option<usize>,
    watch_actions: Vec<WatchAction>,
    state_updates: Vec<StateUpdate>,
    watch_entries_examined: usize,
    literal_probes: usize,
    watch_moves: usize,
    propagation_additions: usize,
    propagation_suppressions: usize,
}

/// Incremental watched-clause state for one immutable native formula.
#[derive(Debug)]
pub(crate) struct WatchScheduler {
    atom_count: usize,
    source_atom_count: usize,
    auxiliary_atom_count: usize,
    clause_offsets: Box<[usize]>,
    literals: Box<[Lit]>,
    clause_shapes: Box<[ClauseShape]>,
    clause_states: Box<[ClauseState]>,
    watches: Box<[WatchPositions]>,
    watch_offsets: Box<[usize]>,
    watch_lengths: Box<[usize]>,
    watch_entries: Box<[WatchEntry]>,
    occurrence_offsets: Box<[usize]>,
    occurrences: Box<[Occurrence]>,
    truths: Box<[Truth]>,
    scheduled_truths: Box<[Truth]>,
    truth_queue: VecDeque<TruthTransition>,
    propagation_queue: VecDeque<ClauseId>,
    propagation_pending: Box<[bool]>,
    caps: WatchCaps,
    telemetry: WatchTelemetry,
}

impl WatchScheduler {
    /// Builds a scheduler with every atom initially unknown.
    pub(crate) fn initialize_unknown(
        formula: &NativeFormula,
        caps: WatchCaps,
    ) -> Result<Capped<Self>, WatchError> {
        validate_formula_shape(formula)?;
        if let Some(limit) = cap_limit(WatchResource::Atoms, formula.atom_count, caps.max_atoms) {
            return Ok(Capped::Abstained(limit));
        }
        let initial = try_filled_vec(formula.atom_count, Truth::Unknown, "initial truth values")?;
        Self::initialize(formula, &initial, caps)
    }

    /// Scans and validates the formula exactly once, then constructs flat
    /// watch and occurrence indices. Initial units/conflicts are queued.
    pub(crate) fn initialize(
        formula: &NativeFormula,
        initial_truths: &[Truth],
        caps: WatchCaps,
    ) -> Result<Capped<Self>, WatchError> {
        validate_formula_counts(formula, initial_truths)?;

        if let Some(limit) = cap_limit(WatchResource::Atoms, formula.atom_count, caps.max_atoms) {
            return Ok(Capped::Abstained(limit));
        }
        if let Some(limit) = cap_limit(
            WatchResource::Clauses,
            formula.clauses.len(),
            caps.max_clauses,
        ) {
            return Ok(Capped::Abstained(limit));
        }

        let literal_list_count =
            formula
                .atom_count
                .checked_mul(2)
                .ok_or(WatchError::CountOverflow {
                    resource: "literal-list",
                })?;
        let mut literal_occurrences = 0usize;
        let mut watch_entry_count = 0usize;
        let mut initial_propagations = 0usize;

        for (clause_index, clause) in formula.clauses.iter().enumerate() {
            let clause_id = clause_id_from_index(clause_index)?;
            validate_clause(clause_id, clause, formula.atom_count)?;
            literal_occurrences =
                checked_add(literal_occurrences, clause.len(), "literal-occurrence")?;
            if let Some(limit) = cap_limit(
                WatchResource::LiteralOccurrences,
                literal_occurrences,
                caps.max_literal_occurrences,
            ) {
                return Ok(Capped::Abstained(limit));
            }
            watch_entry_count = checked_add(watch_entry_count, clause.len().min(2), "watch-entry")?;
            if let Some(limit) = cap_limit(
                WatchResource::WatchEntries,
                watch_entry_count,
                caps.max_watch_entries,
            ) {
                return Ok(Capped::Abstained(limit));
            }

            let (true_count, unknown_count, _) = initial_counts(clause, initial_truths);
            if true_count == 0 && unknown_count <= 1 {
                initial_propagations = checked_add(initial_propagations, 1, "initial-propagation")?;
                if let Some(limit) = cap_limit(
                    WatchResource::PendingPropagations,
                    initial_propagations,
                    caps.max_pending_propagations,
                ) {
                    return Ok(Capped::Abstained(limit));
                }
            }
        }

        let clause_offset_count =
            formula
                .clauses
                .len()
                .checked_add(1)
                .ok_or(WatchError::CountOverflow {
                    resource: "clause-offset",
                })?;
        let literal_offset_count =
            literal_list_count
                .checked_add(1)
                .ok_or(WatchError::CountOverflow {
                    resource: "watch-offset",
                })?;
        let occurrence_offset_count =
            formula
                .atom_count
                .checked_add(1)
                .ok_or(WatchError::CountOverflow {
                    resource: "occurrence-offset",
                })?;

        let mut occurrence_offsets =
            try_filled_vec(occurrence_offset_count, 0usize, "occurrence offsets")?;
        let mut watch_offsets = try_filled_vec(literal_offset_count, 0usize, "watch offsets")?;
        for clause in formula.clauses.iter() {
            for &literal in clause.iter() {
                let atom_offset =
                    literal
                        .atom()
                        .index()
                        .checked_add(1)
                        .ok_or(WatchError::CountOverflow {
                            resource: "occurrence offset",
                        })?;
                occurrence_offsets[atom_offset] =
                    checked_add(occurrence_offsets[atom_offset], 1, "occurrence bucket")?;
                let list = literal_list_index(literal, formula.atom_count)?;
                let list_offset = list.checked_add(1).ok_or(WatchError::CountOverflow {
                    resource: "watch-list offset",
                })?;
                watch_offsets[list_offset] =
                    checked_add(watch_offsets[list_offset], 1, "watch-list bucket")?;
            }
        }
        prefix_sum(&mut occurrence_offsets, "occurrence offsets")?;
        prefix_sum(&mut watch_offsets, "watch offsets")?;

        let mut occurrence_cursors = try_copy_vec(
            &occurrence_offsets[..formula.atom_count],
            "occurrence cursors",
        )?;
        let mut watch_lengths = try_filled_vec(literal_list_count, 0usize, "watch-list lengths")?;
        let placeholder_id = ClauseId::MIN;
        let mut occurrences = try_filled_vec(
            literal_occurrences,
            Occurrence {
                clause: placeholder_id,
                position: 0,
                positive: false,
            },
            "occurrence entries",
        )?;
        let mut watch_entries = try_filled_vec(
            literal_occurrences,
            WatchEntry {
                clause: placeholder_id,
                slot: 0,
            },
            "watch-list storage",
        )?;

        let mut clause_offsets = try_vec_with_capacity(clause_offset_count, "clause offsets")?;
        let mut literals = try_vec_with_capacity(literal_occurrences, "formula literals")?;
        let mut clause_shapes = try_vec_with_capacity(formula.clauses.len(), "clause shapes")?;
        let mut clause_states = try_vec_with_capacity(formula.clauses.len(), "clause states")?;
        let mut watches = try_vec_with_capacity(formula.clauses.len(), "watch positions")?;
        let mut propagation_pending =
            try_filled_vec(formula.clauses.len(), false, "propagation flags")?;
        let mut propagation_queue = VecDeque::new();
        try_reserve_deque(
            &mut propagation_queue,
            initial_propagations,
            "initial propagation queue",
        )?;

        for (clause_index, clause) in formula.clauses.iter().enumerate() {
            let clause_id = clause_id_from_index(clause_index)?;
            clause_offsets.push(literals.len());
            literals.extend_from_slice(clause);

            let shape = clause_shape(clause.len());
            clause_shapes.push(shape);
            let (true_count, unknown_count, unknown_xor) = initial_counts(clause, initial_truths);
            let status = status_from_slice(clause, true_count, unknown_count, unknown_xor)?;
            clause_states.push(ClauseState {
                true_count,
                unknown_count,
                unknown_xor,
                status,
            });

            let selected = select_initial_watches(clause, initial_truths);
            for slot in 0..selected.count as usize {
                let position = selected.positions[slot];
                let list = literal_list_index(clause[position], formula.atom_count)?;
                let destination = checked_add(
                    watch_offsets[list],
                    watch_lengths[list],
                    "watch-list destination",
                )?;
                if destination >= watch_offsets[list + 1] {
                    return Err(WatchError::InvariantViolation(
                        "initial watch exceeds its occurrence capacity",
                    ));
                }
                watch_entries[destination] = WatchEntry {
                    clause: clause_id,
                    slot: slot as u8,
                };
                watch_lengths[list] += 1;
            }
            watches.push(selected);

            for (position, &literal) in clause.iter().enumerate() {
                let atom_index = literal.atom().index();
                let destination = occurrence_cursors[atom_index];
                if destination >= occurrence_offsets[atom_index + 1] {
                    return Err(WatchError::InvariantViolation(
                        "occurrence entry exceeds its atom capacity",
                    ));
                }
                occurrences[destination] = Occurrence {
                    clause: clause_id,
                    position,
                    positive: literal.is_positive(),
                };
                occurrence_cursors[atom_index] += 1;
            }

            if status.is_propagating() {
                propagation_pending[clause_index] = true;
                propagation_queue.push_back(clause_id);
            }
        }
        clause_offsets.push(literals.len());

        let empty_clauses = clause_shapes
            .iter()
            .filter(|&&shape| shape == ClauseShape::Empty)
            .count();
        let unit_clauses = clause_shapes
            .iter()
            .filter(|&&shape| shape == ClauseShape::Unit)
            .count();
        let general_clauses = formula
            .clauses
            .len()
            .checked_sub(empty_clauses)
            .and_then(|value| value.checked_sub(unit_clauses))
            .ok_or(WatchError::InvariantViolation(
                "clause-shape totals exceed clause count",
            ))?;
        let telemetry = WatchTelemetry {
            atoms: formula.atom_count,
            clauses: formula.clauses.len(),
            literal_occurrences,
            empty_clauses,
            unit_clauses,
            general_clauses,
            watch_entries: watch_entry_count,
            watch_storage_slots: literal_occurrences,
            initial_propagations,
            peak_pending_propagations: initial_propagations,
            ..WatchTelemetry::default()
        };

        let truths = try_copy_vec(initial_truths, "current truth values")?;
        let scheduled_truths = try_copy_vec(initial_truths, "scheduled truth values")?;

        Ok(Capped::Complete(Self {
            atom_count: formula.atom_count,
            source_atom_count: formula.source_atom_count,
            auxiliary_atom_count: formula.auxiliary_atom_count,
            clause_offsets: clause_offsets.into_boxed_slice(),
            literals: literals.into_boxed_slice(),
            clause_shapes: clause_shapes.into_boxed_slice(),
            clause_states: clause_states.into_boxed_slice(),
            watches: watches.into_boxed_slice(),
            watch_offsets: watch_offsets.into_boxed_slice(),
            watch_lengths: watch_lengths.into_boxed_slice(),
            watch_entries: watch_entries.into_boxed_slice(),
            occurrence_offsets: occurrence_offsets.into_boxed_slice(),
            occurrences: occurrences.into_boxed_slice(),
            truths: truths.into_boxed_slice(),
            scheduled_truths: scheduled_truths.into_boxed_slice(),
            truth_queue: VecDeque::new(),
            propagation_queue,
            propagation_pending: propagation_pending.into_boxed_slice(),
            caps,
            telemetry,
        }))
    }

    pub(crate) const fn atom_count(&self) -> usize {
        self.atom_count
    }

    pub(crate) const fn source_atom_count(&self) -> usize {
        self.source_atom_count
    }

    pub(crate) const fn auxiliary_atom_count(&self) -> usize {
        self.auxiliary_atom_count
    }

    pub(crate) fn clause_count(&self) -> usize {
        self.clause_states.len()
    }

    pub(crate) const fn telemetry(&self) -> WatchTelemetry {
        self.telemetry
    }

    pub(crate) fn truth(&self, atom: AtomId) -> Result<Truth, WatchError> {
        self.truths
            .get(atom.index())
            .copied()
            .ok_or(WatchError::AtomOutOfRange {
                atom,
                atom_count: self.atom_count,
            })
    }

    pub(crate) fn scheduled_truth(&self, atom: AtomId) -> Result<Truth, WatchError> {
        self.scheduled_truths
            .get(atom.index())
            .copied()
            .ok_or(WatchError::AtomOutOfRange {
                atom,
                atom_count: self.atom_count,
            })
    }

    pub(crate) fn clause(&self, clause: ClauseId) -> Result<&[Lit], WatchError> {
        let index = self.checked_clause_index(clause)?;
        Ok(&self.literals[self.clause_offsets[index]..self.clause_offsets[index + 1]])
    }

    pub(crate) fn clause_shape(&self, clause: ClauseId) -> Result<ClauseShape, WatchError> {
        let index = self.checked_clause_index(clause)?;
        Ok(self.clause_shapes[index])
    }

    pub(crate) fn active_propagation(
        &self,
        clause: ClauseId,
    ) -> Result<Option<PropagationEvent>, WatchError> {
        let index = self.checked_clause_index(clause)?;
        Ok(self.clause_states[index]
            .status
            .propagation_kind()
            .map(|kind| PropagationEvent {
                clause,
                shape: self.clause_shapes[index],
                kind,
            }))
    }

    pub(crate) fn pending_truth_count(&self) -> usize {
        self.truth_queue.len()
    }

    pub(crate) fn pending_propagation_count(&self) -> usize {
        self.propagation_queue.len()
    }

    /// Queues an exact transition. A rejected transition does not alter either
    /// the queue or the scheduled truth tail.
    pub(crate) fn enqueue_transition(
        &mut self,
        transition: TruthTransition,
    ) -> Result<Capped<QueueOutcome>, WatchError> {
        let atom_index = self.checked_atom_index(transition.atom)?;
        let expected = self.scheduled_truths[atom_index];
        if transition.from != expected {
            return Err(WatchError::TransitionMismatch {
                atom: transition.atom,
                expected,
                supplied: transition.from,
            });
        }
        if transition.to == transition.from {
            let next = checked_add(
                self.telemetry.duplicate_truth_events_suppressed,
                1,
                "duplicate truth-event telemetry",
            )?;
            self.telemetry.duplicate_truth_events_suppressed = next;
            return Ok(Capped::Complete(QueueOutcome::DuplicateSuppressed));
        }

        let attempted = checked_add(self.truth_queue.len(), 1, "pending truth events")?;
        if let Some(limit) = cap_limit(
            WatchResource::PendingTruthEvents,
            attempted,
            self.caps.max_pending_truth_events,
        ) {
            return Ok(Capped::Abstained(limit));
        }
        let enqueued = checked_add(
            self.telemetry.truth_events_enqueued,
            1,
            "truth events enqueued",
        )?;
        try_reserve_deque(&mut self.truth_queue, 1, "truth-event queue")?;

        self.truth_queue.push_back(transition);
        self.scheduled_truths[atom_index] = transition.to;
        self.telemetry.truth_events_enqueued = enqueued;
        self.telemetry.peak_pending_truth_events =
            self.telemetry.peak_pending_truth_events.max(attempted);
        Ok(Capped::Complete(QueueOutcome::Enqueued))
    }

    /// Queues a target value using the current tail as `from`. Repeating the
    /// same target is the explicit duplicate-suppression API.
    pub(crate) fn enqueue_truth(
        &mut self,
        source: TruthSource,
        atom: AtomId,
        to: Truth,
    ) -> Result<Capped<QueueOutcome>, WatchError> {
        let from = self.scheduled_truth(atom)?;
        self.enqueue_transition(TruthTransition {
            source,
            atom,
            from,
            to,
        })
    }

    pub(crate) fn enqueue_boolean(
        &mut self,
        atom: AtomId,
        to: Truth,
    ) -> Result<Capped<QueueOutcome>, WatchError> {
        self.enqueue_truth(TruthSource::BooleanTrail, atom, to)
    }

    pub(crate) fn enqueue_theory(
        &mut self,
        atom: AtomId,
        to: Truth,
    ) -> Result<Capped<QueueOutcome>, WatchError> {
        self.enqueue_truth(TruthSource::TheoryPartition, atom, to)
    }

    /// Plans and commits one queued transition. Cap or allocation failure
    /// leaves the transition, truths, clause states, and watch positions intact.
    pub(crate) fn process_next(&mut self) -> Result<Capped<ProcessOutcome>, WatchError> {
        let Some(&transition) = self.truth_queue.front() else {
            return Ok(Capped::Complete(ProcessOutcome::Idle));
        };
        let plan = match self.plan_transition(transition)? {
            Capped::Complete(plan) => plan,
            Capped::Abstained(limit) => return Ok(Capped::Abstained(limit)),
        };

        if plan.propagation_additions != 0 {
            try_reserve_deque(
                &mut self.propagation_queue,
                plan.propagation_additions,
                "propagation queue",
            )?;
        }
        let atom_index = self.checked_atom_index(plan.transition.atom)?;
        if self.truths[atom_index] != plan.transition.from {
            return Err(WatchError::InvariantViolation(
                "truth changed after transition planning",
            ));
        }
        if self.truth_queue.front() != Some(&transition) {
            return Err(WatchError::InvariantViolation(
                "processed truth event differs from queue front",
            ));
        }
        self.truth_queue.pop_front();
        self.commit_transition(&plan);
        Ok(Capped::Complete(ProcessOutcome::Processed {
            transition,
            propagations_queued: plan.propagation_additions,
        }))
    }

    /// Processes all currently queued transitions or returns the first hard
    /// cap. Successfully committed earlier transitions remain committed.
    pub(crate) fn drain_truth_queue(&mut self) -> Result<Capped<usize>, WatchError> {
        let mut processed = 0usize;
        loop {
            match self.process_next()? {
                Capped::Complete(ProcessOutcome::Idle) => {
                    return Ok(Capped::Complete(processed));
                }
                Capped::Complete(ProcessOutcome::Processed { .. }) => {
                    processed = checked_add(processed, 1, "drained truth events")?;
                }
                Capped::Abstained(limit) => return Ok(Capped::Abstained(limit)),
            }
        }
    }

    /// Pops the next still-current propagation. Obsolete queued observations
    /// are discarded without scanning any other clause.
    pub(crate) fn pop_propagation(
        &mut self,
    ) -> Result<Capped<Option<PropagationEvent>>, WatchError> {
        loop {
            let Some(&clause) = self.propagation_queue.front() else {
                return Ok(Capped::Complete(None));
            };
            let clause_index = self.checked_clause_index(clause)?;
            if !self.propagation_pending[clause_index] {
                return Err(WatchError::InvariantViolation(
                    "propagation queue entry is not marked pending",
                ));
            }
            let attempted = checked_add(
                self.telemetry.propagation_dequeues,
                1,
                "propagation dequeues",
            )?;
            if let Some(limit) = cap_limit(
                WatchResource::PropagationDequeues,
                attempted,
                self.caps.max_propagation_dequeues,
            ) {
                return Ok(Capped::Abstained(limit));
            }

            let status = self.clause_states[clause_index].status;
            let event = if let Some(kind) = status.propagation_kind() {
                let delivered = checked_add(
                    self.telemetry.propagations_delivered,
                    1,
                    "propagations delivered",
                )?;
                Some((
                    PropagationEvent {
                        clause,
                        shape: self.clause_shapes[clause_index],
                        kind,
                    },
                    delivered,
                ))
            } else {
                None
            };
            let stale = if event.is_none() {
                checked_add(
                    self.telemetry.stale_propagations_dropped,
                    1,
                    "stale propagations",
                )?
            } else {
                self.telemetry.stale_propagations_dropped
            };

            let removed = self.propagation_queue.pop_front();
            if removed != Some(clause) {
                return Err(WatchError::InvariantViolation(
                    "propagation queue front changed during dequeue",
                ));
            }
            self.propagation_pending[clause_index] = false;
            self.telemetry.propagation_dequeues = attempted;
            if let Some((event, delivered)) = event {
                self.telemetry.propagations_delivered = delivered;
                return Ok(Capped::Complete(Some(event)));
            }
            self.telemetry.stale_propagations_dropped = stale;
        }
    }

    fn plan_transition(
        &self,
        transition: TruthTransition,
    ) -> Result<Capped<TransitionPlan>, WatchError> {
        let atom_index = self.checked_atom_index(transition.atom)?;
        let current = self.truths[atom_index];
        if transition.from != current {
            return Err(WatchError::TransitionMismatch {
                atom: transition.atom,
                expected: current,
                supplied: transition.from,
            });
        }
        if transition.to == transition.from {
            return Err(WatchError::InvariantViolation(
                "no-op truth event entered the processing queue",
            ));
        }

        let false_literal = match transition.to {
            Truth::False => Some(Lit::positive(transition.atom)),
            Truth::True => Some(Lit::negative(transition.atom)),
            Truth::Unknown => None,
        };
        let source_list = false_literal
            .map(|literal| literal_list_index(literal, self.atom_count))
            .transpose()?;
        let source_length = source_list.map_or(0, |list| self.watch_lengths[list]);
        let mut watch_actions = try_vec_with_capacity(source_length, "truth-event watch plan")?;
        let mut literal_probes = 0usize;
        let mut watch_moves = 0usize;

        if let (Some(false_literal), Some(list)) = (false_literal, source_list) {
            let start = self.watch_offsets[list];
            let end = checked_add(start, source_length, "source watch-list end")?;
            if end > self.watch_offsets[list + 1] || end > self.watch_entries.len() {
                return Err(WatchError::InvariantViolation(
                    "watch-list length exceeds contiguous capacity",
                ));
            }
            for &entry in &self.watch_entries[start..end] {
                let clause_index = self.checked_clause_index(entry.clause)?;
                let watch = self.watches[clause_index];
                let slot = entry.slot as usize;
                if slot >= watch.count as usize {
                    return Err(WatchError::InvariantViolation(
                        "watch entry names a missing clause slot",
                    ));
                }
                let false_position = watch.positions[slot];
                let clause = self.clause(entry.clause)?;
                if false_position >= clause.len() || clause[false_position] != false_literal {
                    return Err(WatchError::InvariantViolation(
                        "watch entry and clause position disagree",
                    ));
                }
                if watch.count < 2 {
                    watch_actions.push(WatchAction::Retain(entry));
                    continue;
                }
                let other_slot = 1usize - slot;
                let other_position = watch.positions[other_slot];
                if other_position >= clause.len() || other_position == false_position {
                    return Err(WatchError::InvariantViolation(
                        "two-watch positions are invalid or repeated",
                    ));
                }
                literal_probes = checked_add(literal_probes, 1, "literal probes")?;
                if self.truth_with_override(clause[other_position], transition) == Truth::True {
                    watch_actions.push(WatchAction::Retain(entry));
                    continue;
                }

                let mut replacement = None;
                for (position, &literal) in clause.iter().enumerate() {
                    if position == false_position || position == other_position {
                        continue;
                    }
                    literal_probes = checked_add(literal_probes, 1, "literal probes")?;
                    if self.truth_with_override(literal, transition) != Truth::False {
                        replacement = Some((position, literal));
                        break;
                    }
                }
                if let Some((position, literal)) = replacement {
                    let target_list = literal_list_index(literal, self.atom_count)?;
                    watch_actions.push(WatchAction::Move {
                        entry,
                        replacement: position,
                        target_list,
                    });
                    watch_moves = checked_add(watch_moves, 1, "watch moves")?;
                } else {
                    watch_actions.push(WatchAction::Retain(entry));
                }
            }
        }

        let occurrence_start = self.occurrence_offsets[atom_index];
        let occurrence_end = self.occurrence_offsets[atom_index + 1];
        if occurrence_end < occurrence_start || occurrence_end > self.occurrences.len() {
            return Err(WatchError::InvariantViolation(
                "atom occurrence slice is outside contiguous storage",
            ));
        }
        let occurrence_count = occurrence_end - occurrence_start;
        let mut state_updates =
            try_vec_with_capacity(occurrence_count, "truth-event clause updates")?;
        let mut propagation_additions = 0usize;
        let mut propagation_suppressions = 0usize;
        for &occurrence in &self.occurrences[occurrence_start..occurrence_end] {
            let clause_index = self.checked_clause_index(occurrence.clause)?;
            let clause = self.clause(occurrence.clause)?;
            if occurrence.position >= clause.len()
                || clause[occurrence.position].atom() != transition.atom
                || clause[occurrence.position].is_positive() != occurrence.positive
            {
                return Err(WatchError::InvariantViolation(
                    "atom occurrence and clause literal disagree",
                ));
            }
            let old_literal_truth = atom_truth_to_literal(transition.from, occurrence.positive);
            let new_literal_truth = atom_truth_to_literal(transition.to, occurrence.positive);
            let old_state = self.clause_states[clause_index];
            let (true_count, unknown_count, unknown_xor) = update_counts(
                old_state,
                occurrence.position,
                old_literal_truth,
                new_literal_truth,
            )?;
            let status = status_from_slice(clause, true_count, unknown_count, unknown_xor)?;
            if status != old_state.status && status.is_propagating() {
                if self.propagation_pending[clause_index] {
                    propagation_suppressions =
                        checked_add(propagation_suppressions, 1, "suppressed propagation events")?;
                } else {
                    propagation_additions =
                        checked_add(propagation_additions, 1, "propagation additions")?;
                }
            }
            state_updates.push(StateUpdate {
                clause: occurrence.clause,
                true_count,
                unknown_count,
                unknown_xor,
                status,
            });
        }

        let pending_propagations = checked_add(
            self.propagation_queue.len(),
            propagation_additions,
            "pending propagations",
        )?;
        if let Some(limit) = cap_limit(
            WatchResource::PendingPropagations,
            pending_propagations,
            self.caps.max_pending_propagations,
        ) {
            return Ok(Capped::Abstained(limit));
        }

        let checks = [
            (
                WatchResource::TruthEvents,
                self.telemetry.truth_events_processed,
                1usize,
                self.caps.max_truth_events,
                "truth events processed",
            ),
            (
                WatchResource::WatchEntriesExamined,
                self.telemetry.watch_entries_examined,
                source_length,
                self.caps.max_watch_entries_examined,
                "watch entries examined",
            ),
            (
                WatchResource::LiteralProbes,
                self.telemetry.literal_probes,
                literal_probes,
                self.caps.max_literal_probes,
                "literal probes",
            ),
            (
                WatchResource::ClauseUpdates,
                self.telemetry.clause_updates,
                occurrence_count,
                self.caps.max_clause_updates,
                "clause updates",
            ),
            (
                WatchResource::WatchMoves,
                self.telemetry.watch_moves,
                watch_moves,
                self.caps.max_watch_moves,
                "watch moves",
            ),
        ];
        for (resource, current, delta, cap, name) in checks {
            let attempted = checked_add(current, delta, name)?;
            if let Some(limit) = cap_limit(resource, attempted, cap) {
                return Ok(Capped::Abstained(limit));
            }
        }
        match transition.source {
            TruthSource::BooleanTrail => {
                checked_add(
                    self.telemetry.boolean_events_processed,
                    1,
                    "Boolean truth-event telemetry",
                )?;
            }
            TruthSource::TheoryPartition => {
                checked_add(
                    self.telemetry.theory_events_processed,
                    1,
                    "theory truth-event telemetry",
                )?;
            }
        }
        if transition.to == Truth::Unknown {
            checked_add(
                self.telemetry.rollback_events_processed,
                1,
                "rollback truth-event telemetry",
            )?;
        }

        let mut target_deltas = try_vec_with_capacity(watch_moves, "watch target deltas")?;
        for action in &watch_actions {
            if let WatchAction::Move { target_list, .. } = *action {
                target_deltas.push((target_list, 1usize));
            }
        }
        target_deltas.sort_unstable_by_key(|&(list, _)| list);
        let mut write = 0usize;
        for read in 0..target_deltas.len() {
            if write != 0 && target_deltas[write - 1].0 == target_deltas[read].0 {
                target_deltas[write - 1].1 = checked_add(
                    target_deltas[write - 1].1,
                    target_deltas[read].1,
                    "watch target delta",
                )?;
            } else {
                target_deltas[write] = target_deltas[read];
                write += 1;
            }
        }
        target_deltas.truncate(write);
        for &(list, delta) in &target_deltas {
            if list >= self.watch_lengths.len() {
                return Err(WatchError::InvariantViolation(
                    "watch move targets an invalid literal list",
                ));
            }
            let attempted = checked_add(self.watch_lengths[list], delta, "watch-list length")?;
            let capacity = self.watch_offsets[list + 1] - self.watch_offsets[list];
            if attempted > capacity {
                return Err(WatchError::InvariantViolation(
                    "watch move exceeds literal occurrence capacity",
                ));
            }
        }

        checked_add(
            self.telemetry.propagation_events_queued,
            propagation_additions,
            "propagation events queued",
        )?;
        checked_add(
            self.telemetry.duplicate_propagations_suppressed,
            propagation_suppressions,
            "duplicate propagation telemetry",
        )?;

        Ok(Capped::Complete(TransitionPlan {
            transition,
            source_list,
            watch_actions,
            state_updates,
            watch_entries_examined: source_length,
            literal_probes,
            watch_moves,
            propagation_additions,
            propagation_suppressions,
        }))
    }

    fn commit_transition(&mut self, plan: &TransitionPlan) {
        // All fallible checks and reservations precede this point.
        let atom_index = plan.transition.atom.index();
        self.truths[atom_index] = plan.transition.to;

        for update in &plan.state_updates {
            let clause_index = update.clause.index();
            let old_status = self.clause_states[clause_index].status;
            self.clause_states[clause_index] = ClauseState {
                true_count: update.true_count,
                unknown_count: update.unknown_count,
                unknown_xor: update.unknown_xor,
                status: update.status,
            };
            if update.status != old_status && update.status.is_propagating() {
                if !self.propagation_pending[clause_index] {
                    self.propagation_pending[clause_index] = true;
                    self.propagation_queue.push_back(update.clause);
                }
            }
        }

        if let Some(source_list) = plan.source_list {
            let source_start = self.watch_offsets[source_list];
            let mut retained = 0usize;
            for action in &plan.watch_actions {
                match *action {
                    WatchAction::Retain(entry) => {
                        self.watch_entries[source_start + retained] = entry;
                        retained += 1;
                    }
                    WatchAction::Move {
                        entry,
                        replacement,
                        target_list,
                    } => {
                        let clause_index = entry.clause.index();
                        self.watches[clause_index].positions[entry.slot as usize] = replacement;
                        let destination =
                            self.watch_offsets[target_list] + self.watch_lengths[target_list];
                        self.watch_entries[destination] = entry;
                        self.watch_lengths[target_list] += 1;
                    }
                }
            }
            self.watch_lengths[source_list] = retained;
        }

        self.telemetry.truth_events_processed += 1;
        match plan.transition.source {
            TruthSource::BooleanTrail => self.telemetry.boolean_events_processed += 1,
            TruthSource::TheoryPartition => self.telemetry.theory_events_processed += 1,
        }
        if plan.transition.to == Truth::Unknown {
            self.telemetry.rollback_events_processed += 1;
        }
        self.telemetry.watch_entries_examined += plan.watch_entries_examined;
        self.telemetry.literal_probes += plan.literal_probes;
        self.telemetry.clause_updates += plan.state_updates.len();
        self.telemetry.watch_moves += plan.watch_moves;
        self.telemetry.propagation_events_queued += plan.propagation_additions;
        self.telemetry.duplicate_propagations_suppressed += plan.propagation_suppressions;
        self.telemetry.peak_pending_propagations = self
            .telemetry
            .peak_pending_propagations
            .max(self.propagation_queue.len());
    }

    fn truth_with_override(&self, literal: Lit, transition: TruthTransition) -> Truth {
        let atom_truth = if literal.atom() == transition.atom {
            transition.to
        } else {
            self.truths[literal.atom().index()]
        };
        atom_truth_to_literal(atom_truth, literal.is_positive())
    }

    fn checked_atom_index(&self, atom: AtomId) -> Result<usize, WatchError> {
        let index = atom.index();
        if index >= self.atom_count {
            return Err(WatchError::AtomOutOfRange {
                atom,
                atom_count: self.atom_count,
            });
        }
        Ok(index)
    }

    fn checked_clause_index(&self, clause: ClauseId) -> Result<usize, WatchError> {
        let index = clause.index();
        if index >= self.clause_states.len() {
            return Err(WatchError::ClauseOutOfRange {
                clause,
                clause_count: self.clause_states.len(),
            });
        }
        Ok(index)
    }
}

fn validate_formula_counts(
    formula: &NativeFormula,
    initial_truths: &[Truth],
) -> Result<(), WatchError> {
    validate_formula_shape(formula)?;
    if initial_truths.len() != formula.atom_count {
        return Err(WatchError::InitialTruthCountMismatch {
            expected: formula.atom_count,
            actual: initial_truths.len(),
        });
    }
    Ok(())
}

fn clause_id_from_index(index: usize) -> Result<ClauseId, WatchError> {
    match u32::try_from(index) {
        Ok(raw) => Ok(ClauseId::new(raw)),
        Err(_) => Err(WatchError::ClauseIdSpaceExhausted {
            requested: checked_add(index, 1, "clause identifier request")?,
            maximum: MAX_CLAUSE_IDS,
        }),
    }
}

fn validate_formula_shape(formula: &NativeFormula) -> Result<(), WatchError> {
    let atom_count_u64 =
        u64::try_from(formula.atom_count).map_err(|_| WatchError::AtomIdSpaceExhausted {
            requested: formula.atom_count,
            maximum: MAX_ATOM_IDS,
        })?;
    if atom_count_u64 > MAX_ATOM_IDS {
        return Err(WatchError::AtomIdSpaceExhausted {
            requested: formula.atom_count,
            maximum: MAX_ATOM_IDS,
        });
    }
    let represented = formula
        .source_atom_count
        .checked_add(formula.auxiliary_atom_count)
        .ok_or(WatchError::CountOverflow {
            resource: "formula atom partition",
        })?;
    if represented != formula.atom_count {
        return Err(WatchError::FormulaAtomCountMismatch {
            atom_count: formula.atom_count,
            source_atom_count: formula.source_atom_count,
            auxiliary_atom_count: formula.auxiliary_atom_count,
        });
    }
    let clause_count_u64 =
        u64::try_from(formula.clauses.len()).map_err(|_| WatchError::ClauseIdSpaceExhausted {
            requested: formula.clauses.len(),
            maximum: MAX_CLAUSE_IDS,
        })?;
    if clause_count_u64 > MAX_CLAUSE_IDS {
        return Err(WatchError::ClauseIdSpaceExhausted {
            requested: formula.clauses.len(),
            maximum: MAX_CLAUSE_IDS,
        });
    }
    Ok(())
}

fn validate_clause(
    clause_id: ClauseId,
    clause: &[Lit],
    atom_count: usize,
) -> Result<(), WatchError> {
    for (position, &literal) in clause.iter().enumerate() {
        if literal.atom().index() >= atom_count {
            return Err(WatchError::AtomOutOfRange {
                atom: literal.atom(),
                atom_count,
            });
        }
        if position == 0 {
            continue;
        }
        let previous = clause[position - 1];
        if previous.atom() == literal.atom() {
            if previous == literal {
                return Err(WatchError::DuplicateLiteral {
                    clause: clause_id,
                    literal,
                });
            }
            return Err(WatchError::TautologicalClause {
                clause: clause_id,
                atom: literal.atom(),
            });
        }
        if previous >= literal {
            return Err(WatchError::NonCanonicalClause {
                clause: clause_id,
                position,
            });
        }
    }
    Ok(())
}

fn initial_counts(clause: &[Lit], truths: &[Truth]) -> (usize, usize, usize) {
    let mut true_count = 0usize;
    let mut unknown_count = 0usize;
    let mut unknown_xor = 0usize;
    for (position, &literal) in clause.iter().enumerate() {
        match atom_truth_to_literal(truths[literal.atom().index()], literal.is_positive()) {
            Truth::True => true_count += 1,
            Truth::Unknown => {
                unknown_count += 1;
                unknown_xor ^= position;
            }
            Truth::False => {}
        }
    }
    (true_count, unknown_count, unknown_xor)
}

fn select_initial_watches(clause: &[Lit], truths: &[Truth]) -> WatchPositions {
    let wanted = clause.len().min(2);
    let mut selected = WatchPositions {
        count: 0,
        positions: [0; 2],
    };
    for require_non_false in [true, false] {
        for (position, &literal) in clause.iter().enumerate() {
            if selected.count as usize == wanted {
                return selected;
            }
            let non_false =
                atom_truth_to_literal(truths[literal.atom().index()], literal.is_positive())
                    != Truth::False;
            if non_false == require_non_false {
                selected.positions[selected.count as usize] = position;
                selected.count += 1;
            }
        }
    }
    selected
}

fn clause_shape(length: usize) -> ClauseShape {
    match length {
        0 => ClauseShape::Empty,
        1 => ClauseShape::Unit,
        _ => ClauseShape::General,
    }
}

fn status_from_slice(
    clause: &[Lit],
    true_count: usize,
    unknown_count: usize,
    unknown_xor: usize,
) -> Result<ClauseStatus, WatchError> {
    if true_count > clause.len() || unknown_count > clause.len() - true_count {
        return Err(WatchError::InvariantViolation(
            "clause truth counts exceed clause length",
        ));
    }
    if true_count != 0 || unknown_count >= 2 {
        return Ok(ClauseStatus::Open);
    }
    if unknown_count == 0 {
        return Ok(ClauseStatus::Conflict);
    }
    let literal = clause
        .get(unknown_xor)
        .copied()
        .ok_or(WatchError::InvariantViolation(
            "unit clause unknown XOR is outside clause",
        ))?;
    Ok(ClauseStatus::Unit(literal))
}

fn update_counts(
    state: ClauseState,
    position: usize,
    old_truth: Truth,
    new_truth: Truth,
) -> Result<(usize, usize, usize), WatchError> {
    let mut true_count = state.true_count;
    let mut unknown_count = state.unknown_count;
    let mut unknown_xor = state.unknown_xor;
    match old_truth {
        Truth::True => {
            true_count = true_count
                .checked_sub(1)
                .ok_or(WatchError::InvariantViolation(
                    "clause true count underflow",
                ))?;
        }
        Truth::Unknown => {
            unknown_count = unknown_count
                .checked_sub(1)
                .ok_or(WatchError::InvariantViolation(
                    "clause unknown count underflow",
                ))?;
            unknown_xor ^= position;
        }
        Truth::False => {}
    }
    match new_truth {
        Truth::True => true_count = checked_add(true_count, 1, "clause true count")?,
        Truth::Unknown => {
            unknown_count = checked_add(unknown_count, 1, "clause unknown count")?;
            unknown_xor ^= position;
        }
        Truth::False => {}
    }
    Ok((true_count, unknown_count, unknown_xor))
}

fn atom_truth_to_literal(atom_truth: Truth, positive: bool) -> Truth {
    match (atom_truth, positive) {
        (Truth::Unknown, _) => Truth::Unknown,
        (Truth::True, true) | (Truth::False, false) => Truth::True,
        (Truth::True, false) | (Truth::False, true) => Truth::False,
    }
}

fn literal_list_index(literal: Lit, atom_count: usize) -> Result<usize, WatchError> {
    if literal.atom().index() >= atom_count {
        return Err(WatchError::AtomOutOfRange {
            atom: literal.atom(),
            atom_count,
        });
    }
    literal
        .atom()
        .index()
        .checked_mul(2)
        .and_then(|base| base.checked_add(usize::from(literal.is_positive())))
        .ok_or(WatchError::CountOverflow {
            resource: "literal-list index",
        })
}

fn prefix_sum(values: &mut [usize], resource: &'static str) -> Result<(), WatchError> {
    for index in 1..values.len() {
        values[index] = checked_add(values[index - 1], values[index], resource)?;
    }
    Ok(())
}

fn checked_add(left: usize, right: usize, resource: &'static str) -> Result<usize, WatchError> {
    left.checked_add(right)
        .ok_or(WatchError::CountOverflow { resource })
}

fn cap_limit(resource: WatchResource, attempted: usize, limit: usize) -> Option<WatchLimit> {
    (attempted > limit).then_some(WatchLimit {
        resource,
        attempted,
        limit,
    })
}

fn try_vec_with_capacity<T>(capacity: usize, resource: &'static str) -> Result<Vec<T>, WatchError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| WatchError::AllocationFailed {
            resource,
            requested: capacity,
        })?;
    Ok(values)
}

fn try_filled_vec<T: Clone>(
    length: usize,
    value: T,
    resource: &'static str,
) -> Result<Vec<T>, WatchError> {
    let mut values = try_vec_with_capacity(length, resource)?;
    values.resize(length, value);
    Ok(values)
}

fn try_copy_vec<T: Copy>(values: &[T], resource: &'static str) -> Result<Vec<T>, WatchError> {
    let mut copy = try_vec_with_capacity(values.len(), resource)?;
    copy.extend_from_slice(values);
    Ok(copy)
}

fn try_reserve_deque<T>(
    queue: &mut VecDeque<T>,
    additional: usize,
    resource: &'static str,
) -> Result<(), WatchError> {
    let requested = checked_add(queue.len(), additional, resource)?;
    queue
        .try_reserve(additional)
        .map_err(|_| WatchError::AllocationFailed {
            resource,
            requested,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(index: u32) -> Lit {
        Lit::positive(AtomId::new(index))
    }

    fn n(index: u32) -> Lit {
        Lit::negative(AtomId::new(index))
    }

    fn formula(atom_count: usize, clauses: Vec<Vec<Lit>>) -> NativeFormula {
        NativeFormula {
            atom_count,
            clauses: clauses
                .into_iter()
                .map(|clause| clause.into_boxed_slice())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            source_atom_count: atom_count,
            auxiliary_atom_count: 0,
        }
    }

    fn complete<T>(result: Capped<T>) -> T {
        match result {
            Capped::Complete(value) => value,
            Capped::Abstained(limit) => panic!("unexpected watch abstention: {limit:?}"),
        }
    }

    fn build(formula: &NativeFormula, truths: &[Truth]) -> WatchScheduler {
        complete(WatchScheduler::initialize(formula, truths, WatchCaps::unlimited()).unwrap())
    }

    fn oracle_event(
        clause_id: ClauseId,
        clause: &[Lit],
        truths: &[Truth],
    ) -> Option<PropagationEvent> {
        let mut unknown = None;
        let mut unknown_count = 0usize;
        for &literal in clause {
            match atom_truth_to_literal(truths[literal.atom().index()], literal.is_positive()) {
                Truth::True => return None,
                Truth::Unknown => {
                    unknown = Some(literal);
                    unknown_count += 1;
                }
                Truth::False => {}
            }
        }
        let kind = match (unknown_count, unknown) {
            (0, _) => PropagationKind::Conflict,
            (1, Some(literal)) => PropagationKind::Unit { literal },
            _ => return None,
        };
        Some(PropagationEvent {
            clause: clause_id,
            shape: clause_shape(clause.len()),
            kind,
        })
    }

    fn assert_matches_fresh_oracle(
        scheduler: &WatchScheduler,
        formula: &NativeFormula,
        truths: &[Truth],
    ) {
        assert_eq!(scheduler.truths.as_ref(), truths);
        for (index, clause) in formula.clauses.iter().enumerate() {
            let clause_id = clause_id_from_index(index).unwrap();
            assert_eq!(
                scheduler.active_propagation(clause_id).unwrap(),
                oracle_event(clause_id, clause, truths),
                "clause {index}, truths {truths:?}"
            );
        }
        scheduler.assert_internal_invariants();
    }

    fn apply_transition(
        scheduler: &mut WatchScheduler,
        transition: TruthTransition,
    ) -> Vec<PropagationEvent> {
        assert_eq!(
            complete(scheduler.enqueue_transition(transition).unwrap()),
            QueueOutcome::Enqueued
        );
        assert!(matches!(
            complete(scheduler.process_next().unwrap()),
            ProcessOutcome::Processed { .. }
        ));
        let mut events = Vec::new();
        while let Some(event) = complete(scheduler.pop_propagation().unwrap()) {
            events.push(event);
        }
        events
    }

    impl WatchScheduler {
        fn assert_internal_invariants(&self) {
            let mut slot_seen = vec![[false; 2]; self.clause_count()];
            for list in 0..self.watch_lengths.len() {
                let start = self.watch_offsets[list];
                let end = start + self.watch_lengths[list];
                assert!(end <= self.watch_offsets[list + 1]);
                for &entry in &self.watch_entries[start..end] {
                    let clause_index = entry.clause.index();
                    assert!(clause_index < self.clause_count());
                    let slot = entry.slot as usize;
                    assert!(slot < self.watches[clause_index].count as usize);
                    assert!(!slot_seen[clause_index][slot]);
                    slot_seen[clause_index][slot] = true;
                    let position = self.watches[clause_index].positions[slot];
                    let literal = self.clause(entry.clause).unwrap()[position];
                    assert_eq!(literal_list_index(literal, self.atom_count).unwrap(), list);
                }
            }
            for (clause_index, watch) in self.watches.iter().enumerate() {
                for slot in 0..watch.count as usize {
                    assert!(slot_seen[clause_index][slot]);
                }
                if watch.count == 2 {
                    assert_ne!(watch.positions[0], watch.positions[1]);
                }
            }

            for clause_index in 0..self.clause_count() {
                let clause_id = clause_id_from_index(clause_index).unwrap();
                let clause = self.clause(clause_id).unwrap();
                let (true_count, unknown_count, unknown_xor) = initial_counts(clause, &self.truths);
                let state = self.clause_states[clause_index];
                assert_eq!(state.true_count, true_count);
                assert_eq!(state.unknown_count, unknown_count);
                assert_eq!(state.unknown_xor, unknown_xor);
                assert_eq!(
                    state.status,
                    status_from_slice(clause, true_count, unknown_count, unknown_xor).unwrap()
                );
            }
        }
    }

    #[test]
    fn empty_unit_and_general_clauses_are_explicit() {
        let formula = formula(3, vec![vec![], vec![p(0)], vec![n(0), p(1), p(2)]]);
        let mut scheduler = build(&formula, &[Truth::Unknown; 3]);

        assert_eq!(scheduler.atom_count(), 3);
        assert_eq!(scheduler.source_atom_count(), 3);
        assert_eq!(scheduler.auxiliary_atom_count(), 0);
        assert_eq!(scheduler.clause_count(), 3);
        assert_eq!(
            scheduler.clause_shape(ClauseId::new(0)).unwrap(),
            ClauseShape::Empty
        );
        assert_eq!(
            scheduler.clause_shape(ClauseId::new(1)).unwrap(),
            ClauseShape::Unit
        );
        assert_eq!(
            scheduler.clause_shape(ClauseId::new(2)).unwrap(),
            ClauseShape::General
        );
        assert_eq!(scheduler.telemetry().empty_clauses, 1);
        assert_eq!(scheduler.telemetry().unit_clauses, 1);
        assert_eq!(scheduler.telemetry().general_clauses, 1);
        assert_eq!(scheduler.telemetry().watch_entries, 3);
        assert_eq!(scheduler.telemetry().initial_propagations, 2);

        assert_eq!(
            complete(scheduler.pop_propagation().unwrap()),
            Some(PropagationEvent {
                clause: ClauseId::new(0),
                shape: ClauseShape::Empty,
                kind: PropagationKind::Conflict,
            })
        );
        assert_eq!(
            complete(scheduler.pop_propagation().unwrap()),
            Some(PropagationEvent {
                clause: ClauseId::new(1),
                shape: ClauseShape::Unit,
                kind: PropagationKind::Unit { literal: p(0) },
            })
        );
        assert_eq!(complete(scheduler.pop_propagation().unwrap()), None);
    }

    #[test]
    fn every_small_assignment_and_direct_transition_matches_fresh_full_scan() {
        let formula = formula(
            4,
            vec![
                vec![],
                vec![p(0)],
                vec![n(0), p(1)],
                vec![p(0), n(1), p(2)],
                vec![n(0), n(2), p(3)],
                vec![p(1), n(2), n(3)],
            ],
        );
        let values = [Truth::False, Truth::Unknown, Truth::True];

        for encoded in 0usize..3usize.pow(4) {
            let mut cursor = encoded;
            let mut truths = [Truth::Unknown; 4];
            for truth in &mut truths {
                *truth = values[cursor % 3];
                cursor /= 3;
            }
            let mut scheduler = build(&formula, &truths);
            assert_matches_fresh_oracle(&scheduler, &formula, &truths);
            while complete(scheduler.pop_propagation().unwrap()).is_some() {}

            for atom_index in 0..4usize {
                for &to in &values {
                    if to == truths[atom_index] {
                        continue;
                    }
                    let mut changed = truths;
                    changed[atom_index] = to;
                    let mut branch = build(&formula, &truths);
                    while complete(branch.pop_propagation().unwrap()).is_some() {}
                    let atom = AtomId::new(atom_index as u32);
                    let source = if atom_index % 2 == 0 {
                        TruthSource::TheoryPartition
                    } else {
                        TruthSource::BooleanTrail
                    };
                    let events = apply_transition(
                        &mut branch,
                        TruthTransition {
                            source,
                            atom,
                            from: truths[atom_index],
                            to,
                        },
                    );
                    for event in events {
                        assert_eq!(
                            Some(event),
                            oracle_event(
                                event.clause,
                                branch.clause(event.clause).unwrap(),
                                &changed
                            )
                        );
                    }
                    assert_matches_fresh_oracle(&branch, &formula, &changed);
                }
            }
        }
    }

    #[test]
    fn watch_positions_remain_valid_and_need_no_rollback_log() {
        let formula = formula(3, vec![vec![p(0), p(1), p(2)]]);
        let mut scheduler = build(&formula, &[Truth::Unknown; 3]);
        while complete(scheduler.pop_propagation().unwrap()).is_some() {}

        apply_transition(
            &mut scheduler,
            TruthTransition::boolean(AtomId::new(0), Truth::Unknown, Truth::False),
        );
        let moved = scheduler.watches[0];
        assert!(moved.positions.contains(&2));

        apply_transition(
            &mut scheduler,
            TruthTransition::rollback(TruthSource::BooleanTrail, AtomId::new(0), Truth::False),
        );
        assert_eq!(scheduler.watches[0], moved);
        assert_matches_fresh_oracle(
            &scheduler,
            &formula,
            &[Truth::Unknown, Truth::Unknown, Truth::Unknown],
        );

        apply_transition(
            &mut scheduler,
            TruthTransition::theory(AtomId::new(1), Truth::Unknown, Truth::False),
        );
        assert_matches_fresh_oracle(
            &scheduler,
            &formula,
            &[Truth::Unknown, Truth::False, Truth::Unknown],
        );
    }

    #[test]
    fn boolean_and_theory_queues_suppress_duplicate_updates_and_outputs() {
        let formula = formula(3, vec![vec![p(0), p(1), p(2)]]);
        let mut scheduler = build(&formula, &[Truth::Unknown; 3]);

        assert_eq!(
            complete(
                scheduler
                    .enqueue_theory(AtomId::new(0), Truth::False)
                    .unwrap()
            ),
            QueueOutcome::Enqueued
        );
        assert_eq!(
            complete(
                scheduler
                    .enqueue_theory(AtomId::new(0), Truth::False)
                    .unwrap()
            ),
            QueueOutcome::DuplicateSuppressed
        );
        assert_eq!(scheduler.pending_truth_count(), 1);
        complete(scheduler.drain_truth_queue().unwrap());

        complete(
            scheduler
                .enqueue_boolean(AtomId::new(1), Truth::False)
                .unwrap(),
        );
        complete(scheduler.drain_truth_queue().unwrap());
        assert_eq!(scheduler.pending_propagation_count(), 1);

        complete(
            scheduler
                .enqueue_boolean(AtomId::new(2), Truth::False)
                .unwrap(),
        );
        complete(scheduler.drain_truth_queue().unwrap());
        assert_eq!(scheduler.pending_propagation_count(), 1);
        assert_eq!(scheduler.telemetry().duplicate_truth_events_suppressed, 1);
        assert_eq!(scheduler.telemetry().duplicate_propagations_suppressed, 1);
        assert_eq!(
            complete(scheduler.pop_propagation().unwrap()),
            Some(PropagationEvent {
                clause: ClauseId::new(0),
                shape: ClauseShape::General,
                kind: PropagationKind::Conflict,
            })
        );
    }

    #[test]
    fn randomized_assign_and_backtrack_trace_matches_oracle_after_every_event() {
        let formula = formula(
            6,
            vec![
                vec![p(0)],
                vec![n(0), p(1)],
                vec![p(0), n(1), p(2)],
                vec![n(0), n(2), p(3)],
                vec![p(1), p(3), n(4)],
                vec![n(1), p(2), p(4), n(5)],
                vec![p(0), n(3), p(5)],
                vec![n(2), n(4), n(5)],
            ],
        );

        for seed in 0u64..48 {
            let mut random = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut truths = [Truth::Unknown; 6];
            let mut levels: Vec<Vec<usize>> = vec![Vec::new()];
            let mut scheduler = build(&formula, &truths);
            while complete(scheduler.pop_propagation().unwrap()).is_some() {}

            for step in 0..240usize {
                random = random
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let action = (random >> 32) as usize % 10;
                if action == 0 && levels.len() < 8 {
                    levels.push(Vec::new());
                } else if action <= 2 && levels.len() > 1 {
                    let removed = levels.pop().unwrap();
                    for atom_index in removed.into_iter().rev() {
                        let from = truths[atom_index];
                        truths[atom_index] = Truth::Unknown;
                        let source = if atom_index < 3 {
                            TruthSource::TheoryPartition
                        } else {
                            TruthSource::BooleanTrail
                        };
                        let events = apply_transition(
                            &mut scheduler,
                            TruthTransition::rollback(source, AtomId::new(atom_index as u32), from),
                        );
                        for event in events {
                            assert_eq!(
                                Some(event),
                                oracle_event(
                                    event.clause,
                                    scheduler.clause(event.clause).unwrap(),
                                    &truths,
                                ),
                                "seed {seed}, step {step}"
                            );
                        }
                        assert_matches_fresh_oracle(&scheduler, &formula, &truths);
                    }
                } else {
                    let unknown = (0..truths.len())
                        .filter(|&index| truths[index] == Truth::Unknown)
                        .collect::<Vec<_>>();
                    if unknown.is_empty() {
                        continue;
                    }
                    let atom_index = unknown[(random as usize) % unknown.len()];
                    let to = if random & 1 == 0 {
                        Truth::False
                    } else {
                        Truth::True
                    };
                    truths[atom_index] = to;
                    levels.last_mut().unwrap().push(atom_index);
                    let transition = if atom_index < 3 {
                        TruthTransition::theory(AtomId::new(atom_index as u32), Truth::Unknown, to)
                    } else {
                        TruthTransition::boolean(AtomId::new(atom_index as u32), Truth::Unknown, to)
                    };
                    let events = apply_transition(&mut scheduler, transition);
                    for event in events {
                        assert_eq!(
                            Some(event),
                            oracle_event(
                                event.clause,
                                scheduler.clause(event.clause).unwrap(),
                                &truths,
                            ),
                            "seed {seed}, step {step}"
                        );
                    }
                    assert_matches_fresh_oracle(&scheduler, &formula, &truths);
                }
            }
        }
    }

    #[test]
    fn malformed_formula_and_ids_fail_closed() {
        let out_of_range = formula(2, vec![vec![p(0), p(2)]]);
        assert!(matches!(
            WatchScheduler::initialize_unknown(&out_of_range, WatchCaps::unlimited()),
            Err(WatchError::AtomOutOfRange { .. })
        ));

        let duplicate = formula(2, vec![vec![p(0), p(0)]]);
        assert!(matches!(
            WatchScheduler::initialize_unknown(&duplicate, WatchCaps::unlimited()),
            Err(WatchError::DuplicateLiteral { .. })
        ));

        let tautology = formula(2, vec![vec![n(0), p(0)]]);
        assert!(matches!(
            WatchScheduler::initialize_unknown(&tautology, WatchCaps::unlimited()),
            Err(WatchError::TautologicalClause { .. })
        ));

        let unordered = formula(2, vec![vec![p(1), p(0)]]);
        assert!(matches!(
            WatchScheduler::initialize_unknown(&unordered, WatchCaps::unlimited()),
            Err(WatchError::NonCanonicalClause { .. })
        ));

        let mut mismatched = formula(1, vec![]);
        mismatched.source_atom_count = 0;
        assert!(matches!(
            WatchScheduler::initialize_unknown(&mismatched, WatchCaps::unlimited()),
            Err(WatchError::FormulaAtomCountMismatch { .. })
        ));

        let valid = formula(1, vec![vec![p(0)]]);
        assert!(matches!(
            WatchScheduler::initialize(&valid, &[], WatchCaps::unlimited()),
            Err(WatchError::InitialTruthCountMismatch { .. })
        ));
        let mut scheduler = build(&valid, &[Truth::Unknown]);
        let before = scheduler.telemetry();
        assert!(matches!(
            scheduler.enqueue_boolean(AtomId::new(1), Truth::False),
            Err(WatchError::AtomOutOfRange { .. })
        ));
        assert!(matches!(
            scheduler.clause(ClauseId::new(7)),
            Err(WatchError::ClauseOutOfRange { .. })
        ));
        assert_eq!(scheduler.telemetry(), before);

        complete(
            scheduler
                .enqueue_boolean(AtomId::new(0), Truth::False)
                .unwrap(),
        );
        let queued = scheduler.pending_truth_count();
        assert!(matches!(
            scheduler.enqueue_transition(TruthTransition::theory(
                AtomId::new(0),
                Truth::Unknown,
                Truth::True,
            )),
            Err(WatchError::TransitionMismatch {
                atom,
                expected: Truth::False,
                supplied: Truth::Unknown,
            }) if atom == AtomId::new(0)
        ));
        assert_eq!(scheduler.pending_truth_count(), queued);
        assert_eq!(
            scheduler.scheduled_truth(AtomId::new(0)).unwrap(),
            Truth::False
        );
    }

    #[test]
    fn structural_and_initial_queue_caps_report_exact_attempts() {
        let formula = formula(2, vec![vec![], vec![p(0)], vec![p(0), p(1)]]);
        let cases = [
            (
                WatchCaps {
                    max_atoms: 1,
                    ..WatchCaps::unlimited()
                },
                WatchLimit {
                    resource: WatchResource::Atoms,
                    attempted: 2,
                    limit: 1,
                },
            ),
            (
                WatchCaps {
                    max_clauses: 2,
                    ..WatchCaps::unlimited()
                },
                WatchLimit {
                    resource: WatchResource::Clauses,
                    attempted: 3,
                    limit: 2,
                },
            ),
            (
                WatchCaps {
                    max_literal_occurrences: 2,
                    ..WatchCaps::unlimited()
                },
                WatchLimit {
                    resource: WatchResource::LiteralOccurrences,
                    attempted: 3,
                    limit: 2,
                },
            ),
            (
                WatchCaps {
                    max_watch_entries: 2,
                    ..WatchCaps::unlimited()
                },
                WatchLimit {
                    resource: WatchResource::WatchEntries,
                    attempted: 3,
                    limit: 2,
                },
            ),
            (
                WatchCaps {
                    max_pending_propagations: 1,
                    ..WatchCaps::unlimited()
                },
                WatchLimit {
                    resource: WatchResource::PendingPropagations,
                    attempted: 2,
                    limit: 1,
                },
            ),
        ];
        for (caps, expected) in cases {
            assert!(matches!(
                WatchScheduler::initialize_unknown(&formula, caps).unwrap(),
                Capped::Abstained(limit) if limit == expected
            ));
        }
    }

    #[test]
    fn runtime_caps_abstain_before_logical_mutation() {
        let formula = formula(
            3,
            vec![vec![p(0), p(1)], vec![p(0), p(2)], vec![p(0), p(1), p(2)]],
        );
        let caps = WatchCaps {
            max_pending_truth_events: 1,
            max_watch_entries_examined: 1,
            ..WatchCaps::unlimited()
        };
        let mut scheduler =
            complete(WatchScheduler::initialize(&formula, &[Truth::Unknown; 3], caps).unwrap());
        assert_eq!(
            complete(
                scheduler
                    .enqueue_boolean(AtomId::new(0), Truth::False)
                    .unwrap()
            ),
            QueueOutcome::Enqueued
        );
        assert!(matches!(
            scheduler
                .enqueue_theory(AtomId::new(1), Truth::False)
                .unwrap(),
            Capped::Abstained(WatchLimit {
                resource: WatchResource::PendingTruthEvents,
                attempted: 2,
                limit: 1,
            })
        ));
        assert_eq!(
            scheduler.scheduled_truth(AtomId::new(1)).unwrap(),
            Truth::Unknown
        );

        let before_truths = scheduler.truths.clone();
        let before_watches = scheduler.watches.clone();
        let before_states = scheduler.clause_states.clone();
        let before_telemetry = scheduler.telemetry();
        assert!(matches!(
            scheduler.process_next().unwrap(),
            Capped::Abstained(WatchLimit {
                resource: WatchResource::WatchEntriesExamined,
                attempted: 3,
                limit: 1,
            })
        ));
        assert_eq!(scheduler.truths, before_truths);
        assert_eq!(scheduler.watches, before_watches);
        assert_eq!(scheduler.clause_states, before_states);
        assert_eq!(scheduler.telemetry(), before_telemetry);
        assert_eq!(scheduler.pending_truth_count(), 1);
    }

    #[test]
    fn every_cumulative_runtime_cap_reports_the_exact_next_total() {
        let empty_formula = formula(1, vec![]);
        let mut event_limited = complete(
            WatchScheduler::initialize(
                &empty_formula,
                &[Truth::Unknown],
                WatchCaps {
                    max_truth_events: 0,
                    ..WatchCaps::unlimited()
                },
            )
            .unwrap(),
        );
        complete(
            event_limited
                .enqueue_boolean(AtomId::new(0), Truth::False)
                .unwrap(),
        );
        assert!(matches!(
            event_limited.process_next().unwrap(),
            Capped::Abstained(WatchLimit {
                resource: WatchResource::TruthEvents,
                attempted: 1,
                limit: 0,
            })
        ));
        assert_eq!(event_limited.truth(AtomId::new(0)).unwrap(), Truth::Unknown);

        let binary = formula(2, vec![vec![p(0), p(1)]]);
        let mut update_limited = complete(
            WatchScheduler::initialize(
                &binary,
                &[Truth::Unknown; 2],
                WatchCaps {
                    max_clause_updates: 0,
                    ..WatchCaps::unlimited()
                },
            )
            .unwrap(),
        );
        complete(
            update_limited
                .enqueue_boolean(AtomId::new(0), Truth::False)
                .unwrap(),
        );
        assert!(matches!(
            update_limited.process_next().unwrap(),
            Capped::Abstained(WatchLimit {
                resource: WatchResource::ClauseUpdates,
                attempted: 1,
                limit: 0,
            })
        ));
        assert_eq!(
            update_limited.truth(AtomId::new(0)).unwrap(),
            Truth::Unknown
        );

        let ternary = formula(3, vec![vec![p(0), p(1), p(2)]]);
        let mut move_limited = complete(
            WatchScheduler::initialize(
                &ternary,
                &[Truth::Unknown; 3],
                WatchCaps {
                    max_watch_moves: 0,
                    ..WatchCaps::unlimited()
                },
            )
            .unwrap(),
        );
        complete(
            move_limited
                .enqueue_boolean(AtomId::new(0), Truth::False)
                .unwrap(),
        );
        let before = move_limited.watches.clone();
        assert!(matches!(
            move_limited.process_next().unwrap(),
            Capped::Abstained(WatchLimit {
                resource: WatchResource::WatchMoves,
                attempted: 1,
                limit: 0,
            })
        ));
        assert_eq!(move_limited.watches, before);
        assert_eq!(move_limited.truth(AtomId::new(0)).unwrap(), Truth::Unknown);
    }

    #[test]
    fn transition_work_uses_only_contiguous_indices_for_the_changed_atom() {
        let indexed_formula = formula(
            6,
            vec![
                vec![p(0), p(1), p(2)],
                vec![p(1), p(3)],
                vec![n(2), p(4)],
                vec![n(3), p(5)],
                vec![n(4), n(5)],
            ],
        );
        let mut scheduler = build(&indexed_formula, &[Truth::Unknown; 6]);
        while complete(scheduler.pop_propagation().unwrap()).is_some() {}
        apply_transition(
            &mut scheduler,
            TruthTransition::theory(AtomId::new(0), Truth::Unknown, Truth::False),
        );

        assert_eq!(scheduler.telemetry().clause_updates, 1);
        assert_eq!(scheduler.telemetry().watch_entries_examined, 1);
        assert_eq!(scheduler.telemetry().watch_moves, 1);
        assert_matches_fresh_oracle(
            &scheduler,
            &indexed_formula,
            &[
                Truth::False,
                Truth::Unknown,
                Truth::Unknown,
                Truth::Unknown,
                Truth::Unknown,
                Truth::Unknown,
            ],
        );
    }

    #[test]
    fn corrupted_watch_clause_id_is_rejected_before_transition_commit() {
        let formula = formula(2, vec![vec![p(0), p(1)]]);
        let mut scheduler = build(&formula, &[Truth::Unknown; 2]);
        let list = literal_list_index(p(0), scheduler.atom_count).unwrap();
        let offset = scheduler.watch_offsets[list];
        scheduler.watch_entries[offset].clause = ClauseId::MAX;
        complete(
            scheduler
                .enqueue_boolean(AtomId::new(0), Truth::False)
                .unwrap(),
        );
        let before_states = scheduler.clause_states.clone();
        let before_telemetry = scheduler.telemetry();

        assert!(matches!(
            scheduler.process_next(),
            Err(WatchError::ClauseOutOfRange {
                clause: ClauseId::MAX,
                clause_count: 1,
            })
        ));
        assert_eq!(scheduler.truth(AtomId::new(0)).unwrap(), Truth::Unknown);
        assert_eq!(scheduler.clause_states, before_states);
        assert_eq!(scheduler.telemetry(), before_telemetry);
        assert_eq!(scheduler.pending_truth_count(), 1);
    }

    #[test]
    fn pending_output_and_work_caps_are_transactional() {
        let capped_formula = formula(3, vec![vec![p(0), p(1)], vec![p(0), p(2)]]);
        let caps = WatchCaps {
            max_pending_propagations: 1,
            ..WatchCaps::unlimited()
        };
        let mut scheduler = complete(
            WatchScheduler::initialize(&capped_formula, &[Truth::Unknown; 3], caps).unwrap(),
        );
        complete(
            scheduler
                .enqueue_boolean(AtomId::new(0), Truth::False)
                .unwrap(),
        );
        assert!(matches!(
            scheduler.process_next().unwrap(),
            Capped::Abstained(WatchLimit {
                resource: WatchResource::PendingPropagations,
                attempted: 2,
                limit: 1,
            })
        ));
        assert_eq!(scheduler.truth(AtomId::new(0)).unwrap(), Truth::Unknown);
        assert_eq!(scheduler.pending_propagation_count(), 0);
        assert_eq!(scheduler.telemetry().truth_events_processed, 0);

        let probe_formula = formula(3, vec![vec![p(0), p(1), p(2)]]);
        let probe_caps = WatchCaps {
            max_literal_probes: 1,
            ..WatchCaps::unlimited()
        };
        let mut probe_scheduler = complete(
            WatchScheduler::initialize(&probe_formula, &[Truth::Unknown; 3], probe_caps).unwrap(),
        );
        complete(
            probe_scheduler
                .enqueue_boolean(AtomId::new(0), Truth::False)
                .unwrap(),
        );
        let initial_watches = probe_scheduler.watches.clone();
        assert!(matches!(
            probe_scheduler.process_next().unwrap(),
            Capped::Abstained(WatchLimit {
                resource: WatchResource::LiteralProbes,
                attempted: 2,
                limit: 1,
            })
        ));
        assert_eq!(probe_scheduler.watches, initial_watches);
        assert_eq!(
            probe_scheduler.truth(AtomId::new(0)).unwrap(),
            Truth::Unknown
        );
    }

    #[test]
    fn propagation_dequeue_cap_preserves_queue_front() {
        let formula = formula(1, vec![vec![p(0)]]);
        let caps = WatchCaps {
            max_propagation_dequeues: 0,
            ..WatchCaps::unlimited()
        };
        let mut scheduler =
            complete(WatchScheduler::initialize(&formula, &[Truth::Unknown], caps).unwrap());
        assert!(matches!(
            scheduler.pop_propagation().unwrap(),
            Capped::Abstained(WatchLimit {
                resource: WatchResource::PropagationDequeues,
                attempted: 1,
                limit: 0,
            })
        ));
        assert_eq!(scheduler.pending_propagation_count(), 1);
        assert_eq!(scheduler.telemetry().propagation_dequeues, 0);
    }

    #[test]
    fn impossible_reservation_is_reported_as_allocation_failure() {
        let error = try_vec_with_capacity::<u8>(usize::MAX, "fault injection").unwrap_err();
        assert_eq!(
            error,
            WatchError::AllocationFailed {
                resource: "fault injection",
                requested: usize::MAX,
            }
        );
    }

    #[test]
    fn stale_pending_event_is_dropped_after_truth_improves() {
        let formula = formula(2, vec![vec![p(0), p(1)]]);
        let mut scheduler = build(&formula, &[Truth::Unknown; 2]);
        complete(
            scheduler
                .enqueue_boolean(AtomId::new(0), Truth::False)
                .unwrap(),
        );
        complete(scheduler.drain_truth_queue().unwrap());
        assert_eq!(scheduler.pending_propagation_count(), 1);
        complete(
            scheduler
                .enqueue_theory(AtomId::new(1), Truth::True)
                .unwrap(),
        );
        complete(scheduler.drain_truth_queue().unwrap());
        assert_eq!(complete(scheduler.pop_propagation().unwrap()), None);
        assert_eq!(scheduler.telemetry().stale_propagations_dropped, 1);
    }

    #[test]
    fn stable_clause_and_literal_semantics_are_formula_ordered() {
        let formula = formula(2, vec![vec![n(0), p(1)], vec![p(0)]]);
        let scheduler = build(&formula, &[Truth::Unknown; 2]);
        assert_eq!(ClauseId::MIN.raw(), 0);
        assert_eq!(ClauseId::MAX.raw(), u32::MAX);
        assert_eq!(ClauseId::new(1).index(), 1);
        assert_eq!(scheduler.clause(ClauseId::new(0)).unwrap(), &[n(0), p(1)]);
        assert_eq!(scheduler.clause(ClauseId::new(1)).unwrap(), &[p(0)]);
        assert_eq!(p(1).negate(), n(1));
    }
}
