#![deny(unsafe_code)]

//! Correctness-first first-UIP conflict analysis over stable native literals.
//!
//! This module deliberately knows nothing about congruence-class labels or
//! union-find roots. Theory explanations cross the boundary as ordinary,
//! canonical clauses over stable [`AtomId`] and [`Lit`] identifiers. The
//! analyzer revalidates that contract before every resolution step.

use super::native_clause::{AtomId, ClauseId, Lit};
use super::trail::{Reason, TheoryReasonId, Trail};
use std::cmp::Ordering;
use std::error::Error;
use std::fmt;

/// Supplies immutable reason clauses for assignments recorded on a [`Trail`].
///
/// Implementations must return clauses sorted by [`Lit`], without duplicates
/// or complementary literal pairs. A reason clause must contain the propagated
/// assignment literal; all of its other literals are antecedents. The analyzer
/// treats this as an untrusted boundary and checks the complete contract again.
pub(crate) trait ReasonProvider {
    fn clause_reason(&self, reason: ClauseId) -> Option<&[Lit]>;

    fn theory_reason(&self, reason: TheoryReasonId) -> Option<&[Lit]>;

    fn canonical_reason(&self, reason: Reason) -> Option<&[Lit]> {
        match reason {
            Reason::Clause(reason) => self.clause_reason(reason),
            Reason::Theory(reason) => self.theory_reason(reason),
            Reason::Root | Reason::Decision => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AnalysisCaps {
    pub(crate) max_trail_literals: usize,
    pub(crate) max_clause_literals: usize,
    pub(crate) max_reason_literals: usize,
    pub(crate) max_resolutions: usize,
    pub(crate) max_provider_queries: usize,
    pub(crate) max_literal_visits: usize,
}

impl AnalysisCaps {
    pub(crate) const fn new(
        max_trail_literals: usize,
        max_clause_literals: usize,
        max_reason_literals: usize,
        max_resolutions: usize,
        max_provider_queries: usize,
        max_literal_visits: usize,
    ) -> Self {
        Self {
            max_trail_literals,
            max_clause_literals,
            max_reason_literals,
            max_resolutions,
            max_provider_queries,
            max_literal_visits,
        }
    }

    pub(crate) const fn unlimited() -> Self {
        Self::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
        )
    }
}

impl Default for AnalysisCaps {
    fn default() -> Self {
        Self::new(
            1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000, 50_000_000,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AnalysisResource {
    TrailLiterals,
    ClauseLiterals,
    ReasonLiterals,
    Resolutions,
    ProviderQueries,
    LiteralVisits,
}

impl fmt::Display for AnalysisResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::TrailLiterals => "trail literals",
            Self::ClauseLiterals => "clause literals",
            Self::ReasonLiterals => "reason literals",
            Self::Resolutions => "resolution steps",
            Self::ProviderQueries => "reason-provider queries",
            Self::LiteralVisits => "literal visits",
        };
        write!(output, "{name}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AnalysisAbstention {
    CapExceeded {
        resource: AnalysisResource,
        cap: usize,
        requested: usize,
    },
    CounterOverflow {
        resource: AnalysisResource,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AnalysisStats {
    pub(crate) resolution_steps: usize,
    pub(crate) provider_queries: usize,
    pub(crate) literal_visits: usize,
    pub(crate) peak_clause_literals: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResolutionStep {
    pub(crate) pivot: AtomId,
    pub(crate) conflict_literal: Lit,
    pub(crate) reason: Reason,
    pub(crate) trail_index: usize,
    pub(crate) derived_literals: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LearnedClause {
    pub(crate) literals: Box<[Lit]>,
    /// Literal that becomes unit after backtracking. It is false on the input
    /// trail; its negation is the first UIP assignment.
    pub(crate) asserting_literal: Lit,
    pub(crate) backjump_level: u32,
    pub(crate) conflict_level: u32,
    pub(crate) resolution_trace: Box<[ResolutionStep]>,
    pub(crate) stats: AnalysisStats,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RootConflict {
    pub(crate) literals: Box<[Lit]>,
    pub(crate) stats: AnalysisStats,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AnalysisOutcome {
    Learned(LearnedClause),
    RootConflict(RootConflict),
    Abstained {
        reason: AnalysisAbstention,
        stats: AnalysisStats,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClauseRole {
    Conflict,
    Reason(Reason),
    Resolvent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CanonicalityProblem {
    Duplicate,
    ComplementaryPair,
    OutOfOrder,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AnalysisError {
    AtomOutOfRange {
        role: ClauseRole,
        atom: AtomId,
        atom_count: usize,
    },
    NonCanonicalClause {
        role: ClauseRole,
        index: usize,
        problem: CanonicalityProblem,
    },
    ConflictLiteralUnassigned {
        literal: Lit,
    },
    ConflictLiteralTrue {
        literal: Lit,
    },
    NoCurrentLevelLiteral {
        conflict_level: u32,
    },
    UnresolvablePivot {
        pivot: AtomId,
        reason: Reason,
    },
    MissingReason {
        pivot: AtomId,
        reason: Reason,
    },
    ReasonMissingPropagation {
        pivot: AtomId,
        assignment: Lit,
        reason: Reason,
    },
    ReasonAntecedentUnassigned {
        pivot: AtomId,
        antecedent: Lit,
        reason: Reason,
    },
    ReasonNotUnit {
        pivot: AtomId,
        true_literal: Lit,
        reason: Reason,
    },
    ReasonAntecedentNotEarlier {
        pivot: AtomId,
        pivot_index: usize,
        antecedent: Lit,
        antecedent_index: usize,
        reason: Reason,
    },
    InvalidResolutionPivot {
        pivot: AtomId,
        conflict_occurrences: usize,
        reason_occurrences: usize,
    },
    TautologicalResolvent {
        atom: AtomId,
    },
    NonProgressingResolution {
        pivot: AtomId,
        pivot_index: usize,
        next_index: usize,
    },
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtomOutOfRange {
                role,
                atom,
                atom_count,
            } => write!(
                output,
                "{role:?} atom {} is outside 0..{atom_count}",
                atom.index()
            ),
            Self::NonCanonicalClause {
                role,
                index,
                problem,
            } => write!(
                output,
                "{role:?} clause is not canonical at literal {index}: {problem:?}"
            ),
            Self::ConflictLiteralUnassigned { literal } => write!(
                output,
                "conflict literal {literal:?} is unassigned instead of false"
            ),
            Self::ConflictLiteralTrue { literal } => {
                write!(
                    output,
                    "conflict literal {literal:?} is true instead of false"
                )
            }
            Self::NoCurrentLevelLiteral { conflict_level } => write!(
                output,
                "conflict at decision level {conflict_level} has no current-level literal"
            ),
            Self::UnresolvablePivot { pivot, reason } => write!(
                output,
                "pivot atom {} has non-implication reason {reason:?}",
                pivot.index()
            ),
            Self::MissingReason { pivot, reason } => write!(
                output,
                "provider has no clause for pivot atom {} and reason {reason:?}",
                pivot.index()
            ),
            Self::ReasonMissingPropagation {
                pivot,
                assignment,
                reason,
            } => write!(
                output,
                "reason {reason:?} for pivot atom {} omits assignment {assignment:?}",
                pivot.index()
            ),
            Self::ReasonAntecedentUnassigned {
                pivot,
                antecedent,
                reason,
            } => write!(
                output,
                "reason {reason:?} for pivot atom {} has unassigned antecedent {antecedent:?}",
                pivot.index()
            ),
            Self::ReasonNotUnit {
                pivot,
                true_literal,
                reason,
            } => write!(
                output,
                "reason {reason:?} for pivot atom {} was not unit: {true_literal:?} is also true",
                pivot.index()
            ),
            Self::ReasonAntecedentNotEarlier {
                pivot,
                pivot_index,
                antecedent,
                antecedent_index,
                reason,
            } => write!(
                output,
                "reason {reason:?} antecedent {antecedent:?} at trail index {antecedent_index} is not earlier than pivot atom {} at {pivot_index}",
                pivot.index()
            ),
            Self::InvalidResolutionPivot {
                pivot,
                conflict_occurrences,
                reason_occurrences,
            } => write!(
                output,
                "resolution pivot atom {} occurs {conflict_occurrences} times in the conflict polarity and {reason_occurrences} times in the reason polarity",
                pivot.index()
            ),
            Self::TautologicalResolvent { atom } => write!(
                output,
                "resolution produced complementary literals for atom {}",
                atom.index()
            ),
            Self::NonProgressingResolution {
                pivot,
                pivot_index,
                next_index,
            } => write!(
                output,
                "resolution on atom {} at trail index {pivot_index} did not progress; next current-level index is {next_index}",
                pivot.index()
            ),
        }
    }
}

impl Error for AnalysisError {}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Halt {
    Invalid(AnalysisError),
    Abstain(AnalysisAbstention),
}

impl From<AnalysisError> for Halt {
    fn from(error: AnalysisError) -> Self {
        Self::Invalid(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConflictProfile {
    current_level_literals: usize,
    latest_current: Option<(usize, Lit)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CoreOutcome {
    Learned {
        literals: Box<[Lit]>,
        asserting_literal: Lit,
        backjump_level: u32,
        conflict_level: u32,
        resolution_trace: Box<[ResolutionStep]>,
    },
    RootConflict(Box<[Lit]>),
}

#[derive(Clone, Debug)]
struct AnalysisState {
    caps: AnalysisCaps,
    stats: AnalysisStats,
}

impl AnalysisState {
    fn new(caps: AnalysisCaps) -> Self {
        Self {
            caps,
            stats: AnalysisStats::default(),
        }
    }

    fn check_limit(
        &self,
        resource: AnalysisResource,
        requested: usize,
        cap: usize,
    ) -> Result<(), Halt> {
        if requested > cap {
            return Err(Halt::Abstain(AnalysisAbstention::CapExceeded {
                resource,
                cap,
                requested,
            }));
        }
        Ok(())
    }

    fn charge_literal_visits(&mut self, amount: usize) -> Result<(), Halt> {
        let requested = self
            .stats
            .literal_visits
            .checked_add(amount)
            .ok_or(Halt::Abstain(AnalysisAbstention::CounterOverflow {
                resource: AnalysisResource::LiteralVisits,
            }))?;
        self.check_limit(
            AnalysisResource::LiteralVisits,
            requested,
            self.caps.max_literal_visits,
        )?;
        self.stats.literal_visits = requested;
        Ok(())
    }

    fn begin_provider_query(&mut self) -> Result<(), Halt> {
        let requested = self
            .stats
            .provider_queries
            .checked_add(1)
            .ok_or(Halt::Abstain(AnalysisAbstention::CounterOverflow {
                resource: AnalysisResource::ProviderQueries,
            }))?;
        self.check_limit(
            AnalysisResource::ProviderQueries,
            requested,
            self.caps.max_provider_queries,
        )?;
        self.stats.provider_queries = requested;
        Ok(())
    }

    fn begin_resolution(&mut self) -> Result<(), Halt> {
        let requested = self
            .stats
            .resolution_steps
            .checked_add(1)
            .ok_or(Halt::Abstain(AnalysisAbstention::CounterOverflow {
                resource: AnalysisResource::Resolutions,
            }))?;
        self.check_limit(
            AnalysisResource::Resolutions,
            requested,
            self.caps.max_resolutions,
        )?;
        self.stats.resolution_steps = requested;
        Ok(())
    }

    fn observe_clause(&mut self, literal_count: usize) -> Result<(), Halt> {
        self.check_limit(
            AnalysisResource::ClauseLiterals,
            literal_count,
            self.caps.max_clause_literals,
        )?;
        self.stats.peak_clause_literals = self.stats.peak_clause_literals.max(literal_count);
        Ok(())
    }
}

/// Analyze one fully falsified native clause using deterministic first-UIP
/// resolution.
///
/// Invalid conflicts and reasons return [`AnalysisError`]. Resource exhaustion
/// returns [`AnalysisOutcome::Abstained`] and never exposes a partial clause.
/// The trail and provider are borrowed immutably, so rejection is transactional.
pub(crate) fn analyze<P: ReasonProvider>(
    trail: &Trail,
    provider: &P,
    conflict: &[Lit],
    caps: AnalysisCaps,
) -> Result<AnalysisOutcome, AnalysisError> {
    let mut state = AnalysisState::new(caps);
    let core = run_analysis(trail, provider, conflict, &mut state);
    match core {
        Ok(CoreOutcome::Learned {
            literals,
            asserting_literal,
            backjump_level,
            conflict_level,
            resolution_trace,
        }) => Ok(AnalysisOutcome::Learned(LearnedClause {
            literals,
            asserting_literal,
            backjump_level,
            conflict_level,
            resolution_trace,
            stats: state.stats,
        })),
        Ok(CoreOutcome::RootConflict(literals)) => {
            Ok(AnalysisOutcome::RootConflict(RootConflict {
                literals,
                stats: state.stats,
            }))
        }
        Err(Halt::Invalid(error)) => Err(error),
        Err(Halt::Abstain(reason)) => Ok(AnalysisOutcome::Abstained {
            reason,
            stats: state.stats,
        }),
    }
}

fn run_analysis<P: ReasonProvider>(
    trail: &Trail,
    provider: &P,
    conflict: &[Lit],
    state: &mut AnalysisState,
) -> Result<CoreOutcome, Halt> {
    state.check_limit(
        AnalysisResource::TrailLiterals,
        trail.len(),
        state.caps.max_trail_literals,
    )?;
    state.observe_clause(conflict.len())?;
    validate_canonical_clause(trail.atom_count(), conflict, ClauseRole::Conflict, state)?;

    let conflict_level = trail.current_level();
    let mut working = conflict.to_vec();
    let mut profile = profile_conflict(trail, &working, conflict_level, state)?;
    if conflict_level == 0 {
        return Ok(CoreOutcome::RootConflict(working.into_boxed_slice()));
    }
    if profile.current_level_literals == 0 {
        return Err(AnalysisError::NoCurrentLevelLiteral { conflict_level }.into());
    }

    let mut trace = Vec::new();
    while profile.current_level_literals > 1 {
        let (pivot_index, conflict_literal) = profile
            .latest_current
            .expect("a positive current-level count has a latest literal");
        let pivot = conflict_literal.atom();
        let (assignment, assignment_level, reason) = trail
            .assignment(pivot)
            .expect("canonical range validation covers every working atom")
            .expect("conflict profiling requires every working atom to be assigned");
        debug_assert_eq!(assignment, conflict_literal.negate());
        debug_assert_eq!(assignment_level, conflict_level);

        if matches!(reason, Reason::Root | Reason::Decision) {
            return Err(AnalysisError::UnresolvablePivot { pivot, reason }.into());
        }
        state.begin_provider_query()?;
        let reason_clause = provider
            .canonical_reason(reason)
            .ok_or(AnalysisError::MissingReason { pivot, reason })?;
        state.check_limit(
            AnalysisResource::ReasonLiterals,
            reason_clause.len(),
            state.caps.max_reason_literals,
        )?;
        validate_canonical_clause(
            trail.atom_count(),
            reason_clause,
            ClauseRole::Reason(reason),
            state,
        )?;
        validate_reason(
            trail,
            pivot,
            pivot_index,
            assignment,
            reason,
            reason_clause,
            state,
        )?;

        state.begin_resolution()?;
        let derived = resolve_on(
            &working,
            reason_clause,
            conflict_literal,
            assignment,
            trail.atom_count(),
            state,
        )?;
        let next_profile = profile_conflict(trail, &derived, conflict_level, state)?;
        if next_profile.current_level_literals == 0 {
            return Err(AnalysisError::NoCurrentLevelLiteral { conflict_level }.into());
        }
        if let Some((next_index, _)) = next_profile.latest_current {
            if next_index >= pivot_index {
                return Err(AnalysisError::NonProgressingResolution {
                    pivot,
                    pivot_index,
                    next_index,
                }
                .into());
            }
        }
        trace.push(ResolutionStep {
            pivot,
            conflict_literal,
            reason,
            trail_index: pivot_index,
            derived_literals: derived.len(),
        });
        working = derived;
        profile = next_profile;
    }

    let (_, asserting_literal) = profile
        .latest_current
        .expect("a single current-level literal has a trail index");
    let mut backjump_level = 0;
    state.charge_literal_visits(working.len())?;
    for literal in &working {
        if *literal == asserting_literal {
            continue;
        }
        let (_, level, _) = trail
            .assignment(literal.atom())
            .expect("canonical range validation covers learned atoms")
            .expect("learned clauses remain fully assigned");
        debug_assert!(level < conflict_level);
        backjump_level = backjump_level.max(level);
    }

    Ok(CoreOutcome::Learned {
        literals: working.into_boxed_slice(),
        asserting_literal,
        backjump_level,
        conflict_level,
        resolution_trace: trace.into_boxed_slice(),
    })
}

fn validate_canonical_clause(
    atom_count: usize,
    clause: &[Lit],
    role: ClauseRole,
    state: &mut AnalysisState,
) -> Result<(), Halt> {
    state.charge_literal_visits(clause.len())?;
    for (index, literal) in clause.iter().copied().enumerate() {
        if literal.atom().index() >= atom_count {
            return Err(AnalysisError::AtomOutOfRange {
                role,
                atom: literal.atom(),
                atom_count,
            }
            .into());
        }
        let Some(previous) = index.checked_sub(1).map(|previous| clause[previous]) else {
            continue;
        };
        if previous.atom() == literal.atom() && previous != literal {
            return Err(AnalysisError::NonCanonicalClause {
                role,
                index,
                problem: CanonicalityProblem::ComplementaryPair,
            }
            .into());
        }
        match previous.cmp(&literal) {
            Ordering::Less => {}
            Ordering::Equal => {
                return Err(AnalysisError::NonCanonicalClause {
                    role,
                    index,
                    problem: CanonicalityProblem::Duplicate,
                }
                .into());
            }
            Ordering::Greater => {
                return Err(AnalysisError::NonCanonicalClause {
                    role,
                    index,
                    problem: CanonicalityProblem::OutOfOrder,
                }
                .into());
            }
        }
    }
    Ok(())
}

fn profile_conflict(
    trail: &Trail,
    clause: &[Lit],
    conflict_level: u32,
    state: &mut AnalysisState,
) -> Result<ConflictProfile, Halt> {
    state.charge_literal_visits(clause.len())?;
    let mut current_level_literals = 0usize;
    let mut latest_current = None;
    for literal in clause.iter().copied() {
        let Some((assignment, level, _)) = trail
            .assignment(literal.atom())
            .expect("canonical range validation covers every conflict atom")
        else {
            return Err(AnalysisError::ConflictLiteralUnassigned { literal }.into());
        };
        if assignment == literal {
            return Err(AnalysisError::ConflictLiteralTrue { literal }.into());
        }
        if level == conflict_level {
            current_level_literals = current_level_literals.checked_add(1).ok_or(Halt::Abstain(
                AnalysisAbstention::CounterOverflow {
                    resource: AnalysisResource::ClauseLiterals,
                },
            ))?;
            let trail_index = trail
                .trail_index(literal.atom())
                .expect("canonical range validation covers every conflict atom")
                .expect("assigned conflict literals have trail indices");
            if latest_current.map_or(true, |(latest, _)| trail_index > latest) {
                latest_current = Some((trail_index, literal));
            }
        }
    }
    Ok(ConflictProfile {
        current_level_literals,
        latest_current,
    })
}

fn validate_reason(
    trail: &Trail,
    pivot: AtomId,
    pivot_index: usize,
    assignment: Lit,
    reason: Reason,
    reason_clause: &[Lit],
    state: &mut AnalysisState,
) -> Result<(), Halt> {
    state.charge_literal_visits(reason_clause.len())?;
    if reason_clause.binary_search(&assignment).is_err() {
        return Err(AnalysisError::ReasonMissingPropagation {
            pivot,
            assignment,
            reason,
        }
        .into());
    }
    for antecedent in reason_clause.iter().copied() {
        if antecedent == assignment {
            continue;
        }
        let Some((antecedent_assignment, _, _)) = trail
            .assignment(antecedent.atom())
            .expect("canonical range validation covers every reason atom")
        else {
            return Err(AnalysisError::ReasonAntecedentUnassigned {
                pivot,
                antecedent,
                reason,
            }
            .into());
        };
        if antecedent_assignment == antecedent {
            return Err(AnalysisError::ReasonNotUnit {
                pivot,
                true_literal: antecedent,
                reason,
            }
            .into());
        }
        let antecedent_index = trail
            .trail_index(antecedent.atom())
            .expect("canonical range validation covers every reason atom")
            .expect("assigned reason antecedents have trail indices");
        if antecedent_index >= pivot_index {
            return Err(AnalysisError::ReasonAntecedentNotEarlier {
                pivot,
                pivot_index,
                antecedent,
                antecedent_index,
                reason,
            }
            .into());
        }
    }
    Ok(())
}

fn resolve_on(
    conflict: &[Lit],
    reason: &[Lit],
    conflict_literal: Lit,
    assignment: Lit,
    atom_count: usize,
    state: &mut AnalysisState,
) -> Result<Vec<Lit>, Halt> {
    let conflict_occurrences = conflict
        .iter()
        .filter(|literal| **literal == conflict_literal)
        .count();
    let reason_occurrences = reason
        .iter()
        .filter(|literal| **literal == assignment)
        .count();
    state.charge_literal_visits(conflict.len().checked_add(reason.len()).ok_or(
        Halt::Abstain(AnalysisAbstention::CounterOverflow {
            resource: AnalysisResource::LiteralVisits,
        }),
    )?)?;
    if conflict_literal.atom() != assignment.atom()
        || conflict_literal == assignment
        || conflict_occurrences != 1
        || reason_occurrences != 1
    {
        return Err(AnalysisError::InvalidResolutionPivot {
            pivot: conflict_literal.atom(),
            conflict_occurrences,
            reason_occurrences,
        }
        .into());
    }

    let mut left = conflict
        .iter()
        .copied()
        .filter(|literal| *literal != conflict_literal)
        .peekable();
    let mut right = reason
        .iter()
        .copied()
        .filter(|literal| *literal != assignment)
        .peekable();
    let mut resolvent = Vec::<Lit>::new();
    loop {
        let next = match (left.peek().copied(), right.peek().copied()) {
            (Some(left_literal), Some(right_literal)) => match left_literal.cmp(&right_literal) {
                Ordering::Less => left.next(),
                Ordering::Equal => {
                    right.next();
                    left.next()
                }
                Ordering::Greater => right.next(),
            },
            (Some(_), None) => left.next(),
            (None, Some(_)) => right.next(),
            (None, None) => break,
        }
        .expect("a selected merge branch has a literal");

        if let Some(previous) = resolvent.last().copied() {
            if previous.atom() == next.atom() && previous != next {
                return Err(AnalysisError::TautologicalResolvent { atom: next.atom() }.into());
            }
            if previous == next {
                continue;
            }
        }
        let requested = resolvent.len().checked_add(1).ok_or(Halt::Abstain(
            AnalysisAbstention::CounterOverflow {
                resource: AnalysisResource::ClauseLiterals,
            },
        ))?;
        state.check_limit(
            AnalysisResource::ClauseLiterals,
            requested,
            state.caps.max_clause_literals,
        )?;
        state.charge_literal_visits(1)?;
        resolvent.push(next);
    }
    state.observe_clause(resolvent.len())?;
    validate_canonical_clause(atom_count, &resolvent, ClauseRole::Resolvent, state)?;
    if resolvent
        .iter()
        .any(|literal| literal.atom() == conflict_literal.atom())
    {
        return Err(AnalysisError::InvalidResolutionPivot {
            pivot: conflict_literal.atom(),
            conflict_occurrences,
            reason_occurrences,
        }
        .into());
    }
    Ok(resolvent)
}

#[cfg(test)]
mod tests {
    use super::super::native_clause::{AddOutcome, NativeClauseDb};
    use super::super::trail::EnqueueOutcome;
    use super::*;

    #[derive(Clone, Debug, Default)]
    struct TestProvider {
        clauses: Vec<(ClauseId, Vec<Lit>)>,
        theories: Vec<(TheoryReasonId, Vec<Lit>)>,
    }

    impl TestProvider {
        fn theory(mut self, id: u32, mut clause: Vec<Lit>) -> Self {
            clause.sort_unstable();
            self.theories.push((TheoryReasonId::new(id), clause));
            self
        }

        fn raw_theory(mut self, id: u32, clause: Vec<Lit>) -> Self {
            self.theories.push((TheoryReasonId::new(id), clause));
            self
        }

        fn clause(mut self, id: ClauseId, literals: Vec<Lit>) -> Self {
            self.clauses.push((id, literals));
            self
        }
    }

    impl ReasonProvider for TestProvider {
        fn clause_reason(&self, reason: ClauseId) -> Option<&[Lit]> {
            self.clauses
                .iter()
                .find(|(id, _)| *id == reason)
                .map(|(_, clause)| clause.as_slice())
        }

        fn theory_reason(&self, reason: TheoryReasonId) -> Option<&[Lit]> {
            self.theories
                .iter()
                .find(|(id, _)| *id == reason)
                .map(|(_, clause)| clause.as_slice())
        }
    }

    fn p(index: u32) -> Lit {
        Lit::positive(AtomId::new(index))
    }

    fn n(index: u32) -> Lit {
        Lit::negative(AtomId::new(index))
    }

    fn assigned(index: u32, value: bool) -> Lit {
        if value { p(index) } else { n(index) }
    }

    fn falsified(index: u32, value: bool) -> Lit {
        assigned(index, value).negate()
    }

    fn canonical(mut clause: Vec<Lit>) -> Vec<Lit> {
        clause.sort_unstable();
        clause.dedup();
        clause
    }

    fn learned(outcome: AnalysisOutcome) -> LearnedClause {
        match outcome {
            AnalysisOutcome::Learned(clause) => clause,
            other => panic!("expected learned clause, got {other:?}"),
        }
    }

    #[test]
    fn resolves_to_first_uip_and_computes_backjump_level() {
        let mut trail = Trail::new(4);
        trail.enqueue(p(0), Reason::Root).unwrap();
        trail.new_decision_level().unwrap();
        trail.enqueue(p(1), Reason::Decision).unwrap();
        trail.new_decision_level().unwrap();
        trail.enqueue(p(2), Reason::Decision).unwrap();
        trail
            .enqueue(p(3), Reason::Theory(TheoryReasonId::new(7)))
            .unwrap();
        let provider = TestProvider::default().theory(7, vec![n(0), n(2), p(3)]);
        let result = learned(
            analyze(
                &trail,
                &provider,
                &canonical(vec![n(1), n(2), n(3)]),
                AnalysisCaps::unlimited(),
            )
            .unwrap(),
        );

        assert_eq!(result.literals.as_ref(), &[n(0), n(1), n(2)]);
        assert_eq!(result.asserting_literal, n(2));
        assert_eq!(result.backjump_level, 1);
        assert_eq!(result.conflict_level, 2);
        assert_eq!(result.resolution_trace.len(), 1);
        assert_eq!(result.resolution_trace[0].pivot, AtomId::new(3));
    }

    #[test]
    fn clause_and_theory_reasons_share_the_same_checked_boundary() {
        let mut db = NativeClauseDb::new(3);
        let clause_id = match db.add_clause(&[n(0), p(1)]).unwrap() {
            AddOutcome::Clause(id) => id,
            other => panic!("expected stored clause, got {other:?}"),
        };
        let mut trail = Trail::new(3);
        trail.new_decision_level().unwrap();
        trail.enqueue(p(0), Reason::Decision).unwrap();
        trail.enqueue(p(1), Reason::Clause(clause_id)).unwrap();
        trail
            .enqueue(p(2), Reason::Theory(TheoryReasonId::new(2)))
            .unwrap();
        let provider = TestProvider::default()
            .clause(clause_id, db.clause(clause_id).unwrap().to_vec())
            .theory(2, vec![n(1), p(2)]);
        let result = learned(
            analyze(
                &trail,
                &provider,
                &canonical(vec![n(0), n(1), n(2)]),
                AnalysisCaps::unlimited(),
            )
            .unwrap(),
        );
        assert_eq!(result.literals.as_ref(), &[n(0)]);
        assert_eq!(result.stats.provider_queries, 2);
        assert_eq!(result.stats.resolution_steps, 2);
    }

    #[test]
    fn root_conflicts_are_reported_without_fabricating_an_assertion() {
        let mut trail = Trail::new(2);
        trail.enqueue(p(0), Reason::Root).unwrap();
        trail.enqueue(n(1), Reason::Root).unwrap();
        let outcome = analyze(
            &trail,
            &TestProvider::default(),
            &[n(0), p(1)],
            AnalysisCaps::unlimited(),
        )
        .unwrap();
        match outcome {
            AnalysisOutcome::RootConflict(root) => {
                assert_eq!(root.literals.as_ref(), &[n(0), p(1)]);
                assert_eq!(root.stats.resolution_steps, 0);
            }
            other => panic!("expected root conflict, got {other:?}"),
        }
    }

    #[test]
    fn malformed_conflicts_are_rejected_without_trail_mutation() {
        let mut trail = Trail::new(2);
        trail.new_decision_level().unwrap();
        trail.enqueue(p(0), Reason::Decision).unwrap();
        let before = trail.assigned_literals().to_vec();
        let provider = TestProvider::default();

        assert!(matches!(
            analyze(&trail, &provider, &[p(0)], AnalysisCaps::unlimited()),
            Err(AnalysisError::ConflictLiteralTrue { .. })
        ));
        assert!(matches!(
            analyze(&trail, &provider, &[n(1)], AnalysisCaps::unlimited()),
            Err(AnalysisError::ConflictLiteralUnassigned { .. })
        ));
        assert!(matches!(
            analyze(&trail, &provider, &[n(0), n(0)], AnalysisCaps::unlimited()),
            Err(AnalysisError::NonCanonicalClause {
                problem: CanonicalityProblem::Duplicate,
                ..
            })
        ));
        assert!(matches!(
            analyze(&trail, &provider, &[p(0), n(0)], AnalysisCaps::unlimited()),
            Err(AnalysisError::NonCanonicalClause {
                problem: CanonicalityProblem::ComplementaryPair,
                ..
            })
        ));
        assert!(matches!(
            analyze(&trail, &provider, &[n(2)], AnalysisCaps::unlimited()),
            Err(AnalysisError::AtomOutOfRange { .. })
        ));
        assert_eq!(trail.assigned_literals(), before.as_slice());
    }

    #[test]
    fn malformed_reason_and_non_unit_pivots_are_rejected() {
        let mut trail = Trail::new(4);
        trail.new_decision_level().unwrap();
        trail.enqueue(p(0), Reason::Decision).unwrap();
        trail
            .enqueue(p(1), Reason::Theory(TheoryReasonId::new(1)))
            .unwrap();
        trail.enqueue(p(2), Reason::Root).unwrap();
        let conflict = canonical(vec![n(0), n(1)]);

        let missing_propagation = TestProvider::default().theory(1, vec![n(0)]);
        assert!(matches!(
            analyze(
                &trail,
                &missing_propagation,
                &conflict,
                AnalysisCaps::unlimited()
            ),
            Err(AnalysisError::ReasonMissingPropagation { .. })
        ));

        let non_unit = TestProvider::default().theory(1, vec![n(0), p(1), p(2)]);
        assert!(matches!(
            analyze(&trail, &non_unit, &conflict, AnalysisCaps::unlimited()),
            Err(AnalysisError::ReasonNotUnit { true_literal, .. }) if true_literal == p(2)
        ));

        let unassigned = TestProvider::default().theory(1, vec![n(0), p(1), p(3)]);
        assert!(matches!(
            analyze(&trail, &unassigned, &conflict, AnalysisCaps::unlimited()),
            Err(AnalysisError::ReasonAntecedentUnassigned { .. })
        ));

        let out_of_order = TestProvider::default().raw_theory(1, vec![p(1), n(0)]);
        assert!(matches!(
            analyze(&trail, &out_of_order, &conflict, AnalysisCaps::unlimited()),
            Err(AnalysisError::NonCanonicalClause {
                role: ClauseRole::Reason(Reason::Theory(_)),
                problem: CanonicalityProblem::OutOfOrder,
                ..
            })
        ));

        let absent = TestProvider::default();
        assert!(matches!(
            analyze(&trail, &absent, &conflict, AnalysisCaps::unlimited()),
            Err(AnalysisError::MissingReason { .. })
        ));

        let out_of_range = TestProvider::default().theory(1, vec![n(0), p(1), n(4)]);
        assert!(matches!(
            analyze(
                &trail,
                &out_of_range,
                &conflict,
                AnalysisCaps::unlimited()
            ),
            Err(AnalysisError::AtomOutOfRange {
                role: ClauseRole::Reason(Reason::Theory(_)),
                atom,
                atom_count: 4,
            }) if atom == AtomId::new(4)
        ));
    }

    #[test]
    fn resolution_primitive_rejects_missing_and_wrong_polarity_pivots() {
        let mut state = AnalysisState::new(AnalysisCaps::unlimited());
        assert!(matches!(
            resolve_on(&[n(0), n(1)], &[p(1)], n(0), p(0), 2, &mut state),
            Err(Halt::Invalid(AnalysisError::InvalidResolutionPivot {
                pivot,
                conflict_occurrences: 1,
                reason_occurrences: 0,
            })) if pivot == AtomId::new(0)
        ));

        let mut state = AnalysisState::new(AnalysisCaps::unlimited());
        assert!(matches!(
            resolve_on(&[n(0), n(1)], &[n(0), p(1)], n(0), n(0), 2, &mut state),
            Err(Halt::Invalid(AnalysisError::InvalidResolutionPivot {
                pivot,
                conflict_occurrences: 1,
                reason_occurrences: 1,
            })) if pivot == AtomId::new(0)
        ));
    }

    #[test]
    fn later_antecedents_and_decision_pivots_are_rejected() {
        let mut trail = Trail::new(3);
        trail.new_decision_level().unwrap();
        trail
            .enqueue(p(0), Reason::Theory(TheoryReasonId::new(0)))
            .unwrap();
        trail.enqueue(p(1), Reason::Decision).unwrap();
        trail.enqueue(p(2), Reason::Decision).unwrap();
        let provider = TestProvider::default().theory(0, vec![p(0), n(1)]);
        assert!(matches!(
            analyze(
                &trail,
                &provider,
                &canonical(vec![n(0), n(1)]),
                AnalysisCaps::unlimited()
            ),
            Err(AnalysisError::UnresolvablePivot { pivot, .. }) if pivot == AtomId::new(1)
        ));

        let mut later_trail = Trail::new(3);
        later_trail.new_decision_level().unwrap();
        later_trail.enqueue(p(2), Reason::Decision).unwrap();
        later_trail
            .enqueue(p(0), Reason::Theory(TheoryReasonId::new(0)))
            .unwrap();
        later_trail.enqueue(p(1), Reason::Root).unwrap();
        let later_provider = TestProvider::default().theory(0, vec![p(0), n(1)]);
        assert!(matches!(
            analyze(
                &later_trail,
                &later_provider,
                &canonical(vec![n(0), n(2)]),
                AnalysisCaps::unlimited()
            ),
            Err(AnalysisError::ReasonAntecedentNotEarlier { .. })
        ));
    }

    #[test]
    fn cap_exhaustion_abstains_without_partial_learned_clause() {
        let mut trail = Trail::new(3);
        trail.new_decision_level().unwrap();
        trail.enqueue(p(0), Reason::Decision).unwrap();
        trail
            .enqueue(p(1), Reason::Theory(TheoryReasonId::new(1)))
            .unwrap();
        let provider = TestProvider::default().theory(1, vec![n(0), p(1)]);
        let conflict = canonical(vec![n(0), n(1)]);

        let cases = [
            (
                AnalysisCaps::new(1, 10, 10, 10, 10, 100),
                AnalysisResource::TrailLiterals,
            ),
            (
                AnalysisCaps::new(10, 1, 10, 10, 10, 100),
                AnalysisResource::ClauseLiterals,
            ),
            (
                AnalysisCaps::new(10, 10, 1, 10, 10, 100),
                AnalysisResource::ReasonLiterals,
            ),
            (
                AnalysisCaps::new(10, 10, 10, 0, 10, 100),
                AnalysisResource::Resolutions,
            ),
            (
                AnalysisCaps::new(10, 10, 10, 10, 0, 100),
                AnalysisResource::ProviderQueries,
            ),
            (
                AnalysisCaps::new(10, 10, 10, 10, 10, 0),
                AnalysisResource::LiteralVisits,
            ),
        ];
        for (caps, expected_resource) in cases {
            let outcome = analyze(&trail, &provider, &conflict, caps).unwrap();
            assert!(matches!(
                outcome,
                AnalysisOutcome::Abstained {
                    reason: AnalysisAbstention::CapExceeded { resource, .. },
                    ..
                } if resource == expected_resource
            ));
        }
    }

    #[test]
    fn accounting_overflow_abstains() {
        let mut state = AnalysisState::new(AnalysisCaps::unlimited());
        state.stats.literal_visits = usize::MAX;
        assert_eq!(
            state.charge_literal_visits(1),
            Err(Halt::Abstain(AnalysisAbstention::CounterOverflow {
                resource: AnalysisResource::LiteralVisits
            }))
        );
        state.stats.provider_queries = usize::MAX;
        assert_eq!(
            state.begin_provider_query(),
            Err(Halt::Abstain(AnalysisAbstention::CounterOverflow {
                resource: AnalysisResource::ProviderQueries
            }))
        );
        state.stats.resolution_steps = usize::MAX;
        assert_eq!(
            state.begin_resolution(),
            Err(Halt::Abstain(AnalysisAbstention::CounterOverflow {
                resource: AnalysisResource::Resolutions
            }))
        );
    }

    #[test]
    fn provider_insertion_order_cannot_change_the_learned_clause() {
        let mut trail = Trail::new(4);
        trail.new_decision_level().unwrap();
        trail.enqueue(p(0), Reason::Decision).unwrap();
        trail
            .enqueue(p(1), Reason::Theory(TheoryReasonId::new(10)))
            .unwrap();
        trail
            .enqueue(p(2), Reason::Theory(TheoryReasonId::new(20)))
            .unwrap();
        trail
            .enqueue(p(3), Reason::Theory(TheoryReasonId::new(30)))
            .unwrap();
        let forward = TestProvider::default()
            .theory(10, vec![n(0), p(1)])
            .theory(20, vec![n(1), p(2)])
            .theory(30, vec![n(2), p(3)]);
        let reverse = TestProvider::default()
            .theory(30, vec![n(2), p(3)])
            .theory(20, vec![n(1), p(2)])
            .theory(10, vec![n(0), p(1)]);
        let conflict = canonical(vec![n(0), n(1), n(2), n(3)]);
        let left = analyze(&trail, &forward, &conflict, AnalysisCaps::unlimited()).unwrap();
        let right = analyze(&trail, &reverse, &conflict, AnalysisCaps::unlimited()).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn repeated_analysis_is_byte_for_byte_deterministic() {
        let mut trail = Trail::new(3);
        trail.new_decision_level().unwrap();
        trail.enqueue(n(0), Reason::Decision).unwrap();
        trail
            .enqueue(p(1), Reason::Theory(TheoryReasonId::new(1)))
            .unwrap();
        trail
            .enqueue(n(2), Reason::Theory(TheoryReasonId::new(2)))
            .unwrap();
        let provider = TestProvider::default()
            .theory(1, vec![p(0), p(1)])
            .theory(2, vec![n(1), n(2)]);
        let conflict = canonical(vec![p(0), n(1), p(2)]);
        let expected = analyze(&trail, &provider, &conflict, AnalysisCaps::unlimited()).unwrap();
        for _ in 0..32 {
            assert_eq!(
                analyze(&trail, &provider, &conflict, AnalysisCaps::unlimited()).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn exhaustive_small_implication_graphs_match_truth_table_oracle() {
        for assignment_bits in 0u32..16 {
            let values = [0, 1, 2, 3].map(|index| assignment_bits & (1 << index) != 0);
            for reason_two_mask in 0u32..4 {
                for reason_three_mask in 0u32..8 {
                    let mut reason_two = vec![assigned(2, values[2])];
                    for atom in 0..2 {
                        if reason_two_mask & (1 << atom) != 0 {
                            reason_two.push(falsified(atom, values[atom as usize]));
                        }
                    }
                    let reason_two = canonical(reason_two);
                    let mut reason_three = vec![assigned(3, values[3])];
                    for atom in 0..3 {
                        if reason_three_mask & (1 << atom) != 0 {
                            reason_three.push(falsified(atom, values[atom as usize]));
                        }
                    }
                    let reason_three = canonical(reason_three);
                    let provider = TestProvider::default()
                        .theory(2, reason_two.clone())
                        .theory(3, reason_three.clone());

                    let mut trail = Trail::new(4);
                    assert_eq!(
                        trail.enqueue(assigned(0, values[0]), Reason::Root).unwrap(),
                        EnqueueOutcome::Assigned
                    );
                    trail.new_decision_level().unwrap();
                    trail
                        .enqueue(assigned(1, values[1]), Reason::Decision)
                        .unwrap();
                    trail
                        .enqueue(
                            assigned(2, values[2]),
                            Reason::Theory(TheoryReasonId::new(2)),
                        )
                        .unwrap();
                    trail
                        .enqueue(
                            assigned(3, values[3]),
                            Reason::Theory(TheoryReasonId::new(3)),
                        )
                        .unwrap();

                    for conflict_mask in 1u32..16 {
                        if conflict_mask & 0b1110 == 0 {
                            continue;
                        }
                        let conflict = canonical(
                            (0..4)
                                .filter(|atom| conflict_mask & (1 << atom) != 0)
                                .map(|atom| falsified(atom, values[atom as usize]))
                                .collect(),
                        );
                        let result = learned(
                            analyze(&trail, &provider, &conflict, AnalysisCaps::unlimited())
                                .unwrap(),
                        );

                        assert!(result.literals.iter().all(|literal| *literal
                            == falsified(
                                literal.atom().index() as u32,
                                values[literal.atom().index()]
                            )));
                        let current_count = result
                            .literals
                            .iter()
                            .filter(|literal| literal.atom().index() != 0)
                            .count();
                        assert_eq!(current_count, 1);
                        assert_eq!(result.backjump_level, 0);
                        assert_clause_entailment(
                            4,
                            &[&reason_two, &reason_three, &conflict],
                            &result.literals,
                        );
                        assert!(
                            result
                                .resolution_trace
                                .windows(2)
                                .all(|steps| steps[0].trail_index > steps[1].trail_index)
                        );
                    }
                }
            }
        }
    }

    fn assert_clause_entailment(atom_count: usize, premises: &[&[Lit]], consequence: &[Lit]) {
        for valuation in 0usize..(1usize << atom_count) {
            let premise_true = premises
                .iter()
                .all(|clause| clause_value(clause, valuation));
            if premise_true {
                assert!(
                    clause_value(consequence, valuation),
                    "premises do not entail {consequence:?} under valuation {valuation:b}"
                );
            }
        }
    }

    fn clause_value(clause: &[Lit], valuation: usize) -> bool {
        clause.iter().any(|literal| {
            let value = valuation & (1usize << literal.atom().index()) != 0;
            value == literal.is_positive()
        })
    }
}
