#![forbid(unsafe_code)]

//! Bounded rollback domains and checked Hall propagation for `AllDifferent`.
//!
//! This module deliberately starts after source recognition. Callers supply a
//! stable group of term IDs, one opaque reason for the `AllDifferent` fact,
//! and source-certified bitmask restrictions for every term. The producer
//! computes a maximum matching and complete Hall filtering, but it does not
//! install derived restrictions as new source facts. Instead it returns the
//! filtered domains and replayable witnesses.
//!
//! [`checker`] is the independent proof path. It reconstructs every premise
//! domain from its source restriction chain, recomputes the Hall neighborhood,
//! and checks the conclusion without consulting producer matching state.
//!
//! Both sides have hard limits of eight terms and eight values. All input IDs,
//! masks, configurable caps, counters, snapshots, and allocations are checked.

use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const MAX_HALL_TERMS: usize = 8;
pub(crate) const MAX_HALL_VALUES: usize = 8;
pub(crate) const MAX_HALL_EDGES: usize = MAX_HALL_TERMS * MAX_HALL_VALUES;
pub(crate) const MAX_HALL_SUBSETS: usize = (1usize << MAX_HALL_TERMS) - 1;
pub(crate) const MAX_MATCHING_STEPS: usize = MAX_HALL_TERMS * MAX_HALL_TERMS * MAX_HALL_VALUES;
pub(crate) const MAX_TRAIL_ENTRIES: usize = MAX_HALL_EDGES;
pub(crate) const MAX_RESTRICTIONS_PER_TERM: usize = MAX_HALL_VALUES + 1;
pub(crate) const MAX_ACTIVE_RESTRICTIONS: usize = MAX_HALL_TERMS * MAX_RESTRICTIONS_PER_TERM;
pub(crate) const HALL_WITNESS_VERSION: u16 = 1;

const MAX_TERM_UNIVERSE: u64 = u32::MAX as u64 + 1;
static NEXT_HALL_STATE_ID: AtomicU64 = AtomicU64::new(1);

/// A stable source-term identity, independent of dense group positions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct HallTermId(u32);

impl HallTermId {
    pub(crate) const MIN: Self = Self(0);
    pub(crate) const MAX: Self = Self(u32::MAX);

    pub(crate) const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub(crate) const fn raw(self) -> u32 {
        self.0
    }
}

impl From<u32> for HallTermId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl fmt::Display for HallTermId {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(output)
    }
}

/// An opaque source-owned proof identity. No numeric value is reserved here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SourceReasonId(u64);

impl SourceReasonId {
    pub(crate) const MIN: Self = Self(0);
    pub(crate) const MAX: Self = Self(u64::MAX);

    pub(crate) const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub(crate) const fn raw(self) -> u64 {
        self.0
    }
}

impl From<u64> for SourceReasonId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for SourceReasonId {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(output)
    }
}

/// One initial source-certified domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HallDomainInput {
    pub(crate) term: HallTermId,
    pub(crate) values: u8,
    pub(crate) reason: SourceReasonId,
}

impl HallDomainInput {
    pub(crate) const fn new(term: HallTermId, values: u8, reason: SourceReasonId) -> Self {
        Self {
            term,
            values,
            reason,
        }
    }
}

/// A source-certified mask intersected into a term's domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DomainRestriction {
    allowed_values: u8,
    reason: SourceReasonId,
}

impl DomainRestriction {
    pub(crate) const fn new(allowed_values: u8, reason: SourceReasonId) -> Self {
        Self {
            allowed_values,
            reason,
        }
    }

    pub(crate) const fn allowed_values(self) -> u8 {
        self.allowed_values
    }

    pub(crate) const fn reason(self) -> SourceReasonId {
        self.reason
    }
}

/// Current domain plus the exact active source restriction chain that made it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HallDomainRecord {
    term: HallTermId,
    values: u8,
    restrictions: Vec<DomainRestriction>,
}

impl HallDomainRecord {
    /// Constructs untrusted replay data. The checker validates every field.
    pub(crate) fn from_parts(
        term: HallTermId,
        values: u8,
        restrictions: Vec<DomainRestriction>,
    ) -> Self {
        Self {
            term,
            values,
            restrictions,
        }
    }

    pub(crate) const fn term(&self) -> HallTermId {
        self.term
    }

    pub(crate) const fn values(&self) -> u8 {
        self.values
    }

    pub(crate) fn restrictions(&self) -> &[DomainRestriction] {
        &self.restrictions
    }
}

/// Configurable limits, all bounded by the module's hard limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HallCaps {
    pub(crate) max_terms: usize,
    pub(crate) max_values: usize,
    pub(crate) max_trail_entries: usize,
    pub(crate) max_active_restrictions: usize,
    pub(crate) max_matching_steps: usize,
    pub(crate) max_subset_checks: usize,
    pub(crate) max_removals: usize,
    pub(crate) max_witness_terms: usize,
    pub(crate) max_witness_restrictions: usize,
}

impl Default for HallCaps {
    fn default() -> Self {
        Self {
            max_terms: MAX_HALL_TERMS,
            max_values: MAX_HALL_VALUES,
            max_trail_entries: MAX_TRAIL_ENTRIES,
            max_active_restrictions: MAX_ACTIVE_RESTRICTIONS,
            max_matching_steps: MAX_MATCHING_STEPS,
            max_subset_checks: MAX_HALL_SUBSETS,
            max_removals: MAX_HALL_EDGES,
            max_witness_terms: MAX_HALL_TERMS,
            max_witness_restrictions: MAX_ACTIVE_RESTRICTIONS,
        }
    }
}

impl HallCaps {
    fn validate(self) -> Result<(), HallError> {
        validate_cap("max_terms", self.max_terms, MAX_HALL_TERMS)?;
        validate_cap("max_values", self.max_values, MAX_HALL_VALUES)?;
        validate_cap(
            "max_trail_entries",
            self.max_trail_entries,
            MAX_TRAIL_ENTRIES,
        )?;
        validate_cap(
            "max_active_restrictions",
            self.max_active_restrictions,
            MAX_ACTIVE_RESTRICTIONS,
        )?;
        validate_cap(
            "max_matching_steps",
            self.max_matching_steps,
            MAX_MATCHING_STEPS,
        )?;
        validate_cap(
            "max_subset_checks",
            self.max_subset_checks,
            MAX_HALL_SUBSETS,
        )?;
        validate_cap("max_removals", self.max_removals, MAX_HALL_EDGES)?;
        validate_cap("max_witness_terms", self.max_witness_terms, MAX_HALL_TERMS)?;
        validate_cap(
            "max_witness_restrictions",
            self.max_witness_restrictions,
            MAX_ACTIVE_RESTRICTIONS,
        )?;
        if self.max_witness_terms > self.max_terms {
            return Err(HallError::InvalidCaps(
                "max_witness_terms exceeds max_terms",
            ));
        }
        if self.max_witness_restrictions > self.max_active_restrictions {
            return Err(HallError::InvalidCaps(
                "max_witness_restrictions exceeds max_active_restrictions",
            ));
        }
        Ok(())
    }
}

fn validate_cap(name: &'static str, observed: usize, hard_limit: usize) -> Result<(), HallError> {
    if observed > hard_limit {
        Err(HallError::CapAboveHardLimit {
            name,
            observed,
            hard_limit,
        })
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HallResource {
    Terms,
    Values,
    TrailEntries,
    ActiveRestrictions,
    MatchingSteps,
    SubsetChecks,
    Removals,
    WitnessTerms,
    WitnessRestrictions,
}

impl fmt::Display for HallResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Terms => "Hall terms",
            Self::Values => "Hall values",
            Self::TrailEntries => "Hall trail entries",
            Self::ActiveRestrictions => "active Hall source restrictions",
            Self::MatchingSteps => "Hall matching steps",
            Self::SubsetChecks => "Hall subset checks",
            Self::Removals => "Hall removal records",
            Self::WitnessTerms => "Hall witness terms",
            Self::WitnessRestrictions => "Hall witness source restrictions",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HallSnapshotError {
    ForeignState,
    FutureState,
    DiscardedBranch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HallError {
    InvalidCaps(&'static str),
    CapAboveHardLimit {
        name: &'static str,
        observed: usize,
        hard_limit: usize,
    },
    CapExceeded {
        resource: HallResource,
        attempted: usize,
        limit: usize,
    },
    TermUniverseTooLarge {
        observed: u64,
        limit: u64,
    },
    TermOutOfRange {
        term: HallTermId,
        term_universe: u64,
    },
    DuplicateTerm {
        term: HallTermId,
    },
    UnknownTerm {
        term: HallTermId,
    },
    DomainMaskOutOfRange {
        term: HallTermId,
        bits: u8,
    },
    ArithmeticOverflow {
        resource: HallResource,
    },
    AllocationFailed {
        context: &'static str,
        requested: usize,
    },
    InvalidSnapshot(HallSnapshotError),
    StateIdExhausted,
    SnapshotStateIdExhausted,
    GeneratedWitnessRejected(HallCheckError),
    InvariantViolation(&'static str),
}

impl fmt::Display for HallError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCaps(message) => write!(output, "invalid Hall caps: {message}"),
            Self::CapAboveHardLimit {
                name,
                observed,
                hard_limit,
            } => write!(
                output,
                "Hall cap {name} is {observed}, above hard limit {hard_limit}"
            ),
            Self::CapExceeded {
                resource,
                attempted,
                limit,
            } => write!(
                output,
                "{resource} cap exceeded: attempted {attempted}, limit {limit}"
            ),
            Self::TermUniverseTooLarge { observed, limit } => write!(
                output,
                "Hall term universe has {observed} terms, stable ID limit is {limit}"
            ),
            Self::TermOutOfRange {
                term,
                term_universe,
            } => write!(
                output,
                "Hall term {term} is outside stable universe 0..{term_universe}"
            ),
            Self::DuplicateTerm { term } => {
                write!(output, "Hall group contains duplicate term {term}")
            }
            Self::UnknownTerm { term } => write!(output, "term {term} is not in the Hall group"),
            Self::DomainMaskOutOfRange { term, bits } => write!(
                output,
                "Hall term {term} contains out-of-range value bits {bits:#04x}"
            ),
            Self::ArithmeticOverflow { resource } => {
                write!(output, "arithmetic overflow while counting {resource}")
            }
            Self::AllocationFailed { context, requested } => write!(
                output,
                "allocation failed for {context} while requesting {requested} entries"
            ),
            Self::InvalidSnapshot(HallSnapshotError::ForeignState) => {
                output.write_str("Hall snapshot belongs to a different state")
            }
            Self::InvalidSnapshot(HallSnapshotError::FutureState) => {
                output.write_str("Hall snapshot is newer than the current state")
            }
            Self::InvalidSnapshot(HallSnapshotError::DiscardedBranch) => {
                output.write_str("Hall snapshot belongs to a discarded branch")
            }
            Self::StateIdExhausted => output.write_str("Hall state ID space exhausted"),
            Self::SnapshotStateIdExhausted => {
                output.write_str("Hall snapshot lineage ID space exhausted")
            }
            Self::GeneratedWitnessRejected(error) => {
                write!(output, "generated Hall witness failed replay: {error}")
            }
            Self::InvariantViolation(message) => {
                write!(output, "Hall invariant violation: {message}")
            }
        }
    }
}

impl Error for HallError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::GeneratedWitnessRejected(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct HallSnapshot {
    state_id: u64,
    trail_len: usize,
    lineage_id: u64,
}

impl HallSnapshot {
    pub(crate) const fn depth(self) -> usize {
        self.trail_len
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HallDomainMutation {
    Unchanged { values: u8 },
    Narrowed { previous: u8, current: u8 },
}

#[derive(Debug)]
struct TrailEntry {
    lineage_id: u64,
    domain_index: usize,
    previous_values: u8,
    previous_restriction_len: usize,
}

/// Rollback source-domain state for one stable `AllDifferent` group.
///
/// The type is intentionally not `Clone`: snapshots are tied to one unique
/// history. A successful strict narrowing appends its source mask and reason;
/// rollback removes that exact record. Redundant narrowings are not trailed.
#[derive(Debug)]
pub(crate) struct RollbackHall {
    state_id: u64,
    term_universe: u64,
    value_count: usize,
    group_reason: SourceReasonId,
    domains: Vec<HallDomainRecord>,
    caps: HallCaps,
    trail: Vec<TrailEntry>,
    next_lineage_id: u64,
}

impl RollbackHall {
    pub(crate) fn new(
        term_universe: u64,
        value_count: usize,
        group_reason: SourceReasonId,
        domains: &[HallDomainInput],
    ) -> Result<Self, HallError> {
        Self::with_caps(
            term_universe,
            value_count,
            group_reason,
            domains,
            HallCaps::default(),
        )
    }

    pub(crate) fn with_caps(
        term_universe: u64,
        value_count: usize,
        group_reason: SourceReasonId,
        domains: &[HallDomainInput],
        caps: HallCaps,
    ) -> Result<Self, HallError> {
        caps.validate()?;
        validate_term_universe(term_universe)?;
        enforce_cap(HallResource::Values, value_count, caps.max_values)?;
        enforce_cap(HallResource::Terms, domains.len(), caps.max_terms)?;
        enforce_cap(
            HallResource::ActiveRestrictions,
            domains.len(),
            caps.max_active_restrictions,
        )?;

        let valid_values = low_value_mask(value_count)?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(domains.len())
            .map_err(|_| HallError::AllocationFailed {
                context: "Hall domain records",
                requested: domains.len(),
            })?;
        for input in domains.iter().copied() {
            validate_term(input.term, term_universe)?;
            validate_domain_mask(input.term, input.values, valid_values)?;
            let mut restrictions = Vec::new();
            restrictions
                .try_reserve_exact(1)
                .map_err(|_| HallError::AllocationFailed {
                    context: "initial Hall source restrictions",
                    requested: 1,
                })?;
            restrictions.push(DomainRestriction::new(input.values, input.reason));
            records.push(HallDomainRecord {
                term: input.term,
                values: input.values,
                restrictions,
            });
        }
        records.sort_unstable_by_key(HallDomainRecord::term);
        for pair in records.windows(2) {
            if pair[0].term == pair[1].term {
                return Err(HallError::DuplicateTerm { term: pair[0].term });
            }
        }

        let state_id = NEXT_HALL_STATE_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| HallError::StateIdExhausted)?;
        let state = Self {
            state_id,
            term_universe,
            value_count,
            group_reason,
            domains: records,
            caps,
            trail: Vec::new(),
            next_lineage_id: 1,
        };
        debug_assert!(state.validate().is_ok());
        Ok(state)
    }

    pub(crate) const fn term_universe(&self) -> u64 {
        self.term_universe
    }

    pub(crate) const fn value_count(&self) -> usize {
        self.value_count
    }

    pub(crate) const fn group_reason(&self) -> SourceReasonId {
        self.group_reason
    }

    pub(crate) const fn caps(&self) -> HallCaps {
        self.caps
    }

    pub(crate) fn domains(&self) -> &[HallDomainRecord] {
        &self.domains
    }

    pub(crate) fn domain(&self, term: HallTermId) -> Result<&HallDomainRecord, HallError> {
        validate_term(term, self.term_universe)?;
        self.domain_index(term).map(|index| &self.domains[index])
    }

    pub(crate) fn snapshot(&self) -> HallSnapshot {
        HallSnapshot {
            state_id: self.state_id,
            trail_len: self.trail.len(),
            lineage_id: self.trail.last().map_or(0, |entry| entry.lineage_id),
        }
    }

    pub(crate) fn checkpoint(&self) -> HallSnapshot {
        self.snapshot()
    }

    /// Intersects one source-certified mask into a domain.
    ///
    /// The supplied reason certifies the supplied mask, not a derived Hall
    /// conclusion. A mask that changes no current value is ignored.
    pub(crate) fn narrow(
        &mut self,
        term: HallTermId,
        allowed_values: u8,
        reason: SourceReasonId,
    ) -> Result<HallDomainMutation, HallError> {
        validate_term(term, self.term_universe)?;
        let valid_values = low_value_mask(self.value_count)?;
        validate_domain_mask(term, allowed_values, valid_values)?;
        let index = self.domain_index(term)?;
        let previous = self.domains[index].values;
        let current = previous & allowed_values;
        if current == previous {
            return Ok(HallDomainMutation::Unchanged { values: current });
        }

        let attempted_trail = checked_add(self.trail.len(), 1, HallResource::TrailEntries)?;
        enforce_cap(
            HallResource::TrailEntries,
            attempted_trail,
            self.caps.max_trail_entries,
        )?;
        let active_restrictions = self.active_restriction_count()?;
        let attempted_restrictions =
            checked_add(active_restrictions, 1, HallResource::ActiveRestrictions)?;
        enforce_cap(
            HallResource::ActiveRestrictions,
            attempted_restrictions,
            self.caps.max_active_restrictions,
        )?;
        let previous_restriction_len = self.domains[index].restrictions.len();
        let next_restriction_len = checked_add(
            previous_restriction_len,
            1,
            HallResource::ActiveRestrictions,
        )?;
        enforce_cap(
            HallResource::ActiveRestrictions,
            next_restriction_len,
            MAX_RESTRICTIONS_PER_TERM,
        )?;
        let lineage_id = self.next_lineage_id;
        let next_lineage_id = lineage_id
            .checked_add(1)
            .ok_or(HallError::SnapshotStateIdExhausted)?;

        self.trail
            .try_reserve(1)
            .map_err(|_| HallError::AllocationFailed {
                context: "Hall rollback trail",
                requested: attempted_trail,
            })?;
        self.domains[index]
            .restrictions
            .try_reserve(1)
            .map_err(|_| HallError::AllocationFailed {
                context: "Hall source restriction chain",
                requested: next_restriction_len,
            })?;

        self.trail.push(TrailEntry {
            lineage_id,
            domain_index: index,
            previous_values: previous,
            previous_restriction_len,
        });
        self.domains[index]
            .restrictions
            .push(DomainRestriction::new(allowed_values, reason));
        self.domains[index].values = current;
        self.next_lineage_id = next_lineage_id;
        debug_assert!(self.validate().is_ok());
        Ok(HallDomainMutation::Narrowed { previous, current })
    }

    pub(crate) fn restore(&mut self, snapshot: HallSnapshot) -> Result<usize, HallError> {
        self.validate_snapshot(snapshot)?;
        let restored = self.trail.len() - snapshot.trail_len;
        while self.trail.len() > snapshot.trail_len {
            let entry = self.trail.pop().ok_or(HallError::InvariantViolation(
                "rollback trail unexpectedly empty",
            ))?;
            let record =
                self.domains
                    .get_mut(entry.domain_index)
                    .ok_or(HallError::InvariantViolation(
                        "rollback domain index is out of range",
                    ))?;
            if record.restrictions.len() <= entry.previous_restriction_len {
                return Err(HallError::InvariantViolation(
                    "rollback restriction chain is not newer than its undo record",
                ));
            }
            record.restrictions.truncate(entry.previous_restriction_len);
            record.values = entry.previous_values;
        }
        debug_assert!(self.validate().is_ok());
        Ok(restored)
    }

    pub(crate) fn rollback_to(&mut self, snapshot: HallSnapshot) -> Result<usize, HallError> {
        self.restore(snapshot)
    }

    /// Computes a perfect matching or a checked conflict, then derives every
    /// value excluded by at least one checked tight Hall subset.
    pub(crate) fn propagate(&self) -> Result<HallPropagation, HallError> {
        self.validate()?;
        let mut budget = PropagationBudget::new(self.caps);
        let Some(matched_values) =
            find_perfect_matching(&self.domains, self.value_count, &mut budget)?
        else {
            let witness =
                self.find_conflict_witness(&mut budget)?
                    .ok_or(HallError::InvariantViolation(
                        "matching failed but no Hall conflict subset exists",
                    ))?;
            self.replay_generated(&witness)?;
            return Ok(HallPropagation::Conflict { witness });
        };

        let mut removals = Vec::new();
        removals
            .try_reserve_exact(self.caps.max_removals.min(MAX_HALL_EDGES))
            .map_err(|_| HallError::AllocationFailed {
                context: "Hall removal records",
                requested: self.caps.max_removals.min(MAX_HALL_EDGES),
            })?;
        let mut removed_by_term = [0u8; MAX_HALL_TERMS];
        let subset_end = subset_end(self.domains.len())?;
        for cardinality in 1..=self.domains.len() {
            for subset in 1..subset_end {
                if subset.count_ones() as usize != cardinality {
                    continue;
                }
                budget.charge_subset()?;
                let neighborhood = producer_neighborhood(&self.domains, subset);
                if neighborhood.count_ones() as usize != cardinality {
                    continue;
                }
                for target_index in 0..self.domains.len() {
                    if subset & (1usize << target_index) != 0 {
                        continue;
                    }
                    let forced = self.domains[target_index].values
                        & neighborhood
                        & !removed_by_term[target_index];
                    if forced == 0 {
                        continue;
                    }
                    let attempted = checked_add(removals.len(), 1, HallResource::Removals)?;
                    enforce_cap(HallResource::Removals, attempted, self.caps.max_removals)?;
                    let witness = self.build_witness(
                        subset,
                        neighborhood,
                        HallConclusion::RemoveValues {
                            target: clone_record_checked(
                                &self.domains[target_index],
                                "Hall witness target",
                            )?,
                            values: forced,
                        },
                    )?;
                    self.replay_generated(&witness)?;
                    removals.push(HallRemoval {
                        term: self.domains[target_index].term,
                        values: forced,
                        witness,
                    });
                    removed_by_term[target_index] |= forced;
                }
            }
        }

        let mut matching = Vec::new();
        matching
            .try_reserve_exact(self.domains.len())
            .map_err(|_| HallError::AllocationFailed {
                context: "Hall perfect matching",
                requested: self.domains.len(),
            })?;
        let mut filtered_domains = Vec::new();
        filtered_domains
            .try_reserve_exact(self.domains.len())
            .map_err(|_| HallError::AllocationFailed {
                context: "Hall filtered domains",
                requested: self.domains.len(),
            })?;
        for (index, record) in self.domains.iter().enumerate() {
            let value = matched_values[index].ok_or(HallError::InvariantViolation(
                "perfect matching omitted a term",
            ))?;
            let value_bit =
                1u8.checked_shl(u32::from(value))
                    .ok_or(HallError::InvariantViolation(
                        "matched value does not fit the value bitset",
                    ))?;
            let filtered = record.values & !removed_by_term[index];
            if filtered & value_bit == 0 {
                return Err(HallError::InvariantViolation(
                    "Hall filtering removed an edge from the producer matching",
                ));
            }
            matching.push(HallMatch {
                term: record.term,
                value,
            });
            filtered_domains.push(FilteredHallDomain {
                term: record.term,
                values: filtered,
            });
        }
        Ok(HallPropagation::Consistent {
            matching,
            removals,
            filtered_domains,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), HallError> {
        self.caps.validate()?;
        validate_term_universe(self.term_universe)?;
        enforce_cap(HallResource::Values, self.value_count, self.caps.max_values)?;
        enforce_cap(HallResource::Terms, self.domains.len(), self.caps.max_terms)?;
        let valid_values = low_value_mask(self.value_count)?;
        let mut previous_term = None;
        let mut restriction_count = 0usize;
        for record in &self.domains {
            validate_term(record.term, self.term_universe)?;
            if previous_term.is_some_and(|previous| record.term <= previous) {
                return Err(HallError::InvariantViolation(
                    "domain terms are not strictly sorted",
                ));
            }
            previous_term = Some(record.term);
            validate_domain_record(record, valid_values)?;
            restriction_count = checked_add(
                restriction_count,
                record.restrictions.len(),
                HallResource::ActiveRestrictions,
            )?;
        }
        enforce_cap(
            HallResource::ActiveRestrictions,
            restriction_count,
            self.caps.max_active_restrictions,
        )?;
        enforce_cap(
            HallResource::TrailEntries,
            self.trail.len(),
            self.caps.max_trail_entries,
        )?;
        let mut previous_lineage = 0;
        for entry in &self.trail {
            if entry.lineage_id <= previous_lineage || entry.lineage_id >= self.next_lineage_id {
                return Err(HallError::InvariantViolation(
                    "trail lineage IDs are not strictly increasing",
                ));
            }
            if entry.domain_index >= self.domains.len() {
                return Err(HallError::InvariantViolation(
                    "trail domain index is out of range",
                ));
            }
            previous_lineage = entry.lineage_id;
        }
        Ok(())
    }

    fn domain_index(&self, term: HallTermId) -> Result<usize, HallError> {
        self.domains
            .binary_search_by_key(&term, HallDomainRecord::term)
            .map_err(|_| HallError::UnknownTerm { term })
    }

    fn active_restriction_count(&self) -> Result<usize, HallError> {
        let mut count = 0usize;
        for record in &self.domains {
            count = checked_add(
                count,
                record.restrictions.len(),
                HallResource::ActiveRestrictions,
            )?;
        }
        Ok(count)
    }

    fn validate_snapshot(&self, snapshot: HallSnapshot) -> Result<(), HallError> {
        if snapshot.state_id != self.state_id {
            return Err(HallError::InvalidSnapshot(HallSnapshotError::ForeignState));
        }
        if snapshot.trail_len > self.trail.len() {
            return Err(HallError::InvalidSnapshot(HallSnapshotError::FutureState));
        }
        let expected_lineage = if snapshot.trail_len == 0 {
            0
        } else {
            self.trail[snapshot.trail_len - 1].lineage_id
        };
        if snapshot.lineage_id != expected_lineage {
            return Err(HallError::InvalidSnapshot(
                HallSnapshotError::DiscardedBranch,
            ));
        }
        Ok(())
    }

    fn find_conflict_witness(
        &self,
        budget: &mut PropagationBudget,
    ) -> Result<Option<HallWitness>, HallError> {
        let subset_end = subset_end(self.domains.len())?;
        for cardinality in 1..=self.domains.len() {
            for subset in 1..subset_end {
                if subset.count_ones() as usize != cardinality {
                    continue;
                }
                budget.charge_subset()?;
                let neighborhood = producer_neighborhood(&self.domains, subset);
                if (neighborhood.count_ones() as usize) < cardinality {
                    return self
                        .build_witness(subset, neighborhood, HallConclusion::Conflict)
                        .map(Some);
                }
            }
        }
        Ok(None)
    }

    fn build_witness(
        &self,
        subset: usize,
        neighborhood: u8,
        conclusion: HallConclusion,
    ) -> Result<HallWitness, HallError> {
        let premise_count = subset.count_ones() as usize;
        enforce_cap(
            HallResource::WitnessTerms,
            premise_count,
            self.caps.max_witness_terms,
        )?;

        let mut group_terms = Vec::new();
        group_terms
            .try_reserve_exact(self.domains.len())
            .map_err(|_| HallError::AllocationFailed {
                context: "Hall witness group terms",
                requested: self.domains.len(),
            })?;
        let mut premises = Vec::new();
        premises
            .try_reserve_exact(premise_count)
            .map_err(|_| HallError::AllocationFailed {
                context: "Hall witness premises",
                requested: premise_count,
            })?;
        let mut restriction_count = 0usize;
        for (index, record) in self.domains.iter().enumerate() {
            group_terms.push(record.term);
            if subset & (1usize << index) == 0 {
                continue;
            }
            restriction_count = checked_add(
                restriction_count,
                record.restrictions.len(),
                HallResource::WitnessRestrictions,
            )?;
            enforce_cap(
                HallResource::WitnessRestrictions,
                restriction_count,
                self.caps.max_witness_restrictions,
            )?;
            premises.push(clone_record_checked(record, "Hall witness premises")?);
        }
        if let HallConclusion::RemoveValues { target, .. } = &conclusion {
            restriction_count = checked_add(
                restriction_count,
                target.restrictions.len(),
                HallResource::WitnessRestrictions,
            )?;
            enforce_cap(
                HallResource::WitnessRestrictions,
                restriction_count,
                self.caps.max_witness_restrictions,
            )?;
        }
        Ok(HallWitness {
            version: HALL_WITNESS_VERSION,
            value_count: self.value_count,
            group_terms,
            group_reason: self.group_reason,
            premises,
            claimed_neighborhood: neighborhood,
            conclusion,
        })
    }

    fn replay_generated(&self, witness: &HallWitness) -> Result<(), HallError> {
        checker::replay_against(
            self.term_universe,
            self.value_count,
            self.group_reason,
            &self.domains,
            witness,
            self.caps,
        )
        .map(|_| ())
        .map_err(HallError::GeneratedWitnessRejected)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HallMatch {
    pub(crate) term: HallTermId,
    pub(crate) value: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FilteredHallDomain {
    pub(crate) term: HallTermId,
    pub(crate) values: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HallRemoval {
    pub(crate) term: HallTermId,
    pub(crate) values: u8,
    pub(crate) witness: HallWitness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HallPropagation {
    Conflict {
        witness: HallWitness,
    },
    Consistent {
        matching: Vec<HallMatch>,
        removals: Vec<HallRemoval>,
        filtered_domains: Vec<FilteredHallDomain>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HallConclusion {
    Conflict,
    RemoveValues {
        target: HallDomainRecord,
        values: u8,
    },
}

/// Self-contained, untrusted Hall proof data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HallWitness {
    version: u16,
    value_count: usize,
    group_terms: Vec<HallTermId>,
    group_reason: SourceReasonId,
    premises: Vec<HallDomainRecord>,
    claimed_neighborhood: u8,
    conclusion: HallConclusion,
}

impl HallWitness {
    /// Constructs an untrusted witness, for decoding and independent replay.
    pub(crate) fn from_parts(
        version: u16,
        value_count: usize,
        group_terms: Vec<HallTermId>,
        group_reason: SourceReasonId,
        premises: Vec<HallDomainRecord>,
        claimed_neighborhood: u8,
        conclusion: HallConclusion,
    ) -> Self {
        Self {
            version,
            value_count,
            group_terms,
            group_reason,
            premises,
            claimed_neighborhood,
            conclusion,
        }
    }

    pub(crate) const fn version(&self) -> u16 {
        self.version
    }

    pub(crate) const fn value_count(&self) -> usize {
        self.value_count
    }

    pub(crate) fn group_terms(&self) -> &[HallTermId] {
        &self.group_terms
    }

    pub(crate) const fn group_reason(&self) -> SourceReasonId {
        self.group_reason
    }

    pub(crate) fn premises(&self) -> &[HallDomainRecord] {
        &self.premises
    }

    pub(crate) const fn claimed_neighborhood(&self) -> u8 {
        self.claimed_neighborhood
    }

    pub(crate) const fn conclusion(&self) -> &HallConclusion {
        &self.conclusion
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HallCheckError {
    InvalidCaps(&'static str),
    CapAboveHardLimit {
        name: &'static str,
        observed: usize,
        hard_limit: usize,
    },
    CapExceeded {
        resource: HallResource,
        attempted: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        resource: HallResource,
    },
    AllocationFailed {
        context: &'static str,
        requested: usize,
    },
    TermUniverseTooLarge {
        observed: u64,
        limit: u64,
    },
    UnsupportedVersion {
        observed: u16,
    },
    TermOutOfRange {
        term: HallTermId,
        term_universe: u64,
    },
    GroupTermsNotStrictlySorted {
        previous: HallTermId,
        current: HallTermId,
    },
    EmptyPremises,
    PremisesNotStrictlySorted {
        previous: HallTermId,
        current: HallTermId,
    },
    PremiseOutsideGroup {
        term: HallTermId,
    },
    DomainMaskOutOfRange {
        term: HallTermId,
        bits: u8,
    },
    EmptyRestrictionChain {
        term: HallTermId,
    },
    TooManyRestrictionsForTerm {
        term: HallTermId,
        observed: usize,
        limit: usize,
    },
    RestrictionMaskOutOfRange {
        term: HallTermId,
        restriction: usize,
        bits: u8,
    },
    NonNarrowingRestriction {
        term: HallTermId,
        restriction: usize,
    },
    ReconstructedDomainMismatch {
        term: HallTermId,
        claimed: u8,
        actual: u8,
    },
    ClaimedNeighborhoodOutOfRange {
        bits: u8,
    },
    NeighborhoodMismatch {
        claimed: u8,
        actual: u8,
    },
    NotHallConflict {
        premise_count: usize,
        neighborhood_size: usize,
    },
    NotTightHallSubset {
        premise_count: usize,
        neighborhood_size: usize,
    },
    RemovalTargetOutsideGroup {
        term: HallTermId,
    },
    RemovalTargetInsidePremises {
        term: HallTermId,
    },
    EmptyRemoval {
        term: HallTermId,
    },
    RemovalMaskOutOfRange {
        term: HallTermId,
        bits: u8,
    },
    RemovalOutsideTargetDomain {
        term: HallTermId,
        bits: u8,
    },
    RemovalOutsideNeighborhood {
        term: HallTermId,
        bits: u8,
    },
    BoundValueCountMismatch {
        expected: usize,
        observed: usize,
    },
    BoundGroupReasonMismatch {
        expected: SourceReasonId,
        observed: SourceReasonId,
    },
    BoundGroupTermsMismatch,
    BoundDomainMismatch {
        term: HallTermId,
    },
}

impl fmt::Display for HallCheckError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCaps(message) => write!(output, "invalid Hall checker caps: {message}"),
            Self::CapAboveHardLimit {
                name,
                observed,
                hard_limit,
            } => write!(
                output,
                "Hall checker cap {name} is {observed}, above hard limit {hard_limit}"
            ),
            Self::CapExceeded {
                resource,
                attempted,
                limit,
            } => write!(
                output,
                "Hall checker {resource} cap exceeded: attempted {attempted}, limit {limit}"
            ),
            Self::ArithmeticOverflow { resource } => {
                write!(output, "Hall checker overflow while counting {resource}")
            }
            Self::AllocationFailed { context, requested } => write!(
                output,
                "Hall checker allocation failed for {context} at {requested} entries"
            ),
            Self::TermUniverseTooLarge { observed, limit } => write!(
                output,
                "Hall checker term universe has {observed} terms, limit is {limit}"
            ),
            Self::UnsupportedVersion { observed } => {
                write!(output, "unsupported Hall witness version {observed}")
            }
            Self::TermOutOfRange {
                term,
                term_universe,
            } => write!(
                output,
                "Hall witness term {term} is outside 0..{term_universe}"
            ),
            Self::GroupTermsNotStrictlySorted { previous, current } => write!(
                output,
                "Hall witness group terms are not strictly sorted: {previous} then {current}"
            ),
            Self::EmptyPremises => output.write_str("Hall witness has no premises"),
            Self::PremisesNotStrictlySorted { previous, current } => write!(
                output,
                "Hall premises are not strictly sorted: {previous} then {current}"
            ),
            Self::PremiseOutsideGroup { term } => {
                write!(output, "Hall premise term {term} is outside the group")
            }
            Self::DomainMaskOutOfRange { term, bits } => write!(
                output,
                "Hall witness term {term} has out-of-range domain bits {bits:#04x}"
            ),
            Self::EmptyRestrictionChain { term } => {
                write!(
                    output,
                    "Hall witness term {term} has no source restrictions"
                )
            }
            Self::TooManyRestrictionsForTerm {
                term,
                observed,
                limit,
            } => write!(
                output,
                "Hall witness term {term} has {observed} restrictions, limit is {limit}"
            ),
            Self::RestrictionMaskOutOfRange {
                term,
                restriction,
                bits,
            } => write!(
                output,
                "Hall witness term {term} restriction {restriction} has out-of-range bits {bits:#04x}"
            ),
            Self::NonNarrowingRestriction { term, restriction } => write!(
                output,
                "Hall witness term {term} restriction {restriction} does not narrow the domain"
            ),
            Self::ReconstructedDomainMismatch {
                term,
                claimed,
                actual,
            } => write!(
                output,
                "Hall witness term {term} claims domain {claimed:#04x}, reconstructed {actual:#04x}"
            ),
            Self::ClaimedNeighborhoodOutOfRange { bits } => write!(
                output,
                "Hall witness neighborhood has out-of-range bits {bits:#04x}"
            ),
            Self::NeighborhoodMismatch { claimed, actual } => write!(
                output,
                "Hall witness claims neighborhood {claimed:#04x}, reconstructed {actual:#04x}"
            ),
            Self::NotHallConflict {
                premise_count,
                neighborhood_size,
            } => write!(
                output,
                "Hall conflict needs |N(S)| < |S|, observed {neighborhood_size} >= {premise_count}"
            ),
            Self::NotTightHallSubset {
                premise_count,
                neighborhood_size,
            } => write!(
                output,
                "Hall removal needs |N(S)| = |S|, observed {neighborhood_size} != {premise_count}"
            ),
            Self::RemovalTargetOutsideGroup { term } => {
                write!(output, "Hall removal target {term} is outside the group")
            }
            Self::RemovalTargetInsidePremises { term } => {
                write!(output, "Hall removal target {term} is a Hall premise")
            }
            Self::EmptyRemoval { term } => {
                write!(output, "Hall removal for term {term} is empty")
            }
            Self::RemovalMaskOutOfRange { term, bits } => write!(
                output,
                "Hall removal for term {term} has out-of-range bits {bits:#04x}"
            ),
            Self::RemovalOutsideTargetDomain { term, bits } => write!(
                output,
                "Hall removal for term {term} contains absent domain bits {bits:#04x}"
            ),
            Self::RemovalOutsideNeighborhood { term, bits } => write!(
                output,
                "Hall removal for term {term} contains bits outside N(S): {bits:#04x}"
            ),
            Self::BoundValueCountMismatch { expected, observed } => write!(
                output,
                "Hall witness value count is {observed}, bound state uses {expected}"
            ),
            Self::BoundGroupReasonMismatch { expected, observed } => write!(
                output,
                "Hall witness group reason is {observed}, bound state uses {expected}"
            ),
            Self::BoundGroupTermsMismatch => {
                output.write_str("Hall witness group terms differ from the bound state")
            }
            Self::BoundDomainMismatch { term } => write!(
                output,
                "Hall witness domain record for term {term} differs from the bound state"
            ),
        }
    }
}

impl Error for HallCheckError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CheckedHallWitness {
    conclusion: CheckedHallConclusion,
    premise_terms: Vec<HallTermId>,
    exact_neighborhood: u8,
    source_reasons: Vec<SourceReasonId>,
}

impl CheckedHallWitness {
    pub(crate) const fn conclusion(&self) -> CheckedHallConclusion {
        self.conclusion
    }

    pub(crate) fn premise_terms(&self) -> &[HallTermId] {
        &self.premise_terms
    }

    pub(crate) const fn exact_neighborhood(&self) -> u8 {
        self.exact_neighborhood
    }

    pub(crate) fn source_reasons(&self) -> &[SourceReasonId] {
        &self.source_reasons
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CheckedHallConclusion {
    Conflict,
    RemoveValues { term: HallTermId, values: u8 },
}

/// Independent Hall witness replay. This module contains no matching code.
pub(crate) mod checker {
    use super::*;

    pub(crate) fn replay(
        term_universe: u64,
        witness: &HallWitness,
        caps: HallCaps,
    ) -> Result<CheckedHallWitness, HallCheckError> {
        validate_checker_caps(caps)?;
        validate_checker_term_universe(term_universe)?;
        if witness.version != HALL_WITNESS_VERSION {
            return Err(HallCheckError::UnsupportedVersion {
                observed: witness.version,
            });
        }
        checker_enforce_cap(HallResource::Values, witness.value_count, caps.max_values)?;
        checker_enforce_cap(
            HallResource::Terms,
            witness.group_terms.len(),
            caps.max_terms,
        )?;
        validate_group_terms(term_universe, &witness.group_terms)?;
        if witness.premises.is_empty() {
            return Err(HallCheckError::EmptyPremises);
        }
        checker_enforce_cap(
            HallResource::WitnessTerms,
            witness.premises.len(),
            caps.max_witness_terms,
        )?;

        let valid_values = checker_low_value_mask(witness.value_count)?;
        if witness.claimed_neighborhood & !valid_values != 0 {
            return Err(HallCheckError::ClaimedNeighborhoodOutOfRange {
                bits: witness.claimed_neighborhood & !valid_values,
            });
        }

        let mut exact_neighborhood = 0u8;
        let mut previous_premise = None;
        let mut total_restrictions = 0usize;
        let mut premise_terms = Vec::new();
        premise_terms
            .try_reserve_exact(witness.premises.len())
            .map_err(|_| HallCheckError::AllocationFailed {
                context: "checked Hall premise terms",
                requested: witness.premises.len(),
            })?;
        for premise in &witness.premises {
            validate_checker_record(
                term_universe,
                valid_values,
                premise,
                &mut total_restrictions,
                HallResource::WitnessRestrictions,
                caps.max_witness_restrictions,
            )?;
            if previous_premise.is_some_and(|previous| premise.term <= previous) {
                return Err(HallCheckError::PremisesNotStrictlySorted {
                    previous: previous_premise.expect("checked Some above"),
                    current: premise.term,
                });
            }
            previous_premise = Some(premise.term);
            if witness.group_terms.binary_search(&premise.term).is_err() {
                return Err(HallCheckError::PremiseOutsideGroup { term: premise.term });
            }
            premise_terms.push(premise.term);
            exact_neighborhood |= premise.values;
        }
        if exact_neighborhood != witness.claimed_neighborhood {
            return Err(HallCheckError::NeighborhoodMismatch {
                claimed: witness.claimed_neighborhood,
                actual: exact_neighborhood,
            });
        }

        let premise_count = witness.premises.len();
        let neighborhood_size = exact_neighborhood.count_ones() as usize;
        let conclusion = match &witness.conclusion {
            HallConclusion::Conflict => {
                if neighborhood_size >= premise_count {
                    return Err(HallCheckError::NotHallConflict {
                        premise_count,
                        neighborhood_size,
                    });
                }
                CheckedHallConclusion::Conflict
            }
            HallConclusion::RemoveValues { target, values } => {
                validate_checker_record(
                    term_universe,
                    valid_values,
                    target,
                    &mut total_restrictions,
                    HallResource::WitnessRestrictions,
                    caps.max_witness_restrictions,
                )?;
                if witness.group_terms.binary_search(&target.term).is_err() {
                    return Err(HallCheckError::RemovalTargetOutsideGroup { term: target.term });
                }
                if witness
                    .premises
                    .binary_search_by_key(&target.term, HallDomainRecord::term)
                    .is_ok()
                {
                    return Err(HallCheckError::RemovalTargetInsidePremises { term: target.term });
                }
                if *values == 0 {
                    return Err(HallCheckError::EmptyRemoval { term: target.term });
                }
                if *values & !valid_values != 0 {
                    return Err(HallCheckError::RemovalMaskOutOfRange {
                        term: target.term,
                        bits: *values & !valid_values,
                    });
                }
                if *values & !target.values != 0 {
                    return Err(HallCheckError::RemovalOutsideTargetDomain {
                        term: target.term,
                        bits: *values & !target.values,
                    });
                }
                if *values & !exact_neighborhood != 0 {
                    return Err(HallCheckError::RemovalOutsideNeighborhood {
                        term: target.term,
                        bits: *values & !exact_neighborhood,
                    });
                }
                if neighborhood_size != premise_count {
                    return Err(HallCheckError::NotTightHallSubset {
                        premise_count,
                        neighborhood_size,
                    });
                }
                CheckedHallConclusion::RemoveValues {
                    term: target.term,
                    values: *values,
                }
            }
        };

        let reason_capacity =
            checker_checked_add(total_restrictions, 1, HallResource::WitnessRestrictions)?;
        let mut source_reasons = Vec::new();
        source_reasons
            .try_reserve_exact(reason_capacity)
            .map_err(|_| HallCheckError::AllocationFailed {
                context: "checked Hall source reasons",
                requested: reason_capacity,
            })?;
        push_unique_reason(&mut source_reasons, witness.group_reason);
        for premise in &witness.premises {
            for restriction in &premise.restrictions {
                push_unique_reason(&mut source_reasons, restriction.reason);
            }
        }

        Ok(CheckedHallWitness {
            conclusion,
            premise_terms,
            exact_neighborhood,
            source_reasons,
        })
    }

    /// Replays a witness and also checks that every captured domain record is
    /// the exact active record in the supplied rollback-independent snapshot.
    pub(crate) fn replay_against(
        term_universe: u64,
        value_count: usize,
        group_reason: SourceReasonId,
        domains: &[HallDomainRecord],
        witness: &HallWitness,
        caps: HallCaps,
    ) -> Result<CheckedHallWitness, HallCheckError> {
        let checked = replay(term_universe, witness, caps)?;
        if witness.value_count != value_count {
            return Err(HallCheckError::BoundValueCountMismatch {
                expected: value_count,
                observed: witness.value_count,
            });
        }
        validate_bound_domains(term_universe, value_count, domains, caps)?;
        if witness.group_reason != group_reason {
            return Err(HallCheckError::BoundGroupReasonMismatch {
                expected: group_reason,
                observed: witness.group_reason,
            });
        }
        if witness.group_terms.len() != domains.len()
            || witness
                .group_terms
                .iter()
                .zip(domains)
                .any(|(&term, record)| term != record.term)
        {
            return Err(HallCheckError::BoundGroupTermsMismatch);
        }
        for premise in &witness.premises {
            let index = domains
                .binary_search_by_key(&premise.term, HallDomainRecord::term)
                .map_err(|_| HallCheckError::BoundDomainMismatch { term: premise.term })?;
            if domains[index] != *premise {
                return Err(HallCheckError::BoundDomainMismatch { term: premise.term });
            }
        }
        if let HallConclusion::RemoveValues { target, .. } = &witness.conclusion {
            let index = domains
                .binary_search_by_key(&target.term, HallDomainRecord::term)
                .map_err(|_| HallCheckError::BoundDomainMismatch { term: target.term })?;
            if domains[index] != *target {
                return Err(HallCheckError::BoundDomainMismatch { term: target.term });
            }
        }
        Ok(checked)
    }

    fn validate_bound_domains(
        term_universe: u64,
        value_count: usize,
        domains: &[HallDomainRecord],
        caps: HallCaps,
    ) -> Result<(), HallCheckError> {
        checker_enforce_cap(HallResource::Values, value_count, caps.max_values)?;
        checker_enforce_cap(HallResource::Terms, domains.len(), caps.max_terms)?;
        let valid_values = checker_low_value_mask(value_count)?;
        let mut previous = None;
        let mut total_restrictions = 0usize;
        for record in domains {
            validate_checker_record(
                term_universe,
                valid_values,
                record,
                &mut total_restrictions,
                HallResource::ActiveRestrictions,
                caps.max_active_restrictions,
            )?;
            if previous.is_some_and(|previous| record.term <= previous) {
                return Err(HallCheckError::GroupTermsNotStrictlySorted {
                    previous: previous.expect("checked Some above"),
                    current: record.term,
                });
            }
            previous = Some(record.term);
        }
        Ok(())
    }

    fn validate_group_terms(
        term_universe: u64,
        terms: &[HallTermId],
    ) -> Result<(), HallCheckError> {
        let mut previous = None;
        for &term in terms {
            validate_checker_term(term, term_universe)?;
            if previous.is_some_and(|previous| term <= previous) {
                return Err(HallCheckError::GroupTermsNotStrictlySorted {
                    previous: previous.expect("checked Some above"),
                    current: term,
                });
            }
            previous = Some(term);
        }
        Ok(())
    }

    fn validate_checker_record(
        term_universe: u64,
        valid_values: u8,
        record: &HallDomainRecord,
        total_restrictions: &mut usize,
        restriction_resource: HallResource,
        restriction_limit: usize,
    ) -> Result<(), HallCheckError> {
        validate_checker_term(record.term, term_universe)?;
        if record.values & !valid_values != 0 {
            return Err(HallCheckError::DomainMaskOutOfRange {
                term: record.term,
                bits: record.values & !valid_values,
            });
        }
        if record.restrictions.is_empty() {
            return Err(HallCheckError::EmptyRestrictionChain { term: record.term });
        }
        if record.restrictions.len() > MAX_RESTRICTIONS_PER_TERM {
            return Err(HallCheckError::TooManyRestrictionsForTerm {
                term: record.term,
                observed: record.restrictions.len(),
                limit: MAX_RESTRICTIONS_PER_TERM,
            });
        }
        *total_restrictions = checker_checked_add(
            *total_restrictions,
            record.restrictions.len(),
            restriction_resource,
        )?;
        checker_enforce_cap(restriction_resource, *total_restrictions, restriction_limit)?;

        let mut reconstructed = valid_values;
        for (index, restriction) in record.restrictions.iter().copied().enumerate() {
            if restriction.allowed_values & !valid_values != 0 {
                return Err(HallCheckError::RestrictionMaskOutOfRange {
                    term: record.term,
                    restriction: index,
                    bits: restriction.allowed_values & !valid_values,
                });
            }
            let next = reconstructed & restriction.allowed_values;
            if index > 0 && next == reconstructed {
                return Err(HallCheckError::NonNarrowingRestriction {
                    term: record.term,
                    restriction: index,
                });
            }
            reconstructed = next;
        }
        if reconstructed != record.values {
            return Err(HallCheckError::ReconstructedDomainMismatch {
                term: record.term,
                claimed: record.values,
                actual: reconstructed,
            });
        }
        Ok(())
    }

    fn validate_checker_caps(caps: HallCaps) -> Result<(), HallCheckError> {
        checker_validate_cap("max_terms", caps.max_terms, MAX_HALL_TERMS)?;
        checker_validate_cap("max_values", caps.max_values, MAX_HALL_VALUES)?;
        checker_validate_cap(
            "max_trail_entries",
            caps.max_trail_entries,
            MAX_TRAIL_ENTRIES,
        )?;
        checker_validate_cap(
            "max_active_restrictions",
            caps.max_active_restrictions,
            MAX_ACTIVE_RESTRICTIONS,
        )?;
        checker_validate_cap(
            "max_matching_steps",
            caps.max_matching_steps,
            MAX_MATCHING_STEPS,
        )?;
        checker_validate_cap(
            "max_subset_checks",
            caps.max_subset_checks,
            MAX_HALL_SUBSETS,
        )?;
        checker_validate_cap("max_removals", caps.max_removals, MAX_HALL_EDGES)?;
        checker_validate_cap("max_witness_terms", caps.max_witness_terms, MAX_HALL_TERMS)?;
        checker_validate_cap(
            "max_witness_restrictions",
            caps.max_witness_restrictions,
            MAX_ACTIVE_RESTRICTIONS,
        )?;
        if caps.max_witness_terms > caps.max_terms {
            return Err(HallCheckError::InvalidCaps(
                "max_witness_terms exceeds max_terms",
            ));
        }
        if caps.max_witness_restrictions > caps.max_active_restrictions {
            return Err(HallCheckError::InvalidCaps(
                "max_witness_restrictions exceeds max_active_restrictions",
            ));
        }
        Ok(())
    }

    fn checker_validate_cap(
        name: &'static str,
        observed: usize,
        hard_limit: usize,
    ) -> Result<(), HallCheckError> {
        if observed > hard_limit {
            Err(HallCheckError::CapAboveHardLimit {
                name,
                observed,
                hard_limit,
            })
        } else {
            Ok(())
        }
    }

    fn checker_enforce_cap(
        resource: HallResource,
        attempted: usize,
        limit: usize,
    ) -> Result<(), HallCheckError> {
        if attempted > limit {
            Err(HallCheckError::CapExceeded {
                resource,
                attempted,
                limit,
            })
        } else {
            Ok(())
        }
    }

    fn checker_checked_add(
        left: usize,
        right: usize,
        resource: HallResource,
    ) -> Result<usize, HallCheckError> {
        left.checked_add(right)
            .ok_or(HallCheckError::ArithmeticOverflow { resource })
    }

    fn checker_low_value_mask(value_count: usize) -> Result<u8, HallCheckError> {
        if value_count > MAX_HALL_VALUES {
            return Err(HallCheckError::CapExceeded {
                resource: HallResource::Values,
                attempted: value_count,
                limit: MAX_HALL_VALUES,
            });
        }
        Ok(if value_count == MAX_HALL_VALUES {
            u8::MAX
        } else if value_count == 0 {
            0
        } else {
            (1u8 << value_count) - 1
        })
    }

    fn validate_checker_term_universe(term_universe: u64) -> Result<(), HallCheckError> {
        if term_universe > MAX_TERM_UNIVERSE {
            Err(HallCheckError::TermUniverseTooLarge {
                observed: term_universe,
                limit: MAX_TERM_UNIVERSE,
            })
        } else {
            Ok(())
        }
    }

    fn validate_checker_term(term: HallTermId, term_universe: u64) -> Result<(), HallCheckError> {
        if u64::from(term.raw()) >= term_universe {
            Err(HallCheckError::TermOutOfRange {
                term,
                term_universe,
            })
        } else {
            Ok(())
        }
    }

    fn push_unique_reason(reasons: &mut Vec<SourceReasonId>, reason: SourceReasonId) {
        if !reasons.contains(&reason) {
            reasons.push(reason);
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct PropagationBudget {
    matching_steps: usize,
    subset_checks: usize,
    caps: HallCaps,
}

impl PropagationBudget {
    const fn new(caps: HallCaps) -> Self {
        Self {
            matching_steps: 0,
            subset_checks: 0,
            caps,
        }
    }

    fn charge_matching(&mut self) -> Result<(), HallError> {
        self.matching_steps = checked_add(self.matching_steps, 1, HallResource::MatchingSteps)?;
        enforce_cap(
            HallResource::MatchingSteps,
            self.matching_steps,
            self.caps.max_matching_steps,
        )
    }

    fn charge_subset(&mut self) -> Result<(), HallError> {
        self.subset_checks = checked_add(self.subset_checks, 1, HallResource::SubsetChecks)?;
        enforce_cap(
            HallResource::SubsetChecks,
            self.subset_checks,
            self.caps.max_subset_checks,
        )
    }
}

fn find_perfect_matching(
    domains: &[HallDomainRecord],
    value_count: usize,
    budget: &mut PropagationBudget,
) -> Result<Option<[Option<u8>; MAX_HALL_TERMS]>, HallError> {
    let mut owner_by_value = [None; MAX_HALL_VALUES];
    let mut value_by_term = [None; MAX_HALL_TERMS];
    for term_index in 0..domains.len() {
        let mut visited_values = 0u8;
        if !augment_matching(
            term_index,
            domains,
            value_count,
            &mut visited_values,
            &mut owner_by_value,
            &mut value_by_term,
            budget,
        )? {
            return Ok(None);
        }
    }
    Ok(Some(value_by_term))
}

fn augment_matching(
    term_index: usize,
    domains: &[HallDomainRecord],
    value_count: usize,
    visited_values: &mut u8,
    owner_by_value: &mut [Option<usize>; MAX_HALL_VALUES],
    value_by_term: &mut [Option<u8>; MAX_HALL_TERMS],
    budget: &mut PropagationBudget,
) -> Result<bool, HallError> {
    for value in 0..value_count {
        let value_bit = 1u8
            .checked_shl(
                u32::try_from(value).map_err(|_| HallError::ArithmeticOverflow {
                    resource: HallResource::Values,
                })?,
            )
            .ok_or(HallError::ArithmeticOverflow {
                resource: HallResource::Values,
            })?;
        if domains[term_index].values & value_bit == 0 {
            continue;
        }
        budget.charge_matching()?;
        if *visited_values & value_bit != 0 {
            continue;
        }
        *visited_values |= value_bit;
        let previous_owner = owner_by_value[value];
        let can_reassign = match previous_owner {
            None => true,
            Some(owner) => augment_matching(
                owner,
                domains,
                value_count,
                visited_values,
                owner_by_value,
                value_by_term,
                budget,
            )?,
        };
        if can_reassign {
            owner_by_value[value] = Some(term_index);
            value_by_term[term_index] =
                Some(
                    u8::try_from(value).map_err(|_| HallError::ArithmeticOverflow {
                        resource: HallResource::Values,
                    })?,
                );
            return Ok(true);
        }
    }
    Ok(false)
}

fn producer_neighborhood(domains: &[HallDomainRecord], subset: usize) -> u8 {
    let mut neighborhood = 0u8;
    for (index, record) in domains.iter().enumerate() {
        if subset & (1usize << index) != 0 {
            neighborhood |= record.values;
        }
    }
    neighborhood
}

fn clone_record_checked(
    record: &HallDomainRecord,
    context: &'static str,
) -> Result<HallDomainRecord, HallError> {
    let mut restrictions = Vec::new();
    restrictions
        .try_reserve_exact(record.restrictions.len())
        .map_err(|_| HallError::AllocationFailed {
            context,
            requested: record.restrictions.len(),
        })?;
    restrictions.extend_from_slice(&record.restrictions);
    Ok(HallDomainRecord {
        term: record.term,
        values: record.values,
        restrictions,
    })
}

fn validate_term_universe(term_universe: u64) -> Result<(), HallError> {
    if term_universe > MAX_TERM_UNIVERSE {
        Err(HallError::TermUniverseTooLarge {
            observed: term_universe,
            limit: MAX_TERM_UNIVERSE,
        })
    } else {
        Ok(())
    }
}

fn validate_term(term: HallTermId, term_universe: u64) -> Result<(), HallError> {
    if u64::from(term.raw()) >= term_universe {
        Err(HallError::TermOutOfRange {
            term,
            term_universe,
        })
    } else {
        Ok(())
    }
}

fn validate_domain_mask(term: HallTermId, values: u8, valid_values: u8) -> Result<(), HallError> {
    if values & !valid_values != 0 {
        Err(HallError::DomainMaskOutOfRange {
            term,
            bits: values & !valid_values,
        })
    } else {
        Ok(())
    }
}

fn validate_domain_record(record: &HallDomainRecord, valid_values: u8) -> Result<(), HallError> {
    validate_domain_mask(record.term, record.values, valid_values)?;
    if record.restrictions.is_empty() {
        return Err(HallError::InvariantViolation(
            "domain has no source restriction",
        ));
    }
    if record.restrictions.len() > MAX_RESTRICTIONS_PER_TERM {
        return Err(HallError::InvariantViolation(
            "domain has too many strict source restrictions",
        ));
    }
    let mut reconstructed = valid_values;
    for (index, restriction) in record.restrictions.iter().copied().enumerate() {
        validate_domain_mask(record.term, restriction.allowed_values, valid_values)?;
        let next = reconstructed & restriction.allowed_values;
        if index > 0 && next == reconstructed {
            return Err(HallError::InvariantViolation(
                "stored source restriction does not narrow its domain",
            ));
        }
        reconstructed = next;
    }
    if reconstructed != record.values {
        return Err(HallError::InvariantViolation(
            "stored source restrictions do not reconstruct the domain",
        ));
    }
    Ok(())
}

fn low_value_mask(value_count: usize) -> Result<u8, HallError> {
    if value_count > MAX_HALL_VALUES {
        return Err(HallError::CapExceeded {
            resource: HallResource::Values,
            attempted: value_count,
            limit: MAX_HALL_VALUES,
        });
    }
    Ok(if value_count == MAX_HALL_VALUES {
        u8::MAX
    } else if value_count == 0 {
        0
    } else {
        (1u8 << value_count) - 1
    })
}

fn subset_end(term_count: usize) -> Result<usize, HallError> {
    let shift = u32::try_from(term_count).map_err(|_| HallError::ArithmeticOverflow {
        resource: HallResource::SubsetChecks,
    })?;
    1usize
        .checked_shl(shift)
        .ok_or(HallError::ArithmeticOverflow {
            resource: HallResource::SubsetChecks,
        })
}

fn checked_add(left: usize, right: usize, resource: HallResource) -> Result<usize, HallError> {
    left.checked_add(right)
        .ok_or(HallError::ArithmeticOverflow { resource })
}

fn enforce_cap(resource: HallResource, attempted: usize, limit: usize) -> Result<(), HallError> {
    if attempted > limit {
        Err(HallError::CapExceeded {
            resource,
            attempted,
            limit,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP_REASON: SourceReasonId = SourceReasonId::new(10_000);

    fn term(index: usize) -> HallTermId {
        HallTermId::new(u32::try_from(index).unwrap())
    }

    fn inputs(domains: &[u8]) -> Vec<HallDomainInput> {
        domains
            .iter()
            .copied()
            .enumerate()
            .map(|(index, values)| {
                HallDomainInput::new(term(index), values, SourceReasonId::new(100 + index as u64))
            })
            .collect()
    }

    fn state(domains: &[u8], value_count: usize) -> RollbackHall {
        RollbackHall::new(
            u64::try_from(domains.len()).unwrap(),
            value_count,
            GROUP_REASON,
            &inputs(domains),
        )
        .unwrap()
    }

    fn brute_force_supported(domains: &[u8], value_count: usize) -> (bool, Vec<u8>) {
        fn visit(
            variable: usize,
            domains: &[u8],
            value_count: usize,
            used: u8,
            assignment: &mut [u8],
            supported: &mut [u8],
            found: &mut bool,
        ) {
            if variable == domains.len() {
                *found = true;
                for (index, &value) in assignment.iter().enumerate() {
                    supported[index] |= 1u8 << value;
                }
                return;
            }
            for value in 0..value_count {
                let bit = 1u8 << value;
                if domains[variable] & bit == 0 || used & bit != 0 {
                    continue;
                }
                assignment[variable] = u8::try_from(value).unwrap();
                visit(
                    variable + 1,
                    domains,
                    value_count,
                    used | bit,
                    assignment,
                    supported,
                    found,
                );
            }
        }

        let mut supported = vec![0u8; domains.len()];
        let mut assignment = vec![0u8; domains.len()];
        let mut found = false;
        visit(
            0,
            domains,
            value_count,
            0,
            &mut assignment,
            &mut supported,
            &mut found,
        );
        (found, supported)
    }

    fn assert_matching(domains: &[u8], matching: &[HallMatch]) {
        assert_eq!(matching.len(), domains.len());
        let mut used = 0u8;
        for entry in matching {
            let index = usize::try_from(entry.term.raw()).unwrap();
            let bit = 1u8 << entry.value;
            assert_ne!(domains[index] & bit, 0);
            assert_eq!(used & bit, 0);
            used |= bit;
        }
    }

    #[test]
    fn exhaustive_differential_against_brute_force_through_size_four() {
        for size in 1usize..=4 {
            let graph_count = 1usize << (size * size);
            let domain_mask = (1usize << size) - 1;
            for graph in 0..graph_count {
                let domains: Vec<u8> = (0..size)
                    .map(|index| ((graph >> (index * size)) & domain_mask) as u8)
                    .collect();
                let (has_matching, supported) = brute_force_supported(&domains, size);
                let hall = state(&domains, size);
                let result = hall
                    .propagate()
                    .unwrap_or_else(|error| panic!("size {size}, graph {graph:#x}: {error}"));
                match result {
                    HallPropagation::Conflict { witness } => {
                        assert!(!has_matching, "size {size}, graph {graph:#x}");
                        let checked = checker::replay(
                            u64::try_from(size).unwrap(),
                            &witness,
                            HallCaps::default(),
                        )
                        .unwrap();
                        assert_eq!(checked.conclusion(), CheckedHallConclusion::Conflict);
                        checker::replay_against(
                            u64::try_from(size).unwrap(),
                            size,
                            GROUP_REASON,
                            hall.domains(),
                            &witness,
                            HallCaps::default(),
                        )
                        .unwrap();
                    }
                    HallPropagation::Consistent {
                        matching,
                        removals,
                        filtered_domains,
                    } => {
                        assert!(has_matching, "size {size}, graph {graph:#x}");
                        assert_matching(&domains, &matching);
                        let mut observed_removed = vec![0u8; size];
                        for removal in &removals {
                            let index = usize::try_from(removal.term.raw()).unwrap();
                            assert_eq!(observed_removed[index] & removal.values, 0);
                            observed_removed[index] |= removal.values;
                            let checked = checker::replay(
                                u64::try_from(size).unwrap(),
                                &removal.witness,
                                HallCaps::default(),
                            )
                            .unwrap();
                            assert_eq!(
                                checked.conclusion(),
                                CheckedHallConclusion::RemoveValues {
                                    term: removal.term,
                                    values: removal.values,
                                }
                            );
                        }
                        for index in 0..size {
                            assert_eq!(
                                observed_removed[index],
                                domains[index] & !supported[index],
                                "size {size}, graph {graph:#x}, term {index}"
                            );
                            assert_eq!(
                                filtered_domains[index].values, supported[index],
                                "size {size}, graph {graph:#x}, term {index}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn rollback_restores_masks_reasons_and_branch_lineage() {
        let mut hall = state(&[0b111, 0b111, 0b111], 3);
        let root = hall.snapshot();
        assert_eq!(root.depth(), 0);
        assert_eq!(
            hall.narrow(term(0), 0b001, SourceReasonId::new(200)),
            Ok(HallDomainMutation::Narrowed {
                previous: 0b111,
                current: 0b001,
            })
        );
        let first_branch = hall.checkpoint();
        assert_eq!(hall.domain(term(0)).unwrap().restrictions().len(), 2);
        hall.narrow(term(1), 0b010, SourceReasonId::new(201))
            .unwrap();
        let discarded = hall.snapshot();

        let HallPropagation::Consistent {
            filtered_domains, ..
        } = hall.propagate().unwrap()
        else {
            panic!("expected a consistent three-value group");
        };
        assert_eq!(filtered_domains[2].values, 0b100);

        assert_eq!(hall.restore(first_branch), Ok(1));
        assert_eq!(hall.domain(term(1)).unwrap().values(), 0b111);
        assert_eq!(hall.domain(term(1)).unwrap().restrictions().len(), 1);
        hall.narrow(term(2), 0b100, SourceReasonId::new(202))
            .unwrap();
        assert_eq!(
            hall.restore(discarded),
            Err(HallError::InvalidSnapshot(
                HallSnapshotError::DiscardedBranch
            ))
        );
        assert_eq!(hall.restore(root), Ok(2));
        assert_eq!(
            hall.domains()
                .iter()
                .map(HallDomainRecord::values)
                .collect::<Vec<_>>(),
            vec![0b111, 0b111, 0b111]
        );
        assert!(
            hall.domains()
                .iter()
                .all(|record| record.restrictions().len() == 1)
        );

        let other = state(&[0b1], 1);
        assert_eq!(
            hall.restore(other.snapshot()),
            Err(HallError::InvalidSnapshot(HallSnapshotError::ForeignState))
        );
    }

    #[test]
    fn redundant_narrowing_does_not_consume_trail_or_reason() {
        let mut hall = state(&[0b01, 0b11], 2);
        let before = hall.snapshot();
        assert_eq!(
            hall.narrow(term(0), 0b11, SourceReasonId::MAX),
            Ok(HallDomainMutation::Unchanged { values: 0b01 })
        );
        assert_eq!(hall.snapshot(), before);
        assert_eq!(hall.domain(term(0)).unwrap().restrictions().len(), 1);
    }

    #[test]
    fn witness_mutations_are_rejected_by_independent_checker() {
        let conflict_state = state(&[0b01, 0b01], 2);
        let HallPropagation::Conflict { witness } = conflict_state.propagate().unwrap() else {
            panic!("expected conflict");
        };
        checker::replay(2, &witness, HallCaps::default()).unwrap();

        let mut bad_version = witness.clone();
        bad_version.version += 1;
        assert!(matches!(
            checker::replay(2, &bad_version, HallCaps::default()),
            Err(HallCheckError::UnsupportedVersion { .. })
        ));

        let mut bad_neighborhood = witness.clone();
        bad_neighborhood.claimed_neighborhood = 0b11;
        assert!(matches!(
            checker::replay(2, &bad_neighborhood, HallCaps::default()),
            Err(HallCheckError::NeighborhoodMismatch { .. })
        ));

        let mut bad_domain = witness.clone();
        bad_domain.premises[0].values = 0b11;
        assert!(matches!(
            checker::replay(2, &bad_domain, HallCaps::default()),
            Err(HallCheckError::ReconstructedDomainMismatch { .. })
        ));

        let mut bad_reason = witness.clone();
        bad_reason.premises[0].restrictions[0].reason = SourceReasonId::new(999);
        assert!(checker::replay(2, &bad_reason, HallCaps::default()).is_ok());
        assert!(matches!(
            checker::replay_against(
                2,
                2,
                GROUP_REASON,
                conflict_state.domains(),
                &bad_reason,
                HallCaps::default(),
            ),
            Err(HallCheckError::BoundDomainMismatch { .. })
        ));

        let mut bad_value_count = witness.clone();
        bad_value_count.value_count = 3;
        assert!(checker::replay(2, &bad_value_count, HallCaps::default()).is_ok());
        assert!(matches!(
            checker::replay_against(
                2,
                2,
                GROUP_REASON,
                conflict_state.domains(),
                &bad_value_count,
                HallCaps::default(),
            ),
            Err(HallCheckError::BoundValueCountMismatch {
                expected: 2,
                observed: 3,
            })
        ));

        let removal_state = state(&[0b001, 0b011, 0b110], 3);
        let HallPropagation::Consistent { removals, .. } = removal_state.propagate().unwrap()
        else {
            panic!("expected propagation");
        };
        let removal = removals
            .iter()
            .find(|removal| removal.term == term(2) && removal.values & 0b010 != 0)
            .unwrap();
        let mut outside_neighborhood = removal.witness.clone();
        let HallConclusion::RemoveValues { values, .. } = &mut outside_neighborhood.conclusion
        else {
            unreachable!();
        };
        *values = 0b100;
        assert!(matches!(
            checker::replay(3, &outside_neighborhood, HallCaps::default()),
            Err(HallCheckError::RemovalOutsideNeighborhood { .. })
        ));

        let mut target_in_subset = removal.witness.clone();
        let HallConclusion::RemoveValues { target, .. } = &mut target_in_subset.conclusion else {
            unreachable!();
        };
        *target = target_in_subset.premises[0].clone();
        assert!(matches!(
            checker::replay(3, &target_in_subset, HallCaps::default()),
            Err(HallCheckError::RemovalTargetInsidePremises { .. })
        ));
    }

    #[test]
    fn malformed_ids_masks_duplicates_and_caps_fail_closed() {
        let duplicate = [
            HallDomainInput::new(term(0), 0b1, SourceReasonId::new(1)),
            HallDomainInput::new(term(0), 0b1, SourceReasonId::new(2)),
        ];
        assert!(matches!(
            RollbackHall::new(1, 1, GROUP_REASON, &duplicate),
            Err(HallError::DuplicateTerm { term: duplicate }) if duplicate == term(0)
        ));
        assert!(matches!(
            RollbackHall::new(
                1,
                1,
                GROUP_REASON,
                &[HallDomainInput::new(term(1), 0b1, SourceReasonId::new(1))],
            ),
            Err(HallError::TermOutOfRange {
                term: observed,
                term_universe: 1,
            }) if observed == term(1)
        ));
        assert!(matches!(
            RollbackHall::new(
                1,
                1,
                GROUP_REASON,
                &[HallDomainInput::new(term(0), 0b10, SourceReasonId::new(1))],
            ),
            Err(HallError::DomainMaskOutOfRange {
                term: observed,
                bits: 0b10,
            }) if observed == term(0)
        ));
        assert!(matches!(
            RollbackHall::new(MAX_TERM_UNIVERSE + 1, 0, GROUP_REASON, &[]),
            Err(HallError::TermUniverseTooLarge { .. })
        ));
        assert!(matches!(
            RollbackHall::new(0, MAX_HALL_VALUES + 1, GROUP_REASON, &[]),
            Err(HallError::CapExceeded {
                resource: HallResource::Values,
                ..
            })
        ));

        let invalid_caps = HallCaps {
            max_terms: MAX_HALL_TERMS + 1,
            ..HallCaps::default()
        };
        assert!(matches!(
            RollbackHall::with_caps(0, 0, GROUP_REASON, &[], invalid_caps),
            Err(HallError::CapAboveHardLimit {
                name: "max_terms",
                ..
            })
        ));

        let term_cap = HallCaps {
            max_terms: 1,
            max_witness_terms: 1,
            ..HallCaps::default()
        };
        assert!(matches!(
            RollbackHall::with_caps(2, 2, GROUP_REASON, &inputs(&[0b11, 0b11]), term_cap),
            Err(HallError::CapExceeded {
                resource: HallResource::Terms,
                ..
            })
        ));
    }

    #[test]
    fn work_removal_witness_and_trail_caps_are_enforced_atomically() {
        let matching_caps = HallCaps {
            max_matching_steps: 0,
            ..HallCaps::default()
        };
        let matching_limited =
            RollbackHall::with_caps(1, 1, GROUP_REASON, &inputs(&[0b1]), matching_caps).unwrap();
        assert!(matches!(
            matching_limited.propagate(),
            Err(HallError::CapExceeded {
                resource: HallResource::MatchingSteps,
                ..
            })
        ));

        let subset_caps = HallCaps {
            max_subset_checks: 0,
            ..HallCaps::default()
        };
        let subset_limited =
            RollbackHall::with_caps(1, 1, GROUP_REASON, &inputs(&[0b1]), subset_caps).unwrap();
        assert!(matches!(
            subset_limited.propagate(),
            Err(HallError::CapExceeded {
                resource: HallResource::SubsetChecks,
                ..
            })
        ));

        let removal_caps = HallCaps {
            max_removals: 0,
            ..HallCaps::default()
        };
        let removal_limited =
            RollbackHall::with_caps(2, 2, GROUP_REASON, &inputs(&[0b01, 0b11]), removal_caps)
                .unwrap();
        assert!(matches!(
            removal_limited.propagate(),
            Err(HallError::CapExceeded {
                resource: HallResource::Removals,
                ..
            })
        ));

        let witness_caps = HallCaps {
            max_witness_terms: 1,
            ..HallCaps::default()
        };
        let witness_limited =
            RollbackHall::with_caps(2, 2, GROUP_REASON, &inputs(&[0b01, 0b01]), witness_caps)
                .unwrap();
        assert!(matches!(
            witness_limited.propagate(),
            Err(HallError::CapExceeded {
                resource: HallResource::WitnessTerms,
                ..
            })
        ));

        let trail_caps = HallCaps {
            max_trail_entries: 0,
            ..HallCaps::default()
        };
        let mut trail_limited =
            RollbackHall::with_caps(1, 2, GROUP_REASON, &inputs(&[0b11]), trail_caps).unwrap();
        let before = trail_limited.snapshot();
        assert!(matches!(
            trail_limited.narrow(term(0), 0b01, SourceReasonId::new(7)),
            Err(HallError::CapExceeded {
                resource: HallResource::TrailEntries,
                ..
            })
        ));
        assert_eq!(trail_limited.snapshot(), before);
        assert_eq!(trail_limited.domain(term(0)).unwrap().values(), 0b11);
    }

    #[test]
    fn lineage_overflow_fails_before_mutation() {
        let mut hall = state(&[0b11], 2);
        hall.next_lineage_id = u64::MAX;
        let before = hall.domains().to_vec();
        assert_eq!(
            hall.narrow(term(0), 0b01, SourceReasonId::MAX),
            Err(HallError::SnapshotStateIdExhausted)
        );
        assert_eq!(hall.domains(), before);
        assert_eq!(hall.trail.len(), 0);
    }

    #[test]
    fn zero_value_and_empty_groups_have_total_semantics() {
        let empty = state(&[], 0);
        assert!(matches!(
            empty.propagate().unwrap(),
            HallPropagation::Consistent {
                matching,
                removals,
                filtered_domains,
            } if matching.is_empty() && removals.is_empty() && filtered_domains.is_empty()
        ));

        let impossible = state(&[0], 0);
        let HallPropagation::Conflict { witness } = impossible.propagate().unwrap() else {
            panic!("an empty domain must conflict");
        };
        assert_eq!(witness.claimed_neighborhood(), 0);
        checker::replay(1, &witness, HallCaps::default()).unwrap();
    }
}
