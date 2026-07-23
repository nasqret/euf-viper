#![cfg(test)]
#![forbid(unsafe_code)]

//! Exhaustive, bounded Latin-table search by whole column permutations.
//!
//! This module is a test-only reference search. It is intentionally absent
//! from the production module graph. Columns are drawn from lexicographically
//! ordered permutations, while row-used masks enforce the other Latin axis.
//! Any incomplete traversal, including an oracle failure, is an abstention.

use crate::orbit_canon::BinaryTable;
use std::array;
use std::error::Error;
use std::fmt;

pub(crate) const MAX_ORDER: usize = 8;
const MAX_CELLS: usize = MAX_ORDER * MAX_ORDER;
const MAX_PERMUTATIONS: usize = 40_320;
const MAX_PERMUTATION_WORDS: usize =
    (MAX_PERMUTATIONS + u64::BITS as usize - 1) / u64::BITS as usize;

pub(crate) const HARD_MAX_ORACLE_CALLS: u64 = 10_000_000;
pub(crate) const HARD_MAX_NODES: u64 = 10_000_000;
pub(crate) const HARD_MAX_CANDIDATES: u64 = 1_000_000_000;
pub(crate) const HARD_MAX_PARTIAL_CONFLICTS: u64 = 10_000_000;
pub(crate) const HARD_MAX_LATIN_CONFLICTS: u64 = 1_000_000_000;
pub(crate) const HARD_MAX_COMPLETE_TABLES: u64 = 10_000_000;

const TRACE_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const TRACE_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Test oracle used by the exhaustive column search.
///
/// `partial_conflict` always receives exactly `order * order` row-major masks.
/// Every mask is nonzero and contains only values below `order`. A returned
/// token is a trusted claim that no accepted complete table is consistent with
/// the represented domains. The search only counts and drops the token; proof
/// certificates are deliberately outside this module's current scope.
///
/// `validate_complete` is the exact acceptance boundary. It is called for
/// every complete Latin table that survives partial pruning, and `true` is the
/// only way this search can return [`SearchOutcome::Sat`].
pub(crate) trait FiniteColumnOracle {
    type PartialConflictToken;
    type Error;

    fn root_column_pruning_enabled(&self) -> bool {
        false
    }

    fn root_column_conflict(
        &mut self,
        _column: usize,
        _values_by_row: &[u8],
    ) -> Result<Option<Self::PartialConflictToken>, Self::Error> {
        Ok(None)
    }

    fn partial_conflict(
        &mut self,
        row_major_domains: &[u8],
    ) -> Result<Option<Self::PartialConflictToken>, Self::Error>;

    fn validate_complete(&mut self, table: &BinaryTable) -> Result<bool, Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SearchCaps {
    pub(crate) max_oracle_calls: u64,
    pub(crate) max_nodes: u64,
    pub(crate) max_candidates: u64,
    pub(crate) max_partial_conflicts: u64,
    pub(crate) max_latin_conflicts: u64,
    pub(crate) max_complete_tables: u64,
}

impl Default for SearchCaps {
    fn default() -> Self {
        Self {
            max_oracle_calls: 1_000_000,
            max_nodes: 1_000_000,
            max_candidates: 50_000_000,
            max_partial_conflicts: 1_000_000,
            max_latin_conflicts: 50_000_000,
            max_complete_tables: 1_000_000,
        }
    }
}

impl SearchCaps {
    pub(crate) const fn hard() -> Self {
        Self {
            max_oracle_calls: HARD_MAX_ORACLE_CALLS,
            max_nodes: HARD_MAX_NODES,
            max_candidates: HARD_MAX_CANDIDATES,
            max_partial_conflicts: HARD_MAX_PARTIAL_CONFLICTS,
            max_latin_conflicts: HARD_MAX_LATIN_CONFLICTS,
            max_complete_tables: HARD_MAX_COMPLETE_TABLES,
        }
    }

    fn get(self, resource: SearchResource) -> u64 {
        match resource {
            SearchResource::OracleCalls => self.max_oracle_calls,
            SearchResource::Nodes => self.max_nodes,
            SearchResource::Candidates => self.max_candidates,
            SearchResource::PartialConflicts => self.max_partial_conflicts,
            SearchResource::LatinConflicts => self.max_latin_conflicts,
            SearchResource::CompleteTables => self.max_complete_tables,
        }
    }

    fn validate(self) -> Result<(), SearchAbstention> {
        for resource in SearchResource::ALL {
            let observed = self.get(resource);
            let hard_limit = resource.hard_limit();
            if observed > hard_limit {
                return Err(SearchAbstention::CapAboveHardLimit {
                    resource,
                    observed,
                    hard_limit,
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SearchResource {
    OracleCalls,
    Nodes,
    Candidates,
    PartialConflicts,
    LatinConflicts,
    CompleteTables,
}

impl SearchResource {
    const ALL: [Self; 6] = [
        Self::OracleCalls,
        Self::Nodes,
        Self::Candidates,
        Self::PartialConflicts,
        Self::LatinConflicts,
        Self::CompleteTables,
    ];

    const fn hard_limit(self) -> u64 {
        match self {
            Self::OracleCalls => HARD_MAX_ORACLE_CALLS,
            Self::Nodes => HARD_MAX_NODES,
            Self::Candidates => HARD_MAX_CANDIDATES,
            Self::PartialConflicts => HARD_MAX_PARTIAL_CONFLICTS,
            Self::LatinConflicts => HARD_MAX_LATIN_CONFLICTS,
            Self::CompleteTables => HARD_MAX_COMPLETE_TABLES,
        }
    }

    const fn trace_code(self) -> u64 {
        match self {
            Self::OracleCalls => 1,
            Self::Nodes => 2,
            Self::Candidates => 3,
            Self::PartialConflicts => 4,
            Self::LatinConflicts => 5,
            Self::CompleteTables => 6,
        }
    }
}

impl fmt::Display for SearchResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::OracleCalls => "oracle calls",
            Self::Nodes => "search nodes",
            Self::Candidates => "column candidates",
            Self::PartialConflicts => "partial conflicts",
            Self::LatinConflicts => "Latin conflicts",
            Self::CompleteTables => "complete tables",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SearchInputError {
    InvalidOrder {
        observed: usize,
        maximum: usize,
    },
    WrongDomainCount {
        order: usize,
        expected: usize,
        actual: usize,
    },
    EmptyDomain {
        cell: usize,
    },
    DomainValueOutOfRange {
        cell: usize,
        domain: u8,
        valid_mask: u8,
    },
}

impl fmt::Display for SearchInputError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOrder { observed, maximum } => write!(
                output,
                "Latin-table order is {observed}; expected 1..={maximum}"
            ),
            Self::WrongDomainCount {
                order,
                expected,
                actual,
            } => write!(
                output,
                "order-{order} search needs {expected} cell domains, but received {actual}"
            ),
            Self::EmptyDomain { cell } => write!(output, "cell {cell} has an empty domain"),
            Self::DomainValueOutOfRange {
                cell,
                domain,
                valid_mask,
            } => write!(
                output,
                "cell {cell} domain {domain:#010b} contains values outside {valid_mask:#010b}"
            ),
        }
    }
}

impl Error for SearchInputError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OracleStage {
    Partial,
    Complete,
}

impl fmt::Display for OracleStage {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Partial => "partial-conflict",
            Self::Complete => "complete-table",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SearchAbstention {
    InvalidInput(SearchInputError),
    CapAboveHardLimit {
        resource: SearchResource,
        observed: u64,
        hard_limit: u64,
    },
    CapExceeded {
        resource: SearchResource,
        attempted: u64,
        limit: u64,
    },
    CounterOverflow {
        resource: SearchResource,
    },
    ArithmeticOverflow {
        context: &'static str,
    },
    AllocationFailed {
        context: &'static str,
        requested: usize,
    },
    OracleError {
        stage: OracleStage,
        call: u64,
    },
    InvariantViolation(&'static str),
}

impl fmt::Display for SearchAbstention {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(error) => error.fmt(output),
            Self::CapAboveHardLimit {
                resource,
                observed,
                hard_limit,
            } => write!(
                output,
                "configured {resource} cap {observed} exceeds hard limit {hard_limit}"
            ),
            Self::CapExceeded {
                resource,
                attempted,
                limit,
            } => write!(
                output,
                "{resource} cap exceeded: attempted {attempted}, limit {limit}"
            ),
            Self::CounterOverflow { resource } => {
                write!(output, "{resource} counter overflowed")
            }
            Self::ArithmeticOverflow { context } => {
                write!(output, "arithmetic overflow while computing {context}")
            }
            Self::AllocationFailed { context, requested } => write!(
                output,
                "allocation failed for {context} while requesting {requested} entries"
            ),
            Self::OracleError { stage, call } => {
                write!(output, "{stage} oracle call {call} failed")
            }
            Self::InvariantViolation(message) => {
                write!(output, "finite column search invariant failed: {message}")
            }
        }
    }
}

impl Error for SearchAbstention {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidInput(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SearchOutcome {
    Sat(BinaryTable),
    Unsat,
    Abstain(SearchAbstention),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SearchTelemetry {
    pub(crate) oracle_calls: u64,
    pub(crate) nodes: u64,
    /// Root prefilter and dynamic-MRV column candidates inspected.
    pub(crate) candidates: u64,
    pub(crate) partial_conflicts: u64,
    pub(crate) latin_conflicts: u64,
    pub(crate) complete_tables: u64,
    pub(crate) max_depth: u8,
    pub(crate) trace_hash: u64,
}

impl Default for SearchTelemetry {
    fn default() -> Self {
        Self {
            oracle_calls: 0,
            nodes: 0,
            candidates: 0,
            partial_conflicts: 0,
            latin_conflicts: 0,
            complete_tables: 0,
            max_depth: 0,
            trace_hash: TRACE_OFFSET,
        }
    }
}

impl SearchTelemetry {
    fn get(self, resource: SearchResource) -> u64 {
        match resource {
            SearchResource::OracleCalls => self.oracle_calls,
            SearchResource::Nodes => self.nodes,
            SearchResource::Candidates => self.candidates,
            SearchResource::PartialConflicts => self.partial_conflicts,
            SearchResource::LatinConflicts => self.latin_conflicts,
            SearchResource::CompleteTables => self.complete_tables,
        }
    }

    fn set(&mut self, resource: SearchResource, value: u64) {
        match resource {
            SearchResource::OracleCalls => self.oracle_calls = value,
            SearchResource::Nodes => self.nodes = value,
            SearchResource::Candidates => self.candidates = value,
            SearchResource::PartialConflicts => self.partial_conflicts = value,
            SearchResource::LatinConflicts => self.latin_conflicts = value,
            SearchResource::CompleteTables => self.complete_tables = value,
        }
    }

    fn mix(&mut self, tag: u8, value: u64) {
        self.trace_hash ^= u64::from(tag);
        self.trace_hash = self.trace_hash.wrapping_mul(TRACE_PRIME);
        for byte in value.to_le_bytes() {
            self.trace_hash ^= u64::from(byte);
            self.trace_hash = self.trace_hash.wrapping_mul(TRACE_PRIME);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SearchReport {
    pub(crate) outcome: SearchOutcome,
    pub(crate) telemetry: SearchTelemetry,
}

/// Searches with conservative defaults. Exhaustion under those defaults is
/// reported as [`SearchOutcome::Abstain`], never as UNSAT.
pub(crate) fn search<O: FiniteColumnOracle>(
    order: usize,
    row_major_domains: &[u8],
    oracle: &mut O,
) -> SearchReport {
    search_with_caps(order, row_major_domains, oracle, SearchCaps::default())
}

/// Exhaustively searches all Latin tables represented by the root domains.
///
/// UNSAT means every such table was either rejected exactly or was pruned by a
/// sound partial-conflict token. Any resource or oracle failure aborts the
/// entire traversal with an explicit abstention.
pub(crate) fn search_with_caps<O: FiniteColumnOracle>(
    order: usize,
    row_major_domains: &[u8],
    oracle: &mut O,
    caps: SearchCaps,
) -> SearchReport {
    let mut telemetry = SearchTelemetry::default();
    telemetry.mix(1, usize_trace_value(order));

    let valid_mask = match validate_input(order, row_major_domains) {
        Ok(mask) => mask,
        Err(error) => {
            return immediate_abstention(telemetry, SearchAbstention::InvalidInput(error));
        }
    };
    for (cell, &domain) in row_major_domains.iter().enumerate() {
        telemetry.mix(2, usize_trace_value(cell));
        telemetry.mix(3, u64::from(domain));
    }
    if let Err(reason) = caps.validate() {
        return immediate_abstention(telemetry, reason);
    }

    let mut engine = SearchEngine {
        order,
        valid_mask,
        root_domains: row_major_domains,
        oracle,
        caps,
        telemetry,
        permutations: Vec::new(),
        column_candidate_bits: array::from_fn(|_| Vec::new()),
        column_candidate_counts: [0; MAX_ORDER],
        row_value_bits: array::from_fn(|_| array::from_fn(|_| Vec::new())),
    };
    let result = engine.run();
    engine.finish(result)
}

fn validate_input(order: usize, domains: &[u8]) -> Result<u8, SearchInputError> {
    if order == 0 || order > MAX_ORDER {
        return Err(SearchInputError::InvalidOrder {
            observed: order,
            maximum: MAX_ORDER,
        });
    }
    let expected = order * order;
    if domains.len() != expected {
        return Err(SearchInputError::WrongDomainCount {
            order,
            expected,
            actual: domains.len(),
        });
    }
    let valid_mask = low_mask(order);
    for (cell, &domain) in domains.iter().enumerate() {
        if domain == 0 {
            return Err(SearchInputError::EmptyDomain { cell });
        }
        if domain & !valid_mask != 0 {
            return Err(SearchInputError::DomainValueOutOfRange {
                cell,
                domain,
                valid_mask,
            });
        }
    }
    Ok(valid_mask)
}

const fn low_mask(order: usize) -> u8 {
    ((1u16 << order) - 1) as u8
}

fn usize_trace_value(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn immediate_abstention(mut telemetry: SearchTelemetry, reason: SearchAbstention) -> SearchReport {
    telemetry.mix(250, abstention_trace_code(&reason));
    SearchReport {
        outcome: SearchOutcome::Abstain(reason),
        telemetry,
    }
}

fn abstention_trace_code(reason: &SearchAbstention) -> u64 {
    match reason {
        SearchAbstention::InvalidInput(_) => 1,
        SearchAbstention::CapAboveHardLimit { resource, .. } => 10 + resource.trace_code(),
        SearchAbstention::CapExceeded { resource, .. } => 20 + resource.trace_code(),
        SearchAbstention::CounterOverflow { resource } => 30 + resource.trace_code(),
        SearchAbstention::ArithmeticOverflow { .. } => 40,
        SearchAbstention::AllocationFailed { .. } => 41,
        SearchAbstention::OracleError { stage, .. } => match stage {
            OracleStage::Partial => 42,
            OracleStage::Complete => 43,
        },
        SearchAbstention::InvariantViolation(_) => 44,
    }
}

#[derive(Clone, Copy, Debug)]
struct ColumnPermutation {
    values: [u8; MAX_ORDER],
}

struct CompatibleCandidates {
    words: [u64; MAX_PERMUTATION_WORDS],
    unions: [u8; MAX_ORDER],
    count: usize,
}

struct SearchEngine<'a, O> {
    order: usize,
    valid_mask: u8,
    root_domains: &'a [u8],
    oracle: &'a mut O,
    caps: SearchCaps,
    telemetry: SearchTelemetry,
    permutations: Vec<ColumnPermutation>,
    column_candidate_bits: [Vec<u64>; MAX_ORDER],
    column_candidate_counts: [usize; MAX_ORDER],
    row_value_bits: [[Vec<u64>; MAX_ORDER]; MAX_ORDER],
}

impl<O: FiniteColumnOracle> SearchEngine<'_, O> {
    fn run(&mut self) -> Result<Option<BinaryTable>, SearchAbstention> {
        self.build_lexicographic_permutations()?;
        if !self.prefilter_columns()? {
            return Ok(None);
        }
        self.build_row_value_index()?;

        let mut table = [0u8; MAX_CELLS];
        let mut assigned = [false; MAX_ORDER];
        let mut row_used = [0u8; MAX_ORDER];
        self.visit(&mut table, &mut assigned, &mut row_used, 0)
    }

    fn finish(mut self, result: Result<Option<BinaryTable>, SearchAbstention>) -> SearchReport {
        let outcome = match result {
            Ok(Some(table)) => {
                self.telemetry.mix(247, 1);
                SearchOutcome::Sat(table)
            }
            Ok(None) => {
                self.telemetry.mix(247, 2);
                SearchOutcome::Unsat
            }
            Err(reason) => {
                self.telemetry.mix(250, abstention_trace_code(&reason));
                SearchOutcome::Abstain(reason)
            }
        };
        SearchReport {
            outcome,
            telemetry: self.telemetry,
        }
    }

    fn charge(&mut self, resource: SearchResource) -> Result<u64, SearchAbstention> {
        self.charge_amount(resource, 1)
    }

    fn charge_amount(
        &mut self,
        resource: SearchResource,
        amount: u64,
    ) -> Result<u64, SearchAbstention> {
        let current = self.telemetry.get(resource);
        if amount == 0 {
            return Ok(current);
        }
        let attempted = current
            .checked_add(amount)
            .ok_or(SearchAbstention::CounterOverflow { resource })?;
        let limit = self.caps.get(resource);
        if attempted > limit {
            self.telemetry.mix(240, resource.trace_code());
            self.telemetry.mix(241, attempted);
            self.telemetry.mix(242, limit);
            return Err(SearchAbstention::CapExceeded {
                resource,
                attempted,
                limit,
            });
        }
        self.telemetry.set(resource, attempted);
        self.telemetry.mix(10, resource.trace_code());
        self.telemetry.mix(11, attempted);
        self.telemetry.mix(12, amount);
        Ok(attempted)
    }

    fn build_lexicographic_permutations(&mut self) -> Result<(), SearchAbstention> {
        let expected = checked_factorial(self.order)?;
        if expected > MAX_PERMUTATIONS {
            return Err(SearchAbstention::InvariantViolation(
                "permutation count exceeds the fixed order-eight bound",
            ));
        }
        self.permutations.try_reserve_exact(expected).map_err(|_| {
            SearchAbstention::AllocationFailed {
                context: "lexicographic column permutations",
                requested: expected,
            }
        })?;

        let mut values = [0u8; MAX_ORDER];
        for (value, slot) in values[..self.order].iter_mut().enumerate() {
            *slot = value as u8;
        }
        loop {
            self.permutations.push(ColumnPermutation { values });
            if !advance_lexicographic_permutation(&mut values[..self.order]) {
                break;
            }
        }
        if self.permutations.len() != expected {
            return Err(SearchAbstention::InvariantViolation(
                "lexicographic permutation enumeration has the wrong cardinality",
            ));
        }
        Ok(())
    }

    /// Returns false only after proving that a root column has no permutation.
    fn prefilter_columns(&mut self) -> Result<bool, SearchAbstention> {
        let word_count = self.permutation_word_count();
        for column in 0..self.order {
            let mut candidate_bits = Vec::new();
            candidate_bits.try_reserve_exact(word_count).map_err(|_| {
                SearchAbstention::AllocationFailed {
                    context: "root column candidate bitset",
                    requested: word_count,
                }
            })?;
            candidate_bits.resize(word_count, 0);
            let mut candidate_count = 0usize;

            for permutation_index in 0..self.permutations.len() {
                self.charge(SearchResource::Candidates)?;
                let permutation = self.permutations[permutation_index];
                let mut allowed = (0..self.order).all(|row| {
                    let cell = row * self.order + column;
                    self.root_domains[cell] & (1u8 << permutation.values[row]) != 0
                });
                if allowed
                    && self.oracle.root_column_pruning_enabled()
                    && self.call_root_column_oracle(column, &permutation.values[..self.order])?
                {
                    allowed = false;
                }
                self.telemetry.mix(20, usize_trace_value(column));
                self.telemetry.mix(21, usize_trace_value(permutation_index));
                self.telemetry.mix(22, u64::from(allowed));
                if allowed {
                    candidate_bits[permutation_index / u64::BITS as usize] |=
                        1u64 << (permutation_index % u64::BITS as usize);
                    candidate_count = candidate_count.checked_add(1).ok_or(
                        SearchAbstention::ArithmeticOverflow {
                            context: "root column candidate count",
                        },
                    )?;
                }
            }
            if candidate_count == 0 {
                self.telemetry.mix(23, usize_trace_value(column));
                return Ok(false);
            }
            self.column_candidate_bits[column] = candidate_bits;
            self.column_candidate_counts[column] = candidate_count;
        }
        Ok(true)
    }

    fn build_row_value_index(&mut self) -> Result<(), SearchAbstention> {
        let word_count = self.permutation_word_count();
        for row in 0..self.order {
            for value in 0..self.order {
                let mut bits = Vec::new();
                bits.try_reserve_exact(word_count).map_err(|_| {
                    SearchAbstention::AllocationFailed {
                        context: "row-value permutation bitset",
                        requested: word_count,
                    }
                })?;
                bits.resize(word_count, 0);
                for (permutation_index, permutation) in self.permutations.iter().enumerate() {
                    if usize::from(permutation.values[row]) == value {
                        bits[permutation_index / u64::BITS as usize] |=
                            1u64 << (permutation_index % u64::BITS as usize);
                    }
                }
                self.row_value_bits[row][value] = bits;
            }
        }
        Ok(())
    }

    fn permutation_word_count(&self) -> usize {
        self.permutations.len().div_ceil(u64::BITS as usize)
    }

    fn compatible_candidates(
        &mut self,
        column: usize,
        row_used: &[u8; MAX_ORDER],
    ) -> Result<CompatibleCandidates, SearchAbstention> {
        let word_count = self.permutation_word_count();
        let blocked_values = row_used[..self.order]
            .iter()
            .map(|mask| u64::from(mask.count_ones()))
            .sum::<u64>();
        let word_count_u64 =
            u64::try_from(word_count).map_err(|_| SearchAbstention::ArithmeticOverflow {
                context: "permutation bitset word count",
            })?;
        let bitset_work = word_count_u64.checked_mul(blocked_values + 1).ok_or(
            SearchAbstention::ArithmeticOverflow {
                context: "permutation bitset compatibility work",
            },
        )?;
        self.charge_amount(SearchResource::Candidates, bitset_work)?;

        let mut words = [0u64; MAX_PERMUTATION_WORDS];
        words[..word_count].copy_from_slice(&self.column_candidate_bits[column]);
        for row in 0..self.order {
            let mut blocked = row_used[row];
            while blocked != 0 {
                let value = blocked.trailing_zeros() as usize;
                for (word, value_bits) in words[..word_count]
                    .iter_mut()
                    .zip(&self.row_value_bits[row][value])
                {
                    *word &= !value_bits;
                }
                blocked &= blocked - 1;
            }
        }

        let mut unions = [0u8; MAX_ORDER];
        let mut count = 0usize;
        for (word_index, &candidate_word) in words[..word_count].iter().enumerate() {
            let mut remaining = candidate_word;
            while remaining != 0 {
                let bit = remaining.trailing_zeros() as usize;
                let permutation_index = word_index * u64::BITS as usize + bit;
                let permutation = self.permutations.get(permutation_index).ok_or(
                    SearchAbstention::InvariantViolation(
                        "candidate bitset references a missing permutation",
                    ),
                )?;
                count = count
                    .checked_add(1)
                    .ok_or(SearchAbstention::ArithmeticOverflow {
                        context: "compatible column candidate count",
                    })?;
                for (row, union) in unions[..self.order].iter_mut().enumerate() {
                    *union |= 1u8 << permutation.values[row];
                }
                remaining &= remaining - 1;
            }
        }
        self.charge_amount(
            SearchResource::Candidates,
            u64::try_from(count).map_err(|_| SearchAbstention::ArithmeticOverflow {
                context: "compatible column candidate accounting",
            })?,
        )?;
        if count < self.column_candidate_counts[column] {
            self.charge(SearchResource::LatinConflicts)?;
        }
        self.telemetry.mix(40, usize_trace_value(column));
        self.telemetry.mix(41, usize_trace_value(count));

        Ok(CompatibleCandidates {
            words,
            unions,
            count,
        })
    }

    fn visit(
        &mut self,
        table: &mut [u8; MAX_CELLS],
        assigned: &mut [bool; MAX_ORDER],
        row_used: &mut [u8; MAX_ORDER],
        depth: usize,
    ) -> Result<Option<BinaryTable>, SearchAbstention> {
        self.charge(SearchResource::Nodes)?;
        let depth_u8 = u8::try_from(depth)
            .map_err(|_| SearchAbstention::InvariantViolation("search depth does not fit in u8"))?;
        self.telemetry.max_depth = self.telemetry.max_depth.max(depth_u8);
        self.telemetry.mix(30, usize_trace_value(depth));

        if depth == self.order {
            return self.validate_complete_table(table, row_used);
        }

        let mut partial_domains = [0u8; MAX_CELLS];
        for column in 0..self.order {
            if assigned[column] {
                for row in 0..self.order {
                    let cell = row * self.order + column;
                    partial_domains[cell] = 1u8 << table[cell];
                }
            }
        }

        let mut best_column = None;
        let mut best_count = usize::MAX;
        for column in 0..self.order {
            if assigned[column] {
                continue;
            }
            let compatible = self.compatible_candidates(column, row_used)?;
            if compatible.count == 0 {
                self.telemetry.mix(31, usize_trace_value(column));
                return Ok(None);
            }
            for row in 0..self.order {
                let cell = row * self.order + column;
                partial_domains[cell] = compatible.unions[row];
            }
            if compatible.count < best_count {
                best_count = compatible.count;
                best_column = Some(column);
            }
        }

        let column = best_column.ok_or(SearchAbstention::InvariantViolation(
            "an incomplete node has no unassigned MRV column",
        ))?;
        self.validate_partial_domains(&partial_domains)?;
        if self.call_partial_oracle(&partial_domains)? {
            return Ok(None);
        }

        self.telemetry.mix(32, usize_trace_value(column));
        self.telemetry.mix(33, usize_trace_value(best_count));
        let compatible = self.compatible_candidates(column, row_used)?;
        if compatible.count != best_count {
            return Err(SearchAbstention::InvariantViolation(
                "selected column candidate count changed without an assignment",
            ));
        }
        let word_count = self.permutation_word_count();
        for (word_index, &candidate_word) in compatible.words[..word_count].iter().enumerate() {
            let mut remaining = candidate_word;
            while remaining != 0 {
                let bit = remaining.trailing_zeros() as usize;
                let permutation_index = word_index * u64::BITS as usize + bit;
                let permutation = *self.permutations.get(permutation_index).ok_or(
                    SearchAbstention::InvariantViolation(
                        "selected candidate bitset references a missing permutation",
                    ),
                )?;
                remaining &= remaining - 1;
                self.telemetry.mix(34, usize_trace_value(column));
                self.telemetry.mix(35, usize_trace_value(permutation_index));

                assigned[column] = true;
                for row in 0..self.order {
                    let value = permutation.values[row];
                    let cell = row * self.order + column;
                    table[cell] = value;
                    row_used[row] |= 1u8 << value;
                }

                let child = self.visit(table, assigned, row_used, depth + 1);

                for row in 0..self.order {
                    let value = permutation.values[row];
                    row_used[row] &= !(1u8 << value);
                }
                assigned[column] = false;

                match child? {
                    Some(table) => return Ok(Some(table)),
                    None => {}
                }
            }
        }
        Ok(None)
    }

    fn validate_partial_domains(&self, domains: &[u8; MAX_CELLS]) -> Result<(), SearchAbstention> {
        let cell_count = self.order * self.order;
        for &domain in &domains[..cell_count] {
            if domain == 0 || domain & !self.valid_mask != 0 {
                return Err(SearchAbstention::InvariantViolation(
                    "partial oracle domain is empty or out of range",
                ));
            }
        }
        Ok(())
    }

    fn call_partial_oracle(&mut self, domains: &[u8; MAX_CELLS]) -> Result<bool, SearchAbstention> {
        let call = self.charge(SearchResource::OracleCalls)?;
        let cell_count = self.order * self.order;
        match self.oracle.partial_conflict(&domains[..cell_count]) {
            Ok(Some(token)) => {
                self.charge(SearchResource::PartialConflicts)?;
                self.telemetry.mix(50, call);
                drop(token);
                Ok(true)
            }
            Ok(None) => {
                self.telemetry.mix(51, call);
                Ok(false)
            }
            Err(_) => Err(SearchAbstention::OracleError {
                stage: OracleStage::Partial,
                call,
            }),
        }
    }

    fn call_root_column_oracle(
        &mut self,
        column: usize,
        values_by_row: &[u8],
    ) -> Result<bool, SearchAbstention> {
        let call = self.charge(SearchResource::OracleCalls)?;
        match self.oracle.root_column_conflict(column, values_by_row) {
            Ok(Some(token)) => {
                self.charge(SearchResource::PartialConflicts)?;
                self.telemetry.mix(52, call);
                drop(token);
                Ok(true)
            }
            Ok(None) => {
                self.telemetry.mix(53, call);
                Ok(false)
            }
            Err(_) => Err(SearchAbstention::OracleError {
                stage: OracleStage::Partial,
                call,
            }),
        }
    }

    fn validate_complete_table(
        &mut self,
        table: &[u8; MAX_CELLS],
        row_used: &[u8; MAX_ORDER],
    ) -> Result<Option<BinaryTable>, SearchAbstention> {
        self.charge(SearchResource::CompleteTables)?;
        for (row, &used) in row_used[..self.order].iter().enumerate() {
            if used != self.valid_mask {
                return Err(SearchAbstention::InvariantViolation(
                    "complete row is not a permutation",
                ));
            }
            self.telemetry.mix(60, usize_trace_value(row));
            self.telemetry.mix(61, u64::from(used));
        }
        for column in 0..self.order {
            let mut used = 0u8;
            for row in 0..self.order {
                let cell = row * self.order + column;
                let value = table[cell];
                let bit = 1u8 << value;
                if self.root_domains[cell] & bit == 0 || used & bit != 0 {
                    return Err(SearchAbstention::InvariantViolation(
                        "complete table violates a root domain or column permutation",
                    ));
                }
                used |= bit;
            }
            if used != self.valid_mask {
                return Err(SearchAbstention::InvariantViolation(
                    "complete column is not a permutation",
                ));
            }
        }

        let cell_count = self.order * self.order;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(cell_count)
            .map_err(|_| SearchAbstention::AllocationFailed {
                context: "complete binary table",
                requested: cell_count,
            })?;
        entries.extend(table[..cell_count].iter().copied().map(usize::from));
        let complete = BinaryTable::new(self.order, entries).map_err(|_| {
            SearchAbstention::InvariantViolation("complete BinaryTable construction failed")
        })?;
        for &entry in complete.entries() {
            self.telemetry.mix(62, usize_trace_value(entry));
        }

        let call = self.charge(SearchResource::OracleCalls)?;
        match self.oracle.validate_complete(&complete) {
            Ok(true) => {
                self.telemetry.mix(63, call);
                Ok(Some(complete))
            }
            Ok(false) => {
                self.telemetry.mix(64, call);
                Ok(None)
            }
            Err(_) => Err(SearchAbstention::OracleError {
                stage: OracleStage::Complete,
                call,
            }),
        }
    }
}

fn checked_increment(current: u64, resource: SearchResource) -> Result<u64, SearchAbstention> {
    current
        .checked_add(1)
        .ok_or(SearchAbstention::CounterOverflow { resource })
}

fn checked_factorial(order: usize) -> Result<usize, SearchAbstention> {
    (1..=order).try_fold(1usize, |product, factor| {
        product
            .checked_mul(factor)
            .ok_or(SearchAbstention::ArithmeticOverflow {
                context: "column permutation count",
            })
    })
}

fn advance_lexicographic_permutation(values: &mut [u8]) -> bool {
    let Some(pivot) = (1..values.len())
        .rev()
        .find(|&index| values[index - 1] < values[index])
        .map(|index| index - 1)
    else {
        return false;
    };
    let Some(successor) = (pivot + 1..values.len())
        .rev()
        .find(|&index| values[pivot] < values[index])
    else {
        return false;
    };
    values.swap(pivot, successor);
    values[pivot + 1..].reverse();
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::convert::Infallible;

    fn full_domains(order: usize) -> Vec<u8> {
        vec![low_mask(order); order * order]
    }

    // This deliberately assigns one cell at a time and shares no whole-column
    // permutation or MRV machinery with the implementation under test.
    fn brute_force_latin_tables(order: usize, domains: &[u8]) -> Vec<Vec<usize>> {
        fn visit(
            position: usize,
            order: usize,
            domains: &[u8],
            table: &mut [usize],
            row_used: &mut [u8],
            column_used: &mut [u8],
            output: &mut Vec<Vec<usize>>,
        ) {
            if position == table.len() {
                output.push(table.to_vec());
                return;
            }
            let row = position / order;
            let column = position % order;
            for value in 0..order {
                let bit = 1u8 << value;
                if domains[position] & bit == 0
                    || row_used[row] & bit != 0
                    || column_used[column] & bit != 0
                {
                    continue;
                }
                table[position] = value;
                row_used[row] |= bit;
                column_used[column] |= bit;
                visit(
                    position + 1,
                    order,
                    domains,
                    table,
                    row_used,
                    column_used,
                    output,
                );
                row_used[row] &= !bit;
                column_used[column] &= !bit;
            }
        }

        let mut output = Vec::new();
        let mut table = vec![0; order * order];
        let mut row_used = vec![0u8; order];
        let mut column_used = vec![0u8; order];
        visit(
            0,
            order,
            domains,
            &mut table,
            &mut row_used,
            &mut column_used,
            &mut output,
        );
        output
    }

    #[derive(Default)]
    struct RecordingRejectOracle {
        order: usize,
        complete: Vec<Vec<usize>>,
        partial_calls: u64,
    }

    impl RecordingRejectOracle {
        fn new(order: usize) -> Self {
            Self {
                order,
                ..Self::default()
            }
        }
    }

    impl FiniteColumnOracle for RecordingRejectOracle {
        type PartialConflictToken = Infallible;
        type Error = Infallible;

        fn partial_conflict(
            &mut self,
            domains: &[u8],
        ) -> Result<Option<Self::PartialConflictToken>, Self::Error> {
            assert_eq!(domains.len(), self.order * self.order);
            assert!(
                domains
                    .iter()
                    .all(|&domain| domain != 0 && domain & !low_mask(self.order) == 0)
            );
            self.partial_calls += 1;
            Ok(None)
        }

        fn validate_complete(&mut self, table: &BinaryTable) -> Result<bool, Self::Error> {
            assert_eq!(table.degree(), self.order);
            self.complete.push(table.entries().to_vec());
            Ok(false)
        }
    }

    #[test]
    fn exhaustive_tables_match_independent_brute_force_through_order_four() {
        let expected_counts = [0usize, 1, 2, 12, 576];
        for (order, &expected_count) in expected_counts.iter().enumerate().skip(1) {
            let domains = full_domains(order);
            let expected = brute_force_latin_tables(order, &domains);
            assert_eq!(expected.len(), expected_count);

            let mut oracle = RecordingRejectOracle::new(order);
            let report = search_with_caps(order, &domains, &mut oracle, SearchCaps::hard());
            assert_eq!(report.outcome, SearchOutcome::Unsat);
            assert_eq!(report.telemetry.complete_tables, expected_count as u64);
            assert_eq!(report.telemetry.max_depth, order as u8);
            assert_eq!(oracle.complete.len(), expected_count);

            let expected_set = expected.into_iter().collect::<BTreeSet<_>>();
            let observed_set = oracle.complete.iter().cloned().collect::<BTreeSet<_>>();
            assert_eq!(observed_set.len(), oracle.complete.len());
            assert_eq!(observed_set, expected_set);
        }
    }

    #[test]
    fn constrained_domains_match_independent_brute_force() {
        for order in 1..=4 {
            let mut domains = full_domains(order);
            if order > 1 {
                for row in 0..order {
                    for column in 0..order {
                        if (row + 2 * column) % 3 == 0 {
                            let forbidden = (2 * row + column) % order;
                            domains[row * order + column] &= !(1u8 << forbidden);
                        }
                    }
                }
            }
            let expected = brute_force_latin_tables(order, &domains);
            let mut oracle = RecordingRejectOracle::new(order);
            let report = search_with_caps(order, &domains, &mut oracle, SearchCaps::hard());
            assert_eq!(report.outcome, SearchOutcome::Unsat);
            assert_eq!(report.telemetry.complete_tables, expected.len() as u64);
            assert_eq!(
                oracle.complete.into_iter().collect::<BTreeSet<_>>(),
                expected.into_iter().collect::<BTreeSet<_>>()
            );
        }
    }

    #[derive(Default)]
    struct AcceptSecondOracle {
        complete: Vec<Vec<usize>>,
    }

    impl FiniteColumnOracle for AcceptSecondOracle {
        type PartialConflictToken = Infallible;
        type Error = Infallible;

        fn partial_conflict(
            &mut self,
            _domains: &[u8],
        ) -> Result<Option<Self::PartialConflictToken>, Self::Error> {
            Ok(None)
        }

        fn validate_complete(&mut self, table: &BinaryTable) -> Result<bool, Self::Error> {
            self.complete.push(table.entries().to_vec());
            Ok(self.complete.len() == 2)
        }
    }

    #[test]
    fn exact_rejection_continues_until_a_complete_table_is_accepted() {
        let domains = full_domains(2);
        let expected = brute_force_latin_tables(2, &domains);
        let mut oracle = AcceptSecondOracle::default();
        let report = search(2, &domains, &mut oracle);
        let SearchOutcome::Sat(table) = report.outcome else {
            panic!("the second order-two Latin table should be accepted");
        };
        assert_eq!(oracle.complete, expected);
        assert_eq!(table.entries(), expected[1]);
        assert_eq!(report.telemetry.complete_tables, 2);
    }

    struct TargetOracle {
        target: Vec<usize>,
    }

    impl FiniteColumnOracle for TargetOracle {
        type PartialConflictToken = usize;
        type Error = Infallible;

        fn partial_conflict(
            &mut self,
            domains: &[u8],
        ) -> Result<Option<Self::PartialConflictToken>, Self::Error> {
            Ok(self
                .target
                .iter()
                .enumerate()
                .find(|&(cell, value)| domains[cell] & (1u8 << value) == 0)
                .map(|(cell, _)| cell))
        }

        fn validate_complete(&mut self, table: &BinaryTable) -> Result<bool, Self::Error> {
            Ok(table.entries() == self.target)
        }
    }

    #[test]
    fn sound_partial_tokens_prune_without_skipping_the_target() {
        let order = 3;
        let domains = full_domains(order);
        let target = brute_force_latin_tables(order, &domains)
            .pop()
            .expect("order three has Latin tables");
        let mut oracle = TargetOracle {
            target: target.clone(),
        };
        let report = search(order, &domains, &mut oracle);
        let SearchOutcome::Sat(table) = report.outcome else {
            panic!("target oracle should find its accepted table");
        };
        assert_eq!(table.entries(), target);
        assert!(report.telemetry.partial_conflicts > 0);
        assert_eq!(report.telemetry.complete_tables, 1);
    }

    struct RootConflictOracle;

    impl FiniteColumnOracle for RootConflictOracle {
        type PartialConflictToken = ();
        type Error = Infallible;

        fn partial_conflict(
            &mut self,
            _domains: &[u8],
        ) -> Result<Option<Self::PartialConflictToken>, Self::Error> {
            Ok(Some(()))
        }

        fn validate_complete(&mut self, _table: &BinaryTable) -> Result<bool, Self::Error> {
            Ok(false)
        }
    }

    #[test]
    fn sound_root_conflict_can_close_an_empty_acceptance_set() {
        let mut oracle = RootConflictOracle;
        let report = search(4, &full_domains(4), &mut oracle);
        assert_eq!(report.outcome, SearchOutcome::Unsat);
        assert_eq!(report.telemetry.partial_conflicts, 1);
        assert_eq!(report.telemetry.complete_tables, 0);
    }

    struct AcceptAllOracle;

    impl FiniteColumnOracle for AcceptAllOracle {
        type PartialConflictToken = Infallible;
        type Error = Infallible;

        fn partial_conflict(
            &mut self,
            _domains: &[u8],
        ) -> Result<Option<Self::PartialConflictToken>, Self::Error> {
            Ok(None)
        }

        fn validate_complete(&mut self, _table: &BinaryTable) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    #[test]
    fn first_sat_table_is_found_at_every_supported_order() {
        for order in 1..=MAX_ORDER {
            let mut oracle = AcceptAllOracle;
            let report = search(order, &full_domains(order), &mut oracle);
            let SearchOutcome::Sat(table) = report.outcome else {
                panic!("order {order} should have a Latin table within default caps");
            };
            assert_eq!(table.degree(), order);
            assert_eq!(report.telemetry.complete_tables, 1);
            assert_eq!(report.telemetry.max_depth, order as u8);
        }
    }

    #[derive(Clone, Copy)]
    enum FailingStage {
        Partial,
        Complete,
    }

    struct FailingOracle {
        stage: FailingStage,
    }

    impl FiniteColumnOracle for FailingOracle {
        type PartialConflictToken = ();
        type Error = &'static str;

        fn partial_conflict(
            &mut self,
            _domains: &[u8],
        ) -> Result<Option<Self::PartialConflictToken>, Self::Error> {
            match self.stage {
                FailingStage::Partial => Err("partial failure"),
                FailingStage::Complete => Ok(None),
            }
        }

        fn validate_complete(&mut self, _table: &BinaryTable) -> Result<bool, Self::Error> {
            match self.stage {
                FailingStage::Partial => Ok(false),
                FailingStage::Complete => Err("complete failure"),
            }
        }
    }

    #[test]
    fn oracle_errors_abstain_at_both_boundaries() {
        let domains = full_domains(1);
        let mut partial = FailingOracle {
            stage: FailingStage::Partial,
        };
        let partial_report = search(1, &domains, &mut partial);
        assert!(matches!(
            partial_report.outcome,
            SearchOutcome::Abstain(SearchAbstention::OracleError {
                stage: OracleStage::Partial,
                call: 1,
            })
        ));

        let mut complete = FailingOracle {
            stage: FailingStage::Complete,
        };
        let complete_report = search(1, &domains, &mut complete);
        assert!(matches!(
            complete_report.outcome,
            SearchOutcome::Abstain(SearchAbstention::OracleError {
                stage: OracleStage::Complete,
                call: 2,
            })
        ));
    }

    #[test]
    fn repeat_runs_have_identical_order_telemetry_and_trace() {
        let order = 4;
        let mut domains = full_domains(order);
        domains[0] &= !1;
        domains[5] &= !(1 << 2);

        let mut first_oracle = RecordingRejectOracle::new(order);
        let first = search(order, &domains, &mut first_oracle);
        let mut second_oracle = RecordingRejectOracle::new(order);
        let second = search(order, &domains, &mut second_oracle);

        assert_eq!(first, second);
        assert_eq!(first_oracle.complete, second_oracle.complete);
        assert_ne!(first.telemetry.trace_hash, TRACE_OFFSET);
    }

    struct PanicOracle;

    impl FiniteColumnOracle for PanicOracle {
        type PartialConflictToken = ();
        type Error = Infallible;

        fn partial_conflict(
            &mut self,
            _domains: &[u8],
        ) -> Result<Option<Self::PartialConflictToken>, Self::Error> {
            panic!("malformed input must not call the oracle")
        }

        fn validate_complete(&mut self, _table: &BinaryTable) -> Result<bool, Self::Error> {
            panic!("malformed input must not call the oracle")
        }
    }

    #[test]
    fn malformed_inputs_abstain_before_oracle_use() {
        let cases = [
            (0, Vec::new()),
            (9, vec![1; 81]),
            (2, vec![3; 3]),
            (2, vec![3, 0, 3, 3]),
            (2, vec![3, 3, 3, 7]),
        ];
        for (order, domains) in cases {
            let mut oracle = PanicOracle;
            let report = search(order, &domains, &mut oracle);
            assert!(matches!(
                report.outcome,
                SearchOutcome::Abstain(SearchAbstention::InvalidInput(_))
            ));
            assert_eq!(report.telemetry.oracle_calls, 0);
        }
    }

    fn assert_cap(report: SearchReport, expected: SearchResource) {
        assert!(matches!(
            report.outcome,
            SearchOutcome::Abstain(SearchAbstention::CapExceeded {
                resource,
                attempted: 1,
                limit: 0,
            }) if resource == expected
        ));
    }

    #[test]
    fn every_runtime_cap_abstains_instead_of_returning_unsat() {
        let mut caps = SearchCaps::hard();
        caps.max_candidates = 0;
        let mut reject = RecordingRejectOracle::new(1);
        assert_cap(
            search_with_caps(1, &full_domains(1), &mut reject, caps),
            SearchResource::Candidates,
        );

        let mut caps = SearchCaps::hard();
        caps.max_nodes = 0;
        let mut reject = RecordingRejectOracle::new(1);
        assert_cap(
            search_with_caps(1, &full_domains(1), &mut reject, caps),
            SearchResource::Nodes,
        );

        let mut caps = SearchCaps::hard();
        caps.max_oracle_calls = 0;
        let mut reject = RecordingRejectOracle::new(1);
        assert_cap(
            search_with_caps(1, &full_domains(1), &mut reject, caps),
            SearchResource::OracleCalls,
        );

        let mut caps = SearchCaps::hard();
        caps.max_partial_conflicts = 0;
        let mut conflict = RootConflictOracle;
        assert_cap(
            search_with_caps(1, &full_domains(1), &mut conflict, caps),
            SearchResource::PartialConflicts,
        );

        let mut caps = SearchCaps::hard();
        caps.max_latin_conflicts = 0;
        let mut reject = RecordingRejectOracle::new(2);
        assert_cap(
            search_with_caps(2, &full_domains(2), &mut reject, caps),
            SearchResource::LatinConflicts,
        );

        let mut caps = SearchCaps::hard();
        caps.max_complete_tables = 0;
        let mut reject = RecordingRejectOracle::new(1);
        assert_cap(
            search_with_caps(1, &full_domains(1), &mut reject, caps),
            SearchResource::CompleteTables,
        );
    }

    fn above_hard_limit(resource: SearchResource) -> SearchCaps {
        let mut caps = SearchCaps::hard();
        match resource {
            SearchResource::OracleCalls => caps.max_oracle_calls += 1,
            SearchResource::Nodes => caps.max_nodes += 1,
            SearchResource::Candidates => caps.max_candidates += 1,
            SearchResource::PartialConflicts => caps.max_partial_conflicts += 1,
            SearchResource::LatinConflicts => caps.max_latin_conflicts += 1,
            SearchResource::CompleteTables => caps.max_complete_tables += 1,
        }
        caps
    }

    #[test]
    fn every_configured_cap_is_checked_against_its_hard_limit() {
        for resource in SearchResource::ALL {
            let mut oracle = PanicOracle;
            let report =
                search_with_caps(1, &full_domains(1), &mut oracle, above_hard_limit(resource));
            assert!(matches!(
                report.outcome,
                SearchOutcome::Abstain(SearchAbstention::CapAboveHardLimit {
                    resource: observed_resource,
                    observed,
                    hard_limit,
                }) if observed_resource == resource && observed == hard_limit + 1
            ));
            assert_eq!(report.telemetry.oracle_calls, 0);
        }
    }

    #[test]
    fn counter_increment_is_checked() {
        assert_eq!(
            checked_increment(u64::MAX, SearchResource::Nodes),
            Err(SearchAbstention::CounterOverflow {
                resource: SearchResource::Nodes,
            })
        );
    }

    #[test]
    fn root_prefilter_can_prove_unsat_without_oracle_use() {
        let domains = vec![1, 1, 1, 1];
        let mut oracle = PanicOracle;
        let report = search(2, &domains, &mut oracle);
        assert_eq!(report.outcome, SearchOutcome::Unsat);
        assert_eq!(report.telemetry.oracle_calls, 0);
        assert_eq!(report.telemetry.nodes, 0);
    }
}
