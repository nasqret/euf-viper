#![forbid(unsafe_code)]

//! Bounded finite-table CSP search for one Latin operation table.
//!
//! Cells use stable row-major IDs and values are zero based. A positive
//! literal `(cell, value)` means that the cell has that value; a negative
//! literal means that it does not. Cell domains are `u8` masks, so the hard
//! order limit is eight.
//!
//! This is deliberately a small research kernel. It has deterministic
//! propagation and search, explicit resource abstention, and replayable
//! certificates. It is not wired into the fabric solve path.

use std::error::Error;
use std::fmt;

pub(crate) const MAX_ORDER: usize = 8;
pub(crate) const MAX_CELLS: usize = MAX_ORDER * MAX_ORDER;
pub(crate) const MAX_SOURCE_CLAUSES: usize = 1_024;
pub(crate) const MAX_SOURCE_LITERALS: usize = 16_384;
pub(crate) const MAX_TRAIL_ENTRIES: usize = MAX_CELLS * MAX_ORDER;
pub(crate) const HARD_MAX_WORK: u64 = 100_000_000;
pub(crate) const HARD_MAX_NODES: u64 = 1_000_000;
pub(crate) const HARD_MAX_PROOF_NODES: usize = 1_000_000;
pub(crate) const HARD_MAX_PROOF_EDGES: usize = 1_000_000;
pub(crate) const HARD_MAX_CHECK_WORK: u64 = 200_000_000;
pub(crate) const CERTIFICATE_VERSION: u16 = 1;

/// A stable signed Boolean literal over one row-major cell/value atom.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CellValueLiteral {
    cell: u8,
    value: u8,
    positive: bool,
}

impl CellValueLiteral {
    pub(crate) const fn positive(cell: u8, value: u8) -> Self {
        Self {
            cell,
            value,
            positive: true,
        }
    }

    pub(crate) const fn negative(cell: u8, value: u8) -> Self {
        Self {
            cell,
            value,
            positive: false,
        }
    }

    pub(crate) const fn from_parts(cell: u8, value: u8, positive: bool) -> Self {
        Self {
            cell,
            value,
            positive,
        }
    }

    pub(crate) const fn cell(self) -> u8 {
        self.cell
    }

    pub(crate) const fn value(self) -> u8 {
        self.value
    }

    pub(crate) const fn is_positive(self) -> bool {
        self.positive
    }

    pub(crate) const fn negated(self) -> Self {
        Self {
            cell: self.cell,
            value: self.value,
            positive: !self.positive,
        }
    }
}

/// Stable source identity for one CNF clause.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ClauseId(u32);

impl ClauseId {
    pub(crate) const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub(crate) const fn raw(self) -> u32 {
        self.0
    }
}

impl From<u32> for ClauseId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl fmt::Display for ClauseId {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(output)
    }
}

/// One immutable source CNF clause.
///
/// Problem construction sorts and deduplicates literals and records
/// tautologies. That normalization is semantics preserving and deterministic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceClause {
    id: ClauseId,
    literals: Vec<CellValueLiteral>,
    tautological: bool,
}

impl SourceClause {
    pub(crate) fn new(id: ClauseId, literals: Vec<CellValueLiteral>) -> Self {
        Self {
            id,
            literals,
            tautological: false,
        }
    }

    pub(crate) const fn id(&self) -> ClauseId {
        self.id
    }

    pub(crate) fn literals(&self) -> &[CellValueLiteral] {
        &self.literals
    }

    pub(crate) const fn is_tautological(&self) -> bool {
        self.tautological
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InputError {
    InvalidOrder {
        observed: u8,
        maximum: u8,
    },
    DomainCount {
        observed: usize,
        expected: usize,
    },
    DomainMaskOutOfRange {
        cell: u8,
        mask: u8,
        valid_mask: u8,
    },
    TooManyClauses {
        observed: usize,
        maximum: usize,
    },
    TooManyLiterals {
        observed: usize,
        maximum: usize,
    },
    DuplicateClauseId {
        id: ClauseId,
    },
    LiteralCellOutOfRange {
        clause: ClauseId,
        cell: u8,
        cell_count: usize,
    },
    LiteralValueOutOfRange {
        clause: ClauseId,
        value: u8,
        order: u8,
    },
    ArithmeticOverflow(&'static str),
    AllocationFailed {
        context: &'static str,
        requested: usize,
    },
}

impl fmt::Display for InputError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOrder { observed, maximum } => write!(
                output,
                "Latin table order is {observed}; expected 1..={maximum}"
            ),
            Self::DomainCount { observed, expected } => write!(
                output,
                "Latin table has {observed} cell domains; expected {expected}"
            ),
            Self::DomainMaskOutOfRange {
                cell,
                mask,
                valid_mask,
            } => write!(
                output,
                "cell {cell} domain {mask:#04x} contains bits outside {valid_mask:#04x}"
            ),
            Self::TooManyClauses { observed, maximum } => write!(
                output,
                "source CNF has {observed} clauses; hard maximum is {maximum}"
            ),
            Self::TooManyLiterals { observed, maximum } => write!(
                output,
                "source CNF has {observed} literals; hard maximum is {maximum}"
            ),
            Self::DuplicateClauseId { id } => {
                write!(output, "source CNF contains duplicate clause ID {id}")
            }
            Self::LiteralCellOutOfRange {
                clause,
                cell,
                cell_count,
            } => write!(
                output,
                "clause {clause} references cell {cell} outside 0..{cell_count}"
            ),
            Self::LiteralValueOutOfRange {
                clause,
                value,
                order,
            } => write!(
                output,
                "clause {clause} references value {value} outside 0..{order}"
            ),
            Self::ArithmeticOverflow(context) => {
                write!(output, "arithmetic overflow while counting {context}")
            }
            Self::AllocationFailed { context, requested } => write!(
                output,
                "allocation failed for {context} while requesting {requested} entries"
            ),
        }
    }
}

impl Error for InputError {}

/// Validated input for one `n x n` operation table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LatinProblem {
    order: u8,
    cell_count: usize,
    valid_mask: u8,
    domains: Vec<u8>,
    clauses: Vec<SourceClause>,
}

impl LatinProblem {
    pub(crate) fn new(
        order: u8,
        domains: Vec<u8>,
        mut clauses: Vec<SourceClause>,
    ) -> Result<Self, InputError> {
        if order == 0 || usize::from(order) > MAX_ORDER {
            return Err(InputError::InvalidOrder {
                observed: order,
                maximum: MAX_ORDER as u8,
            });
        }
        let n = usize::from(order);
        let cell_count = n
            .checked_mul(n)
            .ok_or(InputError::ArithmeticOverflow("Latin cells"))?;
        if domains.len() != cell_count {
            return Err(InputError::DomainCount {
                observed: domains.len(),
                expected: cell_count,
            });
        }
        let valid_mask = low_mask(order);
        for (cell, mask) in domains.iter().copied().enumerate() {
            if mask & !valid_mask != 0 {
                return Err(InputError::DomainMaskOutOfRange {
                    cell: cell as u8,
                    mask,
                    valid_mask,
                });
            }
        }
        if clauses.len() > MAX_SOURCE_CLAUSES {
            return Err(InputError::TooManyClauses {
                observed: clauses.len(),
                maximum: MAX_SOURCE_CLAUSES,
            });
        }
        for index in 0..clauses.len() {
            for earlier in 0..index {
                if clauses[index].id == clauses[earlier].id {
                    return Err(InputError::DuplicateClauseId {
                        id: clauses[index].id,
                    });
                }
            }
        }

        let mut raw_literal_count = 0usize;
        for clause in &mut clauses {
            raw_literal_count = raw_literal_count
                .checked_add(clause.literals.len())
                .ok_or(InputError::ArithmeticOverflow("source literals"))?;
            if raw_literal_count > MAX_SOURCE_LITERALS {
                return Err(InputError::TooManyLiterals {
                    observed: raw_literal_count,
                    maximum: MAX_SOURCE_LITERALS,
                });
            }
            for literal in clause.literals.iter().copied() {
                if usize::from(literal.cell) >= cell_count {
                    return Err(InputError::LiteralCellOutOfRange {
                        clause: clause.id,
                        cell: literal.cell,
                        cell_count,
                    });
                }
                if literal.value >= order {
                    return Err(InputError::LiteralValueOutOfRange {
                        clause: clause.id,
                        value: literal.value,
                        order,
                    });
                }
            }
            clause.literals.sort_unstable();
            clause.literals.dedup();
            clause.tautological = clause.literals.windows(2).any(|pair| {
                pair[0].cell == pair[1].cell
                    && pair[0].value == pair[1].value
                    && pair[0].positive != pair[1].positive
            });
        }

        Ok(Self {
            order,
            cell_count,
            valid_mask,
            domains,
            clauses,
        })
    }

    pub(crate) fn full(order: u8, clauses: Vec<SourceClause>) -> Result<Self, InputError> {
        if order == 0 || usize::from(order) > MAX_ORDER {
            return Err(InputError::InvalidOrder {
                observed: order,
                maximum: MAX_ORDER as u8,
            });
        }
        let n = usize::from(order);
        let cell_count = n
            .checked_mul(n)
            .ok_or(InputError::ArithmeticOverflow("Latin cells"))?;
        let mut domains = Vec::new();
        domains
            .try_reserve_exact(cell_count)
            .map_err(|_| InputError::AllocationFailed {
                context: "Latin cell domains",
                requested: cell_count,
            })?;
        domains.resize(cell_count, low_mask(order));
        Self::new(order, domains, clauses)
    }

    pub(crate) const fn order(&self) -> u8 {
        self.order
    }

    pub(crate) const fn cell_count(&self) -> usize {
        self.cell_count
    }

    pub(crate) const fn valid_mask(&self) -> u8 {
        self.valid_mask
    }

    pub(crate) fn domains(&self) -> &[u8] {
        &self.domains
    }

    pub(crate) fn clauses(&self) -> &[SourceClause] {
        &self.clauses
    }

    pub(crate) fn cell_index(&self, row: u8, column: u8) -> Option<u8> {
        if row >= self.order || column >= self.order {
            return None;
        }
        Some(row * self.order + column)
    }
}

const fn low_mask(order: u8) -> u8 {
    ((1u16 << order) - 1) as u8
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KernelCaps {
    pub(crate) max_work: u64,
    pub(crate) max_nodes: u64,
    pub(crate) max_trail_entries: usize,
    pub(crate) max_proof_nodes: usize,
    pub(crate) max_proof_edges: usize,
}

impl Default for KernelCaps {
    fn default() -> Self {
        Self {
            max_work: 20_000_000,
            max_nodes: 250_000,
            max_trail_entries: MAX_TRAIL_ENTRIES,
            max_proof_nodes: 250_000,
            max_proof_edges: 250_000,
        }
    }
}

impl KernelCaps {
    fn validate(self) -> Result<(), KernelError> {
        validate_u64_cap("max_work", self.max_work, HARD_MAX_WORK)?;
        validate_u64_cap("max_nodes", self.max_nodes, HARD_MAX_NODES)?;
        validate_usize_cap(
            "max_trail_entries",
            self.max_trail_entries,
            MAX_TRAIL_ENTRIES,
        )?;
        validate_usize_cap(
            "max_proof_nodes",
            self.max_proof_nodes,
            HARD_MAX_PROOF_NODES,
        )?;
        validate_usize_cap(
            "max_proof_edges",
            self.max_proof_edges,
            HARD_MAX_PROOF_EDGES,
        )?;
        Ok(())
    }
}

fn validate_u64_cap(name: &'static str, observed: u64, hard_limit: u64) -> Result<(), KernelError> {
    if observed > hard_limit {
        Err(KernelError::CapAboveHardLimit {
            name,
            observed,
            hard_limit,
        })
    } else {
        Ok(())
    }
}

fn validate_usize_cap(
    name: &'static str,
    observed: usize,
    hard_limit: usize,
) -> Result<(), KernelError> {
    validate_u64_cap(name, observed as u64, hard_limit as u64)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Resource {
    Work,
    Nodes,
    TrailEntries,
    ProofNodes,
    ProofEdges,
}

impl fmt::Display for Resource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Work => "work",
            Self::Nodes => "search nodes",
            Self::TrailEntries => "trail entries",
            Self::ProofNodes => "proof nodes",
            Self::ProofEdges => "proof edges",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResourceLimit {
    pub(crate) resource: Resource,
    pub(crate) attempted: u64,
    pub(crate) limit: u64,
}

impl fmt::Display for ResourceLimit {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "{} cap exceeded: attempted {}, limit {}",
            self.resource, self.attempted, self.limit
        )
    }
}

#[derive(Debug)]
pub(crate) enum KernelError {
    CapAboveHardLimit {
        name: &'static str,
        observed: u64,
        hard_limit: u64,
    },
    ArithmeticOverflow(&'static str),
    AllocationFailed {
        context: &'static str,
        requested: usize,
    },
    InvariantViolation(&'static str),
}

impl fmt::Display for KernelError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapAboveHardLimit {
                name,
                observed,
                hard_limit,
            } => write!(
                output,
                "kernel cap {name} is {observed}, above hard limit {hard_limit}"
            ),
            Self::ArithmeticOverflow(context) => {
                write!(output, "arithmetic overflow while counting {context}")
            }
            Self::AllocationFailed { context, requested } => write!(
                output,
                "allocation failed for {context} while requesting {requested} entries"
            ),
            Self::InvariantViolation(message) => {
                write!(output, "Latin kernel invariant violation: {message}")
            }
        }
    }
}

impl Error for KernelError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Axis {
    Row,
    Column,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Conflict {
    EmptyCell {
        cell: u8,
    },
    LatinDuplicate {
        axis: Axis,
        index: u8,
        value: u8,
        first_cell: u8,
        second_cell: u8,
    },
    LatinMissing {
        axis: Axis,
        index: u8,
        value: u8,
    },
    Clause {
        clause: ClauseId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SatTable {
    version: u16,
    order: u8,
    values: Vec<u8>,
}

impl SatTable {
    /// Constructs untrusted certificate data for transport or negative tests.
    pub(crate) fn from_parts(version: u16, order: u8, values: Vec<u8>) -> Self {
        Self {
            version,
            order,
            values,
        }
    }

    pub(crate) const fn version(&self) -> u16 {
        self.version
    }

    pub(crate) const fn order(&self) -> u8 {
        self.order
    }

    pub(crate) fn values(&self) -> &[u8] {
        &self.values
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProofEdge {
    value: u8,
    child: u32,
}

impl ProofEdge {
    pub(crate) const fn new(value: u8, child: u32) -> Self {
        Self { value, child }
    }

    pub(crate) const fn value(self) -> u8 {
        self.value
    }

    pub(crate) const fn child(self) -> u32 {
        self.child
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProofNode {
    Conflict(Conflict),
    Branch {
        cell: u8,
        domain: u8,
        edges: Vec<ProofEdge>,
    },
}

impl ProofNode {
    pub(crate) fn conflict(conflict: Conflict) -> Self {
        Self::Conflict(conflict)
    }

    pub(crate) fn branch(cell: u8, domain: u8, edges: Vec<ProofEdge>) -> Self {
        Self::Branch {
            cell,
            domain,
            edges,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnsatCertificate {
    version: u16,
    order: u8,
    root: u32,
    nodes: Vec<ProofNode>,
}

impl UnsatCertificate {
    /// Constructs untrusted certificate data. The checker validates all fields.
    pub(crate) fn from_parts(version: u16, order: u8, root: u32, nodes: Vec<ProofNode>) -> Self {
        Self {
            version,
            order,
            root,
            nodes,
        }
    }

    pub(crate) const fn version(&self) -> u16 {
        self.version
    }

    pub(crate) const fn order(&self) -> u8 {
        self.order
    }

    pub(crate) const fn root(&self) -> u32 {
        self.root
    }

    pub(crate) fn nodes(&self) -> &[ProofNode] {
        &self.nodes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SolveOutcome {
    Sat(SatTable),
    Unsat(UnsatCertificate),
    Limit(ResourceLimit),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SolveStats {
    pub(crate) work: u64,
    pub(crate) nodes: u64,
    pub(crate) trail_peak: usize,
    pub(crate) proof_nodes: usize,
    pub(crate) proof_edges: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SolveReport {
    pub(crate) outcome: SolveOutcome,
    pub(crate) stats: SolveStats,
}

#[derive(Clone, Copy, Debug, Default)]
struct TrailEntry {
    cell: u8,
    previous: u8,
}

#[derive(Debug)]
struct RollbackDomains {
    values: [u8; MAX_CELLS],
    cell_count: usize,
    trail: [TrailEntry; MAX_TRAIL_ENTRIES],
    trail_len: usize,
}

impl RollbackDomains {
    fn new(problem: &LatinProblem) -> Self {
        let mut values = [0u8; MAX_CELLS];
        values[..problem.cell_count].copy_from_slice(&problem.domains);
        Self {
            values,
            cell_count: problem.cell_count,
            trail: [TrailEntry::default(); MAX_TRAIL_ENTRIES],
            trail_len: 0,
        }
    }

    fn domain(&self, cell: usize) -> u8 {
        self.values[cell]
    }

    fn snapshot(&self) -> usize {
        self.trail_len
    }

    fn rollback(&mut self, snapshot: usize) -> Result<(), KernelError> {
        if snapshot > self.trail_len {
            return Err(KernelError::InvariantViolation(
                "rollback snapshot is newer than the trail",
            ));
        }
        while self.trail_len > snapshot {
            self.trail_len -= 1;
            let entry = self.trail[self.trail_len];
            self.values[usize::from(entry.cell)] = entry.previous;
        }
        Ok(())
    }
}

#[derive(Debug)]
enum SearchFailure {
    Limit(ResourceLimit),
    Error(KernelError),
}

impl From<KernelError> for SearchFailure {
    fn from(error: KernelError) -> Self {
        Self::Error(error)
    }
}

enum SearchResult {
    Sat(Vec<u8>),
    Unsat(u32),
}

enum PropagationResult {
    Stable,
    Conflict(Conflict),
}

#[derive(Clone, Copy)]
enum LiteralState {
    True,
    False,
    Undetermined,
}

struct Producer<'problem> {
    problem: &'problem LatinProblem,
    caps: KernelCaps,
    domains: RollbackDomains,
    work: u64,
    nodes: u64,
    trail_peak: usize,
    proof_nodes: Vec<ProofNode>,
    proof_edges: usize,
}

impl<'problem> Producer<'problem> {
    fn new(problem: &'problem LatinProblem, caps: KernelCaps) -> Self {
        Self {
            problem,
            caps,
            domains: RollbackDomains::new(problem),
            work: 0,
            nodes: 0,
            trail_peak: 0,
            proof_nodes: Vec::new(),
            proof_edges: 0,
        }
    }

    fn stats(&self) -> SolveStats {
        SolveStats {
            work: self.work,
            nodes: self.nodes,
            trail_peak: self.trail_peak,
            proof_nodes: self.proof_nodes.len(),
            proof_edges: self.proof_edges,
        }
    }

    fn tick(&mut self, amount: u64) -> Result<(), SearchFailure> {
        let attempted = self
            .work
            .checked_add(amount)
            .ok_or(KernelError::ArithmeticOverflow("producer work"))?;
        if attempted > self.caps.max_work {
            return Err(SearchFailure::Limit(ResourceLimit {
                resource: Resource::Work,
                attempted,
                limit: self.caps.max_work,
            }));
        }
        self.work = attempted;
        Ok(())
    }

    fn enter_node(&mut self) -> Result<(), SearchFailure> {
        let attempted = self
            .nodes
            .checked_add(1)
            .ok_or(KernelError::ArithmeticOverflow("search nodes"))?;
        if attempted > self.caps.max_nodes {
            return Err(SearchFailure::Limit(ResourceLimit {
                resource: Resource::Nodes,
                attempted,
                limit: self.caps.max_nodes,
            }));
        }
        self.nodes = attempted;
        Ok(())
    }

    fn narrow(&mut self, cell: usize, new_domain: u8) -> Result<bool, SearchFailure> {
        if cell >= self.domains.cell_count {
            return Err(KernelError::InvariantViolation("narrowed cell is out of range").into());
        }
        let previous = self.domains.values[cell];
        if new_domain & !previous != 0 {
            return Err(KernelError::InvariantViolation("domain narrowing added a value").into());
        }
        if new_domain == previous {
            return Ok(false);
        }
        self.tick(1)?;
        let attempted = self
            .domains
            .trail_len
            .checked_add(1)
            .ok_or(KernelError::ArithmeticOverflow("trail entries"))?;
        if attempted > self.caps.max_trail_entries {
            return Err(SearchFailure::Limit(ResourceLimit {
                resource: Resource::TrailEntries,
                attempted: attempted as u64,
                limit: self.caps.max_trail_entries as u64,
            }));
        }
        if attempted > MAX_TRAIL_ENTRIES {
            return Err(KernelError::InvariantViolation("hard trail bound exceeded").into());
        }
        let slot = self.domains.trail_len;
        self.domains.trail[slot] = TrailEntry {
            cell: cell as u8,
            previous,
        };
        self.domains.trail_len = attempted;
        self.domains.values[cell] = new_domain;
        self.trail_peak = self.trail_peak.max(attempted);
        Ok(true)
    }

    fn literal_state(&self, literal: CellValueLiteral) -> LiteralState {
        let domain = self.domains.domain(usize::from(literal.cell));
        let bit = 1u8 << literal.value;
        if literal.positive {
            if domain & bit == 0 {
                LiteralState::False
            } else if domain == bit {
                LiteralState::True
            } else {
                LiteralState::Undetermined
            }
        } else if domain & bit == 0 {
            LiteralState::True
        } else if domain == bit {
            LiteralState::False
        } else {
            LiteralState::Undetermined
        }
    }

    fn enforce_literal(
        &mut self,
        literal: CellValueLiteral,
    ) -> Result<Option<Conflict>, SearchFailure> {
        let cell = usize::from(literal.cell);
        let old = self.domains.domain(cell);
        let bit = 1u8 << literal.value;
        let new_domain = if literal.positive {
            old & bit
        } else {
            old & !bit
        };
        self.narrow(cell, new_domain)?;
        if new_domain == 0 {
            Ok(Some(Conflict::EmptyCell { cell: literal.cell }))
        } else {
            Ok(None)
        }
    }

    fn unit_cell(&self, axis: Axis, index: usize, offset: usize) -> usize {
        let n = usize::from(self.problem.order);
        match axis {
            Axis::Row => index * n + offset,
            Axis::Column => offset * n + index,
        }
    }

    fn propagate_latin_unit(
        &mut self,
        axis: Axis,
        index: usize,
    ) -> Result<(bool, Option<Conflict>), SearchFailure> {
        let n = usize::from(self.problem.order);
        let mut changed = false;
        for value in 0..n {
            let bit = 1u8 << value;
            let mut support_count = 0usize;
            let mut sole_support = 0usize;
            let mut first_singleton = None;
            for offset in 0..n {
                self.tick(1)?;
                let cell = self.unit_cell(axis, index, offset);
                let domain = self.domains.domain(cell);
                if domain & bit != 0 {
                    support_count += 1;
                    sole_support = cell;
                }
                if domain == bit {
                    if let Some(first_cell) = first_singleton {
                        return Ok((
                            changed,
                            Some(Conflict::LatinDuplicate {
                                axis,
                                index: index as u8,
                                value: value as u8,
                                first_cell: first_cell as u8,
                                second_cell: cell as u8,
                            }),
                        ));
                    }
                    first_singleton = Some(cell);
                }
            }
            if support_count == 0 {
                return Ok((
                    changed,
                    Some(Conflict::LatinMissing {
                        axis,
                        index: index as u8,
                        value: value as u8,
                    }),
                ));
            }
            if let Some(singleton_cell) = first_singleton {
                for offset in 0..n {
                    let cell = self.unit_cell(axis, index, offset);
                    if cell == singleton_cell {
                        continue;
                    }
                    self.tick(1)?;
                    let old = self.domains.domain(cell);
                    if old & bit == 0 {
                        continue;
                    }
                    let current = old & !bit;
                    changed |= self.narrow(cell, current)?;
                    if current == 0 {
                        return Ok((changed, Some(Conflict::EmptyCell { cell: cell as u8 })));
                    }
                }
            } else if support_count == 1 {
                changed |= self.narrow(sole_support, bit)?;
            }
        }
        Ok((changed, None))
    }

    fn propagate_clause(
        &mut self,
        clause_index: usize,
    ) -> Result<(bool, Option<Conflict>), SearchFailure> {
        self.tick(1)?;
        if self.problem.clauses[clause_index].tautological {
            return Ok((false, None));
        }
        let literal_count = self.problem.clauses[clause_index].literals.len();
        let mut undetermined_count = 0usize;
        let mut unit_literal = None;
        for literal_index in 0..literal_count {
            self.tick(1)?;
            let literal = self.problem.clauses[clause_index].literals[literal_index];
            match self.literal_state(literal) {
                LiteralState::True => return Ok((false, None)),
                LiteralState::False => {}
                LiteralState::Undetermined => {
                    undetermined_count += 1;
                    unit_literal = Some(literal);
                }
            }
        }
        if undetermined_count == 0 {
            return Ok((
                false,
                Some(Conflict::Clause {
                    clause: self.problem.clauses[clause_index].id,
                }),
            ));
        }
        if undetermined_count == 1 {
            let literal = unit_literal.ok_or(KernelError::InvariantViolation(
                "unit clause lost its literal",
            ))?;
            let old = self.domains.domain(usize::from(literal.cell));
            if let Some(conflict) = self.enforce_literal(literal)? {
                return Ok((true, Some(conflict)));
            }
            let current = self.domains.domain(usize::from(literal.cell));
            return Ok((old != current, None));
        }
        Ok((false, None))
    }

    fn propagate(&mut self) -> Result<PropagationResult, SearchFailure> {
        let n = usize::from(self.problem.order);
        loop {
            for cell in 0..self.problem.cell_count {
                self.tick(1)?;
                if self.domains.domain(cell) == 0 {
                    return Ok(PropagationResult::Conflict(Conflict::EmptyCell {
                        cell: cell as u8,
                    }));
                }
            }

            let mut changed = false;
            for index in 0..n {
                let (unit_changed, conflict) = self.propagate_latin_unit(Axis::Row, index)?;
                changed |= unit_changed;
                if let Some(conflict) = conflict {
                    return Ok(PropagationResult::Conflict(conflict));
                }
            }
            for index in 0..n {
                let (unit_changed, conflict) = self.propagate_latin_unit(Axis::Column, index)?;
                changed |= unit_changed;
                if let Some(conflict) = conflict {
                    return Ok(PropagationResult::Conflict(conflict));
                }
            }
            for clause_index in 0..self.problem.clauses.len() {
                let (clause_changed, conflict) = self.propagate_clause(clause_index)?;
                changed |= clause_changed;
                if let Some(conflict) = conflict {
                    return Ok(PropagationResult::Conflict(conflict));
                }
            }
            if !changed {
                return Ok(PropagationResult::Stable);
            }
        }
    }

    fn choose_mrv(&mut self) -> Result<Option<(usize, u8)>, SearchFailure> {
        let mut best = None;
        let mut best_size = u32::MAX;
        for cell in 0..self.problem.cell_count {
            self.tick(1)?;
            let domain = self.domains.domain(cell);
            let size = domain.count_ones();
            if size > 1 && size < best_size {
                best = Some((cell, domain));
                best_size = size;
            }
        }
        Ok(best)
    }

    fn table(&self) -> Result<Vec<u8>, KernelError> {
        let mut values = Vec::new();
        values
            .try_reserve_exact(self.problem.cell_count)
            .map_err(|_| KernelError::AllocationFailed {
                context: "SAT table",
                requested: self.problem.cell_count,
            })?;
        for cell in 0..self.problem.cell_count {
            let domain = self.domains.domain(cell);
            if domain.count_ones() != 1 {
                return Err(KernelError::InvariantViolation(
                    "completed table contains a non-singleton domain",
                ));
            }
            values.push(domain.trailing_zeros() as u8);
        }
        Ok(values)
    }

    fn add_proof_node(&mut self, node: ProofNode) -> Result<u32, SearchFailure> {
        let attempted = self
            .proof_nodes
            .len()
            .checked_add(1)
            .ok_or(KernelError::ArithmeticOverflow("proof nodes"))?;
        if attempted > self.caps.max_proof_nodes {
            return Err(SearchFailure::Limit(ResourceLimit {
                resource: Resource::ProofNodes,
                attempted: attempted as u64,
                limit: self.caps.max_proof_nodes as u64,
            }));
        }
        self.proof_nodes
            .try_reserve(1)
            .map_err(|_| KernelError::AllocationFailed {
                context: "UNSAT proof nodes",
                requested: attempted,
            })?;
        let index = u32::try_from(self.proof_nodes.len())
            .map_err(|_| KernelError::ArithmeticOverflow("proof node indices"))?;
        self.proof_nodes.push(node);
        Ok(index)
    }

    fn add_proof_edge(
        &mut self,
        edges: &mut Vec<ProofEdge>,
        edge: ProofEdge,
    ) -> Result<(), SearchFailure> {
        let attempted = self
            .proof_edges
            .checked_add(1)
            .ok_or(KernelError::ArithmeticOverflow("proof edges"))?;
        if attempted > self.caps.max_proof_edges {
            return Err(SearchFailure::Limit(ResourceLimit {
                resource: Resource::ProofEdges,
                attempted: attempted as u64,
                limit: self.caps.max_proof_edges as u64,
            }));
        }
        edges
            .try_reserve(1)
            .map_err(|_| KernelError::AllocationFailed {
                context: "UNSAT branch edges",
                requested: edges.len().saturating_add(1),
            })?;
        edges.push(edge);
        self.proof_edges = attempted;
        Ok(())
    }

    fn search(&mut self) -> Result<SearchResult, SearchFailure> {
        self.enter_node()?;
        match self.propagate()? {
            PropagationResult::Conflict(conflict) => {
                let node = self.add_proof_node(ProofNode::Conflict(conflict))?;
                return Ok(SearchResult::Unsat(node));
            }
            PropagationResult::Stable => {}
        }

        let Some((cell, domain)) = self.choose_mrv()? else {
            return Ok(SearchResult::Sat(self.table()?));
        };

        let mut edges = Vec::new();
        for value in 0..self.problem.order {
            let bit = 1u8 << value;
            if domain & bit == 0 {
                continue;
            }
            let snapshot = self.domains.snapshot();
            let narrowed = self.narrow(cell, bit);
            let child = match narrowed {
                Ok(_) => self.search(),
                Err(error) => Err(error),
            };
            let rollback = self.domains.rollback(snapshot);
            if let Err(error) = rollback {
                return Err(SearchFailure::Error(error));
            }
            match child? {
                SearchResult::Sat(table) => return Ok(SearchResult::Sat(table)),
                SearchResult::Unsat(child_node) => {
                    self.add_proof_edge(&mut edges, ProofEdge::new(value, child_node))?;
                }
            }
        }
        let node = self.add_proof_node(ProofNode::Branch {
            cell: cell as u8,
            domain,
            edges,
        })?;
        Ok(SearchResult::Unsat(node))
    }
}

pub(crate) fn solve(problem: &LatinProblem) -> Result<SolveReport, KernelError> {
    solve_with_caps(problem, KernelCaps::default())
}

pub(crate) fn solve_with_caps(
    problem: &LatinProblem,
    caps: KernelCaps,
) -> Result<SolveReport, KernelError> {
    caps.validate()?;
    let mut producer = Producer::new(problem, caps);
    let result = producer.search();
    let stats = producer.stats();
    let outcome = match result {
        Ok(SearchResult::Sat(values)) => SolveOutcome::Sat(SatTable {
            version: CERTIFICATE_VERSION,
            order: problem.order,
            values,
        }),
        Ok(SearchResult::Unsat(root)) => SolveOutcome::Unsat(UnsatCertificate {
            version: CERTIFICATE_VERSION,
            order: problem.order,
            root,
            nodes: producer.proof_nodes,
        }),
        Err(SearchFailure::Limit(limit)) => SolveOutcome::Limit(limit),
        Err(SearchFailure::Error(error)) => return Err(error),
    };
    Ok(SolveReport { outcome, stats })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CheckCaps {
    pub(crate) max_work: u64,
    pub(crate) max_nodes: u64,
    pub(crate) max_proof_nodes: usize,
    pub(crate) max_proof_edges: usize,
}

impl Default for CheckCaps {
    fn default() -> Self {
        Self {
            max_work: 100_000_000,
            max_nodes: HARD_MAX_NODES,
            max_proof_nodes: HARD_MAX_PROOF_NODES,
            max_proof_edges: HARD_MAX_PROOF_EDGES,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CheckStats {
    pub(crate) work: u64,
    pub(crate) nodes: u64,
    pub(crate) proof_edges: usize,
    pub(crate) max_depth: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CheckedKind {
    Sat,
    Unsat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CheckReport {
    pub(crate) kind: CheckedKind,
    pub(crate) stats: CheckStats,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CheckError {
    NoCertificate(ResourceLimit),
    CapAboveHardLimit {
        name: &'static str,
        observed: u64,
        hard_limit: u64,
    },
    CapExceeded {
        resource: Resource,
        attempted: u64,
        limit: u64,
    },
    CertificateVersion {
        observed: u16,
        expected: u16,
    },
    OrderMismatch {
        certificate: u8,
        problem: u8,
    },
    SatLength {
        observed: usize,
        expected: usize,
    },
    SatValueOutOfRange {
        cell: u8,
        value: u8,
        order: u8,
    },
    SatValueForbidden {
        cell: u8,
        value: u8,
        domain: u8,
    },
    SatLatinDuplicate {
        axis: Axis,
        index: u8,
        value: u8,
    },
    SatClauseFalse {
        clause: ClauseId,
    },
    EmptyProof,
    RootOutOfRange {
        root: u32,
        node_count: usize,
    },
    NodeOutOfRange {
        node: u32,
        node_count: usize,
    },
    Cycle {
        node: u32,
    },
    SharedNode {
        node: u32,
    },
    UnreachableNode {
        node: u32,
    },
    DepthExceeded {
        observed: usize,
        maximum: usize,
    },
    PathContinuesAfterConflict {
        conflict_depth: usize,
        node_depth: usize,
    },
    FalseConflict {
        node: u32,
        claimed: Conflict,
    },
    ConflictMismatch {
        node: u32,
        claimed: Conflict,
        replayed: Conflict,
    },
    BranchAtConflict {
        node: u32,
        conflict: Conflict,
    },
    BranchAtSolution {
        node: u32,
    },
    BranchCellMismatch {
        node: u32,
        observed: u8,
        expected: u8,
    },
    BranchDomainMismatch {
        node: u32,
        observed: u8,
        expected: u8,
    },
    BranchArity {
        node: u32,
        observed: usize,
        expected: usize,
    },
    BranchValueMismatch {
        node: u32,
        edge: usize,
        observed: u8,
        expected: u8,
    },
    DecisionOutOfRange {
        depth: usize,
        cell: u8,
        value: u8,
    },
    AllocationFailed {
        context: &'static str,
        requested: usize,
    },
    ArithmeticOverflow(&'static str),
}

impl fmt::Display for CheckError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCertificate(limit) => {
                write!(output, "resource abstention has no certificate: {limit}")
            }
            Self::CapAboveHardLimit {
                name,
                observed,
                hard_limit,
            } => write!(
                output,
                "checker cap {name} is {observed}, above hard limit {hard_limit}"
            ),
            Self::CapExceeded {
                resource,
                attempted,
                limit,
            } => write!(
                output,
                "checker {resource} cap exceeded: attempted {attempted}, limit {limit}"
            ),
            Self::CertificateVersion { observed, expected } => write!(
                output,
                "certificate version is {observed}; expected {expected}"
            ),
            Self::OrderMismatch {
                certificate,
                problem,
            } => write!(
                output,
                "certificate order is {certificate}; problem order is {problem}"
            ),
            Self::SatLength { observed, expected } => write!(
                output,
                "SAT table has {observed} cells; expected {expected}"
            ),
            Self::SatValueOutOfRange { cell, value, order } => write!(
                output,
                "SAT cell {cell} has value {value} outside 0..{order}"
            ),
            Self::SatValueForbidden {
                cell,
                value,
                domain,
            } => write!(
                output,
                "SAT cell {cell} value {value} is forbidden by domain {domain:#04x}"
            ),
            Self::SatLatinDuplicate { axis, index, value } => write!(
                output,
                "SAT table repeats value {value} in {axis:?} {index}"
            ),
            Self::SatClauseFalse { clause } => {
                write!(output, "SAT table falsifies source clause {clause}")
            }
            Self::EmptyProof => output.write_str("UNSAT certificate has no proof nodes"),
            Self::RootOutOfRange { root, node_count } => write!(
                output,
                "proof root {root} is outside {node_count} proof nodes"
            ),
            Self::NodeOutOfRange { node, node_count } => write!(
                output,
                "proof edge targets node {node} outside {node_count} proof nodes"
            ),
            Self::Cycle { node } => write!(output, "proof contains a cycle at node {node}"),
            Self::SharedNode { node } => {
                write!(output, "proof node {node} has more than one parent")
            }
            Self::UnreachableNode { node } => {
                write!(output, "proof node {node} is unreachable from the root")
            }
            Self::DepthExceeded { observed, maximum } => write!(
                output,
                "proof depth {observed} exceeds hard maximum {maximum}"
            ),
            Self::PathContinuesAfterConflict {
                conflict_depth,
                node_depth,
            } => write!(
                output,
                "proof path reaches a conflict at depth {conflict_depth} but continues to depth {node_depth}"
            ),
            Self::FalseConflict { node, claimed } => write!(
                output,
                "proof leaf {node} claims {claimed:?}, but replay is consistent"
            ),
            Self::ConflictMismatch {
                node,
                claimed,
                replayed,
            } => write!(
                output,
                "proof leaf {node} claims {claimed:?}, but replay derives {replayed:?}"
            ),
            Self::BranchAtConflict { node, conflict } => write!(
                output,
                "proof node {node} branches from replayed conflict {conflict:?}"
            ),
            Self::BranchAtSolution { node } => {
                write!(output, "proof node {node} branches from a completed table")
            }
            Self::BranchCellMismatch {
                node,
                observed,
                expected,
            } => write!(
                output,
                "proof node {node} branches on cell {observed}; deterministic MRV requires {expected}"
            ),
            Self::BranchDomainMismatch {
                node,
                observed,
                expected,
            } => write!(
                output,
                "proof node {node} records domain {observed:#04x}; replay has {expected:#04x}"
            ),
            Self::BranchArity {
                node,
                observed,
                expected,
            } => write!(
                output,
                "proof node {node} has {observed} children; expected {expected}"
            ),
            Self::BranchValueMismatch {
                node,
                edge,
                observed,
                expected,
            } => write!(
                output,
                "proof node {node} edge {edge} has value {observed}; expected {expected}"
            ),
            Self::DecisionOutOfRange { depth, cell, value } => write!(
                output,
                "proof decision {depth} uses out-of-range cell/value ({cell}, {value})"
            ),
            Self::AllocationFailed { context, requested } => write!(
                output,
                "checker allocation failed for {context} while requesting {requested} entries"
            ),
            Self::ArithmeticOverflow(context) => {
                write!(
                    output,
                    "checker arithmetic overflow while counting {context}"
                )
            }
        }
    }
}

impl Error for CheckError {}

/// Structurally independent certificate replay.
///
/// The checker does not call producer propagation or inspect producer domains,
/// trails, proof counters, or search frames. For every proof node it starts
/// from the input domains and replays the complete root-to-node decision path.
pub(crate) mod checker {
    use super::*;

    #[derive(Clone, Copy, Debug, Default)]
    struct Decision {
        cell: u8,
        value: u8,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Mark {
        Unseen,
        Visiting,
        Done,
    }

    #[derive(Clone, Copy)]
    enum ReplayLiteralState {
        True,
        False,
        Undetermined,
    }

    struct ReplayResult {
        domains: [u8; MAX_CELLS],
        conflict: Option<Conflict>,
    }

    struct IndependentChecker<'input> {
        problem: &'input LatinProblem,
        caps: CheckCaps,
        work: u64,
        nodes: u64,
        proof_edges: usize,
        max_depth: usize,
    }

    impl<'input> IndependentChecker<'input> {
        fn new(problem: &'input LatinProblem, caps: CheckCaps) -> Result<Self, CheckError> {
            validate_caps(caps)?;
            Ok(Self {
                problem,
                caps,
                work: 0,
                nodes: 0,
                proof_edges: 0,
                max_depth: 0,
            })
        }

        fn report(&self, kind: CheckedKind) -> CheckReport {
            CheckReport {
                kind,
                stats: CheckStats {
                    work: self.work,
                    nodes: self.nodes,
                    proof_edges: self.proof_edges,
                    max_depth: self.max_depth,
                },
            }
        }

        fn tick(&mut self, amount: u64) -> Result<(), CheckError> {
            let attempted = self
                .work
                .checked_add(amount)
                .ok_or(CheckError::ArithmeticOverflow("replay work"))?;
            if attempted > self.caps.max_work {
                return Err(CheckError::CapExceeded {
                    resource: Resource::Work,
                    attempted,
                    limit: self.caps.max_work,
                });
            }
            self.work = attempted;
            Ok(())
        }

        fn enter_node(&mut self, depth: usize) -> Result<(), CheckError> {
            let attempted = self
                .nodes
                .checked_add(1)
                .ok_or(CheckError::ArithmeticOverflow("replayed nodes"))?;
            if attempted > self.caps.max_nodes {
                return Err(CheckError::CapExceeded {
                    resource: Resource::Nodes,
                    attempted,
                    limit: self.caps.max_nodes,
                });
            }
            self.nodes = attempted;
            self.max_depth = self.max_depth.max(depth);
            Ok(())
        }

        fn check_sat(&mut self, table: &SatTable) -> Result<CheckReport, CheckError> {
            check_metadata(table.version, table.order, self.problem.order)?;
            if table.values.len() != self.problem.cell_count {
                return Err(CheckError::SatLength {
                    observed: table.values.len(),
                    expected: self.problem.cell_count,
                });
            }
            let n = usize::from(self.problem.order);
            for cell in 0..self.problem.cell_count {
                self.tick(1)?;
                let value = table.values[cell];
                if value >= self.problem.order {
                    return Err(CheckError::SatValueOutOfRange {
                        cell: cell as u8,
                        value,
                        order: self.problem.order,
                    });
                }
                if self.problem.domains[cell] & (1u8 << value) == 0 {
                    return Err(CheckError::SatValueForbidden {
                        cell: cell as u8,
                        value,
                        domain: self.problem.domains[cell],
                    });
                }
            }
            for row in 0..n {
                let mut seen = 0u8;
                for column in 0..n {
                    self.tick(1)?;
                    let value = table.values[row * n + column];
                    let bit = 1u8 << value;
                    if seen & bit != 0 {
                        return Err(CheckError::SatLatinDuplicate {
                            axis: Axis::Row,
                            index: row as u8,
                            value,
                        });
                    }
                    seen |= bit;
                }
            }
            for column in 0..n {
                let mut seen = 0u8;
                for row in 0..n {
                    self.tick(1)?;
                    let value = table.values[row * n + column];
                    let bit = 1u8 << value;
                    if seen & bit != 0 {
                        return Err(CheckError::SatLatinDuplicate {
                            axis: Axis::Column,
                            index: column as u8,
                            value,
                        });
                    }
                    seen |= bit;
                }
            }
            for clause_index in 0..self.problem.clauses.len() {
                self.tick(1)?;
                if self.problem.clauses[clause_index].tautological {
                    continue;
                }
                let mut satisfied = false;
                let literal_count = self.problem.clauses[clause_index].literals.len();
                for literal_index in 0..literal_count {
                    self.tick(1)?;
                    let literal = self.problem.clauses[clause_index].literals[literal_index];
                    let equal = table.values[usize::from(literal.cell)] == literal.value;
                    if equal == literal.positive {
                        satisfied = true;
                        break;
                    }
                }
                if !satisfied {
                    return Err(CheckError::SatClauseFalse {
                        clause: self.problem.clauses[clause_index].id,
                    });
                }
            }
            Ok(self.report(CheckedKind::Sat))
        }

        fn literal_state(
            &self,
            domains: &[u8; MAX_CELLS],
            literal: CellValueLiteral,
        ) -> ReplayLiteralState {
            let domain = domains[usize::from(literal.cell)];
            let bit = 1u8 << literal.value;
            if literal.positive {
                if domain & bit == 0 {
                    ReplayLiteralState::False
                } else if domain == bit {
                    ReplayLiteralState::True
                } else {
                    ReplayLiteralState::Undetermined
                }
            } else if domain & bit == 0 {
                ReplayLiteralState::True
            } else if domain == bit {
                ReplayLiteralState::False
            } else {
                ReplayLiteralState::Undetermined
            }
        }

        fn replay_cell(&self, axis: Axis, index: usize, offset: usize) -> usize {
            let n = usize::from(self.problem.order);
            match axis {
                Axis::Row => index * n + offset,
                Axis::Column => offset * n + index,
            }
        }

        fn narrow_replay(
            &mut self,
            domains: &mut [u8; MAX_CELLS],
            cell: usize,
            new_domain: u8,
        ) -> Result<bool, CheckError> {
            let old = domains[cell];
            if old == new_domain {
                return Ok(false);
            }
            self.tick(1)?;
            domains[cell] = new_domain;
            Ok(true)
        }

        fn propagate_replay_unit(
            &mut self,
            domains: &mut [u8; MAX_CELLS],
            axis: Axis,
            index: usize,
        ) -> Result<(bool, Option<Conflict>), CheckError> {
            let n = usize::from(self.problem.order);
            let mut changed = false;
            for value in 0..n {
                let bit = 1u8 << value;
                let mut support_count = 0usize;
                let mut sole_support = 0usize;
                let mut first_singleton = None;
                for offset in 0..n {
                    self.tick(1)?;
                    let cell = self.replay_cell(axis, index, offset);
                    let domain = domains[cell];
                    if domain & bit != 0 {
                        support_count += 1;
                        sole_support = cell;
                    }
                    if domain == bit {
                        if let Some(first_cell) = first_singleton {
                            return Ok((
                                changed,
                                Some(Conflict::LatinDuplicate {
                                    axis,
                                    index: index as u8,
                                    value: value as u8,
                                    first_cell: first_cell as u8,
                                    second_cell: cell as u8,
                                }),
                            ));
                        }
                        first_singleton = Some(cell);
                    }
                }
                if support_count == 0 {
                    return Ok((
                        changed,
                        Some(Conflict::LatinMissing {
                            axis,
                            index: index as u8,
                            value: value as u8,
                        }),
                    ));
                }
                if let Some(singleton_cell) = first_singleton {
                    for offset in 0..n {
                        let cell = self.replay_cell(axis, index, offset);
                        if cell == singleton_cell {
                            continue;
                        }
                        self.tick(1)?;
                        let old = domains[cell];
                        if old & bit == 0 {
                            continue;
                        }
                        let current = old & !bit;
                        changed |= self.narrow_replay(domains, cell, current)?;
                        if current == 0 {
                            return Ok((changed, Some(Conflict::EmptyCell { cell: cell as u8 })));
                        }
                    }
                } else if support_count == 1 {
                    changed |= self.narrow_replay(domains, sole_support, bit)?;
                }
            }
            Ok((changed, None))
        }

        fn propagate_replay_clause(
            &mut self,
            domains: &mut [u8; MAX_CELLS],
            clause_index: usize,
        ) -> Result<(bool, Option<Conflict>), CheckError> {
            self.tick(1)?;
            if self.problem.clauses[clause_index].tautological {
                return Ok((false, None));
            }
            let mut undetermined_count = 0usize;
            let mut unit_literal = None;
            let literal_count = self.problem.clauses[clause_index].literals.len();
            for literal_index in 0..literal_count {
                self.tick(1)?;
                let literal = self.problem.clauses[clause_index].literals[literal_index];
                match self.literal_state(domains, literal) {
                    ReplayLiteralState::True => return Ok((false, None)),
                    ReplayLiteralState::False => {}
                    ReplayLiteralState::Undetermined => {
                        undetermined_count += 1;
                        unit_literal = Some(literal);
                    }
                }
            }
            if undetermined_count == 0 {
                return Ok((
                    false,
                    Some(Conflict::Clause {
                        clause: self.problem.clauses[clause_index].id,
                    }),
                ));
            }
            if undetermined_count == 1 {
                let literal =
                    unit_literal.ok_or(CheckError::ArithmeticOverflow("unit replay literal"))?;
                let cell = usize::from(literal.cell);
                let old = domains[cell];
                let bit = 1u8 << literal.value;
                let current = if literal.positive {
                    old & bit
                } else {
                    old & !bit
                };
                let changed = self.narrow_replay(domains, cell, current)?;
                if current == 0 {
                    return Ok((changed, Some(Conflict::EmptyCell { cell: literal.cell })));
                }
                return Ok((changed, None));
            }
            Ok((false, None))
        }

        fn propagate_replay(
            &mut self,
            domains: &mut [u8; MAX_CELLS],
        ) -> Result<Option<Conflict>, CheckError> {
            let n = usize::from(self.problem.order);
            loop {
                for cell in 0..self.problem.cell_count {
                    self.tick(1)?;
                    if domains[cell] == 0 {
                        return Ok(Some(Conflict::EmptyCell { cell: cell as u8 }));
                    }
                }
                let mut changed = false;
                for index in 0..n {
                    let (unit_changed, conflict) =
                        self.propagate_replay_unit(domains, Axis::Row, index)?;
                    changed |= unit_changed;
                    if conflict.is_some() {
                        return Ok(conflict);
                    }
                }
                for index in 0..n {
                    let (unit_changed, conflict) =
                        self.propagate_replay_unit(domains, Axis::Column, index)?;
                    changed |= unit_changed;
                    if conflict.is_some() {
                        return Ok(conflict);
                    }
                }
                for clause_index in 0..self.problem.clauses.len() {
                    let (clause_changed, conflict) =
                        self.propagate_replay_clause(domains, clause_index)?;
                    changed |= clause_changed;
                    if conflict.is_some() {
                        return Ok(conflict);
                    }
                }
                if !changed {
                    return Ok(None);
                }
            }
        }

        fn replay_path(
            &mut self,
            path: &[Decision; MAX_CELLS],
            depth: usize,
        ) -> Result<ReplayResult, CheckError> {
            if depth > MAX_CELLS {
                return Err(CheckError::DepthExceeded {
                    observed: depth,
                    maximum: MAX_CELLS,
                });
            }
            let mut domains = [0u8; MAX_CELLS];
            domains[..self.problem.cell_count].copy_from_slice(&self.problem.domains);
            let mut conflict = self.propagate_replay(&mut domains)?;
            if conflict.is_some() && depth > 0 {
                return Err(CheckError::PathContinuesAfterConflict {
                    conflict_depth: 0,
                    node_depth: depth,
                });
            }
            for (decision_index, decision) in path.iter().copied().enumerate().take(depth) {
                if conflict.is_some() {
                    return Err(CheckError::PathContinuesAfterConflict {
                        conflict_depth: decision_index,
                        node_depth: depth,
                    });
                }
                if usize::from(decision.cell) >= self.problem.cell_count
                    || decision.value >= self.problem.order
                {
                    return Err(CheckError::DecisionOutOfRange {
                        depth: decision_index,
                        cell: decision.cell,
                        value: decision.value,
                    });
                }
                self.tick(1)?;
                let cell = usize::from(decision.cell);
                domains[cell] &= 1u8 << decision.value;
                conflict = self.propagate_replay(&mut domains)?;
                if conflict.is_some() && decision_index + 1 < depth {
                    return Err(CheckError::PathContinuesAfterConflict {
                        conflict_depth: decision_index + 1,
                        node_depth: depth,
                    });
                }
            }
            Ok(ReplayResult { domains, conflict })
        }

        fn replay_mrv(
            &mut self,
            domains: &[u8; MAX_CELLS],
        ) -> Result<Option<(u8, u8)>, CheckError> {
            let mut best = None;
            let mut best_size = u32::MAX;
            for (cell, domain) in domains
                .iter()
                .copied()
                .enumerate()
                .take(self.problem.cell_count)
            {
                self.tick(1)?;
                let size = domain.count_ones();
                if size > 1 && size < best_size {
                    best = Some((cell as u8, domain));
                    best_size = size;
                }
            }
            Ok(best)
        }

        fn visit_node(
            &mut self,
            certificate: &UnsatCertificate,
            node_index: u32,
            path: &mut [Decision; MAX_CELLS],
            depth: usize,
            marks: &mut [Mark],
        ) -> Result<(), CheckError> {
            let index = usize::try_from(node_index)
                .map_err(|_| CheckError::ArithmeticOverflow("proof node index"))?;
            if index >= certificate.nodes.len() {
                return Err(CheckError::NodeOutOfRange {
                    node: node_index,
                    node_count: certificate.nodes.len(),
                });
            }
            match marks[index] {
                Mark::Visiting => return Err(CheckError::Cycle { node: node_index }),
                Mark::Done => return Err(CheckError::SharedNode { node: node_index }),
                Mark::Unseen => marks[index] = Mark::Visiting,
            }
            self.enter_node(depth)?;
            let replay = self.replay_path(path, depth)?;
            match &certificate.nodes[index] {
                ProofNode::Conflict(claimed) => match replay.conflict {
                    None => {
                        return Err(CheckError::FalseConflict {
                            node: node_index,
                            claimed: claimed.clone(),
                        });
                    }
                    Some(replayed) if replayed != *claimed => {
                        return Err(CheckError::ConflictMismatch {
                            node: node_index,
                            claimed: claimed.clone(),
                            replayed,
                        });
                    }
                    Some(_) => {}
                },
                ProofNode::Branch {
                    cell,
                    domain,
                    edges,
                } => {
                    if let Some(conflict) = replay.conflict {
                        return Err(CheckError::BranchAtConflict {
                            node: node_index,
                            conflict,
                        });
                    }
                    let Some((expected_cell, expected_domain)) =
                        self.replay_mrv(&replay.domains)?
                    else {
                        return Err(CheckError::BranchAtSolution { node: node_index });
                    };
                    if *cell != expected_cell {
                        return Err(CheckError::BranchCellMismatch {
                            node: node_index,
                            observed: *cell,
                            expected: expected_cell,
                        });
                    }
                    if *domain != expected_domain {
                        return Err(CheckError::BranchDomainMismatch {
                            node: node_index,
                            observed: *domain,
                            expected: expected_domain,
                        });
                    }
                    let expected_arity = expected_domain.count_ones() as usize;
                    if edges.len() != expected_arity {
                        return Err(CheckError::BranchArity {
                            node: node_index,
                            observed: edges.len(),
                            expected: expected_arity,
                        });
                    }
                    if depth >= MAX_CELLS {
                        return Err(CheckError::DepthExceeded {
                            observed: depth + 1,
                            maximum: MAX_CELLS,
                        });
                    }
                    let mut edge_index = 0usize;
                    for value in 0..self.problem.order {
                        if expected_domain & (1u8 << value) == 0 {
                            continue;
                        }
                        let edge = edges[edge_index];
                        if edge.value != value {
                            return Err(CheckError::BranchValueMismatch {
                                node: node_index,
                                edge: edge_index,
                                observed: edge.value,
                                expected: value,
                            });
                        }
                        path[depth] = Decision {
                            cell: expected_cell,
                            value,
                        };
                        self.visit_node(certificate, edge.child, path, depth + 1, marks)?;
                        edge_index += 1;
                    }
                }
            }
            marks[index] = Mark::Done;
            Ok(())
        }

        fn check_unsat(
            &mut self,
            certificate: &UnsatCertificate,
        ) -> Result<CheckReport, CheckError> {
            check_metadata(certificate.version, certificate.order, self.problem.order)?;
            if certificate.nodes.is_empty() {
                return Err(CheckError::EmptyProof);
            }
            enforce_check_cap(
                Resource::ProofNodes,
                certificate.nodes.len(),
                self.caps.max_proof_nodes,
            )?;
            let root = usize::try_from(certificate.root)
                .map_err(|_| CheckError::ArithmeticOverflow("proof root"))?;
            if root >= certificate.nodes.len() {
                return Err(CheckError::RootOutOfRange {
                    root: certificate.root,
                    node_count: certificate.nodes.len(),
                });
            }
            let mut edge_count = 0usize;
            for node in &certificate.nodes {
                if let ProofNode::Branch { edges, .. } = node {
                    edge_count = edge_count
                        .checked_add(edges.len())
                        .ok_or(CheckError::ArithmeticOverflow("proof edges"))?;
                }
            }
            enforce_check_cap(Resource::ProofEdges, edge_count, self.caps.max_proof_edges)?;
            self.proof_edges = edge_count;

            let mut marks = Vec::new();
            marks
                .try_reserve_exact(certificate.nodes.len())
                .map_err(|_| CheckError::AllocationFailed {
                    context: "proof visit marks",
                    requested: certificate.nodes.len(),
                })?;
            marks.resize(certificate.nodes.len(), Mark::Unseen);
            let mut path = [Decision::default(); MAX_CELLS];
            self.visit_node(certificate, certificate.root, &mut path, 0, &mut marks)?;
            if let Some((node, _)) = marks
                .iter()
                .enumerate()
                .find(|(_, mark)| **mark != Mark::Done)
            {
                return Err(CheckError::UnreachableNode { node: node as u32 });
            }
            Ok(self.report(CheckedKind::Unsat))
        }
    }

    fn check_metadata(version: u16, order: u8, problem_order: u8) -> Result<(), CheckError> {
        if version != CERTIFICATE_VERSION {
            return Err(CheckError::CertificateVersion {
                observed: version,
                expected: CERTIFICATE_VERSION,
            });
        }
        if order != problem_order {
            return Err(CheckError::OrderMismatch {
                certificate: order,
                problem: problem_order,
            });
        }
        Ok(())
    }

    fn validate_caps(caps: CheckCaps) -> Result<(), CheckError> {
        check_cap("max_work", caps.max_work, HARD_MAX_CHECK_WORK)?;
        check_cap("max_nodes", caps.max_nodes, HARD_MAX_NODES)?;
        check_cap(
            "max_proof_nodes",
            caps.max_proof_nodes as u64,
            HARD_MAX_PROOF_NODES as u64,
        )?;
        check_cap(
            "max_proof_edges",
            caps.max_proof_edges as u64,
            HARD_MAX_PROOF_EDGES as u64,
        )?;
        Ok(())
    }

    fn check_cap(name: &'static str, observed: u64, hard_limit: u64) -> Result<(), CheckError> {
        if observed > hard_limit {
            Err(CheckError::CapAboveHardLimit {
                name,
                observed,
                hard_limit,
            })
        } else {
            Ok(())
        }
    }

    fn enforce_check_cap(
        resource: Resource,
        observed: usize,
        limit: usize,
    ) -> Result<(), CheckError> {
        if observed > limit {
            Err(CheckError::CapExceeded {
                resource,
                attempted: observed as u64,
                limit: limit as u64,
            })
        } else {
            Ok(())
        }
    }

    pub(crate) fn check(
        problem: &LatinProblem,
        outcome: &SolveOutcome,
    ) -> Result<CheckReport, CheckError> {
        check_with_caps(problem, outcome, CheckCaps::default())
    }

    pub(crate) fn check_with_caps(
        problem: &LatinProblem,
        outcome: &SolveOutcome,
        caps: CheckCaps,
    ) -> Result<CheckReport, CheckError> {
        let mut checker = IndependentChecker::new(problem, caps)?;
        match outcome {
            SolveOutcome::Sat(table) => checker.check_sat(table),
            SolveOutcome::Unsat(certificate) => checker.check_unsat(certificate),
            SolveOutcome::Limit(limit) => Err(CheckError::NoCertificate(*limit)),
        }
    }

    pub(crate) fn check_sat(
        problem: &LatinProblem,
        table: &SatTable,
        caps: CheckCaps,
    ) -> Result<CheckReport, CheckError> {
        IndependentChecker::new(problem, caps)?.check_sat(table)
    }

    pub(crate) fn check_unsat(
        problem: &LatinProblem,
        certificate: &UnsatCertificate,
        caps: CheckCaps,
    ) -> Result<CheckReport, CheckError> {
        IndependentChecker::new(problem, caps)?.check_unsat(certificate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_clause(id: u32, literals: Vec<CellValueLiteral>) -> SourceClause {
        SourceClause::new(ClauseId::new(id), literals)
    }

    fn certified(problem: &LatinProblem) -> SolveReport {
        let report = solve(problem).expect("kernel should not fail");
        match &report.outcome {
            SolveOutcome::Limit(limit) => panic!("unexpected resource limit: {limit}"),
            SolveOutcome::Sat(_) | SolveOutcome::Unsat(_) => {}
        }
        let checked = checker::check(problem, &report.outcome).expect("certificate should replay");
        assert!(checked.stats.work > 0);
        report
    }

    fn enumerate_latin_tables(order: u8) -> Vec<Vec<u8>> {
        fn visit(
            position: usize,
            order: usize,
            table: &mut [u8],
            row_used: &mut [u8; MAX_ORDER],
            column_used: &mut [u8; MAX_ORDER],
            output: &mut Vec<Vec<u8>>,
        ) {
            if position == table.len() {
                output.push(table.to_vec());
                return;
            }
            let row = position / order;
            let column = position % order;
            for value in 0..order {
                let bit = 1u8 << value;
                if row_used[row] & bit != 0 || column_used[column] & bit != 0 {
                    continue;
                }
                table[position] = value as u8;
                row_used[row] |= bit;
                column_used[column] |= bit;
                visit(position + 1, order, table, row_used, column_used, output);
                row_used[row] &= !bit;
                column_used[column] &= !bit;
            }
        }

        let n = usize::from(order);
        let mut table = vec![0; n * n];
        let mut output = Vec::new();
        visit(
            0,
            n,
            &mut table,
            &mut [0; MAX_ORDER],
            &mut [0; MAX_ORDER],
            &mut output,
        );
        output
    }

    fn table_satisfies(problem: &LatinProblem, table: &[u8]) -> bool {
        for (cell, value) in table.iter().copied().enumerate() {
            if problem.domains()[cell] & (1u8 << value) == 0 {
                return false;
            }
        }
        for clause in &problem.clauses {
            if clause.tautological {
                continue;
            }
            if !clause.literals.iter().copied().any(|literal| {
                let equal = table[usize::from(literal.cell)] == literal.value;
                equal == literal.positive
            }) {
                return false;
            }
        }
        true
    }

    fn brute_force_sat(problem: &LatinProblem, latin_tables: &[Vec<u8>]) -> bool {
        latin_tables
            .iter()
            .any(|table| table_satisfies(problem, table))
    }

    fn outcome_is_sat(outcome: &SolveOutcome) -> bool {
        match outcome {
            SolveOutcome::Sat(_) => true,
            SolveOutcome::Unsat(_) => false,
            SolveOutcome::Limit(limit) => panic!("unexpected differential-test limit: {limit}"),
        }
    }

    fn forbid_table(id: u32, table: &[u8]) -> SourceClause {
        source_clause(
            id,
            table
                .iter()
                .copied()
                .enumerate()
                .map(|(cell, value)| CellValueLiteral::negative(cell as u8, value))
                .collect(),
        )
    }

    fn branching_unsat_problem() -> LatinProblem {
        let tables = enumerate_latin_tables(2);
        assert_eq!(tables.len(), 2);
        LatinProblem::full(
            2,
            vec![forbid_table(10, &tables[0]), forbid_table(11, &tables[1])],
        )
        .unwrap()
    }

    fn branching_unsat_certificate() -> (LatinProblem, UnsatCertificate) {
        let problem = branching_unsat_problem();
        let report = certified(&problem);
        let SolveOutcome::Unsat(certificate) = report.outcome else {
            panic!("both order-two Latin tables were forbidden");
        };
        assert!(matches!(
            certificate.nodes[certificate.root as usize],
            ProofNode::Branch { .. }
        ));
        (problem, certificate)
    }

    #[test]
    fn validates_bounded_inputs_and_normalizes_source_clauses() {
        assert!(matches!(
            LatinProblem::full(0, Vec::new()),
            Err(InputError::InvalidOrder { .. })
        ));
        assert!(matches!(
            LatinProblem::full(9, Vec::new()),
            Err(InputError::InvalidOrder { .. })
        ));
        assert!(matches!(
            LatinProblem::new(2, vec![3; 3], Vec::new()),
            Err(InputError::DomainCount { .. })
        ));
        assert!(matches!(
            LatinProblem::new(2, vec![7, 3, 3, 3], Vec::new()),
            Err(InputError::DomainMaskOutOfRange { cell: 0, .. })
        ));
        assert!(matches!(
            LatinProblem::full(
                2,
                vec![source_clause(4, Vec::new()), source_clause(4, Vec::new())]
            ),
            Err(InputError::DuplicateClauseId { id }) if id == ClauseId::new(4)
        ));
        assert!(matches!(
            LatinProblem::full(
                2,
                vec![source_clause(1, vec![CellValueLiteral::positive(4, 0)])]
            ),
            Err(InputError::LiteralCellOutOfRange { .. })
        ));
        assert!(matches!(
            LatinProblem::full(
                2,
                vec![source_clause(1, vec![CellValueLiteral::positive(0, 2)])]
            ),
            Err(InputError::LiteralValueOutOfRange { .. })
        ));

        let literal = CellValueLiteral::positive(0, 1);
        let problem = LatinProblem::full(
            2,
            vec![source_clause(
                7,
                vec![literal, literal, literal.negated(), literal],
            )],
        )
        .unwrap();
        assert_eq!(problem.order(), 2);
        assert_eq!(problem.cell_count(), 4);
        assert_eq!(problem.valid_mask(), 3);
        assert_eq!(problem.cell_index(1, 1), Some(3));
        assert_eq!(problem.cell_index(2, 0), None);
        assert_eq!(problem.clauses()[0].id().raw(), 7);
        assert_eq!(problem.clauses()[0].literals().len(), 2);
        assert!(problem.clauses()[0].is_tautological());
        assert_eq!(literal.cell(), 0);
        assert_eq!(literal.value(), 1);
        assert!(literal.is_positive());
        assert_eq!(CellValueLiteral::from_parts(0, 1, false), literal.negated());
    }

    #[test]
    fn produces_and_independently_checks_sat_and_unsat_results() {
        let sat_problem = LatinProblem::full(3, Vec::new()).unwrap();
        let sat_report = certified(&sat_problem);
        let SolveOutcome::Sat(table) = &sat_report.outcome else {
            panic!("unconstrained order-three Latin table should be SAT");
        };
        assert_eq!(table.version(), CERTIFICATE_VERSION);
        assert_eq!(table.order(), 3);
        assert_eq!(table.values().len(), 9);
        assert_eq!(
            checker::check_sat(&sat_problem, table, CheckCaps::default())
                .unwrap()
                .kind,
            CheckedKind::Sat
        );

        let maximum_order_problem = LatinProblem::full(MAX_ORDER as u8, Vec::new()).unwrap();
        let maximum_order_report = certified(&maximum_order_problem);
        let SolveOutcome::Sat(maximum_order_table) = &maximum_order_report.outcome else {
            panic!("unconstrained maximum-order Latin table should be SAT");
        };
        assert_eq!(maximum_order_table.values().len(), MAX_CELLS);

        let empty_clause_problem =
            LatinProblem::full(1, vec![source_clause(90, Vec::new())]).unwrap();
        let root_unsat = certified(&empty_clause_problem);
        let SolveOutcome::Unsat(certificate) = &root_unsat.outcome else {
            panic!("empty source clause should be UNSAT");
        };
        assert_eq!(certificate.version(), CERTIFICATE_VERSION);
        assert_eq!(certificate.order(), 1);
        assert_eq!(certificate.root(), 0);
        assert_eq!(certificate.nodes().len(), 1);
        assert_eq!(
            certificate.nodes()[0],
            ProofNode::conflict(Conflict::Clause {
                clause: ClauseId::new(90)
            })
        );
        assert_eq!(
            checker::check_unsat(&empty_clause_problem, certificate, CheckCaps::default())
                .unwrap()
                .kind,
            CheckedKind::Unsat
        );

        let branching_problem = branching_unsat_problem();
        let branching_report = certified(&branching_problem);
        let SolveOutcome::Unsat(certificate) = &branching_report.outcome else {
            panic!("all Latin tables are forbidden");
        };
        assert!(certificate.nodes.len() >= 3);
        let ProofNode::Branch {
            cell,
            domain,
            edges,
        } = &certificate.nodes[certificate.root as usize]
        else {
            unreachable!();
        };
        assert_eq!((*cell, *domain), (0, 0b11));
        assert_eq!(edges[0].value(), 0);
        assert!((edges[0].child() as usize) < certificate.nodes.len());
        assert!(branching_report.stats.nodes >= 3);
        assert!(branching_report.stats.proof_edges >= 2);
    }

    #[test]
    fn rollback_restores_state_and_failed_first_value_does_not_poison_sat_branch() {
        let base = LatinProblem::full(2, Vec::new()).unwrap();
        let mut producer = Producer::new(&base, KernelCaps::default());
        assert!(matches!(
            producer.propagate().unwrap(),
            PropagationResult::Stable
        ));
        let before = producer.domains.values;
        let before_trail = producer.domains.trail_len;
        let snapshot = producer.domains.snapshot();
        producer.narrow(0, 1).unwrap();
        assert!(matches!(
            producer.propagate().unwrap(),
            PropagationResult::Stable
        ));
        assert_ne!(producer.domains.values, before);
        assert!(producer.domains.trail_len > before_trail);
        producer.domains.rollback(snapshot).unwrap();
        assert_eq!(producer.domains.values, before);
        assert_eq!(producer.domains.trail_len, before_trail);

        let problem = LatinProblem::full(
            2,
            vec![source_clause(
                55,
                vec![
                    CellValueLiteral::positive(0, 1),
                    CellValueLiteral::positive(1, 0),
                ],
            )],
        )
        .unwrap();
        let report = certified(&problem);
        let SolveOutcome::Sat(table) = report.outcome else {
            panic!("the second deterministic root value should be SAT");
        };
        assert_eq!(table.values, vec![1, 0, 0, 1]);
        assert!(report.stats.proof_nodes >= 1);
        assert!(report.stats.proof_edges >= 1);
    }

    #[test]
    fn all_producer_and_checker_caps_fail_closed() {
        let trivial = LatinProblem::full(1, Vec::new()).unwrap();
        let report = solve_with_caps(
            &trivial,
            KernelCaps {
                max_nodes: 0,
                ..KernelCaps::default()
            },
        )
        .unwrap();
        assert!(matches!(
            report.outcome,
            SolveOutcome::Limit(ResourceLimit {
                resource: Resource::Nodes,
                attempted: 1,
                limit: 0
            })
        ));

        let report = solve_with_caps(
            &trivial,
            KernelCaps {
                max_work: 0,
                ..KernelCaps::default()
            },
        )
        .unwrap();
        assert!(matches!(
            report.outcome,
            SolveOutcome::Limit(ResourceLimit {
                resource: Resource::Work,
                attempted: 1,
                limit: 0
            })
        ));

        let trail_problem = LatinProblem::full(
            2,
            vec![source_clause(1, vec![CellValueLiteral::positive(0, 0)])],
        )
        .unwrap();
        let report = solve_with_caps(
            &trail_problem,
            KernelCaps {
                max_trail_entries: 0,
                ..KernelCaps::default()
            },
        )
        .unwrap();
        assert!(matches!(
            report.outcome,
            SolveOutcome::Limit(ResourceLimit {
                resource: Resource::TrailEntries,
                attempted: 1,
                limit: 0
            })
        ));

        let root_unsat = LatinProblem::full(1, vec![source_clause(2, Vec::new())]).unwrap();
        let report = solve_with_caps(
            &root_unsat,
            KernelCaps {
                max_proof_nodes: 0,
                ..KernelCaps::default()
            },
        )
        .unwrap();
        assert!(matches!(
            report.outcome,
            SolveOutcome::Limit(ResourceLimit {
                resource: Resource::ProofNodes,
                attempted: 1,
                limit: 0
            })
        ));

        let branching = branching_unsat_problem();
        let report = solve_with_caps(
            &branching,
            KernelCaps {
                max_proof_edges: 0,
                ..KernelCaps::default()
            },
        )
        .unwrap();
        assert!(matches!(
            report.outcome,
            SolveOutcome::Limit(ResourceLimit {
                resource: Resource::ProofEdges,
                attempted: 1,
                limit: 0
            })
        ));

        assert!(matches!(
            solve_with_caps(
                &trivial,
                KernelCaps {
                    max_work: HARD_MAX_WORK + 1,
                    ..KernelCaps::default()
                }
            ),
            Err(KernelError::CapAboveHardLimit {
                name: "max_work",
                ..
            })
        ));

        let valid = solve(&trivial).unwrap();
        assert!(matches!(
            checker::check_with_caps(
                &trivial,
                &valid.outcome,
                CheckCaps {
                    max_work: 0,
                    ..CheckCaps::default()
                }
            ),
            Err(CheckError::CapExceeded {
                resource: Resource::Work,
                attempted: 1,
                limit: 0
            })
        ));
        let limited = SolveOutcome::Limit(ResourceLimit {
            resource: Resource::Nodes,
            attempted: 1,
            limit: 0,
        });
        assert!(matches!(
            checker::check(&trivial, &limited),
            Err(CheckError::NoCertificate(_))
        ));
    }

    #[test]
    fn checker_rejects_mutated_sat_tables() {
        let constrained = LatinProblem::new(
            2,
            vec![1, 2, 2, 1],
            vec![source_clause(8, vec![CellValueLiteral::positive(0, 0)])],
        )
        .unwrap();
        let good = SatTable::from_parts(CERTIFICATE_VERSION, 2, vec![0, 1, 1, 0]);
        checker::check_sat(&constrained, &good, CheckCaps::default()).unwrap();

        let bad_version = SatTable::from_parts(99, 2, good.values.clone());
        assert!(matches!(
            checker::check_sat(&constrained, &bad_version, CheckCaps::default()),
            Err(CheckError::CertificateVersion { .. })
        ));
        let bad_length = SatTable::from_parts(CERTIFICATE_VERSION, 2, vec![0, 1]);
        assert!(matches!(
            checker::check_sat(&constrained, &bad_length, CheckCaps::default()),
            Err(CheckError::SatLength { .. })
        ));
        let bad_value = SatTable::from_parts(CERTIFICATE_VERSION, 2, vec![2, 1, 1, 0]);
        assert!(matches!(
            checker::check_sat(&constrained, &bad_value, CheckCaps::default()),
            Err(CheckError::SatValueOutOfRange { .. })
        ));
        let forbidden = SatTable::from_parts(CERTIFICATE_VERSION, 2, vec![1, 0, 0, 1]);
        assert!(matches!(
            checker::check_sat(&constrained, &forbidden, CheckCaps::default()),
            Err(CheckError::SatValueForbidden { .. })
        ));
        let duplicate = SatTable::from_parts(CERTIFICATE_VERSION, 2, vec![0, 0, 1, 1]);
        assert!(matches!(
            checker::check_sat(
                &LatinProblem::full(2, Vec::new()).unwrap(),
                &duplicate,
                CheckCaps::default()
            ),
            Err(CheckError::SatLatinDuplicate { .. })
        ));
        let false_clause_problem = LatinProblem::full(
            2,
            vec![source_clause(9, vec![CellValueLiteral::positive(0, 1)])],
        )
        .unwrap();
        assert!(matches!(
            checker::check_sat(&false_clause_problem, &good, CheckCaps::default()),
            Err(CheckError::SatClauseFalse { .. })
        ));
    }

    #[test]
    fn checker_rejects_malformed_unsat_tree_mutations() {
        let (problem, certificate) = branching_unsat_certificate();

        let mut bad_version = certificate.clone();
        bad_version.version = 2;
        assert!(matches!(
            checker::check_unsat(&problem, &bad_version, CheckCaps::default()),
            Err(CheckError::CertificateVersion { .. })
        ));

        let mut bad_root = certificate.clone();
        bad_root.root = bad_root.nodes.len() as u32;
        assert!(matches!(
            checker::check_unsat(&problem, &bad_root, CheckCaps::default()),
            Err(CheckError::RootOutOfRange { .. })
        ));

        let root = certificate.root as usize;
        let mut bad_cell = certificate.clone();
        let ProofNode::Branch { domain, edges, .. } = &bad_cell.nodes[root] else {
            unreachable!();
        };
        bad_cell.nodes[root] = ProofNode::branch(1, *domain, edges.clone());
        assert!(matches!(
            checker::check_unsat(&problem, &bad_cell, CheckCaps::default()),
            Err(CheckError::BranchCellMismatch { .. })
        ));

        let mut bad_domain = certificate.clone();
        let ProofNode::Branch { domain, .. } = &mut bad_domain.nodes[root] else {
            unreachable!();
        };
        *domain = 1;
        assert!(matches!(
            checker::check_unsat(&problem, &bad_domain, CheckCaps::default()),
            Err(CheckError::BranchDomainMismatch { .. })
        ));

        let mut missing_edge = certificate.clone();
        let ProofNode::Branch { edges, .. } = &mut missing_edge.nodes[root] else {
            unreachable!();
        };
        edges.pop();
        assert!(matches!(
            checker::check_unsat(&problem, &missing_edge, CheckCaps::default()),
            Err(CheckError::BranchArity { .. })
        ));

        let mut wrong_value = certificate.clone();
        let ProofNode::Branch { edges, .. } = &mut wrong_value.nodes[root] else {
            unreachable!();
        };
        edges[0].value = 1;
        assert!(matches!(
            checker::check_unsat(&problem, &wrong_value, CheckCaps::default()),
            Err(CheckError::BranchValueMismatch { .. })
        ));

        let mut cycle = certificate.clone();
        let cycle_root = cycle.root;
        let ProofNode::Branch { edges, .. } = &mut cycle.nodes[root] else {
            unreachable!();
        };
        edges[0].child = cycle_root;
        assert!(matches!(
            checker::check_unsat(&problem, &cycle, CheckCaps::default()),
            Err(CheckError::Cycle { .. })
        ));

        let mut shared = certificate.clone();
        let ProofNode::Branch { edges, .. } = &mut shared.nodes[root] else {
            unreachable!();
        };
        let first_child = edges[0].child;
        edges[1].child = first_child;
        assert!(matches!(
            checker::check_unsat(&problem, &shared, CheckCaps::default()),
            Err(CheckError::SharedNode { .. })
        ));

        let mut bad_leaf = certificate.clone();
        let ProofNode::Branch { edges, .. } = &bad_leaf.nodes[root] else {
            unreachable!();
        };
        let child = edges[0].child as usize;
        bad_leaf.nodes[child] = ProofNode::Conflict(Conflict::Clause {
            clause: ClauseId::new(999),
        });
        assert!(matches!(
            checker::check_unsat(&problem, &bad_leaf, CheckCaps::default()),
            Err(CheckError::ConflictMismatch { .. })
        ));

        let mut unreachable = certificate.clone();
        unreachable
            .nodes
            .push(ProofNode::conflict(Conflict::EmptyCell { cell: 0 }));
        assert!(matches!(
            checker::check_unsat(&problem, &unreachable, CheckCaps::default()),
            Err(CheckError::UnreachableNode { .. })
        ));

        let empty = UnsatCertificate::from_parts(CERTIFICATE_VERSION, problem.order, 0, Vec::new());
        assert!(matches!(
            checker::check_unsat(&problem, &empty, CheckCaps::default()),
            Err(CheckError::EmptyProof)
        ));

        assert!(matches!(
            checker::check_unsat(
                &problem,
                &certificate,
                CheckCaps {
                    max_proof_nodes: certificate.nodes.len() - 1,
                    ..CheckCaps::default()
                }
            ),
            Err(CheckError::CapExceeded {
                resource: Resource::ProofNodes,
                ..
            })
        ));
    }

    #[test]
    fn exhaustive_differential_order_one_and_two_domains_and_clauses() {
        for order in 1..=2u8 {
            let tables = enumerate_latin_tables(order);
            assert_eq!(tables.len(), if order == 1 { 1 } else { 2 });
            let n = usize::from(order);
            let cells = n * n;
            let domain_base = 1usize << order;
            let domain_cases = domain_base.pow(cells as u32);
            for mut encoded in 0..domain_cases {
                let mut domains = vec![0u8; cells];
                for domain in &mut domains {
                    *domain = (encoded % domain_base) as u8;
                    encoded /= domain_base;
                }
                let problem = LatinProblem::new(order, domains, Vec::new()).unwrap();
                let expected = brute_force_sat(&problem, &tables);
                let report = solve(&problem).unwrap();
                assert_eq!(
                    outcome_is_sat(&report.outcome),
                    expected,
                    "domain differential failed for order {order}: {:?}",
                    problem.domains()
                );
                checker::check(&problem, &report.outcome).unwrap();
            }

            let mut signed_literals = Vec::new();
            for cell in 0..cells as u8 {
                for value in 0..order {
                    signed_literals.push(CellValueLiteral::negative(cell, value));
                    signed_literals.push(CellValueLiteral::positive(cell, value));
                }
            }
            let clause_cases = 1usize << signed_literals.len();
            for clause_mask in 0..clause_cases {
                let literals = signed_literals
                    .iter()
                    .copied()
                    .enumerate()
                    .filter_map(|(index, literal)| {
                        (clause_mask & (1usize << index) != 0).then_some(literal)
                    })
                    .collect();
                let problem = LatinProblem::full(order, vec![source_clause(1, literals)]).unwrap();
                let expected = brute_force_sat(&problem, &tables);
                let report = solve(&problem).unwrap();
                assert_eq!(
                    outcome_is_sat(&report.outcome),
                    expected,
                    "single-clause differential failed for order {order}, mask {clause_mask:#x}"
                );
                if clause_mask % 257 == 0 {
                    checker::check(&problem, &report.outcome).unwrap();
                }
            }
        }
    }

    #[test]
    fn exhaustive_differential_order_three_partial_givens() {
        let order = 3u8;
        let tables = enumerate_latin_tables(order);
        assert_eq!(tables.len(), 12);
        let choices = [0b111u8, 0b001, 0b010, 0b100];
        let case_count = choices.len().pow(9);
        for case in 0..case_count {
            let mut encoded = case;
            let mut domains = Vec::with_capacity(9);
            for _ in 0..9 {
                domains.push(choices[encoded % choices.len()]);
                encoded /= choices.len();
            }
            let problem = LatinProblem::new(order, domains, Vec::new()).unwrap();
            let expected = brute_force_sat(&problem, &tables);
            let report = solve(&problem).unwrap();
            assert_eq!(
                outcome_is_sat(&report.outcome),
                expected,
                "order-three partial-given differential failed for case {case}"
            );
            if case % 4_096 == 0 {
                checker::check(&problem, &report.outcome).unwrap();
            }
        }
    }
}
