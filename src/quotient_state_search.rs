#![cfg(test)]
#![allow(dead_code)]
#![deny(unsafe_code)]

//! Deterministic, test-only quotient-state search for small finite ground EUF.
//!
//! This module is an exact reference oracle, not a production solver route.  It
//! searches semantic partitions of ground terms.  A rollback union-find holds
//! the current quotient, application signatures force congruent result classes
//! to merge, disequalities reject collapsed classes, and each quotient class
//! carries a finite-value mask.  When there are more classes than values the
//! search first branches on an optional quotient merge versus separation; it
//! otherwise branches on a finite value.  This is deliberately unlike a lazy
//! e-graph driven by Boolean theory literals: optional model quotients are first
//! class search decisions here.
//!
//! A SAT leaf is totalized into complete row-major function tables and checked
//! from scratch.  An UNSAT result carries the complete deterministic decision
//! tree.  [`check_unsat_certificate`] replays that tree with a separate naive
//! partition fixed point; it does not use the producer's rollback union-find.
//! Every resource limit returns [`SearchOutcome::Abstain`].  In particular, a
//! partially explored tree is never reported as UNSAT.
//!
//! ```text
//! rustc --edition=2024 -O -D warnings --test src/quotient_state_search.rs
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

pub type TermId = usize;
pub type FunctionId = usize;
pub type Value = u8;

const HARD_MAX_DOMAIN_SIZE: usize = u64::BITS as usize;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// A finite set of carrier values, represented by the low 64 bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValueDomain(u64);

impl ValueDomain {
    pub const EMPTY: Self = Self(0);

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    pub const fn contains(self, value: usize) -> bool {
        value < HARD_MAX_DOMAIN_SIZE && self.0 & (1u64 << value) != 0
    }

    pub const fn singleton_value(self) -> Option<Value> {
        if self.0.count_ones() == 1 {
            Some(self.0.trailing_zeros() as Value)
        } else {
            None
        }
    }

    pub fn singleton(value: usize) -> Option<Self> {
        (value < HARD_MAX_DOMAIN_SIZE).then(|| Self(1u64 << value))
    }

    pub fn full(domain_size: usize) -> Option<Self> {
        match domain_size {
            0 => None,
            HARD_MAX_DOMAIN_SIZE => Some(Self(u64::MAX)),
            1..HARD_MAX_DOMAIN_SIZE => Some(Self((1u64 << domain_size) - 1)),
            _ => None,
        }
    }

    fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    fn without(self, value: Value) -> Self {
        Self(self.0 & !(1u64 << value))
    }

    fn values(self) -> impl Iterator<Item = Value> {
        let mut bits = self.0;
        std::iter::from_fn(move || {
            if bits == 0 {
                return None;
            }
            let value = bits.trailing_zeros() as Value;
            bits &= bits - 1;
            Some(value)
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionDecl {
    pub arity: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Application {
    pub function: FunctionId,
    pub arguments: Vec<TermId>,
    pub result: TermId,
}

/// A finite, single-sorted, ground EUF instance.
///
/// Terms without an application record are free constants.  Multiple records
/// may name the same result term and cyclic records are allowed; they are just
/// equations against one shared total function interpretation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FiniteEufProblem {
    pub domain_size: usize,
    pub term_count: usize,
    pub functions: Vec<FunctionDecl>,
    pub applications: Vec<Application>,
    pub equalities: Vec<(TermId, TermId)>,
    pub disequalities: Vec<(TermId, TermId)>,
    pub value_domains: Vec<ValueDomain>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputError {
    InvalidDomainSize {
        domain_size: usize,
    },
    DomainCount {
        expected: usize,
        actual: usize,
    },
    DomainBitsOutOfRange {
        term: TermId,
        bits: u64,
    },
    UnknownFunction {
        application: usize,
        function: FunctionId,
    },
    ArityMismatch {
        application: usize,
        expected: usize,
        actual: usize,
    },
    UnknownTerm {
        context: &'static str,
        index: usize,
        term: TermId,
    },
}

impl fmt::Display for InputError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDomainSize { domain_size } => write!(
                output,
                "domain size {domain_size} is outside 1..={HARD_MAX_DOMAIN_SIZE}"
            ),
            Self::DomainCount { expected, actual } => write!(
                output,
                "received {actual} value domains for {expected} terms"
            ),
            Self::DomainBitsOutOfRange { term, bits } => {
                write!(output, "term {term} has out-of-range domain bits {bits:#x}")
            }
            Self::UnknownFunction {
                application,
                function,
            } => write!(
                output,
                "application {application} references unknown function {function}"
            ),
            Self::ArityMismatch {
                application,
                expected,
                actual,
            } => write!(
                output,
                "application {application} has arity {actual}, expected {expected}"
            ),
            Self::UnknownTerm {
                context,
                index,
                term,
            } => write!(
                output,
                "{context} entry {index} references unknown term {term}"
            ),
        }
    }
}

impl Error for InputError {}

impl FiniteEufProblem {
    pub fn validate(&self) -> Result<(), InputError> {
        let Some(allowed) = ValueDomain::full(self.domain_size) else {
            return Err(InputError::InvalidDomainSize {
                domain_size: self.domain_size,
            });
        };
        if self.value_domains.len() != self.term_count {
            return Err(InputError::DomainCount {
                expected: self.term_count,
                actual: self.value_domains.len(),
            });
        }
        for (term, domain) in self.value_domains.iter().copied().enumerate() {
            let outside = domain.bits() & !allowed.bits();
            if outside != 0 {
                return Err(InputError::DomainBitsOutOfRange {
                    term,
                    bits: outside,
                });
            }
        }
        for (application_index, application) in self.applications.iter().enumerate() {
            let Some(function) = self.functions.get(application.function) else {
                return Err(InputError::UnknownFunction {
                    application: application_index,
                    function: application.function,
                });
            };
            if application.arguments.len() != function.arity {
                return Err(InputError::ArityMismatch {
                    application: application_index,
                    expected: function.arity,
                    actual: application.arguments.len(),
                });
            }
            for (argument_index, term) in application.arguments.iter().copied().enumerate() {
                if term >= self.term_count {
                    return Err(InputError::UnknownTerm {
                        context: "application argument",
                        index: application_index
                            .saturating_mul(function.arity.max(1))
                            .saturating_add(argument_index),
                        term,
                    });
                }
            }
            if application.result >= self.term_count {
                return Err(InputError::UnknownTerm {
                    context: "application result",
                    index: application_index,
                    term: application.result,
                });
            }
        }
        validate_relations("equality", &self.equalities, self.term_count)?;
        validate_relations("disequality", &self.disequalities, self.term_count)?;
        Ok(())
    }

    pub fn fingerprint(&self) -> u64 {
        let mut hash = FNV_OFFSET;
        hash_word(&mut hash, self.domain_size);
        hash_word(&mut hash, self.term_count);
        hash_word(&mut hash, self.functions.len());
        for function in &self.functions {
            hash_word(&mut hash, function.arity);
        }
        hash_word(&mut hash, self.applications.len());
        for application in &self.applications {
            hash_word(&mut hash, application.function);
            hash_word(&mut hash, application.arguments.len());
            for argument in &application.arguments {
                hash_word(&mut hash, *argument);
            }
            hash_word(&mut hash, application.result);
        }
        hash_relations(&mut hash, &self.equalities);
        hash_relations(&mut hash, &self.disequalities);
        hash_word(&mut hash, self.value_domains.len());
        for domain in &self.value_domains {
            hash_u64(&mut hash, domain.bits());
        }
        hash
    }
}

fn validate_relations(
    context: &'static str,
    relations: &[(TermId, TermId)],
    term_count: usize,
) -> Result<(), InputError> {
    for (index, &(left, right)) in relations.iter().enumerate() {
        for term in [left, right] {
            if term >= term_count {
                return Err(InputError::UnknownTerm {
                    context,
                    index,
                    term,
                });
            }
        }
    }
    Ok(())
}

fn hash_relations(hash: &mut u64, relations: &[(TermId, TermId)]) {
    hash_word(hash, relations.len());
    for &(left, right) in relations {
        hash_word(hash, left);
        hash_word(hash, right);
    }
}

fn hash_word(hash: &mut u64, word: usize) {
    hash_u64(hash, word as u64);
}

fn hash_u64(hash: &mut u64, word: u64) {
    for byte in word.to_le_bytes() {
        *hash ^= u64::from(byte);
        *hash = hash.wrapping_mul(FNV_PRIME);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SearchCaps {
    pub max_domain_size: usize,
    pub max_terms: usize,
    pub max_functions: usize,
    pub max_arity: usize,
    pub max_applications: usize,
    pub max_relations: usize,
    pub max_search_nodes: usize,
    pub max_decisions: usize,
    pub max_propagations: usize,
    pub max_conflicts: usize,
    pub max_depth: usize,
    pub max_trail_entries: usize,
    pub max_certificate_nodes: usize,
    pub max_total_function_cells: usize,
}

impl Default for SearchCaps {
    fn default() -> Self {
        Self {
            max_domain_size: 8,
            max_terms: 24,
            max_functions: 16,
            max_arity: 4,
            max_applications: 64,
            max_relations: 128,
            max_search_nodes: 1_000_000,
            max_decisions: 1_000_000,
            max_propagations: 5_000_000,
            max_conflicts: 1_000_000,
            max_depth: 256,
            max_trail_entries: 2_048,
            max_certificate_nodes: 1_000_000,
            max_total_function_cells: 100_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbstainReason {
    StructuralCap {
        resource: &'static str,
        limit: usize,
        actual: usize,
    },
    SearchCap {
        resource: &'static str,
        limit: usize,
    },
    ArithmeticOverflow,
    InternalConsistency(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchTelemetry {
    pub search_nodes: usize,
    pub decisions: usize,
    pub quotient_decisions: usize,
    pub value_decisions: usize,
    pub branch_attempts: usize,
    pub propagations: usize,
    pub equality_merges: usize,
    pub signature_scans: usize,
    pub signatures_considered: usize,
    pub signature_collisions: usize,
    pub signature_merges: usize,
    pub forced_value_merges: usize,
    pub domain_reductions: usize,
    pub conflicts: usize,
    pub certificate_nodes: usize,
    pub models_built: usize,
    pub witness_checks: usize,
    pub max_depth: usize,
    pub max_trail_entries: usize,
    pub decision_trace_hash: u64,
}

impl Default for SearchTelemetry {
    fn default() -> Self {
        Self {
            search_nodes: 0,
            decisions: 0,
            quotient_decisions: 0,
            value_decisions: 0,
            branch_attempts: 0,
            propagations: 0,
            equality_merges: 0,
            signature_scans: 0,
            signatures_considered: 0,
            signature_collisions: 0,
            signature_merges: 0,
            forced_value_merges: 0,
            domain_reductions: 0,
            conflicts: 0,
            certificate_nodes: 0,
            models_built: 0,
            witness_checks: 0,
            max_depth: 0,
            max_trail_entries: 0,
            decision_trace_hash: FNV_OFFSET,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotalFunctionTable {
    pub arity: usize,
    /// Row-major table; the final argument varies fastest.
    pub values: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SatWitness {
    pub term_values: Vec<Value>,
    pub functions: Vec<TotalFunctionTable>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConflictClaim {
    EmptyDomain {
        representative: TermId,
    },
    DisequalityCollapsed {
        left: TermId,
        right: TermId,
    },
    ForcedValueCollision {
        left: TermId,
        right: TermId,
        value: Value,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValueProofBranch {
    pub value: Value,
    pub proof: Box<UnsatProof>,
}

/// Untrusted exhaustive search tree.  The checker reconstructs every state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnsatProof {
    Conflict(ConflictClaim),
    QuotientSplit {
        left: TermId,
        right: TermId,
        merged: Box<UnsatProof>,
        separate: Box<UnsatProof>,
    },
    ValueSplit {
        term: TermId,
        branches: Vec<ValueProofBranch>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsatCertificate {
    /// Non-cryptographic routing guard.  Soundness comes from full replay.
    pub problem_fingerprint: u64,
    pub root: UnsatProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchOutcome {
    Sat {
        witness: SatWitness,
        telemetry: SearchTelemetry,
    },
    Unsat {
        certificate: UnsatCertificate,
        telemetry: SearchTelemetry,
    },
    Abstain {
        reason: AbstainReason,
        telemetry: SearchTelemetry,
    },
}

impl SearchOutcome {
    pub fn telemetry(&self) -> &SearchTelemetry {
        match self {
            Self::Sat { telemetry, .. }
            | Self::Unsat { telemetry, .. }
            | Self::Abstain { telemetry, .. } => telemetry,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessError {
    InvalidProblem(InputError),
    TermCount {
        expected: usize,
        actual: usize,
    },
    TermValueOutOfRange {
        term: TermId,
        value: Value,
    },
    TermOutsideDomain {
        term: TermId,
        value: Value,
    },
    EqualityViolated {
        left: TermId,
        right: TermId,
    },
    DisequalityViolated {
        left: TermId,
        right: TermId,
    },
    FunctionCount {
        expected: usize,
        actual: usize,
    },
    FunctionArity {
        function: FunctionId,
        expected: usize,
        actual: usize,
    },
    FunctionTableSize {
        function: FunctionId,
        expected: usize,
        actual: usize,
    },
    FunctionValueOutOfRange {
        function: FunctionId,
        cell: usize,
        value: Value,
    },
    ApplicationViolated {
        application: usize,
    },
    ArithmeticOverflow,
}

impl fmt::Display for WitnessError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "invalid finite EUF witness: {self:?}")
    }
}

impl Error for WitnessError {}

pub fn check_sat_witness(
    problem: &FiniteEufProblem,
    witness: &SatWitness,
) -> Result<(), WitnessError> {
    problem.validate().map_err(WitnessError::InvalidProblem)?;
    if witness.term_values.len() != problem.term_count {
        return Err(WitnessError::TermCount {
            expected: problem.term_count,
            actual: witness.term_values.len(),
        });
    }
    for (term, value) in witness.term_values.iter().copied().enumerate() {
        if usize::from(value) >= problem.domain_size {
            return Err(WitnessError::TermValueOutOfRange { term, value });
        }
        if !problem.value_domains[term].contains(usize::from(value)) {
            return Err(WitnessError::TermOutsideDomain { term, value });
        }
    }
    for &(left, right) in &problem.equalities {
        if witness.term_values[left] != witness.term_values[right] {
            return Err(WitnessError::EqualityViolated { left, right });
        }
    }
    for &(left, right) in &problem.disequalities {
        if witness.term_values[left] == witness.term_values[right] {
            return Err(WitnessError::DisequalityViolated { left, right });
        }
    }
    if witness.functions.len() != problem.functions.len() {
        return Err(WitnessError::FunctionCount {
            expected: problem.functions.len(),
            actual: witness.functions.len(),
        });
    }
    for (function_id, (declaration, table)) in
        problem.functions.iter().zip(&witness.functions).enumerate()
    {
        if declaration.arity != table.arity {
            return Err(WitnessError::FunctionArity {
                function: function_id,
                expected: declaration.arity,
                actual: table.arity,
            });
        }
        let expected = checked_power(problem.domain_size, declaration.arity)
            .ok_or(WitnessError::ArithmeticOverflow)?;
        if table.values.len() != expected {
            return Err(WitnessError::FunctionTableSize {
                function: function_id,
                expected,
                actual: table.values.len(),
            });
        }
        for (cell, value) in table.values.iter().copied().enumerate() {
            if usize::from(value) >= problem.domain_size {
                return Err(WitnessError::FunctionValueOutOfRange {
                    function: function_id,
                    cell,
                    value,
                });
            }
        }
    }
    for (application_index, application) in problem.applications.iter().enumerate() {
        let arguments: Vec<_> = application
            .arguments
            .iter()
            .map(|term| witness.term_values[*term])
            .collect();
        let cell =
            tuple_index(&arguments, problem.domain_size).ok_or(WitnessError::ArithmeticOverflow)?;
        if witness.functions[application.function].values[cell]
            != witness.term_values[application.result]
        {
            return Err(WitnessError::ApplicationViolated {
                application: application_index,
            });
        }
    }
    Ok(())
}

fn checked_power(base: usize, exponent: usize) -> Option<usize> {
    let mut result = 1usize;
    for _ in 0..exponent {
        result = result.checked_mul(base)?;
    }
    Some(result)
}

fn tuple_index(arguments: &[Value], domain_size: usize) -> Option<usize> {
    let mut index = 0usize;
    for argument in arguments {
        index = index.checked_mul(domain_size)?;
        index = index.checked_add(usize::from(*argument))?;
    }
    Some(index)
}

#[derive(Clone, Copy, Debug)]
struct Snapshot {
    trail_len: usize,
    disequality_len: usize,
}

#[derive(Clone, Debug)]
enum TrailEntry {
    Union {
        child: TermId,
        parent: TermId,
        old_parent_size: usize,
        old_parent_domain: ValueDomain,
    },
    Domain {
        root: TermId,
        old_domain: ValueDomain,
    },
}

#[derive(Debug)]
struct RollbackState {
    parent: Vec<TermId>,
    size: Vec<usize>,
    domain: Vec<ValueDomain>,
    disequalities: Vec<(TermId, TermId)>,
    base_disequality_len: usize,
    trail: Vec<TrailEntry>,
}

impl RollbackState {
    fn new(problem: &FiniteEufProblem) -> Self {
        let mut disequalities: Vec<_> = problem
            .disequalities
            .iter()
            .map(|&(left, right)| ordered_pair(left, right))
            .collect();
        disequalities.sort_unstable();
        disequalities.dedup();
        let base_disequality_len = disequalities.len();
        Self {
            parent: (0..problem.term_count).collect(),
            size: vec![1; problem.term_count],
            domain: problem.value_domains.clone(),
            disequalities,
            base_disequality_len,
            trail: Vec::new(),
        }
    }

    fn find(&self, mut term: TermId) -> TermId {
        while self.parent[term] != term {
            term = self.parent[term];
        }
        term
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            trail_len: self.trail.len(),
            disequality_len: self.disequalities.len(),
        }
    }

    fn rollback(&mut self, snapshot: Snapshot) {
        while self.trail.len() > snapshot.trail_len {
            match self.trail.pop().expect("trail length was checked") {
                TrailEntry::Union {
                    child,
                    parent,
                    old_parent_size,
                    old_parent_domain,
                } => {
                    self.parent[child] = child;
                    self.size[parent] = old_parent_size;
                    self.domain[parent] = old_parent_domain;
                }
                TrailEntry::Domain { root, old_domain } => {
                    self.domain[root] = old_domain;
                }
            }
        }
        self.disequalities.truncate(snapshot.disequality_len);
    }

    fn current_trail_entries(&self) -> usize {
        self.trail
            .len()
            .saturating_add(self.disequalities.len() - self.base_disequality_len)
    }

    fn ensure_trail_capacity(
        &self,
        caps: &SearchCaps,
        additional: usize,
    ) -> Result<(), AbstainReason> {
        let attempted = self
            .current_trail_entries()
            .checked_add(additional)
            .ok_or(AbstainReason::ArithmeticOverflow)?;
        if attempted > caps.max_trail_entries {
            return Err(AbstainReason::SearchCap {
                resource: "trail entries",
                limit: caps.max_trail_entries,
            });
        }
        Ok(())
    }

    fn update_max_trail(&self, telemetry: &mut SearchTelemetry) {
        telemetry.max_trail_entries = telemetry
            .max_trail_entries
            .max(self.current_trail_entries());
    }

    fn union(
        &mut self,
        left: TermId,
        right: TermId,
        caps: &SearchCaps,
        telemetry: &mut SearchTelemetry,
    ) -> Result<bool, AbstainReason> {
        let mut left_root = self.find(left);
        let mut right_root = self.find(right);
        if left_root == right_root {
            return Ok(false);
        }
        if self.size[left_root] < self.size[right_root]
            || (self.size[left_root] == self.size[right_root] && left_root > right_root)
        {
            std::mem::swap(&mut left_root, &mut right_root);
        }
        self.ensure_trail_capacity(caps, 1)?;
        self.trail.push(TrailEntry::Union {
            child: right_root,
            parent: left_root,
            old_parent_size: self.size[left_root],
            old_parent_domain: self.domain[left_root],
        });
        self.parent[right_root] = left_root;
        self.size[left_root] += self.size[right_root];
        self.domain[left_root] = self.domain[left_root].intersect(self.domain[right_root]);
        self.update_max_trail(telemetry);
        Ok(true)
    }

    fn intersect_domain(
        &mut self,
        term: TermId,
        restriction: ValueDomain,
        caps: &SearchCaps,
        telemetry: &mut SearchTelemetry,
    ) -> Result<bool, AbstainReason> {
        let root = self.find(term);
        let reduced = self.domain[root].intersect(restriction);
        if reduced == self.domain[root] {
            return Ok(false);
        }
        self.ensure_trail_capacity(caps, 1)?;
        self.trail.push(TrailEntry::Domain {
            root,
            old_domain: self.domain[root],
        });
        self.domain[root] = reduced;
        self.update_max_trail(telemetry);
        Ok(true)
    }

    fn separate(
        &mut self,
        left: TermId,
        right: TermId,
        caps: &SearchCaps,
        telemetry: &mut SearchTelemetry,
    ) -> Result<(), AbstainReason> {
        self.ensure_trail_capacity(caps, 1)?;
        self.disequalities.push(ordered_pair(left, right));
        self.update_max_trail(telemetry);
        Ok(())
    }

    fn roots(&self) -> Vec<TermId> {
        let mut roots = Vec::new();
        for term in 0..self.parent.len() {
            if self.find(term) == term {
                roots.push(term);
            }
        }
        roots
    }

    fn representatives(&self) -> Vec<TermId> {
        let mut least = BTreeMap::<TermId, TermId>::new();
        for term in 0..self.parent.len() {
            least.entry(self.find(term)).or_insert(term);
        }
        let mut representatives: Vec<_> = least.into_values().collect();
        representatives.sort_unstable();
        representatives
    }

    fn representative_of_root(&self, root: TermId) -> TermId {
        (0..self.parent.len())
            .find(|term| self.find(*term) == root)
            .expect("every root contains itself")
    }

    fn has_disequality_between(&self, left_root: TermId, right_root: TermId) -> bool {
        self.disequalities.iter().any(|&(left, right)| {
            let left = self.find(left);
            let right = self.find(right);
            (left == left_root && right == right_root) || (left == right_root && right == left_root)
        })
    }

    fn first_collapsed_disequality(&self) -> Option<(TermId, TermId)> {
        self.disequalities
            .iter()
            .copied()
            .find(|&(left, right)| self.find(left) == self.find(right))
    }

    fn first_empty_domain(&self) -> Option<TermId> {
        self.roots()
            .into_iter()
            .find(|root| self.domain[*root].is_empty())
    }

    fn all_singleton(&self) -> bool {
        self.roots()
            .into_iter()
            .all(|root| self.domain[root].singleton_value().is_some())
    }
}

fn ordered_pair(left: TermId, right: TermId) -> (TermId, TermId) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PropagationKind {
    Equality,
    Signature,
    ForcedValueMerge,
    DomainReduction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PathAssumption {
    Equal(TermId, TermId),
    Distinct(TermId, TermId),
    Value(TermId, Value),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum NextDecision {
    Quotient { left: TermId, right: TermId },
    Value { term: TermId, values: Vec<Value> },
    Complete,
}

#[derive(Debug)]
enum DfsResult {
    Sat(SatWitness),
    Unsat(UnsatProof),
    Abstain(AbstainReason),
}

struct Search<'a> {
    problem: &'a FiniteEufProblem,
    caps: &'a SearchCaps,
    state: RollbackState,
    path: Vec<PathAssumption>,
    telemetry: SearchTelemetry,
}

pub fn solve_quotient_states(
    problem: &FiniteEufProblem,
    caps: &SearchCaps,
) -> Result<SearchOutcome, InputError> {
    problem.validate()?;
    let mut telemetry = SearchTelemetry::default();
    let relation_count = match problem
        .equalities
        .len()
        .checked_add(problem.disequalities.len())
    {
        Some(count) => count,
        None => {
            return Ok(SearchOutcome::Abstain {
                reason: AbstainReason::ArithmeticOverflow,
                telemetry,
            });
        }
    };
    for (resource, actual, limit) in [
        ("domain size", problem.domain_size, caps.max_domain_size),
        ("terms", problem.term_count, caps.max_terms),
        ("functions", problem.functions.len(), caps.max_functions),
        (
            "applications",
            problem.applications.len(),
            caps.max_applications,
        ),
        ("relations", relation_count, caps.max_relations),
    ] {
        if actual > limit {
            return Ok(SearchOutcome::Abstain {
                reason: AbstainReason::StructuralCap {
                    resource,
                    limit,
                    actual,
                },
                telemetry,
            });
        }
    }
    if let Some(actual) = problem
        .functions
        .iter()
        .map(|function| function.arity)
        .max()
        .filter(|arity| *arity > caps.max_arity)
    {
        return Ok(SearchOutcome::Abstain {
            reason: AbstainReason::StructuralCap {
                resource: "function arity",
                limit: caps.max_arity,
                actual,
            },
            telemetry,
        });
    }

    let mut state = RollbackState::new(problem);
    for &(left, right) in &problem.equalities {
        match state.union(left, right, caps, &mut telemetry) {
            Ok(true) => {
                if let Err(reason) =
                    record_propagation(&mut telemetry, caps, PropagationKind::Equality)
                {
                    return Ok(SearchOutcome::Abstain { reason, telemetry });
                }
            }
            Ok(false) => {}
            Err(reason) => return Ok(SearchOutcome::Abstain { reason, telemetry }),
        }
    }

    let mut search = Search {
        problem,
        caps,
        state,
        path: Vec::new(),
        telemetry,
    };
    let result = search.dfs(0);
    let telemetry = search.telemetry;
    Ok(match result {
        DfsResult::Sat(witness) => SearchOutcome::Sat { witness, telemetry },
        DfsResult::Unsat(root) => SearchOutcome::Unsat {
            certificate: UnsatCertificate {
                problem_fingerprint: problem.fingerprint(),
                root,
            },
            telemetry,
        },
        DfsResult::Abstain(reason) => SearchOutcome::Abstain { reason, telemetry },
    })
}

impl Search<'_> {
    fn dfs(&mut self, depth: usize) -> DfsResult {
        if let Err(reason) = self.enter_node(depth) {
            return DfsResult::Abstain(reason);
        }
        match self.propagate() {
            Ok(Some(())) => return self.conflict_leaf(),
            Ok(None) => {}
            Err(reason) => return DfsResult::Abstain(reason),
        }

        let decision = choose_state_decision(&self.state, self.problem.domain_size);
        match decision {
            NextDecision::Complete => self.complete_model(),
            NextDecision::Quotient { left, right } => {
                if let Err(reason) =
                    self.record_decision(depth, &NextDecision::Quotient { left, right })
                {
                    return DfsResult::Abstain(reason);
                }
                let snapshot = self.state.snapshot();
                self.telemetry.branch_attempts += 1;
                self.path.push(PathAssumption::Equal(left, right));
                let merged_result =
                    match self
                        .state
                        .union(left, right, self.caps, &mut self.telemetry)
                    {
                        Ok(_) => self.dfs(depth + 1),
                        Err(reason) => DfsResult::Abstain(reason),
                    };
                self.path.pop();
                self.state.rollback(snapshot);
                match merged_result {
                    DfsResult::Sat(witness) => return DfsResult::Sat(witness),
                    DfsResult::Abstain(reason) => return DfsResult::Abstain(reason),
                    DfsResult::Unsat(merged) => {
                        self.telemetry.branch_attempts += 1;
                        self.path.push(PathAssumption::Distinct(left, right));
                        let separate_result =
                            match self
                                .state
                                .separate(left, right, self.caps, &mut self.telemetry)
                            {
                                Ok(()) => self.dfs(depth + 1),
                                Err(reason) => DfsResult::Abstain(reason),
                            };
                        self.path.pop();
                        self.state.rollback(snapshot);
                        match separate_result {
                            DfsResult::Sat(witness) => DfsResult::Sat(witness),
                            DfsResult::Abstain(reason) => DfsResult::Abstain(reason),
                            DfsResult::Unsat(separate) => match self.reserve_certificate_node() {
                                Ok(()) => DfsResult::Unsat(UnsatProof::QuotientSplit {
                                    left,
                                    right,
                                    merged: Box::new(merged),
                                    separate: Box::new(separate),
                                }),
                                Err(reason) => DfsResult::Abstain(reason),
                            },
                        }
                    }
                }
            }
            NextDecision::Value { term, values } => {
                if let Err(reason) = self.record_decision(
                    depth,
                    &NextDecision::Value {
                        term,
                        values: values.clone(),
                    },
                ) {
                    return DfsResult::Abstain(reason);
                }
                let snapshot = self.state.snapshot();
                let mut proofs = Vec::with_capacity(values.len());
                for value in values {
                    self.telemetry.branch_attempts += 1;
                    self.path.push(PathAssumption::Value(term, value));
                    let restriction = ValueDomain::singleton(usize::from(value))
                        .expect("search values are in range");
                    let branch = match self.state.intersect_domain(
                        term,
                        restriction,
                        self.caps,
                        &mut self.telemetry,
                    ) {
                        Ok(_) => self.dfs(depth + 1),
                        Err(reason) => DfsResult::Abstain(reason),
                    };
                    self.path.pop();
                    self.state.rollback(snapshot);
                    match branch {
                        DfsResult::Sat(witness) => return DfsResult::Sat(witness),
                        DfsResult::Abstain(reason) => return DfsResult::Abstain(reason),
                        DfsResult::Unsat(proof) => proofs.push(ValueProofBranch {
                            value,
                            proof: Box::new(proof),
                        }),
                    }
                }
                match self.reserve_certificate_node() {
                    Ok(()) => DfsResult::Unsat(UnsatProof::ValueSplit {
                        term,
                        branches: proofs,
                    }),
                    Err(reason) => DfsResult::Abstain(reason),
                }
            }
        }
    }

    fn enter_node(&mut self, depth: usize) -> Result<(), AbstainReason> {
        if depth > self.caps.max_depth {
            return Err(AbstainReason::SearchCap {
                resource: "search depth",
                limit: self.caps.max_depth,
            });
        }
        if self.telemetry.search_nodes >= self.caps.max_search_nodes {
            return Err(AbstainReason::SearchCap {
                resource: "search nodes",
                limit: self.caps.max_search_nodes,
            });
        }
        self.telemetry.search_nodes += 1;
        self.telemetry.max_depth = self.telemetry.max_depth.max(depth);
        Ok(())
    }

    fn record_decision(
        &mut self,
        depth: usize,
        decision: &NextDecision,
    ) -> Result<(), AbstainReason> {
        if self.telemetry.decisions >= self.caps.max_decisions {
            return Err(AbstainReason::SearchCap {
                resource: "decisions",
                limit: self.caps.max_decisions,
            });
        }
        self.telemetry.decisions += 1;
        let (tag, first, second) = match decision {
            NextDecision::Quotient { left, right } => {
                self.telemetry.quotient_decisions += 1;
                (1usize, *left, *right)
            }
            NextDecision::Value { term, values } => {
                self.telemetry.value_decisions += 1;
                (2usize, *term, values.len())
            }
            NextDecision::Complete => unreachable!("complete states are not decisions"),
        };
        for word in [depth, tag, first, second] {
            hash_word(&mut self.telemetry.decision_trace_hash, word);
        }
        Ok(())
    }

    fn reserve_certificate_node(&mut self) -> Result<(), AbstainReason> {
        if self.telemetry.certificate_nodes >= self.caps.max_certificate_nodes {
            return Err(AbstainReason::SearchCap {
                resource: "certificate nodes",
                limit: self.caps.max_certificate_nodes,
            });
        }
        self.telemetry.certificate_nodes += 1;
        Ok(())
    }

    fn conflict_leaf(&mut self) -> DfsResult {
        if self.telemetry.conflicts >= self.caps.max_conflicts {
            return DfsResult::Abstain(AbstainReason::SearchCap {
                resource: "conflicts",
                limit: self.caps.max_conflicts,
            });
        }
        let claim = match audit_path(self.problem, &self.path, None) {
            Ok(AuditOutcome::Conflict(claim)) => claim,
            Ok(AuditOutcome::Consistent(_)) => {
                return DfsResult::Abstain(AbstainReason::InternalConsistency(
                    "rollback state conflict was not reproduced by declarative audit",
                ));
            }
            Err(_) => {
                return DfsResult::Abstain(AbstainReason::InternalConsistency(
                    "declarative audit failed while constructing a conflict leaf",
                ));
            }
        };
        self.telemetry.conflicts += 1;
        match self.reserve_certificate_node() {
            Ok(()) => DfsResult::Unsat(UnsatProof::Conflict(claim)),
            Err(reason) => DfsResult::Abstain(reason),
        }
    }

    fn complete_model(&mut self) -> DfsResult {
        if !self.state.all_singleton() {
            return DfsResult::Abstain(AbstainReason::InternalConsistency(
                "decision heuristic declared a non-singleton state complete",
            ));
        }
        let witness = match build_total_witness(
            self.problem,
            &self.state,
            self.caps.max_total_function_cells,
        ) {
            Ok(witness) => witness,
            Err(reason) => return DfsResult::Abstain(reason),
        };
        self.telemetry.models_built += 1;
        self.telemetry.witness_checks += 1;
        match check_sat_witness(self.problem, &witness) {
            Ok(()) => DfsResult::Sat(witness),
            Err(_) => DfsResult::Abstain(AbstainReason::InternalConsistency(
                "constructed total witness failed independent validation",
            )),
        }
    }

    /// Returns `Some(())` for conflict and `None` at a fixed point.
    fn propagate(&mut self) -> Result<Option<()>, AbstainReason> {
        loop {
            if self.state.first_empty_domain().is_some()
                || self.state.first_collapsed_disequality().is_some()
            {
                return Ok(Some(()));
            }

            self.telemetry.signature_scans += 1;
            let mut signatures = BTreeMap::<(FunctionId, Vec<TermId>), TermId>::new();
            let mut merged_signature = false;
            for application in &self.problem.applications {
                self.telemetry.signatures_considered += 1;
                let key = (
                    application.function,
                    application
                        .arguments
                        .iter()
                        .map(|term| self.state.find(*term))
                        .collect(),
                );
                if let Some(previous_result) = signatures.get(&key).copied() {
                    self.telemetry.signature_collisions += 1;
                    if self.state.find(previous_result) != self.state.find(application.result) {
                        self.state.union(
                            previous_result,
                            application.result,
                            self.caps,
                            &mut self.telemetry,
                        )?;
                        record_propagation(
                            &mut self.telemetry,
                            self.caps,
                            PropagationKind::Signature,
                        )?;
                        merged_signature = true;
                        break;
                    }
                } else {
                    signatures.insert(key, application.result);
                }
            }
            if merged_signature {
                continue;
            }

            let roots = self.state.roots();
            let mut merged_value = false;
            'value_pairs: for (left_index, left_root) in roots.iter().copied().enumerate() {
                let Some(left_value) = self.state.domain[left_root].singleton_value() else {
                    continue;
                };
                for right_root in roots.iter().copied().skip(left_index + 1) {
                    if self.state.domain[right_root].singleton_value() != Some(left_value) {
                        continue;
                    }
                    if self.state.has_disequality_between(left_root, right_root) {
                        return Ok(Some(()));
                    }
                    self.state
                        .union(left_root, right_root, self.caps, &mut self.telemetry)?;
                    record_propagation(
                        &mut self.telemetry,
                        self.caps,
                        PropagationKind::ForcedValueMerge,
                    )?;
                    merged_value = true;
                    break 'value_pairs;
                }
            }
            if merged_value {
                continue;
            }

            let mut reduced_domain = false;
            for &(left, right) in &self.state.disequalities.clone() {
                let left_root = self.state.find(left);
                let right_root = self.state.find(right);
                if left_root == right_root {
                    return Ok(Some(()));
                }
                if let Some(value) = self.state.domain[left_root].singleton_value() {
                    if self.state.domain[right_root].contains(usize::from(value)) {
                        let restriction = self.state.domain[right_root].without(value);
                        self.state.intersect_domain(
                            right_root,
                            restriction,
                            self.caps,
                            &mut self.telemetry,
                        )?;
                        record_propagation(
                            &mut self.telemetry,
                            self.caps,
                            PropagationKind::DomainReduction,
                        )?;
                        reduced_domain = true;
                        break;
                    }
                }
                if let Some(value) = self.state.domain[right_root].singleton_value() {
                    if self.state.domain[left_root].contains(usize::from(value)) {
                        let restriction = self.state.domain[left_root].without(value);
                        self.state.intersect_domain(
                            left_root,
                            restriction,
                            self.caps,
                            &mut self.telemetry,
                        )?;
                        record_propagation(
                            &mut self.telemetry,
                            self.caps,
                            PropagationKind::DomainReduction,
                        )?;
                        reduced_domain = true;
                        break;
                    }
                }
            }
            if reduced_domain {
                continue;
            }
            return Ok(None);
        }
    }
}

fn record_propagation(
    telemetry: &mut SearchTelemetry,
    caps: &SearchCaps,
    kind: PropagationKind,
) -> Result<(), AbstainReason> {
    if telemetry.propagations >= caps.max_propagations {
        return Err(AbstainReason::SearchCap {
            resource: "propagations",
            limit: caps.max_propagations,
        });
    }
    telemetry.propagations += 1;
    match kind {
        PropagationKind::Equality => telemetry.equality_merges += 1,
        PropagationKind::Signature => telemetry.signature_merges += 1,
        PropagationKind::ForcedValueMerge => telemetry.forced_value_merges += 1,
        PropagationKind::DomainReduction => telemetry.domain_reductions += 1,
    }
    Ok(())
}

fn choose_state_decision(state: &RollbackState, domain_size: usize) -> NextDecision {
    let representatives = state.representatives();
    if representatives.len() > domain_size {
        let mut best: Option<(usize, TermId, TermId)> = None;
        for (left_index, left) in representatives.iter().copied().enumerate() {
            let left_root = state.find(left);
            for right in representatives.iter().copied().skip(left_index + 1) {
                let right_root = state.find(right);
                if state.has_disequality_between(left_root, right_root) {
                    continue;
                }
                let overlap = state.domain[left_root]
                    .intersect(state.domain[right_root])
                    .len();
                if overlap == 0 {
                    continue;
                }
                let candidate = (overlap, left, right);
                if best.as_ref().is_none_or(|current| candidate.0 > current.0) {
                    best = Some(candidate);
                }
            }
        }
        if let Some((_, left, right)) = best {
            return NextDecision::Quotient { left, right };
        }
    }

    let mut best_value: Option<(usize, TermId, Vec<Value>)> = None;
    for representative in representatives {
        let root = state.find(representative);
        let domain = state.domain[root];
        if domain.len() <= 1 {
            continue;
        }
        let candidate = (domain.len(), representative, domain.values().collect());
        if best_value.as_ref().is_none_or(|current| {
            candidate.0 < current.0 || (candidate.0 == current.0 && candidate.1 < current.1)
        }) {
            best_value = Some(candidate);
        }
    }
    match best_value {
        Some((_, term, values)) => NextDecision::Value { term, values },
        None => NextDecision::Complete,
    }
}

fn build_total_witness(
    problem: &FiniteEufProblem,
    state: &RollbackState,
    max_total_function_cells: usize,
) -> Result<SatWitness, AbstainReason> {
    let mut term_values = Vec::with_capacity(problem.term_count);
    for term in 0..problem.term_count {
        let root = state.find(term);
        let Some(value) = state.domain[root].singleton_value() else {
            return Err(AbstainReason::InternalConsistency(
                "model construction reached a non-singleton quotient class",
            ));
        };
        term_values.push(value);
    }

    let mut total_cells = 0usize;
    let mut functions = Vec::with_capacity(problem.functions.len());
    for declaration in &problem.functions {
        let cells = checked_power(problem.domain_size, declaration.arity)
            .ok_or(AbstainReason::ArithmeticOverflow)?;
        total_cells = total_cells
            .checked_add(cells)
            .ok_or(AbstainReason::ArithmeticOverflow)?;
        if total_cells > max_total_function_cells {
            return Err(AbstainReason::SearchCap {
                resource: "total function cells",
                limit: max_total_function_cells,
            });
        }
        functions.push(TotalFunctionTable {
            arity: declaration.arity,
            values: vec![0; cells],
        });
    }
    let mut observed: Vec<Vec<Option<Value>>> = functions
        .iter()
        .map(|function| vec![None; function.values.len()])
        .collect();
    for application in &problem.applications {
        let arguments: Vec<_> = application
            .arguments
            .iter()
            .map(|term| term_values[*term])
            .collect();
        let cell = tuple_index(&arguments, problem.domain_size)
            .ok_or(AbstainReason::ArithmeticOverflow)?;
        let value = term_values[application.result];
        if let Some(previous) = observed[application.function][cell] {
            if previous != value {
                return Err(AbstainReason::InternalConsistency(
                    "congruent applications retained different result values",
                ));
            }
        } else {
            observed[application.function][cell] = Some(value);
            functions[application.function].values[cell] = value;
        }
    }
    Ok(SatWitness {
        term_values,
        functions,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateCheckCaps {
    pub max_nodes: usize,
    pub max_depth: usize,
    pub max_path_assumptions: usize,
    pub max_audit_rounds: usize,
}

impl Default for CertificateCheckCaps {
    fn default() -> Self {
        Self {
            max_nodes: 1_000_000,
            max_depth: 256,
            max_path_assumptions: 256,
            max_audit_rounds: 100_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertificateError {
    InvalidProblem(InputError),
    FingerprintMismatch {
        expected: u64,
        actual: u64,
    },
    CheckCap {
        resource: &'static str,
        limit: usize,
    },
    ConflictClaimMismatch {
        expected: ConflictClaim,
        actual: ConflictClaim,
    },
    ConflictLeafAtConsistentState,
    InternalNodeAtConflict(ConflictClaim),
    DecisionMismatch,
    CompleteStateInUnsatTree,
    InvalidCertificateTerm(TermId),
    InvalidCertificateValue(Value),
    AuditDidNotConverge,
}

impl fmt::Display for CertificateError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "invalid quotient-state UNSAT certificate: {self:?}")
    }
}

impl Error for CertificateError {}

pub fn check_unsat_certificate(
    problem: &FiniteEufProblem,
    certificate: &UnsatCertificate,
    caps: &CertificateCheckCaps,
) -> Result<(), CertificateError> {
    problem
        .validate()
        .map_err(CertificateError::InvalidProblem)?;
    let expected = problem.fingerprint();
    if certificate.problem_fingerprint != expected {
        return Err(CertificateError::FingerprintMismatch {
            expected,
            actual: certificate.problem_fingerprint,
        });
    }
    let mut checker = CertificateChecker {
        problem,
        caps,
        path: Vec::new(),
        visited_nodes: 0,
    };
    checker.check_node(&certificate.root, 0)
}

struct CertificateChecker<'a> {
    problem: &'a FiniteEufProblem,
    caps: &'a CertificateCheckCaps,
    path: Vec<PathAssumption>,
    visited_nodes: usize,
}

impl CertificateChecker<'_> {
    fn check_node(&mut self, proof: &UnsatProof, depth: usize) -> Result<(), CertificateError> {
        if depth > self.caps.max_depth {
            return Err(CertificateError::CheckCap {
                resource: "certificate depth",
                limit: self.caps.max_depth,
            });
        }
        if self.visited_nodes >= self.caps.max_nodes {
            return Err(CertificateError::CheckCap {
                resource: "certificate nodes",
                limit: self.caps.max_nodes,
            });
        }
        self.visited_nodes += 1;
        let audit = audit_path(self.problem, &self.path, Some(self.caps.max_audit_rounds))?;
        match proof {
            UnsatProof::Conflict(claim) => match audit {
                AuditOutcome::Conflict(actual) if *claim == actual => Ok(()),
                AuditOutcome::Conflict(actual) => Err(CertificateError::ConflictClaimMismatch {
                    expected: actual,
                    actual: claim.clone(),
                }),
                AuditOutcome::Consistent(_) => Err(CertificateError::ConflictLeafAtConsistentState),
            },
            UnsatProof::QuotientSplit {
                left,
                right,
                merged,
                separate,
            } => {
                let AuditOutcome::Consistent(state) = audit else {
                    let AuditOutcome::Conflict(claim) = audit else {
                        unreachable!()
                    };
                    return Err(CertificateError::InternalNodeAtConflict(claim));
                };
                for term in [*left, *right] {
                    if term >= self.problem.term_count {
                        return Err(CertificateError::InvalidCertificateTerm(term));
                    }
                }
                if state.choose_decision(self.problem.domain_size)
                    != (NextDecision::Quotient {
                        left: *left,
                        right: *right,
                    })
                {
                    return Err(CertificateError::DecisionMismatch);
                }
                self.push_assumption(PathAssumption::Equal(*left, *right))?;
                self.check_node(merged, depth + 1)?;
                self.path.pop();
                self.push_assumption(PathAssumption::Distinct(*left, *right))?;
                self.check_node(separate, depth + 1)?;
                self.path.pop();
                Ok(())
            }
            UnsatProof::ValueSplit { term, branches } => {
                let AuditOutcome::Consistent(state) = audit else {
                    let AuditOutcome::Conflict(claim) = audit else {
                        unreachable!()
                    };
                    return Err(CertificateError::InternalNodeAtConflict(claim));
                };
                if *term >= self.problem.term_count {
                    return Err(CertificateError::InvalidCertificateTerm(*term));
                }
                let expected = match state.choose_decision(self.problem.domain_size) {
                    NextDecision::Value { term, values } => (term, values),
                    NextDecision::Complete => {
                        return Err(CertificateError::CompleteStateInUnsatTree);
                    }
                    NextDecision::Quotient { .. } => {
                        return Err(CertificateError::DecisionMismatch);
                    }
                };
                let actual_values: Vec<_> = branches.iter().map(|branch| branch.value).collect();
                if expected != (*term, actual_values) {
                    return Err(CertificateError::DecisionMismatch);
                }
                for branch in branches {
                    if usize::from(branch.value) >= self.problem.domain_size {
                        return Err(CertificateError::InvalidCertificateValue(branch.value));
                    }
                    self.push_assumption(PathAssumption::Value(*term, branch.value))?;
                    self.check_node(&branch.proof, depth + 1)?;
                    self.path.pop();
                }
                Ok(())
            }
        }
    }

    fn push_assumption(&mut self, assumption: PathAssumption) -> Result<(), CertificateError> {
        if self.path.len() >= self.caps.max_path_assumptions {
            return Err(CertificateError::CheckCap {
                resource: "path assumptions",
                limit: self.caps.max_path_assumptions,
            });
        }
        self.path.push(assumption);
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct AuditState {
    labels: Vec<TermId>,
    domains: Vec<ValueDomain>,
    disequalities: BTreeSet<(TermId, TermId)>,
}

impl AuditState {
    fn representatives(&self) -> Vec<TermId> {
        let mut representatives: Vec<_> = self.labels.iter().copied().collect();
        representatives.sort_unstable();
        representatives.dedup();
        representatives
    }

    fn choose_decision(&self, domain_size: usize) -> NextDecision {
        let representatives = self.representatives();
        if representatives.len() > domain_size {
            let mut best: Option<(usize, TermId, TermId)> = None;
            for (left_index, left) in representatives.iter().copied().enumerate() {
                for right in representatives.iter().copied().skip(left_index + 1) {
                    if self.disequalities.contains(&(left, right)) {
                        continue;
                    }
                    let overlap = self.domains[left].intersect(self.domains[right]).len();
                    if overlap == 0 {
                        continue;
                    }
                    let candidate = (overlap, left, right);
                    if best.as_ref().is_none_or(|current| candidate.0 > current.0) {
                        best = Some(candidate);
                    }
                }
            }
            if let Some((_, left, right)) = best {
                return NextDecision::Quotient { left, right };
            }
        }

        let mut best: Option<(usize, TermId, Vec<Value>)> = None;
        for representative in representatives {
            let domain = self.domains[representative];
            if domain.len() <= 1 {
                continue;
            }
            let candidate = (domain.len(), representative, domain.values().collect());
            if best.as_ref().is_none_or(|current| {
                candidate.0 < current.0 || (candidate.0 == current.0 && candidate.1 < current.1)
            }) {
                best = Some(candidate);
            }
        }
        match best {
            Some((_, term, values)) => NextDecision::Value { term, values },
            None => NextDecision::Complete,
        }
    }
}

#[derive(Clone, Debug)]
enum AuditOutcome {
    Conflict(ConflictClaim),
    Consistent(AuditState),
}

fn audit_path(
    problem: &FiniteEufProblem,
    path: &[PathAssumption],
    max_rounds: Option<usize>,
) -> Result<AuditOutcome, CertificateError> {
    let mut labels: Vec<_> = (0..problem.term_count).collect();
    for &(left, right) in &problem.equalities {
        naive_merge(&mut labels, left, right);
    }
    for assumption in path {
        match *assumption {
            PathAssumption::Equal(left, right) => naive_merge(&mut labels, left, right),
            PathAssumption::Distinct(_, _) | PathAssumption::Value(_, _) => {}
        }
    }

    let mut rounds = 0usize;
    loop {
        if let Some(limit) = max_rounds {
            if rounds >= limit {
                return Err(CertificateError::AuditDidNotConverge);
            }
        }
        rounds += 1;

        let mut representatives = vec![usize::MAX; problem.term_count];
        for (term, label) in labels.iter().copied().enumerate() {
            representatives[label] = representatives[label].min(term);
        }
        for label in &mut labels {
            *label = representatives[*label];
        }

        let mut domains = vec![ValueDomain::EMPTY; problem.term_count];
        let mut initialized = vec![false; problem.term_count];
        for term in 0..problem.term_count {
            let label = labels[term];
            if initialized[label] {
                domains[label] = domains[label].intersect(problem.value_domains[term]);
            } else {
                domains[label] = problem.value_domains[term];
                initialized[label] = true;
            }
        }
        for assumption in path {
            if let PathAssumption::Value(term, value) = *assumption {
                if term >= problem.term_count {
                    return Err(CertificateError::InvalidCertificateTerm(term));
                }
                if usize::from(value) >= problem.domain_size {
                    return Err(CertificateError::InvalidCertificateValue(value));
                }
                let singleton = ValueDomain::singleton(usize::from(value))
                    .expect("certificate value was range checked");
                let label = labels[term];
                domains[label] = domains[label].intersect(singleton);
            }
        }
        if let Some(representative) =
            initialized
                .iter()
                .enumerate()
                .find_map(|(term, initialized)| {
                    (*initialized && domains[term].is_empty()).then_some(term)
                })
        {
            return Ok(AuditOutcome::Conflict(ConflictClaim::EmptyDomain {
                representative,
            }));
        }

        let mut raw_disequalities: Vec<_> = problem
            .disequalities
            .iter()
            .copied()
            .chain(path.iter().filter_map(|assumption| match *assumption {
                PathAssumption::Distinct(left, right) => Some((left, right)),
                PathAssumption::Equal(_, _) | PathAssumption::Value(_, _) => None,
            }))
            .map(|(left, right)| ordered_pair(left, right))
            .collect();
        raw_disequalities.sort_unstable();
        raw_disequalities.dedup();
        if let Some((left, right)) = raw_disequalities
            .iter()
            .copied()
            .find(|&(left, right)| labels[left] == labels[right])
        {
            return Ok(AuditOutcome::Conflict(
                ConflictClaim::DisequalityCollapsed { left, right },
            ));
        }
        let mut disequalities = BTreeSet::new();
        for &(left, right) in &raw_disequalities {
            disequalities.insert(ordered_pair(labels[left], labels[right]));
        }

        loop {
            let mut reduced = false;
            for &(left, right) in &disequalities {
                let left_domain = domains[left];
                let right_domain = domains[right];
                if let (Some(left_value), Some(right_value)) = (
                    left_domain.singleton_value(),
                    right_domain.singleton_value(),
                ) {
                    if left_value == right_value {
                        return Ok(AuditOutcome::Conflict(
                            ConflictClaim::ForcedValueCollision {
                                left,
                                right,
                                value: left_value,
                            },
                        ));
                    }
                }
                if let Some(value) = left_domain.singleton_value() {
                    let next = right_domain.without(value);
                    if next != right_domain {
                        if next.is_empty() {
                            return Ok(AuditOutcome::Conflict(ConflictClaim::EmptyDomain {
                                representative: right,
                            }));
                        }
                        domains[right] = next;
                        reduced = true;
                        break;
                    }
                }
                if let Some(value) = right_domain.singleton_value() {
                    let next = left_domain.without(value);
                    if next != left_domain {
                        if next.is_empty() {
                            return Ok(AuditOutcome::Conflict(ConflictClaim::EmptyDomain {
                                representative: left,
                            }));
                        }
                        domains[left] = next;
                        reduced = true;
                        break;
                    }
                }
            }
            if !reduced {
                break;
            }
        }

        let mut congruence_merge = None;
        'applications: for left_index in 0..problem.applications.len() {
            let left = &problem.applications[left_index];
            for right in problem.applications.iter().skip(left_index + 1) {
                if left.function != right.function
                    || left
                        .arguments
                        .iter()
                        .zip(&right.arguments)
                        .any(|(left, right)| labels[*left] != labels[*right])
                {
                    continue;
                }
                if labels[left.result] != labels[right.result] {
                    congruence_merge = Some((left.result, right.result));
                    break 'applications;
                }
            }
        }
        if let Some((left, right)) = congruence_merge {
            naive_merge(&mut labels, left, right);
            continue;
        }

        let class_representatives: Vec<_> = initialized
            .iter()
            .enumerate()
            .filter_map(|(term, initialized)| initialized.then_some(term))
            .collect();
        let mut value_merge = None;
        'classes: for (left_index, left) in class_representatives.iter().copied().enumerate() {
            let Some(value) = domains[left].singleton_value() else {
                continue;
            };
            for right in class_representatives.iter().copied().skip(left_index + 1) {
                if domains[right].singleton_value() != Some(value)
                    || disequalities.contains(&ordered_pair(left, right))
                {
                    continue;
                }
                value_merge = Some((left, right));
                break 'classes;
            }
        }
        if let Some((left, right)) = value_merge {
            naive_merge(&mut labels, left, right);
            continue;
        }

        return Ok(AuditOutcome::Consistent(AuditState {
            labels,
            domains,
            disequalities,
        }));
    }
}

fn naive_merge(labels: &mut [TermId], left: TermId, right: TermId) {
    let left_label = labels[left];
    let right_label = labels[right];
    if left_label == right_label {
        return;
    }
    let keep = left_label.min(right_label);
    let remove = left_label.max(right_label);
    for label in labels {
        if *label == remove {
            *label = keep;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full(domain_size: usize) -> ValueDomain {
        ValueDomain::full(domain_size).unwrap()
    }

    fn empty_problem(domain_size: usize, term_count: usize) -> FiniteEufProblem {
        FiniteEufProblem {
            domain_size,
            term_count,
            functions: Vec::new(),
            applications: Vec::new(),
            equalities: Vec::new(),
            disequalities: Vec::new(),
            value_domains: vec![full(domain_size); term_count],
        }
    }

    fn solve(problem: &FiniteEufProblem) -> SearchOutcome {
        solve_quotient_states(problem, &SearchCaps::default()).unwrap()
    }

    fn assert_checked(problem: &FiniteEufProblem, outcome: &SearchOutcome) -> bool {
        match outcome {
            SearchOutcome::Sat { witness, .. } => {
                check_sat_witness(problem, witness).unwrap();
                true
            }
            SearchOutcome::Unsat { certificate, .. } => {
                check_unsat_certificate(problem, certificate, &CertificateCheckCaps::default())
                    .unwrap();
                false
            }
            SearchOutcome::Abstain { reason, .. } => {
                panic!("unexpected abstention in exact test: {reason:?}")
            }
        }
    }

    #[derive(Default)]
    struct BruteStats {
        total_function_interpretations: usize,
        total_term_assignments: usize,
    }

    fn brute_force_total_functions(problem: &FiniteEufProblem, stats: &mut BruteStats) -> bool {
        problem.validate().unwrap();
        let table_sizes: Vec<_> = problem
            .functions
            .iter()
            .map(|function| checked_power(problem.domain_size, function.arity).unwrap())
            .collect();
        let total_cells: usize = table_sizes.iter().sum();
        let mut flat_table = vec![0u8; total_cells];
        enumerate_tables(problem, &table_sizes, &mut flat_table, 0, stats)
    }

    fn enumerate_tables(
        problem: &FiniteEufProblem,
        table_sizes: &[usize],
        flat_table: &mut [Value],
        cell: usize,
        stats: &mut BruteStats,
    ) -> bool {
        if cell < flat_table.len() {
            for value in 0..problem.domain_size {
                flat_table[cell] = value as Value;
                if enumerate_tables(problem, table_sizes, flat_table, cell + 1, stats) {
                    return true;
                }
            }
            return false;
        }
        stats.total_function_interpretations += 1;
        let mut offset = 0usize;
        let functions: Vec<_> = problem
            .functions
            .iter()
            .zip(table_sizes)
            .map(|(declaration, size)| {
                let values = flat_table[offset..offset + *size].to_vec();
                offset += *size;
                TotalFunctionTable {
                    arity: declaration.arity,
                    values,
                }
            })
            .collect();
        let mut term_values = vec![0u8; problem.term_count];
        enumerate_terms(problem, &functions, &mut term_values, 0, stats)
    }

    fn enumerate_terms(
        problem: &FiniteEufProblem,
        functions: &[TotalFunctionTable],
        term_values: &mut [Value],
        term: usize,
        stats: &mut BruteStats,
    ) -> bool {
        if term < term_values.len() {
            for value in 0..problem.domain_size {
                term_values[term] = value as Value;
                if enumerate_terms(problem, functions, term_values, term + 1, stats) {
                    return true;
                }
            }
            return false;
        }
        stats.total_term_assignments += 1;
        let witness = SatWitness {
            term_values: term_values.to_vec(),
            functions: functions.to_vec(),
        };
        check_sat_witness(problem, &witness).is_ok()
    }

    #[test]
    fn total_function_signatures_force_result_congruence() {
        let mut problem = empty_problem(2, 4);
        problem.functions.push(FunctionDecl { arity: 1 });
        problem.applications = vec![
            Application {
                function: 0,
                arguments: vec![0],
                result: 2,
            },
            Application {
                function: 0,
                arguments: vec![1],
                result: 3,
            },
        ];
        problem.equalities.push((0, 1));
        problem.disequalities.push((2, 3));
        let outcome = solve(&problem);
        assert!(!assert_checked(&problem, &outcome));
        assert!(outcome.telemetry().signature_collisions > 0);
        assert!(outcome.telemetry().signature_merges > 0);
        assert!(outcome.telemetry().conflicts > 0);
    }

    #[test]
    fn quotient_and_value_decisions_build_a_total_witness() {
        let mut problem = empty_problem(2, 3);
        problem.functions = vec![FunctionDecl { arity: 1 }, FunctionDecl { arity: 2 }];
        problem.applications = vec![
            Application {
                function: 0,
                arguments: vec![0],
                result: 1,
            },
            Application {
                function: 1,
                arguments: vec![0, 1],
                result: 2,
            },
        ];
        let outcome = solve(&problem);
        assert!(assert_checked(&problem, &outcome));
        let SearchOutcome::Sat { witness, telemetry } = outcome else {
            unreachable!()
        };
        assert!(telemetry.quotient_decisions > 0);
        assert!(telemetry.value_decisions > 0);
        assert_eq!(witness.functions[0].values.len(), 2);
        assert_eq!(witness.functions[1].values.len(), 4);
    }

    #[test]
    fn unsat_tree_contains_both_quotient_and_value_splits() {
        let mut problem = empty_problem(2, 4);
        problem.disequalities = vec![(0, 1), (0, 2), (1, 2)];
        let outcome = solve(&problem);
        assert!(!assert_checked(&problem, &outcome));
        let SearchOutcome::Unsat {
            certificate,
            telemetry,
        } = outcome
        else {
            unreachable!()
        };
        assert!(matches!(certificate.root, UnsatProof::QuotientSplit { .. }));
        assert!(telemetry.quotient_decisions > 0);
        assert!(telemetry.value_decisions > 0);
    }

    #[test]
    fn empty_masks_and_collapsed_disequalities_are_certified() {
        let mut empty = empty_problem(2, 1);
        empty.value_domains[0] = ValueDomain::EMPTY;
        assert!(!assert_checked(&empty, &solve(&empty)));

        let mut collapsed = empty_problem(2, 2);
        collapsed.equalities.push((0, 1));
        collapsed.disequalities.push((0, 1));
        assert!(!assert_checked(&collapsed, &solve(&collapsed)));
    }

    #[test]
    fn sat_witness_checker_rejects_table_tampering() {
        let mut problem = empty_problem(2, 2);
        problem.functions.push(FunctionDecl { arity: 1 });
        problem.applications.push(Application {
            function: 0,
            arguments: vec![0],
            result: 1,
        });
        let SearchOutcome::Sat { mut witness, .. } = solve(&problem) else {
            panic!("expected SAT")
        };
        let argument = usize::from(witness.term_values[0]);
        witness.functions[0].values[argument] ^= 1;
        assert!(matches!(
            check_sat_witness(&problem, &witness),
            Err(WitnessError::ApplicationViolated { .. })
        ));
    }

    #[test]
    fn certificate_checker_rejects_fingerprint_leaf_and_coverage_tampering() {
        let mut immediate = empty_problem(2, 1);
        immediate.disequalities.push((0, 0));
        let SearchOutcome::Unsat {
            mut certificate, ..
        } = solve(&immediate)
        else {
            panic!("expected UNSAT")
        };
        certificate.problem_fingerprint ^= 1;
        assert!(matches!(
            check_unsat_certificate(&immediate, &certificate, &CertificateCheckCaps::default()),
            Err(CertificateError::FingerprintMismatch { .. })
        ));
        certificate.problem_fingerprint ^= 1;
        certificate.root = UnsatProof::Conflict(ConflictClaim::EmptyDomain { representative: 0 });
        assert!(matches!(
            check_unsat_certificate(&immediate, &certificate, &CertificateCheckCaps::default()),
            Err(CertificateError::ConflictClaimMismatch { .. })
        ));

        let mut triangle = empty_problem(2, 3);
        triangle.disequalities = vec![(0, 1), (0, 2), (1, 2)];
        let SearchOutcome::Unsat {
            mut certificate, ..
        } = solve(&triangle)
        else {
            panic!("expected UNSAT")
        };
        let UnsatProof::ValueSplit { branches, .. } = &mut certificate.root else {
            panic!("expected a value split")
        };
        branches.pop();
        assert!(matches!(
            check_unsat_certificate(&triangle, &certificate, &CertificateCheckCaps::default()),
            Err(CertificateError::DecisionMismatch)
        ));
    }

    #[test]
    fn search_and_certificate_are_deterministic() {
        let mut problem = empty_problem(2, 4);
        problem.functions.push(FunctionDecl { arity: 1 });
        problem.applications = vec![
            Application {
                function: 0,
                arguments: vec![0],
                result: 2,
            },
            Application {
                function: 0,
                arguments: vec![1],
                result: 3,
            },
        ];
        problem.disequalities = vec![(0, 1), (0, 2), (1, 2)];
        let first = solve(&problem);
        let second = solve(&problem);
        assert_eq!(first, second);
    }

    #[test]
    fn union_by_size_roots_do_not_change_canonical_certificate_order() {
        let mut problem = empty_problem(2, 5);
        // These merges deliberately leave union-find root 2 for a class whose
        // canonical representative is term 0.
        problem.equalities = vec![(2, 3), (2, 0)];
        problem.disequalities = vec![(0, 1), (0, 4), (1, 4)];
        let outcome = solve(&problem);
        assert!(!assert_checked(&problem, &outcome));
        let SearchOutcome::Unsat { certificate, .. } = outcome else {
            unreachable!()
        };
        let UnsatProof::ValueSplit { term, .. } = certificate.root else {
            panic!("expected canonical value split")
        };
        assert_eq!(term, 0);
    }

    #[test]
    fn search_caps_abstain_instead_of_proving_unsat() {
        let mut direct = empty_problem(2, 1);
        direct.disequalities.push((0, 0));

        let mut caps = SearchCaps::default();
        caps.max_search_nodes = 0;
        assert!(matches!(
            solve_quotient_states(&direct, &caps).unwrap(),
            SearchOutcome::Abstain {
                reason: AbstainReason::SearchCap {
                    resource: "search nodes",
                    ..
                },
                ..
            }
        ));

        caps = SearchCaps::default();
        caps.max_conflicts = 0;
        assert!(matches!(
            solve_quotient_states(&direct, &caps).unwrap(),
            SearchOutcome::Abstain {
                reason: AbstainReason::SearchCap {
                    resource: "conflicts",
                    ..
                },
                ..
            }
        ));

        let mut propagated = empty_problem(2, 2);
        propagated.equalities.push((0, 1));
        propagated.disequalities.push((0, 1));
        caps = SearchCaps::default();
        caps.max_propagations = 0;
        assert!(matches!(
            solve_quotient_states(&propagated, &caps).unwrap(),
            SearchOutcome::Abstain {
                reason: AbstainReason::SearchCap {
                    resource: "propagations",
                    ..
                },
                ..
            }
        ));

        caps = SearchCaps::default();
        caps.max_certificate_nodes = 0;
        assert!(matches!(
            solve_quotient_states(&direct, &caps).unwrap(),
            SearchOutcome::Abstain {
                reason: AbstainReason::SearchCap {
                    resource: "certificate nodes",
                    ..
                },
                ..
            }
        ));

        let mut triangle = empty_problem(2, 3);
        triangle.disequalities = vec![(0, 1), (0, 2), (1, 2)];
        caps = SearchCaps::default();
        caps.max_decisions = 0;
        assert!(matches!(
            solve_quotient_states(&triangle, &caps).unwrap(),
            SearchOutcome::Abstain {
                reason: AbstainReason::SearchCap {
                    resource: "decisions",
                    ..
                },
                ..
            }
        ));

        caps = SearchCaps::default();
        caps.max_depth = 0;
        assert!(matches!(
            solve_quotient_states(&triangle, &caps).unwrap(),
            SearchOutcome::Abstain {
                reason: AbstainReason::SearchCap {
                    resource: "search depth",
                    ..
                },
                ..
            }
        ));

        caps = SearchCaps::default();
        caps.max_trail_entries = 0;
        assert!(matches!(
            solve_quotient_states(&triangle, &caps).unwrap(),
            SearchOutcome::Abstain {
                reason: AbstainReason::SearchCap {
                    resource: "trail entries",
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn certificate_checker_caps_fail_closed() {
        let mut triangle = empty_problem(2, 3);
        triangle.disequalities = vec![(0, 1), (0, 2), (1, 2)];
        let SearchOutcome::Unsat { certificate, .. } = solve(&triangle) else {
            panic!("expected UNSAT")
        };
        let mut caps = CertificateCheckCaps::default();
        caps.max_nodes = 0;
        assert!(matches!(
            check_unsat_certificate(&triangle, &certificate, &caps),
            Err(CertificateError::CheckCap {
                resource: "certificate nodes",
                ..
            })
        ));
    }

    #[test]
    fn structural_and_totalization_caps_abstain() {
        let problem = empty_problem(2, 2);
        let mut caps = SearchCaps::default();
        caps.max_terms = 1;
        assert!(matches!(
            solve_quotient_states(&problem, &caps).unwrap(),
            SearchOutcome::Abstain {
                reason: AbstainReason::StructuralCap {
                    resource: "terms",
                    ..
                },
                ..
            }
        ));

        let mut nullary = empty_problem(2, 1);
        nullary.functions.push(FunctionDecl { arity: 0 });
        caps = SearchCaps::default();
        caps.max_total_function_cells = 0;
        assert!(matches!(
            solve_quotient_states(&nullary, &caps).unwrap(),
            SearchOutcome::Abstain {
                reason: AbstainReason::SearchCap {
                    resource: "total function cells",
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn exhaustive_unary_generated_instances_match_total_function_enumeration() {
        let masks = [
            ValueDomain::singleton(0).unwrap(),
            ValueDomain::singleton(1).unwrap(),
            full(2),
        ];
        let pairs = [(0, 1), (0, 2), (1, 2)];
        let application_templates = [
            Application {
                function: 0,
                arguments: vec![0],
                result: 1,
            },
            Application {
                function: 0,
                arguments: vec![1],
                result: 2,
            },
        ];
        let mut generated = 0usize;
        let mut observed_tables = 0usize;
        for application_mask in 0..4usize {
            for relation_code in 0..27usize {
                for domain_code in 0..27usize {
                    let mut problem = empty_problem(2, 3);
                    problem.functions.push(FunctionDecl { arity: 1 });
                    for (index, application) in application_templates.iter().enumerate() {
                        if application_mask & (1 << index) != 0 {
                            problem.applications.push(application.clone());
                        }
                    }
                    let mut code = relation_code;
                    for pair in pairs {
                        match code % 3 {
                            1 => problem.equalities.push(pair),
                            2 => problem.disequalities.push(pair),
                            _ => {}
                        }
                        code /= 3;
                    }
                    code = domain_code;
                    for term in 0..3 {
                        problem.value_domains[term] = masks[code % 3];
                        code /= 3;
                    }

                    let outcome = solve(&problem);
                    let oracle_sat = assert_checked(&problem, &outcome);
                    let mut stats = BruteStats::default();
                    let brute_sat = brute_force_total_functions(&problem, &mut stats);
                    assert_eq!(
                        oracle_sat, brute_sat,
                        "mismatch for app mask {application_mask}, relation code {relation_code}, domain code {domain_code}"
                    );
                    generated += 1;
                    observed_tables += stats.total_function_interpretations;
                }
            }
        }
        assert_eq!(generated, 2_916);
        assert!(observed_tables >= generated);
    }

    #[test]
    fn exhaustive_binary_generated_instances_match_total_function_enumeration() {
        let masks = [
            ValueDomain::singleton(0).unwrap(),
            ValueDomain::singleton(1).unwrap(),
            full(2),
        ];
        let pairs = [(0, 1), (0, 2), (1, 2)];
        let mut generated = 0usize;
        let mut observed_tables = 0usize;
        for relation_code in 0..27usize {
            for domain_code in 0..27usize {
                let mut problem = empty_problem(2, 3);
                problem.functions.push(FunctionDecl { arity: 2 });
                problem.applications.push(Application {
                    function: 0,
                    arguments: vec![0, 1],
                    result: 2,
                });
                let mut code = relation_code;
                for pair in pairs {
                    match code % 3 {
                        1 => problem.equalities.push(pair),
                        2 => problem.disequalities.push(pair),
                        _ => {}
                    }
                    code /= 3;
                }
                code = domain_code;
                for term in 0..3 {
                    problem.value_domains[term] = masks[code % 3];
                    code /= 3;
                }

                let outcome = solve(&problem);
                let oracle_sat = assert_checked(&problem, &outcome);
                let mut stats = BruteStats::default();
                let brute_sat = brute_force_total_functions(&problem, &mut stats);
                assert_eq!(
                    oracle_sat, brute_sat,
                    "mismatch for relation code {relation_code}, domain code {domain_code}"
                );
                generated += 1;
                observed_tables += stats.total_function_interpretations;
            }
        }
        assert_eq!(generated, 729);
        assert!(observed_tables >= generated);
    }

    #[test]
    fn invalid_inputs_are_rejected_before_search() {
        let mut problem = empty_problem(2, 1);
        problem.value_domains[0] = ValueDomain::from_bits(0b100);
        assert!(matches!(
            solve_quotient_states(&problem, &SearchCaps::default()),
            Err(InputError::DomainBitsOutOfRange { .. })
        ));
    }
}
