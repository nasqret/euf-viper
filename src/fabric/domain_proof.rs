#![forbid(unsafe_code)]

//! Frozen source-level proofs for Boolean-domain inferences.
//!
//! A proof is captured before its domain merge and contains only stable source
//! literals. The arena never consults the current partition and never expands
//! another reason recursively. Identical insertions intentionally receive
//! distinct IDs so proofs created on replacement search branches cannot alias.
//!
//! Domain proof reasons own the high-bit [`ReasonId`] namespace. Root, source,
//! action, and other low-bit reasons are therefore rejected by decoding, while
//! [`ReasonId::MAX`] remains reserved for the congruence marker.

use super::native_clause::{AtomId, Lit};
use super::partition::{ReasonId, TermId};
use std::error::Error;
use std::fmt;

pub(crate) const DOMAIN_PROOF_REASON_TAG: u64 = 1_u64 << 63;
const DOMAIN_PROOF_PAYLOAD_MASK: u64 = DOMAIN_PROOF_REASON_TAG - 1;
const MAX_DOMAIN_PROOF_COUNT: u64 = DOMAIN_PROOF_PAYLOAD_MASK;

/// Hard limits for the append-only domain proof arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DomainProofCaps {
    pub(crate) max_proofs: usize,
    pub(crate) max_total_antecedents: usize,
    pub(crate) max_antecedents_per_proof: usize,
}

impl DomainProofCaps {
    pub(crate) const fn new(
        max_proofs: usize,
        max_total_antecedents: usize,
        max_antecedents_per_proof: usize,
    ) -> Self {
        Self {
            max_proofs,
            max_total_antecedents,
            max_antecedents_per_proof,
        }
    }

    pub(crate) const fn unlimited() -> Self {
        Self::new(usize::MAX, usize::MAX, usize::MAX)
    }
}

impl Default for DomainProofCaps {
    fn default() -> Self {
        Self::new(1_000_000, 50_000_000, 1_000_000)
    }
}

/// A resource controlled by [`DomainProofCaps`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DomainProofResource {
    Proofs,
    TotalAntecedents,
    AntecedentsPerProof,
}

impl fmt::Display for DomainProofResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Proofs => "domain proofs",
            Self::TotalAntecedents => "stored domain-proof antecedents",
            Self::AntecedentsPerProof => "domain-proof antecedents",
        };
        output.write_str(name)
    }
}

/// A failed insertion. Every variant leaves the logical arena unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DomainProofError {
    TermOutOfRange {
        term: TermId,
        term_count: usize,
    },
    AtomOutOfRange {
        atom: AtomId,
        source_atom_count: usize,
    },
    ComplementaryAntecedents {
        atom: AtomId,
    },
    ClaimedConclusionIsAntecedent {
        conclusion: Lit,
    },
    ClaimedConclusionIsContradicted {
        conclusion: Lit,
    },
    CapExceeded {
        resource: DomainProofResource,
        attempted: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        resource: DomainProofResource,
    },
    ReasonIdSpaceExhausted {
        index: usize,
        maximum_proofs: u64,
    },
    AllocationFailed {
        context: &'static str,
        requested: usize,
    },
}

impl fmt::Display for DomainProofError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TermOutOfRange { term, term_count } => {
                write!(
                    output,
                    "domain proof term {term} is outside 0..{term_count}"
                )
            }
            Self::AtomOutOfRange {
                atom,
                source_atom_count,
            } => write!(
                output,
                "domain proof source atom {} is outside 0..{source_atom_count}",
                atom.index()
            ),
            Self::ComplementaryAntecedents { atom } => write!(
                output,
                "domain proof contains both polarities of source atom {}",
                atom.index()
            ),
            Self::ClaimedConclusionIsAntecedent { conclusion } => write!(
                output,
                "claimed domain conclusion {conclusion:?} occurs in its own antecedents"
            ),
            Self::ClaimedConclusionIsContradicted { conclusion } => write!(
                output,
                "claimed domain conclusion {conclusion:?} is contradicted by an antecedent"
            ),
            Self::CapExceeded {
                resource,
                attempted,
                limit,
            } => write!(
                output,
                "{resource} cap exceeded: attempted {attempted}, limit {limit}"
            ),
            Self::ArithmeticOverflow { resource } => {
                write!(output, "arithmetic overflow while counting {resource}")
            }
            Self::ReasonIdSpaceExhausted {
                index,
                maximum_proofs,
            } => write!(
                output,
                "domain proof index {index} exceeds the {maximum_proofs}-entry reason namespace"
            ),
            Self::AllocationFailed { context, requested } => write!(
                output,
                "allocation failed for {context} while requesting {requested} entries"
            ),
        }
    }
}

impl Error for DomainProofError {}

/// A checked reason lookup failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DomainProofLookupError {
    ForeignReasonNamespace {
        reason: ReasonId,
    },
    ReservedCongruenceMarker,
    IndexNotRepresentable {
        reason: ReasonId,
        payload: u64,
    },
    UnknownReason {
        reason: ReasonId,
        index: usize,
        proof_count: usize,
    },
    CorruptStoredReason {
        reason: ReasonId,
        stored: ReasonId,
        index: usize,
    },
}

impl fmt::Display for DomainProofLookupError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForeignReasonNamespace { reason } => write!(
                output,
                "reason {reason} is not in the Boolean-domain proof namespace"
            ),
            Self::ReservedCongruenceMarker => {
                output.write_str("ReasonId::MAX is reserved for the congruence marker")
            }
            Self::IndexNotRepresentable { reason, payload } => write!(
                output,
                "domain proof reason {reason} has payload {payload}, which does not fit usize"
            ),
            Self::UnknownReason {
                reason,
                index,
                proof_count,
            } => write!(
                output,
                "domain proof reason {reason} decodes to index {index}, but only {proof_count} proofs are stored"
            ),
            Self::CorruptStoredReason {
                reason,
                stored,
                index,
            } => write!(
                output,
                "domain proof reason {reason} reached index {index}, which stores mismatched reason {stored}"
            ),
        }
    }
}

impl Error for DomainProofLookupError {}

/// Immutable proof data retained for the lifetime of the arena.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FrozenDomainProof {
    reason: ReasonId,
    term: TermId,
    value: bool,
    antecedents: Vec<Lit>,
}

impl FrozenDomainProof {
    pub(crate) const fn reason(&self) -> ReasonId {
        self.reason
    }

    pub(crate) const fn term(&self) -> TermId {
        self.term
    }

    pub(crate) const fn value(&self) -> bool {
        self.value
    }

    pub(crate) fn antecedents(&self) -> &[Lit] {
        &self.antecedents
    }
}

/// A successful insertion. There is deliberately no `Existing` outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DomainProofInsert {
    Stored {
        reason: ReasonId,
        index: usize,
        antecedent_count: usize,
    },
}

impl DomainProofInsert {
    pub(crate) const fn reason(self) -> ReasonId {
        match self {
            Self::Stored { reason, .. } => reason,
        }
    }
}

/// Exact gauges for an arena. Failed insertions do not change them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DomainProofTelemetry {
    pub(crate) proofs_stored: usize,
    pub(crate) antecedents_stored: usize,
    pub(crate) peak_antecedents_per_proof: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AllocationSite {
    CanonicalAntecedents,
    ProofTable,
}

impl AllocationSite {
    const fn context(self) -> &'static str {
        match self {
            Self::CanonicalAntecedents => "canonical domain-proof antecedents",
            Self::ProofTable => "domain proof table",
        }
    }
}

/// Append-only storage for already-flattened Boolean-domain proofs.
#[derive(Debug)]
pub(crate) struct DomainProofArena {
    term_count: usize,
    source_atom_count: usize,
    caps: DomainProofCaps,
    proofs: Vec<FrozenDomainProof>,
    total_antecedents: usize,
    peak_antecedents_per_proof: usize,
    #[cfg(test)]
    fail_allocation_at: Option<AllocationSite>,
    #[cfg(test)]
    next_proof_index_override: Option<usize>,
}

impl DomainProofArena {
    pub(crate) fn new(term_count: usize, source_atom_count: usize, caps: DomainProofCaps) -> Self {
        Self {
            term_count,
            source_atom_count,
            caps,
            proofs: Vec::new(),
            total_antecedents: 0,
            peak_antecedents_per_proof: 0,
            #[cfg(test)]
            fail_allocation_at: None,
            #[cfg(test)]
            next_proof_index_override: None,
        }
    }

    pub(crate) fn term_count(&self) -> usize {
        self.term_count
    }

    pub(crate) fn source_atom_count(&self) -> usize {
        self.source_atom_count
    }

    pub(crate) fn caps(&self) -> DomainProofCaps {
        self.caps
    }

    pub(crate) fn len(&self) -> usize {
        self.proofs.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    pub(crate) fn total_antecedents(&self) -> usize {
        self.total_antecedents
    }

    pub(crate) fn telemetry(&self) -> DomainProofTelemetry {
        DomainProofTelemetry {
            proofs_stored: self.proofs.len(),
            antecedents_stored: self.total_antecedents,
            peak_antecedents_per_proof: self.peak_antecedents_per_proof,
        }
    }

    /// Store a proof when no propagated source literal is part of this API.
    ///
    /// The caller is responsible for associating `(term, value)` with the
    /// semantic conclusion. This method consequently performs no self-reason
    /// check that would require a source conclusion literal.
    pub(crate) fn insert(
        &mut self,
        term: TermId,
        value: bool,
        antecedents: &[Lit],
    ) -> Result<DomainProofInsert, DomainProofError> {
        self.insert_internal(term, value, None, antecedents)
    }

    /// Store a proof while checking an explicitly claimed source conclusion.
    pub(crate) fn insert_with_conclusion(
        &mut self,
        term: TermId,
        value: bool,
        conclusion: Lit,
        antecedents: &[Lit],
    ) -> Result<DomainProofInsert, DomainProofError> {
        self.insert_internal(term, value, Some(conclusion), antecedents)
    }

    /// Decode and retrieve an immutable proof.
    pub(crate) fn lookup(
        &self,
        reason: ReasonId,
    ) -> Result<&FrozenDomainProof, DomainProofLookupError> {
        let index = decode_domain_reason(reason)?;
        let proof = self
            .proofs
            .get(index)
            .ok_or(DomainProofLookupError::UnknownReason {
                reason,
                index,
                proof_count: self.proofs.len(),
            })?;
        if proof.reason != reason {
            return Err(DomainProofLookupError::CorruptStoredReason {
                reason,
                stored: proof.reason,
                index,
            });
        }
        Ok(proof)
    }

    fn insert_internal(
        &mut self,
        term: TermId,
        value: bool,
        conclusion: Option<Lit>,
        antecedents: &[Lit],
    ) -> Result<DomainProofInsert, DomainProofError> {
        if term.index() >= self.term_count {
            return Err(DomainProofError::TermOutOfRange {
                term,
                term_count: self.term_count,
            });
        }
        if let Some(literal) = conclusion {
            self.validate_atom(literal.atom())?;
        }
        for literal in antecedents {
            self.validate_atom(literal.atom())?;
        }

        let mut canonical = self.copy_for_canonicalization(antecedents)?;
        canonical.sort_unstable();
        canonical.dedup();

        if let Some(pair) = canonical
            .windows(2)
            .find(|pair| pair[0].atom() == pair[1].atom())
        {
            return Err(DomainProofError::ComplementaryAntecedents {
                atom: pair[0].atom(),
            });
        }
        if let Some(claimed) = conclusion {
            if canonical.binary_search(&claimed).is_ok() {
                return Err(DomainProofError::ClaimedConclusionIsAntecedent {
                    conclusion: claimed,
                });
            }
            if canonical.binary_search(&claimed.negate()).is_ok() {
                return Err(DomainProofError::ClaimedConclusionIsContradicted {
                    conclusion: claimed,
                });
            }
        }

        check_cap(
            DomainProofResource::AntecedentsPerProof,
            canonical.len(),
            self.caps.max_antecedents_per_proof,
        )?;
        let next_proof_count = checked_add(self.proofs.len(), 1, DomainProofResource::Proofs)?;
        check_cap(
            DomainProofResource::Proofs,
            next_proof_count,
            self.caps.max_proofs,
        )?;
        let next_total = checked_add(
            self.total_antecedents,
            canonical.len(),
            DomainProofResource::TotalAntecedents,
        )?;
        check_cap(
            DomainProofResource::TotalAntecedents,
            next_total,
            self.caps.max_total_antecedents,
        )?;

        let index = self.next_proof_index();
        let reason = domain_reason_from_index(index)?;
        debug_assert_eq!(index, self.proofs.len());
        self.reserve_proof_slot(next_proof_count)?;

        let antecedent_count = canonical.len();
        self.proofs.push(FrozenDomainProof {
            reason,
            term,
            value,
            antecedents: canonical,
        });
        self.total_antecedents = next_total;
        self.peak_antecedents_per_proof = self.peak_antecedents_per_proof.max(antecedent_count);

        Ok(DomainProofInsert::Stored {
            reason,
            index,
            antecedent_count,
        })
    }

    fn validate_atom(&self, atom: AtomId) -> Result<(), DomainProofError> {
        if atom.index() >= self.source_atom_count {
            Err(DomainProofError::AtomOutOfRange {
                atom,
                source_atom_count: self.source_atom_count,
            })
        } else {
            Ok(())
        }
    }

    fn copy_for_canonicalization(
        &mut self,
        antecedents: &[Lit],
    ) -> Result<Vec<Lit>, DomainProofError> {
        self.allocation_gate(AllocationSite::CanonicalAntecedents, antecedents.len())?;
        let mut canonical = Vec::new();
        try_reserve_exact(
            &mut canonical,
            antecedents.len(),
            AllocationSite::CanonicalAntecedents.context(),
        )?;
        canonical.extend_from_slice(antecedents);
        Ok(canonical)
    }

    fn reserve_proof_slot(&mut self, requested: usize) -> Result<(), DomainProofError> {
        self.allocation_gate(AllocationSite::ProofTable, requested)?;
        self.proofs
            .try_reserve(1)
            .map_err(|_| DomainProofError::AllocationFailed {
                context: AllocationSite::ProofTable.context(),
                requested,
            })
    }

    fn allocation_gate(
        &mut self,
        site: AllocationSite,
        requested: usize,
    ) -> Result<(), DomainProofError> {
        #[cfg(test)]
        if self.fail_allocation_at == Some(site) {
            self.fail_allocation_at = None;
            return Err(DomainProofError::AllocationFailed {
                context: site.context(),
                requested,
            });
        }
        let _ = (site, requested);
        Ok(())
    }

    fn next_proof_index(&self) -> usize {
        #[cfg(test)]
        if let Some(index) = self.next_proof_index_override {
            return index;
        }
        self.proofs.len()
    }

    #[cfg(test)]
    fn fail_next_allocation_at(&mut self, site: AllocationSite) {
        self.fail_allocation_at = Some(site);
    }

    #[cfg(test)]
    fn invariants_hold(&self) -> bool {
        if self.proofs.len() > self.caps.max_proofs
            || self.total_antecedents > self.caps.max_total_antecedents
        {
            return false;
        }
        let mut observed_total = 0usize;
        for (index, proof) in self.proofs.iter().enumerate() {
            if proof.reason != domain_reason_from_index(index).expect("stored index is encodable")
                || proof.term.index() >= self.term_count
                || proof.antecedents.len() > self.caps.max_antecedents_per_proof
                || proof
                    .antecedents
                    .iter()
                    .any(|literal| literal.atom().index() >= self.source_atom_count)
                || proof.antecedents.windows(2).any(|pair| pair[0] >= pair[1])
                || proof
                    .antecedents
                    .windows(2)
                    .any(|pair| pair[0].atom() == pair[1].atom())
            {
                return false;
            }
            let Some(next) = observed_total.checked_add(proof.antecedents.len()) else {
                return false;
            };
            observed_total = next;
        }
        observed_total == self.total_antecedents
            && self.peak_antecedents_per_proof
                == self
                    .proofs
                    .iter()
                    .map(|proof| proof.antecedents.len())
                    .max()
                    .unwrap_or(0)
    }
}

/// Decode a high-bit domain proof reason into its stable insertion index.
pub(crate) fn decode_domain_reason(reason: ReasonId) -> Result<usize, DomainProofLookupError> {
    let raw = reason.raw();
    if reason == ReasonId::MAX {
        return Err(DomainProofLookupError::ReservedCongruenceMarker);
    }
    if raw & DOMAIN_PROOF_REASON_TAG == 0 {
        return Err(DomainProofLookupError::ForeignReasonNamespace { reason });
    }
    let payload = raw & DOMAIN_PROOF_PAYLOAD_MASK;
    usize::try_from(payload)
        .map_err(|_| DomainProofLookupError::IndexNotRepresentable { reason, payload })
}

fn domain_reason_from_index(index: usize) -> Result<ReasonId, DomainProofError> {
    let payload = u64::try_from(index).map_err(|_| DomainProofError::ReasonIdSpaceExhausted {
        index,
        maximum_proofs: MAX_DOMAIN_PROOF_COUNT,
    })?;
    if payload >= MAX_DOMAIN_PROOF_COUNT {
        return Err(DomainProofError::ReasonIdSpaceExhausted {
            index,
            maximum_proofs: MAX_DOMAIN_PROOF_COUNT,
        });
    }
    let raw = DOMAIN_PROOF_REASON_TAG | payload;
    debug_assert_ne!(raw, ReasonId::MAX.raw());
    Ok(ReasonId::new(raw))
}

fn checked_add(
    current: usize,
    additional: usize,
    resource: DomainProofResource,
) -> Result<usize, DomainProofError> {
    current
        .checked_add(additional)
        .ok_or(DomainProofError::ArithmeticOverflow { resource })
}

fn check_cap(
    resource: DomainProofResource,
    attempted: usize,
    limit: usize,
) -> Result<(), DomainProofError> {
    if attempted > limit {
        Err(DomainProofError::CapExceeded {
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
) -> Result<(), DomainProofError> {
    values
        .try_reserve_exact(additional)
        .map_err(|_| DomainProofError::AllocationFailed {
            context,
            requested: additional,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ArenaSnapshot {
        term_count: usize,
        source_atom_count: usize,
        caps: DomainProofCaps,
        total_antecedents: usize,
        telemetry: DomainProofTelemetry,
        proofs: Vec<FrozenDomainProof>,
    }

    fn p(index: u32) -> Lit {
        Lit::positive(AtomId::new(index))
    }

    fn n(index: u32) -> Lit {
        Lit::negative(AtomId::new(index))
    }

    fn caps(proofs: usize, total: usize, per_proof: usize) -> DomainProofCaps {
        DomainProofCaps::new(proofs, total, per_proof)
    }

    fn snapshot(arena: &DomainProofArena) -> ArenaSnapshot {
        ArenaSnapshot {
            term_count: arena.term_count(),
            source_atom_count: arena.source_atom_count(),
            caps: arena.caps(),
            total_antecedents: arena.total_antecedents(),
            telemetry: arena.telemetry(),
            proofs: arena.proofs.clone(),
        }
    }

    fn stored(outcome: DomainProofInsert) -> ReasonId {
        match outcome {
            DomainProofInsert::Stored { reason, .. } => reason,
        }
    }

    #[test]
    fn identical_proofs_always_receive_fresh_ids() {
        let mut arena = DomainProofArena::new(4, 4, caps(8, 32, 8));
        assert_eq!(arena.term_count(), 4);
        assert_eq!(arena.source_atom_count(), 4);
        assert_eq!(arena.caps(), caps(8, 32, 8));
        assert!(arena.is_empty());

        let first = stored(arena.insert(TermId::new(2), true, &[p(0), n(1)]).unwrap());
        let second = stored(arena.insert(TermId::new(2), true, &[n(1), p(0)]).unwrap());

        assert_ne!(first, second);
        assert_eq!(first.raw(), DOMAIN_PROOF_REASON_TAG);
        assert_eq!(second.raw(), DOMAIN_PROOF_REASON_TAG + 1);
        assert_eq!(arena.lookup(first).unwrap().antecedents(), &[p(0), n(1)]);
        assert_eq!(arena.lookup(second).unwrap().antecedents(), &[p(0), n(1)]);
        assert_eq!(arena.len(), 2);
        assert!(!arena.is_empty());
        assert!(arena.invariants_hold());
    }

    #[test]
    fn rollback_style_replacement_branches_remain_distinct() {
        let mut arena = DomainProofArena::new(3, 3, DomainProofCaps::unlimited());

        let branch_a = stored(arena.insert(TermId::new(1), false, &[p(2)]).unwrap());
        // The partition and Boolean trail can roll back here; the proof arena
        // remains append-only and the replacement branch gets a new identity.
        let branch_b = stored(arena.insert(TermId::new(1), false, &[p(2)]).unwrap());

        assert_eq!(arena.lookup(branch_a).unwrap().term(), TermId::new(1));
        assert!(!arena.lookup(branch_a).unwrap().value());
        assert_eq!(arena.lookup(branch_b).unwrap().term(), TermId::new(1));
        assert_ne!(branch_a, branch_b);
        assert_eq!(decode_domain_reason(branch_a), Ok(0));
        assert_eq!(decode_domain_reason(branch_b), Ok(1));
    }

    #[test]
    fn canonical_antecedents_are_sorted_and_deduplicated() {
        let mut arena = DomainProofArena::new(2, 4, caps(2, 8, 8));
        let outcome = arena
            .insert(TermId::new(0), true, &[p(3), n(1), p(0), p(3), n(1)])
            .unwrap();
        let reason = outcome.reason();
        let proof = arena.lookup(reason).unwrap();

        assert_eq!(proof.reason(), reason);
        assert_eq!(proof.term(), TermId::new(0));
        assert!(proof.value());
        assert_eq!(proof.antecedents(), &[p(0), n(1), p(3)]);
        assert_eq!(arena.total_antecedents(), 3);
        assert_eq!(
            arena.telemetry(),
            DomainProofTelemetry {
                proofs_stored: 1,
                antecedents_stored: 3,
                peak_antecedents_per_proof: 3,
            }
        );
    }

    #[test]
    fn complementary_antecedents_are_rejected_transactionally() {
        let mut arena = DomainProofArena::new(2, 3, caps(4, 8, 4));
        let before = snapshot(&arena);

        assert_eq!(
            arena.insert(TermId::new(0), true, &[p(1), n(1)]),
            Err(DomainProofError::ComplementaryAntecedents {
                atom: AtomId::new(1),
            })
        );
        assert_eq!(snapshot(&arena), before);
    }

    #[test]
    fn conclusion_checks_apply_only_to_conclusion_api() {
        let mut arena = DomainProofArena::new(2, 3, caps(4, 8, 4));
        let unconstrained = stored(arena.insert(TermId::new(0), true, &[p(1)]).unwrap());
        assert_eq!(arena.lookup(unconstrained).unwrap().antecedents(), &[p(1)]);

        let before = snapshot(&arena);
        assert_eq!(
            arena.insert_with_conclusion(TermId::new(0), true, p(1), &[p(1)]),
            Err(DomainProofError::ClaimedConclusionIsAntecedent { conclusion: p(1) })
        );
        assert_eq!(snapshot(&arena), before);
        assert_eq!(
            arena.insert_with_conclusion(TermId::new(0), true, p(1), &[n(1)]),
            Err(DomainProofError::ClaimedConclusionIsContradicted { conclusion: p(1) })
        );
        assert_eq!(snapshot(&arena), before);
    }

    #[test]
    fn malformed_reason_namespaces_and_max_are_rejected() {
        let arena = DomainProofArena::new(1, 1, DomainProofCaps::unlimited());
        for reason in [ReasonId::MIN, ReasonId::new(1), ReasonId::new(1_u64 << 60)] {
            assert_eq!(
                decode_domain_reason(reason),
                Err(DomainProofLookupError::ForeignReasonNamespace { reason })
            );
            assert_eq!(
                arena.lookup(reason),
                Err(DomainProofLookupError::ForeignReasonNamespace { reason })
            );
        }
        assert_eq!(
            decode_domain_reason(ReasonId::MAX),
            Err(DomainProofLookupError::ReservedCongruenceMarker)
        );
        assert_eq!(
            arena.lookup(ReasonId::MAX),
            Err(DomainProofLookupError::ReservedCongruenceMarker)
        );
    }

    #[test]
    fn unknown_domain_reason_is_not_aliased() {
        let mut arena = DomainProofArena::new(1, 1, DomainProofCaps::unlimited());
        let first = stored(arena.insert(TermId::new(0), true, &[]).unwrap());
        assert_eq!(decode_domain_reason(first), Ok(0));

        let unknown = ReasonId::new(DOMAIN_PROOF_REASON_TAG | 7);
        assert_eq!(
            arena.lookup(unknown),
            Err(DomainProofLookupError::UnknownReason {
                reason: unknown,
                index: 7,
                proof_count: 1,
            })
        );
    }

    #[test]
    fn term_source_and_claimed_conclusion_ranges_are_checked_first() {
        let mut arena = DomainProofArena::new(2, 2, caps(4, 8, 4));
        let before = snapshot(&arena);
        assert_eq!(
            arena.insert(TermId::new(2), true, &[p(0)]),
            Err(DomainProofError::TermOutOfRange {
                term: TermId::new(2),
                term_count: 2,
            })
        );
        assert_eq!(
            arena.insert(TermId::new(0), true, &[p(2)]),
            Err(DomainProofError::AtomOutOfRange {
                atom: AtomId::new(2),
                source_atom_count: 2,
            })
        );
        assert_eq!(
            arena.insert_with_conclusion(TermId::new(0), true, p(2), &[p(0)]),
            Err(DomainProofError::AtomOutOfRange {
                atom: AtomId::new(2),
                source_atom_count: 2,
            })
        );
        assert_eq!(snapshot(&arena), before);
    }

    #[test]
    fn every_structural_cap_is_hard_and_transactional() {
        let mut proof_cap = DomainProofArena::new(1, 2, caps(1, 8, 4));
        proof_cap.insert(TermId::new(0), true, &[p(0)]).unwrap();
        let before = snapshot(&proof_cap);
        assert_eq!(
            proof_cap.insert(TermId::new(0), false, &[p(1)]),
            Err(DomainProofError::CapExceeded {
                resource: DomainProofResource::Proofs,
                attempted: 2,
                limit: 1,
            })
        );
        assert_eq!(snapshot(&proof_cap), before);

        let mut total_cap = DomainProofArena::new(1, 3, caps(4, 2, 3));
        total_cap
            .insert(TermId::new(0), true, &[p(0), p(1)])
            .unwrap();
        let before = snapshot(&total_cap);
        assert_eq!(
            total_cap.insert(TermId::new(0), false, &[p(2)]),
            Err(DomainProofError::CapExceeded {
                resource: DomainProofResource::TotalAntecedents,
                attempted: 3,
                limit: 2,
            })
        );
        assert_eq!(snapshot(&total_cap), before);

        let mut per_proof_cap = DomainProofArena::new(1, 3, caps(4, 8, 1));
        let before = snapshot(&per_proof_cap);
        assert_eq!(
            per_proof_cap.insert(TermId::new(0), true, &[p(0), p(1)]),
            Err(DomainProofError::CapExceeded {
                resource: DomainProofResource::AntecedentsPerProof,
                attempted: 2,
                limit: 1,
            })
        );
        assert_eq!(snapshot(&per_proof_cap), before);
    }

    #[test]
    fn empty_antecedent_proofs_obey_proof_cap_without_consuming_literal_budget() {
        let mut arena = DomainProofArena::new(1, 0, caps(1, 0, 0));
        let reason = stored(arena.insert(TermId::new(0), true, &[]).unwrap());
        assert!(arena.lookup(reason).unwrap().antecedents().is_empty());
        assert_eq!(arena.total_antecedents(), 0);

        let before = snapshot(&arena);
        assert!(matches!(
            arena.insert(TermId::new(0), false, &[]),
            Err(DomainProofError::CapExceeded {
                resource: DomainProofResource::Proofs,
                ..
            })
        ));
        assert_eq!(snapshot(&arena), before);
    }

    #[test]
    fn every_persistent_allocation_failure_is_transactional_and_retryable() {
        for site in [
            AllocationSite::CanonicalAntecedents,
            AllocationSite::ProofTable,
        ] {
            let mut arena = DomainProofArena::new(2, 2, caps(4, 8, 4));
            arena.fail_next_allocation_at(site);
            let before = snapshot(&arena);
            let requested = match site {
                AllocationSite::CanonicalAntecedents => 2,
                AllocationSite::ProofTable => 1,
            };
            assert_eq!(
                arena.insert(TermId::new(1), true, &[p(0), n(1)]),
                Err(DomainProofError::AllocationFailed {
                    context: site.context(),
                    requested,
                })
            );
            assert_eq!(snapshot(&arena), before);

            let reason = stored(arena.insert(TermId::new(1), true, &[p(0), n(1)]).unwrap());
            assert_eq!(reason.raw(), DOMAIN_PROOF_REASON_TAG);
            assert!(arena.invariants_hold());
        }
    }

    #[test]
    fn actual_reservation_failure_is_mapped_without_mutation() {
        let mut values: Vec<Lit> = Vec::new();
        assert_eq!(
            try_reserve_exact(&mut values, usize::MAX, "test domain-proof allocation"),
            Err(DomainProofError::AllocationFailed {
                context: "test domain-proof allocation",
                requested: usize::MAX,
            })
        );
        assert!(values.is_empty());
    }

    #[test]
    fn checked_arithmetic_reports_overflow() {
        assert_eq!(
            checked_add(usize::MAX, 1, DomainProofResource::TotalAntecedents),
            Err(DomainProofError::ArithmeticOverflow {
                resource: DomainProofResource::TotalAntecedents,
            })
        );
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn reason_id_max_is_never_allocated() {
        let mut arena = DomainProofArena::new(1, 0, DomainProofCaps::unlimited());
        arena.next_proof_index_override = Some(MAX_DOMAIN_PROOF_COUNT as usize);
        let before = snapshot(&arena);
        assert_eq!(
            arena.insert(TermId::new(0), true, &[]),
            Err(DomainProofError::ReasonIdSpaceExhausted {
                index: MAX_DOMAIN_PROOF_COUNT as usize,
                maximum_proofs: MAX_DOMAIN_PROOF_COUNT,
            })
        );
        assert_eq!(snapshot(&arena), before);
    }

    #[test]
    fn deterministic_insertion_sequences_are_byte_for_byte_equivalent() {
        let mut left = DomainProofArena::new(4, 5, caps(8, 32, 8));
        let mut right = DomainProofArena::new(4, 5, caps(8, 32, 8));
        let sequence = [
            (TermId::new(3), true, vec![p(4), n(0), p(2), p(4)]),
            (TermId::new(1), false, vec![]),
            (TermId::new(3), true, vec![p(2), n(0), p(4)]),
            (TermId::new(0), false, vec![n(3)]),
        ];

        let left_ids: Vec<_> = sequence
            .iter()
            .map(|(term, value, antecedents)| {
                stored(left.insert(*term, *value, antecedents).unwrap())
            })
            .collect();
        let right_ids: Vec<_> = sequence
            .iter()
            .map(|(term, value, antecedents)| {
                stored(right.insert(*term, *value, antecedents).unwrap())
            })
            .collect();

        assert_eq!(left_ids, right_ids);
        assert_eq!(snapshot(&left), snapshot(&right));
        assert!(left.invariants_hold());
        assert!(right.invariants_hold());
    }
}
