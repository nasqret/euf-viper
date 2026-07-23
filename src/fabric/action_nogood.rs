#![forbid(unsafe_code)]

//! Stable quotient-action nogoods and independently replayable evidence.
//!
//! This module is deliberately separate from Boolean conflict analysis. An
//! [`ActionValue`] is a finite-domain value, not a SAT atom: neither existing
//! quotient classes nor the fresh-class action are encoded as `AtomId`/`Lit`,
//! and no first-UIP operation appears here.
//!
//! Serialized objects retain the original [`TermId`] values supplied by the
//! semantic term arena. Union-find roots, class numbers, and current canonical
//! representatives are used neither as keys nor as stored values. A live
//! [`Partition`] is consulted only by the read-only three-valued matcher.
//!
//! A certificate is a canonical list of stable relation facts. Internal facts
//! identify the exact forbidden conjunct from which they follow; external
//! facts carry an opaque proof-stream token for an independent checker to
//! resolve. Replay uses a small equality closure owned by this module and
//! succeeds only when those facts derive an equality/disequality conflict.
//! The substrate does not learn from recursive UNSAT and does not mutate an
//! action domain or the search engine.

use super::partition::{MAX_TERMS, Partition, PartitionError, Relation, TermId};
use super::semantic::SemanticTerm;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

const MAX_NOGOOD_IDS: u64 = u32::MAX as u64 + 1;

/// A canonical finite-domain key for one quotient placement decision.
///
/// `frontier` is sorted and deduplicated by stable term ID. It never contains
/// `pivot`; equality created later between the pivot and an anchor is a live
/// partition fact and does not rewrite this key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ActionDomainKey {
    pivot: TermId,
    frontier: Vec<TermId>,
}

impl ActionDomainKey {
    pub(crate) fn new(
        pivot: TermId,
        frontier: &[TermId],
        caps: ActionNogoodCaps,
    ) -> Result<Self, ActionNogoodError> {
        check_cap(
            ActionNogoodResource::FrontierAnchorsPerDomain,
            frontier.len(),
            caps.max_frontier_anchors_per_domain,
        )?;
        let mut canonical = try_copy_slice(frontier, "action-domain frontier")?;
        canonical.sort_unstable();
        canonical.dedup();
        if canonical.binary_search(&pivot).is_ok() {
            return Err(ActionNogoodError::Malformed(
                MalformedActionNogood::PivotInFrontier { pivot },
            ));
        }
        Ok(Self {
            pivot,
            frontier: canonical,
        })
    }

    pub(crate) const fn pivot(&self) -> TermId {
        self.pivot
    }

    pub(crate) fn frontier(&self) -> &[TermId] {
        &self.frontier
    }

    pub(crate) fn contains_anchor(&self, anchor: TermId) -> bool {
        self.frontier.binary_search(&anchor).is_ok()
    }
}

/// A value in a quotient action domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ActionValue {
    Existing(TermId),
    Fresh,
}

/// A stable action frozen at the decision frontier where it was created.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct FrozenAction {
    domain: ActionDomainKey,
    value: ActionValue,
}

impl FrozenAction {
    pub(crate) fn new(
        domain: ActionDomainKey,
        value: ActionValue,
    ) -> Result<Self, ActionNogoodError> {
        if let ActionValue::Existing(target) = value {
            if !domain.contains_anchor(target) {
                return Err(ActionNogoodError::Malformed(
                    MalformedActionNogood::ExistingTargetOutsideFrontier {
                        pivot: domain.pivot,
                        target,
                    },
                ));
            }
        }
        Ok(Self { domain, value })
    }

    pub(crate) const fn domain(&self) -> &ActionDomainKey {
        &self.domain
    }

    pub(crate) const fn value(&self) -> ActionValue {
        self.value
    }
}

/// The required truth of one stable equality relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum RequiredRelation {
    Equal,
    Disequal,
}

/// A relation condition with endpoints in stable minimum-ID order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RelationCondition {
    left: TermId,
    right: TermId,
    required: RequiredRelation,
}

impl RelationCondition {
    pub(crate) fn new(left: TermId, right: TermId, required: RequiredRelation) -> Self {
        let (left, right) = ordered_pair(left, right);
        Self {
            left,
            right,
            required,
        }
    }

    pub(crate) fn equal(left: TermId, right: TermId) -> Self {
        Self::new(left, right, RequiredRelation::Equal)
    }

    pub(crate) fn disequal(left: TermId, right: TermId) -> Self {
        Self::new(left, right, RequiredRelation::Disequal)
    }

    pub(crate) const fn left(self) -> TermId {
        self.left
    }

    pub(crate) const fn right(self) -> TermId {
        self.right
    }

    pub(crate) const fn required(self) -> RequiredRelation {
        self.required
    }

    /// Classify reflexive conditions without consulting a partition.
    pub(crate) fn classification(self) -> RelationConditionClass {
        if self.left != self.right {
            RelationConditionClass::Proper(self)
        } else {
            match self.required {
                RequiredRelation::Equal => RelationConditionClass::Tautology(self),
                RequiredRelation::Disequal => RelationConditionClass::Contradiction(self),
            }
        }
    }
}

/// Static classification of one canonical relation condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelationConditionClass {
    Proper(RelationCondition),
    Tautology(RelationCondition),
    Contradiction(RelationCondition),
}

/// Stable handle into an external proof/event stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct EvidenceToken(u64);

impl EvidenceToken {
    pub(crate) const MIN: Self = Self(0);
    pub(crate) const MAX: Self = Self(u64::MAX);

    pub(crate) const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub(crate) const fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Display for EvidenceToken {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(output)
    }
}

/// Why one relation may be asserted during independent certificate replay.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum EvidenceOrigin {
    /// The exact relation occurs in the forbidden conjunction.
    ForbiddenRelation,
    /// The relation is `pivot = target` for this exact existing action.
    ExistingAction(FrozenAction),
    /// The relation is `pivot != anchor` for this exact fresh action.
    FreshAction {
        action: FrozenAction,
        anchor: TermId,
    },
    /// A separate proof stream must prove the relation named by the evidence.
    External(EvidenceToken),
}

/// One canonical stable relation assertion in a replay certificate.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CertificateEvidence {
    relation: RelationCondition,
    origin: EvidenceOrigin,
}

impl CertificateEvidence {
    pub(crate) const fn forbidden_relation(relation: RelationCondition) -> Self {
        Self {
            relation,
            origin: EvidenceOrigin::ForbiddenRelation,
        }
    }

    pub(crate) fn existing(action: FrozenAction) -> Result<Self, ActionNogoodError> {
        let ActionValue::Existing(target) = action.value else {
            return Err(ActionNogoodError::Malformed(
                MalformedActionNogood::ExistingEvidenceNamesFreshAction,
            ));
        };
        let relation = RelationCondition::equal(action.domain.pivot, target);
        Ok(Self {
            relation,
            origin: EvidenceOrigin::ExistingAction(action),
        })
    }

    pub(crate) fn fresh(action: FrozenAction, anchor: TermId) -> Result<Self, ActionNogoodError> {
        if !matches!(action.value, ActionValue::Fresh) {
            return Err(ActionNogoodError::Malformed(
                MalformedActionNogood::FreshEvidenceNamesExistingAction,
            ));
        }
        if !action.domain.contains_anchor(anchor) {
            return Err(ActionNogoodError::Malformed(
                MalformedActionNogood::FreshEvidenceAnchorOutsideFrontier {
                    pivot: action.domain.pivot,
                    anchor,
                },
            ));
        }
        let relation = RelationCondition::disequal(action.domain.pivot, anchor);
        Ok(Self {
            relation,
            origin: EvidenceOrigin::FreshAction { action, anchor },
        })
    }

    pub(crate) const fn external(relation: RelationCondition, token: EvidenceToken) -> Self {
        Self {
            relation,
            origin: EvidenceOrigin::External(token),
        }
    }

    pub(crate) const fn relation(&self) -> RelationCondition {
        self.relation
    }

    pub(crate) const fn origin(&self) -> &EvidenceOrigin {
        &self.origin
    }
}

/// Canonical evidence payload. Replay order is derived, not serialized.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ActionNogoodCertificate {
    evidence: Vec<CertificateEvidence>,
}

impl ActionNogoodCertificate {
    pub(crate) fn evidence(&self) -> &[CertificateEvidence] {
        &self.evidence
    }
}

/// Canonical conjunction whose simultaneous truth is forbidden.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ForbiddenConjunction {
    actions: Vec<FrozenAction>,
    relations: Vec<RelationCondition>,
}

impl ForbiddenConjunction {
    pub(crate) fn actions(&self) -> &[FrozenAction] {
        &self.actions
    }

    pub(crate) fn relations(&self) -> &[RelationCondition] {
        &self.relations
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.actions.is_empty() && self.relations.is_empty()
    }
}

/// One canonical action nogood with stable replay evidence.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ActionNogood {
    term_count: usize,
    forbidden: ForbiddenConjunction,
    certificate: ActionNogoodCertificate,
}

impl ActionNogood {
    pub(crate) const fn term_count(&self) -> usize {
        self.term_count
    }

    pub(crate) const fn forbidden(&self) -> &ForbiddenConjunction {
        &self.forbidden
    }

    pub(crate) const fn certificate(&self) -> &ActionNogoodCertificate {
        &self.certificate
    }

    /// Canonicalize and validate an owned nogood request.
    ///
    /// Input vectors are consumed so sorting and deduplication require no
    /// hidden infallible clone. Caps apply before potentially large work and
    /// again to canonical/expanded sizes.
    pub(crate) fn build(
        term_count: usize,
        mut actions: Vec<FrozenAction>,
        mut relations: Vec<RelationCondition>,
        mut evidence: Vec<CertificateEvidence>,
        caps: ActionNogoodCaps,
    ) -> Result<ActionNogoodBuild, ActionNogoodError> {
        validate_term_universe(term_count, caps)?;
        check_cap(
            ActionNogoodResource::ActionsPerNogood,
            actions.len(),
            caps.max_actions_per_nogood,
        )?;
        check_cap(
            ActionNogoodResource::RelationsPerNogood,
            relations.len(),
            caps.max_relations_per_nogood,
        )?;
        check_cap(
            ActionNogoodResource::CertificateEvidence,
            evidence.len(),
            caps.max_certificate_evidence,
        )?;
        if evidence.is_empty() {
            return Err(ActionNogoodError::Malformed(
                MalformedActionNogood::EmptyCertificate,
            ));
        }

        for action in &actions {
            validate_action(action, term_count, caps)?;
        }
        for relation in &relations {
            validate_relation_terms(*relation, term_count, "forbidden relation")?;
        }
        for item in &evidence {
            validate_relation_terms(item.relation, term_count, "certificate relation")?;
            match item.relation.classification() {
                RelationConditionClass::Proper(_) => {}
                RelationConditionClass::Tautology(relation) => {
                    return Err(ActionNogoodError::Malformed(
                        MalformedActionNogood::TautologicalCertificateRelation { relation },
                    ));
                }
                RelationConditionClass::Contradiction(relation) => {
                    return Err(ActionNogoodError::Malformed(
                        MalformedActionNogood::ContradictoryCertificateRelation { relation },
                    ));
                }
            }
            validate_evidence_action_terms(item, term_count, caps)?;
        }

        actions.sort_unstable();
        actions.dedup();
        relations.sort_unstable();
        relations.dedup();
        evidence.sort_unstable();
        evidence.dedup();

        check_cap(
            ActionNogoodResource::ActionsPerNogood,
            actions.len(),
            caps.max_actions_per_nogood,
        )?;
        check_cap(
            ActionNogoodResource::RelationsPerNogood,
            relations.len(),
            caps.max_relations_per_nogood,
        )?;
        check_cap(
            ActionNogoodResource::CertificateEvidence,
            evidence.len(),
            caps.max_certificate_evidence,
        )?;

        let mut first_static_contradiction = None;
        relations.retain(|relation| match relation.classification() {
            RelationConditionClass::Proper(_) => true,
            RelationConditionClass::Tautology(_) => false,
            RelationConditionClass::Contradiction(relation) => {
                first_static_contradiction
                    .get_or_insert(ForbiddenContradiction::ReflexiveDisequality { relation });
                false
            }
        });

        let total_frontier_anchors = count_frontier_anchors(&actions)?;
        check_cap(
            ActionNogoodResource::TotalFrontierAnchors,
            total_frontier_anchors,
            caps.max_total_frontier_anchors,
        )?;
        let expanded_relations = count_expanded_relations(&actions, &relations)?;
        check_cap(
            ActionNogoodResource::ExpandedRelations,
            expanded_relations,
            caps.max_expanded_relations,
        )?;

        let forbidden = ForbiddenConjunction { actions, relations };
        let certificate = ActionNogoodCertificate { evidence };
        validate_certificate_origins(&forbidden, &certificate)?;

        let contradiction = if let Some(contradiction) = first_static_contradiction {
            Some(contradiction)
        } else {
            detect_forbidden_contradiction(term_count, &forbidden)?
        };
        if let Some(contradiction) = contradiction {
            return Ok(ActionNogoodBuild::TautologicalConstraint {
                contradiction,
                certificate,
            });
        }

        let nogood = Self {
            term_count,
            forbidden,
            certificate,
        };
        if nogood.forbidden.is_empty() {
            // NOT(true) is an unconditional contradiction. It remains an
            // explicit outcome so callers cannot mistake it for an ordinary
            // learned pruning.
            Ok(ActionNogoodBuild::ContradictoryConstraint(nogood))
        } else {
            Ok(ActionNogoodBuild::Built(nogood))
        }
    }

    /// Match the forbidden conjunction against a live partial partition.
    ///
    /// `Matched` means every conjunct is currently proved and the nogood fires;
    /// `Refuted` means at least one conjunct is false; `Undetermined` means none
    /// is false and at least one remains unknown. The partition is never
    /// mutated.
    pub(crate) fn match_partition(
        &self,
        partition: &Partition,
        caps: ActionNogoodCaps,
    ) -> Result<ActionNogoodMatch, ActionNogoodError> {
        if partition.term_count() != self.term_count {
            return Err(ActionNogoodError::PartitionTermCountMismatch {
                nogood_terms: self.term_count,
                partition_terms: partition.term_count(),
            });
        }
        let mut budget = QueryBudget::new(caps.max_match_relation_queries);
        let mut saw_unknown = false;

        for action in &self.forbidden.actions {
            let truth = match match_action(action, partition, &mut budget) {
                Ok(truth) => truth,
                Err(ActionNogoodError::CapExceeded(limit))
                    if limit.resource == ActionNogoodResource::MatchRelationQueries =>
                {
                    return Ok(ActionNogoodMatch::Abstained(limit));
                }
                Err(error) => return Err(error),
            };
            match truth {
                ConditionTruth::True => {}
                ConditionTruth::False => {
                    return Ok(ActionNogoodMatch::Refuted {
                        relation_queries: budget.used,
                    });
                }
                ConditionTruth::Unknown => saw_unknown = true,
            }
        }
        for relation in &self.forbidden.relations {
            let truth = match match_relation(*relation, partition, &mut budget) {
                Ok(truth) => truth,
                Err(ActionNogoodError::CapExceeded(limit))
                    if limit.resource == ActionNogoodResource::MatchRelationQueries =>
                {
                    return Ok(ActionNogoodMatch::Abstained(limit));
                }
                Err(error) => return Err(error),
            };
            match truth {
                ConditionTruth::True => {}
                ConditionTruth::False => {
                    return Ok(ActionNogoodMatch::Refuted {
                        relation_queries: budget.used,
                    });
                }
                ConditionTruth::Unknown => saw_unknown = true,
            }
        }

        if saw_unknown {
            Ok(ActionNogoodMatch::Undetermined {
                relation_queries: budget.used,
            })
        } else {
            Ok(ActionNogoodMatch::Matched {
                relation_queries: budget.used,
            })
        }
    }

    /// Match while treating one frozen action as the candidate currently
    /// under consideration. This does not mutate the partition. Actions from
    /// the same domain are mutually exclusive, and exact relation facts
    /// asserted by the candidate are resolved without a partition query.
    pub(crate) fn match_partition_assuming(
        &self,
        partition: &Partition,
        assumed: &FrozenAction,
        caps: ActionNogoodCaps,
    ) -> Result<ActionNogoodMatch, ActionNogoodError> {
        if partition.term_count() != self.term_count {
            return Err(ActionNogoodError::PartitionTermCountMismatch {
                nogood_terms: self.term_count,
                partition_terms: partition.term_count(),
            });
        }
        validate_action(assumed, self.term_count, caps)?;
        let mut budget = QueryBudget::new(caps.max_match_relation_queries);
        let mut saw_unknown = false;

        for action in &self.forbidden.actions {
            let truth = if action.domain == assumed.domain {
                if action.value == assumed.value {
                    ConditionTruth::True
                } else {
                    ConditionTruth::False
                }
            } else {
                match match_action(action, partition, &mut budget) {
                    Ok(truth) => truth,
                    Err(ActionNogoodError::CapExceeded(limit))
                        if limit.resource == ActionNogoodResource::MatchRelationQueries =>
                    {
                        return Ok(ActionNogoodMatch::Abstained(limit));
                    }
                    Err(error) => return Err(error),
                }
            };
            match truth {
                ConditionTruth::True => {}
                ConditionTruth::False => {
                    return Ok(ActionNogoodMatch::Refuted {
                        relation_queries: budget.used,
                    });
                }
                ConditionTruth::Unknown => saw_unknown = true,
            }
        }
        for relation in &self.forbidden.relations {
            let truth = if let Some(truth) = assumed_relation_truth(assumed, *relation) {
                truth
            } else {
                match match_relation(*relation, partition, &mut budget) {
                    Ok(truth) => truth,
                    Err(ActionNogoodError::CapExceeded(limit))
                        if limit.resource == ActionNogoodResource::MatchRelationQueries =>
                    {
                        return Ok(ActionNogoodMatch::Abstained(limit));
                    }
                    Err(error) => return Err(error),
                }
            };
            match truth {
                ConditionTruth::True => {}
                ConditionTruth::False => {
                    return Ok(ActionNogoodMatch::Refuted {
                        relation_queries: budget.used,
                    });
                }
                ConditionTruth::Unknown => saw_unknown = true,
            }
        }

        if saw_unknown {
            Ok(ActionNogoodMatch::Undetermined {
                relation_queries: budget.used,
            })
        } else {
            Ok(ActionNogoodMatch::Matched {
                relation_queries: budget.used,
            })
        }
    }

    /// Independently replay all certified relation facts under EUF
    /// congruence. The checker owns its equality closure and signature rounds;
    /// it does not call the search engine's partition or congruence backend.
    pub(crate) fn replay_euf_certificate_with<F>(
        &self,
        terms: &[SemanticTerm],
        caps: ActionEufReplayCaps,
        mut resolves_external: F,
    ) -> Result<ActionEufReplay, ActionNogoodError>
    where
        F: FnMut(EvidenceToken, RelationCondition) -> bool,
    {
        if terms.len() != self.term_count {
            return Err(ActionNogoodError::SemanticTermCountMismatch {
                nogood_terms: self.term_count,
                semantic_terms: terms.len(),
            });
        }
        if terms.len() > caps.max_terms {
            return Ok(ActionEufReplay::Abstained(ActionNogoodLimit {
                resource: ActionNogoodResource::EufReplayTerms,
                attempted: terms.len(),
                limit: caps.max_terms,
            }));
        }
        if self.certificate.evidence.len() > caps.max_relations {
            return Ok(ActionEufReplay::Abstained(ActionNogoodLimit {
                resource: ActionNogoodResource::EufReplayRelations,
                attempted: self.certificate.evidence.len(),
                limit: caps.max_relations,
            }));
        }
        validate_certificate_origins(&self.forbidden, &self.certificate)?;
        validate_semantic_terms(terms)?;

        let mut closure = StableEqualityClosure::new(self.term_count)?;
        let mut disequalities = Vec::new();
        disequalities
            .try_reserve_exact(self.certificate.evidence.len())
            .map_err(|_| ActionNogoodError::AllocationFailed {
                context: "EUF replay disequalities",
                requested: self.certificate.evidence.len(),
            })?;
        let mut external_evidence = 0usize;
        for item in &self.certificate.evidence {
            if terms[item.relation.left.index()].sort != terms[item.relation.right.index()].sort {
                return Err(ActionNogoodError::IllSortedCertificateRelation {
                    relation: item.relation,
                });
            }
            if let EvidenceOrigin::External(token) = item.origin {
                external_evidence = checked_add(
                    external_evidence,
                    1,
                    ActionNogoodResource::EufReplayRelations,
                )?;
                if !resolves_external(token, item.relation) {
                    return Ok(ActionEufReplay::ExternalEvidenceRejected {
                        token,
                        relation: item.relation,
                    });
                }
            }
            match item.relation.required {
                RequiredRelation::Equal => {
                    closure.union(item.relation.left, item.relation.right)?;
                }
                RequiredRelation::Disequal => disequalities.push(item.relation),
            }
        }

        let mut rounds = 0usize;
        let mut signature_work = 0usize;
        loop {
            rounds = checked_add(rounds, 1, ActionNogoodResource::EufReplayRounds)?;
            if rounds > caps.max_rounds {
                return Ok(ActionEufReplay::Abstained(ActionNogoodLimit {
                    resource: ActionNogoodResource::EufReplayRounds,
                    attempted: rounds,
                    limit: caps.max_rounds,
                }));
            }
            let mut signatures = Vec::new();
            signatures.try_reserve_exact(terms.len()).map_err(|_| {
                ActionNogoodError::AllocationFailed {
                    context: "EUF replay signatures",
                    requested: terms.len(),
                }
            })?;
            for (index, term) in terms.iter().enumerate() {
                signature_work = checked_add(
                    signature_work,
                    1,
                    ActionNogoodResource::EufReplaySignatureWork,
                )?;
                signature_work = checked_add(
                    signature_work,
                    term.arguments.len(),
                    ActionNogoodResource::EufReplaySignatureWork,
                )?;
                if signature_work > caps.max_signature_work {
                    return Ok(ActionEufReplay::Abstained(ActionNogoodLimit {
                        resource: ActionNogoodResource::EufReplaySignatureWork,
                        attempted: signature_work,
                        limit: caps.max_signature_work,
                    }));
                }
                let mut arguments = Vec::new();
                arguments
                    .try_reserve_exact(term.arguments.len())
                    .map_err(|_| ActionNogoodError::AllocationFailed {
                        context: "EUF replay signature arguments",
                        requested: term.arguments.len(),
                    })?;
                for &argument in &term.arguments {
                    arguments.push(closure.find(argument)?);
                }
                signatures.push((
                    ReplaySignature {
                        function: term.function,
                        sort: term.sort,
                        arguments: arguments.into_boxed_slice(),
                    },
                    TermId::new(index as u32),
                ));
            }
            signatures.sort_unstable();
            let mut changed = false;
            let mut first = 0usize;
            while first < signatures.len() {
                let mut end = first + 1;
                while end < signatures.len() && signatures[end].0 == signatures[first].0 {
                    end += 1;
                }
                let representative = signatures[first].1;
                for entry in &signatures[first + 1..end] {
                    changed |= closure.union(representative, entry.1)?;
                }
                first = end;
            }
            if !changed {
                break;
            }
        }

        for &relation in &disequalities {
            if closure.same(relation.left, relation.right)? {
                return Ok(ActionEufReplay::VerifiedConflict {
                    relations_checked: self.certificate.evidence.len(),
                    external_evidence,
                    rounds,
                    signature_work,
                    witness: relation,
                });
            }
        }
        Ok(ActionEufReplay::NoConflict {
            relations_checked: self.certificate.evidence.len(),
            external_evidence,
            rounds,
            signature_work,
        })
    }

    /// Replay the stable certificate with an independent external-evidence
    /// resolver. Internal origins are rechecked before any relation is used.
    pub(crate) fn replay_certificate_with<F>(
        &self,
        caps: ActionNogoodCaps,
        mut resolves_external: F,
    ) -> Result<CertificateReplay, ActionNogoodError>
    where
        F: FnMut(EvidenceToken, RelationCondition) -> bool,
    {
        let evidence_count = self.certificate.evidence.len();
        if evidence_count > caps.max_replay_relations {
            return Ok(CertificateReplay::Abstained(ActionNogoodLimit {
                resource: ActionNogoodResource::ReplayRelations,
                attempted: evidence_count,
                limit: caps.max_replay_relations,
            }));
        }
        validate_certificate_origins(&self.forbidden, &self.certificate)?;

        let mut external_evidence = 0usize;
        for item in &self.certificate.evidence {
            if let EvidenceOrigin::External(token) = item.origin {
                external_evidence =
                    checked_add(external_evidence, 1, ActionNogoodResource::ReplayRelations)?;
                if !resolves_external(token, item.relation) {
                    return Ok(CertificateReplay::ExternalEvidenceRejected {
                        token,
                        relation: item.relation,
                        relations_checked: evidence_count,
                    });
                }
            }
        }

        let mut closure = StableEqualityClosure::new(self.term_count)?;
        for item in &self.certificate.evidence {
            if matches!(item.relation.required, RequiredRelation::Equal) {
                closure.union(item.relation.left, item.relation.right)?;
            }
        }
        for item in &self.certificate.evidence {
            if matches!(item.relation.required, RequiredRelation::Disequal)
                && closure.same(item.relation.left, item.relation.right)?
            {
                return Ok(CertificateReplay::VerifiedConflict {
                    relations_checked: evidence_count,
                    external_evidence,
                    witness: item.relation,
                });
            }
        }
        Ok(CertificateReplay::NoConflict {
            relations_checked: evidence_count,
            external_evidence,
        })
    }
}

/// Explicit semantic outcome of nogood construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ActionNogoodBuild {
    Built(ActionNogood),
    /// The forbidden conjunction is always true (normally because it is
    /// empty), so its negation is an unconditional contradiction.
    ContradictoryConstraint(ActionNogood),
    /// The forbidden conjunction is internally impossible, so its negation is
    /// a tautology and must not be installed as a pruning.
    TautologicalConstraint {
        contradiction: ForbiddenContradiction,
        certificate: ActionNogoodCertificate,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ForbiddenContradiction {
    ReflexiveDisequality { relation: RelationCondition },
    EqualityDisequalityConflict { left: TermId, right: TermId },
}

/// Three-valued runtime match result plus exact query accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActionNogoodMatch {
    Matched { relation_queries: usize },
    Refuted { relation_queries: usize },
    Undetermined { relation_queries: usize },
    Abstained(ActionNogoodLimit),
}

impl ActionNogoodMatch {
    pub(crate) const fn relation_queries(self) -> Option<usize> {
        match self {
            Self::Matched { relation_queries }
            | Self::Refuted { relation_queries }
            | Self::Undetermined { relation_queries } => Some(relation_queries),
            Self::Abstained(_) => None,
        }
    }
}

/// Outcome of checking a certificate payload independently of live roots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CertificateReplay {
    VerifiedConflict {
        relations_checked: usize,
        external_evidence: usize,
        witness: RelationCondition,
    },
    NoConflict {
        relations_checked: usize,
        external_evidence: usize,
    },
    ExternalEvidenceRejected {
        token: EvidenceToken,
        relation: RelationCondition,
        relations_checked: usize,
    },
    Abstained(ActionNogoodLimit),
}

/// Independent EUF replay limits. Work is charged deterministically so a
/// certificate checker can abstain without trusting producer-controlled size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ActionEufReplayCaps {
    pub(crate) max_terms: usize,
    pub(crate) max_relations: usize,
    pub(crate) max_rounds: usize,
    pub(crate) max_signature_work: usize,
}

impl Default for ActionEufReplayCaps {
    fn default() -> Self {
        Self {
            max_terms: 100_000,
            max_relations: 1_000_000,
            max_rounds: 1_024,
            max_signature_work: 16_000_000,
        }
    }
}

/// Result of replaying a certificate with an independently implemented EUF
/// closure over stable semantic terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActionEufReplay {
    VerifiedConflict {
        relations_checked: usize,
        external_evidence: usize,
        rounds: usize,
        signature_work: usize,
        witness: RelationCondition,
    },
    NoConflict {
        relations_checked: usize,
        external_evidence: usize,
        rounds: usize,
        signature_work: usize,
    },
    ExternalEvidenceRejected {
        token: EvidenceToken,
        relation: RelationCondition,
    },
    Abstained(ActionNogoodLimit),
}

/// Structural and runtime limits for one canonical nogood.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ActionNogoodCaps {
    pub(crate) max_terms: usize,
    pub(crate) max_actions_per_nogood: usize,
    pub(crate) max_relations_per_nogood: usize,
    pub(crate) max_frontier_anchors_per_domain: usize,
    pub(crate) max_total_frontier_anchors: usize,
    pub(crate) max_certificate_evidence: usize,
    pub(crate) max_expanded_relations: usize,
    pub(crate) max_match_relation_queries: usize,
    pub(crate) max_replay_relations: usize,
}

impl ActionNogoodCaps {
    pub(crate) const fn unlimited() -> Self {
        Self {
            max_terms: usize::MAX,
            max_actions_per_nogood: usize::MAX,
            max_relations_per_nogood: usize::MAX,
            max_frontier_anchors_per_domain: usize::MAX,
            max_total_frontier_anchors: usize::MAX,
            max_certificate_evidence: usize::MAX,
            max_expanded_relations: usize::MAX,
            max_match_relation_queries: usize::MAX,
            max_replay_relations: usize::MAX,
        }
    }
}

impl Default for ActionNogoodCaps {
    fn default() -> Self {
        Self {
            max_terms: 1_000_000,
            max_actions_per_nogood: 65_536,
            max_relations_per_nogood: 1_000_000,
            max_frontier_anchors_per_domain: 1_000_000,
            max_total_frontier_anchors: 4_000_000,
            max_certificate_evidence: 4_000_000,
            max_expanded_relations: 8_000_000,
            max_match_relation_queries: 8_000_000,
            max_replay_relations: 4_000_000,
        }
    }
}

/// A bounded resource used by construction, matching, replay, or storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActionNogoodResource {
    Terms,
    ActionsPerNogood,
    RelationsPerNogood,
    FrontierAnchorsPerDomain,
    TotalFrontierAnchors,
    CertificateEvidence,
    ExpandedRelations,
    MatchRelationQueries,
    ReplayRelations,
    EufReplayTerms,
    EufReplayRelations,
    EufReplayRounds,
    EufReplaySignatureWork,
    StoredNogoods,
    StoredActions,
    StoredRelations,
    StoredFrontierAnchors,
    StoredCertificateEvidence,
}

impl fmt::Display for ActionNogoodResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Terms => "action-nogood terms",
            Self::ActionsPerNogood => "actions per nogood",
            Self::RelationsPerNogood => "relations per nogood",
            Self::FrontierAnchorsPerDomain => "frontier anchors per action domain",
            Self::TotalFrontierAnchors => "frontier anchors per nogood",
            Self::CertificateEvidence => "certificate evidence per nogood",
            Self::ExpandedRelations => "expanded action-nogood relations",
            Self::MatchRelationQueries => "action-nogood match relation queries",
            Self::ReplayRelations => "certificate replay relations",
            Self::EufReplayTerms => "EUF replay terms",
            Self::EufReplayRelations => "EUF replay relations",
            Self::EufReplayRounds => "EUF replay signature rounds",
            Self::EufReplaySignatureWork => "EUF replay signature work",
            Self::StoredNogoods => "stored action nogoods",
            Self::StoredActions => "stored action conjuncts",
            Self::StoredRelations => "stored relation conjuncts",
            Self::StoredFrontierAnchors => "stored frontier anchors",
            Self::StoredCertificateEvidence => "stored certificate evidence",
        };
        output.write_str(name)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ActionNogoodLimit {
    pub(crate) resource: ActionNogoodResource,
    pub(crate) attempted: usize,
    pub(crate) limit: usize,
}

impl fmt::Display for ActionNogoodLimit {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "{} cap exceeded: attempted {}, limit {}",
            self.resource, self.attempted, self.limit
        )
    }
}

/// Structural reasons an input cannot denote a stable quotient-action nogood.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MalformedActionNogood {
    PivotInFrontier { pivot: TermId },
    ExistingTargetOutsideFrontier { pivot: TermId, target: TermId },
    EmptyCertificate,
    TautologicalCertificateRelation { relation: RelationCondition },
    ContradictoryCertificateRelation { relation: RelationCondition },
    ExistingEvidenceNamesFreshAction,
    FreshEvidenceNamesExistingAction,
    FreshEvidenceAnchorOutsideFrontier { pivot: TermId, anchor: TermId },
    ForbiddenRelationOriginMissing { relation: RelationCondition },
    ForbiddenActionOriginMissing,
    EvidenceRelationMismatch { relation: RelationCondition },
    NonCanonicalActionDomain,
}

impl fmt::Display for MalformedActionNogood {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PivotInFrontier { pivot } => {
                write!(output, "action pivot {pivot} occurs in its own frontier")
            }
            Self::ExistingTargetOutsideFrontier { pivot, target } => write!(
                output,
                "existing target {target} is absent from pivot {pivot}'s frozen frontier"
            ),
            Self::EmptyCertificate => output.write_str("action nogood has an empty certificate"),
            Self::TautologicalCertificateRelation { relation } => write!(
                output,
                "certificate contains tautological relation {} = {}",
                relation.left, relation.right
            ),
            Self::ContradictoryCertificateRelation { relation } => write!(
                output,
                "certificate contains contradictory relation {} != {}",
                relation.left, relation.right
            ),
            Self::ExistingEvidenceNamesFreshAction => {
                output.write_str("existing-action evidence names a fresh action")
            }
            Self::FreshEvidenceNamesExistingAction => {
                output.write_str("fresh-action evidence names an existing action")
            }
            Self::FreshEvidenceAnchorOutsideFrontier { pivot, anchor } => write!(
                output,
                "fresh-action evidence anchor {anchor} is absent from pivot {pivot}'s frontier"
            ),
            Self::ForbiddenRelationOriginMissing { relation } => write!(
                output,
                "certificate relation {:?} {} {} is absent from the forbidden conjunction",
                relation.required, relation.left, relation.right
            ),
            Self::ForbiddenActionOriginMissing => {
                output.write_str("certificate action is absent from the forbidden conjunction")
            }
            Self::EvidenceRelationMismatch { relation } => write!(
                output,
                "certificate origin does not derive {:?} {} {}",
                relation.required, relation.left, relation.right
            ),
            Self::NonCanonicalActionDomain => {
                output.write_str("action domain is not sorted, unique, and pivot-free")
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ActionNogoodError {
    Malformed(MalformedActionNogood),
    TermOutOfRange {
        context: &'static str,
        term: TermId,
        term_count: usize,
    },
    TooManyTerms {
        requested: usize,
        maximum: u64,
    },
    PartitionTermCountMismatch {
        nogood_terms: usize,
        partition_terms: usize,
    },
    SemanticTermCountMismatch {
        nogood_terms: usize,
        semantic_terms: usize,
    },
    SemanticArgumentOutOfRange {
        term: TermId,
        argument: TermId,
        term_count: usize,
    },
    InconsistentFunctionSignature {
        function: u32,
    },
    IllSortedCertificateRelation {
        relation: RelationCondition,
    },
    CapExceeded(ActionNogoodLimit),
    ArithmeticOverflow {
        resource: ActionNogoodResource,
    },
    NogoodIdSpaceExhausted {
        index: usize,
        maximum: u64,
    },
    AllocationFailed {
        context: &'static str,
        requested: usize,
    },
    Partition(PartitionError),
    InvariantViolation(&'static str),
}

impl fmt::Display for ActionNogoodError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(error) => error.fmt(output),
            Self::TermOutOfRange {
                context,
                term,
                term_count,
            } => write!(output, "{context} term {term} is outside 0..{term_count}"),
            Self::TooManyTerms { requested, maximum } => write!(
                output,
                "action nogood requested {requested} terms, maximum is {maximum}"
            ),
            Self::PartitionTermCountMismatch {
                nogood_terms,
                partition_terms,
            } => write!(
                output,
                "action nogood has {nogood_terms} terms but partition has {partition_terms}"
            ),
            Self::SemanticTermCountMismatch {
                nogood_terms,
                semantic_terms,
            } => write!(
                output,
                "action nogood has {nogood_terms} terms but semantic arena has {semantic_terms}"
            ),
            Self::SemanticArgumentOutOfRange {
                term,
                argument,
                term_count,
            } => write!(
                output,
                "semantic term {term} has argument {argument} outside 0..{term_count}"
            ),
            Self::InconsistentFunctionSignature { function } => write!(
                output,
                "semantic function {function} has inconsistent typed signatures"
            ),
            Self::IllSortedCertificateRelation { relation } => write!(
                output,
                "certificate relates differently sorted terms {} and {}",
                relation.left, relation.right
            ),
            Self::CapExceeded(limit) => limit.fmt(output),
            Self::ArithmeticOverflow { resource } => {
                write!(output, "arithmetic overflow while counting {resource}")
            }
            Self::NogoodIdSpaceExhausted { index, maximum } => write!(
                output,
                "action nogood index {index} exceeds the {maximum}-entry ID space"
            ),
            Self::AllocationFailed { context, requested } => write!(
                output,
                "allocation failed for {context} while requesting {requested} entries"
            ),
            Self::Partition(error) => error.fmt(output),
            Self::InvariantViolation(message) => {
                write!(output, "action-nogood invariant violation: {message}")
            }
        }
    }
}

impl Error for ActionNogoodError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Partition(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PartitionError> for ActionNogoodError {
    fn from(error: PartitionError) -> Self {
        Self::Partition(error)
    }
}

/// Stable append-only identifier for a stored nogood.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ActionNogoodId(u32);

impl ActionNogoodId {
    pub(crate) const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub(crate) const fn raw(self) -> u32 {
        self.0
    }

    pub(crate) const fn index(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for ActionNogoodId {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(output)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ActionNogoodArenaCaps {
    pub(crate) max_nogoods: usize,
    pub(crate) max_total_actions: usize,
    pub(crate) max_total_relations: usize,
    pub(crate) max_total_frontier_anchors: usize,
    pub(crate) max_total_certificate_evidence: usize,
}

impl ActionNogoodArenaCaps {
    pub(crate) const fn unlimited() -> Self {
        Self {
            max_nogoods: usize::MAX,
            max_total_actions: usize::MAX,
            max_total_relations: usize::MAX,
            max_total_frontier_anchors: usize::MAX,
            max_total_certificate_evidence: usize::MAX,
        }
    }
}

impl Default for ActionNogoodArenaCaps {
    fn default() -> Self {
        Self {
            max_nogoods: 1_000_000,
            max_total_actions: 4_000_000,
            max_total_relations: 8_000_000,
            max_total_frontier_anchors: 32_000_000,
            max_total_certificate_evidence: 32_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ActionNogoodArenaTelemetry {
    pub(crate) nogoods: usize,
    pub(crate) actions: usize,
    pub(crate) relations: usize,
    pub(crate) frontier_anchors: usize,
    pub(crate) certificate_evidence: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActionNogoodInsert {
    Stored(ActionNogoodId),
    Existing(ActionNogoodId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArenaAllocationSite {
    NogoodTable,
    CanonicalIndex,
}

impl ArenaAllocationSite {
    const fn context(self) -> &'static str {
        match self {
            Self::NogoodTable => "action-nogood table",
            Self::CanonicalIndex => "action-nogood canonical index",
        }
    }
}

/// Append-only, content-deduplicating storage for canonical nogoods.
#[derive(Debug)]
pub(crate) struct ActionNogoodArena {
    term_count: usize,
    caps: ActionNogoodArenaCaps,
    nogoods: Vec<ActionNogood>,
    canonical_order: Vec<ActionNogoodId>,
    telemetry: ActionNogoodArenaTelemetry,
    #[cfg(test)]
    fail_allocation_at: Option<ArenaAllocationSite>,
}

impl ActionNogoodArena {
    pub(crate) fn new(term_count: usize, caps: ActionNogoodArenaCaps) -> Self {
        Self {
            term_count,
            caps,
            nogoods: Vec::new(),
            canonical_order: Vec::new(),
            telemetry: ActionNogoodArenaTelemetry::default(),
            #[cfg(test)]
            fail_allocation_at: None,
        }
    }

    pub(crate) const fn term_count(&self) -> usize {
        self.term_count
    }

    pub(crate) const fn caps(&self) -> ActionNogoodArenaCaps {
        self.caps
    }

    pub(crate) fn len(&self) -> usize {
        self.nogoods.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.nogoods.is_empty()
    }

    pub(crate) fn get(&self, id: ActionNogoodId) -> Option<&ActionNogood> {
        self.nogoods.get(id.index())
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (ActionNogoodId, &ActionNogood)> {
        self.nogoods
            .iter()
            .enumerate()
            .map(|(index, nogood)| (ActionNogoodId::new(index as u32), nogood))
    }

    pub(crate) const fn telemetry(&self) -> ActionNogoodArenaTelemetry {
        self.telemetry
    }

    /// Insert one already-canonical object. All counters and logical vectors
    /// remain unchanged on every error, including injected allocation failure.
    pub(crate) fn insert(
        &mut self,
        nogood: ActionNogood,
    ) -> Result<ActionNogoodInsert, ActionNogoodError> {
        if nogood.term_count != self.term_count {
            return Err(ActionNogoodError::PartitionTermCountMismatch {
                nogood_terms: nogood.term_count,
                partition_terms: self.term_count,
            });
        }
        let insertion_index = match self
            .canonical_order
            .binary_search_by(|id| self.nogoods[id.index()].cmp(&nogood))
        {
            Ok(index) => return Ok(ActionNogoodInsert::Existing(self.canonical_order[index])),
            Err(index) => index,
        };

        let id = action_nogood_id(self.nogoods.len())?;
        let action_count = nogood.forbidden.actions.len();
        let relation_count = nogood.forbidden.relations.len();
        let frontier_count = count_frontier_anchors(&nogood.forbidden.actions)?;
        let evidence_count = nogood.certificate.evidence.len();
        let next = ActionNogoodArenaTelemetry {
            nogoods: checked_add(
                self.telemetry.nogoods,
                1,
                ActionNogoodResource::StoredNogoods,
            )?,
            actions: checked_add(
                self.telemetry.actions,
                action_count,
                ActionNogoodResource::StoredActions,
            )?,
            relations: checked_add(
                self.telemetry.relations,
                relation_count,
                ActionNogoodResource::StoredRelations,
            )?,
            frontier_anchors: checked_add(
                self.telemetry.frontier_anchors,
                frontier_count,
                ActionNogoodResource::StoredFrontierAnchors,
            )?,
            certificate_evidence: checked_add(
                self.telemetry.certificate_evidence,
                evidence_count,
                ActionNogoodResource::StoredCertificateEvidence,
            )?,
        };
        for (resource, attempted, limit) in [
            (
                ActionNogoodResource::StoredNogoods,
                next.nogoods,
                self.caps.max_nogoods,
            ),
            (
                ActionNogoodResource::StoredActions,
                next.actions,
                self.caps.max_total_actions,
            ),
            (
                ActionNogoodResource::StoredRelations,
                next.relations,
                self.caps.max_total_relations,
            ),
            (
                ActionNogoodResource::StoredFrontierAnchors,
                next.frontier_anchors,
                self.caps.max_total_frontier_anchors,
            ),
            (
                ActionNogoodResource::StoredCertificateEvidence,
                next.certificate_evidence,
                self.caps.max_total_certificate_evidence,
            ),
        ] {
            check_cap(resource, attempted, limit)?;
        }

        self.reserve(ArenaAllocationSite::NogoodTable, 1, next.nogoods)?;
        self.reserve(ArenaAllocationSite::CanonicalIndex, 1, next.nogoods)?;
        self.nogoods.push(nogood);
        self.canonical_order.insert(insertion_index, id);
        self.telemetry = next;
        Ok(ActionNogoodInsert::Stored(id))
    }

    fn reserve(
        &mut self,
        site: ArenaAllocationSite,
        additional: usize,
        requested: usize,
    ) -> Result<(), ActionNogoodError> {
        #[cfg(test)]
        if self.fail_allocation_at == Some(site) {
            self.fail_allocation_at = None;
            return Err(ActionNogoodError::AllocationFailed {
                context: site.context(),
                requested,
            });
        }
        let result = match site {
            ArenaAllocationSite::NogoodTable => self.nogoods.try_reserve(additional),
            ArenaAllocationSite::CanonicalIndex => self.canonical_order.try_reserve(additional),
        };
        result.map_err(|_| ActionNogoodError::AllocationFailed {
            context: site.context(),
            requested,
        })
    }

    #[cfg(test)]
    fn fail_next_allocation_at(&mut self, site: ArenaAllocationSite) {
        self.fail_allocation_at = Some(site);
    }

    #[cfg(test)]
    fn invariants_hold(&self) -> bool {
        if self.nogoods.len() != self.canonical_order.len()
            || self.telemetry.nogoods != self.nogoods.len()
            || self.telemetry.nogoods > self.caps.max_nogoods
            || self.telemetry.actions > self.caps.max_total_actions
            || self.telemetry.relations > self.caps.max_total_relations
            || self.telemetry.frontier_anchors > self.caps.max_total_frontier_anchors
            || self.telemetry.certificate_evidence > self.caps.max_total_certificate_evidence
        {
            return false;
        }
        if self
            .canonical_order
            .iter()
            .any(|id| id.index() >= self.nogoods.len())
            || !self
                .canonical_order
                .windows(2)
                .all(|pair| self.nogoods[pair[0].index()] < self.nogoods[pair[1].index()])
        {
            return false;
        }
        let mut observed = ActionNogoodArenaTelemetry {
            nogoods: self.nogoods.len(),
            ..ActionNogoodArenaTelemetry::default()
        };
        for nogood in &self.nogoods {
            if nogood.term_count != self.term_count {
                return false;
            }
            let Some(actions) = observed.actions.checked_add(nogood.forbidden.actions.len()) else {
                return false;
            };
            let Some(relations) = observed
                .relations
                .checked_add(nogood.forbidden.relations.len())
            else {
                return false;
            };
            let Ok(frontiers) = count_frontier_anchors(&nogood.forbidden.actions) else {
                return false;
            };
            let Some(frontier_anchors) = observed.frontier_anchors.checked_add(frontiers) else {
                return false;
            };
            let Some(certificate_evidence) = observed
                .certificate_evidence
                .checked_add(nogood.certificate.evidence.len())
            else {
                return false;
            };
            observed.actions = actions;
            observed.relations = relations;
            observed.frontier_anchors = frontier_anchors;
            observed.certificate_evidence = certificate_evidence;
        }
        observed == self.telemetry
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConditionTruth {
    True,
    False,
    Unknown,
}

#[derive(Clone, Copy, Debug)]
struct QueryBudget {
    used: usize,
    limit: usize,
}

impl QueryBudget {
    const fn new(limit: usize) -> Self {
        Self { used: 0, limit }
    }

    fn charge(&mut self) -> Result<Option<ActionNogoodLimit>, ActionNogoodError> {
        let attempted = checked_add(self.used, 1, ActionNogoodResource::MatchRelationQueries)?;
        if attempted > self.limit {
            Ok(Some(ActionNogoodLimit {
                resource: ActionNogoodResource::MatchRelationQueries,
                attempted,
                limit: self.limit,
            }))
        } else {
            self.used = attempted;
            Ok(None)
        }
    }
}

fn match_action(
    action: &FrozenAction,
    partition: &Partition,
    budget: &mut QueryBudget,
) -> Result<ConditionTruth, ActionNogoodError> {
    match action.value {
        ActionValue::Existing(target) => {
            if let Some(limit) = budget.charge()? {
                return Err(ActionNogoodError::CapExceeded(limit));
            }
            relation_truth(
                partition.relation(action.domain.pivot, target)?,
                RequiredRelation::Equal,
            )
        }
        ActionValue::Fresh => {
            let mut saw_unknown = false;
            for &anchor in &action.domain.frontier {
                if let Some(limit) = budget.charge()? {
                    return Err(ActionNogoodError::CapExceeded(limit));
                }
                match partition.relation(action.domain.pivot, anchor)? {
                    Relation::Equal => return Ok(ConditionTruth::False),
                    Relation::Disequal => {}
                    Relation::Unknown => saw_unknown = true,
                }
            }
            Ok(if saw_unknown {
                ConditionTruth::Unknown
            } else {
                ConditionTruth::True
            })
        }
    }
}

fn assumed_relation_truth(
    action: &FrozenAction,
    condition: RelationCondition,
) -> Option<ConditionTruth> {
    let required = condition.required;
    let candidate_relation = match action.value {
        ActionValue::Existing(target)
            if RelationCondition::equal(action.domain.pivot, target).left == condition.left
                && RelationCondition::equal(action.domain.pivot, target).right
                    == condition.right =>
        {
            Relation::Equal
        }
        ActionValue::Fresh
            if action.domain.frontier.iter().any(|&anchor| {
                let relation = RelationCondition::disequal(action.domain.pivot, anchor);
                relation.left == condition.left && relation.right == condition.right
            }) =>
        {
            Relation::Disequal
        }
        _ => return None,
    };
    relation_truth(candidate_relation, required).ok()
}

fn match_relation(
    condition: RelationCondition,
    partition: &Partition,
    budget: &mut QueryBudget,
) -> Result<ConditionTruth, ActionNogoodError> {
    if let Some(limit) = budget.charge()? {
        return Err(ActionNogoodError::CapExceeded(limit));
    }
    relation_truth(
        partition.relation(condition.left, condition.right)?,
        condition.required,
    )
}

fn relation_truth(
    relation: Relation,
    required: RequiredRelation,
) -> Result<ConditionTruth, ActionNogoodError> {
    Ok(match (relation, required) {
        (Relation::Equal, RequiredRelation::Equal)
        | (Relation::Disequal, RequiredRelation::Disequal) => ConditionTruth::True,
        (Relation::Equal, RequiredRelation::Disequal)
        | (Relation::Disequal, RequiredRelation::Equal) => ConditionTruth::False,
        (Relation::Unknown, _) => ConditionTruth::Unknown,
    })
}

fn validate_term_universe(
    term_count: usize,
    caps: ActionNogoodCaps,
) -> Result<(), ActionNogoodError> {
    let represented = u64::try_from(term_count).map_err(|_| ActionNogoodError::TooManyTerms {
        requested: term_count,
        maximum: MAX_TERMS,
    })?;
    if represented > MAX_TERMS {
        return Err(ActionNogoodError::TooManyTerms {
            requested: term_count,
            maximum: MAX_TERMS,
        });
    }
    check_cap(ActionNogoodResource::Terms, term_count, caps.max_terms)
}

fn validate_semantic_terms(terms: &[SemanticTerm]) -> Result<(), ActionNogoodError> {
    let mut signatures: BTreeMap<u32, (u32, Box<[u32]>)> = BTreeMap::new();
    for (index, term) in terms.iter().enumerate() {
        let term_id = TermId::new(index as u32);
        let mut argument_sorts = Vec::new();
        argument_sorts
            .try_reserve_exact(term.arguments.len())
            .map_err(|_| ActionNogoodError::AllocationFailed {
                context: "semantic function signature",
                requested: term.arguments.len(),
            })?;
        for &argument in &term.arguments {
            let Some(argument_term) = terms.get(argument.index()) else {
                return Err(ActionNogoodError::SemanticArgumentOutOfRange {
                    term: term_id,
                    argument,
                    term_count: terms.len(),
                });
            };
            argument_sorts.push(argument_term.sort);
        }
        let signature = (term.sort, argument_sorts.into_boxed_slice());
        if let Some(prior) = signatures.get(&term.function) {
            if prior != &signature {
                return Err(ActionNogoodError::InconsistentFunctionSignature {
                    function: term.function,
                });
            }
        } else {
            signatures.insert(term.function, signature);
        }
    }
    Ok(())
}

fn validate_action(
    action: &FrozenAction,
    term_count: usize,
    caps: ActionNogoodCaps,
) -> Result<(), ActionNogoodError> {
    let domain = &action.domain;
    validate_term(domain.pivot, term_count, "action pivot")?;
    check_cap(
        ActionNogoodResource::FrontierAnchorsPerDomain,
        domain.frontier.len(),
        caps.max_frontier_anchors_per_domain,
    )?;
    if domain.frontier.binary_search(&domain.pivot).is_ok()
        || !domain.frontier.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(ActionNogoodError::Malformed(
            MalformedActionNogood::NonCanonicalActionDomain,
        ));
    }
    for &anchor in &domain.frontier {
        validate_term(anchor, term_count, "action frontier")?;
    }
    if let ActionValue::Existing(target) = action.value {
        validate_term(target, term_count, "existing action target")?;
        if !domain.contains_anchor(target) {
            return Err(ActionNogoodError::Malformed(
                MalformedActionNogood::ExistingTargetOutsideFrontier {
                    pivot: domain.pivot,
                    target,
                },
            ));
        }
    }
    Ok(())
}

fn validate_evidence_action_terms(
    evidence: &CertificateEvidence,
    term_count: usize,
    caps: ActionNogoodCaps,
) -> Result<(), ActionNogoodError> {
    match &evidence.origin {
        EvidenceOrigin::ForbiddenRelation | EvidenceOrigin::External(_) => Ok(()),
        EvidenceOrigin::ExistingAction(action) => validate_action(action, term_count, caps),
        EvidenceOrigin::FreshAction { action, anchor } => {
            validate_action(action, term_count, caps)?;
            validate_term(*anchor, term_count, "fresh certificate anchor")
        }
    }
}

fn validate_relation_terms(
    relation: RelationCondition,
    term_count: usize,
    context: &'static str,
) -> Result<(), ActionNogoodError> {
    validate_term(relation.left, term_count, context)?;
    validate_term(relation.right, term_count, context)
}

fn validate_term(
    term: TermId,
    term_count: usize,
    context: &'static str,
) -> Result<(), ActionNogoodError> {
    if term.index() >= term_count {
        Err(ActionNogoodError::TermOutOfRange {
            context,
            term,
            term_count,
        })
    } else {
        Ok(())
    }
}

fn validate_certificate_origins(
    forbidden: &ForbiddenConjunction,
    certificate: &ActionNogoodCertificate,
) -> Result<(), ActionNogoodError> {
    for evidence in &certificate.evidence {
        match &evidence.origin {
            EvidenceOrigin::ForbiddenRelation => {
                if forbidden
                    .relations
                    .binary_search(&evidence.relation)
                    .is_err()
                {
                    return Err(ActionNogoodError::Malformed(
                        MalformedActionNogood::ForbiddenRelationOriginMissing {
                            relation: evidence.relation,
                        },
                    ));
                }
            }
            EvidenceOrigin::ExistingAction(action) => {
                if forbidden.actions.binary_search(action).is_err() {
                    return Err(ActionNogoodError::Malformed(
                        MalformedActionNogood::ForbiddenActionOriginMissing,
                    ));
                }
                let ActionValue::Existing(target) = action.value else {
                    return Err(ActionNogoodError::Malformed(
                        MalformedActionNogood::ExistingEvidenceNamesFreshAction,
                    ));
                };
                if evidence.relation != RelationCondition::equal(action.domain.pivot, target) {
                    return Err(ActionNogoodError::Malformed(
                        MalformedActionNogood::EvidenceRelationMismatch {
                            relation: evidence.relation,
                        },
                    ));
                }
            }
            EvidenceOrigin::FreshAction { action, anchor } => {
                if forbidden.actions.binary_search(action).is_err() {
                    return Err(ActionNogoodError::Malformed(
                        MalformedActionNogood::ForbiddenActionOriginMissing,
                    ));
                }
                if !matches!(action.value, ActionValue::Fresh) {
                    return Err(ActionNogoodError::Malformed(
                        MalformedActionNogood::FreshEvidenceNamesExistingAction,
                    ));
                }
                if !action.domain.contains_anchor(*anchor) {
                    return Err(ActionNogoodError::Malformed(
                        MalformedActionNogood::FreshEvidenceAnchorOutsideFrontier {
                            pivot: action.domain.pivot,
                            anchor: *anchor,
                        },
                    ));
                }
                if evidence.relation != RelationCondition::disequal(action.domain.pivot, *anchor) {
                    return Err(ActionNogoodError::Malformed(
                        MalformedActionNogood::EvidenceRelationMismatch {
                            relation: evidence.relation,
                        },
                    ));
                }
            }
            EvidenceOrigin::External(_) => {}
        }
    }
    Ok(())
}

fn count_frontier_anchors(actions: &[FrozenAction]) -> Result<usize, ActionNogoodError> {
    let mut total = 0usize;
    for action in actions {
        total = checked_add(
            total,
            action.domain.frontier.len(),
            ActionNogoodResource::TotalFrontierAnchors,
        )?;
    }
    Ok(total)
}

fn count_expanded_relations(
    actions: &[FrozenAction],
    relations: &[RelationCondition],
) -> Result<usize, ActionNogoodError> {
    let mut total = relations.len();
    for action in actions {
        let additional = match action.value {
            ActionValue::Existing(_) => 1,
            ActionValue::Fresh => action.domain.frontier.len(),
        };
        total = checked_add(total, additional, ActionNogoodResource::ExpandedRelations)?;
    }
    Ok(total)
}

fn detect_forbidden_contradiction(
    term_count: usize,
    forbidden: &ForbiddenConjunction,
) -> Result<Option<ForbiddenContradiction>, ActionNogoodError> {
    let mut closure = StableEqualityClosure::new(term_count)?;
    for relation in &forbidden.relations {
        if matches!(relation.required, RequiredRelation::Equal) {
            closure.union(relation.left, relation.right)?;
        }
    }
    for action in &forbidden.actions {
        if let ActionValue::Existing(target) = action.value {
            closure.union(action.domain.pivot, target)?;
        }
    }

    for relation in &forbidden.relations {
        if matches!(relation.required, RequiredRelation::Disequal)
            && closure.same(relation.left, relation.right)?
        {
            return Ok(Some(ForbiddenContradiction::EqualityDisequalityConflict {
                left: relation.left,
                right: relation.right,
            }));
        }
    }
    for action in &forbidden.actions {
        if matches!(action.value, ActionValue::Fresh) {
            for &anchor in &action.domain.frontier {
                if closure.same(action.domain.pivot, anchor)? {
                    return Ok(Some(ForbiddenContradiction::EqualityDisequalityConflict {
                        left: action.domain.pivot,
                        right: anchor,
                    }));
                }
            }
        }
    }
    Ok(None)
}

/// A tiny stable-term equality closure used only for static contradiction and
/// certificate replay. It has no path compression and exports no root value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ReplaySignature {
    function: u32,
    sort: u32,
    arguments: Box<[usize]>,
}

#[derive(Debug)]
struct StableEqualityClosure {
    parent: Vec<usize>,
    size: Vec<usize>,
}

impl StableEqualityClosure {
    fn new(term_count: usize) -> Result<Self, ActionNogoodError> {
        let mut parent = Vec::new();
        parent
            .try_reserve_exact(term_count)
            .map_err(|_| ActionNogoodError::AllocationFailed {
                context: "certificate equality parents",
                requested: term_count,
            })?;
        let mut size = Vec::new();
        size.try_reserve_exact(term_count)
            .map_err(|_| ActionNogoodError::AllocationFailed {
                context: "certificate equality sizes",
                requested: term_count,
            })?;
        for index in 0..term_count {
            parent.push(index);
            size.push(1usize);
        }
        Ok(Self { parent, size })
    }

    fn root(&self, term: TermId) -> Result<usize, ActionNogoodError> {
        let mut current = term.index();
        if current >= self.parent.len() {
            return Err(ActionNogoodError::TermOutOfRange {
                context: "equality closure",
                term,
                term_count: self.parent.len(),
            });
        }
        let mut steps = 0usize;
        loop {
            let parent = *self
                .parent
                .get(current)
                .ok_or(ActionNogoodError::InvariantViolation(
                    "equality closure parent is out of range",
                ))?;
            if parent == current {
                return Ok(current);
            }
            current = parent;
            steps = steps
                .checked_add(1)
                .ok_or(ActionNogoodError::ArithmeticOverflow {
                    resource: ActionNogoodResource::ExpandedRelations,
                })?;
            if steps > self.parent.len() {
                return Err(ActionNogoodError::InvariantViolation(
                    "equality closure contains a parent cycle",
                ));
            }
        }
    }

    fn find(&self, term: TermId) -> Result<usize, ActionNogoodError> {
        self.root(term)
    }

    fn union(&mut self, left: TermId, right: TermId) -> Result<bool, ActionNogoodError> {
        let mut left_root = self.root(left)?;
        let mut right_root = self.root(right)?;
        if left_root == right_root {
            return Ok(false);
        }
        let left_size = *self
            .size
            .get(left_root)
            .ok_or(ActionNogoodError::InvariantViolation(
                "equality closure size is out of range",
            ))?;
        let right_size =
            *self
                .size
                .get(right_root)
                .ok_or(ActionNogoodError::InvariantViolation(
                    "equality closure size is out of range",
                ))?;
        if (left_size, std::cmp::Reverse(left_root)) < (right_size, std::cmp::Reverse(right_root)) {
            std::mem::swap(&mut left_root, &mut right_root);
        }
        let combined =
            left_size
                .checked_add(right_size)
                .ok_or(ActionNogoodError::ArithmeticOverflow {
                    resource: ActionNogoodResource::Terms,
                })?;
        self.parent[right_root] = left_root;
        self.size[left_root] = combined;
        Ok(true)
    }

    fn same(&self, left: TermId, right: TermId) -> Result<bool, ActionNogoodError> {
        Ok(self.root(left)? == self.root(right)?)
    }
}

fn ordered_pair(left: TermId, right: TermId) -> (TermId, TermId) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

fn checked_add(
    current: usize,
    additional: usize,
    resource: ActionNogoodResource,
) -> Result<usize, ActionNogoodError> {
    current
        .checked_add(additional)
        .ok_or(ActionNogoodError::ArithmeticOverflow { resource })
}

fn check_cap(
    resource: ActionNogoodResource,
    attempted: usize,
    limit: usize,
) -> Result<(), ActionNogoodError> {
    if attempted > limit {
        Err(ActionNogoodError::CapExceeded(ActionNogoodLimit {
            resource,
            attempted,
            limit,
        }))
    } else {
        Ok(())
    }
}

fn try_copy_slice<T: Copy>(
    values: &[T],
    context: &'static str,
) -> Result<Vec<T>, ActionNogoodError> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(values.len())
        .map_err(|_| ActionNogoodError::AllocationFailed {
            context,
            requested: values.len(),
        })?;
    copied.extend_from_slice(values);
    Ok(copied)
}

fn action_nogood_id(index: usize) -> Result<ActionNogoodId, ActionNogoodError> {
    u32::try_from(index).map(ActionNogoodId::new).map_err(|_| {
        ActionNogoodError::NogoodIdSpaceExhausted {
            index,
            maximum: MAX_NOGOOD_IDS,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::super::partition::{ReasonId, Snapshot};
    use super::*;
    use std::collections::BTreeSet;

    fn t(raw: u32) -> TermId {
        TermId::new(raw)
    }

    fn domain(pivot: u32, frontier: &[u32]) -> ActionDomainKey {
        let terms = frontier.iter().copied().map(t).collect::<Vec<_>>();
        ActionDomainKey::new(t(pivot), &terms, ActionNogoodCaps::unlimited()).unwrap()
    }

    fn existing(pivot: u32, frontier: &[u32], target: u32) -> FrozenAction {
        FrozenAction::new(domain(pivot, frontier), ActionValue::Existing(t(target))).unwrap()
    }

    fn fresh(pivot: u32, frontier: &[u32]) -> FrozenAction {
        FrozenAction::new(domain(pivot, frontier), ActionValue::Fresh).unwrap()
    }

    fn external_conflict(first: u32, second: u32) -> Vec<CertificateEvidence> {
        vec![
            CertificateEvidence::external(
                RelationCondition::equal(t(first), t(second)),
                EvidenceToken::new(10),
            ),
            CertificateEvidence::external(
                RelationCondition::disequal(t(first), t(second)),
                EvidenceToken::new(11),
            ),
        ]
    }

    fn built(
        term_count: usize,
        actions: Vec<FrozenAction>,
        relations: Vec<RelationCondition>,
        evidence: Vec<CertificateEvidence>,
    ) -> ActionNogood {
        match ActionNogood::build(
            term_count,
            actions,
            relations,
            evidence,
            ActionNogoodCaps::unlimited(),
        )
        .unwrap()
        {
            ActionNogoodBuild::Built(nogood) => nogood,
            other => panic!("expected ordinary nogood, got {other:?}"),
        }
    }

    fn single_action_nogood(term_count: usize, action: FrozenAction) -> ActionNogood {
        built(
            term_count,
            vec![action],
            Vec::new(),
            external_conflict(0, 1),
        )
    }

    fn single_relation_nogood(term_count: usize, relation: RelationCondition) -> ActionNogood {
        built(
            term_count,
            Vec::new(),
            vec![relation],
            external_conflict(0, 1),
        )
    }

    fn match_kind(result: ActionNogoodMatch) -> ConditionTruth {
        match result {
            ActionNogoodMatch::Matched { .. } => ConditionTruth::True,
            ActionNogoodMatch::Refuted { .. } => ConditionTruth::False,
            ActionNogoodMatch::Undetermined { .. } => ConditionTruth::Unknown,
            ActionNogoodMatch::Abstained(limit) => panic!("unexpected abstention: {limit:?}"),
        }
    }

    #[test]
    fn domain_keys_sort_deduplicate_and_retain_stable_anchors() {
        let input = [t(4), t(1), t(3), t(1), t(0), t(4)];
        let key = ActionDomainKey::new(t(5), &input, ActionNogoodCaps::unlimited()).unwrap();
        assert_eq!(key.pivot(), t(5));
        assert_eq!(key.frontier(), &[t(0), t(1), t(3), t(4)]);
        assert_eq!(input, [t(4), t(1), t(3), t(1), t(0), t(4)]);

        let permutation = [t(3), t(4), t(0), t(1)];
        assert_eq!(
            key,
            ActionDomainKey::new(t(5), &permutation, ActionNogoodCaps::unlimited()).unwrap()
        );
        assert!(matches!(
            ActionDomainKey::new(t(2), &[t(0), t(2)], ActionNogoodCaps::unlimited()),
            Err(ActionNogoodError::Malformed(
                MalformedActionNogood::PivotInFrontier { pivot }
            )) if pivot == t(2)
        ));
    }

    #[test]
    fn action_values_are_finite_domain_values_not_boolean_literals() {
        let key = domain(4, &[0, 1, 3]);
        let action = FrozenAction::new(key.clone(), ActionValue::Existing(t(1))).unwrap();
        assert_eq!(action.domain(), &key);
        assert_eq!(action.value(), ActionValue::Existing(t(1)));
        assert_eq!(
            FrozenAction::new(key.clone(), ActionValue::Fresh)
                .unwrap()
                .value(),
            ActionValue::Fresh
        );
        assert!(matches!(
            FrozenAction::new(key, ActionValue::Existing(t(2))),
            Err(ActionNogoodError::Malformed(
                MalformedActionNogood::ExistingTargetOutsideFrontier { pivot, target }
            )) if pivot == t(4) && target == t(2)
        ));
    }

    #[test]
    fn relation_conditions_order_endpoints_and_classify_reflexivity() {
        let equality = RelationCondition::equal(t(4), t(1));
        assert_eq!(equality.left(), t(1));
        assert_eq!(equality.right(), t(4));
        assert_eq!(equality.required(), RequiredRelation::Equal);
        assert_eq!(
            equality.classification(),
            RelationConditionClass::Proper(equality)
        );

        let tautology = RelationCondition::equal(t(2), t(2));
        assert_eq!(
            tautology.classification(),
            RelationConditionClass::Tautology(tautology)
        );
        let contradiction = RelationCondition::disequal(t(2), t(2));
        assert_eq!(
            contradiction.classification(),
            RelationConditionClass::Contradiction(contradiction)
        );
    }

    #[test]
    fn build_is_canonical_and_deterministic_under_input_permutations() {
        let first_action = existing(4, &[0, 2, 1], 1);
        let second_action = fresh(5, &[3, 0]);
        let relation_a = RelationCondition::equal(t(1), t(3));
        let relation_b = RelationCondition::disequal(t(2), t(5));
        let evidence_a = CertificateEvidence::existing(first_action.clone()).unwrap();
        let evidence_b = CertificateEvidence::fresh(second_action.clone(), t(3)).unwrap();
        let external = CertificateEvidence::external(
            RelationCondition::disequal(t(1), t(4)),
            EvidenceToken::new(99),
        );

        let first = built(
            6,
            vec![
                second_action.clone(),
                first_action.clone(),
                second_action.clone(),
            ],
            vec![
                relation_b,
                RelationCondition::equal(t(0), t(0)),
                relation_a,
                relation_b,
            ],
            vec![
                external.clone(),
                evidence_b.clone(),
                evidence_a.clone(),
                evidence_b.clone(),
            ],
        );
        let second = built(
            6,
            vec![first_action, second_action],
            vec![relation_a, relation_b],
            vec![evidence_a, external, evidence_b],
        );
        assert_eq!(first, second);
        assert_eq!(first.forbidden.actions.len(), 2);
        assert_eq!(first.forbidden.relations, vec![relation_a, relation_b]);
        assert_eq!(first.certificate.evidence.len(), 3);
        assert!(
            first
                .forbidden
                .actions
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        assert!(
            first
                .certificate
                .evidence
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
    }

    #[test]
    fn malformed_inputs_are_rejected_before_storage() {
        let action = existing(3, &[0, 1], 0);
        assert!(matches!(
            ActionNogood::build(
                3,
                vec![action.clone()],
                Vec::new(),
                external_conflict(0, 1),
                ActionNogoodCaps::unlimited(),
            ),
            Err(ActionNogoodError::TermOutOfRange { context: "action pivot", term, term_count: 3 })
                if term == t(3)
        ));
        assert!(matches!(
            ActionNogood::build(
                4,
                vec![action.clone()],
                Vec::new(),
                Vec::new(),
                ActionNogoodCaps::unlimited(),
            ),
            Err(ActionNogoodError::Malformed(
                MalformedActionNogood::EmptyCertificate
            ))
        ));
        assert!(matches!(
            ActionNogood::build(
                4,
                vec![action.clone()],
                Vec::new(),
                vec![CertificateEvidence::external(
                    RelationCondition::equal(t(1), t(1)),
                    EvidenceToken::new(1),
                )],
                ActionNogoodCaps::unlimited(),
            ),
            Err(ActionNogoodError::Malformed(
                MalformedActionNogood::TautologicalCertificateRelation { .. }
            ))
        ));
        assert!(matches!(
            ActionNogood::build(
                4,
                vec![action.clone()],
                Vec::new(),
                vec![CertificateEvidence::external(
                    RelationCondition::disequal(t(1), t(1)),
                    EvidenceToken::new(1),
                )],
                ActionNogoodCaps::unlimited(),
            ),
            Err(ActionNogoodError::Malformed(
                MalformedActionNogood::ContradictoryCertificateRelation { .. }
            ))
        ));

        let absent_relation = RelationCondition::equal(t(1), t(2));
        assert!(matches!(
            ActionNogood::build(
                4,
                vec![action],
                Vec::new(),
                vec![CertificateEvidence::forbidden_relation(absent_relation)],
                ActionNogoodCaps::unlimited(),
            ),
            Err(ActionNogoodError::Malformed(
                MalformedActionNogood::ForbiddenRelationOriginMissing { relation }
            )) if relation == absent_relation
        ));
    }

    #[test]
    fn impossible_forbidden_conjunctions_are_explicit_tautologies() {
        let equality = RelationCondition::equal(t(0), t(2));
        let disequality = RelationCondition::disequal(t(0), t(2));
        let outcome = ActionNogood::build(
            4,
            Vec::new(),
            vec![disequality, equality],
            external_conflict(0, 1),
            ActionNogoodCaps::unlimited(),
        )
        .unwrap();
        assert!(matches!(
            outcome,
            ActionNogoodBuild::TautologicalConstraint {
                contradiction: ForbiddenContradiction::EqualityDisequalityConflict {
                    left,
                    right
                },
                ..
            } if left == t(0) && right == t(2)
        ));

        let transitive = ActionNogood::build(
            4,
            Vec::new(),
            vec![
                RelationCondition::equal(t(0), t(1)),
                RelationCondition::equal(t(1), t(2)),
                RelationCondition::disequal(t(0), t(2)),
            ],
            external_conflict(2, 3),
            ActionNogoodCaps::unlimited(),
        )
        .unwrap();
        assert!(matches!(
            transitive,
            ActionNogoodBuild::TautologicalConstraint { .. }
        ));

        let key = domain(3, &[0, 1]);
        let existing = FrozenAction::new(key.clone(), ActionValue::Existing(t(0))).unwrap();
        let fresh = FrozenAction::new(key, ActionValue::Fresh).unwrap();
        assert!(matches!(
            ActionNogood::build(
                4,
                vec![fresh, existing],
                Vec::new(),
                external_conflict(1, 2),
                ActionNogoodCaps::unlimited(),
            )
            .unwrap(),
            ActionNogoodBuild::TautologicalConstraint { .. }
        ));

        let reflexive = RelationCondition::disequal(t(1), t(1));
        assert!(matches!(
            ActionNogood::build(
                4,
                Vec::new(),
                vec![reflexive],
                external_conflict(2, 3),
                ActionNogoodCaps::unlimited(),
            )
            .unwrap(),
            ActionNogoodBuild::TautologicalConstraint {
                contradiction: ForbiddenContradiction::ReflexiveDisequality { relation },
                ..
            } if relation == reflexive
        ));
    }

    #[test]
    fn empty_or_only_tautological_forbidden_conjunction_is_explicitly_contradictory() {
        for relations in [
            Vec::new(),
            vec![
                RelationCondition::equal(t(0), t(0)),
                RelationCondition::equal(t(1), t(1)),
            ],
        ] {
            let outcome = ActionNogood::build(
                2,
                Vec::new(),
                relations,
                external_conflict(0, 1),
                ActionNogoodCaps::unlimited(),
            )
            .unwrap();
            let ActionNogoodBuild::ContradictoryConstraint(nogood) = outcome else {
                panic!("expected unconditional contradictory constraint");
            };
            assert!(nogood.forbidden.is_empty());
            assert_eq!(
                nogood
                    .match_partition(&Partition::new(2).unwrap(), ActionNogoodCaps::unlimited())
                    .unwrap(),
                ActionNogoodMatch::Matched {
                    relation_queries: 0
                }
            );
        }
    }

    #[test]
    fn existing_action_matching_is_three_valued_and_rollback_stable() {
        let nogood = single_action_nogood(4, existing(3, &[0, 1, 2], 1));
        let mut partition = Partition::new(4).unwrap();
        let root = partition.snapshot();
        assert_eq!(
            nogood
                .match_partition(&partition, ActionNogoodCaps::unlimited())
                .unwrap(),
            ActionNogoodMatch::Undetermined {
                relation_queries: 1
            }
        );

        partition.merge(t(3), t(1), ReasonId::new(1)).unwrap();
        assert_eq!(
            nogood
                .match_partition(&partition, ActionNogoodCaps::unlimited())
                .unwrap(),
            ActionNogoodMatch::Matched {
                relation_queries: 1
            }
        );
        partition.rollback(root).unwrap();
        assert!(matches!(
            nogood
                .match_partition(&partition, ActionNogoodCaps::unlimited())
                .unwrap(),
            ActionNogoodMatch::Undetermined { .. }
        ));

        partition.separate(t(3), t(1), ReasonId::new(2)).unwrap();
        assert_eq!(
            nogood
                .match_partition(&partition, ActionNogoodCaps::unlimited())
                .unwrap(),
            ActionNogoodMatch::Refuted {
                relation_queries: 1
            }
        );
        partition.rollback(root).unwrap();
        assert!(matches!(
            nogood
                .match_partition(&partition, ActionNogoodCaps::unlimited())
                .unwrap(),
            ActionNogoodMatch::Undetermined { .. }
        ));
    }

    #[test]
    fn fresh_action_means_disequal_from_every_frozen_anchor() {
        let nogood = single_action_nogood(4, fresh(3, &[0, 1, 2]));
        let mut partition = Partition::new(4).unwrap();
        let root = partition.snapshot();
        assert_eq!(
            nogood
                .match_partition(&partition, ActionNogoodCaps::unlimited())
                .unwrap(),
            ActionNogoodMatch::Undetermined {
                relation_queries: 3
            }
        );

        for (anchor, reason) in [(0, 1), (1, 2), (2, 3)] {
            partition
                .separate(t(3), t(anchor), ReasonId::new(reason))
                .unwrap();
        }
        assert_eq!(
            nogood
                .match_partition(&partition, ActionNogoodCaps::unlimited())
                .unwrap(),
            ActionNogoodMatch::Matched {
                relation_queries: 3
            }
        );
        partition.rollback(root).unwrap();

        partition.merge(t(3), t(1), ReasonId::new(4)).unwrap();
        assert_eq!(
            nogood
                .match_partition(&partition, ActionNogoodCaps::unlimited())
                .unwrap(),
            ActionNogoodMatch::Refuted {
                relation_queries: 2
            }
        );
        partition.rollback(root).unwrap();

        let empty_fresh = single_action_nogood(4, fresh(3, &[]));
        assert_eq!(
            empty_fresh
                .match_partition(&partition, ActionNogoodCaps::unlimited())
                .unwrap(),
            ActionNogoodMatch::Matched {
                relation_queries: 0
            }
        );
    }

    #[test]
    fn mixed_conjunction_short_circuits_in_canonical_order() {
        let action = existing(3, &[0, 1], 0);
        let nogood = built(
            4,
            vec![action],
            vec![RelationCondition::equal(t(1), t(2))],
            external_conflict(0, 1),
        );
        let mut partition = Partition::new(4).unwrap();
        partition.separate(t(3), t(0), ReasonId::new(1)).unwrap();
        assert_eq!(
            nogood
                .match_partition(&partition, ActionNogoodCaps::unlimited())
                .unwrap(),
            ActionNogoodMatch::Refuted {
                relation_queries: 1
            }
        );
    }

    #[test]
    fn matching_caps_abstain_without_mutating_the_partition() {
        let nogood = single_action_nogood(4, fresh(3, &[0, 1, 2]));
        let partition = Partition::new(4).unwrap();
        let before = partition.snapshot();
        let caps = ActionNogoodCaps {
            max_match_relation_queries: 1,
            ..ActionNogoodCaps::unlimited()
        };
        assert_eq!(
            nogood.match_partition(&partition, caps).unwrap(),
            ActionNogoodMatch::Abstained(ActionNogoodLimit {
                resource: ActionNogoodResource::MatchRelationQueries,
                attempted: 2,
                limit: 1,
            })
        );
        assert_eq!(partition.snapshot(), before);

        let wrong_partition = Partition::new(3).unwrap();
        assert!(matches!(
            nogood.match_partition(&wrong_partition, ActionNogoodCaps::unlimited()),
            Err(ActionNogoodError::PartitionTermCountMismatch {
                nogood_terms: 4,
                partition_terms: 3
            })
        ));
    }

    #[test]
    fn certificate_replay_checks_internal_origins_and_external_evidence() {
        let action = existing(3, &[0, 1], 0);
        let internal = CertificateEvidence::existing(action.clone()).unwrap();
        let external_relation = RelationCondition::disequal(t(3), t(0));
        let token = EvidenceToken::new(42);
        let nogood = built(
            4,
            vec![action],
            Vec::new(),
            vec![
                CertificateEvidence::external(external_relation, token),
                internal,
            ],
        );

        assert_eq!(
            nogood
                .replay_certificate_with(ActionNogoodCaps::unlimited(), |seen, relation| {
                    seen == token && relation == external_relation
                })
                .unwrap(),
            CertificateReplay::VerifiedConflict {
                relations_checked: 2,
                external_evidence: 1,
                witness: external_relation,
            }
        );
        assert!(matches!(
            nogood
                .replay_certificate_with(ActionNogoodCaps::unlimited(), |_, _| false)
                .unwrap(),
            CertificateReplay::ExternalEvidenceRejected {
                token: rejected,
                relation,
                ..
            } if rejected == token && relation == external_relation
        ));

        let caps = ActionNogoodCaps {
            max_replay_relations: 1,
            ..ActionNogoodCaps::unlimited()
        };
        assert_eq!(
            nogood.replay_certificate_with(caps, |_, _| true).unwrap(),
            CertificateReplay::Abstained(ActionNogoodLimit {
                resource: ActionNogoodResource::ReplayRelations,
                attempted: 2,
                limit: 1,
            })
        );
    }

    #[test]
    fn fresh_certificate_origin_derives_exactly_one_anchor_disequality() {
        let action = fresh(3, &[0, 1, 2]);
        let internal = CertificateEvidence::fresh(action.clone(), t(1)).unwrap();
        assert_eq!(internal.relation(), RelationCondition::disequal(t(3), t(1)));
        let opposite = RelationCondition::equal(t(3), t(1));
        let nogood = built(
            4,
            vec![action.clone()],
            Vec::new(),
            vec![
                internal,
                CertificateEvidence::external(opposite, EvidenceToken::new(8)),
            ],
        );
        assert!(matches!(
            nogood
                .replay_certificate_with(ActionNogoodCaps::unlimited(), |_, _| true)
                .unwrap(),
            CertificateReplay::VerifiedConflict { witness, .. }
                if witness == RelationCondition::disequal(t(3), t(1))
        ));
        assert!(matches!(
            CertificateEvidence::fresh(action, t(4)),
            Err(ActionNogoodError::Malformed(
                MalformedActionNogood::FreshEvidenceAnchorOutsideFrontier { .. }
            ))
        ));
    }

    #[test]
    fn replay_reports_no_conflict_for_insufficient_evidence() {
        let action = existing(3, &[0, 1], 0);
        let nogood = built(
            4,
            vec![action.clone()],
            Vec::new(),
            vec![
                CertificateEvidence::existing(action).unwrap(),
                CertificateEvidence::external(
                    RelationCondition::equal(t(1), t(2)),
                    EvidenceToken::new(5),
                ),
            ],
        );
        assert_eq!(
            nogood
                .replay_certificate_with(ActionNogoodCaps::unlimited(), |_, _| true)
                .unwrap(),
            CertificateReplay::NoConflict {
                relations_checked: 2,
                external_evidence: 1,
            }
        );
    }

    fn arena_snapshot(
        arena: &ActionNogoodArena,
    ) -> (
        usize,
        ActionNogoodArenaTelemetry,
        Vec<ActionNogood>,
        Vec<ActionNogoodId>,
    ) {
        (
            arena.len(),
            arena.telemetry(),
            arena.nogoods.clone(),
            arena.canonical_order.clone(),
        )
    }

    fn storage_nogood(target: u32) -> ActionNogood {
        built(
            5,
            vec![existing(4, &[0, 1, 2], target)],
            vec![RelationCondition::equal(t(2), t(3))],
            external_conflict(0, 1),
        )
    }

    #[test]
    fn arena_deduplicates_exact_content_with_stable_insertion_ids() {
        let mut arena = ActionNogoodArena::new(5, ActionNogoodArenaCaps::unlimited());
        let high = storage_nogood(2);
        let low = storage_nogood(0);
        let high_id = match arena.insert(high.clone()).unwrap() {
            ActionNogoodInsert::Stored(id) => id,
            other => panic!("unexpected insertion: {other:?}"),
        };
        let low_id = match arena.insert(low.clone()).unwrap() {
            ActionNogoodInsert::Stored(id) => id,
            other => panic!("unexpected insertion: {other:?}"),
        };
        assert_eq!(high_id.raw(), 0);
        assert_eq!(low_id.raw(), 1);
        assert_eq!(arena.get(high_id), Some(&high));
        assert_eq!(arena.get(low_id), Some(&low));
        let before = arena.telemetry();
        assert_eq!(
            arena.insert(low).unwrap(),
            ActionNogoodInsert::Existing(low_id)
        );
        assert_eq!(arena.telemetry(), before);
        assert!(arena.invariants_hold());
        assert_eq!(arena.canonical_order, vec![low_id, high_id]);
    }

    #[test]
    fn every_arena_cap_is_transactional() {
        let nogood = storage_nogood(0);
        for (resource, caps) in [
            (
                ActionNogoodResource::StoredNogoods,
                ActionNogoodArenaCaps {
                    max_nogoods: 0,
                    ..ActionNogoodArenaCaps::unlimited()
                },
            ),
            (
                ActionNogoodResource::StoredActions,
                ActionNogoodArenaCaps {
                    max_total_actions: 0,
                    ..ActionNogoodArenaCaps::unlimited()
                },
            ),
            (
                ActionNogoodResource::StoredRelations,
                ActionNogoodArenaCaps {
                    max_total_relations: 0,
                    ..ActionNogoodArenaCaps::unlimited()
                },
            ),
            (
                ActionNogoodResource::StoredFrontierAnchors,
                ActionNogoodArenaCaps {
                    max_total_frontier_anchors: 2,
                    ..ActionNogoodArenaCaps::unlimited()
                },
            ),
            (
                ActionNogoodResource::StoredCertificateEvidence,
                ActionNogoodArenaCaps {
                    max_total_certificate_evidence: 1,
                    ..ActionNogoodArenaCaps::unlimited()
                },
            ),
        ] {
            let mut arena = ActionNogoodArena::new(5, caps);
            let before = arena_snapshot(&arena);
            assert!(matches!(
                arena.insert(nogood.clone()),
                Err(ActionNogoodError::CapExceeded(ActionNogoodLimit {
                    resource: observed,
                    ..
                })) if observed == resource
            ));
            assert_eq!(arena_snapshot(&arena), before);
            assert!(arena.invariants_hold());
        }
    }

    #[test]
    fn every_arena_allocation_failure_is_logically_transactional_and_retryable() {
        for site in [
            ArenaAllocationSite::NogoodTable,
            ArenaAllocationSite::CanonicalIndex,
        ] {
            let mut arena = ActionNogoodArena::new(5, ActionNogoodArenaCaps::unlimited());
            let before = arena_snapshot(&arena);
            arena.fail_next_allocation_at(site);
            assert!(matches!(
                arena.insert(storage_nogood(0)),
                Err(ActionNogoodError::AllocationFailed { context, .. })
                    if context == site.context()
            ));
            assert_eq!(arena_snapshot(&arena), before);
            assert!(arena.invariants_hold());
            assert!(matches!(
                arena.insert(storage_nogood(0)).unwrap(),
                ActionNogoodInsert::Stored(ActionNogoodId(0))
            ));
            assert!(arena.invariants_hold());
        }
    }

    #[test]
    fn all_per_nogood_caps_are_hard_and_checked_before_commit() {
        let action = existing(4, &[0, 1, 2], 0);
        let relation = RelationCondition::equal(t(2), t(3));
        let evidence = external_conflict(0, 1);
        for (resource, caps) in [
            (
                ActionNogoodResource::Terms,
                ActionNogoodCaps {
                    max_terms: 4,
                    ..ActionNogoodCaps::unlimited()
                },
            ),
            (
                ActionNogoodResource::ActionsPerNogood,
                ActionNogoodCaps {
                    max_actions_per_nogood: 0,
                    ..ActionNogoodCaps::unlimited()
                },
            ),
            (
                ActionNogoodResource::RelationsPerNogood,
                ActionNogoodCaps {
                    max_relations_per_nogood: 0,
                    ..ActionNogoodCaps::unlimited()
                },
            ),
            (
                ActionNogoodResource::FrontierAnchorsPerDomain,
                ActionNogoodCaps {
                    max_frontier_anchors_per_domain: 2,
                    ..ActionNogoodCaps::unlimited()
                },
            ),
            (
                ActionNogoodResource::TotalFrontierAnchors,
                ActionNogoodCaps {
                    max_total_frontier_anchors: 2,
                    ..ActionNogoodCaps::unlimited()
                },
            ),
            (
                ActionNogoodResource::CertificateEvidence,
                ActionNogoodCaps {
                    max_certificate_evidence: 1,
                    ..ActionNogoodCaps::unlimited()
                },
            ),
            (
                ActionNogoodResource::ExpandedRelations,
                ActionNogoodCaps {
                    max_expanded_relations: 1,
                    ..ActionNogoodCaps::unlimited()
                },
            ),
        ] {
            let result = ActionNogood::build(
                5,
                vec![action.clone()],
                vec![relation],
                evidence.clone(),
                caps,
            );
            assert!(matches!(
                result,
                Err(ActionNogoodError::CapExceeded(ActionNogoodLimit {
                    resource: observed,
                    ..
                })) if observed == resource
            ));
        }

        let caps = ActionNogoodCaps {
            max_frontier_anchors_per_domain: 2,
            ..ActionNogoodCaps::unlimited()
        };
        assert!(matches!(
            ActionDomainKey::new(t(4), &[t(0), t(1), t(2)], caps),
            Err(ActionNogoodError::CapExceeded(ActionNogoodLimit {
                resource: ActionNogoodResource::FrontierAnchorsPerDomain,
                attempted: 3,
                limit: 2,
            }))
        ));
    }

    fn same_state_partition(reverse: bool) -> Partition {
        let mut partition = Partition::new(6).unwrap();
        let mut reason = 1u64;
        let merges = if reverse {
            vec![(t(0), t(3)), (t(0), t(5)), (t(1), t(4))]
        } else {
            vec![(t(5), t(3)), (t(3), t(0)), (t(4), t(1))]
        };
        for (left, right) in merges {
            partition.merge(left, right, ReasonId::new(reason)).unwrap();
            reason += 1;
        }
        let separations = if reverse {
            vec![(t(2), t(4)), (t(4), t(5))]
        } else {
            vec![(t(3), t(1)), (t(1), t(2))]
        };
        for (left, right) in separations {
            partition
                .separate(left, right, ReasonId::new(reason))
                .unwrap();
            reason += 1;
        }
        partition
    }

    #[test]
    fn stored_ids_and_matches_ignore_union_roots_and_merge_order() {
        let first = same_state_partition(false);
        let second = same_state_partition(true);
        assert_eq!(
            first.canonical_classes().unwrap(),
            second.canonical_classes().unwrap()
        );
        assert_eq!(
            first
                .canonical_disequalities()
                .unwrap()
                .into_iter()
                .map(|edge| (edge.left, edge.right))
                .collect::<Vec<_>>(),
            second
                .canonical_disequalities()
                .unwrap()
                .into_iter()
                .map(|edge| (edge.left, edge.right))
                .collect::<Vec<_>>()
        );

        let nogoods = [
            single_action_nogood(6, existing(5, &[1, 2, 3, 4], 3)),
            single_action_nogood(6, fresh(2, &[0, 1, 4, 5])),
            single_relation_nogood(6, RelationCondition::equal(t(5), t(0))),
            single_relation_nogood(6, RelationCondition::disequal(t(3), t(4))),
            single_relation_nogood(6, RelationCondition::disequal(t(2), t(1))),
        ];
        for nogood in nogoods {
            let frozen = nogood.clone();
            assert_eq!(
                nogood
                    .match_partition(&first, ActionNogoodCaps::unlimited())
                    .unwrap(),
                nogood
                    .match_partition(&second, ActionNogoodCaps::unlimited())
                    .unwrap()
            );
            assert_eq!(nogood, frozen);
        }
    }

    fn restricted_growth_partitions(term_count: usize) -> Vec<Vec<usize>> {
        fn extend(
            index: usize,
            term_count: usize,
            maximum: usize,
            current: &mut Vec<usize>,
            output: &mut Vec<Vec<usize>>,
        ) {
            if index == term_count {
                output.push(current.clone());
                return;
            }
            for class in 0..=maximum + 1 {
                current.push(class);
                extend(index + 1, term_count, maximum.max(class), current, output);
                current.pop();
            }
        }

        if term_count == 0 {
            return vec![Vec::new()];
        }
        let mut output = Vec::new();
        let mut current = vec![0];
        extend(1, term_count, 0, &mut current, &mut output);
        output
    }

    fn class_pairs(class_count: usize) -> Vec<(usize, usize)> {
        let mut pairs = Vec::new();
        for left in 0..class_count {
            for right in left + 1..class_count {
                pairs.push((left, right));
            }
        }
        pairs
    }

    fn oracle_relation(
        classes: &[usize],
        pairs: &[(usize, usize)],
        disequality_mask: usize,
        left: TermId,
        right: TermId,
    ) -> Relation {
        let left_class = classes[left.index()];
        let right_class = classes[right.index()];
        if left_class == right_class {
            return Relation::Equal;
        }
        let pair = if left_class < right_class {
            (left_class, right_class)
        } else {
            (right_class, left_class)
        };
        let index = pairs
            .iter()
            .position(|candidate| *candidate == pair)
            .unwrap();
        if disequality_mask & (1usize << index) != 0 {
            Relation::Disequal
        } else {
            Relation::Unknown
        }
    }

    fn partition_from_oracle(
        classes: &[usize],
        pairs: &[(usize, usize)],
        disequality_mask: usize,
        reverse: bool,
    ) -> Partition {
        let mut partition = Partition::new(classes.len()).unwrap();
        let class_count = classes.iter().copied().max().map_or(0, |value| value + 1);
        let mut reason = 1u64;
        for class in 0..class_count {
            let mut members = classes
                .iter()
                .enumerate()
                .filter_map(|(term, observed)| (*observed == class).then_some(t(term as u32)))
                .collect::<Vec<_>>();
            if reverse {
                members.reverse();
            }
            if let Some(&leader) = members.first() {
                for &member in &members[1..] {
                    partition
                        .merge(leader, member, ReasonId::new(reason))
                        .unwrap();
                    reason += 1;
                }
            }
        }
        let mut active_pairs = pairs
            .iter()
            .enumerate()
            .filter_map(|(index, pair)| {
                (disequality_mask & (1usize << index) != 0).then_some(*pair)
            })
            .collect::<Vec<_>>();
        if reverse {
            active_pairs.reverse();
        }
        for (left_class, right_class) in active_pairs {
            let left = classes
                .iter()
                .position(|class| *class == left_class)
                .unwrap();
            let right = classes
                .iter()
                .position(|class| *class == right_class)
                .unwrap();
            partition
                .separate(t(left as u32), t(right as u32), ReasonId::new(reason))
                .unwrap();
            reason += 1;
        }
        partition
    }

    fn oracle_action_truth(
        action: &FrozenAction,
        classes: &[usize],
        pairs: &[(usize, usize)],
        disequality_mask: usize,
    ) -> ConditionTruth {
        match action.value {
            ActionValue::Existing(target) => relation_truth(
                oracle_relation(
                    classes,
                    pairs,
                    disequality_mask,
                    action.domain.pivot,
                    target,
                ),
                RequiredRelation::Equal,
            )
            .unwrap(),
            ActionValue::Fresh => {
                let mut unknown = false;
                for &anchor in &action.domain.frontier {
                    match oracle_relation(
                        classes,
                        pairs,
                        disequality_mask,
                        action.domain.pivot,
                        anchor,
                    ) {
                        Relation::Equal => return ConditionTruth::False,
                        Relation::Disequal => {}
                        Relation::Unknown => unknown = true,
                    }
                }
                if unknown {
                    ConditionTruth::Unknown
                } else {
                    ConditionTruth::True
                }
            }
        }
    }

    fn oracle_nogood_truth(
        nogood: &ActionNogood,
        classes: &[usize],
        pairs: &[(usize, usize)],
        disequality_mask: usize,
    ) -> ConditionTruth {
        let mut unknown = false;
        for action in &nogood.forbidden.actions {
            match oracle_action_truth(action, classes, pairs, disequality_mask) {
                ConditionTruth::True => {}
                ConditionTruth::False => return ConditionTruth::False,
                ConditionTruth::Unknown => unknown = true,
            }
        }
        for condition in &nogood.forbidden.relations {
            match relation_truth(
                oracle_relation(
                    classes,
                    pairs,
                    disequality_mask,
                    condition.left,
                    condition.right,
                ),
                condition.required,
            )
            .unwrap()
            {
                ConditionTruth::True => {}
                ConditionTruth::False => return ConditionTruth::False,
                ConditionTruth::Unknown => unknown = true,
            }
        }
        if unknown {
            ConditionTruth::Unknown
        } else {
            ConditionTruth::True
        }
    }

    fn four_term_single_conjunct_nogoods() -> Vec<ActionNogood> {
        let mut nogoods = Vec::new();
        for pivot in 0..4u32 {
            let candidates = (0..4u32).filter(|term| *term != pivot).collect::<Vec<_>>();
            for mask in 0usize..(1usize << candidates.len()) {
                let frontier = candidates
                    .iter()
                    .enumerate()
                    .filter_map(|(index, term)| (mask & (1 << index) != 0).then_some(*term))
                    .collect::<Vec<_>>();
                nogoods.push(single_action_nogood(4, fresh(pivot, &frontier)));
                for &target in &frontier {
                    nogoods.push(single_action_nogood(4, existing(pivot, &frontier, target)));
                }
            }
        }
        for left in 0..4u32 {
            for right in left + 1..4u32 {
                nogoods.push(single_relation_nogood(
                    4,
                    RelationCondition::equal(t(left), t(right)),
                ));
                nogoods.push(single_relation_nogood(
                    4,
                    RelationCondition::disequal(t(left), t(right)),
                ));
            }
        }
        nogoods
    }

    #[test]
    fn exhaustive_four_term_states_match_independent_oracle_and_merge_orders() {
        let nogoods = four_term_single_conjunct_nogoods();
        let mut states = 0usize;
        let mut checks = 0usize;
        for classes in restricted_growth_partitions(4) {
            let class_count = classes.iter().copied().max().unwrap() + 1;
            let pairs = class_pairs(class_count);
            for disequality_mask in 0usize..(1usize << pairs.len()) {
                let first = partition_from_oracle(&classes, &pairs, disequality_mask, false);
                let second = partition_from_oracle(&classes, &pairs, disequality_mask, true);
                for nogood in &nogoods {
                    let expected = oracle_nogood_truth(nogood, &classes, &pairs, disequality_mask);
                    let first_result = nogood
                        .match_partition(&first, ActionNogoodCaps::unlimited())
                        .unwrap();
                    let second_result = nogood
                        .match_partition(&second, ActionNogoodCaps::unlimited())
                        .unwrap();
                    assert_eq!(match_kind(first_result), expected);
                    assert_eq!(first_result, second_result);
                    checks += 1;
                }
                states += 1;
            }
        }
        assert_eq!(restricted_growth_partitions(4).len(), 15);
        assert!(states > 100);
        assert!(checks > 10_000);
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ReferenceModel {
        class: Vec<usize>,
        disequalities: BTreeSet<(usize, usize)>,
    }

    impl ReferenceModel {
        fn new(term_count: usize) -> Self {
            Self {
                class: (0..term_count).collect(),
                disequalities: BTreeSet::new(),
            }
        }

        fn relation(&self, left: usize, right: usize) -> Relation {
            let left = self.class[left];
            let right = self.class[right];
            if left == right {
                Relation::Equal
            } else if self
                .disequalities
                .contains(&ordered_index_pair(left, right))
            {
                Relation::Disequal
            } else {
                Relation::Unknown
            }
        }

        fn merge(&mut self, left: usize, right: usize) -> bool {
            let left_class = self.class[left];
            let right_class = self.class[right];
            if left_class == right_class {
                return true;
            }
            if self
                .disequalities
                .contains(&ordered_index_pair(left_class, right_class))
            {
                return false;
            }
            let kept = left_class.min(right_class);
            let removed = left_class.max(right_class);
            for class in &mut self.class {
                if *class == removed {
                    *class = kept;
                }
            }
            self.disequalities = self
                .disequalities
                .iter()
                .map(|&(first, second)| {
                    let first = if first == removed { kept } else { first };
                    let second = if second == removed { kept } else { second };
                    ordered_index_pair(first, second)
                })
                .filter(|(first, second)| first != second)
                .collect();
            true
        }

        fn separate(&mut self, left: usize, right: usize) -> bool {
            let left = self.class[left];
            let right = self.class[right];
            if left == right {
                false
            } else {
                self.disequalities.insert(ordered_index_pair(left, right));
                true
            }
        }
    }

    fn ordered_index_pair(left: usize, right: usize) -> (usize, usize) {
        if left <= right {
            (left, right)
        } else {
            (right, left)
        }
    }

    fn model_match(nogood: &ActionNogood, model: &ReferenceModel) -> ConditionTruth {
        let mut unknown = false;
        for action in &nogood.forbidden.actions {
            let truth = match action.value {
                ActionValue::Existing(target) => relation_truth(
                    model.relation(action.domain.pivot.index(), target.index()),
                    RequiredRelation::Equal,
                )
                .unwrap(),
                ActionValue::Fresh => {
                    let mut action_unknown = false;
                    let mut truth = ConditionTruth::True;
                    for &anchor in &action.domain.frontier {
                        match model.relation(action.domain.pivot.index(), anchor.index()) {
                            Relation::Equal => {
                                truth = ConditionTruth::False;
                                break;
                            }
                            Relation::Disequal => {}
                            Relation::Unknown => action_unknown = true,
                        }
                    }
                    if truth == ConditionTruth::True && action_unknown {
                        ConditionTruth::Unknown
                    } else {
                        truth
                    }
                }
            };
            match truth {
                ConditionTruth::True => {}
                ConditionTruth::False => return ConditionTruth::False,
                ConditionTruth::Unknown => unknown = true,
            }
        }
        for relation in &nogood.forbidden.relations {
            match relation_truth(
                model.relation(relation.left.index(), relation.right.index()),
                relation.required,
            )
            .unwrap()
            {
                ConditionTruth::True => {}
                ConditionTruth::False => return ConditionTruth::False,
                ConditionTruth::Unknown => unknown = true,
            }
        }
        if unknown {
            ConditionTruth::Unknown
        } else {
            ConditionTruth::True
        }
    }

    #[derive(Clone, Copy)]
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }

        fn index(&mut self, bound: usize) -> usize {
            (self.next() as usize) % bound
        }
    }

    #[test]
    fn deterministic_random_updates_and_rollbacks_match_reference_model() {
        let term_count = 7usize;
        let nogoods = vec![
            single_action_nogood(term_count, existing(6, &[0, 1, 2, 3], 2)),
            single_action_nogood(term_count, fresh(5, &[0, 1, 3, 4])),
            single_relation_nogood(term_count, RelationCondition::equal(t(0), t(6))),
            single_relation_nogood(term_count, RelationCondition::disequal(t(2), t(4))),
            built(
                term_count,
                vec![existing(6, &[0, 1], 1)],
                vec![RelationCondition::disequal(t(3), t(5))],
                external_conflict(0, 2),
            ),
        ];
        let mut partition = Partition::new(term_count).unwrap();
        let mut model = ReferenceModel::new(term_count);
        let mut checkpoints: Vec<(Snapshot, ReferenceModel)> =
            vec![(partition.snapshot(), model.clone())];
        let mut random = Lcg(0x8f4d_6ab1_05c2_7719);
        let mut reason = 1u64;

        for _ in 0..2_000 {
            match random.index(5) {
                0 => checkpoints.push((partition.snapshot(), model.clone())),
                1 if checkpoints.len() > 1 => {
                    let selected = random.index(checkpoints.len());
                    let (snapshot, saved) = checkpoints[selected].clone();
                    partition.rollback(snapshot).unwrap();
                    model = saved;
                    checkpoints.truncate(selected + 1);
                }
                2 | 3 => {
                    let left = random.index(term_count);
                    let right = random.index(term_count);
                    let accepted = model.clone().merge(left, right);
                    let result =
                        partition.merge(t(left as u32), t(right as u32), ReasonId::new(reason));
                    reason += 1;
                    assert_eq!(result.is_ok(), accepted);
                    if accepted {
                        assert!(model.merge(left, right));
                    }
                }
                _ => {
                    let left = random.index(term_count);
                    let right = random.index(term_count);
                    let accepted = model.clone().separate(left, right);
                    let result =
                        partition.separate(t(left as u32), t(right as u32), ReasonId::new(reason));
                    reason += 1;
                    assert_eq!(result.is_ok(), accepted);
                    if accepted {
                        assert!(model.separate(left, right));
                    }
                }
            }
            for nogood in &nogoods {
                assert_eq!(
                    match_kind(
                        nogood
                            .match_partition(&partition, ActionNogoodCaps::unlimited())
                            .unwrap()
                    ),
                    model_match(nogood, &model)
                );
            }
        }
    }

    fn shuffle<T>(values: &mut [T], random: &mut Lcg) {
        for index in (1..values.len()).rev() {
            let other = random.index(index + 1);
            values.swap(index, other);
        }
    }

    #[test]
    fn deterministic_random_input_permutations_have_one_canonical_encoding() {
        let canonical_actions = vec![
            existing(5, &[0, 1, 2], 1),
            fresh(4, &[0, 2, 3]),
            existing(3, &[0, 1], 0),
        ];
        let canonical_relations = vec![
            RelationCondition::equal(t(0), t(2)),
            RelationCondition::disequal(t(1), t(4)),
            RelationCondition::equal(t(3), t(5)),
        ];
        let canonical_evidence = external_conflict(0, 1);
        let expected = built(
            6,
            canonical_actions.clone(),
            canonical_relations.clone(),
            canonical_evidence.clone(),
        );
        let mut random = Lcg(0x0ddc_0ffe_e15e_beef);
        for _ in 0..1_000 {
            let mut actions = canonical_actions.clone();
            let mut relations = canonical_relations.clone();
            let mut evidence = canonical_evidence.clone();
            actions.push(actions[random.index(actions.len())].clone());
            relations.push(relations[random.index(relations.len())]);
            evidence.push(evidence[random.index(evidence.len())].clone());
            shuffle(&mut actions, &mut random);
            shuffle(&mut relations, &mut random);
            shuffle(&mut evidence, &mut random);
            assert_eq!(built(6, actions, relations, evidence), expected);
        }
    }

    fn semantic_term(function: u32, sort: u32, arguments: &[u32]) -> SemanticTerm {
        SemanticTerm {
            function,
            sort,
            arguments: arguments
                .iter()
                .copied()
                .map(t)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    #[test]
    fn independent_euf_replay_checks_congruence_conflict() {
        let action = existing(1, &[0], 0);
        let disequality = RelationCondition::disequal(t(2), t(3));
        let nogood = built(
            4,
            vec![action.clone()],
            vec![disequality],
            vec![
                CertificateEvidence::existing(action).unwrap(),
                CertificateEvidence::forbidden_relation(disequality),
            ],
        );
        let terms = [
            semantic_term(0, 0, &[]),
            semantic_term(1, 0, &[]),
            semantic_term(2, 0, &[0]),
            semantic_term(2, 0, &[1]),
        ];
        assert!(matches!(
            nogood
                .replay_euf_certificate_with(&terms, ActionEufReplayCaps::default(), |_, _| false)
                .unwrap(),
            ActionEufReplay::VerifiedConflict { witness, .. } if witness == disequality
        ));

        let mut noncongruent = terms.clone();
        noncongruent[3].function = 3;
        assert!(matches!(
            nogood
                .replay_euf_certificate_with(
                    &noncongruent,
                    ActionEufReplayCaps::default(),
                    |_, _| false,
                )
                .unwrap(),
            ActionEufReplay::NoConflict { .. }
        ));
    }

    #[test]
    fn candidate_assumption_prunes_without_mutating_partition() {
        let action = existing(1, &[0], 0);
        let disequality = RelationCondition::disequal(t(2), t(3));
        let nogood = built(
            4,
            vec![action.clone()],
            vec![disequality],
            vec![
                CertificateEvidence::existing(action.clone()).unwrap(),
                CertificateEvidence::forbidden_relation(disequality),
            ],
        );
        let mut partition = Partition::new(4).unwrap();
        partition.separate(t(2), t(3), ReasonId::new(1)).unwrap();
        let snapshot = partition.snapshot();
        assert!(matches!(
            nogood
                .match_partition(&partition, ActionNogoodCaps::unlimited())
                .unwrap(),
            ActionNogoodMatch::Undetermined { .. }
        ));
        assert!(matches!(
            nogood
                .match_partition_assuming(&partition, &action, ActionNogoodCaps::unlimited(),)
                .unwrap(),
            ActionNogoodMatch::Matched { .. }
        ));
        assert!(matches!(
            nogood
                .match_partition_assuming(
                    &partition,
                    &fresh(1, &[0]),
                    ActionNogoodCaps::unlimited(),
                )
                .unwrap(),
            ActionNogoodMatch::Refuted { .. }
        ));
        assert_eq!(partition.snapshot(), snapshot);
    }

    #[test]
    fn independent_euf_replay_caps_and_typed_input_fail_closed() {
        let action = existing(1, &[0], 0);
        let nogood = single_action_nogood(2, action);
        let terms = [semantic_term(0, 0, &[]), semantic_term(1, 0, &[])];
        assert!(matches!(
            nogood
                .replay_euf_certificate_with(
                    &terms,
                    ActionEufReplayCaps {
                        max_terms: 1,
                        ..ActionEufReplayCaps::default()
                    },
                    |_, _| true,
                )
                .unwrap(),
            ActionEufReplay::Abstained(ActionNogoodLimit {
                resource: ActionNogoodResource::EufReplayTerms,
                ..
            })
        ));

        let ill_typed = [semantic_term(0, 0, &[]), semantic_term(1, 1, &[])];
        let relation = RelationCondition::equal(t(0), t(1));
        let external = built(
            2,
            vec![],
            vec![relation],
            vec![CertificateEvidence::forbidden_relation(relation)],
        );
        assert!(matches!(
            external.replay_euf_certificate_with(
                &ill_typed,
                ActionEufReplayCaps::default(),
                |_, _| false,
            ),
            Err(ActionNogoodError::IllSortedCertificateRelation { .. })
        ));
    }

    #[test]
    fn checked_helpers_report_overflow_and_id_exhaustion() {
        assert_eq!(
            checked_add(
                usize::MAX,
                1,
                ActionNogoodResource::StoredCertificateEvidence
            ),
            Err(ActionNogoodError::ArithmeticOverflow {
                resource: ActionNogoodResource::StoredCertificateEvidence
            })
        );
        if usize::BITS > u32::BITS {
            let index = u32::MAX as usize + 1;
            assert_eq!(
                action_nogood_id(index),
                Err(ActionNogoodError::NogoodIdSpaceExhausted {
                    index,
                    maximum: MAX_NOGOOD_IDS,
                })
            );
        }
    }
}
