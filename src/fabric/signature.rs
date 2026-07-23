#![forbid(unsafe_code)]

//! Deterministic rollback signatures for incremental congruence closure.
//!
//! The index is deliberately separate from [`Partition`]. Callers mutate the
//! partition, identify every term whose canonical representative may have
//! changed, and then update this index transactionally. Rollback similarly has
//! an independent lineage; a solver checkpoint must retain both snapshots.

use super::partition::{MAX_TERMS, Partition, PartitionError, TermId};
use super::semantic::SemanticTerm;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_SIGNATURE_INDEX_ID: AtomicU64 = AtomicU64::new(1);

/// Resource limits for a rollback signature index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SignatureLimits {
    pub(crate) max_terms: usize,
    pub(crate) max_argument_cells: usize,
    /// Maximum number of application rekeys on the active rollback branch.
    pub(crate) max_updates: usize,
    /// Maximum bucket-member and collision-pair work in one transaction.
    pub(crate) max_bucket_work: usize,
}

impl Default for SignatureLimits {
    fn default() -> Self {
        Self {
            max_terms: 1_000_000,
            max_argument_cells: 8_000_000,
            max_updates: 8_000_000,
            max_bucket_work: 64_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignatureResource {
    Terms,
    ArgumentCells,
    Updates,
    BucketWork,
}

impl fmt::Display for SignatureResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Terms => "terms",
            Self::ArgumentCells => "argument cells",
            Self::Updates => "active signature updates",
            Self::BucketWork => "signature bucket work",
        };
        output.write_str(name)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignatureSnapshotError {
    ForeignIndex,
    FutureState,
    DiscardedBranch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SignatureError {
    CapExceeded {
        resource: SignatureResource,
        attempted: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        resource: SignatureResource,
    },
    TooManyTerms {
        requested: usize,
        maximum: u64,
    },
    InvalidArgument {
        application: TermId,
        argument: TermId,
        term_count: usize,
    },
    InvalidChangedTerm {
        term: TermId,
        term_count: usize,
    },
    InvalidApplication {
        term: TermId,
        term_count: usize,
    },
    PartitionTermCountMismatch {
        index_terms: usize,
        partition_terms: usize,
    },
    InvalidSnapshot(SignatureSnapshotError),
    AllocationFailed {
        context: &'static str,
    },
    IndexIdExhausted,
    StateIdExhausted,
    Partition(PartitionError),
    InvariantViolation(&'static str),
}

impl fmt::Display for SignatureError {
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
            Self::ArithmeticOverflow { resource } => {
                write!(output, "arithmetic overflow while counting {resource}")
            }
            Self::TooManyTerms { requested, maximum } => {
                write!(
                    output,
                    "signature index requested {requested} terms, maximum is {maximum}"
                )
            }
            Self::InvalidArgument {
                application,
                argument,
                term_count,
            } => write!(
                output,
                "application {application} has argument {argument} outside 0..{term_count}"
            ),
            Self::InvalidChangedTerm { term, term_count } => {
                write!(output, "changed term {term} is outside 0..{term_count}")
            }
            Self::InvalidApplication { term, term_count } => {
                write!(output, "application {term} is outside 0..{term_count}")
            }
            Self::PartitionTermCountMismatch {
                index_terms,
                partition_terms,
            } => write!(
                output,
                "signature index has {index_terms} terms but partition has {partition_terms}"
            ),
            Self::InvalidSnapshot(SignatureSnapshotError::ForeignIndex) => {
                output.write_str("snapshot belongs to a different signature index")
            }
            Self::InvalidSnapshot(SignatureSnapshotError::FutureState) => {
                output.write_str("signature snapshot is newer than the current state")
            }
            Self::InvalidSnapshot(SignatureSnapshotError::DiscardedBranch) => {
                output.write_str("signature snapshot belongs to a discarded history branch")
            }
            Self::AllocationFailed { context } => {
                write!(output, "allocation failed while building {context}")
            }
            Self::IndexIdExhausted => output.write_str("signature index ID space exhausted"),
            Self::StateIdExhausted => output.write_str("signature state ID space exhausted"),
            Self::Partition(error) => error.fmt(output),
            Self::InvariantViolation(message) => {
                write!(output, "signature index invariant violation: {message}")
            }
        }
    }
}

impl Error for SignatureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Partition(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PartitionError> for SignatureError {
    fn from(error: PartitionError) -> Self {
        Self::Partition(error)
    }
}

/// A congruence signature. Ordering is stable across runs and hash seeds.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ApplicationSignature {
    function: u32,
    result_sort: u32,
    arguments: Box<[TermId]>,
}

impl ApplicationSignature {
    pub(crate) fn function(&self) -> u32 {
        self.function
    }

    pub(crate) fn result_sort(&self) -> u32 {
        self.result_sort
    }

    pub(crate) fn arguments(&self) -> &[TermId] {
        &self.arguments
    }
}

/// A canonical, strictly ordered pair of application term IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CollisionPair {
    pub(crate) left: TermId,
    pub(crate) right: TermId,
}

impl CollisionPair {
    fn new(left: TermId, right: TermId) -> Option<Self> {
        if left < right {
            Some(Self { left, right })
        } else if right < left {
            Some(Self {
                left: right,
                right: left,
            })
        } else {
            None
        }
    }
}

/// Opaque rollback point tied to one index and one history lineage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SignatureSnapshot {
    index_id: u64,
    trail_len: usize,
    state_id: u64,
}

impl SignatureSnapshot {
    pub(crate) const fn depth(self) -> usize {
        self.trail_len
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SignatureTelemetry {
    pub(crate) terms: usize,
    pub(crate) argument_cells: usize,
    pub(crate) reverse_use_edges: usize,
    pub(crate) buckets: usize,
    pub(crate) collision_pairs: usize,
    pub(crate) construction_bucket_work: usize,
    pub(crate) active_key_updates: usize,
    pub(crate) transactions: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SignatureUpdateTelemetry {
    pub(crate) changed_terms: usize,
    pub(crate) affected_applications: usize,
    pub(crate) key_updates: usize,
    pub(crate) involved_buckets: usize,
    pub(crate) bucket_work: usize,
    pub(crate) collisions_added: usize,
    pub(crate) collisions_removed: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SignatureUpdate {
    /// Pairs that did not collide before this transaction and do now.
    pub(crate) newly_colliding: Vec<CollisionPair>,
    pub(crate) telemetry: SignatureUpdateTelemetry,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SignatureRollbackTelemetry {
    pub(crate) transactions: usize,
    pub(crate) key_updates: usize,
    pub(crate) collisions_added_removed: usize,
    pub(crate) collisions_removed_restored: usize,
}

#[derive(Clone, Debug)]
struct KeyChange {
    application: TermId,
    old_key: ApplicationSignature,
    new_key: ApplicationSignature,
}

#[derive(Clone, Debug)]
struct TrailEntry {
    state_id: u64,
    changes: Vec<KeyChange>,
    collisions_added: Vec<CollisionPair>,
    collisions_removed: Vec<CollisionPair>,
}

/// Deterministic application signatures over an externally owned partition.
///
/// Every semantic term is indexed, including nullary applications. Repeated
/// uses of one argument by one application produce one reverse-use edge.
#[derive(Debug)]
pub(crate) struct RollbackSignatureIndex<'terms> {
    terms: &'terms [SemanticTerm],
    limits: SignatureLimits,
    reverse_uses: Box<[Box<[TermId]>]>,
    keys: Box<[ApplicationSignature]>,
    buckets: BTreeMap<ApplicationSignature, BTreeSet<TermId>>,
    collisions: BTreeSet<CollisionPair>,
    argument_cells: usize,
    reverse_use_edges: usize,
    construction_bucket_work: usize,
    active_key_updates: usize,
    index_id: u64,
    trail: Vec<TrailEntry>,
    next_state_id: u64,
}

pub(crate) type SignatureIndex<'terms> = RollbackSignatureIndex<'terms>;

impl<'terms> RollbackSignatureIndex<'terms> {
    pub(crate) fn new(
        terms: &'terms [SemanticTerm],
        partition: &Partition,
    ) -> Result<Self, SignatureError> {
        Self::with_limits(terms, partition, SignatureLimits::default())
    }

    pub(crate) fn with_limits(
        terms: &'terms [SemanticTerm],
        partition: &Partition,
        limits: SignatureLimits,
    ) -> Result<Self, SignatureError> {
        validate_term_count(terms.len(), partition)?;
        check_cap(SignatureResource::Terms, terms.len(), limits.max_terms)?;
        if u64::try_from(terms.len()).map_or(true, |count| count > MAX_TERMS) {
            return Err(SignatureError::TooManyTerms {
                requested: terms.len(),
                maximum: MAX_TERMS,
            });
        }

        let mut argument_cells = 0usize;
        let mut reverse_counts = Vec::new();
        reserve_exact(&mut reverse_counts, terms.len(), "reverse-use counts")?;
        reverse_counts.resize(terms.len(), 0usize);
        for (application_index, term) in terms.iter().enumerate() {
            let application = checked_term_id(application_index, terms.len())?;
            argument_cells = checked_add(
                argument_cells,
                term.arguments.len(),
                SignatureResource::ArgumentCells,
            )?;
            check_cap(
                SignatureResource::ArgumentCells,
                argument_cells,
                limits.max_argument_cells,
            )?;
            for &argument in term.arguments.iter() {
                let argument_index = checked_term_index(argument, terms.len()).ok_or(
                    SignatureError::InvalidArgument {
                        application,
                        argument,
                        term_count: terms.len(),
                    },
                )?;
                reverse_counts[argument_index] = checked_add(
                    reverse_counts[argument_index],
                    1,
                    SignatureResource::ArgumentCells,
                )?;
            }
        }

        let mut reverse = Vec::new();
        reserve_exact(&mut reverse, terms.len(), "reverse-use table")?;
        for count in reverse_counts {
            let mut uses = Vec::new();
            reserve_exact(&mut uses, count, "reverse-use list")?;
            reverse.push(uses);
        }
        for (application_index, term) in terms.iter().enumerate() {
            let application = checked_term_id(application_index, terms.len())?;
            for &argument in term.arguments.iter() {
                reverse[argument.index()].push(application);
            }
        }
        let mut reverse_use_edges = 0usize;
        let mut packed_reverse = Vec::new();
        reserve_exact(&mut packed_reverse, terms.len(), "packed reverse-use table")?;
        for mut uses in reverse {
            uses.dedup();
            reverse_use_edges = checked_add(
                reverse_use_edges,
                uses.len(),
                SignatureResource::ArgumentCells,
            )?;
            packed_reverse.push(uses.into_boxed_slice());
        }

        let mut keys = Vec::new();
        reserve_exact(&mut keys, terms.len(), "application keys")?;
        let mut buckets = BTreeMap::<ApplicationSignature, BTreeSet<TermId>>::new();
        let mut collisions = BTreeSet::new();
        let mut bucket_work = 0usize;
        for (application_index, term) in terms.iter().enumerate() {
            let application = checked_term_id(application_index, terms.len())?;
            let key = signature_for(term, partition)?;
            let bucket = buckets.entry(key.clone()).or_default();
            bucket_work = checked_add(
                bucket_work,
                checked_add(1, bucket.len(), SignatureResource::BucketWork)?,
                SignatureResource::BucketWork,
            )?;
            check_cap(
                SignatureResource::BucketWork,
                bucket_work,
                limits.max_bucket_work,
            )?;
            for &other in bucket.iter() {
                collisions.insert(
                    CollisionPair::new(other, application)
                        .expect("a bucket cannot contain the application before insertion"),
                );
            }
            if !bucket.insert(application) {
                return Err(SignatureError::InvariantViolation(
                    "application was inserted into its construction bucket twice",
                ));
            }
            keys.push(key);
        }

        let index_id = NEXT_SIGNATURE_INDEX_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| SignatureError::IndexIdExhausted)?;

        Ok(Self {
            terms,
            limits,
            reverse_uses: packed_reverse.into_boxed_slice(),
            keys: keys.into_boxed_slice(),
            buckets,
            collisions,
            argument_cells,
            reverse_use_edges,
            construction_bucket_work: bucket_work,
            active_key_updates: 0,
            index_id,
            trail: Vec::new(),
            next_state_id: 1,
        })
    }

    pub(crate) fn term_count(&self) -> usize {
        self.terms.len()
    }

    pub(crate) fn limits(&self) -> SignatureLimits {
        self.limits
    }

    pub(crate) fn telemetry(&self) -> SignatureTelemetry {
        SignatureTelemetry {
            terms: self.term_count(),
            argument_cells: self.argument_cells,
            reverse_use_edges: self.reverse_use_edges,
            buckets: self.buckets.len(),
            collision_pairs: self.collisions.len(),
            construction_bucket_work: self.construction_bucket_work,
            active_key_updates: self.active_key_updates,
            transactions: self.trail.len(),
        }
    }

    pub(crate) fn snapshot(&self) -> SignatureSnapshot {
        SignatureSnapshot {
            index_id: self.index_id,
            trail_len: self.trail.len(),
            state_id: self.trail.last().map_or(0, |entry| entry.state_id),
        }
    }

    pub(crate) fn checkpoint(&self) -> SignatureSnapshot {
        self.snapshot()
    }

    pub(crate) fn reverse_uses(&self, term: TermId) -> Result<&[TermId], SignatureError> {
        let index = checked_term_index(term, self.term_count()).ok_or(
            SignatureError::InvalidChangedTerm {
                term,
                term_count: self.term_count(),
            },
        )?;
        Ok(&self.reverse_uses[index])
    }

    pub(crate) fn application_signature(
        &self,
        application: TermId,
    ) -> Result<&ApplicationSignature, SignatureError> {
        let index = checked_term_index(application, self.term_count()).ok_or(
            SignatureError::InvalidApplication {
                term: application,
                term_count: self.term_count(),
            },
        )?;
        self.keys
            .get(index)
            .ok_or(SignatureError::InvariantViolation(
                "application key table is shorter than the term universe",
            ))
    }

    pub(crate) fn bucket(&self, key: &ApplicationSignature) -> Option<&BTreeSet<TermId>> {
        self.buckets.get(key)
    }

    pub(crate) fn collisions(
        &self,
    ) -> impl ExactSizeIterator<Item = CollisionPair> + DoubleEndedIterator + '_ {
        self.collisions.iter().copied()
    }

    /// Rekeys precisely the applications that use one of `changed_terms`.
    ///
    /// The caller must include every term whose canonical representative may
    /// have changed. Duplicate work is impossible because both the input and
    /// the affected application frontier are ordered sets.
    pub(crate) fn update_after_partition_change(
        &mut self,
        partition: &Partition,
        changed_terms: &BTreeSet<TermId>,
    ) -> Result<SignatureUpdate, SignatureError> {
        validate_term_count(self.term_count(), partition)?;

        let mut affected = BTreeSet::new();
        for &changed in changed_terms {
            let index = checked_term_index(changed, self.term_count()).ok_or(
                SignatureError::InvalidChangedTerm {
                    term: changed,
                    term_count: self.term_count(),
                },
            )?;
            affected.extend(self.reverse_uses[index].iter().copied());
        }

        let mut changes = Vec::new();
        reserve_exact(&mut changes, affected.len(), "pending signature updates")?;
        for &application in &affected {
            let index = application.index();
            let old_key = self
                .keys
                .get(index)
                .ok_or(SignatureError::InvariantViolation(
                    "affected application has no stored key",
                ))?;
            let term = self
                .terms
                .get(index)
                .ok_or(SignatureError::InvariantViolation(
                    "affected application has no semantic term",
                ))?;
            let new_key = signature_for(term, partition)?;
            if *old_key != new_key {
                changes.push(KeyChange {
                    application,
                    old_key: old_key.clone(),
                    new_key,
                });
            }
        }

        let mut telemetry = SignatureUpdateTelemetry {
            changed_terms: changed_terms.len(),
            affected_applications: affected.len(),
            key_updates: changes.len(),
            ..SignatureUpdateTelemetry::default()
        };
        if changes.is_empty() {
            return Ok(SignatureUpdate {
                newly_colliding: Vec::new(),
                telemetry,
            });
        }

        let attempted_updates = checked_add(
            self.active_key_updates,
            changes.len(),
            SignatureResource::Updates,
        )?;
        check_cap(
            SignatureResource::Updates,
            attempted_updates,
            self.limits.max_updates,
        )?;
        let state_id = self.next_state_id;
        let next_state_id = state_id
            .checked_add(1)
            .ok_or(SignatureError::StateIdExhausted)?;

        let mut removals = BTreeMap::<ApplicationSignature, BTreeSet<TermId>>::new();
        let mut additions = BTreeMap::<ApplicationSignature, BTreeSet<TermId>>::new();
        let mut involved = BTreeSet::new();
        for change in &changes {
            removals
                .entry(change.old_key.clone())
                .or_default()
                .insert(change.application);
            additions
                .entry(change.new_key.clone())
                .or_default()
                .insert(change.application);
            involved.insert(change.old_key.clone());
            involved.insert(change.new_key.clone());
        }
        telemetry.involved_buckets = involved.len();

        let mut bucket_work = checked_mul(changes.len(), 2, SignatureResource::BucketWork)?;
        for key in &involved {
            let old_bucket = self.buckets.get(key);
            let old_size = old_bucket.map_or(0, BTreeSet::len);
            if let Some(to_remove) = removals.get(key) {
                let Some(bucket) = old_bucket else {
                    return Err(SignatureError::InvariantViolation(
                        "pending removal refers to a missing bucket",
                    ));
                };
                if !to_remove.iter().all(|term| bucket.contains(term)) {
                    return Err(SignatureError::InvariantViolation(
                        "pending removal refers to a missing bucket member",
                    ));
                }
            }
            if let Some(to_add) = additions.get(key) {
                for term in to_add {
                    if old_bucket.is_some_and(|bucket| bucket.contains(term))
                        && !removals
                            .get(key)
                            .is_some_and(|removed| removed.contains(term))
                    {
                        return Err(SignatureError::InvariantViolation(
                            "pending insertion already belongs to its new bucket",
                        ));
                    }
                }
            }
            let removed = removals.get(key).map_or(0, BTreeSet::len);
            let added = additions.get(key).map_or(0, BTreeSet::len);
            let new_size = old_size
                .checked_sub(removed)
                .and_then(|size| size.checked_add(added))
                .ok_or(SignatureError::ArithmeticOverflow {
                    resource: SignatureResource::BucketWork,
                })?;
            bucket_work = checked_add(
                bucket_work,
                bucket_scan_work(old_size)?,
                SignatureResource::BucketWork,
            )?;
            bucket_work = checked_add(
                bucket_work,
                bucket_scan_work(new_size)?,
                SignatureResource::BucketWork,
            )?;
        }
        check_cap(
            SignatureResource::BucketWork,
            bucket_work,
            self.limits.max_bucket_work,
        )?;
        telemetry.bucket_work = bucket_work;

        let mut staged = BTreeMap::<ApplicationSignature, BTreeSet<TermId>>::new();
        for key in &involved {
            staged.insert(
                key.clone(),
                self.buckets.get(key).cloned().unwrap_or_default(),
            );
        }
        for change in &changes {
            let removed = staged
                .get_mut(&change.old_key)
                .expect("every old key is involved")
                .remove(&change.application);
            if !removed {
                return Err(SignatureError::InvariantViolation(
                    "staged old bucket omitted an application",
                ));
            }
        }
        for change in &changes {
            let inserted = staged
                .get_mut(&change.new_key)
                .expect("every new key is involved")
                .insert(change.application);
            if !inserted {
                return Err(SignatureError::InvariantViolation(
                    "staged new bucket already contained an application",
                ));
            }
        }

        let mut old_pairs = BTreeSet::new();
        let mut new_pairs = BTreeSet::new();
        for key in &involved {
            if let Some(bucket) = self.buckets.get(key) {
                collect_bucket_pairs(bucket, &mut old_pairs);
            }
            collect_bucket_pairs(
                staged.get(key).expect("every involved key was staged"),
                &mut new_pairs,
            );
        }

        let mut collisions_added = Vec::new();
        reserve_exact(
            &mut collisions_added,
            new_pairs.len(),
            "added collision delta",
        )?;
        collisions_added.extend(new_pairs.difference(&old_pairs).copied());
        let mut collisions_removed = Vec::new();
        reserve_exact(
            &mut collisions_removed,
            old_pairs.len(),
            "removed collision delta",
        )?;
        collisions_removed.extend(old_pairs.difference(&new_pairs).copied());
        telemetry.collisions_added = collisions_added.len();
        telemetry.collisions_removed = collisions_removed.len();

        if !old_pairs.iter().all(|pair| self.collisions.contains(pair)) {
            return Err(SignatureError::InvariantViolation(
                "stored collision set omits an old bucket pair",
            ));
        }
        if collisions_added
            .iter()
            .any(|pair| self.collisions.contains(pair))
        {
            return Err(SignatureError::InvariantViolation(
                "new collision was already stored",
            ));
        }

        self.trail
            .try_reserve(1)
            .map_err(|_| SignatureError::AllocationFailed {
                context: "signature rollback trail",
            })?;
        let mut newly_colliding = Vec::new();
        reserve_exact(
            &mut newly_colliding,
            collisions_added.len(),
            "new collision report",
        )?;
        newly_colliding.extend(collisions_added.iter().copied());

        self.apply_key_changes(&changes);
        for pair in &collisions_removed {
            let removed = self.collisions.remove(pair);
            debug_assert!(removed);
        }
        for &pair in &collisions_added {
            let inserted = self.collisions.insert(pair);
            debug_assert!(inserted);
        }
        self.active_key_updates = attempted_updates;
        self.next_state_id = next_state_id;
        self.trail.push(TrailEntry {
            state_id,
            changes,
            collisions_added,
            collisions_removed,
        });

        Ok(SignatureUpdate {
            newly_colliding,
            telemetry,
        })
    }

    pub(crate) fn rollback(
        &mut self,
        snapshot: SignatureSnapshot,
    ) -> Result<SignatureRollbackTelemetry, SignatureError> {
        self.validate_snapshot(snapshot)?;
        let entries = &self.trail[snapshot.trail_len..];
        let mut telemetry = SignatureRollbackTelemetry {
            transactions: entries.len(),
            ..SignatureRollbackTelemetry::default()
        };
        for entry in entries {
            telemetry.key_updates = checked_add(
                telemetry.key_updates,
                entry.changes.len(),
                SignatureResource::Updates,
            )?;
            telemetry.collisions_added_removed = checked_add(
                telemetry.collisions_added_removed,
                entry.collisions_added.len(),
                SignatureResource::BucketWork,
            )?;
            telemetry.collisions_removed_restored = checked_add(
                telemetry.collisions_removed_restored,
                entry.collisions_removed.len(),
                SignatureResource::BucketWork,
            )?;
        }

        while self.trail.len() > snapshot.trail_len {
            let entry = self
                .trail
                .pop()
                .expect("rollback depth guarantees a trail entry");
            self.undo_key_changes(&entry.changes);
            for pair in entry.collisions_added {
                let removed = self.collisions.remove(&pair);
                debug_assert!(removed);
            }
            for pair in entry.collisions_removed {
                let inserted = self.collisions.insert(pair);
                debug_assert!(inserted);
            }
            self.active_key_updates = self
                .active_key_updates
                .checked_sub(entry.changes.len())
                .expect("active update count covers every trail entry");
        }
        Ok(telemetry)
    }

    pub(crate) fn rollback_to(
        &mut self,
        snapshot: SignatureSnapshot,
    ) -> Result<SignatureRollbackTelemetry, SignatureError> {
        self.rollback(snapshot)
    }

    /// Expensive structural check intended for tests and campaign assertions.
    pub(crate) fn validate(&self) -> Result<(), SignatureError> {
        if self.keys.len() != self.term_count() || self.reverse_uses.len() != self.term_count() {
            return Err(SignatureError::InvariantViolation(
                "fixed-size index tables do not match the term universe",
            ));
        }
        let mut seen = vec![false; self.term_count()];
        for (key, bucket) in &self.buckets {
            if bucket.is_empty() {
                return Err(SignatureError::InvariantViolation(
                    "empty signature bucket is stored",
                ));
            }
            for &application in bucket {
                let index = checked_term_index(application, self.term_count()).ok_or(
                    SignatureError::InvariantViolation(
                        "signature bucket contains an invalid application",
                    ),
                )?;
                if seen[index] {
                    return Err(SignatureError::InvariantViolation(
                        "application occurs in multiple signature buckets",
                    ));
                }
                if self.keys[index] != *key {
                    return Err(SignatureError::InvariantViolation(
                        "application key disagrees with its bucket",
                    ));
                }
                seen[index] = true;
            }
        }
        if seen.iter().any(|present| !present) {
            return Err(SignatureError::InvariantViolation(
                "an application is absent from signature buckets",
            ));
        }

        for (argument_index, uses) in self.reverse_uses.iter().enumerate() {
            if uses.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(SignatureError::InvariantViolation(
                    "reverse-use lists are not strictly ordered",
                ));
            }
            let argument = checked_term_id(argument_index, self.term_count())?;
            for &application in uses.iter() {
                let term = self.terms.get(application.index()).ok_or(
                    SignatureError::InvariantViolation(
                        "reverse-use list contains an invalid application",
                    ),
                )?;
                if !term.arguments.contains(&argument) {
                    return Err(SignatureError::InvariantViolation(
                        "reverse-use edge is not present in the semantic term",
                    ));
                }
            }
        }

        let mut expected_collisions = BTreeSet::new();
        for bucket in self.buckets.values() {
            collect_bucket_pairs(bucket, &mut expected_collisions);
        }
        if expected_collisions != self.collisions {
            return Err(SignatureError::InvariantViolation(
                "stored collision set disagrees with signature buckets",
            ));
        }
        let active_updates = self.trail.iter().try_fold(0usize, |total, entry| {
            checked_add(total, entry.changes.len(), SignatureResource::Updates)
        })?;
        if active_updates != self.active_key_updates {
            return Err(SignatureError::InvariantViolation(
                "active update count disagrees with rollback trail",
            ));
        }
        Ok(())
    }

    /// Full oracle check against the current external partition.
    pub(crate) fn validate_against_partition(
        &self,
        partition: &Partition,
    ) -> Result<(), SignatureError> {
        validate_term_count(self.term_count(), partition)?;
        self.validate()?;
        for (index, term) in self.terms.iter().enumerate() {
            let expected = signature_for(term, partition)?;
            if self.keys[index] != expected {
                return Err(SignatureError::InvariantViolation(
                    "stored key is stale relative to the partition",
                ));
            }
        }
        Ok(())
    }

    fn validate_snapshot(&self, snapshot: SignatureSnapshot) -> Result<(), SignatureError> {
        if snapshot.index_id != self.index_id {
            return Err(SignatureError::InvalidSnapshot(
                SignatureSnapshotError::ForeignIndex,
            ));
        }
        if snapshot.trail_len > self.trail.len() {
            return Err(SignatureError::InvalidSnapshot(
                SignatureSnapshotError::FutureState,
            ));
        }
        let expected_state_id = if snapshot.trail_len == 0 {
            0
        } else {
            self.trail[snapshot.trail_len - 1].state_id
        };
        if snapshot.state_id != expected_state_id {
            return Err(SignatureError::InvalidSnapshot(
                SignatureSnapshotError::DiscardedBranch,
            ));
        }
        Ok(())
    }

    fn apply_key_changes(&mut self, changes: &[KeyChange]) {
        for change in changes {
            remove_bucket_member(&mut self.buckets, &change.old_key, change.application);
        }
        for change in changes {
            insert_bucket_member(
                &mut self.buckets,
                change.new_key.clone(),
                change.application,
            );
            self.keys[change.application.index()] = change.new_key.clone();
        }
    }

    fn undo_key_changes(&mut self, changes: &[KeyChange]) {
        for change in changes.iter().rev() {
            remove_bucket_member(&mut self.buckets, &change.new_key, change.application);
        }
        for change in changes.iter().rev() {
            insert_bucket_member(
                &mut self.buckets,
                change.old_key.clone(),
                change.application,
            );
            self.keys[change.application.index()] = change.old_key.clone();
        }
    }
}

fn validate_term_count(term_count: usize, partition: &Partition) -> Result<(), SignatureError> {
    if partition.term_count() != term_count {
        Err(SignatureError::PartitionTermCountMismatch {
            index_terms: term_count,
            partition_terms: partition.term_count(),
        })
    } else {
        Ok(())
    }
}

fn signature_for(
    term: &SemanticTerm,
    partition: &Partition,
) -> Result<ApplicationSignature, SignatureError> {
    let mut arguments = Vec::new();
    reserve_exact(
        &mut arguments,
        term.arguments.len(),
        "canonical signature arguments",
    )?;
    for &argument in term.arguments.iter() {
        arguments.push(partition.representative(argument)?);
    }
    Ok(ApplicationSignature {
        function: term.function,
        result_sort: term.sort,
        arguments: arguments.into_boxed_slice(),
    })
}

fn collect_bucket_pairs(bucket: &BTreeSet<TermId>, output: &mut BTreeSet<CollisionPair>) {
    for (left_index, &left) in bucket.iter().enumerate() {
        for &right in bucket.iter().skip(left_index + 1) {
            output.insert(
                CollisionPair::new(left, right)
                    .expect("different positions in a set contain different terms"),
            );
        }
    }
}

fn remove_bucket_member(
    buckets: &mut BTreeMap<ApplicationSignature, BTreeSet<TermId>>,
    key: &ApplicationSignature,
    application: TermId,
) {
    let empty = {
        let bucket = buckets
            .get_mut(key)
            .expect("trailed signature key must have a bucket");
        let removed = bucket.remove(&application);
        assert!(
            removed,
            "trailed application must occur in its signature bucket"
        );
        bucket.is_empty()
    };
    if empty {
        let removed = buckets.remove(key);
        debug_assert!(removed.is_some());
    }
}

fn insert_bucket_member(
    buckets: &mut BTreeMap<ApplicationSignature, BTreeSet<TermId>>,
    key: ApplicationSignature,
    application: TermId,
) {
    let inserted = buckets.entry(key).or_default().insert(application);
    assert!(
        inserted,
        "trailed application must not already occur in its target bucket"
    );
}

fn checked_term_index(term: TermId, term_count: usize) -> Option<usize> {
    let index = term.index();
    (index < term_count).then_some(index)
}

fn checked_term_id(index: usize, term_count: usize) -> Result<TermId, SignatureError> {
    TermId::try_from(index).map_err(|_| SignatureError::TooManyTerms {
        requested: term_count,
        maximum: MAX_TERMS,
    })
}

fn reserve_exact<T>(
    vector: &mut Vec<T>,
    additional: usize,
    context: &'static str,
) -> Result<(), SignatureError> {
    vector
        .try_reserve_exact(additional)
        .map_err(|_| SignatureError::AllocationFailed { context })
}

fn check_cap(
    resource: SignatureResource,
    attempted: usize,
    limit: usize,
) -> Result<(), SignatureError> {
    if attempted > limit {
        Err(SignatureError::CapExceeded {
            resource,
            attempted,
            limit,
        })
    } else {
        Ok(())
    }
}

fn checked_add(
    left: usize,
    right: usize,
    resource: SignatureResource,
) -> Result<usize, SignatureError> {
    left.checked_add(right)
        .ok_or(SignatureError::ArithmeticOverflow { resource })
}

fn checked_mul(
    left: usize,
    right: usize,
    resource: SignatureResource,
) -> Result<usize, SignatureError> {
    left.checked_mul(right)
        .ok_or(SignatureError::ArithmeticOverflow { resource })
}

fn bucket_scan_work(size: usize) -> Result<usize, SignatureError> {
    let predecessor = size.saturating_sub(1);
    let product = checked_mul(size, predecessor, SignatureResource::BucketWork)?;
    let pairs = product / 2;
    checked_add(size, pairs, SignatureResource::BucketWork)
}

#[cfg(test)]
mod tests {
    use super::super::partition::{MergeOutcome, ReasonId, Snapshot as PartitionSnapshot};
    use super::*;

    fn id(raw: u32) -> TermId {
        TermId::new(raw)
    }

    fn term(function: u32, sort: u32, arguments: &[u32]) -> SemanticTerm {
        SemanticTerm {
            function,
            sort,
            arguments: arguments
                .iter()
                .copied()
                .map(TermId::new)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    fn changed_representatives(partition: &Partition, before: &[TermId]) -> BTreeSet<TermId> {
        before
            .iter()
            .enumerate()
            .filter_map(|(index, &old)| {
                let current = partition.representative(id(index as u32)).unwrap();
                (current != old).then_some(id(index as u32))
            })
            .collect()
    }

    fn representatives(partition: &Partition) -> Vec<TermId> {
        (0..partition.term_count())
            .map(|index| partition.representative(id(index as u32)).unwrap())
            .collect()
    }

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct OracleKey {
        function: u32,
        result_sort: u32,
        arguments: Vec<TermId>,
    }

    fn full_scan_oracle(terms: &[SemanticTerm], partition: &Partition) -> BTreeSet<CollisionPair> {
        let mut buckets = BTreeMap::<OracleKey, Vec<TermId>>::new();
        for (index, term) in terms.iter().enumerate() {
            let key = OracleKey {
                function: term.function,
                result_sort: term.sort,
                arguments: term
                    .arguments
                    .iter()
                    .map(|&argument| partition.representative(argument).unwrap())
                    .collect(),
            };
            buckets.entry(key).or_default().push(id(index as u32));
        }
        let mut pairs = BTreeSet::new();
        for bucket in buckets.values() {
            for left in 0..bucket.len() {
                for right in left + 1..bucket.len() {
                    pairs.insert(CollisionPair {
                        left: bucket[left],
                        right: bucket[right],
                    });
                }
            }
        }
        pairs
    }

    fn assert_matches_oracle(
        index: &RollbackSignatureIndex<'_>,
        terms: &[SemanticTerm],
        partition: &Partition,
    ) {
        index.validate_against_partition(partition).unwrap();
        assert_eq!(
            index.collisions().collect::<BTreeSet<_>>(),
            full_scan_oracle(terms, partition)
        );
    }

    #[test]
    fn construction_is_deterministic_and_separates_every_key_dimension() {
        let terms = vec![
            term(0, 0, &[]),
            term(1, 0, &[]),
            term(10, 0, &[0]),
            term(10, 0, &[1]),
            term(10, 0, &[0, 0]),
            term(11, 0, &[0]),
            term(10, 1, &[0]),
            term(10, 0, &[0]),
        ];
        let partition = Partition::new(terms.len()).unwrap();
        let first = SignatureIndex::new(&terms, &partition).unwrap();
        let second = SignatureIndex::new(&terms, &partition).unwrap();

        assert_eq!(
            first.collisions().collect::<Vec<_>>(),
            vec![CollisionPair {
                left: id(2),
                right: id(7),
            }]
        );
        assert_eq!(
            first.collisions().collect::<Vec<_>>(),
            second.collisions().collect::<Vec<_>>()
        );
        assert_eq!(
            first.reverse_uses(id(0)).unwrap(),
            &[id(2), id(4), id(5), id(6), id(7)]
        );
        assert_eq!(first.reverse_uses(id(1)).unwrap(), &[id(3)]);
        let key = first.application_signature(id(2)).unwrap();
        assert_eq!(key.function(), 10);
        assert_eq!(key.result_sort(), 0);
        assert_eq!(key.arguments(), &[id(0)]);
        assert_eq!(first.bucket(key).unwrap(), &BTreeSet::from([id(2), id(7)]));
        assert_eq!(first.telemetry().argument_cells, 7);
        assert_eq!(first.telemetry().reverse_use_edges, 6);
        assert_matches_oracle(&first, &terms, &partition);
    }

    #[test]
    fn update_reports_only_new_pairs_and_only_rekeys_reverse_frontier() {
        let terms = vec![
            term(0, 0, &[]),
            term(1, 0, &[]),
            term(2, 0, &[]),
            term(10, 0, &[0]),
            term(10, 0, &[1]),
            term(10, 0, &[2]),
            term(20, 0, &[0, 2]),
        ];
        let mut partition = Partition::new(terms.len()).unwrap();
        let mut index = SignatureIndex::new(&terms, &partition).unwrap();

        let before = representatives(&partition);
        partition.merge(id(0), id(1), ReasonId::new(1)).unwrap();
        let changed = changed_representatives(&partition, &before);
        assert_eq!(changed, BTreeSet::from([id(1)]));
        let update = index
            .update_after_partition_change(&partition, &changed)
            .unwrap();
        assert_eq!(
            update.newly_colliding,
            vec![CollisionPair {
                left: id(3),
                right: id(4),
            }]
        );
        assert_eq!(update.telemetry.affected_applications, 1);
        assert_eq!(update.telemetry.key_updates, 1);
        assert_matches_oracle(&index, &terms, &partition);

        let before = representatives(&partition);
        partition.merge(id(1), id(2), ReasonId::new(2)).unwrap();
        let changed = changed_representatives(&partition, &before);
        assert_eq!(changed, BTreeSet::from([id(2)]));
        let update = index
            .update_after_partition_change(&partition, &changed)
            .unwrap();
        assert_eq!(
            update.newly_colliding,
            vec![
                CollisionPair {
                    left: id(3),
                    right: id(5),
                },
                CollisionPair {
                    left: id(4),
                    right: id(5),
                },
            ]
        );
        assert_eq!(update.telemetry.affected_applications, 2);
        assert_eq!(update.telemetry.key_updates, 2);
        assert_matches_oracle(&index, &terms, &partition);
    }

    #[test]
    fn non_monotone_rekey_removes_collisions_and_rolls_back_exactly() {
        let (terms, mut merged_partition) = update_fixture();
        let identity_partition = Partition::new(terms.len()).unwrap();
        let mut index = SignatureIndex::new(&terms, &identity_partition).unwrap();
        let root = index.snapshot();

        merged_partition
            .merge(id(0), id(1), ReasonId::new(1))
            .unwrap();
        let changed = BTreeSet::from([id(1)]);
        let update = index
            .update_after_partition_change(&merged_partition, &changed)
            .unwrap();
        assert_eq!(update.telemetry.collisions_added, 1);
        assert_eq!(update.telemetry.collisions_removed, 0);
        let merged = index.snapshot();
        assert_matches_oracle(&index, &terms, &merged_partition);

        let update = index
            .update_after_partition_change(&identity_partition, &changed)
            .unwrap();
        assert!(update.newly_colliding.is_empty());
        assert_eq!(update.telemetry.collisions_added, 0);
        assert_eq!(update.telemetry.collisions_removed, 1);
        assert_matches_oracle(&index, &terms, &identity_partition);

        let rollback = index.rollback(merged).unwrap();
        assert_eq!(rollback.collisions_removed_restored, 1);
        assert_matches_oracle(&index, &terms, &merged_partition);
        index.rollback(root).unwrap();
        assert_matches_oracle(&index, &terms, &identity_partition);
    }

    #[test]
    fn empty_and_irrelevant_updates_do_not_create_history() {
        let terms = vec![term(0, 0, &[]), term(1, 0, &[]), term(10, 0, &[0])];
        let partition = Partition::new(terms.len()).unwrap();
        let mut index = SignatureIndex::new(&terms, &partition).unwrap();
        let root = index.snapshot();

        let empty = index
            .update_after_partition_change(&partition, &BTreeSet::new())
            .unwrap();
        assert_eq!(empty.telemetry, SignatureUpdateTelemetry::default());
        assert_eq!(index.snapshot(), root);

        let irrelevant = index
            .update_after_partition_change(&partition, &BTreeSet::from([id(1)]))
            .unwrap();
        assert_eq!(irrelevant.telemetry.changed_terms, 1);
        assert_eq!(irrelevant.telemetry.affected_applications, 0);
        assert_eq!(irrelevant.telemetry.key_updates, 0);
        assert_eq!(index.snapshot(), root);
    }

    fn enumerate_partitions(
        position: usize,
        max_label: usize,
        labels: &mut [usize],
        output: &mut Vec<Vec<usize>>,
    ) {
        if position == labels.len() {
            output.push(labels.to_vec());
            return;
        }
        for label in 0..=max_label + 1 {
            labels[position] = label;
            enumerate_partitions(position + 1, max_label.max(label), labels, output);
        }
    }

    fn all_partitions(size: usize) -> Vec<Vec<usize>> {
        if size == 0 {
            return vec![Vec::new()];
        }
        let mut labels = vec![0; size];
        let mut output = Vec::new();
        enumerate_partitions(1, 0, &mut labels, &mut output);
        output
    }

    #[test]
    fn indexed_collisions_match_full_scan_for_every_four_term_partition() {
        let terms = vec![
            term(0, 0, &[]),
            term(1, 0, &[]),
            term(2, 0, &[]),
            term(3, 0, &[]),
            term(10, 0, &[0]),
            term(10, 0, &[1]),
            term(10, 0, &[2]),
            term(10, 0, &[3]),
            term(11, 0, &[0, 1]),
            term(11, 0, &[2, 3]),
            term(11, 1, &[0, 1]),
            term(12, 0, &[0, 1]),
        ];
        let partitions = all_partitions(4);
        assert_eq!(partitions.len(), 15);

        for labels in partitions {
            let identity = Partition::new(terms.len()).unwrap();
            let mut incremental = SignatureIndex::new(&terms, &identity).unwrap();
            let mut partition = Partition::new(terms.len()).unwrap();
            let root = partition.snapshot();
            let mut reason = 1u64;
            for left in 0..4 {
                for right in left + 1..4 {
                    if labels[left] == labels[right]
                        && matches!(
                            partition
                                .merge(id(left as u32), id(right as u32), ReasonId::new(reason))
                                .unwrap(),
                            MergeOutcome::Merged { .. }
                        )
                    {
                        reason += 1;
                    }
                }
            }
            let changed = (0..4).map(|raw| id(raw as u32)).collect();
            incremental
                .update_after_partition_change(&partition, &changed)
                .unwrap();
            assert_matches_oracle(&incremental, &terms, &partition);

            let fresh = SignatureIndex::new(&terms, &partition).unwrap();
            assert_eq!(
                incremental.collisions().collect::<Vec<_>>(),
                fresh.collisions().collect::<Vec<_>>()
            );
            partition.rollback(root).unwrap();
        }
    }

    #[derive(Clone, Copy)]
    struct Checkpoint {
        partition: PartitionSnapshot,
        signature: SignatureSnapshot,
    }

    fn next_random(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state
    }

    #[test]
    fn random_merge_and_rollback_trace_matches_fresh_oracle() {
        let mut terms = (0..6).map(|raw| term(raw, 0, &[])).collect::<Vec<_>>();
        for argument in 0..6 {
            terms.push(term(20, 0, &[argument]));
        }
        for left in 0..6 {
            for right in 0..6 {
                terms.push(term(30, 0, &[left, right]));
            }
        }
        terms.push(term(40, 0, &[6]));
        terms.push(term(40, 0, &[7]));

        for seed in 0..8u64 {
            let mut partition = Partition::new(terms.len()).unwrap();
            let mut index = SignatureIndex::new(&terms, &partition).unwrap();
            let mut checkpoints = vec![Checkpoint {
                partition: partition.snapshot(),
                signature: index.snapshot(),
            }];
            let mut random = 0x6f4d_2c91_7a30_b855u64 ^ seed.wrapping_mul(0x9e37_79b9);
            let mut reason = 1u64;

            for step in 0..500 {
                if checkpoints.len() > 1 && next_random(&mut random) % 5 == 0 {
                    let selected = (next_random(&mut random) as usize) % checkpoints.len();
                    let checkpoint = checkpoints[selected];
                    partition.rollback(checkpoint.partition).unwrap();
                    index.rollback(checkpoint.signature).unwrap();
                    checkpoints.truncate(selected + 1);
                } else {
                    let left = (next_random(&mut random) as usize) % terms.len();
                    let right = (next_random(&mut random) as usize) % terms.len();
                    let before = representatives(&partition);
                    partition
                        .merge(id(left as u32), id(right as u32), ReasonId::new(reason))
                        .unwrap();
                    reason += 1;
                    let changed = changed_representatives(&partition, &before);
                    index
                        .update_after_partition_change(&partition, &changed)
                        .unwrap();
                    if step % 7 == 0 {
                        checkpoints.push(Checkpoint {
                            partition: partition.snapshot(),
                            signature: index.snapshot(),
                        });
                    }
                }
                assert_matches_oracle(&index, &terms, &partition);
            }
        }
    }

    fn update_fixture() -> (Vec<SemanticTerm>, Partition) {
        let terms = vec![
            term(0, 0, &[]),
            term(1, 0, &[]),
            term(10, 0, &[0]),
            term(10, 0, &[1]),
        ];
        let partition = Partition::new(terms.len()).unwrap();
        (terms, partition)
    }

    fn apply_fixture_merge(partition: &mut Partition, index: &mut SignatureIndex<'_>, reason: u64) {
        let before = representatives(partition);
        partition
            .merge(id(0), id(1), ReasonId::new(reason))
            .unwrap();
        let changed = changed_representatives(partition, &before);
        index
            .update_after_partition_change(partition, &changed)
            .unwrap();
    }

    #[test]
    fn rollback_is_exact_and_rejects_foreign_future_and_discarded_snapshots() {
        let (terms, mut partition) = update_fixture();
        let mut index = SignatureIndex::new(&terms, &partition).unwrap();
        let root_partition = partition.snapshot();
        let root = index.snapshot();
        apply_fixture_merge(&mut partition, &mut index, 1);
        let old_branch = index.snapshot();
        assert_eq!(old_branch.depth(), 1);
        let rollback = index.rollback(root).unwrap();
        partition.rollback(root_partition).unwrap();
        assert_eq!(rollback.transactions, 1);
        assert_eq!(rollback.key_updates, 1);
        assert_matches_oracle(&index, &terms, &partition);
        assert_eq!(
            index.rollback(old_branch),
            Err(SignatureError::InvalidSnapshot(
                SignatureSnapshotError::FutureState
            ))
        );

        apply_fixture_merge(&mut partition, &mut index, 2);
        let replacement = index.snapshot();
        assert_eq!(replacement.depth(), old_branch.depth());
        assert_eq!(
            index.rollback(old_branch),
            Err(SignatureError::InvalidSnapshot(
                SignatureSnapshotError::DiscardedBranch
            ))
        );

        let (_, other_partition) = update_fixture();
        let other = SignatureIndex::new(&terms, &other_partition).unwrap();
        assert_eq!(
            index.rollback(other.snapshot()),
            Err(SignatureError::InvalidSnapshot(
                SignatureSnapshotError::ForeignIndex
            ))
        );
        index.rollback_to(replacement).unwrap();
    }

    #[test]
    fn malformed_terms_ids_partitions_and_snapshots_are_rejected_atomically() {
        let malformed = vec![term(0, 0, &[1])];
        let partition = Partition::new(1).unwrap();
        assert!(matches!(
            SignatureIndex::new(&malformed, &partition),
            Err(SignatureError::InvalidArgument {
                application,
                argument,
                term_count: 1,
            }) if application == id(0) && argument == id(1)
        ));

        let (terms, partition) = update_fixture();
        let wrong_partition = Partition::new(terms.len() - 1).unwrap();
        assert!(matches!(
            SignatureIndex::new(&terms, &wrong_partition),
            Err(SignatureError::PartitionTermCountMismatch { .. })
        ));
        let mut index = SignatureIndex::new(&terms, &partition).unwrap();
        let before = index.snapshot();
        let collisions = index.collisions().collect::<Vec<_>>();
        assert_eq!(
            index.update_after_partition_change(&partition, &BTreeSet::from([id(99)])),
            Err(SignatureError::InvalidChangedTerm {
                term: id(99),
                term_count: terms.len(),
            })
        );
        assert_eq!(index.snapshot(), before);
        assert_eq!(index.collisions().collect::<Vec<_>>(), collisions);
        assert_eq!(
            index.reverse_uses(id(99)),
            Err(SignatureError::InvalidChangedTerm {
                term: id(99),
                term_count: terms.len(),
            })
        );
        assert!(matches!(
            index.application_signature(id(99)),
            Err(SignatureError::InvalidApplication { .. })
        ));

        let forged = SignatureSnapshot {
            index_id: before.index_id,
            trail_len: before.trail_len,
            state_id: u64::MAX,
        };
        assert_eq!(
            index.rollback(forged),
            Err(SignatureError::InvalidSnapshot(
                SignatureSnapshotError::DiscardedBranch
            ))
        );
        assert_eq!(index.snapshot(), before);
    }

    #[test]
    fn construction_caps_terms_argument_cells_and_bucket_work() {
        let terms = vec![term(0, 0, &[]), term(0, 0, &[]), term(0, 0, &[])];
        let partition = Partition::new(terms.len()).unwrap();
        let mut limits = SignatureLimits::default();
        limits.max_terms = 2;
        assert!(matches!(
            SignatureIndex::with_limits(&terms, &partition, limits),
            Err(SignatureError::CapExceeded {
                resource: SignatureResource::Terms,
                attempted: 3,
                limit: 2,
            })
        ));

        let argument_terms = vec![term(0, 0, &[]), term(10, 0, &[0, 0])];
        let argument_partition = Partition::new(argument_terms.len()).unwrap();
        let mut limits = SignatureLimits::default();
        limits.max_argument_cells = 1;
        assert!(matches!(
            SignatureIndex::with_limits(&argument_terms, &argument_partition, limits),
            Err(SignatureError::CapExceeded {
                resource: SignatureResource::ArgumentCells,
                attempted: 2,
                limit: 1,
            })
        ));

        let mut limits = SignatureLimits::default();
        limits.max_bucket_work = 5;
        assert!(matches!(
            SignatureIndex::with_limits(&terms, &partition, limits),
            Err(SignatureError::CapExceeded {
                resource: SignatureResource::BucketWork,
                attempted: 6,
                limit: 5,
            })
        ));
    }

    #[test]
    fn update_caps_leave_keys_buckets_collisions_and_history_unchanged() {
        let (terms, mut partition) = update_fixture();
        let mut limits = SignatureLimits::default();
        limits.max_updates = 0;
        let mut index = SignatureIndex::with_limits(&terms, &partition, limits).unwrap();
        let before = index.snapshot();
        let key = index.application_signature(id(3)).unwrap().clone();
        let collisions = index.collisions().collect::<Vec<_>>();
        let before_representatives = representatives(&partition);
        partition.merge(id(0), id(1), ReasonId::new(1)).unwrap();
        let changed = changed_representatives(&partition, &before_representatives);
        assert!(matches!(
            index.update_after_partition_change(&partition, &changed),
            Err(SignatureError::CapExceeded {
                resource: SignatureResource::Updates,
                attempted: 1,
                limit: 0,
            })
        ));
        assert_eq!(index.snapshot(), before);
        assert_eq!(index.application_signature(id(3)).unwrap(), &key);
        assert_eq!(index.collisions().collect::<Vec<_>>(), collisions);
        index.validate().unwrap();

        let (terms, mut partition) = update_fixture();
        let mut limits = SignatureLimits::default();
        limits.max_bucket_work = 4;
        let mut index = SignatureIndex::with_limits(&terms, &partition, limits).unwrap();
        let before = index.snapshot();
        let key = index.application_signature(id(3)).unwrap().clone();
        let before_representatives = representatives(&partition);
        partition.merge(id(0), id(1), ReasonId::new(1)).unwrap();
        let changed = changed_representatives(&partition, &before_representatives);
        assert!(matches!(
            index.update_after_partition_change(&partition, &changed),
            Err(SignatureError::CapExceeded {
                resource: SignatureResource::BucketWork,
                ..
            })
        ));
        assert_eq!(index.snapshot(), before);
        assert_eq!(index.application_signature(id(3)).unwrap(), &key);
        assert!(index.collisions().next().is_none());
        index.validate().unwrap();
    }

    #[test]
    fn active_update_cap_is_recovered_by_rollback() {
        let terms = vec![
            term(0, 0, &[]),
            term(1, 0, &[]),
            term(2, 0, &[]),
            term(10, 0, &[0]),
            term(10, 0, &[1]),
            term(10, 0, &[2]),
        ];
        let mut partition = Partition::new(terms.len()).unwrap();
        let mut limits = SignatureLimits::default();
        limits.max_updates = 1;
        let mut index = SignatureIndex::with_limits(&terms, &partition, limits).unwrap();
        let root_partition = partition.snapshot();
        let root_index = index.snapshot();

        let before = representatives(&partition);
        partition.merge(id(0), id(1), ReasonId::new(1)).unwrap();
        let changed = changed_representatives(&partition, &before);
        index
            .update_after_partition_change(&partition, &changed)
            .unwrap();
        assert_eq!(index.telemetry().active_key_updates, 1);

        let before = representatives(&partition);
        partition.merge(id(1), id(2), ReasonId::new(2)).unwrap();
        let changed = changed_representatives(&partition, &before);
        assert!(matches!(
            index.update_after_partition_change(&partition, &changed),
            Err(SignatureError::CapExceeded {
                resource: SignatureResource::Updates,
                ..
            })
        ));

        partition.rollback(root_partition).unwrap();
        index.rollback(root_index).unwrap();
        assert_eq!(index.telemetry().active_key_updates, 0);
        let before = representatives(&partition);
        partition.merge(id(0), id(2), ReasonId::new(3)).unwrap();
        let changed = changed_representatives(&partition, &before);
        index
            .update_after_partition_change(&partition, &changed)
            .unwrap();
        assert_matches_oracle(&index, &terms, &partition);
    }
}
