#![cfg(test)]
#![allow(dead_code)]

//! Exact reference certificates for complete forbidden-table orbits.
//!
//! This module is deliberately test-only and is not a solver route.  It checks
//! the reduction
//!
//! ```text
//! base(table) /\ table not in forbidden_records
//! ```
//!
//! to one representative of a full `S_n` conjugacy orbit.  Table-set equality
//! is not enough: quotienting is sound only when the separated base is
//! invariant under the same action.  Consequently, recognition requires an
//! explicit assertion-image bijection for every permutation and replays every
//! claimed image through an independent [`BaseActionVerifier`].
//!
//! The caller is responsible for typed extraction before entering this
//! module.  In particular, every [`BinaryTable`] must describe the same closed
//! homogeneous operation `S x S -> S`, and the [`BaseFingerprint`] must commit
//! to the selected sort, ordered carrier, operation symbol, and all assertions
//! left after removing the complete-table exclusions.  Any absent, malformed,
//! or unreplayable obligation returns an error; this module never infers base
//! invariance from the forbidden records.

use crate::orbit_canon::{
    BinaryTable, CheckedPermutation, LexicographicPermutations, MAX_EXHAUSTIVE_DEGREE,
    TableActionError,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

/// Digest binding a base-invariance claim to its typed extraction context.
///
/// The checker treats these bytes as opaque.  The producer must hash a
/// deterministic encoding that includes the selected finite sort, ordered
/// carrier terms, selected operation, and the complete separated base.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BaseFingerprint([u8; 32]);

impl BaseFingerprint {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Claimed action of one carrier permutation on the base-assertion multiset.
///
/// `assertion_images[source] = target` means that relabeling assertion
/// `source` by `permutation` yields assertion `target`.  Exact recognition
/// requires this vector to be a permutation of all base assertion indices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasePermutationWitness {
    permutation: CheckedPermutation,
    assertion_images: Box<[usize]>,
}

impl BasePermutationWitness {
    pub fn new(permutation: CheckedPermutation, assertion_images: Vec<usize>) -> Self {
        Self {
            permutation,
            assertion_images: assertion_images.into_boxed_slice(),
        }
    }

    pub fn permutation(&self) -> &CheckedPermutation {
        &self.permutation
    }

    pub fn assertion_images(&self) -> &[usize] {
        &self.assertion_images
    }
}

/// Untrusted, explicit claim that the separated base is invariant under `S_n`.
///
/// A claim becomes part of an [`OrbitCoverCertificate`] only after exact
/// enumeration and independent replay.  Supplying witnesses for generators
/// alone is intentionally insufficient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseInvarianceClaim {
    degree: usize,
    fingerprint: BaseFingerprint,
    assertion_count: usize,
    witnesses: Box<[BasePermutationWitness]>,
}

impl BaseInvarianceClaim {
    pub fn new(
        degree: usize,
        fingerprint: BaseFingerprint,
        assertion_count: usize,
        witnesses: Vec<BasePermutationWitness>,
    ) -> Self {
        Self {
            degree,
            fingerprint,
            assertion_count,
            witnesses: witnesses.into_boxed_slice(),
        }
    }

    pub fn degree(&self) -> usize {
        self.degree
    }

    pub fn fingerprint(&self) -> BaseFingerprint {
        self.fingerprint
    }

    pub fn assertion_count(&self) -> usize {
        self.assertion_count
    }

    pub fn witnesses(&self) -> &[BasePermutationWitness] {
        &self.witnesses
    }
}

/// Independent replay boundary for base-invariance witnesses.
///
/// An implementation must apply `permutation` to the typed source assertion
/// itself and compare the result with the claimed target assertion.  It must
/// not answer from the witness map being checked.  Returning `false` for any
/// reason makes recognition fail closed.
pub trait BaseActionVerifier {
    fn degree(&self) -> usize;
    fn fingerprint(&self) -> BaseFingerprint;
    fn assertion_count(&self) -> usize;

    fn transformed_assertion_matches(
        &self,
        permutation: &CheckedPermutation,
        source_assertion: usize,
        target_assertion: usize,
    ) -> bool;
}

/// Least seed-to-image witness for one unique forbidden table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrbitImageWitness {
    image: BinaryTable,
    seed_to_image: CheckedPermutation,
}

impl OrbitImageWitness {
    pub fn image(&self) -> &BinaryTable {
        &self.image
    }

    pub fn seed_to_image(&self) -> &CheckedPermutation {
        &self.seed_to_image
    }
}

/// Least seed-to-record witness, aligned with the original record sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForbiddenRecordWitness {
    record_index: usize,
    seed_to_record: CheckedPermutation,
}

impl ForbiddenRecordWitness {
    pub fn record_index(&self) -> usize {
        self.record_index
    }

    pub fn seed_to_record(&self) -> &CheckedPermutation {
        &self.seed_to_record
    }
}

/// Counters emitted on success and retained on every failure path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrbitCoverTelemetry {
    pub degree: usize,
    pub expected_permutations: usize,
    pub base_witness_records: usize,
    pub duplicate_base_permutations: usize,
    pub missing_base_permutations: usize,
    pub base_permutations_replayed: usize,
    pub base_assertion_images_replayed: usize,
    pub base_invariance_verified: bool,
    pub forbidden_records: usize,
    pub unique_forbidden_tables: usize,
    pub duplicate_forbidden_records: usize,
    pub orbit_permutations_enumerated: usize,
    pub unique_orbit_tables: usize,
    pub stabilizer_size: usize,
    pub missing_orbit_tables: usize,
    pub out_of_orbit_tables: usize,
    pub unique_table_witnesses_replayed: usize,
    pub record_witnesses_replayed: usize,
    pub exact_orbit_cover_verified: bool,
}

/// Fully checked, deterministic proof object for one forbidden conjugacy orbit.
///
/// Fields are private so callers cannot manufacture a certificate without the
/// exhaustive recognizer.  [`Self::verify_exact`] independently rebuilds it
/// from the extracted records and base-action verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrbitCoverCertificate {
    degree: usize,
    representative: BinaryTable,
    base_invariance: BaseInvarianceClaim,
    image_witnesses: Box<[OrbitImageWitness]>,
    record_witnesses: Box<[ForbiddenRecordWitness]>,
    telemetry: OrbitCoverTelemetry,
}

impl OrbitCoverCertificate {
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Lexicographically least table in the verified orbit.
    pub fn representative(&self) -> &BinaryTable {
        &self.representative
    }

    pub fn base_invariance(&self) -> &BaseInvarianceClaim {
        &self.base_invariance
    }

    /// Sorted unique orbit images and their least witnesses.
    pub fn image_witnesses(&self) -> &[OrbitImageWitness] {
        &self.image_witnesses
    }

    /// Witnesses aligned with the source extraction order, including repeats.
    pub fn record_witnesses(&self) -> &[ForbiddenRecordWitness] {
        &self.record_witnesses
    }

    pub fn telemetry(&self) -> &OrbitCoverTelemetry {
        &self.telemetry
    }

    pub fn covers(&self, table: &BinaryTable) -> bool {
        self.image_witnesses
            .binary_search_by(|witness| witness.image.cmp(table))
            .is_ok()
    }

    /// Rebuilds the complete proof object and checks every stored witness.
    pub fn verify_exact<V: BaseActionVerifier>(
        &self,
        forbidden_records: &[BinaryTable],
        verifier: &V,
    ) -> Result<OrbitCoverTelemetry, OrbitCoverFailure> {
        verify_orbit_cover_certificate(self, forbidden_records, verifier)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrbitCoverError {
    EmptyForbiddenSet,
    DegreeTooLarge {
        degree: usize,
        maximum: usize,
    },
    MixedTableDegree {
        record_index: usize,
        expected: usize,
        actual: usize,
    },
    BaseClaimDegreeMismatch {
        table_degree: usize,
        claim_degree: usize,
    },
    VerifierDegreeMismatch {
        claim_degree: usize,
        verifier_degree: usize,
    },
    VerifierFingerprintMismatch,
    VerifierAssertionCountMismatch {
        claim_count: usize,
        verifier_count: usize,
    },
    BaseWitnessDegreeMismatch {
        witness_index: usize,
        expected: usize,
        actual: usize,
    },
    BaseWitnessSetMismatch {
        expected: usize,
        unique: usize,
        duplicates: usize,
        missing: usize,
    },
    BaseAssertionImageCountMismatch {
        permutation: CheckedPermutation,
        expected: usize,
        actual: usize,
    },
    BaseAssertionImageOutOfRange {
        permutation: CheckedPermutation,
        source_assertion: usize,
        target_assertion: usize,
        assertion_count: usize,
    },
    DuplicateBaseAssertionImage {
        permutation: CheckedPermutation,
        target_assertion: usize,
    },
    BaseAssertionReplayRejected {
        permutation: CheckedPermutation,
        source_assertion: usize,
        target_assertion: usize,
    },
    PermutationEnumeration,
    TableAction(TableActionError),
    OrbitCardinalityInconsistent {
        permutations: usize,
        orbit_size: usize,
    },
    ForbiddenSetMismatch {
        missing_orbit_tables: usize,
        out_of_orbit_tables: usize,
    },
    UniqueTableWitnessMismatch {
        image_index: usize,
    },
    RecordWitnessMismatch {
        record_index: usize,
    },
    CertificateMismatch,
}

impl fmt::Display for OrbitCoverError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyForbiddenSet => write!(output, "a forbidden orbit needs at least one table"),
            Self::DegreeTooLarge { degree, maximum } => write!(
                output,
                "exact orbit-cover recognition supports degree at most {maximum}, not {degree}"
            ),
            Self::MixedTableDegree {
                record_index,
                expected,
                actual,
            } => write!(
                output,
                "forbidden record {record_index} has degree {actual}, expected {expected}"
            ),
            Self::BaseClaimDegreeMismatch {
                table_degree,
                claim_degree,
            } => write!(
                output,
                "degree-{table_degree} tables cannot use a degree-{claim_degree} base claim"
            ),
            Self::VerifierDegreeMismatch {
                claim_degree,
                verifier_degree,
            } => write!(
                output,
                "base verifier degree {verifier_degree} does not match claim degree {claim_degree}"
            ),
            Self::VerifierFingerprintMismatch => {
                write!(output, "base verifier fingerprint does not match the claim")
            }
            Self::VerifierAssertionCountMismatch {
                claim_count,
                verifier_count,
            } => write!(
                output,
                "base verifier exposes {verifier_count} assertions, claim exposes {claim_count}"
            ),
            Self::BaseWitnessDegreeMismatch {
                witness_index,
                expected,
                actual,
            } => write!(
                output,
                "base witness {witness_index} has degree {actual}, expected {expected}"
            ),
            Self::BaseWitnessSetMismatch {
                expected,
                unique,
                duplicates,
                missing,
            } => write!(
                output,
                "base witness set has {unique} unique permutations and {duplicates} duplicates; expected {expected} with {missing} missing"
            ),
            Self::BaseAssertionImageCountMismatch {
                permutation,
                expected,
                actual,
            } => write!(
                output,
                "base witness {:?} maps {actual} assertions, expected {expected}",
                permutation.images()
            ),
            Self::BaseAssertionImageOutOfRange {
                permutation,
                source_assertion,
                target_assertion,
                assertion_count,
            } => write!(
                output,
                "base witness {:?} maps assertion {source_assertion} to {target_assertion}, outside 0..{assertion_count}",
                permutation.images()
            ),
            Self::DuplicateBaseAssertionImage {
                permutation,
                target_assertion,
            } => write!(
                output,
                "base witness {:?} maps multiple assertions to {target_assertion}",
                permutation.images()
            ),
            Self::BaseAssertionReplayRejected {
                permutation,
                source_assertion,
                target_assertion,
            } => write!(
                output,
                "base replay rejected {:?}: assertion {source_assertion} -> {target_assertion}",
                permutation.images()
            ),
            Self::PermutationEnumeration => {
                write!(output, "failed to enumerate the required permutation group")
            }
            Self::TableAction(error) => error.fmt(output),
            Self::OrbitCardinalityInconsistent {
                permutations,
                orbit_size,
            } => write!(
                output,
                "orbit size {orbit_size} does not divide group size {permutations}"
            ),
            Self::ForbiddenSetMismatch {
                missing_orbit_tables,
                out_of_orbit_tables,
            } => write!(
                output,
                "forbidden set misses {missing_orbit_tables} orbit tables and contains {out_of_orbit_tables} outsiders"
            ),
            Self::UniqueTableWitnessMismatch { image_index } => write!(
                output,
                "orbit witness for unique image {image_index} does not replay"
            ),
            Self::RecordWitnessMismatch { record_index } => write!(
                output,
                "orbit witness for forbidden record {record_index} does not replay"
            ),
            Self::CertificateMismatch => write!(
                output,
                "certificate differs from deterministic exhaustive reconstruction"
            ),
        }
    }
}

impl Error for OrbitCoverError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TableAction(error) => Some(error),
            _ => None,
        }
    }
}

/// Failure with the counters reached before recognition abstained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrbitCoverFailure {
    pub error: OrbitCoverError,
    pub telemetry: OrbitCoverTelemetry,
}

impl fmt::Display for OrbitCoverFailure {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(output)
    }
}

impl Error for OrbitCoverFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.error.source()
    }
}

/// Recognizes and certifies an exact full forbidden orbit under `S_n`.
///
/// Duplicate source records are accepted and individually witnessed because
/// they do not change set semantics.  All distinct records must equal the
/// generated orbit exactly.  The deterministic representative is the least
/// table and every stored permutation is the least witness in lexicographic
/// order.
pub fn recognize_full_forbidden_orbit<V: BaseActionVerifier>(
    forbidden_records: &[BinaryTable],
    base_claim: &BaseInvarianceClaim,
    verifier: &V,
) -> Result<OrbitCoverCertificate, OrbitCoverFailure> {
    let mut telemetry = OrbitCoverTelemetry {
        forbidden_records: forbidden_records.len(),
        ..OrbitCoverTelemetry::default()
    };
    let Some(first_record) = forbidden_records.first() else {
        return Err(failure(OrbitCoverError::EmptyForbiddenSet, &telemetry));
    };
    let degree = first_record.degree();
    telemetry.degree = degree;
    if degree > MAX_EXHAUSTIVE_DEGREE {
        return Err(failure(
            OrbitCoverError::DegreeTooLarge {
                degree,
                maximum: MAX_EXHAUSTIVE_DEGREE,
            },
            &telemetry,
        ));
    }
    telemetry.expected_permutations = checked_factorial(degree).ok_or_else(|| {
        failure(
            OrbitCoverError::DegreeTooLarge {
                degree,
                maximum: MAX_EXHAUSTIVE_DEGREE,
            },
            &telemetry,
        )
    })?;

    for (record_index, record) in forbidden_records.iter().enumerate() {
        if record.degree() != degree {
            return Err(failure(
                OrbitCoverError::MixedTableDegree {
                    record_index,
                    expected: degree,
                    actual: record.degree(),
                },
                &telemetry,
            ));
        }
    }
    let forbidden = forbidden_records.iter().cloned().collect::<BTreeSet<_>>();
    telemetry.unique_forbidden_tables = forbidden.len();
    telemetry.duplicate_forbidden_records = forbidden_records.len() - forbidden.len();

    let normalized_base = verify_base_invariance(degree, base_claim, verifier, &mut telemetry)?;
    let representative = forbidden
        .first()
        .expect("a nonempty record sequence has a nonempty table set")
        .clone();

    let permutations = LexicographicPermutations::new(degree)
        .map_err(|_| failure(OrbitCoverError::PermutationEnumeration, &telemetry))?;
    let mut generated = BTreeMap::<BinaryTable, CheckedPermutation>::new();
    for permutation in permutations {
        telemetry.orbit_permutations_enumerated += 1;
        let image = representative
            .conjugated_by(&permutation)
            .map_err(|error| failure(OrbitCoverError::TableAction(error), &telemetry))?;
        generated.entry(image).or_insert(permutation);
    }
    telemetry.unique_orbit_tables = generated.len();
    if generated.is_empty() || telemetry.expected_permutations % telemetry.unique_orbit_tables != 0
    {
        return Err(failure(
            OrbitCoverError::OrbitCardinalityInconsistent {
                permutations: telemetry.expected_permutations,
                orbit_size: telemetry.unique_orbit_tables,
            },
            &telemetry,
        ));
    }
    telemetry.stabilizer_size = telemetry.expected_permutations / telemetry.unique_orbit_tables;
    telemetry.missing_orbit_tables = generated
        .keys()
        .filter(|table| !forbidden.contains(*table))
        .count();
    telemetry.out_of_orbit_tables = forbidden
        .iter()
        .filter(|table| !generated.contains_key(*table))
        .count();
    if telemetry.missing_orbit_tables != 0 || telemetry.out_of_orbit_tables != 0 {
        return Err(failure(
            OrbitCoverError::ForbiddenSetMismatch {
                missing_orbit_tables: telemetry.missing_orbit_tables,
                out_of_orbit_tables: telemetry.out_of_orbit_tables,
            },
            &telemetry,
        ));
    }

    let mut image_witnesses = Vec::with_capacity(generated.len());
    for (image_index, (image, witness)) in generated.iter().enumerate() {
        let replayed = representative
            .conjugated_by(witness)
            .map_err(|error| failure(OrbitCoverError::TableAction(error), &telemetry))?;
        if &replayed != image {
            return Err(failure(
                OrbitCoverError::UniqueTableWitnessMismatch { image_index },
                &telemetry,
            ));
        }
        telemetry.unique_table_witnesses_replayed += 1;
        image_witnesses.push(OrbitImageWitness {
            image: image.clone(),
            seed_to_image: witness.clone(),
        });
    }

    let mut record_witnesses = Vec::with_capacity(forbidden_records.len());
    for (record_index, record) in forbidden_records.iter().enumerate() {
        let witness = generated
            .get(record)
            .expect("exact set equality gives every source record a witness")
            .clone();
        let replayed = representative
            .conjugated_by(&witness)
            .map_err(|error| failure(OrbitCoverError::TableAction(error), &telemetry))?;
        if &replayed != record {
            return Err(failure(
                OrbitCoverError::RecordWitnessMismatch { record_index },
                &telemetry,
            ));
        }
        telemetry.record_witnesses_replayed += 1;
        record_witnesses.push(ForbiddenRecordWitness {
            record_index,
            seed_to_record: witness,
        });
    }
    telemetry.exact_orbit_cover_verified = true;

    Ok(OrbitCoverCertificate {
        degree,
        representative,
        base_invariance: normalized_base,
        image_witnesses: image_witnesses.into_boxed_slice(),
        record_witnesses: record_witnesses.into_boxed_slice(),
        telemetry,
    })
}

/// Independently reconstructs a certificate and rejects any stored mismatch.
pub fn verify_orbit_cover_certificate<V: BaseActionVerifier>(
    certificate: &OrbitCoverCertificate,
    forbidden_records: &[BinaryTable],
    verifier: &V,
) -> Result<OrbitCoverTelemetry, OrbitCoverFailure> {
    let rebuilt =
        recognize_full_forbidden_orbit(forbidden_records, &certificate.base_invariance, verifier)?;
    let telemetry = rebuilt.telemetry.clone();
    if &rebuilt != certificate {
        return Err(failure(OrbitCoverError::CertificateMismatch, &telemetry));
    }
    Ok(telemetry)
}

fn verify_base_invariance<V: BaseActionVerifier>(
    degree: usize,
    claim: &BaseInvarianceClaim,
    verifier: &V,
    telemetry: &mut OrbitCoverTelemetry,
) -> Result<BaseInvarianceClaim, OrbitCoverFailure> {
    if claim.degree != degree {
        return Err(failure(
            OrbitCoverError::BaseClaimDegreeMismatch {
                table_degree: degree,
                claim_degree: claim.degree,
            },
            telemetry,
        ));
    }
    if verifier.degree() != claim.degree {
        return Err(failure(
            OrbitCoverError::VerifierDegreeMismatch {
                claim_degree: claim.degree,
                verifier_degree: verifier.degree(),
            },
            telemetry,
        ));
    }
    if verifier.fingerprint() != claim.fingerprint {
        return Err(failure(
            OrbitCoverError::VerifierFingerprintMismatch,
            telemetry,
        ));
    }
    if verifier.assertion_count() != claim.assertion_count {
        return Err(failure(
            OrbitCoverError::VerifierAssertionCountMismatch {
                claim_count: claim.assertion_count,
                verifier_count: verifier.assertion_count(),
            },
            telemetry,
        ));
    }

    telemetry.base_witness_records = claim.witnesses.len();
    let mut by_permutation = BTreeMap::<CheckedPermutation, BasePermutationWitness>::new();
    for (witness_index, witness) in claim.witnesses.iter().enumerate() {
        if witness.permutation.degree() != degree {
            return Err(failure(
                OrbitCoverError::BaseWitnessDegreeMismatch {
                    witness_index,
                    expected: degree,
                    actual: witness.permutation.degree(),
                },
                telemetry,
            ));
        }
        if by_permutation
            .insert(witness.permutation.clone(), witness.clone())
            .is_some()
        {
            telemetry.duplicate_base_permutations += 1;
        }
    }

    let expected = LexicographicPermutations::new(degree)
        .map_err(|_| failure(OrbitCoverError::PermutationEnumeration, telemetry))?
        .collect::<Vec<_>>();
    telemetry.missing_base_permutations = expected
        .iter()
        .filter(|permutation| !by_permutation.contains_key(*permutation))
        .count();
    if by_permutation.len() != telemetry.expected_permutations
        || telemetry.duplicate_base_permutations != 0
        || telemetry.missing_base_permutations != 0
    {
        return Err(failure(
            OrbitCoverError::BaseWitnessSetMismatch {
                expected: telemetry.expected_permutations,
                unique: by_permutation.len(),
                duplicates: telemetry.duplicate_base_permutations,
                missing: telemetry.missing_base_permutations,
            },
            telemetry,
        ));
    }

    let mut normalized = Vec::with_capacity(expected.len());
    for permutation in expected {
        let witness = by_permutation
            .remove(&permutation)
            .expect("the exact witness set contains every expected permutation");
        if witness.assertion_images.len() != claim.assertion_count {
            return Err(failure(
                OrbitCoverError::BaseAssertionImageCountMismatch {
                    permutation,
                    expected: claim.assertion_count,
                    actual: witness.assertion_images.len(),
                },
                telemetry,
            ));
        }
        let mut seen_targets = vec![false; claim.assertion_count];
        for (source_assertion, &target_assertion) in witness.assertion_images.iter().enumerate() {
            if target_assertion >= claim.assertion_count {
                return Err(failure(
                    OrbitCoverError::BaseAssertionImageOutOfRange {
                        permutation,
                        source_assertion,
                        target_assertion,
                        assertion_count: claim.assertion_count,
                    },
                    telemetry,
                ));
            }
            if seen_targets[target_assertion] {
                return Err(failure(
                    OrbitCoverError::DuplicateBaseAssertionImage {
                        permutation,
                        target_assertion,
                    },
                    telemetry,
                ));
            }
            seen_targets[target_assertion] = true;
        }
        for (source_assertion, &target_assertion) in witness.assertion_images.iter().enumerate() {
            if !verifier.transformed_assertion_matches(
                &witness.permutation,
                source_assertion,
                target_assertion,
            ) {
                return Err(failure(
                    OrbitCoverError::BaseAssertionReplayRejected {
                        permutation,
                        source_assertion,
                        target_assertion,
                    },
                    telemetry,
                ));
            }
            telemetry.base_assertion_images_replayed += 1;
        }
        telemetry.base_permutations_replayed += 1;
        normalized.push(witness);
    }
    telemetry.base_invariance_verified = true;
    Ok(BaseInvarianceClaim::new(
        claim.degree,
        claim.fingerprint,
        claim.assertion_count,
        normalized,
    ))
}

fn checked_factorial(value: usize) -> Option<usize> {
    (1..=value).try_fold(1usize, |product, factor| product.checked_mul(factor))
}

fn failure(error: OrbitCoverError, telemetry: &OrbitCoverTelemetry) -> OrbitCoverFailure {
    OrbitCoverFailure {
        error,
        telemetry: telemetry.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINGERPRINT: BaseFingerprint = BaseFingerprint::new([0x5a; 32]);

    struct PointAssertionVerifier {
        degree: usize,
        fingerprint: BaseFingerprint,
    }

    impl BaseActionVerifier for PointAssertionVerifier {
        fn degree(&self) -> usize {
            self.degree
        }

        fn fingerprint(&self) -> BaseFingerprint {
            self.fingerprint
        }

        fn assertion_count(&self) -> usize {
            self.degree
        }

        fn transformed_assertion_matches(
            &self,
            permutation: &CheckedPermutation,
            source_assertion: usize,
            target_assertion: usize,
        ) -> bool {
            permutation.image(source_assertion) == Some(target_assertion)
        }
    }

    struct EmptyBaseVerifier {
        degree: usize,
    }

    impl BaseActionVerifier for EmptyBaseVerifier {
        fn degree(&self) -> usize {
            self.degree
        }

        fn fingerprint(&self) -> BaseFingerprint {
            FINGERPRINT
        }

        fn assertion_count(&self) -> usize {
            0
        }

        fn transformed_assertion_matches(
            &self,
            _permutation: &CheckedPermutation,
            _source_assertion: usize,
            _target_assertion: usize,
        ) -> bool {
            false
        }
    }

    fn point_base_claim(degree: usize) -> BaseInvarianceClaim {
        let witnesses = LexicographicPermutations::new(degree)
            .unwrap()
            .map(|permutation| {
                let images = permutation.images().to_vec();
                BasePermutationWitness::new(permutation, images)
            })
            .collect();
        BaseInvarianceClaim::new(degree, FINGERPRINT, degree, witnesses)
    }

    fn empty_base_claim(degree: usize) -> BaseInvarianceClaim {
        let witnesses = LexicographicPermutations::new(degree)
            .unwrap()
            .map(|permutation| BasePermutationWitness::new(permutation, Vec::new()))
            .collect();
        BaseInvarianceClaim::new(degree, FINGERPRINT, 0, witnesses)
    }

    fn orbit(table: &BinaryTable) -> Vec<BinaryTable> {
        LexicographicPermutations::new(table.degree())
            .unwrap()
            .map(|permutation| table.conjugated_by(&permutation).unwrap())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Output frequencies 4,5,...,10 are all distinct and sum to 49, so every
    /// automorphism fixes every value.  The degree-seven orbit is therefore
    /// free and has exactly 7! members, matching the measured qg7 shape.
    fn rigid_degree_seven_table() -> BinaryTable {
        let entries = (0..7)
            .flat_map(|value| std::iter::repeat_n(value, value + 4))
            .collect();
        BinaryTable::new(7, entries).unwrap()
    }

    fn rigid_degree_three_table() -> BinaryTable {
        BinaryTable::new(3, vec![0, 0, 1, 1, 1, 2, 2, 2, 2]).unwrap()
    }

    #[test]
    fn certifies_a_qg7_sized_free_orbit_with_every_witness() {
        let seed = rigid_degree_seven_table();
        let mut records = orbit(&seed);
        assert_eq!(records.len(), 5_040);
        records.reverse();
        records.push(records[17].clone());

        let verifier = PointAssertionVerifier {
            degree: 7,
            fingerprint: FINGERPRINT,
        };
        let certificate =
            recognize_full_forbidden_orbit(&records, &point_base_claim(7), &verifier).unwrap();
        let telemetry = certificate.telemetry();
        assert_eq!(certificate.representative(), orbit(&seed).first().unwrap());
        assert_eq!(telemetry.expected_permutations, 5_040);
        assert_eq!(telemetry.base_permutations_replayed, 5_040);
        assert_eq!(telemetry.base_assertion_images_replayed, 35_280);
        assert_eq!(telemetry.unique_forbidden_tables, 5_040);
        assert_eq!(telemetry.duplicate_forbidden_records, 1);
        assert_eq!(telemetry.unique_orbit_tables, 5_040);
        assert_eq!(telemetry.stabilizer_size, 1);
        assert_eq!(telemetry.unique_table_witnesses_replayed, 5_040);
        assert_eq!(telemetry.record_witnesses_replayed, 5_041);
        assert!(telemetry.base_invariance_verified);
        assert!(telemetry.exact_orbit_cover_verified);
        assert_eq!(
            certificate.verify_exact(&records, &verifier).unwrap(),
            *telemetry
        );
    }

    #[test]
    fn rejects_missing_and_out_of_orbit_tables() {
        let seed = rigid_degree_three_table();
        let mut records = orbit(&seed);
        assert_eq!(records.len(), 6);
        records.pop();
        records.push(BinaryTable::from_fn(3, |left, _right| left).unwrap());
        let verifier = PointAssertionVerifier {
            degree: 3,
            fingerprint: FINGERPRINT,
        };
        let failure =
            recognize_full_forbidden_orbit(&records, &point_base_claim(3), &verifier).unwrap_err();
        assert_eq!(
            failure.error,
            OrbitCoverError::ForbiddenSetMismatch {
                missing_orbit_tables: 1,
                out_of_orbit_tables: 1,
            }
        );
        assert!(!failure.telemetry.exact_orbit_cover_verified);
    }

    #[test]
    fn rejects_a_missing_base_permutation() {
        let table = BinaryTable::from_fn(3, |left, _right| left).unwrap();
        let mut claim = point_base_claim(3);
        claim.witnesses = claim.witnesses[..5].to_vec().into_boxed_slice();
        let verifier = PointAssertionVerifier {
            degree: 3,
            fingerprint: FINGERPRINT,
        };
        let failure = recognize_full_forbidden_orbit(&[table], &claim, &verifier).unwrap_err();
        assert!(matches!(
            failure.error,
            OrbitCoverError::BaseWitnessSetMismatch {
                expected: 6,
                unique: 5,
                duplicates: 0,
                missing: 1,
            }
        ));
    }

    #[test]
    fn rejects_non_bijective_and_semantically_false_base_maps() {
        let table = BinaryTable::from_fn(3, |left, _right| left).unwrap();
        let verifier = PointAssertionVerifier {
            degree: 3,
            fingerprint: FINGERPRINT,
        };

        let mut non_bijective = point_base_claim(3);
        non_bijective.witnesses[0].assertion_images[1] = 0;
        let failure = recognize_full_forbidden_orbit(&[table.clone()], &non_bijective, &verifier)
            .unwrap_err();
        assert!(matches!(
            failure.error,
            OrbitCoverError::DuplicateBaseAssertionImage { .. }
        ));

        let mut false_map = point_base_claim(3);
        false_map.witnesses[1].assertion_images.swap(0, 1);
        let failure = recognize_full_forbidden_orbit(&[table], &false_map, &verifier).unwrap_err();
        assert!(matches!(
            failure.error,
            OrbitCoverError::BaseAssertionReplayRejected { .. }
        ));
    }

    #[test]
    fn verifier_context_must_match_the_bound_base() {
        let table = BinaryTable::from_fn(2, |left, _right| left).unwrap();
        let verifier = PointAssertionVerifier {
            degree: 2,
            fingerprint: BaseFingerprint::new([0xa5; 32]),
        };
        let failure =
            recognize_full_forbidden_orbit(&[table], &point_base_claim(2), &verifier).unwrap_err();
        assert_eq!(failure.error, OrbitCoverError::VerifierFingerprintMismatch);
        assert_eq!(failure.telemetry.orbit_permutations_enumerated, 0);
    }

    #[test]
    fn exhausts_all_s8_witnesses_even_for_a_singleton_orbit() {
        let table = BinaryTable::from_fn(8, |left, _right| left).unwrap();
        let verifier = EmptyBaseVerifier { degree: 8 };
        let certificate =
            recognize_full_forbidden_orbit(&[table], &empty_base_claim(8), &verifier).unwrap();
        assert_eq!(certificate.telemetry.expected_permutations, 40_320);
        assert_eq!(certificate.telemetry.base_permutations_replayed, 40_320);
        assert_eq!(certificate.telemetry.orbit_permutations_enumerated, 40_320);
        assert_eq!(certificate.telemetry.unique_orbit_tables, 1);
        assert_eq!(certificate.telemetry.stabilizer_size, 40_320);
        assert_eq!(certificate.image_witnesses.len(), 1);
        assert!(certificate.image_witnesses[0].seed_to_image().is_identity());
    }

    #[test]
    fn degree_above_reference_cap_fails_before_enumeration() {
        let table = BinaryTable::from_fn(9, |left, _right| left).unwrap();
        let claim = BaseInvarianceClaim::new(9, FINGERPRINT, 0, Vec::new());
        let verifier = EmptyBaseVerifier { degree: 9 };
        let failure = recognize_full_forbidden_orbit(&[table], &claim, &verifier).unwrap_err();
        assert_eq!(
            failure.error,
            OrbitCoverError::DegreeTooLarge {
                degree: 9,
                maximum: 8,
            }
        );
        assert_eq!(failure.telemetry.orbit_permutations_enumerated, 0);
    }

    #[test]
    fn tampered_certificate_is_rejected_by_exact_reconstruction() {
        let seed = rigid_degree_three_table();
        let records = orbit(&seed);
        let verifier = PointAssertionVerifier {
            degree: 3,
            fingerprint: FINGERPRINT,
        };
        let mut certificate =
            recognize_full_forbidden_orbit(&records, &point_base_claim(3), &verifier).unwrap();
        certificate.image_witnesses[0].seed_to_image =
            CheckedPermutation::new(vec![1, 0, 2]).unwrap();
        let failure = certificate.verify_exact(&records, &verifier).unwrap_err();
        assert_eq!(failure.error, OrbitCoverError::CertificateMismatch);
    }
}
