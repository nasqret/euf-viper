#![forbid(unsafe_code)]

//! Replayable proof that a finite-table source entails the Latin property.

use crate::finite_table_source::{
    FiniteTableSource, PartialTableError, StructuralGeneratorBaseRelabelingCertificate,
};
use crate::orbit_cover::GeneratorOrbitCoverCertificate;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LatinAxis {
    Row,
    Column,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LatinCollisionWitness {
    pub(crate) axis: LatinAxis,
    pub(crate) fixed: usize,
    pub(crate) first: usize,
    pub(crate) second: usize,
    pub(crate) repeated_value: usize,
    pub(crate) false_assertion_ordinal: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum LatinEvidenceKind {
    #[default]
    ExhaustiveCollisions,
    SymmetryClasses,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct LatinCertificateTelemetry {
    pub(crate) evidence_kind: LatinEvidenceKind,
    pub(crate) degree: usize,
    pub(crate) collision_obligations: usize,
    pub(crate) representative_obligations: usize,
    pub(crate) replayed_obligations: usize,
    pub(crate) symmetry_derived_obligations: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LatinImplicationCertificate {
    degree: usize,
    witnesses: Box<[LatinCollisionWitness]>,
    telemetry: LatinCertificateTelemetry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SymmetryLatinWitness {
    class_key: u8,
    collision: LatinCollisionWitness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SymmetryLatinImplicationCertificate {
    degree: usize,
    witnesses: Box<[SymmetryLatinWitness]>,
    telemetry: LatinCertificateTelemetry,
}

#[derive(Debug)]
pub(crate) enum LatinCertificateError {
    InvalidDegree {
        degree: usize,
    },
    ObligationCountOverflow,
    AllocationFailed {
        requested: usize,
    },
    SourceDoesNotImplyLatin {
        axis: LatinAxis,
        fixed: usize,
        first: usize,
        second: usize,
        repeated_value: usize,
    },
    SourceEvaluation(PartialTableError),
    CertificateMismatch(&'static str),
}

impl fmt::Display for LatinCertificateError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDegree { degree } => {
                write!(output, "Latin implication degree {degree} is outside 1..=8")
            }
            Self::ObligationCountOverflow => {
                output.write_str("Latin implication obligation count overflowed")
            }
            Self::AllocationFailed { requested } => write!(
                output,
                "could not allocate {requested} Latin implication witnesses"
            ),
            Self::SourceDoesNotImplyLatin {
                axis,
                fixed,
                first,
                second,
                repeated_value,
            } => write!(
                output,
                "source permits a {axis:?} collision at fixed index {fixed}, positions {first}/{second}, value {repeated_value}"
            ),
            Self::SourceEvaluation(error) => error.fmt(output),
            Self::CertificateMismatch(detail) => {
                write!(output, "Latin implication certificate mismatch: {detail}")
            }
        }
    }
}

impl Error for LatinCertificateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SourceEvaluation(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PartialTableError> for LatinCertificateError {
    fn from(error: PartialTableError) -> Self {
        Self::SourceEvaluation(error)
    }
}

fn full_mask(degree: usize) -> u8 {
    if degree == u8::BITS as usize {
        u8::MAX
    } else {
        (1u8 << degree) - 1
    }
}

fn obligation_count(degree: usize) -> Result<usize, LatinCertificateError> {
    degree
        .checked_mul(degree.saturating_sub(1))
        .and_then(|value| value.checked_mul(degree))
        .and_then(|value| value.checked_mul(degree))
        .ok_or(LatinCertificateError::ObligationCountOverflow)
}

fn collision_domains(
    degree: usize,
    axis: LatinAxis,
    fixed: usize,
    first: usize,
    second: usize,
    repeated_value: usize,
) -> Vec<u8> {
    let mut domains = vec![full_mask(degree); degree * degree];
    let (first_cell, second_cell) = match axis {
        LatinAxis::Row => (fixed * degree + first, fixed * degree + second),
        LatinAxis::Column => (first * degree + fixed, second * degree + fixed),
    };
    let singleton = 1u8 << repeated_value;
    domains[first_cell] = singleton;
    domains[second_cell] = singleton;
    domains
}

fn canonical_obligations(
    degree: usize,
) -> impl Iterator<Item = (LatinAxis, usize, usize, usize, usize)> {
    [LatinAxis::Row, LatinAxis::Column]
        .into_iter()
        .flat_map(move |axis| {
            (0..degree).flat_map(move |fixed| {
                (0..degree).flat_map(move |first| {
                    (first + 1..degree).flat_map(move |second| {
                        (0..degree)
                            .map(move |repeated_value| (axis, fixed, first, second, repeated_value))
                    })
                })
            })
        })
}

fn equality_pattern(values: [usize; 4]) -> u8 {
    let mut pattern = 0u8;
    let mut bit = 0u8;
    for left in 0..4 {
        for right in left + 1..4 {
            if values[left] == values[right] {
                pattern |= 1u8 << bit;
            }
            bit += 1;
        }
    }
    pattern
}

/// Complete orbit key for a Latin collision under simultaneous carrier
/// relabeling.  The two colliding positions are unordered, so their swapped
/// equality pattern is normalized as well.
fn collision_class(
    axis: LatinAxis,
    fixed: usize,
    first: usize,
    second: usize,
    repeated_value: usize,
) -> u8 {
    let direct = equality_pattern([fixed, first, second, repeated_value]);
    let swapped = equality_pattern([fixed, second, first, repeated_value]);
    direct.min(swapped)
        | match axis {
            LatinAxis::Row => 0,
            LatinAxis::Column => 1 << 6,
        }
}

fn verify_symmetry_binding(
    source: &FiniteTableSource<'_>,
    relabeling: &StructuralGeneratorBaseRelabelingCertificate,
    orbit: &GeneratorOrbitCoverCertificate,
) -> Result<(), LatinCertificateError> {
    let degree = source.domain().len();
    if relabeling.claim().degree() != degree || orbit.degree() != degree {
        return Err(LatinCertificateError::CertificateMismatch(
            "symmetry proof degree differs from source degree",
        ));
    }
    if orbit.base_invariance() != relabeling.claim()
        || !orbit.telemetry().base_invariance_verified
        || !orbit.telemetry().exact_orbit_cover_verified
    {
        return Err(LatinCertificateError::CertificateMismatch(
            "Latin compression is not bound to the verified source action",
        ));
    }
    Ok(())
}

/// Builds a certificate by proving every possible duplicate in every row and
/// column impossible under the separated source base.
pub(crate) fn certify_latin_implication(
    source: &FiniteTableSource<'_>,
) -> Result<LatinImplicationCertificate, LatinCertificateError> {
    let degree = source.domain().len();
    if degree == 0 || degree > u8::BITS as usize {
        return Err(LatinCertificateError::InvalidDegree { degree });
    }
    let expected = obligation_count(degree)?;
    let mut witnesses = Vec::new();
    witnesses
        .try_reserve_exact(expected)
        .map_err(|_| LatinCertificateError::AllocationFailed {
            requested: expected,
        })?;
    for (axis, fixed, first, second, repeated_value) in canonical_obligations(degree) {
        let domains = collision_domains(degree, axis, fixed, first, second, repeated_value);
        let Some(false_assertion_ordinal) =
            source.first_definitely_false_base_assertion(&domains)?
        else {
            return Err(LatinCertificateError::SourceDoesNotImplyLatin {
                axis,
                fixed,
                first,
                second,
                repeated_value,
            });
        };
        witnesses.push(LatinCollisionWitness {
            axis,
            fixed,
            first,
            second,
            repeated_value,
            false_assertion_ordinal,
        });
    }
    if witnesses.len() != expected {
        return Err(LatinCertificateError::CertificateMismatch(
            "builder produced the wrong number of obligations",
        ));
    }
    Ok(LatinImplicationCertificate {
        degree,
        witnesses: witnesses.into_boxed_slice(),
        telemetry: LatinCertificateTelemetry {
            evidence_kind: LatinEvidenceKind::ExhaustiveCollisions,
            degree,
            collision_obligations: expected,
            representative_obligations: expected,
            replayed_obligations: expected,
            symmetry_derived_obligations: 0,
        },
    })
}

/// Replays every witness from source semantics and canonical obligation order.
pub(crate) fn verify_latin_implication(
    source: &FiniteTableSource<'_>,
    certificate: &LatinImplicationCertificate,
) -> Result<LatinCertificateTelemetry, LatinCertificateError> {
    let degree = source.domain().len();
    if certificate.degree != degree {
        return Err(LatinCertificateError::CertificateMismatch(
            "certificate degree differs from source degree",
        ));
    }
    let expected = obligation_count(degree)?;
    if certificate.witnesses.len() != expected {
        return Err(LatinCertificateError::CertificateMismatch(
            "certificate has the wrong number of witnesses",
        ));
    }
    let mut replayed = 0usize;
    for (expected_fields, witness) in
        canonical_obligations(degree).zip(certificate.witnesses.iter())
    {
        let (axis, fixed, first, second, repeated_value) = expected_fields;
        if (
            witness.axis,
            witness.fixed,
            witness.first,
            witness.second,
            witness.repeated_value,
        ) != (axis, fixed, first, second, repeated_value)
        {
            return Err(LatinCertificateError::CertificateMismatch(
                "witness sequence is not canonical",
            ));
        }
        let domains = collision_domains(degree, axis, fixed, first, second, repeated_value);
        let observed = source.first_definitely_false_base_assertion(&domains)?;
        if observed != Some(witness.false_assertion_ordinal) {
            return Err(LatinCertificateError::CertificateMismatch(
                "source replay selected a different false assertion",
            ));
        }
        replayed += 1;
    }
    let telemetry = LatinCertificateTelemetry {
        evidence_kind: LatinEvidenceKind::ExhaustiveCollisions,
        degree,
        collision_obligations: expected,
        representative_obligations: expected,
        replayed_obligations: replayed,
        symmetry_derived_obligations: 0,
    };
    if telemetry != certificate.telemetry {
        return Err(LatinCertificateError::CertificateMismatch(
            "stored telemetry differs from replay",
        ));
    }
    Ok(telemetry)
}

/// Proves all Latin collision obligations from one source replay per orbit of
/// the verified carrier action.
pub(crate) fn certify_latin_implication_by_symmetry(
    source: &FiniteTableSource<'_>,
    relabeling: &StructuralGeneratorBaseRelabelingCertificate,
    orbit: &GeneratorOrbitCoverCertificate,
) -> Result<SymmetryLatinImplicationCertificate, LatinCertificateError> {
    verify_symmetry_binding(source, relabeling, orbit)?;
    let degree = source.domain().len();
    if degree == 0 || degree > u8::BITS as usize {
        return Err(LatinCertificateError::InvalidDegree { degree });
    }
    let expected = obligation_count(degree)?;
    let mut representatives = BTreeMap::new();
    for fields @ (axis, fixed, first, second, repeated_value) in canonical_obligations(degree) {
        let class = collision_class(axis, fixed, first, second, repeated_value);
        representatives.entry(class).or_insert(fields);
    }

    let mut witnesses = Vec::new();
    witnesses
        .try_reserve_exact(representatives.len())
        .map_err(|_| LatinCertificateError::AllocationFailed {
            requested: representatives.len(),
        })?;
    let mut scratch = source.partial_evaluation_scratch();
    for (&class_key, &(axis, fixed, first, second, repeated_value)) in &representatives {
        let domains = collision_domains(degree, axis, fixed, first, second, repeated_value);
        let Some(false_assertion_ordinal) =
            source.first_definitely_false_base_assertion_with_scratch(&domains, &mut scratch)?
        else {
            return Err(LatinCertificateError::SourceDoesNotImplyLatin {
                axis,
                fixed,
                first,
                second,
                repeated_value,
            });
        };
        witnesses.push(SymmetryLatinWitness {
            class_key,
            collision: LatinCollisionWitness {
                axis,
                fixed,
                first,
                second,
                repeated_value,
                false_assertion_ordinal,
            },
        });
    }
    let representative_obligations = witnesses.len();
    Ok(SymmetryLatinImplicationCertificate {
        degree,
        witnesses: witnesses.into_boxed_slice(),
        telemetry: LatinCertificateTelemetry {
            evidence_kind: LatinEvidenceKind::SymmetryClasses,
            degree,
            collision_obligations: expected,
            representative_obligations,
            replayed_obligations: representative_obligations,
            symmetry_derived_obligations: expected - representative_obligations,
        },
    })
}

/// Reconstructs the canonical collision classes and replays every stored
/// representative directly against the source evaluator.
pub(crate) fn verify_latin_implication_by_symmetry(
    source: &FiniteTableSource<'_>,
    relabeling: &StructuralGeneratorBaseRelabelingCertificate,
    orbit: &GeneratorOrbitCoverCertificate,
    certificate: &SymmetryLatinImplicationCertificate,
) -> Result<LatinCertificateTelemetry, LatinCertificateError> {
    verify_symmetry_binding(source, relabeling, orbit)?;
    let degree = source.domain().len();
    if certificate.degree != degree {
        return Err(LatinCertificateError::CertificateMismatch(
            "symmetry Latin certificate degree differs from source degree",
        ));
    }
    let expected = obligation_count(degree)?;
    let mut representatives = BTreeMap::new();
    for fields @ (axis, fixed, first, second, repeated_value) in canonical_obligations(degree) {
        let class = collision_class(axis, fixed, first, second, repeated_value);
        representatives.entry(class).or_insert(fields);
    }
    if certificate.witnesses.len() != representatives.len() {
        return Err(LatinCertificateError::CertificateMismatch(
            "symmetry Latin certificate has the wrong class count",
        ));
    }

    let mut scratch = source.partial_evaluation_scratch();
    let mut replayed = 0usize;
    for ((&expected_class, &expected_fields), witness) in
        representatives.iter().zip(certificate.witnesses.iter())
    {
        let (axis, fixed, first, second, repeated_value) = expected_fields;
        if witness.class_key != expected_class
            || (
                witness.collision.axis,
                witness.collision.fixed,
                witness.collision.first,
                witness.collision.second,
                witness.collision.repeated_value,
            ) != (axis, fixed, first, second, repeated_value)
        {
            return Err(LatinCertificateError::CertificateMismatch(
                "symmetry Latin witnesses are missing, duplicated, or noncanonical",
            ));
        }
        let domains = collision_domains(degree, axis, fixed, first, second, repeated_value);
        let observed =
            source.first_definitely_false_base_assertion_with_scratch(&domains, &mut scratch)?;
        if observed != Some(witness.collision.false_assertion_ordinal) {
            return Err(LatinCertificateError::CertificateMismatch(
                "symmetry Latin representative replay selected a different assertion",
            ));
        }
        replayed += 1;
    }
    let telemetry = LatinCertificateTelemetry {
        evidence_kind: LatinEvidenceKind::SymmetryClasses,
        degree,
        collision_obligations: expected,
        representative_obligations: representatives.len(),
        replayed_obligations: replayed,
        symmetry_derived_obligations: expected - representatives.len(),
    };
    if telemetry != certificate.telemetry {
        return Err(LatinCertificateError::CertificateMismatch(
            "stored symmetry Latin telemetry differs from replay",
        ));
    }
    Ok(telemetry)
}
