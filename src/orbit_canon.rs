//! Exact reference canonization for finite binary tables.
//!
//! A table `t` of degree `n` is acted on by a permutation `p` through
//! simultaneous relabeling of both arguments and the result:
//!
//! ```text
//! (p . t)(p(x), p(y)) = p(t(x, y)).
//! ```
//!
//! The canonical representative is the lexicographically least row-major
//! table in the resulting `S_n` orbit.  If several permutations produce that
//! representative, the lexicographically least permutation image vector is
//! selected as the witness.  These two tie-breaks make the output independent
//! of traversal details.
//!
//! [`ExhaustiveCanonicalizer`] is deliberately a small reference oracle.  Its
//! public [`BinaryTableCanonicalizer`] contract is the replacement boundary
//! for a future stabilizer-chain implementation.

use std::cmp::Ordering;
use std::error::Error;
use std::fmt;

/// Largest degree accepted by the exhaustive reference implementation.
pub const MAX_EXHAUSTIVE_DEGREE: usize = 8;

/// A total, checked permutation of `0..degree`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheckedPermutation {
    images: Box<[usize]>,
}

impl CheckedPermutation {
    /// Checks that `images` is a bijection of `0..images.len()`.
    pub fn new(images: Vec<usize>) -> Result<Self, PermutationError> {
        let degree = images.len();
        let mut first_preimage = vec![None; degree];

        for (position, &image) in images.iter().enumerate() {
            if image >= degree {
                return Err(PermutationError::ImageOutOfRange {
                    position,
                    image,
                    degree,
                });
            }
            if let Some(first_position) = first_preimage[image] {
                return Err(PermutationError::DuplicateImage {
                    image,
                    first_position,
                    second_position: position,
                });
            }
            first_preimage[image] = Some(position);
        }

        Ok(Self {
            images: images.into_boxed_slice(),
        })
    }

    /// Returns the identity permutation of the requested degree.
    pub fn identity(degree: usize) -> Self {
        Self {
            images: (0..degree).collect::<Vec<_>>().into_boxed_slice(),
        }
    }

    pub fn degree(&self) -> usize {
        self.images.len()
    }

    pub fn images(&self) -> &[usize] {
        &self.images
    }

    /// Returns the image of `point`, or `None` when the point is outside the
    /// permutation's domain.
    pub fn image(&self, point: usize) -> Option<usize> {
        self.images.get(point).copied()
    }

    pub fn is_identity(&self) -> bool {
        self.images
            .iter()
            .enumerate()
            .all(|(point, &image)| point == image)
    }

    pub fn inverse(&self) -> Self {
        let mut inverse = vec![0; self.degree()];
        for (point, &image) in self.images.iter().enumerate() {
            inverse[image] = point;
        }
        Self {
            images: inverse.into_boxed_slice(),
        }
    }

    /// Returns `self o right`: first apply `right`, then apply `self`.
    pub fn compose(&self, right: &Self) -> Result<Self, PermutationError> {
        if self.degree() != right.degree() {
            return Err(PermutationError::DegreeMismatch {
                left_degree: self.degree(),
                right_degree: right.degree(),
            });
        }

        let images = right
            .images
            .iter()
            .map(|&image| self.images[image])
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(Self { images })
    }
}

impl TryFrom<Vec<usize>> for CheckedPermutation {
    type Error = PermutationError;

    fn try_from(images: Vec<usize>) -> Result<Self, Self::Error> {
        Self::new(images)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermutationError {
    ImageOutOfRange {
        position: usize,
        image: usize,
        degree: usize,
    },
    DuplicateImage {
        image: usize,
        first_position: usize,
        second_position: usize,
    },
    DegreeMismatch {
        left_degree: usize,
        right_degree: usize,
    },
}

impl fmt::Display for PermutationError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImageOutOfRange {
                position,
                image,
                degree,
            } => write!(
                output,
                "permutation image {image} at position {position} is outside 0..{degree}"
            ),
            Self::DuplicateImage {
                image,
                first_position,
                second_position,
            } => write!(
                output,
                "permutation image {image} occurs at positions {first_position} and {second_position}"
            ),
            Self::DegreeMismatch {
                left_degree,
                right_degree,
            } => write!(
                output,
                "cannot compose permutations of degrees {left_degree} and {right_degree}"
            ),
        }
    }
}

impl Error for PermutationError {}

/// A total binary operation on the nonempty carrier `0..degree`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BinaryTable {
    degree: usize,
    entries: Box<[usize]>,
}

impl BinaryTable {
    /// Constructs a row-major table and checks its shape and range.
    pub fn new(degree: usize, entries: Vec<usize>) -> Result<Self, TableError> {
        if degree == 0 {
            return Err(TableError::EmptyDomain);
        }
        let expected = degree
            .checked_mul(degree)
            .ok_or(TableError::SizeOverflow { degree })?;
        if entries.len() != expected {
            return Err(TableError::WrongEntryCount {
                degree,
                expected,
                actual: entries.len(),
            });
        }
        for (index, &value) in entries.iter().enumerate() {
            if value >= degree {
                return Err(TableError::ValueOutOfRange {
                    index,
                    value,
                    degree,
                });
            }
        }

        Ok(Self {
            degree,
            entries: entries.into_boxed_slice(),
        })
    }

    /// Constructs and checks a table generated in row-major order.
    pub fn from_fn(
        degree: usize,
        mut value: impl FnMut(usize, usize) -> usize,
    ) -> Result<Self, TableError> {
        let capacity = degree
            .checked_mul(degree)
            .ok_or(TableError::SizeOverflow { degree })?;
        let mut entries = Vec::with_capacity(capacity);
        for left in 0..degree {
            for right in 0..degree {
                entries.push(value(left, right));
            }
        }
        Self::new(degree, entries)
    }

    pub fn degree(&self) -> usize {
        self.degree
    }

    pub fn entries(&self) -> &[usize] {
        &self.entries
    }

    pub fn get(&self, left: usize, right: usize) -> Option<usize> {
        if left >= self.degree || right >= self.degree {
            return None;
        }
        Some(self.entries[left * self.degree + right])
    }

    /// Applies simultaneous relabeling to both arguments and the result.
    pub fn conjugated_by(
        &self,
        permutation: &CheckedPermutation,
    ) -> Result<Self, TableActionError> {
        if self.degree != permutation.degree() {
            return Err(TableActionError::DegreeMismatch {
                table_degree: self.degree,
                permutation_degree: permutation.degree(),
            });
        }

        let mut entries = vec![0; self.entries.len()];
        for left in 0..self.degree {
            let new_left = permutation.images[left];
            for right in 0..self.degree {
                let new_right = permutation.images[right];
                let old_value = self.entries[left * self.degree + right];
                let new_value = permutation.images[old_value];
                entries[new_left * self.degree + new_right] = new_value;
            }
        }

        Ok(Self {
            degree: self.degree,
            entries: entries.into_boxed_slice(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableError {
    EmptyDomain,
    SizeOverflow {
        degree: usize,
    },
    WrongEntryCount {
        degree: usize,
        expected: usize,
        actual: usize,
    },
    ValueOutOfRange {
        index: usize,
        value: usize,
        degree: usize,
    },
}

impl fmt::Display for TableError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDomain => {
                write!(output, "a finite binary table must have a nonempty domain")
            }
            Self::SizeOverflow { degree } => {
                write!(output, "table size for degree {degree} overflows usize")
            }
            Self::WrongEntryCount {
                degree,
                expected,
                actual,
            } => write!(
                output,
                "degree-{degree} table needs {expected} entries, but received {actual}"
            ),
            Self::ValueOutOfRange {
                index,
                value,
                degree,
            } => write!(
                output,
                "table value {value} at index {index} is outside 0..{degree}"
            ),
        }
    }
}

impl Error for TableError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableActionError {
    DegreeMismatch {
        table_degree: usize,
        permutation_degree: usize,
    },
}

impl fmt::Display for TableActionError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DegreeMismatch {
                table_degree,
                permutation_degree,
            } => write!(
                output,
                "cannot act on a degree-{table_degree} table with a degree-{permutation_degree} permutation"
            ),
        }
    }
}

impl Error for TableActionError {}

/// Lexicographic iterator over every checked permutation of a small degree.
#[derive(Debug, Clone)]
pub struct LexicographicPermutations {
    next_images: Option<Vec<usize>>,
}

impl LexicographicPermutations {
    pub fn new(degree: usize) -> Result<Self, CanonicalizationError> {
        if degree > MAX_EXHAUSTIVE_DEGREE {
            return Err(CanonicalizationError::DegreeTooLarge {
                degree,
                maximum: MAX_EXHAUSTIVE_DEGREE,
            });
        }
        Ok(Self {
            next_images: Some((0..degree).collect()),
        })
    }
}

impl Iterator for LexicographicPermutations {
    type Item = CheckedPermutation;

    fn next(&mut self) -> Option<Self::Item> {
        let images = self.next_images.take()?;
        let mut successor = images.clone();
        if advance_lexicographic_permutation(&mut successor) {
            self.next_images = Some(successor);
        }
        Some(CheckedPermutation {
            images: images.into_boxed_slice(),
        })
    }
}

fn advance_lexicographic_permutation(values: &mut [usize]) -> bool {
    let Some(pivot) = (1..values.len())
        .rev()
        .find(|&index| values[index - 1] < values[index])
        .map(|index| index - 1)
    else {
        return false;
    };

    let successor = (pivot + 1..values.len())
        .rev()
        .find(|&index| values[pivot] < values[index])
        .expect("a lexicographic pivot always has a successor");
    values.swap(pivot, successor);
    values[pivot + 1..].reverse();
    true
}

/// Result of exact canonization, including an original-to-canonical witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalForm {
    representative: BinaryTable,
    witness: CheckedPermutation,
}

impl CanonicalForm {
    pub fn representative(&self) -> &BinaryTable {
        &self.representative
    }

    pub fn witness(&self) -> &CheckedPermutation {
        &self.witness
    }

    pub fn into_parts(self) -> (BinaryTable, CheckedPermutation) {
        (self.representative, self.witness)
    }

    pub fn certificate(&self) -> CanonicalCertificate {
        CanonicalCertificate {
            representative: self.representative.clone(),
            witness: self.witness.clone(),
        }
    }
}

/// Common contract for the exhaustive oracle and a future stabilizer search.
///
/// Implementations must return the least row-major orbit image.  They must use
/// the least witness image vector to break ties between equal orbit images.
pub trait BinaryTableCanonicalizer {
    fn canonicalize(&self, table: &BinaryTable) -> Result<CanonicalForm, CanonicalizationError>;
}

/// Exact `S_n` orbit enumeration for degrees at most eight.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExhaustiveCanonicalizer;

impl ExhaustiveCanonicalizer {
    pub fn canonicalize(
        &self,
        table: &BinaryTable,
    ) -> Result<CanonicalForm, CanonicalizationError> {
        canonicalize_exhaustively(table)
    }
}

impl BinaryTableCanonicalizer for ExhaustiveCanonicalizer {
    fn canonicalize(&self, table: &BinaryTable) -> Result<CanonicalForm, CanonicalizationError> {
        canonicalize_exhaustively(table)
    }
}

fn canonicalize_exhaustively(table: &BinaryTable) -> Result<CanonicalForm, CanonicalizationError> {
    let mut permutations = LexicographicPermutations::new(table.degree())?;
    let identity = permutations
        .next()
        .expect("permutation enumeration always contains the identity");
    let mut representative = table.clone();
    let mut witness = identity;

    for candidate in permutations {
        let image = table
            .conjugated_by(&candidate)
            .map_err(CanonicalizationError::Action)?;
        let replace = match image.cmp(&representative) {
            Ordering::Less => true,
            Ordering::Equal => candidate < witness,
            Ordering::Greater => false,
        };
        if replace {
            representative = image;
            witness = candidate;
        }
    }

    Ok(CanonicalForm {
        representative,
        witness,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalizationError {
    DegreeTooLarge { degree: usize, maximum: usize },
    Action(TableActionError),
}

impl fmt::Display for CanonicalizationError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DegreeTooLarge { degree, maximum } => write!(
                output,
                "exhaustive canonization supports degree at most {maximum}, not {degree}"
            ),
            Self::Action(error) => error.fmt(output),
        }
    }
}

impl Error for CanonicalizationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Action(error) => Some(error),
            Self::DegreeTooLarge { .. } => None,
        }
    }
}

/// Portable claim consisting of a canonical table and a relabeling witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalCertificate {
    representative: BinaryTable,
    witness: CheckedPermutation,
}

impl CanonicalCertificate {
    /// Constructs a syntactically well-formed certificate.  Semantic checks
    /// are performed by [`replay_certificate`] or
    /// [`verify_certificate_exact`].
    pub fn new(
        representative: BinaryTable,
        witness: CheckedPermutation,
    ) -> Result<Self, CertificateError> {
        if representative.degree() != witness.degree() {
            return Err(CertificateError::DegreeMismatch {
                table_degree: representative.degree(),
                witness_degree: witness.degree(),
            });
        }
        Ok(Self {
            representative,
            witness,
        })
    }

    pub fn representative(&self) -> &BinaryTable {
        &self.representative
    }

    pub fn witness(&self) -> &CheckedPermutation {
        &self.witness
    }

    /// Replays only the orbit witness.  Use [`Self::verify_exact`] when the
    /// representative's global minimality must also be checked.
    pub fn replay(&self, original: &BinaryTable) -> Result<BinaryTable, CertificateError> {
        replay_certificate(original, self)
    }

    /// Replays the witness and independently checks exact minimality and the
    /// deterministic witness tie-break with the exhaustive oracle.
    pub fn verify_exact(&self, original: &BinaryTable) -> Result<CanonicalForm, CertificateError> {
        verify_certificate_exact(original, self)
    }
}

/// Applies a certificate witness and checks that it yields the claimed table.
pub fn replay_certificate(
    original: &BinaryTable,
    certificate: &CanonicalCertificate,
) -> Result<BinaryTable, CertificateError> {
    if original.degree() != certificate.witness.degree() {
        return Err(CertificateError::DegreeMismatch {
            table_degree: original.degree(),
            witness_degree: certificate.witness.degree(),
        });
    }
    let replayed = original
        .conjugated_by(&certificate.witness)
        .map_err(CertificateError::Action)?;
    if replayed != certificate.representative {
        return Err(CertificateError::WitnessImageMismatch);
    }
    Ok(replayed)
}

/// Replays a certificate and then independently proves its exact canonicality.
pub fn verify_certificate_exact(
    original: &BinaryTable,
    certificate: &CanonicalCertificate,
) -> Result<CanonicalForm, CertificateError> {
    replay_certificate(original, certificate)?;
    let expected = ExhaustiveCanonicalizer
        .canonicalize(original)
        .map_err(CertificateError::Canonicalization)?;
    if expected.representative != certificate.representative {
        return Err(CertificateError::RepresentativeIsNotCanonical);
    }
    if expected.witness != certificate.witness {
        return Err(CertificateError::WitnessIsNotLexicographicallyLeast);
    }
    Ok(expected)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateError {
    DegreeMismatch {
        table_degree: usize,
        witness_degree: usize,
    },
    WitnessImageMismatch,
    RepresentativeIsNotCanonical,
    WitnessIsNotLexicographicallyLeast,
    Action(TableActionError),
    Canonicalization(CanonicalizationError),
}

impl fmt::Display for CertificateError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DegreeMismatch {
                table_degree,
                witness_degree,
            } => write!(
                output,
                "certificate combines table degree {table_degree} with witness degree {witness_degree}"
            ),
            Self::WitnessImageMismatch => {
                write!(
                    output,
                    "certificate witness does not produce the claimed table"
                )
            }
            Self::RepresentativeIsNotCanonical => {
                write!(
                    output,
                    "certificate table is not the least orbit representative"
                )
            }
            Self::WitnessIsNotLexicographicallyLeast => write!(
                output,
                "certificate witness is not the least witness for the canonical table"
            ),
            Self::Action(error) => error.fmt(output),
            Self::Canonicalization(error) => error.fmt(output),
        }
    }
}

impl Error for CertificateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Action(error) => Some(error),
            Self::Canonicalization(error) => Some(error),
            Self::DegreeMismatch { .. }
            | Self::WitnessImageMismatch
            | Self::RepresentativeIsNotCanonical
            | Self::WitnessIsNotLexicographicallyLeast => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashMap};

    #[derive(Clone)]
    struct DeterministicRng(u64);

    impl DeterministicRng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next_u64(&mut self) -> u64 {
            let mut value = self.0;
            value ^= value << 13;
            value ^= value >> 7;
            value ^= value << 17;
            self.0 = value;
            value
        }

        fn below(&mut self, limit: usize) -> usize {
            (self.next_u64() as usize) % limit
        }
    }

    fn generated_table(degree: usize, seed: u64) -> BinaryTable {
        let mut rng = DeterministicRng::new(seed ^ (degree as u64).wrapping_mul(0x9e37_79b9));
        BinaryTable::from_fn(degree, |_, _| rng.below(degree)).unwrap()
    }

    fn sampled_permutations(degree: usize, count: usize, seed: u64) -> Vec<CheckedPermutation> {
        let mut samples = BTreeSet::new();
        samples.insert(CheckedPermutation::identity(degree));
        samples.insert(CheckedPermutation::new((0..degree).rev().collect()).unwrap());

        let mut rng = DeterministicRng::new(seed);
        while samples.len() < count.min(factorial(degree)) {
            let mut images = (0..degree).collect::<Vec<_>>();
            for index in (1..degree).rev() {
                images.swap(index, rng.below(index + 1));
            }
            samples.insert(CheckedPermutation::new(images).unwrap());
        }
        samples.into_iter().collect()
    }

    fn factorial(value: usize) -> usize {
        (1..=value).product()
    }

    #[test]
    fn malformed_permutations_and_tables_are_rejected() {
        assert_eq!(
            CheckedPermutation::new(vec![0, 2]),
            Err(PermutationError::ImageOutOfRange {
                position: 1,
                image: 2,
                degree: 2,
            })
        );
        assert_eq!(
            CheckedPermutation::new(vec![1, 1]),
            Err(PermutationError::DuplicateImage {
                image: 1,
                first_position: 0,
                second_position: 1,
            })
        );
        assert!(CheckedPermutation::new(Vec::new()).is_ok());

        assert_eq!(
            BinaryTable::new(0, Vec::new()),
            Err(TableError::EmptyDomain)
        );
        assert_eq!(
            BinaryTable::new(2, vec![0, 1, 0]),
            Err(TableError::WrongEntryCount {
                degree: 2,
                expected: 4,
                actual: 3,
            })
        );
        assert_eq!(
            BinaryTable::new(2, vec![0, 1, 2, 0]),
            Err(TableError::ValueOutOfRange {
                index: 2,
                value: 2,
                degree: 2,
            })
        );

        let table = BinaryTable::new(2, vec![0, 1, 1, 0]).unwrap();
        let degree_three = CheckedPermutation::identity(3);
        assert_eq!(
            table.conjugated_by(&degree_three),
            Err(TableActionError::DegreeMismatch {
                table_degree: 2,
                permutation_degree: 3,
            })
        );
    }

    #[test]
    fn identity_inverse_and_composition_laws_hold() {
        for degree in 0..=6 {
            let identity = CheckedPermutation::identity(degree);
            let permutations = LexicographicPermutations::new(degree)
                .unwrap()
                .collect::<Vec<_>>();
            for permutation in &permutations {
                let inverse = permutation.inverse();
                assert_eq!(permutation.compose(&inverse).unwrap(), identity);
                assert_eq!(inverse.compose(permutation).unwrap(), identity);
                assert_eq!(permutation.compose(&identity).unwrap(), *permutation);
                assert_eq!(identity.compose(permutation).unwrap(), *permutation);
                for point in 0..degree {
                    let image = permutation.image(point).unwrap();
                    assert_eq!(inverse.image(image), Some(point));
                }
            }
        }

        for degree in 0..=4 {
            let permutations = LexicographicPermutations::new(degree)
                .unwrap()
                .collect::<Vec<_>>();
            for first in &permutations {
                for second in &permutations {
                    for third in &permutations {
                        let left = first.compose(&second.compose(third).unwrap()).unwrap();
                        let right = first.compose(second).unwrap().compose(third).unwrap();
                        assert_eq!(left, right);
                    }
                }
            }
        }

        assert!(matches!(
            CheckedPermutation::identity(2).compose(&CheckedPermutation::identity(3)),
            Err(PermutationError::DegreeMismatch { .. })
        ));
    }

    #[test]
    fn binary_table_conjugation_is_a_group_action() {
        for degree in 1..=5 {
            let table = generated_table(degree, 0x51a7_10a5 + degree as u64);
            let identity = CheckedPermutation::identity(degree);
            assert_eq!(table.conjugated_by(&identity).unwrap(), table);

            let permutations = LexicographicPermutations::new(degree)
                .unwrap()
                .collect::<Vec<_>>();
            for permutation in &permutations {
                let image = table.conjugated_by(permutation).unwrap();
                assert_eq!(image.conjugated_by(&permutation.inverse()).unwrap(), table);
            }
            for left in &permutations {
                for right in &permutations {
                    let composition = left.compose(right).unwrap();
                    let direct = table.conjugated_by(&composition).unwrap();
                    let staged = table
                        .conjugated_by(right)
                        .unwrap()
                        .conjugated_by(left)
                        .unwrap();
                    assert_eq!(direct, staged);
                }
            }
        }
    }

    #[test]
    fn exhaustive_degree_three_space_has_one_canonical_member_per_orbit() {
        let degree: usize = 3;
        let cell_count = degree * degree;
        let table_count = degree.pow(cell_count as u32);
        let canonicalizer = ExhaustiveCanonicalizer;
        let mut orbit_counts: HashMap<BinaryTable, (usize, usize)> = HashMap::new();

        for mut code in 0..table_count {
            let mut entries = vec![0; cell_count];
            for entry in &mut entries {
                *entry = code % degree;
                code /= degree;
            }
            let table = BinaryTable::new(degree, entries).unwrap();
            let canonical = canonicalizer.canonicalize(&table).unwrap();
            let counts = orbit_counts
                .entry(canonical.representative().clone())
                .or_default();
            counts.0 += 1;
            if &table == canonical.representative() {
                counts.1 += 1;
            }
        }

        assert_eq!(
            orbit_counts.values().map(|counts| counts.0).sum::<usize>(),
            table_count
        );
        for (representative, &(orbit_size, canonical_members)) in &orbit_counts {
            assert_eq!(canonical_members, 1, "representative: {representative:?}");
            assert!(matches!(orbit_size, 1 | 2 | 3 | 6));
        }
    }

    #[test]
    fn generated_larger_orbits_contain_exactly_one_canonical_member() {
        let canonicalizer = ExhaustiveCanonicalizer;
        for degree in 4..=6 {
            for seed in 0..4 {
                let table = generated_table(degree, 0xcafe_0000 + seed);
                let canonical = canonicalizer.canonicalize(&table).unwrap();
                let orbit = LexicographicPermutations::new(degree)
                    .unwrap()
                    .map(|permutation| table.conjugated_by(&permutation).unwrap())
                    .collect::<BTreeSet<_>>();
                assert_eq!(
                    orbit
                        .iter()
                        .filter(|image| *image == canonical.representative())
                        .count(),
                    1
                );
                assert_eq!(orbit.first(), Some(canonical.representative()));
            }
        }
    }

    #[test]
    fn canonicalization_is_orbit_invariant_through_degree_eight() {
        let canonicalizer = ExhaustiveCanonicalizer;
        for degree in 1..=8 {
            let table = generated_table(degree, 0x0b17_cafe + degree as u64);
            let expected = canonicalizer.canonicalize(&table).unwrap();
            let sample_count = if degree <= 5 { factorial(degree) } else { 10 };
            let permutations = if degree <= 5 {
                LexicographicPermutations::new(degree)
                    .unwrap()
                    .collect::<Vec<_>>()
            } else {
                sampled_permutations(degree, sample_count, 0x5eed + degree as u64)
            };

            for permutation in permutations {
                let image = table.conjugated_by(&permutation).unwrap();
                let actual = canonicalizer.canonicalize(&image).unwrap();
                assert_eq!(actual.representative(), expected.representative());
                assert_eq!(
                    actual
                        .representative()
                        .entries()
                        .cmp(expected.representative().entries()),
                    Ordering::Equal
                );
            }

            let replayed = expected.certificate().replay(&table).unwrap();
            assert_eq!(&replayed, expected.representative());
        }
    }

    #[test]
    fn canonical_witness_and_certificate_replay_are_exact() {
        let table = BinaryTable::new(3, vec![2; 9]).unwrap();
        let canonical = ExhaustiveCanonicalizer.canonicalize(&table).unwrap();
        assert_eq!(canonical.representative().entries(), &[0; 9]);
        assert_eq!(canonical.witness().images(), &[1, 2, 0]);

        let certificate = canonical.certificate();
        assert_eq!(
            certificate.replay(&table).unwrap(),
            *canonical.representative()
        );
        assert_eq!(certificate.verify_exact(&table).unwrap(), canonical);

        let noncanonical =
            CanonicalCertificate::new(table.clone(), CheckedPermutation::identity(3)).unwrap();
        assert_eq!(noncanonical.replay(&table).unwrap(), table);
        assert_eq!(
            noncanonical.verify_exact(&table),
            Err(CertificateError::RepresentativeIsNotCanonical)
        );

        let wrong_witness = CanonicalCertificate::new(
            canonical.representative().clone(),
            CheckedPermutation::new(vec![2, 1, 0]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            wrong_witness.replay(&table).unwrap(),
            *canonical.representative()
        );
        assert_eq!(
            wrong_witness.verify_exact(&table),
            Err(CertificateError::WitnessIsNotLexicographicallyLeast)
        );

        let wrong_image = CanonicalCertificate::new(
            BinaryTable::new(3, vec![1; 9]).unwrap(),
            canonical.witness().clone(),
        )
        .unwrap();
        assert_eq!(
            wrong_image.replay(&table),
            Err(CertificateError::WitnessImageMismatch)
        );

        assert!(matches!(
            CanonicalCertificate::new(
                canonical.representative().clone(),
                CheckedPermutation::identity(2)
            ),
            Err(CertificateError::DegreeMismatch { .. })
        ));
    }

    #[test]
    fn exhaustive_output_and_enumeration_are_deterministic() {
        for degree in 0..=8 {
            let first = LexicographicPermutations::new(degree).unwrap();
            let second = LexicographicPermutations::new(degree).unwrap();
            let mut previous: Option<CheckedPermutation> = None;
            let mut count = 0;
            for (left, right) in first.zip(second) {
                assert_eq!(left, right);
                if let Some(previous) = previous.replace(left.clone()) {
                    assert!(previous < left);
                }
                count += 1;
            }
            assert_eq!(count, factorial(degree));
        }

        assert!(matches!(
            LexicographicPermutations::new(MAX_EXHAUSTIVE_DEGREE + 1),
            Err(CanonicalizationError::DegreeTooLarge { .. })
        ));

        let table = generated_table(7, 0xd37e_41a1);
        let expected = ExhaustiveCanonicalizer.canonicalize(&table).unwrap();
        for _ in 0..12 {
            assert_eq!(
                ExhaustiveCanonicalizer.canonicalize(&table).unwrap(),
                expected
            );
        }
    }
}
