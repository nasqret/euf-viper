#![forbid(unsafe_code)]

//! Checked symmetry restrictions for bounded finite-table search.

use std::error::Error;
use std::fmt;

pub(crate) const MAX_SYMMETRY_DEGREE: usize = u8::BITS as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ZeroColumnError {
    InvalidDegree {
        observed: usize,
    },
    ValueOutOfRange {
        row: usize,
        value: u8,
        degree: usize,
    },
    DuplicateValue {
        value: u8,
    },
    ColumnOutOfRange {
        column: usize,
        degree: usize,
    },
}

impl fmt::Display for ZeroColumnError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDegree { observed } => write!(
                output,
                "zero-column degree {observed} is outside 1..={MAX_SYMMETRY_DEGREE}"
            ),
            Self::ValueOutOfRange { row, value, degree } => write!(
                output,
                "zero-column row {row} has value {value}, outside 0..{degree}"
            ),
            Self::DuplicateValue { value } => {
                write!(output, "zero-column value {value} occurs more than once")
            }
            Self::ColumnOutOfRange { column, degree } => {
                write!(output, "marked column {column} is outside 0..{degree}")
            }
        }
    }
}

fn validate_permutation(values: &[u8]) -> Result<(), ZeroColumnError> {
    let degree = values.len();
    if degree == 0 || degree > MAX_SYMMETRY_DEGREE {
        return Err(ZeroColumnError::InvalidDegree { observed: degree });
    }
    let mut seen = 0u16;
    for (row, &value) in values.iter().enumerate() {
        if usize::from(value) >= degree {
            return Err(ZeroColumnError::ValueOutOfRange { row, value, degree });
        }
        let bit = 1u16 << value;
        if seen & bit != 0 {
            return Err(ZeroColumnError::DuplicateValue { value });
        }
        seen |= bit;
    }
    Ok(())
}

/// Complete conjugacy invariant for a permutation with one marked carrier
/// point.  The low nibble is the length of the marked cycle; subsequent
/// nibbles count unmarked cycles of each length.
///
/// Two `(column, values)` pairs have the same key exactly when a carrier
/// relabeling maps the first marked column to the second and conjugates one
/// column permutation to the other.
pub(crate) fn marked_permutation_class(
    column: usize,
    values: &[u8],
) -> Result<u64, ZeroColumnError> {
    validate_permutation(values)?;
    let degree = values.len();
    if column >= degree {
        return Err(ZeroColumnError::ColumnOutOfRange { column, degree });
    }

    let mut visited = 0u16;
    let mut current = column;
    let mut marked_length = 0usize;
    loop {
        let bit = 1u16 << current;
        if visited & bit != 0 {
            break;
        }
        visited |= bit;
        marked_length += 1;
        current = usize::from(values[current]);
    }

    let mut cycle_counts = [0u8; MAX_SYMMETRY_DEGREE + 1];
    for start in 0..degree {
        if visited & (1u16 << start) != 0 {
            continue;
        }
        let mut length = 0usize;
        current = start;
        loop {
            let bit = 1u16 << current;
            if visited & bit != 0 {
                break;
            }
            visited |= bit;
            length += 1;
            current = usize::from(values[current]);
        }
        cycle_counts[length] += 1;
    }

    let mut key = marked_length as u64;
    for (length, &count) in cycle_counts.iter().enumerate().skip(1).take(degree) {
        key |= u64::from(count) << (length * 4);
    }
    Ok(key)
}

impl Error for ZeroColumnError {}

fn next_permutation(values: &mut [u8]) -> bool {
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
        .expect("a permutation pivot has a successor");
    values.swap(pivot, successor);
    values[pivot + 1..].reverse();
    true
}

/// Returns true exactly for the least conjugate under carrier permutations
/// fixing value zero.
///
/// For a column permutation `v` and relabeling `s`, the image is
/// `s o v o s^-1`. Restricting `s(0) = 0` leaves column zero in place. If the
/// complete source is invariant under simultaneous carrier relabeling, every
/// model orbit therefore contains a model accepted by this predicate.
pub(crate) fn is_canonical_zero_column(values: &[u8]) -> Result<bool, ZeroColumnError> {
    let degree = values.len();
    validate_permutation(values)?;

    let mut permutation = [0u8; MAX_SYMMETRY_DEGREE];
    for (index, slot) in permutation[..degree].iter_mut().enumerate() {
        *slot = index as u8;
    }
    loop {
        let mut inverse = [0u8; MAX_SYMMETRY_DEGREE];
        for (preimage, &image) in permutation[..degree].iter().enumerate() {
            inverse[usize::from(image)] = preimage as u8;
        }
        let mut image = [0u8; MAX_SYMMETRY_DEGREE];
        for row in 0..degree {
            let old_row = usize::from(inverse[row]);
            image[row] = permutation[usize::from(values[old_row])];
        }
        if image[..degree] < values[..] {
            return Ok(false);
        }
        if !next_permutation(&mut permutation[1..degree]) {
            return Ok(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn permutations(degree: usize) -> Vec<Vec<usize>> {
        let mut values = (0..degree).collect::<Vec<_>>();
        let mut output = Vec::new();
        loop {
            output.push(values.clone());
            let Some(pivot) = (1..values.len())
                .rev()
                .find(|&index| values[index - 1] < values[index])
                .map(|index| index - 1)
            else {
                return output;
            };
            let successor = (pivot + 1..values.len())
                .rev()
                .find(|&index| values[pivot] < values[index])
                .expect("a permutation pivot has a successor");
            values.swap(pivot, successor);
            values[pivot + 1..].reverse();
        }
    }

    #[test]
    fn predicate_matches_direct_conjugacy_minima() {
        for degree in 1..=5 {
            let columns = permutations(degree);
            let stabilizer = permutations(degree.saturating_sub(1));
            for column in columns {
                let mut least = column.clone();
                for tail in &stabilizer {
                    let mut relabeling = vec![0usize; degree];
                    for (index, &image) in tail.iter().enumerate() {
                        relabeling[index + 1] = image + 1;
                    }
                    let mut inverse = vec![0usize; degree];
                    for (preimage, &image) in relabeling.iter().enumerate() {
                        inverse[image] = preimage;
                    }
                    let image = (0..degree)
                        .map(|row| relabeling[column[inverse[row]]])
                        .collect::<Vec<_>>();
                    least = least.min(image);
                }
                let values = column.iter().map(|&value| value as u8).collect::<Vec<_>>();
                assert_eq!(
                    is_canonical_zero_column(&values).unwrap(),
                    column == least,
                    "degree={degree} column={column:?}"
                );
            }
        }
    }

    #[test]
    fn malformed_candidates_are_rejected() {
        assert!(is_canonical_zero_column(&[]).is_err());
        assert!(is_canonical_zero_column(&[0, 0]).is_err());
        assert!(is_canonical_zero_column(&[0, 2]).is_err());
        assert!(is_canonical_zero_column(&[0; 9]).is_err());
        assert!(marked_permutation_class(2, &[0, 1]).is_err());
    }

    #[test]
    fn marked_cycle_key_matches_direct_conjugacy_classes() {
        for degree in 1..=6 {
            let permutations = permutations(degree);
            let mut canonical_by_key = BTreeMap::<u64, Vec<usize>>::new();
            let mut key_by_canonical = BTreeMap::<Vec<usize>, u64>::new();
            for values in &permutations {
                let values_u8 = values.iter().map(|&value| value as u8).collect::<Vec<_>>();
                for column in 0..degree {
                    let mut least = None::<Vec<usize>>;
                    for relabeling in &permutations {
                        if relabeling[column] != 0 {
                            continue;
                        }
                        let mut image = vec![0usize; degree];
                        for row in 0..degree {
                            image[relabeling[row]] = relabeling[values[row]];
                        }
                        least = Some(match least {
                            Some(current) => current.min(image),
                            None => image,
                        });
                    }
                    let least = least.expect("a marked point can always be mapped to zero");
                    let key = marked_permutation_class(column, &values_u8).unwrap();
                    assert_eq!(
                        canonical_by_key.entry(key).or_insert_with(|| least.clone()),
                        &least,
                        "degree={degree} column={column} values={values:?}"
                    );
                    assert_eq!(
                        *key_by_canonical.entry(least).or_insert(key),
                        key,
                        "degree={degree} column={column} values={values:?}"
                    );
                }
            }
        }
    }
}
