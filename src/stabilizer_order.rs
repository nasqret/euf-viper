#![cfg(test)]
#![allow(dead_code)]

//! Exact stabilizer-aware cell ordering for forbidden operation-table orbits.
//!
//! This is a deterministic, fail-closed reference oracle, not production
//! solver code.  It can be checked independently with:
//!
//! ```text
//! rustc --edition=2021 -O -D warnings --test src/stabilizer_order.rs
//! ```
//!
//! For a proper prefix cell set `P`, let `A(P)` be the distinct assignments to
//! `P` occurring among the forbidden tables.  Let `H(P)` be the subgroup of
//! carrier permutations whose induced action fixes every cell in `P`
//! pointwise.  Since the input is checked to be one complete conjugacy orbit,
//! `H(P)` acts on `A(P)` by relabeling assigned values.  The frontier-width
//! surrogate used here is exactly
//!
//! ```text
//! q(P) = |A(P) / H(P)|.
//! ```
//!
//! It is the number of symmetry classes of live trie prefixes before ordinary
//! reduced-MVDD suffix merging.  The terminal frontier has width zero.  Among
//! all cell orders, the oracle minimizes `(max q(P), sum q(P))`, then chooses
//! the lexicographically least order.  A subset dynamic program proves this
//! objective exactly within explicit degree, subset, frontier, and work caps.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

const MAX_ROW_VALUE_DEGREE: usize = (u8::MAX as usize) + 1;

/// Fail-closed limits for exhaustive verification and order optimization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OracleCap {
    pub max_degree: usize,
    pub max_cells: usize,
    pub max_orbit_members: usize,
    pub max_group_permutations: usize,
    pub max_subsets: usize,
    pub max_frontier_states: usize,
    pub max_work_units: usize,
}

impl Default for OracleCap {
    fn default() -> Self {
        Self {
            max_degree: 4,
            max_cells: 16,
            max_orbit_members: 24,
            max_group_permutations: 24,
            max_subsets: 1 << 16,
            max_frontier_states: 24,
            max_work_units: 250_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CappedResource {
    Degree,
    Cells,
    OrbitMembers,
    GroupPermutations,
    Subsets,
    FrontierStates,
    WorkUnits,
}

impl fmt::Display for CappedResource {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Degree => "degree",
            Self::Cells => "table cells",
            Self::OrbitMembers => "orbit members",
            Self::GroupPermutations => "group permutations",
            Self::Subsets => "cell subsets",
            Self::FrontierStates => "frontier states",
            Self::WorkUnits => "reference work units",
        };
        output.write_str(name)
    }
}

/// One untrusted claim that `seed_to_member` conjugates the seed to `table`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrbitMemberClaim {
    table: Box<[u8]>,
    seed_to_member: Box<[usize]>,
}

impl OrbitMemberClaim {
    pub fn new(table: Vec<u8>, seed_to_member: Vec<usize>) -> Self {
        Self {
            table: table.into_boxed_slice(),
            seed_to_member: seed_to_member.into_boxed_slice(),
        }
    }

    pub fn table(&self) -> &[u8] {
        &self.table
    }

    pub fn seed_to_member(&self) -> &[usize] {
        &self.seed_to_member
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrbitVerificationTelemetry {
    pub degree: usize,
    pub cells: usize,
    pub expected_group_permutations: usize,
    pub supplied_members: usize,
    pub unique_members: usize,
    pub witnesses_replayed: usize,
    pub orbit_images_generated: usize,
    pub unique_orbit_images: usize,
    pub work_units: usize,
}

/// A complete orbit whose table and permutation obligations were replayed.
///
/// Fields are private so an unchecked value cannot be manufactured outside
/// this module.  The value owns normalized rows and least witnesses, so later
/// input mutation cannot invalidate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedForbiddenOrbit {
    degree: usize,
    seed: Box<[u8]>,
    members: Box<[Box<[u8]>]>,
    least_seed_witnesses: Box<[Box<[usize]>]>,
    group_permutations: Box<[Box<[usize]>]>,
    telemetry: OrbitVerificationTelemetry,
}

impl VerifiedForbiddenOrbit {
    pub fn degree(&self) -> usize {
        self.degree
    }

    pub fn cell_count(&self) -> usize {
        self.seed.len()
    }

    pub fn seed(&self) -> &[u8] {
        &self.seed
    }

    /// Sorted unique members of the verified complete orbit.
    pub fn members(&self) -> &[Box<[u8]>] {
        &self.members
    }

    /// Least lexicographic seed-to-member witnesses, aligned with `members`.
    pub fn least_seed_witnesses(&self) -> &[Box<[usize]>] {
        &self.least_seed_witnesses
    }

    pub fn telemetry(&self) -> &OrbitVerificationTelemetry {
        &self.telemetry
    }
}

/// Lexicographic optimization target for one complete cell order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OrderObjective {
    pub peak_quotient_width: usize,
    pub total_quotient_width: usize,
}

/// Replayable data for one stabilizer-chain level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StabilizerLevelCertificate {
    pub depth: usize,
    pub added_cell: Option<usize>,
    pub prefix_cells: Vec<usize>,
    pub fixed_carrier_points: Vec<usize>,
    /// Exact lexicographically sorted members of the pointwise stabilizer.
    pub stabilizer_permutations: Vec<Vec<usize>>,
    /// Number of distinct live forbidden prefix assignments before quotient.
    pub live_prefix_width: usize,
    /// Number of those assignments modulo the recorded stabilizer.
    pub quotient_frontier_width: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderEvaluation {
    pub cell_order: Vec<usize>,
    pub levels: Vec<StabilizerLevelCertificate>,
    pub objective: OrderObjective,
    pub stabilizer_area: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SelectionTelemetry {
    pub subsets_evaluated: usize,
    pub group_permutations: usize,
    pub frontier_work_units: usize,
    pub bottleneck_transitions: usize,
    pub area_transitions: usize,
    pub total_work_units: usize,
}

/// Deterministic proof object for the globally selected order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StabilizerOrderCertificate {
    pub degree: usize,
    pub seed: Vec<u8>,
    pub normalized_orbit: Vec<Vec<u8>>,
    pub least_seed_witnesses: Vec<Vec<usize>>,
    pub selected: OrderEvaluation,
    pub lexicographic_baseline: OrderEvaluation,
    pub telemetry: SelectionTelemetry,
}

impl StabilizerOrderCertificate {
    pub fn cell_order(&self) -> &[usize] {
        &self.selected.cell_order
    }

    pub fn objective(&self) -> OrderObjective {
        self.selected.objective
    }

    pub fn strictly_beats_lexicographic(&self) -> bool {
        self.selected.objective < self.lexicographic_baseline.objective
    }

    /// Rebuilds all subset widths, both dynamic programs, and every level.
    pub fn verify_exact(
        &self,
        orbit: &VerifiedForbiddenOrbit,
        cap: OracleCap,
    ) -> Result<SelectionTelemetry, OracleError> {
        verify_order_certificate(orbit, self, cap)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleError {
    InvalidDegree {
        degree: usize,
        maximum_representable: usize,
    },
    CapExceeded {
        resource: CappedResource,
        limit: usize,
        attempted: usize,
    },
    ArithmeticOverflow,
    EmptyOrbit,
    SeedLength {
        expected: usize,
        actual: usize,
    },
    SeedValueOutOfRange {
        cell: usize,
        value: u8,
        degree: usize,
    },
    MemberLength {
        member: usize,
        expected: usize,
        actual: usize,
    },
    MemberValueOutOfRange {
        member: usize,
        cell: usize,
        value: u8,
        degree: usize,
    },
    PermutationLength {
        member: usize,
        expected: usize,
        actual: usize,
    },
    PermutationImageOutOfRange {
        member: usize,
        point: usize,
        image: usize,
        degree: usize,
    },
    DuplicatePermutationImage {
        member: usize,
        image: usize,
        first_point: usize,
        second_point: usize,
    },
    WitnessReplayMismatch {
        member: usize,
    },
    DuplicateOrbitMember {
        first_member: usize,
        second_member: usize,
    },
    OrbitSetMismatch {
        expected: usize,
        supplied: usize,
        missing: usize,
        extra: usize,
    },
    CellOrderLength {
        expected: usize,
        actual: usize,
    },
    CellOutOfRange {
        position: usize,
        cell: usize,
        cell_count: usize,
    },
    DuplicateCell {
        cell: usize,
        first_position: usize,
        second_position: usize,
    },
    CertificateMismatch,
    InternalInconsistency,
}

impl fmt::Display for OracleError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDegree {
                degree,
                maximum_representable,
            } => write!(
                output,
                "degree {degree} is invalid; expected 1..={maximum_representable} for u8 tables"
            ),
            Self::CapExceeded {
                resource,
                limit,
                attempted,
            } => write!(
                output,
                "oracle cap for {resource} is {limit}, attempted {attempted}"
            ),
            Self::ArithmeticOverflow => output.write_str("arithmetic overflow in reference oracle"),
            Self::EmptyOrbit => output.write_str("a forbidden orbit must contain at least one member"),
            Self::SeedLength { expected, actual } => {
                write!(output, "seed has {actual} cells, expected {expected}")
            }
            Self::SeedValueOutOfRange {
                cell,
                value,
                degree,
            } => write!(
                output,
                "seed value {value} at cell {cell} is outside 0..{degree}"
            ),
            Self::MemberLength {
                member,
                expected,
                actual,
            } => write!(
                output,
                "orbit member {member} has {actual} cells, expected {expected}"
            ),
            Self::MemberValueOutOfRange {
                member,
                cell,
                value,
                degree,
            } => write!(
                output,
                "orbit member {member} has value {value} at cell {cell}, outside 0..{degree}"
            ),
            Self::PermutationLength {
                member,
                expected,
                actual,
            } => write!(
                output,
                "witness for member {member} has degree {actual}, expected {expected}"
            ),
            Self::PermutationImageOutOfRange {
                member,
                point,
                image,
                degree,
            } => write!(
                output,
                "witness for member {member} maps point {point} to {image}, outside 0..{degree}"
            ),
            Self::DuplicatePermutationImage {
                member,
                image,
                first_point,
                second_point,
            } => write!(
                output,
                "witness for member {member} maps points {first_point} and {second_point} to {image}"
            ),
            Self::WitnessReplayMismatch { member } => write!(
                output,
                "permutation witness for orbit member {member} does not replay"
            ),
            Self::DuplicateOrbitMember {
                first_member,
                second_member,
            } => write!(
                output,
                "orbit members {first_member} and {second_member} are identical"
            ),
            Self::OrbitSetMismatch {
                expected,
                supplied,
                missing,
                extra,
            } => write!(
                output,
                "supplied orbit has {supplied} members, exhaustive orbit has {expected}: {missing} missing and {extra} extra"
            ),
            Self::CellOrderLength { expected, actual } => write!(
                output,
                "cell order has length {actual}, expected {expected}"
            ),
            Self::CellOutOfRange {
                position,
                cell,
                cell_count,
            } => write!(
                output,
                "cell-order entry {cell} at position {position} is outside 0..{cell_count}"
            ),
            Self::DuplicateCell {
                cell,
                first_position,
                second_position,
            } => write!(
                output,
                "cell {cell} occurs at order positions {first_position} and {second_position}"
            ),
            Self::CertificateMismatch => {
                output.write_str("order certificate differs from exact deterministic replay")
            }
            Self::InternalInconsistency => {
                output.write_str("verified orbit violated an internal oracle invariant")
            }
        }
    }
}

impl Error for OracleError {}

#[derive(Debug, Clone, Copy)]
struct WorkMeter {
    used: usize,
    limit: usize,
}

impl WorkMeter {
    fn new(limit: usize) -> Self {
        Self { used: 0, limit }
    }

    fn with_used(limit: usize, used: usize) -> Result<Self, OracleError> {
        check_cap(CappedResource::WorkUnits, used, limit)?;
        Ok(Self { used, limit })
    }

    fn charge(&mut self, amount: usize) -> Result<(), OracleError> {
        let attempted = self
            .used
            .checked_add(amount)
            .ok_or(OracleError::ArithmeticOverflow)?;
        check_cap(CappedResource::WorkUnits, attempted, self.limit)?;
        self.used = attempted;
        Ok(())
    }
}

/// Replays every supplied witness and checks exact equality with the full
/// `S_degree` conjugacy orbit of `seed`.
pub fn verify_forbidden_orbit(
    degree: usize,
    seed: &[u8],
    claims: &[OrbitMemberClaim],
    cap: OracleCap,
) -> Result<VerifiedForbiddenOrbit, OracleError> {
    if degree == 0 || degree > MAX_ROW_VALUE_DEGREE {
        return Err(OracleError::InvalidDegree {
            degree,
            maximum_representable: MAX_ROW_VALUE_DEGREE,
        });
    }
    check_cap(CappedResource::Degree, degree, cap.max_degree)?;
    let cells = degree
        .checked_mul(degree)
        .ok_or(OracleError::ArithmeticOverflow)?;
    check_cap(CappedResource::Cells, cells, cap.max_cells)?;
    if seed.len() != cells {
        return Err(OracleError::SeedLength {
            expected: cells,
            actual: seed.len(),
        });
    }
    validate_row(seed, degree, None)?;
    if claims.is_empty() {
        return Err(OracleError::EmptyOrbit);
    }
    check_cap(
        CappedResource::OrbitMembers,
        claims.len(),
        cap.max_orbit_members,
    )?;

    let expected_permutations = checked_factorial(degree)?;
    check_cap(
        CappedResource::GroupPermutations,
        expected_permutations,
        cap.max_group_permutations,
    )?;

    let mut meter = WorkMeter::new(cap.max_work_units);
    let group = enumerate_permutations(degree, expected_permutations, &mut meter)?;
    let mut supplied = BTreeMap::<Vec<u8>, usize>::new();
    let mut witnesses_replayed = 0usize;
    for (member, claim) in claims.iter().enumerate() {
        if claim.table.len() != cells {
            return Err(OracleError::MemberLength {
                member,
                expected: cells,
                actual: claim.table.len(),
            });
        }
        validate_row(&claim.table, degree, Some(member))?;
        validate_permutation(&claim.seed_to_member, degree, member)?;
        meter.charge(cells)?;
        if conjugate(seed, degree, &claim.seed_to_member) != claim.table.as_ref() {
            return Err(OracleError::WitnessReplayMismatch { member });
        }
        witnesses_replayed += 1;
        if let Some(&first_member) = supplied.get(claim.table.as_ref()) {
            return Err(OracleError::DuplicateOrbitMember {
                first_member,
                second_member: member,
            });
        }
        supplied.insert(claim.table.to_vec(), member);
    }

    let mut generated = BTreeMap::<Vec<u8>, Vec<usize>>::new();
    for permutation in &group {
        meter.charge(cells)?;
        let image = conjugate(seed, degree, permutation);
        generated
            .entry(image)
            .or_insert_with(|| permutation.clone());
    }
    let missing = generated
        .keys()
        .filter(|row| !supplied.contains_key(*row))
        .count();
    let extra = supplied
        .keys()
        .filter(|row| !generated.contains_key(*row))
        .count();
    if missing != 0 || extra != 0 {
        return Err(OracleError::OrbitSetMismatch {
            expected: generated.len(),
            supplied: supplied.len(),
            missing,
            extra,
        });
    }

    let telemetry = OrbitVerificationTelemetry {
        degree,
        cells,
        expected_group_permutations: expected_permutations,
        supplied_members: claims.len(),
        unique_members: supplied.len(),
        witnesses_replayed,
        orbit_images_generated: group.len(),
        unique_orbit_images: generated.len(),
        work_units: meter.used,
    };
    let members = generated
        .keys()
        .cloned()
        .map(Vec::into_boxed_slice)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let least_seed_witnesses = generated
        .values()
        .cloned()
        .map(Vec::into_boxed_slice)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let group_permutations = group
        .into_iter()
        .map(Vec::into_boxed_slice)
        .collect::<Vec<_>>()
        .into_boxed_slice();

    Ok(VerifiedForbiddenOrbit {
        degree,
        seed: seed.to_vec().into_boxed_slice(),
        members,
        least_seed_witnesses,
        group_permutations,
        telemetry,
    })
}

/// Verifies raw claims and then computes the exact stabilizer-aware order.
pub fn select_stabilizer_order(
    degree: usize,
    seed: &[u8],
    claims: &[OrbitMemberClaim],
    cap: OracleCap,
) -> Result<StabilizerOrderCertificate, OracleError> {
    let orbit = verify_forbidden_orbit(degree, seed, claims, cap)?;
    choose_stabilizer_order(&orbit, cap)
}

/// Computes the globally optimal order for a previously verified orbit.
pub fn choose_stabilizer_order(
    orbit: &VerifiedForbiddenOrbit,
    cap: OracleCap,
) -> Result<StabilizerOrderCertificate, OracleError> {
    validate_verified_orbit_against_cap(orbit, cap)?;
    let prepared = prepare_frontiers(orbit, cap)?;
    let (cell_order, objective, telemetry) = optimize_order(&prepared, orbit, cap)?;
    let selected = build_evaluation(orbit, &prepared, &cell_order)?;
    if selected.objective != objective {
        return Err(OracleError::InternalInconsistency);
    }
    let lexicographic_order = (0..orbit.cell_count()).collect::<Vec<_>>();
    let lexicographic_baseline = build_evaluation(orbit, &prepared, &lexicographic_order)?;

    Ok(StabilizerOrderCertificate {
        degree: orbit.degree,
        seed: orbit.seed.to_vec(),
        normalized_orbit: orbit.members.iter().map(|row| row.to_vec()).collect(),
        least_seed_witnesses: orbit
            .least_seed_witnesses
            .iter()
            .map(|witness| witness.to_vec())
            .collect(),
        selected,
        lexicographic_baseline,
        telemetry,
    })
}

/// Evaluates one caller-supplied order under the exact same surrogate.
pub fn evaluate_cell_order(
    orbit: &VerifiedForbiddenOrbit,
    cell_order: &[usize],
    cap: OracleCap,
) -> Result<OrderEvaluation, OracleError> {
    validate_verified_orbit_against_cap(orbit, cap)?;
    validate_cell_order(orbit.cell_count(), cell_order)?;
    let prepared = prepare_frontiers(orbit, cap)?;
    build_evaluation(orbit, &prepared, cell_order)
}

/// Rebuilds and compares the complete deterministic certificate.
pub fn verify_order_certificate(
    orbit: &VerifiedForbiddenOrbit,
    certificate: &StabilizerOrderCertificate,
    cap: OracleCap,
) -> Result<SelectionTelemetry, OracleError> {
    let expected = choose_stabilizer_order(orbit, cap)?;
    if &expected != certificate {
        return Err(OracleError::CertificateMismatch);
    }
    Ok(expected.telemetry)
}

/// Replays raw orbit witnesses before rebuilding the order certificate.
pub fn replay_order_certificate(
    degree: usize,
    seed: &[u8],
    claims: &[OrbitMemberClaim],
    certificate: &StabilizerOrderCertificate,
    cap: OracleCap,
) -> Result<SelectionTelemetry, OracleError> {
    let orbit = verify_forbidden_orbit(degree, seed, claims, cap)?;
    verify_order_certificate(&orbit, certificate, cap)
}

#[derive(Debug, Clone)]
struct PreparedFrontiers {
    subset_count: usize,
    full_mask: usize,
    quotient_widths: Vec<usize>,
    live_widths: Vec<usize>,
    fixed_point_masks: Vec<usize>,
    stabilizer_indices: Vec<Vec<usize>>,
    frontier_work_units: usize,
}

fn prepare_frontiers(
    orbit: &VerifiedForbiddenOrbit,
    cap: OracleCap,
) -> Result<PreparedFrontiers, OracleError> {
    let cells = orbit.cell_count();
    let subset_count = 1usize
        .checked_shl(
            cells
                .try_into()
                .map_err(|_| OracleError::ArithmeticOverflow)?,
        )
        .ok_or(OracleError::ArithmeticOverflow)?;
    check_cap(CappedResource::Subsets, subset_count, cap.max_subsets)?;
    let full_mask = subset_count - 1;
    let carrier_subset_count = 1usize
        .checked_shl(
            orbit
                .degree
                .try_into()
                .map_err(|_| OracleError::ArithmeticOverflow)?,
        )
        .ok_or(OracleError::ArithmeticOverflow)?;
    let mut meter = WorkMeter::new(cap.max_work_units);

    let mut stabilizer_indices = vec![Vec::new(); carrier_subset_count];
    for (fixed_mask, stabilizer) in stabilizer_indices.iter_mut().enumerate() {
        for (permutation_index, permutation) in orbit.group_permutations.iter().enumerate() {
            meter.charge(orbit.degree.max(1))?;
            let fixes_all = (0..orbit.degree)
                .all(|point| fixed_mask & (1 << point) == 0 || permutation[point] == point);
            if fixes_all {
                stabilizer.push(permutation_index);
            }
        }
        if stabilizer.is_empty() {
            return Err(OracleError::InternalInconsistency);
        }
    }

    let cell_point_masks = (0..cells)
        .map(|cell| {
            let row = cell / orbit.degree;
            let column = cell % orbit.degree;
            (1 << row) | (1 << column)
        })
        .collect::<Vec<_>>();
    let mut fixed_point_masks = vec![0usize; subset_count];
    for mask in 1..subset_count {
        let bit = mask.trailing_zeros() as usize;
        fixed_point_masks[mask] = fixed_point_masks[mask & (mask - 1)] | cell_point_masks[bit];
    }

    let mut quotient_widths = vec![0usize; subset_count];
    let mut live_widths = vec![0usize; subset_count];
    for mask in 0..subset_count {
        if mask == full_mask {
            continue;
        }
        let selected_cells = cells_in_mask(mask, cells);
        let stabilizer = &stabilizer_indices[fixed_point_masks[mask]];
        let mut live = BTreeSet::<Vec<u8>>::new();
        let mut quotient = BTreeSet::<Vec<u8>>::new();
        for row in orbit.members.iter() {
            meter.charge(selected_cells.len().max(1))?;
            let signature = selected_cells
                .iter()
                .map(|&cell| row[cell])
                .collect::<Vec<_>>();
            live.insert(signature.clone());

            let mut canonical = None::<Vec<u8>>;
            for &permutation_index in stabilizer {
                meter.charge(selected_cells.len().max(1))?;
                let permutation = &orbit.group_permutations[permutation_index];
                let image = signature
                    .iter()
                    .map(|&value| permutation[usize::from(value)] as u8)
                    .collect::<Vec<_>>();
                if canonical.as_ref().is_none_or(|best| image < *best) {
                    canonical = Some(image);
                }
            }
            quotient.insert(canonical.ok_or(OracleError::InternalInconsistency)?);
        }
        check_cap(
            CappedResource::FrontierStates,
            live.len(),
            cap.max_frontier_states,
        )?;
        check_cap(
            CappedResource::FrontierStates,
            quotient.len(),
            cap.max_frontier_states,
        )?;
        live_widths[mask] = live.len();
        quotient_widths[mask] = quotient.len();
    }

    Ok(PreparedFrontiers {
        subset_count,
        full_mask,
        quotient_widths,
        live_widths,
        fixed_point_masks,
        stabilizer_indices,
        frontier_work_units: meter.used,
    })
}

fn optimize_order(
    prepared: &PreparedFrontiers,
    orbit: &VerifiedForbiddenOrbit,
    cap: OracleCap,
) -> Result<(Vec<usize>, OrderObjective, SelectionTelemetry), OracleError> {
    let cells = orbit.cell_count();
    let mut meter = WorkMeter::with_used(cap.max_work_units, prepared.frontier_work_units)?;
    let infinity = usize::MAX;
    let mut bottleneck = vec![infinity; prepared.subset_count];
    bottleneck[0] = prepared.quotient_widths[0];
    let mut bottleneck_transitions = 0usize;
    for mask in 0..prepared.subset_count {
        if bottleneck[mask] == infinity {
            continue;
        }
        for cell in 0..cells {
            if mask & (1 << cell) != 0 {
                continue;
            }
            meter.charge(1)?;
            bottleneck_transitions = bottleneck_transitions
                .checked_add(1)
                .ok_or(OracleError::ArithmeticOverflow)?;
            let next = mask | (1 << cell);
            let candidate = bottleneck[mask].max(prepared.quotient_widths[next]);
            if candidate < bottleneck[next] {
                bottleneck[next] = candidate;
            }
        }
    }
    let minimal_peak = bottleneck[prepared.full_mask];
    if minimal_peak == infinity {
        return Err(OracleError::InternalInconsistency);
    }

    let mut areas = vec![None::<usize>; prepared.subset_count];
    let mut paths = vec![None::<Vec<usize>>; prepared.subset_count];
    areas[0] = Some(prepared.quotient_widths[0]);
    paths[0] = Some(Vec::new());
    let mut area_transitions = 0usize;
    for mask in 0..prepared.subset_count {
        let (Some(area), Some(path)) = (areas[mask], paths[mask].clone()) else {
            continue;
        };
        for cell in 0..cells {
            if mask & (1 << cell) != 0 {
                continue;
            }
            let next = mask | (1 << cell);
            if prepared.quotient_widths[next] > minimal_peak {
                continue;
            }
            meter.charge(1)?;
            area_transitions = area_transitions
                .checked_add(1)
                .ok_or(OracleError::ArithmeticOverflow)?;
            let candidate_area = area
                .checked_add(prepared.quotient_widths[next])
                .ok_or(OracleError::ArithmeticOverflow)?;
            let mut candidate_path = path.clone();
            candidate_path.push(cell);
            let replace = match (areas[next], paths[next].as_ref()) {
                (None, None) => true,
                (Some(best_area), Some(best_path)) => {
                    candidate_area < best_area
                        || (candidate_area == best_area && candidate_path < *best_path)
                }
                _ => return Err(OracleError::InternalInconsistency),
            };
            if replace {
                areas[next] = Some(candidate_area);
                paths[next] = Some(candidate_path);
            }
        }
    }
    let cell_order = paths[prepared.full_mask]
        .clone()
        .ok_or(OracleError::InternalInconsistency)?;
    let total_quotient_width =
        areas[prepared.full_mask].ok_or(OracleError::InternalInconsistency)?;
    let objective = OrderObjective {
        peak_quotient_width: minimal_peak,
        total_quotient_width,
    };
    let telemetry = SelectionTelemetry {
        subsets_evaluated: prepared.subset_count,
        group_permutations: orbit.group_permutations.len(),
        frontier_work_units: prepared.frontier_work_units,
        bottleneck_transitions,
        area_transitions,
        total_work_units: meter.used,
    };
    Ok((cell_order, objective, telemetry))
}

fn build_evaluation(
    orbit: &VerifiedForbiddenOrbit,
    prepared: &PreparedFrontiers,
    cell_order: &[usize],
) -> Result<OrderEvaluation, OracleError> {
    validate_cell_order(orbit.cell_count(), cell_order)?;
    let mut levels = Vec::with_capacity(cell_order.len() + 1);
    let mut mask = 0usize;
    let mut peak = 0usize;
    let mut area = 0usize;
    let mut stabilizer_area = 0usize;
    for depth in 0..=cell_order.len() {
        if depth > 0 {
            mask |= 1 << cell_order[depth - 1];
        }
        let stabilizer = &prepared.stabilizer_indices[prepared.fixed_point_masks[mask]];
        let stabilizer_permutations = stabilizer
            .iter()
            .map(|&index| orbit.group_permutations[index].to_vec())
            .collect::<Vec<_>>();
        stabilizer_area = stabilizer_area
            .checked_add(stabilizer_permutations.len())
            .ok_or(OracleError::ArithmeticOverflow)?;
        let quotient_frontier_width = prepared.quotient_widths[mask];
        peak = peak.max(quotient_frontier_width);
        area = area
            .checked_add(quotient_frontier_width)
            .ok_or(OracleError::ArithmeticOverflow)?;
        levels.push(StabilizerLevelCertificate {
            depth,
            added_cell: depth.checked_sub(1).map(|index| cell_order[index]),
            prefix_cells: cell_order[..depth].to_vec(),
            fixed_carrier_points: points_in_mask(prepared.fixed_point_masks[mask], orbit.degree),
            stabilizer_permutations,
            live_prefix_width: prepared.live_widths[mask],
            quotient_frontier_width,
        });
    }
    Ok(OrderEvaluation {
        cell_order: cell_order.to_vec(),
        levels,
        objective: OrderObjective {
            peak_quotient_width: peak,
            total_quotient_width: area,
        },
        stabilizer_area,
    })
}

fn validate_verified_orbit_against_cap(
    orbit: &VerifiedForbiddenOrbit,
    cap: OracleCap,
) -> Result<(), OracleError> {
    check_cap(CappedResource::Degree, orbit.degree, cap.max_degree)?;
    check_cap(CappedResource::Cells, orbit.cell_count(), cap.max_cells)?;
    check_cap(
        CappedResource::OrbitMembers,
        orbit.members.len(),
        cap.max_orbit_members,
    )?;
    check_cap(
        CappedResource::GroupPermutations,
        orbit.group_permutations.len(),
        cap.max_group_permutations,
    )?;
    Ok(())
}

fn validate_row(row: &[u8], degree: usize, member: Option<usize>) -> Result<(), OracleError> {
    for (cell, &value) in row.iter().enumerate() {
        if usize::from(value) >= degree {
            return Err(match member {
                Some(member) => OracleError::MemberValueOutOfRange {
                    member,
                    cell,
                    value,
                    degree,
                },
                None => OracleError::SeedValueOutOfRange {
                    cell,
                    value,
                    degree,
                },
            });
        }
    }
    Ok(())
}

fn validate_permutation(
    permutation: &[usize],
    degree: usize,
    member: usize,
) -> Result<(), OracleError> {
    if permutation.len() != degree {
        return Err(OracleError::PermutationLength {
            member,
            expected: degree,
            actual: permutation.len(),
        });
    }
    let mut first_points = vec![None; degree];
    for (point, &image) in permutation.iter().enumerate() {
        if image >= degree {
            return Err(OracleError::PermutationImageOutOfRange {
                member,
                point,
                image,
                degree,
            });
        }
        if let Some(first_point) = first_points[image] {
            return Err(OracleError::DuplicatePermutationImage {
                member,
                image,
                first_point,
                second_point: point,
            });
        }
        first_points[image] = Some(point);
    }
    Ok(())
}

fn validate_cell_order(cell_count: usize, order: &[usize]) -> Result<(), OracleError> {
    if order.len() != cell_count {
        return Err(OracleError::CellOrderLength {
            expected: cell_count,
            actual: order.len(),
        });
    }
    let mut first_positions = vec![None; cell_count];
    for (position, &cell) in order.iter().enumerate() {
        if cell >= cell_count {
            return Err(OracleError::CellOutOfRange {
                position,
                cell,
                cell_count,
            });
        }
        if let Some(first_position) = first_positions[cell] {
            return Err(OracleError::DuplicateCell {
                cell,
                first_position,
                second_position: position,
            });
        }
        first_positions[cell] = Some(position);
    }
    Ok(())
}

fn conjugate(table: &[u8], degree: usize, permutation: &[usize]) -> Vec<u8> {
    let mut image = vec![0u8; table.len()];
    for left in 0..degree {
        for right in 0..degree {
            let source = left * degree + right;
            let target = permutation[left] * degree + permutation[right];
            image[target] = permutation[usize::from(table[source])] as u8;
        }
    }
    image
}

fn enumerate_permutations(
    degree: usize,
    expected: usize,
    meter: &mut WorkMeter,
) -> Result<Vec<Vec<usize>>, OracleError> {
    let mut current = (0..degree).collect::<Vec<_>>();
    let mut permutations = Vec::with_capacity(expected);
    loop {
        meter.charge(degree.max(1))?;
        permutations.push(current.clone());
        if !advance_permutation(&mut current) {
            break;
        }
    }
    if permutations.len() != expected {
        return Err(OracleError::InternalInconsistency);
    }
    Ok(permutations)
}

fn advance_permutation(values: &mut [usize]) -> bool {
    if values.len() < 2 {
        return false;
    }
    let Some(pivot) = (0..values.len() - 1)
        .rev()
        .find(|&index| values[index] < values[index + 1])
    else {
        return false;
    };
    let successor = (pivot + 1..values.len())
        .rev()
        .find(|&index| values[pivot] < values[index])
        .expect("a lexicographic pivot has a successor");
    values.swap(pivot, successor);
    values[pivot + 1..].reverse();
    true
}

fn checked_factorial(value: usize) -> Result<usize, OracleError> {
    (1..=value).try_fold(1usize, |product, factor| {
        product
            .checked_mul(factor)
            .ok_or(OracleError::ArithmeticOverflow)
    })
}

fn check_cap(resource: CappedResource, attempted: usize, limit: usize) -> Result<(), OracleError> {
    if attempted > limit {
        return Err(OracleError::CapExceeded {
            resource,
            limit,
            attempted,
        });
    }
    Ok(())
}

fn cells_in_mask(mask: usize, cell_count: usize) -> Vec<usize> {
    (0..cell_count)
        .filter(|&cell| mask & (1 << cell) != 0)
        .collect()
}

fn points_in_mask(mask: usize, degree: usize) -> Vec<usize> {
    (0..degree)
        .filter(|&point| mask & (1 << point) != 0)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims_for_seed(degree: usize, seed: &[u8]) -> Vec<OrbitMemberClaim> {
        let expected = checked_factorial(degree).unwrap();
        let mut meter = WorkMeter::new(usize::MAX);
        let permutations = enumerate_permutations(degree, expected, &mut meter).unwrap();
        let mut orbit = BTreeMap::<Vec<u8>, Vec<usize>>::new();
        for permutation in permutations {
            orbit
                .entry(conjugate(seed, degree, &permutation))
                .or_insert(permutation);
        }
        orbit
            .into_iter()
            .map(|(table, witness)| OrbitMemberClaim::new(table, witness))
            .collect()
    }

    fn rigid_seed(degree: usize) -> Vec<u8> {
        match degree {
            1 => vec![0],
            2 => vec![0, 0, 1, 0],
            3 => vec![0, 0, 1, 1, 1, 2, 2, 2, 2],
            4 => {
                let mut row = Vec::new();
                row.extend(std::iter::repeat_n(0, 1));
                row.extend(std::iter::repeat_n(1, 3));
                row.extend(std::iter::repeat_n(2, 5));
                row.extend(std::iter::repeat_n(3, 7));
                row
            }
            _ => panic!("test seed is defined only through degree four"),
        }
    }

    fn objective_for_order(widths: &[usize], order: &[usize]) -> OrderObjective {
        let mut mask = 0usize;
        let mut peak = widths[0];
        let mut area = widths[0];
        for &cell in order {
            mask |= 1 << cell;
            peak = peak.max(widths[mask]);
            area += widths[mask];
        }
        OrderObjective {
            peak_quotient_width: peak,
            total_quotient_width: area,
        }
    }

    fn brute_force_best(widths: &[usize], cells: usize) -> (OrderObjective, Vec<usize>) {
        let mut order = (0..cells).collect::<Vec<_>>();
        let mut best_objective = objective_for_order(widths, &order);
        let mut best_order = order.clone();
        while advance_permutation(&mut order) {
            let objective = objective_for_order(widths, &order);
            if objective < best_objective || (objective == best_objective && order < best_order) {
                best_objective = objective;
                best_order.clone_from(&order);
            }
        }
        (best_objective, best_order)
    }

    fn assert_stabilizer_level_replays(level: &StabilizerLevelCertificate, degree: usize) {
        let mut expected = BTreeSet::new();
        let mut meter = WorkMeter::new(usize::MAX);
        for permutation in
            enumerate_permutations(degree, checked_factorial(degree).unwrap(), &mut meter).unwrap()
        {
            let fixes_prefix = level.prefix_cells.iter().all(|&cell| {
                let left = cell / degree;
                let right = cell % degree;
                permutation[left] == left && permutation[right] == right
            });
            if fixes_prefix {
                expected.insert(permutation);
            }
        }
        assert_eq!(
            level
                .stabilizer_permutations
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
            expected
        );
        assert_eq!(level.stabilizer_permutations.len(), expected.len());
    }

    #[test]
    fn exhausts_groups_and_subset_frontiers_through_degree_four() {
        for degree in 1..=4 {
            let seed = rigid_seed(degree);
            let claims = claims_for_seed(degree, &seed);
            assert_eq!(claims.len(), checked_factorial(degree).unwrap());
            let orbit =
                verify_forbidden_orbit(degree, &seed, &claims, OracleCap::default()).unwrap();
            assert_eq!(orbit.telemetry.witnesses_replayed, claims.len());
            assert_eq!(orbit.telemetry.unique_orbit_images, claims.len());

            let prepared = prepare_frontiers(&orbit, OracleCap::default()).unwrap();
            assert_eq!(prepared.subset_count, 1usize << (degree * degree));
            let certificate = choose_stabilizer_order(&orbit, OracleCap::default()).unwrap();
            assert_eq!(certificate.selected.levels.len(), degree * degree + 1);
            assert_eq!(
                certificate.selected.levels[0].stabilizer_permutations.len(),
                checked_factorial(degree).unwrap()
            );
            assert_eq!(
                certificate
                    .selected
                    .levels
                    .last()
                    .unwrap()
                    .quotient_frontier_width,
                0
            );
            for level in &certificate.selected.levels {
                assert_stabilizer_level_replays(level, degree);
            }
            assert_eq!(
                certificate
                    .verify_exact(&orbit, OracleCap::default())
                    .unwrap(),
                certificate.telemetry
            );

            if degree <= 3 {
                let (objective, order) =
                    brute_force_best(&prepared.quotient_widths, degree * degree);
                assert_eq!(certificate.selected.objective, objective);
                assert_eq!(certificate.selected.cell_order, order);
            }
        }
    }

    #[test]
    fn exhausts_every_binary_operation_table() {
        for encoding in 0usize..(1 << 4) {
            let seed = (0..4)
                .map(|cell| ((encoding >> cell) & 1) as u8)
                .collect::<Vec<_>>();
            let claims = claims_for_seed(2, &seed);
            let orbit = verify_forbidden_orbit(2, &seed, &claims, OracleCap::default()).unwrap();
            let certificate = choose_stabilizer_order(&orbit, OracleCap::default()).unwrap();
            certificate
                .verify_exact(&orbit, OracleCap::default())
                .unwrap();
        }
    }

    #[test]
    fn constructed_orbit_strictly_beats_row_major_lexicographic_order() {
        let seed = vec![0, 0, 1, 0];
        let claims = claims_for_seed(2, &seed);
        let certificate = select_stabilizer_order(2, &seed, &claims, OracleCap::default()).unwrap();
        assert_eq!(certificate.selected.cell_order, vec![1, 2, 0, 3]);
        assert_eq!(
            certificate.selected.objective,
            OrderObjective {
                peak_quotient_width: 2,
                total_quotient_width: 5,
            }
        );
        assert_eq!(
            certificate.lexicographic_baseline.objective,
            OrderObjective {
                peak_quotient_width: 2,
                total_quotient_width: 7,
            }
        );
        assert!(certificate.strictly_beats_lexicographic());
    }

    #[test]
    fn stabilizer_quotient_really_merges_live_prefixes() {
        let seed = vec![1; 9];
        let claims = claims_for_seed(3, &seed);
        let orbit = verify_forbidden_orbit(3, &seed, &claims, OracleCap::default()).unwrap();
        let evaluation =
            evaluate_cell_order(&orbit, &(0..9).collect::<Vec<_>>(), OracleCap::default()).unwrap();
        let diagonal_prefix = &evaluation.levels[1];
        assert_eq!(diagonal_prefix.prefix_cells, vec![0]);
        assert_eq!(diagonal_prefix.stabilizer_permutations.len(), 2);
        assert!(diagonal_prefix.quotient_frontier_width < diagonal_prefix.live_prefix_width);
    }

    #[test]
    fn claim_order_and_nonleast_valid_witnesses_do_not_change_output() {
        let seed = rigid_seed(3);
        let claims = claims_for_seed(3, &seed);
        let first = select_stabilizer_order(3, &seed, &claims, OracleCap::default()).unwrap();
        let mut reversed = claims.clone();
        reversed.reverse();
        let second = select_stabilizer_order(3, &seed, &reversed, OracleCap::default()).unwrap();
        assert_eq!(first, second);

        let projection = (0..3)
            .flat_map(|left| std::iter::repeat_n(left as u8, 3))
            .collect::<Vec<_>>();
        let identity_claim = vec![OrbitMemberClaim::new(projection.clone(), vec![0, 1, 2])];
        let reverse_claim = vec![OrbitMemberClaim::new(projection.clone(), vec![2, 1, 0])];
        let identity =
            select_stabilizer_order(3, &projection, &identity_claim, OracleCap::default()).unwrap();
        let reverse =
            select_stabilizer_order(3, &projection, &reverse_claim, OracleCap::default()).unwrap();
        assert_eq!(identity, reverse);
    }

    #[test]
    fn malformed_tables_permutations_witnesses_and_orbits_fail_closed() {
        let seed = rigid_seed(2);
        let claims = claims_for_seed(2, &seed);

        assert_eq!(
            verify_forbidden_orbit(2, &seed, &[], OracleCap::default()).unwrap_err(),
            OracleError::EmptyOrbit
        );
        assert!(matches!(
            verify_forbidden_orbit(2, &seed[..3], &claims, OracleCap::default()).unwrap_err(),
            OracleError::SeedLength { .. }
        ));
        let mut bad_seed = seed.clone();
        bad_seed[0] = 2;
        assert!(matches!(
            verify_forbidden_orbit(2, &bad_seed, &claims, OracleCap::default()).unwrap_err(),
            OracleError::SeedValueOutOfRange { .. }
        ));

        let mut short_row = claims.clone();
        short_row[0].table = vec![0, 0, 0].into_boxed_slice();
        assert!(matches!(
            verify_forbidden_orbit(2, &seed, &short_row, OracleCap::default()).unwrap_err(),
            OracleError::MemberLength { .. }
        ));
        let mut bad_value = claims.clone();
        bad_value[0].table[0] = 2;
        assert!(matches!(
            verify_forbidden_orbit(2, &seed, &bad_value, OracleCap::default()).unwrap_err(),
            OracleError::MemberValueOutOfRange { .. }
        ));

        let mut short_permutation = claims.clone();
        short_permutation[0].seed_to_member = vec![0].into_boxed_slice();
        assert!(matches!(
            verify_forbidden_orbit(2, &seed, &short_permutation, OracleCap::default()).unwrap_err(),
            OracleError::PermutationLength { .. }
        ));
        let mut out_of_range = claims.clone();
        out_of_range[0].seed_to_member = vec![0, 2].into_boxed_slice();
        assert!(matches!(
            verify_forbidden_orbit(2, &seed, &out_of_range, OracleCap::default()).unwrap_err(),
            OracleError::PermutationImageOutOfRange { .. }
        ));
        let mut duplicate_image = claims.clone();
        duplicate_image[0].seed_to_member = vec![0, 0].into_boxed_slice();
        assert!(matches!(
            verify_forbidden_orbit(2, &seed, &duplicate_image, OracleCap::default()).unwrap_err(),
            OracleError::DuplicatePermutationImage { .. }
        ));

        let mut replay_mismatch = claims.clone();
        let mismatching = replay_mismatch
            .iter()
            .position(|claim| claim.table.as_ref() != seed)
            .unwrap();
        replay_mismatch[mismatching].seed_to_member = vec![0, 1].into_boxed_slice();
        assert_eq!(
            verify_forbidden_orbit(2, &seed, &replay_mismatch, OracleCap::default()).unwrap_err(),
            OracleError::WitnessReplayMismatch {
                member: mismatching
            }
        );

        let mut duplicate = claims.clone();
        duplicate.push(claims[0].clone());
        assert!(matches!(
            verify_forbidden_orbit(2, &seed, &duplicate, OracleCap::default()).unwrap_err(),
            OracleError::DuplicateOrbitMember { .. }
        ));
        let mut missing = claims.clone();
        missing.pop();
        assert!(matches!(
            verify_forbidden_orbit(2, &seed, &missing, OracleCap::default()).unwrap_err(),
            OracleError::OrbitSetMismatch { missing: 1, .. }
        ));
    }

    #[test]
    fn malformed_orders_and_caps_fail_closed() {
        let seed = rigid_seed(4);
        let claims = claims_for_seed(4, &seed);

        let mut cap = OracleCap::default();
        cap.max_degree = 3;
        assert!(matches!(
            verify_forbidden_orbit(4, &seed, &claims, cap).unwrap_err(),
            OracleError::CapExceeded {
                resource: CappedResource::Degree,
                ..
            }
        ));
        cap = OracleCap::default();
        cap.max_cells = 15;
        assert!(matches!(
            verify_forbidden_orbit(4, &seed, &claims, cap).unwrap_err(),
            OracleError::CapExceeded {
                resource: CappedResource::Cells,
                ..
            }
        ));
        cap = OracleCap::default();
        cap.max_orbit_members = 23;
        assert!(matches!(
            verify_forbidden_orbit(4, &seed, &claims, cap).unwrap_err(),
            OracleError::CapExceeded {
                resource: CappedResource::OrbitMembers,
                ..
            }
        ));
        cap = OracleCap::default();
        cap.max_group_permutations = 23;
        assert!(matches!(
            verify_forbidden_orbit(4, &seed, &claims, cap).unwrap_err(),
            OracleError::CapExceeded {
                resource: CappedResource::GroupPermutations,
                ..
            }
        ));

        let orbit = verify_forbidden_orbit(4, &seed, &claims, OracleCap::default()).unwrap();
        cap = OracleCap::default();
        cap.max_subsets = (1 << 16) - 1;
        assert!(matches!(
            choose_stabilizer_order(&orbit, cap).unwrap_err(),
            OracleError::CapExceeded {
                resource: CappedResource::Subsets,
                ..
            }
        ));
        cap = OracleCap::default();
        cap.max_frontier_states = 0;
        assert!(matches!(
            choose_stabilizer_order(&orbit, cap).unwrap_err(),
            OracleError::CapExceeded {
                resource: CappedResource::FrontierStates,
                ..
            }
        ));
        cap = OracleCap::default();
        cap.max_work_units = 0;
        assert!(matches!(
            choose_stabilizer_order(&orbit, cap).unwrap_err(),
            OracleError::CapExceeded {
                resource: CappedResource::WorkUnits,
                ..
            }
        ));

        assert!(matches!(
            evaluate_cell_order(&orbit, &[0, 1], OracleCap::default()).unwrap_err(),
            OracleError::CellOrderLength { .. }
        ));
        let mut duplicate_order = (0..16).collect::<Vec<_>>();
        duplicate_order[15] = 0;
        assert!(matches!(
            evaluate_cell_order(&orbit, &duplicate_order, OracleCap::default()).unwrap_err(),
            OracleError::DuplicateCell { .. }
        ));
        let mut out_of_range_order = (0..16).collect::<Vec<_>>();
        out_of_range_order[15] = 16;
        assert!(matches!(
            evaluate_cell_order(&orbit, &out_of_range_order, OracleCap::default()).unwrap_err(),
            OracleError::CellOutOfRange { .. }
        ));
    }

    #[test]
    fn exact_replay_rejects_every_tampered_certificate_component() {
        let seed = rigid_seed(2);
        let claims = claims_for_seed(2, &seed);
        let orbit = verify_forbidden_orbit(2, &seed, &claims, OracleCap::default()).unwrap();
        let certificate = choose_stabilizer_order(&orbit, OracleCap::default()).unwrap();

        let mut bad_order = certificate.clone();
        bad_order.selected.cell_order.swap(0, 1);
        assert_eq!(
            bad_order
                .verify_exact(&orbit, OracleCap::default())
                .unwrap_err(),
            OracleError::CertificateMismatch
        );

        let mut bad_stabilizer = certificate.clone();
        bad_stabilizer.selected.levels[0]
            .stabilizer_permutations
            .pop();
        assert_eq!(
            bad_stabilizer
                .verify_exact(&orbit, OracleCap::default())
                .unwrap_err(),
            OracleError::CertificateMismatch
        );

        let mut bad_width = certificate.clone();
        bad_width.selected.levels[0].quotient_frontier_width += 1;
        assert_eq!(
            bad_width
                .verify_exact(&orbit, OracleCap::default())
                .unwrap_err(),
            OracleError::CertificateMismatch
        );

        let mut bad_witness = certificate.clone();
        bad_witness.least_seed_witnesses[0].reverse();
        assert_eq!(
            replay_order_certificate(2, &seed, &claims, &bad_witness, OracleCap::default())
                .unwrap_err(),
            OracleError::CertificateMismatch
        );
    }
}
