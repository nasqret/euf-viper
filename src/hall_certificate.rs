#![cfg(test)]
#![allow(dead_code)]

//! Exact, test-only certificates for Hall-set propagation.
//!
//! The checker in this module trusts neither the producer's neighborhood nor
//! its conclusion.  It binds a certificate to an ordered variable-domain
//! snapshot with SHA-256, reconstructs `N(S)`, checks the relevant Hall
//! cardinality, and validates every claimed value removal.  Certificate
//! extraction is deliberately separate from verification and is exhaustive
//! only below an explicit small-instance cap.
//!
//! Domains, Hall subsets, and neighborhoods are represented by `u64` bitsets.
//! This keeps the reference checker simple and exact while imposing hard caps
//! of 64 variables and 64 values.

use std::error::Error;
use std::fmt;

pub const HALL_CERTIFICATE_VERSION: u16 = 1;
pub const HARD_MAX_VARIABLES: usize = u64::BITS as usize;
pub const HARD_MAX_VALUES: usize = u64::BITS as usize;
pub const HARD_MAX_EXTRACTION_VARIABLES: usize = 24;

/// Resource limits checked before any certificate work is performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HallCaps {
    pub max_variables: usize,
    pub max_values: usize,
    pub max_witness_variables: usize,
    pub max_removal_records: usize,
    pub max_extraction_variables: usize,
}

impl Default for HallCaps {
    fn default() -> Self {
        Self {
            max_variables: HARD_MAX_VARIABLES,
            max_values: HARD_MAX_VALUES,
            max_witness_variables: HARD_MAX_VARIABLES,
            max_removal_records: HARD_MAX_VARIABLES,
            max_extraction_variables: 20,
        }
    }
}

impl HallCaps {
    fn validate(self) -> Result<(), HallCertificateError> {
        if self.max_variables > HARD_MAX_VARIABLES {
            return Err(HallCertificateError::InvalidCaps(
                "max_variables exceeds the bitset width",
            ));
        }
        if self.max_values > HARD_MAX_VALUES {
            return Err(HallCertificateError::InvalidCaps(
                "max_values exceeds the bitset width",
            ));
        }
        if self.max_witness_variables > self.max_variables {
            return Err(HallCertificateError::InvalidCaps(
                "max_witness_variables exceeds max_variables",
            ));
        }
        if self.max_removal_records > self.max_variables {
            return Err(HallCertificateError::InvalidCaps(
                "max_removal_records exceeds max_variables",
            ));
        }
        if self.max_extraction_variables > HARD_MAX_EXTRACTION_VARIABLES {
            return Err(HallCertificateError::InvalidCaps(
                "max_extraction_variables exceeds the hard exponential-search cap",
            ));
        }
        if self.max_extraction_variables > self.max_variables {
            return Err(HallCertificateError::InvalidCaps(
                "max_extraction_variables exceeds max_variables",
            ));
        }
        Ok(())
    }
}

/// A set of finite-domain values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValueSet(u64);

impl ValueSet {
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn singleton(value: usize) -> Option<Self> {
        if value < HARD_MAX_VALUES {
            Some(Self(1u64 << value))
        } else {
            None
        }
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
        value < HARD_MAX_VALUES && self.0 & (1u64 << value) != 0
    }

    const fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// A set of variables participating in a Hall witness.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VariableSet(u64);

impl VariableSet {
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

    pub const fn contains(self, variable: usize) -> bool {
        variable < HARD_MAX_VARIABLES && self.0 & (1u64 << variable) != 0
    }
}

/// Ordered finite-domain state to which a certificate is bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSnapshot {
    value_count: usize,
    domains: Box<[ValueSet]>,
}

impl DomainSnapshot {
    pub fn new(value_count: usize, domains: Vec<ValueSet>) -> Result<Self, HallCertificateError> {
        let snapshot = Self {
            value_count,
            domains: domains.into_boxed_slice(),
        };
        snapshot.validate_hard_limits()?;
        Ok(snapshot)
    }

    pub fn from_bits(value_count: usize, domains: Vec<u64>) -> Result<Self, HallCertificateError> {
        Self::new(
            value_count,
            domains.into_iter().map(ValueSet::from_bits).collect(),
        )
    }

    pub fn variable_count(&self) -> usize {
        self.domains.len()
    }

    pub fn value_count(&self) -> usize {
        self.value_count
    }

    pub fn domains(&self) -> &[ValueSet] {
        &self.domains
    }

    pub fn fingerprint(&self) -> SnapshotFingerprint {
        let mut encoding = Vec::with_capacity(48 + self.domains.len() * 8);
        encoding.extend_from_slice(b"euf-viper/hall-domain-snapshot/v1\0");
        encoding.extend_from_slice(&(self.domains.len() as u64).to_le_bytes());
        encoding.extend_from_slice(&(self.value_count as u64).to_le_bytes());
        for domain in &self.domains {
            encoding.extend_from_slice(&domain.bits().to_le_bytes());
        }
        SnapshotFingerprint(sha256(&encoding))
    }

    fn validate_hard_limits(&self) -> Result<(), HallCertificateError> {
        if self.variable_count() > HARD_MAX_VARIABLES {
            return Err(HallCertificateError::TooManyVariables {
                observed: self.variable_count(),
                limit: HARD_MAX_VARIABLES,
            });
        }
        if self.value_count > HARD_MAX_VALUES {
            return Err(HallCertificateError::TooManyValues {
                observed: self.value_count,
                limit: HARD_MAX_VALUES,
            });
        }
        let allowed = low_bits(self.value_count);
        for (variable, domain) in self.domains.iter().enumerate() {
            if domain.bits() & !allowed != 0 {
                return Err(HallCertificateError::DomainBitsOutOfRange {
                    variable,
                    bits: domain.bits() & !allowed,
                });
            }
        }
        Ok(())
    }
}

/// SHA-256 commitment to an ordered [`DomainSnapshot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SnapshotFingerprint([u8; 32]);

impl SnapshotFingerprint {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Hall subset and the producer's claimed exact neighborhood.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HallSubsetWitness {
    variables: VariableSet,
    claimed_neighborhood: ValueSet,
}

impl HallSubsetWitness {
    pub const fn new(variables: VariableSet, claimed_neighborhood: ValueSet) -> Self {
        Self {
            variables,
            claimed_neighborhood,
        }
    }

    pub const fn variables(self) -> VariableSet {
        self.variables
    }

    pub const fn claimed_neighborhood(self) -> ValueSet {
        self.claimed_neighborhood
    }
}

/// One or more values claimed removable from one variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueRemoval {
    variable: usize,
    values: ValueSet,
}

impl ValueRemoval {
    pub const fn new(variable: usize, values: ValueSet) -> Self {
        Self { variable, values }
    }

    pub const fn variable(self) -> usize {
        self.variable
    }

    pub const fn values(self) -> ValueSet {
        self.values
    }
}

/// The consequence claimed by a Hall certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HallConclusion {
    /// Sorted, unique variable records.  Every value bit is checked.
    RemoveValues(Box<[ValueRemoval]>),
    /// The all-different constraint is inconsistent at this snapshot.
    Conflict,
}

/// Untrusted proof object.  Use [`verify_hall_certificate`] before consuming it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HallCertificate {
    version: u16,
    snapshot_fingerprint: SnapshotFingerprint,
    witness: HallSubsetWitness,
    conclusion: HallConclusion,
}

impl HallCertificate {
    pub fn from_parts(
        version: u16,
        snapshot_fingerprint: SnapshotFingerprint,
        witness: HallSubsetWitness,
        conclusion: HallConclusion,
    ) -> Self {
        Self {
            version,
            snapshot_fingerprint,
            witness,
            conclusion,
        }
    }

    pub fn conflict(snapshot: &DomainSnapshot, witness: HallSubsetWitness) -> Self {
        Self::from_parts(
            HALL_CERTIFICATE_VERSION,
            snapshot.fingerprint(),
            witness,
            HallConclusion::Conflict,
        )
    }

    pub fn removals(
        snapshot: &DomainSnapshot,
        witness: HallSubsetWitness,
        removals: Vec<ValueRemoval>,
    ) -> Self {
        Self::from_parts(
            HALL_CERTIFICATE_VERSION,
            snapshot.fingerprint(),
            witness,
            HallConclusion::RemoveValues(removals.into_boxed_slice()),
        )
    }

    pub const fn version(&self) -> u16 {
        self.version
    }

    pub const fn snapshot_fingerprint(&self) -> SnapshotFingerprint {
        self.snapshot_fingerprint
    }

    pub const fn witness(&self) -> HallSubsetWitness {
        self.witness
    }

    pub fn conclusion(&self) -> &HallConclusion {
        &self.conclusion
    }
}

/// Audited facts returned only after exact certificate replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHallCertificate {
    witness_variables: VariableSet,
    exact_neighborhood: ValueSet,
    subset_size: usize,
    neighborhood_size: usize,
    removed_value_count: usize,
    is_conflict: bool,
}

impl VerifiedHallCertificate {
    pub const fn witness_variables(&self) -> VariableSet {
        self.witness_variables
    }

    pub const fn exact_neighborhood(&self) -> ValueSet {
        self.exact_neighborhood
    }

    pub const fn subset_size(&self) -> usize {
        self.subset_size
    }

    pub const fn neighborhood_size(&self) -> usize {
        self.neighborhood_size
    }

    pub const fn removed_value_count(&self) -> usize {
        self.removed_value_count
    }

    pub const fn is_conflict(&self) -> bool {
        self.is_conflict
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HallCertificateError {
    InvalidCaps(&'static str),
    TooManyVariables {
        observed: usize,
        limit: usize,
    },
    TooManyValues {
        observed: usize,
        limit: usize,
    },
    TooManyWitnessVariables {
        observed: usize,
        limit: usize,
    },
    TooManyRemovalRecords {
        observed: usize,
        limit: usize,
    },
    ExtractionCapExceeded {
        observed: usize,
        limit: usize,
    },
    DomainBitsOutOfRange {
        variable: usize,
        bits: u64,
    },
    UnsupportedVersion {
        observed: u16,
    },
    SnapshotFingerprintMismatch,
    EmptyWitness,
    WitnessVariablesOutOfRange {
        bits: u64,
    },
    ClaimedNeighborhoodOutOfRange {
        bits: u64,
    },
    NeighborhoodMismatch {
        claimed: u64,
        actual: u64,
    },
    NotHallConflict {
        subset_size: usize,
        neighborhood_size: usize,
    },
    NotTightHallSet {
        subset_size: usize,
        neighborhood_size: usize,
    },
    EmptyRemovalList,
    RemovalRecordsNotStrictlySorted {
        previous: usize,
        current: usize,
    },
    RemovalVariableOutOfRange {
        variable: usize,
    },
    RemovalVariableInsideWitness {
        variable: usize,
    },
    EmptyRemovalValues {
        variable: usize,
    },
    RemovalValuesOutOfRange {
        variable: usize,
        bits: u64,
    },
    RemovalValuesOutsideNeighborhood {
        variable: usize,
        bits: u64,
    },
    RemovalValuesOutsideDomain {
        variable: usize,
        bits: u64,
    },
}

impl fmt::Display for HallCertificateError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCaps(reason) => write!(output, "invalid Hall certificate caps: {reason}"),
            Self::TooManyVariables { observed, limit } => {
                write!(output, "snapshot has {observed} variables, cap is {limit}")
            }
            Self::TooManyValues { observed, limit } => {
                write!(output, "snapshot has {observed} values, cap is {limit}")
            }
            Self::TooManyWitnessVariables { observed, limit } => write!(
                output,
                "Hall witness has {observed} variables, cap is {limit}"
            ),
            Self::TooManyRemovalRecords { observed, limit } => write!(
                output,
                "Hall certificate has {observed} removal records, cap is {limit}"
            ),
            Self::ExtractionCapExceeded { observed, limit } => write!(
                output,
                "exact Hall extraction needs {observed} variables, cap is {limit}"
            ),
            Self::DomainBitsOutOfRange { variable, bits } => write!(
                output,
                "domain {variable} contains out-of-range value bits {bits:#x}"
            ),
            Self::UnsupportedVersion { observed } => {
                write!(output, "unsupported Hall certificate version {observed}")
            }
            Self::SnapshotFingerprintMismatch => {
                write!(output, "Hall certificate snapshot fingerprint mismatch")
            }
            Self::EmptyWitness => write!(output, "Hall witness is empty"),
            Self::WitnessVariablesOutOfRange { bits } => {
                write!(
                    output,
                    "Hall witness contains out-of-range variables {bits:#x}"
                )
            }
            Self::ClaimedNeighborhoodOutOfRange { bits } => write!(
                output,
                "claimed Hall neighborhood contains out-of-range values {bits:#x}"
            ),
            Self::NeighborhoodMismatch { claimed, actual } => write!(
                output,
                "claimed Hall neighborhood {claimed:#x} differs from exact neighborhood {actual:#x}"
            ),
            Self::NotHallConflict {
                subset_size,
                neighborhood_size,
            } => write!(
                output,
                "conflict needs |N(S)| < |S|, observed {neighborhood_size} >= {subset_size}"
            ),
            Self::NotTightHallSet {
                subset_size,
                neighborhood_size,
            } => write!(
                output,
                "pruning needs |N(S)| = |S|, observed {neighborhood_size} != {subset_size}"
            ),
            Self::EmptyRemovalList => write!(output, "Hall pruning conclusion is empty"),
            Self::RemovalRecordsNotStrictlySorted { previous, current } => write!(
                output,
                "removal records are not strictly sorted: {previous} then {current}"
            ),
            Self::RemovalVariableOutOfRange { variable } => {
                write!(output, "removal variable {variable} is out of range")
            }
            Self::RemovalVariableInsideWitness { variable } => write!(
                output,
                "removal variable {variable} belongs to the Hall subset"
            ),
            Self::EmptyRemovalValues { variable } => {
                write!(output, "removal for variable {variable} has no values")
            }
            Self::RemovalValuesOutOfRange { variable, bits } => write!(
                output,
                "removal for variable {variable} contains out-of-range values {bits:#x}"
            ),
            Self::RemovalValuesOutsideNeighborhood { variable, bits } => write!(
                output,
                "removal for variable {variable} claims values outside N(S): {bits:#x}"
            ),
            Self::RemovalValuesOutsideDomain { variable, bits } => write!(
                output,
                "removal for variable {variable} claims absent domain values: {bits:#x}"
            ),
        }
    }
}

impl Error for HallCertificateError {}

/// Independently validates a Hall certificate against the current snapshot.
pub fn verify_hall_certificate(
    snapshot: &DomainSnapshot,
    certificate: &HallCertificate,
    caps: HallCaps,
) -> Result<VerifiedHallCertificate, HallCertificateError> {
    validate_snapshot_with_caps(snapshot, caps)?;

    if certificate.version != HALL_CERTIFICATE_VERSION {
        return Err(HallCertificateError::UnsupportedVersion {
            observed: certificate.version,
        });
    }
    if certificate.snapshot_fingerprint != snapshot.fingerprint() {
        return Err(HallCertificateError::SnapshotFingerprintMismatch);
    }

    let witness = certificate.witness;
    let variables = witness.variables;
    if variables.is_empty() {
        return Err(HallCertificateError::EmptyWitness);
    }
    let variable_mask = low_bits(snapshot.variable_count());
    if variables.bits() & !variable_mask != 0 {
        return Err(HallCertificateError::WitnessVariablesOutOfRange {
            bits: variables.bits() & !variable_mask,
        });
    }
    if variables.len() > caps.max_witness_variables {
        return Err(HallCertificateError::TooManyWitnessVariables {
            observed: variables.len(),
            limit: caps.max_witness_variables,
        });
    }

    let value_mask = low_bits(snapshot.value_count());
    if witness.claimed_neighborhood.bits() & !value_mask != 0 {
        return Err(HallCertificateError::ClaimedNeighborhoodOutOfRange {
            bits: witness.claimed_neighborhood.bits() & !value_mask,
        });
    }
    let exact_neighborhood = neighborhood(snapshot, variables);
    if witness.claimed_neighborhood != exact_neighborhood {
        return Err(HallCertificateError::NeighborhoodMismatch {
            claimed: witness.claimed_neighborhood.bits(),
            actual: exact_neighborhood.bits(),
        });
    }

    let subset_size = variables.len();
    let neighborhood_size = exact_neighborhood.len();
    let (removed_value_count, is_conflict) = match &certificate.conclusion {
        HallConclusion::Conflict => {
            if neighborhood_size >= subset_size {
                return Err(HallCertificateError::NotHallConflict {
                    subset_size,
                    neighborhood_size,
                });
            }
            (0, true)
        }
        HallConclusion::RemoveValues(removals) => {
            if neighborhood_size != subset_size {
                return Err(HallCertificateError::NotTightHallSet {
                    subset_size,
                    neighborhood_size,
                });
            }
            validate_removal_shape(snapshot, removals, caps)?;
            let mut removed_value_count = 0usize;
            for removal in removals.iter().copied() {
                if variables.contains(removal.variable) {
                    return Err(HallCertificateError::RemovalVariableInsideWitness {
                        variable: removal.variable,
                    });
                }
                if !removal.values.is_subset_of(exact_neighborhood) {
                    return Err(HallCertificateError::RemovalValuesOutsideNeighborhood {
                        variable: removal.variable,
                        bits: removal.values.bits() & !exact_neighborhood.bits(),
                    });
                }
                removed_value_count += removal.values.len();
            }
            (removed_value_count, false)
        }
    };

    Ok(VerifiedHallCertificate {
        witness_variables: variables,
        exact_neighborhood,
        subset_size,
        neighborhood_size,
        removed_value_count,
        is_conflict,
    })
}

/// Finds the least conflict witness ordered by `(cardinality, raw bitset)`.
///
/// The checker does not call this extractor.  Extraction rejects snapshots
/// larger than `caps.max_extraction_variables` before enumerating subsets.
pub fn extract_minimal_conflict_certificate(
    snapshot: &DomainSnapshot,
    caps: HallCaps,
) -> Result<Option<HallCertificate>, HallCertificateError> {
    validate_extraction_input(snapshot, caps)?;
    for_each_subset_in_minimal_order(snapshot.variable_count(), |variables| {
        let exact_neighborhood = neighborhood(snapshot, variables);
        if exact_neighborhood.len() < variables.len() {
            Some(HallCertificate::conflict(
                snapshot,
                HallSubsetWitness::new(variables, exact_neighborhood),
            ))
        } else {
            None
        }
    })
    .map_or(Ok(None), |certificate| {
        verify_hall_certificate(snapshot, &certificate, caps)?;
        Ok(Some(certificate))
    })
}

/// Finds the least tight Hall subset proving all requested removals.
///
/// Requested records must already be strictly sorted by variable and contain
/// only values currently present in that variable's domain.  The extractor
/// preserves them exactly; it does not silently canonicalize malformed input.
pub fn extract_minimal_removal_certificate(
    snapshot: &DomainSnapshot,
    removals: &[ValueRemoval],
    caps: HallCaps,
) -> Result<Option<HallCertificate>, HallCertificateError> {
    validate_extraction_input(snapshot, caps)?;
    validate_removal_shape(snapshot, removals, caps)?;

    for_each_subset_in_minimal_order(snapshot.variable_count(), |variables| {
        let exact_neighborhood = neighborhood(snapshot, variables);
        let proves_all = exact_neighborhood.len() == variables.len()
            && removals.iter().all(|removal| {
                !variables.contains(removal.variable)
                    && removal.values.is_subset_of(exact_neighborhood)
            });
        if proves_all {
            Some(HallCertificate::removals(
                snapshot,
                HallSubsetWitness::new(variables, exact_neighborhood),
                removals.to_vec(),
            ))
        } else {
            None
        }
    })
    .map_or(Ok(None), |certificate| {
        verify_hall_certificate(snapshot, &certificate, caps)?;
        Ok(Some(certificate))
    })
}

fn validate_snapshot_with_caps(
    snapshot: &DomainSnapshot,
    caps: HallCaps,
) -> Result<(), HallCertificateError> {
    caps.validate()?;
    snapshot.validate_hard_limits()?;
    if snapshot.variable_count() > caps.max_variables {
        return Err(HallCertificateError::TooManyVariables {
            observed: snapshot.variable_count(),
            limit: caps.max_variables,
        });
    }
    if snapshot.value_count() > caps.max_values {
        return Err(HallCertificateError::TooManyValues {
            observed: snapshot.value_count(),
            limit: caps.max_values,
        });
    }
    Ok(())
}

fn validate_extraction_input(
    snapshot: &DomainSnapshot,
    caps: HallCaps,
) -> Result<(), HallCertificateError> {
    validate_snapshot_with_caps(snapshot, caps)?;
    if snapshot.variable_count() > caps.max_extraction_variables {
        return Err(HallCertificateError::ExtractionCapExceeded {
            observed: snapshot.variable_count(),
            limit: caps.max_extraction_variables,
        });
    }
    Ok(())
}

fn validate_removal_shape(
    snapshot: &DomainSnapshot,
    removals: &[ValueRemoval],
    caps: HallCaps,
) -> Result<(), HallCertificateError> {
    if removals.is_empty() {
        return Err(HallCertificateError::EmptyRemovalList);
    }
    if removals.len() > caps.max_removal_records {
        return Err(HallCertificateError::TooManyRemovalRecords {
            observed: removals.len(),
            limit: caps.max_removal_records,
        });
    }
    let value_mask = low_bits(snapshot.value_count());
    let mut previous = None;
    for removal in removals.iter().copied() {
        if let Some(previous) = previous
            && removal.variable <= previous
        {
            return Err(HallCertificateError::RemovalRecordsNotStrictlySorted {
                previous,
                current: removal.variable,
            });
        }
        previous = Some(removal.variable);
        if removal.variable >= snapshot.variable_count() {
            return Err(HallCertificateError::RemovalVariableOutOfRange {
                variable: removal.variable,
            });
        }
        if removal.values.is_empty() {
            return Err(HallCertificateError::EmptyRemovalValues {
                variable: removal.variable,
            });
        }
        if removal.values.bits() & !value_mask != 0 {
            return Err(HallCertificateError::RemovalValuesOutOfRange {
                variable: removal.variable,
                bits: removal.values.bits() & !value_mask,
            });
        }
        let domain = snapshot.domains[removal.variable];
        if !removal.values.is_subset_of(domain) {
            return Err(HallCertificateError::RemovalValuesOutsideDomain {
                variable: removal.variable,
                bits: removal.values.bits() & !domain.bits(),
            });
        }
    }
    Ok(())
}

fn neighborhood(snapshot: &DomainSnapshot, variables: VariableSet) -> ValueSet {
    let mut result = ValueSet::default();
    let mut remaining = variables.bits();
    while remaining != 0 {
        let variable = remaining.trailing_zeros() as usize;
        result = result.union(snapshot.domains[variable]);
        remaining &= remaining - 1;
    }
    result
}

fn for_each_subset_in_minimal_order<T>(
    variable_count: usize,
    mut visit: impl FnMut(VariableSet) -> Option<T>,
) -> Option<T> {
    debug_assert!(variable_count <= HARD_MAX_EXTRACTION_VARIABLES);
    if variable_count == 0 {
        return None;
    }
    let end = 1u64 << variable_count;
    for cardinality in 1..=variable_count {
        let mut bits = (1u64 << cardinality) - 1;
        while bits < end {
            if let Some(result) = visit(VariableSet::from_bits(bits)) {
                return Some(result);
            }
            let least_bit = bits & bits.wrapping_neg();
            let incremented = bits + least_bit;
            bits = (((incremented ^ bits) >> 2) / least_bit) | incremented;
        }
    }
    None
}

const fn low_bits(count: usize) -> u64 {
    if count == HARD_MAX_VALUES {
        u64::MAX
    } else if count == 0 {
        0
    } else {
        (1u64 << count) - 1
    }
}

// Small, dependency-free SHA-256 implementation.  Keeping the commitment in
// this test-only module lets it compile and replay independently of features
// selected by the production crate.
fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    let bit_length = (input.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity((input.len() + 72) & !63);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    let mut state = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut schedule = [0u32; 64];
        for (index, word) in chunk.chunks_exact(4).enumerate() {
            schedule[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(ROUND[index])
                .wrapping_add(schedule[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut digest = [0u8; 32];
    for (chunk, word) in digest.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn values(bits: u64) -> ValueSet {
        ValueSet::from_bits(bits)
    }

    fn snapshot(value_count: usize, domains: &[u64]) -> DomainSnapshot {
        DomainSnapshot::from_bits(value_count, domains.to_vec()).unwrap()
    }

    #[test]
    fn sha256_and_snapshot_commitment_are_deterministic() {
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        let first = snapshot(3, &[0b001, 0b110]);
        let same = snapshot(3, &[0b001, 0b110]);
        let reordered = snapshot(3, &[0b110, 0b001]);
        let wider = snapshot(4, &[0b001, 0b110]);
        assert_eq!(first.fingerprint(), same.fingerprint());
        assert_ne!(first.fingerprint(), reordered.fingerprint());
        assert_ne!(first.fingerprint(), wider.fingerprint());
    }

    #[test]
    fn exact_checker_accepts_tight_set_pruning_and_conflict() {
        let pruning = snapshot(3, &[0b001, 0b011, 0b110]);
        let pruning_certificate = HallCertificate::removals(
            &pruning,
            HallSubsetWitness::new(VariableSet::from_bits(0b011), values(0b011)),
            vec![ValueRemoval::new(2, values(0b010))],
        );
        let verified =
            verify_hall_certificate(&pruning, &pruning_certificate, HallCaps::default()).unwrap();
        assert_eq!(verified.subset_size(), 2);
        assert_eq!(verified.neighborhood_size(), 2);
        assert_eq!(verified.removed_value_count(), 1);
        assert!(!verified.is_conflict());

        let multi_pruning = snapshot(3, &[0b001, 0b011, 0b101]);
        let multi_certificate = HallCertificate::removals(
            &multi_pruning,
            HallSubsetWitness::new(VariableSet::from_bits(0b001), values(0b001)),
            vec![
                ValueRemoval::new(1, values(0b001)),
                ValueRemoval::new(2, values(0b001)),
            ],
        );
        assert_eq!(
            verify_hall_certificate(&multi_pruning, &multi_certificate, HallCaps::default())
                .unwrap()
                .removed_value_count(),
            2
        );
        let tampered_second_removal = HallCertificate::removals(
            &multi_pruning,
            HallSubsetWitness::new(VariableSet::from_bits(0b001), values(0b001)),
            vec![
                ValueRemoval::new(1, values(0b001)),
                ValueRemoval::new(2, values(0b100)),
            ],
        );
        assert_eq!(
            verify_hall_certificate(
                &multi_pruning,
                &tampered_second_removal,
                HallCaps::default(),
            ),
            Err(HallCertificateError::RemovalValuesOutsideNeighborhood {
                variable: 2,
                bits: 0b100,
            })
        );

        let conflicting = snapshot(2, &[0b01, 0b01]);
        let conflict_certificate = HallCertificate::conflict(
            &conflicting,
            HallSubsetWitness::new(VariableSet::from_bits(0b11), values(0b01)),
        );
        let verified =
            verify_hall_certificate(&conflicting, &conflict_certificate, HallCaps::default())
                .unwrap();
        assert_eq!(verified.subset_size(), 2);
        assert_eq!(verified.neighborhood_size(), 1);
        assert!(verified.is_conflict());
    }

    #[test]
    fn minimal_extractors_use_cardinality_then_raw_bitset() {
        let conflicting = snapshot(3, &[0b001, 0b001, 0b010]);
        let certificate = extract_minimal_conflict_certificate(&conflicting, HallCaps::default())
            .unwrap()
            .unwrap();
        assert_eq!(certificate.witness().variables().bits(), 0b011);

        let pruning = snapshot(3, &[0b001, 0b011, 0b110]);
        let removals = [ValueRemoval::new(2, values(0b010))];
        let certificate =
            extract_minimal_removal_certificate(&pruning, &removals, HallCaps::default())
                .unwrap()
                .unwrap();
        assert_eq!(certificate.witness().variables().bits(), 0b011);
        assert_eq!(
            certificate.conclusion(),
            &HallConclusion::RemoveValues(removals.into())
        );
    }

    #[test]
    fn stale_and_tampered_certificates_fail_closed() {
        let original = snapshot(3, &[0b001, 0b011, 0b110]);
        let witness = HallSubsetWitness::new(VariableSet::from_bits(0b011), values(0b011));
        let good = HallCertificate::removals(
            &original,
            witness,
            vec![ValueRemoval::new(2, values(0b010))],
        );
        assert!(verify_hall_certificate(&original, &good, HallCaps::default()).is_ok());

        let changed_snapshot = snapshot(3, &[0b001, 0b011, 0b100]);
        assert_eq!(
            verify_hall_certificate(&changed_snapshot, &good, HallCaps::default()),
            Err(HallCertificateError::SnapshotFingerprintMismatch)
        );

        let wrong_digest = HallCertificate::from_parts(
            HALL_CERTIFICATE_VERSION,
            SnapshotFingerprint::from_bytes([0x5a; 32]),
            witness,
            good.conclusion().clone(),
        );
        assert_eq!(
            verify_hall_certificate(&original, &wrong_digest, HallCaps::default()),
            Err(HallCertificateError::SnapshotFingerprintMismatch)
        );

        let wrong_neighborhood = HallCertificate::removals(
            &original,
            HallSubsetWitness::new(VariableSet::from_bits(0b011), values(0b001)),
            vec![ValueRemoval::new(2, values(0b010))],
        );
        assert!(matches!(
            verify_hall_certificate(&original, &wrong_neighborhood, HallCaps::default()),
            Err(HallCertificateError::NeighborhoodMismatch { .. })
        ));

        let inside = HallCertificate::removals(
            &original,
            witness,
            vec![ValueRemoval::new(1, values(0b010))],
        );
        assert_eq!(
            verify_hall_certificate(&original, &inside, HallCaps::default()),
            Err(HallCertificateError::RemovalVariableInsideWitness { variable: 1 })
        );

        let absent = HallCertificate::removals(
            &original,
            witness,
            vec![ValueRemoval::new(2, values(0b001))],
        );
        assert_eq!(
            verify_hall_certificate(&original, &absent, HallCaps::default()),
            Err(HallCertificateError::RemovalValuesOutsideDomain {
                variable: 2,
                bits: 0b001,
            })
        );

        let unsupported_version = HallCertificate::from_parts(
            HALL_CERTIFICATE_VERSION + 1,
            original.fingerprint(),
            witness,
            good.conclusion().clone(),
        );
        assert!(matches!(
            verify_hall_certificate(&original, &unsupported_version, HallCaps::default()),
            Err(HallCertificateError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn malformed_masks_ordering_and_conclusions_are_rejected() {
        assert_eq!(
            DomainSnapshot::from_bits(2, vec![0b100]),
            Err(HallCertificateError::DomainBitsOutOfRange {
                variable: 0,
                bits: 0b100,
            })
        );

        let state = snapshot(3, &[0b001, 0b011, 0b111]);
        let tight = HallSubsetWitness::new(VariableSet::from_bits(0b011), values(0b011));
        let malformed_cases = [
            HallCertificate::removals(&state, tight, vec![]),
            HallCertificate::removals(
                &state,
                tight,
                vec![
                    ValueRemoval::new(2, values(0b001)),
                    ValueRemoval::new(2, values(0b010)),
                ],
            ),
            HallCertificate::removals(&state, tight, vec![ValueRemoval::new(3, values(0b001))]),
            HallCertificate::removals(&state, tight, vec![ValueRemoval::new(2, values(0))]),
            HallCertificate::removals(&state, tight, vec![ValueRemoval::new(2, values(0b1000))]),
        ];
        for certificate in malformed_cases {
            assert!(verify_hall_certificate(&state, &certificate, HallCaps::default()).is_err());
        }

        let empty_witness = HallCertificate::conflict(
            &state,
            HallSubsetWitness::new(VariableSet::from_bits(0), values(0)),
        );
        assert_eq!(
            verify_hall_certificate(&state, &empty_witness, HallCaps::default()),
            Err(HallCertificateError::EmptyWitness)
        );
        let out_of_range_witness = HallCertificate::conflict(
            &state,
            HallSubsetWitness::new(VariableSet::from_bits(0b1000), values(0b001)),
        );
        assert!(matches!(
            verify_hall_certificate(&state, &out_of_range_witness, HallCaps::default()),
            Err(HallCertificateError::WitnessVariablesOutOfRange { .. })
        ));
        let false_conflict = HallCertificate::conflict(&state, tight);
        assert!(matches!(
            verify_hall_certificate(&state, &false_conflict, HallCaps::default()),
            Err(HallCertificateError::NotHallConflict { .. })
        ));
        let non_tight_pruning = HallCertificate::removals(
            &state,
            HallSubsetWitness::new(VariableSet::from_bits(0b010), values(0b011)),
            vec![ValueRemoval::new(2, values(0b010))],
        );
        assert!(matches!(
            verify_hall_certificate(&state, &non_tight_pruning, HallCaps::default()),
            Err(HallCertificateError::NotTightHallSet { .. })
        ));
    }

    #[test]
    fn all_caps_are_enforced_before_search_or_replay() {
        let state = snapshot(3, &[0b001, 0b010, 0b100]);
        let certificate = HallCertificate::removals(
            &state,
            HallSubsetWitness::new(VariableSet::from_bits(0b001), values(0b001)),
            vec![ValueRemoval::new(1, values(0b001))],
        );
        let caps = HallCaps {
            max_variables: 2,
            max_witness_variables: 2,
            max_removal_records: 2,
            max_extraction_variables: 2,
            ..HallCaps::default()
        };
        assert_eq!(
            verify_hall_certificate(&state, &certificate, caps),
            Err(HallCertificateError::TooManyVariables {
                observed: 3,
                limit: 2,
            })
        );

        let caps = HallCaps {
            max_extraction_variables: 2,
            ..HallCaps::default()
        };
        assert_eq!(
            extract_minimal_conflict_certificate(&state, caps),
            Err(HallCertificateError::ExtractionCapExceeded {
                observed: 3,
                limit: 2,
            })
        );

        let invalid_caps = HallCaps {
            max_extraction_variables: HARD_MAX_EXTRACTION_VARIABLES + 1,
            ..HallCaps::default()
        };
        assert!(matches!(
            extract_minimal_conflict_certificate(&state, invalid_caps),
            Err(HallCertificateError::InvalidCaps(_))
        ));

        let value_caps = HallCaps {
            max_values: 2,
            ..HallCaps::default()
        };
        assert_eq!(
            verify_hall_certificate(&state, &certificate, value_caps),
            Err(HallCertificateError::TooManyValues {
                observed: 3,
                limit: 2,
            })
        );

        let witness_caps = HallCaps {
            max_witness_variables: 1,
            ..HallCaps::default()
        };
        let conflict_state = snapshot(1, &[0b1, 0b1]);
        let conflict_certificate = HallCertificate::conflict(
            &conflict_state,
            HallSubsetWitness::new(VariableSet::from_bits(0b11), values(0b1)),
        );
        assert_eq!(
            verify_hall_certificate(&conflict_state, &conflict_certificate, witness_caps),
            Err(HallCertificateError::TooManyWitnessVariables {
                observed: 2,
                limit: 1,
            })
        );

        let removal_state = snapshot(3, &[0b001, 0b011, 0b101]);
        let removal_certificate = HallCertificate::removals(
            &removal_state,
            HallSubsetWitness::new(VariableSet::from_bits(0b001), values(0b001)),
            vec![
                ValueRemoval::new(1, values(0b001)),
                ValueRemoval::new(2, values(0b001)),
            ],
        );
        let removal_caps = HallCaps {
            max_removal_records: 1,
            ..HallCaps::default()
        };
        assert_eq!(
            verify_hall_certificate(&removal_state, &removal_certificate, removal_caps),
            Err(HallCertificateError::TooManyRemovalRecords {
                observed: 2,
                limit: 1,
            })
        );
    }

    #[test]
    fn exhaustive_small_systems_match_independent_bipartite_search() {
        let caps = HallCaps {
            max_extraction_variables: 4,
            ..HallCaps::default()
        };
        let mut systems = 0usize;
        let mut edges = 0usize;

        for variable_count in 0..=4 {
            for value_count in 0..=4 {
                let encoded_bits = variable_count * value_count;
                let system_count = 1u64 << encoded_bits;
                let domain_mask = low_bits(value_count);
                for encoding in 0..system_count {
                    let domains = (0..variable_count)
                        .map(|variable| {
                            if value_count == 0 {
                                0
                            } else {
                                (encoding >> (variable * value_count)) & domain_mask
                            }
                        })
                        .collect::<Vec<_>>();
                    let state = DomainSnapshot::from_bits(value_count, domains).unwrap();
                    let matching_exists = brute_has_matching(&state, None);
                    let conflict = extract_minimal_conflict_certificate(&state, caps).unwrap();
                    assert_eq!(
                        conflict.is_some(),
                        !matching_exists,
                        "conflict mismatch for n={variable_count}, m={value_count}, encoding={encoding:#x}"
                    );
                    if let Some(certificate) = conflict {
                        assert!(
                            verify_hall_certificate(&state, &certificate, caps)
                                .unwrap()
                                .is_conflict()
                        );
                    }

                    if matching_exists {
                        for variable in 0..variable_count {
                            let domain = state.domains()[variable];
                            for value in 0..value_count {
                                if !domain.contains(value) {
                                    continue;
                                }
                                let removal = [ValueRemoval::new(
                                    variable,
                                    ValueSet::singleton(value).unwrap(),
                                )];
                                let certificate =
                                    extract_minimal_removal_certificate(&state, &removal, caps)
                                        .unwrap();
                                let forced_edge_is_supported =
                                    brute_has_matching(&state, Some((variable, value)));
                                assert_eq!(
                                    certificate.is_some(),
                                    !forced_edge_is_supported,
                                    "pruning mismatch for n={variable_count}, m={value_count}, encoding={encoding:#x}, edge=({variable},{value})"
                                );
                                if let Some(certificate) = certificate {
                                    assert_eq!(
                                        verify_hall_certificate(&state, &certificate, caps)
                                            .unwrap()
                                            .removed_value_count(),
                                        1
                                    );
                                }
                                edges += 1;
                            }
                        }
                    }
                    systems += 1;
                }
            }
        }

        assert_eq!(systems, 74_963);
        assert!(edges > 100_000);
    }

    fn brute_has_matching(snapshot: &DomainSnapshot, forced: Option<(usize, usize)>) -> bool {
        let mut used_values = 0u64;
        let mut assigned_variables = 0u64;
        if let Some((variable, value)) = forced {
            if variable >= snapshot.variable_count()
                || value >= snapshot.value_count()
                || !snapshot.domains()[variable].contains(value)
            {
                return false;
            }
            used_values |= 1u64 << value;
            assigned_variables |= 1u64 << variable;
        }
        brute_match_remaining(snapshot, assigned_variables, used_values)
    }

    fn brute_match_remaining(
        snapshot: &DomainSnapshot,
        assigned_variables: u64,
        used_values: u64,
    ) -> bool {
        if assigned_variables.count_ones() as usize == snapshot.variable_count() {
            return true;
        }

        let mut best_variable = None;
        let mut best_available = u64::MAX;
        for variable in 0..snapshot.variable_count() {
            if assigned_variables & (1u64 << variable) != 0 {
                continue;
            }
            let available = snapshot.domains()[variable].bits() & !used_values;
            if available.count_ones() < best_available.count_ones() {
                best_variable = Some(variable);
                best_available = available;
            }
        }
        let variable = best_variable.expect("an unassigned variable exists");
        let mut available = best_available;
        while available != 0 {
            let value_bit = available & available.wrapping_neg();
            if brute_match_remaining(
                snapshot,
                assigned_variables | (1u64 << variable),
                used_values | value_bit,
            ) {
                return true;
            }
            available &= available - 1;
        }
        false
    }
}
