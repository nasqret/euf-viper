#![cfg(test)]
#![forbid(unsafe_code)]

//! External diagnostics for the source-exact finite-table research route.

use crate::finite_column_search::{
    FiniteColumnOracle, SearchCaps, SearchOutcome, search, search_with_caps,
};
use crate::finite_table_source::{
    FiniteTableSource, RelabelingEvidenceKind, SourceTableValidationError,
    compile_finite_table_source,
};
use crate::orbit_canon::{BinaryTable, CheckedPermutation};
use crate::orbit_cover::recognize_full_forbidden_orbit;
use crate::{ScopedLetMode, parse_problem_with_scoped_let_mode};
use std::collections::{BTreeMap, BTreeSet};
use std::{env, fs};

const MAX_EMPIRICAL_ORBIT_IMAGES: usize = 40_320;

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct EmpiricalBaseOrbitMismatch {
    permutation: Vec<usize>,
    seed_holds: bool,
    image_holds: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EmpiricalBaseOrbitReport {
    evidence_kind: RelabelingEvidenceKind,
    permutation_images_checked: usize,
    mismatch: Option<EmpiricalBaseOrbitMismatch>,
}

/// Checks one table orbit only. Even a clean result is deliberately not a
/// source-invariance certificate.
fn empirically_check_base_seed_orbit(
    source: &FiniteTableSource<'_>,
    seed: &BinaryTable,
    max_images: usize,
) -> Result<EmpiricalBaseOrbitReport, String> {
    if seed.degree() != source.domain().len() {
        return Err("empirical seed degree differs from the compiled source".to_owned());
    }
    let images = permutations(seed.degree());
    if images.len() > max_images {
        return Err(format!(
            "empirical relabeling cap exceeded: {} > {max_images}",
            images.len()
        ));
    }
    let seed_holds = source
        .base_assertions_hold(seed)
        .map_err(|error| error.to_string())?;
    let mut permutation_images_checked = 0usize;
    for images in images {
        let permutation =
            CheckedPermutation::new(images.clone()).map_err(|error| error.to_string())?;
        let image = seed
            .conjugated_by(&permutation)
            .map_err(|error| error.to_string())?;
        let image_holds = source
            .base_assertions_hold(&image)
            .map_err(|error| error.to_string())?;
        permutation_images_checked += 1;
        if seed_holds != image_holds {
            return Ok(EmpiricalBaseOrbitReport {
                evidence_kind: RelabelingEvidenceKind::EmpiricalCheck,
                permutation_images_checked,
                mismatch: Some(EmpiricalBaseOrbitMismatch {
                    permutation: images,
                    seed_holds,
                    image_holds,
                }),
            });
        }
    }
    Ok(EmpiricalBaseOrbitReport {
        evidence_kind: RelabelingEvidenceKind::EmpiricalCheck,
        permutation_images_checked,
        mismatch: None,
    })
}

fn is_latin(degree: usize, entries: &[usize]) -> bool {
    let all_values = full_mask(degree);
    (0..degree).all(|row| {
        (0..degree).fold(0_u8, |mask, column| {
            mask | (1_u8 << entries[row * degree + column])
        }) == all_values
    }) && (0..degree).all(|column| {
        (0..degree).fold(0_u8, |mask, row| {
            mask | (1_u8 << entries[row * degree + column])
        }) == all_values
    })
}

fn full_mask(degree: usize) -> u8 {
    if degree == u8::BITS as usize {
        u8::MAX
    } else {
        (1_u8 << degree) - 1
    }
}

struct SourceOracle<'compiled, 'problem> {
    source: &'compiled FiniteTableSource<'problem>,
    partial_conflicts: BTreeMap<usize, u64>,
}

impl SourceOracle<'_, '_> {
    fn source_conflict(&mut self, row_major_domains: &[u8]) -> Result<Option<usize>, String> {
        let conflict = self
            .source
            .first_definitely_false_base_assertion(row_major_domains)
            .map_err(|error| error.to_string())?;
        if let Some(assertion_ordinal) = conflict {
            *self.partial_conflicts.entry(assertion_ordinal).or_default() += 1;
        }
        Ok(conflict)
    }
}

impl FiniteColumnOracle for SourceOracle<'_, '_> {
    type PartialConflictToken = usize;
    type Error = String;

    fn root_column_pruning_enabled(&self) -> bool {
        true
    }

    fn root_column_conflict(
        &mut self,
        column: usize,
        values_by_row: &[u8],
    ) -> Result<Option<Self::PartialConflictToken>, Self::Error> {
        let degree = self.source.domain().len();
        if values_by_row.len() != degree || column >= degree {
            return Err("root column candidate has the wrong shape".to_owned());
        }
        let mut domains = vec![full_mask(degree); degree * degree];
        for (row, &value) in values_by_row.iter().enumerate() {
            if usize::from(value) >= degree {
                return Err("root column candidate has an out-of-range value".to_owned());
            }
            domains[row * degree + column] = 1u8 << value;
        }
        self.source_conflict(&domains)
    }

    fn partial_conflict(
        &mut self,
        row_major_domains: &[u8],
    ) -> Result<Option<Self::PartialConflictToken>, Self::Error> {
        self.source_conflict(row_major_domains)
    }

    fn validate_complete(&mut self, table: &BinaryTable) -> Result<bool, Self::Error> {
        match self.source.validate_source_table(table) {
            Ok(()) => Ok(true),
            Err(SourceTableValidationError::BaseAssertionFalse { .. })
            | Err(SourceTableValidationError::ForbiddenTable { .. }) => Ok(false),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[test]
#[ignore = "requires EUF_VIPER_FINITE_TABLE_CASE"]
fn probe_external_finite_table_domains() {
    let source = fs::read_to_string(env::var("EUF_VIPER_FINITE_TABLE_CASE").unwrap()).unwrap();
    let problem = parse_problem_with_scoped_let_mode(&source, ScopedLetMode::Auto).unwrap();
    let compiled = compile_finite_table_source(&problem).unwrap();
    let degree = compiled.domain().len();
    let all_values = full_mask(degree);
    let permutations = permutations(degree);

    let mut root_column_candidates = Vec::with_capacity(degree);
    for column in 0..degree {
        let mut accepted = 0usize;
        for permutation in &permutations {
            let mut domains = vec![all_values; degree * degree];
            for (row, &value) in permutation.iter().enumerate() {
                domains[row * degree + column] = 1_u8 << value;
            }
            if compiled.base_could_hold(&domains).unwrap() {
                accepted += 1;
            }
        }
        root_column_candidates.push(accepted);
    }

    let forbidden = compiled.unique_forbidden_tables().collect::<Vec<_>>();
    assert!(
        forbidden
            .iter()
            .all(|table| is_latin(degree, table.entries()))
    );
    let column_support = (0..degree)
        .map(|column| {
            forbidden
                .iter()
                .map(|table| {
                    (0..degree)
                        .map(|row| table.entries()[row * degree + column])
                        .collect::<Vec<_>>()
                })
                .collect::<BTreeSet<_>>()
                .len()
        })
        .collect::<Vec<_>>();
    let prefix_support = (1..=degree)
        .map(|columns| {
            forbidden
                .iter()
                .map(|table| {
                    (0..columns)
                        .flat_map(|column| {
                            (0..degree).map(move |row| table.entries()[row * degree + column])
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<BTreeSet<_>>()
                .len()
        })
        .collect::<Vec<_>>();

    println!("degree={degree}");
    println!("permutations={}", permutations.len());
    println!("root_column_candidates={root_column_candidates:?}");
    println!("forbidden_tables={}", forbidden.len());
    println!("forbidden_column_support={column_support:?}");
    println!("forbidden_prefix_support={prefix_support:?}");
}

#[test]
#[ignore = "requires EUF_VIPER_FINITE_TABLE_CASE"]
fn search_external_finite_table_case() {
    let source = fs::read_to_string(env::var("EUF_VIPER_FINITE_TABLE_CASE").unwrap()).unwrap();
    let problem = parse_problem_with_scoped_let_mode(&source, ScopedLetMode::Auto).unwrap();
    let compiled = compile_finite_table_source(&problem).unwrap();
    let degree = compiled.domain().len();
    let structural_relabeling = compiled.certify_structural_base_relabeling().unwrap();
    let structural_telemetry = compiled
        .verify_structural_base_relabeling(&structural_relabeling)
        .unwrap();
    println!(
        "base_relabeling_evidence={:?} permutations_checked={} assertion_images_checked={} normalized_nodes={}",
        structural_telemetry.evidence_kind,
        structural_telemetry.permutations_checked,
        structural_telemetry.assertion_images_checked,
        structural_telemetry.normalized_nodes,
    );
    for &assertion_ordinal in compiled.base_assertion_ordinals() {
        println!(
            "base_assertion_{assertion_ordinal}_atoms={:?}",
            compiled
                .base_assertion_atom_samples(assertion_ordinal, 5)
                .unwrap()
        );
    }
    let forbidden = compiled
        .unique_forbidden_tables()
        .cloned()
        .collect::<BTreeSet<_>>();
    let representative = forbidden.first().unwrap();
    let empirical =
        empirically_check_base_seed_orbit(&compiled, representative, MAX_EMPIRICAL_ORBIT_IMAGES)
            .unwrap();
    println!(
        "base_relabeling_evidence={:?} seed_orbit_images_checked={} mismatch={:?}",
        empirical.evidence_kind, empirical.permutation_images_checked, empirical.mismatch,
    );
    let verifier = compiled.source_base_action_verifier().unwrap();
    let forbidden_records = compiled
        .forbidden_records()
        .iter()
        .map(|record| record.table.clone())
        .collect::<Vec<_>>();
    let orbit_certificate = recognize_full_forbidden_orbit(
        &forbidden_records,
        structural_relabeling.claim(),
        &verifier,
    )
    .unwrap();
    let orbit = orbit_certificate.telemetry();
    println!(
        "forbidden_orbit_size={} forbidden_is_single_orbit={} base_invariance_verified={} exact_orbit_cover_verified={}",
        orbit.unique_orbit_tables,
        orbit.unique_orbit_tables == forbidden.len(),
        orbit.base_invariance_verified,
        orbit.exact_orbit_cover_verified,
    );
    if env::var_os("EUF_VIPER_FINITE_TABLE_SAMPLE_ONLY").is_some() {
        return;
    }
    let root_domains = vec![full_mask(degree); degree * degree];
    let mut oracle = SourceOracle {
        source: &compiled,
        partial_conflicts: BTreeMap::new(),
    };

    let report = if env::var_os("EUF_VIPER_FINITE_TABLE_HARD_CAPS").is_some() {
        search_with_caps(degree, &root_domains, &mut oracle, SearchCaps::hard())
    } else {
        search(degree, &root_domains, &mut oracle)
    };
    println!(
        "partial_conflicts_by_assertion={:?}",
        oracle.partial_conflicts
    );
    println!("{report:#?}");
    assert!(
        !matches!(&report.outcome, SearchOutcome::Abstain(_)),
        "finite-table search abstained: {report:#?}"
    );
}

#[test]
fn permutation_generator_is_lexicographic_and_complete() {
    assert_eq!(permutations(1), vec![vec![0]]);
    assert_eq!(
        permutations(3),
        vec![
            vec![0, 1, 2],
            vec![0, 2, 1],
            vec![1, 0, 2],
            vec![1, 2, 0],
            vec![2, 0, 1],
            vec![2, 1, 0],
        ]
    );
}

fn empirical_test_source(base: &str) -> String {
    format!(
        "(set-logic QF_UF)\n\
         (declare-sort I 0)\n\
         (declare-fun a () I)\n\
         (declare-fun b () I)\n\
         (declare-fun op (I I) I)\n\
         (assert (distinct a b))\n\
         (assert (and\n\
           (or (= (op a a) a) (= (op a a) b))\n\
           (or (= (op a b) a) (= (op a b) b))\n\
           (or (= (op b a) a) (= (op b a) b))\n\
           (or (= (op b b) a) (= (op b b) b))))\n\
         (assert {base})\n\
         (assert (not (and\n\
           (= (op a a) a) (= (op a b) b)\n\
           (= (op b a) b) (= (op b b) a))))\n\
         (check-sat)\n"
    )
}

#[test]
fn empirical_seed_orbit_is_labeled_separately_from_structural_proof() {
    let problem = parse_problem_with_scoped_let_mode(
        &empirical_test_source("(and (= (op a a) a) (= (op b b) b))"),
        ScopedLetMode::Off,
    )
    .unwrap();
    let compiled = compile_finite_table_source(&problem).unwrap();
    let left_projection = BinaryTable::new(2, vec![0, 0, 1, 1]).unwrap();
    let report = empirically_check_base_seed_orbit(&compiled, &left_projection, 2).unwrap();

    assert_eq!(report.evidence_kind, RelabelingEvidenceKind::EmpiricalCheck);
    assert_eq!(report.permutation_images_checked, 2);
    assert_eq!(report.mismatch, None);
    assert_eq!(
        compiled
            .certify_structural_base_relabeling()
            .unwrap()
            .telemetry()
            .evidence_kind,
        RelabelingEvidenceKind::StructuralProof
    );
}

#[test]
fn empirical_seed_orbit_finds_the_asymmetric_counterexample() {
    let problem = parse_problem_with_scoped_let_mode(
        &empirical_test_source("(= (op a a) a)"),
        ScopedLetMode::Off,
    )
    .unwrap();
    let compiled = compile_finite_table_source(&problem).unwrap();
    let all_a = BinaryTable::new(2, vec![0, 0, 0, 0]).unwrap();
    let report = empirically_check_base_seed_orbit(&compiled, &all_a, 2).unwrap();

    assert_eq!(report.evidence_kind, RelabelingEvidenceKind::EmpiricalCheck);
    assert_eq!(
        report.mismatch,
        Some(EmpiricalBaseOrbitMismatch {
            permutation: vec![1, 0],
            seed_holds: true,
            image_holds: false,
        })
    );
    assert!(compiled.certify_structural_base_relabeling().is_err());
}

#[test]
fn empirical_seed_orbit_cap_abstains_instead_of_reporting_success() {
    let problem = parse_problem_with_scoped_let_mode(
        &empirical_test_source("(and (= (op a a) a) (= (op b b) b))"),
        ScopedLetMode::Off,
    )
    .unwrap();
    let compiled = compile_finite_table_source(&problem).unwrap();
    let left_projection = BinaryTable::new(2, vec![0, 0, 1, 1]).unwrap();

    assert_eq!(
        empirically_check_base_seed_orbit(&compiled, &left_projection, 1),
        Err("empirical relabeling cap exceeded: 2 > 1".to_owned())
    );
}
