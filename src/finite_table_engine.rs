#![forbid(unsafe_code)]

//! Default-off source-exact finite-table JIT engine.

use crate::Problem;
use crate::finite_column_search::{
    FiniteColumnOracle, SearchCaps, SearchOutcome, SearchTelemetry, search_with_caps,
};
use crate::finite_symmetry::{is_canonical_zero_column, marked_permutation_class};
use crate::finite_table_source::{
    FiniteTableSource, PartialEvaluationScratch, SourceTableCounts, SourceTableValidationError,
    StructuralBaseRelabelingTelemetry, compile_finite_table_source,
    compile_finite_table_source_with_domain_precheck,
};
use crate::latin_certificate::{
    LatinCertificateTelemetry, certify_latin_implication, certify_latin_implication_by_symmetry,
    verify_latin_implication, verify_latin_implication_by_symmetry,
};
use crate::orbit_canon::BinaryTable;
use crate::orbit_cover::{OrbitCoverTelemetry, recognize_full_forbidden_orbit_from_generators};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FiniteTableEngineCaps {
    pub(crate) search: SearchCaps,
    pub(crate) domain_size_precheck: bool,
}

impl Default for FiniteTableEngineCaps {
    fn default() -> Self {
        Self {
            search: SearchCaps::default(),
            domain_size_precheck: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FiniteTableStage {
    Compile,
    LatinCertificate,
    Search,
    SatValidation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FiniteTableAbstention {
    pub(crate) stage: FiniteTableStage,
    pub(crate) detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FiniteTableEngineOutcome {
    Sat(BinaryTable),
    Unsat,
    Abstain(FiniteTableAbstention),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FiniteTableTimings {
    pub(crate) compile_ns: u128,
    pub(crate) latin_certificate_ns: u128,
    pub(crate) symmetry_certificate_ns: u128,
    pub(crate) search_ns: u128,
    pub(crate) sat_validation_ns: u128,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct FiniteTableEngineStats {
    pub(crate) source: Option<SourceTableCounts>,
    pub(crate) latin: Option<LatinCertificateTelemetry>,
    pub(crate) relabeling: Option<StructuralBaseRelabelingTelemetry>,
    pub(crate) orbit: Option<OrbitCoverTelemetry>,
    pub(crate) symmetry_unavailable: Option<String>,
    pub(crate) latin_compression_unavailable: Option<String>,
    pub(crate) symmetry_prunes: u64,
    pub(crate) root_class_cache_hits: u64,
    pub(crate) root_class_cache_misses: u64,
    pub(crate) source_oracle_ns: u128,
    pub(crate) partial_conflicts_by_assertion: Box<[(usize, u64)]>,
    pub(crate) search: SearchTelemetry,
    pub(crate) exhaustive_cover_completed: bool,
    pub(crate) sat_revalidated: bool,
    pub(crate) timings: FiniteTableTimings,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FiniteTableEngineReport {
    pub(crate) outcome: FiniteTableEngineOutcome,
    pub(crate) stats: FiniteTableEngineStats,
}

struct SourceOracle<'compiled, 'problem> {
    source: &'compiled FiniteTableSource<'problem>,
    canonical_zero_column: bool,
    symmetry_prunes: u64,
    partial_conflicts: Vec<u64>,
    partial_scratch: PartialEvaluationScratch,
    root_class_cache: Vec<(u64, Option<usize>)>,
    root_class_cache_hits: u64,
    root_class_cache_misses: u64,
    source_oracle_ns: u128,
}

impl SourceOracle<'_, '_> {
    fn evaluate_source_conflict(
        &mut self,
        row_major_domains: &[u8],
    ) -> Result<Option<usize>, String> {
        let started = Instant::now();
        let result = self
            .source
            .first_definitely_false_base_assertion_with_scratch(
                row_major_domains,
                &mut self.partial_scratch,
            )
            .map_err(|error| error.to_string());
        self.source_oracle_ns = self
            .source_oracle_ns
            .saturating_add(started.elapsed().as_nanos());
        result
    }

    fn record_source_conflict(&mut self, assertion_ordinal: usize) -> Result<(), String> {
        let counter = self
            .partial_conflicts
            .get_mut(assertion_ordinal)
            .ok_or_else(|| "partial-conflict assertion ordinal is out of range".to_owned())?;
        *counter = counter
            .checked_add(1)
            .ok_or_else(|| "partial-conflict counter overflowed".to_owned())?;
        Ok(())
    }

    fn source_conflict(&mut self, row_major_domains: &[u8]) -> Result<bool, String> {
        let Some(assertion_ordinal) = self.evaluate_source_conflict(row_major_domains)? else {
            return Ok(false);
        };
        self.record_source_conflict(assertion_ordinal)?;
        Ok(true)
    }
}

impl FiniteColumnOracle for SourceOracle<'_, '_> {
    type PartialConflictToken = ();
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
        if self.canonical_zero_column
            && column == 0
            && !is_canonical_zero_column(values_by_row).map_err(|error| error.to_string())?
        {
            self.symmetry_prunes = self
                .symmetry_prunes
                .checked_add(1)
                .ok_or_else(|| "symmetry-prune counter overflowed".to_owned())?;
            return Ok(Some(()));
        }

        let class = self
            .canonical_zero_column
            .then(|| marked_permutation_class(column, values_by_row))
            .transpose()
            .map_err(|error| error.to_string())?;
        if let Some(class) = class
            && let Some((_, conflict)) = self
                .root_class_cache
                .iter()
                .find(|(cached, _)| *cached == class)
        {
            self.root_class_cache_hits = self.root_class_cache_hits.saturating_add(1);
            if let Some(assertion_ordinal) = *conflict {
                self.record_source_conflict(assertion_ordinal)?;
                return Ok(Some(()));
            }
            return Ok(None);
        }

        let all_values = full_mask(degree);
        let mut domains = [all_values; u8::BITS as usize * u8::BITS as usize];
        for (row, &value) in values_by_row.iter().enumerate() {
            if usize::from(value) >= degree {
                return Err("root column candidate has an out-of-range value".to_owned());
            }
            domains[row * degree + column] = 1u8 << value;
        }
        let conflict = self.evaluate_source_conflict(&domains[..degree * degree])?;
        if let Some(class) = class {
            self.root_class_cache_misses = self.root_class_cache_misses.saturating_add(1);
            self.root_class_cache.push((class, conflict));
        }
        if let Some(assertion_ordinal) = conflict {
            self.record_source_conflict(assertion_ordinal)?;
            Ok(Some(()))
        } else {
            Ok(None)
        }
    }

    fn partial_conflict(
        &mut self,
        row_major_domains: &[u8],
    ) -> Result<Option<Self::PartialConflictToken>, Self::Error> {
        self.source_conflict(row_major_domains)
            .map(|conflict| conflict.then_some(()))
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

fn full_mask(degree: usize) -> u8 {
    if degree == u8::BITS as usize {
        u8::MAX
    } else {
        (1u8 << degree) - 1
    }
}

fn abstain(
    stats: FiniteTableEngineStats,
    stage: FiniteTableStage,
    detail: impl Into<String>,
) -> FiniteTableEngineReport {
    FiniteTableEngineReport {
        outcome: FiniteTableEngineOutcome::Abstain(FiniteTableAbstention {
            stage,
            detail: detail.into(),
        }),
        stats,
    }
}

fn compact_conflicts(counters: &[u64]) -> Box<[(usize, u64)]> {
    counters
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, count)| *count != 0)
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

/// Solves only the source-exact fragment recognized by
/// [`compile_finite_table_source`]. Every unsupported or incomplete path
/// abstains. The caller may compose this arm with another internal engine, but
/// this module performs no fallback or benchmark-identity routing itself.
pub(crate) fn solve(problem: &Problem, caps: FiniteTableEngineCaps) -> FiniteTableEngineReport {
    let mut stats = FiniteTableEngineStats::default();

    let started = Instant::now();
    let source = match if caps.domain_size_precheck {
        compile_finite_table_source_with_domain_precheck(problem, true)
    } else {
        compile_finite_table_source(problem)
    } {
        Ok(source) => source,
        Err(error) => {
            stats.timings.compile_ns = started.elapsed().as_nanos();
            return abstain(stats, FiniteTableStage::Compile, error.to_string());
        }
    };
    stats.timings.compile_ns = started.elapsed().as_nanos();
    let source_counts = source.counts();
    stats.source = Some(source_counts);

    let started = Instant::now();
    let symmetry = (|| {
        let relabeling = source
            .certify_structural_base_generators()
            .map_err(|error| error.to_string())?;
        let records = source
            .forbidden_records()
            .iter()
            .map(|record| record.table.clone())
            .collect::<Vec<_>>();
        let orbit = recognize_full_forbidden_orbit_from_generators(
            &records,
            relabeling.claim(),
            relabeling.verifier(),
        )
        .map_err(|error| error.to_string())?;
        let orbit_telemetry = orbit.telemetry().clone();
        if !orbit_telemetry.base_invariance_verified || !orbit_telemetry.exact_orbit_cover_verified
        {
            return Err("orbit recognizer returned an unverified certificate".to_owned());
        }
        Ok((relabeling, orbit))
    })();
    stats.timings.symmetry_certificate_ns = started.elapsed().as_nanos();
    let canonical_zero_column = match &symmetry {
        Ok((relabeling, orbit)) => {
            stats.relabeling = Some(relabeling.telemetry());
            stats.orbit = Some(orbit.telemetry().clone());
            true
        }
        Err(detail) => {
            stats.symmetry_unavailable = Some(detail.clone());
            false
        }
    };

    let started = Instant::now();
    let compressed_latin = match &symmetry {
        Ok((relabeling, orbit)) => {
            match certify_latin_implication_by_symmetry(&source, relabeling, orbit) {
                Ok(certificate) => {
                    verify_latin_implication_by_symmetry(&source, relabeling, orbit, &certificate)
                        .map_err(|error| error.to_string())
                }
                Err(error) => Err(error.to_string()),
            }
        }
        Err(_) => Err("verified carrier symmetry is unavailable".to_owned()),
    };
    let latin_telemetry = match compressed_latin {
        Ok(telemetry) => telemetry,
        Err(compression_error) => {
            stats.latin_compression_unavailable = Some(compression_error);
            let latin = match certify_latin_implication(&source) {
                Ok(certificate) => certificate,
                Err(error) => {
                    stats.timings.latin_certificate_ns = started.elapsed().as_nanos();
                    return abstain(stats, FiniteTableStage::LatinCertificate, error.to_string());
                }
            };
            match verify_latin_implication(&source, &latin) {
                Ok(telemetry) => telemetry,
                Err(error) => {
                    stats.timings.latin_certificate_ns = started.elapsed().as_nanos();
                    return abstain(stats, FiniteTableStage::LatinCertificate, error.to_string());
                }
            }
        }
    };
    stats.timings.latin_certificate_ns = started.elapsed().as_nanos();
    stats.latin = Some(latin_telemetry);

    let degree = source.domain().len();
    let root_domains = vec![full_mask(degree); degree * degree];
    let mut oracle = SourceOracle {
        source: &source,
        canonical_zero_column,
        symmetry_prunes: 0,
        partial_conflicts: vec![0; source_counts.total_assertions],
        partial_scratch: source.partial_evaluation_scratch(),
        root_class_cache: Vec::with_capacity(64),
        root_class_cache_hits: 0,
        root_class_cache_misses: 0,
        source_oracle_ns: 0,
    };
    let started = Instant::now();
    let search = search_with_caps(degree, &root_domains, &mut oracle, caps.search);
    stats.timings.search_ns = started.elapsed().as_nanos();
    stats.search = search.telemetry;
    stats.symmetry_prunes = oracle.symmetry_prunes;
    stats.root_class_cache_hits = oracle.root_class_cache_hits;
    stats.root_class_cache_misses = oracle.root_class_cache_misses;
    stats.source_oracle_ns = oracle.source_oracle_ns;
    stats.partial_conflicts_by_assertion = compact_conflicts(&oracle.partial_conflicts);

    match search.outcome {
        SearchOutcome::Sat(table) => {
            let started = Instant::now();
            let validation = source.validate_source_table(&table);
            stats.timings.sat_validation_ns = started.elapsed().as_nanos();
            match validation {
                Ok(()) => {
                    stats.sat_revalidated = true;
                    FiniteTableEngineReport {
                        outcome: FiniteTableEngineOutcome::Sat(table),
                        stats,
                    }
                }
                Err(error) => abstain(
                    stats,
                    FiniteTableStage::SatValidation,
                    format!("independent SAT revalidation failed: {error}"),
                ),
            }
        }
        SearchOutcome::Unsat => {
            stats.exhaustive_cover_completed = true;
            FiniteTableEngineReport {
                outcome: FiniteTableEngineOutcome::Unsat,
                stats,
            }
        }
        SearchOutcome::Abstain(reason) => {
            abstain(stats, FiniteTableStage::Search, reason.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ScopedLetMode, parse_problem_with_scoped_let_mode};

    fn degree_two_source(include_latin: bool, include_second_orbit_record: bool) -> String {
        let latin = if include_latin {
            "(assert (distinct (op a a) (op a b)))\n\
             (assert (distinct (op b a) (op b b)))\n\
             (assert (distinct (op a a) (op b a)))\n\
             (assert (distinct (op a b) (op b b)))"
        } else {
            ""
        };
        let second = if include_second_orbit_record {
            "(assert (not (and\n\
               (= (op a a) b) (= (op a b) a)\n\
               (= (op b a) a) (= (op b b) b))))"
        } else {
            ""
        };
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
             {latin}\n\
             (assert (not (and\n\
               (= (op a a) a) (= (op a b) b)\n\
               (= (op b a) b) (= (op b b) a))))\n\
             {second}\n\
             (check-sat)\n"
        )
    }

    fn parse(source: &str) -> Problem {
        parse_problem_with_scoped_let_mode(source, ScopedLetMode::Off).unwrap()
    }

    #[test]
    fn exact_degree_two_orbit_is_closed_by_generator_and_latin_certificates() {
        let problem = parse(&degree_two_source(true, true));
        let report = solve(&problem, FiniteTableEngineCaps::default());
        let mut prechecked_caps = FiniteTableEngineCaps::default();
        prechecked_caps.domain_size_precheck = true;
        let prechecked = solve(&problem, prechecked_caps);
        assert_eq!(report.outcome, prechecked.outcome);
        assert_eq!(report.outcome, FiniteTableEngineOutcome::Unsat);
        let latin = report.stats.latin.unwrap();
        assert_eq!(latin.collision_obligations, 8);
        assert_eq!(
            latin.evidence_kind,
            crate::latin_certificate::LatinEvidenceKind::SymmetryClasses
        );
        assert!(latin.representative_obligations < latin.collision_obligations);
        assert_eq!(report.stats.root_class_cache_misses, 2);
        assert!(report.stats.exhaustive_cover_completed);
    }

    #[test]
    fn missing_latin_implication_abstains_before_search() {
        let problem = parse(&degree_two_source(false, true));
        let report = solve(&problem, FiniteTableEngineCaps::default());
        assert!(matches!(
            report.outcome,
            FiniteTableEngineOutcome::Abstain(FiniteTableAbstention {
                stage: FiniteTableStage::LatinCertificate,
                ..
            })
        ));
        assert_eq!(report.stats.search.nodes, 0);
    }

    #[test]
    fn incomplete_forbidden_orbit_disables_symmetry_but_preserves_sat() {
        let problem = parse(&degree_two_source(true, false));
        let report = solve(&problem, FiniteTableEngineCaps::default());
        assert!(matches!(report.outcome, FiniteTableEngineOutcome::Sat(_)));
        assert!(report.stats.symmetry_unavailable.is_some());
        assert_eq!(
            report.stats.latin.unwrap().evidence_kind,
            crate::latin_certificate::LatinEvidenceKind::ExhaustiveCollisions
        );
        assert!(report.stats.sat_revalidated);
    }
}
