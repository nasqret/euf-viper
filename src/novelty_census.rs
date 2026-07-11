#![cfg(feature = "certificates")]

use super::bool_dag_telemetry::{self, AbstentionReason, DagProjection, Limits, Telemetry};
use super::model_scout::{
    self, ScoutBoolFill, ScoutIneligibleReason, ScoutOutcome, ScoutQuotient, ScoutSelection,
};
use super::{Problem, ScopedLetMode, parse_problem_with_scoped_let_mode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

const MANIFEST_ENV: &str = "EUF_VIPER_NOVELTY_CENSUS_MANIFEST";
const OUTPUT_ENV: &str = "EUF_VIPER_NOVELTY_CENSUS_OUTPUT";
const SCHEMA: &str = "euf-viper.novelty-census.v1";
const MAX_MANIFEST_ROWS: usize = 100_000;
const MAX_MANIFEST_LINE_BYTES: usize = 1_048_576;
const MAX_RELATIVE_PATH_BYTES: usize = 4_096;
const MAX_SOURCE_PATH_BYTES: usize = 16_384;
const MAX_STATUS_BYTES: usize = 128;
const MAX_SHA256_BYTES: usize = 128;
const MAX_INPUT_BYTES: usize = 64 * 1_048_576;
const MAX_DIAGNOSTIC_CHARS: usize = 512;

const TELEMETRY_LIMITS: Limits = Limits {
    max_syntax_occurrences: 5_000_000,
    max_equality_facts: 1_000_000,
    max_canonical_nodes: 2_000_000,
    max_canonical_edges: 10_000_000,
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Deserialize)]
struct ManifestWire {
    id: Option<u64>,
    path: Option<String>,
    relative_path: String,
    status: Option<String>,
    sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestEntry {
    id: Option<u64>,
    line_number: u64,
    source_path: PathBuf,
    relative_path: String,
    expected_status: Option<String>,
    source_sha256: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct Manifest {
    entries: Vec<ManifestEntry>,
    blank_lines: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct InstanceRecord {
    manifest_line: u64,
    id: Option<u64>,
    relative_path: String,
    expected_status: Option<String>,
    source_sha256: Option<String>,
    outcome: InstanceOutcome,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
enum InstanceOutcome {
    ReadFailure {
        reason: String,
    },
    InputAbstention {
        reason: String,
        observed_bytes: u64,
        limit_bytes: u64,
    },
    DecodeFailure {
        input_bytes: u64,
        valid_up_to: u64,
        error_len: Option<u64>,
    },
    ParseFailure {
        input_bytes: u64,
        diagnostic: String,
    },
    Analyzed {
        input_bytes: u64,
        problem: ProblemMetrics,
        scout: ScoutMetrics,
        bool_dag: BoolDagRecord,
    },
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
struct ProblemMetrics {
    sorts: u64,
    function_declarations: u64,
    terms: u64,
    applications: u64,
    top_level_equalities: u64,
    top_level_disequalities: u64,
    unsupported_items: u64,
    contradiction_flag: bool,
    boolean_assertions: u64,
    boolean_unsupported_items: u64,
    boolean_data_terms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ScoutDisposition {
    SatWitness,
    NoWitness,
    Ineligible,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ScoutSelectionRecord {
    quotient: String,
    bool_fill: String,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
struct ScoutModelMetrics {
    domains: u64,
    total_domain_elements: u64,
    largest_domain: u64,
    function_entries: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ScoutMetrics {
    disposition: ScoutDisposition,
    sat_witness_found: bool,
    ineligible_reason: Option<String>,
    selection: Option<ScoutSelectionRecord>,
    candidates_attempted: u64,
    candidates_built: u64,
    candidate_build_failures: u64,
    models_validated: u64,
    model_validation_failures: u64,
    source_rejections: u64,
    source_evaluation_failures: u64,
    initial_quotient_merges: u64,
    congruence_merges: u64,
    congruence_rounds: u64,
    hit_function_entries: u64,
    model: Option<ScoutModelMetrics>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum BoolDagStatus {
    Complete,
    Abstained,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
enum BoolDagRecord {
    NotApplicable,
    Analyzed { metrics: BoolDagMetrics },
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
struct DagProjectionMetrics {
    unique_nodes: u64,
    canonical_edges: u64,
    largest_arity: u64,
    duplicate_occurrences: u64,
    duplicate_ratio_ppm: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct AbstentionMetrics {
    reason: String,
    observed: u64,
    limit: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct BoolDagMetrics {
    status: BoolDagStatus,
    assertion_roots: u64,
    data_term_entries: u64,
    data_term_roots: u64,
    syntax_occurrences: u64,
    projected_occurrences: u64,
    unconditional_equality_facts: u64,
    effective_equality_unions: u64,
    nontrivial_quotient_classes: u64,
    quotiented_terms: u64,
    syntactic: Option<DagProjectionMetrics>,
    quotient: Option<DagProjectionMetrics>,
    quotient_unique_reduction: Option<u64>,
    quotient_unique_reduction_ppm: Option<u32>,
    abstention: Option<AbstentionMetrics>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
struct ScoutCrossTab {
    sat_witness: u64,
    no_witness: u64,
    ineligible: u64,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
struct Aggregates {
    instances: u64,
    read_failures: u64,
    input_abstentions: u64,
    decode_failures: u64,
    parse_failures: u64,
    parsed_instances: u64,
    scout_sat_witnesses: u64,
    scout_no_witnesses: u64,
    scout_ineligible: u64,
    bool_dag_not_applicable: u64,
    bool_dag_complete: u64,
    bool_dag_abstentions: u64,
    expected_unsat_scout_sat_witnesses: u64,
    expected_status_counts: BTreeMap<String, u64>,
    read_failure_reasons: BTreeMap<String, u64>,
    input_abstention_reasons: BTreeMap<String, u64>,
    scout_ineligible_reasons: BTreeMap<String, u64>,
    scout_selection_counts: BTreeMap<String, u64>,
    bool_dag_abstention_reasons: BTreeMap<String, u64>,
    scout_by_expected_status: BTreeMap<String, ScoutCrossTab>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
struct Log2Histogram {
    zero: u64,
    #[serde(rename = "floor_log2_buckets")]
    buckets: Vec<u64>,
}

impl Log2Histogram {
    fn observe(&mut self, value: u64) -> Result<(), String> {
        if value == 0 {
            return checked_increment(&mut self.zero, "histogram zero bucket");
        }
        let index = (u64::BITS - 1 - value.leading_zeros()) as usize;
        if self.buckets.len() <= index {
            self.buckets.resize(index + 1, 0);
        }
        checked_increment(&mut self.buckets[index], "histogram bucket")
    }

    fn trim(&mut self) {
        while self.buckets.last() == Some(&0) {
            self.buckets.pop();
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
struct Histograms {
    input_bytes: Log2Histogram,
    terms: Log2Histogram,
    applications: Log2Histogram,
    scout_candidates_attempted: Log2Histogram,
    bool_syntax_occurrences: Log2Histogram,
    syntactic_unique_nodes: Log2Histogram,
    quotient_unique_nodes: Log2Histogram,
    quotient_unique_reduction_ppm: Log2Histogram,
}

impl Histograms {
    fn trim(&mut self) {
        self.input_bytes.trim();
        self.terms.trim();
        self.applications.trim();
        self.scout_candidates_attempted.trim();
        self.bool_syntax_occurrences.trim();
        self.syntactic_unique_nodes.trim();
        self.quotient_unique_nodes.trim();
        self.quotient_unique_reduction_ppm.trim();
    }
}

#[derive(Debug, Serialize)]
struct ReportContract {
    parser: &'static str,
    scout_sat_witness: &'static str,
    scout_no_witness: &'static str,
    histogram_buckets: &'static str,
}

#[derive(Debug, Serialize)]
struct ReportLimits {
    max_manifest_rows: u64,
    max_manifest_line_bytes: u64,
    max_input_bytes: u64,
    max_diagnostic_chars: u64,
    bool_dag_max_syntax_occurrences: u64,
    bool_dag_max_equality_facts: u64,
    bool_dag_max_canonical_nodes: u64,
    bool_dag_max_canonical_edges: u64,
}

#[derive(Debug, Serialize)]
struct ManifestSummary {
    rows: u64,
    blank_lines: u64,
}

#[derive(Debug, Serialize)]
struct CensusReport {
    schema: &'static str,
    contract: ReportContract,
    limits: ReportLimits,
    manifest: ManifestSummary,
    aggregates: Aggregates,
    histograms: Histograms,
    instances: Vec<InstanceRecord>,
}

pub(crate) fn run_from_env() -> Result<(), String> {
    let manifest = required_env_path(MANIFEST_ENV)?;
    let output = required_env_path(OUTPUT_ENV)?;
    run_census(&manifest, &output)
}

fn required_env_path(name: &str) -> Result<PathBuf, String> {
    let value = env::var_os(name).ok_or_else(|| format!("{name} is required"))?;
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(PathBuf::from(value))
}

fn run_census(manifest_path: &Path, output_path: &Path) -> Result<(), String> {
    reject_same_input_and_output(manifest_path, output_path)?;
    let manifest = read_manifest(manifest_path)?;
    let mut instances = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        instances.push(analyze_instance(entry)?);
    }
    let report = build_report(manifest.blank_lines, instances)?;
    let bytes = serialize_report(&report)?;
    atomic_write(output_path, &bytes)
}

fn read_manifest(path: &Path) -> Result<Manifest, String> {
    let file = File::open(path)
        .map_err(|error| format!("failed to open manifest {}: {error}", path.display()))?;
    decode_manifest(BufReader::new(file), path)
}

fn decode_manifest<R: BufRead>(mut reader: R, manifest_path: &Path) -> Result<Manifest, String> {
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    let mut blank_lines = 0u64;
    let mut line_number = 0u64;
    let mut line = String::new();

    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).map_err(|error| {
            format!(
                "failed to read manifest {} at line {}: {error}",
                manifest_path.display(),
                line_number.saturating_add(1)
            )
        })?;
        if bytes == 0 {
            break;
        }
        line_number = line_number
            .checked_add(1)
            .ok_or_else(|| "manifest line count overflow".to_owned())?;
        if bytes > MAX_MANIFEST_LINE_BYTES {
            return Err(format!(
                "{}:{line_number}: line exceeds {MAX_MANIFEST_LINE_BYTES} bytes",
                manifest_path.display()
            ));
        }
        if line.trim().is_empty() {
            checked_increment(&mut blank_lines, "manifest blank line count")?;
            continue;
        }
        if entries.len() >= MAX_MANIFEST_ROWS {
            return Err(format!(
                "{}:{line_number}: manifest exceeds {MAX_MANIFEST_ROWS} rows",
                manifest_path.display()
            ));
        }

        let wire: ManifestWire = serde_json::from_str(&line).map_err(|error| {
            format!(
                "{}:{line_number}: invalid manifest JSON: {error}",
                manifest_path.display()
            )
        })?;
        validate_manifest_wire(&wire, manifest_path, line_number)?;
        if !seen.insert(wire.relative_path.clone()) {
            return Err(format!(
                "{}:{line_number}: duplicate relative_path {:?}",
                manifest_path.display(),
                wire.relative_path
            ));
        }
        let source_path = resolve_source_path(manifest_path, &wire);
        entries.push(ManifestEntry {
            id: wire.id,
            line_number,
            source_path,
            relative_path: wire.relative_path,
            expected_status: wire.status,
            source_sha256: wire.sha256,
        });
    }

    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(Manifest {
        entries,
        blank_lines,
    })
}

fn validate_manifest_wire(
    wire: &ManifestWire,
    manifest_path: &Path,
    line_number: u64,
) -> Result<(), String> {
    let context = || format!("{}:{line_number}", manifest_path.display());
    validate_relative_path(&wire.relative_path)
        .map_err(|message| format!("{}: {message}", context()))?;
    if let Some(path) = &wire.path {
        validate_bounded_text(path, MAX_SOURCE_PATH_BYTES, "path")
            .map_err(|message| format!("{}: {message}", context()))?;
    }
    if let Some(status) = &wire.status {
        validate_bounded_text(status, MAX_STATUS_BYTES, "status")
            .map_err(|message| format!("{}: {message}", context()))?;
    }
    if let Some(sha256) = &wire.sha256 {
        validate_bounded_text(sha256, MAX_SHA256_BYTES, "sha256")
            .map_err(|message| format!("{}: {message}", context()))?;
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), String> {
    validate_bounded_text(value, MAX_RELATIVE_PATH_BYTES, "relative_path")?;
    let path = Path::new(value);
    if path.is_absolute() || value.contains('\\') {
        return Err("relative_path must be a portable relative path".to_owned());
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) || value
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("relative_path must stay below the manifest root".to_owned());
    }
    Ok(())
}

fn validate_bounded_text(value: &str, limit: usize, field: &str) -> Result<(), String> {
    if value.is_empty() || value.contains('\0') || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(format!(
            "{field} must be non-empty text without control bytes"
        ));
    }
    if value.len() > limit {
        return Err(format!("{field} exceeds {limit} bytes"));
    }
    Ok(())
}

fn resolve_source_path(manifest_path: &Path, wire: &ManifestWire) -> PathBuf {
    let candidate = wire.path.as_deref().unwrap_or(&wire.relative_path);
    let candidate = Path::new(candidate);
    if candidate.is_absolute() {
        candidate.to_owned()
    } else {
        manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(candidate)
    }
}

fn analyze_instance(entry: &ManifestEntry) -> Result<InstanceRecord, String> {
    let outcome = match read_bounded(&entry.source_path) {
        Err(error) => InstanceOutcome::ReadFailure {
            reason: io_error_kind(error.kind()).to_owned(),
        },
        Ok(BoundedRead::LimitExceeded { observed_bytes }) => InstanceOutcome::InputAbstention {
            reason: "input_byte_limit".to_owned(),
            observed_bytes: usize_to_u64(observed_bytes, "observed input bytes")?,
            limit_bytes: usize_to_u64(MAX_INPUT_BYTES, "input byte limit")?,
        },
        Ok(BoundedRead::Complete(bytes)) => {
            let input_bytes = usize_to_u64(bytes.len(), "input bytes")?;
            match String::from_utf8(bytes) {
                Err(error) => InstanceOutcome::DecodeFailure {
                    input_bytes,
                    valid_up_to: usize_to_u64(error.utf8_error().valid_up_to(), "valid UTF-8")?,
                    error_len: error
                        .utf8_error()
                        .error_len()
                        .map(|length| usize_to_u64(length, "UTF-8 error length"))
                        .transpose()?,
                },
                Ok(input) => {
                    match parse_problem_with_scoped_let_mode(&input, ScopedLetMode::Auto) {
                        Err(error) => InstanceOutcome::ParseFailure {
                            input_bytes,
                            diagnostic: bounded_diagnostic(&error),
                        },
                        Ok(problem) => analyze_problem(input_bytes, &problem)?,
                    }
                }
            }
        }
    };

    Ok(InstanceRecord {
        manifest_line: entry.line_number,
        id: entry.id,
        relative_path: entry.relative_path.clone(),
        expected_status: entry.expected_status.clone(),
        source_sha256: entry.source_sha256.clone(),
        outcome,
    })
}

enum BoundedRead {
    Complete(Vec<u8>),
    LimitExceeded { observed_bytes: usize },
}

fn read_bounded(path: &Path) -> io::Result<BoundedRead> {
    let file = File::open(path)?;
    let read_limit = MAX_INPUT_BYTES
        .checked_add(1)
        .ok_or_else(|| io::Error::other("input byte limit overflow"))?;
    let mut bytes = Vec::new();
    file.take(read_limit as u64).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_INPUT_BYTES {
        Ok(BoundedRead::LimitExceeded {
            observed_bytes: bytes.len(),
        })
    } else {
        Ok(BoundedRead::Complete(bytes))
    }
}

fn analyze_problem(input_bytes: u64, problem: &Problem) -> Result<InstanceOutcome, String> {
    let problem_metrics = problem_metrics(problem)?;
    let scout_outcome = model_scout::scout_sat_model(problem);
    let scout = scout_metrics(&scout_outcome)?;
    let bool_dag = match &problem.bool_problem {
        None => BoolDagRecord::NotApplicable,
        Some(bool_problem) => {
            let telemetry = bool_dag_telemetry::analyze_with_limits(
                bool_problem,
                &problem.arena,
                TELEMETRY_LIMITS,
            );
            BoolDagRecord::Analyzed {
                metrics: bool_dag_metrics(&telemetry)?,
            }
        }
    };
    Ok(InstanceOutcome::Analyzed {
        input_bytes,
        problem: problem_metrics,
        scout,
        bool_dag,
    })
}

fn problem_metrics(problem: &Problem) -> Result<ProblemMetrics, String> {
    let (boolean_assertions, boolean_unsupported_items, boolean_data_terms) =
        problem.bool_problem.as_ref().map_or((0, 0, 0), |boolean| {
            (
                boolean.assertions.len(),
                boolean.unsupported.len(),
                boolean.data_terms.len(),
            )
        });
    Ok(ProblemMetrics {
        sorts: usize_to_u64(problem.sorts.names.len(), "sort count")?,
        function_declarations: usize_to_u64(
            problem.fun_decls.slots.iter().flatten().count(),
            "function declaration count",
        )?,
        terms: usize_to_u64(problem.arena.terms.len(), "term count")?,
        applications: usize_to_u64(problem.arena.app_count(), "application count")?,
        top_level_equalities: usize_to_u64(problem.eqs.len(), "equality count")?,
        top_level_disequalities: usize_to_u64(problem.diseqs.len(), "disequality count")?,
        unsupported_items: usize_to_u64(problem.unsupported.len(), "unsupported count")?,
        contradiction_flag: problem.contradiction,
        boolean_assertions: usize_to_u64(boolean_assertions, "Boolean assertion count")?,
        boolean_unsupported_items: usize_to_u64(
            boolean_unsupported_items,
            "Boolean unsupported count",
        )?,
        boolean_data_terms: usize_to_u64(boolean_data_terms, "Boolean data term count")?,
    })
}

fn scout_metrics(outcome: &ScoutOutcome) -> Result<ScoutMetrics, String> {
    let telemetry = &outcome.telemetry;
    let disposition = match (outcome.model.is_some(), telemetry.hit, telemetry.ineligible) {
        (true, Some(_), None) => ScoutDisposition::SatWitness,
        (false, None, Some(_)) => ScoutDisposition::Ineligible,
        (false, None, None) => ScoutDisposition::NoWitness,
        _ => return Err("model scout returned an inconsistent outcome".to_owned()),
    };
    let model = outcome
        .model
        .as_ref()
        .map(|model| {
            let total_domain_elements =
                model.domain_sizes.iter().try_fold(0u64, |sum, &size| {
                    sum.checked_add(usize_to_u64(size, "model domain size")?)
                        .ok_or_else(|| "model domain total overflow".to_owned())
                })?;
            let largest_domain = model.domain_sizes.iter().copied().max().unwrap_or(0);
            let function_entries =
                model
                    .functions
                    .iter()
                    .flatten()
                    .try_fold(0u64, |sum, function| {
                        sum.checked_add(usize_to_u64(
                            function.entries.len(),
                            "model function entry count",
                        )?)
                        .ok_or_else(|| "model function entry total overflow".to_owned())
                    })?;
            Ok::<_, String>(ScoutModelMetrics {
                domains: usize_to_u64(model.domain_sizes.len(), "model domain count")?,
                total_domain_elements,
                largest_domain: usize_to_u64(largest_domain, "largest model domain")?,
                function_entries,
            })
        })
        .transpose()?;

    Ok(ScoutMetrics {
        disposition,
        sat_witness_found: matches!(disposition, ScoutDisposition::SatWitness),
        ineligible_reason: telemetry.ineligible.map(scout_ineligible_reason),
        selection: telemetry.hit.map(scout_selection),
        candidates_attempted: usize_to_u64(
            telemetry.candidates_attempted,
            "scout candidates attempted",
        )?,
        candidates_built: usize_to_u64(telemetry.candidates_built, "scout candidates built")?,
        candidate_build_failures: usize_to_u64(
            telemetry.candidate_build_failures,
            "scout candidate build failures",
        )?,
        models_validated: usize_to_u64(telemetry.models_validated, "scout models validated")?,
        model_validation_failures: usize_to_u64(
            telemetry.model_validation_failures,
            "scout model validation failures",
        )?,
        source_rejections: usize_to_u64(telemetry.source_rejections, "scout source rejections")?,
        source_evaluation_failures: usize_to_u64(
            telemetry.source_evaluation_failures,
            "scout source evaluation failures",
        )?,
        initial_quotient_merges: usize_to_u64(
            telemetry.initial_quotient_merges,
            "scout initial quotient merges",
        )?,
        congruence_merges: usize_to_u64(telemetry.congruence_merges, "scout congruence merges")?,
        congruence_rounds: usize_to_u64(telemetry.congruence_rounds, "scout congruence rounds")?,
        hit_function_entries: usize_to_u64(
            telemetry.hit_function_entries,
            "scout hit function entries",
        )?,
        model,
    })
}

fn scout_ineligible_reason(reason: ScoutIneligibleReason) -> String {
    match reason {
        ScoutIneligibleReason::Contradiction => "contradiction".to_owned(),
        ScoutIneligibleReason::UnsupportedSource => "unsupported_source".to_owned(),
        ScoutIneligibleReason::IllSortedTerms => "ill_sorted_terms".to_owned(),
    }
}

fn scout_selection(selection: ScoutSelection) -> ScoutSelectionRecord {
    let quotient = match selection.quotient {
        ScoutQuotient::MaximallyDiverse => "maximally_diverse",
        ScoutQuotient::SingleClass => "single_class",
    };
    let bool_fill = match selection.bool_fill {
        ScoutBoolFill::AllFalse => "all_false",
        ScoutBoolFill::AllTrue => "all_true",
    };
    ScoutSelectionRecord {
        quotient: quotient.to_owned(),
        bool_fill: bool_fill.to_owned(),
    }
}

fn bool_dag_metrics(telemetry: &Telemetry) -> Result<BoolDagMetrics, String> {
    let status = if telemetry.abstention.is_some() {
        if telemetry.syntactic.is_some()
            || telemetry.quotient.is_some()
            || telemetry.quotient_unique_reduction.is_some()
            || telemetry.quotient_unique_reduction_ppm.is_some()
        {
            return Err("Boolean DAG telemetry retained projections after abstention".to_owned());
        }
        BoolDagStatus::Abstained
    } else {
        if telemetry.syntactic.is_none()
            || telemetry.quotient.is_none()
            || telemetry.quotient_unique_reduction.is_none()
            || telemetry.quotient_unique_reduction_ppm.is_none()
        {
            return Err("Boolean DAG telemetry completed without projections".to_owned());
        }
        BoolDagStatus::Complete
    };
    Ok(BoolDagMetrics {
        status,
        assertion_roots: usize_to_u64(telemetry.assertion_roots, "DAG assertion roots")?,
        data_term_entries: usize_to_u64(telemetry.data_term_entries, "DAG data term entries")?,
        data_term_roots: usize_to_u64(telemetry.data_term_roots, "DAG data term roots")?,
        syntax_occurrences: usize_to_u64(telemetry.syntax_occurrences, "DAG syntax occurrences")?,
        projected_occurrences: usize_to_u64(
            telemetry.projected_occurrences,
            "DAG projected occurrences",
        )?,
        unconditional_equality_facts: usize_to_u64(
            telemetry.unconditional_equality_facts,
            "DAG equality facts",
        )?,
        effective_equality_unions: usize_to_u64(
            telemetry.effective_equality_unions,
            "DAG equality unions",
        )?,
        nontrivial_quotient_classes: usize_to_u64(
            telemetry.nontrivial_quotient_classes,
            "DAG quotient classes",
        )?,
        quotiented_terms: usize_to_u64(telemetry.quotiented_terms, "DAG quotiented terms")?,
        syntactic: telemetry.syntactic.map(projection_metrics).transpose()?,
        quotient: telemetry.quotient.map(projection_metrics).transpose()?,
        quotient_unique_reduction: telemetry
            .quotient_unique_reduction
            .map(|value| usize_to_u64(value, "DAG quotient reduction"))
            .transpose()?,
        quotient_unique_reduction_ppm: telemetry.quotient_unique_reduction_ppm,
        abstention: telemetry
            .abstention
            .map(|abstention| {
                Ok::<_, String>(AbstentionMetrics {
                    reason: abstention.reason.as_str().to_owned(),
                    observed: usize_to_u64(abstention.observed, "DAG abstention observation")?,
                    limit: abstention
                        .limit
                        .map(|limit| usize_to_u64(limit, "DAG abstention limit"))
                        .transpose()?,
                })
            })
            .transpose()?,
    })
}

fn projection_metrics(projection: DagProjection) -> Result<DagProjectionMetrics, String> {
    Ok(DagProjectionMetrics {
        unique_nodes: usize_to_u64(projection.unique_nodes, "DAG unique nodes")?,
        canonical_edges: usize_to_u64(projection.canonical_edges, "DAG canonical edges")?,
        largest_arity: usize_to_u64(projection.largest_arity, "DAG largest arity")?,
        duplicate_occurrences: usize_to_u64(
            projection.duplicate_occurrences,
            "DAG duplicate occurrences",
        )?,
        duplicate_ratio_ppm: projection.duplicate_ratio_ppm,
    })
}

fn build_report(
    blank_lines: u64,
    mut instances: Vec<InstanceRecord>,
) -> Result<CensusReport, String> {
    instances.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    for pair in instances.windows(2) {
        if pair[0].relative_path == pair[1].relative_path {
            return Err(format!(
                "duplicate instance path {:?} while building report",
                pair[0].relative_path
            ));
        }
    }
    let (aggregates, mut histograms) = account_instances(&instances)?;
    histograms.trim();
    Ok(CensusReport {
        schema: SCHEMA,
        contract: ReportContract {
            parser: "production SMT-LIB parser with scoped-let mode fixed to auto",
            scout_sat_witness: "a validated satisfying model was found",
            scout_no_witness: "the bounded scout found no model; this is not an UNSAT result",
            histogram_buckets: "zero is separate; floor_log2_buckets[i] counts values with floor(log2(value)) = i",
        },
        limits: ReportLimits {
            max_manifest_rows: usize_to_u64(MAX_MANIFEST_ROWS, "manifest row limit")?,
            max_manifest_line_bytes: usize_to_u64(MAX_MANIFEST_LINE_BYTES, "manifest line limit")?,
            max_input_bytes: usize_to_u64(MAX_INPUT_BYTES, "input byte limit")?,
            max_diagnostic_chars: usize_to_u64(MAX_DIAGNOSTIC_CHARS, "diagnostic character limit")?,
            bool_dag_max_syntax_occurrences: usize_to_u64(
                TELEMETRY_LIMITS.max_syntax_occurrences,
                "DAG syntax limit",
            )?,
            bool_dag_max_equality_facts: usize_to_u64(
                TELEMETRY_LIMITS.max_equality_facts,
                "DAG equality limit",
            )?,
            bool_dag_max_canonical_nodes: usize_to_u64(
                TELEMETRY_LIMITS.max_canonical_nodes,
                "DAG node limit",
            )?,
            bool_dag_max_canonical_edges: usize_to_u64(
                TELEMETRY_LIMITS.max_canonical_edges,
                "DAG edge limit",
            )?,
        },
        manifest: ManifestSummary {
            rows: usize_to_u64(instances.len(), "manifest row count")?,
            blank_lines,
        },
        aggregates,
        histograms,
        instances,
    })
}

fn account_instances(instances: &[InstanceRecord]) -> Result<(Aggregates, Histograms), String> {
    let mut aggregates = Aggregates::default();
    let mut histograms = Histograms::default();
    for instance in instances {
        checked_increment(&mut aggregates.instances, "instance count")?;
        let expected_status = instance
            .expected_status
            .as_deref()
            .unwrap_or("<missing>")
            .to_owned();
        increment_map(
            &mut aggregates.expected_status_counts,
            expected_status.clone(),
            "expected status count",
        )?;
        match &instance.outcome {
            InstanceOutcome::ReadFailure { reason } => {
                checked_increment(&mut aggregates.read_failures, "read failure count")?;
                increment_map(
                    &mut aggregates.read_failure_reasons,
                    reason.clone(),
                    "read failure reason count",
                )?;
            }
            InstanceOutcome::InputAbstention {
                reason,
                observed_bytes,
                ..
            } => {
                checked_increment(&mut aggregates.input_abstentions, "input abstention count")?;
                increment_map(
                    &mut aggregates.input_abstention_reasons,
                    reason.clone(),
                    "input abstention reason count",
                )?;
                histograms.input_bytes.observe(*observed_bytes)?;
            }
            InstanceOutcome::DecodeFailure { input_bytes, .. } => {
                checked_increment(&mut aggregates.decode_failures, "decode failure count")?;
                histograms.input_bytes.observe(*input_bytes)?;
            }
            InstanceOutcome::ParseFailure { input_bytes, .. } => {
                checked_increment(&mut aggregates.parse_failures, "parse failure count")?;
                histograms.input_bytes.observe(*input_bytes)?;
            }
            InstanceOutcome::Analyzed {
                input_bytes,
                problem,
                scout,
                bool_dag,
            } => {
                checked_increment(&mut aggregates.parsed_instances, "parsed instance count")?;
                histograms.input_bytes.observe(*input_bytes)?;
                histograms.terms.observe(problem.terms)?;
                histograms.applications.observe(problem.applications)?;
                histograms
                    .scout_candidates_attempted
                    .observe(scout.candidates_attempted)?;
                account_scout(&mut aggregates, &expected_status, scout)?;
                account_bool_dag(&mut aggregates, &mut histograms, bool_dag)?;
            }
        }
    }
    validate_aggregate_partition(&aggregates)?;
    Ok((aggregates, histograms))
}

fn account_scout(
    aggregates: &mut Aggregates,
    expected_status: &str,
    scout: &ScoutMetrics,
) -> Result<(), String> {
    let cross_tab = aggregates
        .scout_by_expected_status
        .entry(expected_status.to_owned())
        .or_default();
    match scout.disposition {
        ScoutDisposition::SatWitness => {
            if !scout.sat_witness_found || scout.selection.is_none() || scout.model.is_none() {
                return Err("sat-witness scout record is incomplete".to_owned());
            }
            checked_increment(
                &mut aggregates.scout_sat_witnesses,
                "scout SAT witness count",
            )?;
            checked_increment(&mut cross_tab.sat_witness, "scout cross-tab SAT witness")?;
            if expected_status.eq_ignore_ascii_case("unsat") {
                checked_increment(
                    &mut aggregates.expected_unsat_scout_sat_witnesses,
                    "expected-UNSAT scout witness count",
                )?;
            }
            let selection = scout
                .selection
                .as_ref()
                .ok_or_else(|| "sat-witness scout record has no selection".to_owned())?;
            increment_map(
                &mut aggregates.scout_selection_counts,
                format!("{}/{}", selection.quotient, selection.bool_fill),
                "scout selection count",
            )?;
        }
        ScoutDisposition::NoWitness => {
            if scout.sat_witness_found
                || scout.ineligible_reason.is_some()
                || scout.selection.is_some()
                || scout.model.is_some()
            {
                return Err("no-witness scout record contains witness data".to_owned());
            }
            checked_increment(&mut aggregates.scout_no_witnesses, "scout no-witness count")?;
            checked_increment(&mut cross_tab.no_witness, "scout cross-tab no witness")?;
        }
        ScoutDisposition::Ineligible => {
            if scout.sat_witness_found
                || scout.ineligible_reason.is_none()
                || scout.selection.is_some()
                || scout.model.is_some()
            {
                return Err("ineligible scout record is inconsistent".to_owned());
            }
            checked_increment(&mut aggregates.scout_ineligible, "scout ineligible count")?;
            checked_increment(&mut cross_tab.ineligible, "scout cross-tab ineligible")?;
            increment_map(
                &mut aggregates.scout_ineligible_reasons,
                scout
                    .ineligible_reason
                    .clone()
                    .ok_or_else(|| "ineligible scout record has no reason".to_owned())?,
                "scout ineligible reason count",
            )?;
        }
    }
    Ok(())
}

fn account_bool_dag(
    aggregates: &mut Aggregates,
    histograms: &mut Histograms,
    bool_dag: &BoolDagRecord,
) -> Result<(), String> {
    match bool_dag {
        BoolDagRecord::NotApplicable => checked_increment(
            &mut aggregates.bool_dag_not_applicable,
            "Boolean DAG not-applicable count",
        ),
        BoolDagRecord::Analyzed { metrics } => {
            histograms
                .bool_syntax_occurrences
                .observe(metrics.syntax_occurrences)?;
            if let Some(projection) = &metrics.syntactic {
                histograms
                    .syntactic_unique_nodes
                    .observe(projection.unique_nodes)?;
            }
            if let Some(projection) = &metrics.quotient {
                histograms
                    .quotient_unique_nodes
                    .observe(projection.unique_nodes)?;
            }
            if let Some(reduction) = metrics.quotient_unique_reduction_ppm {
                histograms
                    .quotient_unique_reduction_ppm
                    .observe(u64::from(reduction))?;
            }
            match metrics.status {
                BoolDagStatus::Complete => {
                    if metrics.abstention.is_some()
                        || metrics.syntactic.is_none()
                        || metrics.quotient.is_none()
                    {
                        return Err("complete Boolean DAG record is inconsistent".to_owned());
                    }
                    checked_increment(
                        &mut aggregates.bool_dag_complete,
                        "Boolean DAG complete count",
                    )
                }
                BoolDagStatus::Abstained => {
                    let Some(abstention) = &metrics.abstention else {
                        return Err("abstained Boolean DAG record has no reason".to_owned());
                    };
                    if metrics.syntactic.is_some() || metrics.quotient.is_some() {
                        return Err("abstained Boolean DAG record retained projections".to_owned());
                    }
                    checked_increment(
                        &mut aggregates.bool_dag_abstentions,
                        "Boolean DAG abstention count",
                    )?;
                    increment_map(
                        &mut aggregates.bool_dag_abstention_reasons,
                        abstention.reason.clone(),
                        "Boolean DAG abstention reason count",
                    )
                }
            }
        }
    }
}

fn validate_aggregate_partition(aggregates: &Aggregates) -> Result<(), String> {
    let input_partition = [
        aggregates.read_failures,
        aggregates.input_abstentions,
        aggregates.decode_failures,
        aggregates.parse_failures,
        aggregates.parsed_instances,
    ]
    .into_iter()
    .try_fold(0u64, |sum, count| {
        sum.checked_add(count)
            .ok_or_else(|| "input partition overflow".to_owned())
    })?;
    if input_partition != aggregates.instances {
        return Err("input outcome counts do not partition instances".to_owned());
    }
    let scout_partition = [
        aggregates.scout_sat_witnesses,
        aggregates.scout_no_witnesses,
        aggregates.scout_ineligible,
    ]
    .into_iter()
    .try_fold(0u64, |sum, count| {
        sum.checked_add(count)
            .ok_or_else(|| "scout partition overflow".to_owned())
    })?;
    if scout_partition != aggregates.parsed_instances {
        return Err("scout outcomes do not partition parsed instances".to_owned());
    }
    let dag_partition = [
        aggregates.bool_dag_not_applicable,
        aggregates.bool_dag_complete,
        aggregates.bool_dag_abstentions,
    ]
    .into_iter()
    .try_fold(0u64, |sum, count| {
        sum.checked_add(count)
            .ok_or_else(|| "Boolean DAG partition overflow".to_owned())
    })?;
    if dag_partition != aggregates.parsed_instances {
        return Err("Boolean DAG outcomes do not partition parsed instances".to_owned());
    }
    Ok(())
}

fn serialize_report(report: &CensusReport) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    serde_json::to_writer_pretty(&mut bytes, report)
        .map_err(|error| format!("failed to serialize census report: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("output path {} has no file name", path.display()))?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create output directory {}: {error}",
            parent.display()
        )
    })?;

    let mut temporary = None;
    let mut file = None;
    for _ in 0..128 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(format!(".tmp-{}-{sequence}", process::id()));
        let candidate = parent.join(temporary_name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(opened) => {
                temporary = Some(candidate);
                file = Some(opened);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "failed to create atomic output beside {}: {error}",
                    path.display()
                ));
            }
        }
    }
    let temporary = temporary.ok_or_else(|| {
        format!(
            "failed to allocate an atomic output temporary beside {}",
            path.display()
        )
    })?;
    let mut file = file.ok_or_else(|| "atomic output temporary has no open file".to_owned())?;
    let write_result = (|| -> io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(format!(
            "failed to atomically write {}: {error}",
            path.display()
        ));
    }
    Ok(())
}

fn reject_same_input_and_output(manifest: &Path, output: &Path) -> Result<(), String> {
    let manifest = fs::canonicalize(manifest).map_err(|error| {
        format!(
            "failed to resolve manifest path {}: {error}",
            manifest.display()
        )
    })?;
    if let Ok(output) = fs::canonicalize(output)
        && output == manifest
    {
        return Err("manifest and output paths refer to the same file".to_owned());
    }
    Ok(())
}

fn bounded_diagnostic(message: &str) -> String {
    let mut characters = message.chars();
    let mut bounded = characters
        .by_ref()
        .take(MAX_DIAGNOSTIC_CHARS)
        .collect::<String>();
    if characters.next().is_some() {
        bounded.push_str("...");
    }
    bounded
}

fn io_error_kind(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::NotFound => "not_found",
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::InvalidData => "invalid_data",
        io::ErrorKind::InvalidInput => "invalid_input",
        io::ErrorKind::IsADirectory => "is_a_directory",
        io::ErrorKind::NotADirectory => "not_a_directory",
        io::ErrorKind::TooManyLinks => "too_many_links",
        io::ErrorKind::OutOfMemory => "out_of_memory",
        io::ErrorKind::StorageFull => "storage_full",
        io::ErrorKind::ReadOnlyFilesystem => "read_only_filesystem",
        _ => "other",
    }
}

fn usize_to_u64(value: usize, label: &str) -> Result<u64, String> {
    u64::try_from(value).map_err(|_| format!("{label} does not fit in u64"))
}

fn checked_increment(value: &mut u64, label: &str) -> Result<(), String> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| format!("{label} overflow"))?;
    Ok(())
}

fn increment_map(map: &mut BTreeMap<String, u64>, key: String, label: &str) -> Result<(), String> {
    checked_increment(map.entry(key).or_insert(0), label)
}

#[test]
#[ignore = "set EUF_VIPER_NOVELTY_CENSUS_MANIFEST and EUF_VIPER_NOVELTY_CENSUS_OUTPUT"]
fn corpus_census_from_env() {
    run_from_env().expect("novelty corpus census failed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "euf-viper-novelty-census-{label}-{}-{sequence}",
                process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_scout(disposition: ScoutDisposition) -> ScoutMetrics {
        let witness = matches!(disposition, ScoutDisposition::SatWitness);
        let ineligible = matches!(disposition, ScoutDisposition::Ineligible);
        ScoutMetrics {
            disposition,
            sat_witness_found: witness,
            ineligible_reason: ineligible.then(|| "unsupported_source".to_owned()),
            selection: witness.then(|| ScoutSelectionRecord {
                quotient: "maximally_diverse".to_owned(),
                bool_fill: "all_false".to_owned(),
            }),
            candidates_attempted: u64::from(!ineligible),
            candidates_built: u64::from(!ineligible),
            candidate_build_failures: 0,
            models_validated: u64::from(!ineligible),
            model_validation_failures: 0,
            source_rejections: u64::from(matches!(disposition, ScoutDisposition::NoWitness)),
            source_evaluation_failures: 0,
            initial_quotient_merges: 0,
            congruence_merges: 0,
            congruence_rounds: 0,
            hit_function_entries: 0,
            model: witness.then(ScoutModelMetrics::default),
        }
    }

    fn complete_bool_dag() -> BoolDagRecord {
        BoolDagRecord::Analyzed {
            metrics: BoolDagMetrics {
                status: BoolDagStatus::Complete,
                assertion_roots: 1,
                data_term_entries: 0,
                data_term_roots: 0,
                syntax_occurrences: 3,
                projected_occurrences: 3,
                unconditional_equality_facts: 0,
                effective_equality_unions: 0,
                nontrivial_quotient_classes: 0,
                quotiented_terms: 0,
                syntactic: Some(DagProjectionMetrics {
                    unique_nodes: 2,
                    ..DagProjectionMetrics::default()
                }),
                quotient: Some(DagProjectionMetrics {
                    unique_nodes: 1,
                    ..DagProjectionMetrics::default()
                }),
                quotient_unique_reduction: Some(1),
                quotient_unique_reduction_ppm: Some(500_000),
                abstention: None,
            },
        }
    }

    fn abstained_bool_dag() -> BoolDagRecord {
        BoolDagRecord::Analyzed {
            metrics: BoolDagMetrics {
                status: BoolDagStatus::Abstained,
                assertion_roots: 1,
                data_term_entries: 0,
                data_term_roots: 0,
                syntax_occurrences: 6,
                projected_occurrences: 0,
                unconditional_equality_facts: 0,
                effective_equality_unions: 0,
                nontrivial_quotient_classes: 0,
                quotiented_terms: 0,
                syntactic: None,
                quotient: None,
                quotient_unique_reduction: None,
                quotient_unique_reduction_ppm: None,
                abstention: Some(AbstentionMetrics {
                    reason: AbstentionReason::SyntaxOccurrenceCap.as_str().to_owned(),
                    observed: 6,
                    limit: Some(5),
                }),
            },
        }
    }

    fn record(path: &str, status: Option<&str>, outcome: InstanceOutcome) -> InstanceRecord {
        InstanceRecord {
            manifest_line: 1,
            id: None,
            relative_path: path.to_owned(),
            expected_status: status.map(str::to_owned),
            source_sha256: None,
            outcome,
        }
    }

    #[test]
    fn manifest_decoding_is_structured_validated_and_sorted() {
        let input = concat!(
            "{\"id\":2,\"path\":\"cases/z.smt2\",\"relative_path\":\"z.smt2\",\"status\":\"unsat\"}\n",
            "\n",
            "{\"id\":1,\"relative_path\":\"a.smt2\",\"status\":\"sat\",\"sha256\":\"abc\"}\n"
        );
        let manifest_path = Path::new("/corpus/manifest.jsonl");
        let decoded = decode_manifest(Cursor::new(input.as_bytes()), manifest_path).unwrap();

        assert_eq!(decoded.blank_lines, 1);
        assert_eq!(decoded.entries.len(), 2);
        assert_eq!(decoded.entries[0].relative_path, "a.smt2");
        assert_eq!(decoded.entries[0].line_number, 3);
        assert_eq!(decoded.entries[0].source_path, Path::new("/corpus/a.smt2"));
        assert_eq!(decoded.entries[1].relative_path, "z.smt2");
        assert_eq!(
            decoded.entries[1].source_path,
            Path::new("/corpus/cases/z.smt2")
        );

        let duplicate = concat!(
            "{\"relative_path\":\"same.smt2\"}\n",
            "{\"relative_path\":\"same.smt2\"}\n"
        );
        assert!(
            decode_manifest(Cursor::new(duplicate.as_bytes()), manifest_path)
                .unwrap_err()
                .contains("duplicate relative_path")
        );
    }

    #[test]
    fn aggregate_accounting_partitions_failures_witnesses_and_abstentions() {
        let instances = vec![
            record(
                "a-read.smt2",
                None,
                InstanceOutcome::ReadFailure {
                    reason: "not_found".to_owned(),
                },
            ),
            record(
                "b-parse.smt2",
                Some("unknown"),
                InstanceOutcome::ParseFailure {
                    input_bytes: 9,
                    diagnostic: "bad input".to_owned(),
                },
            ),
            record(
                "c-hit.smt2",
                Some("unsat"),
                InstanceOutcome::Analyzed {
                    input_bytes: 32,
                    problem: ProblemMetrics {
                        terms: 4,
                        applications: 1,
                        ..ProblemMetrics::default()
                    },
                    scout: test_scout(ScoutDisposition::SatWitness),
                    bool_dag: complete_bool_dag(),
                },
            ),
            record(
                "d-miss.smt2",
                Some("sat"),
                InstanceOutcome::Analyzed {
                    input_bytes: 64,
                    problem: ProblemMetrics {
                        terms: 8,
                        applications: 2,
                        ..ProblemMetrics::default()
                    },
                    scout: test_scout(ScoutDisposition::NoWitness),
                    bool_dag: abstained_bool_dag(),
                },
            ),
            record(
                "e-ineligible.smt2",
                Some("unknown"),
                InstanceOutcome::Analyzed {
                    input_bytes: 16,
                    problem: ProblemMetrics::default(),
                    scout: test_scout(ScoutDisposition::Ineligible),
                    bool_dag: BoolDagRecord::NotApplicable,
                },
            ),
        ];

        let (aggregate, histograms) = account_instances(&instances).unwrap();
        assert_eq!(aggregate.instances, 5);
        assert_eq!(aggregate.read_failures, 1);
        assert_eq!(aggregate.parse_failures, 1);
        assert_eq!(aggregate.parsed_instances, 3);
        assert_eq!(aggregate.scout_sat_witnesses, 1);
        assert_eq!(aggregate.scout_no_witnesses, 1);
        assert_eq!(aggregate.scout_ineligible, 1);
        assert_eq!(aggregate.expected_unsat_scout_sat_witnesses, 1);
        assert_eq!(aggregate.bool_dag_complete, 1);
        assert_eq!(aggregate.bool_dag_abstentions, 1);
        assert_eq!(aggregate.bool_dag_not_applicable, 1);
        assert_eq!(
            aggregate.bool_dag_abstention_reasons["syntax_occurrence_cap"],
            1
        );
        assert_eq!(aggregate.expected_status_counts["unknown"], 2);
        assert_eq!(histograms.terms.buckets[2], 1);
        assert_eq!(histograms.terms.buckets[3], 1);
    }

    #[test]
    fn serialization_is_deterministic_and_lexically_orders_instances_and_maps() {
        let instances = vec![
            record(
                "z.smt2",
                Some("z-status"),
                InstanceOutcome::ReadFailure {
                    reason: "z-reason".to_owned(),
                },
            ),
            record(
                "a.smt2",
                Some("a-status"),
                InstanceOutcome::ReadFailure {
                    reason: "a-reason".to_owned(),
                },
            ),
        ];
        let first = serialize_report(&build_report(0, instances.clone()).unwrap()).unwrap();
        let second = serialize_report(&build_report(0, instances).unwrap()).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.last(), Some(&b'\n'));
        let text = String::from_utf8(first).unwrap();
        assert!(text.find("a.smt2").unwrap() < text.find("z.smt2").unwrap());
        assert!(text.find("a-status").unwrap() < text.find("z-status").unwrap());
        assert!(!text.contains("timestamp"));
    }

    #[test]
    fn malformed_manifest_fails_closed_without_replacing_output() {
        let directory = TestDirectory::new("fail-closed");
        let manifest = directory.path().join("manifest.jsonl");
        let output = directory.path().join("census.json");
        fs::write(&manifest, b"{\"relative_path\":42}\n").unwrap();
        fs::write(&output, b"sentinel\n").unwrap();

        let error = run_census(&manifest, &output).unwrap_err();
        assert!(error.contains("invalid manifest JSON"));
        assert_eq!(fs::read(&output).unwrap(), b"sentinel\n");
        assert_eq!(
            fs::read_dir(directory.path())
                .unwrap()
                .filter_map(Result::ok)
                .count(),
            2
        );
    }

    #[test]
    fn scout_miss_serializes_only_as_no_witness_never_unsat() {
        let report = build_report(
            0,
            vec![record(
                "miss.smt2",
                Some("sat"),
                InstanceOutcome::Analyzed {
                    input_bytes: 1,
                    problem: ProblemMetrics::default(),
                    scout: test_scout(ScoutDisposition::NoWitness),
                    bool_dag: BoolDagRecord::NotApplicable,
                },
            )],
        )
        .unwrap();
        let serialized = String::from_utf8(serialize_report(&report).unwrap()).unwrap();

        assert!(serialized.contains("\"disposition\": \"no_witness\""));
        assert!(!serialized.contains("scout_unsat"));
        assert!(!serialized.contains("\"disposition\": \"unsat\""));
    }
}
