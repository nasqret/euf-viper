#![cfg(feature = "certificates")]

use super::bool_dag_telemetry::{
    AblationProjection, AblationTelemetry, ProjectedCnf, analyze_four_way_ablation,
};
use super::{Problem, ScopedLetMode, parse_problem_with_scoped_let_mode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const SCHEMA: &str = "euf-viper.t6-theory-dag-census.v1";
const MANIFEST_SCHEMA: &str = "euf-viper.t6-theory-dag-manifest.v1";
const MANIFEST_ENV: &str = "EUF_VIPER_T6_MANIFEST";
const CORPUS_ROOT_ENV: &str = "EUF_VIPER_T6_CORPUS_ROOT";
const OUTPUT_ENV: &str = "EUF_VIPER_T6_OUTPUT";
const REVISION_ENV: &str = "EUF_VIPER_EXPECTED_REVISION";
const EXPECTED_SOURCES: usize = 10;
const EXPECTED_PATH_LIST_SHA256: &str =
    "43f367dfa7bc1684cb48828415249b59779416d17ad1fb2af50d4c8366bf2523";
const REQUIRED_D_REDUCTION_PPM: i64 = 250_000;
const REQUIRED_INCREMENT_OVER_B_PPM: i64 = 50_000;
const REQUIRED_INCREMENT_OVER_C_PPM: i64 = 50_000;
const REQUIRED_QUALIFYING_SOURCES: usize = 8;
const HISTORICAL_PERFORMANCE_REVISION: &str = "58efe9d43dab65675530ad4f52b93df2bf73d729";
const HISTORICAL_PROVENANCE_REVISION: &str = "70d28bf3a5f410ec38047324d581667d298ecc93";
const HISTORICAL_PROVENANCE_SHA256: &str =
    "2a61b9f10d9e5999d1330fe4f00f36c4b0b4b6482d159768a4040f951d02cad1";
const HISTORICAL_RESULT_SHA256: &str =
    "f255208a70c7af4ef34039a577ba6642002397097ef3bb8ac73041293b980863";
const CURRENT_P0_REVISION: &str = "30828a4f0c1e7e478a9c6f406ccb245eeefc4961";
const CURRENT_P0_AUDIT_SHA256: &str =
    "2458b01872a290c89f715a277dfd41e2c28091fc649925c9acbfefeb6e72686a";
const CURRENT_P0_EXPECTED_SOURCES: usize = 12;
const MAX_SOURCE_BYTES: usize = 16 * 1_048_576;
const MAX_DIAGNOSTIC_CHARS: usize = 512;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenManifest {
    schema: String,
    selection: SelectionContract,
    projection_contract: ProjectionContract,
    gate: GateContract,
    current_confirmation: CurrentConfirmationContract,
    sources: Vec<FrozenSource>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionContract {
    candidate_count: usize,
    canonical_order: String,
    canonical_path_list_sha256: String,
    derivation: String,
    domain7_huge_population_path_list_sha256: String,
    evidence_scope: String,
    historical_campaign_result: String,
    historical_campaign_result_sha256: String,
    performance_revision: String,
    provenance_document: String,
    provenance_document_revision: String,
    provenance_document_sha256: String,
    provenance_section: String,
    selection_version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CurrentConfirmationContract {
    derivation_policy: String,
    expected_source_count: usize,
    implementation_or_promotion_eligible: bool,
    p0_audit_path: String,
    p0_audit_sha256: String,
    p0_revision: String,
    required_before_implementation_or_promotion: bool,
    status: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionContract {
    arms: ArmContract,
    encoding: String,
    primary_measure: String,
    secondary_measures: Vec<String>,
    two_watch_rule: String,
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArmContract {
    A: String,
    B: String,
    C: String,
    D: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct GateContract {
    decision_rule: String,
    minimum_qualifying_sources: usize,
    qualifying_source_rule: String,
    required_d_reduction_from_a_ppm: i64,
    required_increment_over_b_ppm: i64,
    required_increment_over_c_ppm: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenSource {
    relative_path: String,
    selection_tags: Vec<String>,
    sequence: usize,
    source_bytes: usize,
    source_sha256: String,
    taxonomy: Taxonomy,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Taxonomy {
    generator_lineage: String,
    rule: String,
    source_family: String,
    variant: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct CensusReport {
    schema: &'static str,
    analysis_revision: String,
    contract: ReportContract,
    manifest: ManifestRecord,
    gate: GateRecord,
    current_confirmation: CurrentConfirmationContract,
    sources: Vec<SourceRecord>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ReportContract {
    analysis: &'static str,
    parser_mode: &'static str,
    primary_measure: &'static str,
    result_semantics: &'static str,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ManifestRecord {
    file_sha256: String,
    canonical_path_list_sha256: String,
    sources: u64,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum GateDecision {
    Pass,
    Reject,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct GateRecord {
    scope: &'static str,
    decision: GateDecision,
    pass_semantics: &'static str,
    qualifying_sources: u64,
    required_qualifying_sources: u64,
    required_d_reduction_from_a_ppm: i64,
    required_increment_over_b_ppm: i64,
    required_increment_over_c_ppm: i64,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct SourceRecord {
    sequence: u64,
    relative_path: String,
    source_bytes: u64,
    source_sha256: String,
    taxonomy: Taxonomy,
    shape: ShapeRecord,
    theory: TheoryRecord,
    projections: ProjectionSet,
    reductions: ReductionRecord,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ShapeRecord {
    sorts: u64,
    function_declarations: u64,
    terms: u64,
    applications: u64,
    assertion_roots: u64,
    boolean_data_roots: u64,
    source_occurrences: u64,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct TheoryRecord {
    unconditional_equality_facts: u64,
    root_equality_unions: u64,
    congruence_unions: u64,
    congruence_rounds: u64,
    congruence_signature_entries: u64,
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, PartialEq, Eq)]
struct ProjectionSet {
    A_tree_no_sharing: ProjectionRecord,
    B_generic_source_dag: ProjectionRecord,
    C_root_union_dag: ProjectionRecord,
    D_full_typed_euf_dag: ProjectionRecord,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ProjectionRecord {
    source_occurrences: u64,
    assertion_roots: u64,
    boolean_data_roots: u64,
    gate_definitions: u64,
    gate_edges: u64,
    cnf: CnfRecord,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
struct CnfRecord {
    atom_variables: u64,
    constant_variables: u64,
    tseitin_variables: u64,
    variables: u64,
    clauses: u64,
    literal_slots: u64,
    unit_clauses: u64,
    two_watch_entries: u64,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
struct ReductionRecord {
    b_reduction_from_a_ppm: i64,
    c_reduction_from_a_ppm: i64,
    d_reduction_from_a_ppm: i64,
    d_increment_over_b_ppm: i64,
    d_increment_over_c_ppm: i64,
    qualifies: bool,
}

pub(crate) fn run_from_env() -> Result<(), String> {
    let manifest = required_path(MANIFEST_ENV)?;
    let corpus_root = required_path(CORPUS_ROOT_ENV)?;
    let output = required_path(OUTPUT_ENV)?;
    let revision = required_revision()?;
    run_census(&manifest, &corpus_root, &output, &revision)
}

fn required_path(name: &str) -> Result<PathBuf, String> {
    let value = env::var_os(name).ok_or_else(|| format!("{name} is required"))?;
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(PathBuf::from(value))
}

fn required_revision() -> Result<String, String> {
    let revision = env::var(REVISION_ENV).map_err(|_| format!("{REVISION_ENV} is required"))?;
    if !(7..=64).contains(&revision.len()) || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(format!(
            "{REVISION_ENV} must be a 7-64 digit hexadecimal revision"
        ));
    }
    Ok(revision.to_ascii_lowercase())
}

fn run_census(
    manifest_path: &Path,
    corpus_root: &Path,
    output_path: &Path,
    revision: &str,
) -> Result<(), String> {
    if manifest_path == output_path {
        return Err("manifest and output paths must differ".to_owned());
    }
    let manifest_bytes = fs::read(manifest_path)
        .map_err(|error| format!("failed to read {}: {error}", manifest_path.display()))?;
    let manifest: FrozenManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("invalid frozen manifest: {error}"))?;
    validate_manifest(&manifest)?;

    let mut sources = Vec::with_capacity(manifest.sources.len());
    for source in &manifest.sources {
        sources.push(analyze_source(corpus_root, source)?);
    }
    let report = build_report(
        revision,
        sha256_hex(&manifest_bytes),
        manifest.selection.canonical_path_list_sha256.clone(),
        manifest.current_confirmation.clone(),
        sources,
    )?;
    let bytes = serialize_report(&report)?;
    atomic_write(output_path, &bytes)
}

fn validate_manifest(manifest: &FrozenManifest) -> Result<(), String> {
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(format!("unexpected manifest schema {:?}", manifest.schema));
    }
    if manifest.selection.candidate_count != EXPECTED_SOURCES
        || manifest.sources.len() != EXPECTED_SOURCES
    {
        return Err(format!(
            "frozen source count mismatch: declared {}, observed {}, expected {EXPECTED_SOURCES}",
            manifest.selection.candidate_count,
            manifest.sources.len()
        ));
    }
    if manifest.selection.canonical_order != "relative_path_bytewise_ascending" {
        return Err("unexpected canonical ordering contract".to_owned());
    }
    if manifest.selection.canonical_path_list_sha256 != EXPECTED_PATH_LIST_SHA256 {
        return Err("unexpected frozen path-list digest".to_owned());
    }
    if manifest.selection.derivation
        != "lexicographically sorted intersection of the frozen DOMAIN7_HUGE selector and the 10 QG entries in the historical pre-fix 58efe9d full-60 timeout table; retained only as the preregistered developmental 8/10 gate"
    {
        return Err("selection derivation drift".to_owned());
    }
    require_sha256(
        &manifest.selection.domain7_huge_population_path_list_sha256,
        "DOMAIN7_HUGE path-list digest",
    )?;
    if manifest.selection.evidence_scope != "historical_58efe9d_developmental_gate_not_current_p0"
        || manifest.selection.historical_campaign_result
            != "results/wmi/four-solver-60s-143248/qf-uf-corpus-143248.csv"
        || manifest.selection.historical_campaign_result_sha256 != HISTORICAL_RESULT_SHA256
        || manifest.selection.performance_revision != HISTORICAL_PERFORMANCE_REVISION
        || manifest.selection.provenance_document
            != "research-vault/06-results/2026-07-11-tail-opportunity-atlas.md"
        || manifest.selection.provenance_document_revision != HISTORICAL_PROVENANCE_REVISION
        || manifest.selection.provenance_document_sha256 != HISTORICAL_PROVENANCE_SHA256
        || manifest.selection.provenance_section != "Exact 60-second timeout manifest"
        || manifest.selection.selection_version
            != "historical-58efe9d-full60-domain7-huge-intersection-v1"
    {
        return Err("selection provenance drift".to_owned());
    }
    require_sha256(
        &manifest.selection.historical_campaign_result_sha256,
        "historical campaign result SHA-256",
    )?;
    require_sha256(
        &manifest.selection.provenance_document_sha256,
        "provenance document SHA-256",
    )?;
    validate_projection_contract(&manifest.projection_contract)?;
    validate_gate_contract(&manifest.gate)?;
    validate_current_confirmation(&manifest.current_confirmation)?;

    let mut previous = None::<&str>;
    for (index, source) in manifest.sources.iter().enumerate() {
        if source.sequence != index {
            return Err(format!(
                "source sequence mismatch at index {index}: {}",
                source.sequence
            ));
        }
        validate_relative_path(&source.relative_path)?;
        if previous.is_some_and(|path| path >= source.relative_path.as_str()) {
            return Err("frozen sources are not strictly path-sorted".to_owned());
        }
        previous = Some(&source.relative_path);
        if source.source_bytes == 0 || source.source_bytes > MAX_SOURCE_BYTES {
            return Err(format!(
                "source byte contract out of range for {}",
                source.relative_path
            ));
        }
        require_sha256(&source.source_sha256, "source SHA-256")?;
        if source.selection_tags
            != [
                "DOMAIN7_HUGE".to_owned(),
                "HISTORICAL_58EFE9D_FULL60_PERSISTENT".to_owned(),
            ]
        {
            return Err(format!("selection tags drift for {}", source.relative_path));
        }
        validate_taxonomy(source)?;
    }
    let path_digest = canonical_path_list_sha256(&manifest.sources);
    if path_digest != manifest.selection.canonical_path_list_sha256 {
        return Err(format!(
            "path-list digest mismatch: computed {path_digest}, frozen {}",
            manifest.selection.canonical_path_list_sha256
        ));
    }
    Ok(())
}

fn validate_current_confirmation(contract: &CurrentConfirmationContract) -> Result<(), String> {
    if contract.derivation_policy
        != "a distinct confirmation manifest must be generated mechanically from the frozen current P0 full-60 audit; hand-selected paths are forbidden"
        || contract.expected_source_count != CURRENT_P0_EXPECTED_SOURCES
        || contract.implementation_or_promotion_eligible
        || contract.p0_audit_path != "p0-144990/continuations/chain-145036/audit/full-60.json"
        || contract.p0_audit_sha256 != CURRENT_P0_AUDIT_SHA256
        || contract.p0_revision != CURRENT_P0_REVISION
        || !contract.required_before_implementation_or_promotion
        || contract.status != "not_materialized"
    {
        return Err("current P0 confirmation contract drift".to_owned());
    }
    require_sha256(&contract.p0_audit_sha256, "current P0 audit SHA-256")?;
    Ok(())
}

fn validate_projection_contract(contract: &ProjectionContract) -> Result<(), String> {
    for (field, value) in [
        ("arm A", contract.arms.A.as_str()),
        ("arm B", contract.arms.B.as_str()),
        ("arm C", contract.arms.C.as_str()),
        ("arm D", contract.arms.D.as_str()),
        ("encoding", contract.encoding.as_str()),
        ("two-watch rule", contract.two_watch_rule.as_str()),
    ] {
        require_nonempty(value, field)?;
    }
    if contract.primary_measure != "literal_slots"
        || contract.secondary_measures
            != [
                "variables".to_owned(),
                "clauses".to_owned(),
                "unit_clauses".to_owned(),
                "two_watch_entries".to_owned(),
            ]
    {
        return Err("projection measure contract drift".to_owned());
    }
    Ok(())
}

fn validate_gate_contract(contract: &GateContract) -> Result<(), String> {
    require_nonempty(&contract.decision_rule, "gate decision rule")?;
    require_nonempty(&contract.qualifying_source_rule, "qualifying-source rule")?;
    if contract.minimum_qualifying_sources != REQUIRED_QUALIFYING_SOURCES
        || contract.required_d_reduction_from_a_ppm != REQUIRED_D_REDUCTION_PPM
        || contract.required_increment_over_b_ppm != REQUIRED_INCREMENT_OVER_B_PPM
        || contract.required_increment_over_c_ppm != REQUIRED_INCREMENT_OVER_C_PPM
    {
        return Err("gate threshold drift".to_owned());
    }
    Ok(())
}

fn validate_taxonomy(source: &FrozenSource) -> Result<(), String> {
    let path = Path::new(&source.relative_path);
    let parts = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if parts.len() != 4
        || parts[0] != "QF_UF"
        || parts[1] != "QG-classification"
        || parts[2] != "qg7"
    {
        return Err(format!(
            "unexpected hard-10 taxonomy path {}",
            source.relative_path
        ));
    }
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("invalid source filename {}", source.relative_path))?;
    let lineage_stem = stem.trim_end_matches(|character: char| character.is_ascii_digit());
    let expected = Taxonomy {
        generator_lineage: format!("QF_UF/QG-classification/{lineage_stem}"),
        rule: "qg-size-variant".to_owned(),
        source_family: "QF_UF/QG-classification".to_owned(),
        variant: "qg7".to_owned(),
    };
    if source.taxonomy != expected {
        return Err(format!("taxonomy drift for {}", source.relative_path));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), String> {
    if value.is_empty() || value.contains('\\') || value.contains('\0') {
        return Err(format!("unsafe relative path {value:?}"));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path.extension().and_then(|extension| extension.to_str()) != Some("smt2")
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("unsafe relative path {value:?}"));
    }
    Ok(())
}

fn require_nonempty(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(format!("{field} must be nonempty printable text"));
    }
    Ok(())
}

fn require_sha256(value: &str, field: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} is not lowercase SHA-256"));
    }
    Ok(())
}

fn canonical_path_list_sha256(sources: &[FrozenSource]) -> String {
    let mut digest = Sha256::new();
    for source in sources {
        digest.update(source.relative_path.as_bytes());
        digest.update(b"\n");
    }
    format!("{:x}", digest.finalize())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let file =
        File::open(path).map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take((MAX_SOURCE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    if bytes.len() > MAX_SOURCE_BYTES {
        return Err(format!(
            "source exceeds {MAX_SOURCE_BYTES} bytes: {}",
            path.display()
        ));
    }
    Ok(bytes)
}

fn verify_source_bytes(source: &FrozenSource, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() != source.source_bytes {
        return Err(format!(
            "source byte mismatch for {}: expected {}, observed {}",
            source.relative_path,
            source.source_bytes,
            bytes.len()
        ));
    }
    let observed = sha256_hex(bytes);
    if observed != source.source_sha256 {
        return Err(format!(
            "source SHA-256 mismatch for {}: expected {}, observed {observed}",
            source.relative_path, source.source_sha256
        ));
    }
    Ok(())
}

fn analyze_source(corpus_root: &Path, source: &FrozenSource) -> Result<SourceRecord, String> {
    let path = corpus_root.join(&source.relative_path);
    let bytes = read_bounded(&path)?;
    verify_source_bytes(source, &bytes)?;
    let input = String::from_utf8(bytes)
        .map_err(|error| format!("invalid UTF-8 in {}: {error}", source.relative_path))?;
    let problem =
        parse_problem_with_scoped_let_mode(&input, ScopedLetMode::Auto).map_err(|error| {
            format!(
                "parse failure in {}: {}",
                source.relative_path,
                bounded_diagnostic(&error)
            )
        })?;
    validate_problem(&problem, &source.relative_path)?;
    let boolean = problem
        .bool_problem
        .as_ref()
        .ok_or_else(|| format!("missing Boolean source IR for {}", source.relative_path))?;
    let telemetry = analyze_four_way_ablation(boolean, &problem.arena).map_err(|abstention| {
        format!(
            "projection abstention in {}: reason={}, observed={}, limit={:?}",
            source.relative_path,
            abstention.reason.as_str(),
            abstention.observed,
            abstention.limit
        )
    })?;
    validate_telemetry(&telemetry)?;
    source_record(source, &problem, telemetry)
}

fn validate_problem(problem: &Problem, relative_path: &str) -> Result<(), String> {
    if !problem.terms_are_well_sorted() {
        return Err(format!("ill-sorted typed IR for {relative_path}"));
    }
    if !problem.unsupported.is_empty() {
        return Err(format!(
            "unsupported source constructs in {relative_path}: {}",
            bounded_diagnostic(&problem.unsupported.join("; "))
        ));
    }
    if let Some(boolean) = &problem.bool_problem {
        if !boolean.unsupported.is_empty() {
            return Err(format!(
                "unsupported Boolean constructs in {relative_path}: {}",
                bounded_diagnostic(&boolean.unsupported.join("; "))
            ));
        }
    }
    Ok(())
}

fn validate_telemetry(telemetry: &AblationTelemetry) -> Result<(), String> {
    let projections = [
        telemetry.tree_no_sharing,
        telemetry.generic_source_dag,
        telemetry.root_union_dag,
        telemetry.full_euf_dag,
    ];
    for projection in projections {
        if projection.source_occurrences != telemetry.source_occurrences
            || projection.assertion_roots != telemetry.assertion_roots
            || projection.boolean_data_roots != telemetry.boolean_data_roots
            || projection.gate_definitions != projection.cnf.tseitin_variables
            || projection.cnf.variables
                != projection
                    .cnf
                    .atom_variables
                    .checked_add(projection.cnf.constant_variables)
                    .and_then(|value| value.checked_add(projection.cnf.tseitin_variables))
                    .ok_or_else(|| "projection variable overflow".to_owned())?
            || projection.cnf.unit_clauses > projection.cnf.clauses
            || projection.cnf.two_watch_entries % 2 != 0
        {
            return Err("inconsistent projection accounting".to_owned());
        }
    }
    if telemetry.generic_source_dag.gate_definitions > telemetry.tree_no_sharing.gate_definitions
        || telemetry.root_union_dag.gate_definitions > telemetry.tree_no_sharing.gate_definitions
        || telemetry.full_euf_dag.gate_definitions > telemetry.tree_no_sharing.gate_definitions
    {
        return Err("DAG projection created more definitions than the tree arm".to_owned());
    }
    Ok(())
}

fn source_record(
    source: &FrozenSource,
    problem: &Problem,
    telemetry: AblationTelemetry,
) -> Result<SourceRecord, String> {
    let reductions = reductions(&telemetry)?;
    Ok(SourceRecord {
        sequence: source.sequence as u64,
        relative_path: source.relative_path.clone(),
        source_bytes: source.source_bytes as u64,
        source_sha256: source.source_sha256.clone(),
        taxonomy: source.taxonomy.clone(),
        shape: ShapeRecord {
            sorts: problem.sorts.names.len() as u64,
            function_declarations: problem.fun_decls.slots.iter().flatten().count() as u64,
            terms: problem.arena.terms.len() as u64,
            applications: problem.arena.app_count() as u64,
            assertion_roots: telemetry.assertion_roots,
            boolean_data_roots: telemetry.boolean_data_roots,
            source_occurrences: telemetry.source_occurrences,
        },
        theory: TheoryRecord {
            unconditional_equality_facts: telemetry.unconditional_equality_facts,
            root_equality_unions: telemetry.root_equality_unions,
            congruence_unions: telemetry.congruence_unions,
            congruence_rounds: telemetry.congruence_rounds,
            congruence_signature_entries: telemetry.congruence_signature_entries,
        },
        projections: ProjectionSet {
            A_tree_no_sharing: projection_record(telemetry.tree_no_sharing),
            B_generic_source_dag: projection_record(telemetry.generic_source_dag),
            C_root_union_dag: projection_record(telemetry.root_union_dag),
            D_full_typed_euf_dag: projection_record(telemetry.full_euf_dag),
        },
        reductions,
    })
}

fn projection_record(projection: AblationProjection) -> ProjectionRecord {
    ProjectionRecord {
        source_occurrences: projection.source_occurrences,
        assertion_roots: projection.assertion_roots,
        boolean_data_roots: projection.boolean_data_roots,
        gate_definitions: projection.gate_definitions,
        gate_edges: projection.gate_edges,
        cnf: cnf_record(projection.cnf),
    }
}

fn cnf_record(cnf: ProjectedCnf) -> CnfRecord {
    CnfRecord {
        atom_variables: cnf.atom_variables,
        constant_variables: cnf.constant_variables,
        tseitin_variables: cnf.tseitin_variables,
        variables: cnf.variables,
        clauses: cnf.clauses,
        literal_slots: cnf.literal_slots,
        unit_clauses: cnf.unit_clauses,
        two_watch_entries: cnf.two_watch_entries,
    }
}

fn reductions(telemetry: &AblationTelemetry) -> Result<ReductionRecord, String> {
    let a = telemetry.tree_no_sharing.cnf.literal_slots;
    let b = reduction_ppm(a, telemetry.generic_source_dag.cnf.literal_slots)?;
    let c = reduction_ppm(a, telemetry.root_union_dag.cnf.literal_slots)?;
    let d = reduction_ppm(a, telemetry.full_euf_dag.cnf.literal_slots)?;
    let d_increment_over_b = d
        .checked_sub(b)
        .ok_or_else(|| "D/B reduction margin overflow".to_owned())?;
    let d_increment_over_c = d
        .checked_sub(c)
        .ok_or_else(|| "D/C reduction margin overflow".to_owned())?;
    Ok(ReductionRecord {
        b_reduction_from_a_ppm: b,
        c_reduction_from_a_ppm: c,
        d_reduction_from_a_ppm: d,
        d_increment_over_b_ppm: d_increment_over_b,
        d_increment_over_c_ppm: d_increment_over_c,
        qualifies: qualifies(d, d_increment_over_b, d_increment_over_c),
    })
}

fn reduction_ppm(baseline: u64, candidate: u64) -> Result<i64, String> {
    if baseline == 0 {
        return if candidate == 0 {
            Ok(0)
        } else {
            Err("nonzero candidate projection with zero baseline".to_owned())
        };
    }
    let difference = i128::from(baseline) - i128::from(candidate);
    let scaled = difference
        .checked_mul(1_000_000)
        .ok_or_else(|| "reduction scaling overflow".to_owned())?
        / i128::from(baseline);
    i64::try_from(scaled).map_err(|_| "reduction does not fit i64".to_owned())
}

fn qualifies(d: i64, increment_b: i64, increment_c: i64) -> bool {
    d >= REQUIRED_D_REDUCTION_PPM
        && increment_b >= REQUIRED_INCREMENT_OVER_B_PPM
        && increment_c >= REQUIRED_INCREMENT_OVER_C_PPM
}

fn build_report(
    revision: &str,
    manifest_sha256: String,
    path_list_sha256: String,
    current_confirmation: CurrentConfirmationContract,
    sources: Vec<SourceRecord>,
) -> Result<CensusReport, String> {
    if sources.len() != EXPECTED_SOURCES {
        return Err(format!(
            "report source count mismatch: expected {EXPECTED_SOURCES}, got {}",
            sources.len()
        ));
    }
    let qualifying_sources = sources
        .iter()
        .filter(|source| source.reductions.qualifies)
        .count();
    Ok(CensusReport {
        schema: SCHEMA,
        analysis_revision: revision.to_owned(),
        contract: ReportContract {
            analysis: "source-only structural projection; no search engine is invoked",
            parser_mode: "production typed parser with scoped-let auto mode",
            primary_measure: "literal_slots",
            result_semantics: "counts are structural opportunity evidence, not timing or novelty evidence",
        },
        manifest: ManifestRecord {
            file_sha256: manifest_sha256,
            canonical_path_list_sha256: path_list_sha256,
            sources: sources.len() as u64,
        },
        gate: GateRecord {
            scope: "historical_58efe9d_developmental_8_of_10",
            decision: if qualifying_sources >= REQUIRED_QUALIFYING_SOURCES {
                GateDecision::Pass
            } else {
                GateDecision::Reject
            },
            pass_semantics: "developmental_only_current_12_confirmation_required_before_implementation_or_promotion",
            qualifying_sources: qualifying_sources as u64,
            required_qualifying_sources: REQUIRED_QUALIFYING_SOURCES as u64,
            required_d_reduction_from_a_ppm: REQUIRED_D_REDUCTION_PPM,
            required_increment_over_b_ppm: REQUIRED_INCREMENT_OVER_B_PPM,
            required_increment_over_c_ppm: REQUIRED_INCREMENT_OVER_C_PPM,
        },
        current_confirmation,
        sources,
    })
}

fn serialize_report(report: &CensusReport) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(report)
        .map_err(|error| format!("failed to serialize T6 report: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("output has no UTF-8 filename: {}", path.display()))?;
    let temporary = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), sequence));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("failed to create {}: {error}", temporary.display()))?;
        file.write_all(bytes)
            .map_err(|error| format!("failed to write {}: {error}", temporary.display()))?;
        file.sync_all()
            .map_err(|error| format!("failed to sync {}: {error}", temporary.display()))?;
        fs::rename(&temporary, path).map_err(|error| {
            format!(
                "failed to replace {} with {}: {error}",
                path.display(),
                temporary.display()
            )
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn bounded_diagnostic(value: &str) -> String {
    let mut result = value.chars().take(MAX_DIAGNOSTIC_CHARS).collect::<String>();
    if value.chars().count() > MAX_DIAGNOSTIC_CHARS {
        result.push_str("...");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frozen_manifest() -> FrozenManifest {
        serde_json::from_str(include_str!("../campaigns/t6-theory-dag-hard10-v1.json")).unwrap()
    }

    #[test]
    fn frozen_manifest_reproduces_audited_path_digest_and_taxonomy() {
        let manifest = frozen_manifest();
        validate_manifest(&manifest).unwrap();
        assert_eq!(
            canonical_path_list_sha256(&manifest.sources),
            EXPECTED_PATH_LIST_SHA256
        );
        assert_eq!(manifest.sources.len(), EXPECTED_SOURCES);
    }

    #[test]
    fn historical_provenance_tags_and_current_confirmation_reject_drift() {
        let mut revision_drift = frozen_manifest();
        revision_drift.selection.performance_revision = CURRENT_P0_REVISION.to_owned();
        assert_eq!(
            validate_manifest(&revision_drift).unwrap_err(),
            "selection provenance drift"
        );

        let mut version_drift = frozen_manifest();
        version_drift.selection.selection_version =
            "p0-full60-domain7-huge-intersection-v1".to_owned();
        assert_eq!(
            validate_manifest(&version_drift).unwrap_err(),
            "selection provenance drift"
        );

        let mut tag_drift = frozen_manifest();
        tag_drift.sources[0].selection_tags[1] = "P0_FULL60_PERSISTENT".to_owned();
        assert!(
            validate_manifest(&tag_drift)
                .unwrap_err()
                .contains("selection tags drift")
        );

        let mut audit_drift = frozen_manifest();
        audit_drift.current_confirmation.p0_audit_sha256 = "0".repeat(64);
        assert_eq!(
            validate_manifest(&audit_drift).unwrap_err(),
            "current P0 confirmation contract drift"
        );

        let mut eligibility_drift = frozen_manifest();
        eligibility_drift
            .current_confirmation
            .implementation_or_promotion_eligible = true;
        assert_eq!(
            validate_manifest(&eligibility_drift).unwrap_err(),
            "current P0 confirmation contract drift"
        );
    }

    #[test]
    fn manifest_reorder_delete_and_path_tampering_fail_closed() {
        let mut reordered = frozen_manifest();
        reordered.sources.swap(0, 1);
        assert!(
            validate_manifest(&reordered)
                .unwrap_err()
                .contains("sequence")
        );

        let mut deleted = frozen_manifest();
        deleted.sources.pop();
        assert!(
            validate_manifest(&deleted)
                .unwrap_err()
                .contains("source count")
        );

        let mut tampered = frozen_manifest();
        tampered.sources[0].relative_path =
            "QF_UF/QG-classification/qg7/gensys_icl_sk002.smt2".to_owned();
        assert!(validate_manifest(&tampered).is_err());
    }

    #[test]
    fn source_bytes_and_hash_are_both_bound() {
        let mut manifest = frozen_manifest();
        let source = &mut manifest.sources[0];
        source.source_bytes = 3;
        source.source_sha256 = sha256_hex(b"abc");
        verify_source_bytes(source, b"abc").unwrap();
        assert!(
            verify_source_bytes(source, b"abd")
                .unwrap_err()
                .contains("SHA-256")
        );
        assert!(
            verify_source_bytes(source, b"ab")
                .unwrap_err()
                .contains("byte mismatch")
        );
    }

    #[test]
    fn gate_boundaries_are_exact_and_use_percentage_point_margins() {
        assert!(qualifies(250_000, 50_000, 50_000));
        assert!(!qualifies(249_999, 50_000, 50_000));
        assert!(!qualifies(250_000, 49_999, 50_000));
        assert!(!qualifies(250_000, 50_000, 49_999));
        assert_eq!(reduction_ppm(100, 75).unwrap(), 250_000);
        assert_eq!(reduction_ppm(100, 80).unwrap(), 200_000);
        assert_eq!(reduction_ppm(100, 105).unwrap(), -50_000);
    }

    fn fake_source(sequence: u64, qualifies: bool) -> SourceRecord {
        let cnf = CnfRecord {
            atom_variables: 1,
            constant_variables: 0,
            tseitin_variables: 1,
            variables: 2,
            clauses: 2,
            literal_slots: 3,
            unit_clauses: 1,
            two_watch_entries: 2,
        };
        let projection = || ProjectionRecord {
            source_occurrences: 1,
            assertion_roots: 1,
            boolean_data_roots: 0,
            gate_definitions: 1,
            gate_edges: 2,
            cnf: CnfRecord { ..cnf },
        };
        SourceRecord {
            sequence,
            relative_path: format!("fixture-{sequence}.smt2"),
            source_bytes: 1,
            source_sha256: "0".repeat(64),
            taxonomy: Taxonomy {
                generator_lineage: "fixture".to_owned(),
                rule: "fixture".to_owned(),
                source_family: "fixture".to_owned(),
                variant: "fixture".to_owned(),
            },
            shape: ShapeRecord {
                sorts: 1,
                function_declarations: 1,
                terms: 1,
                applications: 0,
                assertion_roots: 1,
                boolean_data_roots: 0,
                source_occurrences: 1,
            },
            theory: TheoryRecord {
                unconditional_equality_facts: 0,
                root_equality_unions: 0,
                congruence_unions: 0,
                congruence_rounds: 0,
                congruence_signature_entries: 0,
            },
            projections: ProjectionSet {
                A_tree_no_sharing: projection(),
                B_generic_source_dag: projection(),
                C_root_union_dag: projection(),
                D_full_typed_euf_dag: projection(),
            },
            reductions: ReductionRecord {
                b_reduction_from_a_ppm: 200_000,
                c_reduction_from_a_ppm: 200_000,
                d_reduction_from_a_ppm: 250_000,
                d_increment_over_b_ppm: 50_000,
                d_increment_over_c_ppm: 50_000,
                qualifies,
            },
        }
    }

    #[test]
    fn report_bytes_are_deterministic_and_gate_is_fail_closed() {
        let sources = (0..10)
            .map(|sequence| fake_source(sequence, sequence < 7))
            .collect::<Vec<_>>();
        let first = build_report(
            "0123456789abcdef",
            "1".repeat(64),
            EXPECTED_PATH_LIST_SHA256.to_owned(),
            frozen_manifest().current_confirmation,
            sources,
        )
        .unwrap();
        let first_bytes = serialize_report(&first).unwrap();
        let second_bytes = serialize_report(&first).unwrap();

        assert_eq!(first_bytes, second_bytes);
        assert_eq!(first_bytes.last(), Some(&b'\n'));
        assert_eq!(first.gate.decision, GateDecision::Reject);
        assert_eq!(first.gate.qualifying_sources, 7);
        assert_eq!(first.gate.scope, "historical_58efe9d_developmental_8_of_10");
        assert!(
            first
                .current_confirmation
                .required_before_implementation_or_promotion
        );
        assert!(
            !first
                .current_confirmation
                .implementation_or_promotion_eligible
        );
        let text = String::from_utf8(first_bytes).unwrap();
        assert!(!text.contains("timestamp"));
    }

    #[test]
    #[ignore = "requires the frozen external hard-10 corpus"]
    fn hard10_census_from_env() {
        run_from_env().unwrap();
    }
}
