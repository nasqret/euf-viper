use super::{
    BoolAtomKey, Problem, ProductionSatWitness, ProductionTranscriptEvent, RootCnfOptions,
    SolveReport, SolveResult,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::path::Path;

pub(crate) const SCHEMA: &str = "euf-viper.production-evidence.v4";

const RUN_NONCE_ENV: &str = "EUF_VIPER_RUN_NONCE";
const TRUSTED_EXECUTABLE_SHA256_ENV: &str = "EUF_VIPER_TRUSTED_EXECUTABLE_SHA256";
const SEALED_BUILD_RECEIPT_ENV: &str = "EUF_VIPER_SEALED_BUILD_RECEIPT";
const SEALED_BUILD_RECEIPT_SHA256_ENV: &str = "EUF_VIPER_SEALED_BUILD_RECEIPT_SHA256";
const SEALED_BUILD_RECEIPT_SCHEMA: &str = "euf-viper.sealed-build-receipt.v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceDisposition {
    DecisiveSat,
    Unsupported,
}

#[derive(Serialize)]
struct EvidenceSource {
    path: String,
    sha256: String,
    bytes: usize,
}

#[derive(Serialize)]
struct EvidenceSolver {
    package_version: &'static str,
    revision: String,
    dirty: bool,
    executable_sha256: String,
    backend: String,
    config: BTreeMap<String, String>,
    config_sha256: String,
    build: EvidenceBuild,
    build_sha256: String,
    sealed_build: EvidenceSealedBuild,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SealedArtifact {
    bytes: u64,
    mode: String,
    sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SealedSource {
    dirty: bool,
    revision: String,
    snapshot_manifest_sha256: String,
    tree: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SealedBuild {
    execution_closure_sha256: String,
    features: Vec<String>,
    profile: String,
    target: String,
    toolchain: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SealedBuildReceipt {
    artifacts: BTreeMap<String, SealedArtifact>,
    build: SealedBuild,
    schema: String,
    sealed_build_manifest_sha256: String,
    source: SealedSource,
    status: String,
}

#[derive(Serialize)]
struct EvidenceSealedBuild {
    receipt: SealedBuildReceipt,
    receipt_sha256: String,
}

#[derive(Serialize)]
struct EvidenceBuild {
    features: Vec<String>,
    target: &'static str,
    profile: &'static str,
    rustc: &'static str,
    cargo: &'static str,
    source_manifest_sha256: &'static str,
    sealed_source_manifest_sha256: &'static str,
    execution_closure_sha256: &'static str,
}

#[derive(Serialize)]
struct EvidenceTerm {
    id: usize,
    function: String,
    args: Vec<usize>,
    sort: String,
    class: usize,
    internal: bool,
    internal_kind: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum EvidenceAtom {
    Equality {
        variable: usize,
        left: usize,
        right: usize,
        value: bool,
    },
    BoolTerm {
        variable: usize,
        term: usize,
        value: bool,
    },
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum EvidenceVariable {
    Auxiliary {
        variable: usize,
    },
    Equality {
        variable: usize,
        left: usize,
        right: usize,
    },
    BoolTerm {
        variable: usize,
        term: usize,
    },
}

#[derive(Serialize)]
struct EvidenceBackendCnf {
    format: &'static str,
    claim: &'static str,
    var_count: usize,
    variables: Vec<EvidenceVariable>,
    initial_clause_count: usize,
    initial_clauses_sha256: String,
    initial_clauses: Vec<Vec<i32>>,
    final_clause_count: usize,
    final_clauses_sha256: String,
    final_clauses: Vec<Vec<i32>>,
    transcript_event_count: usize,
    transcript_sha256: String,
    transcript: Vec<EvidenceTranscriptEvent>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum EvidenceTranscriptEvent {
    Clause {
        phase: &'static str,
        clause: Vec<i32>,
    },
    Solve {
        call: usize,
    },
    Assignment {
        call: usize,
        assignment: Vec<i32>,
    },
    Validation {
        call: usize,
        conflicts: Vec<Vec<i32>>,
    },
}

#[derive(Serialize)]
struct EvidenceModel {
    assignment: Vec<i32>,
    assignment_sha256: String,
    terms: Vec<EvidenceTerm>,
    atoms: Vec<EvidenceAtom>,
    true_term: usize,
    false_term: usize,
}

#[derive(Serialize)]
struct ProductionEvidence {
    schema: &'static str,
    run_nonce: String,
    status: &'static str,
    backend_status: &'static str,
    source: EvidenceSource,
    solver: EvidenceSolver,
    backend_cnf: Option<EvidenceBackendCnf>,
    model: Option<EvidenceModel>,
    limitations: Vec<String>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    #[cfg(test)]
    crate::record_evidence_work_for_test(crate::EvidenceWorkKind::Hash);
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    #[cfg(test)]
    crate::record_evidence_work_for_test(crate::EvidenceWorkKind::Serialization);
    let value = serde_json::to_value(value)
        .map_err(|error| format!("failed to serialize production evidence: {error}"))?;
    let mut bytes = serde_json::to_vec(&canonical_value(value))
        .map_err(|error| format!("failed to encode production evidence: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn canonical_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonical_value).collect()),
        Value::Object(values) => {
            let ordered = values
                .into_iter()
                .map(|(key, value)| (key, canonical_value(value)))
                .collect();
            Value::Object(ordered)
        }
        scalar => scalar,
    }
}

fn required_sha256_environment(name: &str) -> Result<String, String> {
    let value =
        env::var(name).map_err(|_| format!("{name} is required for production evidence"))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must be a lowercase SHA-256"));
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
fn running_executable() -> Result<(String, u64), String> {
    {
        let mut executable = File::open("/proc/self/exe")
            .map_err(|error| format!("failed to open running production executable: {error}"))?;
        let before = executable
            .metadata()
            .map_err(|error| format!("failed to inspect production executable: {error}"))?;
        let mut content = Vec::new();
        executable
            .read_to_end(&mut content)
            .map_err(|error| format!("failed to read running production executable: {error}"))?;
        let after = executable
            .metadata()
            .map_err(|error| format!("failed to re-inspect production executable: {error}"))?;
        if before.len() != after.len() || content.len() as u64 != after.len() {
            return Err("running production executable changed while it was hashed".to_owned());
        }
        Ok((sha256_hex(&content), after.len()))
    }
}

#[cfg(not(target_os = "linux"))]
fn running_executable() -> Result<(String, u64), String> {
    Err("production evidence requires Linux /proc/self/exe".to_owned())
}

fn trusted_executable() -> Result<(String, u64), String> {
    let trusted = required_sha256_environment(TRUSTED_EXECUTABLE_SHA256_ENV)?;
    let (actual, bytes) = running_executable()?;
    if actual != trusted {
        return Err(format!(
            "production executable SHA-256 mismatch: expected {trusted}, got {actual}"
        ));
    }
    Ok((actual, bytes))
}

fn require_hash(name: &str, value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("sealed build receipt has malformed {name}"));
    }
    Ok(())
}

fn require_object_id(name: &str, value: &str) -> Result<(), String> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("sealed build receipt has malformed {name}"));
    }
    Ok(())
}

fn validated_sealed_build() -> Result<EvidenceSealedBuild, String> {
    let path = env::var(SEALED_BUILD_RECEIPT_ENV)
        .map_err(|_| format!("{SEALED_BUILD_RECEIPT_ENV} is required for production evidence"))?;
    let expected_sha256 = required_sha256_environment(SEALED_BUILD_RECEIPT_SHA256_ENV)?;
    let raw = crate::nofollow_io::read_regular(Path::new(&path))?;
    let actual_sha256 = sha256_hex(&raw);
    if actual_sha256 != expected_sha256 {
        return Err(format!(
            "sealed build receipt SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
        ));
    }
    let receipt: SealedBuildReceipt = serde_json::from_slice(&raw)
        .map_err(|error| format!("invalid sealed build receipt: {error}"))?;
    if canonical_bytes(&receipt)? != raw {
        return Err("sealed build receipt is not canonical JSON".to_owned());
    }
    if receipt.schema != SEALED_BUILD_RECEIPT_SCHEMA || receipt.status != "accepted" {
        return Err("sealed build receipt has an unsupported schema or status".to_owned());
    }
    if receipt.source.dirty {
        return Err("sealed build receipt records a dirty source tree".to_owned());
    }
    require_object_id("source revision", &receipt.source.revision)?;
    require_object_id("source tree", &receipt.source.tree)?;
    require_hash(
        "source snapshot manifest SHA-256",
        &receipt.source.snapshot_manifest_sha256,
    )?;
    require_hash(
        "build execution closure SHA-256",
        &receipt.build.execution_closure_sha256,
    )?;
    require_hash(
        "sealed build manifest SHA-256",
        &receipt.sealed_build_manifest_sha256,
    )?;
    if !receipt.build.target.contains("linux") || receipt.build.profile != "release" {
        return Err("sealed build receipt does not describe a Linux release build".to_owned());
    }
    if receipt.build.features.is_empty()
        || receipt
            .build
            .features
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || !receipt
            .build
            .features
            .iter()
            .any(|feature| feature == "production-evidence")
    {
        return Err("sealed build receipt has an invalid feature set".to_owned());
    }
    let expected_toolchain = ["cargo", "rustc"];
    if receipt
        .build
        .toolchain
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != expected_toolchain
        || receipt
            .build
            .toolchain
            .values()
            .any(|value| value.is_empty())
    {
        return Err("sealed build receipt has an incomplete toolchain binding".to_owned());
    }
    let expected_artifacts = ["euf-viper", "euf-viper-build-features"];
    if receipt
        .artifacts
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != expected_artifacts
    {
        return Err("sealed build receipt has an unexpected artifact set".to_owned());
    }
    for (name, artifact) in &receipt.artifacts {
        require_hash(&format!("artifact {name} SHA-256"), &artifact.sha256)?;
        if artifact.bytes == 0 || artifact.mode != "0500" {
            return Err(format!(
                "sealed build receipt has invalid metadata for {name}"
            ));
        }
    }
    let (executable_sha256, executable_bytes) = trusted_executable()?;
    let executable = &receipt.artifacts["euf-viper"];
    if executable.sha256 != executable_sha256 {
        return Err("sealed build receipt does not bind the running executable".to_owned());
    }
    if executable.bytes != executable_bytes {
        return Err("sealed build receipt executable byte count differs".to_owned());
    }

    // These embedded values are diagnostics only.  The external receipt above is
    // the authority; disagreement still indicates a corrupt or mixed build set.
    let embedded_features = env!("EUF_VIPER_BUILD_FEATURES")
        .split(',')
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if embedded_features != receipt.build.features
        || env!("EUF_VIPER_BUILD_TARGET") != receipt.build.target
        || env!("EUF_VIPER_BUILD_PROFILE") != receipt.build.profile
        || env!("EUF_VIPER_GIT_REVISION") != receipt.source.revision
        || env!("EUF_VIPER_GIT_DIRTY") != "0"
        || env!("EUF_VIPER_BUILD_SEALED_SOURCE_TREE") != receipt.source.tree
        || env!("EUF_VIPER_BUILD_SEALED_SOURCE_MANIFEST_SHA256")
            != receipt.source.snapshot_manifest_sha256
        || env!("EUF_VIPER_BUILD_EXECUTION_CLOSURE_SHA256")
            != receipt.build.execution_closure_sha256
    {
        return Err("sealed build receipt disagrees with diagnostic binary markers".to_owned());
    }
    Ok(EvidenceSealedBuild {
        receipt,
        receipt_sha256: expected_sha256,
    })
}

pub(crate) fn require_sealed_build() -> Result<(), String> {
    validated_sealed_build().map(|_| ())
}

fn build_manifest() -> Result<(EvidenceBuild, String), String> {
    let features = env!("EUF_VIPER_BUILD_FEATURES")
        .split(',')
        .filter(|feature| !feature.is_empty())
        .map(str::to_owned)
        .collect();
    let build = EvidenceBuild {
        features,
        target: env!("EUF_VIPER_BUILD_TARGET"),
        profile: env!("EUF_VIPER_BUILD_PROFILE"),
        rustc: env!("EUF_VIPER_BUILD_RUSTC"),
        cargo: env!("EUF_VIPER_BUILD_CARGO"),
        source_manifest_sha256: env!("EUF_VIPER_BUILD_SOURCE_MANIFEST_SHA256"),
        sealed_source_manifest_sha256: env!("EUF_VIPER_BUILD_SEALED_SOURCE_MANIFEST_SHA256"),
        execution_closure_sha256: env!("EUF_VIPER_BUILD_EXECUTION_CLOSURE_SHA256"),
    };
    let digest = sha256_hex(&canonical_bytes(&build)?);
    Ok((build, digest))
}

fn runtime_config(root_cnf: RootCnfOptions) -> Result<(BTreeMap<String, String>, String), String> {
    let mut config = env::vars()
        .filter(|(key, _)| {
            key.starts_with("EUF_VIPER_")
                && key != RUN_NONCE_ENV
                && key != TRUSTED_EXECUTABLE_SHA256_ENV
                && key != SEALED_BUILD_RECEIPT_ENV
        })
        .collect::<BTreeMap<_, _>>();
    config.insert(
        "resolved.direct_root_cnf".to_owned(),
        u8::from(root_cnf.direct_root_cnf).to_string(),
    );
    config.insert(
        "resolved.direct_negated_root".to_owned(),
        u8::from(root_cnf.direct_negated_root).to_string(),
    );
    config.insert(
        "resolved.production_evidence_contract".to_owned(),
        "deterministic-cnf-transcript-v1".to_owned(),
    );
    config.insert(
        "resolved.production_evidence_mode".to_owned(),
        "cnf-assignment-transcript".to_owned(),
    );
    config.insert("resolved.eq_abstraction".to_owned(), "off".to_owned());
    config.insert("resolved.finite_domain".to_owned(), "off".to_owned());
    config.insert("resolved.full_ackermann".to_owned(), "off".to_owned());
    config.insert("resolved.chordal_transitivity".to_owned(), "off".to_owned());
    config.insert(
        "resolved.refinement_mode".to_owned(),
        "model-cuts".to_owned(),
    );
    let encoded = canonical_bytes(&config)?;
    Ok((config, sha256_hex(&encoded)))
}

fn symbol_names(problem: &Problem) -> Result<Vec<String>, String> {
    let symbols = problem
        .symbols
        .as_ref()
        .ok_or_else(|| "production evidence parse did not retain symbol identity".to_owned())?;
    let mut names = vec![None; symbols.ids.len()];
    for (name, &id) in &symbols.ids {
        let slot = names
            .get_mut(id as usize)
            .ok_or_else(|| format!("symbol ID {id} is out of range"))?;
        if slot.replace(name.clone()).is_some() {
            return Err(format!("duplicate symbol ID {id}"));
        }
    }
    names
        .into_iter()
        .enumerate()
        .map(|(id, name)| name.ok_or_else(|| format!("missing symbol name for ID {id}")))
        .collect()
}

fn internal_kind(name: &str) -> Option<String> {
    let body = name.strip_prefix("@euf_viper_")?;
    let (kind, ordinal) = body.rsplit_once('_')?;
    ordinal
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| kind.to_owned())
}

fn build_model(problem: &Problem, witness: &ProductionSatWitness) -> Result<EvidenceModel, String> {
    #[cfg(test)]
    crate::record_evidence_work_for_test(crate::EvidenceWorkKind::PayloadBuild);
    if witness.term_classes.len() != problem.arena.terms.len() {
        return Err(format!(
            "production witness has {} term classes for {} terms",
            witness.term_classes.len(),
            problem.arena.terms.len()
        ));
    }
    let names = symbol_names(problem)?;
    let mut terms = Vec::with_capacity(problem.arena.terms.len());
    for (id, term) in problem.arena.terms.iter().enumerate() {
        let function = names
            .get(term.fun as usize)
            .ok_or_else(|| format!("term {id} has unknown function ID {}", term.fun))?
            .clone();
        let internal = problem.internal_functions.contains(&term.fun);
        let kind = internal.then(|| internal_kind(&function)).flatten();
        if internal && kind.is_none() {
            return Err(format!(
                "internal function {function:?} lacks a stable evidence kind"
            ));
        }
        terms.push(EvidenceTerm {
            id,
            function,
            args: term.args.clone(),
            sort: problem.sorts.name(term.sort).to_owned(),
            class: witness.term_classes[id],
            internal,
            internal_kind: kind,
        });
    }
    let atoms = witness
        .atoms
        .iter()
        .map(|atom| match atom.atom {
            BoolAtomKey::Eq(left, right) => EvidenceAtom::Equality {
                variable: atom.variable,
                left,
                right,
                value: atom.value,
            },
            BoolAtomKey::BoolTerm(term) => EvidenceAtom::BoolTerm {
                variable: atom.variable,
                term,
                value: atom.value,
            },
        })
        .collect();
    let assignment_sha256 = sha256_hex(&canonical_bytes(&witness.assignment)?);
    Ok(EvidenceModel {
        assignment: witness.assignment.clone(),
        assignment_sha256,
        terms,
        atoms,
        true_term: witness.true_term,
        false_term: witness.false_term,
    })
}

fn build_backend_cnf(witness: &ProductionSatWitness) -> Result<EvidenceBackendCnf, String> {
    #[cfg(test)]
    crate::record_evidence_work_for_test(crate::EvidenceWorkKind::PayloadBuild);
    let var_count = witness.assignment.len();
    if witness.variables.len() != var_count {
        return Err(format!(
            "production witness has {} variable mappings for {var_count} variables",
            witness.variables.len()
        ));
    }
    let atoms_by_variable = witness
        .atoms
        .iter()
        .map(|atom| (atom.variable, atom))
        .collect::<BTreeMap<_, _>>();
    if atoms_by_variable.len() != witness.atoms.len() {
        return Err("production witness repeats an atom variable".to_owned());
    }
    let mut variables = Vec::with_capacity(var_count);
    for (offset, atom) in witness.variables.iter().enumerate() {
        let variable = offset + 1;
        let mapped = match atom {
            None => {
                if atoms_by_variable.contains_key(&variable) {
                    return Err(format!(
                        "auxiliary variable {variable} is also listed as an atom"
                    ));
                }
                EvidenceVariable::Auxiliary { variable }
            }
            Some(BoolAtomKey::Eq(left, right)) => {
                let recorded = atoms_by_variable
                    .get(&variable)
                    .ok_or_else(|| format!("atom variable {variable} is omitted from the model"))?;
                if !matches!(
                    &recorded.atom,
                    BoolAtomKey::Eq(recorded_left, recorded_right)
                        if recorded_left == left && recorded_right == right
                ) {
                    return Err(format!(
                        "atom variable {variable} has inconsistent metadata"
                    ));
                }
                EvidenceVariable::Equality {
                    variable,
                    left: *left,
                    right: *right,
                }
            }
            Some(BoolAtomKey::BoolTerm(term)) => {
                let recorded = atoms_by_variable
                    .get(&variable)
                    .ok_or_else(|| format!("atom variable {variable} is omitted from the model"))?;
                if !matches!(
                    &recorded.atom,
                    BoolAtomKey::BoolTerm(recorded_term) if recorded_term == term
                ) {
                    return Err(format!(
                        "atom variable {variable} has inconsistent metadata"
                    ));
                }
                EvidenceVariable::BoolTerm {
                    variable,
                    term: *term,
                }
            }
        };
        variables.push(mapped);
    }
    if atoms_by_variable
        .keys()
        .any(|variable| *variable == 0 || *variable > var_count)
    {
        return Err("production model lists an out-of-range atom variable".to_owned());
    }
    let transcript = witness
        .transcript
        .iter()
        .map(|event| match event {
            ProductionTranscriptEvent::Clause { phase, clause } => {
                EvidenceTranscriptEvent::Clause {
                    phase,
                    clause: clause.clone(),
                }
            }
            ProductionTranscriptEvent::Solve { call } => {
                EvidenceTranscriptEvent::Solve { call: *call }
            }
            ProductionTranscriptEvent::Assignment { call, assignment } => {
                EvidenceTranscriptEvent::Assignment {
                    call: *call,
                    assignment: assignment.clone(),
                }
            }
            ProductionTranscriptEvent::Validation { call, conflicts } => {
                EvidenceTranscriptEvent::Validation {
                    call: *call,
                    conflicts: conflicts.clone(),
                }
            }
        })
        .collect::<Vec<_>>();
    let initial_clause_count = witness.initial_clauses.len();
    let initial_clauses_sha256 = sha256_hex(&canonical_bytes(&witness.initial_clauses)?);
    let final_clause_count = witness.backend_clauses.len();
    let final_clauses_sha256 = sha256_hex(&canonical_bytes(&witness.backend_clauses)?);
    let transcript_event_count = transcript.len();
    let transcript_sha256 = sha256_hex(&canonical_bytes(&transcript)?);
    Ok(EvidenceBackendCnf {
        format: "dimacs-literal-arrays",
        claim: "clauses-supplied-through-backend-api",
        var_count,
        variables,
        initial_clause_count,
        initial_clauses_sha256,
        initial_clauses: witness.initial_clauses.clone(),
        final_clause_count,
        final_clauses_sha256,
        final_clauses: witness.backend_clauses.clone(),
        transcript_event_count,
        transcript_sha256,
        transcript,
    })
}

fn evidence_payload(
    source_path: &Path,
    source_bytes: &[u8],
    problem: &Problem,
    report: &SolveReport,
    root_cnf: RootCnfOptions,
) -> Result<(ProductionEvidence, EvidenceDisposition), String> {
    #[cfg(test)]
    crate::record_evidence_work_for_test(crate::EvidenceWorkKind::PayloadBuild);
    let run_nonce = required_sha256_environment(RUN_NONCE_ENV)?;
    let source = EvidenceSource {
        path: source_path.display().to_string(),
        sha256: sha256_hex(source_bytes),
        bytes: source_bytes.len(),
    };
    let (config, config_sha256) = runtime_config(root_cnf)?;
    let sealed_build = validated_sealed_build()?;
    let executable_sha256 = sealed_build.receipt.artifacts["euf-viper"].sha256.clone();
    let (build, build_sha256) = build_manifest()?;
    let solver = EvidenceSolver {
        package_version: env!("CARGO_PKG_VERSION"),
        revision: sealed_build.receipt.source.revision.clone(),
        dirty: sealed_build.receipt.source.dirty,
        executable_sha256,
        backend: report.backend.to_owned(),
        config,
        config_sha256,
        build,
        build_sha256,
        sealed_build,
    };
    match &report.result {
        SolveResult::Sat => {
            if report.backend == "congruence-closure" || solver.dirty {
                let limitation = if solver.dirty {
                    "dirty builds cannot emit decisive production evidence".to_owned()
                } else {
                    "congruence-closure SAT lacks a complete independent production-evidence contract"
                        .to_owned()
                };
                return Ok((
                    ProductionEvidence {
                        schema: SCHEMA,
                        run_nonce,
                        status: "unsupported",
                        backend_status: "sat",
                        source,
                        solver,
                        backend_cnf: None,
                        model: None,
                        limitations: vec![limitation],
                    },
                    EvidenceDisposition::Unsupported,
                ));
            }
            let witness = report.sat_witness.as_ref().ok_or_else(|| {
                "production SAT result did not retain its same-run assignment/model".to_owned()
            })?;
            if witness.backend != report.backend {
                return Err(
                    "production SAT witness backend does not match solve backend".to_owned(),
                );
            }
            let model = build_model(problem, witness)?;
            let backend_cnf = build_backend_cnf(witness)?;
            Ok((
                ProductionEvidence {
                    schema: SCHEMA,
                    run_nonce,
                    status: "sat",
                    backend_status: "sat",
                    source,
                    solver,
                    backend_cnf: Some(backend_cnf),
                    model: Some(model),
                    limitations: Vec::new(),
                },
                EvidenceDisposition::DecisiveSat,
            ))
        }
        SolveResult::Unsat => Ok((
            ProductionEvidence {
                schema: SCHEMA,
                run_nonce,
                status: "unsupported",
                backend_status: "unsat",
                source,
                solver,
                backend_cnf: None,
                model: None,
                limitations: vec![format!(
                    "backend {} returned UNSAT without a same-run independently replayable proof",
                    report.backend
                )],
            },
            EvidenceDisposition::Unsupported,
        )),
        SolveResult::Unsupported(reasons) => Ok((
            ProductionEvidence {
                schema: SCHEMA,
                run_nonce,
                status: "unsupported",
                backend_status: "unsupported",
                source,
                solver,
                backend_cnf: None,
                model: None,
                limitations: reasons.clone(),
            },
            EvidenceDisposition::Unsupported,
        )),
    }
}

pub(crate) fn write(
    output: &Path,
    source_path: &Path,
    source_bytes: &[u8],
    problem: &Problem,
    report: &SolveReport,
    root_cnf: RootCnfOptions,
) -> Result<EvidenceDisposition, String> {
    let (payload, disposition) =
        evidence_payload(source_path, source_bytes, problem, report, root_cnf)?;
    write_canonical_immutable(output, &payload)?;
    Ok(disposition)
}

fn write_canonical_immutable<T: Serialize>(output: &Path, payload: &T) -> Result<(), String> {
    let encoded = canonical_bytes(payload)?;
    #[cfg(test)]
    crate::record_evidence_work_for_test(crate::EvidenceWorkKind::ArtifactWrite);
    crate::nofollow_io::atomic_write_immutable(output, &encoded)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn canonical_config_hash_is_stable() {
        let mut left = BTreeMap::new();
        left.insert("b".to_owned(), "2".to_owned());
        left.insert("a".to_owned(), "1".to_owned());
        let mut right = BTreeMap::new();
        right.insert("a".to_owned(), "1".to_owned());
        right.insert("b".to_owned(), "2".to_owned());
        assert_eq!(
            canonical_bytes(&left).unwrap(),
            canonical_bytes(&right).unwrap()
        );
    }

    #[test]
    fn hash_serialization_and_immutable_write_are_instrumented() {
        crate::reset_evidence_work_telemetry();
        assert_eq!(sha256_hex(b"bound").len(), 64);
        let mut payload = BTreeMap::new();
        payload.insert("status", "sat");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temporary_root = if cfg!(target_os = "macos") {
            std::path::PathBuf::from("/private/tmp")
        } else {
            std::env::temp_dir()
        };
        let directory = temporary_root.join(format!(
            "euf-viper-evidence-instrumentation-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let output = directory.join("evidence.json");
        write_canonical_immutable(&output, &payload).unwrap();
        let work = crate::evidence_work_telemetry();
        assert!(work.hashes > 0, "{work:?}");
        assert!(work.serializations > 0, "{work:?}");
        assert!(work.artifact_writes > 0, "{work:?}");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn model_and_backend_payload_construction_are_instrumented() {
        let problem = crate::parse_problem_with_options(
            "(set-logic QF_UF)\n(declare-fun p () Bool)\n(assert p)\n(check-sat)\n",
            crate::ScopedLetMode::Auto,
            true,
        )
        .unwrap();
        crate::reset_evidence_work_telemetry();
        let report = crate::solve_problem_ref_with_options_and_eq_abstraction(
            &problem,
            crate::RootCnfOptions::existing_behavior(true),
            crate::EqAbstractionMode::Off,
            true,
        );
        let witness = report.sat_witness.as_ref().unwrap();
        build_model(&problem, witness).unwrap();
        build_backend_cnf(witness).unwrap();
        let work = crate::evidence_work_telemetry();
        assert!(work.payload_builds >= 2, "{work:?}");
        assert!(work.hashes > 0, "{work:?}");
        assert!(work.serializations > 0, "{work:?}");
    }
}
