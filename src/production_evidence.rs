use super::{BoolAtomKey, Problem, ProductionSatWitness, RootCnfOptions, SolveReport, SolveResult};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const SCHEMA: &str = "euf-viper.production-evidence.v2";

const RUN_NONCE_ENV: &str = "EUF_VIPER_RUN_NONCE";
const TRUSTED_EXECUTABLE_SHA256_ENV: &str = "EUF_VIPER_TRUSTED_EXECUTABLE_SHA256";

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
    revision: &'static str,
    dirty: bool,
    executable_sha256: String,
    backend: String,
    config: BTreeMap<String, String>,
    config_sha256: String,
    build: EvidenceBuild,
    build_sha256: String,
}

#[derive(Serialize)]
struct EvidenceBuild {
    features: Vec<String>,
    target: &'static str,
    profile: &'static str,
    rustc: &'static str,
    cargo: &'static str,
    source_manifest_sha256: &'static str,
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
    var_count: usize,
    clause_count: usize,
    clauses_sha256: String,
    variables: Vec<EvidenceVariable>,
    clauses: Vec<Vec<i32>>,
}

#[derive(Serialize)]
struct EvidenceModel {
    origin: &'static str,
    assignment: Option<Vec<i32>>,
    assignment_sha256: Option<String>,
    terms: Vec<EvidenceTerm>,
    atoms: Vec<EvidenceAtom>,
    true_term: Option<usize>,
    false_term: Option<usize>,
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
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
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

fn read_regular_nofollow(path: &Path) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path).map_err(|error| {
        format!(
            "failed to open {} without following links: {error}",
            path.display()
        )
    })?;
    let before = file
        .metadata()
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    if !before.is_file() {
        return Err(format!(
            "production evidence input is not a regular file: {}",
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let after = file
        .metadata()
        .map_err(|error| format!("failed to re-inspect {}: {error}", path.display()))?;
    if before.len() != after.len() || bytes.len() as u64 != after.len() {
        return Err(format!(
            "production evidence input changed while reading: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(format!(
                "production evidence input changed while reading: {}",
                path.display()
            ));
        }
        let path_after = fs::symlink_metadata(path)
            .map_err(|error| format!("production evidence input path changed: {error}"))?;
        if !path_after.is_file()
            || path_after.dev() != after.dev()
            || path_after.ino() != after.ino()
        {
            return Err(format!(
                "production evidence input path was replaced while reading: {}",
                path.display()
            ));
        }
    }
    Ok(bytes)
}

fn trusted_executable_sha256() -> Result<String, String> {
    let trusted = required_sha256_environment(TRUSTED_EXECUTABLE_SHA256_ENV)?;
    let executable = env::current_exe()
        .map_err(|error| format!("failed to locate production executable: {error}"))?;
    let actual = sha256_hex(&read_regular_nofollow(&executable)?);
    if actual != trusted {
        return Err(format!(
            "production executable SHA-256 mismatch: expected {trusted}, got {actual}"
        ));
    }
    Ok(actual)
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
    let assignment_sha256 = witness
        .assignment
        .as_ref()
        .map(canonical_bytes)
        .transpose()?
        .map(|bytes| sha256_hex(&bytes));
    Ok(EvidenceModel {
        origin: witness.origin,
        assignment: witness.assignment.clone(),
        assignment_sha256,
        terms,
        atoms,
        true_term: witness.true_term,
        false_term: witness.false_term,
    })
}

fn build_backend_cnf(witness: &ProductionSatWitness) -> Result<Option<EvidenceBackendCnf>, String> {
    let Some(assignment) = witness.assignment.as_ref() else {
        if !witness.variables.is_empty()
            || !witness.backend_clauses.is_empty()
            || !witness.atoms.is_empty()
        {
            return Err("non-CNF production witness carries backend CNF metadata".to_owned());
        }
        return Ok(None);
    };
    let var_count = assignment.len();
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
    let clauses = witness.backend_clauses.clone();
    let clause_count = clauses.len();
    let clauses_sha256 = sha256_hex(&canonical_bytes(&clauses)?);
    Ok(Some(EvidenceBackendCnf {
        format: "dimacs-literal-arrays",
        var_count,
        clause_count,
        clauses_sha256,
        variables,
        clauses,
    }))
}

fn evidence_payload(
    source_path: &Path,
    source_bytes: &[u8],
    problem: &Problem,
    report: &SolveReport,
    root_cnf: RootCnfOptions,
) -> Result<(ProductionEvidence, EvidenceDisposition), String> {
    let run_nonce = required_sha256_environment(RUN_NONCE_ENV)?;
    let source = EvidenceSource {
        path: source_path.display().to_string(),
        sha256: sha256_hex(source_bytes),
        bytes: source_bytes.len(),
    };
    let (config, config_sha256) = runtime_config(root_cnf)?;
    let executable_sha256 = trusted_executable_sha256()?;
    let (build, build_sha256) = build_manifest()?;
    let solver = EvidenceSolver {
        package_version: env!("CARGO_PKG_VERSION"),
        revision: env!("EUF_VIPER_GIT_REVISION"),
        dirty: env!("EUF_VIPER_GIT_DIRTY") != "0",
        executable_sha256,
        backend: report.backend.to_owned(),
        config,
        config_sha256,
        build,
        build_sha256,
    };
    match &report.result {
        SolveResult::Sat => {
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
                    backend_cnf,
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

fn temporary_path(target: &Path) -> Result<PathBuf, String> {
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = target
        .file_name()
        .ok_or_else(|| format!("evidence path has no file name: {}", target.display()))?
        .to_string_lossy();
    for _ in 0..128 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{file_name}.tmp-{}-{sequence}",
            std::process::id()
        ));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "failed to allocate temporary evidence path beside {}",
        target.display()
    ))
}

fn atomic_write_immutable(target: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    if target.exists() {
        return Err(format!(
            "refusing to replace immutable evidence {}",
            target.display()
        ));
    }
    let temporary = temporary_path(target)?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| {
                format!(
                    "failed to create evidence temporary {}: {error}",
                    temporary.display()
                )
            })?;
        file.write_all(bytes).map_err(|error| {
            format!(
                "failed to write evidence temporary {}: {error}",
                temporary.display()
            )
        })?;
        file.sync_all().map_err(|error| {
            format!(
                "failed to sync evidence temporary {}: {error}",
                temporary.display()
            )
        })?;
        fs::hard_link(&temporary, target).map_err(|error| {
            format!(
                "failed to publish immutable evidence {}: {error}",
                target.display()
            )
        })?;
        let directory = OpenOptions::new()
            .read(true)
            .open(parent)
            .map_err(|error| {
                format!(
                    "failed to open evidence directory {}: {error}",
                    parent.display()
                )
            })?;
        directory.sync_all().map_err(|error| {
            format!(
                "failed to sync evidence directory {}: {error}",
                parent.display()
            )
        })?;
        Ok(())
    })();
    let _ = fs::remove_file(&temporary);
    result
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
    atomic_write_immutable(output, &canonical_bytes(&payload)?)?;
    Ok(disposition)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
