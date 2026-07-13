use super::{BoolAtomKey, Problem, ProductionSatWitness, RootCnfOptions, SolveReport, SolveResult};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const SCHEMA: &str = "euf-viper.production-evidence.v1";

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
    backend: String,
    config: BTreeMap<String, String>,
    config_sha256: String,
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
    status: &'static str,
    backend_status: &'static str,
    source: EvidenceSource,
    solver: EvidenceSolver,
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

fn runtime_config(root_cnf: RootCnfOptions) -> Result<(BTreeMap<String, String>, String), String> {
    let mut config = env::vars()
        .filter(|(key, _)| key.starts_with("EUF_VIPER_"))
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

fn evidence_payload(
    source_path: &Path,
    source_bytes: &[u8],
    problem: &Problem,
    report: &SolveReport,
    root_cnf: RootCnfOptions,
) -> Result<(ProductionEvidence, EvidenceDisposition), String> {
    let source = EvidenceSource {
        path: source_path.display().to_string(),
        sha256: sha256_hex(source_bytes),
        bytes: source_bytes.len(),
    };
    let (config, config_sha256) = runtime_config(root_cnf)?;
    let solver = EvidenceSolver {
        package_version: env!("CARGO_PKG_VERSION"),
        revision: env!("EUF_VIPER_GIT_REVISION"),
        dirty: env!("EUF_VIPER_GIT_DIRTY") != "0",
        backend: report.backend.to_owned(),
        config,
        config_sha256,
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
            Ok((
                ProductionEvidence {
                    schema: SCHEMA,
                    status: "sat",
                    backend_status: "sat",
                    source,
                    solver,
                    model: Some(build_model(problem, witness)?),
                    limitations: Vec::new(),
                },
                EvidenceDisposition::DecisiveSat,
            ))
        }
        SolveResult::Unsat => Ok((
            ProductionEvidence {
                schema: SCHEMA,
                status: "unsupported",
                backend_status: "unsat",
                source,
                solver,
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
                status: "unsupported",
                backend_status: "unsupported",
                source,
                solver,
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
