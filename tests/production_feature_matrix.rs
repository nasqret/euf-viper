#[cfg(all(unix, feature = "production-evidence"))]
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
#[cfg(all(unix, feature = "production-evidence"))]
use std::time::{SystemTime, UNIX_EPOCH};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_euf-viper")
}

#[cfg(feature = "production-evidence")]
fn feature_report_binary() -> &'static str {
    env!("CARGO_BIN_EXE_euf-viper-build-features")
}

fn fixture(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn run(arguments: &[&str]) -> Output {
    Command::new(binary())
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .expect("euf-viper integration command should run")
}

#[cfg(all(unix, feature = "production-evidence"))]
fn temporary_directory(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock follows the Unix epoch")
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("euf-viper-{label}-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&path).expect("temporary test directory should be creatable");
    path
}

#[cfg(all(unix, feature = "production-evidence"))]
fn sha256(path: &Path) -> String {
    let bytes = std::fs::read(path).expect("bound artifact should be readable");
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn t1_parse_check_remains_available_in_every_feature_matrix() {
    let input = fixture("tests/fixtures/parser_parity/deterministic.smt2");
    let output = run(&["parse-check", input.to_str().expect("UTF-8 fixture path")]);
    assert!(
        output.status.success(),
        "parse-check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("parse-check emits UTF-8 JSON");
    assert!(stdout.contains("\"schema\":\"euf-viper.typed-parser-parity.v1\""));
    assert!(stdout.contains("\"status\":\"match\""));
    assert!(stdout.contains("\"tree_well_sorted\":true"));
    assert!(stdout.contains("\"stream_well_sorted\":true"));
    assert!(stdout.contains("\"fallback\":false"));
}

#[cfg(not(feature = "production-evidence"))]
#[test]
fn build_without_production_evidence_rejects_evidence_out() {
    let input = fixture("tests/fixtures/parser_parity/deterministic.smt2");
    let output_path = std::env::temp_dir().join(format!(
        "euf-viper-disabled-evidence-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&output_path);
    let output = run(&[
        "solve",
        input.to_str().expect("UTF-8 fixture path"),
        "--evidence-out",
        output_path.to_str().expect("UTF-8 output path"),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--evidence-out requires the production-evidence feature")
    );
    assert!(!output_path.exists());
}

#[test]
fn ordinary_solve_does_not_create_or_require_evidence() {
    let input = fixture("tests/fixtures/parser_parity/deterministic.smt2");
    let output = run(&["solve", input.to_str().expect("UTF-8 fixture path")]);
    assert!(
        output.status.success(),
        "ordinary solve failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(matches!(output.stdout.as_slice(), b"sat\n" | b"unsat\n"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("production-evidence"));
}

#[test]
fn ordinary_solve_preserves_legacy_unknown_and_extra_argument_compatibility() {
    let input = fixture("tests/fixtures/parser_parity/deterministic.smt2");
    let ignored = fixture("tests/fixtures/does-not-exist.smt2");
    let output = run(&[
        "solve",
        "--legacy-option",
        input.to_str().expect("UTF-8 fixture path"),
        ignored.to_str().expect("UTF-8 ignored path"),
        "--another-legacy-option",
    ]);
    assert!(
        output.status.success(),
        "legacy-compatible solve failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(matches!(output.stdout.as_slice(), b"sat\n" | b"unsat\n"));
}

#[cfg(feature = "production-evidence")]
#[test]
fn evidence_mode_fails_closed_for_an_ordinary_unsealed_cargo_build() {
    let input = fixture("tests/fixtures/basic_sat.smt2");
    let output_path = std::env::temp_dir().join(format!(
        "euf-viper-unsealed-evidence-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&output_path);
    let output = run(&[
        "solve",
        input.to_str().expect("UTF-8 fixture path"),
        "--evidence-out",
        output_path.to_str().expect("UTF-8 output path"),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("EUF_VIPER_SEALED_BUILD_RECEIPT"));
    assert!(!output_path.exists());
}

#[cfg(all(unix, feature = "production-evidence"))]
#[test]
fn recorder_checks_the_real_compiled_viper_feature_contract() {
    use std::os::unix::fs::PermissionsExt;

    let root = temporary_directory("real-recorder");
    let comparator = root.join("comparator");
    std::fs::write(
        &comparator,
        "#!/bin/sh\ncase \"$*\" in *version*) echo '4.16.0 1.3.4 2.7.0 2.9.2' ;; *) echo sat ;; esac\n",
    )
    .expect("fake comparator should be writable");
    let mut permissions = comparator
        .metadata()
        .expect("fake comparator metadata should exist")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&comparator, permissions)
        .expect("fake comparator should be executable");
    let output_path = root.join("solver-config.json");
    let receipt_path = root.join("sealed-build-receipt.json");
    let binary_path = Path::new(binary());
    let feature_path = Path::new(feature_report_binary());
    for path in [binary_path, feature_path] {
        let mut permissions = path
            .metadata()
            .expect("sealed artifact metadata should exist")
            .permissions();
        permissions.set_mode(0o500);
        std::fs::set_permissions(path, permissions)
            .expect("sealed artifact mode should be enforceable");
    }
    let feature_output = Command::new(feature_report_binary())
        .output()
        .expect("feature report should run");
    assert!(feature_output.status.success());
    let features = String::from_utf8(feature_output.stdout)
        .expect("feature report should be UTF-8")
        .trim()
        .split(',')
        .filter(|feature| !feature.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut receipt = serde_json::json!({
        "artifacts": {
            "euf-viper": {
                "bytes": binary_path.metadata().expect("binary metadata").len(),
                "mode": "0500",
                "sha256": sha256(binary_path),
            },
            "euf-viper-build-features": {
                "bytes": feature_path.metadata().expect("feature metadata").len(),
                "mode": "0500",
                "sha256": sha256(feature_path),
            },
        },
        "build": {
            "execution_closure_sha256": "2".repeat(64),
            "features": features,
            "profile": "release",
            "target": "x86_64-unknown-linux-gnu",
            "toolchain": {"cargo": "test", "rustc": "test"},
        },
        "schema": "euf-viper.sealed-build-receipt.v3",
        "sealed_build_manifest_sha256": "3".repeat(64),
        "source": {
            "dirty": false,
            "revision": "4".repeat(40),
            "snapshot_manifest_sha256": "1".repeat(64),
            "tree": "5".repeat(40),
        },
        "status": "accepted",
    });
    let attestation = serde_json::json!({
        "artifacts": receipt["artifacts"].clone(),
        "attestor_sha256": "8".repeat(64),
        "build_inputs": {
            "archive_sha256": "9".repeat(64),
            "cargo_sha256": "a".repeat(64),
            "file_count": 2,
            "index_sha256": "b".repeat(64),
            "object_count": 2,
            "rustc_sha256": "c".repeat(64),
        },
        "build_manifest_sha256": receipt["sealed_build_manifest_sha256"].clone(),
        "closure_sha256": receipt["build"]["execution_closure_sha256"].clone(),
        "features": receipt["build"]["features"].clone(),
        "schema": "euf-viper.sealed-build-attestation.v1",
        "source": {
            "bundle_sha256": "d".repeat(64),
            "file_count": 1,
            "manifest_sha256": receipt["source"]["snapshot_manifest_sha256"].clone(),
            "revision": receipt["source"]["revision"].clone(),
            "tree": receipt["source"]["tree"].clone(),
        },
        "status": "accepted",
        "toolchain": receipt["build"]["toolchain"].clone(),
        "traces": {
            "canonical_sha256": "e".repeat(64),
            "discovery_raw_sha256": "f".repeat(64),
            "network": "denied-and-namespaced",
            "production_raw_sha256": "0".repeat(64),
            "randomness_events": 1,
            "time_events": 1,
        },
    });
    receipt["independent_attestation"] = attestation.clone();
    let mut receipt_bytes = serde_json::to_vec(&receipt).expect("receipt serialization");
    receipt_bytes.push(b'\n');
    std::fs::write(&receipt_path, receipt_bytes).expect("receipt should be writable");
    std::fs::set_permissions(&receipt_path, std::fs::Permissions::from_mode(0o400))
        .expect("receipt mode should be immutable");
    let mut attestation_bytes =
        serde_json::to_vec(&attestation).expect("attestation serialization");
    attestation_bytes.push(b'\n');
    std::fs::write(
        root.join("sealed-build-attestation.json"),
        attestation_bytes,
    )
    .expect("attestation should be writable");
    std::fs::set_permissions(
        root.join("sealed-build-attestation.json"),
        std::fs::Permissions::from_mode(0o400),
    )
    .expect("attestation mode should be immutable");
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
    let completed = Command::new("python3")
        .arg(repository.join("scripts/bench/record_solver_config.py"))
        .args(["--campaign"])
        .arg(repository.join("campaigns/best-overall-qf-uf-2026-07.json"))
        .args(["--viper", binary(), "--viper-version", "real-test-build"])
        .arg("--viper-feature-report")
        .arg(feature_report_binary())
        .arg("--viper-sealed-build-receipt")
        .arg(&receipt_path)
        .arg("--z3")
        .arg(&comparator)
        .arg("--cvc5")
        .arg(&comparator)
        .arg("--yices2")
        .arg(&comparator)
        .arg("--opensmt")
        .arg(&comparator)
        .arg("--out")
        .arg(&output_path)
        .current_dir(repository)
        .output()
        .expect("real-binary recorder command should run");

    assert!(
        completed.status.success(),
        "recorder rejected a production-evidence binary: {}",
        String::from_utf8_lossy(&completed.stderr)
    );
    let config = std::fs::read_to_string(&output_path)
        .expect("successful recorder should publish a configuration");
    assert!(config.contains("euf-viper.production-evidence.v4"));
    assert!(config.contains(binary()));
    std::fs::remove_dir_all(root).expect("temporary recorder directory should be removable");
}
