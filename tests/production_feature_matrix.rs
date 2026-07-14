use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_euf-viper")
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
