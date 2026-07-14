use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn git_output(arguments: &[&str]) -> Option<String> {
    let output = Command::new("git").args(arguments).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn command_output(program: &str, arguments: &[&str]) -> String {
    Command::new(program)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .replace('\n', "\\n")
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

fn collect_files(path: &Path, files: &mut Vec<PathBuf>) {
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("cannot inspect build input {}: {error}", path.display()));
    if metadata.file_type().is_symlink() {
        panic!("build input cannot be a symlink: {}", path.display());
    }
    if metadata.is_file() {
        files.push(path.to_owned());
        return;
    }
    let mut entries = fs::read_dir(path)
        .unwrap_or_else(|error| panic!("cannot read build input {}: {error}", path.display()))
        .map(|entry| entry.expect("cannot read build input entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for entry in entries {
        collect_files(&entry, files);
    }
}

fn source_manifest_sha256(inputs: &[&str]) -> String {
    let mut files = Vec::new();
    for input in inputs {
        collect_files(Path::new(input), &mut files);
    }
    files.sort();
    let mut digest = Sha256::new();
    for path in files {
        let path_bytes = path.to_string_lossy();
        let content = fs::read(&path)
            .unwrap_or_else(|error| panic!("cannot read build input {}: {error}", path.display()));
        digest.update((path_bytes.len() as u64).to_be_bytes());
        digest.update(path_bytes.as_bytes());
        digest.update((content.len() as u64).to_be_bytes());
        digest.update(&content);
    }
    format!("{:x}", digest.finalize())
}

fn main() {
    let solver_inputs = [
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "src",
        "vendor/kissat",
    ];
    for path in solver_inputs {
        println!("cargo:rerun-if-changed={path}");
    }
    for name in ["HEAD", "index"] {
        if let Some(path) = git_output(&["rev-parse", "--path-format=absolute", "--git-path", name])
        {
            println!("cargo:rerun-if-changed={path}");
        }
    }

    let revision = git_output(&["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_owned());
    let mut status_arguments = vec!["status", "--porcelain=v1", "--untracked-files=all", "--"];
    status_arguments.extend(solver_inputs);
    let dirty = git_output(&status_arguments)
        .map(|status| !status.is_empty())
        .unwrap_or(true);
    println!("cargo:rustc-env=EUF_VIPER_GIT_REVISION={revision}");
    println!(
        "cargo:rustc-env=EUF_VIPER_GIT_DIRTY={}",
        if dirty { "1" } else { "0" }
    );

    let mut features = env::vars()
        .filter_map(|(name, _)| {
            name.strip_prefix("CARGO_FEATURE_")
                .map(|feature| feature.to_ascii_lowercase().replace('_', "-"))
        })
        .collect::<Vec<_>>();
    features.sort();
    println!(
        "cargo:rustc-env=EUF_VIPER_BUILD_FEATURES={}",
        features.join(",")
    );
    println!(
        "cargo:rustc-env=EUF_VIPER_BUILD_TARGET={}",
        env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned())
    );
    println!(
        "cargo:rustc-env=EUF_VIPER_BUILD_PROFILE={}",
        env::var("PROFILE").unwrap_or_else(|_| "unknown".to_owned())
    );
    println!(
        "cargo:rustc-env=EUF_VIPER_BUILD_RUSTC={}",
        command_output(
            &env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned()),
            &["-vV"]
        )
    );
    println!(
        "cargo:rustc-env=EUF_VIPER_BUILD_CARGO={}",
        command_output(
            &env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()),
            &["-V"]
        )
    );
    println!(
        "cargo:rustc-env=EUF_VIPER_BUILD_SOURCE_MANIFEST_SHA256={}",
        source_manifest_sha256(&solver_inputs)
    );
}
