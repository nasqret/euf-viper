use std::process::Command;

fn git_output(arguments: &[&str]) -> Option<String> {
    let output = Command::new("git").args(arguments).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
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
}
