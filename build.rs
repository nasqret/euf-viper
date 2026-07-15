use std::env;
use std::process::Command;

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-env-changed=RUSTC");

    let revision =
        command_output("git", &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_owned());
    let dirty = command_output("git", &["status", "--porcelain", "--untracked-files=all"])
        .is_none_or(|status| !status.is_empty());
    let rustc = env::var("RUSTC")
        .ok()
        .and_then(|path| command_output(&path, &["--version"]))
        .unwrap_or_else(|| "unknown".to_owned());

    println!("cargo:rustc-env=EUF_VIPER_BUILD_GIT_REVISION={revision}");
    println!(
        "cargo:rustc-env=EUF_VIPER_BUILD_GIT_DIRTY={}",
        if dirty { "true" } else { "false" }
    );
    println!("cargo:rustc-env=EUF_VIPER_BUILD_RUSTC={rustc}");
}
