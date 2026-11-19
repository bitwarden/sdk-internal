#![allow(missing_docs)]

use std::{env, process::Command};

fn main() {
    // Without these, Cargo only reruns this script when a file in the package changes, so a cached
    // build would keep embedding an old version.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SDK_VERSION");

    // Use the SDK_VERSION environment variable if it is set (e.g. by CI) or get it from Git
    let sdk_version = env::var("SDK_VERSION")
        .or_else(|_| version_from_git_info())
        .unwrap_or("unknown".to_string());

    println!("cargo:rustc-env=SDK_VERSION={sdk_version}");
    println!("cargo:rustc-env=CARGO_PKG_VERSION={sdk_version}");
}

fn run(args: &[&str]) -> Result<String, std::io::Error> {
    use std::io::Error;
    let out = Command::new(args[0]).args(&args[1..]).output()?;
    if !out.status.success() {
        return Err(Error::other("Command not successful"));
    }
    Ok(String::from_utf8(out.stdout)
        .map_err(Error::other)?
        .trim()
        .to_string())
}

/// This method reads info from Git, namely tags, branch, and revision
/// To access these values, use:
///    - `env!("GIT_EXACT_TAG")`
///    - `env!("GIT_BRANCH")`
///    - `env!("GIT_REV")`
fn version_from_git_info() -> Result<String, std::io::Error> {
    rerun_if_git_changed();

    // The exact tag for the current commit, can be empty when
    // the current commit doesn't have an associated tag
    let exact_tag = run(&["git", "describe", "--abbrev=0", "--tags", "--exact-match"]).ok();
    if let Some(ref exact) = exact_tag {
        println!("cargo:rustc-env=GIT_EXACT_TAG={exact}");
    }

    // The current branch name
    let branch = run(&["git", "rev-parse", "--abbrev-ref", "HEAD"])?;
    println!("cargo:rustc-env=GIT_BRANCH={branch}");

    // The current git commit hash
    let rev = run(&["git", "rev-parse", "HEAD"])?;
    let rev_short = rev.get(..8).unwrap_or_default();
    println!("cargo:rustc-env=GIT_REV={rev_short}");

    // Combined version
    if let Some(exact) = exact_tag {
        Ok(exact)
    } else {
        Ok(format!("{branch} ({rev_short})"))
    }
}

/// Reruns this script when the checked out commit, the current branch, or the tags change.
fn rerun_if_git_changed() {
    let mut paths = vec![
        "HEAD".to_string(),
        "packed-refs".to_string(),
        "refs/tags".to_string(),
    ];
    if let Ok(branch_ref) = run(&["git", "symbolic-ref", "-q", "HEAD"]) {
        paths.push(branch_ref);
    }
    for path in paths {
        // Cargo reruns the script on every build if a listed path doesn't exist
        if let Ok(path) = run(&["git", "rev-parse", "--git-path", &path])
            && std::path::Path::new(&path).exists()
        {
            println!("cargo:rerun-if-changed={path}");
        }
    }
}
