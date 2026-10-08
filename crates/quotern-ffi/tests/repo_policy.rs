//! Repository policy checks: the forbidden-runtime scan of the dynamic links, linker map and
//! delivered files (PF-12), and the identity of the Rust archive the Swift package links.
//!
//! The scan is `grep -Eiq <seven names>` with its exit status read exactly: 0 (a match) and 2
//! (an error: absent, unreadable) fail, only 1 (clean) passes; an empty capture fails too.

use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const FORBIDDEN: [&str; 7] = [
    "webkit",
    "javascriptcore",
    "electron",
    "chromium",
    "node",
    "bun",
    "python",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[derive(Debug, Eq, PartialEq)]
enum Scan {
    Clean,
    Forbidden,
    /// Absent, unreadable or empty: never a pass.
    Unusable(String),
}

/// PF-12's check on one capture: a nonempty readable file, no forbidden name in any case.
fn scan_capture(path: &Path) -> TestResult<Scan> {
    match std::fs::metadata(path) {
        Err(error) => return Ok(Scan::Unusable(format!("absent: {error}"))),
        Ok(metadata) if metadata.len() == 0 => return Ok(Scan::Unusable("empty".into())),
        Ok(_) => {}
    }
    let mut command = Command::new("grep");
    command.arg("-Eiq");
    for name in FORBIDDEN {
        command.args(["-e", name]);
    }
    let status = command.arg(path).status()?;
    Ok(match status.code() {
        Some(0) => Scan::Forbidden,
        Some(1) => Scan::Clean,
        other => Scan::Unusable(format!("grep status {other:?}")),
    })
}

fn capture(directory: &Path, name: &str, body: &str) -> TestResult<PathBuf> {
    let path = directory.join(name);
    std::fs::write(&path, body)?;
    Ok(path)
}

const ALLOWED_OTOOL: &str = ".build/release/Quotern:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n\t/usr/lib/libc++.1.dylib (compatibility version 1.0.0)\n\t/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit\n";

#[test]
fn forbidden_link_each_runtime() -> TestResult {
    let directory = tempfile::tempdir()?;
    let allowed = capture(directory.path(), "allowed.txt", ALLOWED_OTOOL)?;
    assert_eq!(
        scan_capture(&allowed)?,
        Scan::Clean,
        "the allowed native control passes"
    );

    // Seven names, each lower, upper and mixed case, each rejected (grep status 0).
    let mut rejected = 0;
    for name in FORBIDDEN {
        let mixed: String = name
            .chars()
            .enumerate()
            .map(|(index, c)| {
                if index % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        for variant in [name.to_owned(), name.to_uppercase(), mixed] {
            let path = capture(
                directory.path(),
                &format!("{name}-{variant}.txt"),
                &format!(
                    "{ALLOWED_OTOOL}\t/Library/Frameworks/lib{variant}.dylib (compatibility version 1.0.0)\n"
                ),
            )?;
            assert_eq!(scan_capture(&path)?, Scan::Forbidden, "{variant}");
            rejected += 1;
        }
    }
    assert_eq!(rejected, 21);

    // An absent, an unreadable and an empty capture never pass (grep status 2 or no content).
    let absent = directory.path().join("absent.txt");
    assert!(matches!(scan_capture(&absent)?, Scan::Unusable(_)));
    let empty = capture(directory.path(), "empty.txt", "")?;
    assert_eq!(scan_capture(&empty)?, Scan::Unusable("empty".into()));
    let unreadable = capture(directory.path(), "unreadable.txt", ALLOWED_OTOOL)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o0))?;
    }
    let euid_zero = {
        unsafe extern "C" {
            fn geteuid() -> u32;
        }
        unsafe { geteuid() == 0 }
    };
    assert!(!euid_zero, "the unreadable capture needs euid != 0");
    assert!(
        matches!(scan_capture(&unreadable)?, Scan::Unusable(_)),
        "{:?}",
        scan_capture(&unreadable)?
    );
    Ok(())
}

/// The path the Swift package links, checked against the Cargo target triple.
fn archive_matches(package_swift: &str, cargo_config: &str) -> bool {
    let triple = cargo_config
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("target")
                .and_then(|rest| rest.trim().strip_prefix('='))
        })
        .map(|value| value.trim().trim_matches('"').to_owned());
    let Some(triple) = triple else { return false };
    let wanted = format!("target/{triple}/release/libquotern_ffi.a");
    let linked: Vec<&str> = package_swift
        .lines()
        .filter(|line| line.contains("libquotern_ffi.a"))
        .collect();
    !linked.is_empty()
        && linked.iter().all(|line| line.contains(&wanted))
        && !package_swift.contains("target/release/")
}

#[test]
fn release_archive_path_matches_cargo_target() -> TestResult {
    let package = std::fs::read_to_string(root().join("Package.swift"))?;
    let config = std::fs::read_to_string(root().join(".cargo/config.toml"))?;
    assert!(
        config.contains("aarch64-apple-darwin"),
        "the configured build target"
    );
    assert!(
        archive_matches(&package, &config),
        "canonical control passes"
    );

    // Mutants: target/release, another triple, no archive line, no configured target.
    let bare = package.replace("target/aarch64-apple-darwin/release/", "target/release/");
    assert!(!archive_matches(&bare, &config), "target/release rejected");
    let other = package.replace("aarch64-apple-darwin", "x86_64-apple-darwin");
    assert!(!archive_matches(&other, &config), "another triple rejected");
    let other_config = config.replace("aarch64-apple-darwin", "x86_64-apple-darwin");
    assert!(
        !archive_matches(&package, &other_config),
        "a changed Cargo target rejected"
    );
    assert!(!archive_matches("", &config), "no archive line rejected");
    assert!(
        !archive_matches(&package, "[build]\n"),
        "no configured target rejected"
    );
    Ok(())
}

/// Runs after the native executable's actual relink (SLICE-008), never skipped for AC-001:
/// dynamic links (`otool -L`), linker-map static inputs and the delivered product files.
#[test]
#[ignore = "runs explicitly after the native relink: --ignored --exact forbidden_runtime_in_release_artifacts"]
fn forbidden_runtime_in_release_artifacts() -> TestResult {
    let proof = root().join("build/proof");
    let otool = proof.join("otool-release.txt");
    let link_map = proof.join("Quotern-link-map.txt");
    assert_eq!(scan_capture(&otool)?, Scan::Clean, "dynamic links");
    assert_eq!(
        scan_capture(&link_map)?,
        Scan::Clean,
        "linker-map static inputs"
    );
    let inputs = std::fs::read_to_string(&link_map)?
        .lines()
        .filter(|line| line.starts_with('['))
        .count();
    assert!(inputs > 0, "positive linked-input count");

    // The delivered product files: every regular file name beside the executable.
    let product = root().join(".build/release");
    let delivered: Vec<String> = std::fs::read_dir(&product)?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.file_name().to_string_lossy().to_lowercase())
        .collect();
    assert!(!delivered.is_empty(), "positive delivered-file count");
    assert!(
        delivered
            .iter()
            .all(|name| FORBIDDEN.iter().all(|forbidden| !name.contains(forbidden))),
        "delivered files: {delivered:?}"
    );

    // Prohibited mutants of each kind reject; the allowed native control passes.
    let directory = tempfile::tempdir()?;
    for (kind, body) in [
        (
            "dynamic",
            format!("{ALLOWED_OTOOL}\t/usr/lib/libnode.dylib\n"),
        ),
        ("static", "[  3] /x/libwebkit_glue.a\n".to_owned()),
    ] {
        let mutant = capture(directory.path(), kind, &body)?;
        assert_eq!(scan_capture(&mutant)?, Scan::Forbidden, "{kind} mutant");
    }
    assert!(
        ["electron-helper", "python3"]
            .iter()
            .all(|name| FORBIDDEN.iter().any(|forbidden| name.contains(forbidden))),
        "delivered mutants"
    );
    let control = capture(directory.path(), "control", ALLOWED_OTOOL)?;
    assert_eq!(scan_capture(&control)?, Scan::Clean);
    println!(
        "linked inputs {inputs}, delivered files {}",
        delivered.len()
    );
    Ok(())
}
