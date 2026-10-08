//! Repository policy checks: the forbidden-runtime scan of the dynamic links, linker map and
//! delivered files (PF-12), the identity of the Rust archive the Swift package links, and
//! AC-001's runtime clause on the launched release executable's `--selftest-startup` output.
//!
//! The scan is `grep -Eiq <seven names>` with its exit status read exactly: 0 (a match) and 2
//! (an error: absent, unreadable) fail, only 1 (clean) passes; an empty capture fails too.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::json;

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

// ---- native release artifacts (SLICE-008, PF-12/PF-17) -----------------------------------

/// A runtime is identified by an input or artifact name (`lib` prefix and extensions removed),
/// never by an arbitrary substring: `libunwind` is not Bun and a symbol named `node` is not Node.
fn forbidden_identity(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_lowercase();
    let name = name.strip_prefix("lib").unwrap_or(&name);
    FORBIDDEN
        .iter()
        .any(|forbidden| name.starts_with(forbidden))
}

fn sha256(path: &Path) -> Result<String, String> {
    let output = Command::new("/usr/bin/shasum")
        .args(["-a", "256"])
        .arg(path)
        .output()
        .map_err(|error| format!("shasum: {error}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    match text.split_whitespace().next() {
        Some(digest) if output.status.success() && digest.len() == 64 => Ok(digest.to_owned()),
        _ => Err(format!("no digest for {}", path.display())),
    }
}

/// What the native link and the delivered product may contain, derived independently of the
/// build output: from Package.swift, the Swift sources, `cargo tree` and the Rust sysroot.
struct Allowed {
    root: PathBuf,
    archive: PathBuf,
    archive_sha: String,
    crates: BTreeSet<String>,
    swift_objects: BTreeSet<String>,
    sdk: String,
    products: BTreeSet<String>,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct Linked {
    swift: usize,
    rust: usize,
    system: usize,
}

impl Allowed {
    fn derive(root: &Path) -> TestResult<Self> {
        let package = std::fs::read_to_string(root.join("Package.swift"))?;
        assert!(
            !package.contains("resources:"),
            "a resource bundle would be a delivered artifact this check does not classify"
        );
        let products: BTreeSet<String> = package
            .split(".executable(name: \"")
            .skip(1)
            .filter_map(|rest| rest.split('"').next().map(str::to_owned))
            .collect();
        // One object per Swift source of the executable target, plus the two library targets
        // SwiftPM links as single objects.
        let mut swift_objects: BTreeSet<String> =
            ["CQuotern.o", "QuoternCore.o"].map(String::from).into();
        for entry in std::fs::read_dir(root.join("Sources/Quotern"))? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if let Some(stem) = name.strip_suffix(".swift") {
                swift_objects.insert(format!("{stem}.o"));
            }
        }
        let tree = Command::new(env!("CARGO"))
            .args([
                "tree",
                "-p",
                "quotern-ffi",
                "-e",
                "normal",
                "--prefix",
                "none",
            ])
            .args(["--format", "{lib}", "--locked"])
            .current_dir(root)
            .output()?;
        assert!(tree.status.success(), "cargo tree");
        let mut crates: BTreeSet<String> = String::from_utf8(tree.stdout)?
            .lines()
            .filter_map(|line| line.split_whitespace().next().map(str::to_owned))
            .collect();
        let sysroot = Command::new("rustc")
            .args(["--print", "sysroot"])
            .output()?;
        let sysroot = PathBuf::from(String::from_utf8(sysroot.stdout)?.trim());
        for entry in std::fs::read_dir(sysroot.join("lib/rustlib/aarch64-apple-darwin/lib"))? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if let Some(rest) = name.strip_prefix("lib")
                && let Some(krate) = rest.split('-').next()
            {
                crates.insert(krate.to_owned());
            }
        }
        let sdk = Command::new("xcrun")
            .args(["--sdk", "macosx", "--show-sdk-path"])
            .output()?;
        let archive = root.join("target/aarch64-apple-darwin/release/libquotern_ffi.a");
        let recorded = std::fs::read_to_string(root.join("build/proof/ffi-archive.sha256"))?;
        Ok(Self {
            root: root.canonicalize()?,
            archive: archive.canonicalize()?,
            archive_sha: recorded
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned(),
            crates,
            swift_objects,
            sdk: String::from_utf8(sdk.stdout)?.trim().to_owned(),
            products,
        })
    }

    /// The linker map of `executable`: its output path, every object input classified and
    /// approved, the one Rust archive identical to the recorded PF-05 archive, and the map bound
    /// to this executable by a symbol address.
    fn check_map(&self, map: &str, executable: &Path) -> Result<Linked, String> {
        let mut lines = map.lines();
        let output = lines
            .next()
            .and_then(|line| line.strip_prefix("# Path: "))
            .ok_or("no map output path")?;
        let executable = executable
            .canonicalize()
            .map_err(|error| format!("executable: {error}"))?;
        if Path::new(output).canonicalize().ok().as_ref() != Some(&executable) {
            return Err(format!("map output {output} is not the executable"));
        }
        let objects: Vec<&str> = map
            .lines()
            .skip_while(|line| *line != "# Object files:")
            .skip(1)
            .take_while(|line| !line.starts_with('#'))
            .collect();
        let mut linked = Linked::default();
        for line in objects {
            let input = line
                .split_once("] ")
                .map(|(_, input)| input)
                .unwrap_or(line);
            if input == "linker synthesized" {
                continue;
            }
            let (file, member) = match input.split_once('(') {
                Some((file, member)) => (file, Some(member.trim_end_matches(')'))),
                None => (input, None),
            };
            if forbidden_identity(file) || member.is_some_and(forbidden_identity) {
                return Err(format!("forbidden runtime input {input}"));
            }
            match member {
                Some(member) => {
                    if Path::new(file).canonicalize().ok().as_ref() != Some(&self.archive) {
                        return Err(format!("unapproved archive input {file}"));
                    }
                    let krate = member.split('-').next().unwrap_or_default();
                    if !(self.crates.contains(krate) || member.ends_with("-sqlite3.o")) {
                        return Err(format!("unapproved archive member {member}"));
                    }
                    linked.rust += 1;
                }
                None if file.ends_with(".o") => {
                    let name = file.rsplit('/').next().unwrap_or(file);
                    if !file.starts_with(self.root.join(".build").to_str().unwrap_or("?"))
                        || !self.swift_objects.contains(name)
                    {
                        return Err(format!("unapproved object input {file}"));
                    }
                    linked.swift += 1;
                }
                None if file.ends_with(".tbd") && file.starts_with(&self.sdk) => linked.system += 1,
                None => return Err(format!("unclassified input {file}")),
            }
        }
        if linked.swift == 0 || linked.rust == 0 {
            return Err(format!("missing Swift or Rust inputs: {linked:?}"));
        }
        if sha256(&self.archive)? != self.archive_sha {
            return Err("the linked archive differs from build/proof/ffi-archive.sha256".into());
        }
        let mapped = map
            .lines()
            .find(|line| line.ends_with("] _quotern_abi_version"))
            .and_then(|line| line.split('\t').next())
            .and_then(|address| u64::from_str_radix(address.trim_start_matches("0x"), 16).ok())
            .ok_or("no _quotern_abi_version in the map")?;
        let nm = Command::new("nm")
            .arg(&executable)
            .output()
            .map_err(|error| format!("nm: {error}"))?;
        let actual = String::from_utf8_lossy(&nm.stdout)
            .lines()
            .find(|line| line.ends_with(" _quotern_abi_version"))
            .and_then(|line| u64::from_str_radix(line.split(' ').next()?, 16).ok())
            .ok_or("no _quotern_abi_version in the executable")?;
        if mapped != actual {
            return Err("the map does not describe this executable (stale map)".into());
        }
        Ok(linked)
    }

    /// The delivered product files beside the executable: build intermediates are classified and
    /// skipped; every other entry must be an approved product, readable and not a runtime.
    fn check_delivered(&self, product: &Path) -> Result<usize, String> {
        let product = product
            .canonicalize()
            .map_err(|error| format!("product: {error}"))?;
        let mut delivered = BTreeSet::new();
        let entries = std::fs::read_dir(&product).map_err(|error| error.to_string())?;
        for entry in entries {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry
                .path()
                .canonicalize()
                .map_err(|error| format!("{name}: {error}"))?;
            if forbidden_identity(&name) {
                return Err(format!("forbidden runtime artifact {name}"));
            }
            let intermediate = [".o", ".a", ".swiftmodule", ".dSYM"]
                .iter()
                .any(|suffix| name.ends_with(suffix));
            if intermediate {
                continue;
            }
            if name == "PackageFrameworks" {
                let empty = std::fs::read_dir(&path)
                    .map_err(|error| format!("{name}: {error}"))?
                    .next()
                    .is_none();
                if !empty {
                    return Err("PackageFrameworks holds a delivered framework".into());
                }
                continue;
            }
            let mut magic = [0_u8; 4];
            let mach_o = std::fs::File::open(&path)
                .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut magic))
                .map(|()| matches!(magic, [0xcf, 0xfa, 0xed, 0xfe] | [0xca, 0xfe, 0xba, 0xbe]))
                .map_err(|error| format!("unreadable delivered file {name}: {error}"))?;
            if !mach_o {
                return Err(format!("unclassified delivered file {name}"));
            }
            delivered.insert(name);
        }
        if delivered != self.products {
            return Err(format!(
                "delivered {delivered:?} differs from the products {:?}",
                self.products
            ));
        }
        Ok(delivered.len())
    }
}

/// AC-001's runtime clause on one `startup.json` written by `Quotern --selftest-startup`: the
/// popover hosted in an actual AppKit view, no listening TCP socket, no forbidden runtime image
/// loaded and startup within 5,000 ms. A missing key or a value of another type fails.
fn check_startup(startup: &str) -> Result<(), String> {
    let startup: serde_json::Value =
        serde_json::from_str(startup).map_err(|error| format!("startup.json: {error}"))?;
    if startup["appkit_hosting_view"].as_bool() != Some(true) {
        return Err(format!(
            "appkit_hosting_view {}",
            startup["appkit_hosting_view"]
        ));
    }
    if startup["tcp_listeners"].as_u64() != Some(0) {
        return Err(format!("tcp_listeners {}", startup["tcp_listeners"]));
    }
    if !startup["forbidden_images"]
        .as_array()
        .is_some_and(Vec::is_empty)
    {
        return Err(format!("forbidden_images {}", startup["forbidden_images"]));
    }
    if !startup["startup_ms"]
        .as_u64()
        .is_some_and(|startup_ms| startup_ms <= 5_000)
    {
        return Err(format!("startup_ms {}", startup["startup_ms"]));
    }
    Ok(())
}

/// Doctored copies of a passing `startup.json`, each violating one assertion of `check_startup`.
fn startup_mutants(control: &serde_json::Value) -> Vec<(&'static str, String)> {
    let with = |key: &str, value: Option<serde_json::Value>| {
        let mut mutant = control.clone();
        let map = mutant.as_object_mut().expect("startup.json is an object");
        match value {
            Some(value) => map.insert(key.to_owned(), value),
            None => map.remove(key),
        };
        mutant.to_string()
    };
    vec![
        (
            "no AppKit view",
            with("appkit_hosting_view", Some(json!(false))),
        ),
        ("AppKit view missing", with("appkit_hosting_view", None)),
        (
            "AppKit view as text",
            with("appkit_hosting_view", Some(json!("true"))),
        ),
        ("one TCP listener", with("tcp_listeners", Some(json!(1)))),
        ("listeners missing", with("tcp_listeners", None)),
        ("listeners negative", with("tcp_listeners", Some(json!(-1)))),
        (
            "Python loaded",
            with("forbidden_images", Some(json!(["Python"]))),
        ),
        (
            "WebKit loaded",
            with("forbidden_images", Some(json!(["WebKit"]))),
        ),
        ("images missing", with("forbidden_images", None)),
        (
            "images not a list",
            with("forbidden_images", Some(json!(""))),
        ),
        ("startup 5,001 ms", with("startup_ms", Some(json!(5_001)))),
        ("startup missing", with("startup_ms", None)),
        ("startup fractional", with("startup_ms", Some(json!(1.5)))),
        ("not JSON", String::from("{")),
        ("empty", String::new()),
    ]
}

/// The checker accepts the boundary control and rejects every doctored value; runs in the normal
/// suite so the native marker's runtime assertions are proven able to fail.
#[test]
fn startup_check_rejects_each_doctored_value() {
    let control = json!({"appkit_hosting_view": true, "tcp_listeners": 0,
        "forbidden_images": [], "startup_ms": 5_000});
    assert_eq!(check_startup(&control.to_string()), Ok(()), "control");
    let mutants = startup_mutants(&control);
    assert_eq!(mutants.len(), 15);
    for (label, mutant) in mutants {
        assert!(check_startup(&mutant).is_err(), "{label} must be rejected");
    }
}

/// Launches `executable --selftest-startup` with scratch data and output directories, an
/// environment holding only HOME (scratch) and a PATH with `lsof` and no Python, and a 10 s
/// deadline after which it is killed. The `startup.json` it wrote.
fn run_startup_probe(executable: &Path) -> Result<String, String> {
    let scratch = tempfile::tempdir().map_err(|error| error.to_string())?;
    let (bin, home, data, out) = (
        scratch.path().join("bin"),
        scratch.path().join("home"),
        scratch.path().join("data"),
        scratch.path().join("out"),
    );
    for directory in [&bin, &home, &out] {
        std::fs::create_dir(directory).map_err(|error| error.to_string())?;
    }
    std::os::unix::fs::symlink("/usr/sbin/lsof", bin.join("lsof"))
        .map_err(|error| error.to_string())?;
    for python in ["python", "python3"] {
        let found = Command::new("/usr/bin/which")
            .arg(python)
            .env_clear()
            .env("PATH", &bin)
            .status()
            .map_err(|error| error.to_string())?;
        if found.success() {
            return Err(format!("{python} is on the probe PATH"));
        }
    }
    let log = std::fs::File::create(scratch.path().join("stderr.txt"))
        .map_err(|error| error.to_string())?;
    let mut child = Command::new(executable)
        .arg("--selftest-startup")
        .arg("--data-dir")
        .arg(&data)
        .arg("--out")
        .arg(&out)
        .env_clear()
        .env("PATH", &bin)
        .env("HOME", &home)
        .stdout(std::process::Stdio::null())
        .stderr(log)
        .spawn()
        .map_err(|error| format!("launch {}: {error}", executable.display()))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("--selftest-startup exceeded the 10 s deadline".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let stderr = std::fs::read_to_string(scratch.path().join("stderr.txt")).unwrap_or_default();
    if !status.success() {
        return Err(format!("--selftest-startup {status}: {stderr}"));
    }
    std::fs::read_to_string(out.join("startup.json"))
        .map_err(|error| format!("startup.json: {error}; stderr: {stderr}"))
}

/// Runs after the native executable's actual relink (SLICE-008), never skipped for AC-001:
/// dynamic links (`otool -L`), the linker map's static inputs and the delivered product files,
/// with prohibited mutants of each and the allowed control; then the release executable's
/// startup self-test, whose `startup.json` must pass `check_startup` while doctored copies fail.
#[test]
#[ignore = "runs explicitly after the native relink: --ignored --exact forbidden_runtime_in_release_artifacts"]
fn forbidden_runtime_in_release_artifacts() -> TestResult {
    let root = root();
    let proof = root.join("build/proof");
    let otool = proof.join("otool-release.txt");
    assert_eq!(scan_capture(&otool)?, Scan::Clean, "dynamic links");
    let dynamic = std::fs::read_to_string(&otool)?;
    assert!(
        dynamic.contains("/System/Library/Frameworks/AppKit.framework"),
        "the native AppKit link"
    );

    let allowed = Allowed::derive(&root)?;
    assert_eq!(allowed.products, BTreeSet::from(["Quotern".to_owned()]));
    let executable = root.join(".build/release/Quotern");
    // The map lists symbol names whose bytes need not be UTF-8; only its structure is read.
    let map =
        String::from_utf8_lossy(&std::fs::read(proof.join("Quotern-link-map.txt"))?).into_owned();
    let linked = allowed.check_map(&map, &executable)?;
    let delivered = allowed.check_delivered(&root.join(".build/release"))?;

    // Mutants of the map, each rejected.
    let stale_archive = map.replace(
        "/target/aarch64-apple-darwin/release/libquotern_ffi.a(",
        "/target/release/libquotern_ffi.a(",
    );
    let first_member = map
        .lines()
        .find(|line| line.contains("libquotern_ffi.a("))
        .ok_or("a Rust input")?;
    let with_input =
        |input: &str| map.replacen(first_member, &format!("{first_member}\n[999] {input}"), 1);
    let other_output = map.replacen(
        &format!(
            "# Path: {}",
            map.lines()
                .next()
                .unwrap_or_default()
                .trim_start_matches("# Path: ")
        ),
        &format!("# Path: {}", root.join("Package.swift").display()),
        1,
    );
    let symbol = map
        .lines()
        .find(|line| line.ends_with("] _quotern_abi_version"))
        .ok_or("symbol")?;
    let stale_map = map.replace(symbol, &symbol.replacen("0x", "0x7", 1));
    for (label, mutant) in [
        ("stale target/release archive input", stale_archive),
        (
            "libChromium static input",
            with_input("/x/libchromium_glue.a(glue.o)"),
        ),
        (
            "libBun static input",
            with_input("/opt/bun/libbun.a(runtime.o)"),
        ),
        (
            "Python framework input",
            with_input("/Library/Frameworks/Python.framework/Python.tbd"),
        ),
        ("unclassified input", with_input("/tmp/extra.dylib")),
        ("map of another output", other_output),
        ("stale map", stale_map),
        ("empty map", String::new()),
    ] {
        assert!(
            allowed.check_map(&mutant, &executable).is_err(),
            "{label} must be rejected"
        );
    }
    let mut wrong_sha = Allowed::derive(&root)?;
    wrong_sha.archive_sha = "0".repeat(64);
    assert!(
        wrong_sha.check_map(&map, &executable).is_err(),
        "an archive differing from the recorded SHA-256"
    );
    let absent = proof.join("absent-link-map.txt");
    assert!(
        std::fs::read_to_string(&absent).is_err(),
        "an absent map is unreadable"
    );

    // Mutants of the delivered product, each rejected; the copied control passes.
    let directory = tempfile::tempdir()?;
    let make = |extra: &[(&str, bool)]| -> TestResult<PathBuf> {
        let dir = tempfile::tempdir_in(directory.path())?.keep();
        std::fs::copy(&executable, dir.join("Quotern"))?;
        std::fs::write(dir.join("QuoternCore.o"), b"intermediate")?;
        std::fs::create_dir(dir.join("PackageFrameworks"))?;
        for (name, mach_o) in extra {
            if *mach_o {
                std::fs::copy(&executable, dir.join(name))?;
            } else {
                std::fs::write(dir.join(name), b"#!/bin/sh\n")?;
            }
        }
        Ok(dir)
    };
    assert_eq!(allowed.check_delivered(&make(&[])?)?, 1, "allowed control");
    for (label, extra) in [
        ("Electron helper", ("Electron Helper", true)),
        ("Node binary", ("node", true)),
        ("Bun binary", ("bun", true)),
        ("Python interpreter", ("python3", false)),
        (
            "Chromium framework file",
            ("Chromium Embedded Framework", true),
        ),
        ("renamed extra executable", ("helper", true)),
        ("unclassified extra file", ("notes.txt", false)),
    ] {
        let dir = make(&[extra])?;
        assert!(
            allowed.check_delivered(&dir).is_err(),
            "{label} must be rejected"
        );
    }
    let unreadable = make(&[("Extra", true)])?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            unreadable.join("Extra"),
            std::fs::Permissions::from_mode(0o0),
        )?;
    }
    let refused = allowed.check_delivered(&unreadable);
    assert!(
        refused
            .as_ref()
            .is_err_and(|error| error.contains("unreadable")),
        "{refused:?}"
    );

    // The runtime clause: the release executable actually launched, not a capture.
    let startup = run_startup_probe(&executable)?;
    check_startup(&startup)?;
    let control: serde_json::Value = serde_json::from_str(&startup)?;
    for (label, mutant) in startup_mutants(&control) {
        assert!(check_startup(&mutant).is_err(), "{label} must be rejected");
    }
    println!("startup.json {startup}");

    let digest = sha256(&executable)?;
    println!(
        "executable sha256 {digest}; linked swift {}, rust {}, system {}",
        linked.swift, linked.rust, linked.system
    );
    println!(
        "AC001_NATIVE_POLICY_PASS: {delivered} delivered artifacts; {} linked inputs checked",
        linked.swift + linked.rust + linked.system
    );
    Ok(())
}
