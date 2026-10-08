//! Bridge v1 contract, provider side: the canonical header against the ACTUAL Rust exports
//! (compiled by clang), width/arity/constness mutants, and the shared response goldens against
//! live responses of the real ABI.

use std::collections::BTreeSet;
use std::ffi::{CStr, CString, c_char};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use quotern_ffi::*;
use rusqlite::Connection;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn golden_path(name: &str) -> PathBuf {
    root().join("Contracts/bridge-v1").join(name)
}

fn golden(name: &str) -> TestResult<Value> {
    Ok(serde_json::from_slice(&std::fs::read(golden_path(name))?)?)
}

/// Goldens a live comparison or the production codec consumed in this process.
static CONSUMED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// `golden`, recorded as consumed.
fn consumed_golden(name: &str) -> TestResult<Value> {
    CONSUMED.lock().unwrap().insert(name.to_owned());
    golden(name)
}

// ---- signatures derived from the actual Rust definitions ---------------------------------

trait CType {
    fn c() -> &'static str;
}
impl CType for u32 {
    fn c() -> &'static str {
        "uint32_t"
    }
}
impl CType for () {
    fn c() -> &'static str {
        "void"
    }
}
impl CType for *mut c_char {
    fn c() -> &'static str {
        "char *"
    }
}
impl CType for *const c_char {
    fn c() -> &'static str {
        "const char *"
    }
}
impl CType for *mut QuoternEngine {
    fn c() -> &'static str {
        "QuoternEngine *"
    }
}
impl CType for *mut *mut QuoternEngine {
    fn c() -> &'static str {
        "QuoternEngine **"
    }
}
impl CType for *const QuoternCancel {
    fn c() -> &'static str {
        "const QuoternCancel *"
    }
}
impl CType for *mut QuoternCancel {
    fn c() -> &'static str {
        "QuoternCancel *"
    }
}

trait Signature {
    fn signature(&self) -> String;
}
macro_rules! signature_impls {
    ($($abi:ident: ($($arg:ident),*);)*) => {$(
        impl<R: CType, $($arg: CType),*> Signature for $abi extern "C" fn($($arg),*) -> R {
            fn signature(&self) -> String {
                let args: Vec<&str> = vec![$($arg::c()),*];
                let args = if args.is_empty() { "void".to_owned() } else { args.join(", ") };
                format!("{} (*)({})", R::c(), args)
            }
        }
    )*};
}
signature_impls! {
    unsafe: ();
    unsafe: (A);
    unsafe: (A, B);
    unsafe: (A, B, C, D);
}
macro_rules! safe_signature {
    ($(($($arg:ident),*))*) => {$(
        impl<R: CType, $($arg: CType),*> Signature for extern "C" fn($($arg),*) -> R {
            fn signature(&self) -> String {
                let args: Vec<&str> = vec![$($arg::c()),*];
                let args = if args.is_empty() { "void".to_owned() } else { args.join(", ") };
                format!("{} (*)({})", R::c(), args)
            }
        }
    )*};
}
safe_signature! { () }

fn rust_signatures() -> Vec<(&'static str, String)> {
    let abi_version: extern "C" fn() -> u32 = quotern_abi_version;
    let open: unsafe extern "C" fn(*const c_char, *mut *mut QuoternEngine) -> *mut c_char =
        quotern_engine_open;
    let close: unsafe extern "C" fn(*mut QuoternEngine) = quotern_engine_close;
    let call: unsafe extern "C" fn(
        *mut QuoternEngine,
        *const c_char,
        *const c_char,
        *const QuoternCancel,
    ) -> *mut c_char = quotern_call;
    let cancel_new: extern "C" fn() -> *mut QuoternCancel = quotern_cancel_new;
    let trigger: unsafe extern "C" fn(*const QuoternCancel) = quotern_cancel_trigger;
    let cancel_free: unsafe extern "C" fn(*mut QuoternCancel) = quotern_cancel_free;
    let string_free: unsafe extern "C" fn(*mut c_char) = quotern_string_free;
    vec![
        ("quotern_abi_version", abi_version.signature()),
        ("quotern_engine_open", open.signature()),
        ("quotern_engine_close", close.signature()),
        ("quotern_call", call.signature()),
        ("quotern_cancel_new", cancel_new.signature()),
        ("quotern_cancel_trigger", trigger.signature()),
        ("quotern_cancel_free", cancel_free.signature()),
        ("quotern_string_free", string_free.signature()),
    ]
}

fn probe(include_dir: &Path, signatures: &str, scratch: &Path) -> TestResult<bool> {
    let generated = scratch.join("rust_signatures.h");
    std::fs::write(&generated, signatures)?;
    let status = Command::new("clang")
        .args(["-fsyntax-only", "-std=c11", "-Werror", "-I"])
        .arg(include_dir)
        .arg(format!(
            "-DQUOTERN_RUST_SIGNATURES=\"{}\"",
            generated.display()
        ))
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/abi_signature.c"))
        .output()?;
    Ok(status.status.success())
}

fn generated_include(signatures: &[(&str, String)]) -> String {
    signatures
        .iter()
        .map(|(name, signature)| format!("#define SIG_{name} {signature}\n"))
        .collect()
}

#[test]
fn header_signatures_match_actual_rust_exports() -> TestResult {
    let scratch = tempfile::tempdir()?;
    let include = root().join("Sources/CQuotern/include");
    let signatures = rust_signatures();
    assert_eq!(signatures.len(), 8);
    let canonical = generated_include(&signatures);
    assert!(
        probe(&include, &canonical, scratch.path())?,
        "canonical control must compile"
    );

    // Width, arity and constness mutants of the Rust-derived signature each fail.
    for (label, from, to) in [
        ("width", "uint32_t (*)(void)", "uint64_t (*)(void)"),
        ("arity", ", const QuoternCancel *)", ")"),
        (
            "constness",
            "const char *, const char *,",
            "char *, const char *,",
        ),
        (
            "return width",
            "void (*)(QuoternEngine *)",
            "int (*)(QuoternEngine *)",
        ),
    ] {
        assert!(canonical.contains(from), "{label}: mutation applies");
        let mutant = canonical.replacen(from, to, 1);
        assert!(
            !probe(&include, &mutant, scratch.path())?,
            "{label} mutant must fail"
        );
    }
    // A mutated copy of the header itself fails against the actual signatures.
    let header = std::fs::read_to_string(include.join("quotern.h"))?;
    for (label, from, to) in [
        (
            "header width",
            "uint32_t quotern_abi_version(void)",
            "uint64_t quotern_abi_version(void)",
        ),
        ("header constness", "const char *method", "char *method"),
        (
            "header arity",
            "const QuoternCancel *cancel);\n\nQuoternCancel *quotern_cancel_new",
            "int extra);\n\nQuoternCancel *quotern_cancel_new",
        ),
    ] {
        assert!(header.contains(from), "{label}: mutation applies");
        let dir = scratch.path().join(label.replace(' ', "_"));
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("quotern.h"), header.replacen(from, to, 1))?;
        assert!(
            !probe(&dir, &canonical, scratch.path())?,
            "{label} mutant must fail"
        );
    }
    Ok(())
}

// ---- live responses ---------------------------------------------------------------------

fn text(pointer: *mut c_char) -> String {
    assert!(!pointer.is_null());
    let value = unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned();
    unsafe { quotern_string_free(pointer) };
    value
}

struct Live {
    engine: *mut QuoternEngine,
    directory: tempfile::TempDir,
}

impl Live {
    fn base(&self) -> PathBuf {
        self.directory.path().canonicalize().unwrap()
    }
    fn source(&self) -> PathBuf {
        self.base().join("source")
    }
    fn data(&self) -> PathBuf {
        self.base().join("data")
    }
    fn call(&self, method: &str, request: &str) -> Value {
        self.call_bytes(method, request.as_bytes())
    }
    fn call_bytes(&self, method: &str, request: &[u8]) -> Value {
        let (method, request) = (
            CString::new(method).unwrap(),
            CString::new(request).unwrap(),
        );
        let response = text(unsafe {
            quotern_call(
                self.engine,
                method.as_ptr(),
                request.as_ptr(),
                std::ptr::null(),
            )
        });
        serde_json::from_str(&response).unwrap()
    }
    /// Closes the handle, so no handle is live until `reopen`.
    fn close(&mut self) {
        unsafe { quotern_engine_close(self.engine) };
        self.engine = std::ptr::null_mut();
    }
    fn reopen(&mut self) -> TestResult {
        let config = json!({"data_dir": self.data(), "home": self.base().join("home")}).to_string();
        let (engine, response) = open_bytes(config.as_bytes());
        assert_eq!(response["ok"], json!(true), "{response}");
        self.engine = engine;
        Ok(())
    }
}

/// One open of raw config bytes: the handle (NULL on failure) and the response.
fn open_bytes(config: &[u8]) -> (*mut QuoternEngine, Value) {
    let config = CString::new(config).unwrap();
    let mut engine = std::ptr::null_mut();
    let response: Value = serde_json::from_str(&text(unsafe {
        quotern_engine_open(config.as_ptr(), &mut engine)
    }))
    .unwrap();
    assert_eq!(
        response["ok"] == json!(true),
        !engine.is_null(),
        "{response}"
    );
    (engine, response)
}

fn invalid(field: &str) -> Value {
    json!({"v": 1, "ok": false, "error": {
        "code": "invalid_request", "message": format!("invalid request: {field}"), "retryable": false
    }})
}

fn limit(bound: &str) -> Value {
    json!({"v": 1, "ok": false, "error": {
        "code": "limit_exceeded", "message": format!("limit exceeded: {bound}"), "retryable": false
    }})
}

/// `text` padded with trailing JSON whitespace to exactly `length` bytes.
fn padded(text: &str, length: usize) -> String {
    format!("{text}{}", " ".repeat(length - text.len()))
}

/// `text` with one byte inside its first object turned into invalid UTF-8.
fn invalid_utf8(text: &str) -> Vec<u8> {
    let mut bytes = text.as_bytes().to_vec();
    bytes.insert(1, 0xFF);
    bytes
}

/// History bytes that a refused request must leave as they are.
fn store_image(data: &Path) -> Vec<Option<Vec<u8>>> {
    ["history.sqlite", "history.sqlite-wal"]
        .iter()
        .map(|name| std::fs::read(data.join(name)).ok())
        .collect()
}

impl Drop for Live {
    fn drop(&mut self) {
        unsafe { quotern_engine_close(self.engine) };
    }
}

fn make_source(base: &Path, source_rows: &[Value]) -> TestResult {
    std::fs::create_dir(base.join("source"))?;
    std::fs::create_dir(base.join("home"))?;
    let connection = Connection::open(base.join("source/opencode.db"))?;
    let schema: String = include_str!("../../../Fixtures/harness/opencode/wal/schema.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with("PRAGMA"))
        .collect::<Vec<_>>()
        .join("\n");
    connection.execute_batch(&schema)?;
    for row in source_rows {
        connection.execute(
            "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                row["id"].as_str().unwrap(),
                row["session_id"].as_str().unwrap(),
                row["time_created"].as_i64().unwrap(),
                serde_json::to_vec(&row["data"])?
            ],
        )?;
    }
    drop(connection);
    Ok(())
}

fn open_live(source_rows: &[Value]) -> TestResult<(Live, Value)> {
    let directory = tempfile::tempdir()?;
    let base = directory.path().canonicalize()?;
    make_source(&base, source_rows)?;
    let config = CString::new(
        json!({"data_dir": base.join("data"), "home": base.join("home")}).to_string(),
    )?;
    let mut engine = std::ptr::null_mut();
    let response: Value = serde_json::from_str(&text(unsafe {
        quotern_engine_open(config.as_ptr(), &mut engine)
    }))?;
    assert!(!engine.is_null());
    Ok((Live { engine, directory }, response))
}

/// The shared `requests-first-use.json`, which Swift encodes, parses through the production
/// codec: every request re-serializes to itself, is accepted by the real exports and yields the
/// oracle. Mutants of the
/// SAME requests are refused exactly and leave the store unchanged; a whole config or request of
/// 65,536 B proceeds and one of 65,537 B is refused by its size bound.
#[test]
fn first_use_request_goldens_use_production_codec() -> TestResult {
    let directory = tempfile::tempdir()?;
    let base = directory.path().canonicalize()?;
    make_source(&base, &daily_rows())?;
    let requests = consumed_golden("requests-first-use.json")?;
    let methods: Vec<&str> = requests
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        {
            let mut sorted = methods.clone();
            sorted.sort_unstable();
            sorted
        },
        [
            "ingest",
            "list_sources",
            "open",
            "set_source_selection",
            "today_snapshot"
        ]
    );
    // Round trip: each SAME request parses and validates through the production codec and
    // re-serializes to the golden. Compared as JSON values: the golden file's whitespace is not
    // part of the contract and `Value` objects compare without key order.
    for method in &methods {
        let written = request_round_trip(method, &requests[*method].to_string())?;
        assert_eq!(
            serde_json::from_str::<Value>(&written)?,
            requests[*method],
            "{method} round trip"
        );
    }
    let substitute = |request: &Value| -> String {
        request
            .to_string()
            .replace("/quotern-golden/data", base.join("data").to_str().unwrap())
            .replace("/quotern-golden/home", base.join("home").to_str().unwrap())
            .replace(
                "/quotern-golden/opencode",
                base.join("source").to_str().unwrap(),
            )
    };
    // A copy of the SAME request with one edit.
    let edited = |request: &Value, edit: &dyn Fn(&mut serde_json::Map<String, Value>)| {
        let mut request: Value = serde_json::from_str(&substitute(request)).unwrap();
        edit(request.as_object_mut().unwrap());
        request.to_string()
    };
    let long_path = format!("/{}", "a".repeat(4_096));
    assert_eq!(long_path.len(), 4_097);

    // Open: refusals while no data dir exists, which they leave absent.
    let data = base.join("data");
    let config = substitute(&requests["open"]);
    let (engine, opened) = open_bytes(padded(&config, 65_536).as_bytes());
    assert_eq!(
        opened["ok"],
        json!(true),
        "65,536 B config proceeds: {opened}"
    );
    unsafe { quotern_engine_close(engine) };
    for (label, mutant, expected) in [
        (
            "65,537 B",
            padded(&config, 65_537).into_bytes(),
            limit("config_bytes"),
        ),
        (
            "unknown key",
            edited(&requests["open"], &|o| {
                o.insert("unexpected".into(), json!(true));
            })
            .into_bytes(),
            invalid("config"),
        ),
        (
            "4,097 B field",
            edited(&requests["open"], &|o| {
                o.insert("data_dir".into(), json!(long_path));
            })
            .into_bytes(),
            invalid("data_dir"),
        ),
        (
            "relative data_dir",
            edited(&requests["open"], &|o| {
                o.insert("data_dir".into(), json!("relative/data"));
            })
            .into_bytes(),
            invalid("data_dir"),
        ),
        ("invalid UTF-8", invalid_utf8(&config), invalid("config")),
    ] {
        let (engine, response) = open_bytes(&mutant);
        assert!(engine.is_null(), "open {label}: out is NULL");
        assert_eq!(response, expected, "open {label}");
    }
    assert!(!data.exists(), "refused opens leave the store unchanged");

    let (engine, opened) = open_bytes(config.as_bytes());
    assert_eq!(opened["ok"], json!(true), "{opened}");
    let live = Live { engine, directory };
    for method in [
        "set_source_selection",
        "list_sources",
        "ingest",
        "today_snapshot",
    ] {
        let response = live.call(method, &substitute(&requests[method]));
        assert_eq!(response["ok"], json!(true), "{method}: {response}");
    }
    let snapshot = live.call("today_snapshot", &substitute(&requests["today_snapshot"]));
    assert_eq!(
        snapshot["data"]["source_reported"][0]["input"]["value"],
        json!(27)
    );

    // Calls: every refusal leaves history bytes and the source list unchanged.
    let refuse = |method: &str, mutant: &[u8], expected: Value, label: &str| {
        let (image, listed) = (store_image(&data), live.call("list_sources", "{}"));
        assert_eq!(
            live.call_bytes(method, mutant),
            expected,
            "{method} {label}"
        );
        assert_eq!(store_image(&data), image, "{method} {label}: history");
        assert_eq!(
            live.call("list_sources", "{}"),
            listed,
            "{method} {label}: sources"
        );
    };
    for method in [
        "set_source_selection",
        "list_sources",
        "ingest",
        "today_snapshot",
    ] {
        let request = substitute(&requests[method]);
        let proceeds = live.call(method, &padded(&request, 65_536));
        assert_eq!(proceeds["ok"], json!(true), "{method} 65,536 B: {proceeds}");
        refuse(
            method,
            padded(&request, 65_537).as_bytes(),
            limit("request_bytes"),
            "65,537 B",
        );
        let unknown = edited(&requests[method], &|o| {
            o.insert("unexpected".into(), json!(true));
        });
        refuse(
            method,
            unknown.as_bytes(),
            invalid("request"),
            "unknown key",
        );
        refuse(
            method,
            &invalid_utf8(&request),
            invalid("request"),
            "invalid UTF-8",
        );
    }
    let selection = &requests["set_source_selection"];
    for (label, mutant, field) in [
        (
            "4,097 B field",
            edited(selection, &|o| {
                o.insert("root".into(), json!(long_path));
            }),
            "root",
        ),
        (
            "relative root",
            edited(selection, &|o| {
                o.insert("root".into(), json!("relative/opencode"));
            }),
            "root",
        ),
        (
            "unimplemented harness",
            edited(selection, &|o| {
                o.insert("harness".into(), json!("codex"));
            }),
            "harness",
        ),
    ] {
        refuse(
            "set_source_selection",
            mutant.as_bytes(),
            invalid(field),
            label,
        );
    }
    let long_tz = edited(&requests["today_snapshot"], &|o| {
        o.insert("tz".into(), json!("a".repeat(4_097)));
    });
    refuse(
        "today_snapshot",
        long_tz.as_bytes(),
        invalid("tz"),
        "4,097 B field",
    );
    Ok(())
}

fn daily_rows() -> Vec<Value> {
    let rows: Value = serde_json::from_str(include_str!(
        "../../../Fixtures/harness/opencode/daily/rows.json"
    ))
    .unwrap();
    rows["legacy_messages"].as_array().unwrap().clone()
}

const ID: &str = "0123456789abcdef0123456789abcdef";

/// Replaces the store-minted id with the golden's fixed one.
fn normalized(mut value: Value) -> Value {
    fn walk(value: &mut Value) {
        match value {
            Value::Object(map) => {
                if let Some(id) = map.get_mut("source_id") {
                    *id = json!(ID);
                }
                map.values_mut().for_each(walk);
            }
            Value::Array(items) => items.iter_mut().for_each(walk),
            _ => {}
        }
    }
    walk(&mut value);
    value
}

/// Goldens are fixed files compared byte-for-value with the live provider response; a test never
/// rewrites one. Their numbers are also asserted against the hand-written daily oracle.
fn check_golden(name: &str, actual: Value) -> TestResult {
    assert_eq!(consumed_golden(name)?, actual, "{name}");
    Ok(())
}

const T: i64 = 1_775_124_000_000;

#[test]
fn open_and_first_use_goldens_equal_live_responses() -> TestResult {
    let (live, open) = open_live(&daily_rows())?;
    check_golden("open-ok.json", open)?;
    let selected = live.call(
        "set_source_selection",
        &json!({"harness": "opencode", "root": live.source(), "selected": true}).to_string(),
    );
    assert_eq!(selected["ok"], json!(true), "{selected}");
    let ingested = live.call("ingest", &json!({"now_ms": T}).to_string());
    check_golden("sources-list.json", normalized(ingested))?;
    let snapshot = live.call(
        "today_snapshot",
        &json!({"tz": "UTC", "now_ms": T}).to_string(),
    );
    // The golden's numbers equal the independent hand oracle, not only the live response.
    let expected: Value = serde_json::from_str(include_str!(
        "../../../Fixtures/harness/opencode/daily/expected.json"
    ))?;
    let oracle = expected["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "utc_counters")
        .unwrap();
    assert_eq!(
        snapshot["data"]["source_reported"][0]["input"]["value"],
        json!(27)
    );
    let mut reported = snapshot["data"]["source_reported"][0].clone();
    reported.as_object_mut().unwrap().remove("source_id");
    assert_eq!(
        acquired(&reported),
        acquired_oracle(&oracle["source_reported"])
    );
    // Success at T and a snapshot at T: every present value is current, last good T.
    for field in FIELDS {
        assert_eq!(
            (&reported[field]["status"], &reported[field]["last_good_ms"]),
            (&json!("current"), &json!(T)),
            "{field}"
        );
    }
    check_golden("snapshot-opencode-reported.json", normalized(snapshot))?;
    Ok(())
}

const FIELDS: [&str; 6] = [
    "input",
    "output",
    "reasoning",
    "cache_read",
    "cache_write",
    "total",
];

/// A projection without the lifecycle: each observation keeps value, unit, provenance and
/// completeness; `status` and `last_good_ms` are removed.
fn acquired(projection: &Value) -> Value {
    let mut projection = projection.clone();
    for field in FIELDS {
        let observation = projection[field].as_object_mut().expect(field);
        observation.remove("status");
        observation.remove("last_good_ms");
    }
    projection
}

/// The hand-written four-key daily oracle in the acquired full shape: its acquired status
/// becomes completeness (current → complete, partial → partial, unavailable → null).
fn acquired_oracle(oracle: &Value) -> Value {
    let mut oracle = oracle.clone();
    for field in FIELDS {
        let observation = oracle[field].as_object_mut().expect(field);
        let completeness = match observation
            .remove("status")
            .as_ref()
            .and_then(Value::as_str)
        {
            Some("current") => json!("complete"),
            Some("partial") => json!("partial"),
            Some("unavailable") => Value::Null,
            other => panic!("{field}: oracle status {other:?}"),
        };
        observation.insert("completeness".into(), completeness);
    }
    oracle
}

/// The hand-written `validation_cases` of the daily oracle against the real `quotern_call`, on a
/// store-less engine and on an acquired one. No window is computed here.
#[test]
fn today_snapshot_validation_cases_equal_live_responses() -> TestResult {
    let expected: Value = serde_json::from_str(include_str!(
        "../../../Fixtures/harness/opencode/daily/expected.json"
    ))?;
    let cases = expected["validation_cases"]
        .as_array()
        .ok_or("validation_cases")?;
    assert!(
        cases.iter().any(|case| case.get("window").is_some()),
        "positive rows"
    );
    assert!(
        cases.iter().any(|case| case.get("error").is_some()),
        "rejected rows"
    );
    let (store_less, _) = open_live(&[])?;
    let (acquired, _) = open_live(&daily_rows())?;
    let selected = acquired.call(
        "set_source_selection",
        &json!({"harness": "opencode", "root": acquired.source(), "selected": true}).to_string(),
    );
    assert_eq!(selected["ok"], json!(true), "{selected}");
    assert_eq!(
        acquired.call("ingest", &json!({"now_ms": T}).to_string())["ok"],
        json!(true)
    );
    // The acquired engine is settled: its nonempty daily oracle holds before the rows run.
    assert_eq!(utc_reported(&acquired), utc_oracle()?);
    for (mode, live) in [("store-less", &store_less), ("acquired", &acquired)] {
        for case in cases {
            let response = live.call(
                "today_snapshot",
                &json!({"tz": case["tz"], "now_ms": case["now_ms"]}).to_string(),
            );
            let name = &case["name"];
            match case.get("window") {
                Some(window) => {
                    assert_eq!(response["ok"], json!(true), "{mode} {name}: {response}");
                    assert_eq!(response["data"]["window"], *window, "{mode} {name}");
                }
                None => {
                    let error = &case["error"];
                    assert_eq!(
                        response,
                        json!({"v": 1, "ok": false, "error": {
                            "code": error["code"], "message": error["message"], "retryable": error["retryable"]
                        }}),
                        "{mode} {name}"
                    );
                }
            }
        }
    }
    Ok(())
}

/// The hand-written `utc_counters` daily oracle of the source.
fn utc_oracle() -> TestResult<Value> {
    let expected: Value = serde_json::from_str(include_str!(
        "../../../Fixtures/harness/opencode/daily/expected.json"
    ))?;
    let case = expected["cases"]
        .as_array()
        .ok_or("cases")?
        .iter()
        .find(|case| case["name"] == "utc_counters")
        .ok_or("utc_counters")?;
    assert_eq!(case["source_reported"]["records"], json!(4), "nonempty");
    Ok(acquired_oracle(&case["source_reported"]))
}

/// The single source's acquired projection in the UTC day of `T`, without its store-minted id.
fn utc_reported(live: &Live) -> Value {
    let snapshot = live.call(
        "today_snapshot",
        &json!({"tz": "UTC", "now_ms": T}).to_string(),
    );
    let mut reported = snapshot["data"]["source_reported"][0].clone();
    reported
        .as_object_mut()
        .unwrap_or_else(|| panic!("no projection in {snapshot}"))
        .remove("source_id");
    acquired(&reported)
}

/// Two in-window input values set to i64::MAX and 1 by outside SQL with no handle live (a
/// declared trust-boundary fault, not valid acquired history): the real export answers exactly
/// `store_migration_failed`, never a window or wrapped values; the restored values give the oracle.
#[test]
fn today_snapshot_sum_overflow_is_store_error_envelope() -> TestResult {
    let (mut live, _) = open_live(&daily_rows())?;
    let selected = live.call(
        "set_source_selection",
        &json!({"harness": "opencode", "root": live.source(), "selected": true}).to_string(),
    );
    assert_eq!(selected["ok"], json!(true), "{selected}");
    live.call("ingest", &json!({"now_ms": T}).to_string());
    assert_eq!(utc_reported(&live), utc_oracle()?);

    let history = live.data().join("history.sqlite");
    let set_input = |message: &str, value: i64| -> TestResult<i64> {
        let outside = Connection::open(&history)?;
        let before = outside.query_row(
            "SELECT input_tokens FROM usage_events WHERE message_id = ?1",
            [message],
            |row| row.get(0),
        )?;
        let changed = outside.execute(
            "UPDATE usage_events SET input_tokens = ?2 WHERE message_id = ?1",
            rusqlite::params![message, value],
        )?;
        assert_eq!(changed, 1, "{message}");
        Ok(before)
    };
    live.close();
    let derived = set_input("derived", 9_223_372_036_854_775_807)?;
    let explicit = set_input("explicit", 1)?;
    live.reopen()?;
    assert_eq!(
        live.call(
            "today_snapshot",
            &json!({"tz": "UTC", "now_ms": T}).to_string()
        ),
        json!({"v": 1, "ok": false, "error": {
            "code": "store_migration_failed", "message": "store migration failed", "retryable": true
        }})
    );
    live.close();
    set_input("derived", derived)?;
    set_input("explicit", explicit)?;
    live.reopen()?;
    assert_eq!(utc_reported(&live), utc_oracle()?, "restored control");
    Ok(())
}

/// Every golden in Contracts/bridge-v1 is consumed: each response golden by a comparison with a
/// live envelope, each request golden by the production codec test. This test runs the consuming
/// tests here and records the names they load; the three goldens compared in ffi_ownership.rs are
/// recorded by that binary's `ownership_goldens_are_consumed_by_live_comparisons`.
#[test]
fn every_golden_is_inventoried_by_a_live_comparison() -> TestResult {
    let mut names = BTreeSet::new();
    for entry in std::fs::read_dir(root().join("Contracts/bridge-v1"))? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.ends_with(".json") {
            names.insert(name);
        }
    }
    assert_eq!(
        names,
        BTreeSet::from(
            [
                "error-cancelled.json",
                "error-engine-failed.json",
                "error-internal-panic.json",
                "error-invalid-request.json",
                "error-limit-exceeded.json",
                "open-ok.json",
                "requests-first-use.json",
                "snapshot-catching-up.json",
                "snapshot-empty.json",
                "snapshot-opencode-reported.json",
                "snapshot-pending-partial.json",
                "snapshot-states.json",
                "sources-list.json",
            ]
            .map(String::from)
        ),
        "the 001 golden set plus the 008 lifecycle states"
    );
    open_and_first_use_goldens_equal_live_responses()?;
    empty_inventory_and_error_goldens_equal_live_responses()?;
    pending_and_catching_up_goldens_equal_live_responses()?;
    state_goldens_equal_live_responses()?;
    first_use_request_goldens_use_production_codec()?;
    let mut consumed = CONSUMED.lock().unwrap().clone();
    consumed.extend(
        [
            "error-cancelled.json",
            "error-engine-failed.json",
            "error-internal-panic.json",
        ]
        .map(String::from),
    );
    assert_eq!(consumed, names, "consumed goldens equal the directory");
    Ok(())
}

#[test]
fn empty_inventory_and_error_goldens_equal_live_responses() -> TestResult {
    let (live, _) = open_live(&[])?;
    let empty = live.call(
        "today_snapshot",
        &json!({"tz": "UTC", "now_ms": T}).to_string(),
    );
    check_golden("snapshot-empty.json", empty)?;
    check_golden(
        "error-invalid-request.json",
        live.call("list_sources", "\"x\""),
    )?;
    let oversized = format!("{{\"pad\":\"{}\"}}", "a".repeat(65_540));
    check_golden(
        "error-limit-exceeded.json",
        live.call("list_sources", &oversized),
    )?;
    for (name, code, message, retryable) in [
        (
            "error-invalid-request.json",
            "invalid_request",
            "invalid request: request",
            false,
        ),
        (
            "error-limit-exceeded.json",
            "limit_exceeded",
            "limit exceeded: request_bytes",
            false,
        ),
        ("error-cancelled.json", "cancelled", "cancelled", true),
        (
            "error-internal-panic.json",
            "internal_panic",
            "internal panic",
            false,
        ),
        (
            "error-engine-failed.json",
            "engine_failed",
            "engine failed",
            false,
        ),
    ] {
        assert_eq!(
            golden(name)?,
            json!({"v": 1, "ok": false, "error": {"code": code, "message": message, "retryable": retryable}}),
            "{name} equals the fixed table"
        );
    }
    Ok(())
}

#[test]
fn pending_and_catching_up_goldens_equal_live_responses() -> TestResult {
    // Pending: the source turns unreadable after publication.
    let (live, _) = open_live(&daily_rows())?;
    live.call(
        "set_source_selection",
        &json!({"harness": "opencode", "root": live.source(), "selected": true}).to_string(),
    );
    live.call("ingest", &json!({"now_ms": T}).to_string());
    std::fs::write(live.source().join("opencode.db"), b"overwritten with junk")?;
    live.call("ingest", &json!({"now_ms": T + 1}).to_string());
    let pending = live.call(
        "today_snapshot",
        &json!({"tz": "UTC", "now_ms": T}).to_string(),
    );
    assert_eq!(
        pending["data"]["source_reported"][0]["pending_partial"],
        json!(true)
    );
    // The latest pass failed (not_sqlite) after the success at T: error, last good T.
    for field in FIELDS {
        let observation = &pending["data"]["source_reported"][0][field];
        assert_eq!(
            (
                &observation["status"],
                &observation["completeness"],
                &observation["last_good_ms"]
            ),
            (&json!("error"), &json!("partial"), &json!(T)),
            "{field}"
        );
    }
    check_golden("snapshot-pending-partial.json", normalized(pending))?;

    // Catching up: more rows than one pass reads, so nothing is published yet.
    let bulk: Vec<Value> = (0..5_100)
        .map(|i| json!({"id": format!("m{i}"), "session_id": "s", "time_created": T + i,
            "data": {"role": "assistant", "tokens": {"input": 1, "output": 0, "reasoning": 0, "cache": {"read": 0, "write": 0}, "total": 1}}}))
        .collect();
    let (live, _) = open_live(&bulk)?;
    live.call(
        "set_source_selection",
        &json!({"harness": "opencode", "root": live.source(), "selected": true}).to_string(),
    );
    live.call("ingest", &json!({"now_ms": T}).to_string());
    let catching = live.call(
        "today_snapshot",
        &json!({"tz": "UTC", "now_ms": T}).to_string(),
    );
    assert_eq!(
        catching["data"]["by_source"][0]["outcome"],
        json!("catching_up")
    );
    // Independent oracle: every row carries input 1, so the published records equal the summed
    // input and fewer than all 5,100 rows are visible.
    let published = catching["data"]["source_reported"][0]["records"]
        .as_u64()
        .unwrap();
    assert_eq!(
        catching["data"]["source_reported"][0]["input"]["value"].as_u64(),
        Some(published)
    );
    assert!((1..5_100).contains(&published), "{published}");
    // A fresh success with a live backlog is catching up, never current.
    for field in FIELDS {
        let observation = &catching["data"]["source_reported"][0][field];
        assert_eq!(
            (&observation["status"], &observation["last_good_ms"]),
            (&json!("catching_up"), &json!(T)),
            "{field}"
        );
    }
    check_golden("snapshot-catching-up.json", normalized(catching))?;
    Ok(())
}

/// The UTC day with no record of the daily rows: every observation null.
const EMPTY_DAY_MS: i64 = 1_777_636_800_000;

fn select(live: &Live) {
    let selected = live.call(
        "set_source_selection",
        &json!({"harness": "opencode", "root": live.source(), "selected": true}).to_string(),
    );
    assert_eq!(selected["ok"], json!(true), "{selected}");
}

fn ingest_at(live: &Live, now_ms: i64) {
    let ingested = live.call("ingest", &json!({"now_ms": now_ms}).to_string());
    assert_eq!(ingested["ok"], json!(true), "{ingested}");
}

/// One named lifecycle state: the snapshot request and the live provider response.
fn state(name: &str, live: &Live, now_ms: i64) -> Value {
    let request = json!({"tz": "UTC", "now_ms": now_ms});
    let response = live.call("today_snapshot", &request.to_string());
    assert_eq!(response["ok"], json!(true), "{name}: {response}");
    json!({"name": name, "request": request, "response": normalized(response)})
}

/// A record the adapter rejects: the next pass records `invalid_record` and publishes no new
/// number.
fn hostile(live: &Live, present: bool) -> TestResult {
    let database = Connection::open(live.source().join("opencode.db"))?;
    let changed = if present {
        database.execute(
            "INSERT INTO message(id, session_id, time_created, data) \
             VALUES ('hostile', 'session-day', ?1, '{not json')",
            [T + 5_000],
        )?
    } else {
        database.execute("DELETE FROM message WHERE id = 'hostile'", [])?
    };
    assert_eq!(changed, 1);
    Ok(())
}

/// Every lifecycle state the snapshot can present, each produced live through the real exports
/// and kept as one entry of the SAME `snapshot-states.json` that Swift decodes, renders and
/// checks for accessibility. Expected statuses and times are written here by hand from the
/// precedence rule; values are the hand daily oracle.
#[test]
fn state_goldens_equal_live_responses() -> TestResult {
    let mut states = Vec::new();

    let (live, _) = open_live(&daily_rows())?;
    select(&live);
    ingest_at(&live, T);
    states.push(state("current_at_600000_ms", &live, T + 600_000));
    states.push(state("stale_at_600001_ms", &live, T + 600_001));
    states.push(state("unavailable_empty_window", &live, EMPTY_DAY_MS));
    let denied = live.call(
        "set_source_selection",
        &json!({"harness": "opencode", "root": live.source(), "selected": false}).to_string(),
    );
    assert_eq!(denied["ok"], json!(true), "{denied}");
    states.push(state("denied_retains_values", &live, T));

    // An attached failed pass after, at and before the success instant; then recovery.
    for (name, attempt) in [
        ("error_attached_newer_attempt", T + 1_000),
        ("error_attached_equal_attempt", T),
        ("error_attached_earlier_attempt", T - 1),
    ] {
        let (live, _) = open_live(&daily_rows())?;
        select(&live);
        ingest_at(&live, T);
        hostile(&live, true)?;
        ingest_at(&live, attempt);
        states.push(state(name, &live, attempt.max(T)));
        if attempt < T {
            hostile(&live, false)?;
            ingest_at(&live, T + 10_000);
            states.push(state("current_after_attached_recovery", &live, T + 10_000));
        }
    }

    // A persisted root missing at reopen: only open attempted, then ingest at and before the
    // success instant; then the original root returns.
    let (mut live, _) = open_live(&daily_rows())?;
    select(&live);
    ingest_at(&live, T);
    live.close();
    let moved = live.base().join("moved");
    std::fs::rename(live.source(), &moved)?;
    live.reopen()?;
    states.push(state("error_unattached_null_attempt", &live, T));
    ingest_at(&live, T);
    states.push(state("error_unattached_equal_attempt", &live, T));
    ingest_at(&live, T - 1);
    states.push(state("error_unattached_earlier_attempt", &live, T));
    std::fs::rename(&moved, live.source())?;
    ingest_at(&live, T + 10_000);
    states.push(state("current_after_reattach", &live, T + 10_000));

    let bulk: Vec<Value> = (0..5_100)
        .map(|i| json!({"id": format!("m{i}"), "session_id": "s", "time_created": T + i,
            "data": {"role": "assistant", "tokens": {"input": 1, "output": 0, "reasoning": 0, "cache": {"read": 0, "write": 0}, "total": 1}}}))
        .collect();
    let (live, _) = open_live(&bulk)?;
    select(&live);
    ingest_at(&live, T);
    states.push(state("catching_up_with_live_backlog", &live, T));

    // A fresh success whose values were only partly acquired: partial completeness, current.
    let (live, _) = open_live(&daily_rows())?;
    select(&live);
    ingest_at(&live, T);
    states.push(state("fresh_partial_completeness_is_current", &live, T));

    // One record without reasoning, cache or total: those values are null beside present ones,
    // under a failed pass and then under denied consent.
    let null_components: Vec<Value> = daily_rows()
        .into_iter()
        .filter(|row| row["id"] == "null-components")
        .collect();
    let (live, _) = open_live(&null_components)?;
    select(&live);
    ingest_at(&live, T);
    hostile(&live, true)?;
    ingest_at(&live, T + 1_000);
    states.push(state("null_value_beside_error", &live, T + 1_000));
    let (live, _) = open_live(&null_components)?;
    select(&live);
    ingest_at(&live, T);
    let denied = live.call(
        "set_source_selection",
        &json!({"harness": "opencode", "root": live.source(), "selected": false}).to_string(),
    );
    assert_eq!(denied["ok"], json!(true), "{denied}");
    states.push(state("null_value_beside_denied", &live, T));

    // Hand table: (name, status of every present value, last_attempt_ms, last_good_ms, failed).
    let table: [(&str, &str, Value, i64, bool); 16] = [
        ("current_at_600000_ms", "current", json!(T), T, false),
        ("stale_at_600001_ms", "stale", json!(T), T, false),
        (
            "unavailable_empty_window",
            "unavailable",
            json!(T),
            T,
            false,
        ),
        ("denied_retains_values", "denied", json!(T), T, false),
        (
            "error_attached_newer_attempt",
            "error",
            json!(T + 1_000),
            T,
            true,
        ),
        ("error_attached_equal_attempt", "error", json!(T), T, true),
        (
            "error_attached_earlier_attempt",
            "error",
            json!(T - 1),
            T,
            true,
        ),
        (
            "current_after_attached_recovery",
            "current",
            json!(T + 10_000),
            T + 10_000,
            false,
        ),
        (
            "error_unattached_null_attempt",
            "error",
            Value::Null,
            T,
            true,
        ),
        ("error_unattached_equal_attempt", "error", json!(T), T, true),
        (
            "error_unattached_earlier_attempt",
            "error",
            json!(T - 1),
            T,
            true,
        ),
        (
            "current_after_reattach",
            "current",
            json!(T + 10_000),
            T + 10_000,
            false,
        ),
        (
            "catching_up_with_live_backlog",
            "catching_up",
            json!(T),
            T,
            false,
        ),
        (
            "fresh_partial_completeness_is_current",
            "current",
            json!(T),
            T,
            false,
        ),
        (
            "null_value_beside_error",
            "error",
            json!(T + 1_000),
            T,
            true,
        ),
        ("null_value_beside_denied", "denied", json!(T), T, false),
    ];
    assert_eq!(states.len(), table.len());
    let oracle = utc_oracle()?;
    for (state, (name, status, attempt, good, failed)) in states.iter().zip(table) {
        assert_eq!(state["name"], json!(name));
        let data = &state["response"]["data"];
        let source = &data["by_source"][0];
        assert_eq!(source["last_attempt_ms"], attempt, "{name}: attempt");
        assert_eq!(source["last_success_ms"], json!(good), "{name}: success");
        assert_eq!(
            source["last_error_code"].is_string(),
            failed,
            "{name}: failure"
        );
        let reported = &data["source_reported"][0];
        for field in FIELDS {
            let observation = &reported[field];
            let expected = if observation["value"].is_null() {
                "unavailable"
            } else {
                status
            };
            assert_eq!(observation["status"], json!(expected), "{name} {field}");
            assert_eq!(observation["last_good_ms"], json!(good), "{name} {field}");
        }
        match name {
            "unavailable_empty_window" => {
                assert_eq!(reported["records"], json!(0));
                for field in FIELDS {
                    assert_eq!(
                        reported[field],
                        json!({"value": null, "unit": "tokens", "provenance": null,
                            "completeness": null, "status": "unavailable", "last_good_ms": T}),
                        "{field}: null is never 0"
                    );
                }
            }
            "catching_up_with_live_backlog" => {}
            "null_value_beside_error" | "null_value_beside_denied" => {
                let mut values = reported.clone();
                values.as_object_mut().unwrap().remove("source_id");
                assert_eq!(acquired(&values), null_components_oracle(), "{name}");
                for (field, expected) in [
                    ("input", status),
                    ("output", status),
                    ("reasoning", "unavailable"),
                    ("cache_read", "unavailable"),
                    ("cache_write", "unavailable"),
                    ("total", "unavailable"),
                ] {
                    assert_eq!(reported[field]["status"], json!(expected), "{name} {field}");
                }
            }
            _ => {
                let mut values = reported.clone();
                values.as_object_mut().unwrap().remove("source_id");
                assert_eq!(acquired(&values), oracle, "{name}: values retained");
                if name == "fresh_partial_completeness_is_current" {
                    for field in ["reasoning", "cache_read", "cache_write", "total"] {
                        assert_eq!(
                            (&reported[field]["status"], &reported[field]["completeness"]),
                            (&json!("current"), &json!("partial")),
                            "{name} {field}"
                        );
                    }
                }
            }
        }
    }

    check_golden("snapshot-states.json", json!({"states": states}))?;
    Ok(())
}

/// The hand-written acquired projection of the fixture's `null-components` record alone (input 7,
/// output 1, nothing else): reasoning, cache and total are null, never 0, and no total is derived
/// from incomplete components.
fn null_components_oracle() -> Value {
    let absent = json!({"value": null, "unit": "tokens", "provenance": null, "completeness": null});
    json!({
        "records": 1,
        "input": {"value": 7, "unit": "tokens", "provenance": "reported", "completeness": "complete"},
        "output": {"value": 1, "unit": "tokens", "provenance": "reported", "completeness": "complete"},
        "reasoning": absent.clone(),
        "cache_read": absent.clone(),
        "cache_write": absent.clone(),
        "total": absent,
        "source_convention": null,
        "acquisition_consistency": "sqlite_read_transaction",
        "origin_uncertainty": "unverified_origin",
        "total_mismatch": false,
        "mirror_conflict": false,
        "pending_partial": false
    })
}

/// The strict observation shape both consumers require: exactly the six keys, unit `tokens`, a
/// lifecycle status, a nullable integer last-good time; provenance and completeness are null
/// exactly when the value is, and a null value is `unavailable`.
fn check_observation(observation: &Value) -> Result<(), String> {
    let map = observation.as_object().ok_or("not an object")?;
    let keys: BTreeSet<&str> = map.keys().map(String::as_str).collect();
    let expected = BTreeSet::from([
        "value",
        "unit",
        "provenance",
        "completeness",
        "status",
        "last_good_ms",
    ]);
    if keys != expected {
        return Err(format!("keys {keys:?}"));
    }
    let null = map["value"].is_null();
    if !(null || map["value"].is_u64()) {
        return Err(format!("value {}", map["value"]));
    }
    if map["unit"] != "tokens" {
        return Err(format!("unit {}", map["unit"]));
    }
    let provenance = map["provenance"].as_str();
    let completeness = map["completeness"].as_str();
    let status = map["status"].as_str().unwrap_or_default();
    let valid = if null {
        map["provenance"].is_null() && map["completeness"].is_null() && status == "unavailable"
    } else {
        matches!(provenance, Some("reported" | "derived"))
            && matches!(completeness, Some("complete" | "partial"))
            && matches!(
                status,
                "current" | "stale" | "error" | "denied" | "catching_up" | "unavailable"
            )
    };
    if !valid {
        return Err(format!("inconsistent observation {observation}"));
    }
    if !(map["last_good_ms"].is_null() || map["last_good_ms"].is_i64()) {
        return Err(format!("last_good_ms {}", map["last_good_ms"]));
    }
    Ok(())
}

/// Every observation of every `source_reported` projection anywhere in `golden`, checked
/// strictly; the count of observations checked.
fn check_observations(golden: &Value) -> Result<usize, String> {
    match golden {
        Value::Object(map) => {
            let mut checked = 0;
            for (key, value) in map {
                if key == "source_reported" {
                    for projection in value.as_array().ok_or("source_reported")? {
                        for field in FIELDS {
                            check_observation(&projection[field])
                                .map_err(|error| format!("{field}: {error}"))?;
                            checked += 1;
                        }
                    }
                } else {
                    checked += check_observations(value)?;
                }
            }
            Ok(checked)
        }
        Value::Array(items) => items.iter().map(check_observations).sum(),
        _ => Ok(0),
    }
}

/// The real snapshot goldens pass the strict shape check; each mutant of the SAME states golden
/// is rejected by it.
#[test]
fn observation_shape_rejects_mutated_goldens() -> TestResult {
    for name in [
        "snapshot-states.json",
        "snapshot-opencode-reported.json",
        "snapshot-catching-up.json",
        "snapshot-pending-partial.json",
        "snapshot-empty.json",
    ] {
        let checked = check_observations(&golden(name)?);
        assert!(checked.is_ok(), "{name}: {checked:?}");
    }
    let states = golden("snapshot-states.json")?;
    assert_eq!(check_observations(&states), Ok(16 * FIELDS.len()));

    // states[0] input is a present value; states[2] total is a null one.
    let present = "/states/0/response/data/source_reported/0/input";
    let null = "/states/2/response/data/source_reported/0/total";
    let mutants: [(&str, &str, &str, Option<Value>); 13] = [
        ("missing completeness", present, "completeness", None),
        ("missing provenance", present, "provenance", None),
        ("missing status", present, "status", None),
        ("missing last_good_ms", present, "last_good_ms", None),
        ("extra key", present, "rate", Some(json!(1))),
        (
            "null completeness beside a value",
            present,
            "completeness",
            Some(Value::Null),
        ),
        (
            "null provenance beside a value",
            present,
            "provenance",
            Some(Value::Null),
        ),
        ("unknown status", present, "status", Some(json!("fresh"))),
        ("negative value", present, "value", Some(json!(-1))),
        ("other unit", present, "unit", Some(json!("usd"))),
        (
            "provenance on a null value",
            null,
            "provenance",
            Some(json!("reported")),
        ),
        (
            "completeness on a null value",
            null,
            "completeness",
            Some(json!("complete")),
        ),
        (
            "null value not unavailable",
            null,
            "status",
            Some(json!("current")),
        ),
    ];
    for (label, pointer, key, replacement) in mutants {
        let mut mutant = states.clone();
        let observation = mutant
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .ok_or(pointer)?;
        match replacement {
            Some(value) => observation.insert(key.to_owned(), value),
            None => observation.remove(key),
        };
        assert!(
            check_observations(&mutant).is_err(),
            "{label} must be rejected"
        );
    }
    Ok(())
}

#[test]
fn numeric_width_boundaries() -> TestResult {
    use quotern_core::domain::{
        ConsentState, ObservationStatus, OriginUncertainty, Provenance, SourceKind,
        TokenObservation, TokenUnit,
    };
    use quotern_core::limits::MAX_SOURCE_TIMESTAMP_MS;
    use quotern_core::snapshot::{
        DailyReported, SourceEntry, SourceProjection, TodaySnapshot, Window,
    };
    let widest = |value: Option<u64>| TokenObservation {
        value,
        unit: TokenUnit::Tokens,
        provenance: value.map(|_| Provenance::Reported),
        status: if value.is_some() {
            ObservationStatus::Current
        } else {
            ObservationStatus::Unavailable
        },
    };
    let snapshot = TodaySnapshot {
        window: Window {
            start_ms: 0,
            end_ms: MAX_SOURCE_TIMESTAMP_MS,
            tz: "UTC".into(),
            now_ms: MAX_SOURCE_TIMESTAMP_MS,
        },
        by_source: vec![SourceEntry {
            source_id: ID.into(),
            harness: "opencode".into(),
            root_display: "source".into(),
            kind: SourceKind::Custom,
            consent: ConsentState::Enabled,
            outcome: None,
            last_attempt_ms: Some(MAX_SOURCE_TIMESTAMP_MS),
            last_success_ms: Some(0),
            last_error_code: None,
            rejected_count: u32::MAX,
            pending_partial: false,
        }],
        source_reported: vec![DailyReported {
            source_id: ID.into(),
            projection: SourceProjection {
                records: u64::MAX,
                input: widest(Some(u64::MAX)),
                output: widest(Some(0)),
                reasoning: widest(None),
                cache_read: widest(None),
                cache_write: widest(None),
                total: widest(Some(u64::MAX)),
                source_convention: None,
                acquisition_consistency: None,
                origin_uncertainty: OriginUncertainty::UnverifiedOrigin,
                total_mismatch: false,
                mirror_conflict: false,
                pending_partial: false,
            },
        }],
    };
    // The decimal text, not a float round trip, carries every width exactly.
    let text = serde_json::to_string(&snapshot)?;
    for exact in [
        "\"records\":18446744073709551615",
        "\"value\":18446744073709551615",
        "\"end_ms\":253402300799999",
        "\"last_attempt_ms\":253402300799999",
        "\"rejected_count\":4294967295",
        "\"last_good_ms\":0",
    ] {
        assert!(text.contains(exact), "{exact} in {text}");
    }
    let value: Value = serde_json::from_str(&text)?;
    assert_eq!(
        value["source_reported"][0]["records"].as_u64(),
        Some(u64::MAX)
    );
    assert_eq!(
        value["by_source"][0]["rejected_count"].as_u64(),
        Some(u64::from(u32::MAX))
    );
    assert_eq!(
        value["window"]["end_ms"].as_i64(),
        Some(MAX_SOURCE_TIMESTAMP_MS)
    );
    assert_eq!(MAX_SOURCE_TIMESTAMP_MS, 253_402_300_799_999);
    Ok(())
}
