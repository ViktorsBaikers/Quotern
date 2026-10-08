//! Ownership, precedence, recovery and owner-scope behavior of the real exports. Every returned
//! string is freed exactly once by `text`; handles are closed by `Live`. Hooks and counters of the
//! core are thread-local, so every export runs on the thread that arms them.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, c_char};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use quotern_core::store;
use quotern_ffi::*;
use rusqlite::Connection;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub const T: i64 = 1_775_124_000_000;

fn text(pointer: *mut c_char) -> String {
    assert!(!pointer.is_null(), "an export never returns NULL here");
    let value = unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned();
    unsafe { quotern_string_free(pointer) };
    value
}

fn code(response: &Value) -> (&str, &str, bool) {
    let error = &response["error"];
    (
        error["code"].as_str().unwrap_or("<none>"),
        error["message"].as_str().unwrap_or(""),
        error["retryable"].as_bool().unwrap_or(false),
    )
}

fn message(id: &str, input: u64, time: i64) -> Value {
    json!({"id": id, "session_id": "s", "time_created": time, "data": {"role": "assistant",
        "tokens": {"input": input, "output": 0, "reasoning": 0, "cache": {"read": 0, "write": 0}, "total": input}}})
}

/// Daily fixture rows: UTC input 27 at T.
fn daily_rows() -> Vec<Value> {
    let rows: Value = serde_json::from_str(include_str!(
        "../../../Fixtures/harness/opencode/daily/rows.json"
    ))
    .unwrap();
    rows["legacy_messages"].as_array().unwrap().clone()
}

/// B's hand-written oracle: two records, input 5 + 6.
fn rows_b() -> Vec<Value> {
    vec![message("b1", 5, T), message("b2", 6, T + 1_000)]
}

/// C's rows: input 100, never read once C is denied.
fn rows_c() -> Vec<Value> {
    vec![message("c1", 100, T)]
}

const ORACLE_A: u64 = 27;
const ORACLE_B: u64 = 11;

/// A's full hand-written daily oracle: `utc_counters` of the daily fixture.
fn full_oracle_a() -> Value {
    let expected: Value = serde_json::from_str(include_str!(
        "../../../Fixtures/harness/opencode/daily/expected.json"
    ))
    .unwrap();
    expected["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "utc_counters")
        .unwrap()["source_reported"]
        .clone()
}

/// B's full hand-written daily oracle: two records whose every component is present and whose
/// explicit totals (5, 6) equal their component sums. No total is derived, so no derivation
/// convention is named.
fn full_oracle_b() -> Value {
    let reported = |value: u64| json!({"value": value, "unit": "tokens", "provenance": "reported", "status": "current"});
    json!({"records": 2, "input": reported(11), "output": reported(0), "reasoning": reported(0),
        "cache_read": reported(0), "cache_write": reported(0), "total": reported(11),
        "source_convention": null,
        "acquisition_consistency": "sqlite_read_transaction",
        "origin_uncertainty": "unverified_origin", "total_mismatch": false,
        "mirror_conflict": false, "pending_partial": false})
}

/// A `source_reported` entry without its store-minted id.
fn without_id(mut reported: Value) -> Value {
    reported.as_object_mut().unwrap().remove("source_id");
    reported
}

fn build_source(root: &Path, rows: &[Value]) -> TestResult {
    std::fs::create_dir_all(root)?;
    let connection = Connection::open(root.join("opencode.db"))?;
    let schema: String = include_str!("../../../Fixtures/harness/opencode/wal/schema.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with("PRAGMA"))
        .collect::<Vec<_>>()
        .join("\n");
    connection.execute_batch(&schema)?;
    add_rows(root, rows)?;
    Ok(())
}

fn add_rows(root: &Path, rows: &[Value]) -> TestResult {
    let connection = Connection::open(root.join("opencode.db"))?;
    for row in rows {
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
    Ok(())
}

/// An isolated base directory: `data` is never created by a test, `home` is.
struct World {
    _directory: tempfile::TempDir,
    base: PathBuf,
    /// The data dir sits in `base/outer`, an ancestor that does not contain `home`.
    nested: bool,
}

impl World {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let base = directory.path().canonicalize()?;
        std::fs::create_dir(base.join("home"))?;
        Ok(Self {
            _directory: directory,
            base,
            nested: false,
        })
    }
    fn nested() -> TestResult<Self> {
        let mut world = Self::new()?;
        std::fs::create_dir(world.base.join("outer"))?;
        world.nested = true;
        Ok(world)
    }
    /// A data-dir ancestor that holds no source root and not `home`.
    fn outer(&self) -> PathBuf {
        self.base.join("outer")
    }
    fn with_source(rows: &[Value]) -> TestResult<Self> {
        let world = Self::new()?;
        build_source(&world.source(), rows)?;
        Ok(world)
    }
    fn data(&self) -> PathBuf {
        if self.nested {
            self.outer().join("data")
        } else {
            self.base.join("data")
        }
    }
    fn home(&self) -> PathBuf {
        self.base.join("home")
    }
    fn source(&self) -> PathBuf {
        self.base.join("source")
    }
    fn named(&self, name: &str) -> PathBuf {
        self.base.join(name)
    }
    fn config_for(&self, data: &Path) -> String {
        json!({"data_dir": data, "home": self.home()}).to_string()
    }
    fn config(&self) -> String {
        self.config_for(&self.data())
    }
    fn open(&self) -> (Option<Live>, Value) {
        open_with(&self.config())
    }
    fn live(&self) -> Live {
        self.open().0.expect("open")
    }
}

struct Live {
    engine: *mut QuoternEngine,
}

impl Live {
    fn call_with(&self, method: &str, request: &str, cancel: *const QuoternCancel) -> Value {
        let (method, request) = (
            CString::new(method).unwrap(),
            CString::new(request).unwrap(),
        );
        serde_json::from_str(&text(unsafe {
            quotern_call(self.engine, method.as_ptr(), request.as_ptr(), cancel)
        }))
        .unwrap()
    }
    fn call(&self, method: &str, request: &str) -> Value {
        self.call_with(method, request, std::ptr::null())
    }
    fn select(&self, root: &Path) -> Value {
        self.call(
            "set_source_selection",
            &json!({"harness": "opencode", "root": root, "selected": true}).to_string(),
        )
    }
    fn deselect(&self, root: &Path) -> Value {
        self.call(
            "set_source_selection",
            &json!({"harness": "opencode", "root": root, "selected": false}).to_string(),
        )
    }
    fn ingest(&self, now_ms: i64) -> Value {
        self.call("ingest", &json!({"now_ms": now_ms}).to_string())
    }
    fn snapshot(&self) -> Value {
        self.call(
            "today_snapshot",
            &json!({"tz": "UTC", "now_ms": T}).to_string(),
        )
    }
    fn sources(&self) -> Value {
        self.call("list_sources", "{}")
    }
    /// The source id minted for `root_display == name`.
    fn id_of(&self, name: &str) -> String {
        let listed = self.sources();
        listed["data"]["sources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["root_display"] == json!(name))
            .unwrap_or_else(|| panic!("no source {name} in {listed}"))["source_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }
    /// The `by_source` entry of `id`.
    fn entry(&self, id: &str) -> Value {
        entry_of(&self.snapshot()["data"]["by_source"], id)
    }
    /// The daily `input` of `id` in the UTC day of `T`, or null.
    fn input(&self, id: &str) -> Value {
        reported_of(&self.snapshot(), id)["input"]["value"].clone()
    }
}

fn entry_of(entries: &Value, id: &str) -> Value {
    entries
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["source_id"] == json!(id))
        .unwrap_or_else(|| panic!("no entry {id}"))
        .clone()
}

fn reported_of(snapshot: &Value, id: &str) -> Value {
    entry_of(&snapshot["data"]["source_reported"], id)
}

impl Drop for Live {
    fn drop(&mut self) {
        unsafe { quotern_engine_close(self.engine) };
    }
}

fn open_with(config: &str) -> (Option<Live>, Value) {
    let config = CString::new(config).unwrap();
    let mut engine: *mut QuoternEngine = std::ptr::null_mut();
    let response: Value = serde_json::from_str(&text(unsafe {
        quotern_engine_open(config.as_ptr(), &mut engine)
    }))
    .unwrap();
    if response["ok"] == json!(true) {
        assert!(!engine.is_null());
        (Some(Live { engine }), response)
    } else {
        assert!(engine.is_null(), "a failed open sets out to NULL");
        (None, response)
    }
}

// ---- file images and probes ---------------------------------------------------------------

/// Existence, (dev, ino) and bytes of each history file beneath `data`; a directory has no bytes.
type FileImage = Option<((u64, u64), Option<Vec<u8>>)>;

/// Panics when an existing non-directory entry cannot be read: an unreadable file is never
/// imaged as empty.
fn history_image(data: &Path) -> BTreeMap<&'static str, FileImage> {
    [
        "history.sqlite",
        "history.sqlite-wal",
        "history.sqlite-shm",
        "history.sqlite-journal",
    ]
    .into_iter()
    .map(|name| {
        let path = data.join(name);
        let image = std::fs::symlink_metadata(&path).ok().map(|metadata| {
            let bytes = (!metadata.is_dir()).then(|| {
                std::fs::read(&path)
                    .unwrap_or_else(|error| panic!("{} unreadable: {error}", path.display()))
            });
            ((metadata.dev(), metadata.ino()), bytes)
        });
        (name, image)
    })
    .collect()
}

/// Every file below `root`: relative path and bytes.
fn tree_image(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut image = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => pending.push(path),
                Ok(kind) if kind.is_file() => {
                    image.insert(
                        path.strip_prefix(root).unwrap().to_path_buf(),
                        std::fs::read(&path).unwrap_or_default(),
                    );
                }
                _ => {}
            }
        }
    }
    image
}

/// How many descriptors of this process refer to `path`'s (dev, ino): each `/dev/fd/N` is opened
/// non-blocking (a duplicate of descriptor N) and `fstat`ed. The method is proven by the
/// extra-`Store::open` control of `two_roots_share_one_store_with_independent_totals`.
fn descriptors_of(path: &Path) -> usize {
    use std::os::unix::fs::OpenOptionsExt;
    const O_NONBLOCK: i32 = 0x4;
    let Ok(metadata) = std::fs::metadata(path) else {
        return 0;
    };
    let target = (metadata.dev(), metadata.ino());
    (0..1024)
        .filter(|descriptor| {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(O_NONBLOCK)
                .open(format!("/dev/fd/{descriptor}"))
                .and_then(|file| file.metadata())
                .is_ok_and(|opened| (opened.dev(), opened.ino()) == target)
        })
        .count()
}

fn history_descriptors(data: &Path) -> usize {
    ["history.sqlite", "history.sqlite-wal", "history.sqlite-shm"]
        .iter()
        .map(|name| descriptors_of(&data.join(name)))
        .sum()
}

fn reset_counters() {
    quotern_core::store::reset_writable_open_attempts();
    quotern_core::store::reset_history_descriptor_opens();
}

fn counters() -> (usize, usize) {
    (
        quotern_core::store::writable_open_attempts(),
        quotern_core::store::history_descriptor_opens(),
    )
}

/// `source_status` row of `id`, read through an independent read-only connection.
fn status_row(data: &Path, id: &str) -> TestResult<Vec<String>> {
    let connection = Connection::open_with_flags(
        data.join("history.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let row = connection.query_row(
        "SELECT * FROM source_status WHERE source_id = ?1",
        [id],
        |row| {
            (0..row.as_ref().column_count())
                .map(|index| {
                    row.get::<_, rusqlite::types::Value>(index)
                        .map(|value| format!("{value:?}"))
                })
                .collect::<Result<Vec<_>, _>>()
        },
    )?;
    Ok(row)
}

/// Every durable row of `id`, from each table with a `source_id` column, read by SQL.
fn durable_rows(data: &Path, id: &str) -> TestResult<BTreeMap<String, Vec<String>>> {
    let connection = Connection::open_with_flags(
        data.join("history.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let tables: Vec<String> = connection
        .prepare(
            "SELECT m.name FROM sqlite_master m WHERE m.type = 'table' AND EXISTS \
             (SELECT 1 FROM pragma_table_info(m.name) WHERE name = 'source_id')",
        )?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    let mut image = BTreeMap::new();
    for table in tables {
        let mut statement =
            connection.prepare(&format!("SELECT * FROM \"{table}\" WHERE source_id = ?1"))?;
        let columns = statement.column_count();
        let mut rows: Vec<String> = statement
            .query_map([id], |row| {
                (0..columns)
                    .map(|index| row.get::<_, rusqlite::types::Value>(index))
                    .collect::<Result<Vec<_>, _>>()
                    .map(|values| format!("{values:?}"))
            })?
            .collect::<Result<_, _>>()?;
        rows.sort();
        image.insert(table, rows);
    }
    Ok(image)
}

fn root_euid_is_zero() -> bool {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() == 0 }
}

fn set_mode(path: &Path, mode: u32) -> TestResult {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

// ---- first use, reopen and recovery ---------------------------------------------------------

#[test]
fn fresh_open_creates_nothing_until_first_valid_selection() -> TestResult {
    let world = World::with_source(&daily_rows())?;
    reset_counters();
    let live = world.live();
    assert!(!world.data().exists(), "open creates no data dir");
    assert_eq!(counters(), (0, 0));
    assert_eq!(
        live.call("list_sources", "{}")["data"],
        json!({"sources": []})
    );
    let empty = live.snapshot();
    assert_eq!(empty["data"]["by_source"], json!([]));
    assert_eq!(empty["data"]["source_reported"], json!([]));
    // Invalid and denied first selections create nothing.
    let invalid = live.call(
        "set_source_selection",
        &json!({"harness": "codex", "root": world.source(), "selected": true}).to_string(),
    );
    assert_eq!(code(&invalid).0, "invalid_request");
    let relative = live.call(
        "set_source_selection",
        &json!({"harness": "opencode", "root": "relative", "selected": true}).to_string(),
    );
    assert_eq!(code(&relative).0, "invalid_request");
    assert_eq!(code(&live.deselect(&world.source())).0, "invalid_request");
    assert!(
        !world.data().exists(),
        "nothing created by refused selections"
    );
    assert_eq!(
        counters(),
        (0, 0),
        "no writable open and no history descriptor"
    );
    // The first valid selection creates the store; ingest reads the oracle.
    assert_eq!(live.select(&world.source())["ok"], json!(true));
    assert!(world.data().join("history.sqlite").exists());
    live.ingest(T);
    let id = live.id_of("source");
    assert_eq!(live.input(&id), json!(ORACLE_A));
    Ok(())
}

#[test]
fn existing_history_reopen_reattaches_persisted_roots() -> TestResult {
    let world = World::with_source(&daily_rows())?;
    let id = {
        let live = world.live();
        live.select(&world.source());
        live.ingest(T);
        live.id_of("source")
    };
    let live = world.live();
    let before = live.snapshot();
    assert_eq!(reported_of(&before, &id)["input"]["value"], json!(ORACLE_A));
    let entry = entry_of(&before["data"]["by_source"], &id);
    assert_eq!(entry["consent"], json!("enabled"));
    assert_eq!(entry["last_error_code"], Value::Null);
    assert_eq!(entry["last_success_ms"], json!(T));
    // A new pass adds nothing: replay adds zero.
    live.ingest(T + 1_000_000);
    assert_eq!(
        reported_of(&live.snapshot(), &id),
        reported_of(&before, &id)
    );
    Ok(())
}

#[test]
fn first_use_wire_size_boundary() -> TestResult {
    let world = World::new()?;
    let huge = format!(
        "{{\"data_dir\":\"/{}\",\"home\":\"/h\"}}",
        "a".repeat(65_540)
    );
    let (none, response) = open_with(&huge);
    assert!(none.is_none());
    assert_eq!(
        code(&response),
        ("limit_exceeded", "limit exceeded: config_bytes", false)
    );
    // 65,536 B of config reaches field validation; 65,537 B does not.
    let pad = |total: usize| {
        let fixed = "{\"data_dir\":\"/x\",\"home\":\"/h\",\"p\":\"\"}".len();
        format!(
            "{{\"data_dir\":\"/x\",\"home\":\"/h\",\"p\":\"{}\"}}",
            "a".repeat(total - fixed)
        )
    };
    assert_eq!(pad(65_536).len(), 65_536);
    let (none, response) = open_with(&pad(65_536));
    assert!(none.is_none());
    assert_eq!(
        code(&response).0,
        "invalid_request",
        "an unknown key after the size gate"
    );
    let (none, response) = open_with(&pad(65_537));
    assert!(none.is_none());
    assert_eq!(
        code(&response),
        ("limit_exceeded", "limit exceeded: config_bytes", false)
    );
    let (none, response) =
        open_with(&json!({"data_dir": "/x", "home": "/h", "extra": 1}).to_string());
    assert!(none.is_none());
    assert_eq!(code(&response).0, "invalid_request");
    let long_field = "a".repeat(4_097);
    for config in [
        json!({"data_dir": format!("/{long_field}"), "home": "/h"}),
        json!({"data_dir": "/x", "home": format!("/{long_field}")}),
    ] {
        let (none, response) = open_with(&config.to_string());
        assert!(none.is_none());
        assert_eq!(code(&response).0, "invalid_request", "4,097 B field");
    }
    let live = world.live();
    // 65,536 bytes reaches field validation; 65,537 does not.
    let at_limit = format!("{{\"pad\":\"{}\"}}", "a".repeat(65_536 - 10));
    assert_eq!(at_limit.len(), 65_536);
    assert_eq!(
        code(&live.call("list_sources", &at_limit)).0,
        "invalid_request"
    );
    let over = format!("{{\"pad\":\"{}\"}}", "a".repeat(65_537 - 10));
    assert_eq!(
        code(&live.call("list_sources", &over)),
        ("limit_exceeded", "limit exceeded: request_bytes", false)
    );
    // A 64 B unregistered method reaches recognition; a 65 B method does not, whatever else is wrong.
    assert_eq!(
        code(&live.call(&"m".repeat(64), "{}")),
        ("unknown_method", "unknown method", false)
    );
    let method_bound = ("limit_exceeded", "limit exceeded: method_bytes", false);
    assert_eq!(code(&live.call(&"m".repeat(65), "{}")), method_bound);
    assert_eq!(code(&live.call(&"m".repeat(65), &over)), method_bound);
    let bad_utf8 = CString::new(vec![0xff_u8])?;
    let method = CString::new("m".repeat(65))?;
    let response: Value = serde_json::from_str(&text(unsafe {
        quotern_call(
            live.engine,
            method.as_ptr(),
            bad_utf8.as_ptr(),
            std::ptr::null(),
        )
    }))?;
    assert_eq!(
        code(&response),
        method_bound,
        "the method check precedes invalid UTF-8"
    );
    // A 4,097 B field, an unknown key and invalid UTF-8 are invalid_request.
    let long_tz = json!({"tz": long_field, "now_ms": T}).to_string();
    assert_eq!(
        code(&live.call("today_snapshot", &long_tz)).0,
        "invalid_request"
    );
    assert_eq!(
        code(&live.call("list_sources", "{\"x\":1}")).0,
        "invalid_request"
    );
    let method = CString::new("list_sources")?;
    let response: Value = serde_json::from_str(&text(unsafe {
        quotern_call(
            live.engine,
            method.as_ptr(),
            bad_utf8.as_ptr(),
            std::ptr::null(),
        )
    }))?;
    assert_eq!(code(&response).0, "invalid_request");
    // NULL engine is invalid.
    let request = CString::new("{}")?;
    let response: Value = serde_json::from_str(&text(unsafe {
        quotern_call(
            std::ptr::null_mut(),
            method.as_ptr(),
            request.as_ptr(),
            std::ptr::null(),
        )
    }))?;
    assert_eq!(code(&response).0, "invalid_request");
    assert!(
        !world.data().exists(),
        "every rejection leaves the store unchanged"
    );
    Ok(())
}

#[test]
fn abi_version_and_null_safety() {
    assert_eq!(quotern_abi_version(), 1);
    unsafe {
        quotern_engine_close(std::ptr::null_mut());
        quotern_cancel_trigger(std::ptr::null());
        quotern_cancel_free(std::ptr::null_mut());
        quotern_string_free(std::ptr::null_mut());
    }
    let response: Value = serde_json::from_str(&text(unsafe {
        quotern_engine_open(std::ptr::null(), std::ptr::null_mut())
    }))
    .unwrap();
    assert_eq!(code(&response).0, "invalid_request");
}

#[test]
fn cancel_from_other_thread_during_ingest() -> TestResult {
    let world = World::with_source(&daily_rows())?;
    let live = world.live();
    live.select(&world.source());
    let id = live.id_of("source");
    let before = live.snapshot();
    let token = quotern_cancel_new();
    // The token is triggered from another thread before the call: the pass stops at its first
    // poll, like a budget stop, and commits no partial group.
    let address = token as usize;
    std::thread::spawn(move || unsafe { quotern_cancel_trigger(address as *const QuoternCancel) })
        .join()
        .unwrap();
    let cancelled = live.call_with("ingest", &json!({"now_ms": T}).to_string(), token);
    assert_eq!(code(&cancelled), ("cancelled", "cancelled", true));
    assert_eq!(
        golden("error-cancelled.json")?,
        cancelled,
        "the live cancelled envelope equals its golden"
    );
    unsafe { quotern_cancel_free(token) };
    let after_cancel = live.snapshot();
    let reported = reported_of(&after_cancel, &id);
    assert_eq!(
        (&reported["records"], &reported["input"]["value"]),
        (&json!(0), &Value::Null),
        "nothing published"
    );
    assert_eq!(after_cancel, before, "the snapshot is unchanged");
    // The next ingest converges to the oracle; replay adds nothing.
    live.ingest(T);
    assert_eq!(live.input(&id), json!(ORACLE_A));
    live.ingest(T + 1);
    assert_eq!(live.input(&id), json!(ORACLE_A));

    // In flight: after the pass's first whole SQLite group, a joined second thread triggers the
    // token. Exactly that group is published and the next ingest converges.
    let world = World::with_source(&daily_rows())?;
    let live = world.live();
    assert_eq!(live.select(&world.source())["ok"], json!(true));
    let id = live.id_of("source");
    let token = quotern_cancel_new();
    let address = token as usize;
    quotern_core::adapters::opencode::set_transaction_hook(Some(Box::new(move || {
        std::thread::spawn(move || unsafe {
            quotern_cancel_trigger(address as *const QuoternCancel)
        })
        .join()
        .expect("trigger thread");
    })));
    let cancelled = live.call_with("ingest", &json!({"now_ms": T}).to_string(), token);
    quotern_core::adapters::opencode::set_transaction_hook(None);
    unsafe { quotern_cancel_free(token) };
    assert_eq!(
        golden("error-cancelled.json")?,
        cancelled,
        "in flight: exactly the cancelled golden"
    );
    // rows.json `derived` is the first group: one record, input 10.
    let immediate = reported_of(&live.snapshot(), &id);
    assert_eq!(
        (&immediate["records"], &immediate["input"]["value"]),
        (&json!(1), &json!(10)),
        "the immediate snapshot holds exactly the first group: {immediate}"
    );
    live.ingest(T);
    assert_eq!(live.input(&id), json!(ORACLE_A));
    live.ingest(T + 1);
    assert_eq!(live.input(&id), json!(ORACLE_A), "replay adds zero");
    Ok(())
}

/// Goldens the live comparisons here consumed in this process.
static CONSUMED: std::sync::Mutex<std::collections::BTreeSet<String>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

fn golden(name: &str) -> TestResult<Value> {
    CONSUMED.lock().unwrap().insert(name.to_owned());
    Ok(serde_json::from_slice(&std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../Contracts/bridge-v1")
            .join(name),
    )?)?)
}

/// The goldens contract_v1.rs inventories as consumed here, recorded by running their comparisons.
#[test]
fn ownership_goldens_are_consumed_by_live_comparisons() -> TestResult {
    cancel_from_other_thread_during_ingest()?;
    two_root_panic_rollback_queued_failure_reopen()?;
    assert_eq!(
        CONSUMED.lock().unwrap().clone(),
        std::collections::BTreeSet::from(
            [
                "error-cancelled.json",
                "error-engine-failed.json",
                "error-internal-panic.json",
            ]
            .map(String::from)
        )
    );
    Ok(())
}

#[test]
fn missing_root_returns_and_reattaches() -> TestResult {
    let world = World::new()?;
    let (root_a, root_b, root_c) = (world.named("a"), world.named("b"), world.named("c"));
    build_source(&root_a, &daily_rows())?;
    build_source(&root_b, &rows_b())?;
    build_source(&root_c, &rows_c())?;
    let (id_a, id_b, id_c, last_success, status_before, entry_c, reported_c, reported_a);
    let rows_c_before;
    {
        let live = world.live();
        for root in [&root_a, &root_b, &root_c] {
            assert_eq!(live.select(root)["ok"], json!(true));
        }
        assert_eq!(live.deselect(&root_c)["ok"], json!(true), "C is denied");
        live.ingest(T);
        (id_a, id_b, id_c) = (live.id_of("a"), live.id_of("b"), live.id_of("c"));
        let snapshot = live.snapshot();
        assert_eq!(
            without_id(reported_of(&snapshot, &id_a)),
            full_oracle_a(),
            "A's hand oracle"
        );
        assert_eq!(
            without_id(reported_of(&snapshot, &id_b)),
            full_oracle_b(),
            "B's hand oracle"
        );
        let entry_b = entry_of(&snapshot["data"]["by_source"], &id_b);
        last_success = entry_b["last_success_ms"].clone();
        assert_eq!(last_success, json!(T));
        status_before = status_row(&world.data(), &id_b)?;
        entry_c = entry_of(&snapshot["data"]["by_source"], &id_c);
        assert_eq!(entry_c["consent"], json!("denied"));
        reported_c = reported_of(&snapshot, &id_c);
        reported_a = reported_of(&snapshot, &id_a);
        rows_c_before = durable_rows(&world.data(), &id_c)?;
        assert!(!rows_c_before["sources"].is_empty(), "C's row exists");
    }
    let parked = world.named("parked-b");
    std::fs::rename(&root_b, &parked)?;
    std::fs::remove_dir_all(&root_c)?;

    // No source open ever touches C's path while the handle reopens and ingests.
    let c_opens = std::rc::Rc::new(std::cell::Cell::new(0_usize));
    let (counter, watched) = (std::rc::Rc::clone(&c_opens), root_c.clone());
    quotern_core::ingest::sqlite_ro::set_open_hook(Some(Box::new(move |path, _flags| {
        if path.starts_with(&watched) {
            counter.set(counter.get() + 1);
        }
    })));
    let live = world.live();
    let expected_b = |attempt: Value, error: &str| {
        json!({"consent": "enabled", "outcome": "unavailable", "last_error_code": error,
            "last_attempt_ms": attempt, "last_success_ms": last_success})
    };
    let project = |entry: &Value| {
        json!({"consent": entry["consent"], "outcome": entry["outcome"], "last_error_code": entry["last_error_code"],
            "last_attempt_ms": entry["last_attempt_ms"], "last_success_ms": entry["last_success_ms"]})
    };
    // Before any ingest: A attached and exact, B overlaid, C untouched.
    let listed = live.sources();
    let snapshot = live.snapshot();
    for entries in [&listed["data"]["sources"], &snapshot["data"]["by_source"]] {
        assert_eq!(
            project(&entry_of(entries, &id_b)),
            expected_b(Value::Null, "root_invalid")
        );
        assert_eq!(
            entry_of(entries, &id_c),
            entry_c,
            "C is unchanged and costs no I/O"
        );
        assert_eq!(entry_of(entries, &id_a)["last_error_code"], Value::Null);
    }
    assert_eq!(
        reported_of(&snapshot, &id_a),
        reported_a,
        "A is attached and exact"
    );
    assert_eq!(
        without_id(reported_of(&snapshot, &id_b)),
        full_oracle_b(),
        "B's durable oracle"
    );
    assert_eq!(reported_of(&snapshot, &id_c), reported_c);
    let baseline = history_descriptors(&world.data());
    assert!(baseline > 0, "the handle holds the store");
    // Mandatory control: an extra Store::open is seen by the probe.
    {
        let extra = quotern_core::store::Store::open(&world.data())?;
        assert!(
            history_descriptors(&world.data()) > baseline,
            "the probe sees an extra Store"
        );
        drop(extra);
    }
    // The independent `status_row` reads below park a closed descriptor on the inode while the
    // handle holds its WAL-mode lock, so "no second Store" is the per-ingest delta, not a
    // whole-test total.
    let ingest_adds_no_descriptor = |now_ms: i64| {
        let before = history_descriptors(&world.data());
        live.ingest(now_ms);
        assert_eq!(
            history_descriptors(&world.data()),
            before,
            "ingest at {now_ms} opens no second Store"
        );
    };

    // Ingest at t1: one reattach attempt, replay adds zero, C and B's status row untouched.
    let t1 = T + 5;
    ingest_adds_no_descriptor(t1);
    let after = live.snapshot();
    assert_eq!(
        project(&entry_of(&after["data"]["by_source"], &id_b)),
        expected_b(json!(t1), "root_invalid")
    );
    assert_eq!(reported_of(&after, &id_a), reported_a, "replay adds zero");
    assert_eq!(
        entry_of(&after["data"]["by_source"], &id_c),
        entry_c,
        "C's SourceEntry is byte-equal"
    );
    assert_eq!(reported_of(&after, &id_c), reported_c);
    assert_eq!(without_id(reported_of(&after, &id_b)), full_oracle_b());
    quotern_core::ingest::sqlite_ro::set_open_hook(None);
    assert_eq!(c_opens.get(), 0, "no source open under C's path");
    assert_eq!(
        durable_rows(&world.data(), &id_c)?,
        rows_c_before,
        "C's durable rows are byte-equal by SQL"
    );
    assert_eq!(
        status_row(&world.data(), &id_b)?,
        status_before,
        "B's durable status row is unchanged"
    );

    // Root-swap negative at t2: a different directory at B's path with an extra record.
    let mut swapped_rows = rows_b();
    swapped_rows.push(message("extra", 1_000, T + 2));
    build_source(&root_b, &swapped_rows)?;
    let t2 = T + 10;
    ingest_adds_no_descriptor(t2);
    let swapped = live.snapshot();
    assert_eq!(
        project(&entry_of(&swapped["data"]["by_source"], &id_b)),
        expected_b(json!(t2), "source_overlap_conflict")
    );
    assert_eq!(
        without_id(reported_of(&swapped, &id_b)),
        full_oracle_b(),
        "the extra record is never counted"
    );
    assert_eq!(status_row(&world.data(), &id_b)?, status_before);

    // Positive control at t3: the swap is removed and the original returns.
    std::fs::remove_dir_all(&root_b)?;
    std::fs::rename(&parked, &root_b)?;
    let t3 = T + 15;
    ingest_adds_no_descriptor(t3);
    let restored = live.snapshot();
    let entry_b = entry_of(&restored["data"]["by_source"], &id_b);
    assert_eq!(
        entry_b["last_error_code"],
        Value::Null,
        "the overlay is gone"
    );
    assert_eq!(entry_b["last_attempt_ms"], json!(t3));
    assert_ne!(entry_b["outcome"], json!("unavailable"));
    assert_eq!(
        without_id(reported_of(&restored, &id_b)),
        full_oracle_b(),
        "B equals its oracle, replay adds zero"
    );
    assert_eq!(reported_of(&restored, &id_a), reported_a);
    assert_eq!(
        durable_rows(&world.data(), &id_c)?,
        rows_c_before,
        "C's rows stay byte-equal"
    );
    Ok(())
}

#[test]
fn second_attach_refuses_swapped_data_root() -> TestResult {
    for variant in ["directory", "symlink"] {
        let world = World::new()?;
        let (root_a, root_b) = (world.named("a"), world.named("b"));
        build_source(&root_a, &daily_rows())?;
        build_source(&root_b, &rows_b())?;
        let live = world.live();
        assert_eq!(live.select(&root_a)["ok"], json!(true));
        live.ingest(T);
        let id_a = live.id_of("a");
        let (tree_a, tree_b) = (tree_image(&root_a), tree_image(&root_b));

        let parked = world.named("parked-data");
        std::fs::rename(world.data(), &parked)?;
        let replacement = world.named("other-data");
        std::fs::create_dir(&replacement)?;
        if variant == "directory" {
            std::fs::rename(&replacement, world.data())?;
        } else {
            symlink(&replacement, world.data())?;
        }
        let refused = live.select(&root_b);
        assert_eq!(
            code(&refused),
            ("store_corrupt", "store corrupt", false),
            "{variant}: {refused}"
        );
        assert!(
            tree_image(&replacement).is_empty(),
            "{variant}: nothing is created in the replacement"
        );
        assert_eq!(
            tree_image(&root_a),
            tree_a,
            "{variant}: A's source is untouched"
        );
        assert_eq!(
            tree_image(&root_b),
            tree_b,
            "{variant}: B's source is untouched"
        );
        assert_eq!(
            live.sources()["data"]["sources"].as_array().unwrap().len(),
            1,
            "{variant}: B was not registered"
        );

        // A stays intact: restore the layout and ingest.
        if variant == "directory" {
            std::fs::remove_dir(world.data())?;
        } else {
            std::fs::remove_file(world.data())?;
        }
        std::fs::rename(&parked, world.data())?;
        live.ingest(T + 1);
        assert_eq!(live.input(&id_a), json!(ORACLE_A), "{variant}");
        assert_eq!(
            live.select(&root_b)["ok"],
            json!(true),
            "{variant}: control"
        );
    }
    Ok(())
}

#[test]
fn two_roots_share_one_store_with_independent_totals() -> TestResult {
    use quotern_core::store::Store;
    let world = World::new()?;
    let (root_a, root_b) = (world.named("a"), world.named("b"));
    build_source(&root_a, &daily_rows())?;
    build_source(&root_b, &rows_b())?;
    let live = world.live();
    assert_eq!(live.select(&root_a)["ok"], json!(true));
    live.ingest(T);
    let baseline = history_descriptors(&world.data());
    assert!(baseline > 0, "the handle holds the store");
    // Mandatory control: an extra Store::open raises the count, so the probe can see a second
    // Store. SQLite parks a closed duplicate's descriptor on the inode while the handle still
    // holds its WAL-mode lock, so the count is re-read once the control is dropped.
    {
        let extra = Store::open(&world.data())?;
        assert!(
            history_descriptors(&world.data()) > baseline,
            "the probe sees an extra Store"
        );
        drop(extra);
    }
    let settled = history_descriptors(&world.data());
    assert!(settled >= baseline);
    assert_eq!(live.select(&root_b)["ok"], json!(true));
    live.ingest(T + 1);
    assert_eq!(
        history_descriptors(&world.data()),
        settled,
        "two roots add no descriptor"
    );
    let (id_a, id_b) = (live.id_of("a"), live.id_of("b"));
    let snapshot = live.snapshot();
    assert_eq!(
        reported_of(&snapshot, &id_a)["input"]["value"],
        json!(ORACLE_A)
    );
    assert_eq!(
        reported_of(&snapshot, &id_b)["input"]["value"],
        json!(ORACLE_B)
    );
    assert_eq!(reported_of(&snapshot, &id_a)["records"], json!(4));
    assert_eq!(
        reported_of(&snapshot, &id_b)["records"],
        json!(2),
        "never pooled"
    );
    Ok(())
}

/// Blocks the calling thread's next source open of `root` until a waiter queues behind the
/// engine lock, then lets it proceed. `arm_panic` also arms the next-transaction panic first.
/// The returned flag records whether a queued waiter was observed before the deadline.
fn hold_source_open(
    root: PathBuf,
    engine: usize,
    arm_panic: bool,
    entered: std::sync::mpsc::Sender<()>,
) -> std::rc::Rc<std::cell::Cell<bool>> {
    let queued = std::rc::Rc::new(std::cell::Cell::new(false));
    let seen = std::rc::Rc::clone(&queued);
    let mut fired = false;
    quotern_core::ingest::sqlite_ro::set_open_hook(Some(Box::new(move |path, _flags| {
        if fired || !path.starts_with(&root) {
            return;
        }
        fired = true;
        if arm_panic {
            quotern_core::store::panic_next_commit();
        }
        let _ = entered.send(());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while std::time::Instant::now() < deadline {
            if unsafe { quotern_ffi::queued_waiters(engine as *const QuoternEngine) } > 0 {
                seen.set(true);
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    })));
    queued
}

#[test]
fn two_root_panic_rollback_queued_failure_reopen() -> TestResult {
    let world = World::new()?;
    let (root_a, root_b) = (world.named("a"), world.named("b"));
    build_source(&root_a, &daily_rows())?;
    build_source(&root_b, &rows_b())?;
    let live = world.live();
    live.select(&root_a);
    live.select(&root_b);
    live.ingest(T);
    let (id_a, id_b) = (live.id_of("a"), live.id_of("b"));
    let before = live.snapshot();
    assert_eq!(
        reported_of(&before, &id_a)["input"]["value"],
        json!(ORACLE_A)
    );
    assert_eq!(
        reported_of(&before, &id_b)["input"]["value"],
        json!(ORACLE_B)
    );
    // B gains a record, so its pass has a transaction to commit.
    add_rows(&root_b, &[message("b3", 7, T + 2_000)])?;

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let address = live.engine as usize;
    let waiter = std::thread::spawn(move || {
        entered_rx.recv().expect("the pass entered B");
        reset_counters();
        let method = CString::new("list_sources").unwrap();
        let request = CString::new("{}").unwrap();
        let response: Value = serde_json::from_str(&text(unsafe {
            quotern_call(
                address as *mut QuoternEngine,
                method.as_ptr(),
                request.as_ptr(),
                std::ptr::null(),
            )
        }))
        .unwrap();
        (response, counters())
    });
    let queued_seen = hold_source_open(root_b.clone(), address, true, entered_tx);
    reset_counters();
    let panic = live.ingest(T + 3_000);
    quotern_core::ingest::sqlite_ro::set_open_hook(None);
    assert!(
        queued_seen.get(),
        "a waiter was observed queued behind the lock before the deadline"
    );
    assert_eq!(
        code(&panic),
        ("internal_panic", "internal panic", false),
        "{panic}"
    );
    assert_eq!(
        golden("error-internal-panic.json")?,
        panic,
        "equals its golden"
    );
    let (queued, io) = waiter.join().unwrap();
    assert_eq!(
        code(&queued),
        ("engine_failed", "engine failed", false),
        "the queued waiter never dispatches"
    );
    assert_eq!(
        golden("error-engine-failed.json")?,
        queued,
        "equals its golden"
    );
    assert_eq!(io, (0, 0), "the queued waiter did no I/O");
    for method in ["list_sources", "today_snapshot"] {
        let later = live.call(method, "{}");
        assert_eq!(
            code(&later),
            ("engine_failed", "engine failed", false),
            "{method}"
        );
    }
    drop(live); // close without locking the poisoned state

    let reopened = world.live();
    let after = reopened.snapshot();
    assert_eq!(
        reported_of(&after, &id_a),
        reported_of(&before, &id_a),
        "A is unchanged by the panic"
    );
    assert_eq!(
        reported_of(&after, &id_b),
        reported_of(&before, &id_b),
        "B's transaction rolled back"
    );
    reopened.ingest(T + 4_000);
    let converged = reopened.snapshot();
    assert_eq!(reported_of(&converged, &id_a), reported_of(&before, &id_a));
    assert_eq!(
        reported_of(&converged, &id_b)["input"]["value"],
        json!(ORACLE_B + 7),
        "the new record counts once"
    );
    reopened.ingest(T + 5_000);
    assert_eq!(
        reported_of(&reopened.snapshot(), &id_b),
        reported_of(&converged, &id_b),
        "replay adds zero"
    );
    Ok(())
}

#[test]
fn failed_handle_error_precedence() -> TestResult {
    fn raw(engine: *mut QuoternEngine, method: Option<&[u8]>, request: Option<&[u8]>) -> Value {
        let method = method.map(|bytes| CString::new(bytes).unwrap());
        let request = request.map(|bytes| CString::new(bytes).unwrap());
        serde_json::from_str(&text(unsafe {
            quotern_call(
                engine,
                method
                    .as_ref()
                    .map_or(std::ptr::null(), |text| text.as_ptr()),
                request
                    .as_ref()
                    .map_or(std::ptr::null(), |text| text.as_ptr()),
                std::ptr::null(),
            )
        }))
        .unwrap()
    }
    let over = vec![b'a'; 65_537];
    let long_method = vec![b'm'; 65];
    type Raw<'a> = Option<&'a [u8]>;
    let cases: [(Raw, Raw); 6] = [
        (None, Some(b"{}")),
        (Some(b"list_sources"), None),
        (Some(b"no_such_method"), Some(b"{}")),
        (Some(&long_method), Some(b"{}")),
        (Some(b"list_sources"), Some(&[0xff])),
        (Some(b"list_sources"), Some(&over)),
    ];
    // Healthy controls keep their own codes.
    let healthy_world = World::new()?;
    let healthy = healthy_world.live();
    let healthy_codes: Vec<String> = cases
        .iter()
        .map(|(method, request)| code(&raw(healthy.engine, *method, *request)).0.to_owned())
        .collect();
    assert_eq!(
        healthy_codes,
        [
            "invalid_request",
            "invalid_request",
            "unknown_method",
            "limit_exceeded",
            "invalid_request",
            "limit_exceeded"
        ]
    );

    let world = World::with_source(&daily_rows())?;
    let live = world.live();
    live.select(&world.source());
    live.ingest(T);
    quotern_core::store::panic_next_commit();
    assert_eq!(code(&live.ingest(T + 1)).0, "internal_panic");
    reset_counters();
    for (index, (method, request)) in cases.iter().enumerate() {
        let response = raw(live.engine, *method, *request);
        assert_eq!(
            code(&response),
            ("engine_failed", "engine failed", false),
            "case {index}"
        );
    }
    assert_eq!(
        counters(),
        (0, 0),
        "no dispatch and no I/O on a failed handle"
    );
    assert_eq!(unsafe { quotern_ffi::queued_waiters(live.engine) }, 0);
    // A NULL engine is checked before the failed flag.
    assert_eq!(
        code(&raw(
            std::ptr::null_mut(),
            Some(b"list_sources"),
            Some(b"{}")
        ))
        .0,
        "invalid_request"
    );
    Ok(())
}

#[test]
fn first_attach_store_failure_maps_exact_code() -> TestResult {
    // (1) A 0555 data-dir parent: no history exists, nothing is created. Root ignores the mode.
    assert!(
        !root_euid_is_zero(),
        "the 0555 parent case requires euid != 0"
    );
    {
        let world = World::with_source(&daily_rows())?;
        let parent = world.named("locked");
        std::fs::create_dir(&parent)?;
        set_mode(&parent, 0o555)?;
        let data = parent.join("data");
        let source_before = tree_image(&world.source());
        let live = open_with(&world.config_for(&data))
            .0
            .expect("open creates nothing");
        let refused = live.select(&world.source());
        assert_eq!(
            code(&refused),
            ("store_corrupt", "store corrupt", false),
            "{refused}"
        );
        assert!(!data.exists(), "no data dir");
        assert_eq!(live.sources()["data"], json!({"sources": []}));
        assert_eq!(
            tree_image(&world.source()),
            source_before,
            "source digests unchanged"
        );
        drop(live);
        set_mode(&parent, 0o755)?;
    }

    // (2) user_version 99 history placed after open: store_newer_version, and the failed handle
    // keeps its owner claim with store None until close.
    let world = World::with_source(&daily_rows())?;
    let source_before = tree_image(&world.source());
    let first = world.live();
    std::fs::create_dir(world.data())?;
    {
        let connection = Connection::open(world.data().join("history.sqlite"))?;
        connection.execute_batch("PRAGMA user_version = 99; CREATE TABLE marker(x INTEGER);")?;
    }
    let image = history_image(&world.data());
    let refused = first.select(&world.source());
    assert_eq!(
        code(&refused),
        ("store_newer_version", "store newer version", false),
        "{refused}"
    );
    assert_eq!(
        history_image(&world.data()),
        image,
        "history bytes unchanged"
    );
    assert_eq!(
        first.sources()["data"],
        json!({"sources": []}),
        "store None"
    );
    assert_eq!(tree_image(&world.source()), source_before);

    reset_counters();
    let (second, busy) = world.open();
    assert!(second.is_none());
    assert_eq!(
        code(&busy),
        ("store_busy", "store busy", true),
        "the failed handle keeps its claim: {busy}"
    );
    assert_eq!(counters(), (0, 0));
    assert_eq!(first.sources()["data"], json!({"sources": []}));

    let released = std::rc::Rc::new(std::cell::Cell::new(usize::MAX));
    let probe = (std::rc::Rc::clone(&released), world.data());
    quotern_core::store::set_owner_release_hook(Some(Box::new(move || {
        probe.0.set(history_descriptors(&probe.1))
    })));
    drop(first);
    quotern_core::store::set_owner_release_hook(None);
    assert_eq!(
        released.get(),
        0,
        "the release hook sees no history/-wal/-shm descriptor"
    );
    let (second, response) = world.open();
    assert!(second.is_none());
    assert_eq!(
        code(&response),
        ("store_newer_version", "store newer version", false),
        "never store_busy"
    );
    assert_eq!(
        history_image(&world.data()),
        image,
        "nothing repairs history"
    );
    Ok(())
}

// ---- containment before writes ---------------------------------------------------------------

const HISTORY_FILES: [&str; 4] = [
    "history.sqlite",
    "history.sqlite-wal",
    "history.sqlite-shm",
    "history.sqlite-journal",
];

/// The three layouts of `reopen_refuses_overlapping_root_without_writes`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Overlap {
    /// (a) A's root replaced by a symlink to an ancestor of the data dir.
    RootToAncestor,
    /// (b) the data dir moved inside A's root, its configured path now a symlink to it.
    DataInsideRoot,
    /// (c) A's root at S/x/A, the data dir's files moved into S and its path a symlink to S, A
    /// then missing.
    RootInsideDataMissing,
    /// (c) as above with `S/x` mode 0000.
    RootInsideDataUnreadable,
}

impl Overlap {
    const ALL: [Self; 4] = [
        Self::RootToAncestor,
        Self::DataInsideRoot,
        Self::RootInsideDataMissing,
        Self::RootInsideDataUnreadable,
    ];
    fn inside_data(self) -> bool {
        matches!(
            self,
            Self::RootInsideDataMissing | Self::RootInsideDataUnreadable
        )
    }
}

/// A closed history with root A selected and ingested, ready to be re-laid-out.
struct Overlapped {
    world: World,
    case: Overlap,
    root: PathBuf,
    id: String,
}

impl Overlapped {
    fn new(case: Overlap) -> TestResult<Self> {
        let world = World::new()?;
        let root = if case.inside_data() {
            world.named("s").join("x").join("a")
        } else {
            world.named("a")
        };
        build_source(&root, &daily_rows())?;
        let id = {
            let live = world.live();
            assert_eq!(live.select(&root)["ok"], json!(true));
            live.ingest(T);
            live.id_of("a")
        };
        Ok(Self {
            world,
            case,
            root,
            id,
        })
    }

    /// Where the history files live while the layout is applied.
    fn history_dir(&self) -> PathBuf {
        match self.case {
            Overlap::RootToAncestor => self.world.data(),
            Overlap::DataInsideRoot => self.root.join("moved-data"),
            Overlap::RootInsideDataMissing | Overlap::RootInsideDataUnreadable => {
                self.world.named("s")
            }
        }
    }

    /// Where A's database is while the layout is applied (none when it cannot be read).
    fn source_db_path(&self) -> Option<PathBuf> {
        match self.case {
            Overlap::RootToAncestor => Some(self.world.named("a-parked").join("opencode.db")),
            Overlap::DataInsideRoot => Some(self.root.join("opencode.db")),
            Overlap::RootInsideDataMissing => Some(self.world.named("a-gone").join("opencode.db")),
            Overlap::RootInsideDataUnreadable => None,
        }
    }

    fn apply(&self) -> TestResult {
        let world = &self.world;
        match self.case {
            Overlap::RootToAncestor => {
                std::fs::rename(&self.root, world.named("a-parked"))?;
                symlink(&world.base, &self.root)?;
            }
            Overlap::DataInsideRoot => {
                let moved = self.history_dir();
                std::fs::rename(world.data(), &moved)?;
                symlink(&moved, world.data())?;
            }
            Overlap::RootInsideDataMissing | Overlap::RootInsideDataUnreadable => {
                let s = self.history_dir();
                for name in HISTORY_FILES {
                    if std::fs::symlink_metadata(world.data().join(name)).is_ok() {
                        std::fs::rename(world.data().join(name), s.join(name))?;
                    }
                }
                std::fs::remove_dir(world.data())?;
                symlink(&s, world.data())?;
                if self.case == Overlap::RootInsideDataMissing {
                    std::fs::rename(&self.root, world.named("a-gone"))?;
                } else {
                    set_mode(&s.join("x"), 0)?;
                }
            }
        }
        Ok(())
    }

    /// Undoes the data directory part of the layout.
    fn undo_data(&self) -> TestResult {
        let world = &self.world;
        match self.case {
            Overlap::RootToAncestor => {}
            Overlap::DataInsideRoot => {
                std::fs::remove_file(world.data())?;
                std::fs::rename(self.history_dir(), world.data())?;
            }
            Overlap::RootInsideDataMissing | Overlap::RootInsideDataUnreadable => {
                let s = self.history_dir();
                std::fs::remove_file(world.data())?;
                std::fs::create_dir(world.data())?;
                for name in HISTORY_FILES {
                    if std::fs::symlink_metadata(s.join(name)).is_ok() {
                        std::fs::rename(s.join(name), world.data().join(name))?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Undoes the root part of the layout.
    fn undo_root(&self) -> TestResult {
        let world = &self.world;
        match self.case {
            Overlap::RootToAncestor => {
                std::fs::remove_file(&self.root)?;
                std::fs::rename(world.named("a-parked"), &self.root)?;
            }
            Overlap::DataInsideRoot => {}
            Overlap::RootInsideDataMissing => std::fs::rename(world.named("a-gone"), &self.root)?,
            Overlap::RootInsideDataUnreadable => set_mode(&world.named("s").join("x"), 0o755)?,
        }
        Ok(())
    }

    /// The write-capability witness: a directory 0555 and history files 0444, so a write-capable
    /// open of history fails and cannot hide behind a successful write.
    fn set_witness(&self, on: bool) -> TestResult {
        let (directory, file) = if on { (0o555, 0o444) } else { (0o755, 0o644) };
        set_mode(&self.history_dir(), directory)?;
        for name in HISTORY_FILES {
            let path = self.history_dir().join(name);
            if std::fs::symlink_metadata(&path).is_ok() {
                set_mode(&path, file)?;
            }
        }
        Ok(())
    }

    /// One refused open. `Err` names the first check the single assertion helper failed.
    fn refused_open(
        &self,
        witness: bool,
        forbidden_write_mutant: bool,
    ) -> TestResult<Result<(), String>> {
        self.apply()?;
        if witness {
            assert!(!root_euid_is_zero(), "the witness needs euid != 0");
            self.set_witness(true)?;
        }
        let history = self.history_dir();
        let image = history_image(&history);
        let source_before = self.source_db_path().map(std::fs::read).transpose()?;
        let released = std::rc::Rc::new(std::cell::Cell::new(0_usize));
        let probe = (std::rc::Rc::clone(&released), history.clone());
        store::set_owner_release_hook(Some(Box::new(move || {
            probe
                .0
                .set(probe.0.get().max(history_descriptors(&probe.1)));
        })));
        reset_counters();
        if forbidden_write_mutant {
            // A write-capable open before admission, dropped, and then the same ABI open runs.
            drop(store::Store::open(&self.world.data()));
        }
        let (live, response) = self.world.open();
        store::set_owner_release_hook(None);
        let verdict = (|| {
            if live.is_some() {
                return Err("the open succeeded".to_owned());
            }
            if code(&response) != ("source_overlap_conflict", "source overlap conflict", false) {
                return Err(format!("outcome {response}"));
            }
            if store::writable_open_attempts() != 0 {
                return Err(format!(
                    "writable_open_attempts {}",
                    store::writable_open_attempts()
                ));
            }
            if history_image(&history) != image {
                return Err("history existence, (dev,ino) or bytes changed".to_owned());
            }
            if let (Some(before), Some(path)) = (&source_before, self.source_db_path())
                && std::fs::read(path).ok().as_ref() != Some(before)
            {
                return Err("the source database changed".to_owned());
            }
            if history_descriptors(&history) != 0 || released.get() != 0 {
                return Err("a history descriptor is held".to_owned());
            }
            Ok(())
        })();
        drop(live);
        if witness {
            self.set_witness(false)?;
        }
        Ok(verdict)
    }

    /// Restores the original layout and permissions: the open succeeds with exactly one writable
    /// open, A is reattached and exact, and replay adds zero. For (c) the disjoint layout opens
    /// while A is still away, and A's return is picked up by an ingest on that same handle.
    fn positive_control(&self) -> TestResult {
        self.undo_data()?;
        if self.case.inside_data() {
            // The disjoint layout is back while A stays missing (then unreadable): the open is
            // admitted and A is unattached, its error root_invalid.
            reset_counters();
            let live = self.world.live();
            assert_eq!(store::writable_open_attempts(), 1, "{:?}", self.case);
            assert_eq!(
                live.entry(&self.id)["last_error_code"],
                json!("root_invalid"),
                "{:?}",
                self.case
            );
            assert_eq!(
                live.entry(&self.id)["outcome"],
                json!("unavailable"),
                "{:?}",
                self.case
            );
            assert_eq!(
                live.input(&self.id),
                json!(ORACLE_A),
                "durable totals while A is away"
            );
            // A returns; an ingest on the still-open handle reattaches it, replay adding zero.
            self.undo_root()?;
            live.ingest(T + 1);
            let entry = live.entry(&self.id);
            assert_eq!(entry["last_error_code"], Value::Null, "{:?}", self.case);
            assert_ne!(entry["outcome"], json!("unavailable"), "{:?}", self.case);
            assert_eq!(
                live.input(&self.id),
                json!(ORACLE_A),
                "{:?}: reattached by ingest, replay adds zero",
                self.case
            );
            return Ok(());
        }
        self.undo_root()?;
        reset_counters();
        let live = self.world.live();
        assert_eq!(
            store::writable_open_attempts(),
            1,
            "{:?}: exactly one writable open",
            self.case
        );
        assert_eq!(
            live.input(&self.id),
            json!(ORACLE_A),
            "{:?}: A is reattached and exact",
            self.case
        );
        assert_eq!(
            live.entry(&self.id)["last_error_code"],
            Value::Null,
            "{:?}",
            self.case
        );
        live.ingest(T + 1);
        assert_eq!(
            live.input(&self.id),
            json!(ORACLE_A),
            "{:?}: replay adds zero",
            self.case
        );
        Ok(())
    }
}

#[test]
fn reopen_refuses_overlapping_root_without_writes() -> TestResult {
    assert!(
        !root_euid_is_zero(),
        "the permission witness needs euid != 0"
    );
    for case in Overlap::ALL {
        for witness in [true, false] {
            // The canonical product refuses with no writable open; the control then reopens.
            let scenario = Overlapped::new(case)?;
            let verdict = scenario.refused_open(witness, false)?;
            assert_eq!(verdict, Ok(()), "{case:?} witness={witness}");
            scenario.positive_control()?;

            // The forbidden-write mutant (public Store::open before admission) is rejected by the
            // SAME helper, on the writable-open count.
            let mutated = Overlapped::new(case)?;
            let verdict = mutated.refused_open(witness, true)?;
            let reason = verdict.expect_err("the forbidden-write mutant must be rejected");
            assert!(
                reason.starts_with("writable_open_attempts 1"),
                "{case:?} witness={witness}: {reason}"
            );
        }
    }
    Ok(())
}

// ---- admission recheck -----------------------------------------------------------------------

/// A filesystem that runs `swap` just before the `nth` canonicalization of `watch`: the interval
/// between admission's second root resolve and the writable open.
#[derive(Clone)]
struct LateFs {
    watch: PathBuf,
    nth: usize,
    seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    swap: std::sync::Arc<dyn Fn() + Send + Sync>,
}

impl LateFs {
    fn inert() -> Self {
        Self {
            watch: PathBuf::new(),
            nth: usize::MAX,
            seen: std::sync::Arc::default(),
            swap: std::sync::Arc::new(|| {}),
        }
    }
}

impl quotern_core::ingest::fs::SourceFs for LateFs {
    fn canonicalize(
        &self,
        path: &Path,
        counters: &mut quotern_core::domain::PassCounters,
    ) -> std::io::Result<PathBuf> {
        use quotern_core::ingest::fs::RealSourceFs;
        if path == self.watch
            && self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 == self.nth
        {
            (self.swap)();
        }
        RealSourceFs.canonicalize(path, counters)
    }

    fn metadata(
        &self,
        path: &Path,
        counters: &mut quotern_core::domain::PassCounters,
    ) -> std::io::Result<std::fs::Metadata> {
        use quotern_core::ingest::fs::RealSourceFs;
        RealSourceFs.metadata(path, counters)
    }

    fn read_dir(
        &self,
        path: &Path,
        counters: &mut quotern_core::domain::PassCounters,
    ) -> std::io::Result<quotern_core::ingest::fs::DirEntries> {
        use quotern_core::ingest::fs::RealSourceFs;
        RealSourceFs.read_dir(path, counters)
    }

    fn read_header(
        &self,
        path: &Path,
        counters: &mut quotern_core::domain::PassCounters,
    ) -> std::io::Result<Vec<u8>> {
        use quotern_core::ingest::fs::RealSourceFs;
        RealSourceFs.read_header(path, counters)
    }

    fn read_bounded(
        &self,
        path: &Path,
        max_bytes: usize,
        counters: &mut quotern_core::domain::PassCounters,
    ) -> std::io::Result<quotern_core::ingest::fs::BoundedRead> {
        use quotern_core::ingest::fs::RealSourceFs;
        RealSourceFs.read_bounded(path, max_bytes, counters)
    }

    fn open_sqlite(
        &self,
        path: &Path,
    ) -> Result<Connection, quotern_core::ingest::sqlite_ro::OpenError> {
        use quotern_core::ingest::fs::RealSourceFs;
        RealSourceFs.open_sqlite(path)
    }
}

type CoreEngine = quotern_core::ingest::Engine<LateFs>;

/// A closed history with root A selected and ingested.
fn closed_history() -> TestResult<(World, PathBuf, String)> {
    let world = World::nested()?;
    let root = world.named("a");
    build_source(&root, &daily_rows())?;
    let id = {
        let live = world.live();
        assert_eq!(live.select(&root)["ok"], json!(true));
        live.ingest(T);
        live.id_of("a")
    };
    Ok((world, root, id))
}

fn core_engine(world: &World) -> CoreEngine {
    CoreEngine::open(&world.data(), &world.home())
}

/// Commits one `sources` row through a separate connection (an unsupported outside writer).
/// The connection is returned and kept open by callers that need the commit to stay in `-wal`
/// (the last close of a database checkpoints it into the main file).
fn commit_source(data: &Path, id: &str, root: &Path, consent: &str) -> TestResult<Connection> {
    let connection = Connection::open(data.join("history.sqlite"))?;
    connection.execute(
        "INSERT INTO sources(source_id, harness, canonical_root, kind, consent) VALUES (?1, 'opencode', ?2, 'custom', ?3)",
        rusqlite::params![id, root.to_str().unwrap(), consent],
    )?;
    Ok(connection)
}

fn source_rows(data: &Path) -> TestResult<Vec<(String, String, String)>> {
    let connection = Connection::open_with_flags(
        data.join("history.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut statement = connection
        .prepare("SELECT source_id, canonical_root, consent FROM sources ORDER BY source_id")?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

const X_ID: &str = "ffffffffffffffffffffffffffffffff";

/// The role a child copy of this test binary plays: commit one row, then hold an uncommitted
/// transaction whose pages spill to `-wal`, report, and wait to be killed.
fn crashed_writer_child(history: &str) -> TestResult {
    use std::io::Write;
    let connection = Connection::open(history)?;
    connection.execute_batch("PRAGMA wal_autocheckpoint=0; PRAGMA cache_size=1;")?;
    connection.execute(
        "INSERT INTO sources(source_id, harness, canonical_root, kind, consent) VALUES ('dddddddddddddddddddddddddddddddd', 'opencode', '/committed', 'custom', 'denied')",
        [],
    )?;
    let committed = std::fs::metadata(format!("{history}-wal"))?.len();
    connection.execute_batch("BEGIN IMMEDIATE;")?;
    let mut index = 0_u32;
    while std::fs::metadata(format!("{history}-wal"))?.len() == committed {
        connection.execute(
            "INSERT INTO sources(source_id, harness, canonical_root, kind, consent) VALUES (?1, 'opencode', ?2, 'custom', 'enabled')",
            rusqlite::params![format!("{index:032x}"), format!("/uncommitted/{index}/{}", "p".repeat(512))],
        )?;
        index += 1;
        if index > 100_000 {
            return Err("no spill to -wal".into());
        }
    }
    println!("WRITER_SPILLED");
    std::io::stdout().flush()?;
    loop {
        std::thread::park();
    }
}

/// A child writer SIGKILLed inside an uncommitted transaction after its pages spilled to `-wal`:
/// the valid uncommitted tail is ignored, the open is admitted (count 1) and the committed rows
/// are retained.
fn crashed_writer_control() -> TestResult {
    use std::io::BufRead;
    let (world, _root, id) = closed_history()?;
    let history = world.data().join("history.sqlite");
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "admission_recheck_fails_closed_on_change",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("QUOTERN_CRASH_WRITER", &history)
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    let mut lines = std::io::BufReader::new(child.stdout.take().ok_or("child stdout")?).lines();
    let spilled = lines
        .by_ref()
        .any(|line| line.is_ok_and(|line| line.contains("WRITER_SPILLED")));
    child.kill()?; // SIGKILL inside the uncommitted transaction
    child.wait()?;
    assert!(spilled, "the child spilled uncommitted pages");
    let wal = std::fs::read(world.data().join("history.sqlite-wal"))?;
    let (_, frames) = wal_frames(&wal);
    let last_commit = frames
        .iter()
        .rposition(|&(_, commit)| commit)
        .ok_or("a commit frame")?;
    assert!(
        last_commit + 1 < frames.len(),
        "frames past the last commit frame: {} of {}",
        frames.len() - last_commit - 1,
        frames.len()
    );
    reset_counters();
    let live = world.live();
    assert_eq!(store::writable_open_attempts(), 1, "admitted at count 1");
    assert_eq!(live.input(&id), json!(ORACLE_A), "the committed oracle");
    drop(live);
    let mut committed = vec![id, "d".repeat(32)];
    committed.sort();
    let rows: Vec<String> = source_rows(&world.data())?
        .into_iter()
        .map(|row| row.0)
        .collect();
    assert_eq!(rows, committed, "committed rows only");
    Ok(())
}

#[test]
fn admission_recheck_fails_closed_on_change() -> TestResult {
    use store::AdmissionPoint;
    use store::StoreError;
    if let Ok(history) = std::env::var("QUOTERN_CRASH_WRITER") {
        return crashed_writer_child(&history);
    }

    // (1) A root swapped to an ancestor of the data dir after admission's resolve and before the
    // recheck: RootOverlap, store None, no writable open, files unchanged.
    {
        let (world, root, _id) = closed_history()?;
        let image = history_image(&world.data());
        let (base, swapped, parked) = (world.outer(), root.clone(), world.named("a-parked"));
        let fs = LateFs {
            watch: root.clone(),
            nth: 2,
            seen: std::sync::Arc::default(),
            swap: std::sync::Arc::new(move || {
                std::fs::rename(&swapped, &parked).expect("park");
                symlink(&base, &swapped).expect("alias to an ancestor");
            }),
        };
        reset_counters();
        let mut engine = core_engine(&world);
        assert_eq!(
            engine.load_existing(&fs).err(),
            Some(StoreError::RootOverlap)
        );
        assert!(engine.store().is_none());
        assert_eq!(store::writable_open_attempts(), 0);
        assert_eq!(history_image(&world.data()), image, "files unchanged");
    }

    // (2) A `sources` row committed by a separate connection between admission and recheck.
    {
        let (world, _root, _id) = closed_history()?;
        let other = world.named("x");
        std::fs::create_dir(&other)?;
        let injected = std::rc::Rc::new(std::cell::RefCell::new(None));
        let (data, hook_image, hook_other) =
            (world.data(), std::rc::Rc::clone(&injected), other.clone());
        let writers = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let kept = std::rc::Rc::clone(&writers);
        store::set_admission_hook(Some(Box::new(move |point| {
            if point == AdmissionPoint::AfterAdmission && hook_image.borrow().is_none() {
                kept.borrow_mut().push(
                    commit_source(&data, X_ID, &hook_other, "enabled").expect("outside commit"),
                );
                *hook_image.borrow_mut() = Some(history_image(&data));
            }
        })));
        reset_counters();
        let mut engine = core_engine(&world);
        let refused = engine.load_existing(&LateFs::inert());
        store::set_admission_hook(None);
        assert_eq!(refused.err(), Some(StoreError::Busy));
        assert!(engine.store().is_none());
        assert_eq!(store::writable_open_attempts(), 0);
        assert_eq!(
            Some(history_image(&world.data())),
            injected.borrow().clone(),
            "no effect beyond the injection"
        );
        // The next load admits and reads the new row.
        engine.load_existing(&LateFs::inert())?;
        assert!(engine.store().is_some());
        assert!(engine.enabled_source_ids()?.iter().any(|id| id == X_ID));
        drop(writers);
    }

    // (3) Control: nothing changes -- one writable open and equal history rows.
    {
        let (world, _root, id) = closed_history()?;
        let rows = source_rows(&world.data())?;
        reset_counters();
        let mut engine = core_engine(&world);
        engine.load_existing(&LateFs::inert())?;
        assert!(engine.store().is_some());
        assert_eq!(store::writable_open_attempts(), 1);
        assert_eq!(source_rows(&world.data())?, rows);
        assert_eq!(engine.enabled_source_ids()?, vec![id]);
    }
    crashed_writer_control()?;
    recheck_injections()
}

/// Outside commits at each hook point, with `-wal` absent and present, each enabling a data-dir
/// ancestor root: store_busy with nothing opened writable, then source_overlap_conflict on the
/// hook-free retry. Also the checkpoint-truncate window and the commit after the recheck.
fn recheck_injections() -> TestResult {
    use store::{AdmissionPoint, StoreError};
    let wal_len = |data: &Path| std::fs::metadata(data.join("history.sqlite-wal")).map(|m| m.len());
    for wal_present in [false, true] {
        for point in 0..3 {
            let (world, _root, _id) = closed_history()?;
            let hold = if wal_present {
                let connection = Connection::open(world.data().join("history.sqlite"))?;
                connection.execute_batch("PRAGMA wal_autocheckpoint=0;")?;
                connection.execute(
                    "INSERT INTO sources(source_id, harness, canonical_root, kind, consent) VALUES ('eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', 'opencode', '/nowhere', 'custom', 'denied')",
                    [],
                )?;
                assert!(wal_len(&world.data())? > 0, "a real -wal is present");
                Some(connection)
            } else {
                assert!(wal_len(&world.data()).is_err(), "no -wal");
                None
            };
            let injected = std::rc::Rc::new(std::cell::RefCell::new(None));
            let (data, base, slot) = (world.data(), world.outer(), std::rc::Rc::clone(&injected));
            let writers = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
            let kept = std::rc::Rc::clone(&writers);
            store::set_admission_hook(Some(Box::new(move |at| {
                let here = matches!(
                    (point, at),
                    (0, AdmissionPoint::AfterOverlay)
                        | (1, AdmissionPoint::AfterRoots(_))
                        | (2, AdmissionPoint::AfterAdmission)
                );
                if here && slot.borrow().is_none() {
                    let writer =
                        commit_source(&data, X_ID, &base, "enabled").expect("outside commit");
                    kept.borrow_mut().push(writer);
                    *slot.borrow_mut() = Some(history_image(&data));
                }
            })));
            reset_counters();
            let mut engine = core_engine(&world);
            let refused = engine.load_existing(&LateFs::inert());
            store::set_admission_hook(None);
            let label = format!("wal_present={wal_present} point={point}");
            assert_eq!(refused.err(), Some(StoreError::Busy), "{label}");
            assert!(engine.store().is_none(), "{label}");
            assert_eq!(store::writable_open_attempts(), 0, "{label}");
            assert_eq!(
                Some(history_image(&world.data())),
                injected.borrow().clone(),
                "{label}: only the injection"
            );
            reset_counters();
            assert_eq!(
                engine.load_existing(&LateFs::inert()).err(),
                Some(StoreError::RootOverlap),
                "{label}"
            );
            assert_eq!(store::writable_open_attempts(), 0, "{label}");
            drop(hold);
            drop(writers);
        }
    }

    // A commit plus wal_checkpoint(TRUNCATE) at AfterRoots with `-wal` present at length 0 before
    // and after: the main file keeps its length and 100-byte header yet its enabled rows differ.
    {
        let (world, _root, _id) = closed_history()?;
        let held = Connection::open(world.data().join("history.sqlite"))?;
        held.execute(
            "INSERT INTO sources(source_id, harness, canonical_root, kind, consent) VALUES ('eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', 'opencode', '/nowhere', 'custom', 'denied')",
            [],
        )?;
        held.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        assert_eq!(
            wal_len(&world.data())?,
            0,
            "-wal present at length 0 before"
        );
        let main = |data: &Path| std::fs::read(data.join("history.sqlite"));
        let seen = std::rc::Rc::new(std::cell::RefCell::new(None));
        let (data, base, slot) = (world.data(), world.outer(), std::rc::Rc::clone(&seen));
        store::set_admission_hook(Some(Box::new(move |at| {
            if matches!(at, AdmissionPoint::AfterRoots(_)) && slot.borrow().is_none() {
                let before = (main(&data).unwrap(), source_rows(&data).unwrap());
                let injector = Connection::open(data.join("history.sqlite")).unwrap();
                injector
                    .execute(
                        "INSERT INTO sources(source_id, harness, canonical_root, kind, consent) VALUES (?1, 'opencode', ?2, 'custom', 'enabled')",
                        rusqlite::params![X_ID, base.to_str().unwrap()],
                    )
                    .unwrap();
                injector
                    .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
                    .unwrap();
                drop(injector);
                *slot.borrow_mut() =
                    Some((before, (main(&data).unwrap(), source_rows(&data).unwrap())));
            }
        })));
        reset_counters();
        let mut engine = core_engine(&world);
        let refused = engine.load_existing(&LateFs::inert());
        store::set_admission_hook(None);
        let ((main_before, rows_before), (main_after, rows_after)) =
            seen.borrow().clone().expect("the hook fired");
        assert_eq!(main_before.len(), main_after.len(), "equal main length");
        assert_eq!(
            main_before[..100],
            main_after[..100],
            "equal 100-byte header"
        );
        assert_ne!(rows_before, rows_after, "different enabled rows");
        assert_eq!(wal_len(&world.data())?, 0, "-wal at length 0 after");
        assert_eq!(refused.err(), Some(StoreError::Busy));
        assert!(engine.store().is_none());
        assert_eq!(store::writable_open_attempts(), 0);
        drop(held);
    }

    // Controls: a no-op hook, and a commit after the recheck (outside the owner protocol) opens;
    // that root is never attached or read.
    {
        let (world, _root, _id) = closed_history()?;
        store::set_admission_hook(Some(Box::new(|_| {})));
        reset_counters();
        let mut engine = core_engine(&world);
        engine.load_existing(&LateFs::inert())?;
        store::set_admission_hook(None);
        assert!(engine.store().is_some());
        assert_eq!(store::writable_open_attempts(), 1, "no-op hook control");
    }
    {
        let (world, _root, _id) = closed_history()?;
        build_source(&world.outer(), &daily_rows())?; // a decoy database at the ancestor root
        let decoy = world.outer().join("opencode.db");
        let (data, base, done) = (
            world.data(),
            world.outer(),
            std::rc::Rc::new(std::cell::Cell::new(false)),
        );
        let writers = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let kept = std::rc::Rc::clone(&writers);
        store::set_admission_hook(Some(Box::new(move |at| {
            if at == AdmissionPoint::AfterRecheck && !done.replace(true) {
                kept.borrow_mut().push(
                    commit_source(&data, X_ID, &base, "enabled").expect("commit after the recheck"),
                );
            }
        })));
        let opened = std::rc::Rc::new(std::cell::Cell::new(0_usize));
        let (counter, watched) = (std::rc::Rc::clone(&opened), decoy.clone());
        quotern_core::ingest::sqlite_ro::set_open_hook(Some(Box::new(move |path, _flags| {
            if path == watched {
                counter.set(counter.get() + 1);
            }
        })));
        reset_counters();
        let mut engine = core_engine(&world);
        engine.load_existing(&LateFs::inert())?;
        store::set_admission_hook(None);
        assert!(engine.store().is_some());
        assert_eq!(store::writable_open_attempts(), 1, "opens at count 1");
        assert!(engine.enabled_source_ids()?.iter().any(|id| id == X_ID));
        let report = engine
            .reattach(LateFs::inert(), X_ID, Some(T))
            .expect_err("never attached");
        assert_eq!(
            report.failure,
            Some(quotern_core::domain::FailureCode::RootOverlap)
        );
        quotern_core::ingest::sqlite_ro::set_open_hook(None);
        assert_eq!(opened.get(), 0, "0 source opens under X");
        assert!(!engine.is_attached(X_ID));
    }
    Ok(())
}

// ---- the native owner of a data directory (DEC-062) ----------------------------------------

const BUSY: (&str, &str, bool) = ("store_busy", "store busy", true);

/// An open of `data` that must be refused `store_busy` with no history descriptor, no writable
/// open and the history files untouched.
fn assert_busy(world: &World, data: &Path, history: &Path, label: &str) {
    let image = history_image(history);
    reset_counters();
    let config = json!({"data_dir": data, "home": world.home()}).to_string();
    let (live, response) = open_with(&config);
    assert!(live.is_none(), "{label}: out is NULL");
    assert_eq!(code(&response), BUSY, "{label}: {response}");
    assert_eq!(
        counters(),
        (0, 0),
        "{label}: history_descriptor_opens and writable opens"
    );
    assert_eq!(
        history_image(history),
        image,
        "{label}: existence, (dev,ino) and bytes unchanged"
    );
}

/// The role a child copy of this test binary plays: hold an ABI handle on `data` until stdin ends.
fn owner_child(data: &str, home: &str) -> TestResult {
    use std::io::{Read, Write};
    let (live, response) = open_with(&json!({"data_dir": data, "home": home}).to_string());
    let live = live.ok_or_else(|| format!("child open failed: {response}"))?;
    println!("OWNER_READY");
    std::io::stdout().flush()?;
    std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink())?;
    let _ = std::io::stdin().read(&mut []);
    drop(live);
    Ok(())
}

#[test]
fn second_native_owner_is_store_busy() -> TestResult {
    use std::io::BufRead;
    if let (Ok(data), Ok(home)) = (
        std::env::var("QUOTERN_OWNER_DATA"),
        std::env::var("QUOTERN_OWNER_HOME"),
    ) {
        return owner_child(&data, &home);
    }
    let (world, _root, id) = closed_history()?;
    let data = world.data();
    std::fs::create_dir(data.join("x"))?;
    let alias = world.named("alias");
    symlink(&data, &alias)?;
    let dotdot = PathBuf::from(format!("{}/x/..", data.display()));

    // A child process holds an ABI handle on D, which has history.
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "second_native_owner_is_store_busy",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("QUOTERN_OWNER_DATA", &data)
        .env("QUOTERN_OWNER_HOME", world.home())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    let mut lines = std::io::BufReader::new(child.stdout.take().ok_or("child stdout")?).lines();
    let ready = lines
        .by_ref()
        .any(|line| line.is_ok_and(|line| line.contains("OWNER_READY")));
    assert!(ready, "the child holds its handle");
    let image = history_image(&data);
    for (label, path) in [("D", &data), ("symlink alias", &alias), ("D/x/..", &dotdot)] {
        assert_busy(&world, path, &data, &format!("child holder, {label}"));
    }
    assert_eq!(
        history_image(&data),
        image,
        "history unchanged by the refused opens"
    );
    drop(child.stdin.take());
    assert!(child.wait()?.success(), "child exit 0");

    // After the child exits the parent opens with exactly one writable open and equal totals.
    reset_counters();
    let first = world.live();
    assert_eq!(store::writable_open_attempts(), 1);
    assert_eq!(first.input(&id), json!(ORACLE_A));
    // The same three opens by a second in-process handle while the first lives.
    for (label, path) in [("D", &data), ("symlink alias", &alias), ("D/x/..", &dotdot)] {
        assert_busy(&world, path, &data, &format!("in-process holder, {label}"));
    }
    first.ingest(T + 1);
    assert_eq!(
        first.input(&id),
        json!(ORACLE_A),
        "the first handle ingests its oracle, replay adds zero"
    );
    Ok(())
}

#[test]
fn owner_identity_scope_and_lifetime() -> TestResult {
    // Sibling data dirs and the parent of D are independent owners.
    let world = World::new()?;
    let parent = world.named("p");
    std::fs::create_dir(&parent)?;
    let (d, d2) = (parent.join("d"), parent.join("d2"));
    let roots = [
        world.named("src-p"),
        world.named("src-d"),
        world.named("src-d2"),
    ];
    let rows = [rows_c(), daily_rows(), rows_b()];
    let oracles = [100, ORACLE_A, ORACLE_B];
    for (root, rows) in roots.iter().zip(&rows) {
        build_source(root, rows)?;
    }
    let handles: Vec<Live> = [&parent, &d, &d2]
        .into_iter()
        .map(|data| {
            open_with(&world.config_for(data))
                .0
                .expect("every sibling, parent and child opens")
        })
        .collect();
    for ((handle, root), oracle) in handles.iter().zip(&roots).zip(oracles) {
        assert_eq!(handle.select(root)["ok"], json!(true));
        handle.ingest(T);
        let id = handle.id_of(root.file_name().unwrap().to_str().unwrap());
        assert_eq!(
            handle.input(&id),
            json!(oracle),
            "independent oracle of {root:?}"
        );
        assert_eq!(
            handle.sources()["data"]["sources"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    drop(handles);

    // H1 keeps D store_busy for H2 at every point of its life.
    let world = World::new()?;
    let (root_a, root_b) = (world.named("a"), world.named("b"));
    build_source(&root_a, &daily_rows())?;
    build_source(&root_b, &rows_b())?;
    let data = world.data();
    let h1 = world.live();
    assert_eq!(h1.select(&root_a)["ok"], json!(true));
    h1.ingest(T);
    let id_a = h1.id_of("a");
    assert_busy(&world, &data, &data, "idle");

    let token = quotern_cancel_new();
    let cancelled = h1.call_with("ingest", &json!({"now_ms": T + 1}).to_string(), token);
    unsafe { quotern_cancel_free(token) };
    let token = quotern_cancel_new();
    unsafe { quotern_cancel_trigger(token) };
    let cancelled_after = h1.call_with("ingest", &json!({"now_ms": T + 2}).to_string(), token);
    unsafe { quotern_cancel_free(token) };
    assert_eq!(cancelled["ok"], json!(true));
    assert_eq!(code(&cancelled_after).0, "cancelled");
    assert_busy(&world, &data, &data, "after a cancelled ingest");

    // A refused second attach (the data dir swapped for another directory) changes nothing.
    let image = history_image(&data);
    let parked = world.named("parked-data");
    std::fs::rename(&data, &parked)?;
    std::fs::create_dir(&data)?;
    let refused = h1.select(&root_b);
    assert_eq!(code(&refused).0, "store_corrupt", "{refused}");
    std::fs::remove_dir(&data)?;
    std::fs::rename(&parked, &data)?;
    assert_eq!(history_image(&data), image, "the store is unchanged");
    assert_busy(&world, &data, &data, "after a refused second attach");

    // After panic_next_commit.
    add_rows(&root_a, &[message("a-extra", 3, T + 3_000)])?;
    store::panic_next_commit();
    assert_eq!(code(&h1.ingest(T + 10)).0, "internal_panic");
    assert_eq!(code(&h1.sources()).0, "engine_failed");
    assert_busy(&world, &data, &data, "after panic_next_commit");

    // At H1 close the owner is released with no descriptor on history, -wal or -shm.
    let released = std::rc::Rc::new(std::cell::Cell::new(usize::MAX));
    let probe = (std::rc::Rc::clone(&released), data.clone());
    store::set_owner_release_hook(Some(Box::new(move || {
        probe.0.set(history_descriptors(&probe.1))
    })));
    drop(h1);
    store::set_owner_release_hook(None);
    assert_eq!(
        released.get(),
        0,
        "the release hook sees no process descriptor on history/-wal/-shm"
    );
    let h2 = world.live();
    assert_eq!(
        h2.input(&id_a),
        json!(ORACLE_A),
        "H2 opens with exactly H1's history"
    );
    drop(h2);

    // A refused ABI open releases the owner at once: the same refusal again, never store_busy.
    let scenario = Overlapped::new(Overlap::RootToAncestor)?;
    scenario.apply()?;
    for attempt in 0..2 {
        let (live, response) = scenario.world.open();
        assert!(live.is_none());
        assert_eq!(
            code(&response),
            ("source_overlap_conflict", "source overlap conflict", false),
            "attempt {attempt}: {response}"
        );
    }
    Ok(())
}

#[test]
fn cold_first_attach_claims_owner() -> TestResult {
    // D absent: both handles open and nothing is created.
    let world = World::with_source(&daily_rows())?;
    let data = world.data();
    reset_counters();
    let h1 = world.live();
    let h2 = world.live();
    assert!(!data.exists());
    assert_eq!(counters(), (0, 0));
    let invalid = h2.call(
        "set_source_selection",
        &json!({"harness": "codex", "root": world.source(), "selected": true}).to_string(),
    );
    assert_eq!(code(&invalid).0, "invalid_request");
    assert_eq!(code(&h2.deselect(&world.source())).0, "invalid_request");
    assert!(
        !data.exists(),
        "invalid and denied first selections still create no D"
    );

    // H1's first valid selection creates D and history: the mkdirat chain and the history open.
    reset_counters();
    assert_eq!(h1.select(&world.source())["ok"], json!(true));
    assert_eq!(store::writable_open_attempts(), 2);
    assert!(data.join("history.sqlite").exists());
    let rows = source_rows(&data)?;
    assert_eq!(rows.len(), 1);

    // H2's first valid selection: store_busy, store None, no source row, no writable open.
    let image = history_image(&data);
    reset_counters();
    let busy = h2.select(&world.source());
    assert_eq!(code(&busy), BUSY, "{busy}");
    assert_eq!(counters(), (0, 0));
    assert_eq!(h2.sources()["data"], json!({"sources": []}), "store None");
    assert_eq!(source_rows(&data)?, rows, "no source row of H2");
    assert_eq!(history_image(&data), image);
    drop(h1);
    drop(h2);

    // After H1 closes, H2 retries and history is present, so admission runs with its requested
    // (disjoint) root: a persisted H1 root re-pointed at a data-dir ancestor, and the relocated
    // data dir of reopen case (c). The refused first attach keeps H2's claim with store None.
    let overlap = ("source_overlap_conflict", "source overlap conflict", false);
    for case in [Overlap::RootToAncestor, Overlap::RootInsideDataMissing] {
        let world = World::new()?;
        let root = if case.inside_data() {
            world.named("s").join("x").join("a")
        } else {
            world.named("a")
        };
        build_source(&root, &daily_rows())?;
        let other = world.named("b");
        build_source(&other, &rows_b())?;
        let h2 = world.live(); // D absent: nothing created
        let id = {
            let h1 = world.live();
            assert_eq!(h1.select(&root)["ok"], json!(true));
            h1.ingest(T);
            h1.id_of("a")
        };
        let scenario = Overlapped {
            world,
            case,
            root,
            id,
        };
        scenario.apply()?;
        let history = scenario.history_dir();
        let rows = source_rows(&history)?;
        assert_eq!(rows.len(), 1, "{case:?}: H1's row only");
        let image = history_image(&history);
        // H2's first selection, then its second while the claim is already held: each refused
        // the same way with nothing written.
        for attempt in ["first", "second (claim held)"] {
            reset_counters();
            let refused = h2.select(&other);
            assert_eq!(code(&refused), overlap, "{case:?} {attempt}: {refused}");
            assert_eq!(store::writable_open_attempts(), 0, "{case:?} {attempt}");
            assert_eq!(
                h2.sources()["data"],
                json!({"sources": []}),
                "{case:?} {attempt}: store None"
            );
            assert_eq!(
                history_image(&history),
                image,
                "{case:?} {attempt}: files unchanged"
            );
            assert_eq!(
                source_rows(&history)?,
                rows,
                "{case:?} {attempt}: no source row"
            );
            if attempt == "first" {
                // While H2 lives a rival ABI open of D is busy.
                assert_busy(
                    &scenario.world,
                    &scenario.world.data(),
                    &history,
                    &format!("{case:?}: rival while H2 holds the claim"),
                );
            }
        }
        scenario.undo_data()?;
        scenario.undo_root()?;
        let data = scenario.world.data();
        reset_counters();
        let retried = h2.select(&other);
        if case == Overlap::RootToAncestor {
            assert_eq!(retried["ok"], json!(true), "{case:?}: restored {retried}");
            assert_eq!(store::writable_open_attempts(), 1, "{case:?}");
            drop(h2);
            continue;
        }
        // The relocated case: H2's held directory is no longer D.
        assert_eq!(
            code(&retried),
            ("store_corrupt", "store corrupt", false),
            "{case:?}: {retried}"
        );
        assert_eq!(store::writable_open_attempts(), 0, "{case:?} retry");
        assert_eq!(
            h2.sources()["data"],
            json!({"sources": []}),
            "{case:?} retry: store None"
        );
        assert_eq!(source_rows(&data)?, rows, "{case:?} retry: no source row");
        let released = std::rc::Rc::new(std::cell::Cell::new(usize::MAX));
        let probe = (std::rc::Rc::clone(&released), data.clone());
        store::set_owner_release_hook(Some(Box::new(move || {
            probe.0.set(history_descriptors(&probe.1))
        })));
        drop(h2);
        store::set_owner_release_hook(None);
        assert_eq!(
            released.get(),
            0,
            "{case:?}: the release hook sees no history/-wal/-shm descriptor"
        );
        reset_counters();
        let fresh = scenario.world.live();
        assert_eq!(
            fresh.select(&other)["ok"],
            json!(true),
            "{case:?}: a new handle attaches"
        );
        assert_eq!(store::writable_open_attempts(), 1, "{case:?}: new handle");
    }

    cold_race()
}

// ---- admission budgets -------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Caller {
    Abi,
    Open,
    OpenBound,
}

#[derive(Debug, PartialEq)]
enum Opened {
    Yes,
    Abi(String, String, bool),
    Core(store::StoreError),
}

/// One open of `data` through `caller`, the handle or store dropped at once.
fn open_as(caller: Caller, world: &World, data: &Path) -> TestResult<Opened> {
    Ok(match caller {
        Caller::Abi => {
            let (live, response) = open_with(&world.config_for(data));
            if live.is_some() {
                Opened::Yes
            } else {
                let (code, message, retryable) = code(&response);
                Opened::Abi(code.to_owned(), message.to_owned(), retryable)
            }
        }
        Caller::Open => match store::Store::open(data) {
            Ok(_) => Opened::Yes,
            Err(error) => Opened::Core(error),
        },
        Caller::OpenBound => {
            let (resolved, anchor) = quotern_core::discovery::anchor_for(data)?;
            match store::Store::open_bound(&resolved, &anchor) {
                Ok(_) => Opened::Yes,
                Err(error) => Opened::Core(error),
            }
        }
    })
}

const CALLERS: [Caller; 3] = [Caller::Abi, Caller::Open, Caller::OpenBound];

/// What each caller reports when admission refuses with `bound`.
fn refused_for(caller: Caller, bound: store::AdmissionBound) -> Opened {
    match caller {
        Caller::Abi => Opened::Abi(
            "limit_exceeded".into(),
            format!("limit exceeded: {}", bound.as_str()),
            false,
        ),
        Caller::Open | Caller::OpenBound => Opened::Core(store::StoreError::AdmissionLimit(bound)),
    }
}

/// `open` run with a counting owner-release hook installed: its result and the release count.
fn owner_releases<R>(open: impl FnOnce() -> R) -> (R, usize) {
    let count = std::rc::Rc::new(std::cell::Cell::new(0_usize));
    let counter = std::rc::Rc::clone(&count);
    store::set_owner_release_hook(Some(Box::new(move || counter.set(counter.get() + 1))));
    let result = open();
    store::set_owner_release_hook(None);
    (result, count.get())
}

/// Every caller refuses with `expected` (a per-caller outcome), no writable open, files unchanged;
/// the unguarded core callers release no owner.
fn assert_refused_by_all(
    world: &World,
    data: &Path,
    expected: impl Fn(Caller) -> Opened,
    label: &str,
) -> TestResult {
    for caller in CALLERS {
        let image = history_image(data);
        reset_counters();
        let (opened, releases) = owner_releases(|| open_as(caller, world, data));
        assert_eq!(opened?, expected(caller), "{label} {caller:?}");
        assert_eq!(
            store::writable_open_attempts(),
            0,
            "{label} {caller:?}: no writable open"
        );
        if !matches!(caller, Caller::Abi) {
            assert_eq!(releases, 0, "{label} {caller:?}: no owner release");
        }
        assert_eq!(
            history_image(data),
            image,
            "{label} {caller:?}: bytes, lengths and (dev,ino) unchanged"
        );
    }
    Ok(())
}

/// A copy of a closed history, with a hot `-wal` (an outside connection's committed frames).
fn hot_wal_copy(world: &World, name: &str) -> TestResult<PathBuf> {
    let copy = world.named(name);
    std::fs::create_dir(&copy)?;
    let hold = Connection::open(world.data().join("history.sqlite"))?;
    hold.execute_batch("PRAGMA wal_autocheckpoint=0;")?;
    let tag: String = name.bytes().map(|byte| format!("{byte:02x}")).collect();
    hold.execute(
        "INSERT INTO sources(source_id, harness, canonical_root, kind, consent) VALUES (?1, 'opencode', ?2, 'custom', 'denied')",
        rusqlite::params![format!("{tag:0<32}")[..32].to_owned(), format!("/nowhere/{name}")],
    )?;
    std::fs::copy(
        world.data().join("history.sqlite"),
        copy.join("history.sqlite"),
    )?;
    std::fs::copy(
        world.data().join("history.sqlite-wal"),
        copy.join("history.sqlite-wal"),
    )?;
    drop(hold);
    Ok(copy)
}

fn extend_wal(data: &Path, length: u64) -> TestResult {
    std::fs::OpenOptions::new()
        .write(true)
        .open(data.join("history.sqlite-wal"))?
        .set_len(length)?;
    Ok(())
}

/// Measured read bytes of one admission (the AfterRoots figure).
fn measured_read_bytes(world: &World, data: &Path) -> TestResult<u64> {
    let bytes = std::rc::Rc::new(std::cell::Cell::new(0_u64));
    let slot = std::rc::Rc::clone(&bytes);
    store::set_admission_hook(Some(Box::new(move |point| {
        if let store::AdmissionPoint::AfterRoots(read) = point {
            slot.set(read);
        }
    })));
    let opened = open_as(Caller::Abi, world, data)?;
    store::set_admission_hook(None);
    assert_eq!(opened, Opened::Yes);
    assert!(bytes.get() > 0);
    Ok(bytes.get())
}

fn sqlite_master(path: &Path) -> TestResult<Vec<(String, String, Option<String>)>> {
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut statement = connection
        .prepare("SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name")?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn user_version(path: &Path) -> TestResult<i64> {
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    Ok(connection.query_row("PRAGMA user_version", [], |row| row.get(0))?)
}

const WAL_LIMIT: u64 = 64 * 1024 * 1024;

#[test]
fn admission_budget_limits() -> TestResult {
    use store::AdmissionBound::{EnabledSources, ReadBytes, WalBytes};

    corrupt_enabled_rows()?;

    // (1) A real `-wal` extended past 64 MiB (trailing zero frames SQLite ignores) is refused by
    // every caller, length before any read, never as a corrupt store.
    let (world, _root, id) = closed_history()?;
    let oversized = hot_wal_copy(&world, "oversized")?;
    extend_wal(&oversized, WAL_LIMIT + 4096)?;
    assert_refused_by_all(
        &world,
        &oversized,
        |caller| refused_for(caller, WalBytes),
        "64 MiB + 4096",
    )?;
    // Garbage in the header of that length is the same refusal: the length is checked first.
    let garbage = hot_wal_copy(&world, "garbage-header")?;
    extend_wal(&garbage, WAL_LIMIT + 1)?;
    {
        use std::os::unix::fs::FileExt;
        std::fs::OpenOptions::new()
            .write(true)
            .open(garbage.join("history.sqlite-wal"))?
            .write_all_at(&[0xAB; 32], 0)?;
    }
    assert_refused_by_all(
        &world,
        &garbage,
        |caller| refused_for(caller, WalBytes),
        "garbage header",
    )?;

    // Exactly 64 MiB is walked and admitted.
    let exact = hot_wal_copy(&world, "exact")?;
    extend_wal(&exact, WAL_LIMIT)?;
    reset_counters();
    {
        let (live, response) = open_with(&world.config_for(&exact));
        let live = live.ok_or_else(|| format!("exactly 64 MiB is admitted: {response}"))?;
        assert_eq!(store::writable_open_attempts(), 1);
        assert_eq!(live.input(&id), json!(ORACLE_A));
    }

    // After an outside wal_checkpoint(TRUNCATE) with no handle live and production caps unchanged
    // the next open admits (count 1) and equals the pre-inflation oracle.
    {
        let connection = Connection::open(oversized.join("history.sqlite"))?;
        connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
    }
    reset_counters();
    {
        let (live, response) = open_with(&world.config_for(&oversized));
        let live = live.ok_or_else(|| format!("recovery admits: {response}"))?;
        assert_eq!(store::writable_open_attempts(), 1);
        assert_eq!(
            live.input(&id),
            json!(ORACLE_A),
            "equals the pre-inflation oracle"
        );
    }

    // (2) The read cap: the measured bytes admit, one byte less is refused by every caller.
    let (world, _root, id) = closed_history()?;
    let measured = measured_read_bytes(&world, &world.data())?;
    let mut attempts = Vec::new();
    store::set_admission_read_cap(Some(measured));
    attempts.push((measured, open_as(Caller::Abi, &world, &world.data())?));
    assert_eq!(
        attempts[0].1,
        Opened::Yes,
        "a cap equal to the measured bytes admits"
    );
    store::set_admission_read_cap(Some(measured - 1));
    assert_refused_by_all(
        &world,
        &world.data(),
        |caller| refused_for(caller, ReadBytes),
        "cap one byte below",
    )?;
    // No recovery promise under the same never-reset cap: an outside checkpoint changes nothing,
    // the retry is refused again with the history bytes unchanged.
    {
        let connection = Connection::open(world.data().join("history.sqlite"))?;
        connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
    }
    assert_refused_by_all(
        &world,
        &world.data(),
        |caller| refused_for(caller, ReadBytes),
        "retry under the same cap",
    )?;
    // A cap-resetting retry would admit: the SAME refusal check rejects that mutant.
    store::set_admission_read_cap(None);
    let resetting = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_refused_by_all(
            &world,
            &world.data(),
            |caller| refused_for(caller, ReadBytes),
            "mutant",
        )
    }));
    assert!(
        resetting.is_err(),
        "the cap-resetting retry mutant admits and fails the check"
    );
    // Separately labelled positive control: restoring the cap admits and equals the oracle.
    reset_counters();
    {
        let (live, _) = open_with(&world.config());
        let live = live.expect("positive control admits");
        assert_eq!(store::writable_open_attempts(), 1);
        assert_eq!(live.input(&id), json!(ORACLE_A));
    }
    store::set_admission_read_cap(None);

    // (3) Total-source capacity: the real custom root A plus 62 SQL-seeded enabled `builtin`
    // rows at distinct absent roots (63 rows, 1 custom), so the ABI 16-custom-root gate never
    // intercepts. A 64th row is admitted; a 65th is refused inside the registering transaction.
    let (world, root_a, _id) = closed_history()?;
    {
        let connection = Connection::open(world.data().join("history.sqlite"))?;
        for index in 0..62 {
            connection.execute(
                "INSERT INTO sources(source_id, harness, canonical_root, kind, consent) VALUES (?1, 'opencode', ?2, 'builtin', 'enabled')",
                rusqlite::params![format!("{index:032x}"), format!("/quotern-absent/{index}")],
            )?;
        }
    }
    let (root_b, root_c) = (world.named("b"), world.named("c"));
    build_source(&root_b, &rows_b())?;
    build_source(&root_c, &rows_c())?;
    let counts = |data: &Path| -> TestResult<(i64, i64)> {
        let connection = Connection::open_with_flags(
            data.join("history.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        Ok(connection.query_row(
            "SELECT count(*), count(*) FILTER (WHERE kind = 'custom') FROM sources",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?)
    };
    let table = |data: &Path, name: &str| -> TestResult<Vec<String>> {
        let connection = Connection::open_with_flags(
            data.join("history.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let mut statement = connection.prepare(&format!("SELECT * FROM {name}"))?;
        let columns = statement.column_count();
        let mut rows: Vec<String> = statement
            .query_map([], |row| {
                (0..columns)
                    .map(|index| row.get::<_, rusqlite::types::Value>(index))
                    .collect::<Result<Vec<_>, _>>()
                    .map(|values| format!("{values:?}"))
            })?
            .collect::<Result<_, _>>()?;
        rows.sort();
        Ok(rows)
    };
    let listed = |live: &Live| -> (usize, usize) {
        let sources = live.sources()["data"]["sources"]
            .as_array()
            .unwrap()
            .clone();
        let custom = sources
            .iter()
            .filter(|entry| entry["kind"] == json!("custom"))
            .count();
        (sources.len(), custom)
    };
    assert_eq!(counts(&world.data())?, (63, 1), "63 rows, 1 custom");
    {
        let live = world.live();
        assert_eq!(
            live.select(&root_b)["ok"],
            json!(true),
            "63 -> 64 admit control"
        );
        assert_eq!(counts(&world.data())?, (64, 2));
        // Precondition of the refusal: 64 rows, 2 custom (under the custom-root gate's 16).
        assert_eq!(listed(&live), (64, 2), "list_sources: 64 entries, 2 custom");
        let (sources_before, status_before) = (
            table(&world.data(), "sources")?,
            table(&world.data(), "source_status")?,
        );
        let refused = live.select(&root_c);
        assert_eq!(
            code(&refused),
            ("limit_exceeded", "limit exceeded: store_limit", false),
            "{refused}"
        );
        assert_eq!(table(&world.data(), "sources")?, sources_before);
        assert_eq!(table(&world.data(), "source_status")?, status_before);
        assert_eq!(listed(&live), (64, 2), "list_sources still 64");
        assert_eq!(
            live.select(&root_a)["ok"],
            json!(true),
            "the registered real root A is still selectable"
        );
    }
    reset_counters();
    assert_eq!(
        open_as(Caller::Abi, &world, &world.data())?,
        Opened::Yes,
        "64 enabled rows: the next native open admits"
    );
    assert_eq!(store::writable_open_attempts(), 1);
    drop(commit_source(
        &world.data(),
        "00000000000000000000000000000fff",
        Path::new("/quotern-absent/over"),
        "enabled",
    )?);
    assert_refused_by_all(
        &world,
        &world.data(),
        |caller| refused_for(caller, EnabledSources),
        "65 enabled rows",
    )?;

    empty_main_siblings()?;
    fresh_and_foreign_stores()?;
    ordinary_core_refusals()
}

/// An enabled `sources` row admission cannot decode, written by outside SQL, is refused as a
/// corrupt store by every caller, never read past as an empty root list.
fn corrupt_enabled_rows() -> TestResult {
    use store::StoreError;
    let corrupt = |caller: Caller| match caller {
        Caller::Abi => Opened::Abi("store_corrupt".into(), "store corrupt".into(), false),
        Caller::Open | Caller::OpenBound => Opened::Core(StoreError::Corrupt),
    };
    for (label, sql) in [
        (
            "kind outside the CHECK set",
            "PRAGMA ignore_check_constraints = ON; INSERT INTO sources(source_id, harness, canonical_root, kind, consent) VALUES ('cccccccccccccccccccccccccccccccc', 'opencode', '/quotern-absent/kind', 'bogus', 'enabled');",
        ),
        (
            "root_device -1",
            "INSERT INTO sources(source_id, harness, canonical_root, kind, consent, root_device, root_inode) VALUES ('cccccccccccccccccccccccccccccccc', 'opencode', '/quotern-absent/device', 'custom', 'enabled', -1, 1);",
        ),
    ] {
        let (world, _root, _id) = closed_history()?;
        Connection::open(world.data().join("history.sqlite"))?.execute_batch(sql)?;
        assert_refused_by_all(&world, &world.data(), corrupt, label)?;
    }
    Ok(())
}

/// A zero-byte history is Fresh only with no `-journal` and an absent or empty `-wal`; beside a
/// sidecar every caller refuses it typed like a non-empty history, count 0, files unchanged.
fn empty_main_siblings() -> TestResult {
    use store::AdmissionBound::WalBytes;
    use store::StoreError;
    let corrupt = |caller: Caller| match caller {
        Caller::Abi => Opened::Abi("store_corrupt".into(), "store corrupt".into(), false),
        Caller::Open | Caller::OpenBound => Opened::Core(StoreError::Corrupt),
    };
    let (world, _root, _id) = closed_history()?;
    // A valid store's non-empty log.
    let log = hot_wal_copy(&world, "valid-log")?.join("history.sqlite-wal");
    let empty_main = |name: &str| -> TestResult<PathBuf> {
        let data = world.named(name);
        std::fs::create_dir(&data)?;
        std::fs::File::create(data.join("history.sqlite"))?;
        Ok(data)
    };

    let data = empty_main("empty-main-oversized-wal")?;
    std::fs::copy(&log, data.join("history.sqlite-wal"))?;
    extend_wal(&data, WAL_LIMIT + 4096)?;
    assert_refused_by_all(
        &world,
        &data,
        |caller| refused_for(caller, WalBytes),
        "empty main, -wal past 64 MiB",
    )?;

    let data = empty_main("empty-main-wal")?;
    std::fs::copy(&log, data.join("history.sqlite-wal"))?;
    let length = std::fs::metadata(data.join("history.sqlite-wal"))?.len();
    assert!((1..=WAL_LIMIT).contains(&length), "non-empty within 64 MiB");
    assert_refused_by_all(&world, &data, corrupt, "empty main, non-empty -wal")?;

    let data = empty_main("empty-main-journal")?;
    std::fs::File::create(data.join("history.sqlite-journal"))?;
    assert_refused_by_all(&world, &data, corrupt, "empty main, -journal")?;

    // Control: a zero-byte history with no sidecar is admitted Fresh and finishes exact V1.
    let clean = World::new()?;
    drop(store::Store::open(&clean.data())?);
    let clean_schema = sqlite_master(&clean.data().join("history.sqlite"))?;
    for caller in CALLERS {
        let data = empty_main(&format!("empty-main-{caller:?}"))?;
        reset_counters();
        assert_eq!(
            open_as(caller, &world, &data)?,
            Opened::Yes,
            "{caller:?} Fresh"
        );
        assert_eq!(store::writable_open_attempts(), 1, "{caller:?}");
        let history = data.join("history.sqlite");
        assert_eq!(user_version(&history)?, 1, "{caller:?}");
        assert_eq!(
            sqlite_master(&history)?,
            clean_schema,
            "{caller:?}: exact V1"
        );
    }
    Ok(())
}

/// A store left by a real interrupted creation (user_version 0, no schema object) is admitted
/// Fresh by every caller and completed to exact V1; a version-0 foreign schema is corrupt.
fn fresh_and_foreign_stores() -> TestResult {
    use store::StoreError;
    let clean = World::new()?;
    drop(store::Store::open(&clean.data())?);
    let clean_schema = sqlite_master(&clean.data().join("history.sqlite"))?;
    for caller in CALLERS {
        let world = World::new()?;
        store::migrations::interrupt_next_creation();
        assert_eq!(
            store::Store::open(&world.data()).err(),
            Some(StoreError::Sqlite)
        );
        let history = world.data().join("history.sqlite");
        assert_eq!(
            (user_version(&history)?, sqlite_master(&history)?.len()),
            (0, 0),
            "{caller:?}: asserted empty"
        );
        reset_counters();
        assert_eq!(
            open_as(caller, &world, &world.data())?,
            Opened::Yes,
            "{caller:?} admits Fresh"
        );
        assert_eq!(store::writable_open_attempts(), 1, "{caller:?}");
        assert_eq!(user_version(&history)?, 1, "{caller:?}");
        assert_eq!(
            sqlite_master(&history)?,
            clean_schema,
            "{caller:?}: exact V1"
        );
        if matches!(caller, Caller::Abi) {
            let live = world.live();
            assert_eq!(live.sources()["data"], json!({"sources": []}));
        }

        // Control: user_version 0 with one foreign table.
        let foreign = World::new()?;
        std::fs::create_dir(foreign.data())?;
        Connection::open(foreign.data().join("history.sqlite"))?
            .execute_batch("CREATE TABLE foreign_table(x INTEGER);")?;
        let image = history_image(&foreign.data());
        reset_counters();
        let expected = match caller {
            Caller::Abi => Opened::Abi("store_corrupt".into(), "store corrupt".into(), false),
            _ => Opened::Core(StoreError::Corrupt),
        };
        assert_eq!(
            open_as(caller, &foreign, &foreign.data())?,
            expected,
            "{caller:?} foreign"
        );
        assert_eq!(store::writable_open_attempts(), 0, "{caller:?} foreign");
        assert_eq!(
            history_image(&foreign.data()),
            image,
            "{caller:?} foreign: bytes unchanged"
        );
    }
    Ok(())
}

/// The unguarded core opens run the same read-only preflight: non-ENOENT errors are refused
/// typed before any writable open, and the creating controls count exactly.
fn ordinary_core_refusals() -> TestResult {
    use store::StoreError;
    assert!(!root_euid_is_zero());
    for caller in [Caller::Open, Caller::OpenBound] {
        // history.sqlite mode 0000.
        let (world, _root, _id) = closed_history()?;
        let history = world.data().join("history.sqlite");
        // The readable baseline precedes the chmod.
        let image = history_image(&world.data());
        let mode = std::fs::metadata(&history)?.permissions().mode() & 0o777;
        assert_ne!(mode, 0, "readable before the chmod");
        assert!(
            image["history.sqlite"]
                .as_ref()
                .is_some_and(|(_, bytes)| bytes.as_ref().is_some_and(|bytes| !bytes.is_empty()))
        );
        set_mode(&history, 0)?;
        reset_counters();
        let (opened, releases) = owner_releases(|| open_as(caller, &world, &world.data()));
        assert_eq!(
            opened?,
            Opened::Core(StoreError::UnsafeFile),
            "{caller:?} mode 0000"
        );
        assert_eq!(store::writable_open_attempts(), 0);
        assert_eq!(releases, 0, "{caller:?} mode 0000: no owner release");
        assert_eq!(
            std::fs::metadata(&history)?.permissions().mode() & 0o777,
            0,
            "mode unchanged"
        );
        set_mode(&history, mode)?;
        assert_eq!(
            history_image(&world.data()),
            image,
            "{caller:?} mode 0000: bytes, lengths and (dev,ino) unchanged"
        );

        // A `-wal` that is a directory.
        let (world, _root, _id) = closed_history()?;
        std::fs::create_dir(world.data().join("history.sqlite-wal"))?;
        let image = history_image(&world.data());
        assert_eq!(
            image["history.sqlite-wal"].as_ref().map(|(_, bytes)| bytes),
            Some(&None)
        );
        reset_counters();
        let (opened, releases) = owner_releases(|| open_as(caller, &world, &world.data()));
        assert_eq!(
            opened?,
            Opened::Core(StoreError::UnsafeFile),
            "{caller:?} -wal directory"
        );
        assert_eq!(store::writable_open_attempts(), 0);
        assert_eq!(releases, 0, "{caller:?} -wal directory: no owner release");
        assert_eq!(history_image(&world.data()), image);

        // Controls: a within-bounds existing store opens with one writable open; history absent in
        // an existing data dir takes the original creating path (one); an absent data dir beneath
        // the anchor takes two.
        let (world, _root, _id) = closed_history()?;
        reset_counters();
        assert_eq!(open_as(caller, &world, &world.data())?, Opened::Yes);
        assert_eq!(
            store::writable_open_attempts(),
            1,
            "{caller:?} within bounds"
        );
        let bare = World::new()?;
        std::fs::create_dir(bare.data())?;
        reset_counters();
        assert_eq!(open_as(caller, &bare, &bare.data())?, Opened::Yes);
        assert_eq!(
            store::writable_open_attempts(),
            1,
            "{caller:?} history absent"
        );
        let absent = World::new()?;
        reset_counters();
        assert_eq!(open_as(caller, &absent, &absent.data())?, Opened::Yes);
        assert_eq!(
            store::writable_open_attempts(),
            2,
            "{caller:?} data dir absent"
        );
    }
    Ok(())
}

// ---- unsupported outside-writer windows ------------------------------------------------------

/// Frames of a write-ahead log image: (offset, is a commit frame), and the page size.
fn wal_frames(wal: &[u8]) -> (usize, Vec<(usize, bool)>) {
    let page = u32::from_be_bytes([wal[8], wal[9], wal[10], wal[11]]) as usize;
    let frame = 24 + page;
    let frames = (32..=wal.len().saturating_sub(frame))
        .step_by(frame)
        .map(|offset| (offset, wal[offset + 4..offset + 8] != [0, 0, 0, 0]))
        .collect();
    (page, frames)
}

/// SQLite's write-ahead-log checksum over `data` (an even number of 4-byte words) from `state`.
fn wal_checksum(data: &[u8], big_endian: bool, mut state: (u32, u32)) -> (u32, u32) {
    let word = |bytes: &[u8]| {
        let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        }
    };
    for pair in data.as_chunks::<8>().0 {
        state.0 = state.0.wrapping_add(word(&pair[..4])).wrapping_add(state.1);
        state.1 = state.1.wrapping_add(word(&pair[4..])).wrapping_add(state.0);
    }
    state
}

fn inverse_mod_2_32(odd: u32) -> u32 {
    let mut inverse = odd;
    for _ in 0..5 {
        inverse = inverse.wrapping_mul(2_u32.wrapping_sub(odd.wrapping_mul(inverse)));
    }
    inverse
}

/// Flips the payload byte at `at` (an absolute offset into `wal`) and rewrites two zero words of
/// unused page space so the frame's checksum, and so every later header, stays valid. Returns the
/// frame offset and its rewritten payload.
fn flip_with_checksum_kept(
    wal: &mut [u8],
    at: usize,
    from: u8,
    to: u8,
) -> TestResult<(usize, Vec<u8>)> {
    let (page, frames) = wal_frames(wal);
    let frame = frames
        .iter()
        .map(|(offset, _)| *offset)
        .filter(|offset| *offset <= at)
        .max()
        .ok_or("frame")?;
    assert_eq!(wal[at], from);
    let big = wal[3] & 1 == 1;
    let previous = if frame == 32 {
        24
    } else {
        frame - (24 + page) + 16
    };
    let word = |bytes: &[u8]| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let start = (
        word(&wal[previous..previous + 4]),
        word(&wal[previous + 4..previous + 8]),
    );
    let stored = (
        word(&wal[frame + 16..frame + 20]),
        word(&wal[frame + 20..frame + 24]),
    );
    let mut covered = wal[frame..frame + 8].to_vec();
    covered.extend_from_slice(&wal[frame + 24..frame + 24 + page]);
    assert_eq!(
        wal_checksum(&covered, big, start),
        stored,
        "the frame's stored checksum is the algorithm's"
    );
    let payload_at = at - (frame + 24);
    covered[8 + payload_at] = to;
    let delta = (
        stored.0.wrapping_sub(wal_checksum(&covered, big, start).0),
        stored.1.wrapping_sub(wal_checksum(&covered, big, start).1),
    );
    // Two free pairs: a word of unused (zero) space each; the response of the checksum to a unit
    // change of each is measured, then the 2x2 system is solved modulo 2^32.
    let zero = |pair: usize| {
        covered[pair * 8..pair * 8 + 8]
            .iter()
            .all(|byte| *byte == 0)
    };
    let (mut best, mut run) = ((0, 0), (0, 0));
    for pair in 1..covered.len() / 8 {
        run = if zero(pair) && run.1 == pair {
            (run.0, pair + 1)
        } else if zero(pair) {
            (pair, pair + 1)
        } else {
            (0, 0)
        };
        if run.1 - run.0 > best.1 - best.0 {
            best = run;
        }
    }
    assert!(
        best.1 - best.0 > 40,
        "the page has a run of unused words: {best:?}"
    );
    for (k, m) in
        (0..16).flat_map(|first| (0..16).map(move |last| (best.0 + first, best.1 - 1 - last)))
    {
        let respond = |index: usize| {
            let mut probe = covered.clone();
            probe[index + 3] = 1; // word (big endian) or its byte
            if !big {
                probe[index + 3] = 0;
                probe[index] = 1;
            }
            let moved = wal_checksum(&probe, big, start);
            let base = wal_checksum(&covered, big, start);
            (moved.0.wrapping_sub(base.0), moved.1.wrapping_sub(base.1))
        };
        let (a, b) = (respond(k * 8), respond(m * 8 + 4));
        let determinant = a.0.wrapping_mul(b.1).wrapping_sub(a.1.wrapping_mul(b.0));
        if determinant % 2 == 0 {
            continue;
        }
        let inverse = inverse_mod_2_32(determinant);
        let first = delta
            .0
            .wrapping_mul(b.1)
            .wrapping_sub(delta.1.wrapping_mul(b.0))
            .wrapping_mul(inverse);
        let second =
            a.0.wrapping_mul(delta.1)
                .wrapping_sub(a.1.wrapping_mul(delta.0))
                .wrapping_mul(inverse);
        let put = |covered: &mut Vec<u8>, index: usize, value: u32| {
            let bytes = if big {
                value.to_be_bytes()
            } else {
                value.to_le_bytes()
            };
            covered[index..index + 4].copy_from_slice(&bytes);
        };
        put(&mut covered, k * 8, first);
        put(&mut covered, m * 8 + 4, second);
        assert_eq!(
            wal_checksum(&covered, big, start),
            stored,
            "the rewritten frame keeps its checksum"
        );
        let payload = covered[8..].to_vec();
        wal[frame + 24..frame + 24 + page].copy_from_slice(&payload);
        return Ok((frame, payload));
    }
    Err("no pair of free words solves the checksum".into())
}

/// The enabled source ids a read of a byte copy of history and `-wal` lists (recovery included).
fn enabled_ids_in_copy(data: &Path) -> TestResult<Vec<String>> {
    let scratch = tempfile::tempdir()?;
    for name in ["history.sqlite", "history.sqlite-wal"] {
        if data.join(name).exists() {
            std::fs::copy(data.join(name), scratch.path().join(name))?;
        }
    }
    let connection = Connection::open(scratch.path().join("history.sqlite"))?;
    let mut statement =
        connection.prepare("SELECT source_id FROM sources WHERE consent = 'enabled' ORDER BY 1")?;
    let ids = statement
        .query_map([], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    Ok(ids)
}

/// A forged data dir: a byte copy (no `-shm`) of a closed history plus the log `build` leaves
/// while an outside connection stays open.
fn forge(
    world: &World,
    name: &str,
    build: impl FnOnce(&Connection) -> TestResult,
) -> TestResult<PathBuf> {
    let copy = world.named(&format!("forged-{name}"));
    std::fs::create_dir(&copy)?;
    let hold = Connection::open(world.data().join("history.sqlite"))?;
    hold.execute_batch("PRAGMA wal_autocheckpoint=0;")?;
    build(&hold)?;
    for file in ["history.sqlite", "history.sqlite-wal"] {
        if world.data().join(file).exists() {
            std::fs::copy(world.data().join(file), copy.join(file))?;
        }
    }
    drop(hold);
    Ok(copy)
}

fn x_row(connection: &Connection, outer: &Path, consent: &str) -> TestResult {
    connection.execute(
        "INSERT INTO sources(source_id, harness, canonical_root, kind, consent) VALUES (?1, 'opencode', ?2, 'custom', ?3)",
        rusqlite::params![X_ID, outer.to_str().unwrap(), consent],
    )?;
    Ok(())
}

fn set_x(connection: &Connection, consent: &str) -> TestResult {
    connection.execute(
        "UPDATE sources SET consent = ?1 WHERE source_id = ?2",
        rusqlite::params![consent, X_ID],
    )?;
    Ok(())
}

struct Observed {
    result: Result<(), store::StoreError>,
    writable: usize,
    admitted: Vec<String>,
    after_recheck: Vec<String>,
    engine: CoreEngine,
    ranges: usize,
}

/// One `load_existing` of `data` with `action` run at every admission point. The enabled rows a
/// byte copy lists are recorded after admission (before the action) and after the recheck.
fn observe(
    world: &World,
    data: &Path,
    mut action: impl FnMut(store::AdmissionPoint) + 'static,
) -> TestResult<Observed> {
    use store::AdmissionPoint;
    let admitted = std::rc::Rc::new(std::cell::RefCell::new(None));
    let after = std::rc::Rc::new(std::cell::RefCell::new(None));
    let ranges = std::rc::Rc::new(std::cell::Cell::new(0_usize));
    let (admitted_slot, after_slot, ranges_slot, watched) = (
        std::rc::Rc::clone(&admitted),
        std::rc::Rc::clone(&after),
        std::rc::Rc::clone(&ranges),
        data.to_path_buf(),
    );
    store::set_admission_hook(Some(Box::new(move |point| {
        // The committed state before any injection: the first hook call precedes every action.
        if admitted_slot.borrow().is_none() {
            *admitted_slot.borrow_mut() = Some(enabled_ids_in_copy(&watched).expect("copy read"));
        }
        if let AdmissionPoint::AfterRecheckRange(index) = point {
            ranges_slot.set(ranges_slot.get().max(index + 1));
        }
        action(point);
        if point == AdmissionPoint::AfterRecheck {
            *after_slot.borrow_mut() = Some(enabled_ids_in_copy(&watched).expect("copy read"));
        }
    })));
    reset_counters();
    let mut engine = CoreEngine::open(data, &world.home());
    let result = engine.load_existing(&LateFs::inert());
    store::set_admission_hook(None);
    let writable = store::writable_open_attempts();
    let (admitted, after_recheck) = (
        admitted.borrow().clone().unwrap_or_default(),
        after.borrow().clone().unwrap_or_default(),
    );
    Ok(Observed {
        result,
        writable,
        admitted,
        after_recheck,
        engine,
        ranges: ranges.get(),
    })
}

/// After an unsupported outside write was admitted: A attaches with its oracle and replay adds
/// zero, X is never attached or read and reports source_overlap_conflict.
fn assert_limit_window(world: &World, mut seen: Observed, id_a: &str, label: &str) -> TestResult {
    use quotern_core::domain::{FailureCode, PassOutcome};
    assert_eq!(seen.result, Ok(()), "{label}");
    assert!(seen.engine.store().is_some(), "{label}: store Some");
    assert_eq!(
        seen.writable, 1,
        "{label}: the documented limit, not a Busy promise"
    );
    assert_eq!(
        seen.admitted,
        vec![id_a.to_owned()],
        "{label}: admission listed X disabled"
    );
    assert_eq!(
        seen.after_recheck,
        vec![id_a.to_owned(), X_ID.to_owned()],
        "{label}: non-vacuity, the bytes list X enabled"
    );
    let source_opens = std::rc::Rc::new(std::cell::Cell::new(0_usize));
    let (counter, outer) = (std::rc::Rc::clone(&source_opens), world.outer());
    quotern_core::ingest::sqlite_ro::set_open_hook(Some(Box::new(move |path, _flags| {
        if path.starts_with(&outer) && path.file_name().is_some_and(|name| name == "opencode.db") {
            counter.set(counter.get() + 1);
        }
    })));
    let tree = tree_image(&world.named("a"));
    seen.engine
        .reattach(LateFs::inert(), id_a, Some(T))
        .map_err(|report| format!("{label}: A: {report:?}"))?;
    let failed = seen
        .engine
        .reattach(LateFs::inert(), X_ID, Some(T))
        .expect_err("X never attaches");
    assert_eq!(failed.failure, Some(FailureCode::RootOverlap), "{label}");
    let cancel = std::sync::atomic::AtomicBool::new(false);
    seen.engine
        .ingest(LateFs::inert, T + 1, &cancel)
        .map_err(|_| "cancelled")?;
    quotern_core::ingest::sqlite_ro::set_open_hook(None);
    assert_eq!(source_opens.get(), 0, "{label}: 0 source opens under X");
    assert!(!seen.engine.is_attached(X_ID), "{label}");
    let entry = seen
        .engine
        .source_entries()?
        .into_iter()
        .find(|entry| entry.source_id == X_ID)
        .ok_or("X entry")?;
    assert_eq!(
        (entry.outcome, entry.last_error_code),
        (
            Some(PassOutcome::Unavailable),
            Some(FailureCode::RootOverlap)
        ),
        "{label}"
    );
    let snapshot = seen
        .engine
        .today_snapshot("UTC", T)
        .map_err(|error| format!("{error:?}"))?;
    let reported = snapshot
        .source_reported
        .iter()
        .find(|row| row.source_id == id_a)
        .ok_or("A reported")?;
    assert_eq!(
        reported.projection.input.value,
        Some(ORACLE_A),
        "{label}: A with its oracle, replay adds zero"
    );
    assert_eq!(
        tree_image(&world.named("a")),
        tree,
        "{label}: harness source digests unchanged"
    );
    Ok(())
}

#[test]
fn admission_outside_writer_windows_are_unsupported() -> TestResult {
    use std::os::unix::fs::FileExt;
    use store::AdmissionPoint;
    let enabled_a = |id: &str| vec![id.to_owned()];

    // Control: X disabled in the committed state; no injection opens at count 1, attaches A and
    // never X.
    {
        let (world, _root, id) = closed_history()?;
        let data = forge(&world, "control", |c| x_row(c, &world.outer(), "denied"))?;
        let seen = observe(&world, &data, |_| {})?;
        assert_eq!(seen.result, Ok(()));
        assert_eq!(
            (
                seen.writable,
                seen.admitted.clone(),
                seen.after_recheck.clone()
            ),
            (1, enabled_a(&id), enabled_a(&id))
        );
    }

    // (a) At AfterOverlay a same-length write of payload bytes in the selected commit frame that
    // disables X (its committed text `Enabled` is not the enabled state), headers untouched.
    {
        let (world, _root, id) = closed_history()?;
        let data = forge(&world, "a", |c| {
            c.execute_batch("PRAGMA ignore_check_constraints = ON;")?;
            x_row(c, &world.outer(), "Enabled")
        })?;
        let mut wal = std::fs::read(data.join("history.sqlite-wal"))?;
        let at = wal
            .windows(7)
            .position(|window| window == b"Enabled")
            .ok_or("X's committed bytes")?;
        // The flip and the compensating rewrite of unused words keep the frame checksum valid.
        let (frame, payload) = flip_with_checksum_kept(&mut wal, at, b'E', b'e')?;
        let path = data.join("history.sqlite-wal");
        let seen = observe(&world, &data, move |point| {
            if point == AdmissionPoint::AfterOverlay {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .write_all_at(&payload, (frame + 24) as u64)
                    .unwrap();
            }
        })?;
        assert_limit_window(&world, seen, &id, "(a) selected commit frame payload")?;
    }

    // (b) At AfterAdmission a payload-only completion of an ignored torn tail commit frame that
    // re-enables X, header bytes untouched.
    {
        let (world, _root, id) = closed_history()?;
        let data = forge(&world, "b", |c| {
            x_row(c, &world.outer(), "denied")?;
            set_x(c, "enabled")
        })?;
        let path = data.join("history.sqlite-wal");
        let mut wal = std::fs::read(&path)?;
        let (page, frames) = wal_frames(&wal);
        let (last, commit) = *frames.last().ok_or("frames")?;
        assert!(commit && frames.len() >= 2);
        let payload = wal[last + 24..last + 24 + page].to_vec();
        wal[last + 24..last + 24 + page].fill(0);
        std::fs::write(&path, &wal)?;
        let seen = observe(&world, &data, move |point| {
            if point == AdmissionPoint::AfterAdmission {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .write_all_at(&payload, (last + 24) as u64)
                    .unwrap();
            }
        })?;
        assert_limit_window(&world, seen, &id, "(b) torn tail completed")?;
    }

    // (e) A torn tail commit whose HEADER (commit size and checksum) is completed at AfterRoots,
    // payload already present: the recorded tail header differs, so the recheck refuses it.
    {
        let (world, _root, _id) = closed_history()?;
        let data = forge(&world, "e", |c| {
            x_row(c, &world.outer(), "denied")?;
            set_x(c, "enabled")
        })?;
        let path = data.join("history.sqlite-wal");
        let mut wal = std::fs::read(&path)?;
        let (_, frames) = wal_frames(&wal);
        let (last, commit) = *frames.last().ok_or("frames")?;
        assert!(commit && frames.len() >= 2);
        let header = wal[last..last + 24].to_vec();
        wal[last + 4..last + 8].fill(0);
        wal[last + 16..last + 24].fill(0);
        std::fs::write(&path, &wal)?;
        let injected = std::rc::Rc::new(std::cell::RefCell::new(None));
        let (slot, imaged) = (std::rc::Rc::clone(&injected), data.clone());
        let mut seen = observe(&world, &data, move |point| {
            if matches!(point, AdmissionPoint::AfterRoots(_)) {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .write_all_at(&header, last as u64)
                    .unwrap();
                *slot.borrow_mut() = Some(history_image(&imaged));
            }
        })?;
        assert_eq!(
            seen.result,
            Err(store::StoreError::Busy),
            "a completed tail header is detected"
        );
        assert_eq!((seen.writable, seen.engine.store().is_none()), (0, true));
        assert!(injected.borrow().is_some(), "(e): the hook fired");
        assert_eq!(
            Some(history_image(&data)),
            injected.borrow().clone(),
            "(e): no effect beyond the injection"
        );
        // The hook-free retry admits the completed commit, which enables X; X never attaches.
        reset_counters();
        seen.engine.load_existing(&LateFs::inert())?;
        assert_eq!(store::writable_open_attempts(), 1, "(e): hook-free retry");
        assert!(
            seen.engine
                .enabled_source_ids()?
                .iter()
                .any(|id| id == X_ID),
            "(e): the completed commit enables X"
        );
        let failed = seen
            .engine
            .reattach(LateFs::inert(), X_ID, Some(T))
            .expect_err("X never attaches");
        assert_eq!(
            failed.failure,
            Some(quotern_core::domain::FailureCode::RootOverlap),
            "(e): hook-free retry: source_overlap_conflict"
        );
        assert!(!seen.engine.is_attached(X_ID), "(e)");
    }

    // (c) At AfterAdmission a same-length rewrite of the checksum bytes in the header of an earlier
    // commit frame that disables X; the last commit frame and later headers are untouched.
    {
        let (world, _root, id) = closed_history()?;
        let data = forge(&world, "c", |c| {
            x_row(c, &world.outer(), "enabled")?;
            set_x(c, "denied")?;
            c.execute(
                "INSERT INTO sources(source_id, harness, canonical_root, kind, consent) VALUES ('dddddddddddddddddddddddddddddddd', 'opencode', '/nowhere/z', 'custom', 'denied')",
                [],
            )?;
            Ok(())
        })?;
        let path = data.join("history.sqlite-wal");
        let wal = std::fs::read(&path)?;
        let commits: Vec<usize> = wal_frames(&wal)
            .1
            .into_iter()
            .filter(|(_, commit)| *commit)
            .map(|(offset, _)| offset)
            .collect();
        assert_eq!(commits.len(), 3, "enable, disable, later commit");
        let (earlier, checksum) = (
            commits[1],
            wal[commits[1] + 16..commits[1] + 24]
                .iter()
                .map(|byte| !byte)
                .collect::<Vec<u8>>(),
        );
        let seen = observe(&world, &data, move |point| {
            if point == AdmissionPoint::AfterAdmission {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .write_all_at(&checksum, (earlier + 16) as u64)
                    .unwrap();
            }
        })?;
        assert_limit_window(&world, seen, &id, "(c) earlier commit checksum rewritten")?;
    }

    // (d) X disabled in the main file with no `-wal`: a same-length main-file write enabling X
    // after the range holding X's `sources` page compared equal, with a range still uncompared.
    {
        let outcomes = |at_range: Option<usize>| -> TestResult<(Observed, World)> {
            let (world, _root, _id) = closed_history()?;
            {
                let c = Connection::open(world.data().join("history.sqlite"))?;
                c.execute_batch("PRAGMA ignore_check_constraints = ON;")?;
                x_row(&c, &world.outer(), "Enabled")?;
                // Pad rows after X's push the table onto further leaf pages, read after X's.
                for index in 0..40 {
                    c.execute(
                        "INSERT INTO sources(source_id, harness, canonical_root, kind, consent) VALUES (?1, 'opencode', ?2, 'custom', 'denied')",
                        rusqlite::params![format!("{index:032x}"), format!("/quotern-pad/{index}/{}", "x".repeat(300))],
                    )?;
                }
            }
            assert!(!world.data().join("history.sqlite-wal").exists(), "no -wal");
            let main = world.data().join("history.sqlite");
            let bytes = std::fs::read(&main)?;
            let at = bytes
                .windows(7)
                .position(|window| window == b"Enabled")
                .ok_or("X's main bytes")? as u64;
            let data = world.data();
            let seen = observe(&world, &data, move |point| {
                if let (AdmissionPoint::AfterRecheckRange(index), Some(target)) = (point, at_range)
                    && index == target
                {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&main)
                        .unwrap()
                        .write_all_at(b"e", at)
                        .unwrap();
                }
            })?;
            Ok((seen, world))
        };
        let (baseline, _world) = outcomes(None)?;
        assert_eq!(baseline.result, Ok(()));
        let total = baseline.ranges;
        assert!(total >= 2, "recorded ranges: {total}");
        let mut results = Vec::new();
        for index in 0..total {
            let (seen, _world) = outcomes(Some(index))?;
            results.push((
                index,
                seen.result.clone().err(),
                seen.writable,
                seen.after_recheck.len(),
            ));
        }
        let first_open = results
            .iter()
            .position(|(_, error, _, _)| error.is_none())
            .ok_or("some index opens")?;
        assert!(
            results[..first_open]
                .iter()
                .all(
                    |(_, error, writable, _)| *error == Some(store::StoreError::Busy)
                        && *writable == 0
                ),
            "{results:?}"
        );
        assert!(
            results[first_open..]
                .iter()
                .all(|(_, error, writable, _)| error.is_none() && *writable == 1),
            "{results:?}"
        );
        assert!(
            first_open + 1 < total,
            "at least one recorded range is still uncompared: {results:?}"
        );
    }
    Ok(())
}

/// H1's first valid selection pauses after its directory chain created D and before `flock`,
/// while H2 opens D (history absent), claims it and holds it.
fn cold_race() -> TestResult {
    use std::sync::mpsc::channel;
    let world = World::with_source(&daily_rows())?;
    let (data, source, config) = (world.data(), world.source(), world.config());
    let digest = tree_image(&source);
    let (paused_tx, paused_rx) = channel::<(u64, u64)>();
    let (go_tx, go_rx) = channel::<()>();
    let (first_tx, first_rx) = channel::<(Value, (usize, usize))>();
    let (retry_tx, retry_rx) = channel::<()>();
    let thread_data = data.clone();
    let worker = std::thread::spawn(move || {
        let (h1, _) = open_with(&config);
        let h1 = h1.expect("H1 opens");
        store::set_owner_claim_hook(Some(Box::new(move || {
            let metadata = std::fs::metadata(&thread_data).expect("D exists once the chain ran");
            paused_tx
                .send((metadata.dev(), metadata.ino()))
                .expect("main listens");
            go_rx.recv().expect("main resumes");
        })));
        reset_counters();
        let first = h1.select(&source);
        let counts = counters();
        store::set_owner_claim_hook(None);
        first_tx.send((first, counts)).expect("main listens");
        retry_rx.recv().expect("main retries");
        reset_counters();
        let second = h1.select(&source);
        let counts = counters();
        h1.ingest(T);
        let id = h1.id_of("source");
        (second, counts, h1.input(&id))
    });
    let identity = paused_rx.recv()?;
    let h2 = world.live(); // D exists, history absent: H2 claims D and holds it
    assert!(!data.join("history.sqlite").exists());
    go_tx.send(())?;
    let (first, counts) = first_rx.recv()?;
    assert_eq!(code(&first), BUSY, "{first}");
    assert_eq!(
        counts,
        (1, 0),
        "writable_open_attempts()==1 (the chain) and history_descriptor_opens()==0"
    );
    let metadata = std::fs::metadata(&data)?;
    assert_eq!(
        (metadata.dev(), metadata.ino()),
        identity,
        "D is neither deleted nor replaced"
    );
    assert_eq!(
        history_image(&data).values().flatten().count(),
        0,
        "no history, -wal, -shm or -journal"
    );
    assert_eq!(
        tree_image(&world.source()),
        digest,
        "source digests unchanged"
    );
    drop(h2);
    retry_tx.send(())?;
    let (second, counts, input) = worker.join().expect("H1 thread");
    assert_eq!(second["ok"], json!(true), "{second}");
    assert_eq!(counts, (1, counts.1), "the history open only");
    assert!(counts.1 >= 1);
    assert_eq!(input, json!(ORACLE_A), "H1 attaches with its oracle");
    Ok(())
}
