//! Sink inventory of the Rust side of the bridge. A sentinel planted in OpenCode content, model
//! and provider text, and in hostile request fields, must reach no sink the application owns:
//! every ABI response, every error envelope, the history files and a dump of every history
//! table. The inventory itself is falsifiable: a planted leak, an undeclared sink and a declared
//! but unscanned sink are each rejected.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};

use quotern_ffi::*;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SENTINEL: &str = "QUOTERN-SENTINEL-4F2A";
const T: i64 = 1_775_124_000_000;

/// Every file the application may own in its data directory.
const ALLOWED_FILES: [&str; 3] = [
    "file:history.sqlite",
    "file:history.sqlite-shm",
    "file:history.sqlite-wal",
];
/// Every ABI response sink, by the method that produced it, plus the table dump.
const SERIALIZED_SINKS: [&str; 8] = [
    "open-response",
    "set_source_selection-response",
    "list_sources-response",
    "ingest-response",
    "today_snapshot-response",
    "error-responses",
    "history-table-dump",
    "failed-handle-responses",
];

struct Sink {
    name: String,
    bytes: Vec<u8>,
}

fn contains_sentinel(bytes: &[u8]) -> bool {
    bytes
        .windows(SENTINEL.len())
        .any(|window| window == SENTINEL.as_bytes())
}

#[derive(Debug, Default, Eq, PartialEq)]
struct Findings {
    leaks: BTreeSet<String>,
    /// Sinks that exist but were never declared.
    unexpected: BTreeSet<String>,
    /// Sinks declared but never scanned.
    unscanned: BTreeSet<String>,
}

fn scan(sinks: &[Sink], declared: &BTreeSet<String>) -> Findings {
    let scanned: BTreeSet<String> = sinks.iter().map(|sink| sink.name.clone()).collect();
    Findings {
        leaks: sinks
            .iter()
            .filter(|sink| contains_sentinel(&sink.bytes))
            .map(|sink| sink.name.clone())
            .collect(),
        unexpected: scanned.difference(declared).cloned().collect(),
        unscanned: declared.difference(&scanned).cloned().collect(),
    }
}

fn declared(files: &[Sink]) -> BTreeSet<String> {
    let mut declared: BTreeSet<String> = SERIALIZED_SINKS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    declared.extend(
        files
            .iter()
            .filter(|sink| ALLOWED_FILES.contains(&sink.name.as_str()))
            .map(|sink| sink.name.clone()),
    );
    declared
}

fn file_sinks(root: &Path) -> std::io::Result<Vec<Sink>> {
    let mut pending = vec![root.to_path_buf()];
    let mut sinks = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                let relative = path.strip_prefix(root).map_err(std::io::Error::other)?;
                sinks.push(Sink {
                    name: format!("file:{}", relative.display()),
                    bytes: std::fs::read(&path)?,
                });
            }
        }
    }
    Ok(sinks)
}

/// Every text and blob value of every table, through an independent read-only connection.
fn table_dump(data: &Path) -> TestResult<Vec<u8>> {
    let connection = Connection::open_with_flags(
        data.join("history.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let tables = connection
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut dump = Vec::new();
    for table in tables {
        let mut statement = connection.prepare(&format!("SELECT * FROM \"{table}\""))?;
        let columns = statement.column_count();
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            for index in 0..columns {
                match row.get_ref(index)? {
                    ValueRef::Text(bytes) | ValueRef::Blob(bytes) => dump.extend_from_slice(bytes),
                    ValueRef::Integer(value) => {
                        dump.extend_from_slice(value.to_string().as_bytes())
                    }
                    ValueRef::Real(value) => dump.extend_from_slice(value.to_string().as_bytes()),
                    ValueRef::Null => {}
                }
                dump.push(b'\t');
            }
            dump.push(b'\n');
        }
    }
    Ok(dump)
}

fn text(pointer: *mut std::ffi::c_char) -> String {
    assert!(!pointer.is_null());
    let value = unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned();
    unsafe { quotern_string_free(pointer) };
    value
}

/// One handle plus every response string it returned, kept by sink name.
struct Session {
    engine: *mut QuoternEngine,
    responses: BTreeMap<String, Vec<u8>>,
    data: PathBuf,
    failed: bool,
    storage_present_at_open: bool,
}

impl Session {
    fn open(data: &Path, home: &Path) -> TestResult<Self> {
        let storage_present_at_open = match std::fs::symlink_metadata(data) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let config = CString::new(json!({"data_dir": data, "home": home}).to_string())?;
        let mut engine = std::ptr::null_mut();
        let response = text(unsafe { quotern_engine_open(config.as_ptr(), &mut engine) });
        assert!(!engine.is_null(), "{response}");
        let mut session = Self {
            engine,
            responses: BTreeMap::new(),
            data: data.to_path_buf(),
            failed: false,
            storage_present_at_open,
        };
        session.record("open-response", &response);
        Ok(session)
    }

    fn record(&mut self, sink: &str, response: &str) {
        self.responses
            .entry(sink.to_owned())
            .or_default()
            .extend_from_slice(response.as_bytes());
    }

    fn call(&mut self, method: &str, request: &str) -> Value {
        let (name, body) = (
            CString::new(method).unwrap(),
            CString::new(request).unwrap(),
        );
        let response = text(unsafe {
            quotern_call(self.engine, name.as_ptr(), body.as_ptr(), std::ptr::null())
        });
        let value: Value = serde_json::from_str(&response).unwrap();
        let sink = if self.failed {
            "failed-handle-responses".to_owned()
        } else if value["ok"] == json!(true) {
            format!("{method}-response")
        } else {
            "error-responses".to_owned()
        };
        let sink = if SERIALIZED_SINKS.contains(&sink.as_str()) {
            sink
        } else {
            "error-responses".to_owned()
        };
        self.record(&sink, &response);
        value
    }

    /// Every sink of the current state: files, responses and the table dump.
    fn sinks(&self) -> TestResult<Vec<Sink>> {
        // A fresh engine creates no storage until its first accepted selection.
        let absent_preselection = !self.storage_present_at_open
            && !self.responses.contains_key("set_source_selection-response")
            && matches!(std::fs::symlink_metadata(&self.data), Err(error) if error.kind() == std::io::ErrorKind::NotFound);
        let mut sinks = if absent_preselection {
            Vec::new()
        } else {
            file_sinks(&self.data)?
        };
        for name in SERIALIZED_SINKS {
            if name != "history-table-dump" {
                sinks.push(Sink {
                    name: name.to_owned(),
                    bytes: self.responses.get(name).cloned().unwrap_or_default(),
                });
            }
        }
        sinks.push(Sink {
            name: "history-table-dump".to_owned(),
            bytes: if absent_preselection {
                Vec::new()
            } else {
                table_dump(&self.data)?
            },
        });
        Ok(sinks)
    }

    fn assert_clean(&self) -> TestResult<usize> {
        let sinks = self.sinks()?;
        let present = declared(&sinks);
        assert_eq!(
            scan(&sinks, &present),
            Findings::default(),
            "sink inventory"
        );
        Ok(sinks.len())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe { quotern_engine_close(self.engine) };
    }
}

fn tokens(input: u64) -> Value {
    json!({"input": input, "output": 0, "reasoning": 0, "cache": {"read": 0, "write": 0}, "total": input})
}

/// OpenCode rows carrying the sentinel in text the store never persists, plus a source file whose
/// name is the sentinel.
fn build_source(root: &Path) -> TestResult {
    std::fs::create_dir_all(root)?;
    let connection = Connection::open(root.join("opencode.db"))?;
    let schema: String = include_str!("../../../Fixtures/harness/opencode/wal/schema.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with("PRAGMA"))
        .collect::<Vec<_>>()
        .join("\n");
    connection.execute_batch(&schema)?;
    for index in 0..4_u64 {
        let data = json!({
            "role": "assistant", "content": SENTINEL, "modelID": SENTINEL, "providerID": SENTINEL,
            "model": {"modelID": SENTINEL, "providerID": SENTINEL}, "tokens": tokens(index + 1),
        });
        connection.execute(
            "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, 's', ?2, ?3)",
            rusqlite::params![
                format!("m{index}"),
                T + i64::try_from(index).unwrap(),
                serde_json::to_vec(&data)?
            ],
        )?;
    }
    std::fs::write(root.join(format!("{SENTINEL}.txt")), SENTINEL)?;
    Ok(())
}

fn world() -> TestResult<(tempfile::TempDir, PathBuf, PathBuf, PathBuf)> {
    let directory = tempfile::tempdir()?;
    let base = directory.path().canonicalize()?;
    std::fs::create_dir(base.join("home"))?;
    let (data, home, source) = (base.join("data"), base.join("home"), base.join("source"));
    build_source(&source)?;
    Ok((directory, data, home, source))
}

/// Hostile request fields: the sentinel as a key, a zone, a root and a method name.
fn hostile(session: &mut Session) {
    let mut key = serde_json::Map::new();
    key.insert(SENTINEL.to_owned(), json!(1));
    session.call("list_sources", &Value::Object(key).to_string());
    session.call(
        "today_snapshot",
        &json!({"tz": SENTINEL, "now_ms": T}).to_string(),
    );
    session.call(
        "today_snapshot",
        &json!({"tz": "UTC", "now_ms": -1, SENTINEL: 1}).to_string(),
    );
    session.call(
        "set_source_selection",
        &json!({"harness": SENTINEL, "root": format!("/{SENTINEL}/absent"), "selected": true})
            .to_string(),
    );
    session.call(SENTINEL, "{}");
    session.call("ingest", &format!("{{\"now_ms\":\"{SENTINEL}\"}}"));
}

#[test]
fn opencode_text_and_hostile_requests_never_reach_bridge_sinks() -> TestResult {
    let (_directory, data, home, source) = world()?;
    let source_before = file_sinks(&source)?
        .into_iter()
        .map(|sink| (sink.name, sink.bytes))
        .collect::<BTreeMap<_, _>>();
    assert!(
        source_before.values().any(|bytes| contains_sentinel(bytes)),
        "the source really carries the sentinel"
    );

    let mut scanned = 0;
    let mut session = Session::open(&data, &home)?;
    hostile(&mut session);
    scanned += session.assert_clean()?;
    assert_eq!(
        session.call(
            "set_source_selection",
            &json!({"harness": "opencode", "root": source, "selected": true}).to_string()
        )["ok"],
        json!(true)
    );
    scanned += session.assert_clean()?;
    assert_eq!(
        session.call("ingest", &json!({"now_ms": T}).to_string())["ok"],
        json!(true)
    );
    let snapshot = session.call(
        "today_snapshot",
        &json!({"tz": "UTC", "now_ms": T}).to_string(),
    );
    assert_eq!(snapshot["data"]["source_reported"][0]["records"], json!(4));
    assert_eq!(
        snapshot["data"]["source_reported"][0]["input"]["value"],
        json!(10),
        "independent oracle 1+2+3+4"
    );
    session.call("list_sources", "{}");
    hostile(&mut session);
    scanned += session.assert_clean()?;

    // A cancelled pass, an injected panic (internal_panic, then engine_failed), every response.
    let token = quotern_cancel_new();
    unsafe { quotern_cancel_trigger(token) };
    let (name, body) = (
        CString::new("ingest")?,
        CString::new(json!({"now_ms": T + 1}).to_string())?,
    );
    let cancelled =
        text(unsafe { quotern_call(session.engine, name.as_ptr(), body.as_ptr(), token) });
    unsafe { quotern_cancel_free(token) };
    assert!(cancelled.contains("cancelled"));
    session.record("error-responses", &cancelled);
    scanned += session.assert_clean()?;
    {
        let connection = Connection::open(source.join("opencode.db"))?;
        connection.execute(
            "INSERT INTO message(id, session_id, time_created, data) VALUES ('later', 's', ?1, ?2)",
            rusqlite::params![
                T + 9,
                serde_json::to_vec(
                    &json!({"role": "assistant", "content": SENTINEL, "tokens": tokens(5)})
                )?
            ],
        )?;
    }
    quotern_core::store::panic_next_commit();
    let panicked = session.call("ingest", &json!({"now_ms": T + 2}).to_string());
    assert_eq!(panicked["error"]["code"], json!("internal_panic"));
    session.failed = true;
    for method in ["list_sources", "today_snapshot", "ingest"] {
        let failed = session.call(method, "{}");
        assert_eq!(failed["error"]["code"], json!("engine_failed"));
    }
    scanned += session.assert_clean()?;
    drop(session);

    // Across close and reopen the retained history is clean and the source is unchanged.
    let mut reopened = Session::open(&data, &home)?;
    reopened.call(
        "today_snapshot",
        &json!({"tz": "UTC", "now_ms": T}).to_string(),
    );
    reopened.call("ingest", &json!({"now_ms": T + 3}).to_string());
    hostile(&mut reopened);
    scanned += reopened.assert_clean()?;
    let snapshot = reopened.call(
        "today_snapshot",
        &json!({"tz": "UTC", "now_ms": T}).to_string(),
    );
    assert_eq!(
        snapshot["data"]["source_reported"][0]["input"]["value"],
        json!(15),
        "the committed record counts once"
    );
    drop(reopened);

    let source_after = file_sinks(&source)?
        .into_iter()
        .map(|sink| (sink.name, sink.bytes))
        .collect::<BTreeMap<_, _>>();
    let changed: Vec<_> = source_after
        .keys()
        .filter(|name| source_before.get(*name) != source_after.get(*name))
        .cloned()
        .collect();
    assert_eq!(
        changed,
        ["file:opencode.db".to_owned()],
        "only the test's own appended row changed the source"
    );
    assert!(scanned > 20, "states scanned: {scanned}");
    Ok(())
}

#[test]
fn codex_text_and_hostile_requests_never_reach_bridge_sinks() -> TestResult {
    use std::io::Write;
    let directory = tempfile::tempdir()?;
    let base = directory.path().canonicalize()?;
    let (data, home, source) = (
        base.join("data"),
        base.join("home"),
        base.join("codex-home"),
    );
    std::fs::create_dir(&home)?;
    std::fs::create_dir_all(source.join("sessions/2026/04/02"))?;
    let session_id = "0195f000-0000-7000-8000-00000000ff01";
    let header = json!({"timestamp": "2026-04-02T09:00:00.000Z", "type": "session_meta", "payload": {"id": session_id, "source": "cli", "cli_version": "0.153.0", "cwd": SENTINEL, "instructions": SENTINEL}});
    let record = |response: &str, input: u64| json!({"timestamp": "2026-04-02T09:01:00.000Z", "type": "token_usage_record", "payload": {"thread_id": session_id, "session_id": session_id, "response_id": response, "model": SENTINEL, "provider": SENTINEL, "content": SENTINEL, "usage": {"input_tokens": input, "total_tokens": input}}});
    let path = source.join("sessions/2026/04/02/rollout-sentinel.jsonl");
    std::fs::write(&path, format!("{header}\n{}\n", record("resp", 10)))?;
    std::fs::write(
        source.join("auth.json"),
        format!("{{\"api_key\":\"{SENTINEL}\"}}"),
    )?;
    let before = file_sinks(&source)?
        .into_iter()
        .map(|sink| (sink.name, sink.bytes))
        .collect::<BTreeMap<_, _>>();
    assert!(before.values().any(|bytes| contains_sentinel(bytes)));
    let mut session = Session::open(&data, &home)?;
    hostile(&mut session);
    let mut scanned = session.assert_clean()?;
    assert_eq!(
        session.call(
            "set_source_selection",
            &json!({"harness": "codex", "root": source, "selected": true}).to_string()
        )["ok"],
        json!(true)
    );
    assert_eq!(
        session.call("ingest", &json!({"now_ms": T}).to_string())["ok"],
        json!(true)
    );
    let snapshot = session.call(
        "today_snapshot",
        &json!({"tz": "UTC", "now_ms": T}).to_string(),
    );
    assert_eq!(snapshot["data"]["by_source"][0]["harness"], json!("codex"));
    assert_eq!(
        snapshot["data"]["source_reported"][0]["input"]["value"],
        json!(10)
    );
    assert_eq!(
        snapshot["data"]["source_reported"][0]["origin_uncertainty"],
        json!("unverified_origin")
    );
    session.call("list_sources", "{}");
    scanned += session.assert_clean()?;
    assert_eq!(
        file_sinks(&source)?
            .into_iter()
            .map(|sink| (sink.name, sink.bytes))
            .collect::<BTreeMap<_, _>>(),
        before
    );
    let token = quotern_cancel_new();
    unsafe { quotern_cancel_trigger(token) };
    let (name, body) = (
        CString::new("ingest")?,
        CString::new(json!({"now_ms": T + 1}).to_string())?,
    );
    let cancelled =
        text(unsafe { quotern_call(session.engine, name.as_ptr(), body.as_ptr(), token) });
    unsafe { quotern_cancel_free(token) };
    assert_eq!(
        serde_json::from_str::<Value>(&cancelled)?["error"]["code"],
        json!("cancelled")
    );
    session.record("error-responses", &cancelled);
    scanned += session.assert_clean()?;
    writeln!(
        std::fs::OpenOptions::new().append(true).open(&path)?,
        "{}",
        record("resp_later", 5)
    )?;
    quotern_core::store::panic_next_commit();
    assert_eq!(
        session.call("ingest", &json!({"now_ms": T + 2}).to_string())["error"]["code"],
        json!("internal_panic")
    );
    session.failed = true;
    for method in ["list_sources", "today_snapshot", "ingest"] {
        assert_eq!(
            session.call(method, "{}")["error"]["code"],
            json!("engine_failed")
        );
    }
    scanned += session.assert_clean()?;
    drop(session);
    let mut reopened = Session::open(&data, &home)?;
    assert_eq!(
        reopened.call("ingest", &json!({"now_ms": T + 3}).to_string())["ok"],
        json!(true)
    );
    let snapshot = reopened.call(
        "today_snapshot",
        &json!({"tz": "UTC", "now_ms": T}).to_string(),
    );
    assert_eq!(
        snapshot["data"]["source_reported"][0]["total"]["value"],
        json!(15)
    );
    hostile(&mut reopened);
    scanned += reopened.assert_clean()?;
    assert!(scanned > 20, "states scanned: {scanned}");
    Ok(())
}

/// The inventory is falsifiable: a planted leak, an undeclared sink and a declared sink the scan
/// never reached are each rejected with attribution.
#[test]
fn sink_inventory_rejects_extra_and_unscanned_sinks() -> TestResult {
    let (_directory, data, home, source) = world()?;
    let mut session = Session::open(&data, &home)?;
    session.call(
        "set_source_selection",
        &json!({"harness": "opencode", "root": source, "selected": true}).to_string(),
    );
    session.call("ingest", &json!({"now_ms": T}).to_string());
    session.call(
        "today_snapshot",
        &json!({"tz": "UTC", "now_ms": T}).to_string(),
    );
    session.call("list_sources", "\"x\"");

    let sinks = session.sinks()?;
    let declared_sinks = declared(&sinks);
    assert_eq!(scan(&sinks, &declared_sinks), Findings::default());

    // A sink holding the sentinel is a leak and, being undeclared, an unexpected sink.
    let mut leaking = session.sinks()?;
    leaking.push(Sink {
        name: "file:diagnostics.log".to_owned(),
        bytes: SENTINEL.as_bytes().to_vec(),
    });
    let found = scan(&leaking, &declared_sinks);
    assert_eq!(
        found.leaks,
        BTreeSet::from(["file:diagnostics.log".to_owned()])
    );
    assert_eq!(
        found.unexpected,
        BTreeSet::from(["file:diagnostics.log".to_owned()])
    );

    // A leak inside a declared sink is attributed to it.
    let mut inside = session.sinks()?;
    inside
        .iter_mut()
        .find(|sink| sink.name == "list_sources-response")
        .unwrap()
        .bytes
        .extend_from_slice(SENTINEL.as_bytes());
    assert_eq!(
        scan(&inside, &declared_sinks).leaks,
        BTreeSet::from(["list_sources-response".to_owned()])
    );

    // An undeclared clean sink is still rejected by the inventory.
    let mut extra = session.sinks()?;
    extra.push(Sink {
        name: "file:spill.tmp".to_owned(),
        bytes: b"clean".to_vec(),
    });
    let found = scan(&extra, &declared_sinks);
    assert!(found.leaks.is_empty());
    assert_eq!(
        found.unexpected,
        BTreeSet::from(["file:spill.tmp".to_owned()])
    );

    // A declared sink that the scan never reached is rejected.
    let mut partial = session.sinks()?;
    partial.retain(|sink| sink.name != "history-table-dump");
    let found = scan(&partial, &declared_sinks);
    assert_eq!(
        found.unscanned,
        BTreeSet::from(["history-table-dump".to_owned()])
    );
    assert!(found.leaks.is_empty() && found.unexpected.is_empty());
    Ok(())
}

#[test]
fn sink_enumeration_rejects_inaccessible_directory() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    assert_ne!(
        unsafe { geteuid() },
        0,
        "permission control requires non-root"
    );
    let (_directory, data, home, source) = world()?;
    let mut session = Session::open(&data, &home)?;
    assert!(!data.exists());
    assert_eq!(
        session.sinks()?.len(),
        SERIALIZED_SINKS.len(),
        "absent preselection storage is legitimate"
    );
    assert_eq!(
        session.call(
            "set_source_selection",
            &json!({"harness": "opencode", "root": source, "selected": true}).to_string()
        )["ok"],
        json!(true)
    );
    let hidden = data.join("inaccessible");
    std::fs::create_dir(&hidden)?;
    std::fs::write(hidden.join("diagnostics.log"), SENTINEL)?;
    std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o000))?;
    let inaccessible = session.sinks();
    std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o700))?;
    let error = inaccessible
        .err()
        .ok_or("unreadable sink directory was silently skipped")?;
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::PermissionDenied)
    );
    assert!(
        scan(&session.sinks()?, &declared(&session.sinks()?))
            .leaks
            .contains("file:inaccessible/diagnostics.log")
    );
    assert!(
        file_sinks(&data.join("missing")).is_err(),
        "raw traversal never hides a missing root"
    );
    Ok(())
}

#[test]
fn sink_enumeration_rejects_missing_reopened_storage() -> TestResult {
    let (_directory, data, home, source) = world()?;
    let mut session = Session::open(&data, &home)?;
    assert_eq!(
        session.call(
            "set_source_selection",
            &json!({"harness": "opencode", "root": source, "selected": true}).to_string()
        )["ok"],
        json!(true)
    );
    drop(session);
    let reopened = Session::open(&data, &home)?;
    std::fs::rename(&data, data.with_extension("moved"))?;
    let error = reopened
        .sinks()
        .err()
        .ok_or("missing existing storage was treated as preselection")?;
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::NotFound)
    );
    Ok(())
}
