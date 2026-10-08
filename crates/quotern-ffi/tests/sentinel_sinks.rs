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
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries {
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
}

impl Session {
    fn open(data: &Path, home: &Path) -> TestResult<Self> {
        let config = CString::new(json!({"data_dir": data, "home": home}).to_string())?;
        let mut engine = std::ptr::null_mut();
        let response = text(unsafe { quotern_engine_open(config.as_ptr(), &mut engine) });
        assert!(!engine.is_null(), "{response}");
        let mut session = Self {
            engine,
            responses: BTreeMap::new(),
            data: data.to_path_buf(),
            failed: false,
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
        let mut sinks = file_sinks(&self.data)?;
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
            bytes: if self.data.join("history.sqlite").exists() {
                table_dump(&self.data)?
            } else {
                Vec::new()
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
