//! Codex source-reported ingestion (DEC-077): own-header ownership, fail-closed headers, the
//! legacy coverage era, identity and mirror precedence, the store v1 Codex extension and the
//! shared reported projection. Every expectation comes from the hand-written oracles under
//! `Fixtures/harness/codex/`, `Fixtures/hostile/codex/` and `Fixtures/harness/opencode/peer/`, or
//! from inline line specs whose numbers are read off the lines themselves.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use quotern_core::domain::{
    ConsentState, FailureCode, PassOutcome, PassReport, SourceAuthorization, SourceKind,
};
use quotern_core::ingest::fs::{OpenKind, RealSourceFs, RecordingFs};
use quotern_core::ingest::{Engine, PassCancelled};
use quotern_core::store::{FaultPoint, Store, StoreError};
use rusqlite::Connection;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const BASIC: &str = include_str!("../../../Fixtures/harness/codex/basic/expected.json");
const INCREMENTAL: &str = include_str!("../../../Fixtures/harness/codex/incremental/expected.json");
const HEADERS: &str = include_str!("../../../Fixtures/harness/codex/headers/expected.json");
const HOSTILE_CASES: &str = include_str!("../../../Fixtures/hostile/codex/cases.json");
const HOSTILE_EXPECTED: &str = include_str!("../../../Fixtures/hostile/codex/expected.json");
const PEER_CASES: &str = include_str!("../../../Fixtures/harness/opencode/peer/cases.json");
const PEER_EXPECTED: &str = include_str!("../../../Fixtures/harness/opencode/peer/expected.json");
const OPENCODE_SCHEMA: &str = include_str!("../../../Fixtures/harness/opencode/wal/schema.sql");

const BASIC_FILE: &str = "sessions/2026/03/29/rollout-2026-03-29T09-00-00-basic.jsonl";
const DAY_NOW: i64 = 1_774_785_600_000;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Fixtures")
}

fn json(text: &str) -> TestResult<Value> {
    Ok(serde_json::from_str(text)?)
}

fn enabled() -> SourceAuthorization {
    SourceAuthorization {
        selected: true,
        consent: ConsentState::Enabled,
    }
}

/// The record identity written out by hand: every component with its decimal byte length.
fn key(source_id: &str, session: &str, response: &str) -> String {
    format!(
        "codex:{}:{source_id}:{}:{session}:{}:{response}",
        source_id.len(),
        session.len(),
        response.len()
    )
}

struct World {
    _directory: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    data: PathBuf,
    home: PathBuf,
}

impl World {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let base = directory.path().canonicalize()?;
        let root = base.join("codex-home");
        let home = base.join("home");
        std::fs::create_dir(&root)?;
        std::fs::create_dir(&home)?;
        Ok(Self {
            data: base.join("data"),
            _directory: directory,
            base,
            root,
            home,
        })
    }

    fn put(&self, relative: &str, bytes: &[u8]) -> TestResult<PathBuf> {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, bytes)?;
        Ok(path)
    }

    /// Copies one fixture file to `relative` under the root.
    fn fixture(&self, fixture: &str, relative: &str) -> TestResult<PathBuf> {
        self.put(relative, &std::fs::read(fixtures().join(fixture))?)
    }

    fn basic(&self) -> TestResult<PathBuf> {
        self.fixture(&format!("harness/codex/basic/{BASIC_FILE}"), BASIC_FILE)
    }

    fn engine(&self) -> TestResult<(Engine<RealSourceFs>, String)> {
        let mut engine = Engine::open(&self.data, &self.home);
        let id = engine
            .attach_codex(RealSourceFs, &self.root, enabled(), SourceKind::Custom)
            .map_err(|report| format!("attach_codex failed: {report:?}"))?;
        Ok((engine, id))
    }

    fn history(&self) -> TestResult<Connection> {
        Ok(Connection::open(self.data.join("history.sqlite"))?)
    }
}

fn sql_value(value: rusqlite::types::ValueRef<'_>) -> Value {
    use rusqlite::types::ValueRef;
    match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(number) => json!(number),
        ValueRef::Real(number) => json!(number),
        ValueRef::Text(text) => json!(String::from_utf8_lossy(text)),
        ValueRef::Blob(bytes) => json!(bytes),
    }
}

/// Every row of `sql` as an object keyed by column name.
fn objects(
    connection: &Connection,
    sql: &str,
    parameters: &[&dyn rusqlite::ToSql],
) -> TestResult<Vec<Value>> {
    let mut statement = connection.prepare(sql)?;
    let names: Vec<String> = statement
        .column_names()
        .iter()
        .map(|name| name.to_string())
        .collect();
    let mut rows = statement.query(parameters)?;
    let mut found = Vec::new();
    while let Some(row) = rows.next()? {
        let mut object = serde_json::Map::new();
        for (index, name) in names.iter().enumerate() {
            object.insert(name.clone(), sql_value(row.get_ref(index)?));
        }
        found.push(Value::Object(object));
    }
    Ok(found)
}

const EVENT_COLUMNS: &str = "event_key, family, measurement_kind, harness, source_id, session_id, \
    message_id, occurred_at_ms, input_tokens, cache_read_tokens, cache_write_tokens, output_tokens, \
    reasoning_tokens, total_tokens, total_provenance, source_convention, acquisition_consistency, \
    origin_uncertainty, total_mismatch, mirror_conflict, selected_part_ids, format_rank, mirror_path, \
    pending_partial, pending_reason, revision";

fn events(connection: &Connection, source_id: &str) -> TestResult<Vec<Value>> {
    objects(
        connection,
        &format!(
            "SELECT {EVENT_COLUMNS} FROM usage_events WHERE source_id = ?1 \
             ORDER BY occurred_at_ms, event_key"
        ),
        &[&source_id],
    )
}

fn file_state(connection: &Connection, source_id: &str, relative: &str) -> TestResult<Value> {
    objects(
        connection,
        "SELECT byte_offset, header_id, header_state, header_era, record_state, tail_state, \
         uncovered_from_ms, uncovered_to_ms, file_state FROM source_files \
         WHERE source_id = ?1 AND relative_path = ?2",
        &[&source_id, &relative],
    )?
    .into_iter()
    .next()
    .ok_or_else(|| format!("no source_files row for {relative}").into())
}

fn count(
    connection: &Connection,
    sql: &str,
    parameters: &[&dyn rusqlite::ToSql],
) -> TestResult<i64> {
    Ok(connection.query_row(sql, parameters, |row| row.get(0))?)
}

/// Asserts each expected key of `expected` on `actual`.
fn assert_fields(actual: &Value, expected: &Value, label: &str) {
    let Some(fields) = expected.as_object() else {
        panic!("{label}: oracle is not an object");
    };
    for (name, value) in fields {
        assert_eq!(&actual[name], value, "{label}: field {name} of {actual}");
    }
}

/// Asserts one stored row against an oracle event: identity composed by hand, every column.
fn assert_event(row: &Value, expected: &Value, source_id: &str, label: &str) {
    let session = expected["session_id"].as_str().expect("session");
    let response = expected["response_id"].as_str().expect("response");
    assert_eq!(
        row["event_key"],
        json!(key(source_id, session, response)),
        "{label}"
    );
    assert_eq!(row["source_id"], json!(source_id), "{label}");
    assert_eq!(row["message_id"], json!(response), "{label}");
    let mut fields = expected.clone();
    if let Some(object) = fields.as_object_mut() {
        object.remove("response_id");
    }
    assert_fields(row, &fields, label);
}

fn snapshot<F: quotern_core::ingest::fs::SourceFs>(
    engine: &Engine<F>,
    tz: &str,
    now_ms: i64,
) -> TestResult<Value> {
    let snapshot = engine
        .today_snapshot(tz, now_ms)
        .map_err(|error| format!("today_snapshot: {error:?}"))?;
    Ok(serde_json::to_value(snapshot)?)
}

fn reported_of(snapshot: &Value, source_id: &str) -> TestResult<Value> {
    snapshot["source_reported"]
        .as_array()
        .and_then(|entries| entries.iter().find(|entry| entry["source_id"] == source_id))
        .cloned()
        .ok_or_else(|| format!("no source_reported entry for {source_id}").into())
}

fn by_source_of(snapshot: &Value, source_id: &str) -> TestResult<Value> {
    snapshot["by_source"]
        .as_array()
        .and_then(|entries| entries.iter().find(|entry| entry["source_id"] == source_id))
        .cloned()
        .ok_or_else(|| format!("no by_source entry for {source_id}").into())
}

/// The scenario oracle's `projection` against a snapshot entry: records and, per listed
/// observation, value, completeness and (when given) status.
fn assert_projection(entry: &Value, expected: &Value, label: &str) {
    assert_eq!(entry["records"], expected["records"], "{label}: records");
    for name in [
        "input",
        "output",
        "reasoning",
        "cache_read",
        "cache_write",
        "total",
    ] {
        let Some(want) = expected.get(name) else {
            continue;
        };
        if want.is_object() {
            assert_fields(&entry[name], want, &format!("{label}: {name}"));
        } else {
            assert_eq!(entry[name]["value"], *want, "{label}: {name} value");
        }
    }
    for observation in [
        "input",
        "output",
        "reasoning",
        "cache_read",
        "cache_write",
        "total",
    ] {
        if entry[observation]["value"].is_null() {
            assert!(
                entry[observation]["completeness"].is_null(),
                "{label}: {observation}"
            );
            assert_eq!(
                entry[observation]["status"], "unavailable",
                "{label}: {observation}"
            );
        }
    }
}

fn pass(engine: &mut Engine<RealSourceFs>, id: &str, now_ms: i64) -> PassReport {
    engine.pass(id, enabled(), now_ms)
}

fn header_line(
    timestamp: &str,
    id: &str,
    forked_from: Option<&str>,
    cli_version: Option<&str>,
) -> String {
    let mut payload = json!({ "id": id, "source": "cli" });
    if let Some(parent) = forked_from {
        payload["forked_from_id"] = json!(parent);
    }
    if let Some(version) = cli_version {
        payload["cli_version"] = json!(version);
    }
    format!(
        "{}\n",
        json!({ "timestamp": timestamp, "type": "session_meta", "payload": payload })
    )
}

fn record_line(
    timestamp: &str,
    thread: &str,
    session: &str,
    response: &str,
    usage: Value,
) -> String {
    let line = json!({
        "timestamp": timestamp,
        "type": "token_usage_record",
        "payload": {
            "thread_id": thread, "turn_id": "turn", "session_id": session,
            "root_turn_id": "turn", "response_id": response, "usage": usage
        }
    });
    format!("{line}\n")
}

fn token_count_line(timestamp: &str) -> String {
    let usage = json!({ "input_tokens": 4000, "output_tokens": 10, "total_tokens": 4010 });
    let line = json!({
        "timestamp": timestamp, "type": "event_msg",
        "payload": { "type": "token_count", "info": { "total_token_usage": usage, "last_token_usage": usage }, "rate_limits": null }
    });
    format!("{line}\n")
}

/// SHA-256 and size of a file, or `None` when it is absent.
fn digest(path: &Path) -> TestResult<Option<(String, u64)>> {
    if !path.exists() {
        return Ok(None);
    }
    let output = Command::new("/usr/bin/shasum")
        .args(["-a", "256"])
        .arg(path)
        .output()?;
    if !output.status.success() {
        return Err("shasum failed".into());
    }
    let text = String::from_utf8(output.stdout)?;
    let hash = text
        .split_whitespace()
        .next()
        .ok_or("shasum output")?
        .to_owned();
    Ok(Some((hash, std::fs::metadata(path)?.len())))
}

fn history_digests(data: &Path) -> TestResult<Vec<Option<(String, u64)>>> {
    ["", "-wal", "-shm", "-journal"]
        .iter()
        .map(|suffix| digest(&data.join(format!("history.sqlite{suffix}"))))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Store v1 Codex extension

fn is_check_failure(result: &rusqlite::Result<usize>) -> bool {
    matches!(
        result,
        Err(rusqlite::Error::SqliteFailure(error, _))
            if error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_CHECK
    )
}

/// An `INSERT` of one row with `defaults`, each named column replaced by its SQL literal.
fn insert(table: &str, defaults: &[(&str, &str)], overrides: &[(&str, &str)]) -> String {
    let columns: Vec<&str> = defaults.iter().map(|(name, _)| *name).collect();
    let values: Vec<String> = defaults
        .iter()
        .map(|(name, value)| {
            overrides
                .iter()
                .find(|(column, _)| column == name)
                .map_or_else(|| (*value).to_owned(), |(_, value)| (*value).to_owned())
        })
        .collect();
    format!(
        "INSERT INTO {table}({}) VALUES ({})",
        columns.join(", "),
        values.join(", ")
    )
}

const CODEX_EVENT: &[(&str, &str)] = &[
    ("event_key", "'codex:3:src:4:sess:4:resp'"),
    ("family", "'codex'"),
    ("measurement_kind", "'source_reported'"),
    ("harness", "'codex'"),
    ("source_id", "'src'"),
    ("session_id", "'sess'"),
    ("message_id", "'resp'"),
    ("occurred_at_ms", "1"),
    ("input_tokens", "1"),
    ("output_tokens", "1"),
    ("reasoning_tokens", "1"),
    ("cache_read_tokens", "1"),
    ("cache_write_tokens", "1"),
    ("total_tokens", "5"),
    ("total_provenance", "'reported'"),
    ("source_convention", "NULL"),
    ("acquisition_consistency", "'file_by_file_best_effort'"),
    ("origin_uncertainty", "'unverified_origin'"),
    ("total_mismatch", "0"),
    ("mirror_conflict", "0"),
    ("selected_part_ids", "'[]'"),
    ("format_rank", "0"),
    ("mirror_path", "'sessions/a.jsonl'"),
    ("pending_partial", "0"),
    ("pending_reason", "NULL"),
    ("revision", "1"),
    ("first_seen_ms", "1"),
    ("updated_ms", "1"),
];

const OPENCODE_EVENT: &[(&str, &str)] = &[
    ("event_key", "'opencode:1:s:8:e0000001'"),
    ("family", "'opencode'"),
    ("measurement_kind", "'source_reported'"),
    ("harness", "'opencode'"),
    ("source_id", "'oc'"),
    ("session_id", "'s'"),
    ("message_id", "'e0000001'"),
    ("occurred_at_ms", "1"),
    ("input_tokens", "10"),
    ("output_tokens", "20"),
    ("reasoning_tokens", "3"),
    ("cache_read_tokens", "4"),
    ("cache_write_tokens", "5"),
    ("total_tokens", "42"),
    ("total_provenance", "'derived'"),
    ("source_convention", "'codexbar-3239175f-disjoint'"),
    ("acquisition_consistency", "'sqlite_read_transaction'"),
    ("origin_uncertainty", "'unverified_origin'"),
    ("total_mismatch", "0"),
    ("mirror_conflict", "0"),
    ("selected_part_ids", "'[\"p1\"]'"),
    ("format_rank", "1"),
    ("mirror_path", "'opencode.db'"),
    ("pending_partial", "1"),
    ("pending_reason", "'invalid_record'"),
    ("revision", "1"),
    ("first_seen_ms", "1"),
    ("updated_ms", "1"),
];

const CODEX_FILE: &[(&str, &str)] = &[
    ("source_id", "'src'"),
    ("relative_path", "'sessions/a.jsonl'"),
    ("device", "1"),
    ("inode", "1"),
    ("size", "10"),
    ("mtime_ns", "1"),
    ("byte_offset", "10"),
    ("first_line_fnv64", "7"),
    ("adapter_state", "'codex_jsonl'"),
    ("parse_generation", "0"),
    ("file_state", "'present'"),
    ("header_id", "'h'"),
    ("header_state", "'own'"),
    ("header_era", "'record'"),
    ("record_state", "'own'"),
    ("tail_state", "NULL"),
    ("uncovered_from_ms", "NULL"),
    ("uncovered_to_ms", "NULL"),
];

const OPENCODE_FILE: &[(&str, &str)] = &[
    ("source_id", "'oc'"),
    ("relative_path", "'opencode.db'"),
    ("device", "1"),
    ("inode", "2"),
    ("size", "10"),
    ("mtime_ns", "1"),
    ("byte_offset", "0"),
    ("first_line_fnv64", "0"),
    ("adapter_state", "'sqlite'"),
    ("parse_generation", "0"),
    ("file_state", "'present'"),
];

#[test]
fn codex_family_rows_and_constraints() -> TestResult {
    let world = World::new()?;
    drop(Store::open(&world.data)?);
    let connection = world.history()?;
    // The parent rows every probe references, so only the CHECK under test can refuse it.
    connection.execute_batch(
        "INSERT INTO sources(source_id, harness, canonical_root, kind, consent) \
         VALUES ('src', 'codex', '/src', 'custom', 'enabled'), ('oc', 'opencode', '/oc', 'custom', 'enabled')",
    )?;
    let long_id = format!("'{}'", "h".repeat(257));
    let rejected: Vec<(&str, String)> = vec![
        ("sources harness pi", "INSERT INTO sources(source_id, harness, canonical_root, kind, consent) VALUES ('p', 'pi', '/p', 'custom', 'enabled')".to_owned()),
        ("opencode family with codex harness", insert("usage_events", OPENCODE_EVENT, &[("harness", "'codex'")])),
        ("opencode family with codex: key", insert("usage_events", OPENCODE_EVENT, &[("event_key", "'codex:1:s:1:a:1:b'")])),
        ("codex family with opencode harness", insert("usage_events", CODEX_EVENT, &[("harness", "'opencode'")])),
        ("codex family without codex: key", insert("usage_events", CODEX_EVENT, &[("event_key", "'opencode:1:s:1:r'")])),
        ("codex derived total", insert("usage_events", CODEX_EVENT, &[("total_provenance", "'derived'"), ("source_convention", "'codexbar-3239175f-disjoint'")])),
        ("codex sqlite consistency", insert("usage_events", CODEX_EVENT, &[("acquisition_consistency", "'sqlite_read_transaction'")])),
        ("codex total mismatch", insert("usage_events", CODEX_EVENT, &[("total_mismatch", "1")])),
        ("codex selected parts", insert("usage_events", CODEX_EVENT, &[("selected_part_ids", "'[\"p1\"]'")])),
        ("codex format rank", insert("usage_events", CODEX_EVENT, &[("format_rank", "1")])),
        ("codex pending partial", insert("usage_events", CODEX_EVENT, &[("pending_partial", "1")])),
        ("codex pending reason", insert("usage_events", CODEX_EVENT, &[("pending_reason", "'invalid_record'")])),
        ("family pi", insert("usage_events", CODEX_EVENT, &[("family", "'pi'")])),
        ("harness pi", insert("usage_events", CODEX_EVENT, &[("harness", "'pi'")])),
        ("uncovered from without to", insert("source_files", CODEX_FILE, &[("uncovered_from_ms", "5")])),
        ("uncovered to without from", insert("source_files", CODEX_FILE, &[("uncovered_to_ms", "5")])),
        ("uncovered from after to", insert("source_files", CODEX_FILE, &[("uncovered_from_ms", "10"), ("uncovered_to_ms", "5")])),
        ("uncovered from negative", insert("source_files", CODEX_FILE, &[("uncovered_from_ms", "-1"), ("uncovered_to_ms", "5")])),
        ("codex offset 0 with first-line hash", insert("source_files", CODEX_FILE, &[("byte_offset", "0")])),
        ("codex header state unknown", insert("source_files", CODEX_FILE, &[("header_state", "'bogus'")])),
        ("codex record state unknown", insert("source_files", CODEX_FILE, &[("record_state", "'bogus'")])),
        ("codex era unknown", insert("source_files", CODEX_FILE, &[("header_era", "'bogus'")])),
        ("codex own header without era", insert("source_files", CODEX_FILE, &[("header_era", "NULL")])),
        ("codex foreign header with era", insert("source_files", CODEX_FILE, &[("header_state", "'foreign_first_line'")])),
        ("codex no header with era", insert("source_files", CODEX_FILE, &[("header_state", "NULL")])),
        ("tail state unknown", insert("source_files", CODEX_FILE, &[("tail_state", "'bogus'")])),
        ("empty header id", insert("source_files", CODEX_FILE, &[("header_id", "''")])),
        ("257-byte header id", insert("source_files", CODEX_FILE, &[("header_id", long_id.as_str())])),
        ("other adapter with header id", insert("source_files", OPENCODE_FILE, &[]).replace("(source_id,", "(header_id, source_id,").replace("VALUES (", "VALUES ('h', ")),
        ("other adapter with header state", insert("source_files", OPENCODE_FILE, &[]).replace("(source_id,", "(header_state, source_id,").replace("VALUES (", "VALUES ('own', ")),
        ("other adapter with era", insert("source_files", OPENCODE_FILE, &[]).replace("(source_id,", "(header_era, source_id,").replace("VALUES (", "VALUES ('record', ")),
        ("other adapter with record state", insert("source_files", OPENCODE_FILE, &[]).replace("(source_id,", "(record_state, source_id,").replace("VALUES (", "VALUES ('none', ")),
        ("other adapter with tail state", insert("source_files", OPENCODE_FILE, &[]).replace("(source_id,", "(tail_state, source_id,").replace("VALUES (", "VALUES ('pending', ")),
        ("other adapter with uncovered range", insert("source_files", OPENCODE_FILE, &[]).replace("(source_id,", "(uncovered_from_ms, uncovered_to_ms, source_id,").replace("VALUES (", "VALUES (1, 2, ")),
    ];
    let accepted: Vec<(&str, String)> = vec![
        ("opencode e0000001-shape row", insert("usage_events", OPENCODE_EVENT, &[])),
        ("codex row", insert("usage_events", CODEX_EVENT, &[])),
        ("codex row with NULL cache_write", insert("usage_events", CODEX_EVENT, &[("cache_write_tokens", "NULL")])),
        ("codex file state", insert("source_files", CODEX_FILE, &[])),
        ("codex foreign file state", insert("source_files", CODEX_FILE, &[("header_id", "NULL"), ("header_state", "'foreign_first_line'"), ("header_era", "NULL"), ("record_state", "'none'"), ("uncovered_from_ms", "3"), ("uncovered_to_ms", "3")])),
        ("codex unread file state", insert("source_files", CODEX_FILE, &[("byte_offset", "0"), ("first_line_fnv64", "0"), ("header_id", "NULL"), ("header_state", "NULL"), ("header_era", "NULL"), ("record_state", "'none'"), ("tail_state", "'pending'")])),
        ("opencode file state", insert("source_files", OPENCODE_FILE, &[])),
        ("sources harness codex", "INSERT INTO sources(source_id, harness, canonical_root, kind, consent) VALUES ('c', 'codex', '/c', 'custom', 'enabled')".to_owned()),
    ];
    for (name, sql) in &rejected {
        connection.execute_batch("BEGIN")?;
        let result = connection.execute(sql, []);
        connection.execute_batch("ROLLBACK")?;
        assert!(
            is_check_failure(&result),
            "{name} must be refused by a CHECK: {result:?}\n{sql}"
        );
    }
    for (name, sql) in &accepted {
        connection.execute_batch("BEGIN")?;
        let result = connection.execute(sql, []);
        connection.execute_batch("ROLLBACK")?;
        assert_eq!(result?, 1, "{name}");
    }
    println!(
        "codex_family_rows_and_constraints: {} rejected probes, {} accepted controls",
        rejected.len(),
        accepted.len()
    );
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM usage_events", &[])?,
        0
    );
    Ok(())
}

#[test]
fn pre_codex_v1_shape_refused_untouched() -> TestResult {
    let world = World::new()?;
    world.basic()?;
    {
        let (mut engine, id) = world.engine()?;
        assert_eq!(pass(&mut engine, &id, DAY_NOW).records_committed, 3);
    }
    let database = world.data.join("history.sqlite");
    {
        let connection = Connection::open(&database)?;
        let current: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE name = 'sources'",
            [],
            |row| row.get(0),
        )?;
        let earlier = current.replace(
            "CHECK (harness IN ('opencode', 'codex'))",
            "CHECK (harness = 'opencode')",
        );
        assert_ne!(earlier, current, "the pre-extension clause is rewritten");
        connection.execute_batch("PRAGMA writable_schema=ON")?;
        connection.execute(
            "UPDATE sqlite_schema SET sql = ?1 WHERE name = 'sources'",
            [&earlier],
        )?;
        connection.execute_batch("PRAGMA writable_schema=OFF")?;
        connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
    }
    let counts = |path: &Path| -> TestResult<(i64, i64, i64)> {
        let connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok((
            count(&connection, "SELECT COUNT(*) FROM sources", &[])?,
            count(&connection, "SELECT COUNT(*) FROM usage_events", &[])?,
            count(&connection, "SELECT COUNT(*) FROM source_files", &[])?,
        ))
    };
    let rows_before = counts(&database)?;
    assert_eq!(rows_before.1, 3);
    let user_version = |path: &Path| -> TestResult<u32> {
        let bytes = std::fs::read(path)?;
        Ok(u32::from_be_bytes([
            bytes[60], bytes[61], bytes[62], bytes[63],
        ]))
    };
    let before = history_digests(&world.data)?;
    assert_eq!(user_version(&database)?, 1);
    assert_eq!(Store::open(&world.data).err(), Some(StoreError::Corrupt));
    let mut owned: Engine<RealSourceFs> = Engine::open(&world.data, &world.home);
    assert_eq!(owned.load_existing(&RealSourceFs), Err(StoreError::Corrupt));
    drop(owned);
    let after = history_digests(&world.data)?;
    assert_eq!(after, before, "bytes and sizes unchanged");
    assert_eq!(user_version(&database)?, 1);
    assert_eq!(counts(&database)?, rows_before);
    println!("pre_codex_v1_shape_refused_untouched: digests {before:?}");
    Ok(())
}

#[test]
fn cross_harness_root_registration_refused_unchanged() -> TestResult {
    for (first_codex, label) in [
        (false, "opencode then codex"),
        (true, "codex then opencode"),
    ] {
        let world = World::new()?;
        let alias = world.base.join("alias");
        std::os::unix::fs::symlink(&world.root, &alias)?;
        let mut engine: Engine<RealSourceFs> = Engine::open(&world.data, &world.home);
        let first = if first_codex {
            engine.attach_codex(RealSourceFs, &world.root, enabled(), SourceKind::Custom)
        } else {
            engine.attach_opencode(RealSourceFs, &world.root, enabled(), SourceKind::Custom)
        };
        let first = first.map_err(|report| format!("{label}: {report:?}"))?;
        let rows = engine.store().ok_or("store")?.source_rows()?;
        let digests = history_digests(&world.data)?;
        for root in [&world.root, &alias] {
            let second = if first_codex {
                engine.attach_opencode(RealSourceFs, root, enabled(), SourceKind::Custom)
            } else {
                engine.attach_codex(RealSourceFs, root, enabled(), SourceKind::Custom)
            };
            let report = second
                .err()
                .ok_or_else(|| format!("{label}: the second harness was accepted"))?;
            assert_eq!(report.outcome, PassOutcome::Unavailable, "{label}");
            assert_eq!(report.failure, Some(FailureCode::RootInvalid), "{label}");
            assert!(
                engine.last_store_error().is_none(),
                "{label}: not a store failure"
            );
            assert_eq!(
                engine.store().ok_or("store")?.source_rows()?,
                rows,
                "{label}"
            );
            assert_eq!(history_digests(&world.data)?, digests, "{label}: no write");
        }
        assert!(
            engine.is_attached(&first),
            "{label}: the first runtime stays"
        );
    }
    Ok(())
}

#[test]
fn codex_rows_persist_exact_columns() -> TestResult {
    let expected = json(BASIC)?;
    let world = World::new()?;
    world.basic()?;
    let id = {
        let (mut engine, id) = world.engine()?;
        let report = pass(&mut engine, &id, DAY_NOW);
        assert_eq!(report.outcome, PassOutcome::Consistent, "{report:?}");
        assert_eq!(report.records_committed, 3);
        assert_eq!(
            engine.observations(&id),
            Err(StoreError::UnsupportedHarness)
        );
        assert_eq!(
            engine.observations_page(&id, None, 10).err(),
            Some(StoreError::UnsupportedHarness)
        );
        id
    };
    let connection = world.history()?;
    let rows = events(&connection, &id)?;
    let oracle = expected["events"].as_array().ok_or("events")?;
    assert_eq!(rows.len(), oracle.len());
    for (row, want) in rows.iter().zip(oracle) {
        assert_event(row, want, &id, "basic");
    }
    assert_fields(
        &file_state(&connection, &id, BASIC_FILE)?,
        &json!({
            "byte_offset": expected["file"]["byte_offset"],
            "header_id": expected["file"]["header_id"],
            "header_state": expected["file"]["header_state"],
            "header_era": expected["file"]["header_era"],
            "record_state": expected["file"]["record_state"],
            "tail_state": expected["file"]["tail_state"],
            "uncovered_from_ms": expected["file"]["uncovered_from_ms"],
            "uncovered_to_ms": expected["file"]["uncovered_to_ms"],
            "file_state": expected["file"]["file_state"],
        }),
        "basic file",
    );
    let harness: String = connection.query_row(
        "SELECT harness FROM sources WHERE source_id = ?1",
        [&id],
        |row| row.get(0),
    )?;
    assert_eq!(harness, "codex");
    Ok(())
}

#[test]
fn reopened_projection_matches_codex_oracle() -> TestResult {
    let expected = json(BASIC)?;
    let world = World::new()?;
    world.basic()?;
    {
        let (mut engine, id) = world.engine()?;
        pass(&mut engine, &id, DAY_NOW);
    }
    let (engine, id) = world.engine()?;
    let oracle = &expected["snapshot"];
    let now = oracle["now_ms"].as_i64().ok_or("now")?;
    let snapshot = snapshot(&engine, oracle["tz"].as_str().ok_or("tz")?, now)?;
    assert_eq!(snapshot["window"], oracle["window"]);
    let entry = by_source_of(&snapshot, &id)?;
    assert_fields(&entry, &oracle["by_source"], "by_source");
    let reported = reported_of(&snapshot, &id)?;
    let mut want = oracle["source_reported"].clone();
    want["source_id"] = json!(id);
    assert_eq!(reported, want);
    Ok(())
}

fn opencode_world(base: &Path) -> TestResult<PathBuf> {
    let source = base.join("opencode");
    std::fs::create_dir(&source)?;
    let connection = Connection::open(source.join("opencode.db"))?;
    let schema: String = OPENCODE_SCHEMA
        .lines()
        .filter(|line| !line.trim_start().starts_with("PRAGMA"))
        .collect::<Vec<_>>()
        .join("\n");
    connection.execute_batch(&schema)?;
    let cases: Value = json(PEER_CASES)?;
    let case = cases
        .as_array()
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case["name"] == "named_convention_derives_42")
        })
        .ok_or("peer case")?;
    connection.execute(
        "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            case["message_id"].as_str().ok_or("id")?,
            case["session_id"].as_str().ok_or("session")?,
            case["time_created"].as_i64().ok_or("time")?,
            serde_json::to_vec(&case["data"])?
        ],
    )?;
    Ok(source)
}

#[test]
fn codex_and_opencode_share_store_without_crossing() -> TestResult {
    let basic = json(BASIC)?;
    let peer: Value = json(PEER_EXPECTED)?;
    let peer = peer
        .as_array()
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case["name"] == "named_convention_derives_42")
        })
        .cloned()
        .ok_or("peer oracle")?;
    let world = World::new()?;
    world.basic()?;
    let opencode = opencode_world(&world.base)?;
    let mut engine: Engine<RealSourceFs> = Engine::open(&world.data, &world.home);
    let oc = engine
        .attach_opencode(RealSourceFs, &opencode, enabled(), SourceKind::Custom)
        .map_err(|report| format!("{report:?}"))?;
    let mut settled = None;
    for step in 0..8 {
        let report = engine.pass(&oc, enabled(), 1_700_000_001_000 + step * 600_000);
        if report.outcome == PassOutcome::Consistent {
            settled = Some(report);
            break;
        }
    }
    settled.ok_or("OpenCode never settled")?;
    let opencode_before = engine.observations(&oc)?;
    let codex = engine
        .attach_codex(RealSourceFs, &world.root, enabled(), SourceKind::Custom)
        .map_err(|report| format!("{report:?}"))?;
    assert_eq!(pass(&mut engine, &codex, DAY_NOW).records_committed, 3);
    assert_eq!(
        engine.observations(&oc)?,
        opencode_before,
        "OpenCode rows unchanged"
    );

    let report = engine.pass(&oc, enabled(), 1_700_000_001_000 + 9 * 600_000);
    let projection = serde_json::to_value(engine.snapshot(&oc, &report)?.projection)?;
    for name in [
        "input",
        "output",
        "reasoning",
        "cache_read",
        "cache_write",
        "total",
    ] {
        assert_eq!(projection[name]["value"], peer[name], "OpenCode {name}");
    }
    assert_eq!(projection["total"]["provenance"], peer["total_provenance"]);
    assert_eq!(projection["source_convention"], peer["source_convention"]);

    let snapshot = snapshot(&engine, "UTC", DAY_NOW)?;
    let mut want = basic["snapshot"]["source_reported"].clone();
    want["source_id"] = json!(codex);
    assert_eq!(reported_of(&snapshot, &codex)?, want);
    assert_eq!(
        reported_of(&snapshot, &oc)?["records"],
        0,
        "the OpenCode record is on another day"
    );

    let connection = world.history()?;
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM usage_events e JOIN sources s ON s.source_id = e.source_id \
             WHERE e.harness <> s.harness OR e.family <> s.harness",
            &[]
        )?,
        0,
        "harness join mismatch"
    );
    for table in [
        "reported_groups",
        "group_baseline",
        "opencode_progress",
        "opencode_candidate_spool",
    ] {
        assert_eq!(
            count(
                &connection,
                &format!("SELECT COUNT(*) FROM {table} WHERE source_id = ?1"),
                &[&codex]
            )?,
            0,
            "{table} holds no Codex row"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Ownership, headers and the coverage era

#[test]
fn copied_fork_inherited_records_excluded() -> TestResult {
    let expected = json(INCREMENTAL)?;
    let fork = &expected["fork"];
    let base_file = "sessions/2026/03/29/rollout-2026-03-29T09-00-00-inc.jsonl";
    let fork_file = "sessions/2026/03/29/rollout-2026-03-29T10-00-00-fork.jsonl";
    for (scenario, with_parent) in [("parent_and_child", true), ("child_only", false)] {
        let world = World::new()?;
        if with_parent {
            world.fixture(
                &format!("harness/codex/incremental/base/{base_file}"),
                base_file,
            )?;
        }
        world.fixture(
            &format!("harness/codex/incremental/fork/{fork_file}"),
            fork_file,
        )?;
        let (mut engine, id) = world.engine()?;
        pass(&mut engine, &id, DAY_NOW);
        let connection = world.history()?;
        let rows = events(&connection, &id)?;
        let oracle = fork[scenario]["events"].as_array().ok_or("events")?;
        assert_eq!(rows.len(), oracle.len(), "{scenario}: {rows:?}");
        for (row, want) in rows.iter().zip(oracle) {
            assert_event(row, want, &id, scenario);
        }
        let projection = &fork[scenario]["projection"];
        let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
        assert_eq!(entry["records"], projection["records"], "{scenario}");
        for name in [
            "input",
            "cache_read",
            "cache_write",
            "output",
            "reasoning",
            "total",
        ] {
            assert_eq!(entry[name]["value"], projection[name], "{scenario}: {name}");
        }
        assert_eq!(
            entry["cache_write"]["completeness"],
            projection["cache_write_completeness"]
        );
        let child = &fork["child_file"];
        let state = file_state(&connection, &id, fork_file)?;
        for name in [
            "header_id",
            "header_state",
            "header_era",
            "record_state",
            "uncovered_from_ms",
            "uncovered_to_ms",
            "byte_offset",
        ] {
            assert_eq!(state[name], child[name], "{scenario}: {name}");
        }
    }
    Ok(())
}

/// One header scenario: the listed files in a fresh root, one pass, then rows, absent responses,
/// per-file states and the snapshot projection against `headers/expected.json`.
fn header_scenario(
    name: &str,
    extra: &[(&str, String)],
) -> TestResult<(World, String, Engine<RealSourceFs>)> {
    let expected = json(HEADERS)?;
    let scenario = &expected["scenarios"][name];
    let world = World::new()?;
    for file in scenario["files"].as_array().ok_or("files")? {
        let file = file.as_str().ok_or("file")?;
        world.fixture(
            &format!("harness/codex/headers/sessions/2026/03/29/{file}"),
            &format!("sessions/2026/03/29/{file}"),
        )?;
    }
    for (relative, text) in extra {
        world.put(relative, text.as_bytes())?;
    }
    let (mut engine, id) = world.engine()?;
    let report = pass(
        &mut engine,
        &id,
        expected["pass_now_ms"].as_i64().ok_or("now")?,
    );
    assert_eq!(report.counters.rejected_records, 0, "{name}: {report:?}");
    let connection = world.history()?;
    let rows = events(&connection, &id)?;
    let want: Vec<&str> = scenario["rows"]
        .as_array()
        .ok_or("rows")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mut got: Vec<String> = rows
        .iter()
        .filter_map(|row| row["message_id"].as_str().map(str::to_owned))
        .collect();
    got.sort();
    let mut want_sorted: Vec<String> = want.iter().map(|text| (*text).to_owned()).collect();
    want_sorted.sort();
    assert_eq!(got, want_sorted, "{name}: stored responses");
    for response in &want {
        let row = rows
            .iter()
            .find(|row| row["message_id"] == *response)
            .ok_or("row")?;
        let oracle = &expected["rows"][*response];
        let session = oracle["session_id"].as_str().ok_or("session")?;
        assert_eq!(
            row["event_key"],
            json!(key(&id, session, response)),
            "{name}"
        );
        assert_fields(row, oracle, &format!("{name}: {response}"));
    }
    for absent in scenario["absent_responses"].as_array().ok_or("absent")? {
        assert!(
            rows.iter().all(|row| row["message_id"] != *absent),
            "{name}: {absent} must not be stored"
        );
    }
    for file in scenario["files"].as_array().ok_or("files")? {
        let file = file.as_str().ok_or("file")?;
        let state = file_state(&connection, &id, &format!("sessions/2026/03/29/{file}"))?;
        assert_fields(&state, &expected["files"][file], &format!("{name}: {file}"));
    }
    let tz = scenario["tz"].as_str().ok_or("tz")?;
    let now = scenario["now_ms"].as_i64().ok_or("now")?;
    let snapshot = snapshot(&engine, tz, now)?;
    if let Some(window) = scenario.get("window") {
        assert_eq!(snapshot["window"]["start_ms"], window["start_ms"]);
        assert_eq!(snapshot["window"]["end_ms"], window["end_ms"]);
    }
    assert_projection(&reported_of(&snapshot, &id)?, &scenario["projection"], name);
    Ok((world, id, engine))
}

#[test]
fn subagent_record_with_root_session_counted() -> TestResult {
    let (world, id, _engine) = header_scenario("subagent", &[])?;
    let connection = world.history()?;
    let session: String = connection.query_row(
        "SELECT session_id FROM usage_events WHERE source_id = ?1",
        [&id],
        |row| row.get(0),
    )?;
    let header: String = connection.query_row(
        "SELECT header_id FROM source_files WHERE source_id = ?1",
        [&id],
        |row| row.get(0),
    )?;
    assert_ne!(
        session, header,
        "session_id is the root thread, never the owner test"
    );
    Ok(())
}

#[test]
fn appended_header_fails_closed_partial() -> TestResult {
    header_scenario("appended_header", &[]).map(drop)
}

#[test]
fn foreign_first_line_fails_closed_partial() -> TestResult {
    header_scenario("foreign_first_line", &[]).map(drop)
}

#[test]
fn legacy_token_count_never_counted() -> TestResult {
    let (world, id, _engine) = header_scenario("legacy_counted_day", &[])?;
    let connection = world.history()?;
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM usage_events WHERE source_id = ?1 AND (input_tokens = 5000 OR total_tokens = 5100)",
            &[&id]
        )?,
        0,
        "no token_count value is stored"
    );
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM usage_events WHERE source_id = ?1",
            &[&id]
        )?,
        1
    );
    Ok(())
}

#[test]
fn legacy_only_day_unavailable_not_zero() -> TestResult {
    header_scenario("legacy_only_day", &[]).map(drop)
}

#[test]
fn record_era_token_count_before_first_record_is_complete() -> TestResult {
    header_scenario("record_era", &[]).map(drop)
}

#[test]
fn resumed_legacy_file_is_partial() -> TestResult {
    header_scenario("resumed_legacy", &[]).map(drop)
}

#[test]
fn copied_prefix_token_count_has_no_coverage_effect() -> TestResult {
    header_scenario("copied_prefix", &[]).map(drop)
}

#[test]
fn legacy_fork_child_prefix_token_count_partial() -> TestResult {
    let expected = json(HEADERS)?;
    let spec = &expected["legacy_fork_child"];
    let mut text = String::new();
    for line in spec["lines"].as_array().ok_or("lines")? {
        let timestamp = line["timestamp"].as_str().ok_or("timestamp")?;
        match line["kind"].as_str().ok_or("kind")? {
            "session_meta" => text.push_str(&header_line(
                timestamp,
                line["id"].as_str().ok_or("id")?,
                line["forked_from_id"].as_str(),
                line["cli_version"].as_str(),
            )),
            "token_count" => text.push_str(&token_count_line(timestamp)),
            "record" => {
                let input = line["input"].as_u64().ok_or("input")?;
                text.push_str(&record_line(
                    timestamp,
                    line["thread_id"].as_str().ok_or("thread")?,
                    line["session_id"].as_str().ok_or("session")?,
                    line["response_id"].as_str().ok_or("response")?,
                    json!({ "input_tokens": input, "total_tokens": input }),
                ));
            }
            other => return Err(format!("unknown line kind {other}").into()),
        }
    }
    let relative = spec["relative_path"].as_str().ok_or("path")?;
    let (world, id, _engine) = header_scenario("legacy_fork_child", &[(relative, text)])?;
    let state = file_state(&world.history()?, &id, relative)?;
    assert_fields(&state, &spec["state"], "legacy fork child");
    Ok(())
}

#[test]
fn header_era_semver_threshold() -> TestResult {
    let expected = json(HEADERS)?;
    let world = World::new()?;
    let cases = expected["era_cases"].as_array().ok_or("era cases")?;
    for (index, case) in cases.iter().enumerate() {
        let id = format!("0195f000-0000-7000-8000-0000000e{index:04}");
        let text = header_line(
            "2026-03-29T08:00:00.000Z",
            &id,
            None,
            case["cli_version"].as_str(),
        ) + &record_line(
            "2026-03-29T08:01:00.000Z",
            &id,
            &id,
            &format!("resp_era_{index}"),
            json!({ "input_tokens": 1, "total_tokens": 1 }),
        );
        world.put(
            &format!("sessions/2026/03/29/rollout-era-{index:02}.jsonl"),
            text.as_bytes(),
        )?;
    }
    let (mut engine, id) = world.engine()?;
    pass(&mut engine, &id, DAY_NOW);
    let connection = world.history()?;
    for (index, case) in cases.iter().enumerate() {
        let state = file_state(
            &connection,
            &id,
            &format!("sessions/2026/03/29/rollout-era-{index:02}.jsonl"),
        )?;
        assert_eq!(
            state["header_era"], case["era"],
            "cli_version {}",
            case["cli_version"]
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Identity, copies and precedence

#[test]
fn response_dedup_scoped_to_root_session() -> TestResult {
    let world = World::new()?;
    let (a, b) = (
        "0195f000-0000-7000-8000-0000000d000a",
        "0195f000-0000-7000-8000-0000000d000b",
    );
    let file_a = header_line("2026-03-29T08:00:00.000Z", a, None, Some("0.153.0"))
        + &record_line(
            "2026-03-29T08:01:00.000Z",
            a,
            a,
            "resp_same",
            json!({ "input_tokens": 3, "total_tokens": 3 }),
        );
    let file_b = header_line("2026-03-29T08:10:00.000Z", b, None, Some("0.153.0"))
        + &record_line(
            "2026-03-29T08:11:00.000Z",
            b,
            b,
            "resp_same",
            json!({ "input_tokens": 5, "total_tokens": 5 }),
        );
    world.put("sessions/2026/03/29/rollout-a.jsonl", file_a.as_bytes())?;
    world.put("sessions/2026/03/29/rollout-b.jsonl", file_b.as_bytes())?;
    world.put("archived_sessions/rollout-a.jsonl", file_a.as_bytes())?;
    let (mut engine, id) = world.engine()?;
    pass(&mut engine, &id, DAY_NOW);
    let rows = events(&world.history()?, &id)?;
    let keys: Vec<&Value> = rows.iter().map(|row| &row["event_key"]).collect();
    assert_eq!(
        keys,
        vec![
            &json!(key(&id, a, "resp_same")),
            &json!(key(&id, b, "resp_same"))
        ],
        "one row per (root session, response)"
    );
    let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
    assert_eq!(entry["input"]["value"], 8, "never 3 + 3 + 5");
    Ok(())
}

#[test]
fn copies_archive_symlink_count_once() -> TestResult {
    let expected = json(BASIC)?;
    let world = World::new()?;
    let live = world.basic()?;
    let archived = "archived_sessions/rollout-2026-03-29T09-00-00-basic.jsonl";
    world.fixture(&format!("harness/codex/basic/{BASIC_FILE}"), archived)?;
    std::os::unix::fs::symlink(
        &live,
        world.root.join("sessions/2026/03/29/rollout-alias.jsonl"),
    )?;
    let (mut engine, id) = world.engine()?;
    let first = pass(&mut engine, &id, DAY_NOW);
    let replay = pass(&mut engine, &id, DAY_NOW + 1_000);
    assert_eq!(
        replay.records_committed, 0,
        "replay adds nothing: {replay:?}"
    );
    assert_eq!(
        replay.outcome,
        PassOutcome::Consistent,
        "{first:?} {replay:?}"
    );
    let rows = events(&world.history()?, &id)?;
    assert_eq!(rows.len(), 3);
    for row in &rows {
        assert_eq!(
            row["mirror_path"], archived,
            "the byte-smaller path holds the record"
        );
        assert_eq!(row["revision"], 1);
        assert_eq!(row["mirror_conflict"], 0);
    }
    let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW + 1_000)?, &id)?;
    for name in [
        "input",
        "output",
        "reasoning",
        "cache_read",
        "cache_write",
        "total",
    ] {
        assert_eq!(
            entry[name]["value"], expected["snapshot"]["source_reported"][name]["value"],
            "{name} counted once"
        );
    }
    Ok(())
}

fn conflict_file(input: u64) -> String {
    let id = "0195f000-0000-7000-8000-0000000cf001";
    header_line("2026-03-29T08:00:00.000Z", id, None, Some("0.153.0"))
        + &record_line(
            "2026-03-29T08:01:00.000Z",
            id,
            id,
            "resp_conflict",
            json!({ "input_tokens": input, "total_tokens": input }),
        )
}

/// Replaces a file through a rename, as a rewrite produces a new inode.
fn replace(world: &World, relative: &str, text: &str) -> TestResult {
    let staging = world.base.join("staging.jsonl");
    std::fs::write(&staging, text)?;
    let target = world.root.join(relative);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(&staging, &target)?;
    Ok(())
}

#[test]
fn divergent_copy_conflict_order_independent() -> TestResult {
    let small = "archived_sessions/rollout-x.jsonl";
    let large = "sessions/2026/03/29/rollout-x.jsonl";
    let orders: [[(&str, u64); 3]; 2] = [
        [(large, 10), (small, 10), (large, 20)],
        [(small, 10), (large, 10), (large, 20)],
    ];
    for (index, order) in orders.iter().enumerate() {
        let world = World::new()?;
        let mut id = String::new();
        for (step, (relative, input)) in order.iter().enumerate() {
            replace(&world, relative, &conflict_file(*input))?;
            // Each step runs in a freshly reopened engine.
            let (mut engine, attached) = world.engine()?;
            pass(
                &mut engine,
                &attached,
                DAY_NOW + i64::try_from(step)? * 1_000,
            );
            id = attached;
        }
        let rows = events(&world.history()?, &id)?;
        assert_eq!(rows.len(), 1, "order {index}");
        assert_fields(
            &rows[0],
            &json!({ "mirror_path": small, "input_tokens": 10, "total_tokens": 10, "mirror_conflict": 1, "revision": 1 }),
            &format!("order {index}"),
        );
        let (engine, _) = world.engine()?;
        let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
        assert_eq!(entry["input"]["value"], 10, "order {index}: never added");
        assert_eq!(entry["mirror_conflict"], true, "order {index}");
    }
    Ok(())
}

#[test]
fn rewrite_revision_replaces() -> TestResult {
    let world = World::new()?;
    let relative = "sessions/2026/03/29/rollout-x.jsonl";
    replace(&world, relative, &conflict_file(10))?;
    let (mut engine, id) = world.engine()?;
    pass(&mut engine, &id, DAY_NOW);
    replace(&world, relative, &conflict_file(25))?;
    let report = pass(&mut engine, &id, DAY_NOW + 1_000);
    assert_eq!(report.records_committed, 1);
    let rows = events(&world.history()?, &id)?;
    assert_eq!(rows.len(), 1);
    assert_fields(
        &rows[0],
        &json!({ "input_tokens": 25, "revision": 2 }),
        "revised numbers",
    );
    let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
    assert_eq!(entry["input"]["value"], 25, "replaced, never 35");
    // A revised occurrence instant moves the record to its revised day.
    let moved = conflict_file(25).replace("2026-03-29T08:01:00.000Z", "2026-03-30T08:01:00.000Z");
    replace(&world, relative, &moved)?;
    pass(&mut engine, &id, DAY_NOW + 2_000);
    let rows = events(&world.history()?, &id)?;
    assert_fields(
        &rows[0],
        &json!({ "occurred_at_ms": 1_774_857_660_000_i64, "revision": 3 }),
        "moved",
    );
    assert_eq!(
        reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?["records"],
        0
    );
    Ok(())
}

#[test]
fn two_sources_same_record_never_pooled() -> TestResult {
    let expected = json(BASIC)?;
    let world = World::new()?;
    world.basic()?;
    let other = world.base.join("second-codex-home");
    std::fs::create_dir_all(other.join("sessions/2026/03/29"))?;
    std::fs::copy(world.root.join(BASIC_FILE), other.join(BASIC_FILE))?;
    let (mut engine, first) = world.engine()?;
    let second = engine
        .attach_codex(RealSourceFs, &other, enabled(), SourceKind::Custom)
        .map_err(|report| format!("{report:?}"))?;
    assert_ne!(first, second);
    pass(&mut engine, &first, DAY_NOW);
    pass(&mut engine, &second, DAY_NOW);
    let connection = world.history()?;
    for id in [&first, &second] {
        let rows = events(&connection, id)?;
        assert_eq!(rows.len(), 3);
        for (row, want) in rows
            .iter()
            .zip(expected["events"].as_array().ok_or("events")?)
        {
            assert_event(row, want, id, "per source");
        }
    }
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM usage_events", &[])?,
        6
    );
    let snapshot = snapshot(&engine, "UTC", DAY_NOW)?;
    for id in [&first, &second] {
        let mut want = expected["snapshot"]["source_reported"].clone();
        want["source_id"] = json!(id);
        assert_eq!(
            reported_of(&snapshot, id)?,
            want,
            "each source alone, never pooled"
        );
    }
    Ok(())
}

#[test]
fn explicit_null_counters_remain_sql_null_across_reopen() -> TestResult {
    let world = World::new()?;
    let session = "0195f000-0000-7000-8000-00000000a011";
    let mut text = header_line("2026-03-29T09:00:00.000Z", session, None, Some("0.153.0"));
    text.push_str(&record_line(
        "2026-03-29T09:01:00.000Z",
        session,
        session,
        "resp_null",
        json!({
            "input_tokens": null, "output_tokens": null, "total_tokens": null,
            "cached_input_tokens": 11, "cache_write_input_tokens": null,
            "reasoning_output_tokens": 7
        }),
    ));
    text.push_str(&record_line(
        "2026-03-29T09:02:00.000Z",
        session,
        session,
        "resp_zero",
        json!({
            "input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
            "cached_input_tokens": 0, "cache_write_input_tokens": 0,
            "reasoning_output_tokens": 0
        }),
    ));
    world.put(BASIC_FILE, text.as_bytes())?;
    let (mut engine, id) = world.engine()?;
    let report = pass(&mut engine, &id, DAY_NOW);
    assert_eq!(report.outcome, PassOutcome::Consistent);
    let rows = events(&world.history()?, &id)?;
    assert_eq!(rows.len(), 2);
    assert_fields(
        &rows[0],
        &json!({
            "message_id": "resp_null", "input_tokens": null, "output_tokens": null,
            "total_tokens": null, "total_provenance": null, "cache_read_tokens": 11,
            "cache_write_tokens": null, "reasoning_tokens": 7, "source_convention": null
        }),
        "explicit JSON null persisted",
    );
    assert_fields(
        &rows[1],
        &json!({
            "message_id": "resp_zero", "input_tokens": 0, "output_tokens": 0,
            "total_tokens": 0, "total_provenance": "reported", "cache_read_tokens": 0,
            "cache_write_tokens": 0, "reasoning_tokens": 0, "source_convention": null
        }),
        "explicit zero persisted",
    );
    drop(engine);
    let (engine, reopened) = world.engine()?;
    assert_eq!(reopened, id);
    assert_eq!(events(&world.history()?, &id)?, rows);
    let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
    assert_projection(
        &entry,
        &json!({
            "records": 2,
            "input": { "value": 0, "provenance": "reported", "completeness": "partial" },
            "output": { "value": 0, "provenance": "reported", "completeness": "partial" },
            "cache_read": { "value": 11, "provenance": "reported", "completeness": "complete" },
            "cache_write": { "value": 0, "provenance": "reported", "completeness": "partial" },
            "reasoning": { "value": 7, "provenance": "reported", "completeness": "complete" },
            "total": { "value": 0, "provenance": "reported", "completeness": "partial" }
        }),
        "reopened null and zero projection",
    );
    Ok(())
}

#[test]
fn missing_counters_null_explicit_zero_kept() -> TestResult {
    let world = World::new()?;
    world.basic()?;
    let (mut engine, id) = world.engine()?;
    pass(&mut engine, &id, DAY_NOW);
    let rows = events(&world.history()?, &id)?;
    let absent = rows
        .iter()
        .find(|row| row["message_id"] == "resp_basic_002")
        .ok_or("002")?;
    assert_eq!(
        absent["cache_write_tokens"],
        Value::Null,
        "an absent key is NULL, never 0"
    );
    assert_eq!(
        absent["cache_read_tokens"], 0,
        "an explicit 0 is reported 0"
    );
    let zero = rows
        .iter()
        .find(|row| row["message_id"] == "resp_basic_003")
        .ok_or("003")?;
    for column in [
        "input_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
    ] {
        assert_eq!(zero[column], 0, "{column}");
    }
    let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
    assert_eq!(entry["cache_write"]["value"], 100);
    assert_eq!(
        entry["cache_write"]["completeness"], "partial",
        "one record lacks it"
    );
    Ok(())
}

#[test]
fn codex_dst_windows_riga_kolkata() -> TestResult {
    let expected = json(BASIC)?;
    let dst = &expected["dst"];
    let id = "0195f000-0000-7000-8000-00000000d570";
    let mut text = header_line("2026-03-28T18:00:00.000Z", id, None, Some("0.153.0"));
    for record in dst["records"].as_array().ok_or("records")? {
        let weight = record["weight"].as_u64().ok_or("weight")?;
        text.push_str(&record_line(
            record["timestamp"].as_str().ok_or("timestamp")?,
            id,
            id,
            record["response_id"].as_str().ok_or("response")?,
            json!({ "input_tokens": weight, "total_tokens": weight }),
        ));
    }
    let world = World::new()?;
    world.put("sessions/2026/03/28/rollout-dst.jsonl", text.as_bytes())?;
    let (mut engine, source) = world.engine()?;
    pass(&mut engine, &source, DAY_NOW);
    for window in dst["windows"].as_array().ok_or("windows")? {
        let name = window["name"].as_str().ok_or("name")?;
        let snapshot = snapshot(
            &engine,
            window["tz"].as_str().ok_or("tz")?,
            window["now_ms"].as_i64().ok_or("now")?,
        )?;
        assert_eq!(snapshot["window"]["start_ms"], window["start_ms"], "{name}");
        assert_eq!(snapshot["window"]["end_ms"], window["end_ms"], "{name}");
        let hours = (snapshot["window"]["end_ms"].as_i64().ok_or("end")?
            - snapshot["window"]["start_ms"].as_i64().ok_or("start")?)
            / 3_600_000;
        assert_eq!(json!(hours), window["hours"], "{name}");
        let entry = reported_of(&snapshot, &source)?;
        assert_eq!(entry["records"], window["records"], "{name}");
        assert_eq!(entry["input"]["value"], window["input"], "{name}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Atomicity, reopen, cancellation and zero effect

#[test]
fn codex_event_cursor_fault_reopen_atomic() -> TestResult {
    // BeforeCommit: the single per-file commit fails and nothing of the file is durable.
    let world = World::new()?;
    world.basic()?;
    {
        let (mut engine, id) = world.engine()?;
        engine.inject_commit_fault(FaultPoint::BeforeCommit);
        let report = pass(&mut engine, &id, DAY_NOW);
        assert_eq!(report.failure, Some(FailureCode::Store), "{report:?}");
        assert_eq!(report.records_committed, 0);
    }
    {
        let connection = world.history()?;
        assert_eq!(
            count(&connection, "SELECT COUNT(*) FROM usage_events", &[])?,
            0,
            "rows equal pre-pass"
        );
        assert_eq!(
            count(&connection, "SELECT COUNT(*) FROM source_files", &[])?,
            0,
            "state equals pre-pass"
        );
        assert_eq!(
            count(
                &connection,
                "SELECT COUNT(*) FROM source_projection_totals WHERE records > 0",
                &[]
            )?,
            0
        );
    }
    {
        let (mut engine, id) = world.engine()?;
        let report = pass(&mut engine, &id, DAY_NOW + 1_000);
        assert_eq!(
            report.records_committed, 3,
            "the next pass publishes once: {report:?}"
        );
        assert_eq!(events(&world.history()?, &id)?.len(), 3);
    }
    // AfterCommit: the commit is durable, the pass reports the fault, and replay adds nothing.
    let world = World::new()?;
    world.basic()?;
    let id = {
        let (mut engine, id) = world.engine()?;
        engine.inject_commit_fault(FaultPoint::AfterCommit);
        let report = pass(&mut engine, &id, DAY_NOW);
        assert_eq!(report.failure, Some(FailureCode::Store), "{report:?}");
        id
    };
    let committed = events(&world.history()?, &id)?;
    assert_eq!(committed.len(), 3);
    assert_eq!(
        file_state(&world.history()?, &id, BASIC_FILE)?["byte_offset"],
        3348
    );
    let (mut engine, again) = world.engine()?;
    let report = pass(&mut engine, &again, DAY_NOW + 1_000);
    assert_eq!(
        report.records_committed, 0,
        "replay adds nothing: {report:?}"
    );
    assert_eq!(events(&world.history()?, &id)?, committed);
    Ok(())
}

#[test]
fn codex_reopen_reattaches_persisted_root() -> TestResult {
    let expected = json(BASIC)?;
    let world = World::new()?;
    world.basic()?;
    let id = {
        let mut engine: Engine<RealSourceFs> = Engine::open(&world.data, &world.home);
        engine.load_existing(&RealSourceFs)?;
        let id = engine
            .attach_codex(RealSourceFs, &world.root, enabled(), SourceKind::Custom)
            .map_err(|report| format!("{report:?}"))?;
        assert_eq!(pass(&mut engine, &id, DAY_NOW).records_committed, 3);
        id
    };
    let mut engine: Engine<RealSourceFs> = Engine::open(&world.data, &world.home);
    engine.load_existing(&RealSourceFs)?;
    assert_eq!(engine.enabled_source_ids()?, vec![id.clone()]);
    assert!(!engine.is_attached(&id));
    assert_eq!(
        engine
            .reattach(RealSourceFs, &id, None)
            .map_err(|report| format!("{report:?}"))?,
        id
    );
    assert!(engine.is_attached(&id));
    let report = pass(&mut engine, &id, DAY_NOW + 1_000);
    assert_eq!(report.records_committed, 0, "{report:?}");
    assert_eq!(report.outcome, PassOutcome::Consistent);
    drop(engine);
    // The ABI's ingest path reattaches by harness and runs the pass.
    let mut engine: Engine<RealSourceFs> = Engine::open(&world.data, &world.home);
    engine.load_existing(&RealSourceFs)?;
    engine
        .ingest(|| RealSourceFs, DAY_NOW, &AtomicBool::new(false))
        .map_err(|error| format!("{error:?}"))?;
    assert!(engine.is_attached(&id));
    let snapshot = snapshot(&engine, "UTC", DAY_NOW)?;
    assert_eq!(by_source_of(&snapshot, &id)?["harness"], "codex");
    let mut want = expected["snapshot"]["source_reported"].clone();
    want["source_id"] = json!(id);
    assert_eq!(reported_of(&snapshot, &id)?, want);
    Ok(())
}

#[test]
fn cancel_between_codex_files_commits_whole_files() -> TestResult {
    let world = World::new()?;
    for index in 0..4 {
        let session = format!("0195f000-0000-7000-8000-00000000ca0{index}");
        let text = header_line("2026-03-29T08:00:00.000Z", &session, None, Some("0.153.0"))
            + &record_line(
                "2026-03-29T08:01:00.000Z",
                &session,
                &session,
                "resp",
                json!({ "input_tokens": 1, "total_tokens": 1 }),
            )
            + &record_line(
                "2026-03-29T08:02:00.000Z",
                &session,
                &session,
                "resp2",
                json!({ "input_tokens": 2, "total_tokens": 2 }),
            );
        world.put(
            &format!("sessions/2026/03/29/rollout-{index}.jsonl"),
            text.as_bytes(),
        )?;
    }
    let (mut engine, id) = world.engine()?;
    let flag = Arc::new(AtomicBool::new(false));
    let commits = Arc::new(AtomicUsize::new(0));
    let k = 2;
    {
        let (flag, commits) = (Arc::clone(&flag), Arc::clone(&commits));
        quotern_core::adapters::codex::set_file_commit_hook(Some(Box::new(move || {
            if commits.fetch_add(1, Ordering::SeqCst) + 1 == k {
                flag.store(true, Ordering::Release);
            }
        })));
    }
    let result = engine.pass_until(&id, enabled(), DAY_NOW, &flag);
    quotern_core::adapters::codex::set_file_commit_hook(None);
    assert!(matches!(result, Err(PassCancelled(_))), "{result:?}");
    assert_eq!(commits.load(Ordering::SeqCst), k);
    let connection = world.history()?;
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND byte_offset > 0",
            &[&id]
        )?,
        i64::try_from(k)?,
        "exactly k files committed"
    );
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM usage_events WHERE source_id = ?1",
            &[&id]
        )?,
        i64::try_from(2 * k)?,
        "whole files only"
    );
    let report = pass(&mut engine, &id, DAY_NOW + 1_000);
    assert_eq!(report.records_committed, 4, "{report:?}");
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM usage_events WHERE source_id = ?1",
            &[&id]
        )?,
        8
    );
    Ok(())
}

/// Every byte, length and modification time under `root`, by relative path.
/// (relative path, length, mtime ns, bytes) of one tree entry.
type TreeEntry = (PathBuf, u64, i64, Vec<u8>);

fn tree_image(root: &Path) -> TestResult<Vec<TreeEntry>> {
    use std::os::unix::fs::MetadataExt;
    let mut image = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&directory)?.collect::<Result<_, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::path);
        for entry in entries {
            let metadata = std::fs::symlink_metadata(entry.path())?;
            let relative = entry.path().strip_prefix(root)?.to_path_buf();
            if metadata.is_dir() {
                pending.push(entry.path());
                image.push((relative, 0, metadata.mtime_nsec(), Vec::new()));
            } else if metadata.is_file() {
                image.push((
                    relative,
                    metadata.len(),
                    metadata.mtime_nsec(),
                    std::fs::read(entry.path())?,
                ));
            }
        }
    }
    Ok(image)
}

#[test]
fn codex_denied_and_unselected_roots_have_zero_effects() -> TestResult {
    let world = World::new()?;
    world.basic()?;
    let image = tree_image(&world.root)?;
    let observed = RecordingFs::new();
    let mut engine: Engine<RecordingFs> = Engine::open(&world.data, &world.home);
    for authorization in [
        SourceAuthorization {
            selected: true,
            consent: ConsentState::Denied,
        },
        SourceAuthorization {
            selected: false,
            consent: ConsentState::Enabled,
        },
        SourceAuthorization {
            selected: true,
            consent: ConsentState::Undecided,
        },
    ] {
        let report = engine
            .attach_codex(
                observed.clone(),
                &world.root,
                authorization,
                SourceKind::Custom,
            )
            .err()
            .ok_or("an unauthorized attach was accepted")?;
        assert_eq!(report.counters, Default::default());
    }
    assert_eq!(
        observed.metrics(),
        Default::default(),
        "no filesystem work at all"
    );
    assert!(!world.data.exists(), "no store was created");
    let id = engine
        .attach_codex(observed.clone(), &world.root, enabled(), SourceKind::Custom)
        .map_err(|report| format!("{report:?}"))?;
    let before = observed.metrics();
    for authorization in [
        SourceAuthorization {
            selected: true,
            consent: ConsentState::Denied,
        },
        SourceAuthorization {
            selected: false,
            consent: ConsentState::Enabled,
        },
    ] {
        let report = engine.pass(&id, authorization, DAY_NOW);
        assert_eq!(report.outcome, PassOutcome::Unavailable);
        assert_eq!(report.counters, Default::default());
    }
    engine.deny(&id)?;
    engine
        .ingest(RecordingFs::new, DAY_NOW, &AtomicBool::new(false))
        .map_err(|error| format!("{error:?}"))?;
    let after = observed.metrics();
    assert_eq!(
        after, before,
        "denied and unselected passes do no filesystem work"
    );
    assert_eq!(after.tail_reads, 0);
    assert_eq!(after.bounded_reads, 0);
    let connection = world.history()?;
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM usage_events", &[])?,
        0
    );
    assert_eq!(
        count(&connection, "SELECT COUNT(*) FROM source_files", &[])?,
        0
    );
    assert_eq!(
        tree_image(&world.root)?,
        image,
        "source bytes and times unchanged"
    );
    Ok(())
}

#[test]
fn codex_hostile_cases_rejected() -> TestResult {
    let cases = json(HOSTILE_CASES)?;
    let expected = json(HOSTILE_EXPECTED)?;
    let header = cases["header"].as_str().ok_or("header")?;
    let control = cases["control"].as_str().ok_or("control")?;
    for case in cases["cases"].as_array().ok_or("cases")? {
        let name = case["name"].as_str().ok_or("name")?;
        let want = &expected["cases"][name];
        let world = World::new()?;
        let text = format!(
            "{header}\n{}\n{control}\n",
            case["raw"].as_str().ok_or("raw")?
        );
        world.put(
            &format!("sessions/2026/03/29/rollout-hostile-{name}.jsonl"),
            text.as_bytes(),
        )?;
        let image = tree_image(&world.root)?;
        let (mut engine, id) = world.engine()?;
        let report = pass(&mut engine, &id, DAY_NOW);
        assert_eq!(
            tree_image(&world.root)?,
            image,
            "{name}: source bytes unchanged"
        );
        assert_eq!(
            json!(report.counters.rejected_records),
            want["rejected"],
            "{name}: {report:?}"
        );
        assert_eq!(
            json!(report.failure.map(FailureCode::as_str)),
            want["failure"],
            "{name}"
        );
        assert_eq!(json!(report.outcome), want["outcome"], "{name}");
        let rows = events(&world.history()?, &id)?;
        let mut responses: Vec<&str> = rows
            .iter()
            .filter_map(|row| row["message_id"].as_str())
            .collect();
        responses.sort_unstable();
        assert_eq!(json!(responses), want["responses"], "{name}");
        if let Some(input) = want.get("input_tokens") {
            let row = rows
                .iter()
                .find(|row| row["message_id"] == "resp_hostile")
                .ok_or("row")?;
            assert_eq!(&row["input_tokens"], input, "{name}");
        }
    }
    // Hostile paths: a FIFO named like a rollout and a symlink to a file outside the root are
    // never read; the pass neither blocks nor counts them.
    let world = World::new()?;
    let outside = world.base.join("outside.jsonl");
    std::fs::write(&outside, format!("{header}\n{control}\n"))?;
    std::fs::create_dir_all(world.root.join("sessions/2026/03/29"))?;
    std::os::unix::fs::symlink(
        &outside,
        world.root.join("sessions/2026/03/29/rollout-outside.jsonl"),
    )?;
    let fifo = world.root.join("sessions/2026/03/29/rollout-fifo.jsonl");
    let status = Command::new("/usr/bin/mkfifo").arg(&fifo).status()?;
    assert!(status.success());
    let image = tree_image(&world.root)?;
    let outside_image = digest(&outside)?;
    let fs = RecordingFs::new();
    let opened = Arc::new(std::sync::Mutex::new(Vec::<PathBuf>::new()));
    {
        let opened = Arc::clone(&opened);
        fs.on_boundary(move |kind, path| {
            if matches!(
                kind,
                OpenKind::Header | OpenKind::Bounded | OpenKind::Tail | OpenKind::Sqlite
            ) {
                opened
                    .lock()
                    .expect("test opened lock")
                    .push(path.to_path_buf());
            }
        });
    }
    let mut engine: Engine<RecordingFs> = Engine::open(&world.data, &world.home);
    let id = engine
        .attach_codex(fs, &world.root, enabled(), SourceKind::Custom)
        .map_err(|r| format!("{r:?}"))?;
    engine.pass(&id, enabled(), DAY_NOW);
    assert_eq!(events(&world.history()?, &id)?.len(), 0);
    assert!(
        opened.lock().map_err(|_| "opened lock")?.is_empty(),
        "FIFO and escaped content never opened"
    );
    assert_eq!(tree_image(&world.root)?, image);
    assert_eq!(digest(&outside)?, outside_image);
    Ok(())
}

fn scan_codex_sinks(
    sinks: &std::collections::BTreeMap<String, Vec<u8>>,
    expected: &[&str],
    sentinel: &[u8],
) -> Result<(), String> {
    let observed: std::collections::BTreeSet<&str> = sinks.keys().map(String::as_str).collect();
    let expected: std::collections::BTreeSet<&str> = expected.iter().copied().collect();
    if observed != expected {
        return Err(format!(
            "sink inventory: expected {expected:?}, observed {observed:?}"
        ));
    }
    for (name, bytes) in sinks {
        if bytes
            .windows(sentinel.len())
            .any(|window| window == sentinel)
        {
            return Err(format!("sentinel found in {name}"));
        }
    }
    Ok(())
}

#[test]
fn codex_sentinel_absent_from_store_wal_spool() -> TestResult {
    const SENTINEL: &str = "QUOTERN-CODEX-SENTINEL-7f3a";
    const CAPTURE: &str = "QUOTERN_CODEX_SENTINEL_CHILD";
    if std::env::var_os(CAPTURE).is_none() {
        // A separate test process captures output without redirecting parallel tests' descriptors.
        let output = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "codex_sentinel_absent_from_store_wal_spool",
                "--nocapture",
            ])
            .env(CAPTURE, "1")
            .output()?;
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("numeric-control-input=9"));
        let sinks = std::collections::BTreeMap::from([
            ("captured-stdout".to_owned(), output.stdout),
            ("captured-stderr".to_owned(), output.stderr),
        ]);
        scan_codex_sinks(
            &sinks,
            &["captured-stdout", "captured-stderr"],
            SENTINEL.as_bytes(),
        )?;
        for name in sinks.keys() {
            let mut planted = sinks.clone();
            planted
                .get_mut(name)
                .ok_or("sink")?
                .extend_from_slice(SENTINEL.as_bytes());
            assert_eq!(
                scan_codex_sinks(
                    &planted,
                    &["captured-stdout", "captured-stderr"],
                    SENTINEL.as_bytes()
                ),
                Err(format!("sentinel found in {name}"))
            );
            let mut omitted = sinks.clone();
            omitted.remove(name);
            assert!(
                scan_codex_sinks(
                    &omitted,
                    &["captured-stdout", "captured-stderr"],
                    SENTINEL.as_bytes()
                )
                .is_err()
            );
        }
        return Ok(());
    }
    let world = World::new()?;
    let id = "0195f000-0000-7000-8000-0000000005e1";
    let header = json!({
        "timestamp": "2026-03-29T08:00:00.000Z", "type": "session_meta",
        "payload": { "id": id, "cli_version": "0.153.0", "cwd": format!("/{SENTINEL}/cwd"),
            "base_instructions": { "text": SENTINEL }, "git": { "branch": SENTINEL }, "source": "cli" }
    });
    let message = json!({
        "timestamp": "2026-03-29T08:00:10.000Z", "type": "response_item",
        "payload": { "type": "message", "role": "user", "content": [{ "type": "input_text", "text": SENTINEL }] }
    });
    let context = json!({ "timestamp": "2026-03-29T08:00:11.000Z", "type": "turn_context", "payload": { "model": SENTINEL, "cwd": SENTINEL } });
    let record = json!({
        "timestamp": "2026-03-29T08:01:00.000Z", "type": "token_usage_record",
        "payload": { "thread_id": id, "turn_id": SENTINEL, "session_id": id, "root_turn_id": SENTINEL,
            "response_id": "resp_sentinel", "usage": { "input_tokens": 9, "total_tokens": 9 } }
    });
    let rejected = record.to_string().replace(
        "\"input_tokens\":9",
        &format!("\"input_tokens\":\"{SENTINEL}\""),
    );
    let text =
        format!("{header}\n{message}\n{context}\n{record}\n{rejected}\n{{\"{SENTINEL}\": \n");
    world.put(
        "sessions/2026/03/29/rollout-sentinel.jsonl",
        text.as_bytes(),
    )?;
    for index in 0..70 {
        world.put(&format!("sessions/pad-{index:02}/rollout-empty.jsonl"), b"")?;
    }
    let (mut engine, source) = world.engine()?;
    let report = pass(&mut engine, &source, DAY_NOW);
    assert_eq!(report.records_committed, 1);
    assert!(!format!("{report:?}").contains(SENTINEL));
    let snapshot = serde_json::to_vec(
        &engine
            .today_snapshot("UTC", DAY_NOW)
            .map_err(|error| format!("{error:?}"))?,
    )?;
    let actual: Value = serde_json::from_slice(&snapshot)?;
    assert_eq!(reported_of(&actual, &source)?["input"]["value"], 9);
    let connection = world.history()?;
    let spooled: i64 = connection.query_row(
        "SELECT COUNT(*) FROM metadata_spool WHERE source_id = ?1",
        [&source],
        |row| row.get(0),
    )?;
    assert!(spooled > 0, "active durable spool is scanned");
    let mut dump = Vec::new();
    let tables = objects(
        &connection,
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
        &[],
    )?;
    for table in tables {
        let name = table["name"].as_str().ok_or("table name")?;
        let escaped = name.replace('"', "\"\"");
        dump.extend(serde_json::to_vec(&objects(
            &connection,
            &format!("SELECT * FROM \"{escaped}\""),
            &[],
        )?)?);
    }
    let report_bytes = serde_json::to_vec(&report)?;
    let mut sinks = std::collections::BTreeMap::from([
        ("today-snapshot-json".to_owned(), snapshot.clone()),
        ("pass-report-json".to_owned(), report_bytes.clone()),
        ("history-table-dump".to_owned(), dump),
    ]);
    for entry in std::fs::read_dir(&world.data)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("file name")?;
        sinks.insert(format!("file:{name}"), std::fs::read(&path)?);
    }
    const EXPECTED: [&str; 6] = [
        "file:history.sqlite",
        "file:history.sqlite-wal",
        "file:history.sqlite-shm",
        "today-snapshot-json",
        "pass-report-json",
        "history-table-dump",
    ];
    scan_codex_sinks(&sinks, &EXPECTED, SENTINEL.as_bytes())?;
    for name in sinks.keys() {
        let mut planted = sinks.clone();
        planted
            .get_mut(name)
            .ok_or("sink")?
            .extend_from_slice(SENTINEL.as_bytes());
        assert_eq!(
            scan_codex_sinks(&planted, &EXPECTED, SENTINEL.as_bytes()),
            Err(format!("sentinel found in {name}"))
        );
        let mut omitted = sinks.clone();
        omitted.remove(name);
        assert!(scan_codex_sinks(&omitted, &EXPECTED, SENTINEL.as_bytes()).is_err());
    }
    println!("{}", String::from_utf8(snapshot)?);
    println!("{}", String::from_utf8(report_bytes)?);
    println!("numeric-control-input=9; scanned-sinks={}", sinks.len());
    Ok(())
}

#[test]
fn auth_json_never_opened() -> TestResult {
    let world = World::new()?;
    world.basic()?;
    world.put("auth.json", b"{\"OPENAI_API_KEY\":\"sk-never-read\"}")?;
    world.put(
        "history.jsonl",
        b"{\"session_id\":\"x\",\"text\":\"prompt\"}\n",
    )?;
    world.put("config.toml", b"model = \"gpt-5\"\n")?;
    let observed = RecordingFs::new();
    let opened = Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let opened = Arc::clone(&opened);
        observed.on_boundary(move |_, path| {
            if let Ok(mut opened) = opened.lock() {
                opened.push(path.to_path_buf());
            }
        });
    }
    let mut engine: Engine<RecordingFs> = Engine::open(&world.data, &world.home);
    let id = engine
        .attach_codex(observed.clone(), &world.root, enabled(), SourceKind::Custom)
        .map_err(|report| format!("{report:?}"))?;
    let report = engine.pass(&id, enabled(), DAY_NOW);
    assert_eq!(report.records_committed, 3);
    let opened = opened.lock().map_err(|_| "poisoned")?;
    assert!(!opened.is_empty());
    for path in opened.iter() {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        assert!(
            !["auth.json", "history.jsonl", "config.toml"].contains(&name),
            "{} was opened",
            path.display()
        );
    }
    assert!(observed.metrics().tail_reads >= 1);
    Ok(())
}

#[test]
fn invalid_semver_build_metadata_keeps_legacy_coverage() -> TestResult {
    for (version, completeness) in [
        ("0.153.0+", "partial"),
        ("0.153.0+ ", "partial"),
        ("0.153.0+a..b", "partial"),
        ("0.153.0+a_b", "partial"),
        ("0.153.0+a+b", "partial"),
        ("0.153.0+build.01-a", "complete"),
        ("0.153.0-alpha.1+build.01", "complete"),
    ] {
        let world = World::new()?;
        let text = header_line("2026-03-29T08:00:00Z", "own", None, Some(version))
            + &token_count_line("2026-03-29T08:01:00Z")
            + &record_line(
                "2026-03-29T08:02:00Z",
                "own",
                "own",
                "r",
                json!({"input_tokens":10}),
            );
        world.put("sessions/rollout-version.jsonl", text.as_bytes())?;
        let (mut engine, id) = world.engine()?;
        pass(&mut engine, &id, DAY_NOW);
        let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
        assert_eq!(entry["input"]["value"], 10, "{version}");
        assert_eq!(entry["input"]["completeness"], completeness, "{version}");
    }
    Ok(())
}

#[test]
fn foreign_first_usage_line_contributes_coverage_only() -> TestResult {
    for first in [
        record_line(
            "2026-03-29T08:00:00Z",
            "foreign",
            "foreign",
            "r",
            json!({"input_tokens":900}),
        ),
        token_count_line("2026-03-29T08:00:00Z"),
    ] {
        let world = World::new()?;
        world.put("sessions/rollout-foreign.jsonl", first.as_bytes())?;
        world.put("sessions/rollout-own.jsonl", conflict_file(10).as_bytes())?;
        let (mut engine, id) = world.engine()?;
        pass(&mut engine, &id, DAY_NOW);
        let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
        assert_eq!(entry["records"], 1);
        assert_eq!(entry["input"]["value"], 10);
        assert_eq!(entry["input"]["completeness"], "partial");
        assert_eq!(
            file_state(&world.history()?, &id, "sessions/rollout-foreign.jsonl")?["uncovered_from_ms"],
            1_774_771_200_000i64
        );
    }
    Ok(())
}

#[test]
fn invalid_own_record_coverage_survives_unchanged_reopen() -> TestResult {
    for (timestamp, response, usage, code, from, to) in [
        (
            "2026-03-29T08:00:00Z",
            "bad",
            json!({"input_tokens":-1}),
            FailureCode::InvalidNumber,
            1_774_771_200_000i64,
            1_774_771_200_000i64,
        ),
        (
            "2026-03-29T08:00:00Z",
            "",
            json!({"input_tokens":8}),
            FailureCode::InvalidRecord,
            1_774_771_200_000,
            1_774_771_200_000,
        ),
        (
            "not-a-time",
            "bad",
            json!({"input_tokens":8}),
            FailureCode::InvalidRecord,
            0,
            253_402_300_799_999,
        ),
    ] {
        let world = World::new()?;
        let relative = "sessions/rollout-invalid.jsonl";
        let text = conflict_file(10)
            + &record_line(
                timestamp,
                "0195f000-0000-7000-8000-0000000cf001",
                "own",
                response,
                usage,
            );
        world.put(relative, text.as_bytes())?;
        {
            let (mut engine, id) = world.engine()?;
            let report = pass(&mut engine, &id, DAY_NOW);
            assert_eq!(report.failure, Some(code));
            let state = file_state(&world.history()?, &id, relative)?;
            assert_eq!(state["byte_offset"], text.len());
            assert_eq!(state["uncovered_from_ms"], from);
            assert_eq!(state["uncovered_to_ms"], to);
        }
        let (mut engine, id) = world.engine()?;
        assert_eq!(pass(&mut engine, &id, DAY_NOW + 1000).records_committed, 0);
        let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW + 1000)?, &id)?;
        assert_eq!(entry["input"]["value"], 10);
        assert_eq!(entry["input"]["completeness"], "partial");
    }
    Ok(())
}

#[test]
fn retained_uncovered_range_survives_replacement_and_truncation() -> TestResult {
    for replacement in [false, true] {
        let world = World::new()?;
        let relative = "sessions/rollout-coverage.jsonl";
        let original = header_line("2026-03-29T08:00:00Z", "legacy", None, Some("0.152.0"))
            + &token_count_line("2026-03-29T08:01:00Z");
        world.put(relative, original.as_bytes())?;
        let id = {
            let (mut engine, id) = world.engine()?;
            pass(&mut engine, &id, DAY_NOW);
            id
        };
        if replacement {
            replace(&world, relative, "")?;
        } else {
            world.put(relative, b"")?;
        }
        world.put(
            "sessions/rollout-control.jsonl",
            conflict_file(10).as_bytes(),
        )?;
        let (mut engine, reopened) = world.engine()?;
        assert_eq!(id, reopened);
        pass(&mut engine, &id, DAY_NOW + 1000);
        let state = file_state(&world.history()?, &id, relative)?;
        assert_eq!(state["uncovered_from_ms"], 1_774_771_260_000i64);
        assert_eq!(state["uncovered_to_ms"], 1_774_771_260_000i64);
        let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW + 1000)?, &id)?;
        assert_eq!(entry["input"]["value"], 10);
        assert_eq!(entry["input"]["completeness"], "partial");
    }
    Ok(())
}

#[test]
fn same_id_session_meta_append_survives_reopen() -> TestResult {
    let world = World::new()?;
    let relative = "sessions/rollout-resume.jsonl";
    let text = header_line("2026-03-29T08:00:00Z", "own", None, Some("0.153.0"));
    world.put(relative, text.as_bytes())?;
    {
        let (mut engine, id) = world.engine()?;
        pass(&mut engine, &id, DAY_NOW);
    }
    let append = header_line("2026-03-29T08:01:00Z", "own", None, Some("0.152.0"))
        + &record_line(
            "2026-03-29T08:02:00Z",
            "own",
            "own",
            "r",
            json!({"input_tokens":7}),
        );
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(world.root.join(relative))?
        .write_all(append.as_bytes())?;
    let (mut engine, id) = world.engine()?;
    assert_eq!(pass(&mut engine, &id, DAY_NOW + 1000).records_committed, 1);
    let state = file_state(&world.history()?, &id, relative)?;
    assert_eq!(state["header_state"], "own");
    assert_eq!(state["header_era"], "record");
    let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
    assert_eq!(entry["input"]["value"], 7);
    assert_eq!(entry["input"]["completeness"], "complete");
    assert_eq!(pass(&mut engine, &id, DAY_NOW + 2000).records_committed, 0);
    Ok(())
}

#[test]
fn divergent_smaller_copy_revises_projection_across_reopen() -> TestResult {
    let world = World::new()?;
    let large = "sessions/rollout-x.jsonl";
    let small = "archived_sessions/rollout-x.jsonl";
    world.put(large, conflict_file(10).as_bytes())?;
    {
        let (mut engine, id) = world.engine()?;
        pass(&mut engine, &id, DAY_NOW);
    }
    world.put(small, conflict_file(20).as_bytes())?;
    let (mut engine, id) = world.engine()?;
    assert_eq!(pass(&mut engine, &id, DAY_NOW + 1000).records_committed, 1);
    let rows = events(&world.history()?, &id)?;
    assert_eq!(rows.len(), 1);
    assert_fields(
        &rows[0],
        &json!({"mirror_path":small,"input_tokens":20,"total_tokens":20,"mirror_conflict":1,"revision":2}),
        "smaller divergent copy",
    );
    let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
    assert_eq!(entry["input"]["value"], 20);
    assert_eq!(entry["mirror_conflict"], true);
    assert_eq!(pass(&mut engine, &id, DAY_NOW + 2000).records_committed, 0);
    Ok(())
}

#[test]
fn same_inode_prefix_correction_then_append_revises_consumed_record() -> TestResult {
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    let world = World::new()?;
    let relative = "sessions/rollout-prefix.jsonl";
    let path = world.put(relative, conflict_file(10).as_bytes())?;
    let inode = std::fs::metadata(&path)?.ino();
    {
        let (mut engine, id) = world.engine()?;
        assert_eq!(pass(&mut engine, &id, DAY_NOW).records_committed, 1);
    }
    let corrected = conflict_file(20);
    let append = record_line(
        "2026-03-29T08:02:00Z",
        "0195f000-0000-7000-8000-0000000cf001",
        "0195f000-0000-7000-8000-0000000cf001",
        "resp_append",
        json!({"input_tokens":3,"total_tokens":3}),
    );
    let mut file = std::fs::OpenOptions::new().write(true).open(&path)?;
    file.write_all(corrected.as_bytes())?;
    file.write_all(append.as_bytes())?;
    assert_eq!(std::fs::metadata(&path)?.ino(), inode);
    let (mut engine, id) = world.engine()?;
    pass(&mut engine, &id, DAY_NOW + 1000);
    let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
    assert_eq!(
        entry["input"]["value"], 23,
        "corrected 20 plus appended 3, never stale 10 plus 3"
    );
    let rows = events(&world.history()?, &id)?;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["revision"], 2);
    assert_eq!(pass(&mut engine, &id, DAY_NOW + 2000).records_committed, 0);
    drop(engine);
    let (mut engine, reopened) = world.engine()?;
    assert_eq!(reopened, id);
    assert_eq!(
        reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?["input"]["value"],
        23
    );
    assert_eq!(events(&world.history()?, &id)?, rows);
    assert_eq!(pass(&mut engine, &id, DAY_NOW + 3000).records_committed, 0);
    Ok(())
}

#[test]
fn cancellation_during_later_file_read_commits_no_partial_file() -> TestResult {
    let world = World::new()?;
    for index in 0..3 {
        let own = format!("own{index}");
        let text = header_line("2026-03-29T08:00:00Z", &own, None, Some("0.153.0"))
            + &record_line(
                "2026-03-29T08:01:00Z",
                &own,
                &own,
                "a",
                json!({"input_tokens":2}),
            )
            + &record_line(
                "2026-03-29T08:02:00Z",
                &own,
                &own,
                "b",
                json!({"input_tokens":3}),
            );
        world.put(&format!("sessions/rollout-{index}.jsonl"), text.as_bytes())?;
    }
    let fs = RecordingFs::new();
    let flag = Arc::new(AtomicBool::new(false));
    let interrupted = Arc::new(std::sync::Mutex::new(None::<PathBuf>));
    {
        let (flag, interrupted) = (Arc::clone(&flag), Arc::clone(&interrupted));
        let mut reads = 0;
        fs.on_boundary(move |kind, path| {
            if kind == OpenKind::TailRead {
                reads += 1;
                if reads == 2 {
                    *interrupted.lock().expect("test path lock") = Some(path.to_path_buf());
                    flag.store(true, Ordering::Release);
                }
            }
        });
    }
    let mut engine: Engine<RecordingFs> = Engine::open(&world.data, &world.home);
    let id = engine
        .attach_codex(fs.clone(), &world.root, enabled(), SourceKind::Custom)
        .map_err(|r| format!("{r:?}"))?;
    let cancelled = engine.pass_until(&id, enabled(), DAY_NOW, &flag);
    assert!(matches!(cancelled, Err(PassCancelled(_))), "{cancelled:?}");
    let relative = interrupted
        .lock()
        .map_err(|_| "path lock")?
        .clone()
        .ok_or("interrupted path")?
        .strip_prefix(&world.root)?
        .to_path_buf();
    let connection = world.history()?;
    assert_eq!(
        count(
            &connection,
            "SELECT COUNT(*) FROM source_files WHERE source_id=?1 AND relative_path=?2",
            &[&id, &relative.to_str().ok_or("relative")?]
        )?,
        0
    );
    assert_eq!(
        events(&connection, &id)?.len(),
        2,
        "only earlier whole file committed"
    );
    let projection = engine
        .today_snapshot("UTC", DAY_NOW)
        .map_err(|e| format!("{e:?}"))?;
    let entry = reported_of(&serde_json::to_value(projection)?, &id)?;
    assert_eq!(entry["records"], 2);
    assert_eq!(entry["input"]["value"], 5);
    fs.on_boundary(|_, _| {});
    flag.store(false, Ordering::Release);
    let converged = engine.pass(&id, enabled(), DAY_NOW + 1000);
    assert_eq!(converged.records_committed, 4);
    assert_eq!(events(&connection, &id)?.len(), 6);
    let entry = reported_of(
        &serde_json::to_value(
            engine
                .today_snapshot("UTC", DAY_NOW)
                .map_err(|e| format!("{e:?}"))?,
        )?,
        &id,
    )?;
    assert_eq!(entry["input"]["value"], 15);
    assert_eq!(
        engine
            .pass(&id, enabled(), DAY_NOW + 2000)
            .records_committed,
        0
    );
    Ok(())
}

#[test]
fn cancellation_between_later_file_records_discards_the_whole_batch() -> TestResult {
    let world = World::new()?;
    for own in ["one", "two"] {
        let text = header_line("2026-03-29T08:00:00Z", own, None, Some("0.153.0"))
            + &record_line(
                "2026-03-29T08:01:00Z",
                own,
                own,
                "a",
                json!({"input_tokens":2}),
            )
            + &record_line(
                "2026-03-29T08:02:00Z",
                own,
                own,
                "b",
                json!({"input_tokens":3}),
            );
        world.put(&format!("sessions/rollout-{own}.jsonl"), text.as_bytes())?;
    }
    let (mut engine, id) = world.engine()?;
    let flag = Arc::new(AtomicBool::new(false));
    let lines = Arc::new(AtomicUsize::new(0));
    {
        let (flag, lines) = (Arc::clone(&flag), Arc::clone(&lines));
        quotern_core::adapters::codex::set_line_hook(Some(Box::new(move || {
            if lines.fetch_add(1, Ordering::SeqCst) == 5 {
                flag.store(true, Ordering::Release);
            }
        })));
    }
    let cancelled = engine.pass_until(&id, enabled(), DAY_NOW, &flag);
    quotern_core::adapters::codex::set_line_hook(None);
    assert!(matches!(cancelled, Err(PassCancelled(_))), "{cancelled:?}");
    assert_eq!(lines.load(Ordering::SeqCst), 6);
    assert_eq!(events(&world.history()?, &id)?.len(), 2);
    assert_eq!(
        count(
            &world.history()?,
            "SELECT COUNT(*) FROM source_files WHERE source_id=?1 AND byte_offset>0",
            &[&id]
        )?,
        1
    );
    let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
    assert_eq!(
        entry["input"]["value"], 5,
        "no partly parsed second-file delta"
    );
    flag.store(false, Ordering::Release);
    assert_eq!(pass(&mut engine, &id, DAY_NOW + 1000).records_committed, 2);
    let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
    assert_eq!(entry["input"]["value"], 10);
    assert_eq!(pass(&mut engine, &id, DAY_NOW + 2000).records_committed, 0);
    Ok(())
}

#[test]
fn replacement_and_truncation_during_tail_read_preserve_history_and_cursor() -> TestResult {
    use std::io::Write;
    for replacement in [false, true] {
        let world = World::new()?;
        let relative = "sessions/rollout-changing.jsonl";
        let initial = conflict_file(10);
        let path = world.put(relative, initial.as_bytes())?;
        let fs = RecordingFs::new();
        let mut engine: Engine<RecordingFs> = Engine::open(&world.data, &world.home);
        let id = engine
            .attach_codex(fs.clone(), &world.root, enabled(), SourceKind::Custom)
            .map_err(|r| format!("{r:?}"))?;
        assert_eq!(engine.pass(&id, enabled(), DAY_NOW).records_committed, 1);
        let state = file_state(&world.history()?, &id, relative)?;
        let history = events(&world.history()?, &id)?;
        let append = record_line(
            "2026-03-29T08:02:00Z",
            "0195f000-0000-7000-8000-0000000cf001",
            "own",
            "new",
            json!({"input_tokens":3}),
        );
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)?
            .write_all(append.as_bytes())?;
        let restored = Arc::new(std::sync::Mutex::new(false));
        {
            let restored = Arc::clone(&restored);
            let target = path.clone();
            let staging = world.base.join("replacement.jsonl");
            let initial = initial.clone();
            fs.on_boundary(move |kind, path| {
                if kind == OpenKind::TailRead
                    && path == target
                    && !*restored.lock().expect("test race lock")
                {
                    if replacement {
                        std::fs::write(&staging, &initial).expect("test replacement");
                        std::fs::rename(&staging, &target).expect("test rename");
                    } else {
                        std::fs::OpenOptions::new()
                            .write(true)
                            .open(&target)
                            .expect("test truncate")
                            .set_len(0)
                            .expect("test truncate length");
                    }
                    *restored.lock().expect("test race lock") = true;
                }
            });
        }
        let report = engine.pass(&id, enabled(), DAY_NOW + 1000);
        assert!(
            *restored.lock().map_err(|_| "race lock")?,
            "actual read boundary reached"
        );
        assert_eq!(
            report.failure,
            Some(FailureCode::SourceChanging),
            "replacement={replacement}: {report:?}"
        );
        assert_eq!(
            report.counters.bytes_read,
            (initial.len() + append.len()) as u64,
            "interrupted changed-file acquisition still consumes its full byte budget"
        );
        assert_eq!(report.records_committed, 0);
        assert_eq!(events(&world.history()?, &id)?, history);
        assert_eq!(file_state(&world.history()?, &id, relative)?, state);
        fs.on_boundary(|_, _| {});
        std::fs::write(&path, initial + &append)?;
        assert_eq!(
            engine
                .pass(&id, enabled(), DAY_NOW + 2000)
                .records_committed,
            1
        );
        assert_eq!(events(&world.history()?, &id)?.len(), 2);
        assert_eq!(
            engine
                .pass(&id, enabled(), DAY_NOW + 3000)
                .records_committed,
            0
        );
    }
    Ok(())
}

#[test]
fn attached_codex_root_replacement_is_refused_without_source_access() -> TestResult {
    for data_root in [false, true] {
        let world = World::new()?;
        world.basic()?;
        let fs = RecordingFs::new();
        let mut engine: Engine<RecordingFs> = Engine::open(&world.data, &world.home);
        let id = engine
            .attach_codex(fs.clone(), &world.root, enabled(), SourceKind::Custom)
            .map_err(|r| format!("{r:?}"))?;
        engine.pass(&id, enabled(), DAY_NOW);
        let root = if data_root { &world.data } else { &world.root };
        let detached = world.base.join("detached");
        std::fs::rename(root, &detached)?;
        std::fs::create_dir(root)?;
        let image = tree_image(root)?;
        let before = fs.metrics();
        let report = engine.pass(&id, enabled(), DAY_NOW + 1000);
        assert_eq!(report.outcome, PassOutcome::Unavailable, "{report:?}");
        assert_eq!(report.failure, Some(FailureCode::RootOverlap));
        assert_eq!(fs.metrics().tail_reads, before.tail_reads);
        assert_eq!(fs.metrics().directory_opens, before.directory_opens);
        assert_eq!(tree_image(root)?, image);
        std::fs::remove_dir(root)?;
        std::fs::rename(&detached, root)?;
        let entry = reported_of(
            &serde_json::to_value(
                engine
                    .today_snapshot("UTC", DAY_NOW)
                    .map_err(|e| format!("{e:?}"))?,
            )?,
            &id,
        )?;
        assert_eq!(entry["records"], 3, "last numeric history retained");
        assert_eq!(
            engine
                .pass(&id, enabled(), DAY_NOW + 2000)
                .records_committed,
            0
        );
    }
    Ok(())
}

fn stamp_race_is_retried(boundary: OpenKind, growth: bool) -> TestResult {
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, SystemTime};
    let world = World::new()?;
    let relative = "sessions/rollout-race.jsonl";
    let path = world.put(relative, conflict_file(10).as_bytes())?;
    let fs = RecordingFs::new();
    let mut engine = Engine::open(&world.data, &world.home);
    let id = engine
        .attach_codex(fs.clone(), &world.root, enabled(), SourceKind::Custom)
        .map_err(|r| format!("{r:?}"))?;
    assert_eq!(engine.pass(&id, enabled(), DAY_NOW).records_committed, 1);
    let before_rows = events(&world.history()?, &id)?;
    let before_state = objects(
        &world.history()?,
        "SELECT source_id, relative_path, device, inode, size, mtime_ns, byte_offset, first_line_fnv64, adapter_state, header_id, header_state, header_era, record_state, tail_state, uncovered_from_ms, uncovered_to_ms, file_state, parse_generation FROM source_files WHERE source_id = ?1",
        &[&id],
    )?;
    let before_projection = objects(
        &world.history()?,
        "SELECT * FROM source_projection_totals WHERE source_id = ?1",
        &[&id],
    )?;
    assert_eq!(before_projection.len(), 1);
    assert_eq!(before_state.len(), 1);
    let own = "0195f000-0000-7000-8000-0000000cf001";
    let append = record_line(
        "2026-03-29T08:02:00Z",
        own,
        own,
        "append",
        json!({"input_tokens":3,"total_tokens":3}),
    );
    let selected = conflict_file(if boundary == OpenKind::Tail { 10 } else { 20 }) + &append;
    world.put(relative, selected.as_bytes())?;
    std::fs::File::open(&path)?.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(100))?;
    let selected_stamp = std::fs::metadata(&path)?;
    let mut corrected = conflict_file(20) + &append;
    assert_eq!(selected.len(), corrected.len());
    if growth {
        corrected.push_str("{}\n");
    }
    let corrected_len = corrected.len();
    let calls = Arc::new(AtomicUsize::new(0));
    let called = Arc::clone(&calls);
    fs.on_boundary(move |kind, target| {
        if kind == boundary && called.fetch_add(1, Ordering::SeqCst) == 0 {
            std::fs::write(target, &corrected).expect("synthetic mutation");
            std::fs::File::open(target)
                .expect("synthetic file")
                .set_modified(
                    SystemTime::UNIX_EPOCH + Duration::from_secs(if growth { 100 } else { 200 }),
                )
                .expect("synthetic mtime");
        }
    });
    let tail_reads = fs.metrics().tail_reads;
    let report = engine.pass(&id, enabled(), DAY_NOW + 1000);
    assert_eq!(
        report.failure,
        Some(FailureCode::SourceChanging),
        "{report:?}"
    );
    assert_eq!(report.records_committed, 0);
    assert_eq!(fs.metrics().tail_reads - tail_reads, 1, "no inner retry");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let changed_stamp = std::fs::metadata(&path)?;
    assert_eq!(selected_stamp.ino(), changed_stamp.ino());
    if growth {
        assert_eq!(selected_stamp.len() + 3, changed_stamp.len());
        assert_eq!(selected_stamp.modified()?, changed_stamp.modified()?);
    } else {
        assert_eq!(selected_stamp.len(), changed_stamp.len());
        assert_ne!(selected_stamp.modified()?, changed_stamp.modified()?);
    }
    assert_eq!(events(&world.history()?, &id)?, before_rows);
    assert_eq!(
        objects(
            &world.history()?,
            "SELECT source_id, relative_path, device, inode, size, mtime_ns, byte_offset, first_line_fnv64, adapter_state, header_id, header_state, header_era, record_state, tail_state, uncovered_from_ms, uncovered_to_ms, file_state, parse_generation FROM source_files WHERE source_id = ?1",
            &[&id]
        )?,
        before_state
    );
    assert_eq!(
        objects(
            &world.history()?,
            "SELECT * FROM source_projection_totals WHERE source_id = ?1",
            &[&id]
        )?,
        before_projection
    );
    let failed = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
    assert_eq!(failed["input"]["value"], 10);
    assert_eq!(failed["input"]["status"], "error");
    fs.on_boundary(|_, _| {});
    let retry = engine.pass(&id, enabled(), DAY_NOW + 2000);
    assert_eq!(retry.records_committed, 2, "{retry:?}");
    assert_eq!(retry.counters.bytes_read, corrected_len as u64);
    assert_eq!(retry.counters.header_reads, 1);
    let rows = events(&world.history()?, &id)?;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["revision"], 2);
    assert_eq!(
        reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?["input"]["value"],
        23
    );
    drop(engine);
    let (mut engine, _) = world.engine()?;
    let replay = pass(&mut engine, &id, DAY_NOW + 3000);
    assert_eq!(
        (replay.records_committed, replay.counters.bytes_read),
        (0, 0)
    );
    assert_eq!(events(&world.history()?, &id)?, rows);
    Ok(())
}

#[test]
fn codex_stamp_change_between_stat_and_open_is_retried() -> TestResult {
    stamp_race_is_retried(OpenKind::Tail, false)?;
    stamp_race_is_retried(OpenKind::Tail, true)
}

#[test]
fn codex_stamp_change_during_read_is_retried() -> TestResult {
    stamp_race_is_retried(OpenKind::TailRead, false)?;
    stamp_race_is_retried(OpenKind::TailRead, true)
}

#[test]
fn codex_changed_stamp_resets_header_and_tail_state() -> TestResult {
    for tail in ["pending", "discarding", "failed"] {
        let world = World::new()?;
        let relative = "sessions/rollout-reset.jsonl";
        let initial = header_line("2026-03-29T08:00:00Z", "old", None, Some("0.152.0"))
            + &token_count_line("2026-03-29T08:00:00Z")
            + &record_line(
                "2026-03-29T08:01:00Z",
                "old",
                "old",
                "old-response",
                json!({"input_tokens":10}),
            );
        let mut bytes = initial.as_bytes().to_vec();
        if tail == "discarding" {
            bytes.extend(vec![b'x'; 1_048_577]);
        } else {
            bytes.extend_from_slice(b"{");
        }
        world.put(relative, &bytes)?;
        let (mut engine, id) = world.engine()?;
        for step in 0..4 {
            pass(&mut engine, &id, DAY_NOW + step * 1000);
        }
        if tail == "failed" {
            world.put(relative, b"{}\n")?;
            pass(&mut engine, &id, DAY_NOW + 4000);
        }
        let prior = file_state(&world.history()?, &id, relative)?;
        assert_eq!(
            prior["tail_state"],
            match tail {
                "failed" => Value::Null,
                _ => json!(tail),
            }
        );
        let witness: i64 = world.history()?.query_row(
            "SELECT first_line_fnv64 FROM source_files WHERE source_id=?1",
            [&id],
            |r| r.get(0),
        )?;
        drop(engine);
        let header = header_line("2026-03-29T08:00:00Z", "new", None, Some("0.153.0"));
        let replacement = header
            + &record_line(
                "2026-03-29T08:02:00Z",
                "new",
                "new",
                "new-response",
                json!({"input_tokens":7}),
            );
        let mut replacement = replacement.into_bytes();
        replacement.extend_from_slice(b"{}");
        replacement.resize(bytes.len() + 1, b' ');
        replacement.push(b'\n');
        world.put(relative, &replacement)?;
        let (mut engine, _) = world.engine()?;
        let first = pass(&mut engine, &id, DAY_NOW + 5000);
        assert_eq!(first.counters.header_reads, 1, "{tail}: {first:?}");
        for step in 0..4 {
            pass(&mut engine, &id, DAY_NOW + 6000 + step * 1000);
        }
        let state = file_state(&world.history()?, &id, relative)?;
        assert_fields(
            &state,
            &json!({"header_id":"new","header_state":"own","header_era":"record","record_state":"own","tail_state":null}),
            tail,
        );
        assert_eq!(state["uncovered_from_ms"], prior["uncovered_from_ms"]);
        assert_eq!(state["uncovered_to_ms"], prior["uncovered_to_ms"]);
        let new_witness: i64 = world.history()?.query_row(
            "SELECT first_line_fnv64 FROM source_files WHERE source_id=?1",
            [&id],
            |r| r.get(0),
        )?;
        assert_ne!(new_witness, witness);
        assert_eq!(events(&world.history()?, &id)?.len(), 2);
        let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
        assert_eq!(entry["input"]["value"], 17);
        assert_eq!(entry["input"]["completeness"], "partial");
        world.put(
            relative,
            ("{}\n".to_owned()
                + &record_line(
                    "2026-03-29T08:03:00Z",
                    "new",
                    "new",
                    "forbidden",
                    json!({"input_tokens":99}),
                ))
                .as_bytes(),
        )?;
        assert_eq!(pass(&mut engine, &id, DAY_NOW + 10000).records_committed, 0);
        assert_eq!(
            file_state(&world.history()?, &id, relative)?["header_state"],
            "foreign_first_line"
        );
        assert_eq!(events(&world.history()?, &id)?.len(), 2);
        assert_eq!(
            reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?["input"]["value"],
            17
        );
    }
    Ok(())
}

#[test]
fn corrected_prefix_event_cursor_fault_reopen_atomic() -> TestResult {
    for fault in [FaultPoint::BeforeCommit, FaultPoint::AfterCommit] {
        let world = World::new()?;
        let relative = "sessions/rollout-corrected-fault.jsonl";
        world.put(relative, conflict_file(10).as_bytes())?;
        let (mut engine, id) = world.engine()?;
        assert_eq!(pass(&mut engine, &id, DAY_NOW).records_committed, 1);
        let old_rows = events(&world.history()?, &id)?;
        let old_state = file_state(&world.history()?, &id, relative)?;
        let own = "0195f000-0000-7000-8000-0000000cf001";
        let corrected = conflict_file(20)
            + &record_line(
                "2026-03-29T08:02:00Z",
                own,
                own,
                "append",
                json!({"input_tokens":3}),
            );
        world.put(relative, corrected.as_bytes())?;
        engine.inject_commit_fault(fault);
        assert_eq!(
            pass(&mut engine, &id, DAY_NOW + 1000).failure,
            Some(FailureCode::Store)
        );
        drop(engine);
        let (mut engine, reopened) = world.engine()?;
        assert_eq!(id, reopened);
        if fault == FaultPoint::BeforeCommit {
            assert_eq!(events(&world.history()?, &id)?, old_rows);
            assert_eq!(file_state(&world.history()?, &id, relative)?, old_state);
            assert_eq!(
                reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?["input"]["value"],
                10
            );
            assert_eq!(pass(&mut engine, &id, DAY_NOW + 2000).records_committed, 2);
        } else {
            assert_eq!(
                file_state(&world.history()?, &id, relative)?["byte_offset"],
                corrected.len()
            );
            assert_eq!(pass(&mut engine, &id, DAY_NOW + 2000).records_committed, 0);
        }
        assert_eq!(
            reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?["input"]["value"],
            23
        );
        let rows = events(&world.history()?, &id)?;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["revision"], 2);
        assert_eq!(pass(&mut engine, &id, DAY_NOW + 3000).records_committed, 0);
    }
    Ok(())
}

#[test]
fn cancellation_after_zero_complete_lines_preserves_durable_batch() -> TestResult {
    for mode in ["pending", "oversize", "discarding"] {
        for reopen in [false, true] {
            let world = World::new()?;
            let relative = "sessions/old/cancel.jsonl";
            let text = header_line("2026-03-29T08:00:00Z", "own", None, Some("0.153.0"))
                + &record_line(
                    "2026-03-29T08:01:00Z",
                    "own",
                    "own",
                    "kept",
                    json!({"input_tokens": 10}),
                );
            world.put(relative, text.as_bytes())?;
            let fs = RecordingFs::new();
            let mut engine = Engine::open(&world.data, &world.home);
            let id = engine
                .attach_codex(fs.clone(), &world.root, enabled(), SourceKind::Custom)
                .map_err(|r| format!("{r:?}"))?;
            engine.pass(&id, enabled(), DAY_NOW);
            let bytes = match mode {
                "pending" => vec![b'{'; 10],
                "oversize" => vec![b'x'; 1_048_576],
                _ => vec![b'x'; 3 * 1_048_576],
            };
            let target = world.put(relative, &bytes)?;
            if mode == "discarding" {
                engine.pass(&id, enabled(), DAY_NOW + 1000);
            }
            let connection = world.history()?;
            let state = file_state(&connection, &id, relative)?;
            let retained = events(&connection, &id)?;
            let mut projection = snapshot(&engine, "UTC", DAY_NOW)?["source_reported"].clone();
            projection[0]["input"]["status"] = json!("catching_up");
            let flag = Arc::new(AtomicBool::new(false));
            let raised = Arc::clone(&flag);
            fs.on_boundary(move |kind, path| {
                if kind == OpenKind::TailRead && path == target {
                    raised.store(true, Ordering::Release);
                }
            });
            let result = engine.pass_until(&id, enabled(), DAY_NOW + 2000, &flag);
            fs.on_boundary(|_, _| {});
            assert!(
                flag.load(Ordering::Acquire),
                "read boundary reached: {mode}"
            );
            assert!(
                matches!(result, Err(PassCancelled(_))),
                "{mode}: {result:?}"
            );
            assert_eq!(
                file_state(&connection, &id, relative)?,
                state,
                "{mode}: cursor/parser/uncovered unchanged"
            );
            assert_eq!(events(&connection, &id)?, retained);
            assert_eq!(
                snapshot(&engine, "UTC", DAY_NOW)?["source_reported"],
                projection
            );
            if reopen {
                drop(engine);
                engine = Engine::open(&world.data, &world.home);
                engine
                    .attach_codex(fs.clone(), &world.root, enabled(), SourceKind::Custom)
                    .map_err(|r| format!("{r:?}"))?;
            }
            world.put(relative, text.as_bytes())?;
            let retry = engine.pass(&id, enabled(), DAY_NOW + 3000);
            assert_eq!(retry.records_committed, 0);
            assert_eq!(events(&connection, &id)?, retained);
        }
    }
    Ok(())
}

#[test]
fn boolean_array_object_counters_are_invalid_numbers() -> TestResult {
    for invalid in [json!(true), json!([1]), json!({"value": 1})] {
        let world = World::new()?;
        let text = header_line("2026-03-29T08:00:00Z", "own", None, Some("0.153.0"))
            + &record_line(
                "2026-03-29T08:01:00Z",
                "own",
                "own",
                "valid",
                json!({"input_tokens": 7, "output_tokens": 0, "cache_write_tokens": null}),
            )
            + &record_line(
                "2026-03-29T08:02:00Z",
                "own",
                "own",
                "hostile",
                json!({"input_tokens": invalid, "output_tokens": 0}),
            );
        world.put("sessions/old/types.jsonl", text.as_bytes())?;
        let (mut engine, id) = world.engine()?;
        let report = pass(&mut engine, &id, DAY_NOW);
        assert_eq!(report.failure, Some(FailureCode::InvalidNumber));
        assert_eq!(report.counters.rejected_records, 1);
        assert_eq!(report.records_committed, 1);
        let actual = events(&world.history()?, &id)?;
        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0]["message_id"], "valid");
        assert_eq!(actual[0]["input_tokens"], 7);
        assert_eq!(actual[0]["output_tokens"], 0);
        assert_eq!(actual[0]["cache_write_tokens"], Value::Null);
        let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
        assert_eq!(entry["input"]["value"], 7);
        assert_eq!(entry["input"]["completeness"], "partial");
    }
    Ok(())
}

#[test]
fn raw_positional_payloads_cannot_authorize_or_publish_records() -> TestResult {
    for (header, hostile, rejected, code) in [
        (
            r#"{"type":"session_meta","payload":["own",null,"0.153.0"]}"#,
            r#"{"timestamp":"2026-03-29T08:01:00Z","type":"token_usage_record","payload":{"thread_id":"own","session_id":"own","response_id":"hostile","usage":{"input_tokens":7}}}"#,
            0,
            None,
        ),
        (
            r#"{"type":"session_meta","payload":{"id":"own","cli_version":"0.153.0"}}"#,
            r#"{"timestamp":"2026-03-29T08:01:00Z","type":"token_usage_record","payload":["own","own","hostile",{"input_tokens":7,"total_tokens":7}]}"#,
            1,
            Some(FailureCode::InvalidRecord),
        ),
    ] {
        let world = World::new()?;
        let valid = record_line(
            "2026-03-29T08:02:00Z",
            "own",
            "own",
            "valid",
            json!({"input_tokens":3,"output_tokens":0,"cache_write_input_tokens":null}),
        );
        world.put(
            "sessions/old/raw.jsonl",
            format!("{header}\n{hostile}\n{valid}").as_bytes(),
        )?;
        let (mut engine, id) = world.engine()?;
        let report = pass(&mut engine, &id, DAY_NOW);
        let admitted = if rejected == 0 { 0 } else { 1 };
        assert_eq!(
            report.records_committed, admitted,
            "positional payload: {report:?}"
        );
        assert_eq!(report.counters.rejected_records, rejected);
        assert_eq!(report.failure, code);
        if admitted > 0 {
            assert_eq!(report.outcome, PassOutcome::Partial);
        }
        if admitted == 0 {
            assert_eq!(
                file_state(&world.history()?, &id, "sessions/old/raw.jsonl")?["header_state"],
                "foreign_first_line"
            );
        }
        for reopened in [false, true] {
            if reopened {
                drop(engine);
                (engine, _) = world.engine()?;
            }
            let actual = events(&world.history()?, &id)?;
            assert_eq!(actual.len(), admitted as usize);
            if admitted == 0 {
                let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
                assert_eq!(entry["records"], 0);
                assert_eq!(entry["input"]["value"], Value::Null);
            }
            if admitted > 0 {
                assert_eq!(actual[0]["message_id"], "valid");
                assert_eq!(actual[0]["input_tokens"], 3);
                assert_eq!(actual[0]["output_tokens"], 0);
                assert_eq!(actual[0]["cache_write_tokens"], Value::Null);
                let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
                assert_eq!(entry["input"]["value"], 3);
                assert_eq!(entry["input"]["completeness"], "partial");
            }
        }
    }
    Ok(())
}

#[test]
fn raw_duplicate_known_counters_fail_closed_without_losing_null_or_zero() -> TestResult {
    for field in [
        "input_tokens",
        "cached_input_tokens",
        "cache_write_input_tokens",
        "output_tokens",
        "reasoning_output_tokens",
        "total_tokens",
    ] {
        for (first, second) in [
            ("-1", "7"),
            ("7", "-1"),
            ("7", "7"),
            ("null", "0"),
            ("0", "null"),
        ] {
            let world = World::new()?;
            let header = header_line("2026-03-29T08:00:00Z", "own", None, Some("0.153.0"));
            let hostile = format!(
                r#"{{"timestamp":"2026-03-29T08:01:00Z","type":"token_usage_record","payload":{{"thread_id":"own","session_id":"own","response_id":"hostile","usage":{{"{field}":{first},"{field}":{second}}}}}}}"#
            );
            let valid = record_line(
                "2026-03-29T08:02:00Z",
                "own",
                "own",
                "valid",
                json!({"input_tokens":3,"output_tokens":0,"cache_write_input_tokens":null,"unknown":{"nested":[1,2]}}),
            );
            world.put(
                "sessions/old/duplicate.jsonl",
                format!("{header}{hostile}\n{valid}").as_bytes(),
            )?;
            let (mut engine, id) = world.engine()?;
            let report = pass(&mut engine, &id, DAY_NOW);
            assert_eq!(
                report.failure,
                Some(FailureCode::InvalidRecord),
                "{field} {first}/{second}: {report:?}"
            );
            assert_eq!(report.counters.rejected_records, 1);
            assert_eq!(report.records_committed, 1);
            assert_eq!(report.outcome, PassOutcome::Partial);
            for reopened in [false, true] {
                if reopened {
                    drop(engine);
                    (engine, _) = world.engine()?;
                }
                let actual = events(&world.history()?, &id)?;
                assert_eq!(actual.len(), 1);
                assert_eq!(actual[0]["message_id"], "valid");
                assert_eq!(actual[0]["input_tokens"], 3);
                assert_eq!(actual[0]["output_tokens"], 0);
                assert_eq!(actual[0]["cache_write_tokens"], Value::Null);
                assert_eq!(actual[0]["cache_read_tokens"], Value::Null);
                let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
                assert_eq!(entry["input"]["value"], 3);
                assert_eq!(entry["input"]["completeness"], "partial");
                assert_eq!(entry["output"]["value"], 0);
                assert_eq!(entry["cache_write"]["value"], Value::Null);
            }
        }
    }
    Ok(())
}

#[test]
fn raw_object_boundaries_preserve_error_families_and_skip_unknown_fields() -> TestResult {
    for (header, rejected) in [
        (
            r#"{"type":"session_meta","payload":{"id":"own","id":"other"}}"#,
            0,
        ),
        (
            r#"{"type":"session_meta","type":"session_meta","payload":{"id":"own"}}"#,
            1,
        ),
        (r#"{"type":"session_meta","payload":null}"#, 0),
        (r#"{"type":"session_meta","payload":1}"#, 0),
        (r#"{"type":"session_meta","payload":false}"#, 0),
        (r#"{"type":"session_meta","payload":{"id":"own"}"#, 1),
    ] {
        let world = World::new()?;
        let valid = record_line(
            "2026-03-29T08:01:00Z",
            "own",
            "own",
            "hostile",
            json!({"input_tokens":7}),
        );
        world.put(
            "sessions/old/header.jsonl",
            format!("{header}\n{valid}").as_bytes(),
        )?;
        let (mut engine, id) = world.engine()?;
        let report = pass(&mut engine, &id, DAY_NOW);
        assert_eq!(report.records_committed, 0);
        assert_eq!(report.counters.rejected_records, rejected);
        assert_eq!(
            report.failure,
            if rejected == 0 {
                None
            } else {
                Some(FailureCode::InvalidRecord)
            }
        );
        assert_eq!(
            file_state(&world.history()?, &id, "sessions/old/header.jsonl")?["header_state"],
            "foreign_first_line"
        );
        drop(engine);
        let (engine, _) = world.engine()?;
        assert!(events(&world.history()?, &id)?.is_empty());
        assert_eq!(
            reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?["input"]["value"],
            Value::Null
        );
    }
    for payload in [
        r#"{"thread_id":"own","thread_id":"own","session_id":"own","response_id":"hostile","usage":{"input_tokens":7}}"#,
        r#"{"thread_id":"own","session_id":"own","session_id":"own","response_id":"hostile","usage":{"input_tokens":7}}"#,
        r#"{"thread_id":"own","session_id":"own","response_id":"hostile","response_id":"hostile","usage":{"input_tokens":7}}"#,
        r#"{"thread_id":"own","session_id":"own","response_id":"hostile","usage":null}"#,
        r#"{"thread_id":"own","session_id":"own","response_id":"hostile","usage":[7]}"#,
        r#"{"thread_id":"own","session_id":"own","response_id":"hostile","usage":7}"#,
    ] {
        let world = World::new()?;
        let header = header_line("2026-03-29T08:00:00Z", "own", None, Some("0.153.0"));
        let hostile = format!(
            r#"{{"type":"token_usage_record","timestamp":"2026-03-29T08:01:00Z","payload":{payload}}}"#
        );
        let valid = r#"{"type":"token_usage_record","timestamp":"2026-03-29T08:02:00Z","payload":{"thread_id":"own","session_id":"own","response_id":"valid","usage":{"input_tokens":3,"output_tokens":0,"cache_write_input_tokens":null,"unknown":1,"unknown":{"ignored":[null]}}}}"#;
        world.put(
            "sessions/old/record.jsonl",
            format!("{header}{hostile}\n{valid}\n").as_bytes(),
        )?;
        let (mut engine, id) = world.engine()?;
        let report = pass(&mut engine, &id, DAY_NOW);
        assert_eq!(report.failure, Some(FailureCode::InvalidRecord));
        assert_eq!(report.counters.rejected_records, 1);
        assert_eq!(report.records_committed, 1);
        drop(engine);
        let (engine, _) = world.engine()?;
        assert_eq!(events(&world.history()?, &id)?.len(), 1);
        let entry = reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?;
        assert_eq!(entry["input"]["value"], 3);
        assert_eq!(entry["input"]["completeness"], "partial");
        assert_eq!(entry["output"]["value"], 0);
        assert_eq!(entry["cache_write"]["value"], Value::Null);
    }
    for (payload, completeness) in [
        (r#"["token_count",{}]"#, "complete"),
        (
            r#"{"type":"token_count","info":{},"unknown":[1]}"#,
            "partial",
        ),
    ] {
        let world = World::new()?;
        let header = header_line("2026-03-29T08:00:00Z", "own", None, Some("0.152.0"));
        let event = format!(
            r#"{{"type":"event_msg","timestamp":"2026-03-29T08:01:00Z","payload":{payload}}}"#
        );
        let valid = record_line(
            "2026-03-29T08:02:00Z",
            "own",
            "own",
            "valid",
            json!({"input_tokens":3}),
        );
        world.put(
            "sessions/old/event.jsonl",
            format!("{header}{event}\n{valid}").as_bytes(),
        )?;
        let (mut engine, id) = world.engine()?;
        let report = pass(&mut engine, &id, DAY_NOW);
        assert_eq!(report.counters.rejected_records, 0);
        assert_eq!(report.records_committed, 1);
        assert_eq!(
            reported_of(&snapshot(&engine, "UTC", DAY_NOW)?, &id)?["input"]["completeness"],
            completeness
        );
    }
    Ok(())
}
