mod support;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use quotern_core::domain::{ConsentState, PassOutcome, SourceAuthorization, SourceKind};
use quotern_core::ingest::Engine;
use quotern_core::ingest::fs::RealSourceFs;
use quotern_core::store::FaultPoint;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use support::{Roots, TestResult, rollback_database};

const SENTINEL: &[u8] = b"QUOTERN-SENTINEL-4F2A";
const SENTINEL_TEXT: &str = "QUOTERN-SENTINEL-4F2A";
/// Enough rows that one pass cannot finish the database, so the spool is active between passes.
const BULK_ROWS: u64 = 5_000;

/// Every file the application may own in its data directory.
const ALLOWED_FILES: [&str; 3] = [
    "file:history.sqlite",
    "file:history.sqlite-shm",
    "file:history.sqlite-wal",
];
const SERIALIZED_SINKS: [&str; 4] = [
    "snapshot-json",
    "pass-report-json",
    "observations-json",
    "history-table-dump",
];

fn enabled() -> SourceAuthorization {
    SourceAuthorization {
        selected: true,
        consent: ConsentState::Enabled,
    }
}

struct Sink {
    name: String,
    bytes: Vec<u8>,
}

fn contains_sentinel(bytes: &[u8]) -> bool {
    bytes
        .windows(SENTINEL.len())
        .any(|window| window == SENTINEL)
}

fn file_sinks(root: &Path) -> std::io::Result<Vec<Sink>> {
    let mut pending = vec![root.to_path_buf()];
    let mut sinks = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
                sinks.push(Sink {
                    name: format!("file:{}", relative.display()),
                    bytes: fs::read(&path)?,
                });
            }
        }
    }
    Ok(sinks)
}

/// Every text and blob value of every table, read through an independent connection.
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

fn count(data: &Path, table: &str) -> TestResult<i64> {
    let connection = Connection::open_with_flags(
        data.join("history.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    Ok(
        connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })?,
    )
}

/// What a scan of one application state found.
#[derive(Debug, Default, Eq, PartialEq)]
struct Findings {
    leaks: BTreeSet<String>,
    /// Sinks that exist but were never declared.
    unexpected: BTreeSet<String>,
    /// Sinks declared but never scanned.
    unscanned: BTreeSet<String>,
}

/// Scans `sinks`, comparing what exists with what `declared` promises to cover.
fn scan(sinks: &[Sink], declared: &BTreeSet<String>) -> Findings {
    let scanned = sinks
        .iter()
        .map(|sink| sink.name.clone())
        .collect::<BTreeSet<_>>();
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

fn declared(files_present: &[Sink]) -> BTreeSet<String> {
    let mut declared = SERIALIZED_SINKS
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    declared.extend(
        files_present
            .iter()
            .filter(|sink| ALLOWED_FILES.contains(&sink.name.as_str()))
            .map(|sink| sink.name.clone()),
    );
    declared
}

fn serialized_sinks(
    engine: &Engine<RealSourceFs>,
    engine_id: &str,
    report: &quotern_core::domain::PassReport,
    data: &Path,
) -> TestResult<Vec<Sink>> {
    Ok(vec![
        Sink {
            name: "snapshot-json".to_owned(),
            bytes: serde_json::to_vec(&engine.snapshot(engine_id, report)?)?,
        },
        Sink {
            name: "pass-report-json".to_owned(),
            bytes: serde_json::to_vec(report)?,
        },
        Sink {
            name: "observations-json".to_owned(),
            bytes: serde_json::to_vec(&engine.observations_page(engine_id, None, 1_000)?)?,
        },
        Sink {
            name: "history-table-dump".to_owned(),
            bytes: table_dump(data)?,
        },
    ])
}

/// Scans every sink of the current state and asserts a clean, fully inventoried result.
fn assert_clean(
    engine: &Engine<RealSourceFs>,
    engine_id: &str,
    report: &quotern_core::domain::PassReport,
    data: &Path,
) -> TestResult<usize> {
    let mut sinks = file_sinks(data)?;
    let present = declared(&sinks);
    sinks.extend(serialized_sinks(engine, engine_id, report, data)?);
    let findings = scan(&sinks, &present);
    assert_eq!(findings, Findings::default(), "sink inventory");
    assert!(
        data.join("history.sqlite").exists(),
        "the history database is a real sink"
    );
    Ok(sinks.len())
}

fn insert_message(
    connection: &Connection,
    id: &str,
    session: &str,
    time: i64,
    data: &serde_json::Value,
) -> TestResult {
    connection.execute(
        "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![id, session, time, serde_json::to_vec(data)?],
    )?;
    Ok(())
}

fn tokens(input: u64, output: u64, total: u64) -> serde_json::Value {
    serde_json::json!({
        "input": input, "output": output, "reasoning": 0,
        "cache": {"read": 0, "write": 0}, "total": total
    })
}

/// Legacy (with a part group), v2 and JSON (with a part) records, each carrying the sentinel in
/// message and part text, plus `bulk_rows` more legacy rows and `pad_dirs` empty directories
/// below `pads/` that keep the generation open for further passes.
fn build_source(roots: &Roots) -> TestResult {
    build_source_with(roots, BULK_ROWS, 0)
}

fn build_source_with(roots: &Roots, bulk_rows: u64, pad_dirs: u32) -> TestResult {
    let database = roots.source.join("opencode.db");
    let connection = rollback_database(&database)?;
    let fixture: Vec<serde_json::Value> = serde_json::from_slice(include_bytes!(
        "../../../Fixtures/harness/opencode/peer/cases.json"
    ))?;
    let case = fixture
        .iter()
        .find(|case| case["name"] == "explicit_total_wins_mismatch")
        .ok_or("sentinel case missing")?;
    assert_eq!(case["data"]["content"].as_str(), Some(SENTINEL_TEXT));
    insert_message(
        &connection,
        case["message_id"].as_str().ok_or("id")?,
        case["session_id"].as_str().ok_or("session")?,
        case["time_created"].as_i64().ok_or("time")?,
        &case["data"],
    )?;
    insert_message(
        &connection,
        "legacy-group",
        "session-a",
        1_700_000_002_000,
        &serde_json::json!({"role": "assistant", "tokens": tokens(999, 999, 1998), "content": SENTINEL_TEXT}),
    )?;
    for (part, input, output, total) in [("p1", 10, 30, 40), ("p2", 20, 40, 60)] {
        connection.execute(
            "INSERT INTO part(id, message_id, session_id, time_created, data) VALUES (?1, 'legacy-group', 'session-a', 1, ?2)",
            rusqlite::params![
                part,
                serde_json::to_vec(&serde_json::json!({
                    "type": "step-finish", "content": SENTINEL_TEXT,
                    "tokens": tokens(input, output, total)
                }))?
            ],
        )?;
    }
    connection.execute("INSERT INTO session_v2(id) VALUES ('session-v2')", [])?;
    connection.execute(
        "INSERT INTO session_message(id, session_id, type, seq, time_created, data) VALUES ('v2-record', 'session-v2', 'assistant', 1, 1700000004000, ?1)",
        [serde_json::to_vec(&serde_json::json!({"tokens": tokens(5, 10, 15), "content": SENTINEL_TEXT}))?],
    )?;
    let tx = connection.unchecked_transaction()?;
    for index in 0..bulk_rows {
        tx.execute(
            "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, 'bulk', 1700000003000, ?2)",
            rusqlite::params![
                format!("bulk-{index:05}"),
                serde_json::to_vec(&serde_json::json!({
                    "role": "assistant", "tokens": tokens(1, 1, 2), "content": SENTINEL_TEXT
                }))?
            ],
        )?;
    }
    tx.commit()?;
    drop(connection);

    let message = roots
        .source
        .join("storage/message/session-json/json-record.json");
    let part = roots.source.join("storage/part/json-record/p1.json");
    fs::create_dir_all(message.parent().ok_or("message parent")?)?;
    fs::create_dir_all(part.parent().ok_or("part parent")?)?;
    fs::write(
        &message,
        serde_json::to_vec(&serde_json::json!({
            "role": "assistant", "time": {"created": 1_700_000_005_000_i64},
            "tokens": tokens(1, 1, 2), "content": SENTINEL_TEXT
        }))?,
    )?;
    fs::write(
        &part,
        serde_json::to_vec(&serde_json::json!({
            "type": "step-finish", "content": SENTINEL_TEXT, "tokens": tokens(3, 4, 7)
        }))?,
    )?;
    assert!(roots.source.join("storage").exists());
    for index in 0..pad_dirs {
        fs::create_dir_all(roots.source.join(format!("pads/pad-{index:03}")))?;
    }
    Ok(())
}

fn open(roots: &Roots) -> TestResult<(Engine<RealSourceFs>, String)> {
    let mut engine = Engine::open(&roots.data, &roots.home);
    let source_id = engine
        .attach_opencode(RealSourceFs, &roots.source, enabled(), SourceKind::Custom)
        .map_err(|report| format!("open failed: {report:?}"))?;
    Ok((engine, source_id))
}

/// Sentinel text in source records never reaches an application sink in any state: while the
/// spool is active, after injected faults, across reopen, and after completion.
#[test]
fn opencode_reported_text_never_reaches_application_sinks() -> TestResult {
    let roots = Roots::new()?;
    build_source(&roots)?;
    let source_before = file_sinks(&roots.source)?
        .into_iter()
        .map(|sink| (sink.name, sink.bytes))
        .collect::<Vec<_>>();
    assert!(
        source_before
            .iter()
            .any(|(_, bytes)| contains_sentinel(bytes)),
        "the source really carries the sentinel"
    );

    let (mut engine, engine_id) = open(&roots)?;
    let mut scanned = 0;
    let mut now = 1_700_000_100_000_i64;
    let mut step = || {
        now += 1_000;
        now
    };

    let first = engine.pass(&engine_id, enabled(), step());
    assert_eq!(first.outcome, PassOutcome::CatchingUp, "{first:?}");
    assert!(
        count(&roots.data, "opencode_candidate_spool")? > 0,
        "spool is active: {first:?}"
    );
    assert!(count(&roots.data, "metadata_spool")? > 0);
    assert!(count(&roots.data, "frontier_directories")? > 0);
    scanned += assert_clean(&engine, &engine_id, &first, &roots.data)?;

    for point in [FaultPoint::BeforeCommit, FaultPoint::AfterCommit] {
        engine.inject_commit_fault(point);
        let faulted = engine.pass(&engine_id, enabled(), step());
        assert_eq!(
            faulted.outcome,
            PassOutcome::Partial,
            "{point:?}: {faulted:?}"
        );
        scanned += assert_clean(&engine, &engine_id, &faulted, &roots.data)?;
    }

    let before_reopen = acquisition_state(&roots.data)?;
    assert!(before_reopen[0] > 0, "spool still active before the reopen");
    drop(engine);
    let (mut engine, engine_id) = open(&roots)?;
    assert_eq!(acquisition_state(&roots.data)?, before_reopen);
    let mut last = engine.pass(&engine_id, enabled(), step());
    scanned += assert_clean(&engine, &engine_id, &last, &roots.data)?;
    for _ in 0..8 {
        if last.outcome == PassOutcome::Consistent {
            break;
        }
        last = engine.pass(&engine_id, enabled(), step());
        scanned += assert_clean(&engine, &engine_id, &last, &roots.data)?;
    }
    assert_eq!(last.outcome, PassOutcome::Consistent, "{last:?}");
    assert_eq!(count(&roots.data, "opencode_candidate_spool")?, 0);
    assert_eq!(count(&roots.data, "metadata_spool")?, 0);

    let projection = engine.snapshot(&engine_id, &last)?.projection;
    assert_eq!(projection.records, 4 + BULK_ROWS);
    assert_eq!(
        projection.total.value,
        Some(99 + 100 + 15 + 7 + 2 * BULK_ROWS),
        "independent expected totals"
    );
    assert!(projection.total_mismatch);
    assert_eq!(
        projection.origin_uncertainty,
        quotern_core::domain::OriginUncertainty::UnverifiedOrigin
    );
    assert!(
        engine.observations(&engine_id).is_err(),
        "an unbounded read is refused"
    );
    let first_page = engine.observations_page(&engine_id, None, 1_000)?;
    assert_eq!(first_page.observations.len(), 1_000);
    assert!(first_page.next.is_some());
    scanned += assert_clean(&engine, &engine_id, &last, &roots.data)?;

    let source_after = file_sinks(&roots.source)?
        .into_iter()
        .map(|sink| (sink.name, sink.bytes))
        .collect::<Vec<_>>();
    let mut before_sorted = source_before;
    let mut after_sorted = source_after;
    before_sorted.sort();
    after_sorted.sort();
    assert_eq!(after_sorted, before_sorted, "source bytes unchanged");
    assert!(!roots.data.join("opencode.db").exists());
    println!("sentinel sink states scanned: {scanned}");
    Ok(())
}

/// The inventory itself is falsifiable: planted leaks, undeclared sinks and declared-but-unscanned
/// sinks are each rejected with attribution.
#[test]
fn sink_inventory_rejects_extra_and_unscanned_sinks() -> TestResult {
    let roots = Roots::new()?;
    build_source(&roots)?;
    let (mut engine, engine_id) = open(&roots)?;
    let report = engine.pass(&engine_id, enabled(), 1_700_000_100_000);
    let mut sinks = file_sinks(&roots.data)?;
    let declared_sinks = declared(&sinks);
    sinks.extend(serialized_sinks(&engine, &engine_id, &report, &roots.data)?);
    assert_eq!(scan(&sinks, &declared_sinks), Findings::default());

    // A sink holding the sentinel is a leak, and, being undeclared, also an unexpected sink.
    let mut leaking = file_sinks(&roots.data)?;
    leaking.push(Sink {
        name: "file:diagnostics.log".to_owned(),
        bytes: SENTINEL.to_vec(),
    });
    leaking.extend(serialized_sinks(&engine, &engine_id, &report, &roots.data)?);
    let found = scan(&leaking, &declared_sinks);
    assert_eq!(
        found.leaks,
        BTreeSet::from(["file:diagnostics.log".to_owned()])
    );
    assert_eq!(
        found.unexpected,
        BTreeSet::from(["file:diagnostics.log".to_owned()])
    );

    // An undeclared sink without the sentinel is still rejected by the inventory.
    let mut extra = file_sinks(&roots.data)?;
    extra.push(Sink {
        name: "file:spill.tmp".to_owned(),
        bytes: b"clean".to_vec(),
    });
    extra.extend(serialized_sinks(&engine, &engine_id, &report, &roots.data)?);
    let found = scan(&extra, &declared_sinks);
    assert!(found.leaks.is_empty());
    assert_eq!(
        found.unexpected,
        BTreeSet::from(["file:spill.tmp".to_owned()])
    );

    // A declared sink that the scan never reached is rejected.
    let mut partial = file_sinks(&roots.data)?;
    partial.extend(
        serialized_sinks(&engine, &engine_id, &report, &roots.data)?
            .into_iter()
            .filter(|sink| sink.name != "history-table-dump"),
    );
    let found = scan(&partial, &declared_sinks);
    assert_eq!(
        found.unscanned,
        BTreeSet::from(["history-table-dump".to_owned()])
    );
    drop(engine);
    Ok(())
}

fn spool_ranks(data: &Path) -> TestResult<BTreeSet<i64>> {
    let connection = Connection::open_with_flags(
        data.join("history.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let mut statement =
        connection.prepare("SELECT DISTINCT format_rank FROM opencode_candidate_spool")?;
    Ok(statement
        .query_map([], |row| row.get(0))?
        .collect::<Result<BTreeSet<i64>, _>>()?)
}

/// Rows of the three durable acquisition-in-progress tables.
fn acquisition_state(data: &Path) -> TestResult<[i64; 3]> {
    Ok([
        count(data, "opencode_candidate_spool")?,
        count(data, "metadata_spool")?,
        count(data, "frontier_directories")?,
    ])
}

/// Every pass that leaves the generation open (candidate, metadata and frontier rows durable) is
/// scanned across all sinks, again after a fault, and again on a freshly reopened engine that has
/// not yet run a pass; the persisted rows survive each reopen unchanged and the three layouts are
/// each observed in the spool before completion.
#[test]
fn every_layout_stays_clean_in_every_active_spool_state_across_faults_and_reopen() -> TestResult {
    let roots = Roots::new()?;
    build_source_with(&roots, 0, 200)?;
    let (mut engine, mut engine_id) = open(&roots)?;
    let mut ranks = BTreeSet::new();
    let mut active_states = 0;
    let mut reopened_scans = 0;
    let mut sinks_scanned = 0;
    let mut now = 1_700_000_100_000_i64;
    let mut last = None;
    for pass in 0..15 {
        now += 1_000;
        match pass {
            1 => engine.inject_commit_fault(FaultPoint::BeforeCommit),
            2 => engine.inject_commit_fault(FaultPoint::AfterCommit),
            _ => {}
        }
        let report = engine.pass(&engine_id, enabled(), now);
        if report.outcome == PassOutcome::Consistent {
            last = Some(report);
            break;
        }
        let state = acquisition_state(&roots.data)?;
        assert!(
            state.iter().all(|rows| *rows > 0),
            "pass {pass} {:?} leaves an open generation: {state:?}",
            report.outcome
        );
        active_states += 1;
        ranks.extend(spool_ranks(&roots.data)?);
        sinks_scanned += assert_clean(&engine, &engine_id, &report, &roots.data)?;
        drop(engine);
        (engine, engine_id) = open(&roots)?;
        assert_eq!(
            acquisition_state(&roots.data)?,
            state,
            "reopening changed the durable acquisition state"
        );
        sinks_scanned += assert_clean(&engine, &engine_id, &report, &roots.data)?;
        reopened_scans += 1;
    }
    let last = last.ok_or("the sweep never completed")?;
    assert!(active_states >= 4, "{active_states} active-spool states");
    assert_eq!(reopened_scans, active_states);
    assert_eq!(
        ranks,
        BTreeSet::from([0, 1, 2]),
        "legacy 0, v2 1 and JSON 2 were each in the spool"
    );
    assert_eq!(acquisition_state(&roots.data)?[..2], [0, 0]);
    let projection = engine.snapshot(&engine_id, &last)?.projection;
    assert_eq!(projection.records, 4);
    assert_eq!(projection.total.value, Some(99 + 100 + 15 + 7));
    sinks_scanned += assert_clean(&engine, &engine_id, &last, &roots.data)?;
    drop(engine);
    let (reopened, reopened_id) = open(&roots)?;
    sinks_scanned += assert_clean(&reopened, &reopened_id, &last, &roots.data)?;
    assert_eq!(
        reopened
            .snapshot(&reopened_id, &last)?
            .projection
            .total
            .value,
        Some(221)
    );
    assert!(
        sinks_scanned >= 2 * (active_states + 1) * 5,
        "{sinks_scanned}"
    );
    Ok(())
}

/// Real leaks planted while the spool is active are attributed: a sentinel file and an undeclared
/// clean file in the data directory, a sentinel written into an application table, and a declared
/// sink the scan skipped. Each control is rejected for its own reason and the honest state is
/// clean before and after.
#[test]
fn planted_leaks_undeclared_and_skipped_sinks_are_rejected_in_an_active_spool_state() -> TestResult
{
    let roots = Roots::new()?;
    build_source_with(&roots, 0, 200)?;
    let (mut engine, engine_id) = open(&roots)?;
    let report = engine.pass(&engine_id, enabled(), 1_700_000_100_000);
    assert_eq!(report.outcome, PassOutcome::CatchingUp, "{report:?}");
    assert!(count(&roots.data, "opencode_candidate_spool")? > 0);
    assert_clean(&engine, &engine_id, &report, &roots.data)?;
    let declared_sinks = declared(&file_sinks(&roots.data)?);
    let everything = |engine: &Engine<RealSourceFs>, engine_id: &str| -> TestResult<Vec<Sink>> {
        let mut sinks = file_sinks(&roots.data)?;
        sinks.extend(serialized_sinks(engine, engine_id, &report, &roots.data)?);
        Ok(sinks)
    };

    fs::write(roots.data.join("diagnostics.log"), SENTINEL)?;
    fs::create_dir(roots.data.join("tmp"))?;
    fs::write(roots.data.join("tmp/spill.part"), b"clean")?;
    let found = scan(&everything(&engine, &engine_id)?, &declared_sinks);
    assert_eq!(
        found.leaks,
        BTreeSet::from(["file:diagnostics.log".to_owned()])
    );
    assert_eq!(
        found.unexpected,
        BTreeSet::from([
            "file:diagnostics.log".to_owned(),
            "file:tmp/spill.part".to_owned()
        ])
    );
    assert!(found.unscanned.is_empty());
    fs::remove_file(roots.data.join("diagnostics.log"))?;
    fs::remove_dir_all(roots.data.join("tmp"))?;
    assert_eq!(
        scan(&everything(&engine, &engine_id)?, &declared_sinks),
        Findings::default()
    );

    // A sentinel inside an application table is seen by the table dump, not only by file bytes.
    let writer = Connection::open(roots.data.join("history.sqlite"))?;
    writer.execute(
        "UPDATE source_status SET last_error_code = ?1",
        [SENTINEL_TEXT],
    )?;
    drop(writer);
    let found = scan(&everything(&engine, &engine_id)?, &declared_sinks);
    assert!(found.leaks.contains("history-table-dump"), "{found:?}");
    assert!(
        found.unexpected.is_empty() && found.unscanned.is_empty(),
        "{found:?}"
    );

    // A declared file sink that the scan never reached.
    let skipped: Vec<Sink> = everything(&engine, &engine_id)?
        .into_iter()
        .filter(|sink| sink.name != "file:history.sqlite")
        .collect();
    let found = scan(&skipped, &declared_sinks);
    assert_eq!(
        found.unscanned,
        BTreeSet::from(["file:history.sqlite".to_owned()])
    );
    Ok(())
}

/// Sentinel-bearing parent and part records that exist only in a live writer's WAL (never
/// checkpointed into the main file) are read while the writer holds the source open, with the
/// spool active, across a fault, a reopen and completion. Every application sink stays clean.
#[test]
fn live_wal_only_sentinel_records_never_reach_application_sinks() -> TestResult {
    let roots = Roots::new()?;
    let database = roots.source.join("opencode.db");
    drop(rollback_database(&database)?);
    let mut writer = support::start_existing_writer(&database)?;
    let blob = |value: serde_json::Value| -> TestResult<String> {
        Ok(support::sql_blob(&serde_json::to_vec(&value)?))
    };
    writer.exec(&format!(
        "INSERT INTO message(id, session_id, time_created, data) VALUES ('wal-parent', 'sa', 1700000002000, {}); \
         INSERT INTO part(id, message_id, session_id, time_created, data) VALUES ('p1', 'wal-parent', 'sa', 1, {});",
        blob(serde_json::json!({"role": "assistant", "tokens": tokens(999, 999, 1998), "content": SENTINEL_TEXT}))?,
        blob(serde_json::json!({"type": "step-finish", "content": SENTINEL_TEXT, "tokens": tokens(10, 30, 40)}))?
    ))?;
    // The records are in the writer's log and nowhere else.
    let wal = fs::read(roots.source.join("opencode.db-wal"))?;
    assert!(contains_sentinel(&wal), "the sentinel lives in the WAL");
    assert!(
        !contains_sentinel(&fs::read(&database)?),
        "and not in the main file"
    );
    for index in 0..200 {
        fs::create_dir_all(roots.source.join(format!("pads/pad-{index:03}")))?;
    }
    let (mut engine, mut engine_id) = open(&roots)?;
    let mut now = 1_700_000_100_000_i64;
    let mut scanned = 0;
    let mut active = 0;
    let mut last = None;
    for pass in 0..15 {
        now += 1_000;
        if pass == 1 {
            engine.inject_commit_fault(FaultPoint::BeforeCommit);
        }
        let report = engine.pass(&engine_id, enabled(), now);
        if report.outcome == PassOutcome::Consistent {
            last = Some(report);
            break;
        }
        if count(&roots.data, "opencode_candidate_spool")? > 0 {
            active += 1;
        }
        scanned += assert_clean(&engine, &engine_id, &report, &roots.data)?;
        drop(engine);
        (engine, engine_id) = open(&roots)?;
        scanned += assert_clean(&engine, &engine_id, &report, &roots.data)?;
    }
    let last = last.ok_or("the sweep never completed")?;
    assert!(
        active >= 1,
        "an active spool state held the WAL-only candidate"
    );
    let projection = engine.snapshot(&engine_id, &last)?.projection;
    assert_eq!((projection.records, projection.total.value), (1, Some(40)));
    scanned += assert_clean(&engine, &engine_id, &last, &roots.data)?;
    assert!(scanned >= 10, "{scanned}");
    // The live writer was only read: the WAL still holds what the writer put there.
    assert_eq!(fs::read(roots.source.join("opencode.db-wal"))?, wal);
    writer.stop()?;
    Ok(())
}

/// Entry point the live-WAL test re-executes this binary at to play the OpenCode writer.
#[test]
fn sqlite_writer_child_entrypoint() -> TestResult {
    support::writer_child_main()
}
