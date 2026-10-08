//! The reported daily window: acquired OpenCode records counted by their stored occurrence
//! instant inside a Rust-owned local-day window, against the hand-written
//! `Fixtures/harness/opencode/daily/expected.json`. The source database is built at test time
//! from `Fixtures/harness/opencode/wal/schema.sql` and `daily/rows.json`; no expectation is
//! generated from the implementation.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use quotern_core::domain::{
    ConsentState, FailureCode, PassCounters, PassOutcome, PassReport, SourceAuthorization,
    SourceKind,
};
use quotern_core::ingest::fs::{BoundedRead, DirEntries, RealSourceFs, SourceFs};
use quotern_core::ingest::sqlite_ro::OpenError;
use quotern_core::ingest::{Engine, PassCancelled, TodayError};
use quotern_core::limits::MAX_SOURCE_TIMESTAMP_MS;
use quotern_core::snapshot::{Window, WindowError};
use quotern_core::store::StoreError;
use quotern_core::time::DayBounds;
use rusqlite::Connection;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SCHEMA_SQL: &str = include_str!("../../../Fixtures/harness/opencode/wal/schema.sql");
const ROWS_JSON: &str = include_str!("../../../Fixtures/harness/opencode/daily/rows.json");
const EXPECTED_JSON: &str = include_str!("../../../Fixtures/harness/opencode/daily/expected.json");

fn enabled() -> SourceAuthorization {
    SourceAuthorization {
        selected: true,
        consent: ConsentState::Enabled,
    }
}

fn expected() -> TestResult<Value> {
    Ok(serde_json::from_str(EXPECTED_JSON)?)
}

fn case(expected: &Value, name: &str) -> TestResult<Value> {
    expected["cases"]
        .as_array()
        .and_then(|cases| cases.iter().find(|case| case["name"] == name))
        .cloned()
        .ok_or_else(|| format!("missing oracle case {name}").into())
}

struct World {
    _directory: tempfile::TempDir,
    source: PathBuf,
    data: PathBuf,
    home: PathBuf,
    database: PathBuf,
    /// Rollback-journal connection held for the whole test: no live-WAL sharing is involved.
    connection: Option<Connection>,
}

impl World {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let base = directory.path().canonicalize()?;
        let source = base.join("source");
        let home = base.join("home");
        std::fs::create_dir(&source)?;
        std::fs::create_dir(&home)?;
        let database = source.join("opencode.db");
        let connection = Connection::open(&database)?;
        // The fixture schema minus its journal-mode pragmas: the test holds a rollback database.
        let schema: String = SCHEMA_SQL
            .lines()
            .filter(|line| !line.trim_start().starts_with("PRAGMA"))
            .collect::<Vec<_>>()
            .join("\n");
        connection.execute_batch(&schema)?;
        let rows: Value = serde_json::from_str(ROWS_JSON)?;
        for message in rows["legacy_messages"]
            .as_array()
            .ok_or("legacy_messages")?
        {
            insert_message(
                &connection,
                message["id"].as_str().ok_or("id")?,
                message["session_id"].as_str().ok_or("session_id")?,
                message["time_created"].as_i64().ok_or("time_created")?,
                &message["data"],
            )?;
        }
        Ok(Self {
            data: base.join("data"),
            _directory: directory,
            source,
            home,
            database,
            connection: Some(connection),
        })
    }

    fn connection(&self) -> TestResult<&Connection> {
        self.connection.as_ref().ok_or_else(|| "released".into())
    }

    fn engine(&self) -> TestResult<(Engine<RealSourceFs>, String)> {
        let mut engine = Engine::open(&self.data, &self.home);
        let id = engine
            .attach_opencode(RealSourceFs, &self.source, enabled(), SourceKind::Custom)
            .map_err(|report| format!("attach failed: {report:?}"))?;
        Ok((engine, id))
    }
}

fn insert_message(
    connection: &Connection,
    id: &str,
    session_id: &str,
    time_created: i64,
    data: &Value,
) -> TestResult {
    connection.execute(
        "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![id, session_id, time_created, serde_json::to_vec(data)?],
    )?;
    Ok(())
}

/// Passes until the source is consistent, advancing the injected clock past every backoff.
fn settle<F: SourceFs>(engine: &mut Engine<F>, id: &str, first_ms: i64) -> TestResult<PassReport> {
    let mut last = None;
    for step in 0..8 {
        let report = engine.pass(id, enabled(), first_ms + step * 600_000);
        let done = report.outcome == PassOutcome::Consistent;
        last = Some(report);
        if done {
            break;
        }
    }
    let report = last.ok_or("no pass")?;
    assert_eq!(report.outcome, PassOutcome::Consistent, "{report:?}");
    Ok(report)
}

fn projection_of<F: SourceFs>(engine: &Engine<F>, tz: &str, now_ms: i64) -> TestResult<Value> {
    let snapshot = engine
        .today_snapshot(tz, now_ms)
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(snapshot.source_reported.len(), 1);
    Ok(serde_json::to_value(
        &snapshot.source_reported[0].projection,
    )?)
}

fn records_and_input(projection: &Value) -> (u64, Option<u64>) {
    (
        projection["records"].as_u64().expect("records"),
        projection["input"]["value"].as_u64(),
    )
}

#[test]
fn window_is_local_day_in_request_zone() -> TestResult {
    let expected = expected()?;
    let world = World::new()?;
    let (mut engine, id) = world.engine()?;
    settle(&mut engine, &id, 1)?;
    for name in [
        "utc_counters",
        "riga_spring_23h",
        "riga_fall_25h",
        "kolkata_24h",
        "utc_empty_day",
    ] {
        let case = case(&expected, name)?;
        let (tz, now_ms) = (
            case["tz"].as_str().ok_or("tz")?,
            case["now_ms"].as_i64().ok_or("now")?,
        );
        let snapshot = engine
            .today_snapshot(tz, now_ms)
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(snapshot.window.tz, tz, "{name}: the zone is echoed");
        assert_eq!(
            snapshot.window.start_ms,
            case["window"]["start_ms"].as_i64().ok_or("start")?,
            "{name}"
        );
        assert_eq!(
            snapshot.window.end_ms,
            case["window"]["end_ms"].as_i64().ok_or("end")?,
            "{name}"
        );
        assert_eq!(
            serde_json::to_value(&snapshot.source_reported[0].projection)?,
            case["source_reported"],
            "{name}: the projection equals the hand oracle"
        );
    }
    let hour = 3_600_000_i64;
    let window = |name: &str| -> TestResult<(i64, i64)> {
        let case = case(&expected, name)?;
        Ok((
            case["window"]["start_ms"].as_i64().ok_or("start")?,
            case["window"]["end_ms"].as_i64().ok_or("end")?,
        ))
    };
    let (start, end) = window("riga_spring_23h")?;
    assert_eq!(end - start, 23 * hour);
    let (start, end) = window("riga_fall_25h")?;
    assert_eq!(end - start, 25 * hour);
    let (start, end) = window("kolkata_24h")?;
    assert_eq!(end - start, 24 * hour);
    Ok(())
}

#[test]
fn boundary_records_counted_once_in_their_day() -> TestResult {
    let expected = expected()?;
    let world = World::new()?;
    let (mut engine, id) = world.engine()?;
    settle(&mut engine, &id, 1)?;
    // Each family has records at start-1, start, end-1 and end of one local day. Across the
    // previous, the named and the next day every one of the four is counted exactly once.
    for (name, tz, inputs) in [
        ("riga_spring_23h", "Europe/Riga", [3_u64, 5, 7, 11]),
        ("riga_fall_25h", "Europe/Riga", [13, 17, 19, 23]),
    ] {
        let case = case(&expected, name)?;
        let start = case["window"]["start_ms"].as_i64().ok_or("start")?;
        let end = case["window"]["end_ms"].as_i64().ok_or("end")?;
        let previous = projection_of(&engine, tz, start - 1)?;
        let named = projection_of(&engine, tz, start)?;
        let next = projection_of(&engine, tz, end)?;
        assert_eq!(
            records_and_input(&previous),
            (1, Some(inputs[0])),
            "{name}: start-1 belongs to the previous day"
        );
        assert_eq!(
            records_and_input(&named),
            (2, Some(inputs[1] + inputs[2])),
            "{name}: start and end-1 belong to the named day"
        );
        assert_eq!(
            records_and_input(&next),
            (1, Some(inputs[3])),
            "{name}: end belongs to the next day"
        );
        assert_eq!(named, case["source_reported"], "{name}");
    }
    Ok(())
}

#[test]
fn revision_moves_record_to_revised_day() -> TestResult {
    let expected = expected()?;
    let revision = &expected["revision"];
    let tz = revision["tz"].as_str().ok_or("tz")?;
    let (from_ms, to_ms) = (
        revision["from_ms"].as_i64().ok_or("from")?,
        revision["to_ms"].as_i64().ok_or("to")?,
    );
    let message = &revision["message"];
    let world = World::new()?;
    let input = message["input"].as_u64().ok_or("input")?;
    insert_message(
        world.connection()?,
        message["id"].as_str().ok_or("id")?,
        message["session_id"].as_str().ok_or("session")?,
        from_ms,
        &json!({"role": "assistant", "tokens": {
            "input": input, "output": 0, "reasoning": 0,
            "cache": {"read": 0, "write": 0}, "total": input
        }}),
    )?;
    let (mut engine, id) = world.engine()?;
    settle(&mut engine, &id, 1)?;
    let day = |key: &str| -> TestResult<(i64, Value)> {
        let day = &revision[key];
        Ok((day["now_ms"].as_i64().ok_or("now")?, day.clone()))
    };
    let check = |engine: &Engine<RealSourceFs>, phase: &str| -> TestResult {
        for key in ["day_before", "day_after"] {
            let (now_ms, day) = day(key)?;
            let projection = projection_of(engine, tz, now_ms)?;
            assert_eq!(
                records_and_input(&projection),
                (
                    day[format!("records_{phase}")].as_u64().ok_or("records")?,
                    day[format!("input_{phase}")].as_u64(),
                ),
                "{key} {phase}"
            );
        }
        Ok(())
    };
    check(&engine, "before_revision")?;

    // The record is revised so that its instant crosses local midnight.
    world.connection()?.execute(
        "UPDATE message SET time_created = ?1 WHERE id = ?2",
        rusqlite::params![to_ms, message["id"].as_str().ok_or("id")?],
    )?;
    settle(&mut engine, &id, 10_000_000)?;
    check(&engine, "after_revision")?;
    // Counted once overall: the record is on exactly one of the two days.
    let all = engine.observations(&id)?;
    assert_eq!(all.iter().filter(|r| r.message_id == "moving").count(), 1);
    Ok(())
}

#[test]
fn pending_group_in_window_is_partial() -> TestResult {
    let expected = expected()?;
    let pending = &expected["pending"];
    let utc = case(&expected, pending["case"].as_str().ok_or("case")?)?;
    let world = World::new()?;
    let (mut engine, id) = world.engine()?;
    settle(&mut engine, &id, 1)?;
    let (tz, now_ms) = (
        utc["tz"].as_str().ok_or("tz")?,
        utc["now_ms"].as_i64().ok_or("now")?,
    );
    assert_eq!(projection_of(&engine, tz, now_ms)?, utc["source_reported"]);

    // The source becomes unreadable: retained groups are pending with the failure as reason.
    let World { database, .. } = &world;
    std::fs::write(database, b"overwritten with junk")?;
    let failed = engine.pass(&id, enabled(), 50_000_000);
    assert_eq!(failed.failure, Some(FailureCode::NotSqlite), "{failed:?}");
    let mut want = utc["source_reported"].clone();
    for (field, status) in pending["statuses"].as_object().ok_or("statuses")? {
        want[field]["status"] = status.clone();
    }
    want["pending_partial"] = json!(true);
    assert_eq!(projection_of(&engine, tz, now_ms)?, want);
    let snapshot = engine
        .today_snapshot(tz, now_ms)
        .map_err(|e| format!("{e:?}"))?;
    assert!(snapshot.by_source[0].pending_partial);
    assert_eq!(
        snapshot.by_source[0].last_error_code,
        Some(FailureCode::NotSqlite)
    );
    assert_eq!(
        snapshot.by_source[0]
            .last_error_code
            .map(|code| code.as_str()),
        pending["failure"].as_str()
    );
    Ok(())
}

#[test]
fn empty_window_is_unavailable_not_zero() -> TestResult {
    let expected = expected()?;
    let empty = case(&expected, "utc_empty_day")?;
    let world = World::new()?;
    let (mut engine, id) = world.engine()?;
    settle(&mut engine, &id, 1)?;
    let snapshot = engine
        .today_snapshot(
            empty["tz"].as_str().ok_or("tz")?,
            empty["now_ms"].as_i64().ok_or("now")?,
        )
        .map_err(|e| format!("{e:?}"))?;
    let projection = &snapshot.source_reported[0].projection;
    assert_eq!(projection.records, 0);
    for observation in [
        &projection.input,
        &projection.output,
        &projection.reasoning,
        &projection.cache_read,
        &projection.cache_write,
        &projection.total,
    ] {
        assert_eq!(observation.value, None, "an empty window is never a zero");
        assert_eq!(observation.provenance, None);
    }
    assert_eq!(serde_json::to_value(projection)?, empty["source_reported"]);
    Ok(())
}

#[test]
fn full_span_window_equals_source_projection() -> TestResult {
    let expected = expected()?;
    let world = World::new()?;
    let (mut engine, id) = world.engine()?;
    settle(&mut engine, &id, 1)?;
    let store = engine.store().ok_or("store")?;
    let span = DayBounds {
        start_ms: 0,
        end_ms: MAX_SOURCE_TIMESTAMP_MS + 1,
    };
    let windowed = store.source_window_projection(&id, span)?;
    assert_eq!(windowed, store.source_projection(&id)?);
    assert_eq!(
        windowed.records,
        expected["total_records"].as_u64().ok_or("total")?
    );
    Ok(())
}

#[test]
fn invalid_zone_and_out_of_range_now_rejected() -> TestResult {
    let world = World::new()?;
    let (engine, _id) = world.engine()?;
    for (tz, now_ms, error) in [
        ("Not/AZone", 1_775_124_000_000, WindowError::UnknownZone),
        ("", 1_775_124_000_000, WindowError::UnknownZone),
        ("UTC", -1, WindowError::NowOutOfRange),
        (
            "UTC",
            MAX_SOURCE_TIMESTAMP_MS + 1,
            WindowError::NowOutOfRange,
        ),
        ("UTC", i64::MIN, WindowError::NowOutOfRange),
        ("UTC", i64::MAX, WindowError::NowOutOfRange),
    ] {
        assert_eq!(
            engine.today_snapshot(tz, now_ms).err(),
            Some(TodayError::Window(error)),
            "{tz:?} {now_ms}"
        );
    }
    // The very last local days before year 10000 have a next midnight the calendar library
    // cannot represent: rejected as an out-of-range instant, never an invented window.
    assert_eq!(
        engine.today_snapshot("UTC", MAX_SOURCE_TIMESTAMP_MS).err(),
        Some(TodayError::Window(WindowError::NowOutOfRange))
    );
    for now_ms in [0, 4_102_444_800_000] {
        assert!(engine.today_snapshot("UTC", now_ms).is_ok(), "{now_ms}");
    }
    validation_cases_equal_the_shared_oracle()
}

/// One hand-written `validation_cases` row of the daily oracle.
struct ValidationCase {
    name: String,
    tz: String,
    now_ms: i64,
    /// `Ok((start_ms, end_ms))` or the request field the rejection names.
    outcome: Result<(i64, i64), String>,
}

fn validation_cases() -> TestResult<Vec<ValidationCase>> {
    let expected = expected()?;
    expected["validation_cases"]
        .as_array()
        .ok_or("validation_cases")?
        .iter()
        .map(|row| {
            let outcome = match row.get("window") {
                Some(window) => Ok((
                    window["start_ms"].as_i64().ok_or("start_ms")?,
                    window["end_ms"].as_i64().ok_or("end_ms")?,
                )),
                None => Err(row["error"]["field"]
                    .as_str()
                    .ok_or("error.field")?
                    .to_owned()),
            };
            Ok(ValidationCase {
                name: row["name"].as_str().ok_or("name")?.to_owned(),
                tz: row["tz"].as_str().ok_or("tz")?.to_owned(),
                now_ms: row["now_ms"].as_i64().ok_or("now_ms")?,
                outcome,
            })
        })
        .collect()
}

/// The field a refusal names: only an unknown zone is `tz`, every other refusal is `now_ms`.
fn field_of(error: WindowError) -> &'static str {
    match error {
        WindowError::UnknownZone => "tz",
        WindowError::NowOutOfRange => "now_ms",
    }
}

/// The shared `validation_cases` against the canonical window function and the Engine.
fn validation_cases_equal_the_shared_oracle() -> TestResult {
    let cases = validation_cases()?;
    assert!(
        cases.iter().any(|case| case.outcome.is_ok()),
        "positive rows are present"
    );
    assert!(
        cases.iter().any(|case| case.outcome.is_err()),
        "rejected rows are present"
    );
    // Names of the rows the canonical window function disagrees with.
    let disagreements: Vec<&str> = cases
        .iter()
        .filter(|case| {
            let actual = Window::local_day(case.now_ms, &case.tz)
                .map(|found| (found.start_ms, found.end_ms))
                .map_err(|error| field_of(error).to_owned());
            actual != case.outcome
        })
        .map(|case| case.name.as_str())
        .collect();
    assert_eq!(disagreements, Vec::<&str>::new());

    // The engine reports the same outcome with and without a store, and a window carries its zone.
    // The acquired engine is settled and its nonempty daily oracle asserted before the rows run.
    let expected = expected()?;
    let utc = case(&expected, "utc_counters")?;
    let world = World::new()?;
    let (mut attached, id) = world.engine()?;
    settle(&mut attached, &id, 1)?;
    let acquired = projection_of(
        &attached,
        utc["tz"].as_str().ok_or("tz")?,
        utc["now_ms"].as_i64().ok_or("now")?,
    )?;
    assert_ne!(
        acquired["records"],
        json!(0),
        "the acquired oracle is nonempty"
    );
    assert_eq!(acquired, utc["source_reported"]);
    let bare: Engine<RealSourceFs> = Engine::open(&world.data.join("elsewhere"), &world.home);
    for engine in [&attached, &bare] {
        for case in &cases {
            let found = engine
                .today_snapshot(&case.tz, case.now_ms)
                .map(|snapshot| snapshot.window);
            match (&case.outcome, found) {
                (Ok((start_ms, end_ms)), Ok(window)) => {
                    assert_eq!(
                        (window.start_ms, window.end_ms, window.tz.as_str()),
                        (*start_ms, *end_ms, case.tz.as_str()),
                        "{}",
                        case.name
                    );
                }
                (Err(field), Err(TodayError::Window(error))) => {
                    assert_eq!(field_of(error), field, "{}", case.name)
                }
                (outcome, found) => panic!("{}: expected {outcome:?}, found {found:?}", case.name),
            }
        }
    }
    Ok(())
}

#[test]
fn durable_unattached_reads_history_unknown_id_rejected() -> TestResult {
    let world = World::new()?;
    let (mut attached, id) = world.engine()?;
    let report = settle(&mut attached, &id, 1)?;
    let whole = attached.snapshot(&id, &report)?;
    let observations = attached.observations(&id)?;
    assert_eq!(observations.len(), 12);
    drop(attached);

    // A new Engine over the same history: the id has a durable row but no runtime.
    let mut unattached: Engine<RealSourceFs> = Engine::open(&world.data, &world.home);
    unattached.load_existing(&RealSourceFs)?;
    assert!(!unattached.is_attached(&id));
    assert_eq!(unattached.snapshot(&id, &report)?, whole);
    assert_eq!(unattached.observations(&id)?, observations);
    assert_eq!(
        unattached.observations_page(&id, None, 1_000)?.observations,
        observations
    );
    let entries = unattached.source_entries()?;
    assert_eq!(
        (entries.len(), entries[0].source_id.as_str()),
        (1, id.as_str())
    );
    assert_eq!(entries[0].consent, ConsentState::Enabled);

    let unknown = "0".repeat(32);
    assert_eq!(
        unattached.observations(&unknown),
        Err(StoreError::InvalidRoot)
    );
    assert_eq!(
        unattached.observations_page(&unknown, None, 10).err(),
        Some(StoreError::InvalidRoot)
    );
    assert_eq!(
        unattached.snapshot(&unknown, &report).err(),
        Some(StoreError::InvalidRoot)
    );
    // An Engine without any store knows no id at all.
    let bare: Engine<RealSourceFs> = Engine::open(&world.data.join("elsewhere"), &world.home);
    assert_eq!(bare.observations(&id), Err(StoreError::InvalidRoot));
    Ok(())
}

#[test]
fn midnight_gap_adjacent_days_count_record_once() -> TestResult {
    let expected = expected()?;
    let gap = &expected["midnight_gap"];
    let tz = gap["tz"].as_str().ok_or("tz")?;
    let message = &gap["message"];
    let world = World::new()?;
    let (mut engine, id) = world.engine()?;
    settle(&mut engine, &id, 1)?;
    let input = message["input"].as_u64().ok_or("input")?;
    insert_message(
        world.connection()?,
        message["id"].as_str().ok_or("id")?,
        message["session_id"].as_str().ok_or("session")?,
        message["time_created"].as_i64().ok_or("time_created")?,
        &json!({"role": "assistant", "tokens": {
            "input": input, "output": 0, "reasoning": 0,
            "cache": {"read": 0, "write": 0}, "total": input
        }}),
    )?;
    settle(&mut engine, &id, 10_000_000)?;
    for key in ["gap_day", "following_day"] {
        let day = &gap[key];
        let snapshot = engine
            .today_snapshot(tz, day["now_ms"].as_i64().ok_or("now")?)
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(
            (snapshot.window.start_ms, snapshot.window.end_ms),
            (
                day["window"]["start_ms"].as_i64().ok_or("start")?,
                day["window"]["end_ms"].as_i64().ok_or("end")?,
            ),
            "{key}: window"
        );
        let projection = serde_json::to_value(&snapshot.source_reported[0].projection)?;
        assert_eq!(
            records_and_input(&projection),
            (
                day["records"].as_u64().ok_or("records")?,
                day["input"].as_u64()
            ),
            "{key}: the 00:30 record belongs to the following day only"
        );
    }
    Ok(())
}

#[test]
fn window_sum_overflow_is_store_error() -> TestResult {
    let expected = expected()?;
    let utc = case(&expected, "utc_counters")?;
    let (tz, now_ms) = (
        utc["tz"].as_str().ok_or("tz")?,
        utc["now_ms"].as_i64().ok_or("now")?,
    );
    let world = World::new()?;
    {
        let (mut engine, id) = world.engine()?;
        settle(&mut engine, &id, 1)?;
        assert_eq!(projection_of(&engine, tz, now_ms)?, utc["source_reported"]);
    }
    // A declared trust-boundary fault, not valid acquired history: two in-window input values
    // whose sum exceeds i64, written by outside SQL with no handle live.
    let history = world.data.join("history.sqlite");
    let read_input = |connection: &Connection, message: &str| -> TestResult<i64> {
        Ok(connection.query_row(
            "SELECT input_tokens FROM usage_events WHERE message_id = ?1",
            [message],
            |row| row.get(0),
        )?)
    };
    let set_input = |message: &str, value: i64| -> TestResult {
        let outside = Connection::open(&history)?;
        let changed = outside.execute(
            "UPDATE usage_events SET input_tokens = ?2 WHERE message_id = ?1",
            rusqlite::params![message, value],
        )?;
        assert_eq!(changed, 1, "{message}");
        Ok(())
    };
    let (derived, explicit) = {
        let outside = Connection::open(&history)?;
        (
            read_input(&outside, "derived")?,
            read_input(&outside, "explicit")?,
        )
    };
    set_input("derived", i64::MAX)?;
    set_input("explicit", 1)?;
    {
        let (engine, _id) = world.engine()?;
        let refused = engine.today_snapshot(tz, now_ms);
        assert!(
            matches!(refused, Err(TodayError::Store(StoreError::Sqlite))),
            "never a window or wrapped values: {refused:?}"
        );
    }
    set_input("derived", derived)?;
    set_input("explicit", explicit)?;
    let (engine, _id) = world.engine()?;
    assert_eq!(projection_of(&engine, tz, now_ms)?, utc["source_reported"]);
    Ok(())
}

/// Where the cancel flag is set while a JSON pass runs.
#[derive(Clone, Copy, Debug)]
enum CancelAt {
    /// The first part read of the second message whose parts are read.
    SecondGroupFirstPartRead,
    /// The revalidation metadata call of that message's last part.
    SecondGroupLastPartRevalidation,
}

#[derive(Default)]
struct CancelProbe {
    /// Part directories in the order their first part was read.
    part_directories: Vec<PathBuf>,
    /// Parts read under the second part directory.
    second_group_reads: Vec<PathBuf>,
    fired: bool,
}

/// `RealSourceFs` that sets the cancel flag once, at the point a run names.
struct CancellingFs {
    at: CancelAt,
    flag: Arc<AtomicBool>,
    probe: Rc<RefCell<CancelProbe>>,
}

impl CancellingFs {
    fn fire(&self, probe: &mut CancelProbe) {
        if !probe.fired {
            probe.fired = true;
            self.flag.store(true, Ordering::Release);
        }
    }
}

fn is_part(path: &Path) -> bool {
    path.parent()
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .is_some_and(|name| name == "part")
}

impl SourceFs for CancellingFs {
    fn canonicalize(&self, path: &Path, counters: &mut PassCounters) -> std::io::Result<PathBuf> {
        RealSourceFs.canonicalize(path, counters)
    }

    fn metadata(
        &self,
        path: &Path,
        counters: &mut PassCounters,
    ) -> std::io::Result<std::fs::Metadata> {
        let mut probe = self.probe.borrow_mut();
        if matches!(self.at, CancelAt::SecondGroupLastPartRevalidation)
            && probe.second_group_reads.len() == 2
            && probe.second_group_reads.last().map(PathBuf::as_path) == Some(path)
        {
            self.fire(&mut probe);
        }
        drop(probe);
        RealSourceFs.metadata(path, counters)
    }

    fn read_dir(&self, path: &Path, counters: &mut PassCounters) -> std::io::Result<DirEntries> {
        RealSourceFs.read_dir(path, counters)
    }

    fn read_header(&self, path: &Path, counters: &mut PassCounters) -> std::io::Result<Vec<u8>> {
        RealSourceFs.read_header(path, counters)
    }

    fn read_bounded(
        &self,
        path: &Path,
        max_bytes: usize,
        counters: &mut PassCounters,
    ) -> std::io::Result<BoundedRead> {
        let read = RealSourceFs.read_bounded(path, max_bytes, counters);
        if is_part(path) {
            let mut probe = self.probe.borrow_mut();
            let directory = path.parent().ok_or("parent").map(Path::to_path_buf);
            if let Ok(directory) = directory {
                if !probe.part_directories.contains(&directory) {
                    probe.part_directories.push(directory.clone());
                    if probe.part_directories.len() == 2
                        && matches!(self.at, CancelAt::SecondGroupFirstPartRead)
                    {
                        self.fire(&mut probe);
                    }
                }
                if probe.part_directories.get(1) == Some(&directory) {
                    probe.second_group_reads.push(path.to_path_buf());
                }
            }
        }
        read
    }

    fn open_sqlite(&self, canonical_path: &Path) -> Result<Connection, OpenError> {
        RealSourceFs.open_sqlite(canonical_path)
    }
}

#[test]
fn cancel_during_json_part_scan_publishes_whole_groups() -> TestResult {
    let expected = expected()?;
    let oracle = &expected["json_part_scan"];
    let rows: Value = serde_json::from_str(ROWS_JSON)?;
    for at in [
        CancelAt::SecondGroupFirstPartRead,
        CancelAt::SecondGroupLastPartRevalidation,
    ] {
        let directory = tempfile::tempdir()?;
        let base = directory.path().canonicalize()?;
        let (source, data, home) = (base.join("source"), base.join("data"), base.join("home"));
        std::fs::create_dir(&home)?;
        for message in rows["json_messages"].as_array().ok_or("json_messages")? {
            let id = message["id"].as_str().ok_or("id")?;
            let session = message["session_id"].as_str().ok_or("session_id")?;
            let path = source.join(format!("storage/message/{session}/{id}.json"));
            std::fs::create_dir_all(path.parent().ok_or("parent")?)?;
            std::fs::write(path, serde_json::to_vec(&message["data"])?)?;
            for part in message["parts"].as_array().ok_or("parts")? {
                let part_id = part["id"].as_str().ok_or("part id")?;
                let path = source.join(format!("storage/part/{id}/{part_id}.json"));
                std::fs::create_dir_all(path.parent().ok_or("parent")?)?;
                std::fs::write(path, serde_json::to_vec(&part["data"])?)?;
            }
        }
        let flag = Arc::new(AtomicBool::new(false));
        let probe = Rc::new(RefCell::new(CancelProbe::default()));
        let fs = CancellingFs {
            at,
            flag: Arc::clone(&flag),
            probe: Rc::clone(&probe),
        };
        let mut engine = Engine::open(&data, &home);
        let id = engine
            .attach_opencode(fs, &source, enabled(), SourceKind::Custom)
            .map_err(|report| format!("{at:?}: attach failed: {report:?}"))?;
        let cancelled = engine.pass_until(&id, enabled(), 1, &flag);
        assert!(
            matches!(cancelled, Err(PassCancelled(_))),
            "{at:?}: {cancelled:?}"
        );
        assert!(
            probe.borrow().fired,
            "{at:?}: the trigger point was reached"
        );
        // The second message has two parts: a cancel at its first part read stops before the
        // second is read; a cancel at the last part's revalidation follows both reads.
        let reads = match at {
            CancelAt::SecondGroupFirstPartRead => 1,
            CancelAt::SecondGroupLastPartRevalidation => 2,
        };
        assert_eq!(
            probe.borrow().second_group_reads.len(),
            reads,
            "{at:?}: parts read in the interrupted group"
        );
        let first = probe
            .borrow()
            .part_directories
            .first()
            .and_then(|directory| directory.file_name())
            .and_then(|name| name.to_str())
            .map(str::to_owned)
            .ok_or("first-processed message")?;
        // Only the first-processed message's whole group is published.
        let published = engine.observations(&id)?;
        assert_eq!(
            published
                .iter()
                .map(|record| (record.message_id.as_str(), record.input.value))
                .collect::<Vec<_>>(),
            vec![(first.as_str(), oracle["inputs"][&first].as_u64())],
            "{at:?}: the interrupted group is absent"
        );

        flag.store(false, Ordering::Release);
        settle(&mut engine, &id, 10_000_000)?;
        let tz = oracle["tz"].as_str().ok_or("tz")?;
        let now_ms = oracle["now_ms"].as_i64().ok_or("now")?;
        let converged = projection_of(&engine, tz, now_ms)?;
        assert_eq!(
            records_and_input(&converged),
            (
                oracle["records"].as_u64().ok_or("records")?,
                oracle["input"].as_u64()
            ),
            "{at:?}: convergence"
        );
        // Replay adds 0: another pass leaves the converged projection unchanged.
        settle(&mut engine, &id, 20_000_000)?;
        assert_eq!(projection_of(&engine, tz, now_ms)?, converged, "{at:?}");
    }
    Ok(())
}

#[test]
fn cancel_during_sqlite_sweep_publishes_whole_groups() -> TestResult {
    let expected = expected()?;
    let rows: Value = serde_json::from_str(ROWS_JSON)?;
    let first = &rows["legacy_messages"][0];
    let world = World::new()?;
    let (mut engine, id) = world.engine()?;
    let flag = Arc::new(AtomicBool::new(false));
    let trigger = Arc::clone(&flag);
    quotern_core::adapters::opencode::set_transaction_hook(Some(Box::new(move || {
        trigger.store(true, Ordering::Release)
    })));
    let cancelled = engine.pass_until(&id, enabled(), 1, &flag);
    quotern_core::adapters::opencode::set_transaction_hook(None);
    assert!(matches!(cancelled, Err(PassCancelled(_))), "{cancelled:?}");
    // The flag was set after the first whole group: exactly that group is published.
    let published = engine.observations(&id)?;
    assert_eq!(
        published
            .iter()
            .map(|record| (record.message_id.as_str(), record.input.value))
            .collect::<Vec<_>>(),
        vec![(
            first["id"].as_str().ok_or("id")?,
            first["data"]["tokens"]["input"].as_u64()
        )]
    );
    flag.store(false, Ordering::Release);
    settle(&mut engine, &id, 10_000_000)?;
    let converged = engine.observations(&id)?;
    assert_eq!(
        converged.len() as u64,
        expected["total_records"].as_u64().ok_or("total")?
    );
    // Replay adds 0: another pass leaves every record unchanged.
    settle(&mut engine, &id, 20_000_000)?;
    assert_eq!(engine.observations(&id)?, converged);
    Ok(())
}
