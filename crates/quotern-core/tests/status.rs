//! Lifecycle status of every snapshot observation, derived by Rust from persisted source state
//! and the request instant: first match wins — value null → unavailable; consent denied →
//! denied; latest unresolved failure → error; backlog → catching_up; 0 ≤ now − last success ≤
//! 600,000 ms → current; otherwise stale. Status never changes value, unit, provenance,
//! completeness or `last_good_ms`.
//!
//! Every expectation here is hand-written from that rule and the daily oracle
//! `Fixtures/harness/opencode/daily/expected.json`; the clock is the injected `now_ms`.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use quotern_core::domain::{ConsentState, PassOutcome, SourceAuthorization, SourceKind};
use quotern_core::ingest::Engine;
use quotern_core::ingest::fs::RealSourceFs;
use rusqlite::Connection;
use serde_json::{Map, Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SCHEMA_SQL: &str = include_str!("../../../Fixtures/harness/opencode/wal/schema.sql");
const ROWS_JSON: &str = include_str!("../../../Fixtures/harness/opencode/daily/rows.json");
const EXPECTED_JSON: &str = include_str!("../../../Fixtures/harness/opencode/daily/expected.json");

/// The last success of every settled source: the `utc_counters` instant.
const S: i64 = 1_775_124_000_000;
const FRESH_MS: i64 = 600_000;
const FIELDS: [&str; 6] = [
    "input",
    "output",
    "reasoning",
    "cache_read",
    "cache_write",
    "total",
];

fn enabled() -> SourceAuthorization {
    SourceAuthorization {
        selected: true,
        consent: ConsentState::Enabled,
    }
}

struct World {
    _directory: tempfile::TempDir,
    base: PathBuf,
}

impl World {
    fn new(rows: &[Value]) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let base = directory.path().canonicalize()?;
        std::fs::create_dir(base.join("source"))?;
        std::fs::create_dir(base.join("home"))?;
        let connection = Connection::open(base.join("source/opencode.db"))?;
        let schema: String = SCHEMA_SQL
            .lines()
            .filter(|line| !line.trim_start().starts_with("PRAGMA"))
            .collect::<Vec<_>>()
            .join("\n");
        connection.execute_batch(&schema)?;
        for row in rows {
            insert(&connection, row)?;
        }
        Ok(Self {
            _directory: directory,
            base,
        })
    }

    fn source(&self) -> PathBuf {
        self.base.join("source")
    }

    fn database(&self) -> TestResult<Connection> {
        Ok(Connection::open(self.source().join("opencode.db"))?)
    }

    fn engine(&self) -> Engine<RealSourceFs> {
        Engine::open(&self.base.join("data"), &self.base.join("home"))
    }

    /// An attached Engine whose one pass at `S` succeeded.
    fn settled(&self) -> TestResult<(Engine<RealSourceFs>, String)> {
        let mut engine = self.engine();
        let id = engine
            .attach_opencode(RealSourceFs, &self.source(), enabled(), SourceKind::Custom)
            .map_err(|report| format!("attach failed: {report:?}"))?;
        let report = engine.pass(&id, enabled(), S);
        assert_eq!(report.outcome, PassOutcome::Consistent, "{report:?}");
        Ok((engine, id))
    }
}

fn insert(connection: &Connection, row: &Value) -> TestResult {
    connection.execute(
        "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            row["id"].as_str().ok_or("id")?,
            row["session_id"].as_str().ok_or("session_id")?,
            row["time_created"].as_i64().ok_or("time_created")?,
            serde_json::to_vec(&row["data"])?
        ],
    )?;
    Ok(())
}

fn daily_rows() -> TestResult<Vec<Value>> {
    let rows: Value = serde_json::from_str(ROWS_JSON)?;
    Ok(rows["legacy_messages"]
        .as_array()
        .ok_or("legacy_messages")?
        .clone())
}

fn row(id: &str) -> TestResult<Value> {
    daily_rows()?
        .into_iter()
        .find(|row| row["id"] == id)
        .ok_or_else(|| format!("row {id}").into())
}

/// A record the adapter rejects: the pass that reads it records `invalid_record` and changes no
/// published number.
fn add_hostile(world: &World) -> TestResult {
    world.database()?.execute(
        "INSERT INTO message(id, session_id, time_created, data) \
         VALUES ('hostile', 'session-day', ?1, '{not json')",
        [S + 5_000],
    )?;
    Ok(())
}

fn remove_hostile(world: &World) -> TestResult {
    let removed = world
        .database()?
        .execute("DELETE FROM message WHERE id = 'hostile'", [])?;
    assert_eq!(removed, 1);
    Ok(())
}

/// The serialized daily snapshot: the wire the bridge returns.
fn snapshot(engine: &Engine<RealSourceFs>, tz: &str, now_ms: i64) -> TestResult<Value> {
    let snapshot = engine
        .today_snapshot(tz, now_ms)
        .map_err(|error| format!("{error:?}"))?;
    Ok(serde_json::to_value(snapshot)?)
}

/// The six observations of the single source at `now_ms` in UTC.
fn observations(engine: &Engine<RealSourceFs>, now_ms: i64) -> TestResult<Map<String, Value>> {
    observations_in(engine, "UTC", now_ms)
}

fn observations_in(
    engine: &Engine<RealSourceFs>,
    tz: &str,
    now_ms: i64,
) -> TestResult<Map<String, Value>> {
    let value = snapshot(engine, tz, now_ms)?;
    let reported = &value["source_reported"];
    assert_eq!(
        reported.as_array().map(Vec::len),
        Some(1),
        "one source: {value}"
    );
    let mut fields = Map::new();
    for field in FIELDS {
        let observation = reported[0][field].as_object().ok_or(field)?;
        let mut keys: Vec<&str> = observation.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "completeness",
                "last_good_ms",
                "provenance",
                "status",
                "unit",
                "value"
            ],
            "{field}: the full observation shape"
        );
        fields.insert(field.to_owned(), reported[0][field].clone());
    }
    Ok(fields)
}

/// Every observation field except the lifecycle status.
fn acquired(observations: &Map<String, Value>) -> Map<String, Value> {
    observations
        .iter()
        .map(|(field, observation)| {
            let mut observation = observation.clone();
            observation
                .as_object_mut()
                .expect("object")
                .remove("status");
            (field.clone(), observation)
        })
        .collect()
}

fn statuses(observations: &Map<String, Value>) -> Vec<(String, Value)> {
    observations
        .iter()
        .map(|(field, observation)| (field.clone(), observation["status"].clone()))
        .collect()
}

fn all(status: &str) -> Vec<(String, Value)> {
    let mut expected: Vec<(String, Value)> = FIELDS
        .iter()
        .map(|field| ((*field).to_owned(), json!(status)))
        .collect();
    expected.sort_by(|left, right| left.0.cmp(&right.0));
    expected
}

/// The hand-written `utc_counters` oracle in the full shape: value, unit and provenance as
/// written; completeness is the oracle's acquired status (current → complete, partial →
/// partial, unavailable → null); `last_good_ms` is the given last success.
fn utc_counters_acquired(last_good_ms: Option<i64>) -> TestResult<Map<String, Value>> {
    let expected: Value = serde_json::from_str(EXPECTED_JSON)?;
    let case = expected["cases"]
        .as_array()
        .ok_or("cases")?
        .iter()
        .find(|case| case["name"] == "utc_counters")
        .ok_or("utc_counters")?;
    let mut fields = Map::new();
    for field in FIELDS {
        let oracle = &case["source_reported"][field];
        let completeness = match oracle["status"].as_str() {
            Some("current") => json!("complete"),
            Some("partial") => json!("partial"),
            Some("unavailable") => Value::Null,
            other => return Err(format!("{field}: oracle status {other:?}").into()),
        };
        fields.insert(
            field.to_owned(),
            json!({
                "value": oracle["value"],
                "unit": oracle["unit"],
                "provenance": oracle["provenance"],
                "completeness": completeness,
                "last_good_ms": last_good_ms,
            }),
        );
    }
    Ok(fields)
}

fn by_source(engine: &Engine<RealSourceFs>, now_ms: i64) -> TestResult<Value> {
    Ok(snapshot(engine, "UTC", now_ms)?["by_source"][0].clone())
}

#[test]
fn same_acquired_value_current_to_stale_at_600001_ms() -> TestResult {
    let world = World::new(&daily_rows()?)?;
    let (engine, _) = world.settled()?;
    let oracle = utc_counters_acquired(Some(S))?;
    for now in [S, S + 1, S + FRESH_MS] {
        let at = observations(&engine, now)?;
        assert_eq!(acquired(&at), oracle, "{now}: acquired fields");
        assert_eq!(statuses(&at), all("current"), "{now}");
    }
    let fresh = observations(&engine, S + FRESH_MS)?;
    let old = observations(&engine, S + FRESH_MS + 1)?;
    assert_eq!(statuses(&old), all("stale"), "600,001 ms after success");
    assert_eq!(acquired(&old), acquired(&fresh), "only the status changed");
    // A clock earlier than the last success is never current.
    let earlier = observations(&engine, S - 1)?;
    assert_eq!(statuses(&earlier), all("stale"), "clock before success");
    assert_eq!(acquired(&earlier), oracle);
    Ok(())
}

#[test]
fn recent_success_with_live_backlog_is_catching_up_not_current() -> TestResult {
    // More rows than one pass reads: the first pass publishes some and stays catching up.
    let bulk: Vec<Value> = (0..5_100)
        .map(|i| {
            json!({"id": format!("m{i}"), "session_id": "s", "time_created": S + i,
            "data": {"role": "assistant", "tokens": {"input": 1, "output": 0, "reasoning": 0,
            "cache": {"read": 0, "write": 0}, "total": 1}}})
        })
        .collect();
    let world = World::new(&bulk)?;
    let mut engine = world.engine();
    let id = engine
        .attach_opencode(RealSourceFs, &world.source(), enabled(), SourceKind::Custom)
        .map_err(|report| format!("{report:?}"))?;
    let first = engine.pass(&id, enabled(), S);
    assert_eq!(first.outcome, PassOutcome::CatchingUp);
    let source = by_source(&engine, S)?;
    assert_eq!(
        (&source["outcome"], &source["last_success_ms"]),
        (&json!("catching_up"), &json!(S)),
        "a fresh success with a live backlog"
    );
    let backlog = observations(&engine, S)?;
    assert_eq!(statuses(&backlog), all("catching_up"), "never current");
    let input = &backlog["input"];
    assert!(
        input["value"]
            .as_u64()
            .is_some_and(|v| (1..5_100).contains(&v))
    );
    assert_eq!(input["last_good_ms"], json!(S));

    // Control: once the backlog drains, the same rule gives current.
    let mut now = S;
    for _ in 0..8 {
        now += 10_000;
        if engine.pass(&id, enabled(), now).outcome == PassOutcome::Consistent {
            break;
        }
    }
    let drained = observations(&engine, now)?;
    assert_eq!(statuses(&drained), all("current"));
    assert_eq!(drained["input"]["value"], json!(5_100));
    assert_eq!(drained["input"]["last_good_ms"], json!(now));
    Ok(())
}

#[test]
fn denied_retains_values() -> TestResult {
    let world = World::new(&daily_rows()?)?;
    let (mut engine, id) = world.settled()?;
    let before = observations(&engine, S)?;
    engine.deny(&id)?;
    let denied = observations(&engine, S)?;
    assert_eq!(by_source(&engine, S)?["consent"], json!("denied"));
    assert_eq!(statuses(&denied), all("denied"), "fresh but denied");
    assert_eq!(acquired(&denied), acquired(&before), "values retained");
    assert_eq!(acquired(&denied), utc_counters_acquired(Some(S))?);
    Ok(())
}

#[test]
fn newer_error_after_success() -> TestResult {
    let world = World::new(&daily_rows()?)?;
    let (mut engine, id) = world.settled()?;
    add_hostile(&world)?;
    let failed = engine.pass(&id, enabled(), S + 1_000);
    assert_eq!(failed.outcome, PassOutcome::Partial, "{failed:?}");
    let source = by_source(&engine, S + 1_000)?;
    assert_eq!(source["last_error_code"], json!("invalid_record"));
    assert_eq!(source["last_success_ms"], json!(S));
    let error = observations(&engine, S + 1_000)?;
    assert_eq!(
        statuses(&error),
        all("error"),
        "fresh success, newer failure"
    );
    assert_eq!(acquired(&error), utc_counters_acquired(Some(S))?);
    Ok(())
}

#[test]
fn attached_failure_is_error_at_equal_or_earlier_attempt_time() -> TestResult {
    for attempt in [S, S - 1] {
        let world = World::new(&daily_rows()?)?;
        let (mut engine, id) = world.settled()?;
        add_hostile(&world)?;
        let failed = engine.pass(&id, enabled(), attempt);
        assert_eq!(
            failed.outcome,
            PassOutcome::Partial,
            "{attempt}: {failed:?}"
        );
        let source = by_source(&engine, S)?;
        assert_eq!(
            (
                &source["last_attempt_ms"],
                &source["last_success_ms"],
                &source["last_error_code"]
            ),
            (&json!(attempt), &json!(S), &json!("invalid_record")),
            "{attempt}: the failed pass is the latest attempt"
        );
        // Comparing attempt and success times would call these current; the outcome order
        // calls them error everywhere inside the freshness span.
        for now in [S, S + 1, S + FRESH_MS] {
            let at = observations(&engine, now)?;
            assert_eq!(statuses(&at), all("error"), "attempt {attempt}, now {now}");
            assert_eq!(acquired(&at), utc_counters_acquired(Some(S))?, "{attempt}");
        }

        // Control: a later successful pass clears the failure.
        remove_hostile(&world)?;
        let later = S + 10_000;
        let report = engine.pass(&id, enabled(), later);
        assert_eq!(report.outcome, PassOutcome::Consistent, "{report:?}");
        let recovered = observations(&engine, later)?;
        assert_eq!(statuses(&recovered), all("current"), "{attempt}: recovery");
        assert_eq!(acquired(&recovered), utc_counters_acquired(Some(later))?);
    }
    Ok(())
}

#[test]
fn unattached_failure_is_error_at_any_attempt_time() -> TestResult {
    // The ingest instant after reopen; None means only open has attempted.
    for attempt in [None, Some(S), Some(S - 1)] {
        let world = World::new(&daily_rows()?)?;
        let (engine, id) = world.settled()?;
        let durable = engine.store().ok_or("store")?.source_rows()?;
        drop(engine);
        let moved = world.base.join("moved");
        std::fs::rename(world.source(), &moved)?;

        let mut engine = world.engine();
        engine.load_existing(&RealSourceFs)?;
        assert!(
            engine.reattach(RealSourceFs, &id, None).is_err(),
            "the root is missing"
        );
        if let Some(now_ms) = attempt {
            engine
                .ingest(|| RealSourceFs, now_ms, &AtomicBool::new(false))
                .map_err(|error| format!("{error:?}"))?;
        }
        let source = by_source(&engine, S)?;
        assert_eq!(
            (
                &source["outcome"],
                &source["last_attempt_ms"],
                &source["last_success_ms"]
            ),
            (&json!("unavailable"), &json!(attempt), &json!(S)),
            "{attempt:?}: the unattached overlay"
        );
        assert!(source["last_error_code"].is_string(), "{source}");
        for now in [S, S + 1, S + FRESH_MS] {
            let at = observations(&engine, now)?;
            assert_eq!(
                statuses(&at),
                all("error"),
                "attempt {attempt:?}, now {now}"
            );
            assert_eq!(
                acquired(&at),
                utc_counters_acquired(Some(S))?,
                "{attempt:?}"
            );
        }
        assert_eq!(
            engine.store().ok_or("store")?.source_rows()?,
            durable,
            "{attempt:?}: the durable status row is unchanged"
        );

        // Control: the original root returns; the next ingest reattaches and passes.
        std::fs::rename(&moved, world.source())?;
        let later = S + 10_000;
        engine
            .ingest(|| RealSourceFs, later, &AtomicBool::new(false))
            .map_err(|error| format!("{error:?}"))?;
        assert!(engine.is_attached(&id));
        let recovered = observations(&engine, later)?;
        assert_eq!(
            statuses(&recovered),
            all("current"),
            "{attempt:?}: recovery"
        );
        assert_eq!(acquired(&recovered), utc_counters_acquired(Some(later))?);
    }
    Ok(())
}

#[test]
fn null_value_unavailable() -> TestResult {
    // One record with input 7 and output 1 only: the other components and the total are null.
    let world = World::new(&[row("null-components")?])?;
    let (mut engine, id) = world.settled()?;
    let at = observations(&engine, S)?;
    for field in ["input", "output"] {
        assert_eq!(at[field]["status"], json!("current"), "{field}");
        assert_eq!(at[field]["completeness"], json!("complete"), "{field}");
        assert_eq!(at[field]["provenance"], json!("reported"), "{field}");
    }
    assert_eq!(
        (&at["input"]["value"], &at["output"]["value"]),
        (&json!(7), &json!(1))
    );
    let null = json!({"value": null, "unit": "tokens", "provenance": null,
        "completeness": null, "status": "unavailable", "last_good_ms": S});
    for field in ["reasoning", "cache_read", "cache_write", "total"] {
        assert_eq!(at[field], null, "{field}: null is unavailable, never 0");
    }

    // Null outranks every other rule: stale, error and denied all leave it unavailable.
    assert_eq!(
        observations(&engine, S + FRESH_MS + 1)?["total"]["status"],
        json!("unavailable")
    );
    add_hostile(&world)?;
    engine.pass(&id, enabled(), S + 1_000);
    let error = observations(&engine, S + 1_000)?;
    assert_eq!(
        (&error["input"]["status"], &error["total"]["status"]),
        (&json!("error"), &json!("unavailable"))
    );
    engine.deny(&id)?;
    let denied = observations(&engine, S + 1_000)?;
    assert_eq!(
        (&denied["input"]["status"], &denied["total"]["status"]),
        (&json!("denied"), &json!("unavailable"))
    );

    // An empty window: every observation null and unavailable.
    let empty = observations(&engine, 1_777_636_800_000)?;
    for field in FIELDS {
        assert_eq!(empty[field]["value"], Value::Null, "{field}");
        assert_eq!(empty[field]["status"], json!("unavailable"), "{field}");
    }
    Ok(())
}

#[test]
fn fresh_partial_completeness_is_current() -> TestResult {
    let world = World::new(&daily_rows()?)?;
    let (engine, _) = world.settled()?;
    let at = observations(&engine, S)?;
    // reasoning, cache_read, cache_write and total are partial in the oracle: missing from some
    // records. Completeness never changes the lifecycle status.
    for field in ["reasoning", "cache_read", "cache_write", "total"] {
        assert_eq!(at[field]["completeness"], json!("partial"), "{field}");
        assert_eq!(at[field]["status"], json!("current"), "{field}");
    }
    assert_eq!(at["input"]["completeness"], json!("complete"));
    Ok(())
}
