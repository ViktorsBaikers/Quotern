mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use quotern_core::domain::{
    ConsentState, FailureCode, PassOutcome, PassReport, SourceAuthorization, SourceKind,
};
use quotern_core::ingest::OpenCodeEngine;
use quotern_core::ingest::fs::{OpenKind, RecordingFs};
use quotern_core::limits::{
    MAX_DIRECTORY_ENTRIES, MAX_DIRECTORY_OPENS, MAX_HEADER_READS, MAX_METADATA_CALLS,
    MAX_SOURCE_BYTES_PER_PASS, MAX_SQLITE_ROWS_PER_PASS,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use support::{TestResult, WriterChild, rollback_database, start_existing_writer, start_writer};
use tempfile::TempDir;

struct Roots {
    _directory: TempDir,
    source: PathBuf,
    data: PathBuf,
    home: PathBuf,
}

impl Roots {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("source");
        let data = directory.path().join("data");
        let home = directory.path().join("home");
        fs::create_dir(&source)?;
        fs::create_dir(&home)?;
        Ok(Self {
            _directory: directory,
            source,
            data,
            home,
        })
    }

    fn open(
        &self,
        fs: RecordingFs,
        authorization: SourceAuthorization,
    ) -> Result<OpenCodeEngine<RecordingFs>, PassReport> {
        OpenCodeEngine::open(
            fs,
            &self.source,
            &self.data,
            &self.home,
            authorization,
            SourceKind::Custom,
        )
    }
}

fn enabled() -> SourceAuthorization {
    SourceAuthorization {
        selected: true,
        consent: ConsentState::Enabled,
    }
}

fn assert_bounded(report: &PassReport) {
    assert!(report.counters.entries <= MAX_DIRECTORY_ENTRIES);
    assert!(report.counters.stat_calls <= MAX_METADATA_CALLS);
    assert!(report.counters.header_reads <= MAX_HEADER_READS);
    assert!(report.counters.directory_opens <= MAX_DIRECTORY_OPENS);
    assert!(report.counters.rows_read <= MAX_SQLITE_ROWS_PER_PASS);
    assert!(report.counters.bytes_read <= MAX_SOURCE_BYTES_PER_PASS);
}

/// Live OpenCode database: complete schema, optional v2 rows, held open in WAL mode by a
/// separate process. Returns the holder so the sidecars stay alive for the test.
fn live_database(path: &std::path::Path, rows: &[&str]) -> TestResult<WriterChild> {
    let connection = rollback_database(path)?;
    for sql in rows {
        connection.execute_batch(sql)?;
    }
    drop(connection);
    start_existing_writer(path)
}

#[test]
fn sqlite_writer_child_entrypoint() -> TestResult {
    support::writer_child_main()
}

#[test]
fn denied_and_unselected_sources_are_never_opened() -> TestResult {
    let roots = Roots::new()?;
    fs::write(roots.source.join("opencode-invalid.db"), b"not a database")?;

    for (authorization, expected) in [
        (
            SourceAuthorization {
                selected: false,
                consent: ConsentState::Enabled,
            },
            FailureCode::Unselected,
        ),
        (
            SourceAuthorization {
                selected: true,
                consent: ConsentState::Denied,
            },
            FailureCode::Denied,
        ),
    ] {
        let fs = RecordingFs::new();
        let observed = fs.clone();
        let report = match roots.open(fs, authorization) {
            Err(report) => report,
            Ok(_) => panic!("unauthorized source unexpectedly opened"),
        };
        assert_eq!(report.outcome, PassOutcome::Unavailable);
        assert_eq!(report.failure, Some(expected));
        assert_eq!(report.counters, Default::default());
        let metrics = observed.metrics();
        assert_eq!(metrics.header_reads, 0);
        assert_eq!(metrics.bounded_reads, 0);
        assert_eq!(metrics.directory_opens, 0);
        assert_eq!(metrics.sqlite_opens, 0);
        assert!(!roots.data.exists());
    }
    Ok(())
}

#[test]
fn root_containment_rejects_equality_and_both_ancestor_directions() -> TestResult {
    for direction in ["equal", "data-inside-source", "source-inside-data"] {
        let mut roots = Roots::new()?;
        match direction {
            "equal" => roots.data = roots.source.clone(),
            "data-inside-source" => {
                roots.data = roots.source.join("data");
                fs::create_dir(&roots.data)?;
            }
            "source-inside-data" => {
                roots.data = roots._directory.path().join("shared-data");
                roots.source = roots.data.join("source");
                fs::create_dir(&roots.data)?;
                fs::create_dir(&roots.source)?;
            }
            _ => unreachable!(),
        }
        let fs = RecordingFs::new();
        let observed = fs.clone();
        let report = match OpenCodeEngine::open(
            fs,
            &roots.source,
            &roots.data,
            &roots.home,
            enabled(),
            SourceKind::Custom,
        ) {
            Err(report) => report,
            Ok(_) => panic!("overlapping source and data roots were accepted: {direction}"),
        };
        assert_eq!(
            report.failure,
            Some(FailureCode::RootOverlap),
            "{direction}"
        );
        let metrics = observed.metrics();
        assert_eq!(metrics.header_reads, 0, "{direction}");
        assert_eq!(metrics.bounded_reads, 0, "{direction}");
        assert_eq!(metrics.directory_opens, 0, "{direction}");
        assert_eq!(metrics.sqlite_opens, 0, "{direction}");
    }
    Ok(())
}

#[test]
fn rejected_and_unchanged_passes_keep_bounded_counters() -> TestResult {
    let roots = Roots::new()?;
    fs::write(roots.source.join("opencode-not-sqlite.db"), b"not sqlite")?;
    let mut engine = roots
        .open(RecordingFs::new(), enabled())
        .map_err(|report| format!("open failed: {report:?}"))?;

    for now_ms in [1, 2] {
        let report = engine.pass(enabled(), now_ms);
        assert_eq!(report.outcome, PassOutcome::Unavailable);
        assert_eq!(report.failure, Some(FailureCode::NotSqlite));
        assert_eq!(report.counters.header_reads, 1);
        assert!(report.counters.source_opens > 0);
        assert_bounded(&report);
    }
    Ok(())
}

#[test]
fn cap_and_restart_passes_keep_frontier_counters_bounded() -> TestResult {
    let roots = Roots::new()?;
    let _writer = live_database(&roots.source.join("opencode.db"), &[])?;
    for index in 0..(MAX_DIRECTORY_OPENS as usize + 6) {
        fs::create_dir(roots.source.join(format!("directory-{index:03}")))?;
    }

    let mut engine = roots
        .open(RecordingFs::new(), enabled())
        .map_err(|report| format!("open failed: {report:?}"))?;
    let first = engine.pass(enabled(), 10);
    assert_eq!(first.outcome, PassOutcome::CatchingUp);
    assert_bounded(&first);
    assert_eq!(first.counters.directory_opens, MAX_DIRECTORY_OPENS);
    drop(engine);

    engine = roots
        .open(RecordingFs::new(), enabled())
        .map_err(|report| format!("reopen failed: {report:?}"))?;
    let restarted = engine.pass(enabled(), 20);
    assert_eq!(restarted.outcome, PassOutcome::Consistent, "{restarted:?}");
    assert!(restarted.counters.entries > 0);
    assert_bounded(&restarted);

    let unchanged = engine.pass(enabled(), 30);
    assert_eq!(unchanged.outcome, PassOutcome::CatchingUp, "{unchanged:?}");
    assert_eq!(unchanged.counters.directory_opens, MAX_DIRECTORY_OPENS);
    assert_bounded(&unchanged);
    Ok(())
}

#[test]
fn unchanged_small_source_pass_is_consistent() -> TestResult {
    let roots = Roots::new()?;
    let _writer = live_database(&roots.source.join("opencode.db"), &[])?;
    let mut engine = roots
        .open(RecordingFs::new(), enabled())
        .map_err(|report| format!("open failed: {report:?}"))?;

    for now_ms in [10, 20] {
        let report = engine.pass(enabled(), now_ms);
        assert_eq!(report.outcome, PassOutcome::Consistent);
        assert_bounded(&report);
    }
    Ok(())
}

#[test]
fn over_budget_directory_restart_is_partial_and_keeps_history() -> TestResult {
    let roots = Roots::new()?;
    let _writer = live_database(
        &roots.source.join("opencode.db"),
        &["INSERT INTO session_v2(id) VALUES ('session'); \
           INSERT INTO session_message(id, session_id, type, seq, time_created, data) \
           VALUES ('message', 'session', 'assistant', 1, 1700000000000, \
           '{\"tokens\":{\"input\":10,\"output\":20,\"reasoning\":3,\"cache\":{\"read\":4,\"write\":5}}}')"],
    )?;
    let mut engine = roots
        .open(RecordingFs::new(), enabled())
        .map_err(|report| format!("open failed: {report:?}"))?;
    let initial = engine.pass(enabled(), 1);
    assert_eq!(initial.outcome, PassOutcome::Consistent);
    assert_eq!(engine.observations()?[0].total.value, Some(42));

    let crowded = roots.source.join("crowded");
    fs::create_dir(&crowded)?;
    for index in 0..(MAX_DIRECTORY_ENTRIES as usize + 2) {
        fs::write(crowded.join(format!("entry-{index:05}")), [])?;
    }
    assert!(fs::metadata(&crowded)?.is_dir());
    assert_eq!(
        fs::read_dir(&crowded)?.count(),
        MAX_DIRECTORY_ENTRIES as usize + 2
    );
    let source_entries = fs::read_dir(&roots.source)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    assert!(
        source_entries
            .iter()
            .any(|name| name.to_str() == Some("crowded"))
    );
    assert!(
        source_entries
            .iter()
            .any(|name| name.to_str() == Some("opencode.db"))
    );
    let capped = engine.pass(enabled(), 2);
    assert_eq!(capped.outcome, PassOutcome::CatchingUp);
    assert_eq!(capped.counters.entries, MAX_DIRECTORY_ENTRIES);
    assert_bounded(&capped);
    assert_eq!(engine.observations()?[0].total.value, Some(42));

    let drained = engine.pass(enabled(), 3);
    assert_eq!(drained.outcome, PassOutcome::Consistent, "{drained:?}");
    assert!(drained.counters.entries < MAX_DIRECTORY_ENTRIES);
    assert_bounded(&drained);
    assert_eq!(engine.observations()?[0].total.value, Some(42));

    let capped_again = engine.pass(enabled(), 4);
    assert_eq!(capped_again.outcome, PassOutcome::CatchingUp);
    assert_eq!(capped_again.counters.entries, MAX_DIRECTORY_ENTRIES);
    assert_bounded(&capped_again);
    drop(engine);

    let mut reopened = roots
        .open(RecordingFs::new(), enabled())
        .map_err(|report| format!("reopen failed: {report:?}"))?;
    let restart = reopened.pass(enabled(), 5);
    assert_eq!(restart.outcome, PassOutcome::Partial, "{restart:?}");
    assert_eq!(restart.failure, Some(FailureCode::LimitExceeded));
    assert_eq!(restart.records_committed, 0);
    assert_eq!(restart.last_good_ms, Some(4));
    assert_eq!(restart.counters.entries, 0);
    assert_bounded(&restart);
    assert_eq!(reopened.observations()?[0].total.value, Some(42));

    let resumed = reopened.pass(enabled(), 6);
    assert_eq!(resumed.outcome, PassOutcome::CatchingUp);
    assert_eq!(resumed.counters.entries, MAX_DIRECTORY_ENTRIES);
    assert_bounded(&resumed);
    let final_pass = reopened.pass(enabled(), 7);
    assert_eq!(
        final_pass.outcome,
        PassOutcome::Consistent,
        "{final_pass:?}"
    );
    assert!(final_pass.counters.entries < MAX_DIRECTORY_ENTRIES);
    assert_bounded(&final_pass);
    assert_eq!(reopened.observations()?[0].total.value, Some(42));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Independent accounting oracles. Normative ceilings are written as literals (20,000 entries,
// 40,000 metadata calls, 64 directory opens, 8 held iterators) and every pass is compared with
// the physical operations RecordingFs saw, never with the constants the engine itself uses.
// ---------------------------------------------------------------------------------------------

/// One pass whose reported counters must equal the filesystem work physically observed.
fn measured_pass(
    engine: &mut OpenCodeEngine<RecordingFs>,
    observed: &RecordingFs,
    now_ms: i64,
) -> PassReport {
    let before = observed.metrics();
    let report = engine.pass(enabled(), now_ms);
    let after = observed.metrics();
    let counters = report.counters;
    assert_eq!(
        u64::from(counters.entries),
        after.entries - before.entries,
        "yielded entries: {report:?}"
    );
    assert_eq!(
        u64::from(counters.stat_calls),
        after.stat_calls - before.stat_calls,
        "metadata calls: {report:?}"
    );
    assert_eq!(
        u64::from(counters.header_reads),
        after.header_reads - before.header_reads,
        "header reads: {report:?}"
    );
    assert_eq!(
        u64::from(counters.directory_opens),
        after.directory_opens - before.directory_opens,
        "directory opens: {report:?}"
    );
    assert_eq!(
        u64::from(counters.source_opens),
        (after.header_reads - before.header_reads)
            + (after.bounded_reads - before.bounded_reads)
            + (after.sqlite_opens - before.sqlite_opens),
        "source opens: {report:?}"
    );
    assert!(after.entries - before.entries <= 20_000, "{report:?}");
    assert!(after.stat_calls - before.stat_calls <= 40_000, "{report:?}");
    assert!(
        after.header_reads - before.header_reads <= 256,
        "{report:?}"
    );
    assert!(
        after.directory_opens - before.directory_opens <= 64,
        "{report:?}"
    );
    assert!(after.max_open_directories <= 8, "held iterators: {after:?}");
    report
}

fn write_json(path: &Path, value: &serde_json::Value) -> TestResult {
    fs::create_dir_all(path.parent().ok_or("parent")?)?;
    fs::write(path, serde_json::to_vec(value)?)?;
    Ok(())
}

fn five(input: u64, output: u64, total: u64) -> serde_json::Value {
    serde_json::json!({
        "input": input, "output": output, "reasoning": 0,
        "cache": {"read": 0, "write": 0}, "total": total
    })
}

/// JSON message `m{index}` in its own session directory, whose single step-finish part replaces
/// the parent: input `index + 1`, output 2, total `index + 3`.
fn json_group(source: &Path, index: u64) -> TestResult {
    write_json(
        &source.join(format!(
            "storage/message/session-{index:04}/m{index:04}.json"
        )),
        &serde_json::json!({
            "role": "assistant", "time": {"created": 1_700_000_000_000_i64 + index as i64},
            "tokens": five(1, 1, 2)
        }),
    )?;
    write_json(
        &source.join(format!("storage/part/m{index:04}/p1.json")),
        &serde_json::json!({"type": "step-finish", "tokens": five(index + 1, 2, index + 3)}),
    )
}

/// The frontier keeps seven directory iterators and the synchronous JSON-part scan is the
/// eighth: across many capped passes the high-water mark is exactly eight and no pass leaves the
/// part iterator alive.
#[test]
fn json_part_scans_share_the_eight_iterator_ceiling_across_passes() -> TestResult {
    const GROUPS: u64 = 70;
    let roots = Roots::new()?;
    for index in 0..GROUPS {
        json_group(&roots.source, index)?;
    }
    let fs = RecordingFs::new();
    let observed = fs.clone();
    let mut engine = roots
        .open(fs, enabled())
        .map_err(|report| format!("open failed: {report:?}"))?;

    let mut reports = Vec::new();
    for step in 0..40 {
        let report = measured_pass(&mut engine, &observed, 1 + step);
        assert!(
            observed.metrics().open_directories <= 7,
            "only frontier iterators survive a pass: {:?}",
            observed.metrics()
        );
        let done = report.outcome == PassOutcome::Consistent;
        reports.push(report);
        if done {
            break;
        }
    }
    let last = reports.last().ok_or("no pass ran")?;
    assert_eq!(last.outcome, PassOutcome::Consistent, "{last:?}");
    // root + storage + storage/message + 70 session directories + 70 part directories.
    let opens: u32 = reports
        .iter()
        .map(|report| report.counters.directory_opens)
        .sum();
    assert_eq!(opens, 3 + 2 * GROUPS as u32);
    assert!(reports.len() >= 3, "{} passes", reports.len());
    for capped in &reports[..reports.len() - 1] {
        assert_eq!(capped.outcome, PassOutcome::CatchingUp, "{capped:?}");
        assert_eq!(capped.counters.directory_opens, 64, "{capped:?}");
    }
    let metrics = observed.metrics();
    assert_eq!(metrics.max_open_directories, 8, "{metrics:?}");
    assert_eq!(metrics.open_directories, 0, "{metrics:?}");

    let records = engine.observations()?;
    assert_eq!(records.len() as u64, GROUPS);
    for index in 0..GROUPS {
        let id = format!("m{index:04}");
        let record = records
            .iter()
            .find(|record| record.message_id == id)
            .ok_or_else(|| format!("{id} missing"))?;
        assert_eq!(record.input.value, Some(index + 1), "{id}");
        assert_eq!(record.output.value, Some(2), "{id}");
        assert_eq!(record.total.value, Some(index + 3), "{id}");
        assert_eq!(record.selected_part_ids, ["p1"], "{id}");
    }
    let projection = engine.snapshot(last)?.projection;
    assert_eq!(projection.input.value, Some(GROUPS * (GROUPS + 1) / 2));
    assert_eq!(
        projection.total.value,
        Some(GROUPS * (GROUPS - 1) / 2 + 3 * GROUPS)
    );
    Ok(())
}

/// A part directory with more entries than one pass may yield: the scan stops at the ceiling
/// without pulling an uncounted entry, never publishes a half-read group, keeps its iterator and
/// decoded parts across passes (no entry is yielded twice), and drains to the exact whole group.
/// After a restart the unfinished scan is rebuilt from the start and still drains.
#[test]
fn part_directory_scan_drains_across_passes_and_restart_without_half_publication() -> TestResult {
    for restart in [false, true] {
        let roots = Roots::new()?;
        json_group(&roots.source, 0)?;
        let noise = roots.source.join("storage/part/m0000");
        for index in 0..20_010 {
            fs::write(noise.join(format!("noise-{index:05}.txt")), [])?;
        }
        let fs = RecordingFs::new();
        let observed = fs.clone();
        let mut engine = roots
            .open(fs, enabled())
            .map_err(|report| format!("open failed: {report:?}"))?;
        let first = measured_pass(&mut engine, &observed, 1);
        assert_eq!(first.outcome, PassOutcome::CatchingUp, "{first:?}");
        assert_eq!(first.counters.entries, 20_000, "the entry ceiling, exactly");
        assert_eq!(first.records_committed, 0);
        assert!(
            engine.observations()?.is_empty(),
            "half-read group published"
        );
        let mut yielded = u64::from(first.counters.entries);
        if restart {
            drop(engine);
            engine = roots
                .open(RecordingFs::new(), enabled())
                .map_err(|report| format!("reopen failed: {report:?}"))?;
        }
        let mut last = first;
        for step in 0..10 {
            if last.outcome == PassOutcome::Consistent {
                break;
            }
            last = if restart {
                let report = engine.pass(enabled(), 2 + step);
                yielded += u64::from(report.counters.entries);
                report
            } else {
                let report = measured_pass(&mut engine, &observed, 2 + step);
                yielded += u64::from(report.counters.entries);
                report
            };
            assert_ne!(last.outcome, PassOutcome::Unavailable, "{last:?}");
            assert!(
                engine.observations()?.is_empty() || last.outcome == PassOutcome::Consistent,
                "{restart}: half-read group published: {last:?}"
            );
        }
        assert_eq!(last.outcome, PassOutcome::Consistent, "{restart}: {last:?}");
        if !restart {
            // The held iterator resumed: every entry of the directory was yielded exactly once
            // (20,010 noise files, the part file, and the root/storage listings around it).
            assert!(yielded < 2 * 20_000, "{yielded} entries across the drain");
        }
        let records = engine.observations()?;
        assert_eq!(records.len(), 1, "{restart}");
        assert_eq!(records[0].input.value, Some(1));
        assert_eq!(records[0].output.value, Some(2));
        assert_eq!(records[0].total.value, Some(3));
        assert_eq!(records[0].selected_part_ids, ["p1"]);
        assert!(!records[0].pending_partial);
    }
    Ok(())
}

/// Roughly twenty metadata calls per message, so 2,100 small messages cross the 40,000 ceiling
/// in the middle of a message: no physical call is issued past it, the pass reports exactly the
/// ceiling, and the remaining messages drain on later passes without loss or duplication.
#[test]
fn metadata_ceiling_ends_a_pass_exactly_and_the_sweep_drains() -> TestResult {
    const MESSAGES: u64 = 2_100;
    let roots = Roots::new()?;
    for index in 0..MESSAGES {
        write_json(
            &roots.source.join(format!(
                "storage/message/session-{:02}/m{index:04}.json",
                index % 10
            )),
            &serde_json::json!({
                "role": "assistant", "time": {"created": 1_700_000_000_000_i64 + index as i64},
                "tokens": five(index % 5 + 1, 1, index % 5 + 2)
            }),
        )?;
    }
    let fs = RecordingFs::new();
    let observed = fs.clone();
    let mut engine = roots
        .open(fs, enabled())
        .map_err(|report| format!("open failed: {report:?}"))?;
    let first = measured_pass(&mut engine, &observed, 1);
    assert_eq!(first.outcome, PassOutcome::CatchingUp, "{first:?}");
    assert_eq!(first.counters.stat_calls, 40_000, "{first:?}");
    assert_eq!(first.failure, None, "{first:?}");
    let mut last = first;
    for step in 0..10 {
        if last.outcome == PassOutcome::Consistent {
            break;
        }
        last = measured_pass(&mut engine, &observed, 2 + step);
    }
    assert_eq!(last.outcome, PassOutcome::Consistent, "{last:?}");
    let projection = engine.snapshot(&last)?.projection;
    assert_eq!(projection.records, MESSAGES);
    let expected_input: u64 = (0..MESSAGES).map(|index| index % 5 + 1).sum();
    assert_eq!(projection.input.value, Some(expected_input));
    assert_eq!(projection.output.value, Some(MESSAGES));
    assert_eq!(projection.total.value, Some(expected_input + MESSAGES));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Cap, depth, queue, path, permission and terminal-missing boundaries.
// ---------------------------------------------------------------------------------------------

fn history(data: &Path) -> TestResult<Connection> {
    Ok(Connection::open_with_flags(
        data.join("history.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?)
}

fn frontier_rows(data: &Path) -> TestResult<i64> {
    Ok(
        history(data)?.query_row("SELECT COUNT(*) FROM frontier_directories", [], |row| {
            row.get(0)
        })?,
    )
}

fn file_state(data: &Path, relative: &str) -> TestResult<Option<String>> {
    Ok(history(data)?
        .query_row(
            "SELECT file_state FROM source_files WHERE relative_path = ?1",
            [relative],
            |row| row.get(0),
        )
        .optional()?)
}

/// One usage-bearing v2 row; input and explicit total are `total`.
fn v2_row(message: &str, total: u64) -> String {
    format!(
        "INSERT INTO session_v2(id) VALUES ('s-{message}'); \
         INSERT INTO session_message(id, session_id, type, seq, time_created, data) \
         VALUES ('{message}', 's-{message}', 'assistant', 1, 1700000000000, \
         '{{\"tokens\":{{\"input\":{total},\"output\":0,\"reasoning\":0,\
         \"cache\":{{\"read\":0,\"write\":0}},\"total\":{total}}}}}')"
    )
}

fn message_file(source: &Path, name: &str, input: u64) -> TestResult<PathBuf> {
    let path = source.join(format!("storage/message/session-a/{name}.json"));
    write_json(
        &path,
        &serde_json::json!({
            "role": "assistant", "time": {"created": 1_700_000_000_000_i64},
            "tokens": five(input, 1, input + 1)
        }),
    )?;
    Ok(path)
}

/// The 20,000-entry ceiling ends a pass at exactly 20,000 yielded entries, the replayed entry is
/// never counted twice, and the remainder drains: 2 + 1 + 1 + 1 + 20,002 entries in all.
#[test]
fn entry_ceiling_ends_a_pass_at_twenty_thousand_and_drains_without_loss() -> TestResult {
    let roots = Roots::new()?;
    message_file(&roots.source, "m1", 3)?;
    let crowded = roots.source.join("crowded");
    fs::create_dir(&crowded)?;
    for index in 0..20_002 {
        fs::write(crowded.join(format!("entry-{index:05}")), [])?;
    }
    let fs = RecordingFs::new();
    let observed = fs.clone();
    let mut engine = roots
        .open(fs, enabled())
        .map_err(|report| format!("open failed: {report:?}"))?;
    let first = measured_pass(&mut engine, &observed, 1);
    assert_eq!(first.outcome, PassOutcome::CatchingUp, "{first:?}");
    assert_eq!(first.failure, None);
    assert_eq!(first.counters.entries, 20_000);
    let second = measured_pass(&mut engine, &observed, 2);
    assert_eq!(second.outcome, PassOutcome::Consistent, "{second:?}");
    // root: storage + crowded; storage: message; message: session-a; session-a: m1.json.
    assert_eq!(second.counters.entries, 2 + 1 + 1 + 1 + 20_002 - 20_000);
    let records = engine.observations()?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].input.value, Some(3));
    assert_eq!(records[0].total.value, Some(4));
    Ok(())
}

fn directory_log(fs: &RecordingFs) -> Arc<Mutex<Vec<PathBuf>>> {
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&log);
    fs.on_boundary(move |kind, path| {
        if kind == OpenKind::Directory
            && let Ok(mut opened) = sink.lock()
        {
            opened.push(path.to_path_buf());
        }
    });
    log
}

/// Directories are listed down to nesting level 8; a level-9 directory is rejected as
/// `limit_exceeded` and never listed, while the sibling database keeps its oracle total.
#[test]
fn directory_depth_boundary_reads_level_eight_and_rejects_level_nine() -> TestResult {
    for (levels, deep_is_read) in [(8_usize, true), (9, false)] {
        let roots = Roots::new()?;
        let _shallow = live_database(&roots.source.join("opencode.db"), &[&v2_row("shallow", 10)])?;
        let mut deep = roots.source.clone();
        for level in 1..=levels {
            deep.push(format!("level-{level}"));
        }
        fs::create_dir_all(&deep)?;
        let _deep = live_database(&deep.join("opencode-deep.db"), &[&v2_row("deep", 7)])?;

        let fs = RecordingFs::new();
        let log = directory_log(&fs);
        let mut engine = roots
            .open(fs, enabled())
            .map_err(|report| format!("open failed: {report:?}"))?;
        let mut report = engine.pass(enabled(), 1);
        for step in 0..4 {
            if report.outcome != PassOutcome::CatchingUp {
                break;
            }
            report = engine.pass(enabled(), 2 + step);
        }
        let canonical = roots.source.canonicalize()?;
        let mut opened = log
            .lock()
            .map_err(|_| "directory log poisoned")?
            .iter()
            .map(|path| Ok(path.strip_prefix(&canonical)?.to_path_buf()))
            .collect::<TestResult<Vec<_>>>()?;
        opened.sort();
        opened.dedup();
        let listed_levels = opened
            .iter()
            .map(|path| path.components().count())
            .max()
            .unwrap_or(0);
        let totals: Vec<_> = engine
            .observations()?
            .iter()
            .map(|record| (record.message_id.clone(), record.total.value))
            .collect();
        if deep_is_read {
            assert_eq!(
                report.outcome,
                PassOutcome::Consistent,
                "{levels}: {report:?}"
            );
            assert_eq!(listed_levels, 8, "{opened:?}");
            assert_eq!(
                totals,
                [
                    ("deep".to_owned(), Some(7)),
                    ("shallow".to_owned(), Some(10))
                ]
            );
        } else {
            assert_eq!(report.outcome, PassOutcome::Partial, "{levels}: {report:?}");
            assert_eq!(report.failure, Some(FailureCode::LimitExceeded));
            assert_eq!(listed_levels, 8, "level 9 must never be listed: {opened:?}");
            assert_eq!(totals, [("shallow".to_owned(), Some(10))]);
        }
    }
    Ok(())
}

/// Seven directories of 700 children each keep every iterator slot busy while their children
/// are queued: the persisted queue stops at exactly 4,096 entries, overflow is reported as
/// `limit_exceeded`, and the pass is never called consistent.
#[test]
fn pending_directory_queue_stops_at_4096_across_passes_and_restart() -> TestResult {
    let roots = Roots::new()?;
    for parent in 0..7 {
        for child in 0..700 {
            fs::create_dir_all(roots.source.join(format!("wide-{parent}/dir-{child:03}")))?;
        }
    }
    let fs = RecordingFs::new();
    let observed = fs.clone();
    let mut engine = roots
        .open(fs, enabled())
        .map_err(|report| format!("open failed: {report:?}"))?;
    let first = measured_pass(&mut engine, &observed, 1);
    assert_eq!(first.outcome, PassOutcome::CatchingUp, "{first:?}");
    assert_eq!(first.failure, Some(FailureCode::LimitExceeded), "{first:?}");
    assert_eq!(frontier_rows(&roots.data)?, 4_096);
    for step in 0..3 {
        let report = measured_pass(&mut engine, &observed, 2 + step);
        assert_ne!(report.outcome, PassOutcome::Consistent, "{report:?}");
        assert!(frontier_rows(&roots.data)? <= 4_096);
    }
    drop(engine);
    let mut reopened = roots
        .open(RecordingFs::new(), enabled())
        .map_err(|report| format!("reopen failed: {report:?}"))?;
    let restarted = reopened.pass(enabled(), 10);
    assert_ne!(restarted.outcome, PassOutcome::Consistent, "{restarted:?}");
    assert!(frontier_rows(&roots.data)? <= 4_096);
    Ok(())
}

/// A root path of exactly 4,096 bytes passes the length gate (and fails later as an invalid
/// root); 4,097 bytes is `limit_exceeded` before a single filesystem call.
#[test]
fn root_path_length_boundary_is_4096_bytes() -> TestResult {
    let long = |bytes: usize| PathBuf::from(format!("/{}", "a".repeat(bytes - 1)));
    for (which, bytes, expected, stat_calls) in [
        ("source", 4_096, FailureCode::RootInvalid, 1),
        ("source", 4_097, FailureCode::LimitExceeded, 0),
        ("data", 4_096, FailureCode::RootInvalid, 1),
        ("data", 4_097, FailureCode::LimitExceeded, 0),
    ] {
        let roots = Roots::new()?;
        let (source, data) = if which == "source" {
            (long(bytes), roots.data.clone())
        } else {
            (roots.source.clone(), long(bytes))
        };
        assert_eq!(
            if which == "source" { &source } else { &data }
                .as_os_str()
                .len(),
            bytes
        );
        let fs = RecordingFs::new();
        let observed = fs.clone();
        let report = match OpenCodeEngine::open(
            fs,
            &source,
            &data,
            &roots.home,
            enabled(),
            SourceKind::Custom,
        ) {
            Err(report) => report,
            Ok(_) => panic!("{which} path of {bytes} bytes was accepted"),
        };
        assert_eq!(report.outcome, PassOutcome::Unavailable);
        assert_eq!(report.failure, Some(expected), "{which} {bytes}");
        if stat_calls != 0 {
            assert!(report.counters.stat_calls > 0, "{which} {bytes}");
        } else {
            assert_eq!(report.counters.stat_calls, 0, "{which} {bytes}");
        }
        assert_eq!(
            observed.metrics().stat_calls,
            u64::from(report.counters.stat_calls),
            "{which} {bytes}: charged equals physically performed"
        );
        assert_eq!(observed.metrics().directory_opens, 0);
        assert!(
            !roots.data.exists(),
            "{which} {bytes}: data directory created"
        );
    }
    Ok(())
}

struct Unreadable(PathBuf, u32);

impl Unreadable {
    fn new(path: &Path) -> TestResult<Self> {
        let mode = fs::metadata(path)?.permissions().mode() & 0o7777;
        fs::set_permissions(path, fs::Permissions::from_mode(0o000))?;
        Ok(Self(path.to_path_buf(), mode))
    }
}

impl Drop for Unreadable {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(self.1));
    }
}

/// Permission errors are classified per file: an unreadable directory is `io` and partial, an
/// unreadable message is retried apart from its siblings, an unreadable database is
/// unavailable; prior history survives each, and restoring access recovers exactly.
#[test]
fn unreadable_directory_message_and_database_keep_history_and_recover() -> TestResult {
    // Unreadable directory beside a readable message.
    let roots = Roots::new()?;
    message_file(&roots.source, "m1", 3)?;
    let locked = roots.source.join("locked");
    fs::create_dir(&locked)?;
    let guard = Unreadable::new(&locked)?;
    let mut engine = roots
        .open(RecordingFs::new(), enabled())
        .map_err(|report| format!("open failed: {report:?}"))?;
    let blocked = engine.pass(enabled(), 1);
    assert_eq!(blocked.outcome, PassOutcome::Partial, "{blocked:?}");
    assert_eq!(blocked.failure, Some(FailureCode::Io), "{blocked:?}");
    assert_eq!(engine.observations()?[0].total.value, Some(4));
    drop(guard);
    let recovered = engine.pass(enabled(), 2);
    assert_eq!(recovered.outcome, PassOutcome::Consistent, "{recovered:?}");
    assert_eq!(engine.observations()?.len(), 1);

    // Unreadable message after a published one.
    let roots = Roots::new()?;
    message_file(&roots.source, "m1", 3)?;
    let mut engine = roots
        .open(RecordingFs::new(), enabled())
        .map_err(|report| format!("open failed: {report:?}"))?;
    assert_eq!(engine.pass(enabled(), 1).outcome, PassOutcome::Consistent);
    let second = message_file(&roots.source, "m2", 5)?;
    let guard = Unreadable::new(&second)?;
    let blocked = engine.pass(enabled(), 2);
    assert_eq!(blocked.outcome, PassOutcome::Partial, "{blocked:?}");
    assert_eq!(blocked.failure, Some(FailureCode::Io), "{blocked:?}");
    let kept: Vec<_> = engine
        .observations()?
        .iter()
        .map(|record| (record.message_id.clone(), record.total.value))
        .collect();
    assert_eq!(kept, [("m1".to_owned(), Some(4))]);
    drop(guard);
    let recovered = engine.pass(enabled(), 3);
    assert_eq!(recovered.outcome, PassOutcome::Consistent, "{recovered:?}");
    let totals: Vec<_> = engine
        .observations()?
        .iter()
        .map(|record| (record.message_id.clone(), record.total.value))
        .collect();
    assert_eq!(
        totals,
        [("m1".to_owned(), Some(4)), ("m2".to_owned(), Some(6))]
    );

    // Unreadable database.
    let roots = Roots::new()?;
    let database = roots.source.join("opencode.db");
    let _writer = live_database(&database, &[&v2_row("db-row", 9)])?;
    let guard = Unreadable::new(&database)?;
    let mut engine = roots
        .open(RecordingFs::new(), enabled())
        .map_err(|report| format!("open failed: {report:?}"))?;
    let blocked = engine.pass(enabled(), 1);
    assert_eq!(blocked.outcome, PassOutcome::Unavailable, "{blocked:?}");
    assert_eq!(blocked.failure, Some(FailureCode::Io), "{blocked:?}");
    assert!(engine.observations()?.is_empty());
    drop(guard);
    let recovered = engine.pass(enabled(), 2);
    assert_eq!(recovered.outcome, PassOutcome::Consistent, "{recovered:?}");
    assert_eq!(engine.observations()?[0].total.value, Some(9));
    Ok(())
}

/// Only a sweep that reached every directory cleanly may call an unseen file missing, and a
/// missing file never removes its observation.
#[test]
fn only_a_terminal_sweep_marks_a_vanished_file_missing() -> TestResult {
    let roots = Roots::new()?;
    let first = message_file(&roots.source, "m1", 3)?;
    let second = message_file(&roots.source, "m2", 5)?;
    let relative = |name: &str| format!("storage/message/session-a/{name}.json");
    let mut engine = roots
        .open(RecordingFs::new(), enabled())
        .map_err(|report| format!("open failed: {report:?}"))?;
    assert_eq!(engine.pass(enabled(), 1).outcome, PassOutcome::Consistent);
    for name in ["m1", "m2"] {
        assert_eq!(
            file_state(&roots.data, &relative(name))?.as_deref(),
            Some("present")
        );
    }

    // m1 vanishes during a sweep that is cut short by the entry ceiling: unvisited is not missing.
    fs::remove_file(&first)?;
    let crowded = roots.source.join("crowded");
    fs::create_dir(&crowded)?;
    for index in 0..20_002 {
        fs::write(crowded.join(format!("entry-{index:05}")), [])?;
    }
    let capped = engine.pass(enabled(), 2);
    assert_eq!(capped.outcome, PassOutcome::CatchingUp, "{capped:?}");
    assert_eq!(
        file_state(&roots.data, &relative("m1"))?.as_deref(),
        Some("present")
    );
    let terminal = engine.pass(enabled(), 3);
    assert_eq!(terminal.outcome, PassOutcome::Consistent, "{terminal:?}");
    assert_eq!(
        file_state(&roots.data, &relative("m1"))?.as_deref(),
        Some("missing")
    );
    assert_eq!(
        file_state(&roots.data, &relative("m2"))?.as_deref(),
        Some("present")
    );
    assert_eq!(engine.observations()?.len(), 2, "absence is not removal");

    // m2 vanishes during a sweep that ends with an unresolved error: still not missing.
    fs::remove_file(&second)?;
    message_file(&roots.source, "m3", 7)?;
    fs::remove_dir_all(&crowded)?;
    let locked = roots.source.join("locked");
    fs::create_dir(&locked)?;
    let guard = Unreadable::new(&locked)?;
    let blocked = engine.pass(enabled(), 4);
    assert_eq!(blocked.outcome, PassOutcome::Partial, "{blocked:?}");
    assert_eq!(
        file_state(&roots.data, &relative("m2"))?.as_deref(),
        Some("present")
    );
    drop(guard);
    let clean = engine.pass(enabled(), 5);
    assert_eq!(clean.outcome, PassOutcome::Consistent, "{clean:?}");
    assert_eq!(
        file_state(&roots.data, &relative("m2"))?.as_deref(),
        Some("missing")
    );
    assert_eq!(engine.observations()?.len(), 3);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Consent lifecycle and root validation.
// ---------------------------------------------------------------------------------------------

/// (selected, consent, expected failure) for every authorization state; `None` is the control
/// that must open.
const AUTHORIZATIONS: [(bool, ConsentState, Option<FailureCode>); 6] = [
    (true, ConsentState::Enabled, None),
    (true, ConsentState::Undecided, Some(FailureCode::Denied)),
    (true, ConsentState::Denied, Some(FailureCode::Denied)),
    (false, ConsentState::Enabled, Some(FailureCode::Unselected)),
    (
        false,
        ConsentState::Undecided,
        Some(FailureCode::Unselected),
    ),
    (false, ConsentState::Denied, Some(FailureCode::Unselected)),
];

fn data_tree(root: &Path) -> TestResult<Vec<(PathBuf, Vec<u8>)>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push((path.clone(), fs::read(&path)?));
            }
        }
    }
    files.sort();
    Ok(files)
}

/// Every selected/consent combination at open: only enabled-and-selected opens; all five other
/// states fail with their own code before any filesystem call, counter or data directory.
#[test]
fn every_authorization_state_is_gated_at_open_before_any_source_work() -> TestResult {
    for (selected, consent, expected) in AUTHORIZATIONS {
        let roots = Roots::new()?;
        message_file(&roots.source, "m1", 3)?;
        let fs = RecordingFs::new();
        let observed = fs.clone();
        let outcome = roots.open(fs, SourceAuthorization { selected, consent });
        match (expected, outcome) {
            (None, Ok(mut engine)) => {
                assert!(roots.data.join("history.sqlite").exists());
                assert_eq!(engine.pass(enabled(), 1).outcome, PassOutcome::Consistent);
            }
            (Some(code), Err(report)) => {
                assert_eq!(
                    report.outcome,
                    PassOutcome::Unavailable,
                    "{selected} {consent:?}"
                );
                assert_eq!(report.failure, Some(code), "{selected} {consent:?}");
                assert_eq!(report.counters, Default::default());
                assert_eq!(report.records_committed, 0);
                assert_eq!(report.last_good_ms, None);
                assert_eq!(
                    observed.metrics(),
                    Default::default(),
                    "{selected} {consent:?}"
                );
                assert!(!roots.data.exists(), "{selected} {consent:?}: data created");
            }
            (expected, outcome) => panic!(
                "{selected} {consent:?}: expected {expected:?}, got {:?}",
                outcome.map(|_| "opened")
            ),
        }
    }
    Ok(())
}

/// A handle opened while enabled and later denied, deselected or reset to undecided performs no
/// filesystem work, writes nothing durable and loses nothing; re-enabling resumes normally.
#[test]
fn authorization_withdrawn_after_open_stops_every_pass_without_effects() -> TestResult {
    let roots = Roots::new()?;
    message_file(&roots.source, "m1", 3)?;
    let fs = RecordingFs::new();
    let observed = fs.clone();
    let mut engine = roots
        .open(fs, enabled())
        .map_err(|report| format!("open failed: {report:?}"))?;
    assert_eq!(engine.pass(enabled(), 1).outcome, PassOutcome::Consistent);
    let durable = data_tree(&roots.data)?;
    let totals = |engine: &OpenCodeEngine<RecordingFs>| -> TestResult<Vec<Option<u64>>> {
        Ok(engine
            .observations()?
            .iter()
            .map(|record| record.total.value)
            .collect())
    };
    assert_eq!(totals(&engine)?, [Some(4)]);

    for (selected, consent, expected) in AUTHORIZATIONS {
        let Some(code) = expected else { continue };
        let before = observed.metrics();
        let report = engine.pass(SourceAuthorization { selected, consent }, 10);
        assert_eq!(
            report.outcome,
            PassOutcome::Unavailable,
            "{selected} {consent:?}"
        );
        assert_eq!(report.failure, Some(code), "{selected} {consent:?}");
        assert_eq!(report.counters, Default::default());
        assert_eq!(
            observed.metrics(),
            before,
            "{selected} {consent:?}: source touched"
        );
        assert_eq!(
            data_tree(&roots.data)?,
            durable,
            "{selected} {consent:?}: store changed"
        );
        assert_eq!(totals(&engine)?, [Some(4)]);
    }
    let resumed = engine.pass(enabled(), 20);
    assert_eq!(resumed.outcome, PassOutcome::Consistent, "{resumed:?}");
    assert_eq!(totals(&engine)?, [Some(4)]);
    Ok(())
}

struct RootCase {
    name: &'static str,
    source: PathBuf,
    data: PathBuf,
    home: PathBuf,
    /// `None` must open; `Some` must be rejected with exactly this code.
    expected: Option<FailureCode>,
    /// Paths that must not exist afterwards (nothing created through a hostile target).
    absent: Vec<PathBuf>,
}

/// Canonical, future-parent, root, HOME and alias controls, each with its accepting sibling.
#[test]
fn root_matrix_covers_home_future_parent_and_alias_controls() -> TestResult {
    let invalid = Some(FailureCode::RootInvalid);
    let overlap = Some(FailureCode::RootOverlap);
    let mut cases = Vec::new();
    let mut keep = Vec::new();
    let mut case = |name, build: &dyn Fn(&Path, &Path) -> TestResult<RootCase>| -> TestResult {
        let directory = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let base = directory.path().canonicalize()?;
        fs::create_dir(base.join("source"))?;
        fs::create_dir(base.join("home"))?;
        fs::write(base.join("file"), b"regular")?;
        std::os::unix::fs::symlink(base.join("source"), base.join("link-to-source"))?;
        std::os::unix::fs::symlink(base.join("home"), base.join("link-to-home"))?;
        let mut built = build(&base, &outside.path().canonicalize()?)?;
        built.name = name;
        cases.push(built);
        keep.push((directory, outside));
        Ok(())
    };
    let rooted = |source: PathBuf, data: PathBuf, home: PathBuf, expected, absent| RootCase {
        name: "",
        source,
        data,
        home,
        expected,
        absent,
    };
    case("relative source", &|b, o| {
        Ok(rooted(
            "relative-source".into(),
            o.join("data"),
            b.join("home"),
            invalid,
            vec![],
        ))
    })?;
    case("relative data", &|b, _| {
        Ok(rooted(
            b.join("source"),
            "relative-data".into(),
            b.join("home"),
            invalid,
            vec!["relative-data".into()],
        ))
    })?;
    case("relative home", &|b, o| {
        Ok(rooted(
            b.join("source"),
            o.join("data"),
            "relative-home".into(),
            invalid,
            vec![],
        ))
    })?;
    case("source equals HOME", &|b, o| {
        Ok(rooted(
            b.join("home"),
            o.join("data"),
            b.join("home"),
            invalid,
            vec![o.join("data")],
        ))
    })?;
    case("source is an ancestor of HOME", &|b, o| {
        Ok(rooted(
            b.to_path_buf(),
            o.join("data"),
            b.join("home"),
            invalid,
            vec![o.join("data")],
        ))
    })?;
    case("source is the filesystem root", &|b, o| {
        Ok(rooted(
            "/".into(),
            o.join("data"),
            b.join("home"),
            invalid,
            vec![o.join("data")],
        ))
    })?;
    case("source is a link to HOME", &|b, o| {
        Ok(rooted(
            b.join("link-to-home"),
            o.join("data"),
            b.join("home"),
            invalid,
            vec![o.join("data")],
        ))
    })?;
    case("source is a regular file", &|b, o| {
        Ok(rooted(
            b.join("file"),
            o.join("data"),
            b.join("home"),
            invalid,
            vec![o.join("data")],
        ))
    })?;
    case("source is missing", &|b, o| {
        Ok(rooted(
            b.join("missing"),
            o.join("data"),
            b.join("home"),
            invalid,
            vec![o.join("data")],
        ))
    })?;
    case("HOME is missing", &|b, o| {
        Ok(rooted(
            b.join("source"),
            o.join("data"),
            b.join("no-home"),
            invalid,
            vec![o.join("data")],
        ))
    })?;
    case("data parent is a regular file", &|b, o| {
        let _ = o;
        Ok(rooted(
            b.join("source"),
            b.join("file/data"),
            b.join("home"),
            invalid,
            vec![],
        ))
    })?;
    case("future data inside source", &|b, _| {
        Ok(rooted(
            b.join("source"),
            b.join("source/new/deeper"),
            b.join("home"),
            overlap,
            vec![b.join("source/new")],
        ))
    })?;
    case("future data through a link into source", &|b, _| {
        Ok(rooted(
            b.join("source"),
            b.join("link-to-source/new"),
            b.join("home"),
            overlap,
            vec![b.join("source/new")],
        ))
    })?;
    case("data is a link to source", &|b, _| {
        Ok(rooted(
            b.join("source"),
            b.join("link-to-source"),
            b.join("home"),
            overlap,
            vec![],
        ))
    })?;
    case("data is an ancestor of source", &|b, _| {
        Ok(rooted(
            b.join("source"),
            b.to_path_buf(),
            b.join("home"),
            overlap,
            vec![b.join("history.sqlite")],
        ))
    })?;
    case("control: several missing data parents", &|b, _| {
        Ok(rooted(
            b.join("source"),
            b.join("a/b/c/data"),
            b.join("home"),
            None,
            vec![],
        ))
    })?;
    case("control: future data below HOME", &|b, _| {
        Ok(rooted(
            b.join("source"),
            b.join("home/.local/share/quotern"),
            b.join("home"),
            None,
            vec![],
        ))
    })?;
    case("control: source nested in HOME", &|b, o| {
        let nested = b.join("home/.local/share/opencode");
        fs::create_dir_all(&nested)?;
        Ok(rooted(nested, o.join("data"), b.join("home"), None, vec![]))
    })?;

    for case in cases {
        let fs = RecordingFs::new();
        let observed = fs.clone();
        let outcome = OpenCodeEngine::open(
            fs,
            &case.source,
            &case.data,
            &case.home,
            enabled(),
            SourceKind::Custom,
        );
        match (case.expected, outcome) {
            (None, Ok(_)) => assert!(case.data.is_dir(), "{}: no data directory", case.name),
            (Some(code), Err(report)) => {
                assert_eq!(report.outcome, PassOutcome::Unavailable, "{}", case.name);
                assert_eq!(report.failure, Some(code), "{}", case.name);
                let metrics = observed.metrics();
                assert_eq!(metrics.entries, 0, "{}", case.name);
                assert_eq!(metrics.header_reads, 0, "{}", case.name);
                assert_eq!(metrics.bounded_reads, 0, "{}", case.name);
                assert_eq!(metrics.directory_opens, 0, "{}", case.name);
                assert_eq!(metrics.sqlite_opens, 0, "{}", case.name);
            }
            (expected, outcome) => panic!(
                "{}: expected {expected:?}, got {:?}",
                case.name,
                outcome.map(|_| "opened")
            ),
        }
        for path in &case.absent {
            assert!(!path.exists(), "{}: created {}", case.name, path.display());
        }
    }
    Ok(())
}

/// Replacing the source or data directory after open (different inode, or a link to the original)
/// is `source_overlap_conflict` with no source I/O and no write into the replacement; putting the
/// original back resumes with the retained history.
#[test]
fn roots_replaced_after_open_fail_closed_and_recover_when_restored() -> TestResult {
    let roots = Roots::new()?;
    let base = roots.source.parent().ok_or("base")?.canonicalize()?;
    let (source, data) = (base.join("source"), base.join("data"));
    message_file(&source, "m1", 3)?;
    let fs = RecordingFs::new();
    let observed = fs.clone();
    let mut engine = roots
        .open(fs, enabled())
        .map_err(|report| format!("open failed: {report:?}"))?;
    assert_eq!(engine.pass(enabled(), 1).outcome, PassOutcome::Consistent);
    let totals = |engine: &OpenCodeEngine<RecordingFs>| -> TestResult<Vec<Option<u64>>> {
        Ok(engine
            .observations()?
            .iter()
            .map(|record| record.total.value)
            .collect())
    };
    let fenced = |engine: &mut OpenCodeEngine<RecordingFs>, now_ms: i64, what: &str| {
        let before = observed.metrics();
        let report = engine.pass(enabled(), now_ms);
        let after = observed.metrics();
        assert_eq!(
            report.outcome,
            PassOutcome::Unavailable,
            "{what}: {report:?}"
        );
        assert_eq!(
            report.failure,
            Some(FailureCode::RootOverlap),
            "{what}: {report:?}"
        );
        assert_eq!(after.directory_opens, before.directory_opens, "{what}");
        assert_eq!(after.header_reads, before.header_reads, "{what}");
        assert_eq!(after.bounded_reads, before.bounded_reads, "{what}");
        assert_eq!(after.sqlite_opens, before.sqlite_opens, "{what}");
    };

    // Source replaced by a different directory carrying a decoy message.
    let parked = base.join("source-parked");
    fs::rename(&source, &parked)?;
    message_file(&source, "decoy", 77_777)?;
    fenced(&mut engine, 2, "replaced source directory");
    assert_eq!(totals(&engine)?, [Some(4)]);
    fs::remove_dir_all(&source)?;
    // Source replaced by a link to the original.
    std::os::unix::fs::symlink(&parked, &source)?;
    fenced(&mut engine, 3, "source link");
    fs::remove_file(&source)?;
    fs::rename(&parked, &source)?;

    // Data directory replaced by an empty one: nothing is ever written into the replacement.
    let parked_data = base.join("data-parked");
    fs::rename(&data, &parked_data)?;
    fs::create_dir(&data)?;
    fenced(&mut engine, 4, "replaced data directory");
    assert_eq!(
        fs::read_dir(&data)?.count(),
        0,
        "written into the replacement"
    );
    fs::remove_dir(&data)?;
    fs::rename(&parked_data, &data)?;

    let resumed = engine.pass(enabled(), 5);
    assert_eq!(resumed.outcome, PassOutcome::Consistent, "{resumed:?}");
    assert_eq!(totals(&engine)?, [Some(4)]);
    Ok(())
}

/// Every metadata call is charged where it is issued: an oversized part file costs a stat, a
/// canonicalization (one `lstat` per path component) and a re-stat. The pass reports exactly what
/// the filesystem physically saw, never exceeds the 40,000-call ceiling, and the held iterator
/// resumes across passes so every oversized part is rejected exactly once and the group is
/// never published half-read.
#[test]
fn part_scan_metadata_ceiling_is_exact_and_resumes_without_reyielding() -> TestResult {
    let roots = Roots::new()?;
    json_group(&roots.source, 0)?;
    let part_directory = roots.source.join("storage/part/m0000");
    for index in 0..13_500 {
        let file = fs::File::create(part_directory.join(format!("big-{index:05}.json")))?;
        file.set_len(262_145)?;
    }
    let fs = RecordingFs::new();
    let observed = fs.clone();
    let mut engine = roots
        .open(fs, enabled())
        .map_err(|report| format!("open failed: {report:?}"))?;
    let mut rejected = 0_u64;
    let mut last = None;
    for pass in 1..=60 {
        let before = observed.metrics();
        let report = engine.pass(enabled(), pass);
        let after = observed.metrics();
        assert!(report.counters.stat_calls <= 40_000, "{report:?}");
        assert_eq!(
            after.stat_calls - before.stat_calls,
            u64::from(report.counters.stat_calls),
            "charged equals physically performed: {report:?}"
        );
        assert!(
            engine.observations()?.is_empty(),
            "a half-read or unreadable group is never published"
        );
        rejected += u64::from(report.counters.rejected_records);
        let done = report.outcome != PassOutcome::CatchingUp;
        last = Some(report);
        if done {
            break;
        }
    }
    let last = last.ok_or("no pass ran")?;
    assert_eq!(
        rejected, 13_500,
        "every oversized part is rejected exactly once across the passes"
    );
    assert_eq!(last.outcome, PassOutcome::Partial, "{last:?}");
    assert_eq!(last.failure, Some(FailureCode::RecordTooLarge));
    Ok(())
}

/// Seventy known JSON groups need seventy part-directory opens to revalidate, more than the 64 a
/// pass may use. The reserved current lane is held to half of the open budget and rotates through
/// its known files, so historical discovery always keeps a share: a late new file is found, a
/// late revision of the last known group is seen, and the sweep reaches Consistent.
#[test]
fn known_groups_beyond_the_open_budget_still_discover_a_late_file_and_reach_consistent()
-> TestResult {
    const GROUPS: u64 = 70;
    let roots = Roots::new()?;
    for index in 0..GROUPS {
        json_group(&roots.source, index)?;
    }
    let fs = RecordingFs::new();
    let mut engine = roots
        .open(fs, enabled())
        .map_err(|report| format!("open failed: {report:?}"))?;
    let mut now = 1;
    let mut first = engine.pass(enabled(), now);
    for _ in 0..40 {
        if first.outcome == PassOutcome::Consistent {
            break;
        }
        now += 1;
        first = engine.pass(enabled(), now);
    }
    assert_eq!(first.outcome, PassOutcome::Consistent, "{first:?}");
    assert_eq!(
        engine.observations_page(None, 1_000)?.observations.len() as u64,
        GROUPS
    );
    // A new file in a directory the sweep has not visited, and a revision of the last known group.
    json_group(&roots.source, 9_999)?;
    write_json(
        &roots
            .source
            .join(format!("storage/part/m{:04}/p1.json", GROUPS - 1)),
        &serde_json::json!({"type": "step-finish", "tokens": five(77, 2, 79)}),
    )?;
    let (mut saw_new, mut saw_revision, mut consistent) = (false, false, false);
    for _ in 0..40 {
        now += 1;
        let report = engine.pass(enabled(), now);
        assert!(
            report.counters.directory_opens <= MAX_DIRECTORY_OPENS,
            "{report:?}"
        );
        let records = engine.observations_page(None, 1_000)?.observations;
        saw_new |= records.iter().any(|record| record.message_id == "m9999");
        saw_revision |= records.iter().any(|record| {
            record.message_id == format!("m{:04}", GROUPS - 1) && record.input.value == Some(77)
        });
        if report.outcome == PassOutcome::Consistent && saw_new && saw_revision {
            consistent = true;
            break;
        }
    }
    assert!(saw_new, "the late new file was never discovered");
    assert!(saw_revision, "the late revision was never seen");
    assert!(consistent, "the sweep never reached Consistent");
    let records = engine.observations_page(None, 1_000)?.observations;
    assert_eq!(records.len() as u64, GROUPS + 1, "each group exactly once");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Independent native physical-work proof (macOS arm64 only).
//
// `support::physical_native` exports the C symbols the production code, Rust `std` and the bundled
// SQLite call (`stat`, `fstat`, `opendir`, `readdir`, `read`, ...). It counts attempts that cross
// that native API boundary with a source path or a source descriptor, beneath every production
// counter, tick and hook callback; none of them is read here. The detector below compares those
// native counts with the pass counters and the literal normative ceilings. It does NOT observe
// raw kernel syscalls, libsystem-internal path walks, mmap-consumed bytes or any other target.
//
// The observer replaces process-wide symbols, so each proof runs in ONE re-executed child
// (`--exact <child> --test-threads=1`) that arms it only after every fixture is prepared, drops
// all source handles while armed and then requires a clean state. The SQLite 64 MiB contract bounds
// materialized payload, not raw page I/O: SQLite read bytes are reported, never bounded here.
// ---------------------------------------------------------------------------------------------

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod native {
    use std::ffi::{CString, c_char, c_int, c_void};
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::process::Command;

    use quotern_core::domain::PassCounters;
    use quotern_core::ingest::fs::{
        BoundedRead, DirEntries, SourceFs, charge_metadata, uncharged_metadata_call,
    };
    use quotern_core::ingest::sqlite_ro::{
        MetadataMeter, OpenError, open_canonical, set_open_hook,
    };

    use super::*;
    use crate::support::physical_native::{Counts, Focus, Meta, Observer, json_within, within};

    const CHILD_ENV: &str = "QUOTERN_PHYSICAL_NATIVE_CHILD";

    unsafe extern "C" {
        // Resolved to the observer's exported wrappers at link time, like every production call.
        fn opendir(path: *const c_char) -> *mut c_void;
        fn readdir(stream: *mut c_void) -> *mut c_void;
        fn rewinddir(stream: *mut c_void);
        fn closedir(stream: *mut c_void) -> c_int;
        fn fstatat(fd: c_int, path: *const c_char, buffer: *mut c_void, flags: c_int) -> c_int;
    }

    /// Source filesystem whose every operation counts as source work, ancestor probes included.
    struct ObservedFs<F>(F);

    fn window<T>(call: impl FnOnce() -> T) -> T {
        let _focus = Focus::enter();
        call()
    }

    impl<F: SourceFs> SourceFs for ObservedFs<F> {
        fn canonicalize(&self, p: &Path, c: &mut PassCounters) -> std::io::Result<PathBuf> {
            window(|| self.0.canonicalize(p, c))
        }
        fn metadata(&self, p: &Path, c: &mut PassCounters) -> std::io::Result<fs::Metadata> {
            window(|| self.0.metadata(p, c))
        }
        fn read_dir(&self, p: &Path, c: &mut PassCounters) -> std::io::Result<DirEntries> {
            window(|| self.0.read_dir(p, c))
        }
        fn read_header(&self, p: &Path, c: &mut PassCounters) -> std::io::Result<Vec<u8>> {
            window(|| self.0.read_header(p, c))
        }
        fn read_bounded(
            &self,
            p: &Path,
            n: usize,
            c: &mut PassCounters,
        ) -> std::io::Result<BoundedRead> {
            window(|| self.0.read_bounded(p, n, c))
        }
        fn open_sqlite(&self, p: &Path) -> Result<Connection, OpenError> {
            window(|| self.0.open_sqlite(p))
        }
    }

    type Engine = OpenCodeEngine<ObservedFs<RecordingFs>>;

    fn open_observed(roots: &Roots) -> TestResult<Engine> {
        OpenCodeEngine::open(
            ObservedFs(RecordingFs::new()),
            &roots.source,
            &roots.data,
            &roots.home,
            enabled(),
            SourceKind::Custom,
        )
        .map_err(|report| format!("open failed: {report:?}").into())
    }

    /// The independent detector: physical work must stay within the literal ceilings common to
    /// both acquisitions and equal the work the pass charged. `json_only` additionally ties the
    /// native read bytes to the charged bytes and bounds them by the 64 MiB JSON ceiling: JSON
    /// bytes are the materialized quantity. SQLite page reads are neither charged nor bounded
    /// (the contract bounds the payload SQLite materializes, not its raw page I/O), so a SQLite
    /// pass is only required to have read at least the payload it materialized.
    fn reconcile(counters: &PassCounters, native: Counts, json_only: bool) -> Result<(), String> {
        if !within(native) || (json_only && !json_within(native)) {
            return Err(format!("ceiling: {native:?}"));
        }
        let checks = [
            ("metadata", u64::from(counters.stat_calls), native.metadata),
            ("opens", u64::from(counters.directory_opens), native.opens),
            ("yields", u64::from(counters.entries), native.yields),
        ];
        for (what, charged, seen) in checks {
            if charged != seen {
                return Err(format!(
                    "{what}: charged {charged}, native {seen}: {native:?}"
                ));
            }
        }
        if json_only && counters.bytes_read != native.bytes {
            return Err(format!(
                "bytes: charged {}, native {}: {native:?}",
                counters.bytes_read, native.bytes
            ));
        }
        if !json_only && counters.bytes_read > native.bytes {
            return Err(format!(
                "bytes: {} payload bytes materialized from {} raw bytes read: {native:?}",
                counters.bytes_read, native.bytes
            ));
        }
        Ok(())
    }

    fn driven(
        engine: &mut Engine,
        observer: &Observer,
        json_only: bool,
        now_ms: i64,
    ) -> (PassReport, Counts) {
        observer.begin_pass();
        let report = engine.pass(enabled(), now_ms);
        let seen = observer.snapshot();
        if let Err(error) = reconcile(&report.counters, seen, json_only) {
            panic!("independent physical detector rejected the pass: {error}\n{report:?}");
        }
        assert_bounded(&report);
        (report, seen)
    }

    /// A child that has not finished by then is killed and the test fails.
    const CHILD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

    unsafe extern "C" {
        fn kill(pid: c_int, signal: c_int) -> c_int;
    }

    /// Runs `name` as the only test of a re-executed copy of this binary (`--test-threads=1`),
    /// bounded by [`CHILD_TIMEOUT`].
    pub fn run_child(name: &str) -> TestResult {
        let child = Command::new(std::env::current_exe()?)
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, name)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        let pid = c_int::try_from(child.id())?;
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(child.wait_with_output());
        });
        let output = match finished.recv_timeout(CHILD_TIMEOUT) {
            Ok(output) => output?,
            Err(_) => {
                // SAFETY: SIGKILL to the child this function spawned.
                unsafe { kill(pid, 9) };
                let _ = finished.recv();
                return Err(
                    format!("{name} child exceeded {CHILD_TIMEOUT:?} and was killed").into(),
                );
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{name} child failed ({}):\n{stdout}\n{stderr}",
            output.status
        );
        assert!(
            stdout.contains("running 1 test") && stdout.contains("1 passed"),
            "{name} child did not run its test:\n{stdout}"
        );
        for line in stdout.lines() {
            if let Some(start) = line.find("PHYSICAL ") {
                println!("{}", &line[start..]);
            }
        }
        Ok(())
    }

    pub fn is_child(name: &str) -> bool {
        std::env::var_os(CHILD_ENV).is_some_and(|value| value == name)
    }

    fn c_path(path: &Path) -> TestResult<CString> {
        Ok(CString::new(path.as_os_str().as_bytes())?)
    }

    /// Opens the stream, drains it once per round and rewinds: each round yields every non-dot
    /// entry again, which is the only way to reach 20,000 yields from a one-entry directory.
    fn native_yields(directory: &Path, rounds: u64) -> TestResult {
        let path = c_path(directory)?;
        // SAFETY: `path` is NUL-terminated; the stream is closed below and used only here.
        let stream = unsafe { opendir(path.as_ptr()) };
        assert!(!stream.is_null(), "opendir {}", directory.display());
        for _ in 0..rounds {
            // SAFETY: `stream` is live; readdir returns NULL at the end.
            while !unsafe { readdir(stream) }.is_null() {}
            // SAFETY: `stream` is live.
            unsafe { rewinddir(stream) };
        }
        // SAFETY: `stream` is live and closed exactly once.
        assert_eq!(unsafe { closedir(stream) }, 0);
        Ok(())
    }

    pub fn observer_child() -> TestResult {
        let roots = Roots::new()?;
        let (source, analytics) = (roots.source.clone(), roots.data.clone());
        fs::create_dir(&analytics)?;
        let file = source.join("file.txt");
        let missing = source.join("absent-control");
        fs::write(&file, b"hello")?;
        fs::write(analytics.join("file.txt"), b"hello")?;
        fs::create_dir(source.join("one"))?;
        fs::write(source.join("one/entry"), [])?;
        fs::write(source.join("sparse.bin"), [])?;
        fs::File::options()
            .write(true)
            .open(source.join("sparse.bin"))?
            .set_len(67_108_865)?;
        let database = source.join("opencode.db");
        let mut writer = live_database(&database, &[&v2_row("chain", 10)])?;
        let canonical_database = database.canonicalize()?;

        let observer = Observer::start(&source);
        let only = |metadata, bytes| Counts {
            metadata,
            bytes,
            ..Counts::default()
        };

        // Native positives: metadata, descriptor reads and directory streams of the source.
        observer.begin_pass();
        fs::symlink_metadata(&file)?;
        assert_eq!(observer.snapshot(), only(1, 0));
        observer.begin_pass();
        let mut handle = fs::File::open(&file)?;
        let mut five = [0_u8; 5];
        handle.read_exact(&mut five)?;
        assert_eq!(handle.metadata()?.len(), 5);
        assert_eq!(observer.snapshot(), only(1, 5));
        drop(handle);
        observer.begin_pass();
        let names = fs::read_dir(&source)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        let seen = observer.snapshot();
        assert_eq!(
            (seen.opens, seen.yields, seen.held, seen.peak),
            (1, names.len() as u64, 0, 1),
            "{seen:?}"
        );

        // Analytics (a sibling of the source root) is never attributed to the source.
        observer.begin_pass();
        fs::symlink_metadata(analytics.join("file.txt"))?;
        fs::read(analytics.join("file.txt"))?;
        let _ = fs::read_dir(&analytics)?.count();
        assert_eq!(observer.snapshot(), Counts::default());

        // `fstatat`: a source descriptor decides only for a relative path; an absolute analytics
        // path through it, and an absolute source path through any descriptor, follow the path.
        let directory = fs::File::open(&source)?;
        directory.metadata()?;
        let fd = directory.as_raw_fd();
        let mut buffer = [0_u64; 32];
        let at = |dir: c_int, path: &CString, buffer: &mut [u64; 32]| {
            // SAFETY: `path` is NUL-terminated and `buffer` exceeds sizeof(struct stat).
            unsafe { fstatat(dir, path.as_ptr(), buffer.as_mut_ptr().cast(), 0) }
        };
        observer.begin_pass();
        assert_eq!(at(fd, &CString::new("file.txt")?, &mut buffer), 0);
        assert_eq!(observer.snapshot().metadata, 1, "relative to source dirfd");
        assert_eq!(
            at(fd, &c_path(&analytics.join("file.txt"))?, &mut buffer),
            0
        );
        assert_eq!(
            observer.snapshot().metadata,
            1,
            "absolute analytics path through a source dirfd"
        );
        assert_eq!(at(-2, &c_path(&file)?, &mut buffer), 0);
        assert_eq!(
            observer.snapshot().metadata,
            2,
            "absolute source path, AT_FDCWD"
        );
        drop(directory);

        // Ancestor probes count only inside a Focus window.
        observer.begin_pass();
        fs::symlink_metadata("/")?;
        assert_eq!(observer.snapshot().metadata, 0);
        {
            let _focus = Focus::enter();
            fs::symlink_metadata("/")?;
        }
        fs::symlink_metadata("/")?;
        assert_eq!(observer.snapshot().metadata, 1);

        // errno and return values are preserved through the observer.
        observer.begin_pass();
        let absent = fs::symlink_metadata(&missing).expect_err("absent control exists");
        assert_eq!(absent.kind(), std::io::ErrorKind::NotFound);
        let mut directory_handle = fs::File::open(&source)?;
        let refused = directory_handle
            .read(&mut [0_u8; 4])
            .expect_err("directory read");
        assert_eq!(
            refused.raw_os_error(),
            Some(21),
            "EISDIR through the read hook"
        );
        assert_eq!(observer.snapshot(), only(1, 0));
        drop(directory_handle);

        // A tracked descriptor stays source after its pathname leaves the source root.
        let mut moved = fs::File::open(&file)?;
        moved.metadata()?;
        fs::rename(&file, analytics.join("moved.txt"))?;
        observer.begin_pass();
        moved.read_exact(&mut five)?;
        assert_eq!(observer.snapshot(), only(0, 5));
        drop(moved);
        fs::rename(analytics.join("moved.txt"), &file)?;
        assert!(observer.clean(), "closing a tracked descriptor releases it");

        // Controls: charge without native work, and native work without a charge, must both be
        // rejected by the same detector that accepts matching work.
        let matched =
            |counters: &PassCounters, json: bool| reconcile(counters, observer.snapshot(), json);
        let rejects = |outcome: Result<(), String>, dimension: &str| {
            let error = outcome.expect_err("the independent detector accepted a false pass");
            assert!(error.starts_with(dimension), "{error}");
        };
        let mut counters = PassCounters::default();
        observer.begin_pass();
        charge_metadata(&mut counters)?;
        assert_eq!(counters.stat_calls, 1);
        rejects(matched(&counters, false), "metadata"); // phantom charge
        observer.begin_pass();
        let mut counters = PassCounters::default();
        uncharged_metadata_call(&missing);
        rejects(matched(&counters, false), "metadata"); // production uncharged-call control
        observer.begin_pass();
        let _ = fs::symlink_metadata(&missing);
        rejects(matched(&counters, false), "metadata"); // raw std uncharged call
        observer.begin_pass();
        charge_metadata(&mut counters)?;
        let _ = fs::symlink_metadata(&missing);
        matched(&counters, false).expect("matching charge and native call");
        observer.begin_pass();
        let phantom = PassCounters {
            directory_opens: 1,
            ..PassCounters::default()
        };
        rejects(matched(&phantom, false), "opens");
        observer.begin_pass();
        let _ = fs::read_dir(&source)?.count();
        rejects(matched(&PassCounters::default(), false), "opens");
        let opened = PassCounters {
            directory_opens: 1,
            ..PassCounters::default()
        };
        rejects(matched(&opened, false), "yields");
        let yielded = PassCounters {
            directory_opens: 1,
            entries: u32::try_from(names.len())?,
            ..PassCounters::default()
        };
        matched(&yielded, false).expect("matching directory work");
        observer.begin_pass();
        let phantom_bytes = PassCounters {
            bytes_read: 5,
            ..PassCounters::default()
        };
        rejects(matched(&phantom_bytes, true), "bytes");
        let mut reread = fs::File::open(&file)?;
        reread.read_exact(&mut five)?;
        drop(reread);
        rejects(matched(&PassCounters::default(), true), "bytes");
        let read_bytes = PassCounters {
            bytes_read: 5,
            ..PassCounters::default()
        };
        matched(&read_bytes, true).expect("matching charged and native read bytes");

        // Literal endpoints on the pure predicate.
        let base = Counts::default();
        for (accepted, rejected) in [
            (
                Counts {
                    metadata: 40_000,
                    ..base
                },
                Counts {
                    metadata: 40_001,
                    ..base
                },
            ),
            (Counts { opens: 64, ..base }, Counts { opens: 65, ..base }),
            (Counts { peak: 8, ..base }, Counts { peak: 9, ..base }),
            (
                Counts {
                    yields: 20_000,
                    ..base
                },
                Counts {
                    yields: 20_001,
                    ..base
                },
            ),
            (
                Counts {
                    writable: 0,
                    ..base
                },
                Counts {
                    writable: 1,
                    ..base
                },
            ),
        ] {
            assert!(within(accepted), "{accepted:?}");
            assert!(!within(rejected), "{rejected:?}");
        }
        let (accepted, rejected) = (
            Counts {
                bytes: 67_108_864,
                ..base
            },
            Counts {
                bytes: 67_108_865,
                ..base
            },
        );
        assert!(json_within(accepted), "{accepted:?}");
        assert!(!json_within(rejected), "{rejected:?}");
        assert!(within(accepted) && within(rejected), "common ceilings only");
        assert!(!within(Counts {
            coverage_faults: 1,
            ..base
        }));

        // The same endpoints reached by real native work.
        observer.begin_pass();
        for _ in 0..40_000 {
            let _ = fs::symlink_metadata(&file);
        }
        assert!(within(observer.snapshot()) && observer.snapshot().metadata == 40_000);
        let _ = fs::symlink_metadata(&file);
        assert!(!within(observer.snapshot()), "40,001st metadata call");

        observer.begin_pass();
        for _ in 0..64 {
            drop(fs::read_dir(&source)?);
        }
        assert!(within(observer.snapshot()) && observer.snapshot().opens == 64);
        drop(fs::read_dir(&source)?);
        assert!(!within(observer.snapshot()), "65th directory stream open");

        observer.begin_pass();
        let mut held = Vec::new();
        for _ in 0..8 {
            held.push(fs::read_dir(&source)?);
        }
        assert!(within(observer.snapshot()));
        assert_eq!((observer.snapshot().held, observer.snapshot().peak), (8, 8));
        held.push(fs::read_dir(&source)?);
        assert!(
            !within(observer.snapshot()),
            "9th simultaneously held stream"
        );
        held.clear();
        assert_eq!(observer.snapshot().held, 0);
        assert!(observer.clean());

        observer.begin_pass();
        native_yields(&source.join("one"), 20_000)?;
        assert_eq!(observer.snapshot().yields, 20_000);
        assert!(within(observer.snapshot()));
        native_yields(&source.join("one"), 1)?;
        assert!(!within(observer.snapshot()), "20,001st yielded result");

        observer.begin_pass();
        let mut sparse = fs::File::open(source.join("sparse.bin"))?;
        let mut chunk = vec![0_u8; 1024 * 1024];
        for _ in 0..64 {
            sparse.read_exact(&mut chunk)?;
        }
        assert_eq!(observer.snapshot().bytes, 67_108_864);
        assert!(json_within(observer.snapshot()));
        sparse.read_exact(&mut chunk[..1])?;
        assert_eq!(observer.snapshot().bytes, 67_108_865);
        assert!(
            !json_within(observer.snapshot()),
            "67,108,865th read byte is over the JSON ceiling"
        );
        assert!(
            within(observer.snapshot()),
            "the same raw bytes are not a ceiling for any other acquisition"
        );
        drop(sparse);

        // Linked SQLite chain: the bundled C code's own stat/fstat/pread calls reach the observer
        // beneath the production syscall hooks. The meter counts what those hooks charged.
        observer.begin_pass();
        let meter = MetadataMeter::begin(10_000);
        let rows: i64 = {
            let connection = window(|| open_canonical(&canonical_database))
                .map_err(|error| format!("{error:?}"))?;
            connection.query_row("SELECT COUNT(*) FROM session_v2", [], |row| row.get(0))?
        };
        let (charged, refused) = meter.state();
        drop(meter);
        let chain = observer.snapshot();
        assert_eq!(rows, 1);
        assert!(!refused && charged > 0, "{charged}");
        assert_eq!(
            chain.metadata,
            u64::from(charged),
            "SQLite callback chain: native {chain:?} versus charged {charged}"
        );
        assert!(
            chain.bytes >= 4096,
            "SQLite page reads were not observed: {chain:?}"
        );
        println!("PHYSICAL sqlite-chain charged={charged} native={chain:?}");

        assert!(observer.clean(), "handles dropped while armed");
        drop(observer);

        // Foreign-thread source work and table overflow are coverage faults, never clamped.
        let observer = Observer::start(&source);
        std::thread::scope(|scope| {
            scope
                .spawn(|| fs::symlink_metadata(&file))
                .join()
                .expect("foreign thread")
        })?;
        assert!(observer.snapshot().coverage_faults > 0);
        assert!(!within(observer.snapshot()) && !observer.clean());
        drop(observer);
        let observer = Observer::start(&source);
        let flood = (0..129)
            .map(|_| fs::read_dir(&source))
            .collect::<std::io::Result<Vec<_>>>()?;
        assert!(
            observer.snapshot().coverage_faults > 0,
            "128-stream table overflow"
        );
        assert!(!within(observer.snapshot()));
        drop(flood);
        drop(observer);

        writer.stop()?;
        println!("PHYSICAL observer controls complete");
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // Effective-access controls: the observer reads each source descriptor's kernel access mode
    // on every call made through it, so a descriptor opened for writing is red whichever library
    // opened it and whichever call is made, and the same calls on a read-only descriptor are green.
    // -----------------------------------------------------------------------------------------

    #[repr(C)]
    struct Vector {
        base: *mut c_void,
        length: usize,
    }

    unsafe extern "C" {
        fn preadv(fd: c_int, vectors: *const Vector, count: c_int, offset: i64) -> isize;
        fn dirfd(stream: *mut c_void) -> c_int;
        fn close(fd: c_int) -> c_int;
        fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
        fn stat(path: *const c_char, buffer: *mut c_void) -> c_int;
        fn access(path: *const c_char, mode: c_int) -> c_int;
        fn readlink(path: *const c_char, buffer: *mut c_char, size: usize) -> isize;
        fn readdir_r(stream: *mut c_void, entry: *mut c_void, result: *mut *mut c_void) -> c_int;
        fn __error() -> *mut c_int;
        fn getrlimit(resource: c_int, limit: *mut Rlimit) -> c_int;
        fn setrlimit(resource: c_int, limit: *const Rlimit) -> c_int;
    }

    #[repr(C)]
    struct Rlimit {
        current: u64,
        maximum: u64,
    }

    const RLIMIT_NOFILE: c_int = 8;
    const EBADF: c_int = 9;
    const EINTR: c_int = 4;

    type Operation = fn(&fs::File) -> TestResult;

    fn op_fstat(file: &fs::File) -> TestResult {
        file.metadata()?;
        Ok(())
    }

    fn op_read(file: &fs::File) -> TestResult {
        let mut reader = file;
        let mut buffer = [0_u8; 4];
        assert_eq!(reader.read(&mut buffer)?, 4);
        Ok(())
    }

    fn op_pread(file: &fs::File) -> TestResult {
        use std::os::unix::fs::FileExt;
        let mut buffer = [0_u8; 4];
        assert_eq!(file.read_at(&mut buffer, 1)?, 4);
        Ok(())
    }

    fn op_readv(file: &fs::File) -> TestResult {
        let mut reader = file;
        let (mut first, mut second) = ([0_u8; 2], [0_u8; 2]);
        let mut vectors = [
            std::io::IoSliceMut::new(&mut first),
            std::io::IoSliceMut::new(&mut second),
        ];
        assert_eq!(reader.read_vectored(&mut vectors)?, 4);
        Ok(())
    }

    fn op_preadv(file: &fs::File) -> TestResult {
        let (mut first, mut second) = ([0_u8; 2], [0_u8; 2]);
        let vectors = [
            Vector {
                base: first.as_mut_ptr().cast(),
                length: 2,
            },
            Vector {
                base: second.as_mut_ptr().cast(),
                length: 2,
            },
        ];
        // SAFETY: both vectors point at live two-byte buffers; the descriptor is open.
        let read = unsafe { preadv(file.as_raw_fd(), vectors.as_ptr(), 2, 1) };
        assert_eq!(read, 4);
        Ok(())
    }

    /// Every descriptor call the observer hooks, on a read-only and on a writable descriptor of
    /// the same source file, then on the sidecar kinds, and on a writable descriptor outside the
    /// source.
    fn access_controls(observer: &Observer, source: &Path, analytics: &Path) -> TestResult {
        let plain = source.join("access.bin");
        let wal = source.join("access.db-wal");
        let shm = source.join("access.db-shm");
        let outside = analytics.join("access-outside.bin");
        let open_read = |path: &Path| fs::File::open(path);
        let open_write = |path: &Path| fs::OpenOptions::new().read(true).write(true).open(path);

        let operations: [(&str, Operation, bool); 5] = [
            ("fstat", op_fstat, false),
            ("read", op_read, true),
            ("pread", op_pread, true),
            ("readv", op_readv, true),
            ("preadv", op_preadv, true),
        ];
        for (name, operation, reads) in operations {
            // The call and the close that ends the scope both reach the checker.
            observer.begin_pass();
            {
                let file = open_read(&plain)?;
                operation(&file)?;
            }
            let green = observer.snapshot();
            assert_eq!(green.writable, 0, "{name}: {green:?}");
            assert!(within(green), "{name}: {green:?}");
            assert_eq!(green.bytes > 0, reads, "{name}: {green:?}");
            assert_eq!(observer.reach().other, 2, "{name}");

            observer.begin_pass();
            {
                let file = open_write(&plain)?;
                operation(&file)?;
            }
            let red = observer.snapshot();
            assert_eq!(red.writable, 2, "{name} and its close: {red:?}");
            assert!(!within(red) && !json_within(red), "{name}: {red:?}");
            assert_eq!(observer.reach().other, 2, "{name}");
        }

        // `close` alone, with no other call ever made through the descriptor.
        observer.begin_pass();
        drop(open_write(&plain)?);
        assert_eq!(observer.snapshot().writable, 1);
        observer.begin_pass();
        drop(open_read(&plain)?);
        assert_eq!(observer.snapshot().writable, 0);

        // The sidecar kinds are told apart by the descriptor's own path, and a writable
        // sidecar descriptor is red the same way.
        for (path, kind) in [(&wal, "wal"), (&shm, "shm")] {
            observer.begin_pass();
            {
                let file = open_write(path)?;
                file.metadata()?;
            }
            let (counts, reach) = (observer.snapshot(), observer.reach());
            assert_eq!(counts.writable, 2, "{kind}");
            let expected = if kind == "wal" { (2, 0, 0) } else { (0, 2, 0) };
            assert_eq!((reach.wal, reach.shm, reach.other), expected, "{kind}");
            observer.begin_pass();
            {
                let file = open_read(path)?;
                file.metadata()?;
            }
            assert_eq!(observer.snapshot().writable, 0, "{kind}");
        }

        // A writable descriptor outside the source root is not source work at all.
        observer.begin_pass();
        {
            let file = open_write(&outside)?;
            file.metadata()?;
            op_read(&file)?;
        }
        assert_eq!(observer.snapshot(), Counts::default());
        assert_eq!(observer.reach(), Default::default());

        // A descriptor opened for writing before the pass and used by path-free calls only is
        // still seen while live, and a tracked read-only one is not mistaken for it.
        let held = open_write(&plain)?;
        observer.begin_pass();
        op_read(&held)?;
        assert_eq!(observer.snapshot().writable, 1);
        drop(held);
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // Callback correctness: exact returns and errno, vector reads, stream errors, failed closes,
    // descriptor-table overflow, foreign threads and unwinding, each against the real native
    // functions. No invalid pointer is ever passed: failures are made with a bad descriptor
    // number or with a descriptor closed beneath its (valid) stream.
    // -----------------------------------------------------------------------------------------

    fn errno() -> c_int {
        // SAFETY: errno is thread-local.
        unsafe { *__error() }
    }

    fn set_errno(value: c_int) {
        // SAFETY: errno is thread-local.
        unsafe { *__error() = value };
    }

    /// Return value and errno of `call` with errno preset to `preset`.
    fn returning(preset: c_int, call: impl FnOnce() -> isize) -> (isize, c_int) {
        set_errno(preset);
        let result = call();
        (result, errno())
    }

    fn native_symbol(name: &std::ffi::CStr) -> usize {
        // SAFETY: RTLD_NEXT (-1) resolves the definition after this executable's, i.e. libsystem's.
        let found = unsafe { dlsym((-1_isize) as *mut c_void, name.as_ptr()) };
        assert!(!found.is_null(), "no native {name:?}");
        found as usize
    }

    fn exact_returns_and_errno(source: &Path, outside: &Path) -> TestResult {
        type StatFn = unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int;
        type AccessFn = unsafe extern "C" fn(*const c_char, c_int) -> c_int;
        type ReadlinkFn = unsafe extern "C" fn(*const c_char, *mut c_char, usize) -> isize;
        // SAFETY: each address is the libsystem definition of exactly this C signature.
        let (native_stat, native_access, native_readlink) = unsafe {
            (
                std::mem::transmute::<usize, StatFn>(native_symbol(c"stat")),
                std::mem::transmute::<usize, AccessFn>(native_symbol(c"access")),
                std::mem::transmute::<usize, ReadlinkFn>(native_symbol(c"readlink")),
            )
        };
        let mut buffer = [0_u64; 32];
        let mut link = [0 as c_char; 64];
        let paths = [
            source.join("file.txt"),
            source.join("absent-control"),
            outside.to_path_buf(),
            outside.join("absent-control"),
        ];
        for path in &paths {
            let c = c_path(path)?;
            let pointer = buffer.as_mut_ptr().cast::<c_void>();
            // SAFETY (all calls): `c` is NUL-terminated and the buffers outlast the calls.
            let hooked = returning(EINTR, || unsafe { stat(c.as_ptr(), pointer) } as isize);
            let bare = returning(EINTR, || unsafe { native_stat(c.as_ptr(), pointer) }
                as isize);
            assert_eq!(hooked, bare, "stat {}", path.display());
            let hooked = returning(EINTR, || unsafe { access(c.as_ptr(), 0) } as isize);
            let bare = returning(EINTR, || unsafe { native_access(c.as_ptr(), 0) } as isize);
            assert_eq!(hooked, bare, "access {}", path.display());
            let hooked = returning(EINTR, || unsafe {
                readlink(c.as_ptr(), link.as_mut_ptr(), 64)
            });
            let bare = returning(EINTR, || unsafe {
                native_readlink(c.as_ptr(), link.as_mut_ptr(), 64)
            });
            assert_eq!(hooked, bare, "readlink {}", path.display());
        }
        // A failure keeps the native errno, a success leaves the caller's untouched.
        let missing = c_path(&source.join("absent-control"))?;
        let present = c_path(&source.join("file.txt"))?;
        let pointer = buffer.as_mut_ptr().cast::<c_void>();
        // SAFETY: as above.
        assert_eq!(
            returning(EINTR, || unsafe { stat(missing.as_ptr(), pointer) }
                as isize),
            (-1, 2)
        );
        assert_eq!(
            returning(EINTR, || unsafe { stat(present.as_ptr(), pointer) }
                as isize),
            (0, EINTR)
        );
        Ok(())
    }

    fn vector_reads_are_counted(observer: &Observer, file: &Path) -> TestResult {
        observer.begin_pass();
        let handle = fs::File::open(file)?; // "hello"
        let mut reader = &handle;
        {
            let (mut first, mut second) = ([0_u8; 3], [0_u8; 3]);
            let mut slices = [
                std::io::IoSliceMut::new(&mut first),
                std::io::IoSliceMut::new(&mut second),
            ];
            assert_eq!(reader.read_vectored(&mut slices)?, 5, "readv");
        }
        let (mut first, mut second) = ([0_u8; 3], [0_u8; 3]);
        let vectors = [
            Vector {
                base: first.as_mut_ptr().cast(),
                length: 3,
            },
            Vector {
                base: second.as_mut_ptr().cast(),
                length: 3,
            },
        ];
        assert_eq!(observer.snapshot().bytes, 5);
        // SAFETY: the vectors point at live buffers of the stated lengths.
        let read = unsafe { preadv(handle.as_raw_fd(), vectors.as_ptr(), 2, 1) };
        assert_eq!(read, 4, "preadv at offset 1");
        assert_eq!(observer.snapshot().bytes, 9);
        // End of file: zero bytes, nothing counted.
        // SAFETY: as above.
        assert_eq!(
            unsafe { preadv(handle.as_raw_fd(), vectors.as_ptr(), 2, 5) },
            0
        );
        assert_eq!(observer.snapshot().bytes, 9);
        Ok(())
    }

    /// A stream whose descriptor was closed beneath it: a real native read error on valid
    /// pointers, reported by `readdir` through errno and by `readdir_r` through its return value.
    fn stream_read_errors(directory: &Path) -> TestResult {
        let path = c_path(directory)?;
        // SAFETY: `path` is NUL-terminated.
        let stream = unsafe { opendir(path.as_ptr()) };
        assert!(!stream.is_null());
        // SAFETY: `stream` is a live DIR*.
        let descriptor = unsafe { dirfd(stream) };
        // SAFETY: the number is a descriptor this thread owns; the stream keeps its dangling copy.
        assert_eq!(unsafe { close(descriptor) }, 0);
        let (entry, error) = returning(EINTR, || {
            // SAFETY: `stream` is still a valid DIR*; its descriptor is gone, so the read fails.
            unsafe { readdir(stream) as isize }
        });
        assert_eq!(
            (entry, error),
            (0, EBADF),
            "readdir on a vanished descriptor"
        );
        let mut record = [0_u64; 140];
        let mut result = std::ptr::null_mut();
        // SAFETY: `record` exceeds sizeof(struct dirent); `result` is a valid out-pointer.
        let code = unsafe { readdir_r(stream, record.as_mut_ptr().cast(), &mut result) };
        assert_eq!(
            code, EBADF,
            "readdir_r reports the error as its return value"
        );
        // SAFETY: the stream is valid and closed exactly once; its descriptor is already gone,
        // so the close fails and the stream is freed regardless.
        let closed = unsafe { closedir(stream) };
        assert_ne!(closed, 0, "closing a vanished descriptor must fail");
        Ok(())
    }

    fn raise_descriptor_limit(wanted: u64) -> TestResult {
        let mut limit = Rlimit {
            current: 0,
            maximum: 0,
        };
        // SAFETY: `limit` is a valid out-pointer.
        assert_eq!(unsafe { getrlimit(RLIMIT_NOFILE, &mut limit) }, 0);
        if limit.current < wanted {
            limit.current = wanted.min(limit.maximum);
            // SAFETY: `limit` is a valid in-pointer.
            assert_eq!(unsafe { setrlimit(RLIMIT_NOFILE, &limit) }, 0, "setrlimit");
        }
        assert!(
            limit.current >= wanted,
            "descriptor limit {}",
            limit.current
        );
        Ok(())
    }

    pub fn callback_faults_child() -> TestResult {
        let roots = Roots::new()?;
        let (source, analytics) = (roots.source.clone(), roots.data.clone());
        fs::create_dir(&analytics)?;
        let file = source.join("file.txt");
        fs::write(&file, b"hello")?;
        fs::write(analytics.join("file.txt"), b"hello")?;
        fs::create_dir(source.join("one"))?;
        fs::write(source.join("one/entry"), [])?;
        for name in ["access.bin", "access.db-wal", "access.db-shm"] {
            fs::write(source.join(name), b"0123456789")?;
        }
        fs::write(analytics.join("access-outside.bin"), b"0123456789")?;
        raise_descriptor_limit(4_096)?;

        // Exact returns and errno: hooked calls equal the bare native calls, hit or not.
        let observer = Observer::start(&source);
        exact_returns_and_errno(&source, &analytics.join("file.txt"))?;
        // A clean end of a stream restores the caller's errno; an entry leaves it alone.
        let path = c_path(&source.join("one"))?;
        // SAFETY: `path` is NUL-terminated; the stream is used and closed here only.
        let stream = unsafe { opendir(path.as_ptr()) };
        assert!(!stream.is_null());
        observer.begin_pass();
        let mut entries = 0;
        loop {
            let (entry, after) = returning(EINTR, || {
                // SAFETY: `stream` is live.
                unsafe { readdir(stream) as isize }
            });
            assert_eq!(after, EINTR, "readdir must leave the caller's errno alone");
            if entry == 0 {
                break;
            }
            entries += 1;
        }
        assert_eq!(entries, 3, "., .. and the entry");
        assert_eq!(observer.snapshot().yields, 1);
        // SAFETY: `stream` is live and closed once.
        assert_eq!(unsafe { closedir(stream) }, 0);
        vector_reads_are_counted(&observer, &file)?;
        access_controls(&observer, &source, &analytics)?;
        assert!(observer.clean(), "all handles dropped while armed");
        drop(observer);

        // A close that fails is a coverage fault, with the native return and errno intact.
        let observer = Observer::start(&source);
        {
            let _focus = Focus::enter();
            let (result, error) = returning(0, || {
                // SAFETY: -1 is not a descriptor; the call fails with EBADF and touches nothing.
                unsafe { close(-1) as isize }
            });
            assert_eq!((result, error), (-1, EBADF));
            let (result, error) = returning(0, || {
                // SAFETY: as above, with a number no test descriptor reaches.
                unsafe { close(1_000_000) as isize }
            });
            assert_eq!((result, error), (-1, EBADF));
        }
        assert!(observer.snapshot().coverage_faults >= 2);
        assert!(!within(observer.snapshot()) && !observer.clean());
        drop(observer);

        // A stream read error is a yielded result (errno-exact), a failed closedir a fault.
        let observer = Observer::start(&source);
        observer.begin_pass();
        stream_read_errors(&source.join("one"))?;
        let seen = observer.snapshot();
        assert_eq!(seen.yields, 2, "{seen:?}");
        assert!(seen.coverage_faults > 0, "{seen:?}");
        drop(observer);

        // 1,025 tracked descriptors overflow the 1,024-entry table: a fault, never a clamp.
        let observer = Observer::start(&source);
        let mut held = Vec::new();
        for _ in 0..1_025 {
            let handle = fs::File::open(&file)?;
            handle.metadata()?;
            held.push(handle);
        }
        assert_eq!(
            observer.snapshot().coverage_faults,
            1,
            "{:?}",
            observer.snapshot()
        );
        assert!(!within(observer.snapshot()));
        held.clear();
        drop(observer);
        // 1,024 fit exactly.
        let observer = Observer::start(&source);
        for _ in 0..1_024 {
            let handle = fs::File::open(&file)?;
            handle.metadata()?;
            held.push(handle);
        }
        assert_eq!(observer.snapshot().coverage_faults, 0);
        held.clear();
        assert!(observer.clean());
        drop(observer);

        // A descriptor used from a foreign thread is a fault, whatever it reads.
        let observer = Observer::start(&source);
        std::thread::scope(|scope| scope.spawn(|| fs::read(&file)).join().expect("thread"))?;
        assert!(observer.snapshot().coverage_faults > 0);
        assert!(!within(observer.snapshot()));
        drop(observer);

        // Dropping an armed observer during unwinding disarms it: a fresh one arms cleanly.
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _armed = Observer::start(&source);
            let _ = fs::symlink_metadata(&file);
            panic!("unwinding while the observer is armed");
        }));
        assert!(unwound.is_err());
        let observer = Observer::start(&source);
        assert_eq!(observer.snapshot(), Counts::default());
        assert!(observer.clean());
        drop(observer);

        println!("PHYSICAL callback faults complete");
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // The metadata ceiling reached at the second `fstat` of the production hook.
    // -----------------------------------------------------------------------------------------

    use std::cell::Cell;
    use std::rc::Rc;

    use crate::support::vfs_probe::kernel::{DEFAULT_LIMITS, FstatFailure, Limits, SyscallProbe};

    #[derive(Debug)]
    struct Run {
        native: Counts,
        trace: Vec<(Meta, c_int)>,
        used: u32,
        refused: bool,
        rows: Option<i64>,
        failures: Vec<FstatFailure>,
        /// The probe's receipts were complete and error free when the run ended: no dropped
        /// receipt, no observation fault. Every consumer of `failures` must check it.
        observation: Result<(), String>,
    }

    /// One open-and-query of the database under a physical allowance, observed independently.
    fn bounded_read(
        observer: &Observer,
        probe: &SyscallProbe,
        database: &Path,
        allowance: u32,
    ) -> Run {
        let before = probe.events().fstat_failures.len();
        observer.begin_pass();
        let meter = MetadataMeter::begin(allowance);
        let rows = window(|| -> Result<i64, String> {
            let connection = open_canonical(database).map_err(|error| format!("{error:?}"))?;
            connection
                .query_row("SELECT COUNT(*) FROM session_v2", [], |row| row.get(0))
                .map_err(|error| error.to_string())
        });
        let (used, refused) = meter.state();
        drop(meter);
        let events = probe.events();
        Run {
            native: observer.snapshot(),
            trace: observer.trace(),
            used,
            refused,
            rows: rows.ok(),
            failures: events
                .fstat_failures
                .get(before..)
                .unwrap_or_default()
                .to_vec(),
            observation: events.checked(),
        }
    }

    /// State the squeezing filesystem shares with the test that drives it.
    #[derive(Default)]
    struct Shared {
        /// Allowance to impose on the next SQLite stage.
        allowance: Cell<Option<u32>>,
        /// Native metadata count when that stage began.
        started: Cell<Option<u64>>,
        /// Native metadata the stage consumed, once it ended.
        native: Cell<Option<u64>>,
    }

    /// Source filesystem that squeezes the next SQLite stage to exactly `allowance` physical
    /// metadata operations (by pre-spending the pass budget just before the stage begins) and
    /// measures the native metadata the independent observer saw during that stage.
    struct Squeezed {
        inner: ObservedFs<RecordingFs>,
        observer: Rc<Observer>,
        shared: Rc<Shared>,
    }

    impl Squeezed {
        /// The first source request after the read ends the stage (the identity proof when the
        /// read finished, the pass's own root check when it was refused): everything the
        /// observer saw since the stage began belongs to the stage.
        fn end_stage(&self) {
            if let Some(start) = self.shared.started.get()
                && self.shared.native.get().is_none()
            {
                self.shared
                    .native
                    .set(Some(self.observer.snapshot().metadata - start));
            }
        }
    }

    impl SourceFs for Squeezed {
        fn canonicalize(&self, p: &Path, c: &mut PassCounters) -> std::io::Result<PathBuf> {
            self.end_stage();
            self.inner.canonicalize(p, c)
        }
        fn metadata(&self, p: &Path, c: &mut PassCounters) -> std::io::Result<fs::Metadata> {
            self.end_stage();
            let result = self.inner.metadata(p, c);
            // The last request before the stage is the journal probe of the preflight.
            if p.as_os_str().as_bytes().ends_with(b"-journal")
                && let Some(allowance) = self.shared.allowance.take()
            {
                let spent = MAX_METADATA_CALLS - 4 - allowance;
                c.stat_calls = c.stat_calls.max(spent);
            }
            result
        }
        fn read_dir(&self, p: &Path, c: &mut PassCounters) -> std::io::Result<DirEntries> {
            self.end_stage();
            self.inner.read_dir(p, c)
        }
        fn read_header(&self, p: &Path, c: &mut PassCounters) -> std::io::Result<Vec<u8>> {
            self.end_stage();
            self.inner.read_header(p, c)
        }
        fn read_bounded(
            &self,
            p: &Path,
            n: usize,
            c: &mut PassCounters,
        ) -> std::io::Result<BoundedRead> {
            self.end_stage();
            self.inner.read_bounded(p, n, c)
        }
        fn open_sqlite(&self, p: &Path) -> Result<Connection, OpenError> {
            self.shared
                .started
                .set(Some(self.observer.snapshot().metadata));
            self.shared.native.set(None);
            self.inner.open_sqlite(p)
        }
    }

    /// A refused SQLite stage is a budget stop: the pass is catching up (not consistent, partial
    /// or unavailable), carries no failure code and committed nothing.
    fn budget_stop(report: &PassReport) -> Result<(), String> {
        if report.outcome != PassOutcome::CatchingUp
            || report.failure.is_some()
            || report.records_committed != 0
        {
            return Err(format!("not a budget stop: {report:?}"));
        }
        Ok(())
    }

    pub fn second_fstat_refusal_child() -> TestResult {
        // Direct boundary: open and read under every allowance from zero to the full cost. The
        // receipt buffer is sized for the whole sweep and every run checks it was not exceeded:
        // a dropped receipt would make a later allowance look like one that failed no fstat.
        let roots = Roots::new()?;
        let database = roots.source.join("opencode.db");
        let mut writer = live_database(&database, &[&v2_row("chain", 10)])?;
        let canonical = database.canonicalize()?;
        let sweep_limits = Limits {
            fstat_failures: 4096,
            ..DEFAULT_LIMITS
        };
        let probe = SyscallProbe::start_fstat_only_with(sweep_limits)?;
        let observer = Observer::start(&roots.source);
        bounded_read(&observer, &probe, &canonical, 10_000); // first-use initialisation
        let full = bounded_read(&observer, &probe, &canonical, 10_000);
        assert!(!full.refused && full.rows == Some(1), "{full:?}");
        assert!(full.failures.is_empty(), "{full:?}");
        assert_eq!(full.observation, Ok(()), "{full:?}");
        let total = full.used;
        assert_eq!(full.native.metadata, u64::from(total), "{full:?}");
        assert!(full.trace.len() < 512, "trace table too small: {full:?}");

        let (mut second, mut first, mut errors) = (0, 0, Vec::new());
        let (mut consumed, mut widest) = (0_usize, (0_usize, 0_u32));
        for allowance in 0..=total {
            let run = bounded_read(&observer, &probe, &canonical, allowance);
            assert_eq!(run.observation, Ok(()), "allowance {allowance}: {run:?}");
            consumed += run.failures.len();
            if run.failures.len() > widest.0 {
                widest = (run.failures.len(), allowance);
            }
            assert!(within(run.native), "allowance {allowance}: {run:?}");
            assert!(
                run.native.metadata <= u64::from(allowance),
                "native work above the allowance {allowance}: {run:?}"
            );
            assert_eq!(
                run.native.metadata,
                u64::from(run.used),
                "{allowance}: {run:?}"
            );
            if allowance == total {
                assert!(!run.refused && run.rows == Some(1), "{run:?}");
                assert!(run.failures.is_empty(), "{run:?}");
                continue;
            }
            // A refusal flags the read for the engine to discard. Early ones also fail the
            // connection; a late one (while the connection closes) leaves a readable result that
            // is still flagged, so it is never published.
            assert!(run.refused, "allowance {allowance}: {run:?}");
            assert!(
                run.rows.is_none() || run.native.bytes > 0,
                "allowance {allowance}: {run:?}"
            );
            assert_eq!(
                run.trace,
                full.trace[..run.trace.len()],
                "deterministic prefix"
            );
            // A refusal inside the parent's fstat hook surfaces at the shared boundary as a
            // failing fstat, whatever stale errno it carries. The native work the first failing
            // call did says where it was refused: none, before its first fstat; one, between the
            // hook's two fstats (the second was refused before it ran). Every later fstat finds
            // the allowance spent and is refused before it runs; the count stays small, so
            // SQLite does not retry in a loop.
            if let Some(failure) = run.failures.first() {
                assert!(run.failures.len() <= 8, "{allowance}: {run:?}");
                errors.push(failure.errno);
                match failure.native_delta {
                    0 => first += 1,
                    1 => second += 1,
                    other => panic!("{allowance}: {other} native fstats in a refused call"),
                }
                for later in &run.failures[1..] {
                    assert_eq!(later.native_delta, 0, "{allowance}: {run:?}");
                }
                // A refusal never reaches the kernel, so it sets the errno itself: a stale one
                // (here ENOENT from an earlier probe) could be one that a caller retries.
                for failure in &run.failures {
                    assert_eq!(failure.errno, EBADF, "{allowance}: {run:?}");
                    assert!(!failure.foreign, "{allowance}: {run:?}");
                }
            }
        }
        assert!(
            second > 0,
            "no allowance ended between the hook's two fstats"
        );
        assert!(
            first > 0,
            "no allowance ended before the hook's first fstat"
        );
        errors.sort_unstable();
        errors.dedup();
        println!(
            "PHYSICAL second-fstat: total={total} refused-at-second-fstat={second} refused-before-first-fstat={first} errno-values={errors:?}"
        );
        // Every failing fstat the probe kept was consumed by exactly one run, and the probe
        // restores cleanly: a sticky fault or a failed restoration fails here, not silently.
        let events = probe.finish()?;
        assert_eq!(events.fstat_failures.len(), consumed);

        // Receipt ceilings against the real refusal sequence of the widest allowance: a buffer of
        // exactly its length keeps every failing fstat; one slot fewer drops one, and both the
        // run's observation and the probe's restoration say so.
        let (cap, allowance) = widest;
        assert!(cap >= 2, "widest refused sequence: {widest:?}");
        for (limit, overflows) in [(cap, false), (cap - 1, true)] {
            let capped = Limits {
                fstat_failures: limit,
                ..DEFAULT_LIMITS
            };
            let probe = SyscallProbe::start_fstat_only_with(capped)?;
            let run = bounded_read(&observer, &probe, &canonical, allowance);
            assert_eq!(run.failures.len(), limit, "limit {limit}: {run:?}");
            assert_eq!(
                run.observation.is_err(),
                overflows,
                "limit {limit}: {run:?}"
            );
            if let Err(error) = &run.observation {
                assert!(error.contains("overflow"), "{error}");
            }
            assert_eq!(probe.finish().is_err(), overflows, "limit {limit}");
        }

        // A delegated open that fails after the pre-open probe succeeded (the database is gone at
        // the instant of the open) runs no validation fstat: the reservation goes back, so the
        // meter equals the physical count on the failed read and on the retry.
        let probe = SyscallProbe::start_fstat_only()?;
        let parked = roots.source.join("opencode.db.parked");
        let (hook_database, hook_parked) = (canonical.clone(), parked.clone());
        set_open_hook(Some(Box::new(move |path| {
            if path == hook_database {
                let _ = fs::rename(&hook_database, &hook_parked);
            }
        })));
        let failed = bounded_read(&observer, &probe, &canonical, 10_000);
        set_open_hook(None);
        fs::rename(&parked, &canonical)?;
        assert!(failed.rows.is_none() && !failed.refused, "{failed:?}");
        assert_eq!(failed.observation, Ok(()), "{failed:?}");
        assert!(failed.used > 0, "{failed:?}");
        assert_eq!(failed.native.metadata, u64::from(failed.used), "{failed:?}");
        let retry = bounded_read(&observer, &probe, &canonical, 10_000);
        assert!(!retry.refused && retry.rows == Some(1), "{retry:?}");
        assert_eq!(retry.observation, Ok(()), "{retry:?}");
        assert_eq!(retry.native.metadata, u64::from(retry.used), "{retry:?}");
        probe.finish()?;
        println!(
            "PHYSICAL failed-open: failed read metadata={} retry metadata={}",
            failed.used, retry.used
        );
        drop(observer);
        writer.stop()?;

        // Consumer: the engine's SQLite stage under the same allowances. Nothing is published
        // from a refused stage, history survives, and the retry is exact. Zero allowance stops
        // before any open and is its own case; every other one must have run the stage, been
        // measured, and consumed exactly its allowance.
        let roots = Roots::new()?;
        let database = roots.source.join("opencode.db");
        let mut writer = live_database(&database, &[&v2_row("base", 10)])?;
        let observer = Rc::new(Observer::start(&roots.source));
        let probe = SyscallProbe::start_fstat_only_with(Limits {
            fstat_failures: 4096,
            ..DEFAULT_LIMITS
        })?;
        let mut stage_total = None;
        let mut allowances = vec![None];
        allowances.extend((0..64).map(Some));
        let (mut refused_runs, mut zero_runs) = (0_u32, 0_u32);
        let (mut first_stage, mut second_stage) = (0_u32, 0_u32);
        for (index, allowance) in allowances.into_iter().enumerate() {
            if let (Some(total), Some(allowance)) = (stage_total, allowance)
                && allowance >= total
            {
                break;
            }
            let shared = Rc::new(Shared::default());
            let fs = Squeezed {
                inner: ObservedFs(RecordingFs::new()),
                observer: Rc::clone(&observer),
                shared: Rc::clone(&shared),
            };
            let data = roots._directory.path().join(format!("data-{index}"));
            let mut engine = OpenCodeEngine::open(
                fs,
                &roots.source,
                &data,
                &roots.home,
                enabled(),
                SourceKind::Custom,
            )
            .map_err(|report| format!("open failed: {report:?}"))?;
            let first = engine.pass(enabled(), 1);
            assert_eq!(first.outcome, PassOutcome::Consistent, "{first:?}");
            let history = engine.observations()?;
            assert!(!history.is_empty());
            writer.exec(&v2_row(&format!("later-{index}"), 5))?;

            shared.allowance.set(allowance);
            shared.started.set(None);
            shared.native.set(None);
            let receipts_before = probe.events().fstat_failures.len();
            let second = engine.pass(enabled(), 2);
            let events = probe.events();
            events.checked()?;
            let receipts = &events.fstat_failures[receipts_before..];
            match allowance {
                None => {
                    assert_eq!(second.outcome, PassOutcome::Consistent, "{second:?}");
                    assert!(receipts.is_empty(), "{receipts:?}");
                    assert_eq!(engine.observations()?.len(), history.len() + 1);
                    stage_total = Some(u32::try_from(
                        shared
                            .native
                            .get()
                            .ok_or("the SQLite stage was not measured")?,
                    )?);
                    assert!(stage_total > Some(0));
                }
                Some(allowance) => {
                    refused_runs += 1;
                    // A refused stage is a budget stop whatever the allowance: the pass is
                    // catching up, not unavailable, and nothing is committed.
                    budget_stop(&second).map_err(|error| format!("{allowance}: {error}"))?;
                    // The stage ended at the first source request after it; none ran after a
                    // stage that never began.
                    let stage = shared.native.get();
                    if allowance == 0 {
                        // Refused before the SQLite stage existed: no open, no fstat.
                        zero_runs += 1;
                        assert_eq!((shared.started.get(), stage), (None, None), "{second:?}");
                        assert!(receipts.is_empty(), "{receipts:?}");
                    } else {
                        let stage = stage.ok_or("the SQLite stage was not measured")?;
                        assert_eq!(stage, u64::from(allowance), "{second:?}");
                    }
                    // The receipt of the first refused fstat says where the stage ended.
                    if let Some(failure) = receipts.first() {
                        assert!(allowance > 0 && receipts.len() <= 8, "{receipts:?}");
                        match failure.native_delta {
                            0 => first_stage += 1,
                            1 => second_stage += 1,
                            other => panic!("{allowance}: {other} native fstats in a refused call"),
                        }
                        assert!(
                            receipts[1..].iter().all(|later| later.native_delta == 0),
                            "{receipts:?}"
                        );
                        assert!(
                            receipts
                                .iter()
                                .all(|failure| failure.errno == EBADF && !failure.foreign),
                            "{receipts:?}"
                        );
                    }
                    assert_eq!(
                        engine.observations()?,
                        history,
                        "history changed by a refused stage ({allowance})"
                    );
                    assert_eq!(second.last_good_ms, first.last_good_ms, "{second:?}");
                    // The retry, with the normal budget, reads the same rows exactly once.
                    let retry = engine.pass(enabled(), 3);
                    assert_eq!(retry.outcome, PassOutcome::Consistent, "{retry:?}");
                    assert_eq!(engine.observations()?.len(), history.len() + 1);
                }
            }
            drop(engine);
            assert!(observer.clean());
        }
        assert!(refused_runs > 10, "{refused_runs}");
        assert_eq!(zero_runs, 1, "the zero allowance is exactly one case");
        // Real receipts from both ends of the hook's two fstats, each followed by the same
        // history, last-good and retry assertions above.
        assert!(
            first_stage > 0,
            "no stage ended before the hook's first fstat"
        );
        assert!(
            second_stage > 0,
            "no stage ended between the hook's two fstats"
        );
        probe.finish()?;
        println!(
            "PHYSICAL engine-refusal: stage native metadata={stage_total:?} refused runs={refused_runs} zero-allowance={zero_runs} first-fstat={first_stage} second-fstat={second_stage}"
        );
        drop(observer);
        writer.stop()?;
        Ok(())
    }

    fn drain_report(name: &str, peak: u64, opens: u64, last: &PassReport) {
        println!(
            "PHYSICAL {name}: peak-held={peak} native-opens={opens} final={:?}",
            last.outcome
        );
    }

    pub fn engine_bounds_child() -> TestResult {
        // Seventy JSON groups: the frontier plus the synchronous part scan reach eight held streams.
        {
            const GROUPS: u64 = 70;
            let roots = Roots::new()?;
            for index in 0..GROUPS {
                json_group(&roots.source, index)?;
            }
            let mut engine = open_observed(&roots)?;
            let observer = Observer::start(&roots.source);
            let (mut peak, mut opens, mut last) = (0, 0, None);
            for step in 0..40 {
                let (report, seen) = driven(&mut engine, &observer, true, 1 + step);
                peak = peak.max(seen.peak);
                opens += seen.opens;
                let done = report.outcome == PassOutcome::Consistent;
                if !done {
                    assert_eq!(
                        seen.opens, 64,
                        "a capped pass uses exactly the open ceiling"
                    );
                }
                last = Some(report);
                if done {
                    break;
                }
            }
            let last = last.ok_or("no pass ran")?;
            assert_eq!(last.outcome, PassOutcome::Consistent, "{last:?}");
            assert_eq!(peak, 8);
            assert_eq!(opens, 3 + 2 * GROUPS);
            drain_report("held-iterators", peak, opens, &last);
            drop(engine);
            assert!(observer.clean(), "iterators dropped with the engine");
        }

        // 2,100 messages cross the metadata ceiling mid-message: exactly 40,000 native calls.
        {
            let roots = Roots::new()?;
            for index in 0..2_100_u64 {
                write_json(
                    &roots.source.join(format!(
                        "storage/message/session-{:02}/m{index:04}.json",
                        index % 10
                    )),
                    &serde_json::json!({
                        "role": "assistant", "time": {"created": 1_700_000_000_000_i64 + index as i64},
                        "tokens": five(index % 5 + 1, 1, index % 5 + 2)
                    }),
                )?;
            }
            let mut engine = open_observed(&roots)?;
            let observer = Observer::start(&roots.source);
            let (first, seen) = driven(&mut engine, &observer, true, 1);
            assert_eq!(first.outcome, PassOutcome::CatchingUp, "{first:?}");
            assert_eq!(seen.metadata, 40_000, "{seen:?}");
            let mut last = first;
            for step in 0..10 {
                if last.outcome == PassOutcome::Consistent {
                    break;
                }
                last = driven(&mut engine, &observer, true, 2 + step).0;
            }
            assert_eq!(last.outcome, PassOutcome::Consistent, "{last:?}");
            println!(
                "PHYSICAL metadata-ceiling: first pass native metadata={}",
                seen.metadata
            );
            drop(engine);
            assert!(observer.clean());
        }

        // 20,002 directory entries: the first pass yields exactly the 20,000 ceiling.
        {
            let roots = Roots::new()?;
            message_file(&roots.source, "m1", 3)?;
            let crowded = roots.source.join("crowded");
            fs::create_dir(&crowded)?;
            for index in 0..20_002 {
                fs::write(crowded.join(format!("entry-{index:05}")), [])?;
            }
            let mut engine = open_observed(&roots)?;
            let observer = Observer::start(&roots.source);
            let (first, seen) = driven(&mut engine, &observer, true, 1);
            assert_eq!(first.outcome, PassOutcome::CatchingUp, "{first:?}");
            assert_eq!(seen.yields, 20_000, "{seen:?}");
            let (second, _) = driven(&mut engine, &observer, true, 2);
            assert_eq!(second.outcome, PassOutcome::Consistent, "{second:?}");
            println!(
                "PHYSICAL entry-ceiling: first pass native yields={}",
                seen.yields
            );
            drop(engine);
            assert!(observer.clean());
        }

        // A part directory larger than one pass: the held iterator resumes, nothing re-yields.
        {
            let roots = Roots::new()?;
            json_group(&roots.source, 0)?;
            let noise = roots.source.join("storage/part/m0000");
            for index in 0..20_010 {
                fs::write(noise.join(format!("noise-{index:05}.txt")), [])?;
            }
            let mut engine = open_observed(&roots)?;
            let observer = Observer::start(&roots.source);
            let (mut last, first) = driven(&mut engine, &observer, true, 1);
            assert_eq!(first.yields, 20_000, "{first:?}");
            let mut yields = first.yields;
            for step in 0..10 {
                if last.outcome == PassOutcome::Consistent {
                    break;
                }
                let (report, seen) = driven(&mut engine, &observer, true, 2 + step);
                yields += seen.yields;
                last = report;
            }
            assert_eq!(last.outcome, PassOutcome::Consistent, "{last:?}");
            assert!(
                yields < 2 * 20_000,
                "{yields} native yields across the drain"
            );
            println!("PHYSICAL part-drain: native yields across passes={yields}");
            drop(engine);
            assert!(observer.clean());
        }

        // 13,500 oversized parts: every pass stays within 40,000 native metadata calls.
        {
            let roots = Roots::new()?;
            json_group(&roots.source, 0)?;
            let part_directory = roots.source.join("storage/part/m0000");
            for index in 0..13_500 {
                let file = fs::File::create(part_directory.join(format!("big-{index:05}.json")))?;
                file.set_len(262_145)?;
            }
            let mut engine = open_observed(&roots)?;
            let observer = Observer::start(&roots.source);
            let (mut rejected, mut peak_metadata) = (0_u64, 0_u64);
            let mut last = None;
            for pass in 1..=60 {
                let (report, seen) = driven(&mut engine, &observer, true, pass);
                rejected += u64::from(report.counters.rejected_records);
                peak_metadata = peak_metadata.max(seen.metadata);
                let done = report.outcome != PassOutcome::CatchingUp;
                last = Some(report);
                if done {
                    break;
                }
            }
            let last = last.ok_or("no pass ran")?;
            assert_eq!(rejected, 13_500);
            assert_eq!(last.outcome, PassOutcome::Partial, "{last:?}");
            println!("PHYSICAL part-metadata: highest pass native metadata={peak_metadata}");
            drop(engine);
            assert!(observer.clean());
        }

        // Maximum-size records past the 64 MiB byte budget: native read bytes equal the charged
        // bytes and never exceed the literal ceiling.
        {
            let roots = Roots::new()?;
            for index in 0..300_u64 {
                let path = roots
                    .source
                    .join(format!("storage/message/session-a/m{index:04}.json"));
                fs::create_dir_all(path.parent().ok_or("parent")?)?;
                fs::File::create(path)?.set_len(262_144)?;
            }
            let mut engine = open_observed(&roots)?;
            let observer = Observer::start(&roots.source);
            let (first, seen) = driven(&mut engine, &observer, true, 1);
            assert!(
                seen.bytes <= 67_108_864 && seen.bytes > 33_554_432,
                "{seen:?}"
            );
            println!(
                "PHYSICAL json-bytes: native bytes={} charged={} outcome={:?}",
                seen.bytes, first.counters.bytes_read, first.outcome
            );
            drop(engine);
            assert!(observer.clean());
        }

        // Directory-open ceiling: 70 directories, first pass opens exactly 64 native streams.
        {
            let roots = Roots::new()?;
            for index in 0..70 {
                fs::create_dir(roots.source.join(format!("directory-{index:03}")))?;
            }
            let mut engine = open_observed(&roots)?;
            let observer = Observer::start(&roots.source);
            let (first, seen) = driven(&mut engine, &observer, true, 1);
            assert_eq!(first.outcome, PassOutcome::CatchingUp, "{first:?}");
            assert_eq!(seen.opens, 64, "{seen:?}");
            drop(engine);
            assert!(observer.clean());
        }

        // Live SQLite source (isolated WAL writer child): the candidate's whole pass, SQLite
        // callbacks included, equals what the observer saw beneath it. Raw page bytes are
        // diagnostic only.
        {
            let roots = Roots::new()?;
            let mut writer =
                live_database(&roots.source.join("opencode.db"), &[&v2_row("live", 10)])?;
            let mut engine = open_observed(&roots)?;
            let observer = Observer::start(&roots.source);
            let (report, seen) = driven(&mut engine, &observer, false, 1);
            assert_eq!(report.outcome, PassOutcome::Consistent, "{report:?}");
            assert_eq!(report.records_committed, 1);
            assert!(seen.bytes >= 4096, "{seen:?}");
            println!(
                "PHYSICAL sqlite-pass: native={seen:?} charged-metadata={}",
                report.counters.stat_calls
            );
            drop(engine);
            assert!(observer.clean());
            drop(observer);
            writer.stop()?;
        }

        // WAL-only usage (the engine's own direct WAL descriptor and the shared-memory file are
        // live during the pass): the access mode of both was checked through native calls made
        // while they were held, and none of them was writable.
        {
            let roots = Roots::new()?;
            let database = roots.source.join("opencode.db");
            let mut writer = start_writer(&database)?;
            let mut engine = open_observed(&roots)?;
            let observer = Observer::start(&roots.source);
            let (report, seen) = driven(&mut engine, &observer, false, 1);
            assert_eq!(report.outcome, PassOutcome::Consistent, "{report:?}");
            assert_eq!(report.records_committed, 1, "{report:?}");
            let reach = observer.reach();
            assert!(
                reach.wal > 0 && reach.shm > 0 && reach.other > 0,
                "{reach:?}"
            );
            assert_eq!(seen.writable, 0, "{seen:?}");
            println!("PHYSICAL wal-pass: native={seen:?} access-checked={reach:?}");
            drop(engine);
            assert!(observer.clean());
            drop(observer);
            writer.stop()?;
        }

        // Raw SQLite page I/O above the 64 MiB JSON ceiling with a materialized payload inside
        // its own budget: the common ceilings accept it, the JSON-only ceiling would not.
        {
            const ROWS: u64 = 260;
            const RECORD_BYTES: usize = 262_000;
            let roots = Roots::new()?;
            let database = roots.source.join("opencode.db");
            {
                let connection = rollback_database(&database)?;
                connection.execute_batch("BEGIN")?;
                for index in 0..ROWS {
                    let head = format!(
                        "{{\"tokens\":{{\"input\":{},\"output\":0,\"reasoning\":0,\
                         \"cache\":{{\"read\":0,\"write\":0}},\"total\":{}}},\"pad\":\"",
                        index + 1,
                        index + 1
                    );
                    let payload = format!(
                        "{head}{}\"}}",
                        "x".repeat(RECORD_BYTES - head.len() - "\"}".len())
                    );
                    assert_eq!(payload.len(), RECORD_BYTES);
                    connection.execute(
                        "INSERT INTO session_v2(id) VALUES (?1)",
                        [format!("s-big-{index:04}")],
                    )?;
                    connection.execute(
                        "INSERT INTO session_message(id, session_id, type, seq, time_created, data) \
                         VALUES (?1, ?2, 'assistant', 1, 1700000000000, ?3)",
                        (format!("big-{index:04}"), format!("s-big-{index:04}"), payload),
                    )?;
                }
                connection.execute_batch("COMMIT")?;
            }
            let mut writer = start_existing_writer(&database)?;
            let mut engine = open_observed(&roots)?;
            let observer = Observer::start(&roots.source);
            let (report, seen) = driven(&mut engine, &observer, false, 1);
            assert!(
                seen.bytes > 67_108_864,
                "premise: SQLite read {} raw bytes",
                seen.bytes
            );
            assert!(
                report.counters.bytes_read <= MAX_SOURCE_BYTES_PER_PASS
                    && report.records_committed > 0,
                "{report:?}"
            );
            assert!(within(seen) && !json_within(seen), "{seen:?}");
            assert!(
                reconcile(&report.counters, seen, true)
                    .expect_err("the JSON-only detector accepted raw SQLite bytes")
                    .starts_with("ceiling"),
            );
            println!(
                "PHYSICAL sqlite-raw-bytes: native bytes={} charged payload bytes={} records={}",
                seen.bytes, report.counters.bytes_read, report.records_committed
            );
            drop(engine);
            assert!(observer.clean());
            drop(observer);
            writer.stop()?;
        }
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn physical_native_observer_child() -> TestResult {
    if native::is_child("physical_native_observer_child") {
        native::observer_child()?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn physical_native_engine_bounds_child() -> TestResult {
    if native::is_child("physical_native_engine_bounds_child") {
        native::engine_bounds_child()?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn physical_native_observer_runs_in_one_isolated_child() -> TestResult {
    native::run_child("physical_native_observer_child")
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn physical_native_engine_bounds_run_in_one_isolated_child() -> TestResult {
    native::run_child("physical_native_engine_bounds_child")
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn physical_native_callback_faults_child() -> TestResult {
    if native::is_child("physical_native_callback_faults_child") {
        native::callback_faults_child()?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn physical_native_callback_faults_run_in_one_isolated_child() -> TestResult {
    native::run_child("physical_native_callback_faults_child")
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn physical_native_second_fstat_refusal_child() -> TestResult {
    if native::is_child("physical_native_second_fstat_refusal_child") {
        native::second_fstat_refusal_child()?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn physical_native_second_fstat_refusal_runs_in_one_isolated_child() -> TestResult {
    native::run_child("physical_native_second_fstat_refusal_child")
}
